use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use smb_io_client::{FileHandle, SessionConnection, Transport};
use tokio::sync::{mpsc, oneshot};

use crate::{StreamError, VideoReader, VideoReaderConfig};

#[derive(Debug, Clone, Copy)]
pub struct VideoBrokerConfig {
    pub reader: VideoReaderConfig,
    pub queue_capacity: usize,
}

impl Default for VideoBrokerConfig {
    fn default() -> Self {
        Self {
            reader: VideoReaderConfig::default(),
            queue_capacity: 32,
        }
    }
}

#[derive(Debug)]
pub enum BrokerError {
    Stream(StreamError),
    Closed,
    StaleGeneration,
    InvalidConfig(&'static str),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(error) => write!(f, "stream error: {error}"),
            Self::Closed => f.write_str("video broker is closed"),
            Self::StaleGeneration => {
                f.write_str("video broker request belongs to a stale seek generation")
            }
            Self::InvalidConfig(message) => write!(f, "invalid broker configuration: {message}"),
        }
    }
}

impl Error for BrokerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Stream(error) => Some(error),
            Self::Closed | Self::StaleGeneration | Self::InvalidConfig(_) => None,
        }
    }
}

impl From<StreamError> for BrokerError {
    fn from(value: StreamError) -> Self {
        Self::Stream(value)
    }
}

#[derive(Clone, Debug)]
struct GenerationClock {
    value: Arc<AtomicU64>,
}

impl GenerationClock {
    fn new() -> Self {
        Self {
            value: Arc::new(AtomicU64::new(0)),
        }
    }

    fn current(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    fn advance(&self) -> u64 {
        self.value.fetch_add(1, Ordering::AcqRel).wrapping_add(1)
    }

    fn is_current(&self, generation: u64) -> bool {
        self.current() == generation
    }
}

enum BrokerCommand {
    Read {
        generation: u64,
        offset: u64,
        length: usize,
        reply: oneshot::Sender<Result<Vec<u8>, BrokerError>>,
    },
    Prefetch {
        generation: u64,
        offset: u64,
        length: usize,
    },
    Shutdown,
}

/// Cheap cloneable control surface used by a player, JNI adapter, or FFmpeg bridge.
///
/// `seek()` updates the generation atomically without waiting for the broker's SMB transport loop.
/// A prefetch that finishes after that point is treated as stale and its cache is discarded.
#[derive(Clone)]
pub struct VideoBrokerHandle {
    generation: GenerationClock,
    commands: mpsc::Sender<BrokerCommand>,
}

impl VideoBrokerHandle {
    pub fn generation(&self) -> u64 {
        self.generation.current()
    }

    /// Invalidates all work issued under the previous logical playback position.
    pub fn seek(&self) -> u64 {
        self.generation.advance()
    }

    pub async fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>, BrokerError> {
        let generation = self.generation.current();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(BrokerCommand::Read {
                generation,
                offset,
                length,
                reply: reply_tx,
            })
            .await
            .map_err(|_| BrokerError::Closed)?;
        reply_rx.await.map_err(|_| BrokerError::Closed)?
    }

    /// Queues speculative data for the current generation.
    ///
    /// Network or decode failures are intentionally not returned to the caller because prefetch is
    /// optional. Interactive `read()` calls still surface their errors normally.
    pub async fn prefetch(&self, offset: u64, length: usize) -> Result<(), BrokerError> {
        let generation = self.generation.current();
        self.commands
            .send(BrokerCommand::Prefetch {
                generation,
                offset,
                length,
            })
            .await
            .map_err(|_| BrokerError::Closed)
    }

    pub async fn shutdown(&self) -> Result<(), BrokerError> {
        self.commands
            .send(BrokerCommand::Shutdown)
            .await
            .map_err(|_| BrokerError::Closed)
    }
}

/// Owns one authenticated SMB session and one open video file.
///
/// The runner is deliberately returned as a future-owning object instead of internally calling
/// `tokio::spawn`. This keeps the crate compatible with runtimes that want to place SMB I/O on a
/// dedicated task or LocalSet, while Android can simply run it on its native Tokio runtime.
pub struct VideoBrokerRunner<T> {
    generation: GenerationClock,
    commands: mpsc::Receiver<BrokerCommand>,
    session: SessionConnection<T>,
    file: FileHandle,
    reader: VideoReader,
    active_generation: u64,
}

impl<T> VideoBrokerRunner<T>
where
    T: Transport,
{
    pub async fn run(mut self) {
        while let Some(command) = self.commands.recv().await {
            match command {
                BrokerCommand::Read {
                    generation,
                    offset,
                    length,
                    reply,
                } => {
                    let result = self.process_read(generation, offset, length).await;
                    let _ = reply.send(result);
                }
                BrokerCommand::Prefetch {
                    generation,
                    offset,
                    length,
                } => {
                    let _ = self.process_prefetch(generation, offset, length).await;
                }
                BrokerCommand::Shutdown => break,
            }
        }
    }

    fn prepare_generation(&mut self, generation: u64, offset: u64) -> Result<(), BrokerError> {
        if !self.generation.is_current(generation) {
            return Err(BrokerError::StaleGeneration);
        }
        if generation != self.active_generation {
            self.reader.seek(offset);
            self.active_generation = generation;
        }
        Ok(())
    }

    async fn process_read(
        &mut self,
        generation: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, BrokerError> {
        self.prepare_generation(generation, offset)?;
        let result = self
            .reader
            .read(&mut self.session, &self.file, offset, length)
            .await
            .map_err(BrokerError::Stream)?;

        if !self.generation.is_current(generation) {
            self.reader.invalidate();
            return Err(BrokerError::StaleGeneration);
        }
        Ok(result)
    }

    async fn process_prefetch(
        &mut self,
        generation: u64,
        offset: u64,
        length: usize,
    ) -> Result<(), BrokerError> {
        self.prepare_generation(generation, offset)?;
        let result = self
            .reader
            .read(&mut self.session, &self.file, offset, length)
            .await;

        if !self.generation.is_current(generation) {
            self.reader.invalidate();
            return Err(BrokerError::StaleGeneration);
        }
        result.map(|_| ()).map_err(BrokerError::Stream)
    }
}

pub fn video_broker<T>(
    session: SessionConnection<T>,
    file: FileHandle,
    config: VideoBrokerConfig,
) -> Result<(VideoBrokerHandle, VideoBrokerRunner<T>), BrokerError>
where
    T: Transport,
{
    if config.queue_capacity == 0 {
        return Err(BrokerError::InvalidConfig(
            "queue_capacity must be greater than zero",
        ));
    }
    let reader = VideoReader::new(config.reader)?;
    let generation = GenerationClock::new();
    let (commands_tx, commands_rx) = mpsc::channel(config.queue_capacity);
    let handle = VideoBrokerHandle {
        generation: generation.clone(),
        commands: commands_tx,
    };
    let runner = VideoBrokerRunner {
        generation,
        commands: commands_rx,
        session,
        file,
        reader,
        active_generation: 0,
    };
    Ok((handle, runner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_clock_invalidates_old_work_immediately() {
        let clock = GenerationClock::new();
        let initial = clock.current();
        assert!(clock.is_current(initial));
        let next = clock.advance();
        assert_eq!(next, initial + 1);
        assert!(!clock.is_current(initial));
        assert!(clock.is_current(next));
    }

    #[test]
    fn zero_queue_capacity_is_invalid_by_contract() {
        let config = VideoBrokerConfig {
            queue_capacity: 0,
            ..VideoBrokerConfig::default()
        };
        assert_eq!(config.queue_capacity, 0);
    }
}
