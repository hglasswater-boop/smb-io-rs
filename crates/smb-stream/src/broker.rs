use std::error::Error;
use std::fmt;

use smb_io_client::{
    FileHandle, ReadCancellationToken, ReadOnlyReconnectRecipe, RecoveringReadOnlyFile,
    SessionConnection, TcpTransport, Transport,
};
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
/// `seek()` advances the cancellation generation synchronously. A blocked network READ notices the
/// change, emits SMB2 CANCEL for its outstanding requests, drains their target responses, and then
/// returns control to the broker without admitting stale data into the cache.
#[derive(Clone)]
pub struct VideoBrokerHandle {
    cancellation: ReadCancellationToken,
    commands: mpsc::Sender<BrokerCommand>,
}

impl VideoBrokerHandle {
    pub fn generation(&self) -> u64 {
        self.cancellation.generation()
    }

    /// Invalidates all work issued under the previous logical playback position.
    pub fn seek(&self) -> u64 {
        self.cancellation.advance()
    }

    pub async fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>, BrokerError> {
        let generation = self.cancellation.generation();
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
        let generation = self.cancellation.generation();
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

enum BrokerSource<T> {
    Direct {
        session: SessionConnection<T>,
        file: FileHandle,
    },
    Recovering(Box<RecoveringReadOnlyFile>),
}

/// Owns the SMB read source and video read-ahead/cache state.
///
/// The runner is deliberately returned as a future-owning object instead of internally calling
/// `tokio::spawn`. This keeps the crate compatible with runtimes that want to place SMB I/O on a
/// dedicated task or LocalSet, while Android can simply run it on its native Tokio runtime.
pub struct VideoBrokerRunner<T> {
    cancellation: ReadCancellationToken,
    commands: mpsc::Receiver<BrokerCommand>,
    source: BrokerSource<T>,
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
        if !self.cancellation.is_current(generation) {
            return Err(BrokerError::StaleGeneration);
        }
        if generation != self.active_generation {
            self.reader.seek(offset);
            self.active_generation = generation;
        }
        Ok(())
    }

    async fn read_source(
        &mut self,
        generation: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, StreamError> {
        match &mut self.source {
            BrokerSource::Direct { session, file } => {
                self.reader
                    .read_cancelable(
                        session,
                        file,
                        offset,
                        length,
                        &self.cancellation,
                        generation,
                    )
                    .await
            }
            BrokerSource::Recovering(source) => {
                self.reader
                    .read_recovering_cancelable(
                        source.as_mut(),
                        offset,
                        length,
                        &self.cancellation,
                        generation,
                    )
                    .await
            }
        }
    }

    async fn process_read(
        &mut self,
        generation: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, BrokerError> {
        self.prepare_generation(generation, offset)?;
        let result = self.read_source(generation, offset, length).await;

        match result {
            Ok(data) if self.cancellation.is_current(generation) => Ok(data),
            Ok(_) => {
                self.reader.invalidate();
                Err(BrokerError::StaleGeneration)
            }
            Err(error) if error.is_cancelled() => {
                self.reader.invalidate();
                Err(BrokerError::StaleGeneration)
            }
            Err(error) => Err(BrokerError::Stream(error)),
        }
    }

    async fn process_prefetch(
        &mut self,
        generation: u64,
        offset: u64,
        length: usize,
    ) -> Result<(), BrokerError> {
        self.prepare_generation(generation, offset)?;
        let result = self.read_source(generation, offset, length).await;

        match result {
            Ok(_) if self.cancellation.is_current(generation) => Ok(()),
            Ok(_) => {
                self.reader.invalidate();
                Err(BrokerError::StaleGeneration)
            }
            Err(error) if error.is_cancelled() => {
                self.reader.invalidate();
                Err(BrokerError::StaleGeneration)
            }
            Err(error) => Err(BrokerError::Stream(error)),
        }
    }
}

/// Creates a broker over an already-authenticated session and open file.
pub fn video_broker<T>(
    session: SessionConnection<T>,
    file: FileHandle,
    config: VideoBrokerConfig,
) -> Result<(VideoBrokerHandle, VideoBrokerRunner<T>), BrokerError>
where
    T: Transport,
{
    validate_queue_capacity(config.queue_capacity)?;
    let reader = VideoReader::new(config.reader)?;
    Ok(broker_from_source(
        BrokerSource::Direct { session, file },
        reader,
        config.queue_capacity,
    ))
}

/// Connects a read-only SMB file and creates a broker that transparently restores retryable
/// transport/session failures before replaying the idempotent read.
pub async fn recovering_video_broker(
    recipe: ReadOnlyReconnectRecipe,
    config: VideoBrokerConfig,
) -> Result<(VideoBrokerHandle, VideoBrokerRunner<TcpTransport>), BrokerError> {
    validate_queue_capacity(config.queue_capacity)?;
    let reader = VideoReader::new(config.reader)?;
    let source = RecoveringReadOnlyFile::connect(recipe)
        .await
        .map_err(StreamError::from)?;
    Ok(broker_from_source::<TcpTransport>(
        BrokerSource::Recovering(Box::new(source)),
        reader,
        config.queue_capacity,
    ))
}

fn validate_queue_capacity(queue_capacity: usize) -> Result<(), BrokerError> {
    if queue_capacity == 0 {
        return Err(BrokerError::InvalidConfig(
            "queue_capacity must be greater than zero",
        ));
    }
    Ok(())
}

fn broker_from_source<T>(
    source: BrokerSource<T>,
    reader: VideoReader,
    queue_capacity: usize,
) -> (VideoBrokerHandle, VideoBrokerRunner<T>) {
    let cancellation = ReadCancellationToken::new();
    let (commands_tx, commands_rx) = mpsc::channel(queue_capacity);
    let handle = VideoBrokerHandle {
        cancellation: cancellation.clone(),
        commands: commands_tx,
    };
    let runner = VideoBrokerRunner {
        cancellation,
        commands: commands_rx,
        source,
        reader,
        active_generation: 0,
    };
    (handle, runner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seek_token_invalidates_old_work_immediately() {
        let token = ReadCancellationToken::new();
        let initial = token.generation();
        assert!(token.is_current(initial));
        let next = token.advance();
        assert_eq!(next, initial + 1);
        assert!(!token.is_current(initial));
        assert!(token.is_current(next));
    }

    #[test]
    fn zero_queue_capacity_is_invalid_by_contract() {
        assert!(matches!(
            validate_queue_capacity(0),
            Err(BrokerError::InvalidConfig(_))
        ));
    }
}
