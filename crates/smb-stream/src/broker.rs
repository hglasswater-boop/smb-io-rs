use std::error::Error;
use std::fmt;

use smb_io_client::{
    CloseInfo, CloseOptions, FileHandle, ReadCancellationToken, ReadOnlyReconnectRecipe,
    ReadReconnectPolicy, RecoveringReadOnlyFile, SessionConnection, TcpTransport, Transport,
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

enum InteractiveCommand {
    Read {
        generation: u64,
        offset: u64,
        length: usize,
        reply: oneshot::Sender<Result<Vec<u8>, BrokerError>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<CloseInfo, BrokerError>>,
    },
}

struct PrefetchCommand {
    playback_generation: u64,
    prefetch_generation: u64,
    offset: u64,
    length: usize,
}

/// Cheap cloneable control surface used by a player, JNI adapter, or FFmpeg bridge.
///
/// Foreground reads and control operations use a dedicated high-priority queue. Starting a
/// foreground read also invalidates the speculative-I/O generation, which causes an in-flight
/// prefetch READ, reconnect, or reconnect backoff to stop before the foreground request is run.
#[derive(Clone)]
pub struct VideoBrokerHandle {
    cancellation: ReadCancellationToken,
    prefetch_cancellation: ReadCancellationToken,
    interactive_commands: mpsc::Sender<InteractiveCommand>,
    background_commands: mpsc::Sender<PrefetchCommand>,
    file_len: u64,
}

impl VideoBrokerHandle {
    pub fn generation(&self) -> u64 {
        self.cancellation.generation()
    }

    pub fn len(&self) -> u64 {
        self.file_len
    }

    pub fn is_empty(&self) -> bool {
        self.file_len == 0
    }

    /// Invalidates all work issued under the previous logical playback position.
    pub fn seek(&self) -> u64 {
        self.prefetch_cancellation.advance();
        self.cancellation.advance()
    }

    pub async fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>, BrokerError> {
        self.prefetch_cancellation.advance();
        let generation = self.cancellation.generation();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.interactive_commands
            .send(InteractiveCommand::Read {
                generation,
                offset,
                length,
                reply: reply_tx,
            })
            .await
            .map_err(|_| BrokerError::Closed)?;
        reply_rx.await.map_err(|_| BrokerError::Closed)?
    }

    /// Queues speculative data for the current playback and prefetch generations.
    ///
    /// Prefetch is a hint, so a full background queue drops the new command instead of blocking a
    /// caller that may be on a playback thread. A closed broker remains an error. Any later
    /// foreground read invalidates queued or in-flight speculative work before it can compete for
    /// the SMB connection.
    pub fn prefetch(&self, offset: u64, length: usize) -> Result<(), BrokerError> {
        let command = PrefetchCommand {
            playback_generation: self.cancellation.generation(),
            prefetch_generation: self.prefetch_cancellation.generation(),
            offset,
            length,
        };
        match self.background_commands.try_send(command) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(BrokerError::Closed),
        }
    }

    /// Gracefully stops the broker and sends one SMB CLOSE for the current file handle.
    ///
    /// CLOSE is never replayed after an ambiguous transport failure.
    pub async fn close(&self) -> Result<CloseInfo, BrokerError> {
        self.prefetch_cancellation.advance();
        self.cancellation.advance();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.interactive_commands
            .send(InteractiveCommand::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| BrokerError::Closed)?;
        reply_rx.await.map_err(|_| BrokerError::Closed)?
    }

    pub async fn shutdown(&self) -> Result<(), BrokerError> {
        self.close().await.map(|_| ())
    }
}

struct DirectBrokerSource<T> {
    session: SessionConnection<T>,
    file: FileHandle,
}

enum BrokerSource<T> {
    Direct(Box<DirectBrokerSource<T>>),
    Recovering(Box<RecoveringReadOnlyFile>),
}

/// Owns the SMB read source and video read-ahead/cache state.
///
/// The runner is deliberately returned as a future-owning object instead of internally calling
/// `tokio::spawn`. This keeps the crate compatible with runtimes that want to place SMB I/O on a
/// dedicated task or LocalSet, while Android can simply run it on its native Tokio runtime.
/// Foreground commands are selected before ready background-prefetch commands.
pub struct VideoBrokerRunner<T> {
    cancellation: ReadCancellationToken,
    prefetch_cancellation: ReadCancellationToken,
    interactive_commands: mpsc::Receiver<InteractiveCommand>,
    background_commands: mpsc::Receiver<PrefetchCommand>,
    source: Option<BrokerSource<T>>,
    reader: VideoReader,
    active_generation: u64,
}

impl<T> VideoBrokerRunner<T>
where
    T: Transport,
{
    pub async fn run(mut self) {
        enum SelectedCommand {
            Interactive(Option<InteractiveCommand>),
            Background(Option<PrefetchCommand>),
        }

        let mut interactive_open = true;
        let mut background_open = true;

        while interactive_open || background_open {
            let selected = tokio::select! {
                biased;
                command = self.interactive_commands.recv(), if interactive_open => {
                    SelectedCommand::Interactive(command)
                }
                command = self.background_commands.recv(), if background_open => {
                    SelectedCommand::Background(command)
                }
            };

            match selected {
                SelectedCommand::Interactive(Some(InteractiveCommand::Read {
                    generation,
                    offset,
                    length,
                    reply,
                })) => {
                    let result = self.process_read(generation, offset, length).await;
                    let _ = reply.send(result);
                }
                SelectedCommand::Interactive(Some(InteractiveCommand::Shutdown { reply })) => {
                    let result = self.close_source().await;
                    let _ = reply.send(result);
                    break;
                }
                SelectedCommand::Interactive(None) => interactive_open = false,
                SelectedCommand::Background(Some(command)) => {
                    let _ = self.process_prefetch(command).await;
                }
                SelectedCommand::Background(None) => background_open = false,
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
        offset: u64,
        length: usize,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<Vec<u8>, BrokerError> {
        let source = self.source.as_mut().ok_or(BrokerError::Closed)?;
        match source {
            BrokerSource::Direct(source) => {
                let source = source.as_mut();
                self.reader
                    .read_cancelable(
                        &mut source.session,
                        &source.file,
                        offset,
                        length,
                        cancellation,
                        generation,
                    )
                    .await
                    .map_err(BrokerError::Stream)
            }
            BrokerSource::Recovering(source) => self
                .reader
                .read_recovering_cancelable(
                    source.as_mut(),
                    offset,
                    length,
                    cancellation,
                    generation,
                )
                .await
                .map_err(BrokerError::Stream),
        }
    }

    async fn prefetch_source(
        &mut self,
        hint_offset: u64,
        hint_length: usize,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<usize, BrokerError> {
        let source = self.source.as_mut().ok_or(BrokerError::Closed)?;
        match source {
            BrokerSource::Direct(source) => {
                let source = source.as_mut();
                self.reader
                    .prefetch_cancelable(
                        &mut source.session,
                        &source.file,
                        hint_offset,
                        hint_length,
                        cancellation,
                        generation,
                    )
                    .await
                    .map_err(BrokerError::Stream)
            }
            BrokerSource::Recovering(source) => self
                .reader
                .prefetch_recovering_cancelable(
                    source.as_mut(),
                    hint_offset,
                    hint_length,
                    cancellation,
                    generation,
                )
                .await
                .map_err(BrokerError::Stream),
        }
    }

    async fn process_read(
        &mut self,
        generation: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, BrokerError> {
        self.prepare_generation(generation, offset)?;
        let cancellation = self.cancellation.clone();
        let result = self
            .read_source(offset, length, &cancellation, generation)
            .await;

        match result {
            Ok(data) if self.cancellation.is_current(generation) => Ok(data),
            Ok(_) => {
                self.reader.invalidate();
                Err(BrokerError::StaleGeneration)
            }
            Err(BrokerError::Stream(error)) if error.is_cancelled() => {
                self.reader.invalidate();
                Err(BrokerError::StaleGeneration)
            }
            Err(error) => Err(error),
        }
    }

    async fn process_prefetch(&mut self, command: PrefetchCommand) -> Result<(), BrokerError> {
        if !self
            .prefetch_cancellation
            .is_current(command.prefetch_generation)
        {
            return Err(BrokerError::StaleGeneration);
        }
        self.prepare_generation(command.playback_generation, command.offset)?;

        let cancellation = self.prefetch_cancellation.clone();
        let result = self
            .prefetch_source(
                command.offset,
                command.length,
                &cancellation,
                command.prefetch_generation,
            )
            .await;

        match result {
            Ok(_)
                if self.cancellation.is_current(command.playback_generation)
                    && self
                        .prefetch_cancellation
                        .is_current(command.prefetch_generation) =>
            {
                Ok(())
            }
            Ok(_) => Err(BrokerError::StaleGeneration),
            Err(BrokerError::Stream(error)) if error.is_cancelled() => {
                Err(BrokerError::StaleGeneration)
            }
            Err(error) => Err(error),
        }
    }

    async fn close_source(&mut self) -> Result<CloseInfo, BrokerError> {
        let source = self.source.take().ok_or(BrokerError::Closed)?;
        match source {
            BrokerSource::Direct(mut source) => source
                .session
                .close_file(source.file, CloseOptions::default())
                .await
                .map_err(StreamError::from)
                .map_err(BrokerError::Stream),
            BrokerSource::Recovering(source) => source
                .close()
                .await
                .map_err(StreamError::from)
                .map_err(BrokerError::Stream),
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
    let file_len = file.len();
    Ok(broker_from_source(
        BrokerSource::Direct(Box::new(DirectBrokerSource { session, file })),
        reader,
        config.queue_capacity,
        file_len,
    ))
}

/// Connects a read-only SMB file and creates a broker that transparently restores retryable
/// transport/session failures before replaying the idempotent read.
pub async fn recovering_video_broker(
    recipe: ReadOnlyReconnectRecipe,
    config: VideoBrokerConfig,
) -> Result<(VideoBrokerHandle, VideoBrokerRunner<TcpTransport>), BrokerError> {
    recovering_video_broker_with_policy(recipe, ReadReconnectPolicy::default(), config).await
}

/// Policy-aware recovering broker used by platform adapters that want bounded reconnect handshake
/// retries without changing the one-READ-replay safety rule.
pub async fn recovering_video_broker_with_policy(
    recipe: ReadOnlyReconnectRecipe,
    policy: ReadReconnectPolicy,
    config: VideoBrokerConfig,
) -> Result<(VideoBrokerHandle, VideoBrokerRunner<TcpTransport>), BrokerError> {
    validate_queue_capacity(config.queue_capacity)?;
    let reader = VideoReader::new(config.reader)?;
    let source = RecoveringReadOnlyFile::connect_with_policy(recipe, policy)
        .await
        .map_err(StreamError::from)?;
    let file_len = source.len();
    Ok(broker_from_source::<TcpTransport>(
        BrokerSource::Recovering(Box::new(source)),
        reader,
        config.queue_capacity,
        file_len,
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
    file_len: u64,
) -> (VideoBrokerHandle, VideoBrokerRunner<T>) {
    let cancellation = ReadCancellationToken::new();
    let prefetch_cancellation = ReadCancellationToken::new();
    let (interactive_tx, interactive_rx) = mpsc::channel(queue_capacity);
    let (background_tx, background_rx) = mpsc::channel(queue_capacity);
    let handle = VideoBrokerHandle {
        cancellation: cancellation.clone(),
        prefetch_cancellation: prefetch_cancellation.clone(),
        interactive_commands: interactive_tx,
        background_commands: background_tx,
        file_len,
    };
    let runner = VideoBrokerRunner {
        cancellation,
        prefetch_cancellation,
        interactive_commands: interactive_rx,
        background_commands: background_rx,
        source: Some(source),
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

    #[tokio::test]
    async fn foreground_read_invalidates_prefetch_before_enqueue() {
        let cancellation = ReadCancellationToken::new();
        let prefetch_cancellation = ReadCancellationToken::new();
        let old_prefetch_generation = prefetch_cancellation.generation();
        let (interactive_tx, mut interactive_rx) = mpsc::channel(1);
        let (background_tx, _background_rx) = mpsc::channel(1);
        let handle = VideoBrokerHandle {
            cancellation,
            prefetch_cancellation: prefetch_cancellation.clone(),
            interactive_commands: interactive_tx,
            background_commands: background_tx,
            file_len: 123,
        };

        let caller = tokio::spawn(async move { handle.read(4, 1).await });
        let command = interactive_rx.recv().await.unwrap();
        assert!(!prefetch_cancellation.is_current(old_prefetch_generation));

        match command {
            InteractiveCommand::Read { reply, .. } => {
                reply.send(Ok(vec![7])).unwrap();
            }
            InteractiveCommand::Shutdown { .. } => panic!("unexpected shutdown command"),
        }

        assert_eq!(caller.await.unwrap().unwrap(), vec![7]);
    }

    #[test]
    fn full_prefetch_queue_drops_new_hint_without_waiting() {
        let cancellation = ReadCancellationToken::new();
        let prefetch_cancellation = ReadCancellationToken::new();
        let (interactive_tx, _interactive_rx) = mpsc::channel(1);
        let (background_tx, mut background_rx) = mpsc::channel(1);
        let handle = VideoBrokerHandle {
            cancellation,
            prefetch_cancellation,
            interactive_commands: interactive_tx,
            background_commands: background_tx,
            file_len: 123,
        };

        handle.prefetch(10, 4).unwrap();
        handle.prefetch(20, 4).unwrap();

        let queued = background_rx.try_recv().unwrap();
        assert_eq!(queued.offset, 10);
        assert!(matches!(
            background_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}
