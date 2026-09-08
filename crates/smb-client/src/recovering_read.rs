use std::time::Duration;

use crate::{
    ClientError, CloseInfo, CloseOptions, FileHandle, PipelinedReadOptions, ReadCancellationToken,
    ReadOnlyReconnectRecipe, ReconnectError, SessionConnection, TcpTransport,
    connect_read_only_file, connect_read_only_file_cancelable, is_retryable_client_error,
};

/// Controls how aggressively one recovery episode tries to re-establish the SMB connection.
///
/// `max_connect_attempts` does not increase the number of READ replays. Once a connection is
/// restored, the original idempotent READ is still replayed at most once. A value of zero disables
/// automatic recovery after a retryable READ failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadReconnectPolicy {
    pub max_connect_attempts: usize,
    /// Delay before the second and later connection attempts within one recovery episode.
    pub backoff: Duration,
}

impl Default for ReadReconnectPolicy {
    fn default() -> Self {
        Self {
            max_connect_attempts: 1,
            backoff: Duration::ZERO,
        }
    }
}

/// Long-lived read-only SMB file that can restore its transport/session/tree/file after a
/// retryable connection failure.
///
/// Only idempotent reads are retried. The reconnect recipe revalidates file identity before the
/// read is replayed, so a different file at the same path is never silently accepted.
pub struct RecoveringReadOnlyFile {
    recipe: ReadOnlyReconnectRecipe,
    policy: ReadReconnectPolicy,
    session: SessionConnection<TcpTransport>,
    file: FileHandle,
}

impl RecoveringReadOnlyFile {
    /// Establishes the initial transport/session/tree/file and retains the recipe needed to restore
    /// that logical open later. Recovery uses one connection attempt with no backoff.
    pub async fn connect(recipe: ReadOnlyReconnectRecipe) -> Result<Self, ReconnectError> {
        Self::connect_with_policy(recipe, ReadReconnectPolicy::default()).await
    }

    /// Establishes the initial logical open while retaining a recovery policy for later READ
    /// failures. The initial open itself is attempted once; the policy applies only after a
    /// retryable READ failure.
    pub async fn connect_with_policy(
        recipe: ReadOnlyReconnectRecipe,
        policy: ReadReconnectPolicy,
    ) -> Result<Self, ReconnectError> {
        let (session, file) = connect_read_only_file(&recipe).await?;
        Ok(Self {
            recipe,
            policy,
            session,
            file,
        })
    }

    pub fn file(&self) -> &FileHandle {
        &self.file
    }

    pub fn len(&self) -> u64 {
        self.file.len()
    }

    pub fn is_empty(&self) -> bool {
        self.file.len() == 0
    }

    pub fn recipe(&self) -> &ReadOnlyReconnectRecipe {
        &self.recipe
    }

    pub fn reconnect_policy(&self) -> ReadReconnectPolicy {
        self.policy
    }

    /// Closes the current SMB file without replaying the mutation if the connection is lost.
    pub async fn close(mut self) -> Result<CloseInfo, ClientError> {
        self.session
            .close_file(self.file, CloseOptions::default())
            .await
    }

    /// Positional read with one safe reconnect-and-retry episode for retryable connection
    /// failures. The episode may contain multiple connection attempts according to the policy, but
    /// the READ itself is replayed at most once.
    pub async fn read_at(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, ReconnectError> {
        match self.session.read_at(&self.file, offset, length).await {
            Ok(data) => Ok(data),
            Err(error) if self.should_recover(&error) => {
                self.reconnect().await?;
                self.session
                    .read_at(&self.file, offset, length)
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    /// Pipelined positional read with one safe reconnect-and-retry episode for retryable connection
    /// failures.
    pub async fn read_at_pipelined(
        &mut self,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, ReconnectError> {
        self.read_at_pipelined_with_options(offset, length, PipelinedReadOptions::default())
            .await
    }

    pub async fn read_at_pipelined_with_options(
        &mut self,
        offset: u64,
        length: usize,
        options: PipelinedReadOptions,
    ) -> Result<Vec<u8>, ReconnectError> {
        match self
            .session
            .read_at_pipelined_with_options(&self.file, offset, length, options)
            .await
        {
            Ok(data) => Ok(data),
            Err(error) if self.should_recover(&error) => {
                self.reconnect().await?;
                self.session
                    .read_at_pipelined_with_options(&self.file, offset, length, options)
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    /// Cancellation-aware pipelined read. A seek/close generation change also cancels reconnect
    /// work, including a reconnect backoff delay, and cancellation is never converted into a retry.
    pub async fn read_at_pipelined_cancelable_with_options(
        &mut self,
        offset: u64,
        length: usize,
        options: PipelinedReadOptions,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<Vec<u8>, ReconnectError> {
        if !cancellation.is_current(generation) {
            return Err(ReconnectError::Cancelled);
        }

        match self
            .session
            .read_at_pipelined_cancelable_with_options(
                &self.file,
                offset,
                length,
                options,
                cancellation,
                generation,
            )
            .await
        {
            Ok(data) => Ok(data),
            Err(ClientError::Cancelled) => Err(ReconnectError::Cancelled),
            Err(error) if self.should_recover(&error) => {
                self.reconnect_cancelable(cancellation, generation).await?;
                self.session
                    .read_at_pipelined_cancelable_with_options(
                        &self.file,
                        offset,
                        length,
                        options,
                        cancellation,
                        generation,
                    )
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    fn should_recover(&self, error: &ClientError) -> bool {
        self.policy.max_connect_attempts > 0 && is_retryable_client_error(error)
    }

    async fn reconnect(&mut self) -> Result<(), ReconnectError> {
        let attempts = self.policy.max_connect_attempts;
        debug_assert!(attempts > 0);
        let mut last_retryable = None;

        for attempt in 0..attempts {
            if attempt > 0 && !self.policy.backoff.is_zero() {
                tokio::time::sleep(self.policy.backoff).await;
            }

            match connect_read_only_file(&self.recipe).await {
                Ok((session, file)) => {
                    self.session = session;
                    self.file = file;
                    return Ok(());
                }
                Err(error) if is_retryable_reconnect_error(&error) => {
                    last_retryable = Some(error);
                }
                Err(error) => return Err(error),
            }
        }

        Err(
            last_retryable.unwrap_or(ReconnectError::Client(ClientError::Protocol(
                "SMB reconnect attempts exhausted without an error",
            ))),
        )
    }

    async fn reconnect_cancelable(
        &mut self,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<(), ReconnectError> {
        let attempts = self.policy.max_connect_attempts;
        debug_assert!(attempts > 0);
        let mut last_retryable = None;

        for attempt in 0..attempts {
            ensure_current(cancellation, generation)?;
            if attempt > 0 {
                reconnect_backoff_cancelable(self.policy.backoff, cancellation, generation).await?;
            }

            match connect_read_only_file_cancelable(&self.recipe, cancellation, generation).await {
                Ok((session, file)) => {
                    self.session = session;
                    self.file = file;
                    return Ok(());
                }
                Err(ReconnectError::Cancelled) => return Err(ReconnectError::Cancelled),
                Err(error) if is_retryable_reconnect_error(&error) => {
                    last_retryable = Some(error);
                }
                Err(error) => return Err(error),
            }
        }

        Err(
            last_retryable.unwrap_or(ReconnectError::Client(ClientError::Protocol(
                "SMB reconnect attempts exhausted without an error",
            ))),
        )
    }
}

fn is_retryable_reconnect_error(error: &ReconnectError) -> bool {
    matches!(error, ReconnectError::Client(client) if is_retryable_client_error(client))
}

fn ensure_current(
    cancellation: &ReadCancellationToken,
    generation: u64,
) -> Result<(), ReconnectError> {
    if cancellation.is_current(generation) {
        Ok(())
    } else {
        Err(ReconnectError::Cancelled)
    }
}

async fn reconnect_backoff_cancelable(
    duration: Duration,
    cancellation: &ReadCancellationToken,
    generation: u64,
) -> Result<(), ReconnectError> {
    ensure_current(cancellation, generation)?;
    if duration.is_zero() {
        return Ok(());
    }

    tokio::select! {
        _ = tokio::time::sleep(duration) => ensure_current(cancellation, generation),
        _ = cancellation.wait_for_change(generation) => Err(ReconnectError::Cancelled),
    }
}

fn map_client_error(error: ClientError) -> ReconnectError {
    match error {
        ClientError::Cancelled => ReconnectError::Cancelled,
        other => ReconnectError::Client(other),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn default_policy_keeps_single_connect_attempt() {
        assert_eq!(
            ReadReconnectPolicy::default(),
            ReadReconnectPolicy {
                max_connect_attempts: 1,
                backoff: Duration::ZERO,
            }
        );
    }

    #[test]
    fn only_retryable_client_failures_repeat_the_connect_handshake() {
        assert!(is_retryable_reconnect_error(&ReconnectError::Client(
            ClientError::Io(io::Error::new(io::ErrorKind::ConnectionRefused, "offline")),
        )));
        assert!(!is_retryable_reconnect_error(&ReconnectError::Client(
            ClientError::Protocol("bad frame"),
        )));
        assert!(!is_retryable_reconnect_error(&ReconnectError::Cancelled));
        assert!(!is_retryable_reconnect_error(&ReconnectError::RandomSource));
    }

    #[tokio::test]
    async fn reconnect_backoff_is_cancelled_by_generation_change() {
        let cancellation = ReadCancellationToken::new();
        let generation = cancellation.generation();
        let advancing = cancellation.clone();
        let task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            advancing.advance();
        });

        assert!(matches!(
            reconnect_backoff_cancelable(Duration::from_secs(30), &cancellation, generation,).await,
            Err(ReconnectError::Cancelled)
        ));
        task.await.unwrap();
    }

    #[test]
    fn cancelled_client_error_maps_to_reconnect_cancellation() {
        assert!(matches!(
            map_client_error(ClientError::Cancelled),
            ReconnectError::Cancelled
        ));
    }
}
