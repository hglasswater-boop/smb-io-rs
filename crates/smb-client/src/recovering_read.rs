use crate::{
    ClientError, FileHandle, PipelinedReadOptions, ReadCancellationToken, ReadOnlyReconnectRecipe,
    ReconnectError, SessionConnection, TcpTransport, connect_read_only_file,
    connect_read_only_file_cancelable, is_retryable_client_error,
};

/// Long-lived read-only SMB file that can restore its transport/session/tree/file after a
/// retryable connection failure.
///
/// Only idempotent reads are retried. The reconnect recipe revalidates file identity before the
/// read is replayed, so a different file at the same path is never silently accepted.
pub struct RecoveringReadOnlyFile {
    recipe: ReadOnlyReconnectRecipe,
    session: SessionConnection<TcpTransport>,
    file: FileHandle,
}

impl RecoveringReadOnlyFile {
    /// Establishes the initial transport/session/tree/file and retains the recipe needed to restore
    /// that logical open later.
    pub async fn connect(recipe: ReadOnlyReconnectRecipe) -> Result<Self, ReconnectError> {
        let (session, file) = connect_read_only_file(&recipe).await?;
        Ok(Self {
            recipe,
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

    /// Positional read with a single safe reconnect-and-retry attempt for retryable connection
    /// failures.
    pub async fn read_at(
        &mut self,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, ReconnectError> {
        match self.session.read_at(&self.file, offset, length).await {
            Ok(data) => Ok(data),
            Err(error) if is_retryable_client_error(&error) => {
                self.reconnect().await?;
                self.session
                    .read_at(&self.file, offset, length)
                    .await
                    .map_err(map_client_error)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    /// Pipelined positional read with a single safe reconnect-and-retry attempt for retryable
    /// connection failures.
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
            Err(error) if is_retryable_client_error(&error) => {
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
    /// work, and cancellation is never converted into a retry.
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
            Err(error) if is_retryable_client_error(&error) => {
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

    async fn reconnect(&mut self) -> Result<(), ReconnectError> {
        let (session, file) = connect_read_only_file(&self.recipe).await?;
        self.session = session;
        self.file = file;
        Ok(())
    }

    async fn reconnect_cancelable(
        &mut self,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<(), ReconnectError> {
        let (session, file) =
            connect_read_only_file_cancelable(&self.recipe, cancellation, generation).await?;
        self.session = session;
        self.file = file;
        Ok(())
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
    use super::*;

    #[test]
    fn cancelled_client_error_maps_to_reconnect_cancellation() {
        assert!(matches!(
            map_client_error(ClientError::Cancelled),
            ReconnectError::Cancelled
        ));
    }
}
