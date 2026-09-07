use std::time::Duration;

use smb_io_client::is_retryable_client_error;
use smb_io_stream::StreamError;

pub(crate) fn is_retryable_stream_error(error: &StreamError) -> bool {
    matches!(error, StreamError::Client(client) if is_retryable_client_error(client))
}

pub(crate) async fn reconnect_backoff(duration: Duration) {
    if !duration.is_zero() {
        tokio::time::sleep(duration).await;
    }
}
