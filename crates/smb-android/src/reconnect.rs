use std::time::Duration;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    ClientError, Connection, FileHandle, FileOpenOptions, NegotiateConfig, ReadCancellationToken,
    SessionConnection, SessionSetupConfig, TcpTransport, TcpTransportConfig, TreeConnectOptions,
};
use smb_io_stream::StreamError;
use zeroize::Zeroizing;

pub(crate) const STATUS_NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
pub(crate) const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;
pub(crate) const STATUS_NETWORK_SESSION_EXPIRED: u32 = 0xC000_035C;

pub(crate) struct ReconnectRecipe {
    host: String,
    port: u16,
    share: String,
    path: String,
    username: String,
    password: Zeroizing<String>,
    domain: String,
    workstation: String,
}

impl ReconnectRecipe {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        host: String,
        port: u16,
        share: String,
        path: String,
        username: String,
        password: String,
        domain: String,
        workstation: String,
    ) -> Self {
        Self {
            host,
            port,
            share,
            path,
            username,
            password: Zeroizing::new(password),
            domain,
            workstation,
        }
    }
}

#[derive(Debug)]
pub(crate) enum ReconnectError {
    Client(ClientError),
    Cancelled,
    RandomSource,
}

impl From<ClientError> for ReconnectError {
    fn from(value: ClientError) -> Self {
        Self::Client(value)
    }
}

pub(crate) fn is_retryable_client_error(error: &ClientError) -> bool {
    match error {
        ClientError::Io(_) | ClientError::Timeout(_) => true,
        ClientError::ServerStatus(status) => matches!(
            *status,
            STATUS_NETWORK_NAME_DELETED
                | STATUS_USER_SESSION_DELETED
                | STATUS_NETWORK_SESSION_EXPIRED
        ),
        ClientError::Wire(_)
        | ClientError::Auth(_)
        | ClientError::Cancelled
        | ClientError::Protocol(_) => false,
    }
}

pub(crate) fn is_retryable_stream_error(error: &StreamError) -> bool {
    matches!(error, StreamError::Client(client) if is_retryable_client_error(client))
}

pub(crate) async fn connect_video_cancelable(
    recipe: &ReconnectRecipe,
    cancellation: &ReadCancellationToken,
    generation: u64,
) -> Result<(SessionConnection<TcpTransport>, FileHandle), ReconnectError> {
    tokio::select! {
        result = connect_video(recipe) => result,
        _ = cancellation.wait_for_change(generation) => Err(ReconnectError::Cancelled),
    }
}

pub(crate) async fn connect_video(
    recipe: &ReconnectRecipe,
) -> Result<(SessionConnection<TcpTransport>, FileHandle), ReconnectError> {
    let mut client_guid = [0u8; 16];
    let mut preauth_salt = [0u8; 32];
    getrandom::fill(&mut client_guid).map_err(|_| ReconnectError::RandomSource)?;
    getrandom::fill(&mut preauth_salt).map_err(|_| ReconnectError::RandomSource)?;

    let transport =
        TcpTransport::connect(&recipe.host, recipe.port, TcpTransportConfig::default()).await?;
    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig::modern(client_guid, preauth_salt.to_vec()))
        .await?;

    let mut session = if recipe.username.is_empty() {
        let mut auth = AnonymousNtlmProvider::new();
        connection
            .session_setup(&mut auth, SessionSetupConfig::default())
            .await?
    } else {
        // This transient password copy is immediately owned by NtlmCredentials and zeroized when
        // the authentication provider is dropped. The long-lived copy remains inside Zeroizing.
        let mut credentials =
            NtlmCredentials::new(recipe.username.clone(), recipe.password.as_str().to_owned());
        if !recipe.domain.is_empty() {
            credentials = credentials.with_domain(recipe.domain.clone());
        }
        if !recipe.workstation.is_empty() {
            credentials = credentials.with_workstation(recipe.workstation.clone());
        }
        let mut auth = NtlmV2Provider::new(credentials);
        connection
            .session_setup(&mut auth, SessionSetupConfig::default())
            .await?
    };

    let unc_share = format!("\\\\{}\\{}", recipe.host, recipe.share);
    let tree = session
        .tree_connect(unc_share, TreeConnectOptions::default())
        .await?;
    let file = session
        .open_file(&tree, &recipe.path, FileOpenOptions::read_existing_random())
        .await?;
    Ok((session, file))
}

pub(crate) async fn reconnect_backoff(duration: Duration) {
    if !duration.is_zero() {
        tokio::time::sleep(duration).await;
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn transport_and_session_lifetime_failures_are_retryable() {
        assert!(is_retryable_client_error(&ClientError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset",
        ))));
        assert!(is_retryable_client_error(&ClientError::Timeout("read")));
        assert!(is_retryable_client_error(&ClientError::ServerStatus(
            STATUS_NETWORK_SESSION_EXPIRED,
        )));
        assert!(is_retryable_client_error(&ClientError::ServerStatus(
            STATUS_USER_SESSION_DELETED,
        )));
        assert!(is_retryable_client_error(&ClientError::ServerStatus(
            STATUS_NETWORK_NAME_DELETED,
        )));
    }

    #[test]
    fn security_and_protocol_failures_are_never_retried() {
        assert!(!is_retryable_client_error(&ClientError::Protocol(
            "bad frame"
        )));
        assert!(!is_retryable_client_error(&ClientError::Cancelled));
        assert!(!is_retryable_client_error(&ClientError::ServerStatus(
            0xC000_0022,
        )));
    }
}
