use std::error::Error;
use std::fmt;
use std::sync::OnceLock;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    ClientError, CloseOptions, Connection, DurableFileHandle, DurableHandleV2Options, FileHandle,
    FileOpenOptions, NegotiateConfig, ReadCancellationToken, SessionConnection, SessionSetupConfig,
    TcpTransport, TcpTransportConfig, TreeConnectOptions,
};

pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
pub const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;
pub const STATUS_NETWORK_SESSION_EXPIRED: u32 = 0xC000_035C;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    creation_time: u64,
    last_write_time: u64,
}

impl FileIdentity {
    fn from_file(file: &FileHandle) -> Self {
        Self {
            len: file.len(),
            creation_time: file.creation_time(),
            last_write_time: file.last_write_time(),
        }
    }

    fn is_compatible_with(self, reopened: Self) -> bool {
        self.len == reopened.len
            && timestamp_matches(self.creation_time, reopened.creation_time)
            && timestamp_matches(self.last_write_time, reopened.last_write_time)
    }
}

fn timestamp_matches(original: u64, reopened: u64) -> bool {
    original == 0 || reopened == 0 || original == reopened
}

#[derive(Default)]
struct DurableRecoveryState {
    handle: Option<DurableFileHandle>,
    unavailable: bool,
}

/// Reusable recipe for restoring a read-only SMB file after a transport/session failure.
///
/// Path reopen is always guarded by the first CREATE metadata so a different file at the same path
/// is never silently accepted. Durable Handle V2 can be explicitly enabled for consumers that can
/// also service the BATCH-oplock lifecycle; when enabled, DH2C is attempted before path reopen.
pub struct ReadOnlyReconnectRecipe {
    host: String,
    port: u16,
    share: String,
    path: String,
    username: String,
    password: Zeroizing<String>,
    domain: String,
    workstation: String,
    identity: OnceLock<FileIdentity>,
    client_guid: OnceLock<[u8; 16]>,
    durable_v2_enabled: bool,
    durable: Mutex<DurableRecoveryState>,
}

impl ReadOnlyReconnectRecipe {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
            identity: OnceLock::new(),
            client_guid: OnceLock::new(),
            durable_v2_enabled: false,
            durable: Mutex::new(DurableRecoveryState::default()),
        }
    }

    /// Explicitly opts this logical read-only open into Durable Handle V2 recovery.
    ///
    /// This remains opt-in until the shared request broker can service unsolicited oplock breaks.
    pub fn with_durable_v2(mut self, enabled: bool) -> Self {
        self.durable_v2_enabled = enabled;
        self
    }

    pub fn durable_v2_enabled(&self) -> bool {
        self.durable_v2_enabled
    }

    fn client_guid(&self) -> Result<[u8; 16], ReconnectError> {
        if let Some(guid) = self.client_guid.get() {
            return Ok(*guid);
        }

        let guid = random_guid()?;
        let _ = self.client_guid.set(guid);
        self.client_guid
            .get()
            .copied()
            .ok_or(ReconnectError::RandomSource)
    }

    fn remember_or_validate_file(&self, file: &FileHandle) -> Result<(), ClientError> {
        let reopened = FileIdentity::from_file(file);

        if let Some(original) = self.identity.get() {
            return validate_file_identity(*original, reopened);
        }

        if self.identity.set(reopened).is_ok() {
            return Ok(());
        }

        let original = self.identity.get().ok_or(ClientError::Protocol(
            "SMB reconnect file identity initialization failed",
        ))?;
        validate_file_identity(*original, reopened)
    }
}

fn validate_file_identity(
    original: FileIdentity,
    reopened: FileIdentity,
) -> Result<(), ClientError> {
    if original.is_compatible_with(reopened) {
        Ok(())
    } else {
        Err(ClientError::Protocol(
            "SMB file changed while reconnecting by path",
        ))
    }
}

#[derive(Debug)]
pub enum ReconnectError {
    Client(ClientError),
    Cancelled,
    RandomSource,
}

impl fmt::Display for ReconnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "SMB reconnect client error: {error}"),
            Self::Cancelled => f.write_str("SMB reconnect cancelled"),
            Self::RandomSource => f.write_str("failed to obtain secure random bytes for reconnect"),
        }
    }
}

impl Error for ReconnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Cancelled | Self::RandomSource => None,
        }
    }
}

impl From<ClientError> for ReconnectError {
    fn from(value: ClientError) -> Self {
        Self::Client(value)
    }
}

pub fn is_retryable_client_error(error: &ClientError) -> bool {
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
        | ClientError::Capability(_)
        | ClientError::Protocol(_) => false,
    }
}

/// Establishes a fresh transport/session/tree and restores the configured read-only file.
///
/// With Durable V2 enabled, a remembered durable open is re-established with DH2C first. A stale
/// durable open may fall back only on the protocol-defined STATUS_OBJECT_NAME_NOT_FOUND outcome or
/// an explicitly unavailable capability. Malformed/security failures never fall through to a path
/// reopen.
pub async fn connect_read_only_file(
    recipe: &ReadOnlyReconnectRecipe,
) -> Result<(SessionConnection<TcpTransport>, FileHandle), ReconnectError> {
    let client_guid = recipe.client_guid()?;
    let mut preauth_salt = [0u8; 32];
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

    if recipe.durable_v2_enabled {
        let mut durable_state = recipe.durable.lock().await;

        if let Some(existing) = durable_state.handle.clone() {
            match session
                .reconnect_file_durable_v2(&tree, &existing)
                .await
            {
                Ok(refreshed) => {
                    let file = refreshed.file().clone();
                    if let Err(error) = recipe.remember_or_validate_file(&file) {
                        durable_state.handle = None;
                        let _ = session
                            .close_file(refreshed.into_file(), CloseOptions::default())
                            .await;
                        return Err(error.into());
                    }
                    durable_state.handle = Some(refreshed);
                    return Ok((session, file));
                }
                Err(ClientError::ServerStatus(STATUS_OBJECT_NAME_NOT_FOUND)) => {
                    // The server no longer has this durable Open, for example after an smbd
                    // restart. It is safe to create a new durable open, still guarded by identity.
                    durable_state.handle = None;
                }
                Err(ClientError::Capability(_)) => {
                    durable_state.handle = None;
                    durable_state.unavailable = true;
                }
                Err(error) => return Err(error.into()),
            }
        }

        if !durable_state.unavailable {
            let create_guid = random_guid()?;
            match session
                .open_file_durable_v2(
                    &tree,
                    &recipe.path,
                    FileOpenOptions::read_existing_random(),
                    create_guid,
                    DurableHandleV2Options::default(),
                )
                .await
            {
                Ok(opened) => {
                    let file = opened.file().clone();
                    if let Err(error) = recipe.remember_or_validate_file(&file) {
                        let _ = session
                            .close_file(opened.into_file(), CloseOptions::default())
                            .await;
                        return Err(error.into());
                    }
                    durable_state.handle = Some(opened);
                    return Ok((session, file));
                }
                Err(ClientError::Capability(_)) => {
                    durable_state.unavailable = true;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    let file = session
        .open_file(&tree, &recipe.path, FileOpenOptions::read_existing_random())
        .await?;
    recipe.remember_or_validate_file(&file)?;

    Ok((session, file))
}

/// Cancellation-aware form used by interactive consumers while a seek/close can invalidate work.
pub async fn connect_read_only_file_cancelable(
    recipe: &ReadOnlyReconnectRecipe,
    cancellation: &ReadCancellationToken,
    generation: u64,
) -> Result<(SessionConnection<TcpTransport>, FileHandle), ReconnectError> {
    tokio::select! {
        result = connect_read_only_file(recipe) => result,
        _ = cancellation.wait_for_change(generation) => Err(ReconnectError::Cancelled),
    }
}

fn random_guid() -> Result<[u8; 16], ReconnectError> {
    let mut guid = [0u8; 16];
    getrandom::fill(&mut guid).map_err(|_| ReconnectError::RandomSource)?;
    Ok(guid)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    fn recipe() -> ReadOnlyReconnectRecipe {
        ReadOnlyReconnectRecipe::new(
            "nas.local".to_string(),
            445,
            "video".to_string(),
            "movie.mkv".to_string(),
            "user".to_string(),
            "password".to_string(),
            String::new(),
            String::new(),
        )
    }

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
    fn security_protocol_and_capability_failures_are_never_retried_as_transport() {
        assert!(!is_retryable_client_error(&ClientError::Protocol(
            "bad frame"
        )));
        assert!(!is_retryable_client_error(&ClientError::Capability(
            "optional feature unavailable"
        )));
        assert!(!is_retryable_client_error(&ClientError::Cancelled));
        assert!(!is_retryable_client_error(&ClientError::ServerStatus(
            0xC000_0022,
        )));
    }

    #[test]
    fn durable_v2_recovery_is_explicitly_opt_in() {
        assert!(!recipe().durable_v2_enabled());
        assert!(recipe().with_durable_v2(true).durable_v2_enabled());
    }

    #[test]
    fn reconnect_identity_accepts_the_same_static_file() {
        let original = FileIdentity {
            len: 4_500_000_000,
            creation_time: 100,
            last_write_time: 200,
        };
        assert!(original.is_compatible_with(original));
    }

    #[test]
    fn reconnect_identity_rejects_replacement_or_mutation() {
        let original = FileIdentity {
            len: 1_000,
            creation_time: 100,
            last_write_time: 200,
        };
        assert!(!original.is_compatible_with(FileIdentity {
            len: 999,
            ..original
        }));
        assert!(!original.is_compatible_with(FileIdentity {
            creation_time: 101,
            ..original
        }));
        assert!(!original.is_compatible_with(FileIdentity {
            last_write_time: 201,
            ..original
        }));
    }

    #[test]
    fn reconnect_identity_treats_zero_timestamps_as_unknown() {
        let original = FileIdentity {
            len: 1_000,
            creation_time: 0,
            last_write_time: 200,
        };
        let reopened = FileIdentity {
            len: 1_000,
            creation_time: 123,
            last_write_time: 0,
        };
        assert!(original.is_compatible_with(reopened));
    }
}
