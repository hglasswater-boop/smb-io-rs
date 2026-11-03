use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    ClientError, CloseInfo, CloseOptions, Connection, FileHandle, FileOpenOptions, NegotiateConfig,
    QueryDirectoryOptions, ReadOnlyReconnectRecipe, ReadReconnectPolicy, ReconnectError,
    SessionConnection, SessionSetupConfig, TcpTransport, TcpTransportConfig, TreeConnectOptions,
    TreeHandle,
};
use smb_io_fs::{
    DirectoryMetadataEntry, FsMutationError, FsQueryError, decode_file_id_full_directory_metadata,
};
use smb_io_stream::{
    BrokerError, StreamError, VideoBrokerConfig, VideoBrokerHandle, VideoReaderConfig,
    recovering_video_broker_with_policy,
};
use tokio::runtime::{Builder, Runtime};

#[derive(Debug, Clone, Copy)]
pub struct AndroidEngineConfig {
    pub runtime_worker_threads: usize,
    pub max_read_bytes: usize,
    /// Number of transport reconnect attempts allowed after one retryable read failure.
    ///
    /// The original read is retried only once after a connection has been re-established, so a
    /// permanently failing server cannot trap the caller in an unbounded reconnect loop.
    pub read_reconnect_attempts: usize,
    /// Delay inserted before the second and later reconnect attempts.
    pub reconnect_backoff: Duration,
}

impl Default for AndroidEngineConfig {
    fn default() -> Self {
        Self {
            runtime_worker_threads: 2,
            max_read_bytes: 8 * 1024 * 1024,
            read_reconnect_attempts: 2,
            reconnect_backoff: Duration::from_millis(250),
        }
    }
}

/// Connection settings accepted by the Android boundary.
///
/// This type intentionally does not implement `Debug` or `Clone`: it contains a plaintext password
/// only until `open_video` moves it into a zeroizing reconnect recipe. Anonymous sessions ignore
/// the password field and XFiles passes it as empty.
pub struct VideoOpenRequest {
    pub host: String,
    pub port: u16,
    pub share: String,
    pub path: String,
    pub username: String,
    pub password: String,
    pub domain: String,
    pub workstation: String,
    pub stream: VideoReaderConfig,
}

impl VideoOpenRequest {
    pub fn new(
        host: impl Into<String>,
        share: impl Into<String>,
        path: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port: 445,
            share: share.into(),
            path: path.into(),
            username: username.into(),
            password: password.into(),
            domain: String::new(),
            workstation: String::new(),
            stream: VideoReaderConfig::default(),
        }
    }
}

#[derive(Debug)]
pub enum AndroidBridgeError {
    Runtime(std::io::Error),
    Client(ClientError),
    Fs(FsMutationError),
    Query(FsQueryError),
    Stream(StreamError),
    InvalidHandle(VideoHandle),
    InvalidConfig(&'static str),
    ReadTooLarge { requested: usize, maximum: usize },
    InternalState(&'static str),
    RandomSource,
}

impl fmt::Display for AndroidBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(f, "Android SMB runtime error: {error}"),
            Self::Client(error) => write!(f, "SMB client error: {error}"),
            Self::Fs(error) => write!(f, "SMB filesystem error: {error}"),
            Self::Query(error) => write!(f, "SMB directory query error: {error}"),
            Self::Stream(error) => write!(f, "SMB stream error: {error}"),
            Self::InvalidHandle(handle) => write!(f, "invalid SMB video handle {}", handle.raw()),
            Self::InvalidConfig(message) => {
                write!(f, "invalid Android SMB configuration: {message}")
            }
            Self::ReadTooLarge { requested, maximum } => write!(
                f,
                "Android SMB read request is too large: requested {requested} bytes, maximum {maximum}"
            ),
            Self::InternalState(message) => {
                write!(f, "Android SMB internal state error: {message}")
            }
            Self::RandomSource => f.write_str("failed to obtain secure random bytes"),
        }
    }
}

impl Error for AndroidBridgeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Client(error) => Some(error),
            Self::Fs(error) => Some(error),
            Self::Query(error) => Some(error),
            Self::Stream(error) => Some(error),
            Self::InvalidHandle(_)
            | Self::InvalidConfig(_)
            | Self::ReadTooLarge { .. }
            | Self::InternalState(_)
            | Self::RandomSource => None,
        }
    }
}

impl From<ClientError> for AndroidBridgeError {
    fn from(value: ClientError) -> Self {
        Self::Client(value)
    }
}

impl From<FsMutationError> for AndroidBridgeError {
    fn from(value: FsMutationError) -> Self {
        Self::Fs(value)
    }
}

impl From<FsQueryError> for AndroidBridgeError {
    fn from(value: FsQueryError) -> Self {
        Self::Query(value)
    }
}

impl From<StreamError> for AndroidBridgeError {
    fn from(value: StreamError) -> Self {
        Self::Stream(value)
    }
}

/// One-shot, non-retrying filesystem mutation request.
/// Credentials are moved into the NTLM provider when authentication begins.
pub struct SmbMutationRequest {
    pub host: String,
    pub port: u16,
    pub share: String,
    pub path: String,
    pub username: String,
    pub password: String,
    pub domain: String,
    pub workstation: String,
}

impl SmbMutationRequest {
    pub fn new(
        host: impl Into<String>,
        share: impl Into<String>,
        path: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port: 445,
            share: share.into(),
            path: path.into(),
            username: username.into(),
            password: password.into(),
            domain: String::new(),
            workstation: String::new(),
        }
    }
}

/// Stable opaque identifier intended to cross JNI as a `jlong`/Kotlin `Long`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VideoHandle(u64);

impl VideoHandle {
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

struct HandleTable<T> {
    next: AtomicU64,
    entries: Mutex<HashMap<VideoHandle, Arc<T>>>,
}

impl<T> HandleTable<T> {
    fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, value: T) -> Result<VideoHandle, AndroidBridgeError> {
        let mut entries = lock(&self.entries)?;
        let value = Arc::new(value);
        loop {
            let raw = self.next.fetch_add(1, Ordering::Relaxed);
            if raw == 0 {
                continue;
            }
            let handle = VideoHandle(raw);
            if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(handle) {
                slot.insert(value);
                return Ok(handle);
            }
        }
    }

    fn get(&self, handle: VideoHandle) -> Result<Arc<T>, AndroidBridgeError> {
        lock(&self.entries)?
            .get(&handle)
            .cloned()
            .ok_or(AndroidBridgeError::InvalidHandle(handle))
    }

    fn remove(&self, handle: VideoHandle) -> Result<Arc<T>, AndroidBridgeError> {
        lock(&self.entries)?
            .remove(&handle)
            .ok_or(AndroidBridgeError::InvalidHandle(handle))
    }

    #[cfg(test)]
    fn len(&self) -> Result<usize, AndroidBridgeError> {
        Ok(lock(&self.entries)?.len())
    }
}

enum FileMutation {
    Mkdir,
    Rename { destination: String },
    DeleteFile,
}

struct VideoSession {
    broker: VideoBrokerHandle,
}
/// Independent JNI handle type. The high bit below the sign bit keeps these handles distinct
/// from the low-range video handles, while retaining positive Java Long values.
const DIRECTORY_HANDLE_FLAG: u64 = 1u64 << 62;
const FILE_ID_FULL_DIRECTORY_INFORMATION_CLASS: u8 = 0x26;
const DIRECTORY_QUERY_BUFFER_BYTES: u32 = 65_535;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryHandle(u64);

impl DirectoryHandle {
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    fn table_key(self) -> Result<VideoHandle, AndroidBridgeError> {
        if self.0 & DIRECTORY_HANDLE_FLAG == 0 || self.0 == DIRECTORY_HANDLE_FLAG {
            return Err(AndroidBridgeError::InvalidConfig(
                "invalid directory handle",
            ));
        }
        Ok(VideoHandle::from_raw(self.0 & !DIRECTORY_HANDLE_FLAG))
    }
}

struct DirectorySession {
    session: SessionConnection<TcpTransport>,
    directory: FileHandle,
    exhausted: bool,
}

/// Long-lived runtime and opaque-handle owner for the Android/JNI adapter.
///
/// JNI functions remain mechanical wrappers around this type. SMB lifecycle, reconnect,
/// read-ahead, prefetch cancellation, and I/O priority scheduling live in the portable client and
/// stream crates.
pub struct AndroidEngine {
    runtime: Runtime,
    videos: HandleTable<VideoSession>,
    directories: HandleTable<Mutex<DirectorySession>>,
    max_read_bytes: usize,
    reconnect_policy: ReadReconnectPolicy,
}

impl AndroidEngine {
    pub fn new(config: AndroidEngineConfig) -> Result<Self, AndroidBridgeError> {
        if config.runtime_worker_threads == 0 {
            return Err(AndroidBridgeError::InvalidConfig(
                "runtime_worker_threads must be greater than zero",
            ));
        }
        if config.max_read_bytes == 0 {
            return Err(AndroidBridgeError::InvalidConfig(
                "max_read_bytes must be greater than zero",
            ));
        }
        let runtime = Builder::new_multi_thread()
            .worker_threads(config.runtime_worker_threads)
            .thread_name("smb-io")
            .enable_all()
            .build()
            .map_err(AndroidBridgeError::Runtime)?;
        Ok(Self {
            runtime,
            videos: HandleTable::new(),
            directories: HandleTable::new(),
            max_read_bytes: config.max_read_bytes,
            reconnect_policy: ReadReconnectPolicy {
                max_connect_attempts: config.read_reconnect_attempts,
                backoff: config.reconnect_backoff,
            },
        })
    }

    pub fn open_video(&self, request: VideoOpenRequest) -> Result<VideoHandle, AndroidBridgeError> {
        validate_open_request(&request)?;
        let VideoOpenRequest {
            host,
            port,
            share,
            path,
            username,
            password,
            domain,
            workstation,
            stream,
        } = request;

        let reconnect = ReadOnlyReconnectRecipe::new(
            host,
            port,
            share,
            path,
            username,
            password,
            domain,
            workstation,
        );
        let broker_config = VideoBrokerConfig {
            reader: stream,
            ..VideoBrokerConfig::default()
        };
        let (broker, runner) = self
            .runtime
            .block_on(recovering_video_broker_with_policy(
                reconnect,
                self.reconnect_policy,
                broker_config,
            ))
            .map_err(map_broker_error)?;

        let handle = self.videos.insert(VideoSession { broker })?;
        self.runtime.spawn(runner.run());
        Ok(handle)
    }

    pub fn len(&self, handle: VideoHandle) -> Result<u64, AndroidBridgeError> {
        let video = self.videos.get(handle)?;
        Ok(video.broker.len())
    }

    pub fn read_at(
        &self,
        handle: VideoHandle,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, AndroidBridgeError> {
        self.validate_read_length(length)?;
        let video = self.videos.get(handle)?;
        self.runtime
            .block_on(video.broker.read(offset, length))
            .map_err(map_broker_error)
    }

    /// Queues optional speculative I/O without waiting for the Tokio runtime. Any foreground
    /// `read_at`, seek, or close preempts it, and a full background queue drops the hint.
    pub fn prefetch(
        &self,
        handle: VideoHandle,
        offset: u64,
        length: usize,
    ) -> Result<(), AndroidBridgeError> {
        self.validate_read_length(length)?;
        let video = self.videos.get(handle)?;
        video
            .broker
            .prefetch(offset, length)
            .map_err(map_broker_error)
    }

    /// Advances the playback generation immediately without waiting for the broker runner.
    ///
    /// A concurrent foreground READ emits SMB2 CANCEL, while speculative prefetch/reconnect/backoff
    /// work is independently invalidated so a player seek does not wait behind background I/O.
    pub fn seek(&self, handle: VideoHandle) -> Result<u64, AndroidBridgeError> {
        let video = self.videos.get(handle)?;
        Ok(video.broker.seek())
    }

    pub fn close_video(&self, handle: VideoHandle) -> Result<CloseInfo, AndroidBridgeError> {
        let video = self.videos.remove(handle)?;
        self.runtime
            .block_on(video.broker.close())
            .map_err(map_broker_error)
    }

    /// Create one directory. A transport failure never triggers mutation replay.
    pub fn mkdir(&self, request: SmbMutationRequest) -> Result<(), AndroidBridgeError> {
        self.mutate(request, FileMutation::Mkdir)
    }

    /// Rename an existing entry inside the same share, without replacing an existing destination.
    pub fn rename(
        &self,
        request: SmbMutationRequest,
        destination: String,
    ) -> Result<(), AndroidBridgeError> {
        self.mutate(request, FileMutation::Rename { destination })
    }

    /// Delete one regular file only. Directory removal is a separate operation.
    pub fn delete_file(&self, request: SmbMutationRequest) -> Result<(), AndroidBridgeError> {
        self.mutate(request, FileMutation::DeleteFile)
    }

    /// One authenticated session per mutation. Do not repeat the operation if the server response
    /// is lost, because its outcome cannot safely be inferred from a transport error.
    fn mutate(
        &self,
        request: SmbMutationRequest,
        operation: FileMutation,
    ) -> Result<(), AndroidBridgeError> {
        validate_mutation_request(&request)?;
        if let FileMutation::Rename { ref destination } = operation {
            validate_mutation_path(destination)?;
        }

        self.runtime.block_on(async move {
            let (mut session, tree, path) = connect_share(request).await?;
            match operation {
                FileMutation::Mkdir => smb_io_fs::mkdir(&mut session, &tree, path).await?,
                FileMutation::Rename { destination } => {
                    smb_io_fs::rename(&mut session, &tree, path, destination, false).await?
                }
                FileMutation::DeleteFile => {
                    smb_io_fs::delete_file(&mut session, &tree, path).await?
                }
            }
            Ok(())
        })
    }

    /// Open one share-relative directory and retain the server's QUERY_DIRECTORY scan cursor.
    pub fn open_directory(
        &self,
        request: SmbMutationRequest,
    ) -> Result<DirectoryHandle, AndroidBridgeError> {
        validate_directory_request(&request)?;
        let session = self.runtime.block_on(async move {
            let (mut session, tree, path) = connect_share(request).await?;
            let directory = session
                .open_file(&tree, &path, FileOpenOptions::read_existing_directory())
                .await?;
            Ok::<_, AndroidBridgeError>(DirectorySession {
                session,
                directory,
                exhausted: false,
            })
        })?;
        let id = self.directories.insert(Mutex::new(session))?;
        Ok(DirectoryHandle(id.raw() | DIRECTORY_HANDLE_FLAG))
    }

    /// Return exactly one server QUERY_DIRECTORY page, or an XFL1 zero-count EOF page.
    /// Pages are independent of total folder size and never restart the remote scan.
    pub fn read_directory_page(
        &self,
        handle: DirectoryHandle,
    ) -> Result<Vec<u8>, AndroidBridgeError> {
        let entry = self.directories.get(handle.table_key()?)?;
        let mut state = lock(&entry)?;
        if state.exhausted {
            return encode_directory_metadata(&[]);
        }
        let DirectorySession {
            session,
            directory,
            exhausted,
        } = &mut *state;
        let options = QueryDirectoryOptions::new(
            FILE_ID_FULL_DIRECTORY_INFORMATION_CLASS,
            "*",
            DIRECTORY_QUERY_BUFFER_BYTES,
        );
        let buffer = self
            .runtime
            .block_on(session.query_directory(directory, options))?;
        if buffer.is_empty() {
            *exhausted = true;
            return encode_directory_metadata(&[]);
        }
        let entries = decode_file_id_full_directory_metadata(&buffer)?;
        encode_directory_metadata(&entries)
    }

    /// Remove the handle and close the SMB directory. A later read cannot resurrect its cursor.
    pub fn close_directory(&self, handle: DirectoryHandle) -> Result<(), AndroidBridgeError> {
        let entry = self.directories.remove(handle.table_key()?)?;
        let mut state = lock(&entry)?;
        let directory = state.directory.clone();
        self.runtime
            .block_on(state.session.close_file(directory, CloseOptions::default()))
            .map(|_| ())
            .map_err(AndroidBridgeError::from)
    }

    fn validate_read_length(&self, length: usize) -> Result<(), AndroidBridgeError> {
        if length > self.max_read_bytes {
            return Err(AndroidBridgeError::ReadTooLarge {
                requested: length,
                maximum: self.max_read_bytes,
            });
        }
        Ok(())
    }
}

fn map_broker_error(error: BrokerError) -> AndroidBridgeError {
    match error {
        BrokerError::Stream(StreamError::Reconnect(ReconnectError::RandomSource)) => {
            AndroidBridgeError::RandomSource
        }
        BrokerError::Stream(StreamError::Reconnect(ReconnectError::Cancelled))
        | BrokerError::StaleGeneration => cancelled_bridge_error(),
        BrokerError::Stream(error) => AndroidBridgeError::Stream(error),
        BrokerError::Closed => AndroidBridgeError::InternalState("video broker is closed"),
        BrokerError::InvalidConfig(message) => AndroidBridgeError::InvalidConfig(message),
    }
}

fn cancelled_bridge_error() -> AndroidBridgeError {
    AndroidBridgeError::Stream(StreamError::Client(ClientError::Cancelled))
}

const MAX_DIRECTORY_RESULT_BYTES: usize = 16 * 1024 * 1024;

/// Build one complete, versioned little-endian payload or fail; never return truncated entries.
fn encode_directory_metadata(
    entries: &[DirectoryMetadataEntry],
) -> Result<Vec<u8>, AndroidBridgeError> {
    let count = u32::try_from(entries.len())
        .map_err(|_| AndroidBridgeError::InvalidConfig("directory entry count exceeds u32"))?;
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(b"XFL1");
    bytes.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        let name = entry.name.as_bytes();
        let name_length = u32::try_from(name.len())
            .map_err(|_| AndroidBridgeError::InvalidConfig("directory name too long"))?;
        let required = 4usize
            .checked_add(name.len())
            .and_then(|size| size.checked_add(28))
            .and_then(|size| size.checked_add(bytes.len()))
            .ok_or(AndroidBridgeError::InvalidConfig(
                "directory listing length overflow",
            ))?;
        if required > MAX_DIRECTORY_RESULT_BYTES {
            return Err(AndroidBridgeError::InvalidConfig(
                "directory listing exceeds maximum JNI payload",
            ));
        }
        bytes.extend_from_slice(&name_length.to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&entry.file_attributes.to_le_bytes());
        bytes.extend_from_slice(&entry.end_of_file.to_le_bytes());
        bytes.extend_from_slice(&entry.creation_time.to_le_bytes());
        bytes.extend_from_slice(&entry.last_write_time.to_le_bytes());
    }
    Ok(bytes)
}

/// A read-only query may address the share root with an empty path.
fn validate_directory_request(request: &SmbMutationRequest) -> Result<(), AndroidBridgeError> {
    if request.path.is_empty() {
        let mut root = SmbMutationRequest::new(&request.host, &request.share, "root", "", "");
        root.port = request.port;
        return validate_mutation_request(&root);
    }
    validate_mutation_request(request)
}

/// Shared signed/authenticated SMB session for the one-shot mutations and directory queries.
async fn connect_share(
    request: SmbMutationRequest,
) -> Result<(SessionConnection<TcpTransport>, TreeHandle, String), AndroidBridgeError> {
    let SmbMutationRequest {
        host,
        port,
        share,
        path,
        username,
        password,
        domain,
        workstation,
    } = request;
    let mut client_guid = [0u8; 16];
    let mut preauth_salt = [0u8; 32];
    getrandom::fill(&mut client_guid).map_err(|_| AndroidBridgeError::RandomSource)?;
    getrandom::fill(&mut preauth_salt).map_err(|_| AndroidBridgeError::RandomSource)?;

    let transport = TcpTransport::connect(&host, port, TcpTransportConfig::default()).await?;
    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig::modern(client_guid, preauth_salt.to_vec()))
        .await?;

    let mut session = if username.is_empty() {
        let mut auth = AnonymousNtlmProvider::new();
        connection
            .session_setup(&mut auth, SessionSetupConfig::default())
            .await?
    } else {
        let mut credentials = NtlmCredentials::new(username, password);
        if !domain.is_empty() {
            credentials = credentials.with_domain(domain);
        }
        if !workstation.is_empty() {
            credentials = credentials.with_workstation(workstation);
        }
        let mut auth = NtlmV2Provider::new(credentials);
        connection
            .session_setup(&mut auth, SessionSetupConfig::default())
            .await?
    };

    let tree = session
        .tree_connect(
            format!(r"\\{}\{}", host, share),
            TreeConnectOptions::default(),
        )
        .await?;
    Ok((session, tree, path))
}

fn validate_mutation_request(request: &SmbMutationRequest) -> Result<(), AndroidBridgeError> {
    if request.host.is_empty() || request.host.contains(['\\', '/', '\0']) {
        return Err(AndroidBridgeError::InvalidConfig(
            "host must be a non-empty DNS name or IP address",
        ));
    }
    if request.port == 0 {
        return Err(AndroidBridgeError::InvalidConfig(
            "port must be greater than zero",
        ));
    }
    if request.share.is_empty() || request.share.contains(['\\', '/', '\0']) {
        return Err(AndroidBridgeError::InvalidConfig(
            "share must be a single non-empty share name",
        ));
    }
    validate_mutation_path(&request.path)
}

fn validate_mutation_path(path: &str) -> Result<(), AndroidBridgeError> {
    if path.is_empty()
        || path.starts_with('\\')
        || path.starts_with('/')
        || path.contains('\0')
        || path
            .replace('\\', "/")
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return Err(AndroidBridgeError::InvalidConfig(
            "mutation path must be share-relative, non-empty, and contain no dot components or NUL",
        ));
    }
    Ok(())
}

fn validate_open_request(request: &VideoOpenRequest) -> Result<(), AndroidBridgeError> {
    if request.host.is_empty() || request.host.contains(['\\', '/', '\0']) {
        return Err(AndroidBridgeError::InvalidConfig(
            "host must be a non-empty DNS name or IP address",
        ));
    }
    if request.port == 0 {
        return Err(AndroidBridgeError::InvalidConfig(
            "port must be greater than zero",
        ));
    }
    if request.share.is_empty() || request.share.contains(['\\', '/', '\0']) {
        return Err(AndroidBridgeError::InvalidConfig(
            "share must be a single non-empty share name",
        ));
    }
    if request.path.is_empty() {
        return Err(AndroidBridgeError::InvalidConfig("path must not be empty"));
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, AndroidBridgeError> {
    mutex
        .lock()
        .map_err(|_| AndroidBridgeError::InternalState("mutex poisoned"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_handle_table_never_reuses_live_handle() {
        let table = HandleTable::new();
        let first = table.insert("first").unwrap();
        let second = table.insert("second").unwrap();
        assert_ne!(first, second);
        assert_eq!(&*table.get(first).unwrap(), &"first");
        assert_eq!(&*table.get(second).unwrap(), &"second");
        assert_eq!(table.len().unwrap(), 2);
        assert_eq!(&*table.remove(first).unwrap(), &"first");
        assert_eq!(table.len().unwrap(), 1);
        assert!(matches!(
            table.get(first),
            Err(AndroidBridgeError::InvalidHandle(handle)) if handle == first
        ));
    }

    #[test]
    fn invalid_engine_limits_are_rejected() {
        assert!(
            AndroidEngine::new(AndroidEngineConfig {
                runtime_worker_threads: 0,
                ..AndroidEngineConfig::default()
            })
            .is_err()
        );
        assert!(
            AndroidEngine::new(AndroidEngineConfig {
                max_read_bytes: 0,
                ..AndroidEngineConfig::default()
            })
            .is_err()
        );
    }

    #[test]
    fn reconnect_policy_defaults_to_one_recovery_episode_with_two_connect_attempts() {
        let config = AndroidEngineConfig::default();
        assert_eq!(config.read_reconnect_attempts, 2);
        assert_eq!(config.reconnect_backoff, Duration::from_millis(250));

        let engine = AndroidEngine::new(config).unwrap();
        assert_eq!(
            engine.reconnect_policy,
            ReadReconnectPolicy {
                max_connect_attempts: 2,
                backoff: Duration::from_millis(250),
            }
        );
    }

    #[test]
    fn zero_reconnect_attempts_disable_automatic_recovery() {
        let engine = AndroidEngine::new(AndroidEngineConfig {
            read_reconnect_attempts: 0,
            ..AndroidEngineConfig::default()
        })
        .unwrap();
        assert_eq!(engine.reconnect_policy.max_connect_attempts, 0);
    }

    #[test]
    fn stale_broker_generation_maps_to_cancellation() {
        assert!(matches!(
            map_broker_error(BrokerError::StaleGeneration),
            AndroidBridgeError::Stream(StreamError::Client(ClientError::Cancelled))
        ));
    }

    #[test]
    fn open_request_validation_rejects_unc_share_input() {
        let request = VideoOpenRequest::new(
            "nas.local",
            "\\\\nas.local\\video",
            "movies/sample.mkv",
            "user",
            "password",
        );
        assert!(validate_open_request(&request).is_err());
    }

    #[test]
    fn open_request_validation_accepts_blank_username_for_anonymous() {
        let request = VideoOpenRequest::new("nas.local", "video", "movies/sample.mkv", "", "");
        assert!(validate_open_request(&request).is_ok());
    }
    #[test]
    fn mkdir_contract_requires_new_jni_generation() {
        assert_eq!(crate::API_VERSION, 6);
    }

    #[test]
    fn mkdir_contract_rejects_unsafe_paths_before_connect() {
        for path in [
            "",
            "/absolute",
            r"\absolute",
            "../escape",
            "./name",
            "parent/../name",
            r"dir\..\name",
            "bad\0name",
        ] {
            let request = SmbMutationRequest::new("nas.local", "media", path, "user", "password");
            assert!(
                validate_mutation_request(&request).is_err(),
                "accepted invalid path: {path:?}"
            );
        }
    }

    #[test]
    fn mkdir_contract_validates_connection_and_accepts_unicode_relative_path() {
        let mut request =
            SmbMutationRequest::new("nas.local", "media", "folder/日本語", "user", "password");
        assert!(validate_mutation_request(&request).is_ok());
        request.port = 0;
        assert!(validate_mutation_request(&request).is_err());
        request.port = 445;
        request.share = "media/other".to_string();
        assert!(validate_mutation_request(&request).is_err());
    }
    #[test]
    fn rename_rejects_unsafe_destination_before_any_network_activity() {
        let engine = AndroidEngine::new(AndroidEngineConfig::default()).unwrap();
        for destination in [
            "",
            "/absolute",
            r"\absolute",
            "..",
            "dir/../escape",
            "dir/./name",
            "null\0byte",
        ] {
            let request =
                SmbMutationRequest::new("nas.local", "media", "good/source.txt", "user", "secret");
            assert!(
                matches!(
                    engine.rename(request, destination.to_owned()),
                    Err(AndroidBridgeError::InvalidConfig(_))
                ),
                "unsafe destination passed validation: {destination:?}"
            );
        }
    }

    #[test]
    fn delete_file_rejects_unsafe_source_before_any_network_activity() {
        let engine = AndroidEngine::new(AndroidEngineConfig::default()).unwrap();
        for path in [
            "",
            "../escape",
            "parent/../../outside",
            "/absolute",
            "bad\0name",
        ] {
            let request = SmbMutationRequest::new("nas.local", "media", path, "", "");
            assert!(
                matches!(
                    engine.delete_file(request),
                    Err(AndroidBridgeError::InvalidConfig(_))
                ),
                "unsafe file delete path passed validation: {path:?}"
            );
        }
    }

    #[test]
    fn create_file_rejects_unsafe_input_before_tcp() {
        let engine = AndroidEngine::new(AndroidEngineConfig::default()).unwrap();
        for path in ["", "/absolute", r"\absolute", "../escape", "dot/./name", "null\0name"] {
            let request = SmbMutationRequest::new("no-such-host.invalid", "media", path, "user", "secret");
            assert!(
                matches!(
                    engine.create_file(request),
                    Err(AndroidBridgeError::InvalidConfig(_))
                ),
                "unsafe create_file path accepted: {path:?}"
            );
        }
    }

    #[test]
    fn mutation_path_accepts_share_relative_unicode_without_rewriting_names() {
        assert!(validate_mutation_path("root/サンプル/実験.mkv").is_ok());
        assert!(validate_mutation_path(r"root\ファイル.txt").is_ok());
        assert!(validate_mutation_path("valid-name.txt").is_ok());
    }
    #[test]
    fn directory_query_rejects_unsafe_paths_without_network_access() {
        let engine = AndroidEngine::new(AndroidEngineConfig::default()).unwrap();
        for path in [
            "/absolute",
            r"\absolute",
            "../parent",
            "./dot",
            r"foo\..\bar",
            "nul\0name",
        ] {
            let request = SmbMutationRequest::new("no-such-host.invalid", "files", path, "", "");
            assert!(
                matches!(
                    engine.open_directory(request),
                    Err(AndroidBridgeError::InvalidConfig(_))
                ),
                "accepted unsafe directory path: {path:?}"
            );
        }
    }

    #[test]
    fn directory_root_is_valid_and_unicode_relative_paths_are_unchanged() {
        let root = SmbMutationRequest::new("nas.local", "files", "", "", "");
        assert!(validate_directory_request(&root).is_ok());
        let unicode = SmbMutationRequest::new("nas.local", "files", "root/映画", "user", "secret");
        assert!(validate_directory_request(&unicode).is_ok());
    }

    #[test]
    fn directory_binary_contract_encodes_unicode_name_and_metadata() {
        let entry = smb_io_fs::DirectoryMetadataEntry {
            file_index: 3,
            name: "映画\t一.mkv".to_string(),
            file_attributes: 0x22,
            end_of_file: 123,
            allocation_size: 4096,
            creation_time: 133_000_000_000_000_000,
            last_write_time: 133_001_000_000_000_000,
        };
        let bytes = encode_directory_metadata(&[entry]).unwrap();
        assert_eq!(&bytes[0..4], b"XFL1");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        assert_eq!(&bytes[12..12 + length], "映画\t一.mkv".as_bytes());
        let pos = 12 + length;
        assert_eq!(
            u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()),
            0x22
        );
        assert_eq!(
            u64::from_le_bytes(bytes[pos + 4..pos + 12].try_into().unwrap()),
            123
        );
        assert_eq!(
            u64::from_le_bytes(bytes[pos + 12..pos + 20].try_into().unwrap()),
            133_000_000_000_000_000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[pos + 20..pos + 28].try_into().unwrap()),
            133_001_000_000_000_000
        );
        assert_eq!(bytes.len(), pos + 28);
    }

    #[test]
    fn directory_cursor_handle_contract_is_independent_from_video_handles() {
        // A live directory session keeps its SMB cursor across repeated read calls.
        // The native API no longer returns one giant ByteArray for a whole folder.
        let _open: fn(
            &AndroidEngine,
            SmbMutationRequest,
        ) -> Result<DirectoryHandle, AndroidBridgeError> = AndroidEngine::open_directory;
        let _next: fn(&AndroidEngine, DirectoryHandle) -> Result<Vec<u8>, AndroidBridgeError> =
            AndroidEngine::read_directory_page;
        let _close: fn(&AndroidEngine, DirectoryHandle) -> Result<(), AndroidBridgeError> =
            AndroidEngine::close_directory;
    }

    #[test]
    fn directory_eof_page_is_distinct_from_any_nonempty_data_page() {
        assert_eq!(encode_directory_metadata(&[]).unwrap(), b"XFL1\0\0\0\0");
        let entry = smb_io_fs::DirectoryMetadataEntry {
            file_index: 0,
            name: "item".to_owned(),
            file_attributes: 0,
            end_of_file: 0,
            allocation_size: 0,
            creation_time: 0,
            last_write_time: 0,
        };
        assert_ne!(
            encode_directory_metadata(&[entry]).unwrap(),
            b"XFL1\0\0\0\0"
        );
    }

    #[test]
    fn directory_binary_contract_reports_empty_directory_with_header() {
        assert_eq!(encode_directory_metadata(&[]).unwrap(), b"XFL1\0\0\0\0");
    }

    #[test]
    fn directory_binary_contract_rejects_oversized_single_page() {
        let entry = smb_io_fs::DirectoryMetadataEntry {
            file_index: 0,
            name: "a".repeat(MAX_DIRECTORY_RESULT_BYTES),
            file_attributes: 0,
            end_of_file: 0,
            allocation_size: 0,
            creation_time: 0,
            last_write_time: 0,
        };
        assert!(encode_directory_metadata(&[entry]).is_err());
    }
}
