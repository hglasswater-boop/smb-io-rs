use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use smb_io_auth::{NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    ClientError, CloseInfo, CloseOptions, Connection, FileHandle, FileOpenOptions, NegotiateConfig,
    ReadCancellationToken, SessionConnection, SessionSetupConfig, TcpTransport, TcpTransportConfig,
    TreeConnectOptions,
};
use smb_io_stream::{StreamError, VideoReader, VideoReaderConfig};
use tokio::runtime::{Builder, Runtime};

#[derive(Debug, Clone, Copy)]
pub struct AndroidEngineConfig {
    pub runtime_worker_threads: usize,
    pub max_read_bytes: usize,
}

impl Default for AndroidEngineConfig {
    fn default() -> Self {
        Self {
            runtime_worker_threads: 2,
            max_read_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Connection settings accepted by the Android boundary.
///
/// This type intentionally does not implement `Debug` or `Clone`: it contains a plaintext password
/// only long enough to construct the core `NtlmCredentials`, which immediately takes ownership of
/// it and zeroizes the password allocation on drop.
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

impl From<StreamError> for AndroidBridgeError {
    fn from(value: StreamError) -> Self {
        Self::Stream(value)
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

struct VideoState {
    session: SessionConnection<TcpTransport>,
    file: Option<FileHandle>,
    reader: VideoReader,
}

struct VideoSession {
    cancellation: ReadCancellationToken,
    state: Mutex<VideoState>,
}

/// Long-lived runtime and opaque-handle owner for the Android/JNI adapter.
///
/// JNI functions should remain mechanical wrappers around this type. No SMB packet logic belongs
/// in those functions.
pub struct AndroidEngine {
    runtime: Runtime,
    videos: HandleTable<VideoSession>,
    max_read_bytes: usize,
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
            max_read_bytes: config.max_read_bytes,
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

        let reader = VideoReader::new(stream)?;
        let mut client_guid = [0u8; 16];
        let mut preauth_salt = [0u8; 32];
        getrandom::fill(&mut client_guid).map_err(|_| AndroidBridgeError::RandomSource)?;
        getrandom::fill(&mut preauth_salt).map_err(|_| AndroidBridgeError::RandomSource)?;
        let unc_share = format!("\\\\{host}\\{share}");

        let (session, file) = self.runtime.block_on(async move {
            let transport =
                TcpTransport::connect(&host, port, TcpTransportConfig::default()).await?;
            let mut connection = Connection::new(transport);
            connection
                .negotiate(&NegotiateConfig::modern(client_guid, preauth_salt.to_vec()))
                .await?;

            let mut credentials = NtlmCredentials::new(username, password);
            if !domain.is_empty() {
                credentials = credentials.with_domain(domain);
            }
            if !workstation.is_empty() {
                credentials = credentials.with_workstation(workstation);
            }
            let mut auth = NtlmV2Provider::new(credentials);
            let mut session = connection
                .session_setup(&mut auth, SessionSetupConfig::default())
                .await?;
            let tree = session
                .tree_connect(unc_share, TreeConnectOptions::default())
                .await?;
            let file = session
                .open_file(&tree, path, FileOpenOptions::read_existing_random())
                .await?;
            Ok::<_, ClientError>((session, file))
        })?;

        self.videos.insert(VideoSession {
            cancellation: ReadCancellationToken::new(),
            state: Mutex::new(VideoState {
                session,
                file: Some(file),
                reader,
            }),
        })
    }

    pub fn len(&self, handle: VideoHandle) -> Result<u64, AndroidBridgeError> {
        let video = self.videos.get(handle)?;
        let state = lock(&video.state)?;
        Ok(state
            .file
            .as_ref()
            .ok_or(AndroidBridgeError::InternalState("video handle is closed"))?
            .len())
    }

    pub fn read_at(
        &self,
        handle: VideoHandle,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, AndroidBridgeError> {
        if length > self.max_read_bytes {
            return Err(AndroidBridgeError::ReadTooLarge {
                requested: length,
                maximum: self.max_read_bytes,
            });
        }
        let video = self.videos.get(handle)?;
        let generation = video.cancellation.generation();
        let mut state = lock(&video.state)?;
        let VideoState {
            session,
            file,
            reader,
        } = &mut *state;
        let file = file
            .as_ref()
            .ok_or(AndroidBridgeError::InternalState("video handle is closed"))?;
        self.runtime
            .block_on(reader.read_cancelable(
                session,
                file,
                offset,
                length,
                &video.cancellation,
                generation,
            ))
            .map_err(AndroidBridgeError::Stream)
    }

    /// Advances the generation immediately without taking the session I/O mutex.
    ///
    /// A concurrent `read_at` can therefore send SMB2 CANCEL while this method returns promptly to
    /// a player thread.
    pub fn seek(&self, handle: VideoHandle) -> Result<u64, AndroidBridgeError> {
        let video = self.videos.get(handle)?;
        Ok(video.cancellation.advance())
    }

    pub fn close_video(&self, handle: VideoHandle) -> Result<CloseInfo, AndroidBridgeError> {
        let video = self.videos.remove(handle)?;
        video.cancellation.advance();
        let mut state = lock(&video.state)?;
        let file = state.file.take().ok_or(AndroidBridgeError::InternalState(
            "video handle is already closed",
        ))?;
        self.runtime
            .block_on(state.session.close_file(file, CloseOptions::default()))
            .map_err(AndroidBridgeError::Client)
    }
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
    if request.username.is_empty() {
        return Err(AndroidBridgeError::InvalidConfig(
            "username must not be empty for NTLMv2 authentication",
        ));
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
}
