use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use smb_io_client::{
    ClientError, CloseInfo, ReadOnlyReconnectRecipe, ReadReconnectPolicy, ReconnectError,
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

struct VideoSession {
    broker: VideoBrokerHandle,
}

/// Long-lived runtime and opaque-handle owner for the Android/JNI adapter.
///
/// JNI functions remain mechanical wrappers around this type. SMB lifecycle, reconnect,
/// read-ahead, prefetch cancellation, and I/O priority scheduling live in the portable client and
/// stream crates.
pub struct AndroidEngine {
    runtime: Runtime,
    videos: HandleTable<VideoSession>,
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
        video.broker.prefetch(offset, length).map_err(map_broker_error)
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
}
