use std::error::Error;
use std::fmt;

use smb_io_client::{
    ClientError, FileHandle, PipelinedReadOptions, ReadCancellationToken, ReconnectError,
    RecoveringReadOnlyFile, SessionConnection, Transport,
};

#[derive(Debug, Clone, Copy)]
pub struct VideoReaderConfig {
    /// Amount of data fetched on a cache miss even if the caller asks for less.
    pub read_ahead_bytes: usize,
    /// Maximum bytes retained in the single contiguous cache window.
    pub max_cache_bytes: usize,
    /// SMB request sizing and in-flight depth used to fill the window.
    pub pipeline: PipelinedReadOptions,
}

impl Default for VideoReaderConfig {
    fn default() -> Self {
        Self {
            read_ahead_bytes: 2 * 1024 * 1024,
            max_cache_bytes: 8 * 1024 * 1024,
            pipeline: PipelinedReadOptions::default(),
        }
    }
}

#[derive(Debug)]
pub enum StreamError {
    Client(ClientError),
    Reconnect(ReconnectError),
    InvalidConfig(&'static str),
    OffsetOverflow,
}

impl StreamError {
    pub fn is_cancelled(&self) -> bool {
        matches!(
            self,
            Self::Client(ClientError::Cancelled) | Self::Reconnect(ReconnectError::Cancelled)
        )
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "SMB client error: {error}"),
            Self::Reconnect(error) => write!(f, "SMB reconnect error: {error}"),
            Self::InvalidConfig(message) => write!(f, "invalid stream configuration: {message}"),
            Self::OffsetOverflow => f.write_str("stream offset overflow"),
        }
    }
}

impl Error for StreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::Reconnect(error) => Some(error),
            Self::InvalidConfig(_) | Self::OffsetOverflow => None,
        }
    }
}

impl From<ClientError> for StreamError {
    fn from(value: ClientError) -> Self {
        Self::Client(value)
    }
}

impl From<ReconnectError> for StreamError {
    fn from(value: ReconnectError) -> Self {
        Self::Reconnect(value)
    }
}

#[derive(Debug, Clone)]
struct CachedWindow {
    generation: u64,
    start: u64,
    data: Vec<u8>,
}

impl CachedWindow {
    fn end(&self) -> Result<u64, StreamError> {
        self.start
            .checked_add(u64::try_from(self.data.len()).map_err(|_| StreamError::OffsetOverflow)?)
            .ok_or(StreamError::OffsetOverflow)
    }

    fn contains(&self, offset: u64, length: usize) -> Result<bool, StreamError> {
        let requested_end = request_end(offset, length)?;
        Ok(offset >= self.start && requested_end <= self.end()?)
    }

    fn slice(&self, offset: u64, length: usize) -> Result<Option<Vec<u8>>, StreamError> {
        if !self.contains(offset, length)? {
            return Ok(None);
        }
        let relative =
            usize::try_from(offset - self.start).map_err(|_| StreamError::OffsetOverflow)?;
        let end = relative
            .checked_add(length)
            .ok_or(StreamError::OffsetOverflow)?;
        Ok(Some(self.data[relative..end].to_vec()))
    }
}

#[derive(Debug)]
enum PreparedRead {
    Empty,
    Cached(Vec<u8>),
    Fetch {
        target: usize,
        fetch_len: usize,
        reader_generation: u64,
    },
}

/// Stateful video-oriented reader layered on positional SMB reads.
///
/// It keeps one bounded contiguous read-ahead window. Sequential requests are normally served from
/// that window without touching the network. A seek invalidates the window and increments a
/// generation token so future background-prefetch work can discard stale results safely.
#[derive(Debug)]
pub struct VideoReader {
    config: VideoReaderConfig,
    generation: u64,
    last_request_end: Option<u64>,
    cache: Option<CachedWindow>,
}

impl VideoReader {
    pub fn new(config: VideoReaderConfig) -> Result<Self, StreamError> {
        validate_config(config)?;
        Ok(Self {
            config,
            generation: 0,
            last_request_end: None,
            cache: None,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_current_generation(&self, generation: u64) -> bool {
        self.generation == generation
    }

    pub fn cached_bytes(&self) -> usize {
        self.cache.as_ref().map_or(0, |cache| cache.data.len())
    }

    pub fn cached_range(&self) -> Result<Option<(u64, u64)>, StreamError> {
        self.cache
            .as_ref()
            .map(|cache| Ok((cache.start, cache.end()?)))
            .transpose()
    }

    /// Explicitly moves the logical playback head and invalidates stale read-ahead data.
    pub fn seek(&mut self, offset: u64) -> u64 {
        self.bump_generation();
        self.cache = None;
        self.last_request_end = Some(offset);
        self.generation
    }

    pub fn invalidate(&mut self) -> u64 {
        self.bump_generation();
        self.cache = None;
        self.last_request_end = None;
        self.generation
    }

    pub async fn read<T>(
        &mut self,
        session: &mut SessionConnection<T>,
        file: &FileHandle,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, StreamError>
    where
        T: Transport,
    {
        self.read_impl(session, file, offset, length, None).await
    }

    pub async fn read_cancelable<T>(
        &mut self,
        session: &mut SessionConnection<T>,
        file: &FileHandle,
        offset: u64,
        length: usize,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<Vec<u8>, StreamError>
    where
        T: Transport,
    {
        self.read_impl(
            session,
            file,
            offset,
            length,
            Some((cancellation, generation)),
        )
        .await
    }

    /// Reads through a reconnecting read-only file while preserving the same cache/read-ahead
    /// behavior as `read`.
    pub async fn read_recovering(
        &mut self,
        source: &mut RecoveringReadOnlyFile,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, StreamError> {
        self.read_recovering_impl(source, offset, length, None)
            .await
    }

    /// Cancellation-aware reconnecting read. A seek generation change cancels both outstanding SMB
    /// requests and any reconnect attempt before stale data can enter the cache.
    pub async fn read_recovering_cancelable(
        &mut self,
        source: &mut RecoveringReadOnlyFile,
        offset: u64,
        length: usize,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<Vec<u8>, StreamError> {
        self.read_recovering_impl(source, offset, length, Some((cancellation, generation)))
            .await
    }

    async fn read_impl<T>(
        &mut self,
        session: &mut SessionConnection<T>,
        file: &FileHandle,
        offset: u64,
        length: usize,
        cancellation: Option<(&ReadCancellationToken, u64)>,
    ) -> Result<Vec<u8>, StreamError>
    where
        T: Transport,
    {
        let (target, fetch_len, reader_generation) =
            match self.prepare_read(file.len(), offset, length, cancellation)? {
                PreparedRead::Empty => return Ok(Vec::new()),
                PreparedRead::Cached(data) => return Ok(data),
                PreparedRead::Fetch {
                    target,
                    fetch_len,
                    reader_generation,
                } => (target, fetch_len, reader_generation),
            };

        let fetched = if let Some((token, generation)) = cancellation {
            session
                .read_at_pipelined_cancelable_with_options(
                    file,
                    offset,
                    fetch_len,
                    self.config.pipeline,
                    token,
                    generation,
                )
                .await?
        } else {
            session
                .read_at_pipelined_with_options(file, offset, fetch_len, self.config.pipeline)
                .await?
        };

        self.finish_fetch(offset, target, reader_generation, fetched, cancellation)
    }

    async fn read_recovering_impl(
        &mut self,
        source: &mut RecoveringReadOnlyFile,
        offset: u64,
        length: usize,
        cancellation: Option<(&ReadCancellationToken, u64)>,
    ) -> Result<Vec<u8>, StreamError> {
        let (target, fetch_len, reader_generation) =
            match self.prepare_read(source.len(), offset, length, cancellation)? {
                PreparedRead::Empty => return Ok(Vec::new()),
                PreparedRead::Cached(data) => return Ok(data),
                PreparedRead::Fetch {
                    target,
                    fetch_len,
                    reader_generation,
                } => (target, fetch_len, reader_generation),
            };

        let fetched = if let Some((token, generation)) = cancellation {
            source
                .read_at_pipelined_cancelable_with_options(
                    offset,
                    fetch_len,
                    self.config.pipeline,
                    token,
                    generation,
                )
                .await?
        } else {
            source
                .read_at_pipelined_with_options(offset, fetch_len, self.config.pipeline)
                .await?
        };

        self.finish_fetch(offset, target, reader_generation, fetched, cancellation)
    }

    fn prepare_read(
        &mut self,
        file_len: u64,
        offset: u64,
        length: usize,
        cancellation: Option<(&ReadCancellationToken, u64)>,
    ) -> Result<PreparedRead, StreamError> {
        ensure_not_cancelled(cancellation)?;
        if length == 0 || offset >= file_len {
            return Ok(PreparedRead::Empty);
        }

        let target = target_len(file_len, offset, length)?;
        if let Some(cache) = self.cache.as_ref() {
            if cache.generation == self.generation {
                if let Some(data) = cache.slice(offset, target)? {
                    ensure_not_cancelled(cancellation)?;
                    self.last_request_end = Some(request_end(offset, data.len())?);
                    return Ok(PreparedRead::Cached(data));
                }
            }
        }

        if self.is_seek_miss(offset)? {
            self.bump_generation();
            self.cache = None;
        }

        let remaining = usize::try_from(file_len - offset).unwrap_or(usize::MAX);
        let fetch_len = if target > self.config.max_cache_bytes {
            target
        } else {
            target
                .max(self.config.read_ahead_bytes)
                .min(self.config.max_cache_bytes)
                .min(remaining)
        };

        Ok(PreparedRead::Fetch {
            target,
            fetch_len,
            reader_generation: self.generation,
        })
    }

    fn finish_fetch(
        &mut self,
        offset: u64,
        target: usize,
        reader_generation: u64,
        fetched: Vec<u8>,
        cancellation: Option<(&ReadCancellationToken, u64)>,
    ) -> Result<Vec<u8>, StreamError> {
        ensure_not_cancelled(cancellation)?;
        if reader_generation != self.generation {
            return Ok(Vec::new());
        }

        let returned_len = target.min(fetched.len());
        let result = fetched[..returned_len].to_vec();
        self.last_request_end = Some(request_end(offset, returned_len)?);

        if fetched.len() <= self.config.max_cache_bytes {
            self.cache = Some(CachedWindow {
                generation: reader_generation,
                start: offset,
                data: fetched,
            });
        } else {
            self.cache = None;
        }

        Ok(result)
    }

    fn is_seek_miss(&self, offset: u64) -> Result<bool, StreamError> {
        let Some(last_end) = self.last_request_end else {
            return Ok(false);
        };
        if offset == last_end {
            return Ok(false);
        }
        if let Some(cache) = self.cache.as_ref() {
            if cache.generation == self.generation {
                let cache_end = cache.end()?;
                if offset >= cache.start && offset <= cache_end {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
}

fn ensure_not_cancelled(
    cancellation: Option<(&ReadCancellationToken, u64)>,
) -> Result<(), StreamError> {
    if let Some((token, generation)) = cancellation {
        if !token.is_current(generation) {
            return Err(StreamError::Client(ClientError::Cancelled));
        }
    }
    Ok(())
}

fn validate_config(config: VideoReaderConfig) -> Result<(), StreamError> {
    if config.read_ahead_bytes == 0 {
        return Err(StreamError::InvalidConfig(
            "read_ahead_bytes must be greater than zero",
        ));
    }
    if config.max_cache_bytes == 0 {
        return Err(StreamError::InvalidConfig(
            "max_cache_bytes must be greater than zero",
        ));
    }
    if config.pipeline.chunk_size == 0 {
        return Err(StreamError::InvalidConfig(
            "pipeline chunk_size must be greater than zero",
        ));
    }
    if config.pipeline.max_in_flight == 0 {
        return Err(StreamError::InvalidConfig(
            "pipeline max_in_flight must be greater than zero",
        ));
    }
    Ok(())
}

fn request_end(offset: u64, length: usize) -> Result<u64, StreamError> {
    offset
        .checked_add(u64::try_from(length).map_err(|_| StreamError::OffsetOverflow)?)
        .ok_or(StreamError::OffsetOverflow)
}

fn target_len(file_len: u64, offset: u64, length: usize) -> Result<usize, StreamError> {
    let requested = u64::try_from(length).map_err(|_| StreamError::OffsetOverflow)?;
    usize::try_from(requested.min(file_len - offset)).map_err(|_| StreamError::OffsetOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_window_returns_positional_slice() {
        let cache = CachedWindow {
            generation: 3,
            start: 100,
            data: (0u8..32).collect(),
        };
        assert_eq!(cache.slice(108, 4).unwrap(), Some(vec![8, 9, 10, 11]));
        assert_eq!(cache.slice(95, 4).unwrap(), None);
        assert_eq!(cache.slice(128, 8).unwrap(), None);
    }

    #[test]
    fn seek_invalidates_cache_and_changes_generation() {
        let mut reader = VideoReader::new(VideoReaderConfig::default()).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 0,
            data: vec![1; 1024],
        });
        let generation = reader.seek(4 * 1024 * 1024 * 1024);
        assert_eq!(generation, 1);
        assert_eq!(reader.cached_bytes(), 0);
        assert!(reader.is_current_generation(1));
        assert!(!reader.is_current_generation(0));
    }

    #[test]
    fn invalid_pipeline_depth_is_rejected() {
        let config = VideoReaderConfig {
            pipeline: PipelinedReadOptions {
                max_in_flight: 0,
                ..PipelinedReadOptions::default()
            },
            ..VideoReaderConfig::default()
        };
        assert!(VideoReader::new(config).is_err());
    }

    #[test]
    fn stale_external_generation_is_rejected_before_network_io() {
        let token = ReadCancellationToken::new();
        let generation = token.generation();
        token.advance();
        assert!(matches!(
            ensure_not_cancelled(Some((&token, generation))),
            Err(StreamError::Client(ClientError::Cancelled))
        ));
    }

    #[test]
    fn reconnect_cancellation_is_recognized_as_stream_cancellation() {
        let error = StreamError::Reconnect(ReconnectError::Cancelled);
        assert!(error.is_cancelled());
    }

    #[test]
    fn cache_hit_and_network_fetch_share_one_read_plan() {
        let mut reader = VideoReader::new(VideoReaderConfig::default()).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 100,
            data: (0u8..32).collect(),
        });

        let cached = reader.prepare_read(1_000, 108, 4, None).unwrap();
        assert!(matches!(cached, PreparedRead::Cached(data) if data == vec![8, 9, 10, 11]));

        let fetch = reader.prepare_read(1_000, 500, 4, None).unwrap();
        assert!(matches!(fetch, PreparedRead::Fetch { target: 4, .. }));
    }
}
