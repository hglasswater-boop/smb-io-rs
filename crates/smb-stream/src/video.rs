use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

use smb_io_client::{
    ClientError, FileHandle, PipelinedReadOptions, ReadCancellationToken, ReconnectError,
    RecoveringReadOnlyFile, SessionConnection, Transport,
};

#[derive(Debug, Clone, Copy)]
pub struct VideoReaderConfig {
    /// Target speculative read-ahead window. Cache misses fetch at most one configured
    /// pipeline wave beyond caller demand; background prefetch grows the rolling cache farther.
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

/// Cumulative workload measurements for one video-reader lifetime.
///
/// Timings cover successful SMB fetches end-to-end, including any reconnect delay that happened
/// before the read eventually completed. Cache-only reads never contribute network timing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VideoReaderMetrics {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub foreground_fetches: u64,
    pub foreground_fetch_bytes: u64,
    pub foreground_fetch_micros: u64,
    pub prefetch_fetches: u64,
    pub prefetch_fetch_bytes: u64,
    pub prefetch_fetch_micros: u64,
}

impl VideoReaderMetrics {
    pub fn foreground_throughput_bytes_per_second(self) -> Option<u64> {
        throughput_bytes_per_second(self.foreground_fetch_bytes, self.foreground_fetch_micros)
    }

    pub fn prefetch_throughput_bytes_per_second(self) -> Option<u64> {
        throughput_bytes_per_second(self.prefetch_fetch_bytes, self.prefetch_fetch_micros)
    }

    pub fn total_throughput_bytes_per_second(self) -> Option<u64> {
        throughput_bytes_per_second(
            self.foreground_fetch_bytes
                .saturating_add(self.prefetch_fetch_bytes),
            self.foreground_fetch_micros
                .saturating_add(self.prefetch_fetch_micros),
        )
    }

    fn record_foreground_fetch(&mut self, bytes: usize, elapsed: Duration) {
        self.foreground_fetches = self.foreground_fetches.saturating_add(1);
        self.foreground_fetch_bytes = self
            .foreground_fetch_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        self.foreground_fetch_micros = self
            .foreground_fetch_micros
            .saturating_add(duration_micros(elapsed));
    }

    fn record_prefetch_fetch(&mut self, bytes: usize, elapsed: Duration) {
        self.prefetch_fetches = self.prefetch_fetches.saturating_add(1);
        self.prefetch_fetch_bytes = self
            .prefetch_fetch_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        self.prefetch_fetch_micros = self
            .prefetch_fetch_micros
            .saturating_add(duration_micros(elapsed));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrefetchExtension {
    offset: u64,
    fetch_len: usize,
    reader_generation: u64,
    expected_cache_start: u64,
    expected_cache_len: usize,
    drop_prefix: usize,
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
    metrics: VideoReaderMetrics,
}

impl VideoReader {
    pub fn new(config: VideoReaderConfig) -> Result<Self, StreamError> {
        validate_config(config)?;
        Ok(Self {
            config,
            generation: 0,
            last_request_end: None,
            cache: None,
            metrics: VideoReaderMetrics::default(),
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

    pub fn metrics(&self) -> VideoReaderMetrics {
        self.metrics
    }

    pub fn cached_range(&self) -> Result<Option<(u64, u64)>, StreamError> {
        self.cache
            .as_ref()
            .map(|cache| Ok((cache.start, cache.end()?)))
            .transpose()
    }

    /// Returns a low-water speculative refill hint for the current sequential cursor.
    ///
    /// The broker uses this after delivering a foreground read. No network I/O happens here.
    pub(crate) fn automatic_prefetch_hint(
        &self,
        file_len: u64,
    ) -> Result<Option<(u64, usize)>, StreamError> {
        let Some(cursor) = self.last_request_end else {
            return Ok(None);
        };
        if cursor >= file_len {
            return Ok(None);
        }
        let Some(cache) = self.cache.as_ref() else {
            return Ok(None);
        };
        if cache.generation != self.generation {
            return Ok(None);
        }

        let cache_end = cache.end()?;
        if cursor < cache.start || cursor > cache_end {
            return Ok(None);
        }
        let ahead = usize::try_from(cache_end - cursor).unwrap_or(usize::MAX);
        let low_water = (self.config.read_ahead_bytes / 2).max(1);
        if ahead > low_water {
            return Ok(None);
        }
        Ok(Some((cursor, self.config.read_ahead_bytes)))
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

    /// Extends the current sequential cache without moving the foreground playback cursor.
    ///
    /// The hint must point inside the current cache or exactly at its end. Unrelated/far-away hints,
    /// EOF, and absent caches are ignored. A full cache may roll forward only when already-consumed
    /// prefix bytes can be reclaimed without evicting data around the foreground cursor.
    pub async fn prefetch_cancelable<T>(
        &mut self,
        session: &mut SessionConnection<T>,
        file: &FileHandle,
        hint_offset: u64,
        hint_length: usize,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<usize, StreamError>
    where
        T: Transport,
    {
        let cancellation_context = Some((cancellation, generation));
        let Some(plan) = self.prepare_prefetch_extension(
            file.len(),
            hint_offset,
            hint_length,
            cancellation_context,
        )?
        else {
            return Ok(0);
        };

        let started = Instant::now();
        let fetched = session
            .read_at_pipelined_cancelable_with_options(
                file,
                plan.offset,
                plan.fetch_len,
                self.config.pipeline,
                cancellation,
                generation,
            )
            .await?;
        self.metrics
            .record_prefetch_fetch(fetched.len(), started.elapsed());
        self.finish_prefetch_extension(plan, fetched, cancellation_context)
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

    /// Reconnecting counterpart to `prefetch_cancelable`. Reconnect and retry remain subject to the
    /// source's read-reconnect policy, while cancellation can stop both SMB I/O and reconnect work.
    pub async fn prefetch_recovering_cancelable(
        &mut self,
        source: &mut RecoveringReadOnlyFile,
        hint_offset: u64,
        hint_length: usize,
        cancellation: &ReadCancellationToken,
        generation: u64,
    ) -> Result<usize, StreamError> {
        let cancellation_context = Some((cancellation, generation));
        let Some(plan) = self.prepare_prefetch_extension(
            source.len(),
            hint_offset,
            hint_length,
            cancellation_context,
        )?
        else {
            return Ok(0);
        };

        let started = Instant::now();
        let fetched = source
            .read_at_pipelined_cancelable_with_options(
                plan.offset,
                plan.fetch_len,
                self.config.pipeline,
                cancellation,
                generation,
            )
            .await?;
        self.metrics
            .record_prefetch_fetch(fetched.len(), started.elapsed());
        self.finish_prefetch_extension(plan, fetched, cancellation_context)
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

        let started = Instant::now();
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
        self.metrics
            .record_foreground_fetch(fetched.len(), started.elapsed());

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

        let started = Instant::now();
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
        self.metrics
            .record_foreground_fetch(fetched.len(), started.elapsed());

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
                    self.metrics.cache_hits = self.metrics.cache_hits.saturating_add(1);
                    return Ok(PreparedRead::Cached(data));
                }
            }
        }

        self.metrics.cache_misses = self.metrics.cache_misses.saturating_add(1);
        if self.is_seek_miss(offset)? {
            self.bump_generation();
            self.cache = None;
        }

        let remaining = usize::try_from(file_len - offset).unwrap_or(usize::MAX);
        // Keep foreground miss/seek latency to one configured pipeline wave. The broker's
        // low-water refill extends the cache in the background after the requested bytes return.
        let foreground_read_ahead = self
            .config
            .pipeline
            .chunk_size
            .saturating_mul(self.config.pipeline.max_in_flight)
            .min(self.config.read_ahead_bytes);
        let fetch_len = if target > self.config.max_cache_bytes {
            target
        } else {
            target
                .max(foreground_read_ahead)
                .min(self.config.max_cache_bytes)
                .min(remaining)
        };

        Ok(PreparedRead::Fetch {
            target,
            fetch_len,
            reader_generation: self.generation,
        })
    }

    fn prepare_prefetch_extension(
        &self,
        file_len: u64,
        hint_offset: u64,
        hint_length: usize,
        cancellation: Option<(&ReadCancellationToken, u64)>,
    ) -> Result<Option<PrefetchExtension>, StreamError> {
        ensure_not_cancelled(cancellation)?;
        if hint_length == 0 || hint_offset >= file_len {
            return Ok(None);
        }

        let Some(cache) = self.cache.as_ref() else {
            return Ok(None);
        };
        if cache.generation != self.generation {
            return Ok(None);
        }

        let cache_end = cache.end()?;
        if hint_offset < cache.start || hint_offset > cache_end || cache_end >= file_len {
            return Ok(None);
        }

        // Drop only data safely behind the actual foreground cursor. An explicit prefetch hint is
        // allowed to point farther ahead, but it must never evict bytes the player has not consumed.
        let cursor = self.last_request_end.unwrap_or(cache.start);
        let retain_back = u64::try_from(
            self.config
                .read_ahead_bytes
                .min(self.config.max_cache_bytes),
        )
        .map_err(|_| StreamError::OffsetOverflow)?;
        let keep_from = cursor.saturating_sub(retain_back).max(cache.start);
        let drop_prefix =
            usize::try_from(keep_from - cache.start).map_err(|_| StreamError::OffsetOverflow)?;
        let retained_len = cache
            .data
            .len()
            .checked_sub(drop_prefix)
            .ok_or(StreamError::OffsetOverflow)?;
        let available_capacity = self
            .config
            .max_cache_bytes
            .checked_sub(retained_len)
            .ok_or(StreamError::OffsetOverflow)?;
        if available_capacity == 0 {
            return Ok(None);
        }

        let file_remaining = usize::try_from(file_len - cache_end).unwrap_or(usize::MAX);
        let fetch_len = self
            .config
            .read_ahead_bytes
            .min(available_capacity)
            .min(file_remaining);
        if fetch_len == 0 {
            return Ok(None);
        }

        Ok(Some(PrefetchExtension {
            offset: cache_end,
            fetch_len,
            reader_generation: self.generation,
            expected_cache_start: cache.start,
            expected_cache_len: cache.data.len(),
            drop_prefix,
        }))
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

    fn finish_prefetch_extension(
        &mut self,
        plan: PrefetchExtension,
        fetched: Vec<u8>,
        cancellation: Option<(&ReadCancellationToken, u64)>,
    ) -> Result<usize, StreamError> {
        ensure_not_cancelled(cancellation)?;
        if plan.reader_generation != self.generation {
            return Ok(0);
        }

        let Some(cache) = self.cache.as_mut() else {
            return Ok(0);
        };
        if cache.generation != plan.reader_generation
            || cache.start != plan.expected_cache_start
            || cache.data.len() != plan.expected_cache_len
            || cache.end()? != plan.offset
            || plan.drop_prefix > cache.data.len()
        {
            return Ok(0);
        }

        // Mutate the cache only after the speculative read succeeded and the plan is still current.
        if plan.drop_prefix > 0 {
            let dropped =
                u64::try_from(plan.drop_prefix).map_err(|_| StreamError::OffsetOverflow)?;
            cache.data.drain(..plan.drop_prefix);
            cache.start = cache
                .start
                .checked_add(dropped)
                .ok_or(StreamError::OffsetOverflow)?;
        }

        let capacity = self.config.max_cache_bytes - cache.data.len();
        let append_len = fetched.len().min(capacity);
        cache.data.extend_from_slice(&fetched[..append_len]);
        Ok(append_len)
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

fn duration_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn throughput_bytes_per_second(bytes: u64, micros: u64) -> Option<u64> {
    if bytes == 0 || micros == 0 {
        return None;
    }
    let per_second = u128::from(bytes)
        .saturating_mul(1_000_000)
        .checked_div(u128::from(micros))?;
    Some(u64::try_from(per_second).unwrap_or(u64::MAX))
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
    fn aggregate_throughput_metrics_use_successful_fetch_time() {
        let mut metrics = VideoReaderMetrics::default();
        metrics.record_foreground_fetch(1_000_000, Duration::from_millis(500));
        metrics.record_prefetch_fetch(500_000, Duration::from_millis(250));

        assert_eq!(
            metrics.foreground_throughput_bytes_per_second(),
            Some(2_000_000)
        );
        assert_eq!(
            metrics.prefetch_throughput_bytes_per_second(),
            Some(2_000_000)
        );
        assert_eq!(metrics.total_throughput_bytes_per_second(), Some(2_000_000));
        assert_eq!(metrics.foreground_fetches, 1);
        assert_eq!(metrics.prefetch_fetches, 1);
    }

    #[test]
    fn cache_hit_and_miss_metrics_follow_read_plans() {
        let mut reader = VideoReader::new(VideoReaderConfig::default()).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 100,
            data: (0u8..32).collect(),
        });

        assert!(matches!(
            reader.prepare_read(1_000, 108, 4, None).unwrap(),
            PreparedRead::Cached(_)
        ));
        assert!(matches!(
            reader.prepare_read(1_000, 500, 4, None).unwrap(),
            PreparedRead::Fetch { .. }
        ));

        let metrics = reader.metrics();
        assert_eq!(metrics.cache_hits, 1);
        assert_eq!(metrics.cache_misses, 1);
    }

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

    #[test]
    fn cache_miss_prefetch_is_bounded_to_one_pipeline_wave() {
        let mut reader = VideoReader::new(VideoReaderConfig::default()).unwrap();
        let plan = reader
            .prepare_read(64 * 1024 * 1024, 0, 64 * 1024, None)
            .unwrap();

        assert!(matches!(
            plan,
            PreparedRead::Fetch {
                target: 65_536,
                fetch_len: 1_048_576,
                ..
            }
        ));
    }

    #[test]
    fn configured_read_ahead_caps_the_foreground_pipeline_wave() {
        let config = VideoReaderConfig {
            read_ahead_bytes: 512 * 1024,
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        let plan = reader
            .prepare_read(64 * 1024 * 1024, 0, 64 * 1024, None)
            .unwrap();

        assert!(matches!(
            plan,
            PreparedRead::Fetch {
                target: 65_536,
                fetch_len: 524_288,
                ..
            }
        ));
    }

    #[test]
    fn caller_demand_larger_than_one_wave_is_not_shortened() {
        let mut reader = VideoReader::new(VideoReaderConfig::default()).unwrap();
        let plan = reader
            .prepare_read(64 * 1024 * 1024, 0, 1536 * 1024, None)
            .unwrap();

        assert!(matches!(
            plan,
            PreparedRead::Fetch {
                target: 1_572_864,
                fetch_len: 1_572_864,
                ..
            }
        ));
    }

    #[test]
    fn prefetch_extends_from_cache_end_within_budget() {
        let config = VideoReaderConfig {
            read_ahead_bytes: 2 * 1024,
            max_cache_bytes: 8 * 1024,
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 100,
            data: vec![1; 2 * 1024],
        });
        reader.last_request_end = Some(132);

        let plan = reader
            .prepare_prefetch_extension(20_000, 132, 512, None)
            .unwrap()
            .unwrap();
        assert_eq!(plan.offset, 100 + 2 * 1024);
        assert_eq!(plan.fetch_len, 2 * 1024);
    }

    #[test]
    fn prefetch_does_not_replace_full_or_unrelated_cache() {
        let config = VideoReaderConfig {
            read_ahead_bytes: 2 * 1024,
            max_cache_bytes: 8 * 1024,
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 1_000,
            data: vec![1; 8 * 1024],
        });
        assert!(
            reader
                .prepare_prefetch_extension(50_000, 1_100, 512, None)
                .unwrap()
                .is_none()
        );

        reader.cache.as_mut().unwrap().data.truncate(2 * 1024);
        assert!(
            reader
                .prepare_prefetch_extension(50_000, 10_000, 512, None)
                .unwrap()
                .is_none()
        );
        assert_eq!(reader.cached_range().unwrap(), Some((1_000, 3_048)));
    }

    #[test]
    fn finishing_prefetch_appends_without_moving_foreground_cursor() {
        let config = VideoReaderConfig {
            read_ahead_bytes: 4,
            max_cache_bytes: 16,
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 100,
            data: vec![1, 2, 3, 4],
        });
        reader.last_request_end = Some(102);
        let plan = reader
            .prepare_prefetch_extension(1_000, 102, 1, None)
            .unwrap()
            .unwrap();

        assert_eq!(
            reader
                .finish_prefetch_extension(plan, vec![5, 6, 7, 8], None)
                .unwrap(),
            4
        );
        assert_eq!(reader.cached_range().unwrap(), Some((100, 108)));
        assert_eq!(reader.last_request_end, Some(102));
    }

    #[test]
    fn automatic_prefetch_starts_at_low_water_mark() {
        let config = VideoReaderConfig {
            read_ahead_bytes: 8,
            max_cache_bytes: 32,
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 100,
            data: vec![1; 16],
        });

        reader.last_request_end = Some(108);
        assert_eq!(reader.automatic_prefetch_hint(1_000).unwrap(), None);
        reader.last_request_end = Some(112);
        assert_eq!(
            reader.automatic_prefetch_hint(1_000).unwrap(),
            Some((112, 8))
        );
    }

    #[test]
    fn successful_prefetch_rolls_full_cache_forward() {
        let config = VideoReaderConfig {
            read_ahead_bytes: 4,
            max_cache_bytes: 12,
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 100,
            data: (0u8..12).collect(),
        });
        reader.last_request_end = Some(110);

        let plan = reader
            .prepare_prefetch_extension(1_000, 110, 1, None)
            .unwrap()
            .unwrap();
        assert_eq!(plan.offset, 112);
        assert_eq!(plan.fetch_len, 4);
        assert_eq!(plan.drop_prefix, 6);

        assert_eq!(
            reader
                .finish_prefetch_extension(plan, vec![12, 13, 14, 15], None)
                .unwrap(),
            4
        );
        assert_eq!(reader.cached_range().unwrap(), Some((106, 116)));
        assert_eq!(reader.cached_bytes(), 10);
        assert_eq!(reader.last_request_end, Some(110));
    }

    #[test]
    fn explicit_prefetch_never_drops_unconsumed_bytes() {
        let config = VideoReaderConfig {
            read_ahead_bytes: 4,
            max_cache_bytes: 12,
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 100,
            data: (0u8..12).collect(),
        });
        reader.last_request_end = Some(104);

        let plan = reader
            .prepare_prefetch_extension(1_000, 110, 1, None)
            .unwrap();
        assert!(plan.is_none());
        assert_eq!(reader.cached_range().unwrap(), Some((100, 112)));
    }

    #[test]
    fn stale_prefetch_plan_never_appends() {
        let config = VideoReaderConfig {
            read_ahead_bytes: 4,
            max_cache_bytes: 16,
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        reader.cache = Some(CachedWindow {
            generation: 0,
            start: 100,
            data: vec![1, 2, 3, 4],
        });
        let plan = reader
            .prepare_prefetch_extension(1_000, 102, 1, None)
            .unwrap()
            .unwrap();
        reader.seek(500);

        assert_eq!(
            reader
                .finish_prefetch_extension(plan, vec![5, 6, 7, 8], None)
                .unwrap(),
            0
        );
        assert_eq!(reader.cached_bytes(), 0);
    }
}
