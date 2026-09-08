from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    return text.replace(old, new, 1)


path = Path("crates/smb-stream/src/video.rs")
text = path.read_text()

text = replace_once(
    text,
    """pub struct VideoReaderConfig {
    /// Target speculative read-ahead window. Cache misses fetch at most one configured
    /// pipeline wave beyond caller demand; background prefetch grows the rolling cache farther.
    pub read_ahead_bytes: usize,
    /// Maximum bytes retained in the single contiguous cache window.
""",
    """pub struct VideoReaderConfig {
    /// Bootstrap speculative read-ahead target used until a successful SMB timing sample exists.
    /// Cache misses still await at most one configured pipeline wave beyond caller demand.
    pub read_ahead_bytes: usize,
    /// Time horizon used to convert observed SMB throughput into an adaptive read-ahead target.
    pub target_buffer_duration: Duration,
    /// Maximum bytes retained in the single contiguous cache window.
""",
    "config docs and target duration",
)

text = replace_once(
    text,
    """        Self {
            read_ahead_bytes: 2 * 1024 * 1024,
            max_cache_bytes: 8 * 1024 * 1024,
""",
    """        Self {
            read_ahead_bytes: 2 * 1024 * 1024,
            target_buffer_duration: Duration::from_secs(1),
            max_cache_bytes: 8 * 1024 * 1024,
""",
    "default target duration",
)

text = replace_once(
    text,
    """    pub fn metrics(&self) -> VideoReaderMetrics {
        self.metrics
    }

""",
    """    pub fn metrics(&self) -> VideoReaderMetrics {
        self.metrics
    }

    /// Current speculative window target.
    ///
    /// Before the first successful SMB fetch this is the configured bootstrap value. Afterwards it
    /// tracks observed aggregate fetch throughput for `target_buffer_duration`, clamped between one
    /// SMB request chunk and the configured cache budget.
    pub fn read_ahead_target_bytes(&self) -> usize {
        let bootstrap = self.config.read_ahead_bytes.min(self.config.max_cache_bytes);
        let Some(throughput) = self.metrics.total_throughput_bytes_per_second() else {
            return bootstrap;
        };

        let target = u128::from(throughput)
            .saturating_mul(self.config.target_buffer_duration.as_micros())
            .checked_div(1_000_000)
            .unwrap_or(u128::MAX);
        let minimum = self
            .config
            .pipeline
            .chunk_size
            .min(self.config.max_cache_bytes)
            .max(1);
        usize::try_from(target)
            .unwrap_or(usize::MAX)
            .clamp(minimum, self.config.max_cache_bytes)
    }

""",
    "adaptive target method",
)

text = replace_once(
    text,
    """        let ahead = usize::try_from(cache_end - cursor).unwrap_or(usize::MAX);
        let low_water = (self.config.read_ahead_bytes / 2).max(1);
        if ahead > low_water {
            return Ok(None);
        }
        Ok(Some((cursor, self.config.read_ahead_bytes)))
""",
    """        let ahead = usize::try_from(cache_end - cursor).unwrap_or(usize::MAX);
        let read_ahead_target = self.read_ahead_target_bytes();
        let low_water = (read_ahead_target / 2).max(1);
        if ahead > low_water {
            return Ok(None);
        }
        Ok(Some((cursor, read_ahead_target)))
""",
    "adaptive low water",
)

text = replace_once(
    text,
    """        let foreground_read_ahead = self
            .config
            .pipeline
            .chunk_size
            .saturating_mul(self.config.pipeline.max_in_flight)
            .min(self.config.read_ahead_bytes);
""",
    """        let foreground_read_ahead = self
            .config
            .pipeline
            .chunk_size
            .saturating_mul(self.config.pipeline.max_in_flight)
            .min(self.read_ahead_target_bytes());
""",
    "adaptive foreground miss cap",
)

text = replace_once(
    text,
    """        let retain_back = u64::try_from(
            self.config
                .read_ahead_bytes
                .min(self.config.max_cache_bytes),
        )
        .map_err(|_| StreamError::OffsetOverflow)?;
""",
    """        let retain_back = u64::try_from(
            self.read_ahead_target_bytes()
                .min(self.config.max_cache_bytes),
        )
        .map_err(|_| StreamError::OffsetOverflow)?;
""",
    "adaptive rolling retention",
)

text = replace_once(
    text,
    """        let fetch_len = self
            .config
            .read_ahead_bytes
            .min(available_capacity)
            .min(file_remaining);
""",
    """        let fetch_len = self
            .read_ahead_target_bytes()
            .min(available_capacity)
            .min(file_remaining);
""",
    "adaptive prefetch length",
)

text = replace_once(
    text,
    """    if config.max_cache_bytes == 0 {
        return Err(StreamError::InvalidConfig(
            "max_cache_bytes must be greater than zero",
        ));
    }
""",
    """    if config.target_buffer_duration.is_zero() {
        return Err(StreamError::InvalidConfig(
            "target_buffer_duration must be greater than zero",
        ));
    }
    if config.max_cache_bytes == 0 {
        return Err(StreamError::InvalidConfig(
            "max_cache_bytes must be greater than zero",
        ));
    }
""",
    "target duration validation",
)

marker = """    #[test]
    fn cache_hit_and_miss_metrics_follow_read_plans() {
"""
tests = """    #[test]
    fn adaptive_target_uses_bootstrap_before_network_metrics() {
        let reader = VideoReader::new(VideoReaderConfig::default()).unwrap();
        assert_eq!(reader.read_ahead_target_bytes(), 2 * 1024 * 1024);
    }

    #[test]
    fn adaptive_target_tracks_observed_throughput_horizon() {
        let config = VideoReaderConfig {
            target_buffer_duration: Duration::from_millis(500),
            ..VideoReaderConfig::default()
        };
        let mut reader = VideoReader::new(config).unwrap();
        reader
            .metrics
            .record_foreground_fetch(6 * 1024 * 1024, Duration::from_secs(1));

        assert_eq!(reader.read_ahead_target_bytes(), 3 * 1024 * 1024);
    }

    #[test]
    fn adaptive_target_clamps_to_pipeline_chunk_and_cache_budget() {
        let mut slow = VideoReader::new(VideoReaderConfig::default()).unwrap();
        slow.metrics
            .record_foreground_fetch(64 * 1024, Duration::from_secs(1));
        assert_eq!(
            slow.read_ahead_target_bytes(),
            PipelinedReadOptions::default().chunk_size
        );

        let mut fast = VideoReader::new(VideoReaderConfig::default()).unwrap();
        fast.metrics
            .record_foreground_fetch(64 * 1024 * 1024, Duration::from_secs(1));
        assert_eq!(fast.read_ahead_target_bytes(), 8 * 1024 * 1024);
    }

    #[test]
    fn zero_target_buffer_duration_is_rejected() {
        let config = VideoReaderConfig {
            target_buffer_duration: Duration::ZERO,
            ..VideoReaderConfig::default()
        };
        assert!(VideoReader::new(config).is_err());
    }

""" + marker
text = replace_once(text, marker, tests, "adaptive target tests")

path.write_text(text)
