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
    """    cache: Option<CachedWindow>,
    metrics: VideoReaderMetrics,
}
""",
    """    cache: Option<CachedWindow>,
    metrics: VideoReaderMetrics,
    smoothed_throughput_bytes_per_second: Option<u64>,
}
""",
    "reader throughput state",
)

text = replace_once(
    text,
    """            last_request_end: None,
            cache: None,
            metrics: VideoReaderMetrics::default(),
        })
""",
    """            last_request_end: None,
            cache: None,
            metrics: VideoReaderMetrics::default(),
            smoothed_throughput_bytes_per_second: None,
        })
""",
    "reader throughput init",
)

text = replace_once(
    text,
    """    pub fn metrics(&self) -> VideoReaderMetrics {
        self.metrics
    }

    /// Current speculative window target.
""",
    """    pub fn metrics(&self) -> VideoReaderMetrics {
        self.metrics
    }

    /// Smoothed recent SMB throughput used by the adaptive read-ahead controller.
    pub fn smoothed_throughput_bytes_per_second(&self) -> Option<u64> {
        self.smoothed_throughput_bytes_per_second
    }

    /// Current speculative window target.
""",
    "throughput accessor",
)

text = replace_once(
    text,
    """    /// Before the first successful SMB fetch this is the configured bootstrap value. Afterwards it
    /// tracks observed aggregate fetch throughput for `target_buffer_duration`, clamped between one
    /// SMB request chunk and the configured cache budget.
""",
    """    /// Before the first successful SMB fetch this is the configured bootstrap value. Afterwards it
    /// tracks a recent-throughput EWMA for `target_buffer_duration`, clamped between one SMB request
    /// chunk and the configured cache budget.
""",
    "target docs",
)

text = replace_once(
    text,
    """        let Some(throughput) = self.metrics.total_throughput_bytes_per_second() else {
            return bootstrap;
        };
""",
    """        let Some(throughput) = self.smoothed_throughput_bytes_per_second else {
            return bootstrap;
        };
""",
    "adaptive source",
)

text = text.replace(
    """        self.metrics
            .record_prefetch_fetch(fetched.len(), started.elapsed());
""",
    """        self.record_prefetch_fetch(fetched.len(), started.elapsed());
""",
)
if text.count("self.record_prefetch_fetch(fetched.len(), started.elapsed());") != 2:
    raise SystemExit("prefetch record replacements did not produce two call sites")

text = text.replace(
    """        self.metrics
            .record_foreground_fetch(fetched.len(), started.elapsed());
""",
    """        self.record_foreground_fetch(fetched.len(), started.elapsed());
""",
)
if text.count("self.record_foreground_fetch(fetched.len(), started.elapsed());") != 2:
    raise SystemExit("foreground record replacements did not produce two call sites")

text = replace_once(
    text,
    """    fn is_seek_miss(&self, offset: u64) -> Result<bool, StreamError> {
""",
    """    fn record_foreground_fetch(&mut self, bytes: usize, elapsed: Duration) {
        self.metrics.record_foreground_fetch(bytes, elapsed);
        self.record_throughput_sample(bytes, elapsed);
    }

    fn record_prefetch_fetch(&mut self, bytes: usize, elapsed: Duration) {
        self.metrics.record_prefetch_fetch(bytes, elapsed);
        self.record_throughput_sample(bytes, elapsed);
    }

    fn record_throughput_sample(&mut self, bytes: usize, elapsed: Duration) {
        let Some(sample) = throughput_bytes_per_second(
            u64::try_from(bytes).unwrap_or(u64::MAX),
            duration_micros(elapsed),
        ) else {
            return;
        };
        self.smoothed_throughput_bytes_per_second = Some(
            self.smoothed_throughput_bytes_per_second
                .map_or(sample, |previous| {
                    let average = (u128::from(previous) + u128::from(sample)) / 2;
                    u64::try_from(average).unwrap_or(u64::MAX)
                }),
        );
    }

    fn is_seek_miss(&self, offset: u64) -> Result<bool, StreamError> {
""",
    "throughput recorder methods",
)

text = replace_once(
    text,
    """        reader
            .metrics
            .record_foreground_fetch(6 * 1024 * 1024, Duration::from_secs(1));

        assert_eq!(reader.read_ahead_target_bytes(), 3 * 1024 * 1024);
""",
    """        reader.record_foreground_fetch(6 * 1024 * 1024, Duration::from_secs(1));

        assert_eq!(reader.read_ahead_target_bytes(), 3 * 1024 * 1024);
""",
    "adaptive horizon test",
)

text = replace_once(
    text,
    """        slow.metrics
            .record_foreground_fetch(64 * 1024, Duration::from_secs(1));
""",
    """        slow.record_foreground_fetch(64 * 1024, Duration::from_secs(1));
""",
    "slow clamp test",
)

text = replace_once(
    text,
    """        fast.metrics
            .record_foreground_fetch(64 * 1024 * 1024, Duration::from_secs(1));
""",
    """        fast.record_foreground_fetch(64 * 1024 * 1024, Duration::from_secs(1));
""",
    "fast clamp test",
)

marker = """    #[test]
    fn adaptive_target_uses_bootstrap_before_network_metrics() {
"""
test = """    #[test]
    fn smoothed_throughput_favors_recent_fetches() {
        let mut reader = VideoReader::new(VideoReaderConfig::default()).unwrap();
        reader.record_foreground_fetch(8_000_000, Duration::from_secs(1));
        assert_eq!(reader.smoothed_throughput_bytes_per_second(), Some(8_000_000));

        reader.record_prefetch_fetch(2_000_000, Duration::from_secs(1));
        assert_eq!(reader.smoothed_throughput_bytes_per_second(), Some(5_000_000));
        assert_eq!(reader.metrics().total_throughput_bytes_per_second(), Some(5_000_000));

        reader.record_prefetch_fetch(2_000_000, Duration::from_secs(1));
        assert_eq!(reader.smoothed_throughput_bytes_per_second(), Some(3_500_000));
        assert_eq!(
            reader.metrics().total_throughput_bytes_per_second(),
            Some(4_000_000)
        );
    }

""" + marker
text = replace_once(text, marker, test, "ewma test")

text = replace_once(
    text,
    """    fn adaptive_target_tracks_observed_throughput_horizon() {
""",
    """    fn adaptive_target_tracks_smoothed_throughput_horizon() {
""",
    "adaptive test name",
)

path.write_text(text)
