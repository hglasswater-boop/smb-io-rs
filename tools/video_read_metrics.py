from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    return text.replace(old, new, 1)


video_path = Path("crates/smb-stream/src/video.rs")
text = video_path.read_text()

text = replace_once(
    text,
    "use std::fmt;\n",
    "use std::fmt;\nuse std::time::{Duration, Instant};\n",
    "time imports",
)

marker = """impl Default for VideoReaderConfig {
    fn default() -> Self {
        Self {
            read_ahead_bytes: 2 * 1024 * 1024,
            max_cache_bytes: 8 * 1024 * 1024,
            pipeline: PipelinedReadOptions::default(),
        }
    }
}

"""
metrics = marker + """/// Cumulative workload measurements for one video-reader lifetime.
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

"""
text = replace_once(text, marker, metrics, "metrics type")

text = replace_once(
    text,
    """    last_request_end: Option<u64>,
    cache: Option<CachedWindow>,
}
""",
    """    last_request_end: Option<u64>,
    cache: Option<CachedWindow>,
    metrics: VideoReaderMetrics,
}
""",
    "reader metrics field",
)

text = replace_once(
    text,
    """            generation: 0,
            last_request_end: None,
            cache: None,
        })
""",
    """            generation: 0,
            last_request_end: None,
            cache: None,
            metrics: VideoReaderMetrics::default(),
        })
""",
    "reader metrics init",
)

text = replace_once(
    text,
    """    pub fn cached_bytes(&self) -> usize {
        self.cache.as_ref().map_or(0, |cache| cache.data.len())
    }

""",
    """    pub fn cached_bytes(&self) -> usize {
        self.cache.as_ref().map_or(0, |cache| cache.data.len())
    }

    pub fn metrics(&self) -> VideoReaderMetrics {
        self.metrics
    }

""",
    "metrics accessor",
)

text = replace_once(
    text,
    """                if let Some(data) = cache.slice(offset, target)? {
                    ensure_not_cancelled(cancellation)?;
                    self.last_request_end = Some(request_end(offset, data.len())?);
                    return Ok(PreparedRead::Cached(data));
                }
""",
    """                if let Some(data) = cache.slice(offset, target)? {
                    ensure_not_cancelled(cancellation)?;
                    self.last_request_end = Some(request_end(offset, data.len())?);
                    self.metrics.cache_hits = self.metrics.cache_hits.saturating_add(1);
                    return Ok(PreparedRead::Cached(data));
                }
""",
    "cache hit metric",
)

text = replace_once(
    text,
    """        if self.is_seek_miss(offset)? {
            self.bump_generation();
            self.cache = None;
        }

        let remaining = usize::try_from(file_len - offset).unwrap_or(usize::MAX);
""",
    """        self.metrics.cache_misses = self.metrics.cache_misses.saturating_add(1);
        if self.is_seek_miss(offset)? {
            self.bump_generation();
            self.cache = None;
        }

        let remaining = usize::try_from(file_len - offset).unwrap_or(usize::MAX);
""",
    "cache miss metric",
)

# Instrument direct prefetch.
old = """        let fetched = session
            .read_at_pipelined_cancelable_with_options(
                file,
                plan.offset,
                plan.fetch_len,
                self.config.pipeline,
                cancellation,
                generation,
            )
            .await?;
        self.finish_prefetch_extension(plan, fetched, cancellation_context)
"""
new = """        let started = Instant::now();
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
"""
text = replace_once(text, old, new, "direct prefetch timing")

# Instrument recovering prefetch.
old = """        let fetched = source
            .read_at_pipelined_cancelable_with_options(
                plan.offset,
                plan.fetch_len,
                self.config.pipeline,
                cancellation,
                generation,
            )
            .await?;
        self.finish_prefetch_extension(plan, fetched, cancellation_context)
"""
new = """        let started = Instant::now();
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
"""
text = replace_once(text, old, new, "recovering prefetch timing")

# Instrument both foreground fetch implementations.
needle = """        let fetched = if let Some((token, generation)) = cancellation {
            session
"""
replacement = """        let started = Instant::now();
        let fetched = if let Some((token, generation)) = cancellation {
            session
"""
text = replace_once(text, needle, replacement, "direct foreground timing start")

needle = """        };

        self.finish_fetch(offset, target, reader_generation, fetched, cancellation)
    }

    async fn read_recovering_impl(
"""
replacement = """        };
        self.metrics
            .record_foreground_fetch(fetched.len(), started.elapsed());

        self.finish_fetch(offset, target, reader_generation, fetched, cancellation)
    }

    async fn read_recovering_impl(
"""
text = replace_once(text, needle, replacement, "direct foreground timing record")

needle = """        let fetched = if let Some((token, generation)) = cancellation {
            source
"""
replacement = """        let started = Instant::now();
        let fetched = if let Some((token, generation)) = cancellation {
            source
"""
text = replace_once(text, needle, replacement, "recovering foreground timing start")

needle = """        };

        self.finish_fetch(offset, target, reader_generation, fetched, cancellation)
    }

    fn prepare_read(
"""
replacement = """        };
        self.metrics
            .record_foreground_fetch(fetched.len(), started.elapsed());

        self.finish_fetch(offset, target, reader_generation, fetched, cancellation)
    }

    fn prepare_read(
"""
text = replace_once(text, needle, replacement, "recovering foreground timing record")

# Add integer-only metric helpers before ensure_not_cancelled.
marker = """fn ensure_not_cancelled(
"""
helpers = """fn duration_micros(duration: Duration) -> u64 {
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

""" + marker
text = replace_once(text, marker, helpers, "metric helpers")

# Add deterministic metric tests without sleeping.
test_marker = """    #[test]
    fn cached_window_returns_positional_slice() {
"""
tests = """    #[test]
    fn aggregate_throughput_metrics_use_successful_fetch_time() {
        let mut metrics = VideoReaderMetrics::default();
        metrics.record_foreground_fetch(1_000_000, Duration::from_millis(500));
        metrics.record_prefetch_fetch(500_000, Duration::from_millis(250));

        assert_eq!(metrics.foreground_throughput_bytes_per_second(), Some(2_000_000));
        assert_eq!(metrics.prefetch_throughput_bytes_per_second(), Some(2_000_000));
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

""" + test_marker
text = replace_once(text, test_marker, tests, "metrics tests")

video_path.write_text(text)

lib_path = Path("crates/smb-stream/src/lib.rs")
lib = lib_path.read_text()
lib = replace_once(
    lib,
    "pub use video::{StreamError, VideoReader, VideoReaderConfig};",
    "pub use video::{StreamError, VideoReader, VideoReaderConfig, VideoReaderMetrics};",
    "metrics export",
)
lib_path.write_text(lib)
