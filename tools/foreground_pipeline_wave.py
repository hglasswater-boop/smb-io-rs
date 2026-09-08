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
    """    /// Amount of data fetched on a cache miss even if the caller asks for less.\n    pub read_ahead_bytes: usize,\n""",
    """    /// Target speculative read-ahead window. Cache misses fetch at most one configured\n    /// pipeline wave beyond caller demand; background prefetch grows the rolling cache farther.\n    pub read_ahead_bytes: usize,\n""",
    "read ahead docs",
)

old = """        let remaining = usize::try_from(file_len - offset).unwrap_or(usize::MAX);\n        let fetch_len = if target > self.config.max_cache_bytes {\n            target\n        } else {\n            target\n                .max(self.config.read_ahead_bytes)\n                .min(self.config.max_cache_bytes)\n                .min(remaining)\n        };\n"""
new = """        let remaining = usize::try_from(file_len - offset).unwrap_or(usize::MAX);\n        // Keep foreground miss/seek latency to one configured pipeline wave. The broker's\n        // low-water refill extends the cache in the background after the requested bytes return.\n        let foreground_read_ahead = self\n            .config\n            .pipeline\n            .chunk_size\n            .saturating_mul(self.config.pipeline.max_in_flight)\n            .min(self.config.read_ahead_bytes);\n        let fetch_len = if target > self.config.max_cache_bytes {\n            target\n        } else {\n            target\n                .max(foreground_read_ahead)\n                .min(self.config.max_cache_bytes)\n                .min(remaining)\n        };\n"""
text = replace_once(text, old, new, "foreground fetch sizing")

marker = """    #[test]\n    fn prefetch_extends_from_cache_end_within_budget() {\n"""
insert = """    #[test]\n    fn cache_miss_prefetch_is_bounded_to_one_pipeline_wave() {\n        let mut reader = VideoReader::new(VideoReaderConfig::default()).unwrap();\n        let plan = reader.prepare_read(64 * 1024 * 1024, 0, 64 * 1024, None).unwrap();\n\n        assert!(matches!(\n            plan,\n            PreparedRead::Fetch {\n                target: 65_536,\n                fetch_len: 1_048_576,\n                ..\n            }\n        ));\n    }\n\n    #[test]\n    fn configured_read_ahead_caps_the_foreground_pipeline_wave() {\n        let config = VideoReaderConfig {\n            read_ahead_bytes: 512 * 1024,\n            ..VideoReaderConfig::default()\n        };\n        let mut reader = VideoReader::new(config).unwrap();\n        let plan = reader.prepare_read(64 * 1024 * 1024, 0, 64 * 1024, None).unwrap();\n\n        assert!(matches!(\n            plan,\n            PreparedRead::Fetch {\n                target: 65_536,\n                fetch_len: 524_288,\n                ..\n            }\n        ));\n    }\n\n    #[test]\n    fn caller_demand_larger_than_one_wave_is_not_shortened() {\n        let mut reader = VideoReader::new(VideoReaderConfig::default()).unwrap();\n        let plan = reader\n            .prepare_read(64 * 1024 * 1024, 0, 1536 * 1024, None)\n            .unwrap();\n\n        assert!(matches!(\n            plan,\n            PreparedRead::Fetch {\n                target: 1_572_864,\n                fetch_len: 1_572_864,\n                ..\n            }\n        ));\n    }\n\n"""
text = replace_once(text, marker, insert + marker, "foreground wave tests")
path.write_text(text)
