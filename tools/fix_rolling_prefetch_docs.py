from pathlib import Path

path = Path('crates/smb-stream/src/video.rs')
text = path.read_text()
old = '''    /// The hint must point inside the current cache or exactly at its end. Unrelated/far-away hints,\n    /// full caches, EOF, and absent caches are ignored so speculative work never evicts useful\n    /// foreground data.\n'''
new = '''    /// The hint must point inside the current cache or exactly at its end. Unrelated/far-away hints,\n    /// EOF, and absent caches are ignored. A full cache may roll forward only when already-consumed\n    /// prefix bytes can be reclaimed without evicting data around the foreground cursor.\n'''
if text.count(old) != 1:
    raise SystemExit(f'expected one doc block, got {text.count(old)}')
path.write_text(text.replace(old, new, 1))
