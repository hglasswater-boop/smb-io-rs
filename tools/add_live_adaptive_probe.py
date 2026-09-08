from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    return text.replace(old, new, 1)


path = Path(".github/workflows/samba-integration.yml")
text = path.read_text()
marker = """      - name: Verify signed reconnect after server restart
"""
step = """      - name: Verify adaptive read-ahead reacts to live throughput
        run: |
          set -o pipefail
          cargo run -p smb-io-probe --example adaptive_read_ahead -- \\
            127.0.0.1 \"$SMB_PORT\" auth large.bin \\
            \"$SMB_USER\" \"$SMB_PASSWORD\" \\
            | tee /tmp/auth-adaptive-read-ahead.log
          grep -Eq '^adaptive_foreground_fetches: [1-9][0-9]*$' /tmp/auth-adaptive-read-ahead.log
          grep -Eq '^adaptive_throughput_bytes_per_second: [1-9][0-9]*$' /tmp/auth-adaptive-read-ahead.log
          grep -q '^adaptive_changed: true$' /tmp/auth-adaptive-read-ahead.log

""" + marker
text = replace_once(text, marker, step, "adaptive live step")

text = replace_once(
    text,
    """          cat /tmp/auth-durable.log 2>/dev/null || true
          cat /tmp/auth-reconnect.log 2>/dev/null || true
""",
    """          cat /tmp/auth-durable.log 2>/dev/null || true
          cat /tmp/auth-adaptive-read-ahead.log 2>/dev/null || true
          cat /tmp/auth-reconnect.log 2>/dev/null || true
""",
    "adaptive failure log",
)
path.write_text(text)
