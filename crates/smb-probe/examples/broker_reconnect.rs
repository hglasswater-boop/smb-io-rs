#![forbid(unsafe_code)]

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use smb_io_client::ReadOnlyReconnectRecipe;
use smb_io_stream::{VideoBrokerConfig, VideoBrokerHandle, recovering_video_broker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or_else(usage)?;
    let port = args.next().ok_or_else(usage)?.parse::<u16>()?;
    let share = args.next().ok_or_else(usage)?;
    let path = args.next().ok_or_else(usage)?;
    let username = dash_to_empty(args.next().ok_or_else(usage)?);
    let password = dash_to_empty(args.next().ok_or_else(usage)?);
    let first_offset = args.next().ok_or_else(usage)?.parse::<u64>()?;
    let first_expected = parse_hex(&args.next().ok_or_else(usage)?)?;
    let second_offset = args.next().ok_or_else(usage)?.parse::<u64>()?;
    let second_expected = parse_hex(&args.next().ok_or_else(usage)?)?;
    let ready_file = PathBuf::from(args.next().ok_or_else(usage)?);
    let resume_file = PathBuf::from(args.next().ok_or_else(usage)?);
    if first_expected.is_empty() || second_expected.is_empty() || args.next().is_some() {
        return Err(usage().into());
    }

    let recipe = ReadOnlyReconnectRecipe::new(
        host,
        port,
        share,
        path,
        username,
        password,
        String::new(),
        String::new(),
    );
    let (handle, runner) = recovering_video_broker(recipe, VideoBrokerConfig::default()).await?;
    let runner_task = tokio::spawn(runner.run());

    verify_read(&handle, first_offset, &first_expected).await?;
    std::fs::write(&ready_file, b"ready\n")?;
    println!("broker_reconnect_ready: true");
    wait_for_file(&resume_file, Duration::from_secs(30)).await?;

    handle.seek();
    verify_read(&handle, second_offset, &second_expected).await?;
    println!("broker_reconnect_verified_offset: {second_offset}");
    println!("broker_reconnect_verified: true");

    handle.shutdown().await?;
    runner_task.await?;
    Ok(())
}

async fn verify_read(
    handle: &VideoBrokerHandle,
    offset: u64,
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    let actual = handle.read(offset, expected.len()).await?;
    if actual != expected {
        return Err(format!(
            "broker read mismatch at offset {offset:#x}: expected {}, got {}",
            hex(expected),
            hex(&actual)
        )
        .into());
    }
    Ok(())
}

async fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("timed out waiting for reconnect barrier {}", path.display()).into())
}

fn dash_to_empty(value: String) -> String {
    if value == "-" { String::new() } else { value }
}

fn parse_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let input = value.as_bytes();
    if input.is_empty() || input.len() % 2 != 0 {
        return Err("hex payload must contain an even, non-zero number of digits".into());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or("hex payload contains a non-hex digit")?;
        let low = hex_nibble(pair[1]).ok_or("hex payload contains a non-hex digit")?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn usage() -> String {
    "usage: broker_reconnect <host> <port> <share> <path> <username|-> <password|-> <first-offset> <first-hex> <second-offset> <second-hex> <ready-file> <resume-file>"
        .to_string()
}
