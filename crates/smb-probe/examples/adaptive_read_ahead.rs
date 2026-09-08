#![forbid(unsafe_code)]

use std::error::Error;
use std::time::Duration;

use smb_io_client::{ReadOnlyReconnectRecipe, RecoveringReadOnlyFile};
use smb_io_stream::{VideoReader, VideoReaderConfig};

const BOOTSTRAP_READ_AHEAD: usize = 256 * 1024;
const PROBE_READ_LEN: usize = 64 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or_else(usage)?;
    let port = args.next().ok_or_else(usage)?.parse::<u16>()?;
    let share = args.next().ok_or_else(usage)?;
    let path = args.next().ok_or_else(usage)?;
    let username = dash_to_empty(args.next().ok_or_else(usage)?);
    let password = dash_to_empty(args.next().ok_or_else(usage)?);
    if args.next().is_some() {
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
    let mut source = RecoveringReadOnlyFile::connect(recipe).await?;
    let config = VideoReaderConfig {
        read_ahead_bytes: BOOTSTRAP_READ_AHEAD,
        target_buffer_duration: Duration::from_secs(4),
        ..VideoReaderConfig::default()
    };
    let mut reader = VideoReader::new(config)?;

    let bootstrap = reader.read_ahead_target_bytes();
    if bootstrap != BOOTSTRAP_READ_AHEAD {
        return Err(format!(
            "unexpected bootstrap read-ahead: expected {BOOTSTRAP_READ_AHEAD}, got {bootstrap}"
        )
        .into());
    }

    let data = reader
        .read_recovering(&mut source, 0, PROBE_READ_LEN)
        .await?;
    if data.len() != PROBE_READ_LEN {
        return Err(format!(
            "adaptive probe read was short: expected {PROBE_READ_LEN} bytes, got {}",
            data.len()
        )
        .into());
    }

    let metrics = reader.metrics();
    let throughput = metrics
        .total_throughput_bytes_per_second()
        .ok_or("live SMB fetch did not produce a measurable throughput sample")?;
    let target = reader.read_ahead_target_bytes();
    if target == bootstrap {
        return Err(format!(
            "adaptive read-ahead did not move away from bootstrap: throughput={throughput}, target={target}"
        )
        .into());
    }

    println!("adaptive_bootstrap_bytes: {bootstrap}");
    println!(
        "adaptive_foreground_fetches: {}",
        metrics.foreground_fetches
    );
    println!(
        "adaptive_foreground_fetch_bytes: {}",
        metrics.foreground_fetch_bytes
    );
    println!("adaptive_throughput_bytes_per_second: {throughput}");
    println!("adaptive_target_bytes: {target}");
    println!("adaptive_changed: true");

    source.close().await?;
    Ok(())
}

fn dash_to_empty(value: String) -> String {
    if value == "-" { String::new() } else { value }
}

fn usage() -> String {
    "usage: adaptive_read_ahead <host> <port> <share> <path> <username|-> <password|->".to_string()
}
