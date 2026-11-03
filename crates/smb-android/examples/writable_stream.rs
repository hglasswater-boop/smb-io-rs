#![forbid(unsafe_code)]

//! Signed Samba integration for the Android engine's persistent writable stream.
use std::error::Error;
use std::time::Instant;

use smb_io_android::{AndroidEngine, AndroidEngineConfig, SmbMutationRequest, VideoOpenRequest};

const CHUNK: usize = 1024 * 1024;
const TOTAL: usize = 3 * CHUNK + 17;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or("missing host")?;
    let port = args.next().ok_or("missing port")?.parse::<u16>()?;
    let share = args.next().ok_or("missing share")?;
    let path = args.next().ok_or("missing file path")?;
    let username = args.next().ok_or("missing username")?;
    let password = args.next().ok_or("missing password")?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".into());
    }

    let engine = AndroidEngine::new(AndroidEngineConfig::default())?;
    let mut open = SmbMutationRequest::new(&host, &share, &path, &username, &password);
    open.port = port;
    let writer = engine.open_writable(open)?;
    let expected: Vec<u8> = (0..TOTAL)
        .map(|index| ((index.wrapping_mul(29).wrapping_add(11)) % 251) as u8)
        .collect();
    let started = Instant::now();

    let result = (|| -> Result<(), Box<dyn Error>> {
        for (index, chunk) in expected.chunks(CHUNK).enumerate() {
            let position = (index * CHUNK) as u64;
            let count = engine.write_writable_at(writer, position, chunk)?;
            if count != chunk.len() {
                return Err(format!(
                    "short Android writable chunk: wrote {count}, expected {}",
                    chunk.len()
                )
                .into());
            }
        }
        engine.flush_writable(writer)?;
        Ok(())
    })();
    let close = engine.close_writable(writer);
    result?;
    close?;
    let elapsed = started.elapsed().as_secs_f64();
    println!("writable_stream_bytes: {TOTAL}");
    println!("writable_stream_seconds: {elapsed:.4}");
    println!("writable_stream_flush_verified: true");

    if engine.write_writable_at(writer, 0, b"late write").is_ok() {
        return Err("closed writable handle unexpectedly allowed writes".into());
    }

    let mut request = VideoOpenRequest::new(&host, &share, &path, &username, &password);
    request.port = port;
    let reader = engine.open_video(request)?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        if engine.len(reader)? != TOTAL as u64 {
            return Err("OVERWRITE_IF did not truncate previous file contents".into());
        }
        for (index, chunk) in expected.chunks(CHUNK).enumerate() {
            let position = (index * CHUNK) as u64;
            let actual = engine.read_at(reader, position, chunk.len())?;
            if actual != chunk {
                return Err(format!("JNI writer READBACK mismatch at {position}").into());
            }
        }
        Ok(())
    })();
    let close = engine.close_video(reader);
    result?;
    close?;
    println!("writable_stream_overwrite_verified: true");
    println!("writable_stream_readback_verified: true");
    println!("writable_stream_closed_handle_verified: true");
    Ok(())
}
