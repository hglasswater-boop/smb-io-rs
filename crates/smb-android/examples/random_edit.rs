#![forbid(unsafe_code)]

//! Signed Samba proof that FILE_OPEN edits never truncate existing content on open,
//! and READ tracks EOF changes made through the same long-lived Android handle.
use std::error::Error;

use smb_io_android::{AndroidEngine, AndroidEngineConfig, SmbMutationRequest};

const MIB: usize = 1024 * 1024;
const PREEXISTING_BYTES: usize = 5 * MIB;
const PATTERN_BYTES: usize = 2 * MIB + 17;
const SHRUNK_BYTES: usize = MIB + 11;
const EXTENDED_BYTES: usize = 3 * MIB + 17;

fn request(
    host: &str,
    port: u16,
    share: &str,
    path: &str,
    user: &str,
    pass: &str,
) -> SmbMutationRequest {
    let mut request = SmbMutationRequest::new(host, share, path, user, pass);
    request.port = port;
    request
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or("missing host")?;
    let port = args.next().ok_or("missing port")?.parse::<u16>()?;
    let share = args.next().ok_or("missing share")?;
    let path = args.next().ok_or("missing path")?;
    let user = args.next().ok_or("missing user")?;
    let pass = args.next().ok_or("missing password")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let engine = AndroidEngine::new(AndroidEngineConfig::default())?;
    let missing = request(
        &host,
        port,
        &share,
        "missing-random-v8-not-created.bin",
        &user,
        &pass,
    );
    if let Ok(handle) = engine.open_random(missing) {
        let _ = engine.close_random(handle);
        return Err("FILE_OPEN unexpectedly created a missing file".into());
    }
    println!("random_missing_not_created_verified: true");

    let open = request(&host, port, &share, &path, &user, &pass);
    let handle = engine.open_random(open)?;
    let pattern: Vec<u8> = (0..PATTERN_BYTES)
        .map(|index| ((index.wrapping_mul(29).wrapping_add(17)) % 251) as u8)
        .collect();
    let result = (|| -> Result<(), Box<dyn Error>> {
        // The existing 5MiB zero file must still exist at its original EOF after FILE_OPEN.
        if engine.read_random_at(handle, (PREEXISTING_BYTES - 1) as u64, 1)? != [0u8] {
            return Err("random FILE_OPEN truncated the pre-existing file".into());
        }
        println!("random_nontruncating_open_verified: true");

        for (index, chunk) in pattern.chunks(MIB).enumerate() {
            let position = (index * MIB) as u64;
            if engine.write_random_at(handle, position, chunk)? != chunk.len() {
                return Err("random WRITE returned a short count".into());
            }
        }
        for (index, chunk) in pattern.chunks(MIB).enumerate() {
            if engine.read_random_at(handle, (index * MIB) as u64, chunk.len())? != chunk {
                return Err("random same-handle WRITE/READ mismatch".into());
            }
        }
        println!("random_positional_roundtrip_verified: true");

        engine.set_random_length(handle, SHRUNK_BYTES as u64)?;
        if !engine
            .read_random_at(handle, SHRUNK_BYTES as u64, 1)?
            .is_empty()
        {
            return Err("random SET_INFO shrink did not refresh cached EOF".into());
        }
        if engine.read_random_at(handle, (SHRUNK_BYTES - 1) as u64, 1)?
            != [pattern[SHRUNK_BYTES - 1]]
        {
            return Err("random shrink damaged the retained prefix".into());
        }
        println!("random_shrink_cached_eof_verified: true");

        engine.set_random_length(handle, EXTENDED_BYTES as u64)?;
        if engine.read_random_at(handle, (EXTENDED_BYTES - 1) as u64, 1)? != [0u8] {
            return Err("random extension did not expose zero-filled data on same handle".into());
        }
        if engine
            .read_random_at(handle, SHRUNK_BYTES as u64, MIB)?
            .iter()
            .any(|&byte| byte != 0)
        {
            return Err("random extension leaked discarded bytes".into());
        }
        println!("random_extend_zero_tail_verified: true");

        if engine.write_random_at(handle, (EXTENDED_BYTES - 2) as u64, b"OK")? != 2 {
            return Err("random trailing WRITE returned short count".into());
        }
        if engine.read_random_at(handle, (EXTENDED_BYTES - 2) as u64, 2)? != b"OK" {
            return Err("random same-handle trailing WRITE not visible".into());
        }
        engine.flush_random(handle)?;
        Ok(())
    })();
    let close = engine.close_random(handle);
    result?;
    close?;
    if engine.read_random_at(handle, 0, 1).is_ok() || engine.flush_random(handle).is_ok() {
        return Err("closed random handle unexpectedly accepted operations".into());
    }
    println!("random_closed_handle_rejected_verified: true");

    let opened = request(&host, port, &share, &path, &user, &pass);
    let handle = engine.open_random(opened)?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        if engine.read_random_at(handle, 0, MIB)? != pattern[..MIB]
            || engine.read_random_at(handle, MIB as u64, SHRUNK_BYTES - MIB)?
                != pattern[MIB..SHRUNK_BYTES]
        {
            return Err("reopen lost the retained prefix".into());
        }
        if engine.read_random_at(handle, (EXTENDED_BYTES - 2) as u64, 2)? != b"OK" {
            return Err("reopen lost flushed trailer".into());
        }
        if !engine
            .read_random_at(handle, EXTENDED_BYTES as u64, 1)?
            .is_empty()
        {
            return Err("reopen returned bytes past final EOF".into());
        }
        Ok(())
    })();
    let close = engine.close_random(handle);
    result?;
    close?;
    println!("random_reopen_flush_verified: true");
    Ok(())
}
