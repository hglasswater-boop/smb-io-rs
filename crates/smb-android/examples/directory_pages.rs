#![forbid(unsafe_code)]

//! Live Samba contract: one directory containing >1 SMB response must enumerate fully,
//! without resetting the scan cursor or buffering the whole folder in one JNI payload.
use std::collections::HashSet;
use std::error::Error;

use smb_io_android::{AndroidEngine, AndroidEngineConfig, SmbMutationRequest};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or("host required")?;
    let port = args.next().ok_or("port required")?.parse::<u16>()?;
    let share = args.next().ok_or("share required")?;
    let directory = args.next().ok_or("directory required; use - for root")?;
    let username = args.next().ok_or("username required")?;
    let password = args.next().ok_or("password required")?;
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let mut request = SmbMutationRequest::new(
        host,
        share,
        if directory == "-" { "" } else { &directory },
        username,
        password,
    );
    request.port = port;

    let engine = AndroidEngine::new(AndroidEngineConfig::default())?;
    let handle = engine.open_directory(request)?;
    let result = (|| -> Result<(usize, usize), Box<dyn Error>> {
        let mut names = HashSet::new();
        let mut pages = 0;
        loop {
            let page = engine.read_directory_page(handle)?;
            if page.len() < 8 || &page[..4] != b"XFL1" {
                return Err("bad directory page header".into());
            }
            let count = u32::from_le_bytes(page[4..8].try_into()?) as usize;
            if count == 0 {
                if page.len() != 8 {
                    return Err("EOF page has trailing data".into());
                }
                break;
            }
            pages += 1;
            let mut at = 8usize;
            for _ in 0..count {
                if at + 4 > page.len() {
                    return Err("truncated directory name length".into());
                }
                let length = u32::from_le_bytes(page[at..at + 4].try_into()?) as usize;
                at += 4;
                let end = at.checked_add(length).ok_or("directory length overflow")?;
                if end + 28 > page.len() {
                    return Err("truncated directory record".into());
                }
                let name = std::str::from_utf8(&page[at..end])?.to_owned();
                if !names.insert(name) {
                    return Err("directory entry duplicated across pages".into());
                }
                at = end + 28;
            }
            if at != page.len() {
                return Err("directory page has trailing bytes".into());
            }
        }
        Ok((names.len(), pages))
    })();

    let closed = engine.close_directory(handle);
    let (files, pages) = result?;
    closed?;

    if files < 1_000 || pages < 2 {
        return Err(format!(
            "expected >=1000 files across 2+ pages, got files={files}, pages={pages}"
        )
        .into());
    }
    println!("directory_pages_entries: {files}");
    println!("directory_pages_count: {pages}");
    println!("directory_pages_verified: true");
    Ok(())
}
