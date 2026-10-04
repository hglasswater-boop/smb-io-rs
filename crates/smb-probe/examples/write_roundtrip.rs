#![forbid(unsafe_code)]

use std::error::Error;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    CloseOptions, Connection, FileOpenOptions, NegotiateConfig, SessionConnection,
    SessionSetupConfig, TcpTransport, TcpTransportConfig, TreeConnectOptions,
};

const PATCH_OFFSET: usize = 257 * 1024 + 13;
const PATCH: &[u8] = b"phase8-positional-write";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or_else(usage)?;
    let port = args.next().ok_or_else(usage)?.parse::<u16>()?;
    let share = args.next().ok_or_else(usage)?;
    let path = args.next().ok_or_else(usage)?;
    let username = dash_to_empty(args.next().ok_or_else(usage)?);
    let password = dash_to_empty(args.next().ok_or_else(usage)?);
    let size = args.next().ok_or_else(usage)?.parse::<usize>()?;
    if args.next().is_some() || size <= PATCH_OFFSET + PATCH.len() {
        return Err(usage().into());
    }

    let transport = TcpTransport::connect(&host, port, TcpTransportConfig::default()).await?;
    let mut connection = Connection::new(transport);
    let mut client_guid = [0u8; 16];
    let mut preauth_salt = [0u8; 32];
    getrandom::fill(&mut client_guid)?;
    getrandom::fill(&mut preauth_salt)?;
    connection
        .negotiate(&NegotiateConfig::modern(
            client_guid,
            preauth_salt.to_vec(),
        ))
        .await?;

    let mut session = establish_session(connection, &username, &password).await?;
    let unc = format!("\\\\{host}\\{share}");
    let tree = session
        .tree_connect(unc, TreeConnectOptions::default())
        .await?;

    let file = session
        .open_file(
            &tree,
            &path,
            FileOpenOptions::create_or_truncate_random(),
        )
        .await?;
    let mut expected = make_pattern(size);
    let written = session.write_at(&file, 0, &expected).await?;
    if written != expected.len() {
        return Err(format!(
            "large WRITE length mismatch: wrote={written}, expected={}",
            expected.len()
        )
        .into());
    }

    let patch_written = session.write_at(&file, PATCH_OFFSET as u64, PATCH).await?;
    if patch_written != PATCH.len() {
        return Err(format!(
            "positional WRITE length mismatch: wrote={patch_written}, expected={}",
            PATCH.len()
        )
        .into());
    }
    expected[PATCH_OFFSET..PATCH_OFFSET + PATCH.len()].copy_from_slice(PATCH);
    session.close_file(file, CloseOptions::default()).await?;

    let file = session
        .open_file(&tree, &path, FileOpenOptions::read_existing_random())
        .await?;
    if file.len() != size as u64 {
        return Err(format!(
            "WRITE file length mismatch: CREATE={}, expected={size}",
            file.len()
        )
        .into());
    }
    let actual = session.read_at(&file, 0, size).await?;
    if actual != expected {
        let mismatch = actual
            .iter()
            .zip(expected.iter())
            .position(|(actual, expected)| actual != expected)
            .unwrap_or(actual.len().min(expected.len()));
        return Err(format!("WRITE round-trip mismatch at offset {mismatch}").into());
    }
    session.close_file(file, CloseOptions::default()).await?;

    println!("write_large_bytes: {size}");
    println!("write_positional_offset: {PATCH_OFFSET}");
    println!("write_create_verified: true");
    println!("write_large_verified: true");
    println!("write_positional_verified: true");
    println!("write_roundtrip_verified: true");
    Ok(())
}

fn make_pattern(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| ((index.wrapping_mul(29).wrapping_add(11)) % 251) as u8)
        .collect()
}

async fn establish_session(
    connection: Connection<TcpTransport>,
    username: &str,
    password: &str,
) -> Result<SessionConnection<TcpTransport>, Box<dyn Error>> {
    if username.is_empty() {
        let mut auth = AnonymousNtlmProvider::new();
        Ok(connection
            .session_setup(&mut auth, SessionSetupConfig::default())
            .await?)
    } else {
        let credentials = NtlmCredentials::new(username, password);
        let mut auth = NtlmV2Provider::new(credentials);
        Ok(connection
            .session_setup(&mut auth, SessionSetupConfig::default())
            .await?)
    }
}

fn dash_to_empty(value: String) -> String {
    if value == "-" {
        String::new()
    } else {
        value
    }
}

fn usage() -> String {
    "usage: cargo run -p smb-io-probe --example write_roundtrip -- <host> <port> <share> <path> <username|-> <password|-> <size>"
        .to_string()
}
