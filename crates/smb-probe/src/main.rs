#![forbid(unsafe_code)]

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use smb_io_android::{AndroidEngine, AndroidEngineConfig, VideoOpenRequest};
use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    CloseOptions, Connection, Dialect, FileOpenOptions, NegotiateConfig, SessionConnection,
    SessionSetupConfig, TcpTransport, TcpTransportConfig, TreeConnectOptions,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or_else(usage)?;

    match first.as_str() {
        "negotiate" => {
            let host = args.next().ok_or_else(usage)?;
            let port = parse_port(args.next())?;
            ensure_no_more(args)?;
            run_negotiate(&host, port).await
        }
        "verify" => {
            let request = VerifyRequest {
                host: args.next().ok_or_else(verify_usage)?,
                port: args.next().ok_or_else(verify_usage)?.parse::<u16>()?,
                share: args.next().ok_or_else(verify_usage)?,
                path: args.next().ok_or_else(verify_usage)?,
                username: dash_to_empty(args.next().ok_or_else(verify_usage)?),
                password: dash_to_empty(args.next().ok_or_else(verify_usage)?),
                offset: args.next().ok_or_else(verify_usage)?.parse::<u64>()?,
                expected: parse_hex(&args.next().ok_or_else(verify_usage)?)?,
            };
            ensure_no_more_with(args, verify_usage())?;
            run_verify(request).await
        }
        "verify-reconnect" => {
            let request = ReconnectVerifyRequest {
                host: args.next().ok_or_else(reconnect_usage)?,
                port: args.next().ok_or_else(reconnect_usage)?.parse::<u16>()?,
                share: args.next().ok_or_else(reconnect_usage)?,
                path: args.next().ok_or_else(reconnect_usage)?,
                username: dash_to_empty(args.next().ok_or_else(reconnect_usage)?),
                password: dash_to_empty(args.next().ok_or_else(reconnect_usage)?),
                first_offset: args.next().ok_or_else(reconnect_usage)?.parse::<u64>()?,
                first_expected: parse_hex(&args.next().ok_or_else(reconnect_usage)?)?,
                second_offset: args.next().ok_or_else(reconnect_usage)?.parse::<u64>()?,
                second_expected: parse_hex(&args.next().ok_or_else(reconnect_usage)?)?,
                ready_file: PathBuf::from(args.next().ok_or_else(reconnect_usage)?),
                resume_file: PathBuf::from(args.next().ok_or_else(reconnect_usage)?),
            };
            ensure_no_more_with(args, reconnect_usage())?;
            run_reconnect_verify_on_plain_thread(request)
        }
        host => {
            let port = parse_port(args.next())?;
            ensure_no_more(args)?;
            run_negotiate(host, port).await
        }
    }
}

struct VerifyRequest {
    host: String,
    port: u16,
    share: String,
    path: String,
    username: String,
    password: String,
    offset: u64,
    expected: Vec<u8>,
}

struct ReconnectVerifyRequest {
    host: String,
    port: u16,
    share: String,
    path: String,
    username: String,
    password: String,
    first_offset: u64,
    first_expected: Vec<u8>,
    second_offset: u64,
    second_expected: Vec<u8>,
    ready_file: PathBuf,
    resume_file: PathBuf,
}

async fn run_negotiate(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let (connection, peer) = negotiated_connection(host, port).await?;
    let negotiated = connection
        .negotiated()
        .ok_or("NEGOTIATE completed without negotiated parameters")?;

    println!("peer: {peer}");
    println!("dialect: {}", dialect_name(negotiated.dialect));
    println!("server_guid: {}", format_guid(negotiated.server_guid));
    println!("signing_enabled: {}", negotiated.signing_enabled());
    println!("signing_required: {}", negotiated.signing_required());
    println!("capabilities: 0x{:08X}", negotiated.capabilities);
    println!("initial_credits: {}", negotiated.initial_credits);
    println!("max_transact_size: {}", negotiated.max_transact_size);
    println!("max_read_size: {}", negotiated.max_read_size);
    println!("max_write_size: {}", negotiated.max_write_size);
    println!(
        "preauth_hash_active: {}",
        connection.preauth_hash().is_some()
    );

    Ok(())
}

async fn run_verify(request: VerifyRequest) -> Result<(), Box<dyn Error>> {
    if request.expected.is_empty() {
        return Err("verify expected hex payload must not be empty".into());
    }

    let (connection, peer) = negotiated_connection(&request.host, request.port).await?;
    let mut session = establish_session(connection, &request.username, &request.password).await?;
    let unc = format!("\\\\{}\\{}", request.host, request.share);
    let tree = session
        .tree_connect(unc, TreeConnectOptions::default())
        .await?;
    let file = session
        .open_file(
            &tree,
            &request.path,
            FileOpenOptions::read_existing_random(),
        )
        .await?;

    let expected_end = request
        .offset
        .checked_add(u64::try_from(request.expected.len())?)
        .ok_or("verification offset overflow")?;
    if expected_end > file.len() {
        return Err(format!(
            "verification range {:#x}..{:#x} exceeds file length {:#x}",
            request.offset,
            expected_end,
            file.len()
        )
        .into());
    }

    let direct = session
        .read_at(&file, request.offset, request.expected.len())
        .await?;
    if direct != request.expected {
        return Err(format!(
            "direct read mismatch at offset {:#x}: expected {}, got {}",
            request.offset,
            hex(&request.expected),
            hex(&direct)
        )
        .into());
    }

    let pipelined = session
        .read_at_pipelined(&file, request.offset, request.expected.len())
        .await?;
    if pipelined != request.expected {
        return Err(format!(
            "pipelined read mismatch at offset {:#x}: expected {}, got {}",
            request.offset,
            hex(&request.expected),
            hex(&pipelined)
        )
        .into());
    }

    if !session.read_at(&file, file.len(), 1).await?.is_empty() {
        return Err("direct read at EOF returned data".into());
    }
    if !session
        .read_at_pipelined(&file, file.len(), 1)
        .await?
        .is_empty()
    {
        return Err("pipelined read at EOF returned data".into());
    }

    println!("peer: {peer}");
    println!("mechanism: {:?}", session.mechanism());
    println!("signing_required: {}", session.signing_required());
    println!("file_len: {}", file.len());
    println!("verified_offset: {}", request.offset);
    println!("verified_bytes: {}", request.expected.len());

    session.close_file(file, CloseOptions::default()).await?;
    println!("verified: true");
    Ok(())
}

fn run_reconnect_verify_on_plain_thread(
    request: ReconnectVerifyRequest,
) -> Result<(), Box<dyn Error>> {
    let task = std::thread::spawn(move || {
        run_reconnect_verify(request).map_err(|error| error.to_string())
    });
    match task.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err("reconnect verifier thread panicked".into()),
    }
}

fn run_reconnect_verify(request: ReconnectVerifyRequest) -> Result<(), Box<dyn Error>> {
    if request.first_expected.is_empty() || request.second_expected.is_empty() {
        return Err("reconnect expected payloads must not be empty".into());
    }

    let engine = AndroidEngine::new(AndroidEngineConfig {
        read_reconnect_attempts: 6,
        reconnect_backoff: Duration::from_millis(250),
        ..AndroidEngineConfig::default()
    })?;
    let mut open = VideoOpenRequest::new(
        request.host,
        request.share,
        request.path,
        request.username,
        request.password,
    );
    open.port = request.port;
    let handle = engine.open_video(open)?;

    verify_engine_read(
        &engine,
        handle,
        request.first_offset,
        &request.first_expected,
    )?;
    std::fs::write(&request.ready_file, b"ready\n")?;
    println!("reconnect_ready: true");
    wait_for_file(&request.resume_file, Duration::from_secs(30))?;

    engine.seek(handle)?;
    verify_engine_read(
        &engine,
        handle,
        request.second_offset,
        &request.second_expected,
    )?;
    engine.close_video(handle)?;

    println!("reconnect_verified_offset: {}", request.second_offset);
    println!("reconnect_verified: true");
    Ok(())
}

fn verify_engine_read(
    engine: &AndroidEngine,
    handle: smb_io_android::VideoHandle,
    offset: u64,
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    let actual = engine.read_at(handle, offset, expected.len())?;
    if actual != expected {
        return Err(format!(
            "Android engine read mismatch at offset {offset:#x}: expected {}, got {}",
            hex(expected),
            hex(&actual)
        )
        .into());
    }
    Ok(())
}

fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(format!("timed out waiting for reconnect barrier {}", path.display()).into())
}

async fn negotiated_connection(
    host: &str,
    port: u16,
) -> Result<(Connection<TcpTransport>, std::net::SocketAddr), Box<dyn Error>> {
    let mut client_guid = [0u8; 16];
    let mut preauth_salt = [0u8; 32];
    getrandom::fill(&mut client_guid)?;
    getrandom::fill(&mut preauth_salt)?;

    let transport = TcpTransport::connect(host, port, TcpTransportConfig::default()).await?;
    let peer = transport.peer_addr()?;
    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig::modern(client_guid, preauth_salt.to_vec()))
        .await?;
    Ok((connection, peer))
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

fn parse_port(value: Option<String>) -> Result<u16, Box<dyn Error>> {
    match value {
        Some(value) => Ok(value.parse::<u16>()?),
        None => Ok(445),
    }
}

fn dash_to_empty(value: String) -> String {
    if value == "-" { String::new() } else { value }
}

fn ensure_no_more(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    ensure_no_more_with(&mut args, usage())
}

fn ensure_no_more_with(
    mut args: impl Iterator<Item = String>,
    message: String,
) -> Result<(), Box<dyn Error>> {
    if args.next().is_some() {
        return Err(message.into());
    }
    Ok(())
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

fn dialect_name(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Smb202 => "SMB 2.0.2",
        Dialect::Smb210 => "SMB 2.1",
        Dialect::Smb300 => "SMB 3.0",
        Dialect::Smb302 => "SMB 3.0.2",
        Dialect::Smb311 => "SMB 3.1.1",
    }
}

fn format_guid(guid: [u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in guid {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn usage() -> String {
    "usage: smb-io-probe [negotiate] <host> [port]\n       smb-io-probe verify <host> <port> <share> <path> <username|-> <password|-> <offset> <expected-hex>\n       smb-io-probe verify-reconnect <host> <port> <share> <path> <username|-> <password|-> <first-offset> <first-hex> <second-offset> <second-hex> <ready-file> <resume-file>"
        .to_string()
}

fn verify_usage() -> String {
    "usage: smb-io-probe verify <host> <port> <share> <path> <username|-> <password|-> <offset> <expected-hex>"
        .to_string()
}

fn reconnect_usage() -> String {
    "usage: smb-io-probe verify-reconnect <host> <port> <share> <path> <username|-> <password|-> <first-offset> <first-hex> <second-offset> <second-hex> <ready-file> <resume-file>"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialects_have_stable_display_names() {
        assert_eq!(dialect_name(Dialect::Smb311), "SMB 3.1.1");
        assert_eq!(dialect_name(Dialect::Smb202), "SMB 2.0.2");
    }

    #[test]
    fn guid_formatter_is_fixed_width_hex() {
        assert_eq!(format_guid([0xAB; 16]), "abababababababababababababababab");
    }

    #[test]
    fn hex_parser_accepts_mixed_case() {
        assert_eq!(parse_hex("00AaFf").unwrap(), vec![0x00, 0xaa, 0xff]);
    }

    #[test]
    fn dash_is_anonymous_cli_sentinel() {
        assert_eq!(dash_to_empty("-".to_string()), "");
        assert_eq!(dash_to_empty("alice".to_string()), "alice");
    }
}
