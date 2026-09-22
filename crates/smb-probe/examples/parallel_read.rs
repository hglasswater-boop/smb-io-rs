#![forbid(unsafe_code)]

use std::error::Error;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    CloseOptions, Connection, FileOpenOptions, NegotiateConfig, PipelinedReadOptions,
    SessionConnection, SessionSetupConfig, TcpTransport, TcpTransportConfig, TreeConnectOptions,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or_else(usage)?;
    let port = args.next().ok_or_else(usage)?.parse::<u16>()?;
    let share = args.next().ok_or_else(usage)?;
    let path = args.next().ok_or_else(usage)?;
    let username = dash_to_empty(args.next().ok_or_else(usage)?);
    let password = dash_to_empty(args.next().ok_or_else(usage)?);
    let expected_len = args.next().ok_or_else(usage)?.parse::<usize>()?;
    if args.next().is_some() {
        return Err(usage().into());
    }

    let transport = TcpTransport::connect(&host, port, TcpTransportConfig::default()).await?;
    let mut connection = Connection::new(transport);
    let mut client_guid = [0u8; 16];
    let mut preauth_salt = [0u8; 32];
    getrandom::fill(&mut client_guid)?;
    getrandom::fill(&mut preauth_salt)?;
    connection
        .negotiate(&NegotiateConfig::modern(client_guid, preauth_salt.to_vec()))
        .await?;

    let mut session = establish_session(connection, &username, &password).await?;
    let unc = format!("\\\\{host}\\{share}");
    let tree = session
        .tree_connect(unc, TreeConnectOptions::default())
        .await?;
    let file = session
        .open_file(&tree, &path, FileOpenOptions::read_existing_random())
        .await?;

    if file.len() < expected_len as u64 {
        return Err(format!(
            "fixture is shorter than expected: CREATE={}, expected={expected_len}",
            file.len()
        )
        .into());
    }

    println!(
        "available_credits_before: {}",
        session.available_credits().unwrap_or(0)
    );
    let result = session
        .read_at_pipelined_with_stats(
            &file,
            0,
            expected_len,
            PipelinedReadOptions {
                chunk_size: 256 * 1024,
                max_in_flight: 8,
                credit_request: 64,
            },
        )
        .await?;

    if result.data.len() != expected_len {
        return Err(format!(
            "parallel READ length mismatch: got={}, expected={expected_len}",
            result.data.len()
        )
        .into());
    }
    for (index, byte) in result.data.iter().copied().enumerate() {
        let expected = ((index.wrapping_mul(31).wrapping_add(7)) % 251) as u8;
        if byte != expected {
            return Err(format!(
                "parallel READ content mismatch at offset {index}: got={byte}, expected={expected}"
            )
            .into());
        }
    }
    if result.stats.requests_sent < 2 {
        return Err("parallel READ fixture did not require multiple SMB READ requests".into());
    }
    if result.stats.peak_in_flight < 2 {
        return Err(format!(
            "READ requests never overlapped; peak_in_flight={}",
            result.stats.peak_in_flight
        )
        .into());
    }
    if result.stats.responses_completed != result.stats.requests_sent {
        return Err(format!(
            "READ request/response count mismatch: sent={}, completed={}",
            result.stats.requests_sent, result.stats.responses_completed
        )
        .into());
    }

    println!(
        "parallel_read_requests_sent: {}",
        result.stats.requests_sent
    );
    println!(
        "parallel_read_responses_completed: {}",
        result.stats.responses_completed
    );
    println!(
        "parallel_read_peak_in_flight: {}",
        result.stats.peak_in_flight
    );
    println!(
        "parallel_read_credit_stalls: {}",
        result.stats.credit_stalls
    );
    println!(
        "available_credits_after: {}",
        session.available_credits().unwrap_or(0)
    );
    println!("parallel_read_content_verified: true");
    println!("parallel_read_overlap_verified: true");

    session.close_file(file, CloseOptions::default()).await?;
    Ok(())
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
    "usage: cargo run -p smb-io-probe --example parallel_read -- <host> <port> <share> <path> <username|-> <password|-> <expected-len>"
        .to_string()
}
