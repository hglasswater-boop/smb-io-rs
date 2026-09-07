#![forbid(unsafe_code)]

use std::error::Error;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    CloseOptions, Connection, DurableHandleV2Options, FileOpenOptions, NegotiateConfig,
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
    if args.next().is_some() {
        return Err(usage().into());
    }

    let mut client_guid = [0u8; 16];
    let mut preauth_salt = [0u8; 32];
    let mut create_guid = [0u8; 16];
    getrandom::fill(&mut client_guid)?;
    getrandom::fill(&mut preauth_salt)?;
    getrandom::fill(&mut create_guid)?;

    let transport = TcpTransport::connect(&host, port, TcpTransportConfig::default()).await?;
    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig::modern(client_guid, preauth_salt.to_vec()))
        .await?;
    let mut session = establish_session(connection, &username, &password).await?;
    let unc = format!("\\\\{host}\\{share}");
    let tree = session
        .tree_connect(unc, TreeConnectOptions::default())
        .await?;

    let durable = session
        .open_file_durable_v2(
            &tree,
            path,
            FileOpenOptions::read_existing_random(),
            create_guid,
            DurableHandleV2Options::default(),
        )
        .await?;

    let file_id = durable.file().file_id();
    let file_len = durable.file().len();
    let timeout_ms = durable.server_timeout_ms();
    let persistent = durable.persistent();

    println!("mechanism: {:?}", session.mechanism());
    println!("signing_required: {}", session.signing_required());
    println!("durable_timeout_ms: {timeout_ms}");
    println!("durable_persistent: {persistent}");
    println!("durable_file_id_persistent: {}", file_id.persistent);
    println!("durable_file_id_volatile: {}", file_id.volatile);
    println!("durable_file_len: {file_len}");
    println!("durable_granted: true");

    session
        .close_file(durable.into_file(), CloseOptions::default())
        .await?;
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
    if value == "-" { String::new() } else { value }
}

fn usage() -> String {
    "usage: durable_grant <host> <port> <share> <path> <username|-> <password|->".to_string()
}
