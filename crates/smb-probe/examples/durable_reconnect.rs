#![forbid(unsafe_code)]

use std::error::Error;
use std::time::Duration;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    Connection, DurableHandleV2Options, FileOpenOptions, NegotiateConfig, SessionConnection,
    SessionSetupConfig, TcpTransport, TcpTransportConfig, TreeConnectOptions,
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
    let expected = args.next().ok_or_else(usage)?.into_bytes();
    if expected.is_empty() || args.next().is_some() {
        return Err(usage().into());
    }

    let mut client_guid = [0u8; 16];
    let mut create_guid = [0u8; 16];
    getrandom::fill(&mut client_guid)?;
    getrandom::fill(&mut create_guid)?;

    let mut first_session =
        connect_session(&host, port, client_guid, &username, &password).await?;
    let unc = format!("\\\\{host}\\{share}");
    let first_tree = first_session
        .tree_connect(&unc, TreeConnectOptions::default())
        .await?;
    let durable = first_session
        .open_file_durable_v2(
            &first_tree,
            &path,
            FileOpenOptions::read_existing_random(),
            create_guid,
            DurableHandleV2Options::default(),
        )
        .await?;

    verify_read(&mut first_session, durable.file(), &expected).await?;
    let original_file_id = durable.file().file_id();
    let original_oplock = durable.file().oplock_level();
    println!("durable_initial_read: true");
    println!("durable_initial_oplock: {original_oplock}");

    // Deliberately do not send CLOSE/TREE_DISCONNECT/LOGOFF. Dropping the session closes only the
    // client transport, leaving the server-side durable open eligible for DH2C reconnect.
    drop(first_session);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut second_session =
        connect_session(&host, port, client_guid, &username, &password).await?;
    let second_tree = second_session
        .tree_connect(unc, TreeConnectOptions::default())
        .await?;
    let reconnected = second_session
        .reconnect_file_durable_v2(&second_tree, &durable)
        .await?;

    verify_read(&mut second_session, reconnected.file(), &expected).await?;
    let reconnected_file_id = reconnected.file().file_id();
    println!(
        "durable_original_file_id: {}:{}",
        original_file_id.persistent, original_file_id.volatile
    );
    println!(
        "durable_reconnected_file_id: {}:{}",
        reconnected_file_id.persistent, reconnected_file_id.volatile
    );
    println!(
        "durable_reconnected_oplock: {}",
        reconnected.file().oplock_level()
    );
    println!("durable_reconnect_verified: true");

    // A clean close after successful recovery proves the reconnected FileId is usable for normal
    // SMB operations, not only for the reconnect CREATE itself.
    second_session
        .close_file(reconnected.into_file(), smb_io_client::CloseOptions::default())
        .await?;
    Ok(())
}

async fn connect_session(
    host: &str,
    port: u16,
    client_guid: [u8; 16],
    username: &str,
    password: &str,
) -> Result<SessionConnection<TcpTransport>, Box<dyn Error>> {
    let mut preauth_salt = [0u8; 32];
    getrandom::fill(&mut preauth_salt)?;
    let transport = TcpTransport::connect(host, port, TcpTransportConfig::default()).await?;
    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig::modern(client_guid, preauth_salt.to_vec()))
        .await?;

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

async fn verify_read(
    session: &mut SessionConnection<TcpTransport>,
    file: &smb_io_client::FileHandle,
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    let actual = session.read_at(file, 0, expected.len()).await?;
    if actual != expected {
        return Err(format!(
            "durable read mismatch: expected {:?}, got {:?}",
            expected, actual
        )
        .into());
    }
    Ok(())
}

fn dash_to_empty(value: String) -> String {
    if value == "-" { String::new() } else { value }
}

fn usage() -> String {
    "usage: durable_reconnect <host> <port> <share> <path> <username|-> <password|-> <expected-ascii>"
        .to_string()
}
