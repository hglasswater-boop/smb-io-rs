#![forbid(unsafe_code)]

use std::error::Error;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    CloseOptions, Connection, FileOpenOptions, NegotiateConfig, QueryDirectoryOptions,
    SessionConnection, SessionSetupConfig, TcpTransport, TcpTransportConfig, TreeConnectOptions,
};
use smb_io_fs::{decode_file_names_information, query_standard_information};

const FILE_NAMES_INFORMATION_CLASS: u8 = 0x0c;
const RESTART_SCANS: u8 = 0x01;
const QUERY_BUFFER_SIZE: u32 = 64 * 1024;

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
    let standard = query_standard_information(&mut session, &file).await?;
    if standard.directory {
        return Err("QUERY_INFO reported the fixture file as a directory".into());
    }
    if standard.end_of_file != file.len() {
        return Err(format!(
            "QUERY_INFO EndOfFile mismatch: CREATE={}, QUERY_INFO={}",
            file.len(),
            standard.end_of_file
        )
        .into());
    }
    println!("query_info_end_of_file: {}", standard.end_of_file);
    println!("query_info_verified: true");
    session.close_file(file, CloseOptions::default()).await?;

    println!("directory_root_open_start: true");
    let directory = session
        .open_file(&tree, "", FileOpenOptions::read_existing_directory())
        .await?;
    println!("directory_root_open_verified: true");

    println!("query_directory_first_start: true");
    let mut first_options =
        QueryDirectoryOptions::new(FILE_NAMES_INFORMATION_CLASS, "*", QUERY_BUFFER_SIZE);
    first_options.flags = RESTART_SCANS;
    let first_buffer = session.query_directory(&directory, first_options).await?;
    let mut entries = decode_file_names_information(&first_buffer)?;
    println!("query_directory_first_bytes: {}", first_buffer.len());
    println!("query_directory_first_entries: {}", entries.len());
    println!("query_directory_first_verified: true");

    println!("query_directory_continuation_start: true");
    let continuation_options =
        QueryDirectoryOptions::new(FILE_NAMES_INFORMATION_CLASS, "", QUERY_BUFFER_SIZE);
    let continuation_buffer = session
        .query_directory(&directory, continuation_options)
        .await?;
    println!(
        "query_directory_continuation_bytes: {}",
        continuation_buffer.len()
    );
    if !continuation_buffer.is_empty() {
        entries.extend(decode_file_names_information(&continuation_buffer)?);
    }
    println!("query_directory_continuation_verified: true");

    let expected_name = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .ok_or("fixture path has no file name")?;
    if !entries.iter().any(|entry| entry.name == expected_name) {
        let names = entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(
            format!("QUERY_DIRECTORY did not return {expected_name:?}; entries=[{names}]").into(),
        );
    }
    println!("query_directory_entries: {}", entries.len());
    println!("query_directory_verified: true");
    session
        .close_file(directory, CloseOptions::default())
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
    "usage: cargo run -p smb-io-probe --example query -- <host> <port> <share> <path> <username|-> <password|->"
        .to_string()
}
