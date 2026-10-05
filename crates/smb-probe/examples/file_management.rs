#![forbid(unsafe_code)]

use std::error::Error;

use smb_io_auth::{AnonymousNtlmProvider, NtlmCredentials, NtlmV2Provider};
use smb_io_client::{
    CloseOptions, Connection, FileOpenOptions, NegotiateConfig, SessionConnection,
    SessionSetupConfig, TcpTransport, TcpTransportConfig, TreeConnectOptions, TreeHandle,
};
use smb_io_fs::{
    FsMutationError, delete_directory, delete_file, mkdir, query_standard_information,
    read_directory_names, rename,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let host = args.next().ok_or_else(usage)?;
    let port = args.next().ok_or_else(usage)?.parse::<u16>()?;
    let share = args.next().ok_or_else(usage)?;
    let base = args.next().ok_or_else(usage)?;
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
    let tree = session
        .tree_connect(
            format!("\\\\{host}\\{share}"),
            TreeConnectOptions::default(),
        )
        .await?;

    let root = format!("{base}-日本語");
    mkdir(&mut session, &tree, &root).await?;
    require_name(&mut session, &tree, "", &root, true).await?;
    require_standard_info(&mut session, &tree, &root, true).await?;
    println!("mkdir_verified: true");

    let source = format!("{root}\\source.txt");
    create_file(&mut session, &tree, &source, b"phase9-source").await?;
    let renamed = format!("{root}\\改名済み.txt");
    rename(&mut session, &tree, &source, &renamed, false).await?;
    require_name(&mut session, &tree, &root, "source.txt", false).await?;
    require_name(&mut session, &tree, &root, "改名済み.txt", true).await?;
    require_standard_info(&mut session, &tree, &renamed, false).await?;
    println!("unicode_rename_verified: true");

    let collision_source = format!("{root}\\collision-source.txt");
    let collision_target = format!("{root}\\collision-target.txt");
    create_file(&mut session, &tree, &collision_source, b"source").await?;
    create_file(&mut session, &tree, &collision_target, b"target").await?;
    match rename(
        &mut session,
        &tree,
        &collision_source,
        &collision_target,
        false,
    )
    .await
    {
        Err(FsMutationError::AlreadyExists) => {}
        other => return Err(format!("expected rename collision, got {other:?}").into()),
    }
    println!("collision_verified: true");

    rename(
        &mut session,
        &tree,
        &collision_source,
        &collision_target,
        true,
    )
    .await?;
    require_name(&mut session, &tree, &root, "collision-source.txt", false).await?;
    require_name(&mut session, &tree, &root, "collision-target.txt", true).await?;
    require_standard_info(&mut session, &tree, &collision_target, false).await?;
    println!("replace_existing_verified: true");

    delete_file(&mut session, &tree, &renamed).await?;
    require_name(&mut session, &tree, &root, "改名済み.txt", false).await?;
    delete_file(&mut session, &tree, &collision_target).await?;
    println!("file_delete_verified: true");

    let nonempty = format!("{root}\\nonempty");
    mkdir(&mut session, &tree, &nonempty).await?;
    let child = format!("{nonempty}\\child.txt");
    create_file(&mut session, &tree, &child, b"child").await?;
    match delete_directory(&mut session, &tree, &nonempty).await {
        Err(FsMutationError::DirectoryNotEmpty) => {}
        other => return Err(format!("expected non-empty directory failure, got {other:?}").into()),
    }
    println!("nonempty_directory_guard_verified: true");

    delete_file(&mut session, &tree, &child).await?;
    delete_directory(&mut session, &tree, &nonempty).await?;
    delete_directory(&mut session, &tree, &root).await?;
    require_name(&mut session, &tree, "", &root, false).await?;
    println!("directory_delete_verified: true");
    println!("query_info_verified: true");
    println!("phase9_verified: true");
    Ok(())
}

async fn create_file(
    session: &mut SessionConnection<TcpTransport>,
    tree: &TreeHandle,
    path: &str,
    data: &[u8],
) -> Result<(), Box<dyn Error>> {
    let file = session
        .open_file(tree, path, FileOpenOptions::create_or_truncate_random())
        .await?;
    let written = session.write_at(&file, 0, data).await?;
    if written != data.len() {
        return Err(format!("short fixture write: {written}/{}", data.len()).into());
    }
    session.close_file(file, CloseOptions::default()).await?;
    Ok(())
}

async fn require_name(
    session: &mut SessionConnection<TcpTransport>,
    tree: &TreeHandle,
    directory: &str,
    name: &str,
    expected: bool,
) -> Result<(), Box<dyn Error>> {
    let dir = session
        .open_file(tree, directory, FileOpenOptions::read_existing_directory())
        .await?;
    let entries = read_directory_names(session, &dir).await?;
    session.close_file(dir, CloseOptions::default()).await?;
    let present = entries.iter().any(|entry| entry.name == name);
    if present != expected {
        return Err(format!(
            "directory verification mismatch: directory={directory:?} name={name:?} expected={expected}"
        )
        .into());
    }
    Ok(())
}

async fn require_standard_info(
    session: &mut SessionConnection<TcpTransport>,
    tree: &TreeHandle,
    path: &str,
    directory: bool,
) -> Result<(), Box<dyn Error>> {
    let options = if directory {
        FileOpenOptions::read_existing_directory()
    } else {
        FileOpenOptions::read_existing_random()
    };
    let file = session.open_file(tree, path, options).await?;
    let info = query_standard_information(session, &file).await?;
    session.close_file(file, CloseOptions::default()).await?;
    if info.directory != directory {
        return Err(format!(
            "QUERY_INFO type mismatch: path={path:?} directory={} expected={directory}",
            info.directory
        )
        .into());
    }
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
    "usage: cargo run -p smb-io-probe --example file_management -- <host> <port> <share> <base> <username|-> <password|->"
        .to_string()
}
