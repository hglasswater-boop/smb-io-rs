use core::fmt;

use smb_io_client::{
    ClientError, CloseOptions, FileOpenOptions, SessionConnection, SetInfoOptions, Transport,
    TreeHandle,
};
use smb_io_wire::{FileDispositionInformation, FileRenameInformation, set_info_class};

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;

#[derive(Debug)]
pub enum FsMutationError {
    InvalidPath(&'static str),
    NotFound,
    AlreadyExists,
    AccessDenied,
    SharingViolation,
    DirectoryNotEmpty,
    CannotDelete,
    IsDirectory,
    NotDirectory,
    Client(ClientError),
}

impl fmt::Display for FsMutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(message) => write!(f, "invalid SMB path: {message}"),
            Self::NotFound => f.write_str("SMB path was not found"),
            Self::AlreadyExists => f.write_str("SMB destination already exists"),
            Self::AccessDenied => f.write_str("SMB mutation was denied"),
            Self::SharingViolation => f.write_str("SMB mutation hit a sharing violation"),
            Self::DirectoryNotEmpty => f.write_str("SMB directory is not empty"),
            Self::CannotDelete => f.write_str("SMB server refused deletion"),
            Self::IsDirectory => f.write_str("SMB path is a directory"),
            Self::NotDirectory => f.write_str("SMB path is not a directory"),
            Self::Client(error) => write!(f, "SMB mutation failed: {error}"),
        }
    }
}

impl std::error::Error for FsMutationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ClientError> for FsMutationError {
    fn from(value: ClientError) -> Self {
        map_client_error(value)
    }
}

pub async fn mkdir<T>(
    session: &mut SessionConnection<T>,
    tree: &TreeHandle,
    path: impl Into<String>,
) -> Result<(), FsMutationError>
where
    T: Transport,
{
    let path = normalize_mutation_path(path.into())?;
    let directory = session
        .open_file(tree, path, FileOpenOptions::create_directory())
        .await
        .map_err(map_client_error)?;
    session
        .close_file(directory, CloseOptions::default())
        .await
        .map_err(map_client_error)?;
    Ok(())
}

pub async fn rename<T>(
    session: &mut SessionConnection<T>,
    tree: &TreeHandle,
    source: impl Into<String>,
    destination: impl Into<String>,
    replace_if_exists: bool,
) -> Result<(), FsMutationError>
where
    T: Transport,
{
    let source = normalize_mutation_path(source.into())?;
    let destination = normalize_mutation_path(destination.into())?;
    let file = session
        .open_file(tree, source, FileOpenOptions::mutation_existing())
        .await
        .map_err(map_client_error)?;
    let buffer = FileRenameInformation::new(destination, replace_if_exists).encode()?;
    mutate_then_close(
        session,
        file,
        SetInfoOptions::file(set_info_class::FILE_RENAME_INFORMATION, buffer),
    )
    .await
}

pub async fn delete_file<T>(
    session: &mut SessionConnection<T>,
    tree: &TreeHandle,
    path: impl Into<String>,
) -> Result<(), FsMutationError>
where
    T: Transport,
{
    let path = normalize_mutation_path(path.into())?;
    let file = session
        .open_file(tree, path, FileOpenOptions::mutation_existing_file())
        .await
        .map_err(map_client_error)?;
    mark_delete_pending_then_close(session, file).await
}

pub async fn delete_directory<T>(
    session: &mut SessionConnection<T>,
    tree: &TreeHandle,
    path: impl Into<String>,
) -> Result<(), FsMutationError>
where
    T: Transport,
{
    let path = normalize_mutation_path(path.into())?;
    let directory = session
        .open_file(tree, path, FileOpenOptions::mutation_existing_directory())
        .await
        .map_err(map_client_error)?;
    mark_delete_pending_then_close(session, directory).await
}

async fn mark_delete_pending_then_close<T>(
    session: &mut SessionConnection<T>,
    file: smb_io_client::FileHandle,
) -> Result<(), FsMutationError>
where
    T: Transport,
{
    let buffer = FileDispositionInformation::delete().encode();
    mutate_then_close(
        session,
        file,
        SetInfoOptions::file(set_info_class::FILE_DISPOSITION_INFORMATION, buffer),
    )
    .await
}

async fn mutate_then_close<T>(
    session: &mut SessionConnection<T>,
    file: smb_io_client::FileHandle,
    options: SetInfoOptions,
) -> Result<(), FsMutationError>
where
    T: Transport,
{
    let mutation_result = session.set_info(&file, options).await;
    let close_result = session.close_file(file, CloseOptions::default()).await;
    match (mutation_result, close_result) {
        (Err(error), _) => Err(map_client_error(error)),
        (Ok(()), Err(error)) => Err(map_client_error(error)),
        (Ok(()), Ok(_)) => Ok(()),
    }
}

fn normalize_mutation_path(path: String) -> Result<String, FsMutationError> {
    if path.is_empty() {
        return Err(FsMutationError::InvalidPath("path must not be empty"));
    }
    if path.starts_with('\\') || path.starts_with('/') {
        return Err(FsMutationError::InvalidPath(
            "path must be relative to the connected share",
        ));
    }
    if path.contains('\0') {
        return Err(FsMutationError::InvalidPath("path must not contain NUL"));
    }

    let replaced = path.replace('/', "\\");
    let mut components = Vec::new();
    for component in replaced.split('\\') {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." {
            return Err(FsMutationError::InvalidPath(
                "dot path components are not allowed",
            ));
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err(FsMutationError::InvalidPath("path must name an entry"));
    }
    Ok(components.join("\\"))
}

fn map_client_error(error: ClientError) -> FsMutationError {
    match error {
        ClientError::ServerStatus(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => {
            FsMutationError::NotFound
        }
        ClientError::ServerStatus(STATUS_OBJECT_NAME_COLLISION) => FsMutationError::AlreadyExists,
        ClientError::ServerStatus(STATUS_ACCESS_DENIED) => FsMutationError::AccessDenied,
        ClientError::ServerStatus(STATUS_SHARING_VIOLATION) => FsMutationError::SharingViolation,
        ClientError::ServerStatus(STATUS_DIRECTORY_NOT_EMPTY) => FsMutationError::DirectoryNotEmpty,
        ClientError::ServerStatus(STATUS_CANNOT_DELETE) => FsMutationError::CannotDelete,
        ClientError::ServerStatus(STATUS_FILE_IS_A_DIRECTORY) => FsMutationError::IsDirectory,
        ClientError::ServerStatus(STATUS_NOT_A_DIRECTORY) => FsMutationError::NotDirectory,
        other => FsMutationError::Client(other),
    }
}

impl From<smb_io_wire::WireError> for FsMutationError {
    fn from(value: smb_io_wire::WireError) -> Self {
        FsMutationError::Client(ClientError::Wire(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_share_relative_paths() {
        assert_eq!(
            normalize_mutation_path("dir//sub/日本語.txt".to_string()).unwrap(),
            "dir\\sub\\日本語.txt"
        );
    }

    #[test]
    fn rejects_absolute_and_parent_paths() {
        assert!(normalize_mutation_path("\\absolute".to_string()).is_err());
        assert!(normalize_mutation_path("dir/../escape".to_string()).is_err());
    }

    #[test]
    fn maps_file_management_statuses() {
        assert!(matches!(
            map_client_error(ClientError::ServerStatus(STATUS_OBJECT_NAME_COLLISION)),
            FsMutationError::AlreadyExists
        ));
        assert!(matches!(
            map_client_error(ClientError::ServerStatus(STATUS_DIRECTORY_NOT_EMPTY)),
            FsMutationError::DirectoryNotEmpty
        ));
    }
}
