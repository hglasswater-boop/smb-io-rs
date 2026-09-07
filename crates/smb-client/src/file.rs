use smb_io_wire::{
    Command, CreateRequest, CreateResponse, FileId, HeaderId, Smb2Header, StatusField,
    create_disposition, create_options, desired_access, flags, impersonation_level, oplock_level,
    share_access,
};

use crate::{ClientError, SessionConnection, Transport, TreeHandle};

#[derive(Debug, Clone, Copy)]
pub struct FileOpenOptions {
    pub requested_oplock_level: u8,
    pub impersonation_level: u32,
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub credit_request: u16,
}

impl FileOpenOptions {
    pub const fn read_existing_random() -> Self {
        Self {
            requested_oplock_level: oplock_level::NONE,
            impersonation_level: impersonation_level::IMPERSONATION,
            desired_access: desired_access::GENERIC_READ,
            file_attributes: 0,
            share_access: share_access::READ | share_access::WRITE | share_access::DELETE,
            create_disposition: create_disposition::OPEN,
            create_options: create_options::NON_DIRECTORY_FILE | create_options::RANDOM_ACCESS,
            credit_request: 16,
        }
    }
}

impl Default for FileOpenOptions {
    fn default() -> Self {
        Self::read_existing_random()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle {
    file_id: FileId,
    tree_id: u32,
    path: String,
    allocation_size: u64,
    end_of_file: u64,
    file_attributes: u32,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    create_action: u32,
}

impl FileHandle {
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    pub fn tree_id(&self) -> u32 {
        self.tree_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn len(&self) -> u64 {
        self.end_of_file
    }

    pub fn is_empty(&self) -> bool {
        self.end_of_file == 0
    }

    pub fn allocation_size(&self) -> u64 {
        self.allocation_size
    }

    pub fn file_attributes(&self) -> u32 {
        self.file_attributes
    }

    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }

    pub fn last_access_time(&self) -> u64 {
        self.last_access_time
    }

    pub fn last_write_time(&self) -> u64 {
        self.last_write_time
    }

    pub fn change_time(&self) -> u64 {
        self.change_time
    }

    pub fn create_action(&self) -> u32 {
        self.create_action
    }
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    pub async fn open_file(
        &mut self,
        tree: &TreeHandle,
        path: impl Into<String>,
        options: FileOpenOptions,
    ) -> Result<FileHandle, ClientError> {
        let path = normalize_relative_path(path.into())?;
        if self.session_flags & smb_io_wire::session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }

        let request = CreateRequest {
            requested_oplock_level: options.requested_oplock_level,
            impersonation_level: options.impersonation_level,
            desired_access: options.desired_access,
            file_attributes: options.file_attributes,
            share_access: options.share_access,
            create_disposition: options.create_disposition,
            create_options: options.create_options,
            name: path.clone(),
        };
        let message_id = self.connection.message_ids.allocate(0)?;
        let mut request_message = request.encode_message(
            message_id,
            self.session_id,
            tree.tree_id(),
            options.credit_request,
        )?;
        if self.signing_required {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "CREATE requires signing but the session has no signing key",
            ))?;
            signing.sign(&mut request_message)?;
        }

        self.connection
            .transport
            .send_message(&request_message)
            .await?;
        let mut response_message = self.connection.transport.receive_message().await?;
        let header = Smb2Header::decode(&response_message)?;
        if header.command != Command::Create {
            return Err(ClientError::Protocol(
                "CREATE response command does not match request",
            ));
        }
        if header.message_id != message_id {
            return Err(ClientError::Protocol(
                "CREATE response MessageId does not match request",
            ));
        }
        if header.session_id != self.session_id {
            return Err(ClientError::Protocol(
                "CREATE response SessionId does not match session",
            ));
        }
        match header.id {
            HeaderId::Sync { tree_id, .. } if tree_id == tree.tree_id() => {}
            HeaderId::Sync { .. } => {
                return Err(ClientError::Protocol(
                    "CREATE response TreeId does not match tree",
                ));
            }
            HeaderId::Async { .. } => {
                return Err(ClientError::Protocol(
                    "CREATE response unexpectedly used async header form",
                ));
            }
        }
        match header.status {
            StatusField::Status(0) => {}
            StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
            StatusField::ChannelSequence { .. } => {
                return Err(ClientError::Protocol(
                    "CREATE response used request header form",
                ));
            }
        }

        if header.flags & flags::SIGNED != 0 {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "server signed CREATE without an available signing key",
            ))?;
            signing.verify(&mut response_message)?;
        } else if self.signing_required {
            return Err(ClientError::Protocol(
                "server omitted a required CREATE signature",
            ));
        }

        let response = CreateResponse::decode_message(&response_message)?;
        if response.file_id.is_zero() {
            return Err(ClientError::Protocol(
                "successful CREATE response has a zero FileId",
            ));
        }

        Ok(FileHandle {
            file_id: response.file_id,
            tree_id: tree.tree_id(),
            path,
            allocation_size: response.allocation_size,
            end_of_file: response.end_of_file,
            file_attributes: response.file_attributes,
            creation_time: response.creation_time,
            last_access_time: response.last_access_time,
            last_write_time: response.last_write_time,
            change_time: response.change_time,
            create_action: response.create_action,
        })
    }
}

fn normalize_relative_path(path: String) -> Result<String, ClientError> {
    if path.is_empty() {
        return Err(ClientError::Protocol("file path must not be empty"));
    }
    let normalized = path.replace('/', "\\");
    if normalized.starts_with('\\') {
        return Err(ClientError::Protocol(
            "file path must be relative to the connected tree",
        ));
    }
    if normalized.contains('\0') {
        return Err(ClientError::Protocol("file path must not contain NUL"));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_slashes_are_normalized_for_smb() {
        assert_eq!(
            normalize_relative_path("movies/sub/sample.mkv".to_string()).unwrap(),
            "movies\\sub\\sample.mkv"
        );
    }

    #[test]
    fn absolute_paths_are_rejected() {
        assert!(normalize_relative_path("\\movies\\sample.mkv".to_string()).is_err());
    }
}
