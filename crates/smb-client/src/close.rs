use smb_io_wire::{
    CloseRequest, CloseResponse, Command, HeaderId, Smb2Header, StatusField, close_flags, flags,
    session_flags,
};

use crate::{ClientError, FileHandle, SessionConnection, Transport};

#[derive(Debug, Clone, Copy)]
pub struct CloseOptions {
    pub postquery_attributes: bool,
    pub credit_request: u16,
}

impl Default for CloseOptions {
    fn default() -> Self {
        Self {
            postquery_attributes: false,
            credit_request: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseInfo {
    pub has_postquery_attributes: bool,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Closes an open SMB file handle and consumes the local `FileHandle` so it cannot be reused.
    pub async fn close_file(
        &mut self,
        file: FileHandle,
        options: CloseOptions,
    ) -> Result<CloseInfo, ClientError> {
        if self.session_flags & session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }

        let mut request = CloseRequest::new(file.file_id());
        if options.postquery_attributes {
            request.flags |= close_flags::POSTQUERY_ATTRIB;
        }
        let credit_charge = self.connection.single_request_credit_charge()?;
        let credit_request = self
            .connection
            .reserve_credits(credit_charge, options.credit_request)?;
        let message_id = self.connection.message_ids.allocate(credit_charge)?;
        let mut request_message = request.encode_message(
            message_id,
            self.session_id,
            file.tree_id(),
            credit_charge,
            credit_request,
        )?;
        if self.signing_required {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "CLOSE requires signing but the session has no signing key",
            ))?;
            signing.sign(&mut request_message)?;
        }

        self.connection
            .transport
            .send_message(&request_message)
            .await?;
        let mut response_message = self.connection.transport.receive_message().await?;
        let header = Smb2Header::decode(&response_message)?;
        if header.command != Command::Close {
            return Err(ClientError::Protocol(
                "CLOSE response command does not match request",
            ));
        }
        if header.message_id != message_id {
            return Err(ClientError::Protocol(
                "CLOSE response MessageId does not match request",
            ));
        }
        if header.session_id != self.session_id {
            return Err(ClientError::Protocol(
                "CLOSE response SessionId does not match session",
            ));
        }
        match header.id {
            HeaderId::Sync { tree_id, .. } if tree_id == file.tree_id() => {}
            HeaderId::Sync { .. } => {
                return Err(ClientError::Protocol(
                    "CLOSE response TreeId does not match file tree",
                ));
            }
            HeaderId::Async { .. } => {
                return Err(ClientError::Protocol(
                    "CLOSE response unexpectedly used async header form",
                ));
            }
        }
        self.connection.grant_credits(header.credits)?;
        match header.status {
            StatusField::Status(0) => {}
            StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
            StatusField::ChannelSequence { .. } => {
                return Err(ClientError::Protocol(
                    "CLOSE response used request header form",
                ));
            }
        }

        if header.flags & flags::SIGNED != 0 {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "server signed CLOSE without an available signing key",
            ))?;
            signing.verify(&mut response_message)?;
        } else if self.signing_required {
            return Err(ClientError::Protocol(
                "server omitted a required CLOSE signature",
            ));
        }

        let response = CloseResponse::decode_message(&response_message)?;
        Ok(CloseInfo {
            has_postquery_attributes: response.has_postquery_attributes(),
            creation_time: response.creation_time,
            last_access_time: response.last_access_time,
            last_write_time: response.last_write_time,
            change_time: response.change_time,
            allocation_size: response.allocation_size,
            end_of_file: response.end_of_file,
            file_attributes: response.file_attributes,
        })
    }
}
