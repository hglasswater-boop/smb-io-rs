use smb_io_wire::{
    Command, Dialect, HeaderId, Smb2Header, StatusField, TreeConnectRequest, TreeConnectResponse,
    flags, session_flags, tree_connect_flags,
};

use crate::{ClientError, SessionConnection, Transport};

#[derive(Debug, Clone, Copy)]
pub struct TreeConnectOptions {
    pub flags: u16,
    pub credit_request: u16,
}

impl Default for TreeConnectOptions {
    fn default() -> Self {
        Self {
            flags: 0,
            credit_request: 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHandle {
    tree_id: u32,
    path: String,
    share_type: u8,
    share_flags: u32,
    capabilities: u32,
    maximal_access: u32,
}

impl TreeHandle {
    pub fn tree_id(&self) -> u32 {
        self.tree_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn share_type(&self) -> u8 {
        self.share_type
    }

    pub fn share_flags(&self) -> u32 {
        self.share_flags
    }

    pub fn capabilities(&self) -> u32 {
        self.capabilities
    }

    pub fn maximal_access(&self) -> u32 {
        self.maximal_access
    }
}

impl<T> SessionConnection<T>
where
    T: Transport,
{
    /// Connects the authenticated session to a UNC share such as `\\server\video`.
    ///
    /// SMB 3.1.1 TREE_CONNECT is signed for authenticated non-encrypted sessions even when the
    /// general session signing policy is optional, matching the dialect-specific client rules.
    pub async fn tree_connect(
        &mut self,
        path: impl Into<String>,
        options: TreeConnectOptions,
    ) -> Result<TreeHandle, ClientError> {
        let path = path.into();
        let negotiated = self.connection.negotiated.as_ref().ok_or(ClientError::Protocol(
            "TREE_CONNECT requires negotiated parameters",
        ))?;
        if negotiated.dialect != Dialect::Smb311 && options.flags != 0 {
            return Err(ClientError::Protocol(
                "TREE_CONNECT flags are only valid for SMB 3.1.1",
            ));
        }
        if options.flags & tree_connect_flags::EXTENSION_PRESENT != 0 {
            return Err(ClientError::Protocol(
                "TREE_CONNECT extensions are not implemented yet",
            ));
        }
        if self.session_flags & session_flags::ENCRYPT_DATA != 0 {
            return Err(ClientError::Protocol(
                "encrypted SMB sessions are not implemented yet",
            ));
        }

        let request = TreeConnectRequest {
            flags: options.flags,
            path: path.clone(),
        };
        let message_id = self.connection.message_ids.allocate(0)?;
        let mut request_message = request.encode_message(
            message_id,
            self.session_id,
            options.credit_request,
        )?;

        let smb311_tree_signing = negotiated.dialect == Dialect::Smb311
            && self.mechanism != smb_io_auth::AuthMechanism::Anonymous
            && self.session_flags & (session_flags::IS_GUEST | session_flags::IS_NULL) == 0;
        let request_signed = self.signing_required || smb311_tree_signing;
        if request_signed {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "TREE_CONNECT requires signing but the session has no signing key",
            ))?;
            signing.sign(&mut request_message)?;
        }

        self.connection.transport.send_message(&request_message).await?;
        let mut response_message = self.connection.transport.receive_message().await?;
        let header = Smb2Header::decode(&response_message)?;
        if header.command != Command::TreeConnect {
            return Err(ClientError::Protocol(
                "TREE_CONNECT response command does not match request",
            ));
        }
        if header.message_id != message_id {
            return Err(ClientError::Protocol(
                "TREE_CONNECT response MessageId does not match request",
            ));
        }
        if header.session_id != self.session_id {
            return Err(ClientError::Protocol(
                "TREE_CONNECT response SessionId does not match session",
            ));
        }
        match header.status {
            StatusField::Status(0) => {}
            StatusField::Status(status) => return Err(ClientError::ServerStatus(status)),
            StatusField::ChannelSequence { .. } => {
                return Err(ClientError::Protocol(
                    "TREE_CONNECT response used request header form",
                ));
            }
        }

        if header.flags & flags::SIGNED != 0 {
            let signing = self.signing.as_ref().ok_or(ClientError::Protocol(
                "server signed TREE_CONNECT without an available signing key",
            ))?;
            signing.verify(&mut response_message)?;
        } else if self.signing_required {
            return Err(ClientError::Protocol(
                "server omitted a required TREE_CONNECT signature",
            ));
        }

        let response = TreeConnectResponse::decode_message(&response_message)?;
        let tree_id = match response.header.id {
            HeaderId::Sync { tree_id, .. } if tree_id != 0 => tree_id,
            HeaderId::Sync { .. } => {
                return Err(ClientError::Protocol(
                    "successful TREE_CONNECT response has a zero TreeId",
                ));
            }
            HeaderId::Async { .. } => {
                return Err(ClientError::Protocol(
                    "TREE_CONNECT response unexpectedly used async header form",
                ));
            }
        };

        Ok(TreeHandle {
            tree_id,
            path,
            share_type: response.share_type,
            share_flags: response.share_flags,
            capabilities: response.capabilities,
            maximal_access: response.maximal_access,
        })
    }
}
