use smb_io_wire::{Command, HeaderId, Smb2Header, StatusField};

use crate::ClientError;

/// NTSTATUS returned by an interim response when the server continues a request asynchronously.
pub const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ResponsePhase {
    InterimPending,
    Final,
}

impl ResponsePhase {
    /// SMB2 async STATUS_PENDING is an interim response. Servers are permitted to leave that
    /// response unsigned even when the session requires signing; final responses remain subject to
    /// the normal signing requirement.
    pub(crate) fn requires_signature(self, signing_required: bool) -> bool {
        signing_required && self == Self::Final
    }
}

/// Per-request asynchronous state learned from SMB2_FLAGS_ASYNC_COMMAND responses.
///
/// The MessageId remains the primary correlation key. Once the server supplies a nonzero AsyncId,
/// subsequent async responses for the request must carry the same identifier.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AsyncResponseState {
    async_id: Option<u64>,
}

impl AsyncResponseState {
    pub(crate) fn async_id(self) -> Option<u64> {
        self.async_id
    }

    pub(crate) fn validate(
        &mut self,
        expected_command: Command,
        tree_id: u32,
        session_id: u64,
        message_id: u64,
        header: &Smb2Header,
    ) -> Result<ResponsePhase, ClientError> {
        if header.command != expected_command {
            return Err(ClientError::Protocol(
                "async response command does not match request",
            ));
        }
        if header.message_id != message_id {
            return Err(ClientError::Protocol(
                "async response MessageId does not match request",
            ));
        }
        if header.session_id != session_id {
            return Err(ClientError::Protocol(
                "async response SessionId does not match session",
            ));
        }

        let status = match header.status {
            StatusField::Status(status) => status,
            StatusField::ChannelSequence { .. } => {
                return Err(ClientError::Protocol(
                    "async response used request header form",
                ));
            }
        };

        match header.id {
            HeaderId::Sync {
                tree_id: received_tree_id,
                ..
            } => {
                if self.async_id.is_some() {
                    return Err(ClientError::Protocol(
                        "asynchronous final response reverted to sync header form",
                    ));
                }
                if status == STATUS_PENDING {
                    return Err(ClientError::Protocol(
                        "STATUS_PENDING response did not use async header form",
                    ));
                }
                if received_tree_id != tree_id {
                    return Err(ClientError::Protocol(
                        "response TreeId does not match request tree",
                    ));
                }
                Ok(ResponsePhase::Final)
            }
            HeaderId::Async { async_id } => {
                if async_id == 0 {
                    return Err(ClientError::Protocol(
                        "asynchronous response has a zero AsyncId",
                    ));
                }
                if let Some(expected) = self.async_id {
                    if expected != async_id {
                        return Err(ClientError::Protocol(
                            "asynchronous response AsyncId changed before completion",
                        ));
                    }
                } else {
                    self.async_id = Some(async_id);
                }

                if status == STATUS_PENDING {
                    Ok(ResponsePhase::InterimPending)
                } else {
                    Ok(ResponsePhase::Final)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use smb_io_wire::{Command, HeaderId, Smb2Header, StatusField, flags};

    use super::*;

    const TREE_ID: u32 = 0x1122_3344;
    const SESSION_ID: u64 = 0x0102_0304_0506_0708;
    const MESSAGE_ID: u64 = 42;

    fn response(command: Command, status: u32, id: HeaderId) -> Smb2Header {
        let mut header = Smb2Header::request(command, MESSAGE_ID, 0, 0);
        header.flags = flags::SERVER_TO_REDIR;
        if matches!(id, HeaderId::Async { .. }) {
            header.flags |= flags::ASYNC_COMMAND;
        }
        header.status = StatusField::Status(status);
        header.session_id = SESSION_ID;
        header.id = id;
        header
    }

    #[test]
    fn write_pending_then_matching_async_final_is_accepted() {
        let mut state = AsyncResponseState::default();
        let pending = response(
            Command::Write,
            STATUS_PENDING,
            HeaderId::Async { async_id: 99 },
        );
        assert_eq!(
            state
                .validate(Command::Write, TREE_ID, SESSION_ID, MESSAGE_ID, &pending)
                .unwrap(),
            ResponsePhase::InterimPending
        );
        assert_eq!(state.async_id(), Some(99));

        let final_response = response(Command::Write, 0, HeaderId::Async { async_id: 99 });
        assert_eq!(
            state
                .validate(
                    Command::Write,
                    TREE_ID,
                    SESSION_ID,
                    MESSAGE_ID,
                    &final_response,
                )
                .unwrap(),
            ResponsePhase::Final
        );
    }

    #[test]
    fn read_sync_final_remains_supported() {
        let mut state = AsyncResponseState::default();
        let header = response(
            Command::Read,
            0,
            HeaderId::Sync {
                process_id: 0,
                tree_id: TREE_ID,
            },
        );
        assert_eq!(
            state
                .validate(Command::Read, TREE_ID, SESSION_ID, MESSAGE_ID, &header)
                .unwrap(),
            ResponsePhase::Final
        );
    }

    #[test]
    fn command_mismatch_is_rejected() {
        let mut state = AsyncResponseState::default();
        let header = response(
            Command::Read,
            0,
            HeaderId::Sync {
                process_id: 0,
                tree_id: TREE_ID,
            },
        );
        assert!(
            state
                .validate(Command::Write, TREE_ID, SESSION_ID, MESSAGE_ID, &header)
                .is_err()
        );
    }

    #[test]
    fn changed_async_id_is_rejected() {
        let mut state = AsyncResponseState::default();
        let pending = response(
            Command::Write,
            STATUS_PENDING,
            HeaderId::Async { async_id: 7 },
        );
        state
            .validate(Command::Write, TREE_ID, SESSION_ID, MESSAGE_ID, &pending)
            .unwrap();
        let final_response = response(Command::Write, 0, HeaderId::Async { async_id: 8 });
        assert!(
            state
                .validate(
                    Command::Write,
                    TREE_ID,
                    SESSION_ID,
                    MESSAGE_ID,
                    &final_response,
                )
                .is_err()
        );
    }

    #[test]
    fn pending_with_sync_header_is_rejected() {
        let mut state = AsyncResponseState::default();
        let pending = response(
            Command::Write,
            STATUS_PENDING,
            HeaderId::Sync {
                process_id: 0,
                tree_id: TREE_ID,
            },
        );
        assert!(
            state
                .validate(Command::Write, TREE_ID, SESSION_ID, MESSAGE_ID, &pending)
                .is_err()
        );
    }

    #[test]
    fn unsigned_interim_is_allowed_but_final_still_requires_signing() {
        assert!(!ResponsePhase::InterimPending.requires_signature(true));
        assert!(ResponsePhase::Final.requires_signature(true));
        assert!(!ResponsePhase::Final.requires_signature(false));
    }
}
