use smb_io_wire::{Command, HeaderId, Smb2Header, StatusField};

use crate::ClientError;

/// NTSTATUS returned by an interim response when the server continues a request asynchronously.
pub const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReadResponsePhase {
    InterimPending,
    Final,
}

impl ReadResponsePhase {
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
/// subsequent async responses for the request must carry the same identifier. This state is also
/// used by SMB2 CANCEL so a cancellation after STATUS_PENDING targets the server's AsyncId.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AsyncReadState {
    async_id: Option<u64>,
}

impl AsyncReadState {
    pub(crate) fn async_id(self) -> Option<u64> {
        self.async_id
    }

    pub(crate) fn validate(
        &mut self,
        tree_id: u32,
        session_id: u64,
        message_id: u64,
        header: &Smb2Header,
    ) -> Result<ReadResponsePhase, ClientError> {
        if header.command != Command::Read {
            return Err(ClientError::Protocol(
                "READ response command does not match request",
            ));
        }
        if header.message_id != message_id {
            return Err(ClientError::Protocol(
                "READ response MessageId does not match request",
            ));
        }
        if header.session_id != session_id {
            return Err(ClientError::Protocol(
                "READ response SessionId does not match session",
            ));
        }

        let status = match header.status {
            StatusField::Status(status) => status,
            StatusField::ChannelSequence { .. } => {
                return Err(ClientError::Protocol(
                    "READ response used request header form",
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
                        "asynchronous READ final response reverted to sync header form",
                    ));
                }
                if status == STATUS_PENDING {
                    return Err(ClientError::Protocol(
                        "STATUS_PENDING READ response did not use async header form",
                    ));
                }
                if received_tree_id != tree_id {
                    return Err(ClientError::Protocol(
                        "READ response TreeId does not match file tree",
                    ));
                }
                Ok(ReadResponsePhase::Final)
            }
            HeaderId::Async { async_id } => {
                if async_id == 0 {
                    return Err(ClientError::Protocol(
                        "asynchronous READ response has a zero AsyncId",
                    ));
                }
                if let Some(expected) = self.async_id {
                    if expected != async_id {
                        return Err(ClientError::Protocol(
                            "asynchronous READ response AsyncId changed before completion",
                        ));
                    }
                } else {
                    self.async_id = Some(async_id);
                }

                if status == STATUS_PENDING {
                    Ok(ReadResponsePhase::InterimPending)
                } else {
                    Ok(ReadResponsePhase::Final)
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

    fn response(status: u32, id: HeaderId) -> Smb2Header {
        let mut header = Smb2Header::request(Command::Read, MESSAGE_ID, 0, 0);
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
    fn sync_final_response_is_accepted() {
        let mut state = AsyncReadState::default();
        let header = response(
            0,
            HeaderId::Sync {
                process_id: 0,
                tree_id: TREE_ID,
            },
        );
        assert_eq!(
            state
                .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &header)
                .unwrap(),
            ReadResponsePhase::Final
        );
        assert_eq!(state.async_id(), None);
    }

    #[test]
    fn pending_then_matching_async_final_is_accepted() {
        let mut state = AsyncReadState::default();
        let pending = response(STATUS_PENDING, HeaderId::Async { async_id: 99 });
        assert_eq!(
            state
                .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &pending)
                .unwrap(),
            ReadResponsePhase::InterimPending
        );
        assert_eq!(state.async_id(), Some(99));

        let final_response = response(0, HeaderId::Async { async_id: 99 });
        assert_eq!(
            state
                .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &final_response)
                .unwrap(),
            ReadResponsePhase::Final
        );
    }

    #[test]
    fn direct_async_final_is_accepted_and_records_async_id() {
        let mut state = AsyncReadState::default();
        let final_response = response(0, HeaderId::Async { async_id: 77 });
        assert_eq!(
            state
                .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &final_response)
                .unwrap(),
            ReadResponsePhase::Final
        );
        assert_eq!(state.async_id(), Some(77));
    }

    #[test]
    fn changed_async_id_is_rejected() {
        let mut state = AsyncReadState::default();
        let pending = response(STATUS_PENDING, HeaderId::Async { async_id: 7 });
        state
            .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &pending)
            .unwrap();
        let final_response = response(0, HeaderId::Async { async_id: 8 });
        assert!(
            state
                .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &final_response)
                .is_err()
        );
    }

    #[test]
    fn pending_with_sync_header_is_rejected() {
        let mut state = AsyncReadState::default();
        let pending = response(
            STATUS_PENDING,
            HeaderId::Sync {
                process_id: 0,
                tree_id: TREE_ID,
            },
        );
        assert!(
            state
                .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &pending)
                .is_err()
        );
    }

    #[test]
    fn async_final_cannot_revert_to_sync() {
        let mut state = AsyncReadState::default();
        let pending = response(STATUS_PENDING, HeaderId::Async { async_id: 11 });
        state
            .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &pending)
            .unwrap();
        let final_response = response(
            0,
            HeaderId::Sync {
                process_id: 0,
                tree_id: TREE_ID,
            },
        );
        assert!(
            state
                .validate(TREE_ID, SESSION_ID, MESSAGE_ID, &final_response)
                .is_err()
        );
    }

    #[test]
    fn unsigned_interim_is_allowed_but_final_still_requires_signing() {
        assert!(!ReadResponsePhase::InterimPending.requires_signature(true));
        assert!(ReadResponsePhase::Final.requires_signature(true));
        assert!(!ReadResponsePhase::Final.requires_signature(false));
    }
}
