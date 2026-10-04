use smb_io_wire::{Command, Smb2Header};

use crate::ClientError;

pub const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ResponsePhase {
    InterimPending,
    Final,
}

impl ResponsePhase {
    pub(crate) fn requires_signature(self, _signing_required: bool) -> bool {
        todo!("shared async response policy is implemented after the tests")
    }
}

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
        _expected_command: Command,
        _tree_id: u32,
        _session_id: u64,
        _message_id: u64,
        _header: &Smb2Header,
    ) -> Result<ResponsePhase, ClientError> {
        todo!("shared async response validation is implemented after the tests")
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
