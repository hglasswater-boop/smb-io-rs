use smb_io_wire::{Command, Smb2Header};

use crate::ClientError;
use crate::async_response::{AsyncResponseState, ResponsePhase};

pub(crate) type ReadResponsePhase = ResponsePhase;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AsyncReadState {
    inner: AsyncResponseState,
}

impl AsyncReadState {
    pub(crate) fn async_id(self) -> Option<u64> {
        self.inner.async_id()
    }

    pub(crate) fn validate(
        &mut self,
        tree_id: u32,
        session_id: u64,
        message_id: u64,
        header: &Smb2Header,
    ) -> Result<ReadResponsePhase, ClientError> {
        self.inner
            .validate(Command::Read, tree_id, session_id, message_id, header)
    }
}
