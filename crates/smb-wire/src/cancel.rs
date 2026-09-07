use crate::error::{WireError, require_len};
use crate::header::{Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, put_u16};

pub const CANCEL_REQUEST_STRUCTURE_SIZE: u16 = 4;
pub const CANCEL_REQUEST_FIXED_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CancelRequest;

impl CancelRequest {
    pub fn encode_body(self) -> [u8; CANCEL_REQUEST_FIXED_SIZE] {
        let mut body = [0u8; CANCEL_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, CANCEL_REQUEST_STRUCTURE_SIZE);
        put_u16(&mut body, 2, 0);
        body
    }

    /// Encodes a synchronous SMB2 CANCEL request.
    ///
    /// `message_id` is intentionally reused from the request being cancelled. CANCEL requests do
    /// not consume a new SMB sequence number or credits, and TreeId is zero for the sync form.
    pub fn encode_sync_message(self, message_id: u64, session_id: u64) -> Vec<u8> {
        let mut header = Smb2Header::request(Command::Cancel, message_id, 0, 0);
        header.session_id = session_id;
        header.id = HeaderId::Sync {
            process_id: 0,
            tree_id: 0,
        };
        let body = self.encode_body();
        let mut message = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
        message.extend_from_slice(&header.encode());
        message.extend_from_slice(&body);
        message
    }

    /// Encodes an asynchronous SMB2 CANCEL request for a request that has already returned an
    /// interim async response.
    pub fn encode_async_message(
        self,
        message_id: u64,
        session_id: u64,
        async_id: u64,
    ) -> Vec<u8> {
        let mut header = Smb2Header::request(Command::Cancel, message_id, 0, 0);
        header.flags |= flags::ASYNC_COMMAND;
        header.session_id = session_id;
        header.id = HeaderId::Async { async_id };
        let body = self.encode_body();
        let mut message = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
        message.extend_from_slice(&header.encode());
        message.extend_from_slice(&body);
        message
    }

    pub fn decode_message(message: &[u8]) -> Result<(Smb2Header, Self), WireError> {
        require_len(message, SMB2_HEADER_SIZE + CANCEL_REQUEST_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Cancel {
            return Err(WireError::InvalidField("CANCEL Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR != 0 {
            return Err(WireError::InvalidField("CANCEL request direction"));
        }
        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != CANCEL_REQUEST_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: CANCEL_REQUEST_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }
        if get_u16(body, 2) != 0 {
            return Err(WireError::InvalidField("CANCEL Reserved"));
        }
        Ok((header, Self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_cancel_reuses_message_id_without_credits_or_tree() {
        let message = CancelRequest.encode_sync_message(0x1122_3344, 0x5566_7788);
        let (header, _) = CancelRequest::decode_message(&message).unwrap();
        assert_eq!(header.command, Command::Cancel);
        assert_eq!(header.message_id, 0x1122_3344);
        assert_eq!(header.credit_charge, 0);
        assert_eq!(header.credits, 0);
        assert_eq!(header.session_id, 0x5566_7788);
        assert_eq!(
            header.id,
            HeaderId::Sync {
                process_id: 0,
                tree_id: 0
            }
        );
    }

    #[test]
    fn async_cancel_carries_async_id() {
        let message = CancelRequest.encode_async_message(7, 8, 9);
        let (header, _) = CancelRequest::decode_message(&message).unwrap();
        assert_ne!(header.flags & flags::ASYNC_COMMAND, 0);
        assert_eq!(header.id, HeaderId::Async { async_id: 9 });
    }
}
