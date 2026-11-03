use crate::FileId;
use crate::error::{WireError, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u64, put_u16, put_u32,
    put_u64,
};

pub const FLUSH_REQUEST_STRUCTURE_SIZE: u16 = 24;
pub const FLUSH_REQUEST_FIXED_SIZE: usize = 24;
pub const FLUSH_RESPONSE_STRUCTURE_SIZE: u16 = 4;
pub const FLUSH_RESPONSE_FIXED_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushRequest {
    pub file_id: FileId,
}

impl FlushRequest {
    pub const fn new(file_id: FileId) -> Self {
        Self { file_id }
    }

    pub fn encode_message(
        &self,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        credit_charge: u16,
        credit_request: u16,
    ) -> Result<Vec<u8>, WireError> {
        if self.file_id.is_zero() {
            return Err(WireError::InvalidField("FLUSH FileId"));
        }
        let mut header =
            Smb2Header::request(Command::Flush, message_id, credit_charge, credit_request);
        header.session_id = session_id;
        header.id = HeaderId::Sync {
            process_id: 0,
            tree_id,
        };
        let mut body = [0u8; FLUSH_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, FLUSH_REQUEST_STRUCTURE_SIZE);
        put_u16(&mut body, 2, 0);
        put_u32(&mut body, 4, 0);
        put_u64(&mut body, 8, self.file_id.persistent);
        put_u64(&mut body, 16, self.file_id.volatile);
        let mut message = Vec::with_capacity(SMB2_HEADER_SIZE + FLUSH_REQUEST_FIXED_SIZE);
        message.extend_from_slice(&header.encode());
        message.extend_from_slice(&body);
        Ok(message)
    }

    pub fn decode_message(message: &[u8]) -> Result<(Smb2Header, Self), WireError> {
        require_len(message, SMB2_HEADER_SIZE + FLUSH_REQUEST_FIXED_SIZE)?;
        if message.len() != SMB2_HEADER_SIZE + FLUSH_REQUEST_FIXED_SIZE {
            return Err(WireError::InvalidField("FLUSH request length"));
        }
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Flush || header.flags & flags::SERVER_TO_REDIR != 0 {
            return Err(WireError::InvalidField("FLUSH request header"));
        }
        let body = &message[SMB2_HEADER_SIZE..];
        if get_u16(body, 0) != FLUSH_REQUEST_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: FLUSH_REQUEST_STRUCTURE_SIZE,
                actual: get_u16(body, 0),
            });
        }
        if body[2..8].iter().any(|&byte| byte != 0) {
            return Err(WireError::InvalidField("FLUSH request reserved"));
        }
        let request = Self {
            file_id: FileId::new(get_u64(body, 8), get_u64(body, 16)),
        };
        if request.file_id.is_zero() {
            return Err(WireError::InvalidField("FLUSH FileId"));
        }
        Ok((header, request))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushResponse;

impl FlushResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + FLUSH_RESPONSE_FIXED_SIZE)?;
        if message.len() != SMB2_HEADER_SIZE + FLUSH_RESPONSE_FIXED_SIZE {
            return Err(WireError::InvalidField("FLUSH response length"));
        }
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Flush || header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("FLUSH response header"));
        }
        let body = &message[SMB2_HEADER_SIZE..];
        if get_u16(body, 0) != FLUSH_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: FLUSH_RESPONSE_STRUCTURE_SIZE,
                actual: get_u16(body, 0),
            });
        }
        if get_u16(body, 2) != 0 {
            return Err(WireError::InvalidField("FLUSH response reserved"));
        }
        Ok(Self)
    }
}
