use crate::error::{WireError, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u32, get_u64, put_u16,
    put_u32, put_u64,
};
use crate::FileId;

pub const CLOSE_REQUEST_STRUCTURE_SIZE: u16 = 24;
pub const CLOSE_REQUEST_FIXED_SIZE: usize = 24;
pub const CLOSE_RESPONSE_STRUCTURE_SIZE: u16 = 60;
pub const CLOSE_RESPONSE_FIXED_SIZE: usize = 60;

pub mod close_flags {
    pub const POSTQUERY_ATTRIB: u16 = 0x0001;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseRequest {
    pub flags: u16,
    pub file_id: FileId,
}

impl CloseRequest {
    pub const fn new(file_id: FileId) -> Self {
        Self { flags: 0, file_id }
    }

    pub const fn with_postquery_attributes(mut self) -> Self {
        self.flags |= close_flags::POSTQUERY_ATTRIB;
        self
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.flags & !close_flags::POSTQUERY_ATTRIB != 0 {
            return Err(WireError::InvalidField("CLOSE Flags"));
        }
        if self.file_id.is_zero() {
            return Err(WireError::InvalidField("CLOSE FileId"));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<[u8; CLOSE_REQUEST_FIXED_SIZE], WireError> {
        self.validate()?;
        let mut body = [0u8; CLOSE_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, CLOSE_REQUEST_STRUCTURE_SIZE);
        put_u16(&mut body, 2, self.flags);
        put_u32(&mut body, 4, 0);
        put_u64(&mut body, 8, self.file_id.persistent);
        put_u64(&mut body, 16, self.file_id.volatile);
        Ok(body)
    }

    pub fn encode_message(
        &self,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        credit_charge: u16,
        credit_request: u16,
    ) -> Result<Vec<u8>, WireError> {
        let mut header = Smb2Header::request(Command::Close, message_id, credit_charge, credit_request);
        header.session_id = session_id;
        header.id = HeaderId::Sync {
            process_id: 0,
            tree_id,
        };
        let body = self.encode_body()?;
        let mut message = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
        message.extend_from_slice(&header.encode());
        message.extend_from_slice(&body);
        Ok(message)
    }

    pub fn decode_message(message: &[u8]) -> Result<(Smb2Header, Self), WireError> {
        require_len(message, SMB2_HEADER_SIZE + CLOSE_REQUEST_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Close {
            return Err(WireError::InvalidField("CLOSE Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR != 0 {
            return Err(WireError::InvalidField("CLOSE request direction"));
        }
        let body = &message[SMB2_HEADER_SIZE..];
        if get_u16(body, 0) != CLOSE_REQUEST_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: CLOSE_REQUEST_STRUCTURE_SIZE,
                actual: get_u16(body, 0),
            });
        }
        if get_u32(body, 4) != 0 {
            return Err(WireError::InvalidField("CLOSE Reserved"));
        }
        let request = Self {
            flags: get_u16(body, 2),
            file_id: FileId::new(get_u64(body, 8), get_u64(body, 16)),
        };
        request.validate()?;
        Ok((header, request))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseResponse {
    pub header: Smb2Header,
    pub flags: u16,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
}

impl CloseResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + CLOSE_RESPONSE_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Close {
            return Err(WireError::InvalidField("CLOSE response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("CLOSE response direction"));
        }
        let body = &message[SMB2_HEADER_SIZE..];
        if get_u16(body, 0) != CLOSE_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: CLOSE_RESPONSE_STRUCTURE_SIZE,
                actual: get_u16(body, 0),
            });
        }
        if get_u32(body, 4) != 0 {
            return Err(WireError::InvalidField("CLOSE response Reserved"));
        }
        let response_flags = get_u16(body, 2);
        if response_flags & !close_flags::POSTQUERY_ATTRIB != 0 {
            return Err(WireError::InvalidField("CLOSE response Flags"));
        }
        Ok(Self {
            header,
            flags: response_flags,
            creation_time: get_u64(body, 8),
            last_access_time: get_u64(body, 16),
            last_write_time: get_u64(body, 24),
            change_time: get_u64(body, 32),
            allocation_size: get_u64(body, 40),
            end_of_file: get_u64(body, 48),
            file_attributes: get_u32(body, 56),
        })
    }

    pub const fn has_postquery_attributes(&self) -> bool {
        self.flags & close_flags::POSTQUERY_ATTRIB != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatusField;

    #[test]
    fn close_request_round_trips_file_id() {
        let request = CloseRequest::new(FileId::new(0x1122, 0x3344)).with_postquery_attributes();
        let message = request.encode_message(7, 8, 9, 1, 16).unwrap();
        let (header, decoded) = CloseRequest::decode_message(&message).unwrap();
        assert_eq!(header.command, Command::Close);
        assert_eq!(header.message_id, 7);
        assert_eq!(header.session_id, 8);
        assert_eq!(
            header.id,
            HeaderId::Sync {
                process_id: 0,
                tree_id: 9,
            }
        );
        assert_eq!(decoded, request);
    }

    #[test]
    fn close_response_decodes_postquery_attributes() {
        let mut header = Smb2Header::request(Command::Close, 7, 1, 4);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        header.session_id = 8;
        header.id = HeaderId::Sync {
            process_id: 0,
            tree_id: 9,
        };
        let mut message = header.encode().to_vec();
        let mut body = [0u8; CLOSE_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, CLOSE_RESPONSE_STRUCTURE_SIZE);
        put_u16(&mut body, 2, close_flags::POSTQUERY_ATTRIB);
        put_u64(&mut body, 8, 1);
        put_u64(&mut body, 16, 2);
        put_u64(&mut body, 24, 3);
        put_u64(&mut body, 32, 4);
        put_u64(&mut body, 40, 5);
        put_u64(&mut body, 48, 6);
        put_u32(&mut body, 56, 0x20);
        message.extend_from_slice(&body);

        let response = CloseResponse::decode_message(&message).unwrap();
        assert!(response.has_postquery_attributes());
        assert_eq!(response.end_of_file, 6);
        assert_eq!(response.file_attributes, 0x20);
    }
}
