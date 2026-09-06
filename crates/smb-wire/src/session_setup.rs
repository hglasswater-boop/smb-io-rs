use crate::error::{WireError, checked_range, require_len};
use crate::header::{
    Command, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, put_u16, put_u32, put_u64,
};

pub const SESSION_SETUP_REQUEST_STRUCTURE_SIZE: u16 = 25;
pub const SESSION_SETUP_REQUEST_FIXED_SIZE: usize = 24;
pub const SESSION_SETUP_RESPONSE_STRUCTURE_SIZE: u16 = 9;
pub const SESSION_SETUP_RESPONSE_FIXED_SIZE: usize = 8;

pub mod request_flags {
    pub const BINDING: u8 = 0x01;
}

pub mod session_flags {
    pub const IS_GUEST: u16 = 0x0001;
    pub const IS_NULL: u16 = 0x0002;
    pub const ENCRYPT_DATA: u16 = 0x0004;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupRequest {
    pub flags: u8,
    pub security_mode: u8,
    pub capabilities: u32,
    pub previous_session_id: u64,
    pub security_blob: Vec<u8>,
}

impl SessionSetupRequest {
    pub fn validate(&self) -> Result<(), WireError> {
        if self.security_blob.len() > u16::MAX as usize {
            return Err(WireError::InvalidField("SESSION_SETUP SecurityBufferLength"));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut body = vec![0u8; SESSION_SETUP_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, SESSION_SETUP_REQUEST_STRUCTURE_SIZE);
        body[2] = self.flags;
        body[3] = self.security_mode;
        put_u32(&mut body, 4, self.capabilities);
        put_u32(&mut body, 8, 0); // Channel is reserved and MUST be zero.

        if !self.security_blob.is_empty() {
            let offset = SMB2_HEADER_SIZE
                .checked_add(SESSION_SETUP_REQUEST_FIXED_SIZE)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(WireError::InvalidField("SESSION_SETUP SecurityBufferOffset"))?;
            put_u16(&mut body, 12, offset);
            put_u16(&mut body, 14, self.security_blob.len() as u16);
        }
        put_u64(&mut body, 16, self.previous_session_id);
        body.extend_from_slice(&self.security_blob);
        Ok(body)
    }

    /// Encodes a complete SESSION_SETUP message without the direct-TCP prefix.
    ///
    /// `session_id` is zero for the first authentication exchange and the server-provided session
    /// id for continuation exchanges. `previous_session_id` is the reconnect field in the request
    /// body and is intentionally separate.
    pub fn encode_message(
        &self,
        message_id: u64,
        session_id: u64,
        credit_request: u16,
    ) -> Result<Vec<u8>, WireError> {
        let mut header = Smb2Header::request(Command::SessionSetup, message_id, 0, credit_request);
        header.session_id = session_id;
        let header = header.encode();
        let body = self.encode_body()?;
        let mut message = Vec::with_capacity(header.len() + body.len());
        message.extend_from_slice(&header);
        message.extend_from_slice(&body);
        Ok(message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupResponse {
    pub header: Smb2Header,
    pub session_flags: u16,
    pub security_blob: Vec<u8>,
}

impl SessionSetupResponse {
    /// Decodes a complete SESSION_SETUP response without the direct-TCP prefix.
    ///
    /// Both STATUS_SUCCESS and STATUS_MORE_PROCESSING_REQUIRED responses use this body format, so
    /// the caller owns interpretation of `header.status` after decoding.
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(
            message,
            SMB2_HEADER_SIZE + SESSION_SETUP_RESPONSE_FIXED_SIZE,
        )?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::SessionSetup {
            return Err(WireError::InvalidField("SESSION_SETUP response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("SESSION_SETUP response direction"));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != SESSION_SETUP_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: SESSION_SETUP_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }

        let security_offset = get_u16(body, 4) as usize;
        let security_len = get_u16(body, 6) as usize;
        let security_blob = if security_len == 0 {
            Vec::new()
        } else {
            if security_offset < SMB2_HEADER_SIZE + SESSION_SETUP_RESPONSE_FIXED_SIZE {
                return Err(WireError::InvalidField(
                    "SESSION_SETUP SecurityBufferOffset before response buffer",
                ));
            }
            let range = checked_range(
                message.len(),
                "SESSION_SETUP SecurityBuffer",
                security_offset,
                security_len,
            )?;
            message[range].to_vec()
        };

        Ok(Self {
            header,
            session_flags: get_u16(body, 2),
            security_blob,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{StatusField, put_u32};

    #[test]
    fn request_places_security_blob_at_offset_88() {
        let request = SessionSetupRequest {
            flags: 0,
            security_mode: 1,
            capabilities: 0,
            previous_session_id: 0,
            security_blob: vec![1, 2, 3, 4],
        };
        let body = request.encode_body().unwrap();
        assert_eq!(get_u16(&body, 0), 25);
        assert_eq!(get_u16(&body, 12), 88);
        assert_eq!(get_u16(&body, 14), 4);
        assert_eq!(&body[24..], &[1, 2, 3, 4]);
    }

    #[test]
    fn continuation_request_carries_session_id_in_header() {
        let request = SessionSetupRequest {
            flags: 0,
            security_mode: 1,
            capabilities: 0,
            previous_session_id: 0,
            security_blob: vec![7],
        };
        let message = request.encode_message(4, 0x1122_3344_5566_7788, 8).unwrap();
        let header = Smb2Header::decode(&message).unwrap();
        assert_eq!(header.session_id, 0x1122_3344_5566_7788);
    }

    #[test]
    fn response_parses_auth_token_even_for_nonzero_status() {
        let mut header = Smb2Header::request(Command::SessionSetup, 1, 0, 1);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0xC000_0016); // STATUS_MORE_PROCESSING_REQUIRED
        header.session_id = 42;
        let mut message = header.encode().to_vec();

        let mut body = vec![0u8; SESSION_SETUP_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, SESSION_SETUP_RESPONSE_STRUCTURE_SIZE);
        put_u16(&mut body, 2, 0);
        put_u16(&mut body, 4, 72);
        put_u16(&mut body, 6, 3);
        message.extend_from_slice(&body);
        message.extend_from_slice(&[9, 8, 7]);

        let response = SessionSetupResponse::decode_message(&message).unwrap();
        assert_eq!(response.security_blob, vec![9, 8, 7]);
        assert_eq!(response.header.session_id, 42);
        assert_eq!(response.header.status, StatusField::Status(0xC000_0016));
    }

    #[test]
    fn rejects_security_buffer_outside_packet() {
        let mut header = Smb2Header::request(Command::SessionSetup, 1, 0, 1);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; SESSION_SETUP_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, SESSION_SETUP_RESPONSE_STRUCTURE_SIZE);
        put_u16(&mut body, 4, 0xFFFF);
        put_u16(&mut body, 6, 16);
        message.extend_from_slice(&body);

        assert!(matches!(
            SessionSetupResponse::decode_message(&message),
            Err(WireError::InvalidOffset { .. })
        ));
    }

    #[test]
    fn response_must_be_server_to_client() {
        let mut message = Smb2Header::request(Command::SessionSetup, 1, 0, 1)
            .encode()
            .to_vec();
        let mut body = vec![0u8; SESSION_SETUP_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, SESSION_SETUP_RESPONSE_STRUCTURE_SIZE);
        message.extend_from_slice(&body);
        assert!(SessionSetupResponse::decode_message(&message).is_err());
    }

    #[test]
    fn reserved_channel_is_encoded_as_zero() {
        let request = SessionSetupRequest {
            flags: request_flags::BINDING,
            security_mode: 1,
            capabilities: 1,
            previous_session_id: 123,
            security_blob: vec![1],
        };
        let body = request.encode_body().unwrap();
        assert_eq!(&body[8..12], &[0, 0, 0, 0]);
        // Keep put_u32 referenced by this test module so endian helper changes stay visible here.
        let mut scratch = [0u8; 4];
        put_u32(&mut scratch, 0, 0x1122_3344);
        assert_eq!(scratch, [0x44, 0x33, 0x22, 0x11]);
    }
}
