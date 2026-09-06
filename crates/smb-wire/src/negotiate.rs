use crate::error::{WireError, checked_range, require_len};
use crate::header::{
    Command, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u32, get_u64, put_u16,
    put_u32,
};

pub const NEGOTIATE_REQUEST_STRUCTURE_SIZE: u16 = 36;
pub const NEGOTIATE_RESPONSE_STRUCTURE_SIZE: u16 = 65;
pub const NEGOTIATE_RESPONSE_FIXED_SIZE: usize = 64;

pub mod security_mode {
    pub const SIGNING_ENABLED: u16 = 0x0001;
    pub const SIGNING_REQUIRED: u16 = 0x0002;
}

pub mod capabilities {
    pub const DFS: u32 = 0x0000_0001;
    pub const LEASING: u32 = 0x0000_0002;
    pub const LARGE_MTU: u32 = 0x0000_0004;
    pub const MULTI_CHANNEL: u32 = 0x0000_0008;
    pub const PERSISTENT_HANDLES: u32 = 0x0000_0010;
    pub const DIRECTORY_LEASING: u32 = 0x0000_0020;
    pub const ENCRYPTION: u32 = 0x0000_0040;
}

pub mod context_type {
    pub const PREAUTH_INTEGRITY_CAPABILITIES: u16 = 0x0001;
    pub const ENCRYPTION_CAPABILITIES: u16 = 0x0002;
    pub const COMPRESSION_CAPABILITIES: u16 = 0x0003;
    pub const NETNAME_NEGOTIATE_CONTEXT_ID: u16 = 0x0005;
    pub const TRANSPORT_CAPABILITIES: u16 = 0x0006;
    pub const RDMA_TRANSFORM_CAPABILITIES: u16 = 0x0007;
    pub const SIGNING_CAPABILITIES: u16 = 0x0008;
}

pub mod preauth_hash_algorithm {
    pub const SHA_512: u16 = 0x0001;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum Dialect {
    Smb202 = 0x0202,
    Smb210 = 0x0210,
    Smb300 = 0x0300,
    Smb302 = 0x0302,
    Smb311 = 0x0311,
}

impl TryFrom<u16> for Dialect {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0202 => Self::Smb202,
            0x0210 => Self::Smb210,
            0x0300 => Self::Smb300,
            0x0302 => Self::Smb302,
            0x0311 => Self::Smb311,
            _ => return Err(WireError::Unsupported("SMB dialect")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateContext {
    pub context_type: u16,
    pub data: Vec<u8>,
}

impl NegotiateContext {
    /// Builds the mandatory SMB 3.1.1 preauthentication-integrity context using SHA-512.
    ///
    /// Salt generation belongs to the caller/security layer; the wire layer only serializes it.
    pub fn preauth_sha512(salt: Vec<u8>) -> Result<Self, WireError> {
        let salt_len = u16::try_from(salt.len())
            .map_err(|_| WireError::InvalidField("preauth salt length"))?;
        let mut data = Vec::with_capacity(6 + salt.len());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&salt_len.to_le_bytes());
        data.extend_from_slice(&preauth_hash_algorithm::SHA_512.to_le_bytes());
        data.extend_from_slice(&salt);
        Ok(Self {
            context_type: context_type::PREAUTH_INTEGRITY_CAPABILITIES,
            data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateRequest {
    pub security_mode: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
    pub dialects: Vec<Dialect>,
    pub contexts: Vec<NegotiateContext>,
}

impl NegotiateRequest {
    pub fn validate(&self) -> Result<(), WireError> {
        if self.dialects.is_empty() {
            return Err(WireError::InvalidField("DialectCount"));
        }
        if self.dialects.len() > u16::MAX as usize {
            return Err(WireError::InvalidField("DialectCount"));
        }
        if self.contexts.len() > u16::MAX as usize {
            return Err(WireError::InvalidField("NegotiateContextCount"));
        }

        let has_311 = self.dialects.contains(&Dialect::Smb311);
        let has_preauth = self
            .contexts
            .iter()
            .any(|ctx| ctx.context_type == context_type::PREAUTH_INTEGRITY_CAPABILITIES);

        if has_311 && !has_preauth {
            return Err(WireError::InvalidField(
                "SMB 3.1.1 requires a preauthentication integrity context",
            ));
        }
        if !has_311 && !self.contexts.is_empty() {
            return Err(WireError::InvalidField(
                "negotiate contexts require SMB 3.1.1",
            ));
        }
        for context in &self.contexts {
            if context.data.len() > u16::MAX as usize {
                return Err(WireError::InvalidField("NegotiateContext DataLength"));
            }
        }
        Ok(())
    }

    /// Encodes the NEGOTIATE body. Offsets are calculated relative to the SMB2 header start.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;

        let dialect_count = self.dialects.len() as u16;
        let context_count = self.contexts.len() as u16;
        let mut body = vec![0u8; NEGOTIATE_REQUEST_STRUCTURE_SIZE as usize];
        put_u16(&mut body, 0, NEGOTIATE_REQUEST_STRUCTURE_SIZE);
        put_u16(&mut body, 2, dialect_count);
        put_u16(&mut body, 4, self.security_mode);
        put_u16(&mut body, 6, 0);
        put_u32(&mut body, 8, self.capabilities);
        body[12..28].copy_from_slice(&self.client_guid);

        for dialect in &self.dialects {
            body.extend_from_slice(&(*dialect as u16).to_le_bytes());
        }

        if !self.contexts.is_empty() {
            while (SMB2_HEADER_SIZE + body.len()) % 8 != 0 {
                body.push(0);
            }
            let context_offset = SMB2_HEADER_SIZE
                .checked_add(body.len())
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(WireError::InvalidField("NegotiateContextOffset"))?;
            put_u32(&mut body, 28, context_offset);
            put_u16(&mut body, 32, context_count);

            for context in &self.contexts {
                body.extend_from_slice(&context.context_type.to_le_bytes());
                body.extend_from_slice(&(context.data.len() as u16).to_le_bytes());
                body.extend_from_slice(&0u32.to_le_bytes());
                body.extend_from_slice(&context.data);
                while (SMB2_HEADER_SIZE + body.len()) % 8 != 0 {
                    body.push(0);
                }
            }
        }

        Ok(body)
    }

    /// Encodes a complete SMB2 NEGOTIATE message, without the 4-byte direct-TCP prefix.
    pub fn encode_message(&self, message_id: u64, credit_request: u16) -> Result<Vec<u8>, WireError> {
        let header = Smb2Header::request(Command::Negotiate, message_id, 0, credit_request).encode();
        let body = self.encode_body()?;
        let mut message = Vec::with_capacity(header.len() + body.len());
        message.extend_from_slice(&header);
        message.extend_from_slice(&body);
        Ok(message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateResponse {
    pub header: Smb2Header,
    pub security_mode: u16,
    pub dialect: Dialect,
    pub server_guid: [u8; 16],
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub system_time: u64,
    pub server_start_time: u64,
    pub security_blob: Vec<u8>,
    pub contexts: Vec<NegotiateContext>,
}

impl NegotiateResponse {
    /// Decodes a complete SMB2 NEGOTIATE response, without the direct-TCP prefix.
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + NEGOTIATE_RESPONSE_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Negotiate {
            return Err(WireError::InvalidField("NEGOTIATE response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("NEGOTIATE response direction"));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != NEGOTIATE_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: NEGOTIATE_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }

        let dialect = Dialect::try_from(get_u16(body, 4))?;
        let context_count = get_u16(body, 6) as usize;
        let mut server_guid = [0u8; 16];
        server_guid.copy_from_slice(&body[8..24]);

        let security_offset = get_u16(body, 56) as usize;
        let security_len = get_u16(body, 58) as usize;
        let security_blob = if security_len == 0 {
            Vec::new()
        } else {
            let range = checked_range(
                message.len(),
                "SecurityBuffer",
                security_offset,
                security_len,
            )?;
            message[range].to_vec()
        };

        let context_offset = get_u32(body, 60) as usize;
        let contexts = if context_count == 0 {
            Vec::new()
        } else {
            if dialect != Dialect::Smb311 {
                return Err(WireError::InvalidField(
                    "NegotiateContextCount on pre-SMB3.1.1 response",
                ));
            }
            if context_offset == 0 || context_offset % 8 != 0 {
                return Err(WireError::InvalidField("NegotiateContextOffset"));
            }
            decode_contexts(message, context_offset, context_count)?
        };

        Ok(Self {
            header,
            security_mode: get_u16(body, 2),
            dialect,
            server_guid,
            capabilities: get_u32(body, 24),
            max_transact_size: get_u32(body, 28),
            max_read_size: get_u32(body, 32),
            max_write_size: get_u32(body, 36),
            system_time: get_u64(body, 40),
            server_start_time: get_u64(body, 48),
            security_blob,
            contexts,
        })
    }
}

fn decode_contexts(
    message: &[u8],
    mut cursor: usize,
    count: usize,
) -> Result<Vec<NegotiateContext>, WireError> {
    let mut contexts = Vec::with_capacity(count);
    for index in 0..count {
        let header_range = checked_range(message.len(), "NegotiateContext", cursor, 8)?;
        let header = &message[header_range];
        let context_type = get_u16(header, 0);
        let data_len = get_u16(header, 2) as usize;
        let data_start = cursor + 8;
        let data_range = checked_range(
            message.len(),
            "NegotiateContext.Data",
            data_start,
            data_len,
        )?;
        contexts.push(NegotiateContext {
            context_type,
            data: message[data_range.clone()].to_vec(),
        });

        if index + 1 < count {
            cursor = align_up_8(data_range.end)
                .ok_or(WireError::InvalidField("NegotiateContext alignment"))?;
        }
    }
    Ok(contexts)
}

fn align_up_8(value: usize) -> Option<usize> {
    value.checked_add(7).map(|v| v & !7)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{StatusField, put_u64};

    fn guid() -> [u8; 16] {
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF,
        ]
    }

    #[test]
    fn pre_311_request_has_no_context_offset() {
        let request = NegotiateRequest {
            security_mode: security_mode::SIGNING_ENABLED,
            capabilities: capabilities::LARGE_MTU,
            client_guid: guid(),
            dialects: vec![Dialect::Smb202, Dialect::Smb210, Dialect::Smb302],
            contexts: vec![],
        };
        let body = request.encode_body().unwrap();
        assert_eq!(get_u16(&body, 0), 36);
        assert_eq!(get_u16(&body, 2), 3);
        assert_eq!(get_u32(&body, 28), 0);
        assert_eq!(get_u16(&body, 32), 0);
        assert_eq!(&body[36..42], &[0x02, 0x02, 0x10, 0x02, 0x02, 0x03]);
    }

    #[test]
    fn smb311_requires_preauth_context() {
        let request = NegotiateRequest {
            security_mode: security_mode::SIGNING_ENABLED,
            capabilities: capabilities::LARGE_MTU,
            client_guid: guid(),
            dialects: vec![Dialect::Smb311],
            contexts: vec![],
        };
        assert!(matches!(
            request.validate(),
            Err(WireError::InvalidField(
                "SMB 3.1.1 requires a preauthentication integrity context"
            ))
        ));
    }

    #[test]
    fn smb311_encodes_aligned_preauth_context() {
        let request = NegotiateRequest {
            security_mode: security_mode::SIGNING_ENABLED,
            capabilities: capabilities::LARGE_MTU,
            client_guid: guid(),
            dialects: vec![Dialect::Smb302, Dialect::Smb311],
            contexts: vec![NegotiateContext::preauth_sha512(vec![0xA5; 32]).unwrap()],
        };
        let body = request.encode_body().unwrap();
        let offset = get_u32(&body, 28) as usize;
        assert_eq!(offset % 8, 0);
        assert_eq!(get_u16(&body, 32), 1);
        let local = offset - SMB2_HEADER_SIZE;
        assert_eq!(get_u16(&body, local), context_type::PREAUTH_INTEGRITY_CAPABILITIES);
        assert_eq!(get_u16(&body, local + 8), 1);
        assert_eq!(get_u16(&body, local + 10), 32);
        assert_eq!(get_u16(&body, local + 12), preauth_hash_algorithm::SHA_512);
    }

    #[test]
    fn parses_negotiate_response_offsets_safely() {
        let mut header = Smb2Header::request(Command::Negotiate, 0, 0, 32);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        let header = header.encode();

        let mut body = vec![0u8; NEGOTIATE_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, NEGOTIATE_RESPONSE_STRUCTURE_SIZE);
        put_u16(&mut body, 2, security_mode::SIGNING_ENABLED);
        put_u16(&mut body, 4, Dialect::Smb302 as u16);
        body[8..24].copy_from_slice(&guid());
        put_u32(&mut body, 24, capabilities::LARGE_MTU);
        put_u32(&mut body, 28, 1024 * 1024);
        put_u32(&mut body, 32, 4 * 1024 * 1024);
        put_u32(&mut body, 36, 4 * 1024 * 1024);
        put_u64(&mut body, 40, 1234);
        put_u64(&mut body, 48, 5678);
        put_u16(&mut body, 56, (SMB2_HEADER_SIZE + NEGOTIATE_RESPONSE_FIXED_SIZE) as u16);
        put_u16(&mut body, 58, 3);

        let mut message = Vec::new();
        message.extend_from_slice(&header);
        message.extend_from_slice(&body);
        message.extend_from_slice(&[1, 2, 3]);

        let parsed = NegotiateResponse::decode_message(&message).unwrap();
        assert_eq!(parsed.dialect, Dialect::Smb302);
        assert_eq!(parsed.max_read_size, 4 * 1024 * 1024);
        assert_eq!(parsed.security_blob, vec![1, 2, 3]);
    }

    #[test]
    fn rejects_security_buffer_outside_packet() {
        let mut header = Smb2Header::request(Command::Negotiate, 0, 0, 1);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; NEGOTIATE_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, NEGOTIATE_RESPONSE_STRUCTURE_SIZE);
        put_u16(&mut body, 4, Dialect::Smb302 as u16);
        put_u16(&mut body, 56, 0xFFFF);
        put_u16(&mut body, 58, 16);
        message.extend_from_slice(&body);

        assert!(matches!(
            NegotiateResponse::decode_message(&message),
            Err(WireError::InvalidOffset { .. })
        ));
    }
}
