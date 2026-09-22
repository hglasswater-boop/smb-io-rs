use crate::create::FileId;
use crate::error::{WireError, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u32, put_u16, put_u32,
    put_u64,
};

pub const WRITE_REQUEST_STRUCTURE_SIZE: u16 = 49;
pub const WRITE_REQUEST_FIXED_SIZE: usize = 48;
pub const WRITE_RESPONSE_STRUCTURE_SIZE: u16 = 17;
pub const WRITE_RESPONSE_FIXED_SIZE: usize = 16;
pub const WRITE_DEFAULT_DATA_OFFSET: u16 = (SMB2_HEADER_SIZE + WRITE_REQUEST_FIXED_SIZE) as u16;

pub mod write_channel {
    pub const NONE: u32 = 0x0000_0000;
    pub const RDMA_V1: u32 = 0x0000_0001;
    pub const RDMA_V1_INVALIDATE: u32 = 0x0000_0002;
    pub const RDMA_TRANSFORM: u32 = 0x0000_0003;
}

pub mod write_flags {
    pub const NONE: u32 = 0x0000_0000;
    pub const WRITE_THROUGH: u32 = 0x0000_0001;
    pub const WRITE_UNBUFFERED: u32 = 0x0000_0002;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub offset: u64,
    pub file_id: FileId,
    pub channel: u32,
    pub remaining_bytes: u32,
    pub flags: u32,
    pub data: Vec<u8>,
}

impl WriteRequest {
    pub fn direct(file_id: FileId, offset: u64, data: impl Into<Vec<u8>>) -> Self {
        Self {
            offset,
            file_id,
            channel: write_channel::NONE,
            remaining_bytes: 0,
            flags: write_flags::NONE,
            data: data.into(),
        }
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.file_id.is_zero() {
            return Err(WireError::InvalidField("WRITE FileId"));
        }
        if self.data.len() > u32::MAX as usize {
            return Err(WireError::InvalidField("WRITE Length"));
        }
        if self.channel != write_channel::NONE {
            return Err(WireError::Unsupported("WRITE RDMA channel"));
        }
        if self.remaining_bytes != 0 {
            return Err(WireError::InvalidField(
                "WRITE RemainingBytes without channel information",
            ));
        }
        if self.flags & !(write_flags::WRITE_THROUGH | write_flags::WRITE_UNBUFFERED) != 0 {
            return Err(WireError::InvalidField("WRITE Flags"));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let data_len = u32::try_from(self.data.len())
            .map_err(|_| WireError::InvalidField("WRITE Length"))?;
        let mut body = vec![0u8; WRITE_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, WRITE_REQUEST_STRUCTURE_SIZE);
        put_u16(&mut body, 2, WRITE_DEFAULT_DATA_OFFSET);
        put_u32(&mut body, 4, data_len);
        put_u64(&mut body, 8, self.offset);
        put_u64(&mut body, 16, self.file_id.persistent);
        put_u64(&mut body, 24, self.file_id.volatile);
        put_u32(&mut body, 32, self.channel);
        put_u32(&mut body, 36, self.remaining_bytes);
        put_u16(&mut body, 40, 0);
        put_u16(&mut body, 42, 0);
        put_u32(&mut body, 44, self.flags);
        if self.data.is_empty() {
            // StructureSize is 49 even for a legal zero-length write. Preserve the one-byte
            // Buffer field while Length remains zero.
            body.push(0);
        } else {
            body.extend_from_slice(&self.data);
        }
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
        let mut header =
            Smb2Header::request(Command::Write, message_id, credit_charge, credit_request);
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResponse {
    pub header: Smb2Header,
    pub count: u32,
    pub remaining: u32,
}

impl WriteResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + WRITE_RESPONSE_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Write {
            return Err(WireError::InvalidField("WRITE response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("WRITE response direction"));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != WRITE_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: WRITE_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }
        if get_u16(body, 12) != 0 || get_u16(body, 14) != 0 {
            return Err(WireError::Unsupported("WRITE response channel information"));
        }

        Ok(Self {
            header,
            count: get_u32(body, 4),
            remaining: get_u32(body, 8),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::StatusField;

    #[test]
    fn request_encodes_direct_write_fields_and_payload() {
        let request = WriteRequest::direct(
            FileId::new(0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            0x0102_0304_0506_0708,
            b"hello".to_vec(),
        );
        let message = request.encode_message(7, 8, 9, 4, 32).unwrap();
        let header = Smb2Header::decode(&message).unwrap();
        assert_eq!(header.command, Command::Write);
        assert_eq!(header.credit_charge, 4);
        let body = &message[SMB2_HEADER_SIZE..];
        assert_eq!(get_u16(body, 0), WRITE_REQUEST_STRUCTURE_SIZE);
        assert_eq!(get_u16(body, 2), WRITE_DEFAULT_DATA_OFFSET);
        assert_eq!(get_u32(body, 4), 5);
        assert_eq!(
            u64::from_le_bytes(body[8..16].try_into().unwrap()),
            0x0102_0304_0506_0708
        );
        assert_eq!(&message[usize::from(WRITE_DEFAULT_DATA_OFFSET)..], b"hello");
    }

    #[test]
    fn zero_length_write_keeps_structure_buffer_byte() {
        let request = WriteRequest::direct(FileId::new(1, 2), 0, Vec::new());
        let body = request.encode_body().unwrap();
        assert_eq!(body.len(), WRITE_REQUEST_STRUCTURE_SIZE as usize);
        assert_eq!(get_u32(&body, 4), 0);
        assert_eq!(body[WRITE_REQUEST_FIXED_SIZE], 0);
    }

    #[test]
    fn response_decodes_count() {
        let mut header = Smb2Header::request(Command::Write, 7, 0, 8);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        header.session_id = 8;
        header.id = HeaderId::Sync {
            process_id: 0,
            tree_id: 9,
        };
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; WRITE_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, WRITE_RESPONSE_STRUCTURE_SIZE);
        put_u32(&mut body, 4, 1234);
        message.extend_from_slice(&body);

        let response = WriteResponse::decode_message(&message).unwrap();
        assert_eq!(response.count, 1234);
        assert_eq!(response.remaining, 0);
    }
}
