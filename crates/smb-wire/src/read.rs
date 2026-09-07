use crate::create::FileId;
use crate::error::{WireError, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u32, put_u16, put_u32,
    put_u64,
};

pub const READ_REQUEST_STRUCTURE_SIZE: u16 = 49;
pub const READ_REQUEST_FIXED_SIZE: usize = 48;
pub const READ_RESPONSE_STRUCTURE_SIZE: u16 = 17;
pub const READ_RESPONSE_FIXED_SIZE: usize = 16;

pub mod read_request_flags {
    pub const NONE: u8 = 0x00;
    pub const READ_UNBUFFERED: u8 = 0x01;
    pub const REQUEST_COMPRESSED: u8 = 0x02;
}

pub mod read_channel {
    pub const NONE: u32 = 0x0000_0000;
    pub const RDMA_V1: u32 = 0x0000_0001;
    pub const RDMA_V1_INVALIDATE: u32 = 0x0000_0002;
}

pub mod read_response_flags {
    pub const NONE: u32 = 0x0000_0000;
    pub const RDMA_TRANSFORM: u32 = 0x0000_0001;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub padding: u8,
    pub flags: u8,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub minimum_count: u32,
    pub channel: u32,
    pub remaining_bytes: u32,
}

impl ReadRequest {
    pub fn direct(file_id: FileId, offset: u64, length: u32) -> Self {
        Self {
            padding: 0,
            flags: read_request_flags::NONE,
            length,
            offset,
            file_id,
            minimum_count: 0,
            channel: read_channel::NONE,
            remaining_bytes: 0,
        }
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.file_id.is_zero() {
            return Err(WireError::InvalidField("READ FileId"));
        }
        if self.flags & !(read_request_flags::READ_UNBUFFERED | read_request_flags::REQUEST_COMPRESSED)
            != 0
        {
            return Err(WireError::InvalidField("READ Flags"));
        }
        if self.channel != read_channel::NONE {
            return Err(WireError::Unsupported("READ RDMA channel"));
        }
        if self.remaining_bytes != 0 {
            return Err(WireError::InvalidField(
                "READ RemainingBytes without channel information",
            ));
        }
        if self.minimum_count > self.length {
            return Err(WireError::InvalidField("READ MinimumCount exceeds Length"));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut body = vec![0u8; READ_REQUEST_FIXED_SIZE + 1];
        put_u16(&mut body, 0, READ_REQUEST_STRUCTURE_SIZE);
        body[2] = self.padding;
        body[3] = self.flags;
        put_u32(&mut body, 4, self.length);
        put_u64(&mut body, 8, self.offset);
        put_u64(&mut body, 16, self.file_id.persistent);
        put_u64(&mut body, 24, self.file_id.volatile);
        put_u32(&mut body, 32, self.minimum_count);
        put_u32(&mut body, 36, self.channel);
        put_u32(&mut body, 40, self.remaining_bytes);
        put_u16(&mut body, 44, 0);
        put_u16(&mut body, 46, 0);
        // Buffer is required to occupy at least one byte even when no channel data is present.
        body[48] = 0;
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
            Smb2Header::request(Command::Read, message_id, credit_charge, credit_request);
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
pub struct ReadResponse {
    pub header: Smb2Header,
    pub data_remaining: u32,
    pub flags: u32,
    pub data: Vec<u8>,
}

impl ReadResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + READ_RESPONSE_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Read {
            return Err(WireError::InvalidField("READ response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("READ response direction"));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != READ_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: READ_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }

        let data_offset = usize::from(body[2]);
        let data_length = usize::try_from(get_u32(body, 4))
            .map_err(|_| WireError::InvalidField("READ DataLength"))?;
        if data_length == 0 {
            return Err(WireError::InvalidField(
                "successful READ response contains no data",
            ));
        }
        if data_offset < SMB2_HEADER_SIZE + READ_RESPONSE_FIXED_SIZE {
            return Err(WireError::InvalidField(
                "READ DataOffset before response buffer",
            ));
        }
        let end = data_offset
            .checked_add(data_length)
            .ok_or(WireError::InvalidField("READ DataLength overflow"))?;
        if end > message.len() {
            return Err(WireError::InvalidOffset {
                field: "READ Buffer",
                offset: data_offset,
                len: data_length,
                packet_len: message.len(),
            });
        }

        Ok(Self {
            header,
            data_remaining: get_u32(body, 8),
            flags: get_u32(body, 12),
            data: message[data_offset..end].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::StatusField;

    #[test]
    fn request_encodes_offset_length_file_id_and_credit_charge() {
        let request = ReadRequest::direct(
            FileId::new(0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            4 * 1024 * 1024 * 1024,
            1024 * 1024,
        );
        let message = request.encode_message(7, 8, 9, 16, 32).unwrap();
        let header = Smb2Header::decode(&message).unwrap();
        assert_eq!(header.command, Command::Read);
        assert_eq!(header.credit_charge, 16);
        assert_eq!(header.session_id, 8);
        assert!(matches!(header.id, HeaderId::Sync { tree_id: 9, .. }));
        let body = &message[SMB2_HEADER_SIZE..];
        assert_eq!(get_u16(body, 0), READ_REQUEST_STRUCTURE_SIZE);
        assert_eq!(get_u32(body, 4), 1024 * 1024);
        assert_eq!(
            u64::from_le_bytes(body[8..16].try_into().unwrap()),
            4 * 1024 * 1024 * 1024
        );
        assert_eq!(message.len(), SMB2_HEADER_SIZE + READ_REQUEST_FIXED_SIZE + 1);
    }

    #[test]
    fn response_extracts_data_using_server_offset() {
        let mut header = Smb2Header::request(Command::Read, 7, 0, 8);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        header.session_id = 8;
        header.id = HeaderId::Sync {
            process_id: 0,
            tree_id: 9,
        };
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; READ_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, READ_RESPONSE_STRUCTURE_SIZE);
        body[2] = 80;
        put_u32(&mut body, 4, 5);
        put_u32(&mut body, 8, 0);
        put_u32(&mut body, 12, read_response_flags::NONE);
        message.extend_from_slice(&body);
        message.extend_from_slice(b"hello");

        let response = ReadResponse::decode_message(&message).unwrap();
        assert_eq!(response.data, b"hello");
        assert_eq!(response.data_remaining, 0);
    }
}
