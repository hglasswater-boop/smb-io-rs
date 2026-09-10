use crate::create::FileId;
use crate::error::{WireError, checked_range, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u32, put_u16, put_u32,
    put_u64,
};

pub const QUERY_INFO_REQUEST_STRUCTURE_SIZE: u16 = 41;
pub const QUERY_INFO_REQUEST_FIXED_SIZE: usize = 40;
pub const QUERY_INFO_RESPONSE_STRUCTURE_SIZE: u16 = 9;
pub const QUERY_INFO_RESPONSE_FIXED_SIZE: usize = 8;

pub mod info_type {
    pub const FILE: u8 = 0x01;
    pub const FILESYSTEM: u8 = 0x02;
    pub const SECURITY: u8 = 0x03;
    pub const QUOTA: u8 = 0x04;
}

pub mod query_info_flags {
    pub const NONE: u32 = 0x0000_0000;
    pub const RESTART_SCAN: u32 = 0x0000_0001;
    pub const RETURN_SINGLE_ENTRY: u32 = 0x0000_0002;
    pub const INDEX_SPECIFIED: u32 = 0x0000_0004;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfoRequest {
    pub info_type: u8,
    pub file_info_class: u8,
    pub output_buffer_length: u32,
    pub input_buffer: Vec<u8>,
    pub additional_information: u32,
    pub flags: u32,
    pub file_id: FileId,
}

impl QueryInfoRequest {
    pub fn file(file_id: FileId, file_info_class: u8, output_buffer_length: u32) -> Self {
        Self {
            info_type: info_type::FILE,
            file_info_class,
            output_buffer_length,
            input_buffer: Vec::new(),
            additional_information: 0,
            flags: query_info_flags::NONE,
            file_id,
        }
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.file_id.is_zero() {
            return Err(WireError::InvalidField("QUERY_INFO FileId"));
        }
        if !matches!(
            self.info_type,
            info_type::FILE | info_type::FILESYSTEM | info_type::SECURITY | info_type::QUOTA
        ) {
            return Err(WireError::InvalidField("QUERY_INFO InfoType"));
        }
        if self.input_buffer.len() > u32::MAX as usize {
            return Err(WireError::InvalidField("QUERY_INFO InputBufferLength"));
        }
        if !self.input_buffer.is_empty()
            && SMB2_HEADER_SIZE + QUERY_INFO_REQUEST_FIXED_SIZE > u16::MAX as usize
        {
            return Err(WireError::InvalidField("QUERY_INFO InputBufferOffset"));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut body = vec![0u8; QUERY_INFO_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, QUERY_INFO_REQUEST_STRUCTURE_SIZE);
        body[2] = self.info_type;
        body[3] = self.file_info_class;
        put_u32(&mut body, 4, self.output_buffer_length);

        if self.input_buffer.is_empty() {
            put_u16(&mut body, 8, 0);
            put_u32(&mut body, 12, 0);
        } else {
            put_u16(
                &mut body,
                8,
                u16::try_from(SMB2_HEADER_SIZE + QUERY_INFO_REQUEST_FIXED_SIZE)
                    .map_err(|_| WireError::InvalidField("QUERY_INFO InputBufferOffset"))?,
            );
            put_u32(
                &mut body,
                12,
                u32::try_from(self.input_buffer.len())
                    .map_err(|_| WireError::InvalidField("QUERY_INFO InputBufferLength"))?,
            );
        }
        put_u16(&mut body, 10, 0);
        put_u32(&mut body, 16, self.additional_information);
        put_u32(&mut body, 20, self.flags);
        put_u64(&mut body, 24, self.file_id.persistent);
        put_u64(&mut body, 32, self.file_id.volatile);
        body.extend_from_slice(&self.input_buffer);
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
        let mut header = Smb2Header::request(
            Command::QueryInfo,
            message_id,
            credit_charge,
            credit_request,
        );
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
pub struct QueryInfoResponse {
    pub header: Smb2Header,
    pub output_buffer: Vec<u8>,
}

impl QueryInfoResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + QUERY_INFO_RESPONSE_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::QueryInfo {
            return Err(WireError::InvalidField("QUERY_INFO response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("QUERY_INFO response direction"));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != QUERY_INFO_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: QUERY_INFO_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }

        let output_offset = usize::from(get_u16(body, 2));
        let output_length = usize::try_from(get_u32(body, 4))
            .map_err(|_| WireError::InvalidField("QUERY_INFO OutputBufferLength"))?;
        let output_buffer = if output_length == 0 {
            if output_offset != 0 {
                return Err(WireError::InvalidField(
                    "QUERY_INFO zero-length output has nonzero offset",
                ));
            }
            Vec::new()
        } else {
            if output_offset < SMB2_HEADER_SIZE + QUERY_INFO_RESPONSE_FIXED_SIZE {
                return Err(WireError::InvalidField(
                    "QUERY_INFO OutputBufferOffset before response buffer",
                ));
            }
            let range = checked_range(
                message.len(),
                "QUERY_INFO Buffer",
                output_offset,
                output_length,
            )?;
            message[range].to_vec()
        };

        Ok(Self {
            header,
            output_buffer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::StatusField;

    #[test]
    fn request_encodes_file_query_and_optional_input_buffer() {
        let mut request = QueryInfoRequest::file(
            FileId::new(0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            0x12,
            4096,
        );
        request.input_buffer = vec![1, 2, 3, 4];
        let message = request.encode_message(7, 8, 9, 1, 16).unwrap();
        let header = Smb2Header::decode(&message).unwrap();
        assert_eq!(header.command, Command::QueryInfo);
        assert_eq!(header.credit_charge, 1);
        let body = &message[SMB2_HEADER_SIZE..];
        assert_eq!(get_u16(body, 0), QUERY_INFO_REQUEST_STRUCTURE_SIZE);
        assert_eq!(body[2], info_type::FILE);
        assert_eq!(body[3], 0x12);
        assert_eq!(get_u32(body, 4), 4096);
        assert_eq!(usize::from(get_u16(body, 8)), SMB2_HEADER_SIZE + QUERY_INFO_REQUEST_FIXED_SIZE);
        assert_eq!(get_u32(body, 12), 4);
        assert_eq!(&body[QUERY_INFO_REQUEST_FIXED_SIZE..], &[1, 2, 3, 4]);
    }

    #[test]
    fn response_extracts_output_using_server_offset() {
        let mut header = Smb2Header::request(Command::QueryInfo, 7, 0, 8);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; QUERY_INFO_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, QUERY_INFO_RESPONSE_STRUCTURE_SIZE);
        put_u16(
            &mut body,
            2,
            u16::try_from(SMB2_HEADER_SIZE + QUERY_INFO_RESPONSE_FIXED_SIZE).unwrap(),
        );
        put_u32(&mut body, 4, 5);
        message.extend_from_slice(&body);
        message.extend_from_slice(b"hello");

        let response = QueryInfoResponse::decode_message(&message).unwrap();
        assert_eq!(response.output_buffer, b"hello");
    }

    #[test]
    fn response_rejects_out_of_bounds_output() {
        let mut header = Smb2Header::request(Command::QueryInfo, 7, 0, 8);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; QUERY_INFO_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, QUERY_INFO_RESPONSE_STRUCTURE_SIZE);
        put_u16(&mut body, 2, 72);
        put_u32(&mut body, 4, 100);
        message.extend_from_slice(&body);
        assert!(matches!(
            QueryInfoResponse::decode_message(&message),
            Err(WireError::InvalidOffset { .. })
        ));
    }
}
