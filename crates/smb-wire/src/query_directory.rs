use crate::create::FileId;
use crate::error::{WireError, checked_range, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u32, put_u16, put_u32,
    put_u64,
};

pub const QUERY_DIRECTORY_REQUEST_STRUCTURE_SIZE: u16 = 33;
pub const QUERY_DIRECTORY_REQUEST_FIXED_SIZE: usize = 32;
pub const QUERY_DIRECTORY_RESPONSE_STRUCTURE_SIZE: u16 = 9;
pub const QUERY_DIRECTORY_RESPONSE_FIXED_SIZE: usize = 8;

pub mod query_directory_flags {
    pub const NONE: u8 = 0x00;
    pub const RESTART_SCANS: u8 = 0x01;
    pub const RETURN_SINGLE_ENTRY: u8 = 0x02;
    pub const INDEX_SPECIFIED: u8 = 0x04;
    pub const REOPEN: u8 = 0x10;
}

pub mod file_information_class {
    pub const DIRECTORY_INFORMATION: u8 = 0x01;
    pub const FULL_DIRECTORY_INFORMATION: u8 = 0x02;
    pub const BOTH_DIRECTORY_INFORMATION: u8 = 0x03;
    pub const NAMES_INFORMATION: u8 = 0x0c;
    pub const ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;
    pub const ID_FULL_DIRECTORY_INFORMATION: u8 = 0x26;
    pub const ID_EXTD_DIRECTORY_INFORMATION: u8 = 0x3c;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDirectoryRequest {
    pub file_information_class: u8,
    pub flags: u8,
    pub file_index: u32,
    pub file_id: FileId,
    pub file_name: String,
    pub output_buffer_length: u32,
}

impl QueryDirectoryRequest {
    pub fn new(
        file_id: FileId,
        file_information_class: u8,
        file_name: impl Into<String>,
        output_buffer_length: u32,
    ) -> Self {
        Self {
            file_information_class,
            flags: query_directory_flags::NONE,
            file_index: 0,
            file_id,
            file_name: file_name.into(),
            output_buffer_length,
        }
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.file_id.is_zero() {
            return Err(WireError::InvalidField("QUERY_DIRECTORY FileId"));
        }
        if self.file_name.contains('\0') {
            return Err(WireError::InvalidField(
                "QUERY_DIRECTORY FileName must not contain NUL",
            ));
        }
        let file_name_len = self
            .file_name
            .encode_utf16()
            .count()
            .checked_mul(2)
            .ok_or(WireError::InvalidField(
                "QUERY_DIRECTORY FileNameLength overflow",
            ))?;
        if file_name_len > u16::MAX as usize {
            return Err(WireError::InvalidField("QUERY_DIRECTORY FileNameLength"));
        }
        let known_flags = query_directory_flags::RESTART_SCANS
            | query_directory_flags::RETURN_SINGLE_ENTRY
            | query_directory_flags::INDEX_SPECIFIED
            | query_directory_flags::REOPEN;
        if self.flags & !known_flags != 0 {
            return Err(WireError::InvalidField("QUERY_DIRECTORY Flags"));
        }
        if self.flags & query_directory_flags::INDEX_SPECIFIED == 0 && self.file_index != 0 {
            return Err(WireError::InvalidField(
                "QUERY_DIRECTORY FileIndex requires INDEX_SPECIFIED",
            ));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut file_name = Vec::with_capacity(self.file_name.encode_utf16().count() * 2);
        for unit in self.file_name.encode_utf16() {
            file_name.extend_from_slice(&unit.to_le_bytes());
        }

        let mut body = vec![0u8; QUERY_DIRECTORY_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, QUERY_DIRECTORY_REQUEST_STRUCTURE_SIZE);
        body[2] = self.file_information_class;
        body[3] = self.flags;
        put_u32(&mut body, 4, self.file_index);
        put_u64(&mut body, 8, self.file_id.persistent);
        put_u64(&mut body, 16, self.file_id.volatile);
        if file_name.is_empty() {
            put_u16(&mut body, 24, 0);
            put_u16(&mut body, 26, 0);
        } else {
            put_u16(
                &mut body,
                24,
                u16::try_from(SMB2_HEADER_SIZE + QUERY_DIRECTORY_REQUEST_FIXED_SIZE)
                    .map_err(|_| WireError::InvalidField("QUERY_DIRECTORY FileNameOffset"))?,
            );
            put_u16(
                &mut body,
                26,
                u16::try_from(file_name.len())
                    .map_err(|_| WireError::InvalidField("QUERY_DIRECTORY FileNameLength"))?,
            );
        }
        put_u32(&mut body, 28, self.output_buffer_length);
        body.extend_from_slice(&file_name);
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
            Command::QueryDirectory,
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
pub struct QueryDirectoryResponse {
    pub header: Smb2Header,
    pub output_buffer: Vec<u8>,
}

impl QueryDirectoryResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(
            message,
            SMB2_HEADER_SIZE + QUERY_DIRECTORY_RESPONSE_FIXED_SIZE,
        )?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::QueryDirectory {
            return Err(WireError::InvalidField("QUERY_DIRECTORY response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField(
                "QUERY_DIRECTORY response direction",
            ));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != QUERY_DIRECTORY_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: QUERY_DIRECTORY_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }

        let output_offset = usize::from(get_u16(body, 2));
        let output_length = usize::try_from(get_u32(body, 4))
            .map_err(|_| WireError::InvalidField("QUERY_DIRECTORY OutputBufferLength"))?;
        let output_buffer = if output_length == 0 {
            if output_offset != 0 {
                return Err(WireError::InvalidField(
                    "QUERY_DIRECTORY zero-length output has nonzero offset",
                ));
            }
            Vec::new()
        } else {
            if output_offset < SMB2_HEADER_SIZE + QUERY_DIRECTORY_RESPONSE_FIXED_SIZE {
                return Err(WireError::InvalidField(
                    "QUERY_DIRECTORY OutputBufferOffset before response buffer",
                ));
            }
            let range = checked_range(
                message.len(),
                "QUERY_DIRECTORY Buffer",
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
    fn request_encodes_utf16_search_pattern() {
        let request = QueryDirectoryRequest::new(
            FileId::new(1, 2),
            file_information_class::ID_BOTH_DIRECTORY_INFORMATION,
            "*.mkv",
            64 * 1024,
        );
        let message = request.encode_message(7, 8, 9, 1, 16).unwrap();
        let header = Smb2Header::decode(&message).unwrap();
        assert_eq!(header.command, Command::QueryDirectory);
        let body = &message[SMB2_HEADER_SIZE..];
        assert_eq!(get_u16(body, 0), QUERY_DIRECTORY_REQUEST_STRUCTURE_SIZE);
        assert_eq!(
            usize::from(get_u16(body, 24)),
            SMB2_HEADER_SIZE + QUERY_DIRECTORY_REQUEST_FIXED_SIZE
        );
        assert_eq!(get_u16(body, 26), 10);
        assert_eq!(get_u32(body, 28), 64 * 1024);
    }

    #[test]
    fn response_extracts_directory_buffer() {
        let mut header = Smb2Header::request(Command::QueryDirectory, 7, 0, 8);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; QUERY_DIRECTORY_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, QUERY_DIRECTORY_RESPONSE_STRUCTURE_SIZE);
        put_u16(
            &mut body,
            2,
            u16::try_from(SMB2_HEADER_SIZE + QUERY_DIRECTORY_RESPONSE_FIXED_SIZE).unwrap(),
        );
        put_u32(&mut body, 4, 4);
        message.extend_from_slice(&body);
        message.extend_from_slice(&[1, 2, 3, 4]);

        let response = QueryDirectoryResponse::decode_message(&message).unwrap();
        assert_eq!(response.output_buffer, vec![1, 2, 3, 4]);
    }
}
