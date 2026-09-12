use crate::error::{WireError, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u32, get_u64, put_u16,
    put_u32, put_u64,
};

pub const CREATE_REQUEST_STRUCTURE_SIZE: u16 = 57;
pub const CREATE_REQUEST_FIXED_SIZE: usize = 56;
pub const CREATE_RESPONSE_STRUCTURE_SIZE: u16 = 89;
pub const CREATE_RESPONSE_FIXED_SIZE: usize = 88;

pub mod oplock_level {
    pub const NONE: u8 = 0x00;
    pub const LEVEL_II: u8 = 0x01;
    pub const EXCLUSIVE: u8 = 0x08;
    pub const BATCH: u8 = 0x09;
    pub const LEASE: u8 = 0xff;
}

pub mod impersonation_level {
    pub const ANONYMOUS: u32 = 0x0000_0000;
    pub const IDENTIFICATION: u32 = 0x0000_0001;
    pub const IMPERSONATION: u32 = 0x0000_0002;
    pub const DELEGATE: u32 = 0x0000_0003;
}

pub mod desired_access {
    pub const FILE_READ_DATA: u32 = 0x0000_0001;
    pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
    pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
    pub const FILE_READ_EA: u32 = 0x0000_0008;
    pub const FILE_WRITE_EA: u32 = 0x0000_0010;
    pub const FILE_EXECUTE: u32 = 0x0000_0020;
    pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    pub const DELETE: u32 = 0x0001_0000;
    pub const READ_CONTROL: u32 = 0x0002_0000;
    pub const WRITE_DAC: u32 = 0x0004_0000;
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
    pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_READ: u32 = 0x8000_0000;
}

pub mod share_access {
    pub const READ: u32 = 0x0000_0001;
    pub const WRITE: u32 = 0x0000_0002;
    pub const DELETE: u32 = 0x0000_0004;
}

pub mod create_disposition {
    pub const SUPERSEDE: u32 = 0x0000_0000;
    pub const OPEN: u32 = 0x0000_0001;
    pub const CREATE: u32 = 0x0000_0002;
    pub const OPEN_IF: u32 = 0x0000_0003;
    pub const OVERWRITE: u32 = 0x0000_0004;
    pub const OVERWRITE_IF: u32 = 0x0000_0005;
}

pub mod create_options {
    pub const DIRECTORY_FILE: u32 = 0x0000_0001;
    pub const WRITE_THROUGH: u32 = 0x0000_0002;
    pub const SEQUENTIAL_ONLY: u32 = 0x0000_0004;
    pub const NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
    pub const SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
    pub const SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    pub const NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    pub const COMPLETE_IF_OPLOCKED: u32 = 0x0000_0100;
    pub const NO_EA_KNOWLEDGE: u32 = 0x0000_0200;
    pub const OPEN_REMOTE_INSTANCE: u32 = 0x0000_0400;
    pub const RANDOM_ACCESS: u32 = 0x0000_0800;
    pub const DELETE_ON_CLOSE: u32 = 0x0000_1000;
    pub const OPEN_BY_FILE_ID: u32 = 0x0000_2000;
    pub const OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
    pub const NO_COMPRESSION: u32 = 0x0000_8000;
    pub const OPEN_REQUIRING_OPLOCK: u32 = 0x0001_0000;
    pub const DISALLOW_EXCLUSIVE: u32 = 0x0002_0000;
    pub const RESERVE_OPFILTER: u32 = 0x0010_0000;
    pub const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    pub const OPEN_NO_RECALL: u32 = 0x0040_0000;
    pub const OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x0080_0000;
}

pub mod create_action {
    pub const SUPERSEDED: u32 = 0x0000_0000;
    pub const OPENED: u32 = 0x0000_0001;
    pub const CREATED: u32 = 0x0000_0002;
    pub const OVERWRITTEN: u32 = 0x0000_0003;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

impl FileId {
    pub const fn new(persistent: u64, volatile: u64) -> Self {
        Self {
            persistent,
            volatile,
        }
    }

    pub const fn is_zero(self) -> bool {
        self.persistent == 0 && self.volatile == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    pub requested_oplock_level: u8,
    pub impersonation_level: u32,
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub name: String,
}

impl CreateRequest {
    pub fn open_existing_read(name: impl Into<String>) -> Self {
        Self {
            requested_oplock_level: oplock_level::NONE,
            impersonation_level: impersonation_level::IMPERSONATION,
            desired_access: desired_access::GENERIC_READ,
            file_attributes: 0,
            share_access: share_access::READ | share_access::WRITE | share_access::DELETE,
            create_disposition: create_disposition::OPEN,
            create_options: create_options::NON_DIRECTORY_FILE | create_options::RANDOM_ACCESS,
            name: name.into(),
        }
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.requested_oplock_level == oplock_level::LEASE {
            return Err(WireError::Unsupported("CREATE lease context"));
        }
        if !matches!(
            self.requested_oplock_level,
            oplock_level::NONE
                | oplock_level::LEVEL_II
                | oplock_level::EXCLUSIVE
                | oplock_level::BATCH
        ) {
            return Err(WireError::InvalidField("CREATE RequestedOplockLevel"));
        }
        if self.impersonation_level > impersonation_level::DELEGATE {
            return Err(WireError::InvalidField("CREATE ImpersonationLevel"));
        }
        if self.create_disposition > create_disposition::OVERWRITE_IF {
            return Err(WireError::InvalidField("CREATE CreateDisposition"));
        }
        if self.create_options & create_options::DIRECTORY_FILE != 0
            && self.create_options & create_options::NON_DIRECTORY_FILE != 0
        {
            return Err(WireError::InvalidField(
                "CREATE directory and non-directory options conflict",
            ));
        }
        if self.create_options & create_options::SEQUENTIAL_ONLY != 0
            && self.create_options & create_options::RANDOM_ACCESS != 0
        {
            return Err(WireError::InvalidField(
                "CREATE sequential and random access options conflict",
            ));
        }
        if self.name.starts_with('\\') || self.name.starts_with('/') {
            return Err(WireError::InvalidField(
                "CREATE name must be relative to the tree",
            ));
        }
        if self.name.contains('\0') {
            return Err(WireError::InvalidField("CREATE name must not contain NUL"));
        }
        let name_len = self
            .name
            .encode_utf16()
            .count()
            .checked_mul(2)
            .ok_or(WireError::InvalidField("CREATE NameLength overflow"))?;
        if name_len > u16::MAX as usize {
            return Err(WireError::InvalidField("CREATE NameLength"));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut name = Vec::with_capacity(self.name.encode_utf16().count() * 2);
        for unit in self.name.encode_utf16() {
            name.extend_from_slice(&unit.to_le_bytes());
        }

        let mut body = vec![0u8; CREATE_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, CREATE_REQUEST_STRUCTURE_SIZE);
        body[2] = 0;
        body[3] = self.requested_oplock_level;
        put_u32(&mut body, 4, self.impersonation_level);
        put_u64(&mut body, 8, 0);
        put_u64(&mut body, 16, 0);
        put_u32(&mut body, 24, self.desired_access);
        put_u32(&mut body, 28, self.file_attributes);
        put_u32(&mut body, 32, self.share_access);
        put_u32(&mut body, 36, self.create_disposition);
        put_u32(&mut body, 40, self.create_options);

        let name_offset = u16::try_from(SMB2_HEADER_SIZE + CREATE_REQUEST_FIXED_SIZE)
            .map_err(|_| WireError::InvalidField("CREATE NameOffset"))?;
        put_u16(&mut body, 44, name_offset);
        if name.is_empty() {
            put_u16(&mut body, 46, 0);
            body.push(0);
        } else {
            put_u16(
                &mut body,
                46,
                u16::try_from(name.len())
                    .map_err(|_| WireError::InvalidField("CREATE NameLength"))?,
            );
            body.extend_from_slice(&name);
        }
        put_u32(&mut body, 48, 0);
        put_u32(&mut body, 52, 0);
        Ok(body)
    }

    pub fn encode_message(
        &self,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        credit_request: u16,
    ) -> Result<Vec<u8>, WireError> {
        let mut header = Smb2Header::request(Command::Create, message_id, 0, credit_request);
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
pub struct CreateResponse {
    pub header: Smb2Header,
    pub oplock_level: u8,
    pub flags: u8,
    pub create_action: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
    pub file_id: FileId,
    pub create_contexts_offset: u32,
    pub create_contexts_length: u32,
}

impl CreateResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + CREATE_RESPONSE_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::Create {
            return Err(WireError::InvalidField("CREATE response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("CREATE response direction"));
        }
        if matches!(header.id, HeaderId::Async { .. }) {
            return Err(WireError::InvalidField(
                "CREATE response must use a synchronous header",
            ));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != CREATE_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: CREATE_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }

        let create_contexts_offset = get_u32(body, 80);
        let create_contexts_length = get_u32(body, 84);
        if create_contexts_length != 0 {
            let offset = usize::try_from(create_contexts_offset)
                .map_err(|_| WireError::InvalidField("CREATE CreateContextsOffset"))?;
            let len = usize::try_from(create_contexts_length)
                .map_err(|_| WireError::InvalidField("CREATE CreateContextsLength"))?;
            let end = offset.checked_add(len).ok_or(WireError::InvalidField(
                "CREATE create-context length overflow",
            ))?;
            if offset % 8 != 0 || end > message.len() {
                return Err(WireError::InvalidOffset {
                    field: "CREATE CreateContexts",
                    offset,
                    len,
                    packet_len: message.len(),
                });
            }
        } else if create_contexts_offset != 0 {
            return Err(WireError::InvalidField(
                "CREATE CreateContextsOffset without contexts",
            ));
        }

        Ok(Self {
            header,
            oplock_level: body[2],
            flags: body[3],
            create_action: get_u32(body, 4),
            creation_time: get_u64(body, 8),
            last_access_time: get_u64(body, 16),
            last_write_time: get_u64(body, 24),
            change_time: get_u64(body, 32),
            allocation_size: get_u64(body, 40),
            end_of_file: get_u64(body, 48),
            file_attributes: get_u32(body, 56),
            file_id: FileId::new(get_u64(body, 64), get_u64(body, 72)),
            create_contexts_offset,
            create_contexts_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::StatusField;

    #[test]
    fn video_read_open_encodes_relative_utf16_name() {
        let request = CreateRequest::open_existing_read("movies\\sample.mkv");
        let body = request.encode_body().unwrap();
        assert_eq!(get_u16(&body, 0), CREATE_REQUEST_STRUCTURE_SIZE);
        assert_eq!(body[3], oplock_level::NONE);
        assert_eq!(get_u32(&body, 24), desired_access::GENERIC_READ);
        assert_eq!(
            get_u32(&body, 32),
            share_access::READ | share_access::WRITE | share_access::DELETE
        );
        assert_eq!(get_u32(&body, 36), create_disposition::OPEN);
        assert_eq!(
            get_u32(&body, 40),
            create_options::NON_DIRECTORY_FILE | create_options::RANDOM_ACCESS
        );
        assert_eq!(get_u16(&body, 44), 120);
        assert_eq!(
            usize::from(get_u16(&body, 46)),
            "movies\\sample.mkv".encode_utf16().count() * 2
        );
    }

    #[test]
    fn root_open_keeps_buffer_offset_with_zero_name_length() {
        let request = CreateRequest::open_existing_read("");
        let body = request.encode_body().unwrap();
        assert_eq!(body.len(), CREATE_REQUEST_FIXED_SIZE + 1);
        assert_eq!(get_u16(&body, 44), 120);
        assert_eq!(get_u16(&body, 46), 0);
    }

    #[test]
    fn create_response_decodes_file_id_and_size() {
        let mut header = Smb2Header::request(Command::Create, 4, 0, 8);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        header.session_id = 7;
        header.id = HeaderId::Sync {
            process_id: 0,
            tree_id: 9,
        };
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; CREATE_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, CREATE_RESPONSE_STRUCTURE_SIZE);
        body[2] = oplock_level::NONE;
        put_u32(&mut body, 4, create_action::OPENED);
        put_u64(&mut body, 40, 8 * 1024 * 1024);
        put_u64(&mut body, 48, 7 * 1024 * 1024);
        put_u32(&mut body, 56, 0x20);
        put_u64(&mut body, 64, 0x1111_2222_3333_4444);
        put_u64(&mut body, 72, 0x5555_6666_7777_8888);
        message.extend_from_slice(&body);

        let response = CreateResponse::decode_message(&message).unwrap();
        assert_eq!(response.end_of_file, 7 * 1024 * 1024);
        assert_eq!(response.allocation_size, 8 * 1024 * 1024);
        assert_eq!(response.file_id.persistent, 0x1111_2222_3333_4444);
        assert_eq!(response.file_id.volatile, 0x5555_6666_7777_8888);
    }
}
