use crate::create::FileId;
use crate::error::{WireError, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, put_u16, put_u32, put_u64,
};
use crate::query_info::info_type;

pub const SET_INFO_REQUEST_STRUCTURE_SIZE: u16 = 33;
pub const SET_INFO_REQUEST_FIXED_SIZE: usize = 32;
pub const SET_INFO_RESPONSE_STRUCTURE_SIZE: u16 = 2;
pub const SET_INFO_RESPONSE_FIXED_SIZE: usize = 2;

const RENAME_INFORMATION_FIXED_SIZE: usize = 20;
const RENAME_INFORMATION_MIN_SIZE: usize = 24;

pub mod set_info_class {
    pub const FILE_RENAME_INFORMATION: u8 = 10;
    pub const FILE_DISPOSITION_INFORMATION: u8 = 13;
    pub const FILE_DISPOSITION_INFORMATION_EX: u8 = 64;
    pub const FILE_RENAME_INFORMATION_EX: u8 = 65;
}

pub mod rename_flags {
    pub const REPLACE_IF_EXISTS: u32 = 0x0000_0001;
    pub const POSIX_SEMANTICS: u32 = 0x0000_0002;
    pub const SUPPRESS_PIN_STATE_INHERITANCE: u32 = 0x0000_0004;
    pub const SUPPRESS_STORAGE_RESERVE_INHERITANCE: u32 = 0x0000_0008;
    pub const NO_INCREASE_AVAILABLE_SPACE: u32 = 0x0000_0010;
    pub const NO_DECREASE_AVAILABLE_SPACE: u32 = 0x0000_0020;
    pub const PRESERVE_AVAILABLE_SPACE: u32 = 0x0000_0030;
    pub const IGNORE_READONLY_ATTRIBUTE: u32 = 0x0000_0040;
    pub const FORCE_RESIZE_TARGET_SR: u32 = 0x0000_0080;
    pub const FORCE_RESIZE_SOURCE_SR: u32 = 0x0000_0100;
    pub const FORCE_RESIZE_SR: u32 = 0x0000_0180;
}

pub mod disposition_flags {
    pub const DELETE: u32 = 0x0000_0001;
    pub const POSIX_SEMANTICS: u32 = 0x0000_0002;
    pub const FORCE_IMAGE_SECTION_CHECK: u32 = 0x0000_0004;
    pub const ON_CLOSE: u32 = 0x0000_0008;
    pub const IGNORE_READONLY_ATTRIBUTE: u32 = 0x0000_0010;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoRequest {
    pub info_type: u8,
    pub file_info_class: u8,
    pub buffer: Vec<u8>,
    pub additional_information: u32,
    pub file_id: FileId,
}

impl SetInfoRequest {
    pub fn file(file_id: FileId, file_info_class: u8, buffer: Vec<u8>) -> Self {
        Self {
            info_type: info_type::FILE,
            file_info_class,
            buffer,
            additional_information: 0,
            file_id,
        }
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.file_id.is_zero() {
            return Err(WireError::InvalidField("SET_INFO FileId"));
        }
        if !matches!(
            self.info_type,
            info_type::FILE | info_type::FILESYSTEM | info_type::SECURITY | info_type::QUOTA
        ) {
            return Err(WireError::InvalidField("SET_INFO InfoType"));
        }
        if self.buffer.is_empty() {
            return Err(WireError::InvalidField("SET_INFO BufferLength"));
        }
        if self.buffer.len() > u32::MAX as usize {
            return Err(WireError::InvalidField("SET_INFO BufferLength"));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut body = vec![0u8; SET_INFO_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, SET_INFO_REQUEST_STRUCTURE_SIZE);
        body[2] = self.info_type;
        body[3] = self.file_info_class;
        put_u32(
            &mut body,
            4,
            u32::try_from(self.buffer.len())
                .map_err(|_| WireError::InvalidField("SET_INFO BufferLength"))?,
        );
        put_u16(
            &mut body,
            8,
            u16::try_from(SMB2_HEADER_SIZE + SET_INFO_REQUEST_FIXED_SIZE)
                .map_err(|_| WireError::InvalidField("SET_INFO BufferOffset"))?,
        );
        put_u16(&mut body, 10, 0);
        put_u32(&mut body, 12, self.additional_information);
        put_u64(&mut body, 16, self.file_id.persistent);
        put_u64(&mut body, 24, self.file_id.volatile);
        body.extend_from_slice(&self.buffer);
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
            Command::SetInfo,
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
pub struct SetInfoResponse {
    pub header: Smb2Header,
}

impl SetInfoResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + SET_INFO_RESPONSE_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::SetInfo {
            return Err(WireError::InvalidField("SET_INFO response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("SET_INFO response direction"));
        }
        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != SET_INFO_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: SET_INFO_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }
        Ok(Self { header })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRenameInformation {
    file_name: String,
    replace_if_exists: bool,
}

impl FileRenameInformation {
    pub fn new(file_name: impl Into<String>, replace_if_exists: bool) -> Self {
        Self {
            file_name: file_name.into(),
            replace_if_exists,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let name = encode_relative_utf16_name(&self.file_name)?;
        let mut out = vec![0u8; RENAME_INFORMATION_FIXED_SIZE + name.len()];
        out[0] = u8::from(self.replace_if_exists);
        put_u64(&mut out, 8, 0);
        put_u32(
            &mut out,
            16,
            u32::try_from(name.len())
                .map_err(|_| WireError::InvalidField("FileRenameInformation FileNameLength"))?,
        );
        out[RENAME_INFORMATION_FIXED_SIZE..].copy_from_slice(&name);
        out.resize(out.len().max(RENAME_INFORMATION_MIN_SIZE), 0);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRenameInformationEx {
    file_name: String,
    flags: u32,
}

impl FileRenameInformationEx {
    pub fn new(file_name: impl Into<String>, flags: u32) -> Self {
        Self {
            file_name: file_name.into(),
            flags,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let name = encode_relative_utf16_name(&self.file_name)?;
        let mut out = vec![0u8; RENAME_INFORMATION_FIXED_SIZE + name.len()];
        put_u32(&mut out, 0, self.flags);
        put_u32(&mut out, 4, 0);
        put_u64(&mut out, 8, 0);
        put_u32(
            &mut out,
            16,
            u32::try_from(name.len())
                .map_err(|_| WireError::InvalidField("FileRenameInformationEx FileNameLength"))?,
        );
        out[RENAME_INFORMATION_FIXED_SIZE..].copy_from_slice(&name);
        out.resize(out.len().max(RENAME_INFORMATION_MIN_SIZE), 0);
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDispositionInformation {
    delete_pending: bool,
}

impl FileDispositionInformation {
    pub const fn delete() -> Self {
        Self {
            delete_pending: true,
        }
    }

    pub const fn keep() -> Self {
        Self {
            delete_pending: false,
        }
    }

    pub fn encode(self) -> Vec<u8> {
        vec![u8::from(self.delete_pending)]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDispositionInformationEx {
    flags: u32,
}

impl FileDispositionInformationEx {
    pub const fn new(flags: u32) -> Self {
        Self { flags }
    }

    pub fn encode(self) -> Vec<u8> {
        self.flags.to_le_bytes().to_vec()
    }
}

fn encode_relative_utf16_name(name: &str) -> Result<Vec<u8>, WireError> {
    if name.is_empty() {
        return Err(WireError::InvalidField("rename target must not be empty"));
    }
    if name.starts_with('\\') || name.starts_with('/') {
        return Err(WireError::InvalidField(
            "rename target must be relative to the tree",
        ));
    }
    if name.contains('\0') {
        return Err(WireError::InvalidField("rename target must not contain NUL"));
    }
    let mut out = Vec::with_capacity(name.encode_utf16().count() * 2);
    for unit in name.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    if out.len() > u32::MAX as usize {
        return Err(WireError::InvalidField("rename target exceeds u32 length"));
    }
    Ok(out)
}
