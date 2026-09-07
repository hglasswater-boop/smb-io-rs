use crate::error::{WireError, require_len};
use crate::header::{
    Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, flags, get_u16, get_u32, put_u16,
};

pub const TREE_CONNECT_REQUEST_STRUCTURE_SIZE: u16 = 9;
pub const TREE_CONNECT_REQUEST_FIXED_SIZE: usize = 8;
pub const TREE_CONNECT_RESPONSE_STRUCTURE_SIZE: u16 = 16;
pub const TREE_CONNECT_RESPONSE_FIXED_SIZE: usize = 16;

pub mod tree_connect_flags {
    pub const CLUSTER_RECONNECT: u16 = 0x0001;
    pub const REDIRECT_TO_OWNER: u16 = 0x0002;
    pub const EXTENSION_PRESENT: u16 = 0x0004;
}

pub mod share_type {
    pub const DISK: u8 = 0x01;
    pub const PIPE: u8 = 0x02;
    pub const PRINT: u8 = 0x03;
}

pub mod share_flags {
    pub const MANUAL_CACHING: u32 = 0x0000_0000;
    pub const AUTO_CACHING: u32 = 0x0000_0010;
    pub const VDO_CACHING: u32 = 0x0000_0020;
    pub const NO_CACHING: u32 = 0x0000_0030;
    pub const DFS: u32 = 0x0000_0001;
    pub const DFS_ROOT: u32 = 0x0000_0002;
    pub const RESTRICT_EXCLUSIVE_OPENS: u32 = 0x0000_0100;
    pub const FORCE_SHARED_DELETE: u32 = 0x0000_0200;
    pub const ALLOW_NAMESPACE_CACHING: u32 = 0x0000_0400;
    pub const ACCESS_BASED_DIRECTORY_ENUM: u32 = 0x0000_0800;
    pub const FORCE_LEVELII_OPLOCK: u32 = 0x0000_1000;
    pub const ENABLE_HASH_V1: u32 = 0x0000_2000;
    pub const ENABLE_HASH_V2: u32 = 0x0000_4000;
    pub const ENCRYPT_DATA: u32 = 0x0000_8000;
    pub const IDENTITY_REMOTING: u32 = 0x0004_0000;
    pub const COMPRESS_DATA: u32 = 0x0010_0000;
    pub const ISOLATED_TRANSPORT: u32 = 0x0020_0000;
}

pub mod share_capabilities {
    pub const DFS: u32 = 0x0000_0008;
    pub const CONTINUOUS_AVAILABILITY: u32 = 0x0000_0010;
    pub const SCALEOUT: u32 = 0x0000_0020;
    pub const CLUSTER: u32 = 0x0000_0040;
    pub const ASYMMETRIC: u32 = 0x0000_0080;
    pub const REDIRECT_TO_OWNER: u32 = 0x0000_0100;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectRequest {
    pub flags: u16,
    pub path: String,
}

impl TreeConnectRequest {
    pub fn validate(&self) -> Result<(), WireError> {
        if self.flags & tree_connect_flags::EXTENSION_PRESENT != 0 {
            return Err(WireError::Unsupported(
                "TREE_CONNECT extension-present requests",
            ));
        }
        if self.path.is_empty() {
            return Err(WireError::InvalidField("TREE_CONNECT Path"));
        }
        if !self.path.starts_with("\\\\") {
            return Err(WireError::InvalidField(
                "TREE_CONNECT path must be a UNC path",
            ));
        }
        if self.path.contains('\0') {
            return Err(WireError::InvalidField(
                "TREE_CONNECT path must not contain NUL",
            ));
        }
        let path_len = self
            .path
            .encode_utf16()
            .count()
            .checked_mul(2)
            .ok_or(WireError::InvalidField("TREE_CONNECT PathLength overflow"))?;
        if path_len == 0 || path_len > u16::MAX as usize {
            return Err(WireError::InvalidField("TREE_CONNECT PathLength"));
        }
        Ok(())
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut path = Vec::with_capacity(self.path.encode_utf16().count() * 2);
        for unit in self.path.encode_utf16() {
            path.extend_from_slice(&unit.to_le_bytes());
        }

        let path_offset = SMB2_HEADER_SIZE
            .checked_add(TREE_CONNECT_REQUEST_FIXED_SIZE)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(WireError::InvalidField("TREE_CONNECT PathOffset"))?;
        let path_len = u16::try_from(path.len())
            .map_err(|_| WireError::InvalidField("TREE_CONNECT PathLength"))?;

        let mut body = vec![0u8; TREE_CONNECT_REQUEST_FIXED_SIZE];
        put_u16(&mut body, 0, TREE_CONNECT_REQUEST_STRUCTURE_SIZE);
        put_u16(&mut body, 2, self.flags);
        put_u16(&mut body, 4, path_offset);
        put_u16(&mut body, 6, path_len);
        body.extend_from_slice(&path);
        Ok(body)
    }

    pub fn encode_message(
        &self,
        message_id: u64,
        session_id: u64,
        credit_request: u16,
    ) -> Result<Vec<u8>, WireError> {
        let mut header = Smb2Header::request(Command::TreeConnect, message_id, 0, credit_request);
        header.session_id = session_id;
        let body = self.encode_body()?;
        let mut message = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
        message.extend_from_slice(&header.encode());
        message.extend_from_slice(&body);
        Ok(message)
    }

    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + TREE_CONNECT_REQUEST_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::TreeConnect {
            return Err(WireError::InvalidField("TREE_CONNECT request Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR != 0 {
            return Err(WireError::InvalidField("TREE_CONNECT request direction"));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != TREE_CONNECT_REQUEST_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: TREE_CONNECT_REQUEST_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }
        let request_flags = get_u16(body, 2);
        if request_flags & tree_connect_flags::EXTENSION_PRESENT != 0 {
            return Err(WireError::Unsupported(
                "TREE_CONNECT extension-present requests",
            ));
        }
        let path_offset = usize::from(get_u16(body, 4));
        let path_len = usize::from(get_u16(body, 6));
        if path_len == 0 || path_len % 2 != 0 {
            return Err(WireError::InvalidField("TREE_CONNECT PathLength"));
        }
        if path_offset < SMB2_HEADER_SIZE + TREE_CONNECT_REQUEST_FIXED_SIZE {
            return Err(WireError::InvalidField(
                "TREE_CONNECT PathOffset before request buffer",
            ));
        }
        let end = path_offset
            .checked_add(path_len)
            .ok_or(WireError::InvalidField("TREE_CONNECT PathLength overflow"))?;
        if end > message.len() {
            return Err(WireError::InvalidOffset {
                field: "TREE_CONNECT Path",
                offset: path_offset,
                len: path_len,
                packet_len: message.len(),
            });
        }

        let units = message[path_offset..end]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let path = String::from_utf16(&units)
            .map_err(|_| WireError::InvalidField("TREE_CONNECT Path UTF-16"))?;
        let request = Self {
            flags: request_flags,
            path,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectResponse {
    pub header: Smb2Header,
    pub share_type: u8,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

impl TreeConnectResponse {
    pub fn decode_message(message: &[u8]) -> Result<Self, WireError> {
        require_len(message, SMB2_HEADER_SIZE + TREE_CONNECT_RESPONSE_FIXED_SIZE)?;
        let header = Smb2Header::decode(message)?;
        if header.command != Command::TreeConnect {
            return Err(WireError::InvalidField("TREE_CONNECT response Command"));
        }
        if header.flags & flags::SERVER_TO_REDIR == 0 {
            return Err(WireError::InvalidField("TREE_CONNECT response direction"));
        }
        if matches!(header.id, HeaderId::Async { .. }) {
            return Err(WireError::InvalidField(
                "TREE_CONNECT response must use a synchronous header",
            ));
        }

        let body = &message[SMB2_HEADER_SIZE..];
        let structure_size = get_u16(body, 0);
        if structure_size != TREE_CONNECT_RESPONSE_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: TREE_CONNECT_RESPONSE_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }
        let share_type = body[2];
        if !matches!(
            share_type,
            share_type::DISK | share_type::PIPE | share_type::PRINT
        ) {
            return Err(WireError::InvalidField("TREE_CONNECT ShareType"));
        }

        Ok(Self {
            header,
            share_type,
            share_flags: get_u32(body, 4),
            capabilities: get_u32(body, 8),
            maximal_access: get_u32(body, 12),
        })
    }

    pub fn tree_id(&self) -> u32 {
        match self.header.id {
            HeaderId::Sync { tree_id, .. } => tree_id,
            HeaderId::Async { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{StatusField, put_u32};

    #[test]
    fn request_encodes_utf16_unc_path_at_offset_72() {
        let request = TreeConnectRequest {
            flags: 0,
            path: "\\\\nas\\video".to_string(),
        };
        let body = request.encode_body().unwrap();
        assert_eq!(get_u16(&body, 0), 9);
        assert_eq!(get_u16(&body, 4), 72);
        assert_eq!(
            usize::from(get_u16(&body, 6)),
            "\\\\nas\\video".encode_utf16().count() * 2
        );
        assert_eq!(
            TreeConnectRequest::decode_message(&request.encode_message(3, 7, 1).unwrap()).unwrap(),
            request
        );
    }

    #[test]
    fn request_rejects_non_unc_path() {
        let request = TreeConnectRequest {
            flags: 0,
            path: "nas/video".to_string(),
        };
        assert!(request.encode_body().is_err());
    }

    #[test]
    fn response_decodes_tree_and_share_metadata() {
        let mut header = Smb2Header::request(Command::TreeConnect, 3, 0, 5);
        header.flags = flags::SERVER_TO_REDIR;
        header.status = StatusField::Status(0);
        header.session_id = 0x1122;
        header.id = HeaderId::Sync {
            process_id: 0,
            tree_id: 9,
        };
        let mut message = header.encode().to_vec();
        let mut body = vec![0u8; TREE_CONNECT_RESPONSE_FIXED_SIZE];
        put_u16(&mut body, 0, TREE_CONNECT_RESPONSE_STRUCTURE_SIZE);
        body[2] = share_type::DISK;
        put_u32(&mut body, 4, share_flags::NO_CACHING);
        put_u32(&mut body, 8, share_capabilities::CONTINUOUS_AVAILABILITY);
        put_u32(&mut body, 12, 0x001f_01ff);
        message.extend_from_slice(&body);

        let response = TreeConnectResponse::decode_message(&message).unwrap();
        assert_eq!(response.tree_id(), 9);
        assert_eq!(response.share_type, share_type::DISK);
        assert_eq!(response.share_flags, share_flags::NO_CACHING);
        assert_eq!(
            response.capabilities,
            share_capabilities::CONTINUOUS_AVAILABILITY
        );
        assert_eq!(response.maximal_access, 0x001f_01ff);
    }
}
