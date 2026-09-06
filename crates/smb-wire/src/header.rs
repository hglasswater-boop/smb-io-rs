use crate::error::{WireError, require_len};
use crate::SMB2_PROTOCOL_ID;

pub const SMB2_HEADER_SIZE: usize = 64;
pub const SMB2_HEADER_STRUCTURE_SIZE: u16 = 64;

pub mod flags {
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004;
    pub const SIGNED: u32 = 0x0000_0008;
    pub const PRIORITY_MASK: u32 = 0x0000_0070;
    pub const DFS_OPERATIONS: u32 = 0x1000_0000;
    pub const REPLAY_OPERATION: u32 = 0x2000_0000;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Flush = 0x0007,
    Read = 0x0008,
    Write = 0x0009,
    Lock = 0x000A,
    Ioctl = 0x000B,
    Cancel = 0x000C,
    Echo = 0x000D,
    QueryDirectory = 0x000E,
    ChangeNotify = 0x000F,
    QueryInfo = 0x0010,
    SetInfo = 0x0011,
    OplockBreak = 0x0012,
}

impl TryFrom<u16> for Command {
    type Error = WireError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0000 => Self::Negotiate,
            0x0001 => Self::SessionSetup,
            0x0002 => Self::Logoff,
            0x0003 => Self::TreeConnect,
            0x0004 => Self::TreeDisconnect,
            0x0005 => Self::Create,
            0x0006 => Self::Close,
            0x0007 => Self::Flush,
            0x0008 => Self::Read,
            0x0009 => Self::Write,
            0x000A => Self::Lock,
            0x000B => Self::Ioctl,
            0x000C => Self::Cancel,
            0x000D => Self::Echo,
            0x000E => Self::QueryDirectory,
            0x000F => Self::ChangeNotify,
            0x0010 => Self::QueryInfo,
            0x0011 => Self::SetInfo,
            0x0012 => Self::OplockBreak,
            _ => return Err(WireError::InvalidField("SMB2 Command")),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusField {
    /// Request-side ChannelSequence and reserved value sharing bytes 8..12.
    ChannelSequence { sequence: u16, reserved: u16 },
    /// Response-side NTSTATUS value sharing bytes 8..12.
    Status(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderId {
    Sync { process_id: u32, tree_id: u32 },
    Async { async_id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Header {
    pub credit_charge: u16,
    pub status: StatusField,
    pub command: Command,
    /// CreditRequest for requests and CreditResponse for responses.
    pub credits: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub id: HeaderId,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Smb2Header {
    pub fn request(command: Command, message_id: u64, credit_charge: u16, credit_request: u16) -> Self {
        Self {
            credit_charge,
            status: StatusField::ChannelSequence {
                sequence: 0,
                reserved: 0,
            },
            command,
            credits: credit_request,
            flags: 0,
            next_command: 0,
            message_id,
            id: HeaderId::Sync {
                process_id: 0,
                tree_id: 0,
            },
            session_id: 0,
            signature: [0; 16],
        }
    }

    pub fn encode(&self) -> [u8; SMB2_HEADER_SIZE] {
        let mut out = [0u8; SMB2_HEADER_SIZE];
        out[0..4].copy_from_slice(&SMB2_PROTOCOL_ID);
        put_u16(&mut out, 4, SMB2_HEADER_STRUCTURE_SIZE);
        put_u16(&mut out, 6, self.credit_charge);
        match self.status {
            StatusField::ChannelSequence { sequence, reserved } => {
                put_u16(&mut out, 8, sequence);
                put_u16(&mut out, 10, reserved);
            }
            StatusField::Status(status) => put_u32(&mut out, 8, status),
        }
        put_u16(&mut out, 12, self.command as u16);
        put_u16(&mut out, 14, self.credits);
        put_u32(&mut out, 16, self.flags);
        put_u32(&mut out, 20, self.next_command);
        put_u64(&mut out, 24, self.message_id);
        match self.id {
            HeaderId::Sync { process_id, tree_id } => {
                put_u32(&mut out, 32, process_id);
                put_u32(&mut out, 36, tree_id);
            }
            HeaderId::Async { async_id } => put_u64(&mut out, 32, async_id),
        }
        put_u64(&mut out, 40, self.session_id);
        out[48..64].copy_from_slice(&self.signature);
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        require_len(input, SMB2_HEADER_SIZE)?;

        let protocol = [input[0], input[1], input[2], input[3]];
        if protocol != SMB2_PROTOCOL_ID {
            return Err(WireError::InvalidProtocolId(protocol));
        }

        let structure_size = get_u16(input, 4);
        if structure_size != SMB2_HEADER_STRUCTURE_SIZE {
            return Err(WireError::InvalidStructureSize {
                expected: SMB2_HEADER_STRUCTURE_SIZE,
                actual: structure_size,
            });
        }

        let flags_value = get_u32(input, 16);
        let status = if flags_value & flags::SERVER_TO_REDIR != 0 {
            StatusField::Status(get_u32(input, 8))
        } else {
            StatusField::ChannelSequence {
                sequence: get_u16(input, 8),
                reserved: get_u16(input, 10),
            }
        };
        let id = if flags_value & flags::ASYNC_COMMAND != 0 {
            HeaderId::Async {
                async_id: get_u64(input, 32),
            }
        } else {
            HeaderId::Sync {
                process_id: get_u32(input, 32),
                tree_id: get_u32(input, 36),
            }
        };

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&input[48..64]);

        Ok(Self {
            credit_charge: get_u16(input, 6),
            status,
            command: Command::try_from(get_u16(input, 12))?,
            credits: get_u16(input, 14),
            flags: flags_value,
            next_command: get_u32(input, 20),
            message_id: get_u64(input, 24),
            id,
            session_id: get_u64(input, 40),
            signature,
        })
    }
}

pub(crate) fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

pub(crate) fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

pub(crate) fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

pub(crate) fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_header_round_trips() {
        let mut header = Smb2Header::request(Command::Read, 42, 2, 16);
        header.id = HeaderId::Sync {
            process_id: 0x1122_3344,
            tree_id: 0x5566_7788,
        };
        header.session_id = 0x0102_0304_0506_0708;
        let bytes = header.encode();
        assert_eq!(Smb2Header::decode(&bytes).unwrap(), header);
    }

    #[test]
    fn response_status_is_decoded_from_union_field() {
        let mut bytes = Smb2Header::request(Command::Negotiate, 0, 0, 1).encode();
        put_u32(&mut bytes, 16, flags::SERVER_TO_REDIR);
        put_u32(&mut bytes, 8, 0xC000_0022);
        let decoded = Smb2Header::decode(&bytes).unwrap();
        assert_eq!(decoded.status, StatusField::Status(0xC000_0022));
    }

    #[test]
    fn rejects_bad_protocol_id() {
        let mut bytes = Smb2Header::request(Command::Negotiate, 0, 0, 1).encode();
        bytes[0] = 0xFF;
        assert!(matches!(
            Smb2Header::decode(&bytes),
            Err(WireError::InvalidProtocolId(_))
        ));
    }
}
