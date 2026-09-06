use core::fmt;

/// Errors produced while validating, encoding, or decoding SMB wire data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    BufferTooShort { needed: usize, actual: usize },
    InvalidProtocolId([u8; 4]),
    InvalidStructureSize { expected: u16, actual: u16 },
    InvalidField(&'static str),
    InvalidOffset { field: &'static str, offset: usize, len: usize, packet_len: usize },
    FrameTooLarge(usize),
    TruncatedFrame { declared: usize, actual: usize },
    Unsupported(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, actual } => {
                write!(f, "buffer too short: need {needed} bytes, got {actual}")
            }
            Self::InvalidProtocolId(value) => write!(f, "invalid SMB2 protocol id: {value:02x?}"),
            Self::InvalidStructureSize { expected, actual } => {
                write!(f, "invalid structure size: expected {expected}, got {actual}")
            }
            Self::InvalidField(field) => write!(f, "invalid SMB field: {field}"),
            Self::InvalidOffset { field, offset, len, packet_len } => write!(
                f,
                "invalid {field} range: offset={offset}, len={len}, packet_len={packet_len}",
            ),
            Self::FrameTooLarge(len) => write!(f, "SMB direct-TCP frame exceeds 24-bit length: {len}"),
            Self::TruncatedFrame { declared, actual } => {
                write!(f, "truncated SMB frame: declared {declared} bytes, got {actual}")
            }
            Self::Unsupported(feature) => write!(f, "unsupported SMB wire feature: {feature}"),
        }
    }
}

impl std::error::Error for WireError {}

pub(crate) fn require_len(input: &[u8], needed: usize) -> Result<(), WireError> {
    if input.len() < needed {
        return Err(WireError::BufferTooShort {
            needed,
            actual: input.len(),
        });
    }
    Ok(())
}

pub(crate) fn checked_range(
    packet_len: usize,
    field: &'static str,
    offset: usize,
    len: usize,
) -> Result<core::ops::Range<usize>, WireError> {
    let end = offset.checked_add(len).ok_or(WireError::InvalidOffset {
        field,
        offset,
        len,
        packet_len,
    })?;
    if offset > packet_len || end > packet_len {
        return Err(WireError::InvalidOffset {
            field,
            offset,
            len,
            packet_len,
        });
    }
    Ok(offset..end)
}
