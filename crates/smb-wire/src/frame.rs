use crate::error::{WireError, require_len};

pub const DIRECT_TCP_HEADER_SIZE: usize = 4;
pub const DIRECT_TCP_MAX_PAYLOAD: usize = 0x00FF_FFFF;

/// Encodes an SMB payload with the 4-byte direct-TCP session header used on port 445.
pub fn encode_direct_tcp_frame(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    if payload.len() > DIRECT_TCP_MAX_PAYLOAD {
        return Err(WireError::FrameTooLarge(payload.len()));
    }
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(DIRECT_TCP_HEADER_SIZE + payload.len());
    out.push(0);
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parses only the direct-TCP 4-byte header and returns its payload length.
pub fn decode_direct_tcp_length(header: &[u8]) -> Result<usize, WireError> {
    require_len(header, DIRECT_TCP_HEADER_SIZE)?;
    if header[0] != 0 {
        return Err(WireError::InvalidField("direct TCP reserved byte"));
    }
    Ok(((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize)
}

/// Validates a complete direct-TCP frame and returns the SMB payload.
///
/// Trailing bytes are rejected so callers cannot accidentally merge two SMB messages into one.
pub fn decode_direct_tcp_frame(frame: &[u8]) -> Result<&[u8], WireError> {
    require_len(frame, DIRECT_TCP_HEADER_SIZE)?;
    let declared = decode_direct_tcp_length(&frame[..DIRECT_TCP_HEADER_SIZE])?;
    let actual = frame.len() - DIRECT_TCP_HEADER_SIZE;
    if actual != declared {
        return Err(WireError::TruncatedFrame { declared, actual });
    }
    Ok(&frame[DIRECT_TCP_HEADER_SIZE..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_tcp_round_trip() {
        let payload = [0xFE, b'S', b'M', b'B', 1, 2, 3];
        let frame = encode_direct_tcp_frame(&payload).unwrap();
        assert_eq!(&frame[..4], &[0, 0, 0, 7]);
        assert_eq!(decode_direct_tcp_frame(&frame).unwrap(), payload);
    }

    #[test]
    fn supports_full_24_bit_length_header() {
        let header = [0, 0x12, 0x34, 0x56];
        assert_eq!(decode_direct_tcp_length(&header).unwrap(), 0x12_34_56);
    }

    #[test]
    fn rejects_nonzero_reserved_byte() {
        assert!(matches!(
            decode_direct_tcp_length(&[1, 0, 0, 0]),
            Err(WireError::InvalidField("direct TCP reserved byte"))
        ));
    }
}
