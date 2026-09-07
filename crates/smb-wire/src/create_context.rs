use crate::error::{WireError, checked_range, require_len};
use crate::header::{get_u16, get_u32, put_u16, put_u32};

pub const CREATE_CONTEXT_FIXED_SIZE: usize = 16;
const CREATE_CONTEXT_ALIGNMENT: usize = 8;

/// Raw SMB2 CREATE context.
///
/// The context name is intentionally kept as bytes because most contexts use four-byte network
/// names (for example `DH2Q`/`DH2C`) while some newer contexts use 16-byte identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateContext {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
}

impl CreateContext {
    pub fn new(name: impl Into<Vec<u8>>, data: impl Into<Vec<u8>>) -> Result<Self, WireError> {
        let context = Self {
            name: name.into(),
            data: data.into(),
        };
        context.validate()?;
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.name.len() < 4 {
            return Err(WireError::InvalidField(
                "CREATE context name must be at least four bytes",
            ));
        }
        u16::try_from(self.name.len())
            .map_err(|_| WireError::InvalidField("CREATE context NameLength"))?;
        u32::try_from(self.data.len())
            .map_err(|_| WireError::InvalidField("CREATE context DataLength"))?;
        Ok(())
    }
}

/// Encodes a list of SMB2_CREATE_CONTEXT structures.
///
/// Every non-final context is padded so `Next` points to an 8-byte aligned successor. The final
/// context has `Next == 0` and is not padded past its data payload.
pub fn encode_create_contexts(contexts: &[CreateContext]) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();

    for (index, context) in contexts.iter().enumerate() {
        context.validate()?;
        let is_last = index + 1 == contexts.len();
        let start = out.len();
        let name_offset = CREATE_CONTEXT_FIXED_SIZE;
        let name_length = context.name.len();
        let data_offset = if context.data.is_empty() {
            0
        } else {
            align_up(
                name_offset
                    .checked_add(name_length)
                    .ok_or(WireError::InvalidField("CREATE context name overflow"))?,
                CREATE_CONTEXT_ALIGNMENT,
            )?
        };
        let data_length = context.data.len();

        let payload_end = if data_length == 0 {
            name_offset
                .checked_add(name_length)
                .ok_or(WireError::InvalidField("CREATE context length overflow"))?
        } else {
            data_offset
                .checked_add(data_length)
                .ok_or(WireError::InvalidField("CREATE context length overflow"))?
        };
        let encoded_len = if is_last {
            payload_end
        } else {
            align_up(payload_end, CREATE_CONTEXT_ALIGNMENT)?
        };

        out.resize(
            start
                .checked_add(encoded_len)
                .ok_or(WireError::InvalidField("CREATE context list overflow"))?,
            0,
        );
        let context_bytes = &mut out[start..start + encoded_len];
        put_u32(
            context_bytes,
            0,
            if is_last {
                0
            } else {
                u32::try_from(encoded_len)
                    .map_err(|_| WireError::InvalidField("CREATE context Next"))?
            },
        );
        put_u16(
            context_bytes,
            4,
            u16::try_from(name_offset)
                .map_err(|_| WireError::InvalidField("CREATE context NameOffset"))?,
        );
        put_u16(
            context_bytes,
            6,
            u16::try_from(name_length)
                .map_err(|_| WireError::InvalidField("CREATE context NameLength"))?,
        );
        put_u16(context_bytes, 8, 0);
        put_u16(
            context_bytes,
            10,
            u16::try_from(data_offset)
                .map_err(|_| WireError::InvalidField("CREATE context DataOffset"))?,
        );
        put_u32(
            context_bytes,
            12,
            u32::try_from(data_length)
                .map_err(|_| WireError::InvalidField("CREATE context DataLength"))?,
        );
        context_bytes[name_offset..name_offset + name_length].copy_from_slice(&context.name);
        if data_length != 0 {
            context_bytes[data_offset..data_offset + data_length].copy_from_slice(&context.data);
        }
    }

    Ok(out)
}

/// Decodes an exact CREATE context-list slice.
///
/// The caller is responsible for slicing the SMB packet using CreateContextsOffset/Length. This
/// decoder validates every relative range against its own context extent and rejects malformed
/// `Next` values before following them.
pub fn decode_create_contexts(input: &[u8]) -> Result<Vec<CreateContext>, WireError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut contexts = Vec::new();
    let mut cursor = 0usize;

    loop {
        let remaining = &input[cursor..];
        require_len(remaining, CREATE_CONTEXT_FIXED_SIZE)?;

        let next = usize::try_from(get_u32(remaining, 0))
            .map_err(|_| WireError::InvalidField("CREATE context Next"))?;
        let extent = if next == 0 {
            remaining.len()
        } else {
            if next < CREATE_CONTEXT_FIXED_SIZE || next % CREATE_CONTEXT_ALIGNMENT != 0 {
                return Err(WireError::InvalidField("CREATE context Next alignment"));
            }
            if next > remaining.len() {
                return Err(WireError::InvalidOffset {
                    field: "CREATE context Next",
                    offset: cursor,
                    len: next,
                    packet_len: input.len(),
                });
            }
            next
        };
        let current = &remaining[..extent];

        let name_offset = usize::from(get_u16(current, 4));
        let name_length = usize::from(get_u16(current, 6));
        let reserved = get_u16(current, 8);
        let data_offset = usize::from(get_u16(current, 10));
        let data_length = usize::try_from(get_u32(current, 12))
            .map_err(|_| WireError::InvalidField("CREATE context DataLength"))?;

        if reserved != 0 {
            return Err(WireError::InvalidField("CREATE context Reserved"));
        }
        if name_length < 4 || name_offset < CREATE_CONTEXT_FIXED_SIZE {
            return Err(WireError::InvalidField("CREATE context Name"));
        }
        if name_offset % CREATE_CONTEXT_ALIGNMENT != 0 {
            return Err(WireError::InvalidField("CREATE context NameOffset alignment"));
        }
        let name_range = checked_range(extent, "CREATE context Name", name_offset, name_length)?;

        let data_range = if data_length == 0 {
            if data_offset != 0 && data_offset % CREATE_CONTEXT_ALIGNMENT != 0 {
                return Err(WireError::InvalidField(
                    "CREATE context DataOffset alignment",
                ));
            }
            None
        } else {
            if data_offset < CREATE_CONTEXT_FIXED_SIZE
                || data_offset % CREATE_CONTEXT_ALIGNMENT != 0
            {
                return Err(WireError::InvalidField(
                    "CREATE context DataOffset alignment",
                ));
            }
            Some(checked_range(
                extent,
                "CREATE context Data",
                data_offset,
                data_length,
            )?)
        };

        if let Some(data_range) = &data_range {
            if ranges_overlap(&name_range, data_range) {
                return Err(WireError::InvalidField(
                    "CREATE context name/data ranges overlap",
                ));
            }
        }

        contexts.push(CreateContext {
            name: current[name_range].to_vec(),
            data: data_range.map_or_else(Vec::new, |range| current[range].to_vec()),
        });

        if next == 0 {
            break;
        }
        cursor = cursor
            .checked_add(next)
            .ok_or(WireError::InvalidField("CREATE context cursor overflow"))?;
        if cursor >= input.len() {
            return Err(WireError::InvalidField(
                "CREATE context Next points past final context",
            ));
        }
    }

    Ok(contexts)
}

fn align_up(value: usize, alignment: usize) -> Result<usize, WireError> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(WireError::InvalidField("CREATE context alignment overflow"))
}

fn ranges_overlap(left: &core::ops::Range<usize>, right: &core::ops::Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_context_round_trips_without_trailing_chain_padding() {
        let contexts = vec![CreateContext::new(b"DH2Q".to_vec(), vec![0x11; 32]).unwrap()];
        let encoded = encode_create_contexts(&contexts).unwrap();
        assert_eq!(get_u32(&encoded, 0), 0);
        assert_eq!(get_u16(&encoded, 4), 16);
        assert_eq!(get_u16(&encoded, 6), 4);
        assert_eq!(get_u16(&encoded, 10), 24);
        assert_eq!(get_u32(&encoded, 12), 32);
        assert_eq!(decode_create_contexts(&encoded).unwrap(), contexts);
    }

    #[test]
    fn multiple_contexts_use_eight_byte_aligned_next_offsets() {
        let contexts = vec![
            CreateContext::new(b"DH2Q".to_vec(), vec![0x22; 32]).unwrap(),
            CreateContext::new(b"QFid".to_vec(), Vec::new()).unwrap(),
        ];
        let encoded = encode_create_contexts(&contexts).unwrap();
        let next = usize::try_from(get_u32(&encoded, 0)).unwrap();
        assert_eq!(next % 8, 0);
        assert_eq!(decode_create_contexts(&encoded).unwrap(), contexts);
    }

    #[test]
    fn decoder_rejects_unaligned_next() {
        let contexts = vec![
            CreateContext::new(b"DH2Q".to_vec(), vec![0; 32]).unwrap(),
            CreateContext::new(b"QFid".to_vec(), Vec::new()).unwrap(),
        ];
        let mut encoded = encode_create_contexts(&contexts).unwrap();
        put_u32(&mut encoded, 0, 17);
        assert!(decode_create_contexts(&encoded).is_err());
    }

    #[test]
    fn decoder_rejects_out_of_range_payload() {
        let context = CreateContext::new(b"DH2Q".to_vec(), vec![0; 32]).unwrap();
        let mut encoded = encode_create_contexts(&[context]).unwrap();
        put_u16(&mut encoded, 10, u16::MAX);
        assert!(decode_create_contexts(&encoded).is_err());
    }

    #[test]
    fn decoder_rejects_name_data_overlap() {
        let context = CreateContext::new(b"DH2Q".to_vec(), vec![0; 32]).unwrap();
        let mut encoded = encode_create_contexts(&[context]).unwrap();
        put_u16(&mut encoded, 10, 16);
        assert!(decode_create_contexts(&encoded).is_err());
    }
}
