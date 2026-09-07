use crate::create::FileId;
use crate::create_context::CreateContext;
use crate::error::{WireError, require_len};
use crate::header::{get_u32, get_u64, put_u32, put_u64};

pub const DURABLE_HANDLE_REQUEST_V2_NAME: [u8; 4] = *b"DH2Q";
pub const DURABLE_HANDLE_RECONNECT_V2_NAME: [u8; 4] = *b"DH2C";
pub const DURABLE_HANDLE_REQUEST_V2_DATA_SIZE: usize = 32;
pub const DURABLE_HANDLE_RECONNECT_V2_DATA_SIZE: usize = 36;
pub const DURABLE_HANDLE_RESPONSE_V2_DATA_SIZE: usize = 8;

pub mod durable_handle_flags {
    pub const PERSISTENT: u32 = 0x0000_0002;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableHandleRequestV2 {
    pub timeout_ms: u32,
    pub flags: u32,
    pub create_guid: [u8; 16],
}

impl DurableHandleRequestV2 {
    pub fn new(create_guid: [u8; 16]) -> Self {
        Self {
            timeout_ms: 0,
            flags: 0,
            create_guid,
        }
    }

    pub fn encode_data(self) -> Result<[u8; DURABLE_HANDLE_REQUEST_V2_DATA_SIZE], WireError> {
        validate_flags(self.flags)?;
        let mut out = [0u8; DURABLE_HANDLE_REQUEST_V2_DATA_SIZE];
        put_u32(&mut out, 0, self.timeout_ms);
        put_u32(&mut out, 4, self.flags);
        // Reserved bytes 8..16 remain zero.
        out[16..32].copy_from_slice(&self.create_guid);
        Ok(out)
    }

    pub fn decode_data(input: &[u8]) -> Result<Self, WireError> {
        require_exact_len(
            input,
            DURABLE_HANDLE_REQUEST_V2_DATA_SIZE,
            "DH2Q request length",
        )?;
        if input[8..16].iter().any(|byte| *byte != 0) {
            return Err(WireError::InvalidField("DH2Q Reserved"));
        }
        let flags = get_u32(input, 4);
        validate_flags(flags)?;
        let mut create_guid = [0u8; 16];
        create_guid.copy_from_slice(&input[16..32]);
        Ok(Self {
            timeout_ms: get_u32(input, 0),
            flags,
            create_guid,
        })
    }

    pub fn into_context(self) -> Result<CreateContext, WireError> {
        CreateContext::new(
            DURABLE_HANDLE_REQUEST_V2_NAME.to_vec(),
            self.encode_data()?.to_vec(),
        )
    }

    pub fn from_context(context: &CreateContext) -> Result<Self, WireError> {
        require_name(
            context,
            &DURABLE_HANDLE_REQUEST_V2_NAME,
            "DH2Q context name",
        )?;
        Self::decode_data(&context.data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableHandleReconnectV2 {
    pub file_id: FileId,
    pub create_guid: [u8; 16],
    pub flags: u32,
}

impl DurableHandleReconnectV2 {
    pub fn new(file_id: FileId, create_guid: [u8; 16]) -> Self {
        Self {
            file_id,
            create_guid,
            flags: 0,
        }
    }

    pub fn encode_data(self) -> Result<[u8; DURABLE_HANDLE_RECONNECT_V2_DATA_SIZE], WireError> {
        validate_flags(self.flags)?;
        let mut out = [0u8; DURABLE_HANDLE_RECONNECT_V2_DATA_SIZE];
        put_u64(&mut out, 0, self.file_id.persistent);
        put_u64(&mut out, 8, self.file_id.volatile);
        out[16..32].copy_from_slice(&self.create_guid);
        put_u32(&mut out, 32, self.flags);
        Ok(out)
    }

    pub fn decode_data(input: &[u8]) -> Result<Self, WireError> {
        require_exact_len(
            input,
            DURABLE_HANDLE_RECONNECT_V2_DATA_SIZE,
            "DH2C reconnect length",
        )?;
        let flags = get_u32(input, 32);
        validate_flags(flags)?;
        let mut create_guid = [0u8; 16];
        create_guid.copy_from_slice(&input[16..32]);
        Ok(Self {
            file_id: FileId::new(get_u64(input, 0), get_u64(input, 8)),
            create_guid,
            flags,
        })
    }

    pub fn into_context(self) -> Result<CreateContext, WireError> {
        CreateContext::new(
            DURABLE_HANDLE_RECONNECT_V2_NAME.to_vec(),
            self.encode_data()?.to_vec(),
        )
    }

    pub fn from_context(context: &CreateContext) -> Result<Self, WireError> {
        require_name(
            context,
            &DURABLE_HANDLE_RECONNECT_V2_NAME,
            "DH2C context name",
        )?;
        Self::decode_data(&context.data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableHandleResponseV2 {
    pub timeout_ms: u32,
    pub flags: u32,
}

impl DurableHandleResponseV2 {
    pub fn decode_data(input: &[u8]) -> Result<Self, WireError> {
        require_exact_len(
            input,
            DURABLE_HANDLE_RESPONSE_V2_DATA_SIZE,
            "DH2Q response length",
        )?;
        let flags = get_u32(input, 4);
        validate_flags(flags)?;
        Ok(Self {
            timeout_ms: get_u32(input, 0),
            flags,
        })
    }

    pub fn from_context(context: &CreateContext) -> Result<Self, WireError> {
        require_name(
            context,
            &DURABLE_HANDLE_REQUEST_V2_NAME,
            "DH2Q context name",
        )?;
        Self::decode_data(&context.data)
    }
}

fn validate_flags(flags: u32) -> Result<(), WireError> {
    if flags & !durable_handle_flags::PERSISTENT != 0 {
        return Err(WireError::InvalidField("durable handle v2 Flags"));
    }
    Ok(())
}

fn require_name(
    context: &CreateContext,
    expected: &[u8],
    field: &'static str,
) -> Result<(), WireError> {
    if context.name == expected {
        Ok(())
    } else {
        Err(WireError::InvalidField(field))
    }
}

fn require_exact_len(input: &[u8], expected: usize, field: &'static str) -> Result<(), WireError> {
    require_len(input, expected)?;
    if input.len() != expected {
        return Err(WireError::InvalidField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_request_v2_round_trips_and_zeroes_reserved() {
        let request = DurableHandleRequestV2 {
            timeout_ms: 0,
            flags: durable_handle_flags::PERSISTENT,
            create_guid: [0x11; 16],
        };
        let encoded = request.encode_data().unwrap();
        assert_eq!(&encoded[8..16], &[0; 8]);
        assert_eq!(
            DurableHandleRequestV2::decode_data(&encoded).unwrap(),
            request
        );
        let context = request.into_context().unwrap();
        assert_eq!(context.name, b"DH2Q");
        assert_eq!(
            DurableHandleRequestV2::from_context(&context).unwrap(),
            request
        );
    }

    #[test]
    fn durable_reconnect_v2_round_trips_file_id_guid_and_flags() {
        let reconnect = DurableHandleReconnectV2 {
            file_id: FileId::new(0x0102_0304_0506_0708, 0x1112_1314_1516_1718),
            create_guid: [0x22; 16],
            flags: durable_handle_flags::PERSISTENT,
        };
        let encoded = reconnect.encode_data().unwrap();
        assert_eq!(encoded.len(), 36);
        assert_eq!(
            DurableHandleReconnectV2::decode_data(&encoded).unwrap(),
            reconnect
        );
        assert_eq!(
            DurableHandleReconnectV2::from_context(&reconnect.into_context().unwrap()).unwrap(),
            reconnect
        );
    }

    #[test]
    fn durable_response_v2_decodes_server_timeout() {
        let mut data = [0u8; DURABLE_HANDLE_RESPONSE_V2_DATA_SIZE];
        put_u32(&mut data, 0, 60_000);
        put_u32(&mut data, 4, durable_handle_flags::PERSISTENT);
        let response = DurableHandleResponseV2::decode_data(&data).unwrap();
        assert_eq!(response.timeout_ms, 60_000);
        assert_eq!(response.flags, durable_handle_flags::PERSISTENT);
    }

    #[test]
    fn unknown_durable_flags_are_rejected() {
        let request = DurableHandleRequestV2 {
            timeout_ms: 0,
            flags: 0x8000_0000,
            create_guid: [0; 16],
        };
        assert!(request.encode_data().is_err());
    }

    #[test]
    fn nonzero_request_reserved_is_rejected() {
        let mut data = DurableHandleRequestV2::new([0; 16]).encode_data().unwrap();
        data[8] = 1;
        assert!(DurableHandleRequestV2::decode_data(&data).is_err());
    }
}
