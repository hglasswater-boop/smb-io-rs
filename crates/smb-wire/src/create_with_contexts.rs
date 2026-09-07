use crate::create::{
    CREATE_REQUEST_FIXED_SIZE, CREATE_RESPONSE_FIXED_SIZE, CreateRequest, CreateResponse,
};
use crate::create_context::{CreateContext, decode_create_contexts, encode_create_contexts};
use crate::error::{WireError, checked_range};
use crate::header::{Command, HeaderId, SMB2_HEADER_SIZE, Smb2Header, put_u32};

const CREATE_BUFFER_ALIGNMENT: usize = 8;

/// Encodes an SMB2 CREATE request with an explicit CREATE-context list without changing the
/// public `CreateRequest` layout used by context-free callers.
pub fn encode_create_request_with_contexts(
    request: &CreateRequest,
    contexts: &[CreateContext],
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    credit_request: u16,
) -> Result<Vec<u8>, WireError> {
    if contexts.is_empty() {
        return request.encode_message(message_id, session_id, tree_id, credit_request);
    }

    request.validate()?;
    let encoded_contexts = encode_create_contexts(contexts)?;
    if encoded_contexts.is_empty() {
        return Err(WireError::InvalidField(
            "CREATE context encoder returned an empty list",
        ));
    }

    let mut body = request.encode_body()?;
    // Context-free root CREATE keeps Buffer at least one byte long. With contexts present, the
    // context list itself satisfies that requirement, so discard the synthetic root-name byte.
    if request.name.is_empty() {
        body.truncate(CREATE_REQUEST_FIXED_SIZE);
    }

    let contexts_body_offset = align_up(body.len(), CREATE_BUFFER_ALIGNMENT)?;
    body.resize(contexts_body_offset, 0);
    let contexts_offset = SMB2_HEADER_SIZE
        .checked_add(contexts_body_offset)
        .ok_or(WireError::InvalidField("CREATE CreateContextsOffset overflow"))?;
    put_u32(
        &mut body,
        48,
        u32::try_from(contexts_offset)
            .map_err(|_| WireError::InvalidField("CREATE CreateContextsOffset"))?,
    );
    put_u32(
        &mut body,
        52,
        u32::try_from(encoded_contexts.len())
            .map_err(|_| WireError::InvalidField("CREATE CreateContextsLength"))?,
    );
    body.extend_from_slice(&encoded_contexts);

    let mut header = Smb2Header::request(Command::Create, message_id, 0, credit_request);
    header.session_id = session_id;
    header.id = HeaderId::Sync {
        process_id: 0,
        tree_id,
    };

    let mut message = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
    message.extend_from_slice(&header.encode());
    message.extend_from_slice(&body);
    Ok(message)
}

/// Decodes the fixed CREATE response plus its validated CREATE-context list.
///
/// The existing `CreateResponse::decode_message` remains the context-free compatibility API.
pub fn decode_create_response_with_contexts(
    message: &[u8],
) -> Result<(CreateResponse, Vec<CreateContext>), WireError> {
    let response = CreateResponse::decode_message(message)?;
    if response.create_contexts_length == 0 {
        return Ok((response, Vec::new()));
    }

    let offset = usize::try_from(response.create_contexts_offset)
        .map_err(|_| WireError::InvalidField("CREATE CreateContextsOffset"))?;
    let len = usize::try_from(response.create_contexts_length)
        .map_err(|_| WireError::InvalidField("CREATE CreateContextsLength"))?;
    let minimum_offset = SMB2_HEADER_SIZE
        .checked_add(CREATE_RESPONSE_FIXED_SIZE)
        .ok_or(WireError::InvalidField("CREATE response fixed-size overflow"))?;
    if offset < minimum_offset || offset % CREATE_BUFFER_ALIGNMENT != 0 {
        return Err(WireError::InvalidOffset {
            field: "CREATE CreateContexts",
            offset,
            len,
            packet_len: message.len(),
        });
    }
    let range = checked_range(message.len(), "CREATE CreateContexts", offset, len)?;
    let contexts = decode_create_contexts(&message[range])?;
    if contexts.is_empty() {
        return Err(WireError::InvalidField(
            "CREATE response declared an empty context list",
        ));
    }
    Ok((response, contexts))
}

fn align_up(value: usize, alignment: usize) -> Result<usize, WireError> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(WireError::InvalidField("CREATE buffer alignment overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{CREATE_RESPONSE_STRUCTURE_SIZE, create_action, oplock_level};
    use crate::header::{StatusField, flags, get_u32, put_u16, put_u64};

    #[test]
    fn request_places_contexts_on_an_eight_byte_boundary_after_the_name() {
        let request = CreateRequest::open_existing_read("movie.mkv");
        let context = CreateContext::new(b"DH2Q".to_vec(), vec![0x11; 32]).unwrap();
        let message = encode_create_request_with_contexts(&request, &[context.clone()], 4, 7, 9, 8)
            .unwrap();
        let body = &message[SMB2_HEADER_SIZE..];
        let offset = usize::try_from(get_u32(body, 48)).unwrap();
        let len = usize::try_from(get_u32(body, 52)).unwrap();
        assert_eq!(offset % 8, 0);
        assert!(offset >= SMB2_HEADER_SIZE + CREATE_REQUEST_FIXED_SIZE);
        assert_eq!(decode_create_contexts(&message[offset..offset + len]).unwrap(), vec![context]);
    }

    #[test]
    fn root_request_uses_context_list_as_the_required_buffer() {
        let request = CreateRequest::open_existing_read("");
        let context = CreateContext::new(b"DH2Q".to_vec(), vec![0x22; 32]).unwrap();
        let message = encode_create_request_with_contexts(&request, &[context], 4, 7, 9, 8).unwrap();
        let body = &message[SMB2_HEADER_SIZE..];
        assert_eq!(get_u32(body, 48), 120);
    }

    #[test]
    fn response_contexts_are_decoded_from_the_declared_slice() {
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
        put_u64(&mut body, 48, 1024);
        put_u64(&mut body, 64, 0x1111);
        put_u64(&mut body, 72, 0x2222);
        let contexts = encode_create_contexts(&[
            CreateContext::new(b"DH2Q".to_vec(), vec![0x33; 8]).unwrap(),
        ])
        .unwrap();
        put_u32(&mut body, 80, 152);
        put_u32(&mut body, 84, u32::try_from(contexts.len()).unwrap());
        message.extend_from_slice(&body);
        message.extend_from_slice(&contexts);

        let (response, decoded) = decode_create_response_with_contexts(&message).unwrap();
        assert_eq!(response.file_id.persistent, 0x1111);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, b"DH2Q");
    }

    #[test]
    fn response_rejects_context_slice_inside_the_fixed_create_response() {
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
        put_u64(&mut body, 64, 1);
        put_u64(&mut body, 72, 2);
        put_u32(&mut body, 80, 64);
        put_u32(&mut body, 84, 16);
        message.extend_from_slice(&body);

        assert!(decode_create_response_with_contexts(&message).is_err());
    }
}
