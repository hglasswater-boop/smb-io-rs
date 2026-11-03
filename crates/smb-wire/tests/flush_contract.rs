use smb_io_wire::{
    Command, FileId, FlushRequest, FlushResponse, HeaderId, Smb2Header, StatusField, flags,
};

#[test]
fn flush_request_encodes_signed_header_fields_and_file_id() {
    let file = FileId::new(0x1234, 0x5678);
    let message = FlushRequest::new(file)
        .encode_message(13, 21, 34, 1, 8)
        .unwrap();
    let (header, request) = FlushRequest::decode_message(&message).unwrap();
    assert_eq!(header.command, Command::Flush);
    assert_eq!(header.message_id, 13);
    assert_eq!(header.session_id, 21);
    assert_eq!(
        header.id,
        HeaderId::Sync {
            process_id: 0,
            tree_id: 34
        }
    );
    assert_eq!(request.file_id, file);
    assert_eq!(message.len(), 64 + 24);
    assert_eq!(&message[64..66], &24u16.to_le_bytes());
}

#[test]
fn flush_request_rejects_invalid_file_id_and_nonzero_reserved() {
    assert!(
        FlushRequest::new(FileId::new(0, 0))
            .encode_message(1, 2, 3, 1, 8)
            .is_err()
    );
    let good = FlushRequest::new(FileId::new(1, 2))
        .encode_message(1, 2, 3, 1, 8)
        .unwrap();
    let mut broken = good.clone();
    broken[66] = 1;
    assert!(FlushRequest::decode_message(&broken).is_err());
    let mut truncated = good;
    truncated.pop();
    assert!(FlushRequest::decode_message(&truncated).is_err());
}

#[test]
fn flush_response_checks_structure_size_and_reserved() {
    let mut header = Smb2Header::request(Command::Flush, 11, 1, 8);
    header.flags = flags::SERVER_TO_REDIR;
    header.status = StatusField::Status(0);
    header.session_id = 55;
    header.id = HeaderId::Sync {
        process_id: 0,
        tree_id: 66,
    };
    let mut msg = header.encode().to_vec();
    msg.extend_from_slice(&4u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    assert!(FlushResponse::decode_message(&msg).is_ok());
    msg[64] = 8;
    assert!(FlushResponse::decode_message(&msg).is_err());
    msg[64] = 4;
    msg[66] = 1;
    assert!(FlushResponse::decode_message(&msg).is_err());
    msg.pop();
    assert!(FlushResponse::decode_message(&msg).is_err());
}
