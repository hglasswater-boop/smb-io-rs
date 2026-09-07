use smb_io_auth::{AuthError, AuthMechanism, AuthProvider, AuthState, AuthStep, SecretBytes};
use smb_io_client::{
    Connection, Dialect, FileOpenOptions, NegotiateConfig, SessionSetupConfig, SigningAlgorithm,
    SigningState, TreeConnectOptions,
};
use smb_io_testkit::ScriptedTransport;
use smb_io_wire::{
    Command, HeaderId, SMB2_PROTOCOL_ID, Smb2Header, StatusField, TreeConnectRequest, capabilities,
    create_action, flags, security_mode, share_flags, share_type,
};

const MIB: usize = 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;

struct StaticAuth {
    key: Option<SecretBytes>,
}

impl StaticAuth {
    fn new(key: [u8; 16]) -> Self {
        Self {
            key: Some(SecretBytes::new(key.to_vec())),
        }
    }
}

impl AuthProvider for StaticAuth {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::NtlmV2
    }

    fn initial_token(&mut self) -> Result<AuthStep, AuthError> {
        Ok(AuthStep {
            token: b"static-auth".to_vec(),
            state: AuthState::Complete,
        })
    }

    fn next_token(&mut self, _server_token: &[u8]) -> Result<AuthStep, AuthError> {
        Ok(AuthStep {
            token: Vec::new(),
            state: AuthState::Complete,
        })
    }

    fn take_session_key(&mut self) -> Option<SecretBytes> {
        self.key.take()
    }
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn negotiate_302_response() -> Vec<u8> {
    let mut message = vec![0u8; 128];
    message[0..4].copy_from_slice(&SMB2_PROTOCOL_ID);
    put_u16(&mut message, 4, 64);
    put_u16(&mut message, 12, Command::Negotiate as u16);
    put_u16(&mut message, 14, 32);
    put_u32(&mut message, 16, flags::SERVER_TO_REDIR);
    put_u64(&mut message, 24, 0);

    let body = 64;
    put_u16(&mut message, body, 65);
    put_u16(
        &mut message,
        body + 2,
        security_mode::SIGNING_ENABLED | security_mode::SIGNING_REQUIRED,
    );
    put_u16(&mut message, body + 4, Dialect::Smb302 as u16);
    message[body + 8..body + 24].copy_from_slice(&[0x42; 16]);
    put_u32(&mut message, body + 24, capabilities::LARGE_MTU);
    put_u32(&mut message, body + 28, 1024 * 1024);
    put_u32(&mut message, body + 32, 4 * 1024 * 1024);
    put_u32(&mut message, body + 36, 4 * 1024 * 1024);
    message
}

fn signed_session_response(session_id: u64, signing: &SigningState) -> Vec<u8> {
    let mut header = Smb2Header::request(Command::SessionSetup, 1, 0, 16);
    header.flags = flags::SERVER_TO_REDIR;
    header.status = StatusField::Status(0);
    header.session_id = session_id;
    let mut message = header.encode().to_vec();
    let mut body = vec![0u8; 8];
    put_u16(&mut body, 0, 9);
    message.extend_from_slice(&body);
    signing.sign(&mut message).unwrap();
    message
}

fn signed_tree_response(session_id: u64, tree_id: u32, signing: &SigningState) -> Vec<u8> {
    let mut header = Smb2Header::request(Command::TreeConnect, 2, 0, 16);
    header.flags = flags::SERVER_TO_REDIR;
    header.status = StatusField::Status(0);
    header.session_id = session_id;
    header.id = HeaderId::Sync {
        process_id: 0,
        tree_id,
    };
    let mut message = header.encode().to_vec();
    let mut body = vec![0u8; 16];
    put_u16(&mut body, 0, 16);
    body[2] = share_type::DISK;
    put_u32(&mut body, 4, share_flags::NO_CACHING);
    put_u32(&mut body, 8, 0);
    put_u32(&mut body, 12, 0x001f_01ff);
    message.extend_from_slice(&body);
    signing.sign(&mut message).unwrap();
    message
}

fn signed_create_response(session_id: u64, tree_id: u32, signing: &SigningState) -> Vec<u8> {
    let mut header = Smb2Header::request(Command::Create, 3, 0, 16);
    header.flags = flags::SERVER_TO_REDIR;
    header.status = StatusField::Status(0);
    header.session_id = session_id;
    header.id = HeaderId::Sync {
        process_id: 0,
        tree_id,
    };
    let mut message = header.encode().to_vec();
    let mut body = vec![0u8; 88];
    put_u16(&mut body, 0, 89);
    put_u32(&mut body, 4, create_action::OPENED);
    put_u64(&mut body, 40, 6 * GIB + MIB as u64);
    put_u64(&mut body, 48, 6 * GIB);
    put_u32(&mut body, 56, 0x20);
    put_u64(&mut body, 64, 0x1111_2222_3333_4444);
    put_u64(&mut body, 72, 0x5555_6666_7777_8888);
    message.extend_from_slice(&body);
    signing.sign(&mut message).unwrap();
    message
}

fn signed_read_response(session_id: u64, tree_id: u32, signing: &SigningState) -> Vec<u8> {
    let data = vec![0xA7; MIB];
    let mut header = Smb2Header::request(Command::Read, 4, 16, 32);
    header.flags = flags::SERVER_TO_REDIR;
    header.status = StatusField::Status(0);
    header.session_id = session_id;
    header.id = HeaderId::Sync {
        process_id: 0,
        tree_id,
    };
    let mut message = header.encode().to_vec();
    let mut body = vec![0u8; 16];
    put_u16(&mut body, 0, 17);
    body[2] = 0x50;
    put_u32(&mut body, 4, MIB as u32);
    put_u32(&mut body, 8, 0);
    put_u32(&mut body, 12, 0);
    message.extend_from_slice(&body);
    message.extend_from_slice(&data);
    signing.sign(&mut message).unwrap();
    message
}

#[tokio::test]
async fn authenticated_session_reads_one_mib_above_four_gib_with_signing() {
    let session_key = [0xA5; 16];
    let session_id = 0x1122_3344_5566_7788;
    let tree_id = 0x42;
    let read_offset = 4 * GIB + 12_345;
    let signing = SigningState::derive(
        Dialect::Smb302,
        SigningAlgorithm::AesCmac,
        &SecretBytes::new(session_key.to_vec()),
        None,
    )
    .unwrap();

    let transport = ScriptedTransport::new([
        negotiate_302_response(),
        signed_session_response(session_id, &signing),
        signed_tree_response(session_id, tree_id, &signing),
        signed_create_response(session_id, tree_id, &signing),
        signed_read_response(session_id, tree_id, &signing),
    ]);
    let mut connection = Connection::new(transport);
    let config = NegotiateConfig {
        dialects: vec![Dialect::Smb302],
        security_mode: security_mode::SIGNING_REQUIRED,
        capabilities: capabilities::LARGE_MTU,
        client_guid: [0x11; 16],
        preauth_salt: Vec::new(),
        signing_algorithms: Vec::new(),
        credit_request: 32,
    };
    connection.negotiate(&config).await.unwrap();

    let mut auth = StaticAuth::new(session_key);
    let mut session = connection
        .session_setup(&mut auth, SessionSetupConfig::default())
        .await
        .unwrap();
    assert!(session.signing_required());
    assert_eq!(session.signing_algorithm(), Some(SigningAlgorithm::AesCmac));

    let tree = session
        .tree_connect("\\\\nas\\video", TreeConnectOptions::default())
        .await
        .unwrap();
    assert_eq!(tree.tree_id(), tree_id);
    assert_eq!(tree.path(), "\\\\nas\\video");
    assert_eq!(tree.share_type(), share_type::DISK);
    assert_eq!(tree.share_flags(), share_flags::NO_CACHING);
    assert_eq!(tree.maximal_access(), 0x001f_01ff);

    let file = session
        .open_file(
            &tree,
            "movies/sample.mkv",
            FileOpenOptions::read_existing_random(),
        )
        .await
        .unwrap();
    assert_eq!(file.tree_id(), tree_id);
    assert_eq!(file.path(), "movies\\sample.mkv");
    assert_eq!(file.len(), 6 * GIB);
    assert_eq!(file.allocation_size(), 6 * GIB + MIB as u64);
    assert_eq!(file.file_id().persistent, 0x1111_2222_3333_4444);
    assert_eq!(file.file_id().volatile, 0x5555_6666_7777_8888);

    let data = session.read_at(&file, read_offset, MIB).await.unwrap();
    assert_eq!(data.len(), MIB);
    assert!(data.iter().all(|byte| *byte == 0xA7));

    let transport = session.into_connection().into_transport();
    assert_eq!(transport.sent_messages().len(), 5);

    let tree_request_message = &transport.sent_messages()[2];
    let tree_header = Smb2Header::decode(tree_request_message).unwrap();
    assert_eq!(tree_header.command, Command::TreeConnect);
    assert_eq!(tree_header.credit_charge, 1);
    assert_eq!(tree_header.session_id, session_id);
    assert_ne!(tree_header.flags & flags::SIGNED, 0);
    let request = TreeConnectRequest::decode_message(tree_request_message).unwrap();
    assert_eq!(request.path, "\\\\nas\\video");

    let create_header = Smb2Header::decode(&transport.sent_messages()[3]).unwrap();
    assert_eq!(create_header.command, Command::Create);
    assert_eq!(create_header.credit_charge, 1);
    assert_eq!(create_header.session_id, session_id);
    assert_ne!(create_header.flags & flags::SIGNED, 0);

    let read_request = &transport.sent_messages()[4];
    let read_header = Smb2Header::decode(read_request).unwrap();
    assert_eq!(read_header.command, Command::Read);
    assert_eq!(read_header.message_id, 4);
    assert_eq!(read_header.credit_charge, 16);
    assert_eq!(read_header.session_id, session_id);
    assert_ne!(read_header.flags & flags::SIGNED, 0);

    let body = &read_request[64..];
    assert_eq!(body[2], 0x50);
    assert_eq!(
        u32::from_le_bytes(body[4..8].try_into().unwrap()),
        MIB as u32
    );
    assert_eq!(
        u64::from_le_bytes(body[8..16].try_into().unwrap()),
        read_offset
    );
    assert_eq!(
        u64::from_le_bytes(body[16..24].try_into().unwrap()),
        0x1111_2222_3333_4444
    );
    assert_eq!(
        u64::from_le_bytes(body[24..32].try_into().unwrap()),
        0x5555_6666_7777_8888
    );
}
