use smb_io_auth::{AuthError, AuthMechanism, AuthProvider, AuthState, AuthStep, SecretBytes};
use smb_io_client::{
    Connection, Dialect, NegotiateConfig, STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS,
    SessionSetupConfig,
};
use smb_io_testkit::ScriptedTransport;
use smb_io_wire::{
    Command, SMB2_PROTOCOL_ID, Smb2Header, StatusField, capabilities, context_type, flags,
    preauth_hash_algorithm, security_mode,
};

struct FakeNtlm {
    key: Option<SecretBytes>,
}

impl FakeNtlm {
    fn new() -> Self {
        Self { key: None }
    }
}

impl AuthProvider for FakeNtlm {
    fn mechanism(&self) -> AuthMechanism {
        AuthMechanism::NtlmV2
    }

    fn initial_token(&mut self) -> Result<AuthStep, AuthError> {
        Ok(AuthStep {
            token: b"negotiate-token".to_vec(),
            state: AuthState::Continue,
        })
    }

    fn next_token(&mut self, server_token: &[u8]) -> Result<AuthStep, AuthError> {
        if server_token != b"challenge-token" {
            return Err(AuthError::InvalidToken("unexpected fake challenge"));
        }
        self.key = Some(SecretBytes::new(vec![0xA5; 16]));
        Ok(AuthStep {
            token: b"authenticate-token".to_vec(),
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

fn negotiate_311_response() -> Vec<u8> {
    let mut message = vec![0u8; 128];
    message[0..4].copy_from_slice(&SMB2_PROTOCOL_ID);
    put_u16(&mut message, 4, 64);
    put_u16(&mut message, 12, Command::Negotiate as u16);
    put_u16(&mut message, 14, 32);
    put_u32(&mut message, 16, flags::SERVER_TO_REDIR);
    put_u64(&mut message, 24, 0);

    let body = 64;
    put_u16(&mut message, body, 65);
    put_u16(&mut message, body + 2, security_mode::SIGNING_ENABLED);
    put_u16(&mut message, body + 4, Dialect::Smb311 as u16);
    put_u16(&mut message, body + 6, 1);
    message[body + 8..body + 24].copy_from_slice(&[0x42; 16]);
    put_u32(&mut message, body + 24, capabilities::LARGE_MTU);
    put_u32(&mut message, body + 28, 1024 * 1024);
    put_u32(&mut message, body + 32, 4 * 1024 * 1024);
    put_u32(&mut message, body + 36, 4 * 1024 * 1024);
    put_u32(&mut message, body + 60, 128);

    let salt = [0x5A; 32];
    message.extend_from_slice(&context_type::PREAUTH_INTEGRITY_CAPABILITIES.to_le_bytes());
    message.extend_from_slice(&38u16.to_le_bytes());
    message.extend_from_slice(&0u32.to_le_bytes());
    message.extend_from_slice(&1u16.to_le_bytes());
    message.extend_from_slice(&32u16.to_le_bytes());
    message.extend_from_slice(&preauth_hash_algorithm::SHA_512.to_le_bytes());
    message.extend_from_slice(&salt);
    message
}

fn session_response(
    message_id: u64,
    session_id: u64,
    status: u32,
    security_blob: &[u8],
) -> Vec<u8> {
    let mut header = Smb2Header::request(Command::SessionSetup, message_id, 0, 16);
    header.flags = flags::SERVER_TO_REDIR;
    header.status = StatusField::Status(status);
    header.session_id = session_id;
    let mut message = header.encode().to_vec();

    let mut body = vec![0u8; 8];
    put_u16(&mut body, 0, 9);
    put_u16(&mut body, 2, 0);
    if !security_blob.is_empty() {
        put_u16(&mut body, 4, 72);
        put_u16(&mut body, 6, security_blob.len() as u16);
    }
    message.extend_from_slice(&body);
    message.extend_from_slice(security_blob);
    message
}

#[tokio::test]
async fn multi_round_session_setup_reuses_server_session_id_and_extends_preauth_hash() {
    let session_id = 0x1122_3344_5566_7788;
    let transport = ScriptedTransport::new([
        negotiate_311_response(),
        session_response(
            1,
            session_id,
            STATUS_MORE_PROCESSING_REQUIRED,
            b"challenge-token",
        ),
        session_response(2, session_id, STATUS_SUCCESS, &[]),
    ]);

    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig::modern([0x11; 16], vec![0x22; 32]))
        .await
        .unwrap();
    let negotiate_hash = connection.preauth_hash().unwrap().clone();

    let mut auth = FakeNtlm::new();
    let session = connection
        .session_setup(&mut auth, SessionSetupConfig::default())
        .await
        .unwrap();

    assert_eq!(session.session_id(), session_id);
    assert_eq!(session.mechanism(), AuthMechanism::NtlmV2);
    assert!(session.has_session_key());
    assert_ne!(session.preauth_hash().unwrap(), &negotiate_hash);

    let transport = session.into_connection().into_transport();
    assert_eq!(transport.sent_messages().len(), 3);

    let first_setup = Smb2Header::decode(&transport.sent_messages()[1]).unwrap();
    let second_setup = Smb2Header::decode(&transport.sent_messages()[2]).unwrap();
    assert_eq!(first_setup.message_id, 1);
    assert_eq!(first_setup.session_id, 0);
    assert_eq!(second_setup.message_id, 2);
    assert_eq!(second_setup.session_id, session_id);
}

#[tokio::test]
async fn server_cannot_change_session_id_mid_exchange() {
    let transport = ScriptedTransport::new([
        negotiate_311_response(),
        session_response(1, 0xAA, STATUS_MORE_PROCESSING_REQUIRED, b"challenge-token"),
        session_response(2, 0xBB, STATUS_SUCCESS, &[]),
    ]);

    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig::modern([0x33; 16], vec![0x44; 32]))
        .await
        .unwrap();

    let mut auth = FakeNtlm::new();
    assert!(
        connection
            .session_setup(&mut auth, SessionSetupConfig::default())
            .await
            .is_err()
    );
}
