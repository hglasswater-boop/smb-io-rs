use smb_io_auth::{
    AuthError, AuthMechanism, AuthProvider, AuthState, AuthStep, NtlmCredentials, NtlmV2Provider,
    SecretBytes, ntlm_flags,
};
use smb_io_client::{
    Connection, CreditManager, Dialect, NegotiateConfig, PreauthIntegrityHash,
    STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS, SessionSetupConfig, SigningAlgorithm,
    SigningState,
};
use smb_io_testkit::ScriptedTransport;
use smb_io_wire::{
    Command, NegotiateContext, NegotiateRequest, SMB2_PROTOCOL_ID, SessionSetupRequest, Smb2Header,
    StatusField, capabilities, context_type, flags, preauth_hash_algorithm, security_mode,
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

fn set_credit_charge(message: &mut [u8], credit_charge: u16) {
    message[6..8].copy_from_slice(&credit_charge.to_le_bytes());
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
    put_u16(&mut message, body + 2, security_mode::SIGNING_ENABLED);
    put_u16(&mut message, body + 4, Dialect::Smb302 as u16);
    message[body + 8..body + 24].copy_from_slice(&[0x42; 16]);
    put_u32(&mut message, body + 24, capabilities::LARGE_MTU);
    put_u32(&mut message, body + 28, 1024 * 1024);
    put_u32(&mut message, body + 32, 4 * 1024 * 1024);
    put_u32(&mut message, body + 36, 4 * 1024 * 1024);
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

fn modern_311_request(client_guid: [u8; 16], preauth_salt: Vec<u8>) -> Vec<u8> {
    let signing_context = NegotiateContext {
        context_type: context_type::SIGNING_CAPABILITIES,
        data: vec![
            2,
            0,
            SigningAlgorithm::AesCmac as u8,
            0,
            SigningAlgorithm::HmacSha256 as u8,
            0,
        ],
    };
    let request = NegotiateRequest {
        security_mode: security_mode::SIGNING_ENABLED,
        capabilities: capabilities::LARGE_MTU,
        client_guid,
        dialects: vec![
            Dialect::Smb202,
            Dialect::Smb210,
            Dialect::Smb300,
            Dialect::Smb302,
            Dialect::Smb311,
        ],
        contexts: vec![
            NegotiateContext::preauth_sha512(preauth_salt).unwrap(),
            signing_context,
        ],
    };
    request.encode_message(0, 64).unwrap()
}

fn signed_final_311_response_for_fake(
    client_guid: [u8; 16],
    preauth_salt: Vec<u8>,
    session_id: u64,
) -> Vec<u8> {
    let negotiate_request = modern_311_request(client_guid, preauth_salt);
    let negotiate_response = negotiate_311_response();

    // Keep this fixture's SESSION_SETUP transcript byte-for-byte aligned with the client's credit
    // accounting. Credit fields participate in the SMB 3.1.1 preauthentication hash.
    let mut credits = CreditManager::new(32).unwrap();
    credits.reserve(1).unwrap();
    let first_credit_request = credits.request_hint(32);
    let mut first_request = SessionSetupRequest {
        flags: 0,
        security_mode: security_mode::SIGNING_ENABLED as u8,
        capabilities: 0,
        previous_session_id: 0,
        security_blob: b"negotiate-token".to_vec(),
    }
    .encode_message(1, 0, first_credit_request)
    .unwrap();
    set_credit_charge(&mut first_request, 1);

    let first_response = session_response(
        1,
        session_id,
        STATUS_MORE_PROCESSING_REQUIRED,
        b"challenge-token",
    );
    credits.grant(16).unwrap();
    credits.reserve(1).unwrap();
    let final_credit_request = credits.request_hint(32);
    let mut final_request = SessionSetupRequest {
        flags: 0,
        security_mode: security_mode::SIGNING_ENABLED as u8,
        capabilities: 0,
        previous_session_id: 0,
        security_blob: b"authenticate-token".to_vec(),
    }
    .encode_message(2, session_id, final_credit_request)
    .unwrap();
    set_credit_charge(&mut final_request, 1);

    let mut preauth = PreauthIntegrityHash::new();
    for message in [
        negotiate_request.as_slice(),
        negotiate_response.as_slice(),
        first_request.as_slice(),
        first_response.as_slice(),
        final_request.as_slice(),
    ] {
        preauth.update(message);
    }

    let signing = SigningState::derive(
        Dialect::Smb311,
        SigningAlgorithm::AesCmac,
        &SecretBytes::new(vec![0xA5; 16]),
        Some(&preauth),
    )
    .unwrap();
    let mut response = session_response(2, session_id, STATUS_SUCCESS, &[]);
    signing.sign(&mut response).unwrap();
    response
}

fn ntlm_type2_challenge() -> Vec<u8> {
    let mut target_info = Vec::new();
    // MsvAvNbDomainName = "Domain"
    target_info.extend_from_slice(&2u16.to_le_bytes());
    target_info.extend_from_slice(&12u16.to_le_bytes());
    for unit in "Domain".encode_utf16() {
        target_info.extend_from_slice(&unit.to_le_bytes());
    }
    // MsvAvNbComputerName = "Server"
    target_info.extend_from_slice(&1u16.to_le_bytes());
    target_info.extend_from_slice(&12u16.to_le_bytes());
    for unit in "Server".encode_utf16() {
        target_info.extend_from_slice(&unit.to_le_bytes());
    }
    // Fixed MsvAvTimestamp keeps this integration test deterministic except for ClientChallenge.
    target_info.extend_from_slice(&7u16.to_le_bytes());
    target_info.extend_from_slice(&8u16.to_le_bytes());
    target_info.extend_from_slice(&0x01c3_34b7_36d3_9000u64.to_le_bytes());
    // MsvAvEOL
    target_info.extend_from_slice(&0u16.to_le_bytes());
    target_info.extend_from_slice(&0u16.to_le_bytes());

    let mut message = vec![0u8; 48];
    message[0..8].copy_from_slice(b"NTLMSSP\0");
    put_u32(&mut message, 8, 2);
    let challenge_flags = ntlm_flags::NEGOTIATE_UNICODE
        | ntlm_flags::NEGOTIATE_NTLM
        | ntlm_flags::NEGOTIATE_ALWAYS_SIGN
        | ntlm_flags::NEGOTIATE_EXTENDED_SESSIONSECURITY
        | ntlm_flags::NEGOTIATE_TARGET_INFO
        | ntlm_flags::NEGOTIATE_128
        | ntlm_flags::NEGOTIATE_56;
    put_u32(&mut message, 20, challenge_flags);
    message[24..32].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    put_u16(&mut message, 40, target_info.len() as u16);
    put_u16(&mut message, 42, target_info.len() as u16);
    put_u32(&mut message, 44, 48);
    message.extend_from_slice(&target_info);
    message
}

fn find_ntlm_message(blob: &[u8]) -> &[u8] {
    let start = blob
        .windows(8)
        .position(|window| window == b"NTLMSSP\0")
        .expect("SPNEGO token should contain NTLMSSP");
    &blob[start..]
}

fn read_ntlm_security_buffer(message: &[u8], field_offset: usize) -> &[u8] {
    let length = usize::from(u16::from_le_bytes([
        message[field_offset],
        message[field_offset + 1],
    ]));
    let offset = u32::from_le_bytes([
        message[field_offset + 4],
        message[field_offset + 5],
        message[field_offset + 6],
        message[field_offset + 7],
    ]) as usize;
    &message[offset..offset + length]
}

fn utf16le(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[tokio::test]
async fn multi_round_session_setup_reuses_server_session_id_and_extends_preauth_hash() {
    let session_id = 0x1122_3344_5566_7788;
    let client_guid = [0x11; 16];
    let preauth_salt = vec![0x22; 32];
    let transport = ScriptedTransport::new([
        negotiate_311_response(),
        session_response(
            1,
            session_id,
            STATUS_MORE_PROCESSING_REQUIRED,
            b"challenge-token",
        ),
        signed_final_311_response_for_fake(client_guid, preauth_salt.clone(), session_id),
    ]);

    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig::modern(client_guid, preauth_salt))
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
    assert_eq!(session.signing_algorithm(), Some(SigningAlgorithm::AesCmac));
    assert_ne!(session.preauth_hash().unwrap(), &negotiate_hash);

    let transport = session.into_connection().into_transport();
    assert_eq!(transport.sent_messages().len(), 3);

    let first_setup = Smb2Header::decode(&transport.sent_messages()[1]).unwrap();
    let second_setup = Smb2Header::decode(&transport.sent_messages()[2]).unwrap();
    assert_eq!(first_setup.message_id, 1);
    assert_eq!(first_setup.credit_charge, 1);
    assert_eq!(first_setup.session_id, 0);
    assert_eq!(second_setup.message_id, 2);
    assert_eq!(second_setup.credit_charge, 1);
    assert_eq!(second_setup.session_id, session_id);
}

#[tokio::test]
async fn smb311_rejects_unsigned_final_session_setup_response() {
    let session_id = 0x8877_6655_4433_2211;
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
        .negotiate(&NegotiateConfig::modern([0x31; 16], vec![0x41; 32]))
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

#[tokio::test]
async fn real_ntlmv2_provider_emits_type1_then_type3_through_session_setup() {
    let session_id = 0x0102_0304_0506_0708;
    let transport = ScriptedTransport::new([
        negotiate_302_response(),
        session_response(
            1,
            session_id,
            STATUS_MORE_PROCESSING_REQUIRED,
            &ntlm_type2_challenge(),
        ),
        session_response(2, session_id, STATUS_SUCCESS, &[]),
    ]);

    let mut connection = Connection::new(transport);
    connection
        .negotiate(&NegotiateConfig {
            dialects: vec![Dialect::Smb302],
            security_mode: security_mode::SIGNING_ENABLED,
            capabilities: capabilities::LARGE_MTU,
            client_guid: [0x55; 16],
            preauth_salt: Vec::new(),
            signing_algorithms: Vec::new(),
            credit_request: 64,
        })
        .await
        .unwrap();

    let credentials = NtlmCredentials::new("User", "Password")
        .with_domain("Domain")
        .with_workstation("COMPUTER");
    let mut auth = NtlmV2Provider::new(credentials);
    let session = connection
        .session_setup(&mut auth, SessionSetupConfig::default())
        .await
        .unwrap();

    assert_eq!(session.session_id(), session_id);
    assert_eq!(session.mechanism(), AuthMechanism::NtlmV2);
    assert!(session.has_session_key());

    let transport = session.into_connection().into_transport();
    let first = SessionSetupRequest::decode_message(&transport.sent_messages()[1]).unwrap();
    let second = SessionSetupRequest::decode_message(&transport.sent_messages()[2]).unwrap();

    let type1 = find_ntlm_message(&first.security_blob);
    assert_eq!(u32::from_le_bytes(type1[8..12].try_into().unwrap()), 1);

    let type3 = find_ntlm_message(&second.security_blob);
    assert_eq!(u32::from_le_bytes(type3[8..12].try_into().unwrap()), 3);
    assert_eq!(read_ntlm_security_buffer(type3, 28), utf16le("Domain"));
    assert_eq!(read_ntlm_security_buffer(type3, 36), utf16le("User"));
    assert_eq!(read_ntlm_security_buffer(type3, 44), utf16le("COMPUTER"));
    assert_eq!(read_ntlm_security_buffer(type3, 12), vec![0u8; 24]);
    assert!(!read_ntlm_security_buffer(type3, 20).is_empty());
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
