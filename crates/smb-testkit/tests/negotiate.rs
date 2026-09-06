use smb_io_client::{Connection, Dialect, NegotiateConfig};
use smb_io_testkit::ScriptedTransport;
use smb_io_wire::{SMB2_PROTOCOL_ID, capabilities, context_type, preauth_hash_algorithm, security_mode};

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn negotiate_response(dialect: Dialect, message_id: u64, with_preauth: bool) -> Vec<u8> {
    let mut message = vec![0u8; 128];
    message[0..4].copy_from_slice(&SMB2_PROTOCOL_ID);
    put_u16(&mut message, 4, 64);
    put_u16(&mut message, 12, 0); // NEGOTIATE
    put_u16(&mut message, 14, 32); // initial credits
    put_u32(&mut message, 16, 1); // SERVER_TO_REDIR
    put_u64(&mut message, 24, message_id);

    let body = 64;
    put_u16(&mut message, body, 65);
    put_u16(&mut message, body + 2, security_mode::SIGNING_ENABLED);
    put_u16(&mut message, body + 4, dialect as u16);
    message[body + 8..body + 24].copy_from_slice(&[0x42; 16]);
    put_u32(&mut message, body + 24, capabilities::LARGE_MTU);
    put_u32(&mut message, body + 28, 1024 * 1024);
    put_u32(&mut message, body + 32, 4 * 1024 * 1024);
    put_u32(&mut message, body + 36, 4 * 1024 * 1024);

    if with_preauth {
        put_u16(&mut message, body + 6, 1);
        put_u32(&mut message, body + 60, 128);

        let salt = [0x5A; 32];
        let mut context = Vec::new();
        context.extend_from_slice(&context_type::PREAUTH_INTEGRITY_CAPABILITIES.to_le_bytes());
        context.extend_from_slice(&38u16.to_le_bytes());
        context.extend_from_slice(&0u32.to_le_bytes());
        context.extend_from_slice(&1u16.to_le_bytes());
        context.extend_from_slice(&32u16.to_le_bytes());
        context.extend_from_slice(&preauth_hash_algorithm::SHA_512.to_le_bytes());
        context.extend_from_slice(&salt);
        message.extend_from_slice(&context);
    }

    message
}

#[tokio::test]
async fn negotiates_smb302_and_records_exact_request() {
    let transport = ScriptedTransport::new([negotiate_response(Dialect::Smb302, 0, false)]);
    let mut connection = Connection::new(transport);
    let config = NegotiateConfig {
        dialects: vec![Dialect::Smb210, Dialect::Smb302],
        security_mode: security_mode::SIGNING_ENABLED,
        capabilities: capabilities::LARGE_MTU,
        client_guid: [0x11; 16],
        preauth_salt: Vec::new(),
        credit_request: 32,
    };

    let negotiated = connection.negotiate(&config).await.unwrap();
    assert_eq!(negotiated.dialect, Dialect::Smb302);
    assert_eq!(negotiated.max_read_size, 4 * 1024 * 1024);
    assert_eq!(negotiated.initial_credits, 32);
    assert!(connection.preauth_hash().is_none());

    let transport = connection.into_transport();
    assert_eq!(transport.sent_messages().len(), 1);
    assert_eq!(&transport.sent_messages()[0][0..4], &SMB2_PROTOCOL_ID);
}

#[tokio::test]
async fn smb311_keeps_negotiate_preauth_hash() {
    let transport = ScriptedTransport::new([negotiate_response(Dialect::Smb311, 0, true)]);
    let mut connection = Connection::new(transport);
    let config = NegotiateConfig::modern([0x22; 16], vec![0x33; 32]);

    let negotiated = connection.negotiate(&config).await.unwrap();
    assert_eq!(negotiated.dialect, Dialect::Smb311);
    assert_ne!(connection.preauth_hash().unwrap().current(), &[0; 64]);
}

#[tokio::test]
async fn mismatched_message_id_is_rejected() {
    let transport = ScriptedTransport::new([negotiate_response(Dialect::Smb302, 77, false)]);
    let mut connection = Connection::new(transport);
    let config = NegotiateConfig {
        dialects: vec![Dialect::Smb302],
        security_mode: security_mode::SIGNING_ENABLED,
        capabilities: capabilities::LARGE_MTU,
        client_guid: [0x44; 16],
        preauth_salt: Vec::new(),
        credit_request: 8,
    };

    assert!(connection.negotiate(&config).await.is_err());
}
