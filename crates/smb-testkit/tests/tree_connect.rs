use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use smb_io_auth::{AuthError, AuthMechanism, AuthProvider, AuthState, AuthStep, SecretBytes};
use smb_io_client::{
    ClientError, Connection, Dialect, FileOpenOptions, NegotiateConfig, PipelinedReadOptions,
    ReadCancellationToken, STATUS_CANCELLED, SessionSetupConfig, SigningAlgorithm, SigningState,
    Transport, TreeConnectOptions,
};
use smb_io_testkit::ScriptedTransport;
use smb_io_wire::{
    CancelRequest, Command, HeaderId, SMB2_PROTOCOL_ID, Smb2Header, StatusField,
    TreeConnectRequest, capabilities, create_action, flags, security_mode, share_flags, share_type,
};
use tokio::sync::Notify;

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;
const PIPELINE_CHUNK: usize = 256 * KIB;

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

#[derive(Default)]
struct CancelGateState {
    sent: Mutex<Vec<Vec<u8>>>,
    reads_sent: AtomicUsize,
    cancels_sent: AtomicUsize,
    reads_ready: Notify,
    cancels_ready: Notify,
}

#[derive(Clone)]
struct CancelGateProbe {
    state: Arc<CancelGateState>,
}

impl CancelGateProbe {
    async fn wait_for_reads(&self, minimum: usize) {
        loop {
            let notified = self.state.reads_ready.notified();
            if self.state.reads_sent.load(Ordering::Acquire) >= minimum {
                return;
            }
            notified.await;
        }
    }

    fn cancel_count(&self) -> usize {
        self.state.cancels_sent.load(Ordering::Acquire)
    }

    fn sent_messages(&self) -> Vec<Vec<u8>> {
        self.state.sent.lock().unwrap().clone()
    }
}

struct CancelGateTransport {
    initial: VecDeque<Vec<u8>>,
    gated: VecDeque<Vec<u8>>,
    required_cancels: usize,
    state: Arc<CancelGateState>,
}

impl CancelGateTransport {
    fn new(
        initial: impl IntoIterator<Item = Vec<u8>>,
        gated: impl IntoIterator<Item = Vec<u8>>,
        required_cancels: usize,
    ) -> (Self, CancelGateProbe) {
        let state = Arc::new(CancelGateState::default());
        let probe = CancelGateProbe {
            state: state.clone(),
        };
        (
            Self {
                initial: initial.into_iter().collect(),
                gated: gated.into_iter().collect(),
                required_cancels,
                state,
            },
            probe,
        )
    }
}

impl Transport for CancelGateTransport {
    async fn send_message(&mut self, message: &[u8]) -> Result<(), ClientError> {
        let header = Smb2Header::decode(message)?;
        self.state.sent.lock().unwrap().push(message.to_vec());
        match header.command {
            Command::Read => {
                self.state.reads_sent.fetch_add(1, Ordering::AcqRel);
                self.state.reads_ready.notify_waiters();
            }
            Command::Cancel => {
                self.state.cancels_sent.fetch_add(1, Ordering::AcqRel);
                self.state.cancels_ready.notify_waiters();
            }
            _ => {}
        }
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<Vec<u8>, ClientError> {
        if let Some(message) = self.initial.pop_front() {
            return Ok(message);
        }

        loop {
            let notified = self.state.cancels_ready.notified();
            if self.state.cancels_sent.load(Ordering::Acquire) >= self.required_cancels {
                return self.gated.pop_front().ok_or(ClientError::Protocol(
                    "cancel gate transport has no gated response",
                ));
            }
            notified.await;
        }
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

fn signed_read_response(
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    fill: u8,
    signing: &SigningState,
) -> Vec<u8> {
    let data = vec![fill; PIPELINE_CHUNK];
    let mut header = Smb2Header::request(Command::Read, message_id, 4, 4);
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
    put_u32(&mut body, 4, PIPELINE_CHUNK as u32);
    put_u32(&mut body, 8, 0);
    put_u32(&mut body, 12, 0);
    message.extend_from_slice(&body);
    message.extend_from_slice(&data);
    signing.sign(&mut message).unwrap();
    message
}

fn signed_cancelled_read_response(
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    signing: &SigningState,
) -> Vec<u8> {
    let mut header = Smb2Header::request(Command::Read, message_id, 4, 4);
    header.flags = flags::SERVER_TO_REDIR;
    header.status = StatusField::Status(STATUS_CANCELLED);
    header.session_id = session_id;
    header.id = HeaderId::Sync {
        process_id: 0,
        tree_id,
    };
    let mut message = header.encode().to_vec();
    signing.sign(&mut message).unwrap();
    message
}

async fn open_test_file<T: Transport>(
    transport: T,
    session_key: [u8; 16],
) -> (
    smb_io_client::SessionConnection<T>,
    smb_io_client::FileHandle,
) {
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
    let tree = session
        .tree_connect("\\\\nas\\video", TreeConnectOptions::default())
        .await
        .unwrap();
    let file = session
        .open_file(
            &tree,
            "movies/sample.mkv",
            FileOpenOptions::read_existing_random(),
        )
        .await
        .unwrap();
    (session, file)
}

#[tokio::test]
async fn authenticated_session_pipelines_out_of_order_reads_above_four_gib() {
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
        signed_read_response(session_id, tree_id, 12, 0xA2, &signing),
        signed_read_response(session_id, tree_id, 4, 0xA0, &signing),
        signed_read_response(session_id, tree_id, 16, 0xA3, &signing),
        signed_read_response(session_id, tree_id, 8, 0xA1, &signing),
    ]);
    let (mut session, file) = open_test_file(transport, session_key).await;
    assert!(session.signing_required());
    assert_eq!(session.signing_algorithm(), Some(SigningAlgorithm::AesCmac));
    assert_eq!(file.tree_id(), tree_id);
    assert_eq!(file.path(), "movies\\sample.mkv");
    assert_eq!(file.len(), 6 * GIB);
    assert_eq!(file.allocation_size(), 6 * GIB + MIB as u64);
    assert_eq!(file.file_id().persistent, 0x1111_2222_3333_4444);
    assert_eq!(file.file_id().volatile, 0x5555_6666_7777_8888);

    let data = session
        .read_at_pipelined(&file, read_offset, MIB)
        .await
        .unwrap();
    assert_eq!(data.len(), MIB);
    for (index, expected) in [0xA0, 0xA1, 0xA2, 0xA3].into_iter().enumerate() {
        let start = index * PIPELINE_CHUNK;
        let end = start + PIPELINE_CHUNK;
        assert!(data[start..end].iter().all(|byte| *byte == expected));
    }

    let transport = session.into_connection().into_transport();
    assert_eq!(transport.sent_messages().len(), 8);

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

    for (index, expected_message_id) in [4u64, 8, 12, 16].into_iter().enumerate() {
        let read_request = &transport.sent_messages()[4 + index];
        let read_header = Smb2Header::decode(read_request).unwrap();
        assert_eq!(read_header.command, Command::Read);
        assert_eq!(read_header.message_id, expected_message_id);
        assert_eq!(read_header.credit_charge, 4);
        assert_eq!(read_header.session_id, session_id);
        assert_ne!(read_header.flags & flags::SIGNED, 0);

        let body = &read_request[64..];
        assert_eq!(body[2], 0x50);
        assert_eq!(
            u32::from_le_bytes(body[4..8].try_into().unwrap()),
            PIPELINE_CHUNK as u32
        );
        assert_eq!(
            u64::from_le_bytes(body[8..16].try_into().unwrap()),
            read_offset + (index * PIPELINE_CHUNK) as u64
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
}

#[tokio::test]
async fn seek_cancels_in_flight_reads_drains_old_responses_and_reuses_connection() {
    let session_key = [0xA5; 16];
    let session_id = 0x1122_3344_5566_7788;
    let tree_id = 0x42;
    let read_offset = 4 * GIB + 33_333;
    let signing = SigningState::derive(
        Dialect::Smb302,
        SigningAlgorithm::AesCmac,
        &SecretBytes::new(session_key.to_vec()),
        None,
    )
    .unwrap();

    let (transport, probe) = CancelGateTransport::new(
        [
            negotiate_302_response(),
            signed_session_response(session_id, &signing),
            signed_tree_response(session_id, tree_id, &signing),
            signed_create_response(session_id, tree_id, &signing),
        ],
        [
            signed_cancelled_read_response(session_id, tree_id, 12, &signing),
            signed_cancelled_read_response(session_id, tree_id, 4, &signing),
            signed_cancelled_read_response(session_id, tree_id, 16, &signing),
            signed_cancelled_read_response(session_id, tree_id, 8, &signing),
            signed_read_response(session_id, tree_id, 20, 0xBC, &signing),
        ],
        4,
    );
    let (mut session, file) = open_test_file(transport, session_key).await;

    let cancellation = ReadCancellationToken::new();
    let generation = cancellation.generation();
    let trigger_token = cancellation.clone();
    let trigger_probe = probe.clone();
    let trigger = tokio::spawn(async move {
        trigger_probe.wait_for_reads(4).await;
        trigger_token.advance()
    });

    let cancelled = session
        .read_at_pipelined_cancelable_with_options(
            &file,
            read_offset,
            MIB,
            PipelinedReadOptions {
                chunk_size: PIPELINE_CHUNK,
                max_in_flight: 4,
                credit_request: 32,
            },
            &cancellation,
            generation,
        )
        .await;
    assert!(matches!(cancelled, Err(ClientError::Cancelled)));
    let next_generation = trigger.await.unwrap();
    assert_eq!(next_generation, generation + 1);
    assert_eq!(probe.cancel_count(), 4);

    let resumed = session
        .read_at_pipelined_cancelable_with_options(
            &file,
            read_offset + MIB as u64,
            PIPELINE_CHUNK,
            PipelinedReadOptions {
                chunk_size: PIPELINE_CHUNK,
                max_in_flight: 1,
                credit_request: 32,
            },
            &cancellation,
            next_generation,
        )
        .await
        .unwrap();
    assert_eq!(resumed.len(), PIPELINE_CHUNK);
    assert!(resumed.iter().all(|byte| *byte == 0xBC));

    let sent = probe.sent_messages();
    let headers = sent
        .iter()
        .map(|message| Smb2Header::decode(message).unwrap())
        .collect::<Vec<_>>();
    let read_ids = headers
        .iter()
        .filter(|header| header.command == Command::Read)
        .map(|header| header.message_id)
        .collect::<Vec<_>>();
    assert_eq!(read_ids, vec![4, 8, 12, 16, 20]);

    let cancel_messages = sent
        .iter()
        .filter(|message| Smb2Header::decode(message).unwrap().command == Command::Cancel)
        .collect::<Vec<_>>();
    assert_eq!(cancel_messages.len(), 4);
    for (message, expected_message_id) in cancel_messages.iter().zip([4u64, 8, 12, 16]) {
        let (header, _) = CancelRequest::decode_message(message).unwrap();
        assert_eq!(header.message_id, expected_message_id);
        assert_eq!(header.credit_charge, 0);
        assert_eq!(header.credits, 0);
        assert_eq!(header.session_id, session_id);
        assert_ne!(header.flags & flags::SIGNED, 0);
        assert_eq!(
            header.id,
            HeaderId::Sync {
                process_id: 0,
                tree_id: 0,
            }
        );
    }
}
