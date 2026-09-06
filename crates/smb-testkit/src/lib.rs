#![forbid(unsafe_code)]

//! Test fixtures, mock transports, interoperability helpers, and fuzz support.

use std::collections::VecDeque;

use smb_io_client::{ClientError, Transport};

/// Identifies a protocol fixture by a stable human-readable name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureName(pub &'static str);

/// Deterministic message transport for protocol-state tests.
///
/// Each call to `receive_message` pops one pre-scripted SMB message. Every sent message is retained
/// byte-for-byte so tests can verify MessageIds, negotiate contexts, signing input, and preauth
/// hashing without opening a socket.
#[derive(Debug, Default)]
pub struct ScriptedTransport {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl ScriptedTransport {
    pub fn new(incoming: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            incoming: incoming.into_iter().collect(),
            sent: Vec::new(),
        }
    }

    pub fn sent_messages(&self) -> &[Vec<u8>] {
        &self.sent
    }

    pub fn remaining_messages(&self) -> usize {
        self.incoming.len()
    }
}

impl Transport for ScriptedTransport {
    async fn send_message(&mut self, message: &[u8]) -> Result<(), ClientError> {
        self.sent.push(message.to_vec());
        Ok(())
    }

    async fn receive_message(&mut self) -> Result<Vec<u8>, ClientError> {
        self.incoming
            .pop_front()
            .ok_or(ClientError::Protocol("scripted transport has no queued response"))
    }
}
