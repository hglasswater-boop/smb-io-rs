#![forbid(unsafe_code)]

//! SMB2/SMB3 wire-format primitives.
//!
//! This crate owns packet representation, framing, endian-safe encoding/decoding,
//! and validation only. It must not depend on sockets, credentials, reconnect
//! policy, platform bindings, or application caching.

/// SMB2 protocol identifier (`0xFE 'S' 'M' 'B'`).
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
