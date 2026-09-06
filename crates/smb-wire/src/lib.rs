#![forbid(unsafe_code)]

//! SMB2/SMB3 wire-format primitives.
//!
//! This crate owns packet representation, framing, endian-safe encoding/decoding,
//! and validation only. It must not depend on sockets, credentials, reconnect
//! policy, platform bindings, or application caching.

mod error;
mod frame;
mod header;
mod negotiate;

pub use error::WireError;
pub use frame::{
    DIRECT_TCP_HEADER_SIZE, DIRECT_TCP_MAX_PAYLOAD, decode_direct_tcp_frame,
    decode_direct_tcp_length, encode_direct_tcp_frame,
};
pub use header::{
    Command, HeaderId, SMB2_HEADER_SIZE, SMB2_HEADER_STRUCTURE_SIZE, Smb2Header, StatusField, flags,
};
pub use negotiate::{
    Dialect, NEGOTIATE_REQUEST_STRUCTURE_SIZE, NEGOTIATE_RESPONSE_FIXED_SIZE,
    NEGOTIATE_RESPONSE_STRUCTURE_SIZE, NegotiateContext, NegotiateRequest, NegotiateResponse,
    capabilities, context_type, preauth_hash_algorithm, security_mode,
};

/// SMB2 protocol identifier (`0xFE 'S' 'M' 'B'`).
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
