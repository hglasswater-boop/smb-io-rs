#![forbid(unsafe_code)]

//! SMB2/SMB3 wire-format primitives.
//!
//! This crate owns packet representation, framing, endian-safe encoding/decoding,
//! and validation only. It must not depend on sockets, credentials, reconnect
//! policy, platform bindings, or application caching.

mod cancel;
mod create;
mod error;
mod frame;
mod header;
mod negotiate;
mod read;
mod session_setup;
mod tree_connect;

pub use cancel::{CANCEL_REQUEST_FIXED_SIZE, CANCEL_REQUEST_STRUCTURE_SIZE, CancelRequest};
pub use create::{
    CREATE_REQUEST_FIXED_SIZE, CREATE_REQUEST_STRUCTURE_SIZE, CREATE_RESPONSE_FIXED_SIZE,
    CREATE_RESPONSE_STRUCTURE_SIZE, CreateRequest, CreateResponse, FileId, create_action,
    create_disposition, create_options, desired_access, impersonation_level, oplock_level,
    share_access,
};
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
pub use read::{
    READ_REQUEST_FIXED_SIZE, READ_REQUEST_STRUCTURE_SIZE, READ_RESPONSE_FIXED_SIZE,
    READ_RESPONSE_STRUCTURE_SIZE, ReadRequest, ReadResponse, read_channel, read_request_flags,
    read_response_flags,
};
pub use session_setup::{
    SESSION_SETUP_REQUEST_FIXED_SIZE, SESSION_SETUP_REQUEST_STRUCTURE_SIZE,
    SESSION_SETUP_RESPONSE_FIXED_SIZE, SESSION_SETUP_RESPONSE_STRUCTURE_SIZE, SessionSetupRequest,
    SessionSetupResponse, request_flags, session_flags,
};
pub use tree_connect::{
    TREE_CONNECT_REQUEST_FIXED_SIZE, TREE_CONNECT_REQUEST_STRUCTURE_SIZE,
    TREE_CONNECT_RESPONSE_FIXED_SIZE, TREE_CONNECT_RESPONSE_STRUCTURE_SIZE, TreeConnectRequest,
    TreeConnectResponse, share_capabilities, share_flags, share_type, tree_connect_flags,
};

/// SMB2 protocol identifier (`0xFE 'S' 'M' 'B'`).
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
