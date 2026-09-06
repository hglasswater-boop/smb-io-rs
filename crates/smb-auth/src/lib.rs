#![forbid(unsafe_code)]

//! Authentication provider boundary for SMB sessions.
//!
//! Initial implementations will cover SPNEGO + NTLMv2. Session keys and
//! credential material must remain secret types and must never leak through
//! logs or Debug output.

/// Authentication mechanism selected for a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMechanism {
    Anonymous,
    NtlmV2,
}
