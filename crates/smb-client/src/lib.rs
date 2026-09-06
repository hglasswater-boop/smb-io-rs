#![forbid(unsafe_code)]

//! SMB client protocol state and request engine.
//!
//! This crate will own transport lifecycle, negotiation/session/tree state,
//! MessageIds, SMB Credits, outstanding request dispatch, signing/security
//! transforms, timeouts, cancellation, reconnect coordination, and metrics.

/// Supported SMB dialects for the initial client scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Dialect {
    Smb202,
    Smb210,
    Smb300,
    Smb302,
    Smb311,
}
