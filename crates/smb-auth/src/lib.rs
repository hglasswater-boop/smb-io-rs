#![forbid(unsafe_code)]

//! Authentication provider boundary for SMB sessions.
//!
//! Implementations cover SPNEGO + NTLMv2 first and can later add Kerberos without leaking
//! mechanism-specific packet details into the SMB protocol state machine. Session keys and
//! credential material remain secret types and never expose plaintext through `Debug`.

mod anonymous;
mod ntlm;
mod provider;
mod secret;
mod spnego;

pub use anonymous::AnonymousNtlmProvider;
pub use ntlm::{NtlmCredentials, NtlmV2Provider, flags as ntlm_flags};
pub use provider::{AuthError, AuthMechanism, AuthProvider, AuthState, AuthStep};
pub use secret::SecretBytes;
