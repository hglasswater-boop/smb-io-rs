use core::fmt;

use crate::SecretBytes;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMechanism {
    Anonymous,
    NtlmV2,
    Kerberos,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthState {
    Continue,
    Complete,
}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthStep {
    pub token: Vec<u8>,
    pub state: AuthState,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuthError {
    InvalidToken(&'static str),
    InvalidState(&'static str),
    Unsupported(&'static str),
    Failed(&'static str),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToken(message) => write!(f, "invalid authentication token: {message}"),
            Self::InvalidState(message) => write!(f, "invalid authentication state: {message}"),
            Self::Unsupported(message) => {
                write!(f, "unsupported authentication feature: {message}")
            }
            Self::Failed(message) => write!(f, "authentication failed: {message}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Authentication mechanism plugged into the SMB SESSION_SETUP exchange.
///
/// Implementations own SPNEGO/NTLM/Kerberos token semantics. The SMB client only transports the
/// returned opaque tokens and takes ownership of the final session key after authentication.
pub trait AuthProvider {
    fn mechanism(&self) -> AuthMechanism;

    /// Produce the first token sent in SESSION_SETUP.
    fn initial_token(&mut self) -> Result<AuthStep, AuthError>;

    /// Process one server security blob and optionally produce the next client token.
    fn next_token(&mut self, server_token: &[u8]) -> Result<AuthStep, AuthError>;

    /// Transfers the completed mechanism's session key into the SMB session.
    ///
    /// Anonymous mechanisms may return `None`. Authenticated mechanisms are expected to return a
    /// key after reaching `AuthState::Complete`.
    fn take_session_key(&mut self) -> Option<SecretBytes>;
}
