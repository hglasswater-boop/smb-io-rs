use core::fmt;

use smb_io_auth::AuthError;
use smb_io_wire::WireError;

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Wire(WireError),
    Auth(AuthError),
    Timeout(&'static str),
    ServerStatus(u32),
    Cancelled,
    /// A well-formed peer or negotiated dialect does not provide an optional capability.
    ///
    /// This is intentionally distinct from `Protocol`: callers may choose a documented fallback
    /// for an unavailable optional feature, but must never use that fallback to mask malformed or
    /// security-invalid protocol traffic.
    Capability(&'static str),
    Protocol(&'static str),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "SMB transport I/O failed: {error}"),
            Self::Wire(error) => write!(f, "SMB wire error: {error}"),
            Self::Auth(error) => write!(f, "SMB authentication error: {error}"),
            Self::Timeout(stage) => write!(f, "SMB operation timed out during {stage}"),
            Self::ServerStatus(status) => write!(f, "SMB server returned NTSTATUS 0x{status:08X}"),
            Self::Cancelled => f.write_str("SMB operation was cancelled"),
            Self::Capability(message) => write!(f, "SMB capability unavailable: {message}"),
            Self::Protocol(message) => write!(f, "SMB protocol error: {message}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::Auth(error) => Some(error),
            Self::Timeout(_)
            | Self::ServerStatus(_)
            | Self::Cancelled
            | Self::Capability(_)
            | Self::Protocol(_) => None,
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<WireError> for ClientError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<AuthError> for ClientError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}
