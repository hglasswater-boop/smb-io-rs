#![forbid(unsafe_code)]

//! SMB client protocol state and request engine.
//!
//! This crate owns transport lifecycle, negotiation/session/tree state, MessageIds,
//! SMB Credits, outstanding request dispatch, signing/security transforms, timeouts,
//! cancellation, reconnect coordination, and protocol metrics.

mod credits;
mod error;
mod file;
mod message_id;
mod negotiate;
mod preauth;
mod read;
mod session;
mod signing;
mod transport;
mod tree;

pub use credits::CreditManager;
pub use error::ClientError;
pub use file::{FileHandle, FileOpenOptions};
pub use message_id::MessageIdAllocator;
pub use negotiate::{Connection, NegotiateConfig, NegotiatedParameters};
pub use preauth::PreauthIntegrityHash;
pub use read::{PipelinedReadOptions, ReadOptions, STATUS_END_OF_FILE};
pub use session::{
    STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS, SessionConnection, SessionSetupConfig,
};
pub use signing::{SigningAlgorithm, SigningState};
pub use smb_io_wire::Dialect;
pub use transport::{TcpTransport, TcpTransportConfig, Transport};
pub use tree::{TreeConnectOptions, TreeHandle};
