#![forbid(unsafe_code)]

//! SMB client protocol state and request engine.
//!
//! This crate owns transport lifecycle, negotiation/session/tree state, MessageIds,
//! SMB Credits, outstanding request dispatch, signing/security transforms, timeouts,
//! cancellation, reconnect coordination, and protocol metrics.

mod error;
mod message_id;
mod negotiate;
mod preauth;
mod transport;

pub use error::ClientError;
pub use message_id::MessageIdAllocator;
pub use negotiate::{Connection, NegotiateConfig, NegotiatedParameters};
pub use preauth::PreauthIntegrityHash;
pub use smb_io_wire::Dialect;
pub use transport::{TcpTransport, TcpTransportConfig, Transport};
