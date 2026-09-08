#![forbid(unsafe_code)]

//! SMB client protocol state and request engine.
//!
//! This crate owns transport lifecycle, negotiation/session/tree state, MessageIds,
//! SMB Credits, outstanding request dispatch, signing/security transforms, timeouts,
//! cancellation, reconnect coordination, and protocol metrics.

mod cancel;
mod cancellation;
mod close;
mod credits;
mod durable_open;
mod error;
mod file;
mod message_id;
mod negotiate;
mod preauth;
mod read;
mod read_async;
mod reconnect;
mod recovering_read;
mod session;
mod signing;
mod transport;
mod tree;

pub use cancel::STATUS_CANCELLED;
pub use cancellation::ReadCancellationToken;
pub use close::{CloseInfo, CloseOptions};
pub use credits::CreditManager;
pub use durable_open::{DurableFileHandle, DurableHandleV2Options};
pub use error::ClientError;
pub use file::{FileHandle, FileOpenOptions, FileOpenResult};
pub use message_id::MessageIdAllocator;
pub use negotiate::{Connection, NegotiateConfig, NegotiatedParameters};
pub use preauth::PreauthIntegrityHash;
pub use read::{PipelinedReadOptions, ReadOptions, STATUS_END_OF_FILE};
pub use read_async::STATUS_PENDING;
pub use reconnect::{
    ReadOnlyReconnectRecipe, ReconnectError, STATUS_NETWORK_NAME_DELETED,
    STATUS_NETWORK_SESSION_EXPIRED, STATUS_USER_SESSION_DELETED, connect_read_only_file,
    connect_read_only_file_cancelable, is_retryable_client_error,
};
pub use recovering_read::{ReadReconnectPolicy, RecoveringReadOnlyFile};
pub use session::{
    STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS, SessionConnection, SessionSetupConfig,
};
pub use signing::{SigningAlgorithm, SigningState};
pub use smb_io_wire::Dialect;
pub use transport::{TcpTransport, TcpTransportConfig, Transport};
pub use tree::{TreeConnectOptions, TreeHandle};
