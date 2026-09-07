#![forbid(unsafe_code)]

//! High-throughput positional I/O policy for SMB files.
//!
//! Owns request splitting/reassembly, priority scheduling, adaptive read-ahead,
//! bounded range caching, cancellation generations, and workload metrics.

mod video;

pub use video::{StreamError, VideoReader, VideoReaderConfig};

/// Scheduling classes used by the stream request broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum IoPriority {
    Background,
    Transfer,
    SequentialPrefetch,
    Control,
    Interactive,
}
