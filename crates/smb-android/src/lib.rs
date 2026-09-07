//! Thin Android/JNI bridge.
//!
//! This crate may contain narrowly scoped, documented unsafe code required by JNI.
//! SMB protocol behavior must remain in the portable core crates.

mod engine;

pub use engine::{
    AndroidBridgeError, AndroidEngine, AndroidEngineConfig, VideoHandle, VideoOpenRequest,
};

/// Marker for the first Android bridge API generation.
pub const API_VERSION: u32 = 1;
