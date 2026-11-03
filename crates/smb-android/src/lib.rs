//! Thin Android/JNI bridge.
//!
//! This crate may contain narrowly scoped, documented unsafe code required by JNI.
//! SMB protocol behavior must remain in the portable core crates.

mod engine;
mod jni;

pub use engine::{
    AndroidBridgeError, AndroidEngine, AndroidEngineConfig, SmbMutationRequest, VideoHandle,
    VideoOpenRequest,
};

/// Android bridge API generation that adds one-shot non-retrying mkdir to the video API.
pub const API_VERSION: u32 = 3;
