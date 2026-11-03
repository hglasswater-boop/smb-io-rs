//! Thin Android/JNI bridge.
//!
//! This crate may contain narrowly scoped, documented unsafe code required by JNI.
//! SMB protocol behavior must remain in the portable core crates.

mod engine;
mod jni;

pub use engine::{
    AndroidBridgeError, AndroidEngine, AndroidEngineConfig, DirectoryHandle, RandomHandle,
    SmbMutationRequest, VideoHandle, VideoOpenRequest, WritableHandle,
};

/// Android bridge API generation for video, mutations, metadata, capacity and directory size.
pub const API_VERSION: u32 = 9;
