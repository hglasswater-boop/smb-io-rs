#![forbid(unsafe_code)]

//! Filesystem-oriented SMB semantics.
//!
//! Maps stable filesystem operations to SMB CREATE/QUERY/SET_INFO behavior
//! without exposing SMB wire details to consumers.

/// High-level file kind exposed by the filesystem layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Other,
}
