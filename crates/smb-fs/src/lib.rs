#![forbid(unsafe_code)]

//! Filesystem-oriented SMB semantics.
//!
//! Maps stable filesystem operations to SMB CREATE/QUERY/SET_INFO behavior
//! without exposing SMB wire details to consumers.

mod query;

pub use query::{
    DirectoryNameEntry, FileStandardInformation, FsQueryError, decode_file_names_information,
    query_standard_information, read_directory_names, read_directory_names_matching,
};

/// High-level file kind exposed by the filesystem layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Other,
}
