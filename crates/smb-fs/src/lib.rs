#![forbid(unsafe_code)]

//! Filesystem-oriented SMB semantics.
//!
//! Maps stable filesystem operations to SMB CREATE/QUERY/SET_INFO behavior
//! without exposing SMB wire details to consumers.

mod mutation;
mod query;

pub use mutation::{FsMutationError, create_file, delete_directory, delete_file, mkdir, rename};
pub use query::{
    DirectoryMetadataEntry, DirectoryNameEntry, FileFsFullSizeInformation, FileStandardInformation,
    FsQueryError, decode_file_id_full_directory_information,
    decode_file_id_full_directory_metadata, decode_file_names_information,
    query_standard_information, read_directory_metadata, read_directory_metadata_matching,
    read_directory_names, read_directory_names_matching,
};

/// High-level file kind exposed by the filesystem layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Other,
}
