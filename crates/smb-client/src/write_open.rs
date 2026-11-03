use smb_io_wire::{
    create_disposition, create_options, desired_access, impersonation_level, oplock_level,
    share_access,
};

use crate::FileOpenOptions;

impl FileOpenOptions {
    /// Creates a new regular file without opening or modifying an existing destination.
    /// SMB2 FILE_CREATE is intentionally distinct from OVERWRITE_IF and OPEN_IF.
    pub const fn create_new_random() -> Self {
        Self::writable_random(create_disposition::CREATE)
    }

    /// Opens an existing non-directory file for positional read/write I/O.
    pub const fn write_existing_random() -> Self {
        Self::writable_random(create_disposition::OPEN)
    }

    /// Opens a non-directory WRITE-only output stream with OVERWRITE_IF semantics.
    ///
    /// Unlike random read/write handles, this does not request GENERIC_READ. Some writable SMB
    /// shares deliberately deny reading, so openOut must not require read access.
    pub const fn overwrite_for_stream() -> Self {
        let mut options = Self::writable_random(create_disposition::OVERWRITE_IF);
        options.desired_access = desired_access::GENERIC_WRITE;
        options
    }

    /// Opens or creates a non-directory file and truncates existing content.
    pub const fn create_or_truncate_random() -> Self {
        Self::writable_random(create_disposition::OVERWRITE_IF)
    }

    /// Opens an existing non-directory file without truncating it, or creates it when absent.
    ///
    /// Append remains explicit positional I/O: callers use the observed EOF as the `write_at`
    /// offset. This does not promise atomic append against concurrent writers.
    pub const fn open_or_create_random() -> Self {
        Self::writable_random(create_disposition::OPEN_IF)
    }

    const fn writable_random(create_disposition: u32) -> Self {
        Self {
            requested_oplock_level: oplock_level::NONE,
            impersonation_level: impersonation_level::IMPERSONATION,
            desired_access: desired_access::GENERIC_READ | desired_access::GENERIC_WRITE,
            file_attributes: 0,
            share_access: share_access::READ | share_access::WRITE | share_access::DELETE,
            create_disposition,
            create_options: create_options::NON_DIRECTORY_FILE | create_options::RANDOM_ACCESS,
            credit_request: 16,
        }
    }
}

#[cfg(test)]
mod create_file_contract_tests {
    use super::*;

    #[test]
    fn overwrite_stream_requires_only_generic_write_and_truncates_existing_content() {
        let options = FileOpenOptions::overwrite_for_stream();
        assert_eq!(options.create_disposition, create_disposition::OVERWRITE_IF);
        assert_eq!(options.desired_access, desired_access::GENERIC_WRITE);
        assert_ne!(
            options.create_options & create_options::NON_DIRECTORY_FILE,
            0
        );
        assert_eq!(
            options.share_access,
            share_access::READ | share_access::WRITE | share_access::DELETE
        );
    }

    #[test]
    fn random_access_existing_file_uses_open_without_truncation_or_creation() {
        let options = FileOpenOptions::write_existing_random();
        assert_eq!(options.create_disposition, create_disposition::OPEN);
        assert_eq!(
            options.desired_access,
            desired_access::GENERIC_READ | desired_access::GENERIC_WRITE
        );
        assert_ne!(
            options.create_options & create_options::NON_DIRECTORY_FILE,
            0
        );
        assert_ne!(options.create_disposition, create_disposition::OVERWRITE_IF);
        assert_ne!(options.create_disposition, create_disposition::OPEN_IF);
    }

    #[test]
    fn new_file_uses_create_not_overwrite_or_open_if() {
        let new_file = FileOpenOptions::create_new_random();
        assert_eq!(new_file.create_disposition, create_disposition::CREATE);
        assert_ne!(
            new_file.create_disposition,
            create_disposition::OVERWRITE_IF
        );
        assert_ne!(new_file.create_disposition, create_disposition::OPEN_IF);
        assert_eq!(
            new_file.create_options & create_options::NON_DIRECTORY_FILE,
            create_options::NON_DIRECTORY_FILE
        );
    }
}
