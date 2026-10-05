use smb_io_wire::{
    create_disposition, create_options, desired_access, impersonation_level, oplock_level,
    share_access,
};

use crate::FileOpenOptions;

impl FileOpenOptions {
    pub const fn mutation_existing() -> Self {
        Self {
            requested_oplock_level: oplock_level::NONE,
            impersonation_level: impersonation_level::IMPERSONATION,
            desired_access: desired_access::DELETE | desired_access::FILE_READ_ATTRIBUTES,
            file_attributes: 0,
            share_access: share_access::READ | share_access::WRITE | share_access::DELETE,
            create_disposition: create_disposition::OPEN,
            create_options: 0,
            credit_request: 16,
        }
    }

    pub const fn mutation_existing_file() -> Self {
        Self {
            create_options: create_options::NON_DIRECTORY_FILE,
            ..Self::mutation_existing()
        }
    }

    pub const fn mutation_existing_directory() -> Self {
        Self {
            create_options: create_options::DIRECTORY_FILE,
            ..Self::mutation_existing()
        }
    }

    pub const fn create_directory() -> Self {
        Self {
            requested_oplock_level: oplock_level::NONE,
            impersonation_level: impersonation_level::IMPERSONATION,
            desired_access: desired_access::DELETE
                | desired_access::FILE_READ_ATTRIBUTES
                | desired_access::FILE_WRITE_ATTRIBUTES,
            file_attributes: 0,
            share_access: share_access::READ | share_access::WRITE | share_access::DELETE,
            create_disposition: create_disposition::CREATE,
            create_options: create_options::DIRECTORY_FILE,
            credit_request: 16,
        }
    }
}
