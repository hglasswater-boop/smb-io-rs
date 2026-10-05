use smb_io_client::FileOpenOptions;
use smb_io_wire::{create_disposition, create_options, desired_access, share_access};

#[test]
fn mutation_file_open_requests_delete_access_without_write_data() {
    let options = FileOpenOptions::mutation_existing_file();
    assert_ne!(options.desired_access & desired_access::DELETE, 0);
    assert_ne!(
        options.desired_access & desired_access::FILE_READ_ATTRIBUTES,
        0
    );
    assert_eq!(options.desired_access & desired_access::FILE_WRITE_DATA, 0);
    assert_eq!(options.create_disposition, create_disposition::OPEN);
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
fn mutation_directory_open_requests_delete_access() {
    let options = FileOpenOptions::mutation_existing_directory();
    assert_ne!(options.desired_access & desired_access::DELETE, 0);
    assert_eq!(options.create_disposition, create_disposition::OPEN);
    assert_ne!(options.create_options & create_options::DIRECTORY_FILE, 0);
    assert_eq!(
        options.create_options & create_options::NON_DIRECTORY_FILE,
        0
    );
}

#[test]
fn mkdir_open_is_create_new_directory() {
    let options = FileOpenOptions::create_directory();
    assert_eq!(options.create_disposition, create_disposition::CREATE);
    assert_ne!(options.create_options & create_options::DIRECTORY_FILE, 0);
    assert_eq!(
        options.create_options & create_options::NON_DIRECTORY_FILE,
        0
    );
    assert_ne!(options.desired_access & desired_access::DELETE, 0);
}
