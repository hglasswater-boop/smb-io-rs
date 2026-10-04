use smb_io_client::FileOpenOptions;
use smb_io_wire::{create_disposition, create_options, desired_access};

#[test]
fn write_existing_random_requests_positional_read_write_access() {
    let options = FileOpenOptions::write_existing_random();
    assert_eq!(
        options.desired_access,
        desired_access::GENERIC_READ | desired_access::GENERIC_WRITE
    );
    assert_eq!(options.create_disposition, create_disposition::OPEN);
    assert_ne!(options.create_options & create_options::NON_DIRECTORY_FILE, 0);
    assert_ne!(options.create_options & create_options::RANDOM_ACCESS, 0);
}

#[test]
fn create_or_truncate_random_uses_overwrite_if() {
    let options = FileOpenOptions::create_or_truncate_random();
    assert_eq!(
        options.desired_access,
        desired_access::GENERIC_READ | desired_access::GENERIC_WRITE
    );
    assert_eq!(
        options.create_disposition,
        create_disposition::OVERWRITE_IF
    );
}

#[test]
fn open_or_create_random_preserves_existing_content() {
    let options = FileOpenOptions::open_or_create_random();
    assert_eq!(
        options.desired_access,
        desired_access::GENERIC_READ | desired_access::GENERIC_WRITE
    );
    assert_eq!(options.create_disposition, create_disposition::OPEN_IF);
}
