use smb_io_client::SetInfoOptions;
use smb_io_wire::{info_type, set_info_class};

#[test]
fn file_set_info_options_preserve_phase9_information_class() {
    let options = SetInfoOptions::file(set_info_class::FILE_RENAME_INFORMATION, vec![1, 2, 3, 4]);
    assert_eq!(options.info_type, info_type::FILE);
    assert_eq!(
        options.file_info_class,
        set_info_class::FILE_RENAME_INFORMATION
    );
    assert_eq!(options.buffer, vec![1, 2, 3, 4]);
    assert_eq!(options.additional_information, 0);
    assert!(options.credit_request > 0);
}
