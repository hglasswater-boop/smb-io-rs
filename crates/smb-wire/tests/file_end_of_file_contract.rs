use smb_io_wire::{FileEndOfFileInformation, set_info_class};

#[test]
fn eof_file_info_class_is_file_end_of_file_information() {
    assert_eq!(set_info_class::FILE_END_OF_FILE_INFORMATION, 20);
}

#[test]
fn eof_information_encodes_exactly_eight_signed_le_bytes() {
    assert_eq!(
        FileEndOfFileInformation::new(0).unwrap().encode(),
        0i64.to_le_bytes()
    );
    assert_eq!(
        FileEndOfFileInformation::new(0x1234_5678).unwrap().encode(),
        0x1234_5678i64.to_le_bytes()
    );
    assert_eq!(
        FileEndOfFileInformation::new(i64::MAX as u64)
            .unwrap()
            .encode(),
        i64::MAX.to_le_bytes()
    );
}

#[test]
fn eof_information_rejects_unrepresentable_file_length() {
    assert!(FileEndOfFileInformation::new(i64::MAX as u64 + 1).is_err());
    assert!(FileEndOfFileInformation::new(u64::MAX).is_err());
}
