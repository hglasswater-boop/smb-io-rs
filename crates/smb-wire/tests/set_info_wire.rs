use smb_io_wire::{
    Command, FileDispositionInformation, FileDispositionInformationEx, FileId,
    FileRenameInformation, FileRenameInformationEx, SetInfoRequest, Smb2Header, disposition_flags,
    info_type, rename_flags, set_info_class,
};

#[test]
fn set_info_file_request_uses_protocol_layout() {
    let file_id = FileId::new(0x1111_2222_3333_4444, 0x5555_6666_7777_8888);
    let buffer = FileRenameInformation::new("folder\\新名.txt", true)
        .encode()
        .unwrap();
    let request = SetInfoRequest::file(
        file_id,
        set_info_class::FILE_RENAME_INFORMATION,
        buffer.clone(),
    );
    let message = request.encode_message(7, 8, 9, 1, 16).unwrap();

    let header = Smb2Header::decode(&message).unwrap();
    assert_eq!(header.command, Command::SetInfo);
    assert_eq!(header.credit_charge, 1);

    let body = &message[64..];
    assert_eq!(u16::from_le_bytes([body[0], body[1]]), 33);
    assert_eq!(body[2], info_type::FILE);
    assert_eq!(body[3], set_info_class::FILE_RENAME_INFORMATION);
    assert_eq!(
        u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize,
        buffer.len()
    );
    assert_eq!(u16::from_le_bytes(body[8..10].try_into().unwrap()), 96);
    assert_eq!(u32::from_le_bytes(body[12..16].try_into().unwrap()), 0);
    assert_eq!(
        u64::from_le_bytes(body[16..24].try_into().unwrap()),
        file_id.persistent
    );
    assert_eq!(
        u64::from_le_bytes(body[24..32].try_into().unwrap()),
        file_id.volatile
    );
    assert_eq!(&body[32..], buffer.as_slice());
}

#[test]
fn classic_rename_encodes_smb2_type2_and_unicode_name() {
    let encoded = FileRenameInformation::new("dir\\日本語.txt", true)
        .encode()
        .unwrap();
    assert_eq!(encoded[0], 1);
    assert_eq!(&encoded[1..8], &[0; 7]);
    assert_eq!(u64::from_le_bytes(encoded[8..16].try_into().unwrap()), 0);
    let name_len = u32::from_le_bytes(encoded[16..20].try_into().unwrap()) as usize;
    assert_eq!(name_len, "dir\\日本語.txt".encode_utf16().count() * 2);
    assert!(encoded.len() >= 24);
    assert_eq!((encoded.len() - 20).min(name_len), name_len);
}

#[test]
fn extended_rename_and_disposition_expose_phase9_flags() {
    let rename = FileRenameInformationEx::new(
        "replacement.txt",
        rename_flags::REPLACE_IF_EXISTS | rename_flags::IGNORE_READONLY_ATTRIBUTE,
    )
    .encode()
    .unwrap();
    assert_eq!(
        u32::from_le_bytes(rename[0..4].try_into().unwrap()),
        rename_flags::REPLACE_IF_EXISTS | rename_flags::IGNORE_READONLY_ATTRIBUTE
    );
    assert_eq!(u64::from_le_bytes(rename[8..16].try_into().unwrap()), 0);
    assert!(rename.len() >= 24);

    assert_eq!(FileDispositionInformation::delete().encode(), vec![1]);
    assert_eq!(FileDispositionInformation::keep().encode(), vec![0]);

    let disposition = FileDispositionInformationEx::new(
        disposition_flags::DELETE | disposition_flags::IGNORE_READONLY_ATTRIBUTE,
    )
    .encode();
    assert_eq!(
        disposition,
        (disposition_flags::DELETE | disposition_flags::IGNORE_READONLY_ATTRIBUTE)
            .to_le_bytes()
            .to_vec()
    );
}

#[test]
fn phase9_file_information_class_numbers_match_ms_fscc() {
    assert_eq!(set_info_class::FILE_RENAME_INFORMATION, 10);
    assert_eq!(set_info_class::FILE_DISPOSITION_INFORMATION, 13);
    assert_eq!(set_info_class::FILE_DISPOSITION_INFORMATION_EX, 64);
    assert_eq!(set_info_class::FILE_RENAME_INFORMATION_EX, 65);
}
