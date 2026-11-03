use std::error::Error;
use std::fmt;

use smb_io_client::{
    ClientError, FileHandle, QueryDirectoryOptions, QueryInfoOptions, SessionConnection, Transport,
};

const FILE_STANDARD_INFORMATION_CLASS: u8 = 0x05;
const FILE_ID_FULL_DIRECTORY_INFORMATION_CLASS: u8 = 0x26;
const STANDARD_INFORMATION_SIZE: usize = 24;
const FILE_NAMES_INFORMATION_FIXED_SIZE: usize = 12;
const FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE: usize = 80;
const FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET: usize = 60;
const DEFAULT_QUERY_BUFFER_SIZE: u32 = 65_535;

#[derive(Debug)]
pub enum FsQueryError {
    Client(ClientError),
    InvalidData(&'static str),
    InvalidUtf16,
}

impl fmt::Display for FsQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "SMB query failed: {error}"),
            Self::InvalidData(field) => write!(f, "invalid SMB filesystem query data: {field}"),
            Self::InvalidUtf16 => write!(f, "invalid UTF-16 file name in SMB directory response"),
        }
    }
}

impl Error for FsQueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::InvalidData(_) | Self::InvalidUtf16 => None,
        }
    }
}

impl From<ClientError> for FsQueryError {
    fn from(value: ClientError) -> Self {
        Self::Client(value)
    }
}

/// FileFsFullSizeInformation (SMB2 QUERY_INFO, InfoType=FILESYSTEM, class 7).
/// CallerAvailableAllocationUnits respects quotas; ActualAvailableAllocationUnits does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileFsFullSizeInformation {
    total_units: u64,
    caller_available_units: u64,
    sectors_per_unit: u32,
    bytes_per_sector: u32,
}

impl FileFsFullSizeInformation {
    pub fn decode(buffer: &[u8]) -> Result<Self, FsQueryError> {
        if buffer.len() != 32 {
            return Err(FsQueryError::InvalidData(
                "FileFsFullSizeInformation must be 32 bytes",
            ));
        }
        let total = i64::from_le_bytes(buffer[0..8].try_into().expect("fixed slice"));
        let caller = i64::from_le_bytes(buffer[8..16].try_into().expect("fixed slice"));
        let actual = i64::from_le_bytes(buffer[16..24].try_into().expect("fixed slice"));
        let sectors = u32::from_le_bytes(buffer[24..28].try_into().expect("fixed slice"));
        let bytes = u32::from_le_bytes(buffer[28..32].try_into().expect("fixed slice"));
        if total < 0 || caller < 0 || actual < 0 || sectors == 0 || bytes == 0 {
            return Err(FsQueryError::InvalidData(
                "invalid FileFsFullSizeInformation units",
            ));
        }
        Ok(Self {
            total_units: total as u64,
            caller_available_units: caller as u64,
            sectors_per_unit: sectors,
            bytes_per_sector: bytes,
        })
    }

    /// Java longs cannot represent capacities > i64::MAX; saturate instead of wrapping.
    pub fn capacity_bytes(self) -> (i64, i64) {
        let bytes_per_unit = u128::from(self.sectors_per_unit) * u128::from(self.bytes_per_sector);
        let to_java =
            |units: u64| (u128::from(units) * bytes_per_unit).min(i64::MAX as u128) as i64;
        (
            to_java(self.total_units),
            to_java(self.caller_available_units),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileStandardInformation {
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub number_of_links: u32,
    pub delete_pending: bool,
    pub directory: bool,
}

impl FileStandardInformation {
    pub fn decode(buffer: &[u8]) -> Result<Self, FsQueryError> {
        if buffer.len() < STANDARD_INFORMATION_SIZE {
            return Err(FsQueryError::InvalidData(
                "FileStandardInformation is shorter than 24 bytes",
            ));
        }

        let allocation_size = i64::from_le_bytes(buffer[0..8].try_into().expect("fixed range"));
        let end_of_file = i64::from_le_bytes(buffer[8..16].try_into().expect("fixed range"));
        if allocation_size < 0 {
            return Err(FsQueryError::InvalidData(
                "FileStandardInformation AllocationSize is negative",
            ));
        }
        if end_of_file < 0 {
            return Err(FsQueryError::InvalidData(
                "FileStandardInformation EndOfFile is negative",
            ));
        }

        Ok(Self {
            allocation_size: allocation_size as u64,
            end_of_file: end_of_file as u64,
            number_of_links: u32::from_le_bytes(buffer[16..20].try_into().expect("fixed range")),
            delete_pending: buffer[20] != 0,
            directory: buffer[21] != 0,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryNameEntry {
    pub file_index: u32,
    pub name: String,
}

/// Full FileIdFullDirectoryInformation metadata. Timestamps are raw Windows FILETIME.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryMetadataEntry {
    pub file_index: u32,
    pub name: String,
    pub creation_time: u64,
    pub last_write_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
}

pub fn decode_file_names_information(
    buffer: &[u8],
) -> Result<Vec<DirectoryNameEntry>, FsQueryError> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < buffer.len() {
        let remaining = &buffer[offset..];
        if remaining.len() < FILE_NAMES_INFORMATION_FIXED_SIZE {
            return Err(FsQueryError::InvalidData(
                "FileNamesInformation entry is shorter than 12 bytes",
            ));
        }

        let next_entry_offset =
            u32::from_le_bytes(remaining[0..4].try_into().expect("fixed range")) as usize;
        let file_index = u32::from_le_bytes(remaining[4..8].try_into().expect("fixed range"));
        let file_name_length =
            u32::from_le_bytes(remaining[8..12].try_into().expect("fixed range")) as usize;
        if file_name_length % 2 != 0 {
            return Err(FsQueryError::InvalidData(
                "FileNamesInformation FileNameLength is not UTF-16 aligned",
            ));
        }

        let name_end = FILE_NAMES_INFORMATION_FIXED_SIZE
            .checked_add(file_name_length)
            .ok_or(FsQueryError::InvalidData(
                "FileNamesInformation FileNameLength overflow",
            ))?;
        if name_end > remaining.len() {
            return Err(FsQueryError::InvalidData(
                "FileNamesInformation file name exceeds response buffer",
            ));
        }

        let mut units = Vec::with_capacity(file_name_length / 2);
        for pair in remaining[FILE_NAMES_INFORMATION_FIXED_SIZE..name_end].chunks_exact(2) {
            units.push(u16::from_le_bytes([pair[0], pair[1]]));
        }
        let name = String::from_utf16(&units).map_err(|_| FsQueryError::InvalidUtf16)?;
        entries.push(DirectoryNameEntry { file_index, name });

        if next_entry_offset == 0 {
            break;
        }
        if next_entry_offset < name_end
            || next_entry_offset > remaining.len()
            || next_entry_offset % 8 != 0
        {
            return Err(FsQueryError::InvalidData(
                "FileNamesInformation NextEntryOffset is invalid",
            ));
        }
        offset = offset
            .checked_add(next_entry_offset)
            .ok_or(FsQueryError::InvalidData(
                "FileNamesInformation NextEntryOffset overflow",
            ))?;
    }

    Ok(entries)
}

/// Existing name-only interface, retained for Rust clients using Phase 6.
pub fn decode_file_id_full_directory_information(
    buffer: &[u8],
) -> Result<Vec<DirectoryNameEntry>, FsQueryError> {
    Ok(decode_file_id_full_directory_metadata(buffer)?
        .into_iter()
        .map(|entry| DirectoryNameEntry {
            file_index: entry.file_index,
            name: entry.name,
        })
        .collect())
}

pub fn decode_file_id_full_directory_metadata(
    buffer: &[u8],
) -> Result<Vec<DirectoryMetadataEntry>, FsQueryError> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < buffer.len() {
        let remaining = &buffer[offset..];
        if remaining.len() < FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE {
            return Err(FsQueryError::InvalidData(
                "FileIdFullDirectoryInformation entry is shorter than 80 bytes",
            ));
        }

        let next_entry_offset =
            u32::from_le_bytes(remaining[0..4].try_into().expect("fixed range")) as usize;
        let file_index = u32::from_le_bytes(remaining[4..8].try_into().expect("fixed range"));
        let creation_time = u64::from_le_bytes(remaining[8..16].try_into().expect("fixed range"));
        let last_write_time =
            u64::from_le_bytes(remaining[24..32].try_into().expect("fixed range"));
        let end_of_file = i64::from_le_bytes(remaining[40..48].try_into().expect("fixed range"));
        let allocation_size =
            i64::from_le_bytes(remaining[48..56].try_into().expect("fixed range"));
        if end_of_file < 0 || allocation_size < 0 {
            return Err(FsQueryError::InvalidData(
                "FileIdFullDirectoryInformation has negative file size or allocation",
            ));
        }
        let file_attributes =
            u32::from_le_bytes(remaining[56..60].try_into().expect("fixed range"));
        let file_name_length = u32::from_le_bytes(
            remaining[FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET
                ..FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET + 4]
                .try_into()
                .expect("fixed range"),
        ) as usize;
        if file_name_length % 2 != 0 {
            return Err(FsQueryError::InvalidData(
                "FileIdFullDirectoryInformation FileNameLength is not UTF-16 aligned",
            ));
        }

        let name_end = FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE
            .checked_add(file_name_length)
            .ok_or(FsQueryError::InvalidData(
                "FileIdFullDirectoryInformation FileNameLength overflow",
            ))?;
        if name_end > remaining.len() {
            return Err(FsQueryError::InvalidData(
                "FileIdFullDirectoryInformation file name exceeds response buffer",
            ));
        }

        let mut units = Vec::with_capacity(file_name_length / 2);
        for pair in
            remaining[FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE..name_end].chunks_exact(2)
        {
            units.push(u16::from_le_bytes([pair[0], pair[1]]));
        }
        let name = String::from_utf16(&units).map_err(|_| FsQueryError::InvalidUtf16)?;
        entries.push(DirectoryMetadataEntry {
            file_index,
            name,
            creation_time,
            last_write_time,
            end_of_file: end_of_file as u64,
            allocation_size: allocation_size as u64,
            file_attributes,
        });

        if next_entry_offset == 0 {
            break;
        }
        if next_entry_offset < name_end
            || next_entry_offset > remaining.len()
            || next_entry_offset % 8 != 0
        {
            return Err(FsQueryError::InvalidData(
                "FileIdFullDirectoryInformation NextEntryOffset is invalid",
            ));
        }
        offset = offset
            .checked_add(next_entry_offset)
            .ok_or(FsQueryError::InvalidData(
                "FileIdFullDirectoryInformation NextEntryOffset overflow",
            ))?;
    }

    Ok(entries)
}

pub async fn query_standard_information<T>(
    session: &mut SessionConnection<T>,
    file: &FileHandle,
) -> Result<FileStandardInformation, FsQueryError>
where
    T: Transport,
{
    let buffer = session
        .query_info(
            file,
            QueryInfoOptions::file(
                FILE_STANDARD_INFORMATION_CLASS,
                STANDARD_INFORMATION_SIZE as u32,
            ),
        )
        .await?;
    FileStandardInformation::decode(&buffer)
}

pub async fn read_directory_names<T>(
    session: &mut SessionConnection<T>,
    directory: &FileHandle,
) -> Result<Vec<DirectoryNameEntry>, FsQueryError>
where
    T: Transport,
{
    read_directory_names_matching(session, directory, "*").await
}

pub async fn read_directory_names_matching<T>(
    session: &mut SessionConnection<T>,
    directory: &FileHandle,
    pattern: &str,
) -> Result<Vec<DirectoryNameEntry>, FsQueryError>
where
    T: Transport,
{
    Ok(
        read_directory_metadata_matching(session, directory, pattern)
            .await?
            .into_iter()
            .map(|entry| DirectoryNameEntry {
                file_index: entry.file_index,
                name: entry.name,
            })
            .collect(),
    )
}

/// Paged, signed QUERY_DIRECTORY with size, timestamps, and attribute bits.
pub async fn read_directory_metadata<T>(
    session: &mut SessionConnection<T>,
    directory: &FileHandle,
) -> Result<Vec<DirectoryMetadataEntry>, FsQueryError>
where
    T: Transport,
{
    read_directory_metadata_matching(session, directory, "*").await
}

pub async fn read_directory_metadata_matching<T>(
    session: &mut SessionConnection<T>,
    directory: &FileHandle,
    pattern: &str,
) -> Result<Vec<DirectoryMetadataEntry>, FsQueryError>
where
    T: Transport,
{
    if pattern.is_empty() {
        return Err(FsQueryError::InvalidData(
            "directory search pattern must not be empty",
        ));
    }

    let mut entries = Vec::new();
    loop {
        let options = QueryDirectoryOptions::new(
            FILE_ID_FULL_DIRECTORY_INFORMATION_CLASS,
            pattern,
            DEFAULT_QUERY_BUFFER_SIZE,
        );
        let buffer = session.query_directory(directory, options).await?;
        if buffer.is_empty() {
            break;
        }
        entries.extend(decode_file_id_full_directory_metadata(&buffer)?);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_file_standard_information() {
        let mut buffer = [0u8; STANDARD_INFORMATION_SIZE];
        buffer[0..8].copy_from_slice(&8192i64.to_le_bytes());
        buffer[8..16].copy_from_slice(&1234i64.to_le_bytes());
        buffer[16..20].copy_from_slice(&2u32.to_le_bytes());
        buffer[20] = 1;
        buffer[21] = 0;

        let info = FileStandardInformation::decode(&buffer).unwrap();
        assert_eq!(info.allocation_size, 8192);
        assert_eq!(info.end_of_file, 1234);
        assert_eq!(info.number_of_links, 2);
        assert!(info.delete_pending);
        assert!(!info.directory);
    }

    #[test]
    fn decodes_multiple_file_names_using_next_entry_offsets() {
        let first_name: Vec<u8> = "one.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let second_name: Vec<u8> = "two.mkv"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let first_size = FILE_NAMES_INFORMATION_FIXED_SIZE + first_name.len();
        let first_aligned = (first_size + 7) & !7;
        let second_size = FILE_NAMES_INFORMATION_FIXED_SIZE + second_name.len();
        let mut buffer = vec![0u8; first_aligned + second_size];

        buffer[0..4].copy_from_slice(&(first_aligned as u32).to_le_bytes());
        buffer[4..8].copy_from_slice(&1u32.to_le_bytes());
        buffer[8..12].copy_from_slice(&(first_name.len() as u32).to_le_bytes());
        buffer[12..12 + first_name.len()].copy_from_slice(&first_name);

        let second = first_aligned;
        buffer[second + 4..second + 8].copy_from_slice(&2u32.to_le_bytes());
        buffer[second + 8..second + 12].copy_from_slice(&(second_name.len() as u32).to_le_bytes());
        buffer[second + 12..second + 12 + second_name.len()].copy_from_slice(&second_name);

        let entries = decode_file_names_information(&buffer).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "one.txt");
        assert_eq!(entries[1].name, "two.mkv");
    }

    #[test]
    fn decodes_multiple_file_id_full_names_using_next_entry_offsets() {
        let first_name: Vec<u8> = "one.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let second_name: Vec<u8> = "two.mkv"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let first_size = FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE + first_name.len();
        let first_aligned = (first_size + 7) & !7;
        let second_size = FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE + second_name.len();
        let mut buffer = vec![0u8; first_aligned + second_size];

        buffer[0..4].copy_from_slice(&(first_aligned as u32).to_le_bytes());
        buffer[4..8].copy_from_slice(&11u32.to_le_bytes());
        buffer[FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET
            ..FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET + 4]
            .copy_from_slice(&(first_name.len() as u32).to_le_bytes());
        buffer[FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE
            ..FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE + first_name.len()]
            .copy_from_slice(&first_name);

        let second = first_aligned;
        buffer[second + 4..second + 8].copy_from_slice(&22u32.to_le_bytes());
        buffer[second + FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET
            ..second + FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET + 4]
            .copy_from_slice(&(second_name.len() as u32).to_le_bytes());
        buffer[second + FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE
            ..second + FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE + second_name.len()]
            .copy_from_slice(&second_name);

        let entries = decode_file_id_full_directory_information(&buffer).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].file_index, 11);
        assert_eq!(entries[0].name, "one.txt");
        assert_eq!(entries[1].file_index, 22);
        assert_eq!(entries[1].name, "two.mkv");
    }

    #[test]
    fn rejects_unaligned_next_entry_offset() {
        let mut buffer = vec![0u8; 24];
        buffer[0..4].copy_from_slice(&13u32.to_le_bytes());
        assert!(decode_file_names_information(&buffer).is_err());
    }

    #[test]
    fn rejects_overlapping_file_id_full_next_entry_offset() {
        let name: Vec<u8> = "overlap.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut buffer = vec![0u8; 128];
        buffer[0..4].copy_from_slice(&80u32.to_le_bytes());
        buffer[FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET
            ..FILE_ID_FULL_DIRECTORY_INFORMATION_NAME_LENGTH_OFFSET + 4]
            .copy_from_slice(&(name.len() as u32).to_le_bytes());
        buffer[FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE
            ..FILE_ID_FULL_DIRECTORY_INFORMATION_FIXED_SIZE + name.len()]
            .copy_from_slice(&name);

        assert!(decode_file_id_full_directory_information(&buffer).is_err());
    }
    #[test]
    fn decodes_file_id_full_metadata_with_unicode_and_raw_filetime() {
        let name: Vec<u8> = "日本語.mkv"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let creation = 133_000_000_000_000_000u64;
        let modified = 133_001_000_000_000_000u64;
        let mut data = vec![0u8; 80 + name.len()];
        data[4..8].copy_from_slice(&17u32.to_le_bytes());
        data[8..16].copy_from_slice(&creation.to_le_bytes());
        data[24..32].copy_from_slice(&modified.to_le_bytes());
        data[40..48].copy_from_slice(&1234i64.to_le_bytes());
        data[48..56].copy_from_slice(&4096i64.to_le_bytes());
        data[56..60].copy_from_slice(&0x22u32.to_le_bytes());
        data[60..64].copy_from_slice(&(name.len() as u32).to_le_bytes());
        data[80..].copy_from_slice(&name);

        let entries = decode_file_id_full_directory_metadata(&data).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.name, "日本語.mkv");
        assert_eq!(entry.file_index, 17);
        assert_eq!(entry.end_of_file, 1234);
        assert_eq!(entry.allocation_size, 4096);
        assert_eq!(entry.creation_time, creation);
        assert_eq!(entry.last_write_time, modified);
        assert_eq!(entry.file_attributes, 0x22);
    }

    #[test]
    fn metadata_rejects_negative_file_size_and_allocation() {
        let mut data = [0u8; 80];
        data[40..48].copy_from_slice(&(-1i64).to_le_bytes());
        assert!(decode_file_id_full_directory_metadata(&data).is_err());

        data[40..48].copy_from_slice(&0i64.to_le_bytes());
        data[48..56].copy_from_slice(&(-1i64).to_le_bytes());
        assert!(decode_file_id_full_directory_metadata(&data).is_err());
    }

    #[test]
    fn metadata_rejects_truncated_fixed_header() {
        let data = [0u8; 79];
        assert!(decode_file_id_full_directory_metadata(&data).is_err());
    }

    #[test]
    fn metadata_decodes_multiple_entries_with_aligned_offsets() {
        let first_name: Vec<u8> = "one".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let second_name: Vec<u8> = "二番目".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let first_len = (80 + first_name.len() + 7) & !7;
        let mut data = vec![0u8; first_len + 80 + second_name.len()];
        data[0..4].copy_from_slice(&(first_len as u32).to_le_bytes());
        data[40..48].copy_from_slice(&42i64.to_le_bytes());
        data[60..64].copy_from_slice(&(first_name.len() as u32).to_le_bytes());
        data[80..80 + first_name.len()].copy_from_slice(&first_name);
        data[first_len + 40..first_len + 48].copy_from_slice(&7i64.to_le_bytes());
        data[first_len + 56..first_len + 60].copy_from_slice(&0x10u32.to_le_bytes());
        data[first_len + 60..first_len + 64]
            .copy_from_slice(&(second_name.len() as u32).to_le_bytes());
        data[first_len + 80..].copy_from_slice(&second_name);

        let entries = decode_file_id_full_directory_metadata(&data).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "one");
        assert_eq!(entries[0].end_of_file, 42);
        assert_eq!(entries[1].name, "二番目");
        assert_eq!(entries[1].file_attributes, 0x10);
        assert_eq!(entries[1].end_of_file, 7);
    }
    fn full_size_bytes(total: i64, caller: i64, actual: i64, sectors: u32, bytes: u32) -> [u8; 32] {
        let mut data = [0u8; 32];
        data[0..8].copy_from_slice(&total.to_le_bytes());
        data[8..16].copy_from_slice(&caller.to_le_bytes());
        data[16..24].copy_from_slice(&actual.to_le_bytes());
        data[24..28].copy_from_slice(&sectors.to_le_bytes());
        data[28..32].copy_from_slice(&bytes.to_le_bytes());
        data
    }

    #[test]
    fn full_size_information_uses_caller_available_for_quota_aware_free_space() {
        let info =
            FileFsFullSizeInformation::decode(&full_size_bytes(1000, 20, 300, 8, 512)).unwrap();
        assert_eq!(info.capacity_bytes(), (4_096_000, 81_920));
    }

    #[test]
    fn full_size_information_rejects_invalid_and_truncated_counts() {
        assert!(FileFsFullSizeInformation::decode(&[0u8; 31]).is_err());
        assert!(FileFsFullSizeInformation::decode(&full_size_bytes(-1, 1, 1, 8, 512)).is_err());
        assert!(FileFsFullSizeInformation::decode(&full_size_bytes(1, -1, 1, 8, 512)).is_err());
        assert!(FileFsFullSizeInformation::decode(&full_size_bytes(1, 1, -1, 8, 512)).is_err());
        assert!(FileFsFullSizeInformation::decode(&full_size_bytes(1, 1, 1, 0, 512)).is_err());
        assert!(FileFsFullSizeInformation::decode(&full_size_bytes(1, 1, 1, 8, 0)).is_err());
    }

    #[test]
    fn full_size_information_saturates_java_long_capacity() {
        let info = FileFsFullSizeInformation::decode(&full_size_bytes(
            i64::MAX,
            i64::MAX,
            i64::MAX,
            u32::MAX,
            u32::MAX,
        ))
        .unwrap();
        assert_eq!(info.capacity_bytes(), (i64::MAX, i64::MAX));
    }
}
