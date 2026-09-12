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

pub fn decode_file_id_full_directory_information(
    buffer: &[u8],
) -> Result<Vec<DirectoryNameEntry>, FsQueryError> {
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
        entries.push(DirectoryNameEntry { file_index, name });

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
    if pattern.is_empty() {
        return Err(FsQueryError::InvalidData(
            "directory search pattern must not be empty on the first query",
        ));
    }

    let mut entries = Vec::new();
    let mut first = true;
    loop {
        let options = QueryDirectoryOptions::new(
            FILE_ID_FULL_DIRECTORY_INFORMATION_CLASS,
            if first { pattern } else { "" },
            DEFAULT_QUERY_BUFFER_SIZE,
        );
        let buffer = session.query_directory(directory, options).await?;
        if buffer.is_empty() {
            break;
        }
        entries.extend(decode_file_id_full_directory_information(&buffer)?);
        first = false;
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
}
