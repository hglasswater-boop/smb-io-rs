# SMB2 directory metadata contract (Issue #37)

## Why

Rust Phase 6 can enumerate directory names via `FileIdFullDirectoryInformation`, but XFiles `SmbFileSystem.list/stat` needs more than names: directory flag, file size, timestamps, hidden/reparse attributes. The existing `DirectoryNameEntry` interface must remain compatible while a typed metadata API is introduced.

## Wire layout and types

For each `FileIdFullDirectoryInformation` entry, all offsets are measured from the entry start (little-endian):

| Offset | Width | Field | Exposed meaning |
| --- | --- | --- | --- |
| 0 | 4 | NextEntryOffset | Relative byte stride to next entry; zero is final |
| 4 | 4 | FileIndex | Server-provided index, not a durable identifier |
| 8 | 8 | CreationTime | Raw unsigned Windows FILETIME, 100ns since 1601-01-01 UTC |
| 16 | 8 | LastAccessTime | Not initially needed by XFiles; retained on wire |
| 24 | 8 | LastWriteTime | Raw unsigned Windows FILETIME |
| 32 | 8 | ChangeTime | Not initially needed by XFiles; retained on wire |
| 40 | 8 | EndOfFile | Signed 64-bit length; reject negative values |
| 48 | 8 | AllocationSize | Signed 64-bit allocation; reject negative values |
| 56 | 4 | FileAttributes | Raw bitmask (directory 0x10, hidden 0x02, reparse 0x400) |
| 60 | 4 | FileNameLength | Byte count, must be even and within response bounds |
| 64 | 4 | EaSize | Not surfaced initially |
| 68 | 4 | Reserved | Do not interpret |
| 72 | 8 | FileId | May not remain stable across server sessions |
| 80 | variable | FileName | UTF-16LE |

The decoder returns a typed `DirectoryMetadataEntry` with `name`, `file_index`, `end_of_file`, `allocation_size`, `creation_time`, `last_write_time`, and `file_attributes`. The unchanged `DirectoryNameEntry` API continues to work.

## Safety/compatibility gates

- Validate fixed header length, UTF-16 byte alignment/decoding, addition overflows, data bounds, non-overlapping/aligned `NextEntryOffset`, negative size/allocation. Reject malformed entries as a structured error; do not fabricate metadata.
- Skip `.` and `..` in XFiles mapping, not in the portable parser (which reports server entries exactly).
- Keep timestamps as raw FILETIME in Rust; Android converts only after validating the conversion range. Do not use current time or zero as an invented last-write value.
- Never follow reparse-point directories when recursively computing directory size.
- Preserve page continuation behavior, mandatory signing and query errors from Phase 6.
- This core parser alone is not the XFiles migration: Android JNI DTO, `list/stat` routing, unit/instrumentation tests and NAS parity remain tracked under XFiles #244 and #239. Both Issues remain Open until verified.
