# Android filesystem mutation bridge (incremental)

Status: **in progress** — XFiles #239 / smb-io-rs #33. This document describes the narrow first migration slice, not SMBJ replacement.

## Baseline

The existing Android bridge API v2 is read-oriented (`nativeOpenVideo`, `nativeReadAt`, `nativeLen`, `nativeSeek`, `nativePrefetch`, `nativeClose`). The Rust core already provides `smb_io_fs::mkdir`, `rename`, `delete_file`, and `delete_directory` after Phase 9.

The first new JNI operation is `nativeMkdir`: create exactly one new directory within a configured SMB share. It does **not** recursively create missing ancestors and must not silently overwrite an existing entry. The JNI API version advances to **3** for the additional entry point. XFiles must update its expected version and one shared engine pin in the same app integration PR.

## Boundary and safety

- Kotlin passes host, port, share, **share-relative path including any configured basePath**, username, password, domain and workstation. A blank username means an anonymous session and the password is ignored.
- The native boundary validates host, port, share and path **before opening a network connection**. Absolute paths, dot/parent components and NUL are rejected. The portable `smb-fs` layer performs its own path validation.
- JNI converts values and throws `java.io.IOException` on SMB/server failures; programming errors in JNI argument range become `java.lang.IllegalArgumentException`.
- `smb-android` executes SMB NEGOTIATE → SESSION_SETUP (SPNEGO/NTLMv2 or anonymous) → TREE_CONNECT → `smb-fs::mkdir` using the shared long-lived Tokio runtime. Signing and preauth remain the responsibility of `smb-client`.
- No transport retry or automatic mutation replay occurs. After an ambiguous connection failure, the caller must not assume mkdir succeeded or failed. **Never fall back to SMBJ after a Rust mutation attempt fails.**
- No secrets are logged or included in Debug output. Credential ownership moves to an `NtlmCredentials` value that zeroizes password memory on drop.
- The initial bridge creates a fresh authenticated connection for one mutation. Connection/session pooling is a later migration gate, **not** the target end-state; the final design remains shared connections as in `docs/ARCHITECTURE.md`.

## XFiles rollout gate

- Only the explicit `rust` diagnostic backend may call the new mkdir bridge initially. Normal `auto` and explicit `smbj` retain SMBJ mkdir.
- Existing WireGuard connection preparation/reachability must be addressed before enabling production auto mode; do not retry mkdir as a network-probing mechanism.
- Recursive directory deletion, create/write/flush, rename and cross-share transfers remain separate migration tasks.
- Test requirements: validation rejects invalid input before any network call; JNI symbol/version test; Rust CI; Android JNI (3 ABIs); XFiles Android Debug CI and Rust SMB Preview; physical NAS and VPN integration before auto rollout.

## Non-goals

This first slice does not switch list/stat/openIn/openOut/delete/rename or writable random-access to Rust and does not remove SMBJ. The umbrella Issue #239 and #33 remain open until their independently verified exit gates.

## Next slice: Android JNI v4 rename and delete_file (Issue #35)

The next Android API exposes the already-tested Phase 9 primitives, without changing production XFiles routing in this Rust PR.

- `nativeRename(host, port, share, source, destination, username, password, domain, workstation)`: move/rename **within the same connected share**, with `replace_if_exists=false`. Both paths are share-relative and include any configured basePath. A collision is an error. The same Rust primitive supports an ordinary file or a directory; cross-share moves are not atomic renames.
- `nativeDeleteFile(host, port, share, path, username, password, domain, workstation)`: delete **one regular file only**. No recursive directory delete. This API does not yet perform XFiles' SMBJ read-only-attribute recovery for `STATUS_CANNOT_DELETE`; XFiles must preserve that behavior until separately implemented/tested.
- Both operations negotiate a fresh session with the existing signing/preauth policy and perform **one mutation at most**. A transient timeout or ambiguous server response is propagated, never retried through Rust or SMBJ.
- Validate source and destination before TCP. Require non-empty paths without leading slash, dot/parent components, or NUL. Reject empty/invalid host, share and port. Unicode names are retained; never normalize to a different file name.
- JNI v4 preserves existing v3 functions and adds only new `nativeRename` and `nativeDeleteFile`. XFiles must promote its expected API version and pinned Rust SHA **together** before calling them.
- Reuse a shared Rust connection/session helper for `mkdir`, `rename`, `delete_file`; avoid an additional copy of authentication and tree connection logic. Credentials are moved into the NTLM provider and must not be logged.
- Rust CI / Android JNI 3 ABI symbol checks / Samba Phase 9 regression tests gate the Rust PR. Kotlin routing, WireGuard route preparation, collision/error parity, existing read-only delete recovery and real NAS evidence gate XFiles #246. Unready operations remain SMBJ.
- Do not expose `delete_directory` as a replacement for `XFileSystem.delete`: Rust Phase 9 deletes **only empty directories**, while XFiles currently deletes directories recursively.

XFiles #239, #246 and smb-io-rs #35 remain Open after PR merging until verification is complete.

## Read-only directory metadata JNI v5 (Issue #39)

The new `nativeListDirectory` reads directory entries via signed `QUERY_DIRECTORY(FileIdFullDirectoryInformation)`, preserving Phase 6 pagination and the full decoder merged in PR #38. One operation establishes a signed/authenticated session, TREE_CONNECT, opens the target directory, enumerates it and closes the handle; no filesystem mutation is performed.

- Inputs: host, port, share, **share-relative directory path** (an empty path is allowed for the share root), username, password, domain and workstation. Host/share/port and path are validated **before TCP**; absolute, NUL and dot/parent path components are disallowed. Anonymous sessions ignore supplied credentials, and the Kotlin caller sends an empty password.
- Result: a Java `byte[]` using the bounded binary **XFL1** format. Every number is little-endian. The first 4 bytes are ASCII `XFL1`, followed by a u32 entry count. For each entry: u32 UTF-8 name length, exact name bytes (no escaping or delimiter), u32 raw SMB file-attribute mask, u64 nonnegative file length (`EndOfFile`), u64 creation FILETIME, u64 last-write FILETIME. No values are silently fabricated. The name is exactly the decoded SMB name, including Unicode.
- The entire encoded result is capped at **16 MiB**; exceeding it fails with IOException instead of returning an incomplete list. All checked lengths/counts must fit the buffer and the JVM array limit. The Kotlin decoder must reject truncated, trailing, invalid version, or nonsensical data and convert raw Windows FILETIME (100ns since 1601 UTC) to milliseconds with checked arithmetic.
- The Rust JNI generation advances from **4** to **5** in the same XFiles pin/expected-version update. JNI generation 5 preserves v4 video, mkdir, rename and deleteFile methods.
- Rust CI, Phase 6 signed Samba, and Android JNI all three ABI exported symbol checks must pass. XFiles #244 separately gates `SmbFileSystem.list` routing, basePath, dot-directory filtering, hidden/reparse attribute mapping, Unicode/timestamps/size, VPN preparation, Mobile/TV CI and NAS parity.
- In `auto`, read-only list may use SMBJ **only if JNI is missing/incompatible before the call**, to prevent hiding real Rust failures. Explicit `rust` is strict. Explicit `smbj` never loads Rust. `stat` continues to call `list(parent)`, retaining its semantics without a separate native method.
- This is not complete filesystem parity. `storageSpace`, `directorySize`, file creation, write, recursive delete and transfers remain separate tasks. Keep #39 / XFiles #244 / umbrella #239 Open through real-device verification.
