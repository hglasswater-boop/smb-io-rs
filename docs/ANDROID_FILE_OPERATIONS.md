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

## Read-only paginated directory metadata JNI v5 (Issue #39)

The native API is **cursor-based**, not a one-shot all-files byte array. An individual directory may contain any number of entries. The 16 MiB safety ceiling is **per response page**, never a cap on a folder. Full collection is supported until the SMB server returns end-of-directory. Rust must preserve the same authenticated TREE_CONNECT, open directory file handle and SMB QUERY_DIRECTORY scan cursor across pages.

- `nativeOpenDirectory(host,port,share,path,username,password,domain,workstation): Long` opens a directory session. The share root uses an empty directory path; all other paths are share-relative, including saved XFiles basePath. Validation rejects absolute, NUL, dot and parent paths before TCP. Credentials are not logged.
- `nativeReadDirectoryPage(handle: Long): ByteArray` issues **one** signed `QUERY_DIRECTORY(FileIdFullDirectoryInformation)` on the same open file handle and returns all entries contained in that SMB response, rather than enumerating the whole directory first. An empty page (XFL1 count=0) means end-of-directory; repeated reads after EOF keep returning the empty page.
- `nativeCloseDirectory(handle: Long)` closes the file handle and removes it from the table even after a query failure. Kotlin must always call it in `finally` after a successful open; open failure has nothing to close. Concurrent reads on one handle serialize.
- Each returned **page** uses the versioned binary `XFL1` wire-to-JNI format: ASCII `XFL1`, u32 little-endian count; per entry u32 UTF-8 name length + exact bytes, u32 file attribute mask, u64 nonnegative file length, u64 creation FILETIME and u64 last-write FILETIME (100ns since 1601 UTC). Names may include Unicode, spaces and delimiters. The decoder must detect malformed length, unknown version, trailing bytes and invalid time conversion, never invent values.
- The per-page response is capped at 16 MiB (well above the SMB per-query `65535`-byte raw response), with checked lengths/counts. Exceeding the **per-page** cap reports an error, not a silently incomplete page. A large directory simply needs more pages, so **no folder-wide size/entry limit** is imposed by JNI. XFiles may progressively render/collect these pages using bounded buffers. A network error is not EOF and must not be swallowed; a partly loaded directory must not be presented as a fully successful result.
- JNI generation **v5** preserves the v4 video/mutation entries. All three new JNI symbols must be verified on three Android ABIs. XFiles updates its pinned Rust engine SHA and expected version atomically, with tests for pagination, EOF, and native handle cleanup.
- Rust CI + signed Samba/Phase 6/query continuation and Android JNI CI gate this Rust PR. XFiles #244 separately tracks `list` mapping, `stat` via parent listing, timestamps, reparse/hidden/dir handling, WireGuard and NAS parity.
- `auto` can use SMBJ only when native incompatibility is detected **before** opening Rust; actual Rust network/query failures are errors, not silent fallbacks. `smbj` never invokes JNI. Keep #39 / #244 / parent #239 Open pending verification.
