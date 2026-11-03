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

## Non-overwriting file creation JNI v6 (Issue #41)

This small slice implements the XFiles `SmbFileSystem.createFile` contract only. It must not change `openOut` (OVERWRITE_IF), positional writes, flush, truncate, file deletion, or recursive operations.

- `smb_io_fs::create_file` performs exactly one SMB2 CREATE with disposition `FILE_CREATE` (fail if any file/directory already exists), `NON_DIRECTORY_FILE`, then CLOSE. It creates a zero-length regular file. A server name collision is returned as `FsMutationError::AlreadyExists`, **never overwrites or truncates existing content**.
- `FileOpenOptions::create_new_random()` centralizes `create_disposition::CREATE` using the existing writable non-directory flags and signed CREATE behavior. It must not accidentally select `OVERWRITE_IF` or `OPEN_IF`.
- `nativeCreateFile(host, port, share, path, username, password, domain, workstation)` is a one-shot JNI method. JNI API generation advances **5→6** while preserving existing JNI functions. Validate share-relative nonempty paths and credentials before network; XFiles sends the saved `basePath` and prepares Wi-Fi/WireGuard before invoking Rust.
- Never retry CREATE after an ambiguous disconnect, and never switch to SMBJ after native CREATE has started. `auto` may choose SMBJ only if native JNI is missing/incompatible at the pre-call check. `rust` is strict, `smbj` never loads JNI.
- XFiles #245 will add the matching Kotlin adapter and tests, update engine pin/API together, and retain existing SMBJ stat fallback behavior after a successful creation. Real NAS and WireGuard verification remain required.
- Prove CREATE collision with mandatory-signing Samba: create a new empty Unicode file, attempt the same CREATE again, check `AlreadyExists` and zero size, plus negative/absolute/dot path tests. Rust CI/Android JNI (3 ABIs)/Samba/Phase 9 gates precede Rust main merge.
- `openOut`, `write_at`, `setLength`, `flush`, copying, and `SmbRandomAccessOutputFile` remain separate substeps under XFiles #245. **Do not claim complete write migration.** Preserve Rust #41 and XFiles #245/#239 Open through device parity checks.

## Writable stream foundation: SMB2 FLUSH before Android openOut migration (Issue #43)

The XFiles `openOut` contract opens a regular file with **OVERWRITE_IF** (existing content is truncated), streams all bytes, then closes. This is distinct from `createFile`'s non-overwriting **FILE_CREATE**. The Rust Phase 8 `SessionConnection::write_at` already implements signed, credit-limited writes, but there is no FLUSH implementation in the Rust protocol client yet. A direct Android migration **must not** treat CLOSE or successful WRITE responses as a substitute for the app's explicit flush contract.

- Implement SMB2 `FLUSH` command 0x0007 with request StructureSize 24, reserved bytes zero, valid nonzero persistent/volatile FileId; response StructureSize 4, reserved zero. The full SMB2 64-byte signed request header includes MessageId/SessionId/TreeId and credit charging. Reject malformed/oversized/truncated packets and response IDs, status, or missing signatures under mandatory signing. Validate response before returning success.
- Add `SessionConnection::flush_file(&FileHandle)` for an **already-open** handle. Send exactly one SMB2 FLUSH, preserve NTSTATUS on failure; never replay after an ambiguous transport error. FLUSH does not automatically close or truncate the file.
- Add wire unit tests for request round-trip, reserved-field validation, malformed response and response StructureSize. Client tests exercise the request/response boundary and actual signing-mandatory Samba integration must prove a write can be flushed before close and read back.
- Do not change the JNI API or XFiles runtime in this foundation PR. A subsequent Issue #43 slice can add a writable handle (open/write/flush/close) reusing signed authenticated `connect_share`; it must manage resources with `finally`, bound JNI chunks, and compare throughput to SMBJ's 8 MiB pipeline before production `auto` switching.
- Keep Rust #43, XFiles #245, and umbrella #239 **Open**. A successful protocol FLUSH implementation is not end-to-end writable Android migration.

## Persistent Android writable stream JNI v7 (Issue #43; follows FLUSH PR #44)

Rust FLUSH is merged at `e87f8c6` and was exercised with the 8 MiB signing-mandatory Samba WRITE/FLUSH/READBACK test. The next slice exposes **only a writable stream handle** over JNI. The Android `XFileSystem.openOut` production `auto` backend stays on SMBJ until output semantics, performance and devices match.

- `nativeOpenWritable(host,port,share,path,username,password,domain,workstation): Long` uses the same authenticated signed `connect_share` helper. Validate share-relative non-empty file path before TCP. Open a **non-directory** file with `OVERWRITE_IF` (existing file truncates to zero; absent file is created) and `GENERIC_WRITE` access, not `FILE_CREATE`. If open/overwrite begins, never retry via SMBJ on failure.
- `nativeWriteAt(handle,position,source: ByteArray,sourceOffset,length): Int` performs a positional, signed `write_at` on the persistent server FileId and the same session. Validate positive typed handle, position (nonnegative), source offset/length within Java array, and **at most 1 MiB per JNI call** before copying. Zero-length writes return zero without SMB mutation. A short server response is processed by the Rust core until all supplied bytes are written or an error occurs. Any write failure poisons this writable handle; subsequent writes/flush must reject, not guess the remote commit position or replay bytes. An invalid Java argument must not poison the handle.
- `nativeFlushWritable(handle): Unit` sends signed SMB2 FLUSH exactly once, returns errors; never substitutes CLOSE for a failed flush. Failed FLUSH poisons the handle. `nativeCloseWritable(handle): Unit` removes and closes the server FileId, even after a prior WRITE/FLUSH failure; a second close or write on an invalid handle fails instead of silently recreating the stream.
- Writable JNI handles have a distinct type/disjoint ID range from video and directory cursors. Per-handle `Mutex` serializes writes/flush/close; native byte arrays are copied with a fixed 1 MiB maximum and owned by the call. Cross-thread use must not race or mix file positions.
- JNI API generation **v7** preserves all existing v6 video/list/mkdir/rename/createFile entrypoints. All 3 ABI symbol checks must include the four new functions. Rust tests cover handle type/invalid paths, correct write-only `OVERWRITE_IF` options, negative offsets/oversized chunks and poison-on-error. Signing-mandatory Samba integration writes multiple 1 MiB chunks, explicitly FLUSHes and CLOSEs, and reads the whole result back.
- XFiles #245 integrates the new JNI version/pin and initially tests explicit `rust` output streams. **No production auto switch** until Mobile/TV, unit/lint/emulator, real NAS/WireGuard, errors and measured throughput vs the existing SMBJ eight-in-flight async writer pass. Random access `SmbRandomAccessOutputFile.setLength/read`, recursive deletion, cross-share copies remain separate.
- Never mark Issue #43, XFiles #245, or umbrella #239 complete based only on JNI/CI or PR merge.
