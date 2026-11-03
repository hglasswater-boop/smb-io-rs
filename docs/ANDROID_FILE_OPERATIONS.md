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
