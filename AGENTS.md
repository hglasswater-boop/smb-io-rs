# smb-io-rs Engineering Instructions

This repository implements a purpose-built Pure Rust SMB2/SMB3 client engine.

## Product concept

Do not build an SMBJ API clone. Do not wrap Samba, libsmbclient, libsmb2, or another SMB client in the core data path.

Build a protocol-correct, reusable SMB2/SMB3 client whose data path is deliberately optimized for large files, media streaming, low-latency random seeking, metadata/thumbnail probes, copy/export, and positional editing.

The native file I/O model is positional:

- `read_at(offset, len)`
- `write_at(offset, data)`
- `len`
- `set_len`
- `flush`
- `stat`
- `list`
- `rename`
- `delete`
- `mkdir`

`seek + read` may exist as an adapter, but must not be the internal primitive.

## Non-negotiable rules

1. Pure Rust protocol core. Android/JNI is an adapter only.
2. Implement against Microsoft's `[MS-SMB2]` specification. Other clients are interoperability references, not the source of truth.
3. Never support or silently fall back to SMB1.
4. Security is protocol core. Signing, SMB 3.1.1 preauthentication integrity, key derivation, and signature verification are designed from the beginning.
5. Never silently weaken security. Unsupported required security features produce explicit errors.
6. Never implement cryptographic primitives from scratch. Use established Rust cryptography crates.
7. Own SMB Credits, MessageIds, outstanding request correlation, negotiated limits, and request scheduling explicitly.
8. Pipeline large reads/writes. Do not serialize every chunk behind one request/response RTT.
9. Foreground/interactive I/O outranks speculative prefetch and background work.
10. A seek creates a new stream generation. Drop obsolete queued prefetch and cancel eligible old in-flight work with SMB2 CANCEL.
11. Use adaptive chunking/read-ahead based on negotiated limits, credits, RTT, throughput, access pattern, and bounded memory. Do not freeze application-level cache constants into protocol design.
12. Share transport/session/tree resources. Do not create one TCP connection or authenticated session per file handle.
13. Do not blindly replay mutations after ambiguous transport failures. Reads/queries and mutations have different retry classes.
14. Keep core crates portable. No Android/JNI types in protocol/client/filesystem/stream crates.
15. Keep FFI thin. Applications see stable handles, file operations, metrics, and typed errors, not SMB wire structs.
16. Core crates should use `#![forbid(unsafe_code)]`. Isolate unavoidable FFI `unsafe` inside the platform bridge with documented invariants.
17. Untrusted network bytes must never panic. All parser offsets/counts are bounds-checked and fuzzable.
18. Avoid double caching. When smb-stream owns read-ahead/cache, consumers should not stack equivalent caches above it.
19. Measure before claiming faster. Performance changes need reproducible benchmarks against a baseline on the same server/network/file.
20. Do not distort the architecture for one consumer. XFiles is the first production consumer, not the protocol boundary.

## Initial protocol scope

Dialects:

- SMB 2.0.2
- SMB 2.1
- SMB 3.0
- SMB 3.0.2
- SMB 3.1.1

Initial transport: direct TCP, normally port 445.

Initial authentication: SPNEGO + NTLMv2, plus anonymous sessions where explicitly permitted. Kerberos is a later extension.

Required command path before production replacement of an existing SMB client:

- NEGOTIATE
- SESSION_SETUP
- TREE_CONNECT / TREE_DISCONNECT
- CREATE
- READ
- WRITE
- FLUSH
- QUERY_INFO
- QUERY_DIRECTORY
- SET_INFO
- CANCEL
- CLOSE
- LOGOFF

Later features such as SMB3 encryption, durable handles, leases/oplocks, Kerberos, multichannel, QUIC, DFS, compression, and RDMA must have clean extension points but should not block the first protocol milestones unless a target environment requires them.

## Responsibility boundaries

- `smb-wire`: packet types, framing, endian-safe encode/decode, validation, NTSTATUS representation.
- `smb-auth`: SPNEGO/NTLMv2 integration and secret/session-key handling.
- `smb-client`: transport, negotiate/session/tree/open state, MessageIds, credits, request dispatch, signing/security transforms, reconnect.
- `smb-fs`: filesystem semantics and CREATE/QUERY/SET_INFO mapping.
- `smb-stream`: `read_at`/`write_at`, request splitting/reassembly, priority scheduling, adaptive read-ahead/cache, cancellation generations, metrics.
- `smb-android`: opaque handles/DTOs/error mapping and runtime ownership only.
- `smb-testkit`: fixtures, mock transport, interop harnesses, fuzz/property helpers.

The physical crate layout may evolve, but these responsibility boundaries must remain clear.

## Acceptance priorities

Correctness and security first, then performance. For media workloads, playback start latency, sustained sequential throughput, random-seek latency, CPU, memory, connection count, and reconnect behavior are first-class acceptance metrics.

See `docs/ARCHITECTURE.md` for the design baseline and `docs/ROADMAP.md` for implementation phases.
