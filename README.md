# smb-io-rs

A purpose-built, Pure Rust SMB2/SMB3 client engine focused on fast positional file I/O.

`smb-io-rs` is not an SMBJ clone and is not a thin wrapper over Samba or libsmbclient. Its core goal is to provide a protocol-correct SMB2/3 client with a data path optimized for large files, media streaming, low-latency random seeks, thumbnail/metadata probing, copy/export, and random-access editing.

## Core concept

The native I/O model is positional:

```rust
read_at(offset, len)
write_at(offset, data)
```

Sequential streams are adapters built on top of positional I/O, not the internal primitive.

The engine owns SMB credits, request pipelining, MessageIds, signing, reconnect state, adaptive read-ahead, cancellation, and shared sessions so applications do not have to rebuild those concerns above the protocol layer.

## Initial scope

- SMB 2.0.2 / 2.1 / 3.0 / 3.0.2 / 3.1.1
- Direct TCP transport on port 445
- SPNEGO + NTLMv2 and anonymous sessions where explicitly permitted
- NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, READ, WRITE, FLUSH, QUERY_INFO, QUERY_DIRECTORY, SET_INFO, CANCEL, CLOSE, TREE_DISCONNECT, LOGOFF
- SMB signing and SMB 3.1.1 preauthentication integrity as protocol-core features
- Shared server/session/tree resources instead of one connection per file
- Multiple in-flight READ/WRITE requests subject to negotiated limits and SMB credits
- Adaptive read-ahead/cache for media workloads
- Thin Android/JNI bridge as one consumer, not a core dependency

SMB1 is intentionally unsupported.

## Workspace direction

```text
crates/
  smb-wire/      # packet encoding/decoding and framing
  smb-auth/      # SPNEGO / NTLMv2 integration
  smb-client/    # transport, sessions, credits, dispatch, signing, reconnect
  smb-fs/        # filesystem semantics
  smb-stream/    # positional I/O, pipelining, cache, priority, cancellation
  smb-android/   # thin JNI bridge
  smb-testkit/   # fixtures, mock transport, interoperability/fuzz helpers
```

See `AGENTS.md` for implementation rules and `docs/ARCHITECTURE.md` for the design baseline.

## First production consumer

XFiles is the first production consumer and benchmark target, but the Rust core must remain portable and reusable outside Android.
