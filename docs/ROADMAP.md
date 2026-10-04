# smb-io-rs Roadmap

This roadmap is the repository documentation counterpart of GitHub Issue #28. Phase numbering and completion status must stay aligned with that tracker.

## Core implementation

### Phase 1: TCP/445 + SMB2 header — complete

- direct TCP transport on port 445;
- NetBIOS-style SMB2 framing;
- SMB2 header encode/decode and validation;
- MessageId allocation foundation.

Exit gate: protocol framing and SMB2 headers are validated by unit tests and can establish the initial transport path used by later phases.

### Phase 2: NEGOTIATE — complete

- SMB 2.0.2 through SMB 3.1.1 negotiation;
- negotiated limits and capabilities;
- SMB 3.1.1 negotiate contexts and preauthentication-integrity foundation.

Exit gate: negotiate succeeds against the supported Samba integration target and records dialect and limits deterministically.

### Phase 3: SESSION_SETUP + SPNEGO / NTLMv2 — complete

- SPNEGO + NTLMv2 authentication;
- anonymous sessions where explicitly permitted;
- SESSION_SETUP state machine;
- signing/session-key handling;
- SMB 3.1.1 preauthentication integrity.

Exit gate: authenticated signed sessions interoperate and invalid signatures fail closed.

### Phase 4: TREE_CONNECT — complete

- TREE_CONNECT / TREE_DISCONNECT;
- share state and negotiated share capabilities.

Exit gate: authenticated sessions can connect to the configured share and cleanly disconnect.

### Phase 5: CREATE / READ / CLOSE — complete

- CREATE / CLOSE;
- positional READ;
- large-offset reads;
- Android/JNI read path;
- media broker, reconnecting read-only source, adaptive read-ahead, cancellation, and rolling cache.

Exit gate: signed SMB reads, random access, media playback, and read-only reconnect scenarios pass the permanent integration gates.

### Phase 6: QUERY_DIRECTORY / QUERY_INFO — complete

- QUERY_INFO request/response and typed filesystem decoding;
- paged QUERY_DIRECTORY enumeration;
- share-root directory opens;
- filesystem metadata and directory listing integration.

Exit gate: QUERY_INFO and QUERY_DIRECTORY pass the permanent real-Samba Phase 6 integration workflow.

### Phase 7: parallel READ / credit management — complete

- credit-driven sliding READ window;
- explicit outstanding request tracking by MessageId;
- out-of-order and async STATUS_PENDING dispatch;
- server-error draining;
- pipelined READ metrics and credit-stall metrics.

Exit gate: the permanent Phase 7 workflow reads a 32 MiB Samba fixture with at least 128 READ requests, verifies content, and observes more than one in-flight request.

### Phase 8: WRITE — in progress

Issue: #21.

Required scope:

- SMB2 WRITE request/response encode/decode;
- FileId, offset, data-length, and channel-field validation;
- negotiated `MaxWriteSize` chunking;
- correct CreditCharge for multi-credit writes;
- partial/short-write handling;
- synchronous and asynchronous (`STATUS_PENDING` + AsyncId) WRITE response correlation and validation;
- create / overwrite / append open semantics needed by the filesystem layer;
- preserve write-side NTSTATUS failures as structured `ClientError::ServerStatus` values;
- zero-length and boundary-condition tests;
- real-Samba CREATE → WRITE → READ → CLOSE verification;
- large-write integration coverage.

Design constraints:

- `write_at(offset, data)` is the native write primitive; do not introduce seek-based internal state;
- do not silently retry mutations after ambiguous transport failure;
- chunking must respect negotiated server limits and available credits rather than fixed application constants;
- async interim responses may grant credits and may be unsigned, while final responses must satisfy the session signing policy;
- protocol packet handling remains in `smb-wire`, request execution/credits in `smb-client`, and filesystem semantics in `smb-fs` / `smb-stream` as applicable;
- WRITE tests are added before the corresponding client/filesystem implementation.

Exit gate: new files and existing files can be written at arbitrary offsets, large writes complete within credit and MaxWriteSize constraints, sync and async WRITE responses are handled safely, written bytes round-trip through READ, and the real-Samba write integration workflow is green.

### Phase 9: rename / delete / mkdir — pending

Issue: #22.

- directory CREATE for mkdir;
- SET_INFO rename and disposition/delete operations;
- replace-if-exists and delete-on-close semantics;
- filesystem error mapping;
- Unicode and integration coverage.

Exit gate: mkdir, rename, file delete, and empty-directory delete all round-trip through QUERY_DIRECTORY / QUERY_INFO against real Samba.

### Phase 10: reconnect / durable handle — pending

Issue: #23.

- transport disconnect detection and connection-state transitions;
- NEGOTIATE / SESSION_SETUP / TREE_CONNECT restoration;
- Durable Handle V2 request/reconnect support;
- logical-handle restoration and FileId update;
- explicit outstanding-request and mutation replay policy;
- reconnect stress coverage.

Existing read-only reconnect support is useful groundwork but does not complete this phase; Phase 10 requires the full documented handle/reconnect contract, including write-side behavior.

Exit gate: deliberate transport interruption can restore eligible handles and continue READ / WRITE / CLOSE safely, while ambiguous mutations are never silently duplicated.

## Post phases

These do not block the Phase 1–10 core roadmap unless a target environment makes them mandatory:

- Kerberos authentication — Issue #24;
- SMB3 encryption — Issue #25;
- SMB3 multichannel — Issue #26;
- SMB over QUIC — Issue #27.

## XFiles integration

XFiles is the first production consumer, not the protocol boundary. XFiles should only advance its pinned Rust engine revision after the corresponding smb-io-rs phase gates are green. SMBJ may remain as a temporary rollback path until required SMB file-management operations have Rust parity, but new Rust protocol functionality must not be designed around SMBJ APIs.
