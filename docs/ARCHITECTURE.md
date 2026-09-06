# smb-io-rs Architecture

Status: implementation baseline

## 1. Purpose

`smb-io-rs` is a reusable SMB2/SMB3 client engine optimized for correct, high-throughput positional file I/O.

It is not a line-for-line port of SMBJ and it is not intended to implement every SMB feature before delivering value. The first production use case is Android media/file access, especially:

- browsing SMB shares;
- opening and streaming very large media files;
- low-latency random seeking;
- metadata and thumbnail extraction from arbitrary offsets;
- copy/export;
- positional read/write for editing;
- truncate, flush, rename, delete, mkdir;
- controlled recovery from ordinary transport interruptions.

The implementation should remain usable from non-Android consumers.

## 2. Native I/O model

The core abstraction is positional I/O, not a shared mutable cursor.

Conceptually:

```rust
pub trait RandomAccessFile {
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes, SmbError>;
    async fn write_at(&self, offset: u64, data: Bytes) -> Result<usize, SmbError>;
    async fn len(&self) -> Result<u64, SmbError>;
    async fn set_len(&self, len: u64) -> Result<(), SmbError>;
    async fn flush(&self) -> Result<(), SmbError>;
}
```

The exact trait shape may change as buffer ownership and zero-copy decisions mature, but offset-based I/O remains the primitive. Sequential streams are adapters on top.

Benefits:

- Media players seek naturally by offset.
- MP4/MKV parsers jump between file regions.
- Thumbnail extraction probes head/tail/keyframe areas.
- Editing writes known ranges.
- Independent ranges can be pipelined without serializing on a shared cursor.

## 3. Logical topology

Do not model a file as owning a TCP connection.

```text
SmbEngine
  └─ ServerPool[ServerKey]
       └─ Connection
            ├─ negotiated dialect/capabilities
            ├─ MessageId allocator
            ├─ credit scheduler
            ├─ request writer
            └─ response dispatcher
                 └─ Session[CredentialIdentity]
                      └─ Tree[ShareName]
                           ├─ FileHandle A
                           ├─ FileHandle B
                           └─ FileHandle C
```

Connections and authenticated sessions are reused only when endpoint, identity, and security policy are compatible.

This lets playback, thumbnail reads, directory queries, and transfers share one protocol engine while remaining independently cancellable and prioritized.

## 4. Protocol state owned by the engine

The client must keep protocol state explicit:

- negotiated dialect and capabilities;
- `MaxReadSize`, `MaxWriteSize`, `MaxTransactSize`;
- multi-credit capability and current credit balance;
- MessageId allocation;
- outstanding requests keyed by MessageId/AsyncId;
- session signing/encryption state;
- SMB 3.1.1 preauthentication hash state;
- TreeIds and FileIds;
- reconnect generation;
- open-handle recovery metadata;
- per-request retry classification.

If this state is hidden behind generic streams, correct pipelining, cancellation, signing, and reconnect become fragile.

## 5. Layering

### `smb-wire`

Owns SMB2/3 packet representation and framing only.

Responsibilities:

- SMB2 header and command structures;
- little-endian encode/decode;
- NetBIOS-over-TCP framing where applicable;
- strict offset/length/count validation;
- NTSTATUS representation;
- compound-message support when introduced.

No sockets, credentials, reconnect logic, Android code, or cache policy.

### `smb-auth`

Responsibilities:

- SPNEGO token flow;
- NTLMv2 integration;
- secret/session-key handling;
- future Kerberos provider boundary.

Sensitive material must not leak through `Debug`, logs, telemetry, snapshots, or panic text.

### `smb-client`

Responsibilities:

- transport lifecycle;
- NEGOTIATE / SESSION_SETUP / TREE_CONNECT state machines;
- MessageId allocation;
- SMB Credit accounting;
- request writer and response demultiplexer;
- outstanding-request table;
- timeouts and cancellation;
- signing / preauth / encryption transform coordination;
- reconnect coordination;
- protocol metrics.

### `smb-fs`

Responsibilities:

- high-level file/share semantics;
- mapping open intent to CREATE fields;
- directory listing;
- stat;
- rename/delete/truncate/mkdir/create semantics;
- path normalization.

Raw SMB access-mask/detail types must not leak into platform APIs.

### `smb-stream`

Responsibilities:

- `read_at` / `write_at` orchestration;
- split by negotiated operation limits;
- multiple in-flight requests;
- out-of-order completion and reassembly;
- interactive priority scheduling;
- adaptive prefetch and bounded cache;
- seek generations and cancellation;
- throughput/RTT/cache metrics.

This is where media-oriented performance policy lives.

### `smb-android`

Responsibilities only:

- own one long-lived engine/runtime;
- convert Kotlin settings to Rust configuration;
- expose opaque handles and stable DTOs;
- transfer buffers and map errors;
- contain any JNI-only unsafe code.

No SMB protocol behavior belongs in JNI functions.

### `smb-testkit`

Responsibilities:

- byte fixtures;
- mock transport;
- scripted server responses;
- interoperability harnesses;
- property/fuzz helpers;
- benchmark fixtures.

## 6. Request engine

Recommended per-connection task structure:

```text
callers
  |
  v
RequestBroker
  - priority
  - credits
  - MessageIds
  |
  v
writer task  ---- TCP ----> server

reader task  <--- TCP ----- server
  |
  v
outstanding[MessageId/AsyncId]
  |
  +--> request completion
```

The broker assigns/dispatches work only when enough credits exist and negotiated limits are respected.

The reader task:

1. reads a complete frame;
2. decrypts if required;
3. verifies signatures as applicable;
4. validates header/command correlation;
5. applies returned credit grants;
6. resolves the outstanding request;
7. handles async/unsolicited cases explicitly.

Unknown or malformed traffic must not be silently accepted.

## 7. SMB Credits and pipelining

Credits are a scheduling resource.

Rules:

- calculate multi-credit `CreditCharge` according to dialect/protocol rules;
- never exceed negotiated max request sizes;
- never oversubscribe granted credits;
- split large reads/writes into legal subrequests;
- allow independent subrequests in flight concurrently;
- reserve capacity so prefetch cannot block an urgent interactive read;
- expose credit wait/utilization metrics.

The target is to avoid RTT-bound behavior where every chunk waits for the previous response before the next request is sent.

## 8. Priority model

Initial priority classes:

1. `Interactive`: bytes directly blocking playback/current user action.
2. `Control`: open/stat/list/close needed for visible progress.
3. `SequentialPrefetch`: likely next bytes for an active stream.
4. `Transfer`: user-started copy/export/write pipeline.
5. `Background`: thumbnails/indexing/speculative work.

Use bounded fairness/aging so low-priority work is not permanently starved, but speculative I/O may yield aggressively to playback.

## 9. Seek and cancellation

Each streaming consumer owns a generation number.

On a material seek:

1. increment the generation;
2. drop queued prefetch from older generations;
3. cancel eligible speculative in-flight requests with SMB2 CANCEL;
4. preserve generally useful cached ranges only within memory budget;
5. dispatch the new offset as `Interactive` immediately.

Do not cancel an almost-complete request merely because its result became unnecessary if completion is cheaper than cancellation. This policy can use observed RTT/progress later.

## 10. Adaptive media pipeline

Avoid hard-coded application cache geometry such as a permanent `2 MiB x 2` policy.

Observe stable metrics such as:

- request RTT;
- delivered throughput;
- cache hit ratio;
- sequential run length;
- seek frequency/distance;
- negotiated MaxReadSize;
- available credits;
- active consumer count;
- memory budget.

Chunk size should be chosen from workload and negotiated constraints, not just the largest legal server request.

For sequential playback, prefer a time-oriented prefetch target:

```text
prefetch_bytes ~= observed_throughput * target_buffer_seconds
```

Then clamp by memory budget, credits, operation limits, and competing foreground demand.

The cache should represent byte ranges/pages and understand ranges already in flight.

## 11. Write semantics and retry safety

`write_at` may pipeline independent ranges when caller ordering permits, but remote mutation recovery must be conservative.

`flush()` maps to SMB2 FLUSH and represents the requested durability boundary.

Every command has an explicit retry class, conceptually:

```rust
enum RetryClass {
    SafeAfterReconnect,
    ReopenAndValidate,
    ReplayAwareOnly,
    NeverAutomatically,
}
```

Typical policy:

- READ / QUERY: generally safe after reopen/validation;
- directory query: restartable with care around resume state;
- WRITE: never blindly resend after an ambiguous transport failure;
- rename/delete/SET_INFO: never blindly replay.

Future durable handles/replay semantics may broaden safe recovery, but correctness wins over convenience.

## 12. Security architecture

### SMB 3.1.1 preauthentication integrity

Maintain rolling preauthentication integrity state over the exact bytes required by `[MS-SMB2]`. Serialization used for hashing must match bytes actually sent/received.

### Signing

Support dialect-appropriate signing algorithms and verify signed responses before delivering payloads.

Expected algorithm families include:

- HMAC-SHA256 for SMB 2.x;
- AES-CMAC for SMB 3.x where applicable;
- AES-GMAC for SMB 3.1.1 when negotiated.

Invalid signatures are security failures, not warnings.

### Encryption

SMB3 transform encryption is a production-parity milestone. Keep a message-transform boundary so it can be added without rewriting request dispatch.

```text
request object
  -> encode
  -> sign if required
  -> encrypt if required
  -> frame

frame
  -> decrypt if present/required
  -> verify signature as applicable
  -> decode/validate
  -> dispatch
```

If a target requires encryption before support exists, return an explicit unsupported-security-feature error. Never downgrade silently.

## 13. Reconnect state machine

Reconnect is a state machine, not a catch-all retry loop.

A transport failure transitions the affected connection generation and coordinates:

- outstanding request completion/cancellation;
- transport re-establishment;
- dialect/session re-establishment as required;
- tree reattachment;
- file-handle reopen/validation where safe;
- per-operation retry policy.

Design file handles so future durable-handle recovery can be added without changing application-facing APIs.

## 14. Platform boundary

The Rust core should expose stable semantic operations, not SMB wire details.

A platform consumer should be able to hold opaque engine/session/share/file handles and call operations equivalent to:

- connect/authenticate;
- mount/connect share;
- open file;
- `read_at` / `write_at`;
- `len` / `set_len` / `flush`;
- `stat` / `list`;
- `rename` / `delete` / `mkdir`;
- close.

Media3's blocking `DataSource.read()` can block its I/O thread while the Rust engine itself remains backed by one long-lived async runtime and pipelined network requests. Never create a runtime or TCP connection per Java/Kotlin `read()` call.

## 15. Quality gates

Do not declare the engine production-ready merely because one NAS can list/read a file.

Required classes of validation:

- wire encode/decode unit tests;
- malformed packet tests;
- fuzzing/property tests for packet parsers;
- scripted protocol state-machine tests;
- interoperability tests against representative SMB servers;
- signing and SMB 3.1.1 preauth tests;
- reconnect tests without unsafe mutation replay;
- read/write/truncate/flush/rename/delete behavior tests;
- Android lifecycle/reopen tests for the bridge;
- benchmarks for playback start, sequential throughput, random seek latency, CPU, memory, connection count, and reconnect behavior.

For the first XFiles migration, the Rust path must show no material regression against the existing SMBJ path on the same server/file/network. Media seek latency and sustained throughput are first-class acceptance metrics.

## 16. Initial non-goals

The first milestones do not need to cover all of:

- SMB1;
- server implementation;
- printer shares;
- named-pipe/RPC management APIs;
- DFS;
- compression;
- Kerberos;
- multichannel;
- QUIC;
- RDMA;
- leases/oplocks beyond what concrete interoperability requires;
- durable handles beyond the extension boundary.

These non-goals must not become excuses to hard-code architecture that prevents later support.
