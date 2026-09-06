# smb-io-rs Roadmap

## Phase 0: repository and protocol harness

- establish Cargo workspace boundaries;
- define typed error model and metrics vocabulary;
- build byte-level fixture/test harness;
- add packet parser fuzz targets;
- document interoperability test matrix.

Exit gate: workspace/test harness builds cleanly and malformed packet input cannot panic basic header/frame parsing.

## Phase 1: transport + SMB2 header + NEGOTIATE

- direct TCP transport on port 445;
- frame reader/writer;
- SMB2 header encode/decode;
- MessageId allocation;
- NEGOTIATE request/response for 2.0.2 through 3.1.1;
- negotiated limits/capabilities model;
- SMB 3.1.1 negotiate contexts and preauth state foundation.

Exit gate: negotiate successfully against representative Windows/Samba/NAS targets and record dialect/limits deterministically.

## Phase 2: authentication + session security

- SPNEGO provider boundary;
- NTLMv2;
- anonymous session where permitted;
- SESSION_SETUP state machine;
- signing key derivation;
- SMB2/3 signing verification;
- SMB 3.1.1 preauthentication integrity.

Exit gate: authenticated signed sessions interoperate and invalid signatures fail closed.

## Phase 3: share + read-only file path

- TREE_CONNECT / TREE_DISCONNECT;
- CREATE / CLOSE;
- QUERY_INFO;
- QUERY_DIRECTORY;
- READ;
- high-level `stat`, `list`, `open`, `read_at`, `len`.

Exit gate: browse shares and random-read large files without SMBJ/libsmbclient.

## Phase 4: request broker, credits, pipelined reads

- explicit SMB Credit accounting;
- multi-credit request charge;
- outstanding request table;
- reader/writer task split;
- multiple in-flight READ requests;
- split/reassemble large positional reads;
- priority classes and foreground credit reserve;
- latency/throughput/credit metrics.

Exit gate: sustained sequential read is no longer one-RTT-per-chunk and is benchmarked against baseline clients.

## Phase 5: media stream engine

- adaptive chunk sizing;
- range cache;
- sequential access detection;
- bounded read-ahead;
- stream generations;
- SMB2 CANCEL for eligible obsolete speculative reads;
- memory budget and cache metrics.

Exit gate: playback start and random seek benchmarks meet the XFiles migration targets without a duplicate Kotlin media cache.

## Phase 6: mutations and write pipeline

- WRITE;
- FLUSH;
- SET_INFO;
- `write_at`, `set_len`, rename, delete, mkdir/create;
- safe request retry classification;
- independent-range write pipelining where semantics permit.

Exit gate: filesystem behavior required by the first consumer passes mutation/recovery tests with no blind replay after ambiguous failures.

## Phase 7: reconnect and resilience

- connection generation state;
- transport reconnect;
- session/tree restoration;
- file reopen/validation;
- read/query recovery;
- conservative mutation failure behavior;
- architecture hooks for durable handles.

Exit gate: expected mobile/network interruptions recover read-only workloads and never silently duplicate mutations.

## Phase 8: Android bridge + XFiles A/B migration

- long-lived Rust runtime ownership;
- opaque JNI handles;
- stable DTO/error mapping;
- efficient buffer transfer;
- backend adapter in XFiles;
- SMBJ vs Rust A/B benchmark path;
- remove duplicate Kotlin media cache when Rust stream cache is active.

Replacement gate: XFiles functional parity for required SMB operations, security interoperability, lifecycle/reconnect tests, and no material regression in playback start, seek latency, sustained throughput, CPU, memory, or connection count.

## After first production replacement

Prioritize from concrete compatibility/performance demand:

- SMB3 encryption;
- durable handles and replay semantics;
- leases/oplocks;
- Kerberos;
- DFS;
- multichannel;
- QUIC;
- compression;
- additional platform bindings.
