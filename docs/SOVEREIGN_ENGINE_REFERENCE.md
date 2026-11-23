# Sovereign Engine reference

> Module: `github.com/hr18vk/sovereign` · Go 1.26.1 · Primary target: ARM64 Linux on AWS Graviton
>
> The source is the authority for the behavior described here. Optional, dormant, benchmark-only, and test-only facilities are labeled as such.

## 1. Overview

Sovereign Engine is an off-heap δ-CRDT database engine for convergent, causally attributable state across mutually distrusting nodes. It is designed for partitions, duplication, reordering, and message loss. Its central data path uses arena allocation, compare-and-swap updates, and epoch-based reclamation to keep the core HAMT write path free of Go heap allocation and mutexes.

### The data model

A mutable row loses concurrent history; an append-only log records events but not directly the state known at a particular transaction time. Sovereign Engine instead keys state by **system time** (when the system observed a fact), **valid time** (when the fact applied), and **assertion time** (the causal assertion epoch). **Decision time** is also carried on the wire.

State is an Add-Wins Set lattice folded by merge-union `Join`. Concurrent writers can therefore merge without a central sequencer. The durable tier materializes the same history as an off-heap LSM tree: a SkipListArena MemTable, per-entity Arrow IPC L0 files, and merged L1 files. `Resolver.AsOf` and `Resolver.Range` combine those files with live HAMT state for read-your-writes queries.

### Measured operating envelope

These figures measure different layers and are not interchangeable.

| Measurement | Result | Conditions and receipt |
|---|---|---|
| Core stack microbenchmark | 50,736,038 to 68,278,197 ops/s | `TestScalingGate`, GOMAXPROCS=32 on a c8g.8xlarge with Graviton4, Go 1.26.1, measured 2026-09-03. This exercises the in-process ShardedStack push/pop path, not signed ingest. [Receipt](evidence/core-crucible.txt). |
| HAMT steady-state allocation | 0 B/op, 0 allocs/op | `HAMT.Set`; the allocation test skips under `-race` because race instrumentation changes allocation counts. [Receipt](evidence/zero-alloc.txt). |
| `Join` microbenchmark | about 5.5M completed iterations per run; about 8174 ns/op, 472 B/op, 6 allocs/op | Historical in-process baseline preserved from v0.1.0 (`BenchmarkCRDTEngine_Join` with a 2 GiB arena; `crdt_test.go`). The iteration count is not a per-second rate. |
| Signed receive path | 5.7M–6.0M deltas/sec | `BenchmarkBatchedVerifyParallel` at GOMAXPROCS=32 on c8g.8xlarge, measured 2026-09-15. Ed25519 verification, envelope decoding, and CRDT apply run in process; sockets and disk are outside the loop. [Receipt](evidence/ingest-ed25519.txt). |
| Multi-region convergence | 8.950s after origin quiescence | 100 node processes on three machines across three AWS regions, with WAL durability enabled, measured 2026-09-13. [Receipt](evidence/convergence-100-node.txt). |
| Unbatched Ed25519 verification | about 60.19 µs/op | Historical benchmark baseline preserved from v0.1.0. The dominant per-frame receive cost that admission checks and batch verification seek to avoid or amortize. |
| ML-DSA-65 size cost | 3309 B signature, 1952 B public key | The signature is 51.7× the 64 B Ed25519 signature on the fixed 120 B signing payload. Hybrid signing is opt-in. |

The 1.1M ops/s false-sharing result and the core range above explain the allocator's cache-line layout; neither is an end-to-end database throughput claim. Component benchmarks also use different machine classes, so each benchmark's own conditions matter more than a `_4c` or `_32c` suffix.

### Main mechanisms

- **Tri-temporal history.** The HAMT retains causal dots; Arrow files retain temporal rows and support point-in-time and interval queries.
- **Off-heap core state.** `HamtArena` stores nodes, leaves, strings, and entry arrays in an `mmap` region. `NodePtr` is a `uintptr`, invisible to the Go garbage collector.
- **Cache-line separation.** Contended atomics and stack slots are padded and sharded to limit coherence traffic.
- **CAS and EBR.** Root updates and free-list operations use compare-and-swap. Epoch pins and hazard pointers delay reuse until readers are safe.
- **Causal and spatial fields.** Every `CRDTEntry` carries an H3 cell and temporal fields. The optional secondary index adds exact-cell and system-time queries; it does not provide radius or ring search.
- **Explicit cryptographic status.** Ed25519 verification is the default. Hybrid Ed25519+ML-DSA-65 signing is compiled in but disabled unless requested. TLS can negotiate X25519MLKEM768 when both peers support it.

## 2. Architecture and data flow

The engine has a δ-CRDT core surrounded by admission and signature checks, a replication mesh, a durable LSM tier, and operator interfaces.

### 2.1 Package layers

| Layer | Packages | Responsibility |
|---|---|---|
| CRDT core | `pkg/sync` | Sharded persistent HAMT, causal dots, merge-union `Join`, IBLT reconciliation, arena allocation, EBR and hazard pointers, wire reconstruction, and lock-free stack experiments. |
| Storage and recovery | `internal/database`, `pkg/durability` | Jemalloc-backed SkipListArena, Arrow L0/L1 files, compaction, pruning, queries, WAL, checkpoints, snapshots, and recovery. |
| Mesh and admission | `pkg/mesh`, `pkg/clock`, `pkg/admission` | TLS peer gossip, digest exchange, hierarchical peer selection, physical-clock and per-peer rate admission, and the mTLS control server. |
| Receive and transport | `pkg/receive`, `pkg/transport` | Frame dispatch, relay and origin verification, batch application, relay retention, TLS configuration, and optional kernel steering. |
| Identity and cryptography | `pkg/identity`, `pkg/crypto`, `internal/crypto`, `pkg/authorization` | Ed25519 and optional ML-DSA-65 operations, key directories, development certificates, PII masking, and benchmark-only Cedar evaluation. |
| Attribution and telemetry | `pkg/attribution`, `internal/telemetry`, `pkg/metrics` | Relay envelopes, signed batches and digests, sharded counters, and Prometheus export. |
| Network, index, and spatial support | `internal/network`, `internal/transport`, `internal/index`, `internal/spatial`, `api/capnp/api/capnp` | HTTP and Cap'n Proto support, object storage, the optional H3/system-time index, the external H3 worker ring, and generated wire bindings. |
| Fault testing | `internal/chaos` | Byzantine inputs, in-memory partitions, WAL tests, and supervisor/worker crash tests. |
| Commands and clients | `cmd/sovereign-node`, `cmd/mesh-bootstrap`, `cmd/convergence-gate`, `cmd/fleet-gate`, `sdk/sovereign`, `examples/` | Node wiring, local mesh setup and checks, client access, and embedding examples. |
| Measurement-only packages | `pkg/codec120`, `pkg/durability120`, `pkg/pqecobench` | Byte-cost, durability-latency, and post-quantum cost benchmarks; these are not node services. |

### 2.2 CRDT core

`DeltaCRDTEngine` routes each entity to one of its per-shard `atomic.Pointer[HAMT]` roots. The default is 256 shards (`defaultShardCount`), which avoids a single root CAS locus. Its other central state includes:

- `lamportCounter` for local dot allocation and `lastSavedCounter` for the persistence watermark;
- `arena` and `ebr`, immutable after initialization;
- an unbuffered `persistCh` and its worker, with `persistMu` confined to persistence;
- `deltaPool` for delta recycling; and
- `observedInboundRateBits`, an EWMA input to the inbound Lamport-skew bound.

`CRDTEntry` is exactly 120 bytes, 8-byte aligned, with no padding:

```text
PayloadDigest   [32]byte  @0    SHA-256 of the payload
OriginNodeID    [16]byte  @32   origin identity
DotNodeID       [16]byte  @48   identity that minted the dot
DotCounter      uint64    @64   Lamport counter
SystemTime      int64     @72   observation time
ValidTimeStart  int64     @80   start of valid interval
ValidTimeEnd    int64     @88   end of valid interval
AssertionTime   int64     @96   assertion epoch
DecisionTime    int64     @104  decision timestamp
H3Index         uint64    @112  spatial cell
```

`CausalDot{NodeID, Counter}` identifies a mutation. `CRDTDelta` carries `OriginNodeID` and a push iterator `Seq func(yield func(entityID string, entry CRDTEntry) bool)`, avoiding a materialized entry slice. `Release` returns a delta to its pool.

`HAMT.Set` and `HAMT.Delete` path-copy nodes and share unchanged structure. Although `HamtNode` contains a cached `merkleHash`, `HAMT.MerkleRoot` and `DeltaCRDTEngine.MerkleRootFromShards` do not return that field in constant time. They collect `(DotNodeID, DotCounter)` pairs, sort them, and hash the canonical sequence with SHA-256. Root equality therefore compares dot sets, not complete entries. `durability.StateFingerprint` covers the entity ID and every entry field for full-state comparison.

`HamtArena` uses private anonymous `mmap` storage and 17 size classes: one node class and 16 variable-size classes. Node and variable free-lists are sharded 256 ways. Variable blocks use tagged Treiber heads: a 32-bit generation counter and a 32-bit word offset occupy one atomic head, so a pop followed by a push cannot recreate the same head unnoticed. Allocation probes nearby shards before extending the bump offset.

There is a known defect in the fixed-size node free-list. `AllocNode` and `pushFreeNode` store the next link in the first 8 bytes of a freed node, overlapping `refCount` and `bitmap`, instead of using the dedicated `nextFree` field at offset 64. The defect remains in v0.2.0. Reuse currently relies on EBR delaying reclamation until no earlier reader can still observe those fields; the dedicated field is otherwise unused.

`reclamation.go` implements EBR with a global epoch, a 3-epoch by 256-shard retired ring, and a 2-epoch grace window. `Participant.Enter` pins a reader's epoch; `DetachAndProtect` publishes a hazard pointer for a detached node. Retirement and reclamation must exclude both earlier readers and protected addresses before memory returns to a free-list. The variable-list generation tag and this grace period address different ABA opportunities.

Inbound entries pass through `ReconstructEntry` or `ReconstructEntryWithSkewBound` before `Join`. Reconstruction checks the payload digest, required Cap'n Proto fields, and dot/origin attribution. The skew-aware form compares each dot against `MaxAcceptableDotCounter(snapshot)` with saturating arithmetic, allowing the apply layer to reject or hold an excessive dot before it changes local Lamport state. `ReconstructedEntry` is returned by value to avoid a per-entry heap allocation.

`pkg/sync` still contains the legacy IBLT and `StrataEstimator` implementations. Live production digests carry IBLT data without an estimator; the estimator is added only by a compatibility-test switch. The default digest uses a fixed table. `--iblt-v2` selects decorrelated placement, `IBL2` framing, header-only requests, and a bounded per-peer bucket ladder based on observed peel results. `GenerateDelta` subtracts and peels the remote digest. `GenerateDeltaStratified` is not part of the current API.

### 2.3 Storage and durability

`internal/database` accepts `TriTemporalEvent` values, buffers them in a pointerless `SkipListArena`, asynchronously writes per-entity Arrow IPC files, compacts L0 into L1, and answers temporal queries.

- **`JemallocAllocator`** uses CGO `mallocx` with 64-byte alignment and zeroing, and `sdallocx` for sized frees. Its allocation counter reports current off-heap usage; SkipListArena enforces the MemTable's configured arena capacity, 256 MB by default.
- **`SkipListArena`** uses 64-byte nodes, a 40-byte composite key, a maximum height of 11 levels, and geometric level selection with `pValue=4`. `Seek` performs a descent without splicing; it is correct but not used by `scanWindowRecordBatch`.
- **Composite keys** contain `[hash16 | sysTime | validTimeStart | assertTime]` in big-endian order. Lexicographic byte order therefore matches numeric field order. `hash16` is the truncated SHA-256 of the entity ID.
- **`MemTable`** swaps a full arena for a fresh one under its write lock. Frozen arenas flush asynchronously, with a capacity-4 semaphore bounding flushes in flight.
- **`L0Flusher`** writes nine Arrow fields: the entity hash, four nanosecond timestamps, H3 cell, payload digest, entity ID, and payload. Open-ended validity uses `MaxValidTimeEndNs = 9_000_000_000_000_000_000` rather than a year-9999 value whose Unix nanoseconds overflow `int64`.
- **`L1Compactor`** merges per-entity L0 files and optionally applies `DominancePrune`. Each compaction writes one L1 file. The default trigger is 64 L0 files per entity. `MaxL1FilesPerEntity=4` is reserved for possible future multi-L1 tiering; the current compactor does not use it as a retention limit. Pruning is disabled by default.
- **`Resolver`** combines durable rows with an optional `LiveSource`. Defaults include `MaxL0Files=1000`, `MaxRangeRows=4096`, and first-system-time file and manifest skipping. A zero row limit means unlimited, not an imposed default.
- **`L0Reaper`** is opt-in through `--compaction-reap-enable`. Before deleting an old L0 object it confirms that the replacement L1 object still downloads successfully; any failure preserves the old data.
- **`EpochCompactor`** has no production importer. Current collection uses dominance pruning and the L0 reaper, not tombstones.

`pkg/durability` connects the core to persistent recovery:

- **`Bridge.PutLocal`** applies a local mutation, records its payload digest, appends one WAL mutation, and fsyncs before reporting success. **`Bridge.PutLocals`** and `WAL.AppendMutations` provide the group-commit path for a batch. If the WAL append fails after insertion, the mutation can remain in memory; HTTP 503 means the write was not acknowledged, not that its in-memory application was rolled back.
- **`OpenWAL` and `ReplayWAL`** re-export the WAL implemented in `internal/chaos`; the alias layer adds no independent recovery behavior. New records contain full 120-byte V2 mutations inside 0x06 CRC32C frames. Legacy 80-byte records still replay, but their absent temporal and H3 fields remain zero.
- **`RecoverEngine`** replays the full WAL. **`RecoverEngineWithSnapshot`** loads a checkpoint image and replays only the later record-sequence tail. Full replay reconstructs local-origin records, so a checkpoint root that also contains foreign entries is not generally a valid full-replay comparison. Root and fingerprint checks run when the corresponding checkpoint metadata is available. `RecoveryWitness` records which branch ran and why.
- **`SnapshotImage`** writes a versioned binary checkpoint object under `ckpt/<LamportHigh>`, containing canonical 120-byte entry records and a CRC32C. Arrow L0 files are separate query artifacts, not the checkpoint container. **`LocalFS`** supplies the lister, downloader, uploader, and deleter interfaces for local tests and single-node deployments.

### 2.4 Mesh, admission, and control

`Gossiper` owns the `PeerSet`, payload cache, engine, identity directory, and anti-entropy schedule. A sweep orders peers deterministically, selects a full or digest-derived delta, sends it as one signed batch or as individual frames, and releases the delta afterward. Digest waits can adapt to observed response latency. Optional defer handling retries later or sends bounded rotating slices instead of immediately sending the full keyset after repeated failures.

`TopologyManager` adds region-aware peer selection when `--region-aware` is set. Its options cover regional fan-out, gateways, rotating partial intra-region views, deterministic sweep phase offsets, and an out-of-band peer directory. Without region-aware routing, the ordinary peer set remains the topology.

`clock.IngressHLCScalarCap.Admit` performs only a physical-time check. It rejects a timestamp more than 2000 µs ahead of the local clock before signature verification. It does not advance the Lamport counter. Accepted entries advance that counter inside `Join`; an earlier advance would contaminate the snapshot used for skew validation. `Advance` remains available for explicit post-apply catch-up, and the receiver's pre-apply call exists only as a test fault.

`admission.PeerBucket` shards peer EWMA state across 16 mutex-protected maps. Single-frame admission keys shards with the Ed25519 public key; batch admission uses the zero-extended origin node ID. Charges reflect counter deltas rather than absolute counters. Rate and clock rejection happen before origin verification; pre-authentication rejections refund an uncommitted rate charge.

`mesh.ControlServer` serves `/v1/insert`, `/v1/batch-insert`, `/v1/get`, `/v1/query`, `/v1/range`, and `/v1/merkle` over mTLS. It can also serve `/livecheck` and `/metrics`. With `--secondary-index`, it registers `/v1/querybyh3` and `/v1/querybysystime`. A missing resolver returns 503 before query parameter validation. `handleGet` selects the entry and payload from one live snapshot so it cannot combine values from different dots.

### 2.5 Receive and transport

`receive.Receiver` is the first production caller of `Join`. `HandleFrame`, `HandleBatchFrame`, and `HandleHybridFrame` return an `AcceptVerdict` whose `Accepted` count reports joined entries. Relay retention and secondary-index callbacks run only after successful application.

The single-frame path is:

```text
complete frame
  -> relay envelope and gate-field decoding
  -> per-peer rate admission
  -> physical-clock admission
  -> hop-depth check and relay signature verification
  -> origin key lookup and origin signature verification
  -> signed-inner / outer-header consistency check
  -> ReconstructEntry[WithSkewBound]
  -> DeltaCRDTEngine.Join
  -> index, clock-advance, and relay-retention callbacks
```

Batch handling verifies one Ed25519 signature over the batch and charges the origin once using its monotonic `OriginSeq`. Hybrid batches require both Ed25519 and ML-DSA-65 signatures over the same 120-byte SHAKE256 pad. The physical-clock and hop-depth sequence shown above belongs to the single-frame path; batch and hybrid handlers have their own admission and verification paths.

`transport.TransmitHeapBuffer` defines a copy-from-mmap-to-heap boundary for callers that pin egress buffers; it does not pin the `mmap` region itself. The node TLS transport currently uses Go's ordinary TCP write path, without `MSG_ZEROCOPY` or `runtime.Pinner`.

`TLSConnections` requires TLS 1.3 and mutual certificate verification. Leaf, CA, and CRL replacements are independent; a leaf reload does not implicitly replace the trust pool. CRL loading parses the configured file and extracts revoked serials but does not verify the CRL signature, so the file's provenance is part of the deployment trust boundary. `KernelFanout` is available only with the `ebpf_kernel` build tag and is not the default ingress path. The in-process `ReusePortFanout` route-selection helper likewise has no production caller.

### 2.6 End-to-end paths

A local write follows this route:

```text
sdk.Client.InsertLocal
  -> ControlServer.handleInsert
  -> Gossiper.InsertLocalEvents
  -> with a configured WAL: Bridge.PutLocal
       -> payload digest stamping
       -> engine.InsertLocal / NextDot / HAMT.Set
       -> WAL persistence and optional checkpoint
  -> with the default empty --wal-path: in-memory branch
       -> payload digest stamping
       -> engine.InsertLocal / NextDot / HAMT.Set
  -> origin payload cache
  -> later gossip batch
```

`handleBatchInsert` uses `Gossiper.InsertLocalEventsBatch` for several entries. With the durable tier configured, node wiring also feeds MemTable writes, asynchronous Arrow L0 flushes, the compaction scheduler, and the optional L0 reaper. Those storage stages are separate from HAMT insertion and do not run inside its CAS loop.

A replicated write arrives through the peer TLS listener and the receive gate stack. Wire reconstruction precedes `Join`. Accepted entries advance Lamport time; duplicates do not create another clock-advance WAL record. An over-bound dot is not allowed to advance the clock before its own skew check.

A temporal query follows this route:

```text
ControlServer.handleQuery or handleRange
  -> Resolver.AsOf or Resolver.Range
       -> eligible L0 and L1 objects
       -> durable entity, transaction-time, and valid-time filters
       -> LiveSource.LiveRead
            -> engineHAMTAdapter
            -> DeltaCRDTEngine.PointGet on the entity's shard
       -> live transaction-time and valid-time filters
       -> AsOf dominance merge or Range deduplication by system time and digest
  -> digest-bearing response without a durable payload field
```

Both resolvers scan durable objects before calling `LiveRead`. `PointGet` holds an EBR pin and copies only the requested entity's entries. It avoids constructing `State()` and copying the whole HAMT for each live read. Durable files and manifests whose first system time is later than the query transaction time can be skipped. A missing live result is normal and merges with durable history.

Anti-entropy has three broad outcomes: a full delta, a digest-derived difference, or a deferred/bounded retry when configured. The digest exchange is a mesh-internal advisory protocol; its frames are not CRDT deltas and do not pass through the origin-signature gate as state updates. The resulting delta still uses the ordinary signed batch or relay path.

Local dots come from `NextDot`. WAL replay instead restores each mutation at its recorded `(DotNodeID, DotCounter)` through exact-dot `Join`; it never calls `InsertLocal` to mint a replacement dot. The post-checkpoint tail is selected by WAL record sequence, because a Lamport value is not a log position and concurrent mint and append order can differ. Replayed clock advances merge as a monotone maximum, so restored state does not depend on replay order.

### 2.7 Cross-subsystem contracts

- **Receive to core:** reconstruction and skew checks run before merge. Batch application does not partially commit elements that fail the wire-integrity contract.
- **Identity to mesh:** the wire carries node IDs, not public keys. `identity.Directory` resolves verification keys out of band; the peer directory can provision both Ed25519 and ML-DSA-65 keys.
- **Core to recovery:** local writes and foreign clock advances reach the WAL through separate paths. Merkle roots identify dot sets; checkpoint state fingerprints cover complete entries.
- **Core to storage:** `engineHAMTAdapter` is the narrow live-read interface into `internal/database`, avoiding an import cycle and a full-state copy.
- **Telemetry to Prometheus:** `TelemetryBridge` reads cumulative values from `internal/telemetry` and exposes them alongside the labelled `sovereign_*` recorder series. Existing `supremum_*` metric names remain wire-compatible.

## 3. Design rationale

### 3.1 Why a δ-CRDT

A delta carries state needed by a remote replica rather than an instruction that must be applied in one global order. Merge-union `Join` is commutative, associative, and idempotent. Property tests cover those laws, while `internal/chaos` exercises convergence through partitions, drops, duplication, and reordering. `TestMerkleConvergenceAfterPartition` uses 32 engines and repeats partition/heal rounds until the roots agree; `TestConvergenceDeterminismAcrossRuns` compares independent runs with deduplication disabled.

IBLT subtraction avoids sending the complete set when peers differ only slightly. A failed exchange or peel cannot be treated as a small difference: the default response is a full delta, while the optional defer path delays or bounds the send. Correctness does not depend on a successful estimate.

The former `LWWOperator.Resolve` discarded the losing dot and could not reproduce merge-union history after later reconciliation. ADR-0033 records why that operator was removed rather than used for lossless live reads. `selectLatestDot` chooses a deterministic current value from the full dot set without deleting the other dots.

### 3.2 Why off-heap allocation

Go heap pointers cannot describe stable positions in the `mmap` arena, so `NodePtr` stores an integer address and views are rebuilt only while the relevant memory is alive. Nodes, leaves, strings, entry arrays, and even the HAMT wrapper reside in the arena. `makeBinaryKey` uses a small stack buffer whose bytes are copied into the arena before `Set` returns.

The zero-allocation contract is deliberately narrow: it applies to steady-state `HAMT.Set`, not to every network, cryptographic, or storage operation. `FrameReader` allocates a frame buffer, signing allocates, and verification allocates curve points. `TestHotPathZeroAllocations` guards the core path; the ingest receipt reports its own allocation counts rather than inheriting the core result.

### 3.3 Why cache-line separation and sharding

Independent atomics that share a cache line still contend when different cores write them. The measured false-sharing configuration reached about 1.1M ops/s where the padded and sharded configurations produced the core range in §1. `ElimSlot` and `secShard` occupy 128 B; telemetry stripes occupy 64 B; the spatial ring uses a 64 B slot and a 192 B header to separate writer, reader, and control state.

Sharding applies the same reasoning to root CAS operations and free-lists. `TestMemoryLayoutAnalysis` checks selected field offsets and sizes, while `TestNodeFreelistSharded` exercises distribution across free-list shards. Padding does not remove the need to inspect contention: the benchmark result belongs to the specific workload and machine on which it was measured.

### 3.4 Why CAS and EBR share the write path

`Join`, `InsertLocal`, and `NextDot` use atomic updates rather than a core-wide mutex. `persistMu` belongs to the persistence worker, and `stateViewMu` protects only the lazily constructed `State` view. Other packages do use mutexes where appropriate: peer EWMA shards, the identity directory, the payload cache, and WAL serialization are examples.

Lock-free update creates a lifetime problem. A reader can observe a node just before another thread retires and reuses it. EBR pins prevent reuse during that window; hazard pointers cover detached nodes that need explicit protection. Variable-size lists additionally tag their heads against ABA. The fixed-size node-list defect described in §2.2 is a reminder that field lifetime and list lifetime must be considered together, not separate implementation details.

Residency helpers such as `LockHotPages`, `PrefaultPages`, and `PrefaultHot` are available for experiments but have no production caller. `HamtArena.Free` calls `UnlockAllPages` during teardown; that does not make page locking part of normal node operation.

### 3.5 Why replay restores recorded dots

Re-minting during replay is incorrect because mint order and WAL append order can differ under concurrency. A counter-derived starting seed can also skip or duplicate entries when a checkpoint overlaps in-flight writes. Restoring the recorded dot makes replay an idempotent merge, and cutting the tail by record sequence makes the checkpoint boundary explicit.

A non-quiescent checkpoint still needs a consistent replay boundary. Capture records the WAL `CutSeq` before one pinned shard walk derives both the root and the local watermark from the same image. Replay then uses that record-sequence cut rather than treating the Lamport watermark as a log position. Recovery seeds its clock from the checkpoint's `ClockHigh`, restored dots, and recorded advances.

A Merkle root alone cannot validate complete recovery state because it omits entity IDs, payload digests, and temporal fields. When a snapshotter is configured, `Bridge.AppendCheckpoint` computes a full-entry state fingerprint from the checkpoint image records and stores it in the WAL checkpoint metadata. The image itself contains the root and entry records, with a CRC32C in its encoded form; recovery compares the image fingerprint with the WAL metadata when that metadata is available.

### 3.6 Why temporal and spatial fields belong to the entry

The composite storage key and Arrow schema let a query ask what was true during a valid-time interval as known at a transaction time. `AsOf` selects a dominant point; `Range` uses interval intersection rather than accepting only rows whose start lies inside the requested window.

Dominance pruning removes rows superseded within the same temporal lattice only when they fall before the selected horizon. The observed query frontier advances monotonically. The inferred horizon is `max(operatorFloor, observedFrontier - backoff)`, so inference cannot lower an operator's floor. Pruning remains opt-in, and the L0 reaper verifies replacement objects before deletion.

`H3Index` travels with each live entry and durable row. The optional `internal/index` supports exact H3-cell and system-time queries across entities. It tracks current placements, not historical cell membership; when its configured entity ceiling prevents complete indexing, the control routes reject the known-degraded index rather than returning partial results as success. Geospatial enrichment is separate: `internal/spatial` provides a shared-memory SPSC ring and `EpochBatcher` for an externally supplied C++ H3 worker. In-tree tests use mock consumers, so the ring does not by itself supply a working geocoder.

### 3.7 Cryptographic boundaries

`identity.VerifyCRDTFrame` performs the default Ed25519 check and rejects non-canonical and small-order forms. `SignCRDTFrame` uses randomized-nonce Ed25519: it hashes 64 random bytes with the message to derive the nonce, then emits an ordinary RFC-8032 signature. It does not include the secret-key prefix in that nonce hash, so it depends on `crypto/rand` and is not hedged against random-number-generator failure.

ML-DSA-65 support is compiled into the default build. `--hybrid-sign` adds an ML-DSA-65 signature beside Ed25519 for self-originated batches; `--hybrid-verify` requires both signatures. Both sign the same fixed-size SHAKE256 pad while the receiver applies the original batch bytes. The larger signature and public-key sizes are part of the wire-cost trade-off.

TLS 1.3 leaves curve preferences to Go, which advertises X25519MLKEM768 by default on the supported toolchain. Peers that both support it can negotiate that hybrid key exchange; other peers can fall back to X25519. `RecordHandshake` reports the negotiated curve after dialing, but the server-side control-port accept path does not use that reporting hook. Neither key exchange nor optional hybrid signing makes every deployment post-quantum by default.

### 3.8 Fault tests and measurement discipline

`internal/chaos` supplies faults that generic infrastructure tools cannot express directly. It can re-sign a semantically malicious dot ratchet, drive real engines through an in-memory partition network, and terminate a child process with an off-heap fault before recovering from its WAL. `TestSIGSEGVSurvival` is intended to check recovery of the pre-crash Merkle root and preservation of the active connection owned by the test process. It skips when `CHAOS_WORKER_BIN` is unset, but setting it does not make the test runnable: the supplied path is ignored, and `buildWorkerBinary` unconditionally runs `go build` for `./cmd/chaos-worker/`. That command is absent from this tree, so the test fails during the build before any assertion executes.

Benchmarks name their layer and conditions. The stack core, signed in-process receive path, and multi-region mesh answer different questions. Negative results remain useful: for example, the kernel-steering benchmarks compare against hash fallback rather than assuming eBPF is faster. Receipt links and exact commands belong beside public performance figures.

## 4. Capabilities and status

“Wired” below means reachable from the node or its control plane. It is not a production-readiness certification.

| Capability | Status and limit |
|---|---|
| Sharded HAMT, merge-union `Join`, causal dots, EBR | Wired core path. |
| Wire reconstruction and Lamport-skew checks | Wired before `Join`; malformed or excessive input does not become accepted state. |
| Fixed-size IBLT reconciliation | Available through `--stratified-anti-entropy`; failure falls back to full-state delta by default. |
| Adaptive IBLT v2 | Opt-in with `--iblt-v2`; peers must use compatible protocol settings. |
| Deferred and bounded oversend | Opt-in with `--defer-handler`; saturation crossover is separately controlled. |
| Region-aware hierarchy and gateways | Opt-in with `--region-aware` and the topology flags. |
| WAL and snapshot recovery | Enabled by `--wal-path`; snapshots use `--lsm-root`. |
| L1 compaction | Wired; dominance pruning and L0 reaping are separate opt-in features. |
| Live temporal reads | Wired through `PointGet` and `Resolver`; durable queries require a configured resolver. |
| Secondary H3/system-time index | Opt-in with `--secondary-index`; exact current placements only, not historical cell membership. Routes reject a known-degraded index rather than returning partial results as success. |
| External H3 worker integration | Structural support only; the worker is externally supplied and tests use mock consumers. |
| `SkipListArena.Seek` | Implemented and tested, but not used by the record-batch scan. |
| Residency locking and prefault helpers | Test and benchmark support, not called by normal node setup. |
| Kernel `SK_REUSEPORT` steering | Requires the `ebpf_kernel` build tag and suitable kernel privileges; not default ingress. |
| `ReusePortFanout` | In-process route-selection helper with no production caller. |
| Ed25519 signing and verification | Default frame authentication path; signing depends on a sound random source. |
| Hybrid Ed25519+ML-DSA-65 frames | Compiled in, opt-in with `--hybrid-sign` and `--hybrid-verify`. |
| X25519MLKEM768 TLS key exchange | Available by default on the Go toolchain when both peers support it; classical fallback remains possible. |
| aws-lc signing bridge | Panic stub behind the disabled `aws_lc_hedged` build tag. |
| Development certificate authority | Suitable for development meshes. Leaf/CA/CRL reloads exist; HSM custody and production PKI operations are not supplied. |
| Automatic certificate rotation | Optional manager; the in-process certificate minter requires `--selftest`. |
| Cedar authorization | Benchmark only. No Cedar policy is enforced on an API path. |
| PII masking | Used by MemTable writes; the no-match path returns the original string without allocation. |
| EPOLLET Cap'n Proto ingestion | Partial: IPv4-only, single-segment messages only, tested on Unix sockets, and limited to `TriTemporalEvent`. |
| Postgres bulk load | SQL and configuration support are tested; no live COPY test covers the full operation. |
| S3 upload | SHA-256-prefixed keys and sequential multipart upload; no live AWS upload test is included. |
| `pkg/durability/wal.go` | Alias layer over `internal/chaos` WAL, not an independent implementation. |
| `EpochCompactor` | No production importer; not part of current collection. |
| Origin payload and relay caches | Wired without an explicit size ceiling or LRU. Limited stale and superseded-entry cleanup is not a general capacity bound. |
| L0 growth | A checkpoint can create another L0 object. Object listing is uncapped; `MaxL0Files` caps query scanning of the uncompacted tail. Compaction and reaping control growth only when configured. |
| `pkg/codec120`, `pkg/durability120`, `pkg/pqecobench` | Benchmark-only packages with no node service role. |

### Telemetry

`internal/telemetry.Counter` is a sharded LongAdder whose stripes occupy separate cache lines. Its registry covers storage and query activity, compaction and pruning, reconciliation fallback, certificate rotation and revocation, post-quantum negotiation, hybrid acceptance, inter-region traffic, and mesh write timeouts.

`pkg/metrics.TelemetryBridge` enumerates that registry when constructed and reads cumulative values at collection time. New registry entries therefore require no counter-specific bridge branch. Dotted instrument names such as `supremum.l0.arrow_serial_bytes` map to `supremum_*` Prometheus names; the separate `sovereign_*` family belongs to the labelled recorder. `TestRealScrapeCumulativeNotDelta` guards against exporting only the delta since the previous scrape.

## 5. Workloads and limits

### Event history across replicas

The merge-union core fits event histories that must accept writes at multiple replicas and reconcile later without a central sequencer. The HAMT preserves causal dots, while Arrow files provide temporal history. Digest exchange reduces routine oversend but retains a full-delta fallback. Tests and receipts describe specific node counts and workloads; they do not establish an unlimited scale bound.

### Multi-region state

TLS peer links, causal dots, and digest-based anti-entropy support replicas that diverge during partitions and merge after healing. The multi-region receipt measures convergence from origin quiescence, not from the first client write and not general transaction latency. Local acknowledgement and remote convergence are separate events.

### Temporal and indexed telemetry

`AsOf` and `Range` suit telemetry and audit records that need valid-time and transaction-time views. The optional secondary index adds exact H3-cell and system-time selection across entities. It does not provide arbitrary geographic search, and the external H3 worker still has to be supplied and operated.

### High-rate ingest

Batch signature verification, early admission checks, off-heap core updates, and asynchronous storage flushing address different costs in a high-rate pipeline. The core allocation result does not describe the whole receive path, and the in-process receive benchmark excludes sockets and disk. Capacity planning needs measurements on the intended deployment.

### Partitioned and edge deployments

Local WAL recovery and merge-based reconciliation suit nodes that must restart or heal without a global coordinator. Kernel steering, page residency controls, and some transport experiments are not active by default. Operational security also depends on protecting the node environment, private keys, control listener, and diagnostics listeners.

## 6. Integration and operations

### 6.1 `cmd/sovereign-node`

The node binary wires the engine, receive gates, peer and control listeners, optional recovery and storage, telemetry, secondary indexing, and region-aware topology.

Listener, identity, and core flags:

```text
--bind                    peer TLS listener
--peers                   comma-separated peer addresses, optionally with region tags
--tls-cert --tls-key --tls-ca
                          leaf keypair and trust root
--node-id                 explicit 16-byte node ID; with --identity-seed, it must match the seed-derived ID
--identity-seed           Ed25519 seed used to derive node and signing identities
--metrics-addr            plain-HTTP liveness, metrics, and optional debug listener
--control-addr            mTLS client control listener; empty disables it
--pprof-addr              loopback-only pprof listener
--diag-profile            enable mutex and block profiling
--arena-mib               HAMT arena size in MiB
--admission-budget-ns     relay-depth admission budget
--selftest                run the development self-test
```

When `--identity-seed` and `--node-id` are both supplied, startup fails if the seed does not derive the configured node ID.

Gossip and protocol flags:

```text
--gossip-tick             anti-entropy interval
--batch-size              self-originated entries per signed batch
--lamport-absolute-slack  additional cold-peer Lamport allowance
--stratified-anti-entropy enable digest exchange
--digest-wait-timeout     per-peer digest response timeout
--digest-wait-adaptive    adapt the wait from observed response latency
--iblt-v2                 enable adaptive IBLT v2 exchange
--iblt-v2-min-buckets     set the v2 starting and decay floor
--defer-handler           defer or bound sends after digest failure
--defer-crossover         permit guarded full-keyset crossover after saturation
--mesh-write-timeout      close and redial a connection after a frame-write timeout
```

Recovery, storage, and export flags:

```text
--wal-path                     enable WAL persistence
--wal-checkpoint-interval      mutations between periodic checkpoints
--lsm-root                     snapshot and durable-tier root
--compaction-prune-enable      enable dominance pruning
--compaction-prune-horizon-ns  operator horizon floor
--compaction-prune-backoff-ns  distance behind the observed query frontier
--compaction-reap-enable       enable superseded L0 deletion
--compaction-reap-interval     reaper interval
--otel                         enable OpenTelemetry log export
--otel-interval                OpenTelemetry export interval
```

Certificate, topology, and index flags:

```text
--cert-rotation-enable         enable the leaf-rotation manager
--cert-rotation-poll           rotation poll interval
--cert-rotation-lifetime       lead time before leaf expiry
--crl-path                     PEM CRL used to reject revoked serials
--hybrid-sign                  sign local batches with Ed25519 and ML-DSA-65
--hybrid-verify                require both signatures on received frames
--region-aware                 enable regional peer selection
--self-region                  numeric region tag for this node
--region-fanout                cross-region targets per sweep
--gateways-per-region          gateway count per region
--partial-intra-view           rotate a bounded intra-region peer subset
--sweep-phase-jitter           apply deterministic per-node sweep offsets
--peer-dir                     out-of-band peer identity and key directory
--peer-auto-reconcile          derive routing IDs for unprovisioned peers
--secondary-index              enable H3 and system-time indexes and routes
--secondary-index-max-entities cap distinct indexed entities
```

The plain-HTTP listener exposes more than liveness when diagnostics are enabled: `/debug/memstats` is always registered there, while `/debug/state-fingerprint`, `/debug/responder-indegree`, and `/debug/heartbeat` depend on their environment switches. `/debug/pprof/` uses its separate loopback-only listener. Keep these interfaces off public networks.

Fault-injection environment variables are test controls, not a security boundary. Whoever controls a node's environment controls the node. In particular, test switches can change diagnostic state or disable safety checks; production deployments should start from a controlled, minimal environment. See [SECURITY.md](../SECURITY.md).

### 6.2 Client SDK

`sdk/sovereign/client.go` implements an mTLS HTTP client. `Dial` forces TLS 1.3, and `DialWithCerts` loads the certificate, key, CA, and server name from disk.

```go
func Dial(addr string, tlsCfg *tls.Config) (*Client, error)
func DialWithCerts(addr, certPath, keyPath, caPath, serverName string) (*Client, error)
func (c *Client) InsertLocal(key, val string) (dotHex string, err error)
func (c *Client) Get(key string) (GetResult, error)
func (c *Client) MerkleRoot() (string, error)
func (c *Client) Status() (NodeStatus, error)
func (c *Client) Metrics() (MetricSamples, error)
func (c *Client) RunDemo() error
func (c *Client) Close() error
func (s MetricSamples) Value(name string) (float64, bool)
func (s MetricSamples) Samples(name string) MetricSamples
```

`InsertLocal` returns after the origin applies and persists the local write according to its configuration; it does not wait for every peer. `GetResult.Payload` is available from the origin's payload cache. A peer that only reconstructed a delta has the digest but not the original value, so it returns an empty payload and a nonempty digest. `MetricSamples.Value` reports false for a missing or ambiguous metric name rather than silently choosing one sample.

The [SDK quickstart](sdk-quickstart.md) is the short client walkthrough. `examples/sdk` demonstrates that API. `examples/embed` exercises the older exported lock-free stacks, not the δ-CRDT HAMT engine.

### 6.3 HTTP surfaces

| Endpoint | Transport | Behavior |
|---|---|---|
| `/livecheck` | Plain HTTP on the metrics listener; optionally mTLS on the control listener | Node liveness and selected runtime status. |
| `/metrics` | Plain HTTP; optionally mTLS | Prometheus metrics from the recorder and telemetry bridge. |
| `/v1/insert` | mTLS | One local insert through `Gossiper.InsertLocalEvents`; `Bridge.PutLocal` when a WAL is configured, otherwise the in-memory `InsertLocal` branch. |
| `/v1/batch-insert` | mTLS | Multiple local inserts through `Gossiper.InsertLocalEventsBatch`. |
| `/v1/get` | mTLS | Current live value on the origin, digest-only result on a peer without the payload. |
| `/v1/query` | mTLS | `Resolver.AsOf`; returns 503 when no resolver is configured. |
| `/v1/range` | mTLS | `Resolver.Range` with interval intersection and the configured row cap. |
| `/v1/merkle` | mTLS | Current `MerkleRootFromShards` result plus `commit_in_flight`, commit count, and total and maximum commit-append timing fields. |
| `/v1/querybyh3` | mTLS | Exact-cell query, registered only with the secondary index. |
| `/v1/querybysystime` | mTLS | System-time query, registered only with the secondary index. |
| `/debug/memstats` | Plain HTTP | Runtime memory and selected recovery statistics. |
| `/debug/state-fingerprint` | Plain HTTP, environment-gated | Full-state fingerprint diagnostics. |
| `/debug/responder-indegree` | Plain HTTP, environment-gated | Digest responder occupancy diagnostics. |
| `/debug/heartbeat` | Plain HTTP, environment-gated | Digest exchange timing diagnostics. |
| `/debug/pprof/` | Separate loopback HTTP listener | Go execution profiles; mutex and block profiles require explicit enablement. |

Temporal query responses include payload digests, not durable payload bodies. The live origin cache and the durable Arrow index have different value-availability contracts. An insert with no explicit valid-time end receives the open-ended sentinel used by the engine.

### 6.4 Local mesh and operations

[`scripts/local-mesh.sh`](../scripts/local-mesh.sh) is the shortest complete node exercise. It uses `cmd/mesh-bootstrap` to create development identities and a peer directory, starts three nodes on loopback, and uses `cmd/convergence-gate` to check convergence. `CRASH=1` adds an origin `kill -9` and WAL recovery check. Loopback regions are test topology labels, not wide-area measurements.

For a manually operated node, provision a CA and leaves with `pkg/crypto` or an existing PKI, set `--tls-cert`, `--tls-key`, and `--tls-ca`, then configure `--bind`, `--peers`, `--metrics-addr`, and `--control-addr`. Add `--wal-path` and `--lsm-root` for persistent recovery. Pruning, reaping, hybrid signatures, secondary indexing, region-aware routing, and adaptive reconciliation remain separate choices.

### 6.5 Direct engine use

Import the engine with an alias to distinguish `pkg/sync` from the standard library. This complete program inserts on one engine, reconciles into a second engine, and applies the inserted entry through the wire decoder. `InsertLocal` assigns the origin and dot on its copy of the entry, so the caller copies those fields back before building the wire event. Both the generated digest and delta must be released.

```go
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

func main() {
	scratch, err := os.MkdirTemp("", "sovereign-direct-engine-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(scratch)
	eng.DataDir = scratch

	const arenaSize = 64 << 20
	sourceID := [16]byte{1}
	remoteID := [16]byte{2}
	source, err := eng.NewDeltaCRDTEngine(sourceID, 0, arenaSize)
	if err != nil {
		panic(err)
	}
	defer source.Close()
	remote, err := eng.NewDeltaCRDTEngine(remoteID, 0, arenaSize)
	if err != nil {
		panic(err)
	}
	defer remote.Close()

	entityID, payload := "sensor", "value"
	now := time.Now().UnixNano()
	entry := eng.CRDTEntry{
		PayloadDigest:  sha256.Sum256([]byte(payload)),
		SystemTime:     now,
		ValidTimeStart: now,
		ValidTimeEnd:   now + int64(time.Hour),
		AssertionTime:  now,
		DecisionTime:   now,
		H3Index:        1,
	}
	dot := source.InsertLocal(entityID, entry)
	entry.OriginNodeID = sourceID
	entry.DotNodeID = dot.NodeID
	entry.DotCounter = dot.Counter

	remoteDigest := remote.GenerateDigest()
	delta := source.GenerateDelta(remoteDigest)
	remoteDigest.Release()
	remote.Join(*delta)
	delta.Release()

	wire, err := eng.BuildCRDTDeltaEvent(entityID, payload, entry)
	if err != nil {
		panic(err)
	}
	if err := remote.ApplyCRDTDeltaEvent(wire); err != nil {
		panic(err)
	}

	fmt.Printf("roots match: %t; remote inserts: %d\n",
		source.MerkleRootFromShards() == remote.MerkleRootFromShards(),
		remote.Stats()["entries_inserted"])
}
```

For WAL-backed writes and recovery:

```go
wal, err := durability.OpenWAL(path)
bridge := durability.NewBridge(engine, wal, checkpointInterval)
dot, err := bridge.PutLocal(entityID, payload, entry)
err = bridge.AppendCheckpoint()

engine, wal, replayed, err := durability.RecoverEngine(nodeID, walPath, arenaSize)
engine, wal, replayed, witness, err := durability.RecoverEngineWithSnapshot(
    nodeID, walPath, store, arenaSize,
)
```

For durable queries, construct the default configuration as a function call and add a live source when required:

```go
cfg := database.DefaultResolverConfig()
cfg.LiveSource = liveSource
resolver := database.NewResolver(lister, downloader, alloc, bucket, cfg)
row, err := resolver.AsOf(ctx, entity, validTime, txTime)
rows, truncated, err := resolver.Range(ctx, entity, vLo, vHi, txTime)
```

## Further reading

- [Architecture](architecture/1_ARCHITECTURE.md) for the system-level design.
- [Decision records](architecture/adr/README.md) for the reasons behind individual choices.
- [Evidence](evidence/README.md) for measured claims, conditions, and reproduction commands.
- [Security](../SECURITY.md) for reporting and deployment boundaries.

