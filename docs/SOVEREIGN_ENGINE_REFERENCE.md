# Sovereign Engine — Defining Architecture Document

> Module: `github.com/hr18vk/sovereign` · Go 1.26.1 · Target silicon: ARM64 (AWS Graviton, Neoverse V2 / Cortex-A76-class)
> The source is the primary source of truth: where this document and the code disagree, the code wins. Where a feature is production-wired, opt-in, dormant, bench-only, or a stub, it is labeled as such.

---

## 1. Executive Summary / Overview

The Sovereign Engine is a planetary-scale, zero-garbage-collection, off-heap **δ-CRDT database engine**. It solves a specific, hard data problem: how to maintain a single, convergent, causally-attributable view of state across a large fleet of mutually-distrusting nodes that partition, heal, reorder, duplicate, and drop messages — while keeping the write/read hot path free of allocator pressure, futex stalls, and cache-line contention, and while being post-quantum-secure from day one.

### The data problem it addresses

Most operational databases model state as either a mutable row (last-writer-wins, single site of truth) or an append-only operational log (event sourcing with a replay-based read model). Neither handles the planetary edge case well: a mutable row conflicts under concurrent multi-region writers; an operational log conflates *what happened* with *what the system believed to be true at a given moment*. The Sovereign Engine instead models state as a **tri-temporal CRDT** — keyed simultaneously by **system_time** (when the system observed the fact), **valid_time** (when the fact was true in the real world), and **assertion_time** (the causal/assertion epoch under which the fact was claimed) — with a fourth **decision_time** carried on the wire. State is an Add-Wins Set lattice element folded by a merge-union `Join`, so concurrent writers converge without coordination and without losing history.

The durable tier materializes this tri-temporal lattice as an off-heap LSM tree (SkipListArena MemTable → per-entity Arrow IPC L0 files → merged L1 files) with bitemporal point-in-time (`AsOf`) and interval (`Range`) queries, a read-your-writes live δ-CRDT HAMT merge, and tri-temporal dominance pruning with an auto-inferred garbage-collection horizon.

### Operating envelope and headline numbers

| Metric | Value | Source / caveat |
|---|---|---|
| CRDT apply hot path (CORE microbench, NOT ingest) | 50,736,038 ops/s (gate-passing low-end) to 68,278,197 ops/s (**measured on this tree, 2026-09-03**, c8g.8xlarge, Graviton4 CPU part 0xd4f, Go 1.26.1) at GOMAXPROCS=32, ARM64 Graviton (c8g/Graviton4); range 50.7M-68.3M | Cache-line law post-mortem, `docs/architecture/6_ENGINEERING_POST_MORTEM.md`; the load-bearing measured contrast is **1.1M ops/s with false sharing vs 50.7M-68.3M ops/s without** |
| Hot-path allocations | **0 allocs/op** for `HAMT.Set` | `TestHotPathZeroAllocations` (`pkg/sync/physics_test.go`); the `raceEnabled` build-tag pair self-skips the gate under `-race` (shadow-memory instrumentation inflates `AllocsPerRun`) |
| End-to-end `Join` benchmark | ~5.5M ops/s, ~8174 ns/op, 472 B/op, 6 allocs/op | `BenchmarkCRDTEngine_Join` at 2 GiB arena (`crdt_test.go`); 64 MiB arena panics `HamtArena: OOM` at ~1M ops due to reclamation lag |
| Production ingest (receive path) | **5.7M–6.0M deltas/sec** @32c (Ed25519 verify + apply + envelope) | Measured on this tree (c8g.8xlarge, Go 1.26.1); the production receive rate, distinct from the in-process core microbench above |
| Ed25519 verify cost | **~60.19 µs/op** | The crypto-dominated ingress cost; the entire cheap-gate stack exists to drop forged frames *before* this verify |
| Post-quantum (default build) | X25519MLKEM768 key exchange by default; hybrid Ed25519+ML-DSA-65 signing available. ML-DSA-65 sig = 3309 B, pub = 1952 B (**51.7×** sig inflation vs Ed25519 64 B on a 120 B frame) | `filippo.io/mldsa`; in the default build — not a preview |

**Gear-honesty disclosure:** the core headline is the cache-line-law measured contrast at GOMAXPROCS=32 — **re-measured on this tree 2026-09-03: 68,278,197 ops/s 32c** (c8g.8xlarge, Graviton4 CPU part 0xd4f, Go 1.26.1). The majority of *component-level* benches in the tree are honestly measured on a **4-core 0xd40 (Cortex-A76-class / Graviton-3-era) gear**, and carry a `_4c` tag; a `_32c` tag is honest measured gear ONLY where a c8g run is cited. A gear-honesty test gate (`TestGate_GearHonesty` and per-package variants) actively forbids relabeling a 4-core number as 32-core. Numbers are reported here as numbers, never as adjectives.

### Headline differentiators (each grounded in a real mechanism)

1. **Tri-temporal CRDT state** — `(system_time × valid_time × assertion_time)` keyed lattice, materialized as a 40-byte composite key + 9-field Arrow IPC rows. No competitor offers this.
2. **Off-heap, zero-GC hot path** — state lives in a `mmap`'d segregated-slab `HamtArena` (17 size classes, 256-way sharded Treiber free-lists); `NodePtr` is a GC-invisible `uintptr`; even the `*HAMT` wrapper is arena-allocated. The memory law is enforced by `TestHotPathZeroAllocations`.
3. **128-byte cache-line discipline** — every contended atomic is `CacheLinePad`-isolated; `ElimSlot`, `secShard`, and `EBRManager.globalEpoch` are each exactly one or two cache lines, verified by `unsafe.Sizeof` and `TestMemoryLayoutAnalysis`. The measured cost of violating this is the 1.1M-vs-50.7M-68.3M cliff above.
4. **CAS + EBR, no futex on the write path** — `Join`/`InsertLocal`/`NextDot` use compare-and-swap and epoch-based reclamation with hazard pointers only; the only `sync.Mutex` (`persistMu`) guards disk fsync in a decoupled background worker, off the hot CAS path.
5. **H3 spatial CRDT** — `H3Index uint64` carried on every `CRDTEntry` and in the Arrow schema; geocoding is offloaded to an isolated C++ worker over a `memfd`-backed SPSC shared-memory ring (no syscalls/futexes on the hot path).
6. **Post-quantum from day one** — X25519MLKEM768 key exchange in the default build plus hybrid Ed25519+ML-DSA-65 (FIPS 204) signing, alongside a hedged (randomized-nonce) Ed25519 signer that stays compatible with the unchanged verifier.
7. **Honest-negative measurement culture** — every bench carries a gear tag; honest negatives (e.g. eBPF steer slower than hash-fallback at single-box scale) are recorded verbatim as "ACCEPTED-with-NEGATIVE-perf" rather than relabeled; the SDK honestly reports the originator-vs-peer payload boundary (a peer `Get` returns the digest, never a value it does not have).

---

## 2. Core Architecture & Design

The engine is a layered system organized around a single frozen δ-CRDT core, wrapped by an ingress gate stack, a durable LSM tier, a replication mesh, and operations/developer surfaces. This section walks the layered package architecture and then traces the request/data flow end to end, naming real packages, types, and functions.

### 2.1 Layered package architecture

| Layer | Packages | Role |
|---|---|---|
| **CRDT core** | `pkg/sync` (the engine's *own* `pkg/sync`, not the stdlib) | The δ-CRDT engine: sharded lock-free HAMT, Lamport dot minting, merge-union `Join`, IBLT/strata set reconciliation, EBR + hazard-pointer reclamation, wire-integrity seam, lock-free stack candidates. This is the write/read hot path everything else builds on. |
| **Storage & durability** | `internal/database`, `pkg/durability` | Off-heap jemalloc-backed SkipListArena MemTable, async L0 flush to per-entity Arrow IPC in S3-style object storage, L0→L1 compaction with tri-temporal dominance pruning, L0 reaper, bitemporal `Resolver` (`AsOf`/`Range`) + read-your-writes `LiveSource` merge, Postgres bulk-load. `pkg/durability` owns the WAL, checkpoint, snapshot, bounded-recovery, and the `Bridge` write-through seam. |
| **Mesh & replication** | `pkg/mesh`, `pkg/clock`, `pkg/admission` | TLS 1.3 peer gossip, anti-entropy sweep (oversend / batched / stratified), JSON-over-mTLS control port, convergence probe. `pkg/clock` is the Byzantine HLC physical-bound cap (first ingress gate, sub-µs). `pkg/admission` is the per-peer Sybil-burst token bucket. |
| **Receive & transport** | `pkg/receive`, `pkg/transport` | Length-prefix frame reassembly, gate-stack composition (first production caller of `Join`), relay-forward egress, edge-triggered epoll ingress, eBPF `SK_REUSEPORT` steering, TLS 1.3 mTLS config with SIGHUP rotation, zero-copy egress boundary (copy-mmap-to-heap → `runtime.Pinner` → `MSG_ZEROCOPY`). |
| **Identity & crypto** | `pkg/identity`, `pkg/crypto`, `internal/crypto` | ZIP-215 Ed25519 verify gate, origin→pubkey `Directory`, hedged EdDSA signer, hybrid Ed25519+ML-DSA-65 signing, dev-mesh x509 CA, zero-GC PII masking. |
| **Attribution & telemetry** | `pkg/attribution`, `internal/telemetry`, `pkg/metrics` | Relay-provenance envelopes + batch/digest dispatch (third admission gate), zero-GC sharded LongAdder counters (19 named instruments), Prometheus registry + `TelemetryBridge`. |
| **Network, spatial, capnp** | `internal/network`, `internal/transport`, `internal/spatial`, `api/capnp/api/capnp` | EPOLLET Cap'n Proto ingestion server, jittered-backoff HTTP client + bounded lock-free pool, SHA-256-prefix-sharded S3 uploader, memfd SPSC H3 ring + `EpochBatcher`, generated capnp wire bindings. |
| **Chaos** | `internal/chaos` | Semantic Byzantine injector, in-memory `VirtualNet` partition fabric, engine-side WAL, supervisor/worker process-crash survival, the verification guards. |
| **Operator/developer** | `cmd/sovereign-node`, `sdk/sovereign`, `examples/embed`, `examples/sdk` | The production binary, the client SDK, and the examples. |

### 2.2 The CRDT core (`pkg/sync`)

The heart of the engine is `DeltaCRDTEngine` (`crdt.go:141`). Its load-bearing fields:

- `shards []shardRoot` + `routeSeed maphash.Seed` — the sharded root CAS, default 256 shards (`defaultShardCount`); each `shardRoot{ptr atomic.Pointer[HAMT]}` is a per-shard CAS locus; `routeShard(entityID)` hashes the entity ID to pick the shard. This eliminates the single-root CAS bottleneck.
- `lamportCounter atomic.Uint64` + `lastSavedCounter atomic.Uint64` (Cache Line 1) — Lamport dot minting + monotone persistence watermark.
- `arena *HamtArena`, `ebr *EBRManager` (Cache Line 2, read-only after init) — off-heap allocation + safe memory reclamation.
- `persistCh chan uint64` (unbuffered) + `persistWorkerWg` + `persistStopOnce` + `persistWorkerReady`/`persistWorkerParked` (cap-1) — the decoupled persist worker; the only `sync.Mutex` (`persistMu`) guards disk fsync in this worker, not the hot CAS path.
- `deltaPool sync.Pool` — the zero-GC delta recycling.
- `observedInboundRateBits atomic.Uint64` — IEEE-754 bits of an EWMA inbound rate feeding the Lamport-skew bound.

The lattice element is `CRDTEntry` (`hamt.go:35`), **exactly 120 bytes, 8-byte aligned, zero padding** (pinned by `TestCRDTEntry_SizeAndAlignment`). It encodes the full tri-temporal + spatial + causal-dot tuple:

```
PayloadDigest   [32]byte  @0   (SHA-256 of payload)
OriginNodeID    [16]byte  @32  (who originated the dot)
DotNodeID       [16]byte  @48  (who minted the dot)
DotCounter      uint64    @64  (Lamport counter — the causal dot)
SystemTime      int64     @72  (when the system observed the fact)
ValidTimeStart  int64     @80  (when the fact became true)
ValidTimeEnd    int64     @88  (when the fact ceased to be true)
AssertionTime   int64     @96  (causal/assertion epoch)
DecisionTime    int64     @104
H3Index         uint64    @112 (spatial index)
```

`CausalDot{NodeID [16]byte; Counter uint64}` (`hamt.go:25`) is the unique mutation-event id. `CRDTDelta{OriginNodeID [16]byte; Entries Seq}` (`crdt.go:1522`) carries a push-based iterator `Seq func(yield func(entityID string, entry CRRTEntry) bool)` — zero-alloc, no slice materialization — and `(*CRDTDelta).Release()` returns it to `deltaPool`.

The `HAMT` (`hamt.go:121`) is a persistent, immutable, path-copying trie (Add-Wins Set keyed by entity ID); `Set`/`Delete` return a new root with path-copied nodes and structural sharing. Interior `HamtNode` carries `refCount atomic.Int32`, `bitmap uint32`, `childrenPtr/entriesPtr NodePtr`, a cached `merkleHash [32]byte` (→ O(1) `MerkleRoot()`), and `nextFree NodePtr`. The 32-byte `hamtLeaf` rebuilds Go views via `unsafe.Slice`/`unsafe.String` over the arena.

The `HamtArena` (`hamt_arena.go:168`) is the `mmap`'d (`MAP_ANON|MAP_PRIVATE`) off-heap allocator: 17 size classes (1 node class + 16 var classes), `nodeFreelist [256]` and `varFreelist [16][256]` sharded Treiber free-lists (the three hottest CAS sites are sharded 256-way to defeat CAS-storms), four `CacheLinePad`-isolated route counters, and a `bumpOffset atomic.Uint64`. `NodePtr` is a `uintptr` — GC-invisible, the foundation of true zero-GC.

EBR + hazard pointers live in `reclamation.go`: `EBRManager.globalEpoch` (CAS'd by `AdvanceEpoch`, on its own cache line), a 3-epoch × 256-shard retired ring `retired [3][256]RetiredList` with a 2-epoch grace window, and `Participant.Enter`/`DetachAndProtect(slot,ptr)` for hazard-pointer publication. Retired nodes reclaim only after the grace window proves zero lingering readers, making the slab free-lists ABA-immune (proven by `TestHEBRDetachAllowsEpochAdvance`).

The wire-integrity seam (`crdt_reconstruct.go`, `crdt_reconstruct_skew.go`) is the gate every inbound element crosses before `Join`: `ReconstructEntry` cross-validates `PayloadDigest == SHA-256(payload)` and reads all 12 contract fields off the capnp frame (returning typed `WireIntegrityError` with `Kind` ∈ `WireIntegrityDigestMismatch`/`FieldUnread`/`DotOriginMismatch`/`LamportSkewPoisoning`); a `DotNodeID!= OriginNodeID` attribution check is enforced; `ReconstructEntryWithSkewBound` rejects far-future dots (`DotCounter > MaxAcceptableDotCounter(snapshot)`, strict) with saturation arithmetic, closing the Byzantine far-future-dot and disk-state-poisoning attacks. `ReconstructedEntry` is returned **by value** (ADR-0014) to kill a per-element heap alloc.

Set reconciliation uses `IBLT` (`iblt.go`: XOR-accumulator buckets, 0.00% false-positive purity) and `StrataEstimator` (32 fixed IBLTs, 80 buckets, k=3) to compute the symmetric-difference size that drives `DynamicIBLTSize(dEst) = dEst * ibltSafetyFactor` floored at `minDynamicBuckets=128`. `iblt_wire.go` is a deliberate little-endian (non-capnp) codec to keep IBLT off the frozen capnp schema surface.

### 2.3 Storage & durability (`internal/database` + `pkg/durability`)

The durable tier accepts `TriTemporalEvent`s (entity × system_time × valid_time × assertion_time + H3 + payload), buffers them in a jemalloc-backed pointerless `SkipListArena`, asynchronously flushes frozen arenas to per-entity Arrow IPC files, runs background L0→L1 compaction with tri-temporal dominance pruning, and answers bitemporal queries.

- **`JemallocAllocator`** (`memory_allocator.go`): CGO `mallocx(size, MALLOCX_ALIGN(64)|MALLOCX_ZERO)` → 64-byte cache-line aligned + zeroed; sized free via `sdallocx`; `bytesAllocated atomic.Int64` enforces the MemTable 256 MB ceiling. Implements `arrow.memory.Allocator`.
- **`SkipListArena`** (`skiplist_arena.go`): pointerless, array-backed, lock-free. `nodeSize=64` (cache-line aligned), `maxHeight=11`, `pValue=4` (geometric 1/4 height prob), `keySize=40`. Concurrency via `casNodeNext` on next pointers. `Seek` = Put descent without splice; proven correct (ADR-0028) but **dormant** (not wired into `scanWindowRecordBatch`).
- **40-byte composite key** (`keySize=40`): `[hash16 | sysTime8 | validTimeStart8 | assertTime8]` all BigEndian, so `bytes.Compare` == lexicographic == numeric. `hash16` = truncated SHA-256 of EntityID (128-bit).
- **`MemTable`** (`memtable.go`): `mu sync.RWMutex` guards the SkipListArena pointer swap (freeze→replace); `flushSem chan struct{}` (cap 4) bounds frozen arenas in flight (backpressure); async double-buffered flush — a full arena is frozen (immutable), a fresh one swapped in under the write lock, then the frozen one streams to L0 off the write path.
- **`L0Flusher`** (`l0_flusher.go`): serializes a frozen SkipListArena → per-entity Arrow IPC → S3. The `ArrowSchema` is 9 IPC fields: `entity_id_hash` (FixedSizeBinary 16), four `Timestamp ns UTC` fields, `h3_index` (Uint64), `payload_digest` (FixedSizeBinary 32), `entity_id` (LargeBinary), `payload` (Binary). `MaxValidTimeEndNs int64 = 9_000_000_000_000_000_000` (9e18 ns ≈ year 2253, below `MaxInt64`) is the open-ended valid-time sentinel — it replaced a deleted `time.Date(9999,...)` whose `.UnixNano()` overflowed int64 to a negative value, silently hiding rows from AsOf's Filter3.
- **`L1Compactor`** (`l1_compactor.go`): per-entity L0→L1 merge + `DominancePrune` + T_gc auto-inference. `CompactionConfig` carries `L0FilesPerEntityTrigger` (def 64), `MaxL1FilesPerEntity` (def 4), `EnableDominancePruning` (def **false**, opt-in), `PruningHorizonInt64Ns` (T_gc floor), `PruneBackoffInt64Ns` (backoff).
- **`Resolver`** (`query.go`): bitemporal `AsOf`/`Range` + `LiveSource` live-merge. `ResolverConfig` carries `LiveSource` (nil = durable-only, byte-identical to), `MaxL0Files` (def 1000), `MaxRangeRows` (def 4096; 0 = UNLIMITED, deliberately not coerced up), `EnableFirstSysSkip` (def true; gates both file and manifest skips).
- **`L0Reaper`** (`l0_reaper.go`): cross-entity superseded-L0 disk-reclaim sweep, **opt-in** (`--compaction-reap-enable`, default false). Stages A–F verify each manifest's `l1Key` is still present via `Download` before deleting any L0; any download failure ⇒ preserve.
- **`EpochCompactor`** (`compactor.go`): **DEAD** — zero production importers; retained as a documented dead-end (not wired). The real GC path is DominancePrune + L0 reaper, not tombstones.

`pkg/durability` is the crash-recovery surface:

- **`Bridge`** (`bridge.go`): the write-through seam — `PutLocal` does `engine.InsertLocal` + WAL fsync + (optional) checkpoint; the single chokepoint through which a locally-originated mutation enters both the in-memory HAMT and the fsync-per-mutation WAL. ACK-before-durability: a zero `CausalDot` from `PutLocal` (WAL fsync failed) → the control port returns **503, not a lying 200+zero-dot**.
- **`OpenWAL`/`ReplayWAL`** (`wal.go`): a **pure alias layer** re-exporting `internal/chaos` WAL with zero own logic (every symbol maps 1:1 via Go type/const/func aliasing) — so the production WAL surface is only as proven as the chaos harness.
- **`RecoverEngine`/`RecoverEngineWithSnapshot`** (`recovery.go`): full WAL replay or bounded snapshot+tail. `SnapshotStore.SnapshotExists` is the cheap probe gating the bounded branch; `RecoveryWitness` reports which branch ran and why.
- **`SnapshotImage`** (`snapshot.go`): a dot-bearing snapshot image (`snapshotMagic="SNSP"`, 120-byte big-endian `CRDTEntry` wire per record) + Arrow index → O(post-checkpoint) recovery instead of O(writes-since-boot).
- **`LocalFS`** (`localfs.go`): local-FS shim implementing the four S3 interfaces (`S3Lister`/`S3Downloader`/`S3Uploader`/`S3Deleter`), used by tests and single-node deployments.

### 2.4 Mesh & replication (`pkg/mesh` + `pkg/clock` + `pkg/admission`)

`pkg/mesh` is the production peer-to-peer gossip layer over the TLS 1.3 transport. The `Gossiper` (`gossip.go`) owns the `PeerSet`, a `payloadCache`, the engine, the identity `Directory`, and ~10 setter-driven seams (`SetBridge`, `SetBatchSize`, `SetStratifiedAntiEntropy`, `SetStratifiedFallbackReporter`, `SetDigestWaitTimeout`, `SetRoundReporter`). `AntiEntropySweep` sorts peer IDs deterministically and, per peer, generates a sweep delta and ships it (batched via `ShipBatch`/`shipBatchedDelta`, or per-frame via `shipDelta`), then `delta.Release()`s.

`pkg/clock`'s `IngressHLCScalarCap` (`admission.go`) is the **first ingress gate** — a Byzantine HLC physical-bound cap that drops future-skewed frames (`incomingPhysicalUSec - localPhysicalUSec > 2000 us`) in sub-µs *before* the ~71.4 µs Ed25519 verify. On accept it calls `engine.AdvanceLamportTo(incomingLogical)` unconditionally (the engine's max-CAS no-ops stale logicals). `maxDriftEpsilon=2000` is unit-locked by a static guard plus compile-time array guards.

`pkg/admission`'s `PeerBucket` (`ewma.go`) is the per-peer Sybil-burst rate-isolation token bucket — 16 shards each `sync.Mutex` + `map[PeerBucketKey]*PeerEWMA`, sharded by the low 4 bits of the first byte of the 32-byte Ed25519 pubkey. An attacker saturates only its own shard (`TestPeerBucket_SybilIsolation`). The EWMA (`alpha=0.1`) advances on Counter-*delta* (per-frame advancement, not absolute), so a fresh peer is never penalized.

`pkg/mesh`'s `ControlServer` (`control.go`) exposes the JSON-over-mTLS control port: `/v1/insert|get|query|range|merkle`, `/livecheck`, `/metrics`. It honestly returns **503 (not 404)** when the resolver is nil, and the 503 guard runs *before* param validation. `handleGet` uses a single-snapshot discipline (one `State().Get`, one `selectLatestDot`, one `PayloadForDot`) so payload and digest derive from the same entry (no TOCTOU).

### 2.5 Receive & transport (`pkg/receive` + `pkg/transport`)

`pkg/receive`'s `Receiver` is the gate-stack composer and the **first production caller of `Join`**. The ingress pipeline is:

```
[wire]
  → FrameReader.ReadFrame (length-prefix reassembly, [uint32 frameLen BE][envelope])
  → 3-way dispatch (batch "SBAT" / digest "SDST" / relay 0x02|0x03)
  → RelayEnvelope.Open: readLastHop (O(1) raw-byte read) → readGateFields (v3 O(1) header mirror)
  → PeerBucket.Accept        (3.1 rate, ~36 ns)
  → IngressHLCScalarCap.Admit (3.0 clock, calls engine.AdvanceLamportTo on accept)
  → RelayEnvelope.Open(maxHops) (3.2 depth O(1), then N outer Ed25519 Verifies)
  → Directory.Lookup          (origin→pubkey)
  → identity.VerifyCRDTFrame  (~60 µs inner origin verify)
  → crossCheckGateFields      (§4 accept-path security guard)
  → engine.ApplyCRDTDeltaEvent / ApplyCRDTDeltaBatch  (Join)
```

Cheap gates run *before* expensive verify — a forged deep/rate/clock frame drops in nanoseconds with **zero Ed25519 Verifies** (the `VerifyHookCount==0` guards). `HandleBatchFrame` amortizes one Ed25519 over N deltas (60.19 µs → 60.19/N µs/delta) and decrements the rate bucket once per batch on the origin's monotonic `OriginSeq`.

`pkg/transport` owns the egress zero-copy boundary (`TransmitHeapBuffer`: `make([]byte,len) → copy(heap,mmap) → Pin(&heap[0])`) — it **never** pins the mmap region (Pin on a non-Go address is a documented silent no-op, empirically proven by `TestTransmitHeapBuffer_MmapPinIsNoOp_Physics`), and a source guard (`detectForbiddenPin`) textually bans any Pin not on a `make([]byte)` var. `TLSConnections` (`tls_transport.go`) is 1.3-only mTLS (`Min==Max==VersionTLS13`, `RequireAndVerifyClientCert`) with SIGHUP leaf rotation. `KernelFanout` (`ebpf_reuseport.go`, `//go:build ebpf_kernel`) loads a live `BPF_PROG_TYPE_SK_REUSEPORT` program keyed on `OriginNodeID` via `BPF_MAP_TYPE_SOCKHASH` (cilium/ebpf v0.22.0, the first production-loadable eBPF dep) — the silicon form of the in-process `ReusePortFanout.SelectRoute`. Route selection keys **only** on plaintext `OriginNodeID`, before any crypto (`TestNoCryptoBeforeRoute`).

### 2.6 Request/data flow (end to end)

**Write/egress path** (locally-originated mutation):

```
sdk.Client.InsertLocal(key,val)  ──HTTPS/mTLS──▶  ControlServer.handleInsert
   → Gossiper.InsertLocalEvents            (gossip.go:1210; NEVER engine.InsertLocal directly)
      → bridge.PutLocal(entityID, payload, entry)   (bridge.go)
           ├─ sha256(payload) stamped into entry.PayloadDigest BEFORE engine folds it (an order guard)
           ├─ engine.InsertLocal  →  NextDot() → sharded root CAS → HAMT.Set (0 allocs/op) → EBR retire
           └─ WAL.AppendMutation + f.Sync()  (fsync-per-mutation; ACK only after durable)
        → payloadCache.record
        → (tick) Bridge.AppendCheckpoint  → dot-bearing snapshot image + l0/{hex8}/{sysNs}.arrow
   → MemTable.Write  →  async double-buffered flush  →  L0Flusher.FlushArenaToIPC  →  Arrow IPC in S3/LocalFS
   → (scheduler) L1Compactor.Compaction  →  DominancePrune (opt-in)  →  L0Reaper.Reap (opt-in)
```

**Replication/ingress path** (peer-originated delta):

```
peer TLS conn  →  FrameReader.ReadFrame  →  3-way dispatch
   → PeerBucket.Accept  →  IngressHLCScalarCap.Admit  →  RelayEnvelope.Open(maxHops)
   → Directory.Lookup  →  VerifyCRDTFrame  →  crossCheckGateFields
   → engine.ApplyCRDTDeltaEvent / ApplyCRDTDeltaBatch
        → ReconstructEntry[WithSkewBound]  (wire-integrity + skew bound)
        → Join  (frozen merge-union per-shard CAS; crdt.go:1173)
        → HAMT path-copying Set  →  EBR retire retired nodes through 256-way sharded free-lists
   →  onClockAdvance fires ONLY when post > preAdvance → WAL.AppendClockAdvance (kills the fsync bomb on stale re-receive)
```

**Read path** (`/v1/query` or `/v1/range`):

```
ControlServer.handleQuery / handleRange  (503 if resolver nil, BEFORE param validation)
   → Resolver.AsOf(ctx, entity, validTime, txTime) / Range(ctx, entity, vLo, vHi, tx)
        ├─  QueryTxTimeFrontier = monotone atomic MAX of observed txTime (feeds T_gc inference)
        ├─ LiveSource.LiveRead(ctx, entityID, txTimeNs)  ( read-your-writes; EBR-pinned live HAMT)
        │    → engineHAMTAdapter: ebr.Acquire → participant.Enter → Filter2 (SystemTime<=txTime) → defer Release
        ├─ durable tier: list L0+L1 per entity, (/25) skip files/manifests whose firstSys STRICTLY > txTime
        ├─ Filter1 (full-16-byte hash) · Filter2 (SystemTime<=txTime STRICT) · Filter3 (half-open valid-time) · Filter4 (entity-id collision guard)
        └─ live vs durable dedup by (sysTime, digest); nil/empty live is NOT an error
   → response echoes PayloadDigest verbatim; deliberately NO payload field (digest-is-not-value; Law V)
```

**Gossip/anti-entropy** (`SweepLoop`):

```
AntiEntropySweep  (sorts peerIDs deterministically)
   per peer:
     ├─  oversend: GenerateDelta(empty IBLT) — one-round CRDT-idempotent convergence, pays N*entries verify
     ├─  batched:  BuildCRCTDeltaBatch — one Ed25519 over N deltas (amortizes 60.19 µs → 60.19/N)
     └─  stratified: register recv chan → send StrataEstimator → block on recv (digestWaitTimeout)
           → GenerateDeltaStratified(remoteSE) for minimal delta ∝ |A−B|; falls back to oversend on timeout
     shipBatchedDelta / shipDelta  →  peers.Publish (TLS)  →  delta.Release() (EBR epoch pin drop)
   → selectLatestDot total order: max DotCounter, ties → smallest DotNodeID (bytes.Compare) — deterministic across iteration order
   → stampConvergence (sweep 1 advances prevRoot, sweep 2 stamps convergence, sweep 3 does NOT re-stamp)
```

**Clock attribution**: `NextDot` mints `{NodeID; Counter}` via monotone CAS on `lamportCounter`; `AdvanceLamportTo(remoteCounter)` adopts a remote counter (monotone-CAS-shaped). **WAL-replay invariant (CORRECTED 2026-08-31, ADR-0045): replay RESTORES each mutation at its WAL-recorded `(DotNodeID, DotCounter)` and never re-mints**; the post-checkpoint tail is cut by WAL RECORD SEQUENCE, not by a counter comparison. Both re-minting seeds (`LamportHigh - len(Mutations)`, `firstMutation.Counter-1`) are REFUTED — WAL append order need not equal mint order. Foreign `AdvanceLamportTo` is still recorded as `WALRecClockAdvance=0x03` and replayed; because dot-union `Join` is commutative and `AdvanceLamportTo` is a monotone max, restored state is order-independent and only the final clock is order-sensitive (a max).

### 2.7 Cross-subsystem interactions

The architecture's joints are where the laws compound:

- **receive → CRDT apply → HAMT → WAL → compaction**: the `Receiver` is the *first production caller* of the frozen `Join`; a corrupt element is rejected by the wire-integrity seam *before* `Join`, so it never partial-applies earlier batch elements (atomic-reject). Accepted elements flow into the sharded root CAS, retired nodes reclaim through EBR, the WAL records the mutation (and any clock advance) for crash recovery, and the MemTable flushes asynchronously to the durable tier where compaction eventually prunes.
- **gossip → mesh → clock**: the `Gossiper` drives `AntiEntropySweep` over `PeerSet`; the clock cap (`IngressHLCScalarCap`) sits at the transport seam *before* the Ed25519 verify, so a Byzantine far-future frame is dropped before it can brick the receiver's Lamport clock (closed by the skew bound on the wire-integrity seam).
- **identity → attribution → mesh**: `identity.Directory` resolves `originNodeID → pubkey` (the frozen wire carries no pubkey, forcing out-of-band resolution); `attribution.RelayEnvelope` binds each relay hop with a forward-secure chain a relay cannot splice; `Gossiper.InsertLocalEvents` routes local writes through `bridge.PutLocal` (WAL fsync) — never `engine.InsertLocal` directly.
- **telemetry → metrics → control port**: the hot path writes to `internal/telemetry`'s 19 zero-GC LongAdder counters without plumbing an OTel Meter; `TelemetryBridge` projects them onto cumulative `supremum_*` Prometheus series on `/metrics` with zero bridge code edits when a new counter is added (counter auto-surfacing).

---

## 3. Design Rationale & Philosophy

The engine is governed by five physical laws, each enforced by a named test gate. Each law exists because a measured failure mode made it non-optional. This section ties each rationale to the real mechanism that implements it.

### 3.1 Why δ-CRDTs (vs operational logs)

An operational log conflates *what happened* with *what the system believed*. A δ-CRDT separates them: state is a join-semilattice element, and a delta is the *minimal* state-difference needed to bring a remote replica up to date. The merge operation is a pure function (`Join`, `crdt.go:1173`, **frozen**), so convergence is a lattice-join property — commutative, associative, idempotent — *proven* by the rapid-based property tests (`TestCRDTJoinCommutativity`, `TestCRDTJoinAssociativity`, `TestCRDTJoinIdempotence`, `TestCRDTConvergenceMultiNode`, `TestCRDTJoinMonotonicGrowth`) and *proven to survive* a lossy/duplicating/reordering/partitioned transport by `internal/chaos`'s `TestMerkleConvergenceAfterPartition` (32 engines, asymmetric partition, 12 gossip rounds, byte-equal roots after heal) and `TestConvergenceDeterminismAcrossRuns` (two independent 8-node runs converge to the same root with dedup *disabled* — Join idempotence alone guarantees correctness).

The δ-prefix is what makes this planetary: instead of shipping full state, the engine ships `GenerateDelta(remoteDigest)` (the set of entries the remote is missing, computed via IBLT subtract+peel) or `GenerateDeltaStratified(remoteSE)` (minimal delta ∝ |A−B| via strata estimation). This is why the mesh can converge 1000 split events in ≤10 rounds over real TLS 1.3 loopback (`TestTwoNodeConvergence_InMemory`).

A known, **deliberately-not-fixed** convergence-law regression is documented honestly: `Join` is MERGE-UNION on `CausalDot`, but `LWWOperator.Resolve` (elsewhere) drops the loser — a dropped dot cannot re-merge across a foreign `AdvanceLamportTo`. Per ADR-0033 this is a won't-fix in `pkg/sync`; the genuine lossless conflict resolution is the live HAMT read path shipped, which reads the *full* dot set losslessly via `selectLatestDot` and `engineHAMTAdapter`.

### 3.2 Why off-heap / zero-GC (the memory law)

> *Memory law: 0 allocs/op on the hot path. Every allocation on the hot path is a future GC pause. One `make()` on the write path at 68.3M ops/s = stop-the-world ~every 4ms. Unacceptable.*

The mechanism: `NodePtr` is a GC-invisible `uintptr`; all node/leaf/string/entry-array data lives in the `mmap`'d `HamtArena`; even the `*HAMT` wrapper is arena-allocated (`allocHAMTWrapper`); `makeBinaryKey` writes into a stack `[8]byte` then `unsafe.String` (safe because `makeLeaf` synchronously copies bytes into the arena before `Set` returns). The gate is `TestHotPathZeroAllocations` asserting `HAMT.Set` = 0 allocs/op. The `raceEnabled` build-tag pair lets it self-skip under `-race` (shadow-memory instrumentation inflates `AllocsPerRun`).

The same philosophy propagates outward: `internal/database`'s `JemallocAllocator` (CGO `mallocx` with 64-byte alignment + zeroing) backs the SkipListArena and the Arrow IPC allocator; `internal/telemetry`'s `Counter` is a 64-stripe LongAdder with zero hot-path allocations (all construction at `init()`); `internal/crypto`'s `MaskPII` returns the input verbatim with an identical data pointer on the no-PII fast path (proven by `TestMaskPII_NoPII_ReturnsInputUnchanged` comparing `unsafe.StringData`); `internal/network`'s S3 `ShardedKey` uses fixed-size stack buffers (zero heap escape, `BenchmarkShardedKey`).

Where the law does not bind, it is honestly waived: `VerifyCRDTFrame`/`RejectSmallOrderKey` allocate ~3 `edwards25519.Point`s per call — explicitly justified because signature verification itself allocates far more; the sign path (`SignCRDTFrame`) allocates per call — it is not the 68.3M ops/s apply hot path; `FrameReader.ReadFrame` does `make([]byte, frameLen)` per frame — the zero-alloc law applies to the engine hot path, not this wire edge.

### 3.3 Why 128-byte cache-line padding (the cache law)

> *Cache law: 128-byte stride for every contended atomic. Two atomics on one cache line at 32 cores = HITM storm = 1.1M ops/s (1.6% efficiency) vs 50.7M-68.3M ops/s range. This was measured — and re-measured on this tree 2026-09-03 (68,278,197 ops/s 32c, c8g.8xlarge).*

The mechanism: every hot atomic is `CacheLinePad`-isolated. `ElimSlot` is exactly 128 B (two cache lines) verified compile-time via `unsafe.Sizeof`; `secShard` is exactly 128 B; `EBRManager.globalEpoch` is on its own line; `internal/telemetry`'s `counterStripe` is exactly 64 B (`//go:align 64`, 56-byte lead pad + 8-byte atomic). The gate is `TestMemoryLayoutAnalysis` (`layout_analysis_test.go`), which enumerates field offsets and flags any line holding >1 contended field as "FALSE SHARING RISK". The spatial SPSC ring carries the same discipline across a process boundary: `RingSlot` is exactly 64 B (one L1 line) and `RingHeader` is exactly 192 B (3 cache lines) with 56/56/52-byte padding isolating `WriterCursor`, `ReaderCursor`, and the control word — no false sharing between the Go writer and the C++ reader.

The CAS-storm sharding is the same law applied to free-lists: the three hottest CAS sites — class-0 node freelist (was 92% of `AllocNode` CPU at 32c), the var freelist, and the EBR per-epoch retire head — are sharded 256-way with route counters dispersing the locus (`TestNodeFreelistSharded` proves a 1.5× cardinality speedup).

### 3.4 Why CAS + EBR and no mutexes on the hot path (the lock law)

> *Lock law: No `sync.Mutex` on the write path. CAS + EBR only. A futex is a scheduler stall. A scheduler stall at 68.3M ops/s is a cliff.*

The mechanism: `Join`/`InsertLocal`/`NextDot` use CAS + EBR only. The only `sync.Mutex` in the CRDT core (`persistMu`) guards disk fsync in the *decoupled background worker*, not the hot CAS path; `stateViewMu` guards only the lazy `State()` merged view (off the hot path). EBR (`reclamation.go`) gives safe memory reclamation without fences on the read path: `globalEpoch` is CAS'd by `AdvanceEpoch`; participants pin the epoch on `Enter`; `RetireBlock` cannot recycle a node onto a Treiber free-list while a participant holds an epoch pin → the slab free-lists are ABA-immune (proven by `TestHEBRDetachAllowsEpochAdvance` and the ABA suite). Hazard pointers (`DetachAndProtect`) publish a retired-node address so a concurrent reader's `isHazardProtected` check can rescue it.

The same law propagates: `internal/telemetry`'s hot path is wait-free (each writer picks `stripes[stripeIndex()]` deterministically and CAS-loops only on that one cache line); `internal/network`'s `ClientPool` is lock-free acquire via `connSlot.inUse.CompareAndSwap(false,true)`; the spatial SPSC ring uses `atomic.StoreUint32`/`LoadUint32` with release semantics and a phased `procyield`/`sync.Cond` wait (deliberately eradicating `runtime.Gosched()`). Where mutexes *do* appear, they are honestly off the hot path: `PeerBucket`'s 16 shards (per-shard `sync.Mutex`), `Directory`'s `sync.RWMutex` (read-dominated receiver path), `payloadCache`'s `sync.Mutex` (TOCTOU guard), the WAL's `sync.Mutex` (serializes appends + `f.Sync()`).

### 3.5 Why WAL replay restores the recorded dot instead of re-minting (the WAL law)

> *WAL law (CORRECTED 2026-08-31, ADR-0045): Replay RESTORES the recorded dot — it never re-mints. Each mutation is re-applied at its WAL-recorded `(DotNodeID, DotCounter)` via the exact-dot route (synthetic-delta `Join`); the post-checkpoint tail is selected by WAL RECORD SEQUENCE against the checkpoint's sequence cut, never by a scalar Lamport counter.*

The mechanism that made the old law necessary: `InsertLocal` re-stamps `DotNodeID`/`DotCounter` from `NextDot()`, so a *re-minting* replay must boot at exactly the right seed to reproduce the recorded dots. Three counterexamples killed every such seed: (1) **mint order ≠ append order** — two concurrent writers mint 2 and 3 while the WAL mutex serializes their appends in the opposite order, so a first-record-derived seed re-mints the second at 4 (`ErrRecoveryRootMismatch`); (2) **a scalar counter is not a log position** — `InsertLocal` reserves its counter before publication, so a checkpoint can record watermark N while that mutation's record lands after the checkpoint record, and any counter-compared tail cut silently drops it; (3) a **non-quiescent checkpoint** leaks post-watermark dots into the snapshot image, and re-minting them double-dots every leaked entity (silicon run: 10,800 live dots for 10,000 keys, permanent divergence).

Under exact-dot restore the ordering problem dissolves: dot-union `Join` is monotone, idempotent and commutative, so restored STATE is order-independent; only the final clock is order-sensitive, and it is a max over (restored dots, replayed advances). Two honesty corollaries: `MerkleRoot` folds only `DotNodeID+DotCounter` under SHA-256, so **root equality is NOT a full-state integrity verification** — the WAL's persisted entry is 80 bytes (5 of 10 `CRDTEntry` fields), so `ValidTimeStart/End`, `AssertionTime`, `DecisionTime` and `H3Index` replay as zeros while roots still match; and the historical determinism gate (`TestWALRecoveryDeterminism`) stayed green only because its scenario is sequential and single-writer.

Bounded recovery makes this O(post-checkpoint): `SnapshotStore.SnapshotExists` gates the bounded branch; if the dot-bearing snapshot image at `ckpt/<LamportHigh>` exists, seed from it and replay only the post-checkpoint tail; `RecoveryWitness` reports which branch ran and why.

### 3.6 Why tri-temporal + H3 spatial + post-quantum from day one

**Tri-temporal** is the moat: keying state by `(system_time × valid_time × assertion_time)` (plus `decision_time` on the wire) lets the engine answer "who owned entity X at valid-time V as the system knew it by tx-time T" — a query a mutable-row or log-only model cannot answer without an auxiliary history store. The durable tier materializes this as the 40-byte composite key (`[hash16|sysTime|validTimeStart|assertTime]`) and the 9-field Arrow IPC rows; the read path enforces four-record-batch filters (Filter1 hash, Filter2 `SystemTime <= txTime` STRICT, Filter3 half-open valid-time, Filter4 entity-id collision guard) with `Range` generalizing to **interval-intersection** (not point-in-window — the data-loss class). Dominance pruning (ADR-0020) is three claws of the tri-temporal lattice: C1 structural sweep order, C2 `[vs,ve)` containment, C3 the `txTime <= horizon` FLOOR guard — pure function `DominancePrune(rows, horizon)`, idempotent, preserve-all the byte-identical default.

**H3 spatial** is carried on every `CRDTEntry` (`H3Index uint64` @112) and in the Arrow schema (`h3_index` Uint64). Geocoding is offloaded to an isolated C++ worker over a `memfd`-backed SPSC shared-memory ring (`internal/spatial/h3_spsc_ring.go`) — cache-line-padded, MESI-coherent cross-process via `MAP_SHARED`, no syscalls/futexes/mutexes on the hot path — fronted by an `EpochBatcher` that batches coordinate submissions to amortize cross-process round-trips. (Honest caveat: the C++ `h3_worker` binary is externally supplied; in-tree tests use mock Go consumers.)

**Post-quantum from day one** is a hedge against harvest-now-decrypt-later. The Ed25519 verify gate (`identity.VerifyCRDTFrame`) is the production seam; a hedged (randomized-nonce) signer (`eddsa_hedge.go`) stays compatible with the *unchanged* verifier (proven by `TestSignCRDTFrame_VerifiesUnderVerifyCRDTFrame` — the construction follows the exact `s*B = R + k*A` equation per RFC-8032 §5.1.6). Hybrid Ed25519+ML-DSA-65 (FIPS 204) signing ships in the default build (`pq_mldsa.go`); its size economics are measured, not assumed: sig = 3309 B, pub = 1952 B = **51.7×** sig inflation vs Ed25519 64 B on a 120 B frame — a measured size-economics bound (`bloat-ratio >= 50×`).

### 3.7 Why a chaos test harness

`internal/chaos` exists because three invariants cannot be synthesized by external tools (AWS FIS, Chaos Mesh):

1. **Semantic Byzantine injection** (`byzantine.go`): a DotCounter ratchet toward `MaxUint64` *re-signed with circl* is cryptographically valid but semantically malicious — FIS cannot forge a valid signature on mutated material. The catch is `admission.PeerBucket.Accept`, proven by `TestByzantine_A2RatchetCaughtByAdmission` (Max-ratchet dropped in 1 admit) and `TestByzantine_A2RatchetIncrementalCaught` (incremental drains within `maxAdmits=5`).
2. **Merkle convergence under partition** (`partition.go` + `virtualnet.go`): an in-memory `VirtualNet` simulates partitions, drops, duplicates, reorders and drives *real* `DeltaCRDTEngine` anti-entropy — `TestMerkleConvergenceAfterPartition` (32 nodes, byte-equal roots after heal).
3. **Process-crash survival from off-heap SIGSEGV** (`supervisor.go` + `fuzzer.go` + `probe.go`): a raw off-heap SIGSEGV in a child worker is recovered from the WAL *without dropping an active TCP connection* — because `recover()` cannot catch a SIGSEGV in `mmap`'d C-space (`TestSIGSEGVSurvival`, conditionally skipped pending `CHAOS_WORKER_BIN`).

The harness also enforces no-fabrication guards via `go/ast` source scans: `TestByzantine_NoVectorClockLamportTime` bans deprecated identifiers, `TestByzantine_UsesRandV2` requires `math/rand/v2`, `TestByzantine_NoInPlaceDeltaMutation` bans in-place delta mutation.

### 3.8 The honesty law

> *Honesty law: Report numbers, not adjectives, and report the layer. "The CRDT core gate passed at 50,736,038 ops/s 32c (the gate-passing run; the reproducible range is 50.7M-68.3M with this tree's re-run at 68,278,197 ops/s on 2026-09-03, c8g.8xlarge; CORE microbench, NOT the production ingest path which is 5.7M-6.0M deltas/sec 32c (this tree, 2026-09-15))" is a fact. Quoting any single high-end figure alone as "sustained throughput" was a hero-number round-up the post-mortem explicitly forbids. "Blazing fast" is evidence of incompetence.*

This is not a workflow rule but a load-bearing engineering discipline enforced by gates: the gear-honesty guards (`TestGate_GearHonesty`, `TestBench_GearHonesty_4c`) assert `NumCPU==4` else `t.Skip`, scan every `.go` in a package for a forbidden `_32c` tag, and forbid relabeling a 4c number as 32c. Honest negatives are recorded verbatim: `BenchmarkEBPFDelivery_vs_HashFallback_32c` tolerates an eBPF-steer-slower-than-hash-fallback NEGATIVE at single-box scale; `BenchmarkBatchedVerify` records its negative as "ACCEPTED-with-NEGATIVE-perf". The SDK honestly reports the originator-vs-peer payload boundary (`TestClientGetOnPeerReturnsDigestNotValue`: a peer `Get` returns `Payload==""` + `PayloadDigest!=""`).

---

## 4. Key Features & Specialties

This section enumerates the concrete specialties, with the package/file where each lives and an honest label where the feature is bench-only, stub, dormant, or opt-in.

### 4.1 The CRDT core (`pkg/sync`)

| Specialty | Mechanism | Status |
|---|---|---|
| **Sharded lock-free HAMT** | `DeltaCRDTEngine.shards []shardRoot` (default 256) + `routeShard`; per-shard `atomic.Pointer[HAMT]` CAS | Production |
| **Merge-union `Join`** | `crdt.go:1173`; frozen; per-element routing through the wire-integrity seam | Production (frozen) |
| **IBLT + Strata Estimator** | `iblt.go`; XOR-accumulator buckets (0.00% FP purity); `StrataEstimator` = 32 fixed IBLTs; `DynamicIBLTSize(dEst)` | Production (set reconciliation) |
| **EBR + hazard pointers** | `reclamation.go`; 3-epoch × 256-shard retired ring; 2-epoch grace window; ABA-immune | Production |
| **Wire-integrity seam** | `crdt_reconstruct.go` + `crdt_reconstruct_skew.go`; 3 axes (digest, attribution, skew bound); closes the Byzantine far-future-dot / disk-state-poisoning attacks | Production |
| **Capnp wire** | `crdt_capnp_wire.go` (marshal-only `BuildCRDTDeltaEvent`); `CRDTDeltaEvent` 13-field schema; C5/C6 version/format guards | Production |
| **IBLT wire codec** | `iblt_wire.go`; deliberate little-endian (non-capnp) `IBL1`/`STRA` magic | Production |
| **Lock-free stack candidates** | `elimination.go` (elimination-backoff), `flatcomb.go` (flat-combining), `sharded.go` (SEC-sharded) | **Bench/experiment** — three candidates coexist; the active candidate for `TestScalingGate` is chosen by `init()` override ordering (SEC wins); no single committed winner |
| **Residency hardening** | `residency.go` — mlock/madvise/prefault page-fault mitigation | Production (opt-in; `residencyMaxStall=10µs` is documentation-only; the CI gate is the fault delta) |
| **Lamport durability decoupling** | `persistCh chan uint64` (unbuffered) + `persistWorkerLoop`; `lastSavedCounter` monotone CAS loop | Production |

### 4.2 Tri-temporal state

State is keyed by `(system_time × valid_time × assertion_time)` with `decision_time` on the wire (`CRDTEntry` fields @72–104). The durable tier materializes this as the 40-byte composite key + 9-field Arrow IPC rows. The read path enforces the four-filter bitemporal discipline; `Range` uses interval-intersection (not point-in-window). Dominance pruning (`DominancePrune`, `l1_compactor.go`) is the tri-temporal lattice's GC: C1 structural, C2 `[vs,ve)` containment, C3 `txTime <= horizon` FLOOR. T_gc auto-inference (ADR-0027) tracks the observed live-query txTime frontier as a monotone atomic MAX at AsOf-entry and feeds `effective = max(operatorFloor, observedFrontier - backoff)` into the unchanged `DominancePrune` — the inferrer *floors* the configured `operatorFloor` (never replaces it); retreats are refused + counted (`telemetry.PruningHorizonRetreatRefused`) + logged.

### 4.3 H3 spatial CRDT

`H3Index uint64` is carried on every `CRDTEntry` (@112) and in the Arrow schema (`h3_index` Uint64). Enrichment runs in an isolated C++ worker over a `memfd`-backed SPSC shared-memory ring (`internal/spatial/h3_spsc_ring.go`): `RingSlot` exactly 64 B, `RingHeader` exactly 192 B (3 cache lines), `MAP_SHARED|MAP_POPULATE` pre-faulted, survives `execve` via `ExtraFiles` at fd 3 (a later fix replacing `Mmap(-1, MAP_ANON)` which severed at execve → EBADF deadlock). `EpochBatcher` (`epoch_batcher.go`) batches coordinate submissions (`DefaultEpochSize=4096`, `CollectTimeout=100ms`) to amortize cross-process round-trips. **Honest caveat:** the C++ `h3_worker` binary is externally supplied; in-tree tests use mock Go consumers, so cross-process memfd-inheritance + real H3 computation is proven only structurally (`TestNewSPSCRing_MemfdCreated`).

### 4.4 Post-quantum + hedged cryptography

| Feature | Location | Status |
|---|---|---|
| **ZIP-215 Ed25519 verify** | `pkg/identity/verify.go` — circl v1.6.4 (RFC-8032-strict canonical-Y/S) + `RejectSmallOrderKey` cofactor-8/small-order rejection | Production |
| **Hedged (randomized-nonce) EdDSA** | `pkg/identity/eddsa_hedge.go` (`!aws_lc_hedged` tag) — RFC-8032 §5.1.6 with a 64-byte `crypto/rand` nonce prefix; verifies under *unchanged* circl.Verify | Production (sign path) |
| **ML-DSA-65 (FIPS 204)** | `pkg/identity/pq_mldsa.go` — randomized `sk.Sign`, context domain-separation, `filippo.io/mldsa`; sig=3309B, pub=1952B | **Default build** — available for hybrid Ed25519+ML-DSA-65 signing |
| **aws-lc hedged bridge** | `pkg/identity/aws_lc_hedged_stub.go` (`aws_lc_hedged` tag, OFF) | **Panic stub** — real CGO bridge deferred to; the Go binding `github.com/aws/aws-lc-go` is repo-not-found |
| **X25519MLKEM768** | post-quantum key exchange | **Default build** |
| **Dev-mesh x509 PKI** | `pkg/crypto/certgen.go` — Ed25519 self-signed CA (10-year, IsCA) issuing 1-year server+client leaves; **stdlib** `crypto/ed25519` + `crypto/x509` (distinct key space from CRDT-delta signing) | **Dev mesh only** — not production PKI (no offline root, intermediate CAs, HSM custody, OCSP/CRL, automated rotation) |
| **Zero-GC PII masking** | `internal/crypto/pii.go` — `MaskPII` three-pass scan; no-PII fast path returns input verbatim with identical data pointer; rare path one exact alloc; `//go:nosplit`/`//go:noinline`; `xxhash`-deterministic redaction | Production (memtable calls it per write) |

### 4.5 eBPF reuseport steering

`pkg/transport/ebpf_reuseport.go` (`//go:build ebpf_kernel`) loads a live `BPF_PROG_TYPE_SK_REUSEPORT` program via cilium/ebpf v0.22.0 (the first production-loadable eBPF dep), keyed on `OriginNodeID` via `BPF_MAP_TYPE_SOCKHASH` (`bpf_sk_select_reuseport` helper id 82). The program reads `ctx->data[88:104]` (= `udpHeaderSize(8)` + `originNodeIDWireOffset(80)`) — a later correction; the prior draft's `[80:96]` read half-`dotCounter`+half-`originNodeID` garbage and the kernel fell back to hash. A miss is **never a drop** (`SK_PASS` → kernel hash fallback → delivered, not dropped). `AttachProgram` uses `SO_ATTACH_REUSEPORT_EBPF=0x34`; `DetachProgram` uses `SO_DETACH_REUSEPORT_BPF=0x44` (a root-cause fix — the `fd=0` `SO_ATTACH` trick `EINVAL`'d on kernel 6.18). Proven on silicon: `TestEBPFRoamStickiness_32Sockets` (32 sockets, 1000 frames, 4-tuple roam / CID constant → all 1000 on pinned socket 0), `TestEBPFDeterminism`, `TestNoCryptoBeforeRoute_EBPF`. **Honest caveat:** `ebpf_kernel` is opt-out by default; default ingress stays on the in-process `ReusePortFanout`; silicon tests `t.Skip` cleanly on a capability-absent box (require `sudo` + c8g kernel 6.18).

### 4.6 TLS 1.3 mesh

`pkg/transport/tls_transport.go`'s `TLSConnections` is 1.3-only mTLS (`Min==Max==VersionTLS13` — 1.2/1.1/1.0 impossible; `RequireAndVerifyClientCert`), with `GetCertificate`/`GetClientCertificate` hooks serving a live leaf for SIGHUP rotation (`Reload()` re-reads leaf cert+key, atomically swaps; the CA pool is NOT reloaded — a trust-root change requires transport restart). Gates: `TestTLSHandshake_13_Only` (Version==TLS1.3, AEAD cipher in {AES_128_GCM_SHA256, AES_256_GCM_SHA384}), `TestTLSRejectWithoutClientCert`, `TestTLSCertRotation_SIGHUP` (new leaf to same paths + `Reload()` → re-Dial presents new leaf within 5s). The peer data plane, the `/metrics`+`/livecheck` plain-HTTP surface, and the `/v1/*` mTLS control port share one trust root but ride separate listeners.

### 4.7 Telemetry → Prometheus bridge

`internal/telemetry`'s `Counter` is a zero-GC, lock-free, sharded LongAdder (64 stripes, each exactly one 64-byte cache line via `//go:align 64`); the hot path is wait-free (each writer CAS-loops only on its own stripe). A singleton registry binds **19 named instruments** (3 gauges + 16 counters): `ArrowSerialBytes`, `MemTableFlushTotal`, `OffHeapAllocatedBytes`, `QueryL0ListCapped`, `QueryL1FilesScanned`, `CompactionMerged`, `CompactionL1Written`, `CompactionRowsPruned`, `L0ReapSweeps`, `L0ReapL0Deleted`, `L0ReapManifestsReaped`, `L0ReapSkippedOrphan`, `QueryTxTimeHighWaterMark`, `PruningHorizonEffective`, `PruningHorizonRetreatRefused`, `QueryDownloadSkippedFirstSys`, `QueryManifestSkippedFirstSys`, `QueryLiveSourceReads`, `StratifiedAntiEntropyFallback`.

`pkg/metrics`'s `TelemetryBridge` (`telemetry_bridge.go`, ADR-0023) is a `prometheus.Collector` that enumerates `telemetry.Counters()` at construction and dispatches on `Mode()` at `Collect` — **counter auto-surfacing**: adding a counter to `internal/telemetry`'s `allCounters()` slice surfaces it as a new `supremum_*` series with zero bridge code edits (name mapping is `strings.ReplaceAll(name, ".", "_")`, the only transformation). The double-count trap is closed: the bridge reads ONLY `c.Value()` (the 64-stripe cumulative sum) and NEVER reads `lastReported` (the OTel delta-dedup cursor), making it safe whether or not an OTel MeterProvider is bound. The two metric families coexist by name prefix: `sovereign_*` (labelled, from `Recorder`) and `supremum_*` (cumulative, from the bridge) — never collide.

### 4.8 The chaos harness

`internal/chaos` (covered in §3.7) is the verification layer proving the three hardest invariants under hostile conditions: semantic Byzantine injection, Merkle convergence under partition, and off-heap SIGSEGV survival via supervisor/worker process isolation + WAL recovery. It is explicitly a VERIFICATION layer, not the 68.3M ops/s hot path.

### 4.9 Honest-negative measurement culture

The gear-honesty guards, honest-negative bench recording, and the SDK's originator-vs-peer payload boundary (§3.8) are themselves a specialty: the engine treats measurement discipline as a load-bearing engineering property, enforced by CI gates, not a convention.

---

## 5. Primary Use Cases

Each use case is grounded in a real, shipped capability.

### 5.1 Planetary-scale event sourcing

The δ-CRDT core + IBLT/strata set reconciliation + sharded lock-free HAMT make the engine a fit for event-sourcing workloads that must converge across a large fleet without a central sequencer. `Join` is a merge-union join-semilattice (commutative/associative/idempotent, proven by rapid property tests and chaos mesh convergence), so events can be originated at any node and folded without coordination. `GenerateDelta(remoteDigest)` ships the minimal missing state; `GenerateDeltaStratified(remoteSE)` makes the delta ∝ |A−B| via strata estimation. The async double-buffered MemTable flush (256 MB arenas, cap-4 in-flight backpressure) keeps the write path off the hot CAS path while streaming to per-entity Arrow IPC. **Honest scale caveat:** the chaos mesh gate runs 32 nodes × 64 events, not millions; the §3 convergence property is scale-free but the planetary-scale claim is unproven by these tests (the test doc is explicit).

### 5.2 Multi-region eventually-consistent state

The TLS 1.3 mesh + anti-entropy sweep + Lamport causal dots + ACK-before-durability contract make the engine a fit for multi-region state that must remain available under partition and converge after heal. `TestPartitionHeal_ConvergesUnder100ms` proves bidirectional partition → divergence injection → heal → byte-equal roots + zero data loss + heal-to-convergence < 100 ms SLO. The clock cap (`IngressHLCScalarCap`) drops future-skewed frames before the ~60 µs verify, so a Byzantine peer cannot brick a receiver's Lamport clock. The skew-bound wire-integrity seam closes the far-future-dot and disk-state-poisoning attacks. `InsertLocalEvents` routes through `bridge.PutLocal` (WAL fsync) and returns 503 — not a lying 200+zero-dot — on fsync failure, so a client learns durability was not achieved.

### 5.3 Geo / spatial-temporal workloads

`H3Index` on every `CRDTEntry` + the Arrow `h3_index` column + the memfd SPSC H3 ring make the engine a fit for workloads that query by both time and geography (fleet telemetry, asset tracking, coverage analysis). The bitemporal `AsOf`/`Range` queries resolve "what did the system believe about entity X at valid-time V as of tx-time T" over the durable Arrow tier plus a read-your-writes live HAMT merge. The `EpochBatcher` amortizes H3 enrichment across cross-process round-trips. **Honest caveat:** the C++ `h3_worker` is externally supplied; the SPSC ring is proven structurally but not with the real worker.

### 5.4 Post-quantum-secure data infrastructure

The Ed25519 verify gate is a production seam; hybrid Ed25519+ML-DSA-65 signing is available in the default build, and X25519MLKEM768 is the default key exchange. The size economics are measured, not assumed (sig 3309 B, pub 1952 B, 51.7× inflation), and the PQ size-economics check enforces `bloat-ratio >= 50×` so the size bound cannot drift silently. The hedged EdDSA signer (randomized nonce) closes side-channel nonce-reuse attacks while staying compatible with the unchanged verifier. For workloads with long confidentiality horizons (decades), the engine is post-quantum-secure *from day one* rather than retrofittable.

### 5.5 High-write low-latency telemetry / CDR pipelines

The zero-GC hot path (0 allocs/op for `HAMT.Set`), the 128-byte cache-line discipline, the CAS+EBR lock-free write path, and the off-heap jemalloc SkipListArena make the engine a fit for high-write low-latency pipelines (CDR, telemetry, audit). The telemetry→Prometheus bridge surfaces 19 `supremum_*` cumulative series on `/metrics` with zero hot-path allocations; the `Recorder` records ingest/verify latency histograms and a six-value verdict counter (no `WithLabelValues` map lookup per frame). `internal/transport`'s EPOLLET Cap'n Proto ingestion server (`MaxConnections=4096`, `ReadBufSize=64KB`, jemalloc-backed reassembly, `runtime.Pinner` zero-copy dispatch) is the high-throughput ingress path — proven E2E by `TestParseMessages_RealClient_EndToEnd` (Unix socket, all 5 `TriTemporalEvent` fields within 2s). The `MaskPII` zero-GC hot path scrubs 12-digit runs deterministically (same token → same marker → downstream join without retaining raw PII), so CDR payloads with PII can be ingested and redacted without allocator pressure.

### 5.6 Edge / replicated deployments under partition

The chaos-proven partition/heal convergence, the opt-in WAL + bounded snapshot recovery (O(post-checkpoint)), the eBPF `SK_REUSEPORT` steering (sticky across 4-tuple roam), and the jittered-backoff HTTP client with a bounded lock-free pool (the "1M edge nodes won't thunder the coordinator" mandate) make the engine a fit for edge deployments that partition frequently. The `ConvergenceProbe` (`pkg/mesh/probe.go`) composes two Gossipers/PeerSets/engines for partition/heal/SLO measurement. `RecoverEngineWithSnapshot` recovers from a crash with `witness.Bounded` and preserves history (`TestQuery_ResilientAfterBoundedRecovery_HistorySurvivesCrash`). The `peer_key_slice_probe.go` negative-compile guard bans the non-comparable `map[ed25519.PublicKey]X` pattern, so the admission layer stays compile-safe on edge toolchains.

---

## 6. Integration & Usage

This section is an honest readiness assessment: what is production-wired, what is opt-in, what is bench-only, and what is stub.

### 6.1 The production binary: `cmd/sovereign-node`

`cmd/sovereign-node/main.go` is the single binary that wires every seam: the frozen δ-CRDT engine, the receive gate stack, the TLS 1.3 peer listener, the JSON/mTLS control port, the plain-HTTP `/livecheck`+`/metrics` ops surface, opt-in WAL durability + bounded snapshot recovery, the L0→L1 compaction scheduler with T_gc auto-inference, the L0 reaper, the OTel meter provider, and the read-your-writes live source adapter.

**Flags** (defaults: `defaultArenaSize=64 MiB`, `defaultAdmissionBudget=50 ms`):

```
--bind                       peer data-plane TLS listener (host:port)
--peers                      comma-separated peer host:port list
--tls-cert --tls-key --tls-ca  mTLS leaf cert/key and CA bundle paths
--node-id                    16-byte node ID (hex); derived from identity-seed if absent
--metrics-addr               plain-HTTP /metrics + /livecheck listener
--control-addr               mTLS /v1/* control-port listener (optional)
--arena-mib                  HamtArena size in MiB (default 64)
--admission-budget-ns        relay depth budget in nanoseconds (default 50ms)
--gossip-tick                anti-entropy sweep interval
--identity-seed              Ed25519 seed for node identity (derives nodeID + leaf)
--selftest                   mint self-test certs (dev)
--batch-size                  batched-send batch size (default 100, max 256)
--wal-path                   WAL file path (enables opt-in durability)
--wal-checkpoint-interval    checkpoint interval (LamportCounter ticks)
--lsm-root                   durable-tier root (LocalFS root or S3 bucket)
--compaction-prune-enable    opt-IN Level-2 DominancePrune (default false)
--compaction-prune-horizon-ns  T_gc configured floor (ns)
--compaction-prune-backoff-ns   observed-frontier backoff (ns)
--compaction-reap-enable     opt-IN L0 reaper (default false)
--compaction-reap-interval   reaper sweep interval (default 5m)
--otel                       arm OTel MeterProvider at boot
--otel-interval              OTel export interval
```

**Key functions**: `parseFlags`, `resolveNodeID`, `parsePeers`, `run`, `acceptLoopWithDigest`, `serveConnWithDigest`, `convergenceGaugePoller`, `startLivecheck`, `startControlPort`, `mintSelftestCerts`, `buildNodeIdentity`, `compactionSchedulerLoop` (hardcoded `30 * time.Second` interval, off the write path), `runCompactionSweep`, `reaperLoop`, `runReaperSweep`, `engineHAMTAdapter` (implements `database.LiveSource`; the ONLY place the concrete engine is in scope for `internal/database`, avoiding an import cycle). `armOTel` (`otel.go`) arms the OTel MeterProvider gated on `--otel`; `logOutputExporter` writes OTel batches to the node's log stream (NOT a Prometheus bridge — the bridge is separate).

### 6.2 The client SDK: `sdk/sovereign`

`sdk/sovereign/client.go` is a <50-line mTLS control-port client. `Dial(addr, tlsCfg)` forces `Min==Max==tls.VersionTLS13` + `ForceAttemptHTTP2:false`; `DialWithCerts(addr, certPath, keyPath, caPath, serverName)` loads on-disk credentials.

```go
type Client struct { httpClient *http.Client; baseURL string }
type GetResult struct {... Payload string; PayloadDigest string... }  // the read-path boundary
type MetricSample struct { Name, Labels string; Value float64 }
type MetricSamples []MetricSample

func Dial(addr string, tlsCfg *tls.Config) (*Client, error)
func DialWithCerts(addr, certPath, keyPath, caPath, serverName string) (*Client, error)
func (c *Client) InsertLocal(key, val string) error   // POSTs /v1/insert (routes through Gossiper.InsertLocalEvents, NEVER engine.InsertLocal)
func (c *Client) Get(key string) (GetResult, error)    // GET /v1/get — Payload only on originator; digest on peers
func (c *Client) MerkleRoot() (string, error)          // GET /v1/merkle
func (c *Client) Status() (NodeStatus, error)
func (c *Client) Metrics() (MetricSamples, error)      // parses /metrics, label-preserving
func (c *Client) RunDemo() error
func (c *Client) Close() error
func (s MetricSamples) Value(name string) (float64, bool)  // false for 0/multiple samples
func (s MetricSamples) Samples(name string) []MetricSample
```

**Honest boundary (the read-path boundary):** `GetResult.Payload` is non-empty only on the originator (cache hit); peers return `Payload==""` + `PayloadDigest!=""` because the engine stores only the `PayloadDigest` on a joined `CRDTEntry` (`TestClientGetOnPeerReturnsDigestNotValue`). The SDK does **not** claim linearizability — `InsertLocal` returns at LOCAL-apply; peer convergence is eventual (next gossip sweep).

### 6.3 Examples

- **`examples/sdk/main.go`** — the canonical <50-line SDK example (`main`, `run`).
- **`examples/embed/main.go`** — the OLDER lock-free stack export (`ShardedStack`/`EliminationStack` + per-goroutine `NewElimPRNG`, 200k ops/worker, asserts `pushed - popped == drained`). It proves external linearizable usability of the *stack core*, **not** the δ-CRDT HAMT engine — a historical artifact, not the current engine. Requires `GOMAXPROCS>=2`.

### 6.4 Control surface

| Endpoint | Transport | Purpose | Status |
|---|---|---|---|
| `/livecheck` | plain HTTP | liveness | Production |
| `/metrics` | plain HTTP | Prometheus scrape (`sovereign_*` labelled + `supremum_*` cumulative) | Production |
| `/v1/insert` | mTLS | local insert (→ `Gossiper.InsertLocalEvents` → `bridge.PutLocal` WAL fsync → `AppendCheckpoint` → L0 Arrow) | Production |
| `/v1/get` | mTLS | single-snapshot Get (digest on peers, value on originator) | Production |
| `/v1/query` | mTLS | bitemporal `AsOf` (503 if resolver nil, BEFORE param validation) | Production |
| `/v1/range` | mTLS | bitemporal `Range` (interval-intersection, capped by `MaxRangeRows`) | Production |
| `/v1/merkle` | mTLS | current root | Production |

`handleInsert` stamps a open-ended `ValidTime` default; `handleQuery`/`handleRange` echo `PayloadDigest` verbatim with deliberately no `payload` field (the index stores a sentry body; reporting one would be the "digest-is-not-value" fabrication). `parseQueryTime` and `dotHex` are helpers; `OpenEndedValidEndNs = 9e18` (year ~2253, deliberately NOT `database.MaxValidTime.UnixNano()` which overflowed).

### 6.5 TLS / cert provisioning

The dev-mesh CA (`pkg/crypto/certgen.go`: `NewMeshCA` → `IssueLeaf` → `WriteCAPEM`/`Leaf.WritePEM`) mints an Ed25519 self-signed CA (10-year, IsCA, CertSign|CRLSign, MaxPathLen=1) and 1-year server+client leaves (DigitalSignature, ServerAuth+ClientAuth, DNSNames {nodeID, localhost}); 62-bit crypto/rand serials; PEM to disk (CA pubkey at 0644 — CA private key stays in-process; leaf key PKCS8 at 0600). The binary's `--tls-cert --tls-key --tls-ca` point at these; SIGHUP → `tr.Reload()` rotates the leaf (CA pool NOT reloaded). **Honest caveat:** this is a DEV mesh CA, not production PKI — offline root, intermediate CAs, HSM-backed key custody, OCSP/CRL revocation, and automated rotation are named as post-launch work (ADR-0006).

### 6.6 Honest readiness assessment

| Capability | Readiness | Evidence |
|---|---|---|
| δ-CRDT core (`Join`, HAMT, IBLT, EBR) | **Production** | frozen; rapid property tests + chaos mesh convergence; 0 allocs/op hot path |
| Wire-integrity + skew bound | **Production** | closes the Byzantine far-future-dot / disk-state-poisoning attacks |
| TLS 1.3 mTLS mesh + control port | **Production** | `TestTLSHandshake_13_Only`, `TestTwoNodeConvergence_InMemory`, `/v1/*` route guards |
| Admission (rate + clock) | **Production** | `TestPeerBucket_SybilIsolation`, `TestAdmit_*`; `FrameDecision.Drop` returns Drop but real EAGAIN-at-TCP-layer is (not yet shipped) |
| WAL + bounded snapshot recovery | **Production (opt-in)** | `--wal-path`; `TestWALRecoveryDeterminism`, `TestQuery_ResilientAfterBoundedRecovery_HistorySurvivesCrash` |
| L0→L1 compaction + DominancePrune | **Production (prune opt-in)** | `--compaction-prune-enable` default false; ADR-0019/0020/0025 guards |
| T_gc auto-inference | **Production** | ADR-0027; inferrer floors the configured floor; retreats refused+counted |
| L0 reaper | **Production (opt-in)** | `--compaction-reap-enable` default false; never auto-runs |
| Read-your-writes LiveSource | **Production** | ADR-0032; `TestLiveReadYourWrites` (insert→IMMEDIATE query→200); scale bound: `engine.State().Get` is O(total entries) (separate change for O(1) per-entity) |
| SkipListArena.Seek | **Dormant** | Proven correct (ADR-0028) but NOT wired into `scanWindowRecordBatch` |
| eBPF SK_REUSEPORT steering | **Production (opt-out build tag)** | `//go:build ebpf_kernel`; silicon tests `t.Skip` cleanly on capability-absent box; default ingress uses in-process `ReusePortFanout` |
| EPOLLET Cap'n Proto ingestion | **Partial** | `TestParseMessages_RealClient_EndToEnd` (Unix socket E2E); `TestEpollServer_BasicMessage` is partial (binds, no message); IPv6 unsupported; only `TriTemporalEvent` parsed (not `CRDTDeltaEvent`/`CRDTDeltaBatch`) |
| H3 spatial CRDT (C++ worker) | **Structural-only** | SPSC ring proven structurally; C++ `h3_worker` externally supplied; in-tree tests use mock Go consumers |
| Ed25519 verify + hedged signer | **Production** | `VerifyCRDTFrame` + `RejectSmallOrderKey`; `TestSignCRDTFrame_VerifiesUnderVerifyCRDTFrame` |
| Post-quantum (X25519MLKEM768 + ML-DSA-65) | **Default build** | X25519MLKEM768 key exchange by default; hybrid Ed25519+ML-DSA-65 signing available |
| aws-lc hedged bridge | **Stub** | `aws_lc_hedged_stub.go` is a panic stub; real CGO bridge deferred |
| Dev-mesh x509 PKI | **Dev only** | Not production PKI (no offline root/intermediates/HSM/OCSP/rotation) |
| Zero-GC PII masking | **Production** | `internal/crypto/pii.go`; memtable calls `MaskPII` per write; `internal/crypto/doc.go` is a STALE stub that contradicts it |
| Telemetry → Prometheus bridge | **Production** | ADR-0023; counter auto-surfacing; 19 instruments; `TestRealScrapeCumulativeNotDelta` |
| Chaos harness | **Verification** (not hot path) | `internal/chaos`; SIGSEGV survival test conditionally skipped pending `CHAOS_WORKER_BIN` |
| Postgres bulk load | **Partial** | `InitializeSwarmPool` + `UnloggedStagingPromotion` (uses a TEMPORARY table despite the name); no live COPY test — only SQL-string construction and config parsing are tested |
| S3 uploader | **Partial** | `AWSS3Uploader` with SHA-256 prefix sharding (65,536 partitions); multipart is **sequential, not concurrent**; no live `Upload` test (AWS creds assumed absent); `database.S3Uploader` conformance asserted only via compile-time `var _` |
| `pkg/durability/wal.go` | **Alias layer** | Pure re-export of `internal/chaos` WAL with zero own logic; production WAL surface is only as proven as the chaos harness |
| `EpochCompactor` | **Dead** | Zero production importers; retained as a documented dead-end; real GC is DominancePrune + L0 reaper |
| `payloadCache` | **Production (unbounded)** | No eviction/LRU; ADR-0007 debt |
| L0 file growth | **Debt disclosed** | One fresh `l0/*.arrow` per checkpoint, no merge/compaction by default; bounded by `ResolverConfig.MaxL0Files` (1000); `TestQuery_L0FileGrowthDisclosed` asserts the debt's existence |

### 6.7 Getting started (operations)

1. **Provision a mesh CA** (dev): use `pkg/crypto`'s `NewMeshCA`/`IssueLeaf`/`WriteCAPEM` to mint a CA and per-node leaves (or supply your own PKI and point `--tls-cert --tls-key --tls-ca` at it).
2. **Derive node identity**: pass `--identity-seed` (Ed25519 seed); `nodeID` is the first 16 bytes of the derived pubkey and must equal `engine.localNodeID`.
3. **Start a node**: `cmd/sovereign-node --bind :443 --peers peer1:443,peer2:443 --tls-cert cert.pem --tls-key key.pem --tls-ca ca.pem --metrics-addr :9100 --control-addr :4433 --arena-mib 4096 --wal-path /var/lib/sovereign/wal --lsm-root /var/lib/sovereign/lsm --gossip-tick 1s --batch-size 100`. Defaults are byte-identical conservative: pruning OFF, reaper OFF.
4. **Opt into durability/compaction**: add `--wal-checkpoint-interval N`, `--compaction-prune-enable --compaction-prune-horizon-ns <T_gc> --compaction-prune-backoff-ns <backoff>` once you trust the T_gc floor; add `--compaction-reap-enable` once you trust your storage layer's existence-probe (the reaper never auto-ONs).
5. **Observe**: scrape `/metrics` for `sovereign_*` (labelled) and `supremum_*` (cumulative) series; hit `/livecheck` for liveness; arm `--otel` for OTel export to the node's log.
6. **Write/read**: via the SDK (`sdk/sovereign`) over mTLS to the control port — `InsertLocal` (originator), `Get` (digest on peers, value on originator), `AsOf`/`Range` (`/v1/query`, `/v1/range`).

### 6.8 Getting started (developer)

Embed the stack core via `examples/embed` (historical API) or drive a full node via `examples/sdk` (the canonical SDK path). For direct engine use, the `pkg/sync` public surface is:

```go
eng, err:= sync.NewDeltaCRDTEngine(nodeID, initialCounter, arenaSize)
dot:= eng.InsertLocal(entityID, entry)      // 0 allocs/op hot path
eng.Join(delta)                              // frozen merge-union
remoteDigest:= eng.GenerateDigest()         // IBLT
delta:= eng.GenerateDelta(remoteDigest)    // minimal missing set; defer delta.Release()
eng.ApplyCRDTDeltaEvent(wire)               // wire-integrity + Join
wire, _:= sync.BuildCRDTDeltaEvent(entityID, payload, entry)
```

For durability, `pkg/durability`:

```go
wal, _:= durability.OpenWAL(path)
bridge:= durability.NewBridge(eng, wal, checkpointInterval)
dot, err:= bridge.PutLocal(entityID, payload, entry)  // InsertLocal + WAL fsync
bridge.AppendCheckpoint()
eng, wal, replayed, err:= durability.RecoverEngine(nodeID, walPath, arenaSize)
eng, wal, _, witness, err:= durability.RecoverEngineWithSnapshot(nodeID, walPath, store, arenaSize)  // bounded
```

For queries, `internal/database`:

```go
resolver:= database.NewResolver(lister, downloader, alloc, bucket, database.DefaultResolverConfig)
row, err:= resolver.AsOf(ctx, entity, validTime, txTime)
rows, ok, err:= resolver.Range(ctx, entity, vLo, vHi, tx)
// LiveSource ( read-your-writes): set cfg.LiveSource to an EBR-pinned adapter
```

---

Where a feature is production-wired, opt-in, dormant, bench-only, or a stub, it is labeled as such, and measured numbers are reported as numbers. The defining property of the Sovereign Engine is not a single benchmark but the conjunction of its laws — memory, cache, lock, WAL, honesty — each enforced by a named gate and each tied to a measured failure mode that made it non-optional.