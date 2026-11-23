# 1. Architecture Overview — Sovereign Engine

## 1.1 Abstract

Sovereign Engine is a lock-free, off-heap $\delta$-CRDT synchronization engine
implemented in Go 1.26.1. It stores temporal state that converges without a
leader and retains the causal dots needed to attribute each mutation. The
largest measured deployment is **1,000 node processes on 30 c7gd.8xlarge
machines across three AWS regions**, measured on 2026-11-06
([receipt](../evidence/convergence-1000-node.txt)). An earlier run on
2026-09-13 measured **100 node processes on three c7gd.8xlarge machines,
one per AWS region**
([ADR-0041](adr/0041_100_node_silicon_convergence.md),
[receipt](../evidence/convergence-100-node.txt)).

**Throughput has two measurement layers:**

- **Sharded-stack microbenchmark:** `TestScalingGate` exercises an
  in-process `ShardedStack` with producer/consumer push and pop bursts,
  without Ed25519 verification, envelope decoding, networking, TLS, or
  persistence. Its ops/s figure counts every push and pop attempt, including
  empty pops. It requires 50M ops/s at 32 cores; the gate-passing floor is
  **50,736,038 ops/s**. Published 32-core results on AWS Graviton span
  **50.7M–68.3M ops/s**. A c8g.8xlarge (Graviton4) measured the high end,
  **68,278,197 ops/s**, on 2026-09-03
  ([receipt](../evidence/core-crucible.txt)).
- **In-process production ingest benchmark:** the receive path verifies an
  Ed25519 signature, decodes the envelope, and applies each CRDT delta. The
  single-origin shared path measured **5.7M–6.0M deltas/sec** at 32 cores with
  batches of N=100–256 on 2026-09-15; the distinct-origin ceiling path measured
  **12.5M–14.7M deltas/sec** ([receipt](../evidence/ingest-ed25519.txt)).

The stack result is a data-structure measurement, not a network ingest rate or a
multi-region convergence time. It is distinct from the `HAMT.Set` allocation
measurements below and from signed receive benchmarks. The ingest figures are
also in-process benchmark results, not a claim about a deployed fleet's
sustained write rate.

Three implementation choices shape the core. HAMT nodes and entries live in an
anonymous `mmap` arena outside the Go heap. The 128-byte-stride Home-Shard SEC
allocator spreads contended free-list heads across cache lines. Delta-CRDT
merges retain the union of causal dots, allowing replicas to apply updates
asynchronously and reach the same state.

The measured `HAMT.Set` hot path does not allocate Go heap objects, acquire a
mutex, use file-backed `mmap`, or call `fsync`. Higher-level insertion and
receive paths can allocate, and WAL, networking, and storage work is outside
this core measurement. [The memory model](2_MEMORY_MODEL.md) gives the arena
and allocator invariants.

## 1.2 Hardware and Runtime Constraints

Three constraints account for the core's layout and concurrency rules.

1. **Cache coherence.** When every core compares and swaps the same word,
   ownership of its cache line moves between cores and serializes the
   operation. The retained single-locus benchmark,
   `TestEliminationCrucibleScalingGate`, measured **1.1M ops/s at 32 cores
   (1.6% parallel efficiency)** because every free/recycle CAS targeted one
   cache line. Sharding the heads gives different cores different lines.
2. **Garbage collection.** Go's collector scans heap objects and applies write
   barriers as the heap changes. Keeping HAMT nodes and entries off-heap
   removes that work from the `HAMT.Set` path;
   `TestHotPathZeroAllocations` checks its zero-allocation contract. The
   [memory model](2_MEMORY_MODEL.md) describes the boundary rather than
   extending the claim to networking or ingest.
3. **Page residency.** A major page fault can block the calling OS thread on
   synchronous I/O until the kernel resolves it. `LockHotPages` uses `mlock(2)`
   to pin a selected arena range, but permission and memory limits can leave
   the pin partial or denied. `ResidencyStatus` reports that outcome and the
   engine continues without a complete pin; see
   [storage and durability](3_STORAGE_DURABILITY.md).

## 1.3 System Topology

The process-isolation harness in `internal/chaos` uses a decoupled
Supervisor–Worker model. This is a testable deployment boundary, not a
requirement imposed on every in-process embedding of `DeltaCRDTEngine`. The
production daemon does not construct this Supervisor.

```
┌──────────────────── Supervisor + external front end ─────────────────────┐
│  net.Listener (external TCP connections stay outside the worker)         │
│  Supervisor: WAL path + Worker NodeID                                    │
│        │                                                                 │
│        │  os/exec.Command (piped stdin/stdout; child crash closes pipe)  │
│        ▼                                                                 │
└────────────────────────────── WORKER PROCESS ────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────┐
│  DeltaCRDTEngine (off-heap δ-CRDT, mmap'd arena)                         │
│  ┌───────────────┐  ┌──────────────────┐  ┌──────────────────────┐       │
│  │  HAMT (Trie)  │  │  HamtArena (mmap)│  │ EBRManager           │       │
│  │ path-copying  │  │  slab allocator  │  │ Epoch + Hazard Ptrs  │       │
│  └───────────────┘  └──────────────────┘  └──────────────────────┘       │
│  WAL (fsync-on-commit)                                                   │
└──────────────────────────────────────────────────────────────────────────┘
```

An external front end, or the test process in `TestSIGSEGVSurvival`, owns the
listening socket and client connections; `chaos.Supervisor` is
listener-agnostic. The worker owns the engine and WAL. A fatal `SIGSEGV` while
accessing off-heap memory cannot be intercepted by Go's `recover()`. The worker
exits and its stdout pipe closes. The Supervisor observes the read error,
starts a fresh worker that replays the WAL, and retries the failed submit once.
Because the listener never belonged to the worker, the worker's exit does not
close those externally held client connections.

`TestSIGSEGVSurvival` is intended to check that an active connection still
responds after recovery and that the recovered root matches the committed
state. The current test uses `CHAOS_WORKER_BIN` only as a skip gate, then
ignores the supplied path and unconditionally tries to build the absent
`cmd/chaos-worker` command. When enabled, it fails before starting a worker
rather than executing those checks. The storage implications are covered in
[Storage and Durability](3_STORAGE_DURABILITY.md).

## 1.4 Temporal Data Model

Each stored mutation is a `CRDTEntry` carrying valid, transaction, and
assertion timestamps. A fourth field, `DecisionTime`, is reserved. The current
`AsOf` and `Range` query APIs filter on valid and transaction time; assertion
time is stored and returned but is not a separate query predicate.

| Temporal axis | Stored field | Semantics |
|:--|:--|:--|
| Valid time | `[ValidTimeStart, ValidTimeEnd)` | The half-open interval during which the event applies to the modeled entity. |
| Transaction time | `SystemTime` | A caller-supplied Unix-nanosecond timestamp. HTTP insertion defaults it to the write time. `AsOf` and `Range` exclude records above the requested transaction horizon. |
| Assertion time | `AssertionTime` | A timestamp recorded with the mutation and returned in query responses. Current `AsOf` and `Range` APIs do not accept an assertion-time filter. |
| Decision time | `DecisionTime` | A reserved fourth field on `CRDTEntry` and `CRDTDeltaEvent` (`decisionTime @10 :Int64`). The snapshot layout preserves it at `[104:112)`, but current read, range, and `AsOf` selection do not consult it. |

The logical history is append-only. `(*DeltaCRDTEngine).Join` sorts incoming
entries, deduplicates dot-equal entries, and lets `perShardMerge` union the
remaining dots with the existing per-entity history. Concurrent entries with
different dots both remain; choosing a current value does not delete the other
entry. `HashCausalDot` applies FNV-1a to `(DotNodeID, DotCounter,
PayloadDigest)` for IBLT reconciliation.

Current point reads use `selectLatestDot`: the greatest `DotCounter` wins, and
a tie selects the lexicographically smallest `DotNodeID`. Both `handleGet` and
`LatestPayload` use this selector, so `/v1/get` and the accessor make the same
choice without performing I/O inside the selection loop. Historical `AsOf`
queries instead use the temporal dominance rules described above.

> **Conflict-policy boundary.** The TOKI operator algebra (LWW,
> Evidence-Weighted, Await-Confirm) is not implemented.
> [ADR-0033](adr/0033_toki_closure_ghost_exorcism.md) records why eager TOKI
> resolution was rejected: dropping the losing dot inside `Join` would violate
> merge-union convergence. The engine instead retains dot-bearing `CRDTEntry`
> values and selects a value at read time. There is no separate `AuditRecord`
> or Judge-Log subsystem in the codebase.

| Dimension | Legacy CRUD model | Sovereign temporal model |
|:--|:--|:--|
| History | An update replaces the previous row | Each mutation adds a dot-bearing event; reads select from retained history |
| Time semantics | A single `created_at` instant | Valid, transaction, and assertion timestamps, with the query boundaries above |
| Conflict policy | Last write wins by wall clock | Merge-union of distinct dots, then deterministic read-time selection |
| Auditability | History is reconstructed from external logs | Every retained event carries its causal dot and temporal fields; no separate audit ledger is implemented |

### 1.4.1 H3 Cell Storage and Optional Secondary Index

Every `CRDTEntry` carries an `H3Index uint64`. `CRDTDeltaEvent` transmits it as
`h3Index @5 :UInt64`, and the snapshot and memtable layouts retain it. The
engine treats the value as an opaque H3 cell identifier; it does not infer a
cell from latitude and longitude on this path.

With `--secondary-index` enabled (default off), `internal/index` maintains a
current-state candidate index over caller-supplied H3 cells and system time.
`GET /v1/querybyh3` is then registered on the control server and returns exact
cell matches after temporal resolution through the query tier. The route also
requires that query tier; without a resolver it returns 503. Because the index
tracks current placements, a historical query after an entity changes cells
can miss that entity. The response exposes this `current_state` boundary and
reports truncation or index-capacity degradation rather than presenting a
partial answer as complete. [ADR-0058](adr/0058_secondary_index_production_wiring.md)
defines the opt-in behavior.

The insert API accepts `h3_index` only when the secondary index is enabled.
Its validation checks H3 mode bits, not geographic validity. No radius, ring,
or general geometry query is implemented.

Coordinate-to-cell conversion is a separate, unwired component.
`internal/spatial.SPSCRing` is a Go single-producer/single-consumer ring backed
by `memfd_create(2)`; an external C++ `h3_worker` would consume coordinates and
write cell IDs back. `EpochBatcher` batches `Stage(lat, lng)` calls around that
ring. Neither component has a non-test importer outside `internal/spatial`,
and the repository ships neither the worker nor an H3 library.

The ring uses a memory file descriptor because `os/exec.Cmd.ExtraFiles` can
pass it to the worker across `execve`; an anonymous mapping would not survive
that process boundary. The slot layout in `internal/spatial/h3_spsc_ring.go`
is the interface an external consumer must implement. These components are
built but not connected to insertion, and `--secondary-index` does not enable
them.

## 1.5 Convergence Mechanisms

The engine is a state-based $\delta$-CRDT replication substrate. Convergence
comes from lattice joins, not a leader election or quorum vote.

- **Local mutation:** `InsertLocal(entityID, entry)` uses `NextDot` to assign a
  `CausalDot{DotNodeID, DotCounter}` from the source node's Lamport counter.
- **Anti-entropy:** `GenerateDelta(remoteDigest)` subtracts and peels an
  Invertible Bloom Lookup Table to find entries the receiver lacks, and
  `Join(delta)` merges them. An incompatible digest or failed peel falls back
  to the full local set, so a small delta is not guaranteed; see
  [Network and Consensus](4_NETWORK_CONSENSUS.md).
- **Merkle comparison:** `MerkleRoot` and `MerkleRootFromShards` hash SHA-256
  over canonically sorted `(DotNodeID, DotCounter)` pairs. The root does not
  depend on Go's randomized `maphash` seed, so equal dot sets produce equal
  roots across processes.

## 1.6 Edge Integration and Wire Encoding

No browser or edge runtime ships in this repository. SQLite-WASM with an OPFS
VFS and DuckDB-WASM analytics over Parquet are possible integration points,
not implemented components; no browser VFS has been selected or wired.

The production mesh wire is independent of those ideas. `GenerateDelta`
returns an in-memory `CRDTDelta` whose lazy `Entries` iterator yields missing
`(entityID, CRDTEntry)` pairs. `BuildCRDTDeltaEvent` serializes an entry with
the `CRDTDeltaEvent` schema. The batch path uses `CRDTDeltaBatch`; its receiver
verifies the signed batch before reconstructing and joining its events. The separate
`TriTemporalEvent` schema describes client ingestion rather than peer-to-peer
CRDT synchronization. All three schemas live in
`api/capnp/api/capnp/schema.capnp`; [Wire Protocol](8_WIRE_PROTOCOL.md) covers
framing and attribution.

Cap'n Proto provides typed views over message buffers without eagerly
materializing every field. It does not remove socket reads, length framing,
TLS, signature verification, or payload-digest checks. The binary deltagram
codec in `internal/chaos` is test-harness traffic, not the production Cap'n
Proto wire.

## 1.7 Document Suite Compass

| File | Domain |
|:--|:--|
| [1_ARCHITECTURE.md](1_ARCHITECTURE.md) | System overview, process isolation, temporal model, and convergence |
| [2_MEMORY_MODEL.md](2_MEMORY_MODEL.md) | Off-heap arena, allocation rules, cache-line layout, and memory ordering |
| [3_STORAGE_DURABILITY.md](3_STORAGE_DURABILITY.md) | Page residency, WAL, snapshots, and recovery |
| [4_NETWORK_CONSENSUS.md](4_NETWORK_CONSENSUS.md) | Delta-CRDT anti-entropy, IBLT reconciliation, and gossip |
| [5_BENCHMARKS_AND_LIMITS.md](5_BENCHMARKS_AND_LIMITS.md) | Benchmark methods, measurement layers, and scaling limits |
| [6_ENGINEERING_POST_MORTEM.md](6_ENGINEERING_POST_MORTEM.md) | Engineering failures, root causes, and measurements |
| [7_FORMAL_VERIFICATION.md](7_FORMAL_VERIFICATION.md) | Formal specifications, enforced properties, and unverified areas |
| [8_WIRE_PROTOCOL.md](8_WIRE_PROTOCOL.md) | Framing, Cap'n Proto schemas, attribution, and signatures |
