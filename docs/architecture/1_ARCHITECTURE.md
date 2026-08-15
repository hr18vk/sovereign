# 1. Architecture Overview — The Supremum Ledger Engine

## 1.1 Abstract

The Supremum Ledger is a planetary-scale, lock-free, off-heap $\delta$-CRDT
synchronization engine implemented in Go (1.26+). It serves as the temporal
state substrate for a planetary-scale temporal ledger mandated to govern billions of records
across a 100-year horizon with sub-millisecond latency bounds.

**Throughput — the layer discipline (never conflate the two numbers):**
- **CRDT core microbenchmark** (in-process `HAMT.Set` producer-consumer crucible, NO Ed25519 verify, NO envelope, NO network, NO TLS, NO persistence): the `TestStage5ScalingGate` gate passes the 50M ops/s absolute mandate; the gate-passing run measured **50,736,038 ops/s** at 32c (c8g.8xlarge, Graviton4), and reruns ranged **50.7M-57.6M ops/s** (the 57,638,422 figure is the residency high-end of that range, NOT "sustained" throughput and NOT a hero number — see the cache-line post-mortem at `docs/architecture/6_ENGINEERING_POST_MORTEM.md` which explicitly refuses the "58M" round-up).
- **Production ingest path** (verified Ed25519 + CRDT apply + envelope unmarshal, the real per-node receive rate): **1.0M-3.1M deltas/sec** at 64c (N=256 batch) — ~17-57x below the core number, because the core number omits the ~60us/batch Ed25519 verify.

Quoting 57.6M as the engine's ingest rate is a **layer mismatch**. The core number is the data-structure floor, NOT the production rate an operator sees.

**Provenance:** the 32c core number was physically measured on upstream-lineage pre-fork silicon (cache-line post-mortem SHA `f719be4`, not in this fork's git history). A this-fork 32c re-run of `RUN_CRUCIBLE=1 go test -v -run TestStage5ScalingGate ./pkg/sync/` on operator-provided c8g.8xlarge is PENDING (the track4 c8g run recorded other benches but not the Stage5 crucible). Until that re-run, this fork inherits the upstream evidence honestly.

This throughput is not a software-engineering flourish; it is
the result of three deliberate physical abstractions: (i) the complete
circumvention of Go's mark-and-sweep garbage collector via an `mmap`'d
off-heap arena, (ii) the eradication of cache-coherence stall via a
**128-byte-stride Home-Shard SEC Allocator** that defeats the Neoverse-V1
L2 spatial prefetcher, and (iii) the mathematical convergence guarantee of
state-based $\delta$-CRDTs, which makes the engine's distributed state
asynchronous and recoverable.

The engine executes entirely in user-space. No `mmap`'d file-backed page
cache, no kernel `fsync` blocking on the hot path, and no mutex acquisition
in the steady-state read/write path. The architecture partitions every
responsibility along hardware boundaries — cache lines, NUMA domains, and
process isolation boundaries — so that the parallelism of the software is
isomorphic to the parallelism of the silicon.

## 1.2 The Physical Constraints That Shape The Architecture

Three hardware limits bound the design space. Stating them first makes
every architectural choice that follows deductive rather than accidental.

1. **The L3 interconnect ceiling.** A Neoverse-V1 core retires instructions
   at its issue width; the 32-core CMN-700 mesh can transport only a finite
   number of cache lines per nanosecond between coherent L1/L2 caches.
   Once a workload produces cross-core coherence traffic (store-owned cache
   lines migrating between cores), throughput collapses to the interconnect's
   serialized bandwidth rather than the aggregate issue rate. The blueprint's
   legacy single-locus SEC gate (`TestEliminationCrucibleScalingGate`)
   measurably exhibits this: it caps at **1.1M ops/s @32c (1.6% parallel
   efficiency)** because every free/recycle CAS funnels onto one cache line.
2. **The Go garbage collector.** Go's concurrent mark-and-sweep collector
   runs `gcBgMarkWorker` goroutines that scan the live object graph and apply
   write barriers. At tens of millions of allocations per second, the
   collector saturates the CPU and introduces stop-the-world pauses that
   violate sub-millisecond tail latency. The only escape is to never allocate
   on the hot path at all — the Zero-GC mandate (see §2 of this suite,
   `2_MEMORY_MODEL.md`).
3. **Major page faults.** A virtual page that is not resident in physical RAM
   triggers a synchronous, un-schedulable disk I/O on first touch. The Go
   cooperative scheduler is blind to this — a single deref of an evicted page
   stalls the entire `GOMAXPROCS` thread pool. The engine pins its hot index
   pages with `mlock(2)` (see `3_STORAGE_DURABILITY.md`).

## 1.3 System Topology

The engine is organized as a **decoupled Supervisor–Worker process model**,
a topology mandated by the physics of off-heap memory faults.

```
┌────────────────────────────── SUPERVISOR PROCESS ──────────────────────────────┐
│  net.Listener (owns all external TCP connections — NEVER handed to a worker)      │
│  WAL path + Worker NodeID                                                      │
│        │                                                                       │
│        │  os/exec.Spawn  (piped stdin/stdout — survives child SIGSEGV)         │
│        ▼                                                                       │
└────────────────────────────── WORKER PROCESS ─────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────┐
│  DeltaCRDTEngine (off-heap δ-CRDT, mmap'd arena)                               │
│  ┌───────────────┐  ┌──────────────────┐  ┌──────────────────────┐             │
│  │  HAMT (Trie)  │  │  HamtArena (mmap)│  │ EBRManager           │             │
│  │ path-copying  │  │  slab allocator  │  │ Epoch + Hazard Ptrs  │             │
│  └───────────────┘  └──────────────────┘  └──────────────────────┘             │
│  WAL (fsync-on-commit)                                                         │
└────────────────────────────────────────────────────────────────────────────────┘
```

The Supervisor owns the listening socket. A worker process owns the engine
and the WAL. When a worker suffers a fatal `SIGSEGV` in off-heap C-space —
an event `recover()` cannot intercept, since `mmap`'d memory is outside
Go's safety net — the worker dies and its stdout pipe closes; the
Supervisor observes the `io.EOF`, replays the WAL into a freshly-spawned
worker, and retransmits the last unacknowledged mutation. **No active
client connection is dropped** across the crash + recovery cycle, because
no connection ever transits the worker's address space. This property is
mechanically proven by `TestStage6SIGSEGVSurvival` (see `3_STORAGE_DURABILITY.md`).

## 1.4 The Bitemporal Property Graph And Data Model

The ledger's elementary unit of mutation is the `TriTemporalEvent`, a tuple
that records three disjoint time dimensions to preserve an immutable,
auditable historical trajectory. The engine brands the **three load-bearing**
temporal axes — `SystemTime × ValidTime × AssertionTime` — as "tri-temporal";
a fourth field, `DecisionTime`, is carried on the struct and the wire but is
not yet a load-bearing query axis (see the table note below).

| Temporal Axis      | Source               | Semantics                                                            |
|:-------------------|:---------------------|:--------------------------------------------------------------------|
| **Valid Time**     | `[ValidTimeStart, ValidTimeEnd)` | The interval in the modeled reality during which the event is true. |
| **Transaction Time** (`SystemTime`) | Lamport-stamped at `InsertLocal` | The instant the engine durably accepted the mutation. |
| **Assertion Time** | `AssertionTime`     | The instant a downstream authority attested the record (audit ledger). |
| **Decision Time** | `DecisionTime`       | A fourth temporal field on `CRDTEntry` (`pkg/sync/hamt.go:38`) and the wire (`decisionTime @10 :Int64` in `api/capnp/api/capnp/schema.capnp`). Carried, round-tripped by the chaos codec/byzantine harness (`internal/chaos/codec.go`, `byzantine.go`), and persisted in the snapshot layout (`[104:112)` in `pkg/durability/snapshot.go`). **Reserved/currently non-load-bearing:** it is not consulted by any in-tree read, range, or AsOf selection — the three axes above are the active query dimensions. |

An event is never overwritten. Two events describing the same entity at
overlapping Valid-Time intervals are resolved by the **CRDT dot-join**:
`Join(delta)` (`pkg/sync/crdt.go:1089`) is a merge-union over the per-shard
HAMT — `perShardMerge` runs the per-entityID dot-merge and **drops nothing**;
both the winner and the loser dot stay in the append-only HAMT. `HashCausalDot`
(`pkg/sync/crdt.go:1580`) FNV-1a hashes `(DotNodeID, DotCounter, PayloadDigest)`
for the IBLT. The lossless read-time tie-break is `selectLatestDot`
(`pkg/mesh/gossip.go:531`), a pure 2-dimensional pick — larger `DotCounter`,
then `bytes.Compare(DotNodeID)` — through which both `handleGet` and
`LatestPayload` route so `/v1/get` and the accessor can never disagree (the
Day-6.5 FIX B root cause). The engine never performs I/O inside the resolver.

> **Operator-algebra status (honest negative).** The blueprint's **TOKI
> operator algebra** (LWW, Evidence-Weighted, Await-Confirm) is a **planned,
> not-yet-implemented** conflict policy — a documented P0 gap
> (`pkg/conflict/strategy.go`). ADR-0033
> (`docs/architecture/adr/0033_toki_closure_ghost_exorcism_track28.md`)
> **deleted** the `internal/temporal_store/` TOKI module on Day 28 precisely
> because wiring its eager `Resolve` into `Join` is a CRDT convergence-law
> regression; the live HAMT read path shipped Day 27 IS the genuine lossless
> conflict resolution. Likewise the **128-byte cache-aligned `AuditRecord`**
> and the **Judge-Log** subsystem described in earlier drafts are **planned,
> not implemented** — no such struct or subsystem compiles into the engine
> (`grep AuditRecord JudgeLog` returns zero hits). On conflict the engine
> emits the dot-bearing `CRDTEntry`; the loser is **not** dropped.

| Dimension        | Legacy CRUD Model                  | Supremum Tri-Temporal Model                                 |
|:-----------------|:-----------------------------------|:-------------------------------------------------------------|
| History          | Destructive `UPDATE`/`DELETE`      | Immutable; every mutation appends a new event                |
| Time semantics   | Single `created_at` instant        | Three disjoint axes (Valid / Transaction / Assertion)        |
| Conflict policy  | Last-write-wins by wall clock      | CRDT dot-join (merge-union, no drop) + lossless read-time `selectLatestDot` pick; TOKI operator algebra is planned, not yet implemented (ADR-0033) |
| Auditability     | Reconstructable from binlogs       | H1-compliant: the audit ledger is first-class state          |

### 1.4.1 H3 Hexagonal Spatial Index — Reserved Axis, Not a Live Subsystem

Each event carries an `H3Index uint64` field on `CRDTEntry`
(`pkg/sync/hamt.go:39`) and on the wire (`h3Index` in
`api/capnp/api/capnp/schema.capnp`); it is set by the mesh and snapshot paths
and packed into the O2.2 memtable value layout. It is intended as a cell
identifier in the H3 Hexagonal Hierarchical Spatial Index, so that spatial
relationships could be expressed as integer cell arithmetic rather than
floating-point polygon intersection (eliminating the non-determinism of
IEEE-754 geometry). **H3 cells are not, however, computed on any in-tree
engine path.** The `h3o`/uber-h3 dependency is absent from `go.mod` (the
`zeebo/xxh3` entry is an unrelated hash library), the tree contains no
`.c`/`.cpp`/`.h` source, and the only in-tree assignment of `H3Index` on a
real path is a **synthetic key-derived value** in the chaos harness
(`H3Index: uint64(k) << 8` at `internal/chaos/partition.go:336`) — not an H3
cell. H3 is therefore a **reserved/passthrough spatial axis**, not a working
native geospatial index.

The in-tree Go producer that *would* feed a real H3 resolver ships in this
repository but is currently **unwired**: `internal/spatial/h3_spsc_ring.go`
is a pure-Go single-producer/single-consumer ring buffer (no `import "C"`,
no `#include`) that `mmap`s a `memfd_create(2)` region and writes `(lat, lng)`
into slots, expecting an **external C++ `h3_worker` binary** (referenced at
`h3_spsc_ring.go:136,:328`) to drain the ring and write the computed cell
back. That binary **does not exist anywhere in this repository** — it is an
operator-supplied/out-of-tree process boundary. The companion
`internal/spatial/epoch_batcher.go` (`EpochBatcher`) batches `Stage(lat,lng)`
calls into epochs and reads results back, but neither the ring nor the
batcher is imported by any non-test file outside `internal/spatial/` itself
(`grep -rHn 'supremum/internal/spatial' --include='*.go'` restricted to
production callers returns zero hits). The Go-side `memfd_create` + `ExtraFiles`
plumbing is real and is the reason the `memfd` route (rather than anonymous
`mmap`) is used: anonymous mappings are **severed across `execve`
boundaries**, so the child would receive `fd=-1` and the ring would diverge.

> **Open-source release note.** The Go-side SPSC ring and `EpochBatcher`
> producer (`internal/spatial/`) ship in this repository as a **reserved,
> currently-unwired** spatial axis — no engine path instantiates them, and no
> H3 cell is computed in-tree. The standalone C++ `h3-worker` consumer binary
> that drains the ring is **out-of-tree**: it is an operator-supplied process
> boundary, not a library concern, and is not present in this repo. The ring's
> memory layout is documented at `internal/spatial/h3_spsc_ring.go` so an
> operator can build a compatible consumer against it. To wire H3 as a live
> spatial index, an operator must supply the `h3_worker` binary and add an
> engine importer of `internal/spatial`; until then the `H3Index uint64` is
> carried passthrough and (on the chaos path) seeded synthetically.

## 1.5 Consensus Mechanisms

The engine is a state-based $\delta$-CRDT replication substrate. Convergence
is the **lattice-join** property, not a quorum vote.

- **Local mutation** is `InsertLocal(entityID, entry)`, which mints a
  `CausalDot{DotNodeID, DotCounter}` from the source node's Lamport counter.
- **Anti-entropy** is `GenerateDelta(remoteDigest)` → `Join(delta)`. The
  delta encodes only the symmetric difference between the sender and the
  receiver, computed via an Invertible Bloom Lookup Table (IBLT) subtract
  and peel — a *sub-linear* reconciliation (see `4_NETWORK_CONSENSUS.md`).
- **Merkle convergence** is asserted post-recovery: `Node[i].MerkleRoot() ==
  Node[j].MerkleRoot()`. The root is `SHA-256` over the canonical sort of
  `(DotNodeID, DotCounter)` pairs — it is **seed-independent**, so a worker
  started from a fresh `maphash.MakeSeed()` reproduces the identical root
  for the same mutation sequence.

## 1.6 Edge Ubiquity

The ledger is supremum on the edge as well as in the datacenter. The edge
substrate (deliberately deferred from the core engine per
D8 FIX: the prior revision referenced an `EXTERNAL_INTEGRATIONS_DEFERRED.md`
that does not exist in this repo. The edge substrate is out of scope for the
core ledger ball and is described at the architectural level only; it selects
between three OPFS-backed
SQLite-WASM VFSes — `AccessHandlePoolVFS` (exclusive, single-tab),
`OPFSCoopSyncVFS` (leader-tab multiplexing), and `OPFSWriteAheadVFS`
(dual-WAL, the chosen production VFS for multi-tab durability) — to perform
offline-first bitemporal queries directly in the browser. Analytical
workloads run on DuckDB-WASM, which issues HTTP range requests against Parquet
files on decentralized object storage, bypassing centralized egress taxes.
Inter-node traffic is encoded in Cap'n Proto for zero-copy RPC: the engine's
`GenerateDelta` returns a `*CRDTDelta` whose `Entries` lazy iterator yields
the (entityID, CRDTEntry) pairs the remote peer is missing; a transport
encodes those pairs (see `internal/chaos/partition.go` for the canonical
length-prefixed deltagram encoding) into the wire format the receiver
`Join`s. The ingestion plane uses the `TriTemporalEvent` Cap'n Proto
schema (see `api/capnp/api/capnp/schema.capnp`), whose bytes are readable
directly from the network socket memory without CPU deserialization.

## 1.7 Document Suite Compass

| File                                | Domain                                                                  |
|:------------------------------------|:------------------------------------------------------------------------|
| `1_ARCHITECTURE.md` (this file)     | Master overview, topology, data model                                   |
| `2_MEMORY_MODEL.md`                 | Zero-GC, off-heap physics, Home-Shard SEC, MESI, SPSC                   |
| `3_STORAGE_DURABILITY.md`           | `mmap` hazards, chunked `mlock`, WAL, `io_uring`/`O_DIRECT`              |
| `4_NETWORK_CONSENSUS.md`            | $\delta$-CRDT, Birkhoff decomposition, TOKI (planned/closed-by-rejection, ADR-0033), IBLT, Edge compute |
| `5_BENCHMARKS_AND_LIMITS.md`        | 57.6M RPS decomposition, silicon wall, scaling limits                 |
