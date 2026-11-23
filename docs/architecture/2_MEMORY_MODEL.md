# 2. Memory Model

## 2.1 Off-Heap Allocation and the Go Collector

Go's concurrent, tri-color mark-and-sweep collector finds and scans objects
on the Go heap. Path-copying a HAMT on every mutation would make that work
part of the write path: new nodes would need runtime allocation bookkeeping,
and heap pointer writes could require write barriers. Sovereign Engine
instead keeps the trie and its payloads in an anonymous mapping that the
collector does not scan.

This is a property of a specific path, not a global collector switch. The
in-process core benchmark measured 50.7M–68.3M ops/s at 32 cores; that is
not the network ingest rate. `TestHotPathZeroAllocations` uses
`testing.AllocsPerRun` to assert `0 allocs/op` for `HAMT.Set` when the race
detector is off. Other engine paths still allocate Go heap objects, and the
runtime collector remains enabled.

`go test -run TestArenaUsagePerSet ./pkg/sync/` measures the other side of
this design: arena consumption. It logs the per-op figure for one batch,
then repeats the measurement after more insertions have deepened the trie.
The mapping avoids Go heap allocation for these writes; it does not make
their storage free.

## 2.2 The Off-Heap Substrate

`NewHamtArena` obtains memory with
`syscall.Mmap(-1, 0, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE)`.
It records the mapping's base address in `HamtArena.base` and uses
`unsafe.Pointer` arithmetic to reach nodes and payloads. The Go runtime has
no heap metadata for these pages, so the collector does not scan them.

### 2.2.1 HamtNode Layout

The fixed allocation unit for a trie branch is `HamtNode`:

```go
type HamtNode struct {
    refCount    atomic.Int32 // 4 B  — reference count
    bitmap      uint32       // 4 B  — HAMT child-presence bitmap
    _           uint32       // 4 B  — explicit pointer alignment
    childrenPtr NodePtr      // 8 B  — children array address
    entriesPtr  NodePtr      // 8 B  — leaf entries array address
    merkleHash  [32]byte     // 32 B — reserved branch-hash field
    nextFree    NodePtr      // 8 B  — reserved free-list field
}
```

`NodePtr` is a `uintptr` holding an address in the arena, not a Go pointer.
Storing a `NodePtr` therefore does not create a collector-visible heap
reference or require a heap write barrier. Code that places a Go pointer in
an off-heap wrapper must keep its target reachable elsewhere; `HAMT.arena`
is the important example.

The reserved fields do not imply unused fast paths are active.
`HAMT.MerkleRoot` currently walks leaf entries, sorts their dots, and hashes
them instead of reading `merkleHash`. Class-0 recycling writes the next
free-list link into a dead node's first machine word, not into `nextFree`.

### 2.2.2 The Segregated Slab Allocator

The arena has 17 size classes: one dedicated to `HamtNode` (the `nodeSize`
constant, measured by `unsafe.Sizeof`) and 16 power-of-two variable classes.
Every variable block has an 8-byte allocator header before its payload.

| Class | Block size (B) | Payload capacity (B) | Typical occupant |
|------:|:---------------|:---------------------|:-----------------|
| 0 | `nodeSize` | — | `HamtNode` |
| 1 | 16 | ≤ 8 | next-pointer / small scalar |
| 2 | 32 | ≤ 24 | `allocString` short-key bytes |
| 3 | 64 | ≤ 56 | `hamtLeaf` arrays: one 32 B leaf plus its 8 B length prefix uses 40 B of payload before the separate slab header |
| 4 | 128 | ≤ 120 | `CRDTEntry` (exactly 120 B) |
| … | … | … | power-of-two doubling |
| 16 | 524,288 | ≤ 524,280 | large payloads / bulk transfer |

Both node and variable free-lists are sharded lock-free Treiber stacks, but
they use different ABA protection. `AllocNode` holds an EBR participant
across each pop. Its untagged 64-bit head cannot revisit a retired node
while that participant prevents reclamation.

Variable-class heads pack a generation with the block's word offset. Each
block's 8-byte header atomically packs the next word offset and class index.
This protects both EBR-deferred reclamation and direct `pushFreeVar` calls
that do not hold an EBR pin. `allocVar` sweeps a bounded set of shards under
one pin before falling back to the atomic `bumpOffset` allocator.

## 2.3 Cache Coherence

The allocator layouts target Neoverse-V1 systems with 64-byte L1 cache
lines and 128-byte L2 spatial-prefetch pairs. On the 32-core CMN-700 system,
writes to shared lines require coherence transfers across the mesh. A HITM
(Hit In a Modified cache line) identifies the case where the requested line
is modified in another cache.

### 2.3.1 False Sharing

False sharing occurs when logically independent variables occupy the same
cache line. A store by one core invalidates that line in another core's
cache, even when the second core accesses a different field. Its next
access must fetch the line again. Repeated writes can therefore serialize
otherwise independent operations on coherence traffic. `perf c2c` reports
HITM events for measuring this behavior.

### 2.3.2 The 128-Byte Stride Discipline

A structure that occupies its own 128-byte prefetch pair cannot share that
pair with a neighboring structure. The pool uses this layout for its
free-list shards:

```go
type ElimPoolShard struct {
    free atomic.Uint64 // 8 B   — packed free-list head
    _pad [120]byte     // 120 B — fill the prefetch pair
}
// sizeof(ElimPoolShard) == 128 B exactly
```

The free-list array is `[64]ElimPoolShard`, so adjacent heads start on
separate 128-byte boundaries. `ElimSlot` and `secShard` use the same stride;
`TestEliminationSlotSize` and `TestShardedShardSize` assert their sizes.
Other padded structures use different layouts where a full prefetch pair is
not required.

### 2.3.3 The Sharded Stack Allocator

The legacy single-locus design measured 1.1M ops/s at 1.6% parallel
efficiency on 32 cores. Its free and recycle operations contended on one
pool-head cache line. `ShardedStack` instead routes P-local operations to
64 padded stack heads and spreads the index pool across the same number of
`ElimPoolShard` heads, which occupy 8 KiB in total.

A per-goroutine `secDeepCache` keeps most index recycling local. On a cache
miss, `deepAlloc` refills from the caller's shard and probes later shards if
necessary. `deepFreeLocal` retains a popped index in that cache and drains
overflow to the caller's shard. Thus the sharded pop path does not route
through `freeIndexHome(idx)`. That helper remains for callers without a P
ID and returns an index to shard `idx % 64`.

Both stack heads and pool free-list heads pack a generation with an index.
When the successor is non-empty, a CAS derives the new generation from the
observed head. A recycled index therefore does not by itself make a stale
non-empty head compare equal.

The in-process sharded benchmark has a published range of 50.7M–68.3M ops/s
at 32 cores, with a gate-passing floor of 50,736,038 ops/s. The
[core benchmark receipt](../evidence/core-crucible.txt) records 68,278,197
ops/s on a 32-core AWS Graviton4 c8g.8xlarge with Go 1.26.1. It measures
stack and allocator work without network, cryptographic verification, or
persistence; it is not an ingest throughput measurement.

## 2.4 Epoch-Based Reclamation and Hazard Pointers

`RetireBlock` places a block on a sharded list in a three-epoch ring.
`AdvanceEpoch` refuses to advance while an active participant records an
older epoch. After a successful advance, it detaches the list that has
completed its grace interval and reclaims entries that are not protected by
a hazard pointer. Reclamation therefore requires later epoch advances; a
retirement is not simply delayed by counting three calls.

Each participant has four hazard slots. `DetachAndProtect` publishes a
pointer in a slot and marks the participant inactive, allowing a read to
continue without holding an EBR pin. Reclamation snapshots the published
hazards and requeues a matching block for a later epoch instead of freeing
it while the reader can still dereference it.

`TestEBRHazardPointerSequencing` exercises the ordering between protection
and reclamation. `TestConcurrentInsertLocalRace` exercises concurrent
insertion and root retirement under the race detector.

## 2.5 Cross-Process SPSC Ring

`internal/spatial` contains a single-producer, single-consumer ring for
sending coordinates to an external C++ H3 worker. This package is built but
not wired into the production engine: no non-test engine path constructs
the ring or its `EpochBatcher`, and the worker binary is not in this
repository. It does not currently compute H3 cells for engine writes.

`NewSPSCRing` creates a `memfd`, sizes it, and maps it with
`MAP_SHARED|MAP_POPULATE`. The file descriptor can be passed to a child
through `os/exec.Cmd.ExtraFiles`, allowing both processes to map the same
pages. A steady-state slot handoff uses shared-memory atomics rather than a
message-passing syscall.

The header reserves cache-line-padded `WriterCursor` and `ReaderCursor`
fields, but Go does not currently use those cursors for coordination.
Instead, `RingSlot.State` tracks each slot:

- `Submit` waits for `SlotEmpty`, writes the request, and stores `SlotReady`.
- The external consumer changes ready slots through `SlotProcessing` to
  `SlotDone` after writing the result.
- `Collect` waits for `SlotDone`, reads the result, and returns the slot to
  `SlotEmpty`.
- `EpochBatcher` adds a bounded collection wait and uses compare-and-swap
  when recovering or reclaiming a timed-out slot.

The SPSC contract limits each ring to one producer and one consumer. It does
not imply that every wait is spin-only: a full submission can park on a Go
condition variable.

## 2.6 Limits

Off-heap pointer arithmetic bypasses Go's memory safety. An invalid arena
address can raise a fatal `SIGSEGV` rather than a panic that `recover()` can
handle; the process boundary and recovery path are described in
[Storage and Durability](3_STORAGE_DURABILITY.md). Off-heap wrappers also
require an explicit Go-heap owner for any Go pointers they contain.

The memory costs are visible in the layouts. Cache-pair padding increases
the footprint of sharded heads and slots. Power-of-two slab classes can
waste up to 2× the requested space at class boundaries. Reclamation is
deferred by epoch and hazard safety, so protected blocks remain allocated
until their readers finish.
