# 2. Memory Model — Zero-GC Off-Heap Physics

## 2.1 The Failure Of Standard Go At Scale

Go's runtime ships a concurrent, tri-color mark-and-sweep garbage collector.
At steady state under light load it is efficient. Under the Supremum
Ledger's target load — tens of millions of mutations per second, each
touching a path-copied HAMT subtrie — it is the dominant cost. Every heap
allocation registers with the runtime's `mspan`/`mcentral` hierarchy; every
pointer write to a heap object that may be referenced concurrently is
intercepted by a write barrier; and `gcBgMarkWorker` goroutines consume one
P each to scan the live object graph. At 57.63M ops/s the collector would
run continuously, its mark assist goroutines stealing application CPU and
its periodic stop-the-world sweeps inserting tail latencies incompatible
with the sub-millisecond mandate.

The engine's response is structural, not tunable. The hot path **does not
allocate on the Go heap, ever**. Stage 1's `TestHotPathZeroAllocations`
gate is a compile-time-enforced CI assertion reporting `0 allocs/op` on the
`HAMT.Set` path; `go test -run TestArenaUsagePerSet` logs per-op arena
consumption (observed ~1,153 B/Set at shallow trie depth; the test logs a
second batch to show the per-op figure grows with trie depth), all of it in
the `mmap`'d region the collector does not scan. The result is a strict Zero-GC runtime
state — the collector sees no live root set on the hot path and turns
itself off.

## 2.2 The Off-Heap Substrate

The engine obtains memory directly from the kernel via
`syscall.Mmap(-1, 0, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE)`.
The returned slice's base address is captured into a `uintptr`
(`HamtArena.base`); all subsequent access is raw `unsafe.Pointer` arithmetic
into this region. Because the Go runtime has no metadata describing these
pages, the garbage collector cannot scan them, and the write barrier is
never engaged for arena traffic.

### 2.2.1 HamtNode Layout

The fundamental allocation unit is the `HamtNode`, a struct whose layout is
fixed at compile time and intentionally cache-aligned at the field level:

```go
type HamtNode struct {
    refCount    atomic.Int32   // 4 B  — EBR reference count
    bitmap      uint32          // 4 B  — HAMT child-presence bitmap
    _           uint32          // 4 B  — explicit pointer alignment
    childrenPtr NodePtr         // 8 B  — offset to children array
    entriesPtr  NodePtr         // 8 B  — offset to leaf entries array
    merkleHash  [32]byte       // 32 B — cached branch hash (O(1) MerkleRoot)
    nextFree    NodePtr         // 8 B  — intrusive Treiber free-list link
}
```

`NodePtr` is defined as `uintptr` deliberately — using a non-pointer type
prevents the Go runtime from treating arena offsets as roots the collector
must trace. The compiler therefore never inserts a write barrier for
`childrenPtr`/`entriesPtr` updates, even mid-CAS-loop.

### 2.2.2 The Segregated Slab Allocator

The arena is a **segregated slab allocator** of 17 size classes: one
dedicated class for `HamtNode` (the `nodeSize` constant, measured by
`unsafe.Sizeof`) and 16 power-of-two variable classes for payloads.

| Class | Block size (B)  | Payload capacity (B) | Typical occupant                     |
|------:|:----------------|:---------------------|:-------------------------------------|
| 0     | `nodeSize`      | —                    | `HamtNode` (cache-aligned fixed)     |
| 1     | 16              | ≤ 8                  | next-pointer / small scalar          |
| 2     | 32              | ≤ 24                 | `allocString` short-key bytes (≤24 B payload + 8 B header) |
| 3     | 64              | ≤ 56                 | `hamtLeaf` arrays (8 B length prefix + N×32 B leaves), classed by total size — a single 32 B leaf + 8 B header = 40 B → 64 B class-3 block |
| 4     | 128             | ≤ 120                | `CRDTEntry` (exactly 120 B)          |
| …     | …               | …                    | power-of-two doubling                |
| 16    | 524,288         | ≤ 524,280            | large payloads / bulk transfer       |

Free memory in each class is managed by a **lock-free Treiber stack** whose
ABA immunity does **not** rely on a packed generation word — it relies on
**EBR epoch-pinning**: each pop wraps its Treiber CAS in
`participant.Enter/Exit` (`hamt_arena.go` AllocNode, ~:463-464), pinning the
goroutine to the current epoch so no concurrent `RetireBlock` can recycle
the `head` offset back onto the stack during the CAS ("eliminating ABA
without generation counters," `hamt_arena.go` ~:460; "Pure 64-bit CAS — no
generation counter needed," ~:490). "ABA immunity is provided by the
EBRManager" (`hamt_arena.go` ~:159). (The packed `(generation, offset)`
tagged-counter ABA scheme belongs to the **elimination pool** allocator of
§2.3.3, `elimPackIndex` in `elimination.go` ~:1015-1024 — a *different* ABA
mechanism from the arena slab.) Allocation falls back to a linear bump
pointer (`bumpOffset`) when a class's free stack is empty, guaranteeing
$O(1)$ amortized allocation with zero contention.

## 2.3 Cache-Coherence Physics

A modern multi-core die is not a flat memory. Each Neoverse-V1 core owns a
64-byte-line L1 and a 128-byte-pair L2; the 32 cores share an L3 and its
CMN-700 mesh interconnect. Coherence is maintained by the **MESI protocol**
(Modified, Exclusive, Shared, Invalid). The economically significant event
in this protocol for a write-heavy workload is a **HITM** — a Hit In a
Modified cache line — which forces the owning core to push the line across
the interconnect to the requesting core, serializing two cores onto the
mesh bandwidth.

### 2.3.1 False Sharing

False sharing occurs when two logically independent variables land in the
same 64-byte cache line. A store by Core A invalidates the line in Core B's
cache; Core B's next read of *its own* variable misses and must pull the
line back from Core A. The two cores execute sequentially at interconnect
speed rather than in parallel. `perf c2c` (the blueprint's Stage 4 probe)
measures this directly via HITM counters.

### 2.3.2 The 128-Byte Stride Discipline

The engine defeats false sharing with a **128-byte stride discipline**,
chosen because the Neoverse-V1 L2 spatial prefetcher pulls *pairs* of
adjacent 64-byte lines. A 64-byte pad between two structures is insufficient
— the prefetcher would still pair them. The engine therefore aligns every
hot data structure to **128 bytes (two cache lines)**:

```go
type ElimPoolShard struct {
    free  atomic.Uint64   // 8 B  — the locus of all free/recycle CAS
    _pad  [120]byte       // 120 B — fill the remaining line pair
}
// sizeof(ElimPoolShard) == 128 B exactly
```

The free-list is an array `[64]ElimPoolShard`, so adjacent allocator shards
sit on disjoint 128-byte line pairs — the prefetcher cannot engender
cross-shard coherence traffic. This same discipline is applied to the engine
proxy structs, the elimination slots (`ElimSlot` at 128 B, asserted by
`TestEliminationSlotSize`), and the home-shard stack shards (`secShard` at
128 B, asserted by `TestSecShardSize`). (An earlier plan referenced a
`JudgeLogRingBuffer` here; that type was never built — it was sketched in
`internal/temporal_store/toki.go`, which ADR-0033 / Day 28 deleted. The
128-byte stride is carried by the three real structs above, not by a phantom
ring buffer.)

### 2.3.3 The Home-Shard SEC Allocator

The allocator's free path is the most contentious locus in a producer-heavy
workload. The legacy single-locus design (one Treiber stack head for the
whole pool) collapses to 2% parallel efficiency on the 32-core mesh because
every producer's free CAS funnels onto one `head` cache line, recreating the
coherence storm the per-core sharding was meant to defeat.

The **Home-Shard SEC Allocator** replaces it with a **multi-locus free-list**:

| Property            | Legacy single-locus             | Home-Shard SEC                                     |
|:--------------------|:--------------------------------|:---------------------------------------------------|
| Free locus          | 1 shared `head` cache line      | 64 sharded `ElimPoolShard` heads (8 KiB total)      |
| Free routing        | push to executing thread's shard | `freeIndexHome(idx)` → shard `idx % 64`            |
| Alloc routing       | pop from shared stack           | local-shard-first, probe `(pid+1, +2, …)` on miss |
| Stride              | unguarded (false-shared)        | 128 B (defeats Neoverse-V1 L2 prefetcher pair)     |
| @32c throughput     | **1.1M ops/s** (1.6% eff.)      | **57.63M ops/s** (`RUN_CRUCIBLE=1`, linearizable)  |

The "Home-Shard" naming reflects the routing rule: a producer freeing index
`i` pushes to shard `i % 64`, not to its own executing thread's shard. Under
skew (many producers, few consumers) the consumers scatter their frees across
all 64 home shards, continuously refilling every producer's local shard and
defeating the work-stealing trap. ABA immunity is preserved: the sharded
stacks reuse the identical packed `(gen, idx)` encoding and the strict
monotonic generation discipline of the legacy stack.

## 2.4 Concurrency Physics: Elimination And Hazard Pointers

The engine combines two complementary lock-free primitives.

- **Epoch-Based Reclamation (EBR)** batches node retirement: a retired node
  is not freed until three epochs have passed, after which no reader whose
  `Participant.Enter()` preceded the retirement can still hold a reference.
  This bounds reclamation cost and removes the mutex from the free path.
- **Hazard Pointers** protect the single-pointer hand-off on the read path:
  a reader publishes the `NodePtr` it is about to dereference into a hazard
  slot before reading; a retiree scans the hazard slots and defers reclaiming
  any node a reader has published. The mutual ordering is the EBR epoch
  barrier, guaranteeing the dereference cannot observe a freed node.

These two compose: EBR amortizes retirement; hazard pointers close the
read-vs-reclaim race. `TestEBRHazardPointerSequencing` and
`TestConcurrentInsertLocalRace` (Stage 2, `-race` clean) are the
mechanical witnesses.

## 2.5 Cross-Core Lock-Free Message Passing — The SPSC Ring

Where mutation must cross a process boundary (Go parent ↔ C H3 worker) the
engine uses a **Single-Producer Single-Consumer ring buffer** backed by
`memfd_create(2)` and mapped `MAP_SHARED` in both processes. The ring is
split into a header (`head`, `tail`, cache-line-padded on each side) and a
slot array. The producer advances `tail` with a single `atomic` store; the
consumer advances `head` with a single `atomic` store; the visibility of
those stores across processes is the `MAP_SHARED` kernel page-cache coherence
guarantee — no message-passing system call, no context switch. The SPSC
invariant (exactly one producer, one consumer) is what removes the lock:
there is no CAS, only `Store`/`Load`, which the architecture allows without
a coherence-invalidation storm because each side writes a *disjoint* cache
line. An `Elimination-Array` (the SEC layer) supplements this intra-core via
parallelism where a SPSC contract is too restrictive.

## 2.6 Honest Limits

The Zero-GC mandate is bought with the loss of Go's safety net in `mmap`'d
space. A single off-by-one in arena pointer arithmetic raises a `SIGSEGV`
that `recover()` cannot intercept (see `3_STORAGE_DURABILITY.md`). The
128-byte stride doubles the memory footprint of every padded structure
relative to a naive layout. The slab allocator's static class boundaries
incur internal fragmentation up to 2× the requested size at class edges.
These are accepted costs of the latency bound, not defects to be tuned away.
