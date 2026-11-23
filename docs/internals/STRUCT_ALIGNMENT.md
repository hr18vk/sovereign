# Struct Alignment — The Byte-Level Proof

This document records the byte layouts of the engine's hot Go structs.
Uncontended records avoid unnecessary alignment padding; concurrently written
fields are grouped or separated according to their access patterns. The size
and field offsets of `CRDTEntry` (120 B) and `hamtLeaf` (32 B) are pinned by
`TestCRDTEntry_SizeAndAlignment` and `TestHamtLeaf_SizeAndAlignment`.
`TestEliminationSlotSize` pins `ElimSlot` at 128 B. `TestHamtNodeOffsets` and
[`TestMemoryLayoutAnalysis`](../../pkg/sync/layout_analysis_test.go) print sizes
and offsets for inspection; they are diagnostics, not assertion gates. Section
4 distinguishes the tests that reject a layout change from the reports that only
describe it.

## 1. Cache coherence and false sharing

A Graviton core fetches memory in 64-byte cache lines, and cache coherence
tracks ownership at line granularity. If two cores write to distinct fields in
the same line, ownership can pass between them on every write. The cores then
wait for coherence transfers rather than making independent progress.

The layouts below use a 128-byte stride between independently contended slots
where that separation is required. Fields that participate in one exchange or
are updated as a group may deliberately share a padded region. Uncontended
records instead aim for zero bytes of avoidable interior padding.

The retired single-locus allocator recorded 1.1M ops/s at 32 cores. After the
allocator was sharded, the in-process CRDT core benchmark recorded
50.7M–68.3M ops/s at 32 cores. Its [upper receipt](../evidence/core-crucible.txt)
reports 68,278,197 ops/s on a c8g.8xlarge on 2026-09-03. These are allocator and
core measurements, not results from the engine-proxy benchmark below.

The in-process receive path is a separate layer. It measured 5.7M–6.0M
deltas/sec at 32 cores on 2026-09-15, including Ed25519 verification, envelope
decoding and CRDT application; its conditions and output are in the
[receive-path receipt](../evidence/ingest-ed25519.txt).

The focused false-sharing comparison is in
[`physics_test.go`](../../pkg/sync/physics_test.go): two `atomic.Uint64`
counters on one line versus counters separated by `CacheLinePad` (`[64]byte`).
On multi-core hardware the padded variant is typically 2×–10× faster. The test
skips when fewer than two threads can run concurrently and allows a timing
margin for scheduler noise; it does not require a fixed speedup.

## 2. Record Structs — Zero Wasted Padding

These record structs prioritize compact representation over per-field line
isolation. Some are immutable after publication; others, such as `HamtNode`,
use atomics or ownership rules for mutable fields. Their order satisfies each
field's alignment requirement without unused gaps.

### `CRDTEntry` — 120 bytes, zero internal padding

[`CRDTEntry`](../../pkg/sync/hamt.go) is a single element in the Add-Wins Set
lattice. Its nested `CausalDot` is flattened into `DotNodeID` and `DotCounter`
to avoid indirection and the resulting alignment hole.

| Field              | Type          | Size (B) | Offset |
|:--|:--|--:|--:|
| `PayloadDigest`    | `[32]byte`    | 32 | 0  |
| `OriginNodeID`     | `[16]byte`    | 16 | 32 |
| `DotNodeID`        | `[16]byte`    | 16 | 48 |
| `DotCounter`       | `uint64`      |  8 | 64 |
| `SystemTime`       | `int64`       |  8 | 72 |
| `ValidTimeStart`   | `int64`       |  8 | 80 |
| `ValidTimeEnd`     | `int64`       |  8 | 88 |
| `AssertionTime`    | `int64`       |  8 | 96 |
| `DecisionTime`     | `int64`       |  8 | 104|
| `H3Index`          | `uint64`      |  8 | 112|
| **total**          |               | **120** | |

The byte arrays come first, followed by the 8-byte words. After `DotNodeID`,
every subsequent field begins at an offset that satisfies its alignment. The
size, alignment and offset assertions in `TestCRDTEntry_SizeAndAlignment` make
an unintended reorder visible; `fieldalignment` is not the enforcing gate.

### `hamtLeaf` — 32 bytes

[`hamtLeaf`](../../pkg/sync/hamt.go) stores entries for one entity ID at a leaf.
Both `entityPtr` and `entriesPtr` are `NodePtr` values (uint64 offsets into the
mmap arena), not Go pointers, so the leaf does not add Go heap pointers to the
arena representation. Its test asserts a size of exactly 32 bytes.

| Field         | Type      | Size | Offset |
|:--|:--|--:|--:|
| `hash`        | `uint64`  |  8 | 0  |
| `entityPtr`   | `NodePtr` |  8 | 8  |
| `entriesPtr`  | `NodePtr` |  8 | 16 |
| `entityLen`   | `uint32`  |  4 | 24 |
| `entriesLen`  | `uint32`  |  4 | 28 |
| **total**     |           | **32** | |

The two `uint32` length fields are packed into the tail 8 bytes after the three
`uint64` fields, so the struct's size is 32 with zero trailing pad. An 8-byte
read of `(entityLen, entriesLen)` cannot cross a 64-byte cache-line boundary.

### `HamtNode` — 72 bytes

[`HamtNode`](../../pkg/sync/hamt_arena.go) is an off-heap HAMT node with an
atomic reference count for epoch-based reclamation. The struct occupies 72
bytes. `TestHamtNodeOffsets` logs its size and selected offsets; it does not
assert them.

| Field                | Type           | Size | Offset |
|:--|:--|--:|--:|
| `refCount`           | `atomic.Int32` |  4 | 0  |
| `bitmap`             | `uint32`       |  4 | 4  |
| `_` (explicit pad)   | `uint32`       |  4 | 8  |
| compiler alignment   |                |  4 | —  |
| `childrenPtr`        | `NodePtr`      |  8 | 16 |
| `entriesPtr`         | `NodePtr`      |  8 | 24 |
| `merkleHash`         | `[32]byte`     | 32 | 32 |
| `nextFree`           | `NodePtr`      |  8 | 64 |
| **total**            |                | **72** | |

`refCount` and `bitmap` already fill the first 8 bytes, so the explicit
`_ uint32` at offset 8 does not fill a gap between them and `childrenPtr`. The
compiler inserts four more bytes of alignment after that explicit field, before
`childrenPtr` at offset 16. The 72-byte total therefore includes both the
explicit word and the implicit four-byte gap.

The current free-list implementation does not store its link in `nextFree`.
After EBR makes a dead node reusable, `pushFreeNode` writes the Treiber
next-offset into its first 8 bytes, overwriting `refCount` and `bitmap`;
`AllocNode` reads the same word while holding an EBR participant. `nextFree` is
zeroed during allocation but is not used as the link.

## 3. Contended atomics and cache-line separation

These structs contain fields written concurrently by multiple cores. Packing
them as tightly as possible would introduce false sharing between independent
operations. `CacheLinePad` (`[64]byte`) separates hot regions, while fields that
belong to one protocol may share a region by design. Offsets below are relative
to the struct's base; physical cache-line placement also depends on the base
address's alignment.

### `DeltaCRDTEngine` — sharded root, per-shard CAS locus

[`DeltaCRDTEngine`](../../pkg/sync/crdt.go) holds `shards []shardRoot`, with each
shard owning one slice of the entity-ID space. `InsertLocal` and `Join` update
the HAMT root only within the selected shard. Padding around each
`shardRoot.ptr` keeps independent root CAS operations on separate lines.

```
per shard (shardRoot):
  _padHead | ptr atomic.Pointer[HAMT] | _padTail
```

The Lamport clock remains shared across root shards. `lamportCounter` and
`lastSavedCounter` occupy one padded region; both are atomic because `NextDot`
and `AdvanceLamportTo` can run concurrently. `epochCounter` and its advance
threshold occupy another padded region. The four metrics counters share a third
region, separated from the clock and epoch fields.

`paddedEngineProxy` and `unpaddedEngineProxy` in
[`physics_test.go`](../../pkg/sync/physics_test.go) compare groups of engine-like
state, Lamport, epoch and metrics atomics with and without padding. The proxy
does not execute `DeltaCRDTEngine.InsertLocal` or the allocator. It isolates
cache-coherence effects rather than measuring end-to-end engine throughput.

### `EBRManager` — separated manager fields

[`EBRManager`](../../pkg/sync/reclamation.go) updates `globalEpoch` in
`AdvanceEpoch` and `head` in `Register`. Padding separates those fields:

```
_globalEpochPad0 | globalEpoch atomic.Uint64 | _globalEpochPad1
_headPad0 | head atomic.Pointer[Participant] | _headPad1
retired [3][arenaRetiredFreelistShardCount]RetiredList
_retiredRoutePad0 | retiredRoute atomic.Uint64 | _retiredRoutePad1
pool | retiredPool
_closingPad0 | closing atomic.Bool | _closingPad1
```

Retirement is distributed across the per-epoch `RetiredList` shards.
`retiredRoute` selects a shard and has its own padded region, as does `closing`.
The two pools sit between those regions.

### `Participant` — per-field isolation

Within each [`Participant`](../../pkg/sync/reclamation.go), `active`, `epoch`
and the `hazards` array are bracketed by `CacheLinePad`. This separates fields
within one participant; it does not make a claim about the relative addresses
of separately allocated participants.

### `ElimSlot` — the 128-byte stride in full

[`ElimSlot`](../../pkg/sync/elimination.go) deliberately places `state` and
`value` on the same line because the two goroutines exchanging a value use both
fields. A full 64-byte tail separates the slot from its neighbour.

```
ElimSlot (128 bytes = 2 cache lines):
  offset  0 : _padLead [48]byte            leading fill
  offset 48 : state    atomic.Uint64       packed (op<<62)|stamp
  offset 56 : value    atomic.Uint64       payload or sink
  offset 64 : _padTail CacheLinePad (64B)  trailing isolation
```

Slot *n*'s `state` is at relative offset `128n+48`, and slot *n+1*'s is at
`128(n+1)+48`. The 128-byte stride keeps adjacent states on different lines
when the array's first line is cache-line aligned. `TestEliminationSlotSize`
asserts the total size that provides this stride.

### `ElimStack.head` — the central contended line

The Treiber head in [`ElimStack`](../../pkg/sync/elimination.go) remains a
single CAS locus when elimination does not absorb contention. Padding separates
it from `collisions`, the adaptive probe-budget accumulator, and from the
embedded `EliminationArray`. The array is held by value, so its slots do not
require separate heap allocations.

## 4. What checks the layout

The public CI workflow's struct-layout step runs
`TestCRDTEntry_SizeAndAlignment`, `TestHamtLeaf_SizeAndAlignment` and
`TestHamtNodeOffsets`. The first two use assertions to check size, alignment
and every field offset. `TestHamtNodeOffsets` only logs its results, so its
presence in that step is diagnostic rather than an offset gate.

`TestEliminationSlotSize` calls `t.Fatalf` if `ElimSlot` is not 128 B, but the
current public CI selection does not include that test.
[`TestMemoryLayoutAnalysis`](../../pkg/sync/layout_analysis_test.go) uses
`unsafe.Offsetof` to print layouts for inspection and has no layout assertions.

`fieldalignment` is not part of the public CI workflow. It is useful as a
report, not as an automatic rewrite: its suggested packing can move or remove
the `CacheLinePad` separation that these concurrent layouts require. A layout
change therefore needs both the relevant assertions and review against the
fields' access patterns. A smaller struct is not necessarily a better
concurrent layout.
