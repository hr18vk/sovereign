# Struct Alignment — The Byte-Level Proof

This document is the structural proof that the Sovereign Engine packs Go structs
into cache lines so that no two concurrently-written fields share a line, and
no hot struct carries alignment padding it does not need. The byte sizes of the
record structs are pinned by hard assertion gates that fail the build if they
change: `TestCRDTEntry_SizeAndAlignment` (120 B), `TestHamtLeaf_SizeAndAlignment`
(32 B), and `TestEliminationSlotSize` (128 B). The contended-atomic layout is
enforced by `fieldalignment` (CI). The `[pkg/sync/layout_analysis_test.go](../../pkg/sync/layout_analysis_test.go)`
is a *diagnostic printer* — it walks every struct via `unsafe.Offsetof` and logs
the layout; it reports, it does not itself fail the build. Reading order: the
physics, then the record structs, then the contended-atomics proof.

## 1. The Physics

A Graviton core fetches memory in **64-byte cache lines**, and the MESI
coherence protocol invalidates on the line. If two goroutines on two cores
write to two distinct fields that happen to fall in the same 64-byte line, the
cores fight for ownership of that line — a HITM storm — and the write throughput
collapses to the coherence-serialization rate, not the cores' issue width.

The engine's standard is a **128-byte stride** (two cache lines) for any record
that may be touched concurrently by more than one core, and a **wasted-interior-
padding budget of zero bytes** for records that are not concurrently contended.
The padding that isolates hot atomics is not decorative; it is the difference
between 1.1M ops/s and 57.63M ops/s (the CORE microbench range @32c; the production ingest path is 1.0M-3.1M deltas/sec — see README LAYER DISCIPLINE) (§3).

The reference measurement for the cost of false sharing is the Stage 4
false-sharing benchmark (`[pkg/sync/physics_test.go](../../pkg/sync/physics_test.go)`): two `atomic.Uint64`
fields on one line vs. the same fields flanked by `CacheLinePad` (`[64]byte`).
On multi-core hardware the padded variant is typically 2×–10× faster; the gate
requires only that padded is not *slower* than unpadded, so a single-core CI
cannot produce a false failure.

## 2. Record Structs — Zero Wasted Padding

These structs are read and written from a single goroutine's hot path or are
immutable after publication, so they do not need inter-field line isolation.
They need intropy: every field packed against the previous one with no
alignment gap, so the struct size equals the sum of field sizes.

### `CRDTEntry` — 120 bytes, zero internal padding

`[pkg/sync/hamt.go:29](../../pkg/sync/hamt.go#L29)`. A single element in the Add-Wins Set lattice. ADR 10
deliberately flattened the nested `CausalDot` into `DotNodeID`/`DotCounter` to
remove indirection and the resulting alignment hole.

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

Field order is byte-descending: the `[32]byte` and `[16]byte` arrays first, then
the 8-byte words, so no field ever needs more alignment than the previous field's
trailing offset already satisfies. A `fieldalignment` reordering of these
fields is a build failure — the canonical order above is the layout, not a
suggestion.

### `hamtLeaf` — 32 bytes

`[pkg/sync/hamt.go:53](../../pkg/sync/hamt.go#L53)`. Stores entries for one entity ID at a leaf. Both
`entityPtr` and `entriesPtr` are `NodePtr` (uint64 offsets into the mmap arena),
not Go pointers — the leaf stays Zero-GC. Asserted to be exactly 32 bytes.

| Field         | Type      | Size | Offset |
|:--|:--|--:|--:|
| `hash`        | `uint64`  |  8 | 0  |
| `entityPtr`   | `NodePtr` |  8 | 8  |
| `entriesPtr`  | `NodePtr` |  8 | 16 |
| `entityLen`   | `uint32`  |  4 | 24 |
| `entriesLen`  | `uint32`  |  4 | 28 |
| **total**     |           | **32** | |

The two `uint32` length fields are packed into the tail 8 bytes after the three
`uint64` fields, so the struct's size is 32 with zero trailing pad. A 8-byte
read of `(entityLen, entriesLen)` is one cache-line access.

### `HamtNode` — 72 bytes

`[pkg/sync/hamt_arena.go:20](../../pkg/sync/hamt_arena.go#L20)`. An off-heap HAMT node with an atomic reference
count for epoch-based reclamation and an intrusive Treiber free-list pointer.
The 72-byte size and the offset-64 `nextFree` placement are a consequence of
the struct field order (above); `TestHamtNodeOffsets` *logs* them (it does not
hard-assert — it is a reporting test), and `fieldalignment` (CI) is the gate
that fails the build if a reorder leaks padding.

| Field          | Type            | Size | Offset |
|:--|:--|--:|--:|
| `refCount`     | `atomic.Int32`  |  4 | 0  |
| `bitmap`        | `uint32`        |  4 | 4  |
| `_` (pad)      | `uint32`        |  4 | 8  |  ← explicit, to align the 8-byte ptrs
| `childrenPtr`  | `NodePtr`       |  8 | 16 |
| `entriesPtr`   | `NodePtr`       |  8 | 24 |
| `merkleHash`   | `[32]byte`      | 32 | 32 |
| `nextFree`     | `NodePtr`       |  8 | 64 |
| **total**      |                 | **72** | |

The explicit `_ uint32` pad at offset 8 is the *only* deliberately inserted
padding in a record struct: `childrenPtr` and `entriesPtr` must be 8-aligned and
the two preceding 4-byte atomics fill 8 bytes, leaving a 4-byte gap that is
named (not silent) so `fieldalignment` does not move it. `nextFree` lives at
offset 64 — its own cache line — because the free-list steals the first 8 bytes
of a dead node, and putting it on a line boundary keeps the CAS off the line
holding `merkleHash`.

## 3. Contended Atomics — One Atomic Per Line

These structs are written concurrently by multiple cores. Field packing is the
wrong goal here; **line isolation** is. Every contended atomic is flanked by
`CacheLinePad` (`[64]byte`), so no other field can migrate onto its line under
MESI.

### `DeltaCRDTEngine` — sharded root, per-shard CAS locus

`[pkg/sync/crdt.go:135](../../pkg/sync/crdt.go#L135)`. The engine root is **sharded** — `shards []shardRoot`
(`crdt.go:160`), where each `[pkg/sync/crdt.go:72 shardRoot](../../pkg/sync/crdt.go#L72)` owns one slice of
the entityID space. The hottest atomic is therefore *not* a single engine-level
field: it is the **per-shard** `shardRoot.ptr` (the HAMT root pointer for that
shard, CAS'd on every `InsertLocal`/`Join` *within that shard*). Each shard is
its own padded CAS slot, so the locus is dispersed across N lines instead of
collapsing onto one.

```
per shard (shardRoot):
  _padHead | ptr atomic.Pointer[HAMT] | _padTail    ← per-shard hottest CAS, isolated
```

At the engine level, the remaining contended atomics — `lamportCounter` (Add'd
on every `NextDot`, a SINGLE atomic shared across shards exactly as the
pre-shard design shared it), `epochCounter` (Add'd on every operation), and the
metrics counters — each get their own padded regions, same as before the shard.
`lamportCounter` and `lastSavedCounter` are written by the *same* goroutine in
`NextDot`, so they safely share a line with each other.

The proof that this matters is `paddedEngineProxy` vs `unpaddedEngineProxy` in
`[pkg/sync/physics_test.go](../../pkg/sync/physics_test.go)`: a single shared line holding all four metrics
plus the CAS field is the layout that produced the parallel-efficiency collapse.
The shard disperses the root CAS across N such lines so no two shards contend.

### `EBRManager` — two CAS locus split

`[pkg/sync/reclamation.go:47](../../pkg/sync/reclamation.go#L47)`. `globalEpoch` is CAS'd by `AdvanceEpoch`;
`head` is CAS'd by `Register`. Different goroutines, hot concurrently. Both are
flanked:

```
Line 0 : _globalEpochPad0 | globalEpoch atomic.Uint64 | _globalEpochPad1
Line 1 : _headPad0 | head atomic.Pointer[Participant] | _headPad1
Line 2+: retired [3]RetiredList | pool | retiredPool   ← cold
```

### `Participant` — per-slot isolation

`[pkg/sync/reclamation.go:97](../../pkg/sync/reclamation.go#L97)`. Each `active`, `epoch`, and `hazards` array
is bracketed by its own `CacheLinePad`, so two cores transacting different
participants never invalidate each other's lines.

### `ElimSlot` — the 128-byte stride in full

`[pkg/sync/elimination.go:203](../../pkg/sync/elimination.go#L203)`. The elimination backoff arena packs two
hot fields onto *one* shared line (they are touched by the two exchanging
goroutines, so co-location is the rendezvous protocol, not contention), then
pads with a full 64-byte tail so the *next* slot starts on a fresh line.

```
ElimSlot (128 bytes = 2 cache lines):
  offset  0 : _padLead [48]byte            ← fill line-0 so state+value land together
  offset 48 : state    atomic.Uint64       ← packed (op<<62)|stamp, control plane
  offset 56 : value    atomic.Uint64       ← payload/sink, data plane
  offset 64 : _padTail CacheLinePad (64B)  ← line-1 isolation; next slot starts at 128
```

Adjacent slots therefore never share a line: slot *n*'s `state` at offset
`128n+48`, slot *n+1*'s `state` at offset `128(n+1)+48` — always 128 bytes
apart, two cores hitting adjacent slots issue zero cross-core invalidation.

### `ElimStack.head` — the surviving contended line

`[pkg/sync/elimination.go:219](../../pkg/sync/elimination.go#L219)`. The Treiber stack head is the one cache line
that *does* contend under backoff starvation. It is padded away from
`collisions` (the adaptive probe-budget accumulator, itself on its own pad) and
from the embedded `EliminationArray` (by value, Zero-GC — no slot heap alloc).

## 4. Why This Is a Build Gate, Not a Comment

The byte sizes of the record structs are pinned by hard assertion gates:
`TestCRDTEntry_SizeAndAlignment` (120 B), `TestHamtLeaf_SizeAndAlignment`
(32 B), and `TestEliminationSlotSize` (128 B) each `t.Fatalf` if the size
drifts. `fieldalignment` (CI) rejects any reorder that leaks intra-struct
padding or co-locates two contended atomics, and `bencher` (CI) re-verifies
that no pad removal regresses throughput. The
`[pkg/sync/layout_analysis_test.go](../../pkg/sync/layout_analysis_test.go)` is
a *diagnostic*: it walks every struct via `unsafe.Offsetof` and prints the
layout so a human can read it — it reports, it does not itself fail the build.
A maintainer who "cleans up" the `CacheLinePad` fields or re-flattens
`CRDTEntry` fails the size-assertion gates + `fieldalignment` before review —
and the engineering post-mortem records that this is exactly how the
manufactured bugs of Stages 4–6 were caught: by gates that pinned the exact
expected layout and refused to round it.
