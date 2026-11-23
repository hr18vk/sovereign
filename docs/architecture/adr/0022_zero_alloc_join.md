# ADR-0022: The zero-allocation Join sort step

**Status:** Accepted  
**Date:** 2026-08-04

## Context

ADR-0015 pooled the scratch buffers used by `(*DeltaCRDTEngine).Join`, but the
join still allocated while sorting its input. Join collects `(entityID, entry)`
pairs, sorts them by entity ID and then causal dot, removes duplicate dots, and
groups each entity run by its routed shard. Those steps require equal entities
and dots to be adjacent.

The original implementation used `sort.Slice`. Escape analysis showed that its
comparator was inlined; the allocation came instead from passing the input slice
through `sort.Slice`'s reflection-based `interface{}` parameter, which spilled
the slice header. The callback passed to `CRDTDelta.Entries` also escapes because
it captures the input slice. That is a separate allocation and remains outside
this decision.

Sorting cannot be removed. Generated deltas walk HAMT shards in hash order, not
lexical entity order. `(*HAMT).MerkleRoot` independently sorts dot pairs, so
Merkle determinism does not depend on Join's input order, but Join's deduplication
and shard batching do.

## Decision

Replace the reflective sort with:

```go
slices.SortFunc(incoming, cmpIncomingEntries)
```

`cmpIncomingEntries` is a package-level function that receives two
`incomingEntry` values, captures no slice, compares entity IDs lexically, and
uses `compareDots` as the tie-breaker. The generic sort preserves the previous
ordering with O(N log N) worst-case work and avoids the reflection spill.

The `slices` package was already used by `GenerateDelta`. The `sort` import stays
because Join still uses `sort.Ints` for shard order and the delta iterator uses
`sort.Search`.

### Rejected alternative: assume nearly sorted input

An insertion-sort pass such as `stabilizeNearlySorted` would be incorrect for
multi-entity deltas: hash-order iteration does not provide the lexical runs that
deduplication and shard partitioning require. It also has quadratic worst-case
behavior on reversed or adversarial dot sequences. A full sort avoids both the
false ordering premise and that receiver CPU-amplification case.

### Rejected alternative: cache the last entity ID

A `lastEntityID` field in `joinBuffers` would not remove an allocation. Appending
the cached string and appending the yielded string copy the same pointer-and-length
header; the string itself was allocated upstream by Cap'n Proto reconstruction or
by the benchmark's `fmt.Sprintf` call. `BenchmarkCRDTEngine_JoinParallel` builds
its delta directly with `makeSeq` and never calls `ReconstructEntry`, so the
proposed cache would not affect that benchmark either.

The cache would also outlive a pooled Join call because the cleanup path
truncates `buf.incoming` without resetting such a field. A cached transient
arena- or Cap'n Proto-backed string view could then dangle on a later call. The
current heap-copy paths make that a lifetime risk rather than an observed
failure, but there is no allocation benefit to justify it.

## Consequences

Join preserves its entity-and-dot ordering, deduplication, shard batching, EBR
retirement behavior, and struct layouts. The sort remains an in-place operation;
using a package-level function value does not require the comparator itself to
be inlined.

This removes one reflection-related allocation, not every Join allocation. The
iterator callback can still capture and spill the incoming slice, and append
growth and cold pool initialization still allocate. The proposed PreSorted Seq
was not added by this decision or by later delta-generation changes; current
Join still calls `slices.SortFunc` with the same comparator.

## Evidence

The original before-and-after measurements used ARM64 with `GOMAXPROCS=4` and
identical flags for each implementation. The record does not identify the machine
model. Serial `BenchmarkCRDTEngine_Join` used `-benchtime=5000x -count=6`:

| Measurement | `sort.Slice` | `slices.SortFunc` | Change |
|:--|--:|--:|--:|
| allocs/op | 4 | 3 | −1 (−25%) |
| B/op | 99 | 75 | −24 |
| ns/op | 2837 | 2771 | −66 (−2.3%, within noise) |

Parallel `BenchmarkCRDTEngine_JoinParallel` used `-benchtime=3000x -count=8` and
showed a noisier result:

| Measurement | `sort.Slice` | `slices.SortFunc` |
|:--|--:|--:|
| steady allocs/op | 5–6 | 4–5 |
| B/op | 127–184 | 102–136 |
| ns/op | 1.6–2.0 µs | 1.6–2.3 µs |

The serial result corrects the earlier estimate of a 6-to-3 allocation drop: the
measured drop was 4 to 3. The 24 B/op reduction is consistent with the spilled
slice header and reflection boxing. Cold single-iteration runs measure pool
initialization and buffer growth and are not comparable with these steady-state
figures.

The regression evidence includes:

- `TestJoinDeterminism_PooledVsUnpooledMerkleEqual`, which compares Merkle roots
  for pooled and unpooled Join paths;
- `TestJoinPool_DoesNotRetirePoolBuffers`, which checks that pooled scratch is
  not retired as HAMT state;
- `TestCRDTEntry_SizeAndAlignment`, which covers the unchanged entry layout;
- `TestHotPathZeroAllocations` for the separate `HAMT.Set` hot-path contract;
  and
- `TestBenchArenaGreen` and `TestJoinParallelContentionCurve` for benchmark
  validity and parallel behavior.

The original acceptance record reports successful build, vet, formatting,
field-alignment, and race-enabled regression runs. The benchmark figures above
are historical measurements from that record, not a new performance run for
v0.2.0.
