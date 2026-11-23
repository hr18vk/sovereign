# ADR-0015: Pool the Join hot path's incoming buffer and per-block merge scratch

**Status:** Accepted
**Date:** 2026-08-01
**Supersedes:** The restriction on editing `Join` in [ADR-0014](0014_ingest_alloc_hardening.md)

---

## §1. Context

[ADR-0014](0014_ingest_alloc_hardening.md) reduced the integrated receive path from 638 to
538 allocs/op (−15.7%), measured with 100 deltas per frame on four cores, by returning
`ReconstructedEntry` by value. The resulting allocation profile isolated two costs inside
`(*DeltaCRDTEngine).Join`:

| Source | Allocation share | Cause |
|--------|------------------|-------|
| Per-block merge scratch in `Join` | 33.6% | A new incoming block and merged slice for every block, shard, and Join |
| Incoming buffer in `Join` | 26.0% | Append growth while collecting entries from the delta |
| `capnp.Ptr.Text` | 29.8% | The entity-ID string retained during reconstruction on the ingest path |
| `ReconstructEntry` | 7.5% | The `string(payloadBytes)` retained in `ReconstructedEntry.Payload` |
| `circl` signature verification | 2% | Amortized across the deltas in a frame |

The first two sources account for 59.6% of the 538 allocs/op profile. Unlike the Cap'n Proto
and reconstruction costs, they can be addressed inside `Join` without changing its signature.

`Join` had been left unchanged while the surrounding ingest path was built so that its merge,
reclamation, and layout behavior had a stable reference point. This decision permits buffer
reuse on the caller side of those boundaries; it does not change the merge rule or wire format.

---

## §2. Contracts Preserved by the Change

### C1 — Determinism

`Join` does not acquire `stateViewMu`. It routes entity IDs with `routeShard`, using
`maphash` and a fixed `routeSeed`, sorts the selected shard indices with
`sort.Ints(shardOrder)`, and merges dots independently within each shard. Reusing a buffer
does not change the CAS order, retirement order, or merge result. The resulting Merkle root
remains a function of the applied dot set.

### C2 — EBR reclamation

`maybeAdvanceEpoch` runs once per Join after its EBR participant exits. A replaced shard root
is retired after a successful CAS; an unpublished candidate is retired after a failed CAS.
The pooled incoming and scratch slices have a separate owner: they return through
`sync.Pool`, never through `(*EBRManager).Retire`. Retiring a Go heap pointer into the
off-heap arena's free list would corrupt later allocations.

### C3 — 57.6M ops/s

At the time of this decision, 57.6M ops/s was the residency high end of the separate
in-process CRDT core benchmark at 32 cores. It was not a Join or ingest throughput
measurement, and the number itself is not the linearizability contract. The relevant contract
is the per-shard `atomic.Pointer` CAS in `shardRoot`. Buffer pooling takes place before that
CAS and does not alter it.

### C4 — Alignment

The change adds no fields to `CRDTEntry` or `shardRoot`. Their size, alignment, and cache-line
padding remain unchanged, checked by `TestCRDTEntry_SizeAndAlignment` and the layout analysis.

---

## §3. Decision

### Pool the incoming buffer

Replace the function-local `var incoming []incomingEntry` with a `sync.Pool` of buffers:

```go
type joinBuffers struct {
    incoming     []incomingEntry
    blockScratch []CRDTEntry
    mergeScratch []CRDTEntry
}

var joinBufPool = sync.Pool{New: func() any { return &joinBuffers{} }}
```

At Join entry, get a `joinBuffers` value and reslice `buf.incoming` to zero length. The delta
iterator appends into that slice, reusing its backing array when capacity allows. Store the
collected slice in `buf.incoming`. A deferred cleanup truncates it to zero length and returns
the buffer to the pool.

Pooling recycles append-growth allocations across Join calls. It does not make Join
allocation-free: a cold pool still allocates, and the delta iterator can let the slice header
escape. The initial analysis of the surviving sort allocation was later corrected, as §5
explains.

### Reuse per-block merge scratch

Use the remaining fields in `joinBuffers` instead of allocating an incoming block and merged
slice for every entity block:

- Grow `buf.blockScratch` to the incoming block length and copy that block into it.
- Grow `buf.mergeScratch` to hold the existing and incoming entries, then reslice it to zero
  length for the merge.
- After `HAMT.Set` copies the merged entries into arena storage, assign `merged[:0]` back to
  `buf.mergeScratch` so any capacity growth is retained.

The same scratch arrays serve subsequent entity blocks and CAS retries within the call.
`HAMT.Set` does not retain these slices, so they can be reused immediately after it returns.

### Defer sequence and entity-ID changes

Changing the entity-ID string retention or the `Join` sequence signature is outside this
decision. Those changes cross reconstruction, delta application, and Cap'n Proto decoding
boundaries and require separate treatment. A pre-sorted sequence was proposed for later work,
but this change neither implements nor depends on it.

### Scope

The change is limited to `(*DeltaCRDTEngine).Join` and its private buffer types. It does not
change `CRDTEntry`, `shardRoot`, the Cap'n Proto schema, or the dot-merge rule.

---

## §4. Cold Start and Steady State

Pooling reduces allocations after the buffers have grown; it does not eliminate first-use
allocation. The recorded `BenchmarkCRDTEngine_JoinParallel` comparison used four cores and
steady-state operation:

| Measurement | B/op | allocs/op | ns/op |
|-------------|------|-----------|-------|
| Before this change | 546 | 9 | 2725 |
| After this change | 131 | 6 | 2765 |
| Change | −415 (−76.0%) | −3 (−33.3%) | +1.5% (within run-to-run noise) |

The reduction comes from reusing the incoming array and per-block scratch. A new buffer starts
with zero-length, nil slices, and `sync.Pool` may discard retained buffers during garbage
collection. A Join that receives a fresh buffer therefore pays the original growth cost again.
These steady-state figures do not bound that cold path.

---

## §5. Remaining Allocations and the Later Sort Change

| Source | Allocation share | Status after this decision |
|--------|------------------|----------------------------|
| `capnp.Ptr.Text` entity-ID retain | 29.8% | Unchanged; outside `Join`, on the integrated ingest path |
| `ReconstructEntry` payload string | 7.5% | Unchanged; production applies the entry but discards this field |
| `circl` signature verification | 2% | Unchanged and amortized across a frame |
| Sort and iterator escapes | Not removed by pooling | The sort spill was addressed later by ADR-0022 |
| Pool cold start after GC | 1-2% | Unchanged; a fresh buffer must grow its slices |

The Cap'n Proto and reconstruction percentages describe the integrated ingest profile, not
`BenchmarkCRDTEngine_JoinParallel`, which constructs its deltas directly and does not call
either path.

This decision initially attributed the surviving sort cost to comparator closure capture.
Escape analysis later distinguished two mechanisms: `sort.Slice` spilled the slice header
through its reflection-based interface parameter, while the `delta.Entries` yield callback
was the escaping closure. [ADR-0022](0022_zero_alloc_join.md) replaced `sort.Slice` with
`slices.SortFunc` and a package-level comparator, removing the sort spill. It retained a full
sort because generated deltas walk HAMTs in hash order, not lexical entity order. The yield
callback remains a separate allocation source.

---

## §6. Evidence

The following results were recorded for this change. ADR-0022 records the later measurements
for the sort change; they do not replace the baseline established here.

| Contract | Check | Recorded result |
|----------|-------|-----------------|
| Build | `go build ./...` | PASS |
| Build | `go vet` | PASS; existing `unsafe.Pointer` findings unchanged |
| Build | `gofmt` | PASS |
| C1 | `TestJoinDeterminism_PooledVsUnpooledMerkleEqual` | PASS; both Merkle roots began `57cde666` |
| C1 | `TestRecoveryDeterminism_KillRebuildMerkleEqual` | PASS |
| C1 | `TestWALRecoveryDeterminism` | PASS |
| C2 | `TestJoinPool_DoesNotRetirePoolBuffers` | PASS; two `Retire` sites, neither receiving a pool buffer |
| C2 | `TestHAMTSetReclamationGuard` | PASS |
| C2 | `TestTreiberStackABAImmunity` | PASS |
| C2 | `TestEBRHazardPointerSequencing` | PASS |
| C3 | `TestScalingGate` | PASS |
| C3 | `TestHotPathZeroAllocations` | PASS |
| C4 | `TestCRDTEntry_SizeAndAlignment` | PASS |
| C4 | `fieldalignment` | No layout change |
| Benchmark | `BenchmarkCRDTEngine_JoinParallel` | Allocation reduction in §4; ns/op change +1.5%, within noise |
| Ingest | `TestBenchAllocNoRegression` | PASS; 5.8 allocs/delta ceiling at N=100 |

---

## §7. Consequences and Limitations

(a) **Pooling does not remove slice-header escapes.** It reuses backing arrays; it cannot by
itself keep the incoming slice or iterator callback off the heap. ADR-0022 removed the
reflection-based sort spill, while the yield-callback escape remains.

(b) **Reuse depends on garbage-collection behavior.** `sync.Pool` may drop entries during GC,
so the allocation benefit varies with pool survival and workload. It is not a stable memory
reservation or a guarantee of reuse.

(c) **Cold calls still grow buffers.** The pool's `New` function returns a zero-valued
`joinBuffers`. Its slices have no spare capacity until appended to, so steady-state figures
do not describe the first use of a fresh buffer.

(d) **The entity-ID string retain is unchanged.** The 29.8% allocation share belongs to the
Cap'n Proto reconstruction path outside `Join`. Removing it requires a change to that path,
not another Join-local cache.

(e) **The payload string retain is unchanged.** `ReconstructedEntry.Payload` remains a string
for the reconstruction tests and callers that inspect it, although the production apply path
discards it. This accounts for 7.5% of the historical integrated profile.

(f) **Later Join edits must re-verify the contracts.** Determinism, EBR ownership, CAS
behavior, and layout checks remain necessary. The buffer-pool tests do not establish those
properties for unrelated changes.

(g) **Scratch capacity follows the largest block.** A large entity block grows the scratch
arrays retained by later blocks and later calls. This is reachable capacity rather than a
leak, but it can increase memory held until the pool entry is discarded.

(h) **Shard grouping still allocates.** The `map[int][]blockRange` and shard-order slice are
outside the pool. The historical profile attributed less than 1% of the allocation ceiling to
the map, so this decision leaves it unchanged.

---

## §8. Objections Considered

### A pool buffer could enter the EBR free list

That would put a Go heap pointer into the off-heap arena, allowing a later arena allocation
to return that pointer and causing reclamation errors. `TestJoinPool_DoesNotRetirePoolBuffers`
inspects every `Retire` call in `Join` and rejects references to the pool buffers. Only shard
roots and unpublished HAMT candidates are retired.

### Concurrent Join calls could share scratch space

`sync.Pool` is safe for concurrent use, but its per-P implementation is not a guarantee that
calls never contend or that a value returns to the same P. Buffer safety instead comes from
ownership: once checked out, a `joinBuffers` value is referenced only by that Join call until
its deferred return. Concurrent calls receive distinct values.

### The deferred return could reuse an escaped slice too early

Delta iteration and sorting are synchronous and finish before the deferred cleanup runs.
Truncating the slice changes its length without overwriting its backing array. The merge
scratch is also safe to reuse because `HAMT.Set` copies its contents into arena storage before
returning.

### Reusing scratch across blocks could corrupt an earlier merge

Each block is copied into the HAMT before the next block reuses the arrays. A failed CAS can
repeat the merge with the same scratch because no candidate from the failed attempt is
published, and the failed candidate itself is retired through EBR rather than through the
pool.

---

## §9. References

- [ADR-0014](0014_ingest_alloc_hardening.md) — the integrated receive-path allocation baseline.
- [ADR-0022](0022_zero_alloc_join.md) — the sort-spill analysis and `slices.SortFunc` change.
- [Engineering post-mortem](../6_ENGINEERING_POST_MORTEM.md) — the core benchmark, CAS, and
  alignment context.
