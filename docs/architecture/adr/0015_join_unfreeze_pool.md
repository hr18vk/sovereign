# ADR-0015: Unfreeze crdt.go — Pool the Join Incoming Buffer + Per-Block Merge Scratch

**Status:** Accepted
**Date:** 2026-08-01
**Author:** Harsh Rawat
**Supersedes:** ADR-0014 §6 (crdt.go frozen classification)

---

## §1. Context

The ingest alloc hardening recorded in ADR-0014 reduced the
ingest alloc ceiling 638→538 allocs/op (−15.7%, FIX C: value-return `ReconstructedEntry`). The
post-FIX-C alloc profile isolated the frozen-locked alloc ceiling owned by `crdt.go:1173-1446`
(the Join body):

| Source | Alloc % | Location |
|--------|---------|----------|
| `Join.func3` (perShardMerge) | 33.6% | `incomingBlock := make([]CRDTEntry, ...)` + `merged := make([]CRDTEntry, ...)` per block per shard per Join |
| `Join` direct (incoming buffer) | 26.0% | `var incoming []incomingEntry` + `append` per yielded entry; escapes via `sort.Slice` capture |
| `capnp.Ptr.Text` | 29.8% | `EntityId` `string(b)` retain — `api/capnp/api/capnp/schema.capnp.go` frozen; irreducible without a Join signature change |
| `ReconstructEntry` | 7.5% | `string(payloadBytes)` retained field (ADR-0014 FIX A residual) |
| `circl` verify | 2% | amortized |

**Join-owned ceiling:** 33.6% + 26.0% = 59.6% of 538 allocs/op — ALL in the `Join` body.

The `Join` body was frozen (deliberately not edited, ADR-0014 §6) to protect three
physical contracts while the pipeline was being built out. I unfreeze it here BECAUSE those
contracts are proven — and the pool is on the CALLER side of each contract boundary.

---

## §2. The 3 Proven Contracts (the teeth that gate the unfreeze)

### C1 — Determinism
`Join` NEVER touches `stateViewMu` (grep-verified across the full body). The determinism
contract is: `routeShard` (pure `maphash` over a fixed `routeSeed`) + `sort.Ints(shardOrder)`
(deterministic shard order) + the per-shard dot-merge. A pooled buffer does NOT change
the CAS order, the retire order, or the merge result. The Merkle root stays a pure
function of the dot set. **PROVEN-CONTRACT SAFE.**

### C2 — EBR Reclamation
`maybeAdvanceEpoch()` is called ONCE per Join (`crdt.go:1441`) + `Retire` per successful
per-shard CAS (`crdt.go:1418`). Pooling the incoming buffer does NOT touch either.
Pool buffers recycle via `sync.Pool`, NOT `ebr.Retire` — a pool buffer passed through
`Retire` would corrupt the arena freelist. `TestJoinPool_DoesNotRetirePoolBuffers` catches
this. **PROVEN-CONTRACT SAFE.**

### C3 — 57.6M ops/s
The 57.6M contract is per-shard `atomic.Pointer` CAS linearizability (`shardRoot` struct,
`CacheLinePad`-padded at `crdt.go:78`). Pooling a Join-local incoming buffer is on the
CALLER side of the CAS; it cannot change the CAS. **PROVEN-CONTRACT SAFE.**

### C4 — Alignment
`CRDTEntry` size and alignment unchanged. `shardRoot` field layout unchanged. The
`fieldalignment` CI gate and `TestCRDTEntry_SizeAndAlignment` confirm. **PROVEN-CONTRACT SAFE.**

---

## §3. Decision

### FIX J1 — Pool the incoming buffer (claim the 26% Join-direct)

Replace `var incoming []incomingEntry` + append-per-entry with a `sync.Pool`-backed
`joinBuffers` struct:

```go
type joinBuffers struct {
    incoming     []incomingEntry
    blockScratch []CRDTEntry
    mergeScratch []CRDTEntry
}
var joinBufPool = sync.Pool{New: func() any { return &joinBuffers{} }}
```

- `buf := joinBufPool.Get().(*joinBuffers)` at Join entry
- `incoming := buf.incoming[:0]` — zero-length slice backed by the pooled array
- `buf.incoming = incoming` — store the final slice after sort+dedup
- `defer` Put back to pool (reset `[:0]`)

**Net:** The GROWTH reallocs (the append doubling) recycle across Join calls. The
slice-header escape from `sort.Slice` SURVIVES (the closure captures the slice header)
— honest scope: this is a POOLING win, not a zero-alloc win. The irreducible escape
is removed by the follow-up PreSorted Seq contract that removes the sort.

### FIX J2 — Pool the per-block merge scratch (claim the 33.6% func3)

Replace `incomingBlock := make([]CRDTEntry, r.end-r.start)` and
`merged := make([]CRDTEntry, 0, needed)` in `perShardMerge` with the `joinBuffers`
scratch slices:

- `buf.blockScratch` — checked/grown to `br.end-br.start`, sliced `[:needed]`
- `buf.mergeScratch` — checked/grown to `len(existing) + len(incomingBlock)`, sliced `[:0]`
- After `Set` (which copies into the HAMT arena), `buf.mergeScratch = merged[:0]` captures
  any capacity growth from append

**Net:** The per-block `make()` calls recycle WITHIN one Join (the scratch is reused across
blocks in the `perShardMerge` closure). The HAMT `Set` copies the data; the scratch is
free to reuse immediately.

### FIX J3 — NOT NOW (the 29.8% capnp Text + the Seq signature)

Deferred to the follow-up. Requires a Join signature change to accept arena-backed keys
OR a pre-counted sorted batch. Ripples to `pkg/sync/crdt_apply.go` (frozen) + the capnp path.

### Scope of the unfreeze

This change unfreezes and edits `crdt.go` only (the Join buffer pool). The four other
frozen files (`pkg/sync/crdt_apply.go`, `api/capnp/api/capnp/schema.capnp`,
`api/capnp/api/capnp/schema.capnp.go`, `pkg/attribution/envelope.go`) are left
unchanged.

---

## §4. Cold-Start vs Steady-State

A pool does NOT make the first Join zero-alloc. It recycles across sustained load.

| Scenario | B/op | allocs/op | ns/op |
|----------|------|-----------|-------|
| **PRE (pre-fix):** JoinParallel, 4c, steady | 546 | 9 | 2725 |
| **POST (this change):** JoinParallel, 4c, steady | 131 | 6 | 2765 |
| **Delta:** | −415 (−76.0%) | −3 (−33.3%) | ±1.5% (noise) |

The steady-state reclaims the growth reallocs. The cold-start cost (the first Join
after a GC, when `sync.Pool` is cleared) is unchanged — `sync.Pool` is GC-weak
and the New func grows fresh. The bench's `b.RunParallel` is steady-state by
construction (the warm apply runs before measurement).

---

## §5. The Post-Change Residual (honest ceiling)

| Source | Alloc % | Status |
|--------|---------|--------|
| `capnp.Ptr.Text` (EntityId string retain) | 29.8% | deferred (arena-pooled PreSorted Seq) |
| `ReconstructEntry` string(`payloadBytes`) | 7.5% | ADR-0014 FIX A residual (production path discards; 2 tests assert) |
| `circl` verify | 2% | amortized |
| Slice-header escape (`sort.Slice` capture) | irreducible | removed by the follow-up PreSorted Seq contract |
| Pool cold-start (first Join after GC) | 1-2% | `sync.Pool` is GC-weak; documented, not fixable |

The steady-state `incoming` GROWTH (J1) and per-block `make()` (J2) are recycled. The
remaining per-Join allocs are the irreducible escape from `sort.Slice` (the closure
captures the slice header) + the capnp string retain + the ReconstructEntry field.

---

## §6. Verification results

| Contract | Test | Verdict |
|------|------|---------|
| — | `go build ./...` | PASS |
| — | `go vet` (pre-existing `unsafe.Pointer` only) | PASS |
| — | `gofmt` (corrected 1 indentation drift) | PASS |
| C1 | `TestJoinDeterminism_PooledVsUnpooledMerkleEqual` | PASS — Merkle `57cde666` == `57cde666` |
| C1 | `TestRecoveryDeterminism_KillRebuildMerkleEqual` | PASS |
| C1 | `TestWALRecoveryDeterminism` | PASS |
| C2 | `TestJoinPool_DoesNotRetirePoolBuffers` | PASS — 2 Retire calls, ZERO on pool buffers |
| C2 | `TestHAMTSetReclamationGuard` | PASS |
| C2 | `TestTreiberStackABAImmunity` | PASS |
| C2 | `TestEBRHazardPointerSequencing` | PASS |
| C3 | `TestScalingGate` | PASS |
| C3 | `TestHotPathZeroAllocations` | PASS |
| C4 | `TestCRDTEntry_SizeAndAlignment` | PASS |
| — | `BenchmarkCRDTEngine_JoinParallel` (no regression) | PASS — ns/op within noise (+1.5%) |
| — | the alloc-regression tooth (`bench_alloc_regression_test.go`, 5.8 allocs/delta ceiling) | PASS |
| — | the four other frozen files unchanged (no core bleed) | PASS |

---

## §7. Honest Weaknesses

(a) **Slice-header escape survives `sort.Slice` capture.** The pool reduces GROWTH, not the
escape — the sort.Slice closure captures `incoming` as a closure variable, which escapes
the slice header to heap. A follow-up removes the sort via a PreSorted Seq contract.

(b) **`sync.Pool` is GC-pressure-sensitive.** Under `GOGC`, the pool is cleared on GC.
The pool softens, not eliminates, the GC storm at `GOGC=off`. The first Join after a GC
is a fresh grow (unpooled cost).

(c) **Pool cold-start.** The first Join after a GC grows fresh — the pool's New function
returns a zero-valued `joinBuffers`. The GROWTH amortizes across subsequent Joins
(steady-state), but the cold-start cost is unchanged from the unpooled baseline.

(d) **The 29.8% capnp Text residual.** `EntityId` `string(b)` retain in
`api/capnp/api/capnp/schema.capnp.go` (Orchestrator). The follow-up requires a Seq
signature change to support arena-backed keys.

(e) **The 7.5% ReconstructEntry string retain.** The ADR-0014 FIX A kept the `Payload` field
as a `string` because 2 tests assert it. The production path discards it; the unit
tooth guards it.

(f) **The crdt.go unfreeze widens the blast radius.** A future Join edit is no longer
blocked by the freeze. The contract teeth (C1–C4) are the new guard.

(g) **Per-block scratch capacity retained across blocks.** If blocks within one Join
have wildly different sizes, the merged scratch grows to the max (cap retained across
blocks). This is a capacity retention, not a leak — the pool recycles it across Joins.

(h) **The per-shard shardBatches map allocates** (map[int][]blockRange) on every Join.
A follow-up could pool this too, but it's a small allocation (<1% of the ceiling).

---

## §8. Self-Adversarial Review

1. **A pool buffer Retire'd through EBR corrupts the freelist.** A pool buffer put through
   `ebr.Retire` would write a GC-managed heap pointer into the EBR arena freelist. The next
   `Alloc` from the arena would return a pointer into the Go heap, not the arena — eventual
   double-free or use-after-free. `TestJoinPool_DoesNotRetirePoolBuffers` catches it: it
   reads `crdt.go` source and asserts all `Retire` calls are on shard-pointer CAS targets only.

2. **A pool shared across goroutines.** `sync.Pool` is per-P. Under `RunParallel`, each P has
   its own pool, so the bench's goroutines do not contend on it. A production mesh with one
   Join goroutine per CPU has the same benefit. Recorded honestly; no fix.

3. **The deferred Put runs AFTER the slice escaped to sort.** The deferred Put resets `[:0]`
   then puts back. The `[:0]` on an escaped slice is safe (the backing array is preserved;
   length resets). The sort-capture reference is gone by the time the defer runs (sort is
   synchronous, defer runs after return). Safe by inspection.

4. **The per-block scratch can race if Join were reentrant.** Join is NOT reentrant (it holds
   no engine lock, but is single-threaded per delta). The pool is per-join-call-local (the
   `buf` variable is local to the Join call), NOT engine-shared. Safe by construction.

5. **A frozen-file edit could be done silently (no disclosure).** The discipline is that
   any edit to a previously-frozen file is disclosed openly in the ADR, not slipped in
   quietly. This ADR discloses the crdt.go unfreeze explicitly and re-gates the contracts
   it protects.

One closing note on discipline: the engine's core had been frozen as a tripwire while the
contracts were proven. Unfreezing it is an act of trust in the teeth, not a repeal of the
discipline. If the C1–C4 teeth ever fail, the correct response is to revert and re-freeze.

---

## §9. References

- `docs/architecture/6_ENGINEERING_POST_MORTEM.md` — the 57.6M/CSA/alignment contracts
- `ADR-0014` — the ingest alloc hardening (the post-FIX-C baseline)
