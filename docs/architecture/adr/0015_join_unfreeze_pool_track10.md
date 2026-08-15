# ADR-0015: Unfreeze crdt.go — Pool the Join Incoming Buffer + Per-Block Merge Scratch

**Status:** Accepted
**Date:** 2026-08-01
**Phase:** 3, Day 10
**Author:** Sovereign Executor (NVIDIA NIM proxy → GLM-5.2)
**Supersedes:** ADR-0014 §6 (crdt.go FROZEN classification)

---

## §1. Context

The Day-9 ingest alloc hardening (commit `2b42ed9` + `9364591`, ADR-0014) reduced the ingest
alloc ceiling 638→538 allocs/op (−15.7%, FIX C: value-return `ReconstructedEntry`). The
post-FIX-C alloc profile isolated the FROZEN-locked alloc ceiling owned by `crdt.go:1016-1210`
(the Join body):

| Source | Alloc % | Location |
|--------|---------|----------|
| `Join.func3` (perShardMerge) | 33.6% | `incomingBlock := make([]CRDTEntry, ...)` + `merged := make([]CRDTEntry, ...)` per block per shard per Join |
| `Join` direct (incoming buffer) | 26.0% | `var incoming []incomingEntry` + `append` per yielded entry; escapes via `sort.Slice` capture |
| `capnp.Ptr.Text` | 29.8% | `EntityId` `string(b)` retain — schema.capnp.go FROZEN; irreducible without a Join signature change |
| `ReconstructEntry` | 7.5% | `string(payloadBytes)` retained field (Day-9 FIX A residual) |
| `circl` verify | 2% | amortized |

**Join-owned ceiling:** 33.6% + 26.0% = 59.6% of 538 allocs/op — ALL in the `Join` body.

The `Join` body was frozen at md5 `4512bd67` (TestG09c, ADR-0014 §6 rule 6) during
Day 2.5c to protect three physical contracts during the Phase-3 pipeline. Day 10
unfreezes it BECAUSE those contracts are proven — and the pool is on the CALLER side
of each contract boundary.

---

## §2. The 3 Proven Contracts (the teeth that gate the unfreeze)

### C1 — Determinism
`Join` NEVER touches `stateViewMu` (grep-verified across the full body). The determinism
contract is: `routeShard` (pure `maphash` over a fixed `routeSeed`) + `sort.Ints(shardOrder)`
(deterministic shard order) + the per-shard dot-merge. A pooled buffer does NOT change
the CAS order, the retire order, or the merge result. The Merkle root stays a pure
function of the dot set. **PROVEN-CONTRACT SAFE.**

### C2 — EBR Reclamation
`maybeAdvanceEpoch()` is called ONCE per Join (`crtt.go:1204`) + `Retire` per successful
per-shard CAS (`crt.go:1186`). Pooling the incoming buffer does NOT touch either.
Pool buffers recycle via `sync.Pool`, NOT `ebr.Retire` — a pool buffer passed through
`Retire` would corrupt the arena freelist. G10.c catches this. **PROVEN-CONTRACT SAFE.**

### C3 — 57.6M ops/s
The 57.6M contract is per-shard `atomic.Pointer` CAS linearizability (`shardRoot` struct,
`CacheLinePad`-padded at `crdt.go:54`). Pooling a Join-local incoming buffer is on the
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
is Day 11 (the PreSorted Seq contract that removes the sort).

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

### FIX J3 — NOT TODAY (the 29.8% capnp Text + the Seq signature)

Deferred to Day 11. Requires a Join signature change to accept arena-backed keys
OR a pre-counted sorted batch. Ripples to `cdrt_apply.go` (FROZEN) + the capnp path.

### md5 Re-Pin

The crdt.go `md5` transitions `4512bd67 → 0af1438`. TestG09c's frozen table is updated
with a Day-10 citation comment. The 4 OTHER FROZEN md5s (`cdrt_apply.go`, `schema.capnp`,
`schema.capnp.go`, `envelope.go`) stay byte-identical at their Day-9 pins.

---

## §4. Cold-Start vs Steady-State

A pool does NOT make the first Join zero-alloc. It recycles across sustained load.

| Scenario | B/op | allocs/op | ns/op |
|----------|------|-----------|-------|
| **PRE (9364591):** JoinParallel, 4c, steady | 546 | 9 | 2725 |
| **POST (Day 10):** JoinParallel, 4c, steady | 131 | 6 | 2765 |
| **Delta:** | −415 (−76.0%) | −3 (−33.3%) | ±1.5% (noise) |

The steady-state reclaims the growth reallocs. The cold-start cost (the first Join
after a GC, when `sync.Pool` is cleared) is unchanged — `sync.Pool` is GC-weak
and the New func grows fresh. The bench's `b.RunParallel` is steady-state by
construction (the warmapply applies before measurement).

---

## §5. The Post-Day-10 Residual (honest ceiling)

| Source | Alloc % | Status |
|--------|---------|--------|
| `capnp.Ptr.Text` (EntityId string retain) | 29.8% | Day 11 (arena-pooled PreSorted Seq) |
| `ReconstructEntry` string(`payloadBytes`) | 7.5% | Day-9 FIX A residual (production path discards; 2 tests assert) |
| `circl` verify | 2% | amortized |
| Slice-header escape (`sort.Slice` capture) | irreducible | Day 11 removes the sort |
| Pool cold-start (first Join after GC) | 1-2% | `sync.Pool` is GC-weak; documented, not fixable |

The steady-state `incoming` GROWTH (J1) and per-block `make()` (J2) are recycled. The
remaining per-Join allocs are the irreducible escape from `sort.Slice` (the closure
captures the slice header) + the capnp string retain + the ReconstructEntry field.

---

## §6. Gate Log

| Gate | Test | Verdict |
|------|------|---------|
| G10.a | `go build ./...` | PASS |
| G10.a | `go vet` (pre-existing `unsafe.Pointer` only) | PASS |
| G10.a | `gofmt` (corrected 1 indentation drift) | PASS |
| G10.b (C1) | `TestJoinDeterminism_PooledVsUnpooledMerkleEqual` | PASS — Merkle `57cde666` == `57cde666` |
| G10.b (C1) | `TestRecoveryDeterminism_KillRebuildMerkleEqual` | PASS |
| G10.b (C1) | `TestStage6WALRecoveryDeterminism` | PASS |
| G10.c (C2) | `TestJoinPool_DoesNotRetirePoolBuffers` | PASS — 2 Retire calls, ZERO on pool buffers |
| G10.c (C2) | `TestPhase2L_HAMTSetReclamationTooth` | PASS |
| G10.c (C2) | `TestTreiberStackABAImmunity` | PASS |
| G10.c (C2) | `TestEBRHazardPointerSequencing` | PASS |
| G10.d (C3) | `TestStage5ScalingGate` | PASS |
| G10.d (C3) | `TestHotPathZeroAllocations` | PASS |
| G10.d (C3) | `TestCRDTEntry_SizeAndAlignment` | PASS |
| G10.e | `BenchmarkCRDTEngine_JoinParallel` (no regression) | PASS — ns/op within noise (+1.5%) |
| G10.e | `TestG09e_BenchAllocNoRegression` (5.8/delta ceiling) | PASS |
| G10.f | `TestG09c` — new crdt.go pin `b0af1438` | PASS |
| G10.f | 4 OTHER FROZEN md5s unchanged | PASS |
| G10.g | Scope hygiene | See §7 |

---

## §7. Honest Weaknesses

(a) **Slice-header escape survives `sort.Slice` capture.** The pool reduces GROWTH, not the
escape — the sort.Slice closure captures `incoming` as a closure variable, which escapes
the slice header to heap. Day 11 removes the sort via a PreSorted Seq contract.

(b) **`sync.Pool` is GC-pressure-sensitive.** Under `GOGC`, the pool is cleared on GC.
The pool softens, not eliminates, the GC storm at `GOGC=off`. The first Join after a GC
is a fresh grow (unpooled cost).

(c) **Pool cold-start.** The first Join after a GC grows fresh — the pool's New function
returns a zero-valued `joinBuffers`. The GROWTH amortizes across subsequent Joins
(steady-state), but the cold-start cost is unchanged from the unpooled baseline.

(d) **The 29.8% capnt Text residual.** `EntityId` `string(b)` retain in `schema.capnp.go`
(Orchestrator). Day 11 requires a Seq signature change to support arena-backed keys.

(e) **The 7.5% ReconstructEntry string retain.** Day-9 FIX A kept the `Payload` field
as a `string` because 2 tests assert it. The production path discards it; the unit
tooth guards it.

(f) **The crdt.go unfreeze widens the blast radius.** A future Join edit is now unguarded
by the md5 freeze. The 3-contract teeth (G10.b/c/d) are the new guard.

(g) **Per-block scratch capacity retained across blocks.** If blocks within one Join
have wildly different sizes, the merged scratch grows to the max (cap retained across
blocks). This is a capacity retention, not a leak — the pool recycles it across Joins.

(h) **The per-shard shardBatches map allocates** (map[int][]blockRange) on every Join.
Day 11 could pool this too, but it's a small allocation (<1% of the ceiling).

---

## §8. Self-Adversarial (5 ATTACK + 1 MEDIOCRITY)

### ATTACK 1 — A pool buffer Retire'd through EBR corrupts the freelist.
A pool buffer put through `ebr.Retire` would write a GC-managed heap pointer into the
EBR arena freelist. The next `Alloc` from the arena would return a pointer into the
Go heap, not the arena — eventual double-free or use-after-free. **G10.c catches it:**
`TestJoinPool_DoesNotRetirePoolBuffers` reads `crdt.go` source and asserts all `Retire`
calls are on shard-pointer CAS targets only.

### ATTACK 2 — A pool shared across goroutines.
`sync.Pool` is per-P. Under contention, multiple goroutines from different Ps racing
on the same pool can cause contention (the pool's `Get`/`Put` are per-P, but a pool
shared across many Ps under `RunParallel` means each P has its own pool, so the
bench's `RunParallel` goroutines each have a per-P pool — no contention). A production
mesh with one Join goroutine per CPU has the same benefit. **Recorded honestly; no fix.**

### ATTACK 3 — The deferred Put runs AFTER the slice escaped to sort.
The deferred Put resets `[:0]` then puts back. The `[:0]` on an escaped slice is safe
(the backing array is preserved; length resets). The sort-capture reference is gone by
the time the defer runs (sort is synchronous, defer runs after return). **Safe by inspection.**

### ATTACK 4 — The per-block scratch can race if Join were reentrant.
Join is NOT reentrant (it holds no engine lock, but is single-threaded per delta). The
pool is per-join-call-local (the `buf` variable is local to the Join call), NOT
engine-shared. **Safe by construction — recorded honestly.**

### ATTACK 5 — The crdt.zip re-pin could be done SILENTLY (update the test without disclosure).
The Day-8.5 receiver.go precedent established re-pin with disclosure, not silence. **This
ADR discloses the transition. TestG09c is updated with a Day-10 citation comment.**

### MEDIOCRITY 1 — The engine's heart was frozen for 4 days.
The freeze was a discipline artifact — the 3 contracts were proven but the md5 pin
served as a tripwire. The owner unfreezing it in one day is an act of trust in the teeth,
not a repeal of the discipline. If the teeth are insufficient, Day 10 corrupts the
engine's proven core. **Mitigation:** G10.b/c/d are the load-bearing proof; if any
failures, REVERT and re-freeze.

---

## §9. References

- `docs/architecture/6_ENGINEERING_POST_MORTEM.md` — the 57.6M/CSA/alignment contracts
- `ADR-0014` — Day 9 ingest alloc hardening (the post-FIX-C baseline)
- `UNIVERSAL_CODEX.md` § THE ARCHITECT'S COMPLETE OWNERSHIP DOCTRINE
- Commit `9364591` (pre-Day-10 HEAD) — the FROZEN baselines
- Day-8.5 receiver.zip re-pin precedent (re-pin with disclosure, not silence)