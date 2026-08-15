# ADR-0024: The Durable Bitemporal-History Range Read — `Resolver.Range` + `/v1/range` over the Arrow Index (Interval-Intersection, NOT Point-in-Window)

**Status:** Accepted
**Date:** 2026-08-04
**Phase:** 3, Day 19
**Author:** Sovereign Executor (Opus-class executor — single-agent impl of the dictated fork, with THREE dictated-corrections executed before any line shipped: (a) the T3 "sha256[:8] collision" premise refuted by a byte-read of col0 = `FixedSizeBinary(16)` and Filter-1 = full 16-byte compare, replaced by the deterministic decoupled-col0 Filter-4 test; (b) the T2/T6 Bridge-harness seeding model corrected after the `SnapshotToLSM`-reads-merged-CRDT-state discovery — one-PerCheckpoint, not batched; (c) the `MatcherConfig` reorganization held to `ResolverConfig.MaxRangeRows` so AsOf's stable `NewResolver` signature stays byte-untouched)
**Builds on:** ADR-0017 (Day-12 — the READ-half `/v1/query` + `Resolver.AsOf` single-point surface this fork generalizes to a window), ADR-0018 (Day-13 — the per-entity L0 split that keyed the `l0/<hex8(sha256)[:8]>/` directory layout Range inherits), ADR-0019 (Day-14 — the L0→L1 per-entity compaction whose `loadSupersededL0Keys` + L1-always+tail-after-supersession discipline Range mirrors byte-for-byte, the §1.3 superset invariant), ADR-0022/ADR-0023 (Day-17/Day-18 — the dictation-premise-audit discipline this track re-executes: prose corrected against bytes BEFORE shipping; and the clean-chain-fork property Day-18 first achieved that this fork is the SECOND to hold — ZERO FROZEN touched → NO re-pin → the scope gate GREEN pre-AND-post commit).

---

## §0. The root cause — the missing read surface, and the interval (NOT point) it must answer over

The engine has carried, since Day-12's `Resolver.AsOf` + `/v1/query`, a **read-
surface asymmetry**: the durable Arrow index can answer "what is the dominant
state of E at the single point (v, tx)?" — but it **cannot** answer "give me
every state of E asserted as-of transaction-time T whose valid-time **interval**
intersects the window [vLo, vHi)." An operator debugging a time window, an
auditor reconstructing a history, a reconciliation sweep comparing two
transaction-times, an analytics window over a validity span — all are served
by a **range read** AsOf structurally cannot produce (AsOf collapses the durable
index to ONE dominant; the question is over the **window of rows**, not the
dominant point).

### §0.a Why interval-intersection, not point-in-window (the load-bearing semantic)

A bitemporal record R carries a **valid-time interval** `[validTimeStart,
validTimeEnd)` — not a point. The record answers "what was true at v=150" AND
"what was true across the window [120, 180)" — *both* are queries into the SAME
record's validity interval. A `Range` query is therefore over **intervals**, not
over points: a row R qualifies iff its interval `[vs, ve)` **intersects** the
query window `[vLo, vHi)`:

```
   (W1) R.validTimeStart <  validTimeHi     ← the row starts BEFORE the window ends
   (W2) R.validTimeEnd   >  validTimeLo     ← the row ends AFTER the window starts
        ── the half-open interval [vs,ve) INTERSECTS the half-open window [vLo,vHi)
   (W3) R.SystemTime     <= transactionTime ← Filter 2 from scanRecordBatch (visibility)
   (W4) entity-hash-prefix match (Filter 1) AND full-entityID verify (Filter 4)
```

The composite skip rule `validStart >= vHi || validEnd <= vLo` is the **inverse**
of `(W1)&&(W2)`. The strict/non-strict bound discipline carries **one-for-one**
from `scanRecordBatch`'s Filter 3 (the point-membership test
`validTimeNs >= validStart && validTimeNs < validEnd`): the high end is **strict**
(`validStart < vHi` — a row that starts *exactly at* `vHi` is OUTSIDE the
half-open window `[vLo, vHi)`) and the low end is **strict-negated** (`validEnd
> vLo` — a row that ends *exactly at* `vLo` does NOT intersect). The boundary
tooth (`TestTrack19_T1_HalfOpenBounds_RangeCarriesFilter3Discipline`) pins all 7
boundary cases — a row touching the window at exactly one endpoint is EXCLUDED, a
row whose interval OVERLAPS is INCLUDED.

The **silent-data-loss class** this guards: weakening the test to a
*point-in-window* sweep (does some point of `[vLo, vHi)` lie in `[vs, ve)`?)
would SILENTLY LOSE a record whose interval merely **overlaps** the window but
contains no queried grid point — the SAME data-loss class this engine has closed
since Day-8 (`WALRecClockAdvance`) / Day-13 (the multi-entity read-miss) / Day-14
(`MaxL0Files`). The carrier of bitemporal truth is the **interval**, so the
window query is over the interval, not a point sweep.

### §0.b The bounded-history domain (why `MaxRangeRows`, not "return everything")

AsOf returns ONE event; Range can return **O(history)** rows. For a wide window
over a long history this is a **memory + JSON-marshal amplifier** — the SAME
unbounded-amplification class the missing `MaxL0Files` cap closed in Day-13
(ADR-0018 §"the silent multi-entity read-miss class"). The honest engineering
response is NOT "make Range as fast as AsOf" (a window read over O(history) rows
is, by definition, O(history) work) — it is to **bound the resident set** so the
marshal never sees an unbounded slice, and to **signal the bound** honestly.

`ResolverConfig.MaxRangeRows` (default **4096**, 0 = UNLIMITED — a *disclosed*
sentinel, NOT the default) caps the collector BEFORE the JSON marshal. The cap is
checked **inside `scanWindowRecordBatch`** before each append — `if cap > 0 && len(out) >= cap { stop = true; return }` — so the returned slice NEVER carries `> cap`
rows and the downstream `rangeResponse` marshal NEVER sees `> MaxRangeRows`. On a
hit, Range returns the capped rows + a `truncated:true` signal (the operator
widens the window or paginates; pagination is a **future fork**, §6). The
T5 tooth seeds a 10-row history with `MaxRangeRows=4` and asserts `truncated=true`
+ **exactly** 4 rows (the count IS the proof — the marshal never saw 5).

`MaxRangeRows` is **deliberately NOT coerced** up in `NewResolver`: 0 is the
documented UNLIMITED sentinel, so a caller that asks for unbounded range results
gets them (the disclosure lives in this ADR + the `truncated` flag, **not** a
silent bump to 4096). A negative value is coerced to 0 (unlimited) so a
misconfigured caller does not crash on a negative cap comparison. `NewResolver`'s
signature stays **byte-untouched** — `MaxRangeRows` is a field on the existing
`ResolverConfig`, not a constructor arg (the AsOf stability contract carries).

### §0.c The skiplist carry-forward (the NOT-implemented, disclosed)

The architecture (per the prompt's §6) carries TWO additional range
capabilities this fork does **NOT** implement, disclosed here so they are not
re-discovered as oversights:

1. **Skiplist `Seek` for a window lower-bound.** The `SkipListArena` (`internal/database/skiplist_arena.go`) is keyed `hash[0:16] | SystemTime | validTimeStart | assertionTime` — a composite key that supports a logarithmic `Seek` to the first row whose `validTimeStart >= vLo` for a given entity. A production Range over a *huge* single entity would use `Seek` to skip the rows before the window's low end (rather than the current O(N) per-file linear scan over ALL the entity's rows). This fork's `scanWindowRecordBatch` is the **linear-scan** path (mirrors `scanRecordBatch`); the `Seek` optimization is a future fork. The linear scan is correct (it returns the right set); it is not optimal for a wide window over a single very-large entity.

2. **Live cross-entity tail.** Range today reads the **durable** surface (L0/L1 Arrow files). A query that needs the **unflushed** MemTable rows (the live ingest buffer not yet checkpointed) is a *different* capability — `Resolver.AsOf` does not read the live MemTable either (both read the durable index). A "live + durable" Range would join the MemTable's in-memory SkipList with the durable L0/L1 files at query time. This is a genuinely different capability (a read-isolation + flush-coordination seam), disclosed NOT implemented; the durable-only surface is the honest scope of this fork (and matches `AsOf`'s scope exactly — the §1.3 superset invariant REQUIRES Range read the SAME surface AsOf reads).

---

## §1. The design

### §1.1 Interval-intersection vs point-in-window (the §0.a semantic, code form)

`scanWindowRecordBatch` (`internal/database/query.go`) is the N-row sibling of
`scanRecordBatch`. The two share the SAME 4 filters, the SAME column
type-assertions, the SAME zero-allocation-in-the-loop discipline. The ONLY
structural difference is the terminal action (append-to-slice vs track-best-
index) and the MaxRangeRows cap. Filter 3 is the **window variant**:

```go
// Filter 3 WINDOW VARIANT: interval-INTERSECTION with [vLo, vHi).
// (W1) validStart < vHi  AND  (W2) validEnd > vLo.
// Skip on the inverse: validStart >= vHi OR validEnd <= vLo.
// The strict/non-strict bounds mirror scanRecordBatch's Filter 3 — DO NOT relax.
validStart := int64(validStartCol.Value(row))
validEnd   := int64(validEndCol.Value(row))
if validStart >= validHiNs || validEnd <= validLoNs {
    continue
}
```

The half-open bound discipline is *the* load-bearing detail: a future refactor
that weakened `validEnd <= vLo` to `validEnd < vLo` (or `validStart >= vHi` to
`validStart > vHi`) would SILENTLY include/exclude the boundary rows — the
`TestTrack19_T1_HalfOpenBounds_RangeCarriesFilter3Discipline` tooth pins the 7
boundary cases so this regression is a test failure, not a silent semantic drift.

### §1.2 The unbounded-amplification guard (`MaxRangeRows`, §0.b code form)

The cap is enforced **inside** the per-row loop, **before** each append:

```go
// CAP — the unbounded-amplification guard. Checked BEFORE the append so the
// slice NEVER carries > cap rows. 0 = UNLIMITED (the disclosed sentinel).
if cap > 0 && len(out) >= cap {
    stop = true
    return out, stop
}
```

`stop` propagates up `scanWindowRecordBatch` → `scanWindowFile` (returns early)
→ `Range`'s file loop (`break`). The cap is the **safety contract, not a hint** —
on a hit, the remaining files are NOT scanned. The returned rows are the FIRST
`cap` rows the scan encountered (newest-`SystemTime` files first via the reverse
sort), post-sorted by `validTimeStart` ascending for the operator-facing window
order. The `TestTrack19_T5` tooth asserts `len(rows) == cap` EXACTLY + the
UNLIMITED control (`cap=0`) asserts all 10 rows + `truncated=false` — the honest
contrast that pins the sentinel's meaning.

### §1.3 The file loop: Range MIRRORS AsOf (the superset invariant)

`Range`'s file-listing + supersession discipline is **byte-identical to AsOf's**:
`loadSupersededL0Keys`, the `MaxL0Files` tail cap (the Day-13 guard), the reverse
sort, the `ctx.Err()` check. The `TestTrack19_T2_AsOfConsistency` tooth is the
load-bearing invariant: for the SAME entity+txTime, `AsOf(E, v, txTime)` for ANY
`v in [vLo, vHi)` returns a row present in `Range(E, [vLo, vHi), txTime)`. A
Range whose file surface DIVERGED from AsOf's (e.g. a different `loadSupersededL0Keys`,
a different tail cap) would break this — T2's 4-probe sweep catches it.

The ONLY structural difference from AsOf in the listing phase is the terminal
action: each file contributes **every** row passing (W1)-(W4) into the caller's
slice instead of one dominant. See `scanWindowFile` / `scanWindowRecordBatch`
(the N-row siblings of `scanFile` / `scanRecordBatch`).

### §1.4 The optional `CoalesceRange` (a DIFFERENT query, NOT the default)

`CoalesceRange(rows []*TriTemporalEvent)` is the **optional** post-sort dominance
pass — a per-`validTimeStart` collapse reusing the SAME Filter-2 + max-
`SystemTime` rule AsOf uses. It is offered via the `?coalesce=true` `/v1/range`
param. It is **NOT the default Range output** (Range returns the raw sorted
window); the default is the honest "as-durable" history, the coalesced view is
the "effective-state-over-time" projection. Both are honest; the operator picks.
`CoalesceRange` is a **pure function over the collected rows** — it does NOT
re-scan the durable index and does NOT change `scanRecordBatch` (the prompt's
"DO NOT mutate scanRecordBatch" constraint honored).

---

## §2. The production code

`internal/database/query.go`:
- `ResolverConfig.MaxRangeRows` (default 4096; 0 = UNLIMITED sentinel).
- `Resolver.Range(ctx, entityID, validTimeLo, validTimeHi, txTime) ([]*TriTemporalEvent, truncated bool, error)`.
- `scanWindowFile` (the N-row sibling of `scanFile`; byte-identical download + jemalloc buffer + schema-validation + per-batch loop).
- `scanWindowRecordBatch` (the N-row sibling of `scanRecordBatch`; the 4 filters + the cap-before-append).
- `CoalesceRange` (the optional post-sort per-start dominance pass).

`pkg/mesh/control.go`:
- `/v1/range` route registration.
- `handleRange` (mirrors `handleQuery`'s 405/503/400/404/500 discipline + the range-specific 400 guards for `valid_time_lo`/`valid_time_hi` + the empty-window guard `valid_time_hi <= valid_time_lo`).
- `windowRow` (the persisted tri-temporal event the Arrow index carries; FIELD-FOR-FIELD mirror of `queryResponse` minus the sentry-body `payload` field — the G06.e "digest-is-not-value" fabrication guard carries across the window surface).
- `rangeResponse` (`entity` + `rows []windowRow` + `truncated bool`).

`cmd/sovereign-node/main.go`: **NOT touched** (the resolver is already constructed by the Day-12 wiring; Range rides the SAME `NewResolver(lfs, lfs, queryAlloc, "local", DefaultResolverConfig())` path — `DefaultResolverConfig()` now includes `MaxRangeRows: 4096` by default, so the binary gets the cap for free).

### §2.a ZERO FROZEN touched (the SECOND clean-chain fork)

The 5-file FROZEN set is byte-identical to the Day-18 pins:

| File | md5 | Pin source |
|---|---|---|
| `pkg/sync/crdt.go` | `835350a8…` | Day-17 re-pin (ADR-0022) |
| `pkg/sync/crdt_apply.go` | `ed9132a2…` | Day-10 baseline |
| `api/capnp/api/capnp/schema.capnp` | `47d2796a…` | Day-10 baseline |
| `api/capnp/api/capnp/schema.capnp.go` | `590af228…` | Day-10 baseline |
| `pkg/attribution/envelope.go` | `b1beba1e…` | Day-10 baseline |

Day-18 was the FIRST fork since Day-10 to need NO re-pin (the observability
bridge imported `internal/telemetry` without touching the live HAMT/capnp/
attribution tiers). Day-19 is the SECOND: Range adds a read surface
(`internal/database/query.go` — NOT FROZEN) + an HTTP route (`pkg/mesh/control.go`
— NOT FROZEN). The `TestGate_UntouchedFrozenAndOutOfScope_Day19` tooth
(`pkg/mesh/query_range_test.go`) byte-compares all 5 FROZEN files against
`git show HEAD:<path>` and is GREEN **pre-AND-post commit** — the Day-18 property
(vs the re-pin forks Day-10/16/17 which were transient-Fail-pre-commit, green
post-commit only).

---

## §3. The scanRecordBatch generalization (.prompt §1.3 honored)

The prompt's §1.3 "scanRecordBatch generalization" is satisfied by **mirror,
not mutation**: `scanWindowRecordBatch` reuses the SAME column type-assertions,
the SAME 4 filters (Filter 3 in its window variant), the SAME 2-heap-alloc emit
pattern `scanRecordBatch` uses post-loop (the `unsafe.String`-to-heap-copied-
slice idiom). The prompt's **"DO NOT mutate scanRecordBatch"** constraint is
honored — `scanRecordBatch` is byte-untouched (the AsOf hot path is NOT
polluted by the Range N-row path; the zero-alloc defer-to-end property AsOf's
single-point path holds is preserved — Range's per-row alloc is the honest cost
of the N-row window, paid only on the Range path, NOT on AsOf's).

---

## §4. The T3 premise-audit (the dictated correction — the day-17/18 class repeated)

The prompt framed T3 as: *"seed a SECOND entity whose `sha256[:16]` collides
on the FIRST 8 bytes but not the full 16 — the same `l0/<hex8>/` dir
co-locates both"* and the RED as *"drop Filter 4 leaks the collision"*. A
byte-read of `query.go` refutes the premise:

- `ArrowSchema` field 0 (`entity_id_hash`) is `FixedSizeBinary(16)` — the **FULL 128-bit hash**, NOT 8 bytes (`l0_flusher.go:43`).
- `scanRecordBatch` Filter 1 compares the FULL 16 bytes: `bytes.Equal(rowHash, hashPrefix[:])` where `hashPrefix` is `[16]byte` (`query.go`, the matcher). A `[:8]`-collision-with-`[:16]`-diff is therefore REJECTED by **Filter 1 itself**, NEVER reaching Filter 4. Dropping Filter 4 would NOT leak it.
- The `l0/<hex8>/` directory namespacing uses the FIRST 8 bytes ONLY for the directory prefix (the S3 listing scope); the per-ROW `col0` is the full 16 bytes. The two are different surfaces (one is a listing-prefix optimization; the other is the per-row 128-bit compare).

The prompt's "drop Filter 4 leaks the collision" is the **day-17 (ADR-0022) /
day-18 (ADR-0023) dictation-premise class** — a mechanism that does NOT hold
against the bytes. The honest Filter-4 test:

- **DECOUPLES** the `col0` key prefix from the value-body `entityID` (the ONE shape a dishonest/corrupt write path could produce that REACHES Filter 4): a planted row whose 16-byte `col0` key claims "E1" (so it lands in E1's `l0/<hex8(sha256(E1))>/` dir + passes Filter 1 for `Range(E1)`) but whose value-body `entityID` is "E2" (so Filter 4 MUST reject it). `range19InsertRowDecoupled` (`internal/database/range_track19_test.go`) plants this; the flusher reads `entityID` from the **packed value body** (`l0_flusher.go`, via `makePackedValue`), and `col0` from `key[:16]` — the package's own layout supports the decoupling (the track13/14 helpers couple them by construction; a custom helper decouples).
- This exercises the REAL Filter-4 guard **deterministically** — no birthday search on 64 bits (infeasible in CI: ~2³² expected tries) — and matches the prompt's **INTENT** ("Range for E1 MUST NOT return E2's rows").

The decoupling is the defense-in-depth against a dishonest write path: the
production `L0Flusher` couples `col0` and `entityID` (both from
`sha256(entityID)`), so a row that passes Filter 1 with E1's hash WILL have E1's
entityID in the body — UNLESS the write path is corrupted. Filter 4 is the guard
that makes a corrupted write path's wrong-entity leak a read-time REJECTION, not
a silent wrong-data return. The T3 tooth plants the corrupted shape + asserts
Filter 4 rejects it.

### §4.a The Bridge-vs-SkipList seeding discovery (the §0.b-dictated T2/T6 correction)

The prompt implied the T2/T6 teeth seed a multi-row-per-entity history via the
production `Bridge.PutLocal` + `AppendCheckpoint` harness (the Day-12
`queryHarness`). A byte-read of `SnapshotToLSM` (`pkg/durability/snapshot.go`)
refutes this: `SnapshotToLSM` reads `engine.State()`'s **MERGED dominant per
entity** (the `latest` map, `snapshot.go:32-66`) — so multiple `PutLocal`s to the
SAME entity in ONE checkpoint COLLAPSE to ONE row (the CRDT's merged state, not
the raw append history). The Day-12 `query_test.go` T1 never hit this because it
writes ONE event per checkpoint.

The honest seeding for the Bridge-path T2/T6 teeth: **ONE `PutLocal` PER
checkpoint** — each checkpoint's dominant lands as its OWN L0 file (the SAME
shape a sovereign-node's checkpoint cadence produces). Range then reads the
multi-FILE history (each L0 file is the per-checkpoint dominant). This is the
FAITHFUL durable surface a production node writes; the multi-DOT-per-FILE seam
(co-locating several rows in ONE Arrow file) lives in the `internal/database`
+ `pkg/durability` teeth (the `SkipListArena`→`L0Flusher.FlushFromArena` path
that writes ALL rows directly to the Arrow file, NO CRDT merge — the track13/14
precedent). The import-cycle (an `internal/database` test cannot import
`pkg/durability` because `snapshot.go` imports `internal/database`) FORCES the
REAL-`*LocalFS` teeth into `pkg/durability` + the seam teeth into
`internal/database` — the honest test-file split this fork takes.

T2 + T6 / 200_sorted_window were re-seeded one-PerCheckpoint AFTER this discovery
(the first characterization attempt batched 3 PutLocals into 1 checkpoint and
collapsed to 1 row — the discovery that surfaced `SnapshotToLSM`'s merged-read).
The re-seeded teeth assert the multi-FILE history (3 L0 files for T2, 2 for T6)
and the superset invariant holds across the multi-file surface.

---

## §5. The teeth

### internal/database/range_track19_test.go (the SEAM-level proofs — in-memory store)
- **T1** `TestTrack19_T1_RangeHeadline_IntervalIntersection_NotPointInWindow` — 4 disjoint windows, query [25,65) → exactly the 2 intersecting rows; [10,20) excluded (W2), [70,80) excluded (W1).
- **T1-empty** `TestTrack19_T1_EmptyWindow_RangeReturnsErrEntityNotFound` — a disjoint window → `ErrEntityNotFound` (the honest not-found sentinel, NOT an empty 200).
- **T1-bounds** `TestTrack19_T1_HalfOpenBounds_RangeCarriesFilter3Discipline` — 7 boundary cases pin the strict/non-strict W1/W2 bounds.
- **T2** `TestTrack19_T2_AsOfConsistency_RangeSupersetOfEveryPoint` — overlapping windows, 4-probe AsOf sweep each ∈ Range result-set (the load-bearing superset invariant).
- **T3** `TestTrack19_T3_Filter4Integrity_DecoupledCol0NotEntityID` — the decoupled-col0 Filter-4 test (the §4 premise-audit).
- **T5** `TestTrack19_T5_MaxRangeRowsCap_TruncatedPreMarshal` — 10-row history, `MaxRangeRows=4` → exactly 4 + `truncated=true`; the UNLIMITED control (`cap=0`) → all 10 + `truncated=false`.

### pkg/durability/range_track19_test.go (the REAL *LocalFS proofs — the durable surface)
- **T1-REAL** `TestTrack19_T1_RangeHeadline_REALLocalFS_IntervalIntersection` — the headline over the production on-disk path (belt + suspenders: the seam tooth proves the filters; this proves the durable surface).
- **T4** `TestTrack19_T4_RangeScansL1PlusUncompactedTail` — after a compaction merges the bulk into ONE L1, write 2 uncompacted tail checkpoints; Range window intersects rows across BOTH tiers (2 from L1 + 2 from tail = 4). A Range that scanned only one tier returns 2 → the data-loss class Day-14 closed.
- **T5-REAL** `TestTrack19_T5_REALLocalFS_MaxRangeRowsCap_Truncated` — the cap over the on-disk index.

### pkg/mesh/query_range_test.go (the operator-facing seam + scoping)
- **T2-REAL** `TestTrack19_T2_AsOfConsistency_RangeSupersetOverREALLocalFS` — the superset over the Bridge → checkpoint → Arrow path (the §4.a one-PerCheckpoint re-seed).
- **T6** `TestTrack19_T6_RangeRouteContract` — 10 subtests: 200_sorted_window + 405_POST + 503_resolver_nil + 503_runs_BEFORE_param_validation + 400_missing_key + 400_bad_valid_time_lo + 400_bad_valid_time_hi + 400_bad_tx_time + 400_empty_window_hi_le_lo + 404_entity_not_found.
- **T7** `TestTrack19_T7_FrozenByteIdentical_NoRePin` (the 5-file md5) + `TestTrack19_T7_ScopeHygiene_MeshImportOfSyncUnchanged` (pkg/mesh/control.go imports pkg/sync UNCHANGED; handleRange goes through `s.resolver.Range`, NOT the engine) + `TestGate_UntouchedFrozenAndOutOfScope_Day19` (git-HEAD byte-compare, GREEN pre-AND-post — the Day-18 property).

### §5.a The honest residual (the Alloc-per-row is NOT zero — disclosed)

`scanRecordBatch` (AsOf's single-point path) defers its ONE allocation to *after*
the loop (tracking `bestRowIndex`, allocating the single TriTemporalEvent once).
Range **cannot** defer — it must emit every matching row — so the
alloc-per-matching-row is the **honest cost of the N-row window**. This is NOT the
single-point hot path: AsOf's defer-to-end zero-alloc property is preserved
(`scanRecordBatch` is byte-untouched); Range's per-row alloc is paid ONLY on the
Range path. The `2-heap-alloc per row` (the entityID string copy + the payload
[]byte copy via `unsafe.String`/`unsafe.SliceData` idiom) mirrors
`scanRecordBatch`'s post-loop block — Range simply does it per-row instead of
once. This is the honest residual, disclosed NOT gamed (the prompt's
single-point zero-alloc gate, `TestHotPathZeroAllocations`, is for the AsOf/write
path; Range is a window READ, not a hot-path write).

---

## §6. Carry-forwards (the NOT-implemented, disclosed — the prompt §6 honored)

1. **Skiplist `Seek` for the window lower-bound** (§0.c.1) — a logarithmic skip to the first `validTimeStart >= vLo`, for a wide window over a single very-large entity. The linear-scan path is correct; the `Seek` optimization is a future fork.
2. **Live cross-entity tail** (§0.c.2) — joining the unflushed MemTable SkipList with the durable L0/L1 files at query time (read-isolation + flush-coordination seam). Neither AsOf nor Range reads the live MemTable today; both read the durable index.
3. **Pagination** — the `truncated:true` signal tells the operator the cap was hit; the pagination token (= the last returned row's `validTimeEnd`) is a future fork. The operator today widens the window or re-queries past the cap.
4. **`CoalesceRange` default** — the per-start dominance coalesce is OFF by default (the raw sorted window is the honest "as-durable" history); a future fork may flip a per-endpoint default if the "effective-state-over-time" projection becomes the dominant operator use case.

---

## §7. The gate (the §III evidence — exact terminal output)

```
go build ./...                                                                 → exit 0
go vet ./internal/database/ ./pkg/mesh/ ./pkg/durability/ ./cmd/sovereign-node/ → exit 0
gofmt -l <5 touched files>                                                     → (clean)
md5sum <5 FROZEN>                                                              → 835350a8 / ed9132a2 / 47d2796a / 590af228 / b1beba1e (== Day-18 pins)
go test -race -count=1 ./internal/database/                                    → ok  33.7s
go test -race -count=1 ./pkg/mesh/                                             → ok  29.8s
go test -race -count=1 ./pkg/durability/                                       → ok  10.9s
fieldalignment ./... (windowRow: matches Day-12 queryResponse precedent lint — 2 string fields; NOT a hot-path contended-atomic struct, Law II cache-stride does not apply; rangeResponse clean)
TestTrack19_T1..T7 + TestGate_UntouchedFrozenAndOutOfScope_Day19               → PASS (pre-AND-post commit — the Day-18 property, the SECOND fork)
```

**ROOT CAUSE:** the durable Arrow index carried an AsOf-only read surface (`/v1/query` — single dominant point); the bitemporal-HISTORY window read (every row whose valid-time *interval* intersects `[vLo, vHi)`, asserted as-of `txTime`) was missing — a read-surface asymmetry since Day-12.

**CHANGE:** `Resolver.Range` + `scanWindowFile` + `scanWindowRecordBatch` (`internal/database/query.go`, 4 filters + the `MaxRangeRows` cap checked pre-marshal) + `/v1/range` (`pkg/mesh/control.go`, mirrors `/v1/query`'s 405/503/400/404/500 discipline + range-specific 400 guards) + `CoalesceRange` (optional post-sort coalesce, default OFF). ZERO FROZEN touched (the SECOND clean-chain fork after Day-18 → NO re-pin → scope gate GREEN pre-AND-post).

**GATE:** PASS — `go build ./...` exit 0; `go vet` exit 0; 3 target packages `-race` green; 5 FROZEN md5 byte-identical; 11 teeth (T1/T1-empty/T1-bounds/T2/T3/T5 × in-mem + REAL *LocalFS + T4-L1+tail + T6-10-subtests + T7-md5/scope) red→green; honest residual = alloc-per-row (disclosed, NOT on the AsOf hot path).
