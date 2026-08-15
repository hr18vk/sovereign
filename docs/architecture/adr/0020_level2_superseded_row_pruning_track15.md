# ADR-0020: The Level-2 Superseded-Row Pruning Fork — the Tri-Temporal Dominance Lattice + a Transaction-Time GC Floor (the honest closure of the §0.4 truth-maintenance trap ADR-0019 deferred)

**Status:** Accepted
**Date:** 2026-08-03
**Phase:** 3, Day 15
**Author:** Sovereign Architect (head, dictated the prompt) + Sovereign Executor (same session — single-agent impl of the dictated fork)
**Builds on:** ADR-0019 (Day-14 L0→L1 per-entity compaction — Preserve-All the §0.4 truth-maintenance trap; this fork closes it), ADR-0018 (Day-13 per-entity keying — the merge is a single-key op), ADR-0017 (the resolver read-half — the scanRecordBatch dominance rule + Filter2/Filter3 the prune rests on), the Day-12.5 [243c10a] tooth-principle ("a tooth that proves X→Y must DRIVE X the route, not shortcut to Y's seam")

---

## §1. Context (the §0.4 truth-maintenance trap; ADR-0019 deferred it; Day 15 closes it)

ADR-0019 delivered the Level-1 compaction (the L0→L1 per-entity merge) that eliminates the
`MaxL0Files` silent-data-loss cap. The merge **PRESERVED EVERY ROW** — explicitly, because row-
pruning (superseded-row elimination) is bitemporal **truth maintenance**: a row R is safe to drop
on merge IFF a row R' in the merged set dominates R for **every future query** (`sysTime(R') >
sysTime(R)` AND `[validStart(R'),validEnd(R'))` contains `[validStart(R),validEnd(R))`). ADR-0019 §6
**explicitly DISCLOSED** this as the Level-2 fork: determining interval containment over an
unbounded future query space is O(rows²) at worst AND WRONG under partial observability — a query
with `txTime` in the past sees an OLDER dominant, not the newer one, so dropping R "overwrites
the past." Day 15 is the honest closure of that trap: a **tri-temporal dominance lattice** + a
**transaction-time GC horizon/floor** that makes the drop **provably-safe for the LIVE query
set** without ever silently overwriting the past.

The dead `EpochCompactor` (ADR-0018 §6; the Level-2 *tombstone* reaper) stays DEAD — zero
production importers (grep-verified; `NewEpochCompactor`/`SetCompactor`/`InsertTombstone`/
`PruneTombstones` each have 0 production callers; the L0Flusher.compactor field + the nil-guarded
`PruneTombstones` call at `l0_flusher.go:125` are the only references, `f.compactor` always nil).
Day-15 pruning is **NOT** a tombstone DELETE op; it is a pure-function seam that drops rows **at
compaction-merge time** (the rows are written fresh into the L1, minus the dead ones), with NO
live-DELETE, NO memtable mutation, NO WAL record.

## §2. The root cause + the (C3) load-bearing insight (the txTime-GAP proof)

**Root cause (one sentence):** a horizon-less "(C1)&&(C2)-only" prune SILENTLY OVERWRITES the past
— for R < R' with `sysTime(R') > sysTime(R)` and `[vs',ve')` containing `[vs,ve)`, a query at
`(V in [vs,ve), txTime in [sysTime(R),sysTime(R')))` admits R but NOT R' (`scanRecordBatch`
Filter2: `sysTime(R') > txTime` → `continue`), so R is the SOLE winner; dropping R returns an
OLDER admitted row (or `ErrEntityNotFound`), NOT the truth → the SAME silent-data-loss class the
engine has closed since Day 8.

**The (C3) floor — the load-bearing insight.** The horizon `T_gc` is a **transaction-time FLOOR**:
the operator guarantees NO live query will AS-OF a transaction time `txTime < T_gc` (a monotone
non-decreasing retention low-water mark; the operator advances it as the application retires
historical AS-OF queries). A dominator R' is SAFE to rely on for the LIVE query set only if it is
**Filter2-admitted for every live query** — i.e. `sysTime(R') <= T_gc` (a live query has
`txTime >= T_gc >= sysTime(R')`, so Filter2 admits R'). That is exactly **(C3)**:

```
SAFE-DROP: drop row R  iff  ∃ a RETAINED row R' with
  (C1) sysTime(R') > sysTime(R)              -- R' is NEWER (a later assertion)
  (C2) [vs',ve') contains [vs,ve)             -- R' answers every validTime R does
  (C3) sysTime(R') <= T_gc                     -- the dominator is FLOOR-admitted
```

Each claw is **individually necessary** (the teeth pin each in isolation via a φ-break fixture that
strips one claw):

- **drop (C3)** → a live query at `txTime ∈ [sysTime(R),sysTime(R'))` admits R but NOT R' → R is
  the SOLE winner → drop corrupts (T1 RED — the §0.4(ii) txTime-GAP proof).
- **drop (C2)** → a query at `V ∈ [vs,vs')` (inside R's interval but OUTSIDE R's) is answered ONLY
  by R (R' is Filter3-skipped: `V < vs'`) → R is LIVE → drop corrupts (T2 RED — the containment claw).
- **drop (C1)** → an OLDER R' cannot dominate a NEWER R on the `scanRecordBatch` max-`sysTime`
  dominance rule (R would beat R', not be beaten by it) → the claw is impossible to violate in a
  way that loses data; it is a structural guard, not a load-bearing one — but the prune pins it
  regardless (the test chassis verifies an older row never drops a newer one).

**(C3) makes the drop PROVABLY-SAFE for the LIVE set:** for every live query `(V, txTime >= T_gc)`,
R' is Filter2-admitted (`sysTime(R') <= T_gc <= txTime`), is Filter3-valid (containment (C2)), and
is NEWER (C1) → R' beats R on the max-`sysTime` rule → R is **provably-never-the-answer** for the
live set → SAFE to drop. NO silent data loss for the LIVE set; the below-floor set is the operator's
contract to retire (the disclosed residual — the floor advances monotonically).

## §3. The fix + the byte chain

**The byte-verified chain (HEAD 43f368b → Day-15 HEAD, read from the committed tree, not memory):**

```
l1_compactor.go:49-82   CompactionConfig{ EnableDominancePruning bool; PruningHorizonInt64Ns int64 }
l1_compactor.go:84-97   DefaultCompactionConfig() → Preserve-All (EnableDominancePruning=false) the byte-
                        identical Day-14 default
l1_compactor.go:139-176 NewL1Compactor — the LOUD horizon guard: ENABLED + horizon<=0 → WARN +
                        coerce-to-Preserve-All (log.Printf, NOT a swallowed nil — Law: every error
                        path must be loud)
l1_compactor.go:~250-330 DominancePrune(rows, horizon) []mergedRowT — the PURE FUNCTION. In-place
                        compaction via a SINK index; a row R is dropped iff a retained R' satisfies
                        (C1)&&(C2)&&(C3). horizon<=0 → returns rows UNCHANGED (Preserve-All).
l1_compactor.go (Compaction body): the prune call inserted between sort.SliceStable (the sort) and
                        the column-append loop (the SINGLE minimum-blast-radius insertion point
                        Day-14 left open). Sets RowsBefore/RowsAfter/RowsPruned; sets telemetry.
l1_compactor.go (CompactionResult): +RowsBefore/RowsAfter/RowsPruned (Rows == RowsAfter — the Day-14
                        back-compat field)
registry.go:160-165     CompactionRowsPruned *Counter — the disclose-it counter (Law V); Preserve-All
                        never touches it
main.go:111-122         nodeConfig.compactionPruneEnable + compactionPruneHorizon
main.go (parseFlags)    --compaction-prune-enable (default false) + --compaction-prune-horizon-ns (default 0)
main.go (~330)          compactionCfg := DefaultCompactionConfig(); .EnableDominancePruning = cfg flag;
                        .PruningHorizonInt64Ns = cfg flag; NewL1Compactor(...) — operator knobs VERBATIM
```

**The prune is an OPT-IN pure function.** `EnableDominancePruning=false` (the DEFAULT) skips the
`DominancePrune` call entirely → rows UNCHANGED → the byte-IDENTICAL Day-14 behavior (G15.h back-
compat). The engine **NEVER auto-prunes** — `T_gc` is an OPERATOR RETENTION POLICY, NEVER an
inferred optimisation (a future fork infers it off live-query `txTime` telemetry; disclosed, NOT
in Day-15 scope).

**The retained set is a SORTED SUB-SEQUENCE of the input.** `DominancePrune` compacts in-place via
a SINK index → the output is a sub-sequence of the composite-key-sorted input (schema-identical;
only the cardinality shrinks). The L1 is therefore byte-stable across runs (T3 idempotency — two
compactions on the same L0 set + horizon yield identical L1 bytes), and a pruned L1 is a STRICT
SUBSET of the Preserve-All L1 for the LIVE query set (T4 equivalence).

## §4. The teeth (the gate) — all GREEN

**G15.a — build:** `go build ./...` → PASS (0 errors).
**G15.b — vet:** `go vet ./...` → PASS (0 warnings) on the touched packages.
**G15.c — gofmt:** `gofmt -l` on the edited files → clean.
**G15.d — -race:** `GOMAXPROCS=4 go test -race -run TestTrack15 ./internal/database/ ./pkg/durability/` →
PASS (0 races — the prune is a single-goroutine pure function inside the existing compactor call;
the only shared state is the `rows []mergedRowT` buffer, owned by the Compaction goroutine).

**The teeth (each WITH run output):**

- **T1 — (C3) the §0.4(ii) txTime-GAP proof (RED→GREEN, REAL *LocalFS route):** two rows same wide
  interval, R(sys=100,'R') + R'(sys=250,'D'). GREEN-LOW (floor 200 < dominator 250): (C3) refuses
  → R retained (`RowsPruned=0`); the GAP AsOf(txTime=150, in [100,250)) resolves to R (the sole
  Filter2-admitted row). GREEN-HIGH (floor 1000 >= dominator 250): (C3) admits → R dropped
  (`RowsPruned=1`); the LIVE AsOf(txTime=1000 >= floor) resolves to R' ('D', the dominator, same
  answer Preserve-All gives); the below-floor query honestly returns `ErrEntityNotFound` (the
  disclosed residual — the operator's no-below-floor-query contract). The pure-function φ-break RED
  (`track15PruneNoC3`) DROPS R even with the dominator above the floor → proves (C3) is load-bearing.
- **T2 — (C2) the containment claw (RED→GREEN, REAL *LocalFS route):** SCENARIO-A (dominator
  NARROWER): (C2) refuses → R retained (`RowsPruned=0`); the boundary V=10 (R-only; R' Filter3-
  skipped: `10 < vs'=200`) resolves to R. SCENARIO-B (dominator WIDER + floor-admitted): (C1)&&(C2)&&
  (C3) all hold → R dropped (`RowsPruned=1`); the covered V=500 resolves to R' ('D', same as
  Preserve-All). The pure-function φ-break RED (`track15PruneNoC2`) DROPS R even when the interval is
  not contained → proves (C2) is load-bearing.
- **T3 — idempotency + Preserve-All default:** T3a (pure fn): two `DominancePrune` calls on the same
  input → byte-identical survivors; re-pruning the pruned output is a fixed point. T3c (pure fn):
  horizon<=0 returns the input unchanged (Preserve-All). T3b (route): the Preserve-All DEFAULT +
  the LOUD-coerce path (ENABLED + floor<=0 → WARN + disable) produce BYTE-IDENTICAL L1s (2210 bytes
  each, `RowsPruned=0` for both); ENABLED + floor above every sysTime drops A,B (`RowsPruned=2`,
  `RowsAfter=1`) and the L1 DIFFERS from Preserve-All by the 2 pruned rows — the prune IS wired
  (not a silent no-op).
- **T4 — live-query EQUIVALENCE (REAL *LocalFS):** 4 rows same wide interval, sysTime 100/200/300/400.
  Preserve-All (RowsAfter=4) vs Pruned at floor 1000 (RowsPruned=3, RowsAfter=1). A 4-probe LIVE
  sweep ((V,txTime) at (0,1000)/(200,1500)/(500,5000)/(999,9999999)) — Preserve-All and Pruned resolve
  to **identical** `(D, sys=400)` across all 4. The pruned L1 is a STRICT SUBSET of Preserve-All
  answers for the LIVE set; ZERO query divergence.
- **T5 — scope hygiene (dead tombstone compactor stays DEAD):** `SetCompactor`/`InsertTombstone`/
  `NewEpochCompactor`/`PruneTombstones` each have **0 production callers** (grep-verified over
  internal/pkg/cmd, excluding the definition sites compactor.go + l0_flusher.go and the nil-guard).
  Day-15 introduces NO new production importer of the dead compactor — the prune is a pure-function
  seam, not a tombstone operator.
- **T6 — FROZEN md5 set (Day-15 touches NO pkg/sync/capnp/attribution file):**
  - `pkg/sync/crdt.go`             → `705ac671` (pinned, ==)
  - `pkg/sync/crdt_apply.go`       → `ed9132a2` (pinned, ==)
  - `api/capnp/api/capnp/schema.capnp`     → `47d2796a` (pinned, ==)
  - `api/capnp/api/capnp/schema.capnp.go`  → `590af228` (pinned, ==)
  - `pkg/attribution/envelope.go`          → `b1beba1e` (pinned, ==)
  All 5 TRUE-FROZEN files byte-identical — the prune is a pure-function seam in
  `internal/database/l1_compactor.go`, no core bleed, no `crdt.go` unfreeze.

**The Day-12.5 [243c10a] tooth-principle ENFORCED:** T1/T2/T4 DRIVE the OLDEST/LIVE-query ROUTE
over a REAL *LocalFS (write → compaction → AsOf), NOT the prune seam with hand-tuned in-memory rows.
The pure-function φ-break teeth (T1-RED, T2-RED) are a COMPLEMENT that isolates each claw in
isolation; the route teeth prove the SAFE drop holds end-to-end.

## §5. Honest residuals / what this fork does NOT do

- **NOT a tombstone DELETE op.** The `EpochCompactor` family stays DEAD. The prune drops rows at
  compaction-merge time by NOT appending them to the fresh L1 — there is NO live DELETE, NO memtable
  mutation, NO WAL record, NO tombstone. A pruned row is simply absent from the next L1; the OLD L1
  is superseded by the manifest (T6 of ADR-0019 — the L0 reaper is a FUTURE fork).
- **NOT a live read-path change.** `AsOf`'s `scanRecordBatch` (Filter1/Filter2/Filter3 + the max-
  `sysTime` dominance rule) is UNCHANGED. A pruned L1 is a strict subset of the Preserve-All L1 for
  the LIVE query set ONLY; for below-floor queries the dropped row is absent (the disclosed residual —
  the operator's no-below-floor-query contract).
- **NOT a `crdt.go` unfreeze.** The 5-file FROZEN md5 set is byte-identical (T6). The Join, the
  HAMT, the SkipList — all untouched.
- **NOT a write-path change.** The prune runs INSIDE the existing `Compaction` call (on the
  existing `compactionSchedulerLoop` goroutine — ADR-0019) — NO new goroutine, NO new lock, NO
  hot-path touch.
- **NOT auto-horizon inference.** `T_gc` is operator-configured. The LOUD `NewL1Compactor` guard
  refuses ENABLED + horizon<=0 (WARN + coerce to Preserve-All). A future fork infers `T_gc` off
  live-query `txTime` telemetry (see §6) — NOT in Day-15 scope.

## §6. Residuals (the OPEN-P1 Level-3 prune refinements)

- **(a) Auto-inference of `T_gc` off live-query `txTime` telemetry.** Day-15 takes `T_gc` as an
  operator-config knob. A future fork tracks the min over recent live-query `txTime`s + advances
  the floor monotonically (the disclosed "(C3)-inference" fork). Until then the operator sets it.
- **(b) `O(N²)→O(N·H)` interval-sweep optimisation.** `DominancePrune` is `O(N²)` with early-exit
  on the first dominating R' (the rows `[]mergedRowT` is ALREADY materialized `O(N)` by the Day-14
  merge; the prune is a BACKGROUND job off the hot path; the gate is CORRECTNESS not throughput).
  The honest lower bound is `O(N·H)` (H = average coverage depth via an interval-tree / segment-
  sweep) — the future optimisation.
- **(c) The L0 reaper.** ADR-0019 keeps the manifest-superseded L0 files durable as the crash-
  recovery backstop. A future fork reaps them once delete-after-read-safety is wired.

**Latent landmines carried forward (unchanged):** the `MaxValidTime.UnixNano()` int64 overflow
(ADR-0017 §6.4 — zero prod callers) and the `eng.DataDir` global (ADR-0013 §7g).

## §7. What this proves

The Level-2 prune is a **provably-safe opt-in pure function** with a **byte-identical default** to
Day-14. It closes the §0.4 truth-maintenance trap ADR-0019 deferred, at the honest cost of an
operator floor (T_gc — the disclosed no-inference contract). The 6 teeth pin each claw in
isolation + prove the SAFE drop holds end-to-end over the REAL write/compact/read route. The engine
NEVER auto-prunes; the 5-file FROZEN set is untouched; the dead tombstone compactor stays dead.

The chain is consistent: Day 8..14 closed the silent-data-loss class on the WRITE/recovery/
keying/cap axes; Day 15 closes it on the **truth-maintenance** axis — the honest end of the
preserve-all era.
