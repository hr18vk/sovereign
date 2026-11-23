# ADR-0025: The DominancePrune interval sweep

**Status:** Accepted  
**Date:** 2026-08-07

## Context

ADR-0020 introduced superseded-row pruning during per-entity L0-to-L1
compaction. For a row `R`, the original `DominancePrune` searched every other row
for a dominator `R'` satisfying:

- (C1) `R'.SystemTime > R.SystemTime`;
- (C2) `[R'.ValidTimeStart, R'.ValidTimeEnd)` contains
  `[R.ValidTimeStart, R.ValidTimeEnd)`; and
- (C3) `R'.SystemTime <= horizon`.

C3 prevents removal of a row that a transaction-time query between the two
system times could still select. The double loop cost O(N²) comparisons in the
worst case. A survivors-only forward pass would not be equivalent: a row that is
itself dominated may be the direct dominator of an older row, with containment
transitivity carrying the final surviving dominator back to that older row.

`(*L1Compactor).Compaction` supplies a stronger precondition. It handles one
entity at a time and stable-sorts the composite fragment containing the entity
hash, system time, valid-time start, and assertion time before pruning. Within
one entity, the rows therefore arrive in ascending system-time order. The output
must remain a subsequence in that same order because the Arrow column builders
consume it directly.

Pruning is a background compaction operation, not part of the query or write hot
path. It remains disabled unless `EnableDominancePruning` is true and the
configured horizon is positive. A non-positive horizon passed directly to
`DominancePrune` preserves every row.

## Decision

Replace the double loop with a reverse sweep over equal-system-time batches and
a `live` slice of admissible dominator intervals. `liveInterval` stores only the
valid-time bounds `vs` and `ve`.

For each batch, from newest to oldest:

1. Probe every row against intervals from strictly newer batches. Equal-time
   rows are probed together because C1 is strict and they cannot dominate one
   another.
2. Mark a row dominated when a live interval contains its valid-time interval.
3. After probing the whole batch, append its surviving rows to `live` only when
   the batch system time is at or below the horizon. This enforces C3.
4. Once all batches are processed, compact unmarked rows forward in their
   original order.

The containment probe is a linear scan of `live`. Its cost is O(N·H), where H is
the number of live intervals examined, rather than O(log N) per row. A balanced
or augmented interval tree was not introduced: the sweep is confined to one
pure function and preserves the existing allocation and ordering model. Disjoint
intervals can still produce O(N²)/2 probes.

### Equivalence argument

Let `D_ref` be the rows dropped by the original all-pairs implementation and
`D_sweep` those dropped by the sweep.

If a row belongs to `D_ref`, either its direct dominator survives and enters
`live`, or that dominator is itself dominated. Following the dominators produces
a chain whose system times strictly increase, remain bounded by the horizon,
and whose valid-time containment is transitive. The finite chain terminates at
a survivor that contains the original row, so the sweep drops it too. Thus
`D_ref ⊆ D_sweep`.

Conversely, every interval in `live` comes from a strictly newer,
horizon-admitted survivor. A containment match therefore satisfies C1, C2, and
C3 for the original implementation as well, so `D_sweep ⊆ D_ref`.

The dominated sets are equal, and forward compaction preserves the same survivor
sequence. This argument relies on ascending system-time input; the function does
not sort or reject unsorted input itself.

## Consequences

The sweep allocates a `dominated []bool` marker and a `live []liveInterval`
slice. Each live entry contains two `int64` fields and no pointers. These
allocations remain off the query and write hot paths.

Nested intervals collapse `live` quickly because a newer containing interval
dominates older ones. Disjoint intervals all survive and accumulate in `live`,
which is the quadratic case. An augmented tree remains a possible later
optimization if this background cost becomes a measured bottleneck.

The production sort is part of the function's contract. Reversed input can lose
dominators without panicking, and `TestReversedSysTimePreconditionDisclosure`
documents that limitation rather than claiming order independence. Direct
callers outside `Compaction` must provide the same ordering.

The differential cases use one constant entity tag, matching the production
per-entity precondition. They do not cover a mixed-entity input slice. The
negative control for C3 is separate from the randomized loop: it demonstrates
that byte-sequence comparison detects a missing-floor divergence, not that the
loop executes a deliberately corrupted implementation.

[ADR-0027](0027_t_gc_auto_inference.md) subsequently implemented automatic
horizon inference. It changed the horizon source, not this sweep or its
survivor-equivalence argument. Pruning still requires an explicit opt-in and a
positive horizon.

## Evidence

`TestEquivDifferentialFuzz` ran 10,000 seeded cases with 0..2000 rows per case,
using seed 20. Each case compared `DominancePrune` with
`dominancePruneReference` after applying the production composite-key sort. All
10,000 produced the same ordered survivor fragments. Other focused tests cover:

- `TestLoFloorRefusesDominatorByteIdentical`: a dominator at system time 250 is
  inadmissible at horizon 200 and admitted at horizon 1000;
- `TestContainmentRefusesNarrowerByteIdentical`: a newer but narrower interval
  cannot dominate;
- `TestIdempotencyAndPreserveAllByteIdentical`: determinism, idempotency, and
  the non-positive-horizon fast path;
- `TestEquivRedControlOffByOneFloor`: the separate missing-C3 negative control;
- `TestReversedSysTimePreconditionDisclosure`: the ascending-input requirement;
  and
- `TestCompactionSweepLiveQueryEquivalenceByteIdentical`: four rows written
  through `SkipListArena`, `L0Flusher`, and a real `LocalFS`, then read through
  `Resolver.AsOf` after preserve-all and pruned compactions.

The filesystem fixture uses system times 100/200/300/400 over `[0,1000)`.
Preserve-all retains four rows. Horizon 1000 prunes three and leaves the row at
system time 400; all four query probes return that same row from both versions.

### Comparison counts and timings

`TestPruneBenchComparisonCounts` measures 1000-row fixtures rather than claiming
a universal speedup:

| Fixture | Reference comparisons | Sweep comparisons | Ratio |
|:--|--:|--:|--:|
| coverage-N: all rows cover `[0,1000)` | 500,499 | 999 | 0.0020 |
| coverage-1: disjoint `[i*10, i*10+5)` windows | 999,000 | 499,500 | 0.5000 |

The coverage-N fixture keeps `live` at one interval because the newest row
dominates every earlier row. The coverage-1 fixture retains every interval and
therefore grows `live` to N. This corrects the initial complexity prediction:
coverage-N is the collapsing case, while coverage-1 is the accumulating case.

The same historical record, using `-benchmem -benchtime=200ms`, reports:

| Fixture | Reference | Sweep |
|:--|--:|--:|
| coverage-N | 308,248 ns/op | 37,873 ns/op |
| coverage-1 | 785,766 ns/op | 222,309 ns/op |

These correspond to 8.1× and 3.5× lower elapsed time respectively. The original
record does not include host metadata for the timings, so they are not a current
cross-machine performance claim. Both comparison-count ratios satisfy the
test's 1.01 upper bound.
