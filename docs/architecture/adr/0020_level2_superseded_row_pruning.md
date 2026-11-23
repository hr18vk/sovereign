# ADR-0020: Level-2 Superseded-Row Pruning

**Status:** Accepted  
**Date:** 2026-08-03

## Context

[ADR-0019](0019_l0_l1_per_entity_compaction.md) preserves every row when it
merges L0 into L1. That avoids losing history, but L1 grows with the entity's
complete write history. Removing an older row requires more than valid-time
containment: a newer row can be invisible to a historical transaction-time
query even when it covers the same valid-time interval.

`AsOf` admits a row only when `sysTime <= txTime` and
`validStart <= validTime < validEnd`, then selects the greatest admitted
`sysTime`. Suppose R has system time 100 and R' has system time 250. A query at
transaction time 150 can see R but not R'. Dropping R merely because R' is newer
would erase the answer at that coordinate.

The decision therefore needs a retention contract as well as a dominance rule.
[ADR-0017](0017_query_resolver_read_half.md) supplies the read predicates, and
ADR-0019 supplies the per-entity compaction point at which rows can be omitted
without a live delete, MemTable mutation, or WAL record.

## Decision

Prune only during L0-to-L1 compaction, and only when a newer row can replace the
older row for every query allowed by the retention contract:

```text
drop R iff a retained row R' satisfies
  (C1) sysTime(R') > sysTime(R)
  (C2) [validStart(R'), validEnd(R')) contains [validStart(R), validEnd(R))
  (C3) sysTime(R') <= T_gc
```

`T_gc` is a transaction-time floor: the caller guarantees that live queries use
`txTime >= T_gc`. C3 ensures R' is visible to every such query, C2 ensures it
covers the requested valid time, and C1 ensures it wins dominance. Queries below
the floor are outside the pruning contract and can lose rows that were present
before compaction.

The input is one entity's composite-key-sorted batch. `mergedRowT.frag` is a
40-byte big-endian key laid out as `hash(16) | sysTime(8) | validStart(8) |
assertTime(8)`. The entity hash is constant within a batch, so the preceding
`sort.SliceStable` orders rows by system time, valid start, and assertion time.
Pruning returns a subsequence in the same order.

Dominance pruning is opt-in. `--compaction-prune-enable` defaults to false and
`--compaction-prune-horizon-ns` defaults to 0. `NewL1Compactor` logs a warning
and restores preserve-all behavior if pruning is enabled without a positive
horizon. `CompactionResult` reports `RowsBefore`, `RowsAfter`, and `RowsPruned`;
`Rows` remains equal to `RowsAfter`. `CompactionRowsPruned` records the number
of omitted rows. The tombstone `EpochCompactor` remains unused.

[ADR-0025](0025_dominance_prune_interval_sweep.md) replaces the original O(N²)
pair scan with a reverse sweep over equal-system-time batches. Its active set
contains newer, floor-admitted survivor intervals. The sweep costs O(N·H), where
H is the active-set size: O(N) for overlapping intervals and O(N²)/2 for disjoint
intervals. It relies on the compaction sort and preserves the reference
implementation's survivor order.

[ADR-0027](0027_t_gc_auto_inference.md) later adds horizon inference. `AsOf`
tracks the highest observed transaction time, and the scheduler computes
`max(operatorFloor, observedFrontier - backoff)`. The node flag
`--compaction-prune-backoff-ns` defaults to 5m. The effective horizon never
moves backward; a refused retreat is logged and counted. Inference does not
enable pruning when `--compaction-prune-enable` is false.

## Consequences

Default compaction remains preserve-all and produces the same L1 bytes as before
this decision. Enabling pruning trades storage below the retention floor for a
strict query contract: callers must not request transaction times below the
floor after older rows have been removed. An inferred horizon is based on
observed queries, not proof about future queries; the operator floor and backoff
must still cover the application's historical-read requirements.

Pruning does not change `AsOf`, issue a tombstone, or add a write-path lock. It
runs inside the existing background compaction job. The reverse sweep removes
the original pair scan's worst-case constant factor but still reaches O(N²)/2
comparisons for disjoint intervals. ADR-0025 records that trade-off and its
measurements.

L0 reclamation is a separate concern completed by
[ADR-0021](0021_l0_reaper.md). That ADR also replaces the overflowing
`MaxValidTime` sentinel and adds instance-level data-directory synchronization;
the package-global constructor race remains disclosed there.

## Evidence

The original acceptance run used `GOMAXPROCS=4` and included:

```text
go build ./...
go vet ./...
GOMAXPROCS=4 go test -race ./internal/database/ ./pkg/durability/
```

The build, vet, formatting, and race checks passed. The behavior is covered by
these regression fixtures:

- `TestLoadBearingTxTimeGapRedThenGreen` checks pure pruning with rows at
  system times 100 and 250. A floor of 200 retains R. A floor of 1000 admits
  the newer row and prunes R. The negative control `pruneNoC3` drops R even
  when its dominator is above the floor.
  `TestCompactionRouteTxTimeGapRedThenGreen` checks the LocalFS route. With a
  floor of 200 the query at transaction time 150 returns R. After pruning at
  floor 1000 the live query at 1000 returns the newer row.
- `TestLoadBearingContainmentRedThenGreen` checks that pure pruning retains R
  when the newer interval is narrower. `pruneNoC2` demonstrates the failure
  without containment. `TestCompactionRouteContainmentRedThenGreen` checks the
  LocalFS route at valid time 10 outside an interval that starts at 200. It
  then checks valid time 500 when the newer interval covers R.
- `TestIdempotencyAndPreserveAllDefault` checks deterministic output, a fixed
  point on repeated pruning, and unchanged input at horizon 0.
- `TestCompactionPreserveAllByteIdenticalDefault` records identical 2210-byte
  L1 files for the default and coerced configurations, with `RowsPruned=0` for
  both. With floor 1000 its three-row fixture prunes two rows and leaves one.
- `TestCompactionLiveQueryEquivalence` uses four rows at increasing system times
  from 100 to 400. Pruning at floor 1000 removes three and retains one. Four
  probes — `(V,txTime)` at `(0,1000)`, `(200,1500)`, `(500,5000)`, and
  `(999,9999999)` — return `(D, sys=400)` for both preserve-all and pruned stores.

ADR-0025 adds `TestEquivDifferentialFuzz`: 10,000 seeded cases compare the
reverse sweep with the O(N²) reference, including survivor order.
`TestEquivRedControlOffByOneFloor` shows that removing C3 causes a detectable
divergence. The seed is 20.

ADR-0027 adds direct inference tests. `TestInferFloor` covers both branches of
the maximum calculation: inference above the operator floor and an operator
floor above the inferred value. `TestInferMonotone` and the LocalFS round trip
check monotonicity and pruning at the inferred horizon.

