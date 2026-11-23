# ADR-0027: Infer the GC floor from the observed live-query frontier

**Status:** Accepted  
**Date:** 2026-08-08

## Context

ADR-0020 made `CompactionConfig.PruningHorizonInt64Ns` a static transaction-time
retention floor. Dominance pruning drops a row only when a newer,
interval-containing row is at or below that floor. Setting the floor too low
allows pruning that the operator did not intend; setting it too high retains
history the workload has moved past.

Every `Resolver.AsOf` call already carries the transaction time being served,
but that observation did not reach the compactor. The operator therefore had to
estimate the live-query frontier when configuring the floor. ADR-0025 retained
automatic inference as follow-up work, and ADR-0026 supplied the telemetry
initialization needed to expose it.

The inference must not lower a horizon after rows have been dropped at a higher
one. Such a retreat would make previously removed rows necessary again for
historical reads. It also must not enable pruning: the default remains
preserve-all unless the operator explicitly enables it with a positive floor.

## Decision

### Observe a monotone query frontier

Add the package-private `pruningFrontierObserved int64` field to `Resolver`.
After computing `transactionTime.UnixNano()`, `AsOf` calls
`observeQueryTxTime`, which implements an atomic maximum with a load and
compare-and-swap loop. `QueryTxTimeFrontier` returns the atomic value.

The observation occurs before storage listing, so it advances even when the
query later returns `ErrEntityNotFound`. A lower historical query cannot reduce
the maximum. The stored value is an integer number of nanoseconds, not a
`time.Time`, and a no-advance observation performs no allocation.

The frontier describes queries already observed on this resolver. It is not a
proof about future queries; the configured floor and backoff remain the
operator's retention controls.

### Derive and clamp the effective horizon

Give `L1Compactor` an immutable `horizonInferrer` containing the operator floor
and `CompactionConfig.PruneBackoffInt64Ns`, both captured by `NewL1Compactor`.
`EffectiveHorizon` computes:

```text
max(operatorFloor, observedFrontier - backoff)
```

The operator floor is not a per-call argument. Tests that need a different floor
construct another compactor.

`SetInferredHorizon` advances `PruningHorizonInt64Ns` only when the candidate is
strictly greater than the current value. A lower candidate leaves the horizon
unchanged, increments `PruningHorizonRetreatRefused`, and writes a warning.
`InferHorizon` reads the resolver frontier, computes and applies the effective
horizon, and updates the two gauges described below. A nil resolver leaves the
configuration unchanged.

The scheduler calls `InferHorizon(resolver)` before per-entity
`CompactionByHash8`. The setter and compaction run on the scheduler goroutine
between sweeps; concurrent calls with compaction are not supported.

The node exposes `--compaction-prune-backoff-ns` as a duration with a default of
5m. `DefaultCompactionConfig` itself leaves the backoff at zero, while the node
wires its flag into `PruneBackoffInt64Ns`.

When pruning is disabled, inference may still advance the stored horizon and
its gauges, but the pruning call is skipped and no rows are dropped. A node
without a query resolver retains its configured static floor.

### Expose the inference state

Add three instruments to both counter initialization paths and to
`allCounters()`:

- `QueryTxTimeHighWaterMark`, a gauge containing the raw observed frontier;
- `PruningHorizonEffective`, a gauge containing the horizon applied by the
  compactor; and
- `PruningHorizonRetreatRefused`, a cumulative counter for rejected retreats.

The Prometheus bridge enumerates `telemetry.Counters()`, so these instruments
need no bridge-specific cases. Counters and gauges are exported according to
their existing modes, and OTel observes them through the same registration
path as the earlier instruments.

At the time of this decision, the registry grew from 12 to 15 instruments: from
one to three gauges and from 11 to 12 counters. Subsequent decisions added more
instruments; those earlier totals are not the current registry size.

## Consequences

The horizon calculation and pruning configuration remain `int64`. Telemetry
conversion to `float64` affects only the exported gauge values: integers above
2^53 can be rounded in a scrape even though the horizon used by compaction is
unchanged.

The backoff is not inferred or auto-tuned. A workload that queries farther into
the past needs an appropriate floor and backoff; the observed maximum alone
cannot establish that no older query will arrive. Conversely, a workload with no
historical reads can choose a smaller backoff or a higher floor.

Later mesh instrumentation added direct counter reads to
`cmd/sovereign-node/main.go`. That does not add another `telemetry.Init` caller:
`armOTel` remains the only initialization call site, and the bridge still
receives its counters after that call.

The test helper `scrapeCounterValue`, defined in
`pkg/metrics/telemetry_bridge_test.go`, does not parse exponent notation.
Prometheus renders sufficiently large gauge values in that form, so the bridge
test uses small integers. This is a limitation of the test parser, not of the
production Prometheus encoder or of OTel collection, which walks
`metricdata.ResourceMetrics` directly.

## Evidence

The inference tests are divided by the APIs they exercise:

- `TestInferAsOfObserves` checks increasing and historical query times on an
  empty store. `TestInferAsOfObservesConcurrentRace` drives 3,200 concurrent
  calls under `-race` and checks that the frontier equals their global maximum.
- `TestInferMonotone` applies candidates `[100, 500, 200, 800, 300]` and expects
  `[100, 500, 500, 800, 800]`, with two retreat refusals.
  `TestInferMonotoneRedControlNoClamp` demonstrates the backward step that the
  clamp rejects.
- `TestInferFloor` checks an observed frontier of 5000 with backoff 500: the
  result is 4500 at operator floors 1000 and 100, and 6000 at an operator floor
  of 6000. `TestInferFloorRedControlIgnoreOperatorFloor` covers the unsafe
  formula without the maximum.
- `TestInferRetreatCounterLoud` checks the warning and counter increment, while
  `TestInferRetreatCounterGreen` checks that an advancing sequence does not
  increment the counter.

`TestInferEquiv` runs 10,000 seeded cases with seed 22. It supplies the same
inferred horizon to the reference and sweep, so it checks pruning equivalence at
that horizon but cannot detect incorrect inference arithmetic. The floor tests
check the arithmetic directly, and the filesystem round trip below checks its
effect on pruning.

`TestInferAlloc` compares two `testing.AllocsPerRun` measurements of the same
warmed, no-advance `AsOf` path. The historical result was 2 allocs/op in both
runs, a delta of zero. Because both runs include observation, this demonstrates
allocation stability on that path rather than isolating the cost of adding it;
the two allocations belong to the empty-store read path, not the write-path
zero-allocation contract.

`TestInferCountersInRegistry` checks registry membership and unique names.
`TestInferCountersNonNilPostInit_Subproc` checks all three instruments after
`Init` and their presence in OTel output. `TestBridgeAutoSurfacesNewCounters`
checks HELP, TYPE, and value lines through a real Prometheus scrape. Its small
integer samples avoid the test parser's exponent limitation.

The end-to-end evidence is in `pkg/durability/tgc_infer_test.go`:

- `TestGCFloorInferRealLocalFS` writes rows at system times 100 and 250, then
  observes a query at transaction time 2000. It uses floor 100 with backoff 400.
  The effective horizon becomes 1600 and the older row is pruned; the same live
  query still returns the row at system time 250.
- `TestGCFloorInferRealLocalFSNoOpControl` never advances the frontier. The
  horizon stays at 100, below the dominator at 250, and both rows survive.

The original acceptance record reports successful build, vet, and targeted
race-enabled runs across the affected database, durability, telemetry, metrics,
and command packages. The measured values above are fixtures and historical test
results, not a production retention policy recommendation.
