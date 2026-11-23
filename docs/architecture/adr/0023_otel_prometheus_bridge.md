# ADR-0023: Bridge internal telemetry to Prometheus

**Status:** Accepted
**Date:** 2026-08-04

## Context

The storage data plane calls `Add` and `Inc` on `internal/telemetry`
LongAdders during flushes, compaction, pruning, and reaping, but none of those
values reached `/metrics`. A Prometheus scrape therefore omitted the entire
flush, compaction, and reaper surface. In particular, it could not reveal
`supremum_compaction_l0_reap_manifests_skipped_orphan`, which records that the
reaper preserved a manifest because its target L1 object was missing. The
reaper logged that decision, but a monitoring system could not alert on it.
The recovery behavior itself is described in [ADR-0021](0021_l0_reaper.md).

The observability gap had two layers. The counters worked in process, but OTel
had no registered observable instruments and Prometheus had no collector for
them. Adding only an OTel provider would not populate the existing Prometheus
registry; adding only a Prometheus exporter that depended on OTel callbacks
would leave the default startup path silent.

The existing metrics `Exporter` already owned a per-process
`prometheus.Registry` and its `/metrics` handler. That registry held the
Recorder's `sovereign_*` instruments, while the telemetry counters remained
in-process only. Using the same registry adds the telemetry series without
reviving the duplicate-registration problem that [ADR-0008](0008_prometheus_metrics.md)
resolved by avoiding the global registerer.

At the time of this decision, `telemetry.Init` had no callers in production or
tests, and `cmd/sovereign-node/main.go` did not import `internal/telemetry`.
During package initialization, no meter provider had been stored, so the local
`metric.Meter` remained nil and `init` constructed the registry directly rather
than calling `rebuildCounters`. `newCounter` still returned a working
LongAdder, but `register` returned immediately for the nil meter. No OTel
observable was created, its callback never ran, and `lastReported` remained
zero. `Add`, `Inc`, and `Value` worked in process, yet neither OTel nor
Prometheus exported the result.

The bridge had to close the Prometheus gap without requiring an OTel provider.
It also had to remain correct if a provider was bound later.

The two export paths require different temporality. The OTel integer-counter
callback reads the current total, subtracts the previous total, reports that
per-interval delta, and advances `lastReported` with a compare-and-swap:

```go
delta := now - int64(prev)
lastReported.CompareAndSwap(prev, uint64(now))
```

A Prometheus counter instead carries its cumulative value and leaves rate
calculation to the Prometheus server. The bridge must therefore read
`Counter.Value()` and must not pre-delta it. If the bridge used or advanced
`lastReported`, an OTel callback between scrapes could change the next
Prometheus value or corrupt the following OTel delta. Reading only the
cumulative value keeps the two paths independent whether OTel is absent or a
provider is bound later.

### Registry contents at the time

The initial design counted 24 telemetry counters. Reading the registry showed
that this was the number of construction calls, not the number of instruments.
The original registry contained 24 `newCounter` invocations but only 12
distinct package variables: 11 counters and 1 gauge. `init()` made 13 calls,
including two identical constructions of `QueryL0ListCapped`; the second left
the first object unreachable. `rebuildCounters()` made 11 calls and omitted
`QueryL0ListCapped` entirely. Sorting the unique metric-name literals confirmed
that the 12 variables mapped one-to-one to 12 distinct telemetry names. The
bridge therefore exposes 12 series, not 24.

The omission meant that binding a meter could leave `QueryL0ListCapped` nil.
The guarded query use would then silently stop counting capped query lists.
The duplicate construction ruled out the apparent shortcut of appending to a
registry slice inside `newCounter`: the same
`supremum.l0.query_list_capped` name would appear twice, and
`Registry.MustRegister` would reject the duplicate descriptor and panic during
startup. Enumeration therefore had to use the distinct package variables
rather than the construction calls.

## Decision

### Enumerate the registry once

Add `allCounters()` to return the distinct package variables in stable order.
Both `init()` and `rebuildCounters()` populate the package pointers and then
store that list in `counters`. This keeps one enumeration for package
initialization and meter binding without recording intermediate constructions.

The alternative, appending each new counter as it is constructed, would copy
the duplicate `QueryL0ListCapped` construction into the slice. Building the
slice after construction makes that duplicate unreachable and guarantees one
entry per distinct variable. `TestCountersNoDuplicateNames` guards against a
return to the append-during-construction design.

`NewTelemetryBridge` snapshots `telemetry.Counters()` once per process, after
`NewExporter` and before `startLivecheck` begins serving scrapes. Both registry
construction paths finish behind that startup barrier, so the bridge reads its
snapshot without a lock. There is no append during construction for a
`countersMu` to protect. A counter subsequently added to `allCounters()`
appears in the bridge without a second bridge-specific list.

Expose the immutable counter metadata through `Name`, `Description`, `Unit`, and
`Mode`. The existing `Value` method remains the only value accessor.
`lastReported` remains unexported, and no `Delta` or `Reset` accessor is added;
either would invite a caller to pre-delta the Prometheus value.

`Mode` returns the unexported `counterMode` type, so another package cannot
compare its result with the unexported `modeCounter` and `modeGauge` constants.
Export the existing type under an alias and provide exported constants:

```go
type CounterMode = counterMode
const (
    ModeCounter counterMode = modeCounter
    ModeGauge   counterMode = modeGauge
)
```

The alias preserves `func (c *Counter) Mode() counterMode` and avoids renaming
the mode constants at the 24 registry construction sites. Only the bridge uses
`telemetry.ModeCounter` and `telemetry.ModeGauge`.


### Preserve cumulative values

`Collect` reads `Counter.Value()` for every entry. For a counter, this sums the
64 LongAdder stripes; for a gauge, it returns the latest `Set` value. It passes
that value to Prometheus without consulting `lastReported`. This keeps scrape
results independent of whether an OTel callback has run.

### Project onto the existing Prometheus registry

`TelemetryBridge` implements `prometheus.Collector`. Dots in telemetry names
become underscores, producing `supremum_*` series that coexist with the
Recorder's `sovereign_*` series. The instruments have no labels.

Descriptors are built once by `NewTelemetryBridge` and reused by `Describe` and
`Collect`. The installed `github.com/prometheus/client_golang v1.23.2` provides
`MustNewConstMetric` and `NewConstMetric`, plus constructors for histograms,
summaries, and metrics with created timestamps. It does not provide the
initially assumed `MustNewConstCounter` or `MustNewConstGauge` names. The
`ValueType` argument performs that dispatch instead:

```go
prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value)
prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value)
```

`CounterValue` emits a cumulative counter and `GaugeValue` emits the latest set
value. Both calls pass no label values, matching the descriptors' nil label
lists; otherwise the constructor would panic on label arity. These are
singleton instruments without dimensions. At the decision date,
`OffHeapAllocatedBytes` was the sole gauge and the other 11 instruments were
counters.


### Keep OTel independent

[ADR-0026](0026_otel_init_dedup_query_list_capped.md) later supplied the OTel
startup path anticipated here. `--otel` is off by default. When enabled,
`armOTel` calls `telemetry.Init` once, before `NewTelemetryBridge`, so the
bridge snapshots the rebuilt counters. The OTel `PeriodicReader` exports deltas
through `logOutputExporter`, not through the Prometheus registry.

That later decision also removed the duplicate `QueryL0ListCapped` construction
and added the missing rebuild. The bridge itself never calls `telemetry.Init`;
with OTel disabled it continues to export the package-initialized counters.

## Consequences

The decision-time bridge exposes 12 telemetry series, one for each distinct
package variable, rather than 24 construction sites. New entries in
`allCounters()` appear on `/metrics` without changes to `TelemetryBridge`.
Each descriptor is unique within the per-process registry. The `supremum_*`
and `sovereign_*` namespaces remain distinct, and constructing another
`Exporter` does not register instruments globally.

### Open items at the decision date

The duplicate `QueryL0ListCapped` construction and its omission from
`rebuildCounters` remain outside this change. The first object created by
`init` becomes unreachable when the variable is reassigned. That is harmless
startup garbage for this bridge, but it is exactly the object that an
append-in-`newCounter` registry would expose as a duplicate descriptor.

Binding a real OTel meter without first correcting `rebuildCounters` would set
`QueryL0ListCapped` to nil. The query guard would then silently stop counting
capped lists. A future OTel change must add that counter to the rebuild and
remove the duplicate initialization before arming the callback. This decision
closes the Prometheus egress only; it deliberately leaves `telemetry.Init`
uncalled and wires no OTel exporter. The bridge is the sole direct importer of
`internal/telemetry` from the node command's dependency path.

### Collection allocations

Descriptor reuse does not make collection allocation-free. With the original
12 instruments, `testing.AllocsPerRun(100, ...)` measured 62 allocations per
collection. The measurement decomposes into 12 allocations from the bridge's
`Value()` reads and 50 from `prometheus.MustNewConstMetric` across those
instruments.

Each counter read decodes and sums the 64 LongAdder stripes, and boxing its
`float64` result across the method boundary accounts for one allocation per
instrument. The const-metric constructor accounts for the boxed value,
`*dto.Metric`, label-pair storage, and delivery through the channel. These
allocations occur off the data plane at the default 15s scrape cadence.

The zero-allocation target is therefore unmet. The structural property the
bridge can guarantee is narrower: descriptors are built once and their map is
not changed by collection. Reaching zero allocations would require a custom
`prometheus.Metric` implementation and reusable `*dto.Metric` storage rather
than the const-metric constructors. That work is outside this decision.

`telemetry.Init` remains a startup operation, not a reconfiguration API. Once
an OTel meter is active, `lastReported` can be nonzero; that remains the
callback's state and does not alter the bridge's cumulative read path.

## Evidence

The contract guards use real Prometheus registration and HTTP scrapes where
the behavior crosses the package boundary. The assertions below describe the
implementation at the decision date.

| Guard | Race coverage | Property checked |
|---|---|---|
| `T1` — `TestRealScrapeCumulativeNotDelta` | `-race` | An `httptest` scrape surfaces every `supremum_*` series with help, type, and value lines. `supremum_memtable_flush_total` advances from 0 to 7 across two scrapes; a delta-reporting bridge would show the increment once and then reset. |
| `T1b` — `TestSafetyCriticalOrphanSignal` | `-race` | An increment to `L0ReapSkippedOrphan` becomes visible at `/metrics`, including the descriptor for the preserved-manifest signal. |
| `T2` — `TestTelemetryCounterEnumeration` and `TestCountersNoDuplicateNames` | `-race` | The bridge retains the exact `telemetry.Counters()` snapshot by identity and emits one descriptor per entry. The in-package assertion expects 12 distinct names with no duplicates: 11 counters and 1 gauge. |
| `T3` — `TestZeroAllocCollect` | `-race` | Descriptors remain unchanged across collections. `testing.AllocsPerRun(100, Collect)` reports 62 allocations rather than skipping const-metric construction to claim zero. |
| `T4` — `TestDoubleCountTrapGuard` and `TestLastReportedUntouchedByBridge` | `-race` | After 11 increments, the scraped pruning counter equals `Counter.Value()`. In the telemetry package, 13 increments leave `lastReported` at zero while the cumulative value advances. OTel-driving tests use separate processes so they do not disturb this baseline. |
| `T5` — `TestNilOTelSafe` | `-race` | The bridge exports package-initialized counters without calling `telemetry.Init`; two increments to `CompactionMerged` produce a nonzero scrape value. |
| `T6` — source and scope checks | `-race` | The change touches none of the five core CRDT and wire-schema files, and `telemetry.Init` retains zero production callers. |

The focused race-enabled run is:

```bash
go test -race ./pkg/metrics ./internal/telemetry \
  -run 'Test(RealScrapeCumulativeNotDelta|SafetyCriticalOrphanSignal|TelemetryCounterEnumeration|ZeroAllocCollect|DoubleCountTrapGuard|NilOTelSafe|LastReportedUntouchedByBridge|CountersNoDuplicateNames)$' \
  -count=1 -v
```

### Limits of the evidence

The scrape tests establish that the bridge exports the counters correctly.
They do not create a missing L1 object, drive a reaper orphan through
`*LocalFS`, and scrape the resulting signal end to end.
[ADR-0021](0021_l0_reaper.md) covers the reaper's filesystem behavior
separately. This decision proves that the egress carries the signal, not that
the bridge exercises the reaper itself.

The original 62-allocation measurement, the 12-instrument registry, and the
historical `T2` assertion describe the implementation at the date of this
decision. They are retained as historical evidence, not presented as later
registry totals or a promise of allocation-free scrapes. The initial 24-counter
count and the assumed constructor names were both corrected by reading the
source and installed dependency before implementation.


