# ADR-0026: Arm `telemetry.Init` at boot; deduplicate and rebuild counters

**Status:** Accepted  
**Date:** 2026-08-08

## Context

ADR-0023 separated two read paths for the package-level telemetry counters. The
Prometheus bridge reads cumulative values through `Counter.Value`; OTel
observable callbacks report per-interval deltas using `lastReported`. At that
point `telemetry.Init` had no production caller, so only the bridge operated.

Two construction defects blocked enabling a real Meter. `init()` constructed
`QueryL0ListCapped` twice, leaving its first object orphaned, while
`rebuildCounters()` omitted it entirely. Calling `Init` rebound the other
package-level counters but set `QueryL0ListCapped` to nil. The guarded increment
in `Resolver.AsOf` then stopped reporting capped L0 listings.

Enabling the SDK also exposed two integration requirements. The new direct
imports required `go.opentelemetry.io/otel/sdk` and
`go.opentelemetry.io/otel/sdk/metric` to move from indirect to direct `go.mod`
requirements, both at v1.43.0. No new module version was introduced. Separately,
`resource.Merge` rejects mismatched non-empty schema URLs, so the resource passed
by the node must use the same schema URL as `resource.Default()`:
`https://opentelemetry.io/schemas/1.40.0`.

## Decision

### Reconstruct every counter exactly once per initialization path

Remove the duplicate `QueryL0ListCapped` construction from `init()` and add the
missing construction to `rebuildCounters()`, between `MemTableFlushTotal` and
`OffHeapAllocatedBytes` to match initialization order. The registry slice
continues to list package variables once; no shared-constructor refactor is
needed.

At the time of this decision, construction calls in `init()` fell from 13 to 12
and calls in `rebuildCounters()` rose from 11 to 12. The combined count stayed
at 24 across 12 distinct instruments. The duplicate removal and omitted
reconstruction cancel numerically, but they fix independent defects.

Every later instrument must follow the same rule: construct it in both
initialization paths and include it once in `allCounters()`.

### Arm OTel during node startup

Add `armOTel` in `cmd/sovereign-node/otel.go`. With `--otel=true`, it constructs
a `sdkmetric.MeterProvider` using a `PeriodicReader` over a
`logOutputExporter`, calls `telemetry.Init`, and returns the provider's shutdown
function for graceful exit. The resource has a fixed
`service.name="sovereign-node"` and a `service.instance.id` derived from the
node ID. A resource-merge failure disables OTel export without disabling the
in-process counters, the Prometheus bridge, or the data plane.

`--otel` defaults to false. `--otel-interval` defaults to 60s and controls the
periodic export cadence. The node calls `armOTel` before
`metrics.NewTelemetryBridge`, allowing the bridge to snapshot the rebuilt
counter set. With OTel disabled, the existing nil-Meter behavior and
Prometheus-only export remain in place.

`Init` remains a once-per-process startup operation. A second call leaves the
existing counters in place rather than swapping package pointers while data-plane
writers may be using them.

### Keep export destinations independent

The OTel exporter writes collected batches to the node's log writer. It is not a
`prometheus.Collector` and is never registered with `Exporter.Registry()`.
Counters and observable counters use delta temporality; gauges use last-value
aggregation.

The bridge continues to emit cumulative counters and latest-set gauges through
`Value()` and never touches `lastReported`. OTel callbacks alone advance that
field when calculating deltas. Keeping the destinations separate prevents an
OTel export from being counted again by the Prometheus registry.

## Consequences

`QueryL0ListCapped` remains non-nil after `Init`, and increments after rebuilding
reach the new counter observed by OTel. Tests that use a real Meter run in fresh
subprocesses because the singleton cannot be reset safely within one process.

Enabling OTel makes `lastReported` advance on collection, so zero is no longer a
universal baseline for that field. The narrower bridge invariant is unchanged:
the bridge neither reads nor writes it. Counter increments modify the striped
values, while the callback owns `lastReported` through atomics.

OTel output is opt-in log export, not an OTLP pipeline. The resource name is
fixed rather than region-aware. The exporter formats batches with `fmt.Fprintf`
on the reader's cadence and is not pooled; that work is outside the data plane.

The Prometheus scrape is not allocation-free. The historical measurement at this
decision was 62 allocs/Collect: 12 bridge `Value()` reads and 50 Prometheus
const-metric constructions. Later decisions expanded the registry, so the
construction and allocation figures in this ADR are snapshots rather than
current totals.

[ADR-0027](0027_t_gc_auto_inference.md) later implemented the horizon inference
that this telemetry work enabled. Additional instruments still use the same
two-destination rule and mirrored construction discipline.

## Evidence

The registry and exporter tests in `internal/telemetry/otel_init_test.go` cover:

- `TestQueryL0ListCappedConstructedOnce`, which counts one construction in each
  initialization path;
- `TestCountersDistinctAfterDedup`, which rejects duplicate names;
- `TestDedupFill_Subproc`, which checks that the counter is non-nil after `Init`;
- `TestOmissionFired_Subproc`, which applies two `Add(1)` calls and checks that
  the rebuilt counter advances;
- `TestOtelExport_Subproc`, which increments a counter seven times, collects
  through a separate `ManualReader`, and checks the observed value and advanced
  `lastReported`; and
- `TestLastReportedObservableUnderInit`, which isolates callback-driven changes
  to that field in a subprocess.

The subprocess cases use `SUPREMUM_OTEL_INIT_SUBPROC` to select their entry
point. Their resource uses schema URL 1.40.0, matching the production helper.

`TestArmedBridge` in `pkg/metrics/telemetry_init_armed_test.go` checks that
`armOTel` is the sole production caller of `telemetry.Init` and that the bridge
does not call it. `TestLastReportedUntouchedByBridge` separately preserves the
bridge's field-level independence, and `TestNilOTelSafe` covers operation with
no Meter.

The original acceptance record reports successful build and vet runs, plus
race-enabled tests across `internal/telemetry`, `internal/database`,
`pkg/metrics`, and `pkg/durability`. These tests establish registration,
collection, and concurrency behavior; they are not evidence of a sustained
production OTLP deployment.
