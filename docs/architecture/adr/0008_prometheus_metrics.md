# ADR-0008: Prometheus metrics and ingest-latency histograms

**Status:** Accepted  
**Date:** 2026-07-28

## Context

The transport and two-node mesh established by
[ADR-0006](0006_tls13_transport_default_tier.md) and
[ADR-0007](0007_real_socket_mesh.md) exposed no scrape endpoint. An operator
could not read ingest latency, admission outcomes, verification cost, gossip
rounds, or convergence lag from a running node. The partition-heal work in
[ADR-0009](0009_chaos_partition_probe.md) needed those measurements.

The instrumentation also had to preserve the receive implementation and make
its own cost measurable. Early admission rejects return before signature
verification, while accepted origin frames pay for verification and CRDT
application, so a single average would hide two different latency populations.

## Decision

Add `pkg/metrics` with a `Recorder` for frame observations and an `Exporter`
that owns a `prometheus.NewRegistry`. A fresh registry per exporter prevents
duplicate registration when several instances coexist in one process and keeps
these instruments independent of the OpenTelemetry initialization path.

Observe `HandleFrame` from its caller rather than adding a metrics field to
`Receiver` or changing `NewReceiver`:

```text
start := time.Now()
verdict := receiver.HandleFrame(frame)
recorder.RecordIngest(time.Since(start), verdict.Verdict)
```

The typed receive verdict already identifies the admission outcome. Cache the
six resulting `prometheus.Counter` handles during construction so each frame
increments a counter directly instead of repeating a label lookup.

The caller-side observer was chosen over injecting a `*metrics.Recorder` into
`Receiver` and `NewReceiver`. The verdict enum carries the complete per-gate
result, so injection would change the receive API without adding information.
Each connection goroutine handles one frame at a time, and the fixed six-value
verdict set bounds metric cardinality.

Serve `Exporter.Handler` at `127.0.0.1:7431/metrics` by default on the existing
plain-HTTP operational listener. A one-second poller updates the ingest-rate
and convergence gauges outside frame processing.

This decision introduces seven `sovereign_*` metric families:

| Series | Type | Source |
|---|---|---|
| `sovereign_ingest_latency_seconds` | Histogram | `RecordIngest` |
| `sovereign_verify_seconds` | Histogram | `RecordVerify` |
| `sovereign_ingest_verdicts_total` | Counter vector | Six receive verdict labels |
| `sovereign_ingest_pps` | Gauge | Verdict-counter delta from the poller |
| `sovereign_convergence_lag_seconds` | Gauge | `Gossiper.ConvergenceLag` |
| `sovereign_gossip_rounds_total` | Counter | `Recorder.IncGossipRound` |
| `sovereign_convergence_roots_equal` | Gauge | Current and last-converged roots |

The ingest histogram buckets, in seconds, are `[1e-7, 2e-7, 5e-7, 1e-6, 2e-6,
5e-6, 1e-5, 5e-5, 1e-4]`. The lower buckets retain early-rejection samples;
the upper buckets retain frames that reach signature verification. An accepted
origin frame with no relay hops performs one origin verification. A relay hop
adds another verification and can move that sample above the `1e-4` bucket.

## Consequences

The histogram distinguishes cheap rejects from verified frames; it does not
establish a workload-independent p99. The approximately 60us unbatched
verification cost recorded in [ADR-0007](0007_real_socket_mesh.md) belongs to
accepted single-delta frames. At 32 cores it implies roughly 533K
frames per second before batching. This receive-path estimate is distinct from
the 57.6M ops/s in-memory HAMT arena benchmark, which performs no cryptography.
Counter contention at the verify-bound receive rate is therefore a different
problem from contention on the arena path. Batched envelopes later amortize
verification across deltas.

Early rejection samples in the `le="1e-06"` bucket and accepted origin-only
samples around 60us occupy different buckets. This makes the cost of passing
verification visible instead of allowing the numerous cheap rejects to hide it
in an average or a sub-microsecond latency claim. A relay hop adds verification
work and falls outside the single-verify bucket population.

`RecordVerify` and `sovereign_verify_seconds` remain available, but v0.2.0 has
no production caller of `RecordVerify`; its cost is benchmarked rather than
continuously recorded by the node. The seven families above are the families
introduced by this decision, not the whole current scrape. The node also
registers telemetry-bridge series and optional secondary-index gauges.

`/metrics` is unauthenticated plain HTTP on the operational listener. It is not
served on the peer TLS listener and should not be exposed on a public interface.
The Prometheus registry is separate from the OpenTelemetry meter initialization,
and `promhttp.HandlerFor` does not take a receive-path lock. The one-second
convergence poller also runs outside frame processing; a scrape concurrent with
a 100k-frame burst was not a high-core acceptance measurement.

At acceptance, `sovereign_convergence_roots_equal` was a two-node binary
indicator, with a three-node quorum-aware gauge left for later work. The mesh
used a 100ms default gossip tick and a 50ms partition-probe override; the lag
gauge reads `ConvergenceLag` and is independent of that tick.

The four-core recorder results were not relabeled as high-core measurements. A
96-vCPU contention run associated with the later at-least-1M-syncs/sec target was
deferred, as was a 24-hour scrape-stationarity and leak soak. Those runs did not
accompany the original decision.

## Evidence

Four benchmarks on the 4-core development box isolated recorder overhead:

| Benchmark | Result | Allocations |
|---|---:|---:|
| `BenchmarkRecordIngest-4` | 46.2 ns/op | 0 allocs/op |
| `BenchmarkHistogramObserve-4` | 40.9 ns/op | 0 allocs/op |
| `BenchmarkVerdictCounterInc-4` | 7.6 ns/op | 0 allocs/op |
| `BenchmarkRecordVerify-4` | 40.7 ns/op | 0 allocs/op |

The 46.2 ns/op result exceeded the 5ns recorder budget. Histogram observation
contributed 40.9 ns/op, or 88% of `RecordIngest`; the cached counter increment
contributed 7.6 ns/op. Replacing that increment with a sharded LongAdder was
estimated to cost approximately 2–3ns and reduce the total only to
approximately 42ns. It could not meet the 5ns budget while the histogram's
bucket search, atomic updates, and floating-point conversion remained around
40ns. The measured 46 ns against a 60000ns verification interval is
approximately 0.08% of the single-verify frame cost.

That analysis justified direct Prometheus instruments and cached verdict
counters instead of the LongAdder fallback: at the verify-bound receive rate,
changing the counter implementation would not remove the histogram cost.
Caching the six counter handles also removed a label lookup that cost
approximately 60ns of the uncached 102ns/op path. These are local
microbenchmarks, not network-throughput results.

`TestExportersRegister` constructs three independent exporters and scrapes each
one. `TestSevenSeriesScrapeable` checks `HELP` and `TYPE` metadata for every
family introduced here.

`TestIngestLatencyRecorded` drives 100k frames through `HandleFrame` and the
recorder: approximately 200 valid origin-only signed frames and ~99.8k
malformed frames. It requires the full sample count and nonzero verify-path and
early-rejection buckets. In an ordinary run those buckets are `le="0.0001"`
and `le="1e-06"`; under the race detector a wider early-rejection bucket allows
for instrumentation overhead.

`TestConvergenceLagRecorded` in `pkg/mesh` checks that two stable root stamps
establish convergence and that the lag subsequently grows. The original
acceptance also included a live-binary `/metrics` scrape.
