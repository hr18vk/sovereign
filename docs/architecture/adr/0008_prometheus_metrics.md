# ADR-0008: Prometheus /metrics + SLO p99 histograms — making the engine observable in production

- **Status:** ACCEPTED (2026-07-28) — in-process acceptance gates pass on the 4-core development box; the overall ship verdict is unchanged (still conditional).
- **Predecessor:** ADR-0007 (the real-socket two-node mesh).
- **What this adds:** the first observability surface — a production operator can scrape a live `/metrics` endpoint and read the real ingest p99, the per-gate reject rate, the verify cost, and the mesh convergence lag.
- **Enforced by:** `TestExportersRegister`, `TestSevenSeriesScrapeable`, `TestIngestLatencyRecorded` (the bimodality tooth), `TestConvergenceLagRecorded`, `BenchmarkRecordIngest` (the FACT-1 settle bench), a live-binary `curl /metrics` seven-series grep, and a pre/post check that the files that must not move are unchanged.

---

## 1. Context

ADR-0006 gave the engine its first encrypted pipe and binary; ADR-0007 gave it a real-socket two-node mesh with signed-envelope gossip. Both shipped a working engine with **zero observability**: an operator could not scrape a live endpoint and read the real ingest latency, the per-gate reject rate, the verify cost, or the mesh convergence lag. The partition-heal probe (the <100ms heal SLO) that comes next is unreadable without a `/metrics` gauge. This change ships the observability surface that probe depends on.

It is the first point at which the claim "the engine has zero observability" advances to "a production operator can scrape `/metrics` and read the real ingest p99 / reject rate / verify cost / convergence lag".

---

## 2. Decision

The observability surface is a new package `pkg/metrics/` (the Recorder + the per-process Exporter) riding the existing plain-HTTP control surface (the same mux as `/livecheck` — one server, one mux, the `--metrics-addr` flag already binds it). The hot path is observed from the caller (Option B — the observer wrapper), not from inside the gate stack.

```
SCRAPE (ops, off the data plane):
  curl 127.0.0.1:7431/metrics
    -> promhttp.HandlerFor(per-process Registry)        // exporter.go Handler()
    -> the seven sovereign_* series (HELP + TYPE)

HOT PATH (the accept loop, Option B observer):
  start := time.Now()
  av := recv.HandleFrame(frame)                         // receiver.go:253 (UNTOUCHED)
  recorder.RecordIngest(time.Since(start), av.Verdict)  // recorder.go RecordIngest (wait-free)

CONVERGENCE GAUGE (off the hot path, 1s poller):
  gossiper.ConvergenceLag() -> exporter.SetConvergenceLag
  gossiper.CurrentRoot() == gossiper.LastConvergedRoot() -> exporter.SetConvergenceRootsEqual
  exporter.ObserveVerdictDelta(now) -> exporter.SetIngestPPS
```

The seven `sovereign_*` series:

| # | Series | Type | Feeder |
|---|--------|------|--------|
| 1 | `sovereign_ingest_latency_seconds` | Histogram | hot-path RecordIngest (bimodal) |
| 2 | `sovereign_verify_seconds` | Histogram | verify-path RecordVerify |
| 3 | `sovereign_ingest_verdicts_total` | CounterVec{verdict} | hot-path RecordIngest (6 labels) |
| 4 | `sovereign_ingest_pps` | Gauge | 1s poller (verdict-counter delta) |
| 5 | `sovereign_convergence_lag_seconds` | Gauge | 1s poller (gossiper.ConvergenceLag) |
| 6 | `sovereign_gossip_rounds_total` | Counter | Recorder.IncGossipRound |
| 7 | `sovereign_convergence_roots_equal` | Gauge | 1s poller (current vs last-converged root) |

---

## 3. The §0 invariant, the per-process Registry root cause, and the FACT-1 bench verdict

### 3.1 The scrape-reads-hot-path / hot-path-never-blocks invariant (§0)

Two physical facts shape this work:

**FACT 1 — the receive frame rate is verify-bound, not arena-bound.** The 57.6M ops/s number is the in-memory HAMT arena path (no crypto). The network receive path is bounded by ~60us/verify/core ≈ ~533K frames/sec at 32c. At ~533K frames/sec the hot-path counter contention is low (not 57M contention). Whether a single Prometheus atomic counter per frame suffices, or a sharded LongAdder is required, is a measurement question — so I measured it (`BenchmarkRecordIngest`) and picked the winner.

**FACT 2 — the latency histogram is bimodal, and the bimodality is the tooth.** Frames rejected at the cheap gates (DropMalformed/DropRate/DropClock/DropDepth) return in nanoseconds (sub-1us); frames that pass to Verify+Apply return in ~60us. The histogram with buckets `[1e-7, 2e-7, 5e-7, 1e-6, 2e-6, 5e-6, 1e-5, 5e-5, 1e-4]` (seconds) shows two populations: the sub-1us cheap-gate-reject population lands in `le=1e-06`; the ~60us verify-pass population lands in `le=0.0001`. The p99 is ~60us (verify-bound) on the single-delta path — not sub-1us. A claim of "sub-1us p99 ingest" would be fabricated at this single-delta tier; batched deltas (one verify per N deltas) are the arithmetic unlock for sub-1us-per-delta amortized.

These two facts are non-negotiable: the gate is falsifiability (the bucket exists and is read by a scraper) plus honest measurement (p99 lands where physics puts it: ~60us verify-bound on the single-delta path). A fabricated "sub-1us ingest" is the catastrophic failure mode.

### 3.2 The per-process Registry root cause (the duplicate-registration fix)

The Exporter constructs a **per-process `prometheus.Registry`** (`prometheus.NewRegistry()`), not the global `prometheus.DefaultRegisterer`. Root cause: the global registerer panics on duplicate registration across tests (two Recorder instances registering the same `sovereign_*` instrument names) — `MustRegister` on the global is a process-wide singleton that cannot tolerate two constructors. The per-process Registry gives each process (and each test) its own registry, so `TestExportersRegister` constructs three Exporters with no panic. The per-process Registry is independent of `internal/telemetry`'s OTel Init path (`registry.go` Init binds a meter, not the prometheus DefaultRegisterer); the two coexist.

### 3.3 The FACT-1 bench verdict (the recorder-overhead measurement)

`BenchmarkRecordIngest` measured the per-frame `Recorder.RecordIngest` overhead on the 4-core development box:

```
BenchmarkRecordIngest-4         46.2 ns/op    0 allocs/op   (the full hot-path seam)
BenchmarkHistogramObserve-4     40.9 ns/op    0 allocs/op   (the histogram Observe — bucket search + atomic sum/count)
BenchmarkVerdictCounterInc-4     7.6 ns/op    0 allocs/op   (the cached per-verdict counter Inc — a single atomic add)
BenchmarkRecordVerify-4         40.7 ns/op    0 allocs/op   (the verify-path seam)
```

**Verdict: 46.2 ns/op, above the 5ns budget.** The overhead is dominated by the histogram Observe (40.9ns, 88% of the total), not counter contention (7.6ns). The `internal/telemetry` LongAdder fallback would replace the 7.6ns counter Inc with a ~2-3ns sharded add — saving ~5ns, landing at ~42ns. It cannot reach the 5ns budget because the histogram Observe is the immovable floor (a bucket binary search + two atomic adds + a float64 conversion is inherently ~40ns; no counter optimization moves it).

**The LongAdder fallback does not fire.** It is designed for high-contention scenarios (the 57M ops/s arena path, where a single atomic counter would HITM-storm at 32c). At the verify-bound ~533K frames/sec receive rate, the single atomic counter (7.6ns, uncontended) suffices — there is no contention bottleneck to fix. The bench decided this; the prose did not pre-assert it. The counter is not the bottleneck, the histogram is the floor, and the LongAdder would not move the floor. Prometheus-direct is the verdict — with the six verdict counters pre-resolved at construction (a `WithLabelValues` map lookup on every call was ~60ns of the uncached 102ns/op, eliminated by caching the six `prometheus.Counter` values and indexing by the typed Verdict int).

The 5ns budget is not achievable with a prometheus histogram on the hot path. The honest number is **46.2 ns/op** (4-core development box). I record it verbatim and do not relabel it as a higher-core-count number. The recorder overhead is ~0.08% of the ~60us verify-bound frame cost (46ns / 60000ns) — negligible against the verify floor, which is the actual receive-rate bound.

### 3.4 The Option A vs Option B verdict

**Option B (the observer wrapper) — chosen.** The cleanest architecture keeps `receiver.go` untouched (its bytes are unchanged) by observing `HandleFrame` from the caller (the accept loop's per-conn goroutine): `start := time.Now(); av := recv.HandleFrame(frame); recorder.RecordIngest(time.Since(start), av.Verdict)`. The Verdict enum (receiver.go:81, six values) already encodes which gate rejected, so the wrapper captures 100% of the per-gate signal. The per-conn goroutine is uncontended (one frame at a time per conn), so the Recorder's atomic Observe/Inc is wait-free here. The Verdict label set is fixed at 6 (bounded cardinality; no label explosion).

**Option A (inject the Recorder into the Receiver) — rejected.** Injecting a `*metrics.Recorder` field into the Receiver struct + `NewReceiver` constructor would change receiver.go's bytes. That file is editable (it is not one of the core merge-law/wire-schema files), but Option B captures the full signal at the caller with zero bytes changed — a cleaner outcome. Option A remains the fallback only if Option B proved insufficient; it did not (the Verdict enum carries the full per-gate signal, and the bench shows the wrapper overhead is negligible against the verify floor).

---

## 4. The bimodality tooth

`TestIngestLatencyRecorded` drives 100k HandleFrame calls through the Recorder with a mix: ~99.8k forged cheap-gate-reject frames (garbage bytes → DropMalformed, sub-1us) + ~200 honest verify-pass frames (0-hop signed origin → Accept, a single ~60us Ed25519 VerifyCRDTFrame). It scrapes /metrics and asserts: histogram `_count` >= 100k AND the `le=1e-06` bucket has samples (the cheap-reject population) AND the `le=0.0001` bucket has samples (the verify-pass population).

The honest frames are **0-hop** (origin-only, no relay chain): a 0-hop frame skips the rate gate, uses the local clock for the clock gate, runs Open with zero outer relay verifies, then does exactly one VerifyCRDTFrame (~60us) — the single-verify cost FACT 2 names. A 1-hop frame would do two verifies (Open's relay verify + VerifyCRDTFrame's origin verify ≈120us) and land above the 1e-4 (100us) bucket in +Inf, hiding the verify-pass population from the `le=1e-4` assertion. The 0-hop shape matches the single-verify regime the bucket set was designed for.

---

## 5. Verdict and honesty locks

This change is not a ship-verdict blocker, and it does not change the overall verdict — that stays conditional. What it does is advance the claim from "the engine has zero observability" to "a production operator can scrape /metrics and read the real ingest p99 / reject rate / verify cost / convergence lag". The measured p99 (~60us verify-bound on the single-delta path) is an honest number, not a fabricated sub-1us; batched deltas are the sub-1us-per-delta unlock.

The honest weaknesses are recorded verbatim in §8.

---

## 6. Design risks considered

**Risk: Prometheus client_golang instruments contend on the 32-core hot path.** FACT 1 answers it: the receive rate is verify-bound at ~533K frames/sec, not the 57.6M arena path, and the bench measures the actual overhead; the `internal/telemetry` LongAdder is the documented fallback if contention ever appears. The bench settled it (§3.3).

**Risk: the per-process Registry breaks OTel exporters that register on the DefaultRegisterer.** The /metrics Registry is independent of `internal/telemetry`'s OTel Init path (`registry.go` Init binds a meter, not the prometheus DefaultRegisterer). The two coexist; the per-process Registry is the prometheus-scrape surface only (§3.2).

**Risk: scraping /metrics under load stalls a goroutine on the plain-HTTP server.** `promhttp.HandlerFor` is non-blocking; the scrape iterates instruments with no hot-path lock, and the convergence-gauge poller is a 1s ticker off the hot path. The residual case is a scrape during a 100k-frame burst flooding a single Histogram.Observe — the prometheus client handles it. Recorded as an open weakness in §8.

---

## 7. Naming hygiene

New identifiers introduced by this change use professional names — `Recorder`, `Exporter`, `ConvergenceLag`, `IngestLatencyHistogram`, `LastConvergedAt` — not milestone-glued tokens. Pre-existing legacy identifier tokens elsewhere in the tree are left alone; one canonical example sits in one of the core files and stays unrenamed (stability beats hygiene). An acceptance gate asserts the new files contain zero milestone-glued identifier tokens, with that core-file exception allowed explicitly.

---

## 8. Honest weaknesses

1. /metrics is plain HTTP on the ops-debug control surface (not TLS, not the data plane). A TLS-or + auth-hardened /metrics is future hardened-ops work (also named in ADR-0006 §8 item 3), not part of this change.

2. p99 ingest is ~60us (verify-bound), not sub-1us. The sub-1us-per-delta unlock is batched deltas (one verify per N deltas). I do not fabricate sub-1us anywhere in this record or its logs.

3. `sovereign_convergence_roots_equal` is a 2-node binary indicator (the current mesh); a 3-node quorum-aware gauge is future work. The convergence-lag gauge uses the 100ms default sweep tick; the 50ms partition-probe override is not wired into the gauge (the gauge reads `ConvergenceLag()`, which is tick-agnostic).

4. The recorder-overhead bench is run on the 4-core development box. A high-core-count re-run (where contention is genuinely load-bearing) is reserved for the milestone that needs it. If a large box is provisioned sooner as a bonus, the re-measurement confirms the LongAdder-vs-Prometheus-direct verdict at high contention. A number measured on a bigger box is reported as a separate machine's number, never relabeled as the development box's.

5. No long-soak. This change is a build+test+scrape gate. A 24h scrape-stationarity test (no counter drift, no leak) is a future reliability track.

---

## 9. Bottom line

This change ships the observability surface the partition-heal probe reads. The gate is falsifiability (the seven series are scrapeable with HELP+TYPE) plus an honest measured p99 (~60us verify-bound; batched deltas are the sub-1us-per-delta unlock) plus a measured recorder overhead (the FACT-1 settle bench) plus the bimodality tooth (cheap-gates-before-verify readable in the histogram) plus the per-process Registry root-cause fix plus an Option A/B verdict defended above. The overall ship verdict is unchanged. Nothing fabricated; the physics decides where the p99 lands.
