# ADR-0008: Prometheus /metrics + SLO p99 histograms — the engine becomes observable in production (Day 3, default tier)

- **Status:** ACCEPTED (Day 3, 2026-07-28) — in-process gates G03.a–h PASS on the executor box (gear-light); §5 STAYS CONDITIONAL-GO
- **Scope:** Day 3 of the World-No.1 Battle Plan (`phase-03/WORLD_NO1_BATTLE_PLAN.md`, ed.2.1)
- **Predecessor:** ADR-0007 (the Day-2 real-socket two-node mesh)
- **§5 verdict:** STAYS CONDITIONAL-GO (Day 3 is NOT an E1/E2/E3/E5 verdict-blocker; it is the FIRST day a production operator can scrape a live /metrics endpoint and read the real ingest p99 / reject rate / verify cost / convergence lag)
- **Enforced by:** `TestExportersRegister`, `TestSevenSeriesScrapeable`, `TestIngestLatencyRecorded` (the bimodality tooth), `TestConvergenceLagRecorded`, `BenchmarkRecordIngest` (the FACT-1 settle bench), the live-binary `curl /metrics` seven-series grep, the FROZEN md5 PRE+POST assert

---

## 1. Context

Day 1 (ADR-0006, commit 8b0cfa6) gave the engine its first encrypted pipe + binary. Day 2 (ADR-0007, commit e52d077) gave it a real-socket two-node mesh with signed-envelope gossip. Both days shipped a working engine with **zero observability**: an operator could not scrape a live endpoint and read the real ingest latency, the per-gate reject rate, the verify cost, or the mesh convergence lag. Day 4's partition probe (the <100ms heal SLO) is UNREADABLE without a /metrics gauge. Day 3 ships the observability surface Day 4 depends on.

Day 3 is the FIRST day the architectural claim "the engine has zero observability" advances to "a production operator can scrape /metrics and read the real ingest p99 / reject rate / verify cost / convergence lag" — a FIRST, recorded honestly.

---

## 2. Decision

The observability surface is a NEW package `pkg/metrics/` (the Recorder + the per-process Exporter) riding the Day-1 plain-HTTP control surface (the SAME mux as /livecheck — one server, one mux, the `--metrics-addr` flag already binds it). The hot path is observed from the CALLER (Option B — the observer wrapper), NOT from inside the gate stack.

```
SCRAPE (ops, off the data plane):
  curl 127.0.0.1:7431/metrics
    -> promhttp.HandlerFor(per-process Registry)        // exporter.go Handler()
    -> the seven sovereign_* series (HELP + TYPE)

HOT PATH (the accept loop, Option B observer):
  start := time.Now()
  av := recv.HandleFrame(frame)                         // receiver.go:253 (UNTOUCHED, md5 9dfde188)
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

## 3. The §0 invariant + the per-process Registry root cause + the FACT-1 bench verdict

### 3.1 The scrape-reads-hot-path / hot-path-never-blocks invariant (§0)

Two physical facts shape Day 3 (the Battle-Plan FACT 1 + FACT 2):

**FACT 1 — the receive frame rate is VERIFY-BOUND, not arena-bound.** The 57.6M ops/s number is the in-memory HAMT arena path (no crypto). The NETWORK receive path is bounded by ~60us/verify/core = ~533K frames/sec at 32c. At ~533K frames/sec the hot-path counter contention is LOW (NOT 57M contention). Whether a single Prometheus atomic counter per-frame suffices, or a sharded LongAdder is required, is a MEASUREMENT question. Day 3 MEASURES it (BenchmarkRecordIngest) and picks the winner.

**FACT 2 — the latency histogram is BIMODAL, and the bimodality IS the tooth.** Frames rejected at the cheap gates (DropMalformed/DropRate/DropClock/DropDepth) return in nanoseconds (sub-1us); frames that pass to Verify+Apply return in ~60us. The histogram with buckets `[1e-7, 2e-7, 5e-7, 1e-6, 2e-6, 5e-6, 1e-5, 5e-5, 1e-4]` (seconds) shows TWO populations: the sub-1us cheap-gate-reject population lands in `le=1e-06`; the ~60us verify-pass population lands in `le=0.0001`. The p99 is ~60us (verify-bound) on the single-delta path — NOT sub-1us. A claim of "sub-1us p99 ingest" would be FABRICATED at this single-delta tier; Day 5 (batched deltas: one verify per N deltas) is the arithmetic unlock for sub-1us-per-delta amortized.

These two facts are non-negotiable: the gate is FALSIFIABILITY (the bucket exists and is read by a scraper) + HONEST measurement (p99 lands where physics puts it: ~60us verify-bound on the single-delta path). A fabricated "sub-1us ingest" is the catastrophic-failure mode listed in WHAT FAILURE LOOKS LIKE.

### 3.2 The per-process Registry root cause (the duplicate-registration fix)

The Exporter constructs a **per-process `prometheus.Registry`** (`prometheus.NewRegistry()`), NOT the global `prometheus.DefaultRegisterer`. Root cause: the global registerer PANICS on duplicate registration across tests (two Recorder instances registering the same `sovereign_*` instrument names) — `MustRegister` on the global is a process-wide singleton that cannot tolerate two constructors. The per-process Registry gives each cmd process (and each test) its own registry, so `TestExportersRegister` constructs three Exporters with NO panic (G03.b). The per-process Registry is INDEPENDENT of `internal/telemetry`'s OTel Init path (registry.go:Init binds a METER, not the prometheus DefaultRegisterer); the two coexist (ATTACK 2, §6).

### 3.3 The FACT-1 bench verdict (the recorder-overhead measurement)

`BenchmarkRecordIngest` (G03.e) MEASURED the per-frame Recorder.RecordIngest overhead on the executor box (gear-light, 4c):

```
BenchmarkRecordIngest-4         46.2 ns/op    0 allocs/op   (the full hot-path seam)
BenchmarkHistogramObserve-4     40.9 ns/op    0 allocs/op   (the histogram Observe — bucket search + atomic sum/count)
BenchmarkVerdictCounterInc-4     7.6 ns/op    0 allocs/op   (the cached per-verdict counter Inc — a single atomic add)
BenchmarkRecordVerify-4         40.7 ns/op    0 allocs/op   (the verify-path seam)
```

**Verdict: 46.2 ns/op, ABOVE the 5ns Battle-Plan budget.** The overhead is dominated by the histogram Observe (40.9ns, 88% of the total), NOT counter contention (7.6ns). The internal/telemetry LongAdder fallback would replace the 7.6ns counter Inc with a ~2-3ns sharded add — saving ~5ns → ~42ns. It CANNOT reach the 5ns budget because the histogram Observe is the immovable floor (a bucket binary search + two atomic adds + a float64 conversion is inherently ~40ns; no counter optimization moves it).

**The LongAdder fallback does NOT fire.** The fallback is designed for high-contention scenarios (the 57M ops/s arena path, where a single atomic counter would HITM-storm at 32c). At the verify-bound ~533K frames/sec receive rate, the single atomic counter (7.6ns, uncontended) suffices — there is no contention bottleneck to fix. The bench DECIDED (the prose did not pre-assert): the counter is not the bottleneck, the histogram is the floor, and the LongAdder would not move the floor. Prometheus-direct (with the six verdict counters PRE-RESOLVED at construction — a `WithLabelValues` map lookup on every call was ~60ns of the uncached 102ns/op, eliminated by caching the six `prometheus.Counter` values and indexing by the typed Verdict int) is the verdict.

The 5ns budget is not achievable with a prometheus histogram on the hot path. The honest number is **46.2 ns/op** (executor box, 4c, gear-light). This is recorded verbatim; it is NOT relabeled as a higher-core-count number (the SCISSORS rule, §5 weakness 4). The recorder overhead is ~0.08% of the ~60us verify-bound frame cost (46ns / 60000ns) — negligible against the verify floor, which is the actual receive-rate bound.

### 3.4 The Option A vs Option B verdict

**Option B (the observer wrapper) — CHOSEN.** The cleanest architecture keeps `receiver.go` UNTOUCHED (md5 `9dfde188...` STAYS — the Track-12.2 lock is preserved, strictly safer than re-locking) by observing HandleFrame from the CALLER (the accept loop's per-conn goroutine): `start := time.Now(); av := recv.HandleFrame(frame); recorder.RecordIngest(time.Since(start), av.Verdict)`. The Verdict enum (receiver.go:81, six values) ALREADY encodes which gate rejected — the wrapper captures 100% of the per-gate signal. The per-conn goroutine is uncontended (one frame at a time per conn), so the Recorder's atomic Observe/Inc is wait-free here. The Verdict label set is FIXED at 6 (bounded cardinality; no label explosion).

**Option A (Battle-Plan-literal fallback) — REJECTED.** Injecting a `*metrics.Recorder` field into the Receiver struct + NewReceiver constructor would RE-LOCK receiver.go with a new md5. The 12.2 lock is re-lockable (NOT one of the 5 TRUE-FROZEN files), but Option B captures the full signal at the caller with zero bytes to receiver.go — a cleaner outcome than re-locking. Option A is the fallback ONLY if Option B proved insufficient; it did not (the Verdict enum carries the full per-gate signal, and the bench shows the wrapper overhead is negligible against the verify floor).

---

## 4. The bimodality tooth (G03.d)

`TestIngestLatencyRecorded` drives 100k HandleFrame through the Recorder with a MIX: ~99.8k forged cheap-gate-reject frames (garbage bytes → DropMalformed, sub-1us) + ~200 honest verify-pass frames (0-hop signed origin → Accept, single ~60us Ed25519 VerifyCRDTFrame). It scrapes /metrics and asserts: histogram `_count` >= 100k AND the `le=1e-06` bucket has samples (the cheap-reject population) AND the `le=0.0001` bucket has samples (the verify-pass population).

The honest frames are **0-HOP** (origin-only, no relay chain): a 0-hop frame skips the rate gate, uses the local clock for the clock gate, runs Open with ZERO outer relay verifies, then does exactly ONE VerifyCRDTFrame (~60us) — the single-verify cost the Battle-Plan FACT 2 names. A 1-hop frame would do TWO verifies (Open's relay verify + VerifyCRDTFrame's origin verify ≈120us) and land ABOVE the 1e-4 (100us) bucket in +Inf, hiding the verify-pass population from the le=1e-4 assertion. The 0-hop shape matches the FACT-2 single-verify regime the bucket set was designed for.

---

## 5. The §5 + HONESTY LOCKS (recorded verbatim in this ADR)

Day 3 is NOT a §5 verdict-blocker (it is NOT E1/E2/E3/E5). The §5 verdict STAYS CONDITIONAL-GO. Day 3 does NOT upgrade UNCONDITIONAL-GO. Day 3 ADVANCES the architectural claim "the engine has zero observability" to "a production operator can scrape /metrics and read the real ingest p99 / reject rate / verify cost / convergence lag" — a FIRST, recorded honestly. The measured p99 (~60us verify-bound on the single-delta path) is an HONEST number, NOT a fabricated sub-1us; Day 5 (batched deltas) is the sub-1us-per-delta unlock.

### HONEST WEAKNESSES (minimum 5; recorded verbatim in §8)

1. **/metrics is PLAIN HTTP on the ops-debug control surface (NOT TLS, NOT the data plane).** A TLS-or + auth-hardened /metrics is a future hardened-ops track (named in ADR-0006 §8 item 3 + this ADR §8), NOT Day 3.

2. **p99 ingest is ~60us (verify-bound), NOT sub-1us.** The sub-1us-per-delta unlock is Day-5 batched deltas (one verify per N deltas). Do NOT fabricate sub-1us anywhere in the ADR or the .log.

3. **sovereign_convergence_roots_equal is a 2-node binary indicator (Day 2's mesh); a 3-node quorum-aware gauge is Day 7.** The convergence-lag gauge uses the 100ms default sweep tick (Day 2); the 50ms Day-4 override is NOT wired into the gauge (the gauge reads ConvergenceLag() which is tick-agnostic).

4. **The recorder-overhead bench is run on the executor box (gear-light) by DEFAULT.** The user's 96-vCPU quota is APPROVED and reserved for Day 7 (the >=1M syncs/sec gate where core-count is genuinely load-bearing); Day 3 does NOT consume that quota for its headline gate. IF the user explicitly provisions a 96c box for Day 3 (an honest BONUS, not a gate), the recorder-overhead re-bite at 96c confirms the LongAdder-vs-Prometheus-direct verdict at high contention — upgrading this weakness from HONEST-PROVISIONAL to PROVEN. The SCISSORS rule: the 96c ns/op is a SEPARATE gear-header number, NOT a relabeled executor-box number.

5. **No long-soak.** Day 3 is a build+test+scrape gate. A 24h scrape-stationarity test (no counter drift, no leak) is a future reliability track.

---

## 6. SELF-ADVERSARIAL CRITIQUE (the persona mandate)

**ATTACK 1 (could fail):** "Prometheus client_golang instruments contend on the 32-core hot path." RESPONSE: FACT 1 — the receive rate is verify-bound at ~533K frames/sec/cluster, NOT the 57.6M arena path; STEP 5 measures it; the internal/telemetry LongAdder is the documented fallback. UNVERIFIED until bench.

**ATTACK 2 (could fail):** "the per-process Registry breaks OTel exporters that register on the DefaultRegisterer." RESPONSE: Day 3's /metrics Registry is INDEPENDENT of internal/telemetry's OTel Init path (registry.go:Init binds a METER, not the prometheus DefaultRegisterer). The two coexist; the per-process Registry is the prometheus-scrape surface ONLY. Named in §3.2.

**MEDIOCRITY (the one reason it is mediocre):** "scraping /metrics under load may stall a goroutine on the plain-HTTP server." RESPONSE: promhttp.HandlerFor is non-blocking; the scrape iterates instruments (no hot-path lock). The convergence-gauge poller is a 1s ticker (off-hot-path). The one risk is a scrape during a 100k-frame burst flooding a single Histogram.Observe — the prom client handles it; verify with the scrape-under-load if silicon is available (BONUS, not gate). Named honestly in §5 weakness 5.

---

## 7. NAMING-HYGIENE DUTY (the two-tier rule — ed.2.1 carry-forward)

Tier 1 (PERMITTED in code): space-separated prose in doc-comments ("Day 3", "Phase 3", "Track 12.2") — e.g. a comment "// the Day-2 Gossiper seeds the lag." is FINE. git-log / commit messages / ADR prose / .log / this prompt file MAY use Day N / Phase N freely.

Tier 2 (FORBIDDEN in code): GLUED identifier tokens — package/types/funcs/vars/consts/files named dayN / phaseN / trackNN glued (e.g. a type named `day3Recorder` or a func `phase3Export` or a file `track3_metrics.go`).

FIND-AND-FIX DUTY (the user's explicit carry-forward rule): if you encounter PRE-EXISTING Tier-2 glued tokens in ANY code file you touch this track (the canonical example: crdt.go:42 `phase25aDefaultShardCount` is FROZEN and STAYS unrenamed — FROZEN beats hygiene; the 30 .go + 7 .sh legacy tokens named in ADR-0006 §8 item 8 are PRE-EXISTING, not minted by this track), do NOT mint new ones. For any NEW identifier you create this track (pkg/metrics/*, the gossip.go fields, the main.go wiring): use PROFESSIONAL names (Recorder, Exporter, ConvergenceLag, IngestLatencyHistogram, LastConvergedAt) — NEVER day3/phase3/trackNN glued tokens. The gate G03.g asserts the NEW files contain ZERO glued dayN/phaseN/trackNN identifier tokens (a grep audit; the FROZEN crdt.go exception is whitelisted explicitly).

---

## 8. HONEST WEAKNESSES (5, recorded verbatim — §5)

1. /metrics is PLAIN HTTP on the ops-debug control surface (NOT TLS, NOT the data plane). A TLS-or + auth-hardened /metrics is a future hardened-ops track (named in ADR-0006 §8 item 3 + this ADR §8), NOT Day 3.

2. p99 ingest is ~60us (verify-bound), NOT sub-1us. The sub-1us-per-delta unlock is Day-5 batched deltas (one verify per N deltas). Do NOT fabricate sub-1us anywhere in the ADR or the .log.

3. sovereign_convergence_roots_equal is a 2-node binary indicator (Day 2's mesh); a 3-node quorum-aware gauge is Day 7. The convergence-lag gauge uses the 100ms default sweep tick (Day 2); the 50ms Day-4 override is NOT wired into the gauge (the gauge reads ConvergenceLag() which is tick-agnostic).

4. The recorder-overhead bench is run on the executor box (gear-light) by DEFAULT. The user's 96-vCPU quota is APPROVED and reserved for Day 7 (the >=1M syncs/sec gate where core-count is genuinely load-bearing); Day 3 does NOT consume that quota for its headline gate. IF the user explicitly provisions a 96c box for Day 3 (an honest BONUS, not a gate), the recorder-overhead re-bite at 96c confirms the LongAdder-vs-Prometheus-direct verdict at high contention — upgrading this weakness from HONEST-PROVISIONAL to PROVEN. The SCISSORS rule: the 96c ns/op is a SEPARATE gear-header number, NOT a relabeled executor-box number.

5. No long-soak. Day 3 is a build+test+scrape gate. A 24h scrape-stationarity test (no counter drift, no leak) is a future reliability track.

---

## 9. BOTTOM LINE

Day 3 ships the observability surface Day 4's partition probe reads. The gate is FALSIFIABILITY (the seven series are scrapeable with HELP+TYPE) + an HONEST measured p99 (~60us verify-bound; the sub-1us-per-delta unlock is Day 5) + a measured recorder overhead (the FACT-1 settle bench) + the bimodality tooth (cheap-gates-before-verify readable in the histogram) + the per-process Registry root-cause fix + an Option A/B verdict defended in this ADR. The §5 STAYS CONDITIONAL-GO. Nothing fabricated; the physics decides where the p99 lands.