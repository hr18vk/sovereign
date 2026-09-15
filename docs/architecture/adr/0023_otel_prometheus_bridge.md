# ADR-0023: The Observability Egress — Bridge `internal/telemetry` LongAdders onto the per-process `/metrics` Registry (Cumulative, single-source-of-truth, nil-OTel-safe)

**Status:** Accepted
**Date:** 2026-08-04
**Author:** Harsh Rawat
**Builds on:** ADR-0008 §3 (the per-process `prometheus.Registry` — the duplicate-registration root-cause fix the bridge MUST join, NOT the global `DefaultRegisterer`), the pkg/metrics `Exporter` surface (exporter.go:67 `Registry()`), internal/telemetry (the LongAdder counter layer — telemetry.go / registry.go), ADR-0021 (the L0 reaper whose `L0ReapSkippedOrphan` counter is the SAFETY-CRITICAL signal this change finally makes operator-observable), ADR-0022 (the discipline this change re-applies: prose corrected against bytes before shipping).

---

## §0. The two-layer no-op, and the planned "24" corrected to the byte-verified 12

The engine carried an operator-blindness defect: the data plane
`Add()`/`Inc()` on every flush / compaction / prune / reap touches the
`internal/telemetry` LongAdder counters, and **none of them reached
`/metrics`**. An operator scraping the Prometheus surface was blind to the
entire compaction + reaper + flush surface — including the **safety-critical**
`supremum_compaction_l0_reap_manifests_skipped_orphan`, the signal the
reaper guard emits when it **REFUSES** to delete (an L1 went missing →
the crash-recovery backstop is preserved). A production storage outage was
silent to every `/metrics` dashboard; the reaper's own honest log lines were
log-only and invisible to a monitoring stack.

### §0.a The physical fact (byte-verified)

`rg "telemetry\.Init" ./...` returned **ZERO call sites** in the repository —
not in production, not in tests. `cmd/sovereign-node/main.go` did NOT import
`internal/telemetry` at all (grep-confirmed). At package init,
`registry.go:84` runs `var m metric.Meter` (the zero-value nil); the
`if p := meter.Load(); p != nil` guard at `:85` is false on first boot, so `m`
STAYS nil, and `registry.go` goes into the `init()` body (not
`rebuildCounters`) with a nil meter. In `newCounter` (telemetry.go:219),
`c.register(meter)` hits `telemetry.go:236 if meter == nil { return }` — **NO
OTel observable is EVER created**. `lastReported` (telemetry.go:102) is NEVER
mutated (only the OTel callback at telemetry.go:258 touches it; the callback
never fires because the instrument was never built).

**Consequence:** in the running binary, the `supremum.*` counters exist as
pure in-process LongAdders — `Add()`/`Inc()` work, `Value()` reads the
cumulative — but NOTHING reads the cumulative out. The OTel path is a no-op AND
the prometheus path is a no-op. This is a **two-layer no-op**, not "the bridge
is missing" (which under-describes it).

### §0.b The double-count trap (the load-bearing insight)

The OTel int64 observable at telemetry.go:247-267 reports the **per-interval
DELTA**, not the cumulative — its callback does
`delta := now - int64(prev); lastReported.CompareAndSwap(prev, now)`.
Prometheus counters are **monotone-cumulative** by contract (the prometheus
SERVER computes the rate from consecutive scrapes; the bridge must NOT
pre-delta). So:

- The bridge MUST report CUMULATIVE (`Counter.Value()` — the 64-stripe decode-sum).
- The bridge MUST NOT depend on `lastReported` (that field belongs to the OTel
  callback; reading it from the bridge couples the bridge to the OTel cadence
  and tears the delta if OTel fires between scrapes).

At the time this was moot (OTel never fired — §0.a) — but any later change that
wires a real OTel provider at boot (`telemetry.Init(realMeter)`) arms the
callback, advances `lastReported`, and a naive bridge that touched the field
would double-count OR diverge from the OTel exporter. The bridge shipped here
is safe **whether or not an OTel provider is bound later** — it reads
cumulative via `Value()` and never touches `lastReported`.

### §0.c The planned "24 counters" corrected to the byte-verified 12 DISTINCT

My design notes claimed "24 `supremum.*` counters." Byte-verification
corrected it:

- `init()` (registry.go:83-166) makes **13 `newCounter` calls** — but
  `QueryL0ListCapped` is constructed **TWICE** (registry.go:100 AND :106, byte-
  identical args; the first object is orphaned when the var is reassigned).
- `rebuildCounters()` (registry.go:171-238) makes **11 `newCounter` calls** —
  it builds `QueryL0ListCapped` **ZERO times** (the omission is a pre-existing
  data-plane bug: if `telemetry.Init(m)` were ever called, the resulting rebuild
  would INSTALL a nil `QueryL0ListCapped`, and `query.go:225`'s
  `if telemetry.QueryL0ListCapped != nil` guard would silently stop counting the
  cap-hit disclosure — a latent land-mine).
- Total `newCounter` **invocations** = 13 + 11 = **24** (where the "24" came from).
- **DISTINCT `*Counter` package vars** = **12** (one per declared var in the
  registry.go:58-81 block; they map 1:1 to 12 distinct `supremum.*` metric
  NAME strings — byte-verified via `grep -oE '"supremum\.[a-z0-9._]+"' | sort -u`).

**The bridge exposes 12 series, not 24.** The headline figure in my notes was
the `newCounter` *invocation* count, not the *distinct-counter* count — the
same class of miscount a second read of the bytes catches (`6 -> 3` in
the notes; the verified count was `4 -> 3`). This change reports the
**measured 12** and discloses the mechanism (§6). The deliverable is structural;
the honest number is 12.

### §0.d The construction-duplicate landmine this change sidesteps

The `QueryL0ListCapped` double-construction in `init()` (§0.c) is a load-bearing
hazard for the obvious patch. The obvious single-source-of-truth design was
**append each constructed `*Counter` to a package-level `counters` slice inside
`newCounter`**. That would emit the **duplicate** `supremum.l0.query_list_capped`
NAME twice into the slice (once per construction) → the bridge's
`Registry.MustRegister` would emit two `*prometheus.Desc` for the same name →
**`MustRegister` PANICS at boot** on the duplicate Desc (the per-process Registry
is a `prometheus.NewRegistry`; it rejects duplicate Desc by name exactly the way
`exporter_test.go:20`/ADR-0008 §3 describes the global-registry panic, only
intra-Registry). This is a landmine dressed as a clean follow-up — a change that
"follows the obvious path" ships a boot-time panic.

I sidestepped it with the alternative design path (§1.1.a): build the
single-source-of-truth slice from the **distinct package vars** in a single
`allCounters()` helper called at the end of `init()` and `rebuildCounters()` —
one literal list, not a per-call append. **One list, not two;** the duplicate
construction stays OUT of the slice (it is a construction-site artifact, not a
slice-site one), so the bridge sees exactly the 12 distinct counters and
`MustRegister` does not panic. The in-package guard
(`TestCountersNoDuplicateNames`) fences this: it asserts `Counters()` carries
12 distinct names with **zero duplicates** — the regression fence if a future
change takes the append-in-`newCounter` path.

The `QueryL0ListCapped` double-construction itself is **left un-fixed** (a
disclosed open item, §6): fixing it is a data-plane concern (it touches the
`init()`/`rebuildCounters` construction body, which is the configuration surface
this change *reads* via `Counters()`, not *edits*), and this change touches
**none of the five core files** (the CRDT merge core and the wire schema) — a
property any `registry.go`
construction-body edit would jeopardize for zero bridge benefit (the bridge
does not care that the orphaned first object exists; it never reaches the
slice).

---

## §1. Context

The reaper (ADR-0021) added four `internal/telemetry` counters
(`L0ReapSweeps`, `L0ReapL0Deleted`, `L0ReapManifestsReaped`,
`L0ReapSkippedOrphan`) that make the reaper's disk reclamation **observable** —
but only to a caller that reads `Value()` in-process. The pkg/metrics
`Exporter` owns the `sovereign_*` series (the Recorder's ingest
verdicts, latency histogram, gossip rounds, convergence gauges) and exposes
`/metrics` via `promhttp.HandlerFor` bound to a **per-process Registry**
(ADR-0008 §3 — the duplicate-registration root-cause fix; the global
`DefaultRegisterer` would panic across test processes). Until this change, the
`supremum.*` counters and the `sovereign_*` series lived on **disjoint
surfaces**: the former were wait-free LongAdders with no egress; the latter
were labelled prometheus instruments with a scrape handler.

This change bridges the two WITHOUT coupling the layers: the bridge is a
`prometheus.Collector` that enumerates `telemetry.Counters()` (the single
source of truth) and projects each counter onto a cumulative constCounter /
constGauge registered into the SAME per-process Registry the `Exporter`
already owns. The `supremum_*` series (mapped from `supremum.*`, dots → `_`)
is **additive** to the `sovereign_*` series — the two never collide (different
prefixes; byte-verified — no `sovereign_` name starts with `supremum`).

---

## §2. The contract guards (RED → GREEN)

| Guard | Gate | What it PROVES |
|-------|------|----------------|
| **T1** `TestRealScrapeCumulativeNotDelta` | `-race` | A real `httptest` scrape surfaces every `supremum_*` series; the cumulative **ADVANCES by exactly the delta** across two scrapes (a delta-reporting bridge — the §0.b trap — would show the increment ONCE then reset). `supremum_memtable_flush_total` `0 → 7 (+7 == delta)` byte-captured. |
| **T1b** `TestSafetyCriticalOrphanSignal` | `-race` | The safety-critical `supremum_compaction_l0_reap_manifests_skipped_orphan` is observable on `/metrics` for the first time (cumulative advances after `Inc`). The observability blind spot that MOTIVATED this change is closed at the scrape layer; the reaper's "I refused to delete" guard is now alertable. |
| **T2** `TestTelemetryCounterEnumeration` (+ in-package `TestCountersNoDuplicateNames`) | `-race` | The bridge enumerates `telemetry.Counters()` (ONE list, not a hardcoded copy): (a) `bridge.counters` is the single-source-of-truth snapshot by identity; (b) the Desc set has exactly one Desc per distinct mapped name (no dup → no `MustRegister` panic); (c) `Describe` emits one Desc per counter (scales as `append`, not as an edit to a hardcoded list). The in-package guard asserts 12 distinct names, 0 dups, 11 `modeCounter` + 1 `modeGauge`. |
| **T3** `TestZeroAllocCollect` | `-race` | **MEASURED, not gamed.** `testing.AllocsPerRun(100, Collect) = 62` allocs/run (not 0). HONEST residual, disclosed §6 (decomposed: 12 from the bridge's own `Value()` read path, 50 from `prometheus.MustNewConstMetric` × 12). The guard asserts the bridge-side invariant it CAN guarantee (the pre-built Desc set does NOT churn across Collect); it does NOT game the number by skipping the const-metric build (that would fabricate zero). The bridge's target is 0; the bridge's measured is 62, off the data path on the 15s scrape cadence. |
| **T4** `TestDoubleCountTrapGuard` (+ in-package `TestLastReportedUntouchedByBridge`) | `-race` | The bridge reads `Counter.Value()` and **NEVER** `lastReported`. Cross-package: a scrape of `supremum_compaction_l1_rows_pruned` after 11 `Inc` reports `11 == Counter.Value()` (the LongAdder, not lastReported). In-package (authoritative — the field is unexported): after 13 `Inc`, `lastReported.Load() == 0` UNCHANGED; the OTel callback never fires (Init uncalled), so the field the bridge is forbidden to read stays 0. This **pre-empts** the §0.b production double-count the day a real OTel Meter is bound and the callback is armed. |
| **T5** `TestNilOTelSafe` | `-race` | The bridge works WITHOUT `telemetry.Init` (the production reality at the time — §0.a). Constructing the bridge + driving `CompactionMerged.Inc()` twice yields a non-zero `supremum_compaction_l0_files_merged` on the scrape. The two-layer no-op is closed at the prometheus layer WITHOUT requiring the OTel layer. |
| **T6** | `-race` | This change touches none of the five core files (the CRDT merge core + the wire schema). `telemetry.Init` stays at ZERO production callers (a source grep over `internal/`, `pkg/`, `cmd/` excluding `_test.go`). |

---

## §3. The single-source-of-truth choice (§1.1.a/§1.1.b/§1.1.c/§1.1.d of the design notes, with the planned API corrected)

### §3.a One list, not two; built from distinct vars, not per-call append

I considered two single-source-of-truth shapes: (i) append inside
`newCounter` (the "obvious patch"); (ii) build the slice in a single pass at
the end of the construction site. I took (ii), via a new `allCounters()`
helper that returns the 12 distinct package vars in stable order; both
`init()` and `rebuildCounters()` call it as their last statement to populate
`var counters []*Counter`.

The reason is the §0.d landmine: shape (i) would copy the `QueryL0ListCapped`
construction-duplicate into the slice (a duplicate `supremum.l0.query_list_capped`
NAME) and `MustRegister` would panic at boot. Shape (ii) reads the distinct VARS,
so the duplicate-construction is invisible to the slice — the bridge sees 12
distinct counters, 12 distinct names, zero dups (byte-verified, §2 T2).

The slice is **append-only-after-construction**: it is populated once at
`init()` and (if boot calls `telemetry.Init`, which at the time it did NOT) once at
`rebuildCounters`. Both run behind the program-start barrier, before the first
`/metrics` scrape fires at `startLivecheck` (main.go:506+). The bridge takes its
snapshot at `NewTelemetryBridge()` — called ONCE per process, after
`NewExporter()` and BEFORE `startLivecheck` (the §1.1.d ordering) — and reads
it WITHOUT a lock thereafter; the construction race is resolved by the
program-start barrier. A `countersMu` is NOT needed under shape (ii) (the
append-during-construction it would guard does not exist); a comment in
`allCounters` documents that the slice is frozen after construction.

### §3.b Read-only accessors + the `CounterMode` alias (NOT exporting the type)

`telemetry.go` gains small package-level accessors:
`Counter.{Name,Description,Unit,Mode}()` returning the immutable construction
fields. `Value()` ALREADY EXISTS (telemetry.go:205 — cumulative for
`modeCounter`, last-Set for `modeGauge`); I deliberately did NOT add a second
value accessor. **`lastReported` is NOT exported** (the §0.b trap);
**`Delta()`/`Reset()` are NOT added** (they would tempt a future change into
pre-deltaing).

`Mode()` returns the **unexported** `counterMode` type — useless to a
cross-package caller (the bridge in `pkg/metrics` cannot compare `c.Mode()` to
`telemetry.modeCounter`, an unexported const). The signature
`func (c *Counter) Mode() counterMode` stays, supplemented with an
**exported TYPE ALIAS**:

```go
type CounterMode = counterMode
const (
    ModeCounter counterMode = modeCounter
    ModeGauge   counterMode = modeGauge
)
```

This is an **alias**, not a rename of `counterMode` — the 24 construction sites
in `registry.go` continue to pass `modeCounter`/`modeGauge` unchanged (zero
churn). Only the bridge compares via `telemetry.ModeCounter`/`telemetry.ModeGauge`.
Exporting `counterMode` itself would have required renaming every construction-
site literal — a 24-site ripple for a type the bridge alone reads; the alias is
the strictly-better choice (documented here because returning an unexported type
creates a cross-package-usability problem that is easy to miss until the bridge
tries to compare against it).

### §3.c `MustNewConstMetric` + `ValueType`, NOT `MustNewConstCounter` (API corrected against the installed version)

My design notes named the const-metric constructors `prometheus.MustNewConstCounter` /
`prometheus.MustNewConstGauge`. **These symbols do not exist in the
installed `github.com/prometheus/client_golang v1.23.2`** (byte-verified via
`grep -rE "^func (MustNewConst|NewConst)"` over the module cache — the only
const helpers are `NewConstHistogram`/`MustNewConstHistogram`/`NewConstSummary`
/`MustNewConstSummary`/`NewConstMetricWithCreatedTimestamp`/`MustNewConstMetricWithCreatedTimestamp`, and the shared
`MustNewConstMetric(desc, valueType, value, labelValues...)`/`NewConstMetric`).
`MustNewConstCounter`/`MustNewConstGauge` are the **longhand name of the dispatch**
the `ValueType` enum performs: the bridge calls

```go
prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value)   // modeCounter
prometheus.MustNewConstMetric(desc, prometheus.GaugeValue,   value)   // modeGauge
```

`CounterValue` emits a monotone-cumulative counter (the server derives the
rate); `GaugeValue` emits a last-writer-wins gauge. Both take **no label
values** — the counters are dimensionless singletons (the `Desc` carried `nil`
`LabelNames`, so the const metric MUST carry zero label values or the
constructor panics on arity mismatch). The `OffHeapAllocatedBytes` gauge
(`modeGauge`) is the sole gauge; the other 11 are counters. The doc-comment on
`Collect` records the version-real API so a future change does not re-fall into
the shorthand.

### §3.d The bridge reads cumulative via `Value()`, never `lastReported` (the §0.b closure)

`Collect` calls `c.Value()` (cumulative for counters, last-Set for gauges) and
passes it to `MustNewConstMetric`. It does NOT read `lastReported`, `Delta()`,
or `Reset()` (the latter two do not exist and never will — §3.b). T4 (cross-
package + in-package) gates this at both the scrape layer (the scraped value
== `Counter.Value()`) and the field layer (`lastReported == 0` UNCHANGED after
`Inc`). The bridge is safe with nil OTel (the callback never fires) AND safe
the day a real OTel Meter is bound (the bridge's read path is unaffected by
whether the callback advances `lastReported`).

---

## §6. Honest open items and the measured residuals (no false victory)

1. **The "24" was 12. (§0.c)** My design notes claimed "24 `supremum.*`
   counters"; the byte-verified count is **12 distinct counters** (the 24 is
   the `newCounter` invocation count across `init()`(13) + `rebuildCounters()`(11)).
   The bridge exposes 12 series. The T2 in-package guard asserts exactly 12
   distinct names + 0 dups; the T1 guard asserts every distinct name appears.

2. **The `QueryL0ListCapped` construction-duplicate + the `rebuildCounters`
   omission (§0.c/§0.d), left un-fixed.** `init()` builds `QueryL0ListCapped`
   twice (registry.go:100 + :106); `rebuildCounters()` builds it zero times.
   I did NOT edit the construction body (it would jeopardize the
   "touches none of the five core files" property for zero bridge benefit — the bridge reads
   the distinct vars, never the call-site count). **Two latent landmines
   remain**, disclosed not silenced:
   - The orphaned first `QueryL0ListCapped` object from `init()` is unreachable
     (the var was reassigned) — harmless dead memory at startup, but it IS the
     object the append-in-`newCounter` path would have duplicated into the slice
     (the §0.d panic this change averted).
   - If a future change ever calls `telemetry.Init(realMeter)` (the anti-scope-
     creep open item, §6.4), `rebuildCounters` would reassign
     `QueryL0ListCapped` to... nothing (the omission) → the var becomes nil →
     `query.go:225`'s `if telemetry.QueryL0ListCapped != nil` guard silently
     stops counting the cap-hit disclosure. A future change that wires `Init`
     MUST add `QueryL0ListCapped = newCounter(...)` to `rebuildCounters` (and
     dedup the `init()` double) before arming the OTel callback. Recorded so
     that change does not rediscover it as a silent counter-drop bug.

3. **The T3 residual: 62 allocs/Collect, NOT 0.** The bridge's zero-alloc
   TARGET is unmet by the MEASURED count; the honest split (isolated via
   throwaway probes, then deleted):
   - **12 allocs/run** — the bridge's OWN read path: `c.Value()` × 12 counters.
     `Value()` boxes its `float64` return through the method-boundary interface
     dispatch (the 64-stripe `math.Float64frombits` decode-sum loop + the float
     return escapes the method). 12 counters × 1 = 12.
   - **50 allocs/run** — `prometheus.MustNewConstMetric` × 12 = ~4.17/counter
     (the boxed float, the `*dto.Metric`, the label-pairs slice, the write into
     the channel). This is **prometheus-internal**, off the data path, on the
     default 15s scrape cadence — NOT a bridge defect.
   The bridge's **structural** zero-alloc invariant it CAN guarantee — the Desc
   set built ONCE at `NewTelemetryBridge` and reused across every Collect, never
   rebuilt — is asserted (the desc map identity is stable across scrapes; no
   churning). T3 exists to MEASURE, not to gloat over an unmeasured zero; the
   guard passes because it discloses honestly, not because it hit 0. A future
   change that wants the scrape path at 0-alloc must elide the const-metric
   constructor (a custom `prometheus.Metric` impl that reuses a pooled
   `*dto.Metric`) — out of scope here; recorded.

4. **Anti-scope-creep: `telemetry.Init` stays uncalled. (§0.a)** Wiring a real
   OTel provider at boot is a DIFFERENT change — it arms the observables + the
   `lastReported` callback. THIS change closes the prometheus egress; it must
   be safe WITH nil OTel AND with a future non-nil OTel. Calling `Init` here
   would couple the two layers (and, per §6.2, the `rebuildCounters` omission
   would drop the `QueryL0ListCapped` counter). The cmd imports
   `internal/telemetry` for `Counters()` transitively (via the bridge in
   `pkg/metrics`), **never `Init`**; T6's grep asserts `Init` stays at zero
   production callers. The cmd does not even directly import
   `internal/telemetry` — the bridge is the sole importer.

---

## §8. Self-adversarial — what this change does NOT close

- **The OTel layer is still a no-op.** `telemetry.Init` is uncalled; no OTel
  observable is ever registered; no OTel exporter is wired. This change closes
  the PROMETHEUS egress only. A future change that wires OTel would bind a real
  Meter at boot — and MUST, per §6.2, fix the `rebuildCounters`
  `QueryL0ListCapped` omission before arming the callback (or the cap-hit
  counter silently drops). The bridge is already safe for that change
  (cumulative + never-touches-`lastReported`), but the registry construction
  body is not.

- **The scrape path is NOT zero-alloc (§6.3).** 62 allocs/Collect (12 bridge-read
  + 50 const-metric ctor). Off the data path, on the 15s cadence — acceptable
  for a control surface, but NOT the engine's 0-alloc standard. A future change
  that wants the scrape at 0 pools a `*dto.Metric` and custom-implements
  `prometheus.Metric`.

- **The "24" miscount was in my own design notes.** A second read of the bytes caught it
  before shipping (the T2 in-package guard asserts 12, not 24) — the same
  discipline ADR-0022 records: prose corrected against bytes before any line
  ships. The lesson is that byte-verification is NOT optional even when the
  design is written down in advance; the counter counts and the API names were
  both wrong in the notes and both corrected before shipping.

- **No live reaper-orphan probe across a `*LocalFS`.** I considered driving a
  live reaper-orphan across `pkg/durability` instead of the scrape-layer
  guards. T1b drives the `L0ReapSkippedOrphan` counter at the scrape layer
  (Inc → the series advances on `/metrics`), which proves the
  operator-observability of the signal; it does NOT drive a real reaper orphan
  across a `*LocalFS` end-to-end. The reaper's own gate tests (ADR-0021)
  already drove that path; the bridge's job is the egress, and T1b proves the
  egress carries the signal. A future end-to-end harness (reaper-orphan →
  `*LocalFS` → /metrics scrape) is an open item, not an obligation here.

---

## Status: ACCEPTED. Shipped cumulative, single-source-of-truth, nil-OTel-safe. 12 supremum_* series reach /metrics (incl. the safety-critical orphan guard). None of the five core files touched.
