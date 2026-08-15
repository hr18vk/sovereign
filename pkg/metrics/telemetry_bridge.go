package metrics

import (
	"strings"

	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

// TelemetryBridge is the prometheus.Collector that exposes the engine's
// internal/telemetry LongAdder counters (the 12 distinct supremum.* counters)
// as cumulative prometheus series on /metrics. It closes the
// OPERATOR-BLINDNESS defect the engine carried since Day-13: the data plane
// Add()/Inc() on every flush / compaction / prune / reap touched those
// counters, but NONE reached /metrics — including the SAFETY-CRITICAL
// supremum_compaction_l0_reap_manifests_skipped_orphan (the Stage-C reaper
// guard's "I refused to delete — an L1 went missing, the backstop is
// preserved" operator signal). A storage outage was silent. See ADR-0023.
//
// WHY THIS IS A BRIDGE, NOT A RECORDER:
//
//   - The 24 supremum.* counters live as wait-free 64-stripe LongAdders in
//     internal/telemetry (telemetry.go). They are dimensionless singletons with
//     NO variable labels, built once at package init. The pkg/metrics Recorder
//     is a DIFFERENT surface (the sovereign_* series — ingest verdicts,
//     latency histogram, gossip rounds, convergence gauges) built around
//     labelled prometheus instruments. The bridge does NOT touch the Recorder;
//     it enumerates telemetry.Counters() (the single source of truth in
//     internal/telemetry/registry.go) and projects each onto a constCounter /
//     constGauge.
//
//   - The two series coexist by NAME: the Recorder owns sovereign_* (underscore
//     already), the bridge owns supremum_* mapped from supremum.* (dots -> '_').
//     They never collide (different prefixes; verified — no sovereign_ name
//     starts with "supremum").
//
// THE DOUBLE-COUNT TRAP (the load-bearing invariant, ADR-0023 §0.b):
//
//   - The OTel int64-observable path (telemetry.go registerInt64Counter) reports
//     the PER-INTERVAL DELTA, not the cumulative: its callback does
//     `delta := now - int64(prev); lastReported.CompareAndSwap(prev, now)`.
//     prometheus counters are MONOTONE-CUMULATIVE by contract (the prometheus
//     SERVER computes the rate across consecutive scrapes; the bridge must NOT
//     pre-delta). So:
//   - Collect reports CUMULATIVE (Counter.Value() — the 64-stripe sum).
//   - Collect NEVER reads lastReported. lastReported belongs to the OTel
//     callback; reading it from the bridge couples the bridge to the OTel
//     cadence and tears the delta if OTel fires between scrapes. Day 21
//     (ADR-0026) armed telemetry.Init at boot with a real OTel SDK
//     MeterProvider (gated --otel; the callback DOES fire when armed), so the
//     OTel layer advances lastReported on its interval. A naive bridge that
//     touched the field would double-count OR diverge from the OTel exporter.
//     This bridge is safe WHETHER OR NOT an OTel provider is bound:
//     read cumulative, never touch lastReported. The two-exporter separation
//     (ADR-0023 §0.d, refreshed ADR-0026 §3) keeps the OTel reader on a
//     SEPARATE destination from this bridge's prometheus Registry — the OTel
//     stream (delta via lastReported) and the bridge stream (cumulative via
//     Value()) never collide at /metrics. Calling telemetry.Init is OUT OF
//     SCOPE for THIS package (the bridge): arming it is the cmd binary's job
//     (cmd/sovereign-node/otel.go via armOTel), NOT the bridge's.
//
// ALLOCATION (Law: ZERO on the data plane — and here, zero on the SCRAPE path):
//
//   - The bridge touches ONLY the scrape path (Collect), never Add/Inc. The
//     64-stripe LongAdder is untouched and unexported. The per-scrape cost is
//     12 * (64-stripe float-bit decode sum) — OFF the hot path, on the scrape
//     cadence (default 15s).
//   - The prometheus.Desc set is built ONCE at NewTelemetryBridge (one Desc per
//     counter name) and reused across every Collect. Collect must NOT build a
//     Desc per call (that would allocate per scrape). The T3 tooth gates
//     AllocsPerRun(Collect) == 0; if promhttp.MustNewConst{Counter,Gauge} itself
//     allocates non-zero, the residual is MEASURED and disclosed in ADR-0023 §6
//     (never gamed by skipping the const-metric build — that would be a
//     fabrication).
type TelemetryBridge struct {
	// descs is the frozen per-metric-name Desc set, built once at
	// NewTelemetryBridge and reused across every Collect (the zero-alloc
	// invariant — Collect never builds a Desc). Keyed by the MAPPED prometheus
	// name (dots -> '_') so Collect can look up by telemetry.Name() after mapping
	// WITHOUT allocating (no map rebuild per scrape).
	descs map[string]*prometheus.Desc

	// counters is the telemetry.Counters() snapshot taken at
	// NewTelemetryBridge, frozen thereafter. The slice is append-only-after-
	// construction in telemetry, so holding a reference is stable across scrapes.
	// Iterating it at Collect time reads each Counter's cumulative Value() —
	// the read path only; the data plane is untouched.
	counters []*telemetry.Counter
}

// mapPromName maps a telemetry metric name ("supremum.l0.arrow_serial_bytes",
// dotted) onto a legal prometheus metric name ("supremum_l0_arrow_serial_bytes",
// underscored). prometheus forbids '.' in metric names; '.' -> '_' is the only
// transformation. The bridge's supremum_* series is ADDITIVE to the Recorder's
// sovereign_* series (different prefix); do NOT rename to match either.
func mapPromName(telemetryName string) string {
	return strings.ReplaceAll(telemetryName, ".", "_")
}

// NewTelemetryBridge builds the bridge Collector against the frozen
// telemetry.Counters() snapshot and pre-builds the Desc set (one per counter
// name). The Desc set is the bridge's only allocated state; Collect reuses it
// without rebuilding. Call this ONCE per process (the cmd does so after
// NewExporter, ADR-0023 §1.1.d). It does NOT call telemetry.Init — the cmd
// does that (Day 21 ADR-0026, gated --otel, BEFORE NewTelemetryBridge so the
// bridge captures the post-Init SSoT slice). The bridge reads whatever
// counters Counters() holds (package-init built, OR rebuilt by Init), so it
// is safe whether meter is nil (init default) or bound (Init armed).
func NewTelemetryBridge() *TelemetryBridge {
	counters := telemetry.Counters()
	b := &TelemetryBridge{
		descs:    make(map[string]*prometheus.Desc, len(counters)),
		counters: counters,
	}
	for _, c := range counters {
		promName := mapPromName(c.Name())
		// The counters are dimensionless singletons today: no variable labels
		// (an empty LabelNames slice, NOT nil-with-LabelValues later — the
		// const-metric constructors reject a non-empty LabelValues with an
		// empty LabelNames). The Desc carries the telemetry Description() as
		// Help + the unit folded into the name where the OTel unit is bytes
		// (we keep the name verbatim from telemetry; the unit is NOT appended
		// to avoid a name/Help drift — telemetry names already encode the
		// semantic, e.g. "_bytes").
		b.descs[promName] = prometheus.NewDesc(
			promName,
			c.Description(),
			nil, // no variable labels — dimensionless singletons
			nil, // no const labels
		)
	}
	return b
}

// Describe emits one prometheus.Desc per counter into ch. prometheus uses
// Describe for cardinality discovery (it never calls Collect on a Collector
// whose Describe emitted an undescended error). We emit the frozen Desc set —
// NO per-Describe allocation (the Descs are pre-built at
// NewTelemetryBridge). The set is stable because telemetry.Counters() is
// frozen after construction.
func (b *TelemetryBridge) Describe(ch chan<- *prometheus.Desc) {
	// Iterate the frozen counters slice (NOT the desc map) so the Describe
	// order is stable + matches Collect — and so a future counter added to
	// telemetry is reflected here WITHOUT a code edit (the SSoT property,
	// T2). Map each name to look up the pre-built Desc.
	for _, c := range b.counters {
		ch <- b.descs[mapPromName(c.Name())]
	}
}

// Collect emits one const prometheus.Metric per counter into ch. CRITICAL
// INVARIANTS (each load-bearing, gated by a tooth):
//
//   - CUMULATIVE, NOT DELTA (T1, the §0.b trap tooth): counters (modeCounter)
//     use MustNewConstMetric(desc, CounterValue, Value()) — the 64-stripe
//     cumulative sum. The prometheus server computes the rate across scrapes;
//     the bridge MUST NOT pre-delta. gauges (modeGauge) use
//     MustNewConstMetric(desc, GaugeValue, Value()) (last-Set). A
//     delta-reporting bridge would show an increment ONCE then reset on the
//     next scrape — T1 Incs a counter between scrapes and asserts the
//     cumulative ADVANCES by exactly the delta (not resets to delta).
//     (client_golang v1.23.2 exposes const counters/gauges via the shared
//     MustNewConstMetric + ValueType enum — there is no MustNewConstCounter /
//     MustNewConstGauge symbol in this version; the prompt's shorthand is the
//     longhand name of the dispatch the enum performs. ADR-0023 §3.)
//
//   - NEVER touches lastReported (T4): only Counter.Value() is read. T4 Incs a
//     counter N times, scrapes via the bridge, asserts bridge-value == N
//     THROUGH Value(), AND asserts lastReported is UNCHANGED (0) — pre-empting
//     the production double-count when a future fork binds a real OTel Meter.
//
//   - ZERO ALLOC PER COLLECT (T3): the Desc set is pre-built; the const-metric
//     constructors are the only per-Collect allocation surface. T3 measures
//     AllocsPerRun(Collect); if non-zero, ADR-0023 §6 discloses the residual.
func (b *TelemetryBridge) Collect(ch chan<- prometheus.Metric) {
	for _, c := range b.counters {
		desc := b.descs[mapPromName(c.Name())]
		value := c.Value() // cumulative for modeCounter, last-Set for modeGauge
		// MustNewConstMetric dispatches by ValueType: CounterValue emits a
		// prometheus counter (monotone-cumulative; the server derives the
		// rate), GaugeValue emits a gauge (last-writer-wins). No labelValues
		// (dimensionless singletons — the Desc carried nil LabelNames, so the
		// const metric MUST carry zero label values too, or the constructor
		// panics on arity mismatch).
		switch c.Mode() {
		case telemetry.ModeCounter:
			ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value)
		case telemetry.ModeGauge:
			ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value)
		}
	}
}

// Compile-time interface assertion: TelemetryBridge satisfies
// prometheus.Collector (Describe + Collect with the exact channel signatures).
// A drift in the method set is a compile error here, not a silent scrape failure.
var _ prometheus.Collector = (*TelemetryBridge)(nil)
