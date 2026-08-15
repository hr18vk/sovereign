// Package metrics is the production observability surface for the Sovereign
// Engine. It exposes a hot-path Recorder (the wait-free ingest/verify
// instruments the accept loop observes) and a per-process Prometheus Registry
// scraped at /metrics.
//
// The two physical facts that shape this package (see ADR-0008 §0):
//
//  1. The receive frame rate is VERIFY-BOUND (~533K frames/sec/cluster at 32c,
//     bounded by the ~60us Ed25519 Verify), NOT the 57.6M in-memory arena path.
//     Hot-path counter contention is therefore LOW; whether a single Prometheus
//     atomic counter per frame suffices is a MEASUREMENT question settled by
//     BenchmarkRecordIngest (the FACT-1 settle bench). The internal/telemetry
//     LongAdder is the documented fallback if the bench exceeds the budget.
//
//  2. The ingest-latency histogram is BIMODAL: frames rejected at the cheap
//     gates (DropMalformed/DropRate/DropClock/DropDepth) return in nanoseconds
//     (sub-1us); frames that pass to Verify+Apply return in ~60us. The bucket
//     set [1e-7..1e-4] seconds therefore shows TWO populations — the
//     cheap-gates-before-verify invariant is READABLE in the metrics, not just
//     in the source. The p99 is ~60us (verify-bound) on the single-delta path,
//     NOT sub-1us; the sub-1us-per-delta unlock is the Day-5 batched-delta path.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/hr18vk/supremum/pkg/receive"
)

// IngestLatencyBuckets is the Battle-Plan histogram bucket set (seconds). It
// spans the two populations: the sub-1us cheap-gate-reject population lands in
// le="1e-6" (and below); the ~60us verify-pass population lands in le="1e-4".
// The bucket boundaries are the bimodality tooth — an operator reads the real
// p99 from /metrics, not a fabricated sub-1us claim.
var IngestLatencyBuckets = []float64{
	1e-7, // 100ns  — the cheap-gate reject floor
	2e-7, // 200ns
	5e-7, // 500ns
	1e-6, // 1us    — the cheap-gate-reject population ceiling
	2e-6, // 2us
	5e-6, // 5us
	1e-5, // 10us
	5e-5, // 50us   — the verify-pass population floor
	1e-4, // 100us  — the ~60us verify-bound p99 lands here
}

// VerdictLabel is the label value for the per-gate decision counter. It mirrors
// receiver.Verdict.String() (receiver.go:111) so the six-value label set is
// FIXED and bounded (no label explosion). The Recorder accepts the typed
// receiver.Verdict and maps it to the label string itself, so the caller never
// hand-writes a label.
type VerdictLabel string

const (
	VerdictAccept        VerdictLabel = "Accept"
	VerdictDropMalformed VerdictLabel = "DropMalformed"
	VerdictDropRate      VerdictLabel = "DropRate"
	VerdictDropClock     VerdictLabel = "DropClock"
	VerdictDropDepth     VerdictLabel = "DropDepth"
	VerdictDropVerify    VerdictLabel = "DropVerify"
)

// verdictLabel maps the typed receiver.Verdict to its label string. It is the
// single source of truth for the label set; the const block above is the
// human-readable mirror kept in lockstep with receiver.Verdict.String().
func verdictLabel(v receive.Verdict) VerdictLabel {
	switch v {
	case receive.Accept:
		return VerdictAccept
	case receive.DropMalformed:
		return VerdictDropMalformed
	case receive.DropRate:
		return VerdictDropRate
	case receive.DropClock:
		return VerdictDropClock
	case receive.DropDepth:
		return VerdictDropDepth
	case receive.DropVerify:
		return VerdictDropVerify
	default:
		return VerdictLabel(v.String())
	}
}

// Recorder is the hot-path observability instrument set. It holds the
// Prometheus instruments the accept loop observes per frame. The hot-path
// methods (RecordIngest, RecordVerify, IncGossipRound) are NON-BLOCKING on the
// data plane: they call the prometheus client's atomic Observe/Inc, which is
// wait-free under the verify-bound receive rate (FACT 1). The
// BenchmarkRecordIngest gate settles whether Prometheus-direct suffices or the
// internal/telemetry LongAdder fallback must fire.
//
// The six verdict counters are PRE-RESOLVED at construction (verdictCounters):
// a CounterVec's WithLabelValues does a map lookup on EVERY call (~60ns of the
// uncached 102ns/op), so the hot path caches the six prometheus.Counter values
// and indexes them by the typed Verdict int — the hot-path Inc is a single
// atomic add with NO label lookup. The CounterVec is still registered (it owns
// the HELP/TYPE + the label dimension); the cached counters are the same
// underlying metric objects.
//
// The convergence-lag gauge is NOT recorded here: it is fed from an EXTERNAL
// 1s poller (the cmd wiring) that reads gossiper.ConvergenceLag() off the hot
// path. The Recorder owns only the instruments the hot path touches.
type Recorder struct {
	reg             prometheus.Registerer
	ingestHist      prometheus.Histogram            // sovereign_ingest_latency_seconds
	verifyHist      prometheus.Histogram            // sovereign_verify_seconds
	verdictCount    *prometheus.CounterVec          // sovereign_ingest_verdicts_total{verdict=...}
	verdictCounters [numVerdicts]prometheus.Counter // pre-resolved per-verdict counters (hot-path cache)
	gossipRounds    prometheus.Counter              // sovereign_gossip_rounds_total
}

// numVerdicts is the count of Verdict enum values (receiver.go:81 — six). The
// cached-counter array is indexed by the typed Verdict int, so it is bounded
// by the enum cardinality (no map, no label lookup on the hot path).
const numVerdicts = 6

// NewRecorder constructs the hot-path instruments and registers them against
// the supplied Registerer (a per-process Registry, NOT the global
// DefaultRegisterer — the per-process Registry is the root-cause fix for the
// duplicate-registration panics across tests; see ADR-0008 §3). It uses
// promauto so a registration collision panics loudly at construction (a
// programming error), never silently mis-registers.
func NewRecorder(reg prometheus.Registerer) *Recorder {
	factory := promauto.With(reg)
	r := &Recorder{reg: reg}
	r.ingestHist = factory.NewHistogram(prometheus.HistogramOpts{
		Name:    "sovereign_ingest_latency_seconds",
		Help:    "Per-frame ingest latency from HandleFrame entry to verdict. Bimodal: cheap-gate rejects land sub-1us (le=1e-6); verify-passed frames land ~60us (le=1e-4, the Ed25519 verify-bound p99 on the single-delta path). The sub-1us-per-delta unlock is the batched-delta path (future track).",
		Buckets: IngestLatencyBuckets,
	})
	r.verifyHist = factory.NewHistogram(prometheus.HistogramOpts{
		Name:    "sovereign_verify_seconds",
		Help:    "Per-frame Ed25519 VerifyCRDTFrame latency (~60us verify-bound at 32c, circl v1.6.4 ZIP-215). The receive rate is bounded by this cost, not the arena path.",
		Buckets: IngestLatencyBuckets,
	})
	r.verdictCount = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "sovereign_ingest_verdicts_total",
		Help: "Per-gate ingest decision count, keyed by the six-value Verdict label (Accept/DropMalformed/DropRate/DropClock/DropDepth/DropVerify). The label set is fixed and bounded (no cardinality explosion).",
	}, []string{"verdict"})
	r.gossipRounds = factory.NewCounter(prometheus.CounterOpts{
		Name: "sovereign_gossip_rounds_total",
		Help: "Anti-entropy sweep rounds executed by the mesh Gossiper.",
	})
	// Materialize all six verdict labels at construction so the CounterVec is
	// always scrapeable (a CounterVec with zero observed label values emits NO
	// HELP/TYPE — the gate G03.c asserts the seven series are scrapeable with
	// HELP+TYPE from a cold start). The six-value label set is FIXED and
	// bounded (no cardinality explosion); pre-initializing it is the honest
	// representation of the fixed Verdict enum. The SAME call pre-resolves the
	// cached per-verdict counters the hot path indexes by the Verdict int, so
	// RecordIngest does a single atomic Inc with NO label map lookup.
	for i, label := range verdictLabels {
		r.verdictCounters[i] = r.verdictCount.WithLabelValues(string(label))
	}
	return r
}

// RecordIngest observes a single frame's ingest latency and increments the
// per-gate verdict counter. It is the hot-path observation seam: the accept
// loop wraps HandleFrame with `start := time.Now(); av := recv.HandleFrame(f);
// recorder.RecordIngest(time.Since(start), av.Verdict)` (Option B — the
// observer wrapper; receiver.go stays byte-locked). Both the Observe and the
// Inc are atomic per the prometheus client contract. The verdict counter is
// the pre-resolved cached counter (no WithLabelValues map lookup on the hot
// path); the Verdict int indexes the fixed six-element array directly.
func (r *Recorder) RecordIngest(latency time.Duration, v receive.Verdict) {
	r.ingestHist.Observe(latency.Seconds())
	if idx := int(v); idx >= 0 && idx < numVerdicts {
		r.verdictCounters[idx].Inc()
	} else {
		// An out-of-range Verdict is a programming error (the enum is fixed at
		// six); fall back to the label path so it is still attributed, not lost.
		r.verdictCount.WithLabelValues(string(verdictLabel(v))).Inc()
	}
}

// RecordVerify observes a single Ed25519 VerifyCRDTFrame latency. It is called
// from the verify-path observation seam (the ~60us population feeder).
func (r *Recorder) RecordVerify(latency time.Duration) {
	r.verifyHist.Observe(latency.Seconds())
}

// IncGossipRound increments the sweep-round counter. Called once per
// AntiEntropySweep round (off the ingest hot path).
func (r *Recorder) IncGossipRound() {
	r.gossipRounds.Inc()
}

// IngestVerdictCounter exposes the verdict CounterVec so the cmd poller can
// compute instantaneous frames/sec from the counter delta over the poll
// interval (the sovereign_ingest_pps gauge feeder). It is read OFF the hot
// path (the 1s poller), never per-frame.
func (r *Recorder) IngestVerdictCounter() *prometheus.CounterVec {
	return r.verdictCount
}
