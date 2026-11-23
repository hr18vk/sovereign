// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package metrics exposes ingest, verification, gossip, and convergence
// instruments through a Prometheus registry and an HTTP scrape handler.
//
// Ingest observations form two latency populations. Rejections at the early
// admission gates avoid signature verification, while accepted frames include
// Ed25519 verification and CRDT application. IngestLatencyBuckets covers both
// ranges so a scrape preserves that distinction (ADR-0008).
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/hr18vk/sovereign/pkg/receive"
)

// IngestLatencyBuckets covers both early admission rejections and frames that
// reach signature verification. Values are seconds; the lower buckets resolve
// the cheap rejection path and the upper buckets include the verify path.
var IngestLatencyBuckets = []float64{
	1e-7, // 100ns
	2e-7, // 200ns
	5e-7, // 500ns
	1e-6, // 1us
	2e-6, // 2us
	5e-6, // 5us
	1e-5, // 10us
	5e-5, // 50us
	1e-4, // 100us
}

// VerdictLabel is the label value for the per-gate decision counter. Its six
// values mirror receive.Verdict.String, bounding the label set. Recorder maps
// the typed verdict to a label so callers do not construct label strings.
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

// Recorder holds the Prometheus instruments observed during frame processing.
// RecordIngest and RecordVerify update histograms and counters through the
// client library; IncGossipRound records anti-entropy sweeps. The benchmarks in
// recorder_test.go measure their overhead.
//
// Construction resolves all six verdict counters once. RecordIngest indexes
// this array directly instead of performing a CounterVec label lookup for each
// frame. The registered CounterVec and cached entries refer to the same metric
// objects, so scrapes retain the verdict label dimension.
//
// Exporter owns the convergence gauges because the command's poller updates
// them separately from frame processing.
type Recorder struct {
	reg             prometheus.Registerer
	ingestHist      prometheus.Histogram            // sovereign_ingest_latency_seconds
	verifyHist      prometheus.Histogram            // sovereign_verify_seconds
	verdictCount    *prometheus.CounterVec          // sovereign_ingest_verdicts_total{verdict=...}
	verdictCounters [numVerdicts]prometheus.Counter // cached per-verdict counters
	gossipRounds    prometheus.Counter              // sovereign_gossip_rounds_total
}

// numVerdicts bounds the cached-counter array by the receive.Verdict enum.
const numVerdicts = 6

// NewRecorder constructs the instrument set and registers it with reg.
// promauto panics on a duplicate registration, making a name collision visible
// at construction rather than leaving an incomplete registry (ADR-0008).
func NewRecorder(reg prometheus.Registerer) *Recorder {
	factory := promauto.With(reg)
	r := &Recorder{reg: reg}
	r.ingestHist = factory.NewHistogram(prometheus.HistogramOpts{
		Name:    "sovereign_ingest_latency_seconds",
		Help:    "Per-frame ingest latency from HandleFrame entry to verdict. Early admission rejects occupy the lower buckets; frames that reach Ed25519 verification occupy the upper buckets.",
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
	// Materializing the bounded label set makes every verdict visible in a cold
	// scrape and populates the cached counters used by RecordIngest.
	for i, label := range verdictLabels {
		r.verdictCounters[i] = r.verdictCount.WithLabelValues(string(label))
	}
	return r
}

// RecordIngest observes one frame's latency and increments its verdict counter.
// Known verdicts index the cached counter array directly. An unknown verdict
// falls back to WithLabelValues so the observation is still counted.
func (r *Recorder) RecordIngest(latency time.Duration, v receive.Verdict) {
	r.ingestHist.Observe(latency.Seconds())
	if idx := int(v); idx >= 0 && idx < numVerdicts {
		r.verdictCounters[idx].Inc()
	} else {
		r.verdictCount.WithLabelValues(string(verdictLabel(v))).Inc()
	}
}

// RecordVerify observes the latency of one Ed25519 VerifyCRDTFrame call.
func (r *Recorder) RecordVerify(latency time.Duration) {
	r.verifyHist.Observe(latency.Seconds())
}

// IncGossipRound increments the anti-entropy sweep counter once per round.
func (r *Recorder) IncGossipRound() {
	r.gossipRounds.Inc()
}

// IngestVerdictCounter returns the verdict CounterVec for the command's poller,
// which computes sovereign_ingest_pps from successive totals.
func (r *Recorder) IngestVerdictCounter() *prometheus.CounterVec {
	return r.verdictCount
}
