package metrics

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Exporter owns the per-process Prometheus Registry and exposes the /metrics
// scrape handler. The Registry is PER-CMD-PROCESS, NOT the global
// prometheus.DefaultRegisterer: the global registerer PANICS on duplicate
// registration across tests (two Recorder instances registering the same
// instrument names), and a single shared global is the wrong ownership boundary
// for a binary that may construct the surface once per process. The
// per-process Registry is the root-cause fix (ADR-0008 §3).
//
// The Exporter registers the Recorder's four hot-path instruments plus three
// poller-fed gauges (ingest pps, convergence lag, convergence roots-equal).
// The gauges are Set-style: a 1s poller in the cmd wiring reads
// gossiper.ConvergenceLag() and the verdict-counter delta off the hot path and
// calls the Exporter's Set methods. The hot path never touches the gauges.
type Exporter struct {
	reg      *prometheus.Registry
	recorder *Recorder

	ingestPPS          prometheus.Gauge
	convergenceLag     prometheus.Gauge
	convergenceRootsEq prometheus.Gauge

	// ppsState holds the last counter snapshot + timestamp the poller read,
	// so the pps gauge is computed as delta(counter)/delta(t). Guarded by the
	// poller's single-writer discipline (one goroutine); reads under atomic
	// for the scrape path's safety.
	ppsLastCount uint64 // atomic
	ppsLastTime  int64  // atomic — unix-nano
}

// NewExporter constructs a fresh per-process Registry, a Recorder bound to it,
// and the three poller-fed gauges. Constructing two Exporters (two Registries)
// MUST NOT panic — the per-process Registry is the fixture for
// TestExportersRegister (G03.b).
func NewExporter() *Exporter {
	reg := prometheus.NewRegistry()
	rec := NewRecorder(reg)
	e := &Exporter{reg: reg, recorder: rec}
	e.ingestPPS = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sovereign_ingest_pps",
		Help: "Instantaneous ingest frames/sec, computed by the 1s poller from the sovereign_ingest_verdicts_total delta over the poll interval.",
	})
	e.convergenceLag = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sovereign_convergence_lag_seconds",
		Help: "Time since the mesh last reached a stable MerkleRoot across two consecutive sweeps (gossiper.ConvergenceLag). 0 when never converged or just-converged; grows while the mesh diverges.",
	})
	e.convergenceRootsEq = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sovereign_convergence_roots_equal",
		Help: "Binary convergence indicator: 1.0 when the 2-node MerkleRoots match per the last sweep, 0.0 otherwise. A 3-node quorum-aware gauge is a future track.",
	})
	reg.MustRegister(e.ingestPPS, e.convergenceLag, e.convergenceRootsEq)
	return e
}

// Registry returns the per-process Registry (test seam + the scrape handler
// binds to it).
func (e *Exporter) Registry() *prometheus.Registry { return e.reg }

// Recorder returns the hot-path Recorder (the accept loop observes through it).
func (e *Exporter) Recorder() *Recorder { return e.recorder }

// Handler returns the /metrics scrape handler. It is promhttp.HandlerFor bound
// to the per-process Registry; promhttp is non-blocking (the scrape iterates
// instruments, no hot-path lock). The handler is attached to the SAME plain-HTTP
// mux as /livecheck (one server, one mux, the --metrics-addr flag already binds
// it) — /metrics is ops debug, NOT the data plane (the C1 boundary).
func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.reg, promhttp.HandlerOpts{
		// Disable the default Go runtime/process collector: the engine's
		// observability surface is the seven sovereign_* series, not the
		// process metrics. Keeping them off avoids a surprise scrape-cost spike
		// and keeps the gate's seven-series grep unambiguous.
		Registry: e.reg,
	})
}

// SetIngestPPS sets the instantaneous frames/sec gauge. Called by the 1s
// poller off the hot path.
func (e *Exporter) SetIngestPPS(pps float64) { e.ingestPPS.Set(pps) }

// SetConvergenceLag sets the convergence-lag gauge (seconds). Called by the
// 1s poller from gossiper.ConvergenceLag().
func (e *Exporter) SetConvergenceLag(lag time.Duration) {
	e.convergenceLag.Set(lag.Seconds())
}

// SetConvergenceRootsEqual sets the binary roots-equal gauge (1.0 match, 0.0
// diverged). Called by the 1s poller.
func (e *Exporter) SetConvergenceRootsEqual(equal bool) {
	if equal {
		e.convergenceRootsEq.Set(1.0)
	} else {
		e.convergenceRootsEq.Set(0.0)
	}
}

// ObserveVerdictDelta feeds the pps gauge: the poller reads the verdict-counter
// total, and this helper computes frames/sec from the delta since the last
// call. It is OFF the hot path (the 1s poller). The counter total is the sum
// across all six verdict labels (every frame, accepted or dropped, is a frame).
func (e *Exporter) ObserveVerdictDelta(now time.Time) float64 {
	// Sum every verdict label's counter value (the full frame count).
	var total uint64
	if cv := e.recorder.IngestVerdictCounter(); cv != nil {
		for _, label := range verdictLabels {
			m, err := cv.GetMetricWithLabelValues(string(label))
			if err != nil {
				continue
			}
			// prometheus counters expose their value via the dto; the
			// test-asserted path is to read through Write. For the poller we
			// use the lightweight process-collector-free read below.
			total += readCounterValue(m)
		}
	}
	lastCount := atomic.LoadUint64(&e.ppsLastCount)
	lastNs := atomic.LoadInt64(&e.ppsLastTime)
	nowNs := now.UnixNano()
	atomic.StoreUint64(&e.ppsLastCount, total)
	atomic.StoreInt64(&e.ppsLastTime, nowNs)
	if lastNs == 0 {
		return 0 // first sample: no delta yet
	}
	dt := float64(nowNs-lastNs) / float64(time.Second)
	if dt <= 0 {
		return 0
	}
	return float64(total-lastCount) / dt
}

// verdictLabels is the full ordered label set (every frame, accepted or
// dropped, increments exactly one of these).
var verdictLabels = []VerdictLabel{
	VerdictAccept,
	VerdictDropMalformed,
	VerdictDropRate,
	VerdictDropClock,
	VerdictDropDepth,
	VerdictDropVerify,
}
