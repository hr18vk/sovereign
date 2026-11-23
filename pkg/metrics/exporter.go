// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Exporter owns a Prometheus registry and its /metrics handler. Each Exporter
// has independent instruments, so constructing another one does not collide
// with names already registered elsewhere in the process (ADR-0008).
//
// The registry contains the Recorder instruments and three gauges: ingest rate,
// convergence lag, and convergence root equality. A one-second poller in the
// command wiring updates the gauges; the receive path does not access them.
type Exporter struct {
	reg      *prometheus.Registry
	recorder *Recorder

	ingestPPS          prometheus.Gauge
	convergenceLag     prometheus.Gauge
	convergenceRootsEq prometheus.Gauge

	// The poller stores its previous count and timestamp so it can compute a
	// rate from successive samples. A single poller writes both fields; atomic
	// accesses also make scrapes safe.
	ppsLastCount uint64 // atomic
	ppsLastTime  int64  // atomic Unix timestamp in nanoseconds
}

// NewExporter constructs an independent registry, a Recorder, and the three
// poller-fed gauges. Separate Exporters may register the same instrument names
// without affecting one another.
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
		Help: "Binary convergence indicator: 1.0 when the two nodes' Merkle roots match in the latest sweep, 0.0 otherwise.",
	})
	reg.MustRegister(e.ingestPPS, e.convergenceLag, e.convergenceRootsEq)
	return e
}

// Registry returns the registry used by the scrape handler and tests.
func (e *Exporter) Registry() *prometheus.Registry { return e.reg }

// Recorder returns the instrument set used by the accept loop.
func (e *Exporter) Recorder() *Recorder { return e.recorder }

// Handler returns a Prometheus scrape handler for this Exporter's registry.
// The command serves it from the operational HTTP listener configured by
// --metrics-addr, separately from the data plane.
func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.reg, promhttp.HandlerOpts{
		// A new Registry has no Go runtime or process collectors. Only the
		// instruments registered by this package and its callers are exposed.
		Registry: e.reg,
	})
}

// SetIngestPPS sets the ingest-rate gauge. The poller calls it outside the
// frame-processing path.
func (e *Exporter) SetIngestPPS(pps float64) { e.ingestPPS.Set(pps) }

// SetConvergenceLag records the value returned by gossiper.ConvergenceLag in
// seconds.
func (e *Exporter) SetConvergenceLag(lag time.Duration) {
	e.convergenceLag.Set(lag.Seconds())
}

// SetConvergenceRootsEqual records 1 for equal roots and 0 otherwise.
func (e *Exporter) SetConvergenceRootsEqual(equal bool) {
	if equal {
		e.convergenceRootsEq.Set(1.0)
	} else {
		e.convergenceRootsEq.Set(0.0)
	}
}

// ObserveVerdictDelta computes frames per second from the total across all
// verdict labels and the previous sample. The first sample and non-increasing
// timestamps return zero. It is intended for the poller, not frame processing.
func (e *Exporter) ObserveVerdictDelta(now time.Time) float64 {
	var total uint64
	if cv := e.recorder.IngestVerdictCounter(); cv != nil {
		for _, label := range verdictLabels {
			m, err := cv.GetMetricWithLabelValues(string(label))
			if err != nil {
				continue
			}
			// Counter.Write exposes the current value without adding another
			// counter or reading any receive-path state.
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

// verdictLabels lists the bounded set of outcomes in counter-cache order.
var verdictLabels = []VerdictLabel{
	VerdictAccept,
	VerdictDropMalformed,
	VerdictDropRate,
	VerdictDropClock,
	VerdictDropDepth,
	VerdictDropVerify,
}
