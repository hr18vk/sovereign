package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// readCounterValue reads a prometheus counter's current value via its Write
// method (the dto.Metric path). It is OFF the hot path — used only by the 1s
// poller that feeds the sovereign_ingest_pps gauge. The Write call is the
// prometheus client's sanctioned read; it does not contend with the hot-path
// atomic Inc (the counter's internal value is read under its own lock, not the
// ingest path's).
func readCounterValue(m prometheus.Metric) uint64 {
	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		return 0
	}
	if pb.GetCounter() == nil {
		return 0
	}
	return uint64(pb.GetCounter().GetValue())
}
