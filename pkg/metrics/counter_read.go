// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// readCounterValue reads a Prometheus counter through its Write method. Only
// the poller that feeds sovereign_ingest_pps calls it; frame ingestion does not.
// A write error or a non-counter metric produces zero.
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
