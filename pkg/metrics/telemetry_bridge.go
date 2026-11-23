// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

import (
	"strings"

	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

// TelemetryBridge exposes internal/telemetry counters as Prometheus series.
// Storage flushes, compaction, pruning, and reaping update those counters in
// the data plane; the bridge makes their values available at /metrics
// (ADR-0023). In particular, it exposes the count of manifests preserved by
// the reaper because their target L1 object was missing.
//
// The instruments are unlabelled LongAdders. Recorder instead owns the
// sovereign_* ingest and mesh instruments. TelemetryBridge enumerates
// telemetry.Counters and maps dots in each telemetry name to underscores,
// leaving the two instrument sets independent.
//
// Counter values must remain cumulative:
//
//   - registerInt64Counter in internal/telemetry reports per-interval deltas
//     to OTel and advances lastReported in its callback. Prometheus counters
//     instead carry cumulative values, leaving rate calculation to the server.
//   - Collect reads Counter.Value, never lastReported. An OTel callback can
//     advance lastReported between scrapes, so using that field here would
//     couple the exporters and corrupt their values. The command initializes
//     OTel behind --otel; this package never calls telemetry.Init (ADR-0026).
//
// Descriptors are built once by NewTelemetryBridge and reused by every scrape.
// Collect runs outside the data plane. TestZeroAllocCollect measures the
// allocations made by the const-metric constructors rather than assuming that
// reusing descriptors makes the entire scrape allocation-free.
type TelemetryBridge struct {
	// descs maps Prometheus names to the descriptors constructed once by
	// NewTelemetryBridge. Collect looks up entries without rebuilding the map.
	descs map[string]*prometheus.Desc

	// counters is the snapshot returned by telemetry.Counters at construction.
	// telemetry freezes the slice after initialization, so scrapes can iterate
	// it without synchronization and read each counter's current value.
	counters []*telemetry.Counter
}

// mapPromName replaces dots with underscores to make an OTel metric name legal
// in Prometheus. The supremum_* prefix remains distinct from the Recorder's
// sovereign_* instruments.
func mapPromName(telemetryName string) string {
	return strings.ReplaceAll(telemetryName, ".", "_")
}

// NewTelemetryBridge snapshots telemetry.Counters and constructs one
// descriptor per metric. The command creates the bridge after NewExporter and,
// when --otel is enabled, after telemetry.Init, so the snapshot contains the
// initialized counters (ADR-0023, ADR-0026). The bridge itself never calls
// telemetry.Init and also works with package-initialized counters alone.
func NewTelemetryBridge() *TelemetryBridge {
	counters := telemetry.Counters()
	b := &TelemetryBridge{
		descs:    make(map[string]*prometheus.Desc, len(counters)),
		counters: counters,
	}
	for _, c := range counters {
		promName := mapPromName(c.Name())
		// These instruments have neither variable nor constant labels. Their
		// descriptions come from telemetry, and their names already carry units
		// such as _bytes or _ns where applicable.
		b.descs[promName] = prometheus.NewDesc(
			promName,
			c.Description(),
			nil, // no variable labels
			nil, // no const labels
		)
	}
	return b
}

// Describe sends the pre-built descriptor for every snapshotted counter to ch.
// Iterating the counter slice gives the same stable order as Collect.
func (b *TelemetryBridge) Describe(ch chan<- *prometheus.Desc) {
	for _, c := range b.counters {
		ch <- b.descs[mapPromName(c.Name())]
	}
}

// Collect emits a const metric for each counter. ModeCounter uses the
// cumulative Counter.Value sum; ModeGauge uses the latest value supplied by
// Set. Neither path reads lastReported, which belongs exclusively to the OTel
// delta exporter.
//
// client_golang exposes both forms through MustNewConstMetric and ValueType.
// Descriptors come from the pre-built map; the constructors may still allocate,
// which TestZeroAllocCollect measures and reports.
func (b *TelemetryBridge) Collect(ch chan<- prometheus.Metric) {
	for _, c := range b.counters {
		desc := b.descs[mapPromName(c.Name())]
		value := c.Value() // cumulative for modeCounter, last Set for modeGauge
		// These descriptors have no labels, so the const metric takes no label
		// values. CounterValue is cumulative; GaugeValue reports the latest Set.
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
