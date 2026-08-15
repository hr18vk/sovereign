package main

// otel.go constructs the OpenTelemetry MeterProvider that arms
// telemetry.Init at boot (Day 21, ADR-0026). The two-exporter separation
// (ADR-0023 §0.d) is load-bearing: this OTel layer and the prometheus bridge
// (pkg/metrics/telemetry_bridge.go) export through DIFFERENT destinations.
// The bridge registers a prometheus.Collector into metricsExp.Registry() and
// is scraped via the /metrics mux; this OTel layer uses its OWN
// logOutputExporter driven by a PeriodicReader and NEVER touches that
// prometheus Registry. The two read the SAME underlying *Counter objects:
//   - the bridge reads the CUMULATIVE Value() (telemetry.go:223), NEVER
//     lastReported (the §0.b double-count trap);
//   - the OTel callback reads the DELTA via lastReported (the int64-observable
//     callback advances lastReported, reporting the per-interval delta the
//     OTel exporter expects).
// cumulative == sum-of-deltas across the two; they never collide at /metrics
// because OTel's logOutputExporter is NOT a prometheus Collector. Wiring OTel
// to the bridge's prometheus Registry WOULD double-count (the §0.d hazard) —
// refuse that.

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/hr18vk/supremum/internal/telemetry"
)

// otelMeterProviderShutdown drains the OTel periodic reader's unreported batch
// on the graceful-exit path (the controller flushes on Shutdown; without it the
// final interval's deltas are lost). Captured by the closure returned from
// armOTel so the caller can defer it alongside metricsSrv.Shutdown. Nil when OTel
// is armed off (the research node keeps the Day-18 bridge-alone behavior).
type otelMeterProviderShutdown func(ctx context.Context) error

// armOTel constructs the OTel MeterProvider and binds it into the telemetry
// package via telemetry.Init. Gated on the --otel flag: a research node keeps
// OTel OFF (the nil-Meter fallback in registry.go, byte-identical Day-18
// bridge-alone behavior — the honest-disabled sister of the 503 precedent, NOT
// a silent no-op). When armed, the counters are rebuilt against a REAL sdk
// Meter whose observable callbacks fire on the periodic reader's cadence; this
// is what makes the longError landmines honest under a real Meter (the
// omission would otherwise nil QueryL0ListCapped). The OTel reader is a
// PeriodicReader over logOutputExporter — a SEPARATE destination from the
// bridge's prometheus Registry (§0.d). The service.name resource attribute is
// derived from nodeID (a future fork attributes per-region; disclosed ADR-0026
// §6).
func armOTel(otelEnabled bool, nodeIDHex string, exportInterval time.Duration) (otelMeterProviderShutdown, error) {
	if !otelEnabled {
		log.Printf("sovereign-node: OTel OFF (--otel=false) — prometheus bridge serves /metrics alone (Day-18 behavior)")
		return func(context.Context) error { return nil }, nil
	}
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "sovereign-node"),
			attribute.String("service.instance.id", nodeIDHex),
		),
	)
	if err != nil {
		// A resource-merge error makes the OTel layer UNUSABLE but does NOT
		// impair the data plane (the counters keep working as in-process
		// LongAdders; the bridge still scrapes them cumulatively). Fail loud so
		// the operator knows the OTel stream is dark, but boot continues.
		log.Printf("sovereign-node: OTel resource merge FAILED: %v — OTel dark, prometheus bridge unaffected", err)
		return func(context.Context) error { return nil }, nil
	}
	exp := &logOutputExporter{w: log.Writer()}
	reader := sdkmetric.NewPeriodicReader(exp,
		sdkmetric.WithInterval(exportInterval),
	)
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)
	m := mp.Meter("internal/telemetry")
	telemetry.Init(m)
	log.Printf("sovereign-node: OTel armed (MeterProvider periodic reader interval=%s) — telemetry.Init bound the sdk Meter; the bridge's prometheus Registry is SEPARATE", exportInterval)
	return mp.Shutdown, nil
}

// logOutputExporter is a minimal sdkmetric.Exporter that writes each collected
// batch to a log writer. It is NOT a prometheus.Collector and is NOT registered
// with metricsExp.Registry() — the two-exporter separation (ADR-0026 §0.d). An
// OTel-to-prometheus bridge is a DIFFERENT fork; today the OTel stream lands in
// the operator log stream (a separate destination from the /metrics scrape).
//
// Temporality: DeltaTemporality for counters (the OTel callback reports the
// per-interval delta via lastReported, matching the bridge's cumulative ==
// sum-of-deltas invariant). This is the temporality the §0.d consistency proof
// relies on; CumulativeTemporality here would still be consistent but would
// duplicate the bridge's cumulative role.
type logOutputExporter struct {
	w  io.Writer
	mu sync.Mutex
}

func (e *logOutputExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	// Counters + observable counters report delta (lastReported's role).
	// Gauges report the current value (last-value aggregation); temporality is
	// immaterial for a gauge but the SDK still asks — Cumulative is safe.
	switch k {
	case sdkmetric.InstrumentKindCounter,
		sdkmetric.InstrumentKindObservableCounter,
		sdkmetric.InstrumentKindUpDownCounter,
		sdkmetric.InstrumentKindObservableUpDownCounter:
		return metricdata.DeltaTemporality
	default:
		return metricdata.CumulativeTemporality
	}
}

func (e *logOutputExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	// Default aggregation; the SDK picks Sum for counters, LastValue for
	// gauges. Returning nil (AggregationDefault) is the documented zero.
	return sdkmetric.AggregationDefault{}
}

func (e *logOutputExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	fmt.Fprintf(e.w, "otel-export: scope %d\r\n", len(rm.ScopeMetrics))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			fmt.Fprintf(e.w, "  metric name=%s unit=%s data=%T\r\n", m.Name, m.Unit, m.Data)
		}
	}
	_ = ctx
	return nil
}

func (e *logOutputExporter) ForceFlush(context.Context) error { return nil }

func (e *logOutputExporter) Shutdown(context.Context) error { return nil }
