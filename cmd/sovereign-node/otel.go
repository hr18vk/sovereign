// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// This file constructs the optional OpenTelemetry MeterProvider (ADR-0026).
// Its PeriodicReader exports to the log, separately from the Prometheus
// collector registered on /metrics (ADR-0023). Both exporters read the same
// counters: the bridge reads cumulative Value, while OTel observable callbacks
// advance lastReported and export per-interval deltas. Keeping the destinations
// separate prevents either exporter from counting the other's output.

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

	"github.com/hr18vk/sovereign/internal/telemetry"
)

// otelMeterProviderShutdown flushes the periodic reader during graceful
// shutdown. armOTel returns a no-op function when OTel is disabled so the caller
// can defer the result in either configuration.
type otelMeterProviderShutdown func(ctx context.Context) error

// armOTel binds an SDK Meter into the telemetry package when otelEnabled is
// true. Its observable callbacks run on exportInterval and write deltas through
// logOutputExporter. service.instance.id identifies the node; service.name is
// sovereign-node. When disabled, telemetry retains its nil-Meter fallback and
// only the Prometheus bridge exports the counters.
func armOTel(otelEnabled bool, nodeIDHex string, exportInterval time.Duration) (otelMeterProviderShutdown, error) {
	if !otelEnabled {
		log.Printf("sovereign-node: OTel disabled (--otel=false); prometheus bridge serves /metrics")
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
		// A resource-merge error disables OTel export but not the data plane.
		// The in-process counters and Prometheus bridge remain usable.
		log.Printf("sovereign-node: OTel resource merge failed: %v; OTel export disabled, prometheus bridge unaffected", err)
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
	log.Printf("sovereign-node: OTel enabled (export interval=%s); telemetry.Init bound the SDK Meter", exportInterval)
	return mp.Shutdown, nil
}

// logOutputExporter writes each collected batch to a log writer. It is not a
// prometheus.Collector and is never registered on the /metrics registry.
// Counter instruments use delta temporality because their observable callbacks
// advance lastReported once per interval; the bridge continues to expose the
// cumulative counter values.
type logOutputExporter struct {
	w  io.Writer
	mu sync.Mutex
}

func (e *logOutputExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	// Counters and observable counters report deltas through lastReported.
	// Gauges use last-value aggregation, so their temporality does not affect
	// the exported value.
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
	// gauges. sdkmetric.AggregationDefault{} is the documented default.
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
