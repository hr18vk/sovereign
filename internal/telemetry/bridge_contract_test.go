// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package telemetry

import (
	"math"
	"testing"
)

// These tests cover invariants that the cross-package pkg/metrics bridge cannot
// check directly because they involve Counter.lastReported and counterMode.
// The bridge uses only Name, Description, Unit, Mode, and Value.
//
// Value returns a cumulative value, while lastReported belongs to the
// OpenTelemetry delta callback. If the bridge also advanced lastReported, an
// interleaved OpenTelemetry collection could corrupt the next delta. This test
// process increments a counter without calling Init and checks that
// lastReported remains zero.
//
// Counters returns each package variable once. QueryL0ListCapped is constructed
// once during package initialization and once by rebuildCounters, but appears
// only once in the slice. A duplicate name would make Prometheus MustRegister
// panic on a duplicate descriptor.

// TestLastReportedUntouchedByBridge checks that increments alone do not modify
// lastReported. Once Init binds a Meter, registerInt64Counter advances that
// field during collection; the Prometheus bridge still reads only Value.
func TestLastReportedUntouchedByBridge(t *testing.T) {
	c := CompactionRowsPruned
	if c == nil {
		t.Fatal("CompactionRowsPruned nil — construction order changed")
	}
	// Baseline: lastReported must be 0 in-process before any Init call.
	if got := c.lastReported.Load(); got != 0 {
		t.Fatalf("baseline lastReported=%d, want 0 — "+
			"a prior call initialized telemetry.Init; "+
			"this test verifies the Prometheus bridge never "+
			"touches lastReported, so a non-zero baseline is test-order "+
			"contamination rather than a bridge defect.", got)
	}
	const n = 13
	for i := 0; i < n; i++ {
		c.Inc()
	}
	// The cumulative must have advanced (Value() is the read path the bridge
	// uses); lastReported must still be 0 (the bridge reads only Value()).
	cumulative := c.Value()
	if math.Abs(cumulative-float64(n)) > 0.5 {
		t.Fatalf("Counter.Value() after %d Inc = %v (want %d) — "+
			"bridge read path broken", n, cumulative, n)
	}
	if got := c.lastReported.Load(); got != 0 {
		t.Fatalf("lastReported advanced to %d after Inc without "+
			"an OpenTelemetry callback firing — something outside "+
			"the OTel callback modified lastReported",
			got)
	}
	t.Logf("after %d Inc calls, Value()=%v cumulative and "+
		"lastReported==0 unchanged — the bridge reads "+
		"Value() directly and leaves lastReported untouched", n, cumulative)
}

// TestCountersNoDuplicateNames checks that Counters contains each metric name
// once, so Prometheus MustRegister cannot fail on duplicate descriptors.
func TestCountersNoDuplicateNames(t *testing.T) {
	cs := Counters()
	seen := map[string]int{}
	for _, c := range cs {
		seen[c.Name()]++
	}
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("duplicate telemetry name in Counters(): %q x%d — bridge MustRegister would panic on duplicate Desc", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("Counters() contains %d duplicate names", dups)
	}
	const wantDistinct = 25
	if len(cs) != wantDistinct {
		t.Fatalf("Counters() len=%d, want %d distinct (bridge exposes %d series)",
			len(cs), wantDistinct, len(cs))
	}
	if len(seen) != wantDistinct {
		t.Fatalf("distinct names=%d, want %d", len(seen), wantDistinct)
	}
	counters, gauges := 0, 0
	for _, c := range cs {
		switch c.Mode() {
		case modeCounter:
			counters++
		case modeGauge:
			gauges++
		}
	}
	const wantGauges = 3
	const wantCounters = 22
	if gauges != wantGauges || counters != wantCounters {
		t.Fatalf("mode split: %d counters + %d gauges; want %d counters + %d gauges", counters, gauges, wantCounters, wantGauges)
	}
	t.Logf("Counters() contains %d metrics and %d names; duplicate names=%d; %d counters and %d gauges",
		len(cs), len(seen), dups, counters, gauges)
}
