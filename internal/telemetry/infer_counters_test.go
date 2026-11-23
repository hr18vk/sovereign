// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package telemetry

// infer_counters_test.go tests registry membership and OpenTelemetry export for
// the three pruning-horizon inference metrics (QueryTxTimeHighWaterMark,
// PruningHorizonEffective, PruningHorizonRetreatRefused; ADR-0027).
//
// All 25 metrics live in allCounters() and are reconstructed in
// rebuildCounters(), so Init(meter) preserves them and TelemetryBridge can
// enumerate them automatically.

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// inferSubprocessMarker selects the subprocess entry point. Init accepts only
// its first call, so the test uses a fresh process for a real Meter.
const inferSubprocessMarker = "SUPREMUM_INFER_SUBPROC"

// TestInferCountersInRegistry asserts the three horizon-inference counters are
// present in Counters() with unique names and expected cardinality.
func TestInferCountersInRegistry(t *testing.T) {
	cs := Counters()
	const wantDistinct = 25
	if len(cs) != wantDistinct {
		t.Fatalf("len(Counters())=%d, want %d", len(cs), wantDistinct)
	}
	wantNames := map[string]bool{
		"supremum.query_txtime_high_water_mark_ns":            false,
		"supremum.compaction.pruning_horizon_effective_ns":    false,
		"supremum.compaction.pruning_horizon_retreat_refused": false,
	}
	seen := map[string]int{}
	for _, c := range cs {
		seen[c.Name()]++
		if _, isWant := wantNames[c.Name()]; isWant {
			wantNames[c.Name()] = true
		}
	}
	for n, found := range wantNames {
		if !found {
			t.Errorf("counter %q missing from Counters()", n)
		}
	}
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("duplicate name in Counters(): %q x%d (MustRegister would panic at boot)", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("%d duplicate names in Counters() (MustRegister would panic at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("distinct names=%d, want %d", len(seen), wantDistinct)
	}
	t.Logf("Counters() carries %d distinct metrics including the three inferrer metrics with zero duplicates", len(cs))
}

// TestInferCountersNonNilPostInit_Subproc runs telemetry.Init in a fresh
// subprocess and checks that all three inference metrics stay non-nil and
// register with an OpenTelemetry ManualReader.
func TestInferCountersNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(inferSubprocessMarker) == "newcounters" {
		runInferNewCountersSubproc(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInferCountersNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), inferSubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("infer-new-counters subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "infer-new-counters pass") {
		t.Fatalf("infer-new-counters subprocess did not pass:\n%s", out)
	}
	t.Logf("inference-counter subprocess passed with all three metrics bound after Init")
}

func runInferNewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "infer-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	if QueryTxTimeHighWaterMark == nil {
		t.Fatalf("QueryTxTimeHighWaterMark nil post-Init (missing from rebuildCounters)")
	}
	if PruningHorizonEffective == nil {
		t.Fatalf("PruningHorizonEffective nil post-Init (missing from rebuildCounters)")
	}
	if PruningHorizonRetreatRefused == nil {
		t.Fatalf("PruningHorizonRetreatRefused nil post-Init (missing from rebuildCounters)")
	}

	QueryTxTimeHighWaterMark.Set(7_000_000)
	PruningHorizonEffective.Set(6_500_000)
	PruningHorizonRetreatRefused.Add(3)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("Collect: %v", cerr)
	}
	foundGauges := map[string]bool{
		"supremum.query_txtime_high_water_mark_ns":         false,
		"supremum.compaction.pruning_horizon_effective_ns": false,
	}
	foundCounter := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "supremum.query_txtime_high_water_mark_ns":
				foundGauges["supremum.query_txtime_high_water_mark_ns"] = true
			case "supremum.compaction.pruning_horizon_effective_ns":
				foundGauges["supremum.compaction.pruning_horizon_effective_ns"] = true
			case "supremum.compaction.pruning_horizon_retreat_refused":
				foundCounter = true
			}
		}
	}
	for n, found := range foundGauges {
		if !found {
			t.Errorf("gauge %q not found in OTel Collect output", n)
		}
	}
	if !foundCounter {
		t.Errorf("counter 'supremum.compaction.pruning_horizon_retreat_refused' not found in OTel Collect output")
	}
	t.Logf("infer-new-counters pass: all three inference metrics are non-nil after Init and present in OpenTelemetry output")
}
