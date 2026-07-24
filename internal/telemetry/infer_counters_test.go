// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package telemetry

// The auto-inference counter guards (ADR-0027).
//
// The 3 new inferrer counters are in allCounters() (0 dups, all registered
// under the real Meter after a subprocess Init). The bridge
// (pkg/metrics/telemetry_bridge.go) enumerates them WITHOUT a bridge edit (the
// slice auto-surface property — a sister guard in pkg/metrics scrapes /metrics
// and asserts the 3 new names appear). This in-package guard asserts the
// allCounters() slice carries the 3 new distinct counters + the subprocess-Init
// fill discipline (a counter missing from rebuildCounters() silently drops to
// nil under --otel — not reopened for the 3 new counters; the
// construction-vs-distinct trap disarmed).
//
// The subprocess Init guard asserts the 3 new counters are NON-nil post-Init
// (the rebuildCounters fill held for the inferrer counters — the omission
// landmine stays closed for the 3 new ones).

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

// inferSubprocessMarker is the env var the subprocess guards set when they
// re-invoke the test binary for a fresh process (the Init once-per-process
// guard makes a second Init a rejected no-op in-process).
const inferSubprocessMarker = "SUPREMUM_INFER_SUBPROC"

// TestInferCountersInRegistry asserts the 3 new inferrer counters are in
// allCounters() (the counter slice), carry their distinct names, and that the
// slice grew to include them (the honest growth ADR-0027 discloses). The bridge
// enumerates this slice automatically (verified by the sister guard in
// pkg/metrics). The guard ALSO asserts the 3 new counters are registered under
// a real Meter (a subprocess Init + ManualReader Collect surfaces the 3 new
// instruments — the "OTel callback observes the new gauges automatically" claim
// byte-verified).
func TestInferCountersInRegistry(t *testing.T) {
	cs := Counters()
	const wantDistinct = 24 // distinct counters; grew across the ADR series as disclosure counters were added
	if len(cs) != wantDistinct {
		t.Fatalf("infer-telemetry: len(Counters())=%d, want %d (grew the counter 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure; grew the counter 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure; grew the counter 18->19; the stratified-anti-entropy fallback counter — StratifiedAntiEntropyFallback — grew the counter; the live-source — QueryLiveSourceReads — grew it; the manifest-skip — QueryManifestSkippedFirstSys — grew it; the download-skip — QueryDownloadSkippedFirstSys — grew it; the 3 inferrer counters grew it)", len(cs), wantDistinct)
	}
	// The 3 new names MUST be present (the slice carries them).
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
			t.Errorf("infer-telemetry: the new counter %q is NOT in Counters() (the counter must carry it for the bridge to auto-surface)", n)
		}
	}
	// 0 dups (the construction-vs-distinct trap — a dup would panic MustRegister
	// at boot under the bridge).
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("infer-telemetry: duplicate name in Counters(): %q x%d (MustRegister would PANIC at boot)", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("infer-telemetry: %d duplicate names — the construction-vs-distinct trap (MustRegister PANIC at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("infer-telemetry: distinct names=%d, want %d", len(seen), wantDistinct)
	}
	t.Logf("infer-telemetry PASS: Counters() carries %d DISTINCT (16->17; 15->16; 12->15), the 3 inferrer names present, 0 dups — the counter grew honestly; the bridge auto-surfaces the manifest-skip counter WITHOUT an edit (verified by the pkg/metrics sister guard)", len(cs))
}

// TestInferCountersNonNilPostInit_Subproc drives a REAL telemetry.Init
// (testMeter) in a fresh subprocess + asserts the 3 new counters are NON-nil
// post-Init (the rebuildCounters fill held for the inferrer counters — the
// omission landmine stays closed for the 3 new ones; the
// construction-vs-distinct trap disarmed). Negative control: a stale tree where
// rebuildCounters OMITTED the 3 new fills would leave them nil post-Init (the
// var the init() object was assigned to gets reassigned by rebuildCounters;
// without the fill the new assignment is nil).
func TestInferCountersNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(inferSubprocessMarker) == "newcounters" {
		runInferNewCountersSubproc(t)
		return
	}
	// Parent: re-invoke the test binary as a subprocess for a fresh process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestInferCountersNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), inferSubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("infer-new-counters subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "infer-new-counters PASS") {
		t.Fatalf("infer-new-counters subprocess did not pass:\n%s", out)
	}
	t.Logf("infer-new-counters PASS (subprocess): the 3 inferrer counters are NON-nil post-Init — the rebuildCounters fill held for them (the omission landmine stays closed)")
}

// runInferNewCountersSubproc is the subprocess entry. It builds a ManualReader,
// Init's the Meter against it, asserts the 3 new counters are NON-nil, drives
// the retreat-refuse counter + the two gauges, Collects, and asserts the 3 new
// instruments appear in the OTel Collect output (the "gauges observed
// automatically" claim byte-verified — NO additional OTel wiring).
func runInferNewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "infer-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("infer-new-counters: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	// (a) The 3 new counters are NON-nil post-Init (the rebuildCounters fill).
	if QueryTxTimeHighWaterMark == nil {
		t.Fatalf("infer-new-counters: QueryTxTimeHighWaterMark nil post-Init (the rebuildCounters fill is MISSING — the omission landmine reopened)")
	}
	if PruningHorizonEffective == nil {
		t.Fatalf("infer-new-counters: PruningHorizonEffective nil post-Init (the rebuildCounters fill is MISSING)")
	}
	if PruningHorizonRetreatRefused == nil {
		t.Fatalf("infer-new-counters: PruningHorizonRetreatRefused nil post-Init (the rebuildCounters fill is MISSING)")
	}

	// (b) Drive the 2 gauges + the retreat-refuse counter, then Collect + assert
	// the 3 new instruments appear in the OTel stream (the "gauges observed
	// automatically" claim — the PeriodicReader/ManualReader observes modeGauge
	// via Value() -> GaugeValue(); NO additional wiring).
	QueryTxTimeHighWaterMark.Set(7_000_000)
	PruningHorizonEffective.Set(6_500_000)
	PruningHorizonRetreatRefused.Add(3)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("infer-new-counters: Collect: %v", cerr)
	}
	// The 3 new names MUST appear in the OTel Collect output (the gauges as a
	// Gauge instrument; the counter as a Sum). The OTel callback observes them
	// automatically.
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
			t.Errorf("infer-new-counters: the gauge %q NOT found in the OTel Collect output (the auto-observe claim is FALSE — the observable callback did not register the gauge under the Meter)", n)
		}
	}
	if !foundCounter {
		t.Errorf("infer-new-counters: the counter 'supremum.compaction.pruning_horizon_retreat_refused' NOT found in the OTel Collect output (the observable callback did not register)")
	}
	t.Logf("infer-new-counters PASS: the 3 inferrer counters are NON-nil post-Init + observed by the OTel ManualReader Collect (the gauges via Value()->GaugeValue() at telemetry.go:230; the auto-observe claim byte-verified — NO additional OTel wiring)")
}
