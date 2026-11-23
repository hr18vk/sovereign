// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package telemetry

// manifest_skip_counter_test.go tests registry membership and OpenTelemetry
// export for the manifest-channel download-skip counter
// (QueryManifestSkippedFirstSys, ADR-0030).
//
// QueryManifestSkippedFirstSys is part of allCounters() and is reconstructed in
// rebuildCounters(), so Init(meter) preserves it for OpenTelemetry collection
// and TelemetryBridge scraping.

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

// manifestSkipSubprocessMarker selects the subprocess entry point. Init accepts
// only its first call, so the test uses a fresh process for a real Meter.
const manifestSkipSubprocessMarker = "SUPREMUM_MANIFEST_SKIP_SUBPROC"

// TestManifestSkipCounterInRegistry asserts QueryManifestSkippedFirstSys is in
// Counters() without duplicate metric names and alongside prior counters.
func TestManifestSkipCounterInRegistry(t *testing.T) {
	cs := Counters()
	const wantDistinct = 25
	if len(cs) != wantDistinct {
		t.Fatalf("len(Counters())=%d, want %d", len(cs), wantDistinct)
	}
	wantNames := map[string]bool{
		"supremum.compaction.query_manifest_skipped_first_sys": false,
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
		t.Fatalf("%d duplicate names in Counters()", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("distinct names=%d, want %d", len(seen), wantDistinct)
	}
	for _, n := range []string{
		"supremum.query_txtime_high_water_mark_ns",
		"supremum.compaction.pruning_horizon_effective_ns",
		"supremum.compaction.pruning_horizon_retreat_refused",
		"supremum.l0.query_download_skipped_first_sys",
	} {
		if _, ok := seen[n]; !ok {
			t.Errorf("expected prior counter %q missing from Counters()", n)
		}
	}
	t.Logf("Counters() carries %d distinct metrics including manifest-skip name with 0 duplicates", len(cs))
}

// TestManifestSkipCounterNonNilPostInit_Subproc runs telemetry.Init in a fresh
// subprocess and verifies QueryManifestSkippedFirstSys stays non-nil and is
// exported through an OpenTelemetry ManualReader.
func TestManifestSkipCounterNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(manifestSkipSubprocessMarker) == "newcounters" {
		runManifestSkipNewCountersSubproc(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestManifestSkipCounterNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), manifestSkipSubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("manifest-skip subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "manifest-new-counters pass") {
		t.Fatalf("manifest-skip subprocess did not pass:\n%s", out)
	}
	t.Logf("manifest-skip subprocess passed with QueryManifestSkippedFirstSys bound after Init")
}

func runManifestSkipNewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "manifest-skip-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("manifest-skip: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	if QueryManifestSkippedFirstSys == nil {
		t.Fatalf("manifest-skip: QueryManifestSkippedFirstSys nil post-Init (missing from rebuildCounters)")
	}

	QueryManifestSkippedFirstSys.Add(11)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("manifest-skip: Collect: %v", cerr)
	}
	foundCounter := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "supremum.compaction.query_manifest_skipped_first_sys" {
				foundCounter = true
			}
		}
	}
	if !foundCounter {
		t.Errorf("manifest-skip: counter 'supremum.compaction.query_manifest_skipped_first_sys' not found in OTel Collect output")
	}
	t.Logf("manifest-new-counters pass: QueryManifestSkippedFirstSys is non-nil after Init and present in OpenTelemetry output")
}
