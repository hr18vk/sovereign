// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package telemetry

// download_skip_counter_test.go tests registration and OpenTelemetry export
// for the filename-bounded download-skip counter (QueryDownloadSkippedFirstSys,
// ADR-0029) and manifest-skip counter (QueryManifestSkippedFirstSys, ADR-0030).
//
// Both counters live in allCounters() and are rebuilt in rebuildCounters(), so
// Init(meter) preserves them and TelemetryBridge can enumerate them
// automatically.

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

// downloadSkipSubprocessMarker selects the subprocess entry point. Init accepts
// only its first call, so the test uses a fresh process for a real Meter.
const downloadSkipSubprocessMarker = "SUPREMUM_DOWNLOAD_SKIP_SUBPROC"

// TestDownloadSkipCounterInRegistry asserts the download-skip counter is in
// allCounters(), carries its distinct name, and coexists with prior counters
// without duplicate metric names.
func TestDownloadSkipCounterInRegistry(t *testing.T) {
	cs := Counters()
	const wantDistinct = 25
	if len(cs) != wantDistinct {
		t.Fatalf("len(Counters())=%d, want %d", len(cs), wantDistinct)
	}
	wantNames := map[string]bool{
		"supremum.l0.query_download_skipped_first_sys":         false,
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
	} {
		if _, ok := seen[n]; !ok {
			t.Errorf("expected counter %q missing from Counters()", n)
		}
	}
	t.Logf("Counters() carries %d distinct counters including download-skip and manifest-skip names with 0 duplicates", len(cs))
}

// TestDownloadSkipCounterNonNilPostInit_Subproc runs telemetry.Init in a fresh
// subprocess and verifies QueryDownloadSkippedFirstSys stays non-nil and is
// exported through an OpenTelemetry ManualReader.
func TestDownloadSkipCounterNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(downloadSkipSubprocessMarker) == "newcounters" {
		runDownloadSkipNewCountersSubproc(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDownloadSkipCounterNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), downloadSkipSubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "skip-new-counters PASS") {
		t.Fatalf("subprocess did not pass:\n%s", out)
	}
	t.Logf("download-skip subprocess passed with the counter bound after Init")
}

func runDownloadSkipNewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "download-skip-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	if QueryDownloadSkippedFirstSys == nil {
		t.Fatalf("QueryDownloadSkippedFirstSys nil post-Init (missing from rebuildCounters)")
	}

	QueryDownloadSkippedFirstSys.Add(7)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("Collect: %v", cerr)
	}
	foundCounter := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "supremum.l0.query_download_skipped_first_sys" {
				foundCounter = true
			}
		}
	}
	if !foundCounter {
		t.Errorf("counter 'supremum.l0.query_download_skipped_first_sys' not found in OTel Collect output")
	}
	t.Logf("skip-new-counters PASS: download-skip counter is non-nil after Init and present in OpenTelemetry output")
}
