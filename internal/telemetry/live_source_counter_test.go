// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package telemetry

// live_source_counter_test.go tests registration and OpenTelemetry export for
// the read-your-writes live-source counter (QueryLiveSourceReads, ADR-0032).
//
// QueryLiveSourceReads is part of allCounters() and is reconstructed in
// rebuildCounters() so Init(meter) preserves it. It adds one modeCounter while
// leaving the gauge count at 3.

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

// liveSourceSubprocessMarker selects the subprocess entry point. Init accepts
// only its first call, so the test uses a fresh process for a real Meter.
const liveSourceSubprocessMarker = "SUPREMUM_LIVE_SOURCE_SUBPROC"

// TestLiveSourceCounterInRegistry asserts QueryLiveSourceReads is present in
// Counters(), carries its distinct name, and preserves the 22-counter / 3-gauge
// mode split.
func TestLiveSourceCounterInRegistry(t *testing.T) {
	cs := Counters()
	const wantDistinct = 25
	if len(cs) != wantDistinct {
		t.Fatalf("len(Counters())=%d, want %d", len(cs), wantDistinct)
	}
	wantNames := map[string]bool{
		"supremum.query.live_source_reads": false,
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
	for _, n := range []string{
		"supremum.l0.query_download_skipped_first_sys",
		"supremum.compaction.query_manifest_skipped_first_sys",
	} {
		if _, ok := seen[n]; !ok {
			t.Errorf("expected prior counter %q missing from Counters()", n)
		}
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
	if gauges != 3 || counters != 22 {
		t.Fatalf("mode split %d counters + %d gauges; want 22 counters + 3 gauges", counters, gauges)
	}
	t.Logf("Counters() carries %d distinct metrics including live-source reads with 0 duplicates (22 counters + 3 gauges)", len(cs))
}

// TestLiveSourceCounterNonNilPostInit_Subproc runs telemetry.Init in a fresh
// subprocess and checks QueryLiveSourceReads stays non-nil and exports through
// an OpenTelemetry ManualReader.
func TestLiveSourceCounterNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(liveSourceSubprocessMarker) == "newcounters" {
		runLiveSourceNewCountersSubproc(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLiveSourceCounterNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), liveSourceSubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("live-new-counters subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "live-new-counters pass") {
		t.Fatalf("live-new-counters subprocess did not pass:\n%s", out)
	}
	t.Logf("live-source subprocess passed with QueryLiveSourceReads bound after Init")
}

func runLiveSourceNewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "live-source-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	if QueryLiveSourceReads == nil {
		t.Fatalf("QueryLiveSourceReads nil post-Init (missing from rebuildCounters)")
	}

	QueryLiveSourceReads.Add(7)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("Collect: %v", cerr)
	}
	foundCounter := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "supremum.query.live_source_reads" {
				foundCounter = true
			}
		}
	}
	if !foundCounter {
		t.Errorf("counter 'supremum.query.live_source_reads' not found in OTel Collect output")
	}
	t.Logf("live-new-counters pass: QueryLiveSourceReads is non-nil after Init and present in OpenTelemetry output")
}
