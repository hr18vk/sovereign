// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package telemetry

// The filename-bounded download-skip counter guards (ADR-0029).
//
// The new download-skip counter (QueryDownloadSkippedFirstSys) is in
// allCounters() (0 dups, registered under the real Meter after a subprocess
// Init). The bridge (pkg/metrics/telemetry_bridge.go) enumerates the slice
// WITHOUT a bridge edit (the slice auto-surface property — a sister guard in
// pkg/metrics scrapes /metrics and asserts the new name appears). This
// in-package guard asserts the allCounters() slice carries the new distinct
// counter + the subprocess-Init fill discipline (a counter missing from
// rebuildCounters() silently drops to nil under --otel — not reopened for the
// new counter; the construction-vs-distinct trap disarmed).
//
// The subprocess Init guard asserts the new counter is NON-nil post-Init (the
// rebuildCounters fill held for the download-skip counter — the omission
// landmine stays closed for it). The distinct-counter count grows as disclosure
// counters are added (the T_gc auto-inference counters, this download-skip
// counter, then the manifest-skip counter); the bridge auto-surfaces each new
// series WITHOUT an edit.

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

// downloadSkipSubprocessMarker is the env var the subprocess guards set when they
// re-invoke the test binary for a fresh process (the Init once-per-process
// guard makes a second Init a rejected no-op in-process).
const downloadSkipSubprocessMarker = "SUPREMUM_DOWNLOAD_SKIP_SUBPROC"

// TestDownloadSkipCounterInRegistry asserts the new download-skip counter is in
// allCounters() (the counter slice) and carries its distinct name; the slice
// grew to include it (the honest growth ADR-0029 discloses) and later grew
// again when the manifest-skip counter was added (its name joined the wantNames
// table). The bridge enumerates this slice automatically (verified by the
// sister guard in pkg/metrics). The guard ALSO asserts the new counter is
// registered under a real Meter (a subprocess Init + ManualReader Collect
// surfaces the new instrument — the "OTel callback observes the new counter
// automatically" claim byte-verified).
func TestDownloadSkipCounterInRegistry(t *testing.T) {
	cs := Counters()
	const wantDistinct = 24 // distinct counters; grew across the ADR series as disclosure counters were added
	if len(cs) != wantDistinct {
		t.Fatalf("skip-telemetry: len(Counters())=%d, want %d (grew the counter 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure MUST be in the slice; grew the counter 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure MUST be in the slice; grew the counter 18->19; the stratified-anti-entropy fallback counter — StratifiedAntiEntropyFallback — MUST be in the slice; grew 17->18; grew 16->17; grew 15->16; the download-skip counter — QueryDownloadSkippedFirstSys — MUST be in the slice; the manifest-skip counter — QueryManifestSkippedFirstSys — grew it 16->17)", len(cs), wantDistinct)
	}
	// The new names MUST be present (the slice carries BOTH the download-skip
	// counter AND the manifest-skip counter; the two coexist).
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
			t.Errorf("skip-telemetry: the new counter %q is NOT in Counters() (the counter must carry it for the bridge to auto-surface)", n)
		}
	}
	// 0 dups (the construction-vs-distinct trap — a dup would panic MustRegister
	// at boot under the bridge).
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("skip-telemetry: duplicate name in Counters(): %q x%d (MustRegister would PANIC at boot)", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("skip-telemetry: %d duplicate names — the construction-vs-distinct trap (MustRegister PANIC at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("skip-telemetry: distinct names=%d, want %d", len(seen), wantDistinct)
	}
	// The three inferrer counters are STILL present (the slice grew, did NOT
	// drop any prior counter — the append-only-after-construction contract at
	// registry.go allCounters()).
	for _, n := range []string{
		"supremum.query_txtime_high_water_mark_ns",
		"supremum.compaction.pruning_horizon_effective_ns",
		"supremum.compaction.pruning_horizon_retreat_refused",
	} {
		if _, ok := seen[n]; !ok {
			t.Errorf("skip-telemetry: the counter %q is MISSING (must append, not replace)", n)
		}
	}
	t.Logf("skip-telemetry PASS: Counters() carries %d DISTINCT (15->16->17), the download-skip + manifest-skip names present, 0 dups, the 3 counters preserved — the counter grew honestly; the bridge auto-surfaces the manifest-skip counter WITHOUT an edit (verified by the pkg/metrics sister guard)", len(cs))
}

// TestDownloadSkipCounterNonNilPostInit_Subproc drives a REAL telemetry.Init
// (testMeter) in a fresh subprocess + asserts the new download-skip counter is
// NON-nil post-Init (the rebuildCounters fill held for it — the omission
// landmine stays closed for the new counter; the construction-vs-distinct trap
// disarmed). Negative control: a stale tree where rebuildCounters OMITTED the
// new fill would leave it nil post-Init (the var the init() object was assigned
// to gets reassigned by rebuildCounters; without the fill the new assignment is
// nil).
func TestDownloadSkipCounterNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(downloadSkipSubprocessMarker) == "newcounters" {
		runDownloadSkipNewCountersSubproc(t)
		return
	}
	// Parent: re-invoke the test binary as a subprocess for a fresh process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestDownloadSkipCounterNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), downloadSkipSubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("skip-new-counters subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "skip-new-counters PASS") {
		t.Fatalf("skip-new-counters subprocess did not pass:\n%s", out)
	}
	t.Logf("skip-new-counters PASS (subprocess): the download-skip counter is NON-nil post-Init — the rebuildCounters fill held for it (the omission landmine stays closed for the new counter)")
}

// runDownloadSkipNewCountersSubproc is the subprocess entry. It builds a ManualReader,
// Init's the Meter against it, asserts the new counter is NON-nil, drives it,
// Collects, and asserts the new instrument appears in the OTel Collect output
// (the "counter is observed automatically" claim byte-verified — NO additional
// OTel wiring).
func runDownloadSkipNewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "download-skip-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("skip-new-counters: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	// (a) The new counter is NON-nil post-Init (the rebuildCounters fill).
	if QueryDownloadSkippedFirstSys == nil {
		t.Fatalf("skip-new-counters: QueryDownloadSkippedFirstSys nil post-Init (the rebuildCounters fill is MISSING — the omission landmine reopened for the new counter)")
	}

	// (b) Drive the counter, then Collect + assert the new instrument appears in
	// the OTel stream (the "counter is observed automatically" claim — the
	// ManualReader observes the modeCounter via Value()).
	QueryDownloadSkippedFirstSys.Add(7)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("skip-new-counters: Collect: %v", cerr)
	}
	// The new name MUST appear in the OTel Collect output (the counter as a Sum).
	foundCounter := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "supremum.l0.query_download_skipped_first_sys" {
				foundCounter = true
			}
		}
	}
	if !foundCounter {
		t.Errorf("skip-new-counters: the counter 'supremum.l0.query_download_skipped_first_sys' NOT found in the OTel Collect output (the observable callback did not register — the auto-observe claim is FALSE)")
	}
	t.Logf("skip-new-counters PASS: the download-skip counter is NON-nil post-Init + observed by the OTel ManualReader Collect (the auto-observe claim byte-verified — NO additional OTel wiring)")
}
