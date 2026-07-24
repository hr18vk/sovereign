// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package telemetry

// The read-your-writes live-source counter guards (ADR-0032).
//
// The new read-your-writes live-source disclosure counter (QueryLiveSourceReads)
// is in allCounters() (0 dups, registered under the real Meter after a
// subprocess Init). The bridge (pkg/metrics/telemetry_bridge.go) enumerates the
// slice WITHOUT a bridge edit (the slice auto-surface property — the bridge is
// byte-unchanged). This in-package guard asserts the allCounters() slice carries
// the new distinct counter + the subprocess-Init fill discipline (a counter
// missing from rebuildCounters() silently drops to nil under --otel — not
// reopened for the new counter; the construction-vs-distinct trap disarmed).
//
// The distinct-counter count grows as disclosure counters are added (the T_gc
// auto-inference counters, the two download-skip counters, then this
// live-source counter); the bridge auto-surfaces each new series WITHOUT an
// edit. Each addition is a modeCounter, so the gauge count stays 3.

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

// liveSourceSubprocessMarker is the env var the subprocess guards set when they
// re-invoke the test binary for a fresh process (the Init once-per-process
// guard makes a second Init a rejected no-op in-process).
const liveSourceSubprocessMarker = "SUPREMUM_LIVE_SOURCE_SUBPROC"

// TestLiveSourceCounterInRegistry asserts the new read-your-writes live-source
// counter is in allCounters() (the counter slice), carries its distinct name,
// and that the slice grew to include it (the honest growth ADR-0032 discloses).
// The bridge enumerates this slice automatically (verified byte-unchanged). The
// guard ALSO asserts the new counter is registered under a real Meter (a
// subprocess Init + ManualReader Collect surfaces the new instrument — the
// "OTel callback observes the new counter automatically" claim byte-verified).
// The guard re-verifies the download-skip + manifest-skip counters are STILL
// present (the slice appended, did NOT drop any prior counter — the
// append-only-after-construction contract).
func TestLiveSourceCounterInRegistry(t *testing.T) {
	cs := Counters()
	const wantDistinct = 24 // distinct counters; grew across the ADR series as disclosure counters were added
	if len(cs) != wantDistinct {
		t.Fatalf("live-source: len(Counters())=%d, want %d (grew the counter 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure MUST be in the slice; grew the counter 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure MUST be in the slice; grew the counter 18->19; the stratified-anti-entropy fallback counter — StratifiedAntiEntropyFallback — MUST be in the slice; the live-source — QueryLiveSourceReads — grew it 17->18; the manifest-skip grew it 16->17; the download-skip grew it 15->16; the 3 inferrer counters grew it 12->15)", len(cs), wantDistinct)
	}
	// The new name MUST be present (the slice carries it).
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
			t.Errorf("live-source: the new counter %q is NOT in Counters() (the counter must carry it for the bridge to auto-surface)", n)
		}
	}
	// 0 dups (the construction-vs-distinct trap — a dup would panic MustRegister
	// at boot under the bridge).
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("live-source: duplicate name in Counters(): %q x%d (MustRegister would PANIC at boot)", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("live-source: %d duplicate names — the §0.f construction-vs-distinct trap (MustRegister PANIC at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("live-source: distinct names=%d, want %d", len(seen), wantDistinct)
	}
	// The download-skip + manifest-skip counters are STILL present (the slice
	// appended, did NOT drop any prior counter — the append-only-after-
	// construction contract at registry.go allCounters()).
	for _, n := range []string{
		"supremum.l0.query_download_skipped_first_sys",
		"supremum.compaction.query_manifest_skipped_first_sys",
	} {
		if _, ok := seen[n]; !ok {
			t.Errorf("live-source: the prior counter %q is MISSING (must append, not replace)", n)
		}
	}
	// The mode split: 3 gauges + the rest modeCounters. Every disclosure counter
	// added is a modeCounter, so the gauge count stays 3 while the counter count
	// grows. The mode split is asserted to match the honest growth.
	counters, gauges := 0, 0
	for _, c := range cs {
		switch c.Mode() {
		case modeCounter:
			counters++
		case modeGauge:
			gauges++
		}
	}
	if gauges != 3 || counters != 21 {
		t.Fatalf("live-source: mode split %d counters + %d gauges; want 21 counters + 3 gauges (added ONE modeCounter — InterRegionEnvelopesShipped, the region-aware inter-region-envelope disclosure — the gauge count STAYS 3; added ONE modeCounter — HybridFrameAccepted, the hybrid-SIGN-WIRE accept disclosure — the gauge count STAYS 3; added ONE modeCounter — PQHandshakeNegotiated, the PQ-KEM disclosure — the gauge count STAYS 3; added TWO modeCounters — CertRotationTriggered + CertRevokedRejected, the PKI leaf-rotation + revocation-reject disclosure — the gauge count STAYS 3; added a modeCounter — the gauge count STAYS 3; was 15+3, grew 15->16 counters, grew 16->18 counters, grew 18->19 counters, grew 19->20 counters, grew 20->21 counters)", counters, gauges)
	}
	t.Logf("live-source PASS: Counters() carries %d DISTINCT (15->16->17->18->19->21->22->23->24), the new live-source name present, 0 dups, the +25 counters preserved, mode split 21 counters + 3 gauges — the counter grew honestly; the bridge auto-surfaces the 20th + 21st + 22nd + 23rd + 24th WITHOUT an edit (byte-unchanged, verified by the internal/database no-protected-core-touch guard)", len(cs))
}

// TestLiveSourceCounterNonNilPostInit_Subproc drives a REAL telemetry.Init
// (testMeter) in a fresh subprocess + asserts the new live-source counter is
// NON-nil post-Init (the rebuildCounters fill held for it — the omission
// landmine stays closed for the new counter; the construction-vs-distinct trap
// disarmed). Negative control: a stale tree where rebuildCounters OMITTED the
// new fill would leave it nil post-Init (the var the init() object was assigned
// to gets reassigned by rebuildCounters; without the fill the new assignment is
// nil).
func TestLiveSourceCounterNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(liveSourceSubprocessMarker) == "newcounters" {
		runLiveSourceNewCountersSubproc(t)
		return
	}
	// Parent: re-invoke the test binary as a subprocess for a fresh process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestLiveSourceCounterNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), liveSourceSubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("live-source-new-counters subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "live-source-new-counters PASS") {
		t.Fatalf("live-source-new-counters subprocess did not pass:\n%s", out)
	}
	t.Logf("live-source-new-counters PASS (subprocess): the live-source counter is NON-nil post-Init — the rebuildCounters fill held for it (the omission landmine stays closed for the 18th)")
}

// runLiveSourceNewCountersSubproc is the subprocess entry. It builds a ManualReader,
// Init's the Meter against it, asserts the new counter is NON-nil, drives it,
// Collects, and asserts the new instrument appears in the OTel Collect output
// (the "counter is observed automatically" claim byte-verified — NO additional
// OTel wiring — the bridge + the OTel callback both observe the new counter via
// the slice, NOT a per-counter registration).
func runLiveSourceNewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "live-source-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("live-source-new-counters: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	// (a) The new counter is NON-nil post-Init (the rebuildCounters fill).
	if QueryLiveSourceReads == nil {
		t.Fatalf("live-source-new-counters: QueryLiveSourceReads nil post-Init (the rebuildCounters fill is MISSING — the §0.f omission landmine reopened for the 18th counter)")
	}

	// (b) Drive the counter, then Collect + assert the new instrument appears in
	// the OTel stream (the "counter is observed automatically" claim — the
	// ManualReader observes the modeCounter via Value()).
	QueryLiveSourceReads.Add(7)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("live-source-new-counters: Collect: %v", cerr)
	}
	// The new name MUST appear in the OTel Collect output (the counter as a Sum).
	foundCounter := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "supremum.query.live_source_reads" {
				foundCounter = true
			}
		}
	}
	if !foundCounter {
		t.Errorf("live-source-new-counters: the counter 'supremum.query.live_source_reads' NOT found in the OTel Collect output (the observable callback did not register — the §6.e auto-observe claim is FALSE)")
	}
	t.Logf("live-source-new-counters PASS: the live-source counter is NON-nil post-Init + observed by the OTel ManualReader Collect (the §6.e auto-observe claim byte-verified — NO additional OTel wiring)")
}
