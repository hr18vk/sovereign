package telemetry

// day25_track25_test.go (Day 25, ADR-0030) — the in-package SSoT tooth for the
// manifest-channel download-skip counter.
//
// §0.f  T-MANIFEST-TELEMETRY-SSoT: the new manifest-channel download-skip counter
// (QueryManifestSkippedFirstSys) is in allCounters() (count grew 16 -> 17 Day 25,
// 0 dups, all 17 registered under the real Meter after a subprocess Init). The
// bridge (pkg/metrics/telemetry_bridge.go) enumerates the 17 WITHOUT a bridge
// edit (the §0.f SSoT-grows-auto property — verified by a sister tooth in
// pkg/metrics/day25_track25_test.go that scrapes /metrics + asserts the new name
// appears). This tooth (in-package) asserts the allCounters() slice carries the
// new distinct counter + the subprocess-Init fill discipline (the Day-21 fill: a
// counter missing from rebuildCounters() silently drops to nil under --otel —
// Day 25 does NOT reopen it for the new counter; the §0.f construction-vs-distinct
// trap disarmed).
//
// The subprocess teeth (T-DEDUP-FILL, T-OMISSION-FIRED, T-OTEL-EXPORT) live in
// day21_track21_test.go (the Day-21 pattern). This tooth adds the Day-25
// analogue: a subprocess Init that asserts the new counter is NON-nil post-Init
// (the rebuildCounters fill held for the manifest-skip counter — the omission
// landmine Day 21 closed stays closed for the 17th counter).
//
// Day 22 grew 12 -> 15 (the three T_gc auto-inference counters). Day 24 grew
// 15 -> 16 (the filename-bounded download-skip counter). Day 25 grows 16 -> 17
// (the manifest-channel download-skip counter). The bridge auto-surfaces the
// 17th series WITHOUT an edit (the §0.f SSoT-grows-auto property — the bridge
// was UNCHANGED across Day 22, Day 24, AND Day 25; the SIXTH, SEVENTH, then
// EIGHTH clean-chain forks; ZERO FROZEN touched).

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

// day25SubprocessMarker is the env var the Day-25 subprocess tooth sets when it
// re-invokes the test binary for a fresh process (the Init once-per-process guard
// at registry.go makes a second Init a rejected no-op in-process — the Day-21/22/
// 24 pattern, re-used).
const day25SubprocessMarker = "SUPREMUM_DAY25_SUBPROC"

// TestTrack25_T_SSoT asserts the new manifest-channel download-skip counter is in
// allCounters() (the SSoT slice), carries its distinct name, and the count grew
// 16 -> 17 (Day 25, the honest growth ADR-0030 §0.f discloses). The bridge
// enumerates this slice automatically (verified by the sister tooth in pkg/metrics).
// The tooth ALSO asserts the new counter is registered under a real Meter (a
// subprocess Init + ManualReader Collect surfaces the new instrument — the §6.e
// "the OTel callback observes the new counter automatically" claim byte-verified).
// The tooth re-verifies the 3 Day-22 inferrer counters + the Day-24 download-skip
// counter are STILL present (Day 25 appended a 17th, did NOT drop any prior
// counter — the append-only-after-construction contract).
func TestTrack25_T_SSoT(t *testing.T) {
	cs := Counters()
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) RE-PINNED 21 -> 22 (PQHandshakeNegotiated — the PQ-KEM disclosure); Day 30 (ADR-0035) RE-PINNED 19 -> 21 (TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure; Day 29 re-pinned 18 -> 19; Day 27 grew 17 -> 18; Day 25 grew 16 -> 17; Day 24 grew 15 -> 16; Day 22 grew 12 -> 15)
	if len(cs) != wantDistinct {
		t.Fatalf("T-MANIFEST-TELEMETRY-SSoT: len(Counters())=%d, want %d (Day 31 grew the SSoT 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure MUST be in the slice; Day 30 grew the SSoT 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure MUST be in the slice; Day 29 grew the SSoT 18->19; the stratified-anti-entropy fallback counter — StratifiedAntiEntropyFallback — MUST be in the slice; Day 27's live-source — QueryLiveSourceReads — grew it 17->18; Day 25's manifest-skip — QueryManifestSkippedFirstSys — grew it 16->17; Day 24's download-skip — QueryDownloadSkippedFirstSys — grew it 15->16; the 3 inferrer counters grew it 12->15 Day 22)", len(cs), wantDistinct)
	}
	// The new name MUST be present (the SSoT carries it).
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
			t.Errorf("T-MANIFEST-TELEMETRY-SSoT: the new counter %q is NOT in Counters() (the SSoT must carry it for the bridge to auto-surface)", n)
		}
	}
	// 0 dups (the construction-vs-distinct trap — a dup would panic MustRegister
	// at boot under the bridge).
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("T-MANIFEST-TELEMETRY-SSoT: duplicate name in Counters(): %q x%d (MustRegister would PANIC at boot)", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("T-MANIFEST-TELEMETRY-SSoT: %d duplicate names — the §0.f construction-vs-distinct trap (MustRegister PANIC at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("T-MANIFEST-TELEMETRY-SSoT: distinct names=%d, want %d", len(seen), wantDistinct)
	}
	// The three Day-22 inferrer counters + the Day-24 download-skip counter are
	// STILL present (Day 25 appended a 17th, did NOT drop any prior counter — the
	// append-only-after-construction contract at registry.go allCounters()).
	for _, n := range []string{
		"supremum.query_txtime_high_water_mark_ns",
		"supremum.compaction.pruning_horizon_effective_ns",
		"supremum.compaction.pruning_horizon_retreat_refused",
		"supremum.l0.query_download_skipped_first_sys",
	} {
		if _, ok := seen[n]; !ok {
			t.Errorf("T-MANIFEST-TELEMETRY-SSoT: the prior counter %q is MISSING (Day 25 must append, not replace)", n)
		}
	}
	t.Logf("T-MANIFEST-TELEMETRY-SSoT PASS: Counters() carries %d DISTINCT (15->16->17), the new manifest-skip name present, 0 dups, the 3 Day-22 counters + the Day-24 download-skip preserved — the SSoT grew honestly; the bridge auto-surfaces the 17th WITHOUT an edit (verified by the pkg/metrics sister tooth)", len(cs))
}

// TestTrack25_T_NewCounterNonNilPostInit_Subproc drives a REAL telemetry.Init
// (testMeter) in a fresh subprocess + asserts the new manifest-skip counter is
// NON-nil post-Init (the rebuildCounters fill held for the 17th counter — the
// omission landmine Day 21 closed for QueryL0ListCapped stays closed for Day 25's
// new counter; the §0.f construction-vs-distinct trap disarmed). RED control: a
// stale tree where rebuildCounters OMITTED the new fill would leave it nil post-
// Init (the var the init() object was assigned to gets reassigned by
// rebuildCounters; without the fill the new assignment is nil).
func TestTrack25_T_NewCounterNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(day25SubprocessMarker) == "newcounters" {
		runDay25NewCountersSubproc(t)
		return
	}
	// Parent: re-invoke the test binary as a subprocess for a fresh process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestTrack25_T_NewCounterNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), day25SubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("T-MANIFEST-NEW-COUNTERS subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "T-MANIFEST-NEW-COUNTERS PASS") {
		t.Fatalf("T-MANIFEST-NEW-COUNTERS subprocess did not pass:\n%s", out)
	}
	t.Logf("T-MANIFEST-NEW-COUNTERS PASS (subprocess): the manifest-skip counter is NON-nil post-Init — the rebuildCounters fill held for it (the Day-21 omission landmine stays closed for the 17th)")
}

// runDay25NewCountersSubproc is the subprocess entry. It builds a ManualReader,
// Init's the Meter against it, asserts the new counter is NON-nil, drives it,
// Collects, and asserts the new instrument appears in the OTel Collect output
// (the §6.e "the counter is observed automatically" claim byte-verified — NO
// additional OTel wiring — the bridge + the OTel callback both observe the new
// counter via the SSoT slice, NOT a per-counter registration).
func runDay25NewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "track25-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("T-MANIFEST-NEW-COUNTERS: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	// (a) The new counter is NON-nil post-Init (the rebuildCounters fill).
	if QueryManifestSkippedFirstSys == nil {
		t.Fatalf("T-MANIFEST-NEW-COUNTERS: QueryManifestSkippedFirstSys nil post-Init (the rebuildCounters fill is MISSING — the §0.f omission landmine reopened for the 17th counter)")
	}

	// (b) Drive the counter, then Collect + assert the new instrument appears in
	// the OTel stream (the §6.e "the counter is observed automatically" claim —
	// the ManualReader observes the modeCounter via Value() at telemetry.go).
	QueryManifestSkippedFirstSys.Add(11)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("T-MANIFEST-NEW-COUNTERS: Collect: %v", cerr)
	}
	// The new name MUST appear in the OTel Collect output (the counter as a Sum).
	foundCounter := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "supremum.compaction.query_manifest_skipped_first_sys" {
				foundCounter = true
			}
		}
	}
	if !foundCounter {
		t.Errorf("T-MANIFEST-NEW-COUNTERS: the counter 'supremum.compaction.query_manifest_skipped_first_sys' NOT found in the OTel Collect output (the observable callback did not register — the §6.e auto-observe claim is FALSE)")
	}
	t.Logf("T-MANIFEST-NEW-COUNTERS PASS: the manifest-skip counter is NON-nil post-Init + observed by the OTel ManualReader Collect (the §6.e auto-observe claim byte-verified — NO additional OTel wiring)")
}
