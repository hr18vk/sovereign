package telemetry

// day24_track24_test.go (Day 24, ADR-0029) — the filename-bounded download-skip
// SSoT tooth.
//
// §2.f  T-SKIP-TELEMETRY-SSoT: the new download-skip counter
// (QueryDownloadSkippedFirstSys) is in allCounters() (count grew 15 -> 16 Day 24;
// Day 25 ADR-0030 grew it 16 -> 17 via the manifest-skip counter
// QueryManifestSkippedFirstSys, 0 dups, all 17 registered under the real Meter
// after a subprocess Init). The bridge (pkg/metrics/telemetry_bridge.go)
// enumerates the 17 WITHOUT a bridge edit (the §0.f SSoT-grows-auto property —
// verified by a sister tooth in pkg/metrics/day24_track24_test.go that scrapes
// /metrics + asserts the new name appears). This tooth (in-package) asserts the
// allCounters() slice carries the new distinct counter + the subprocess-Init fill
// discipline (the Day-21 fill: a counter missing from rebuildCounters() silently
// drops to nil under --otel — Day 24 does NOT reopen it for the new counter; the
// §0.f construction-vs-distinct trap disarmed).
//
// The subprocess teeth (T-DEDUP-FILL, T-OMISSION-FIRED, T-OTEL-EXPORT) live in
// day21_track21_test.go (the Day-21 pattern). This tooth adds the Day-24
// analogue: a subprocess Init that asserts the new counter is NON-nil post-Init
// (the rebuildCounters fill held for the download-skip counter — the omission
// landmine Day 21 closed stays closed for the 16th counter).
//
// Day 22 grew 12 -> 15 (the three T_gc auto-inference counters). Day 24 grows
// 15 -> 16 (the single download-skip counter). Day 25 (ADR-0030) grew it 16 -> 17
// (the manifest-skip counter); this tooth was RE-PINNED 16 -> 17 by Day 25 (the
// honest count-growth class Day-22 M4 + Day-24 hit again — the SSoT grows, the
// assertion teeth follow). The bridge auto-surfaces the 17th series WITHOUT an
// edit (the §0.f SSoT-grows-auto property — the bridge was UNCHANGED across
// Day-22 AND Day-24 AND Day-25; the SIXTH, SEVENTH, then EIGHTH clean-chain
// forks).

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

// day24SubprocessMarker is the env var the Day-24 subprocess teeth set when they
// re-invoke the test binary for a fresh process (the Init once-per-process guard
// at registry.go:42 makes a second Init a rejected no-op in-process — the
// Day-21/22 pattern, re-used).
const day24SubprocessMarker = "SUPREMUM_DAY24_SUBPROC"

// TestTrack24_T_SSoT asserts the new download-skip counter is in allCounters()
// (the SSoT slice), carries its distinct name, and the count grew 15 -> 16
// (Day 24, the honest growth ADR-0029 §0.f discloses) — Day 25 (ADR-0030) later
// re-pinned this tooth 16 -> 17 + added the manifest-skip name to its
// wantNames table (the count-growth class Day-22 M4 + Day-24 hit again). The
// bridge enumerates this slice automatically (verified by the sister tooth in
// pkg/metrics). The tooth ALSO asserts the new counter is registered under a
// real Meter (a subprocess Init + ManualReader Collect surfaces the new
// instrument — the §6.e "the OTel callback observes the new counter
// automatically" claim byte-verified).
func TestTrack24_T_SSoT(t *testing.T) {
	cs := Counters()
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) RE-PINNED 21 -> 22 (PQHandshakeNegotiated — the PQ-KEM disclosure); RE-PINNED 19 -> 21 by Day 30 (ADR-0035, TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure); Day 29 re-pinned 18 -> 19 (the stratified-anti-entropy fallback counter); Day 27 re-pinned 17 -> 18 (the live-source counter); Day 25 re-pinned 16 -> 17 (the manifest-skip counter); Day 24 grew 15 -> 16 (the download-skip counter)
	if len(cs) != wantDistinct {
		t.Fatalf("T-SKIP-TELEMETRY-SSoT: len(Counters())=%d, want %d (Day 31 grew the SSoT 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure MUST be in the slice; Day 30 grew the SSoT 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure MUST be in the slice; Day 29 re-pinned the SSoT 18->19; the stratified-anti-entropy fallback counter — StratifiedAntiEntropyFallback — MUST be in the slice; Day 27 re-pinned 17->18; Day 25 re-pinned 16->17; Day 24 grew 15->16; the download-skip counter — QueryDownloadSkippedFirstSys — MUST be in the slice; the manifest-skip counter — QueryManifestSkippedFirstSys — grew it 16->17)", len(cs), wantDistinct)
	}
	// The new names MUST be present (the SSoT carries BOTH the Day-24 download-
	// skip counter AND the Day-25 manifest-skip counter — Day 25 re-pinned this
	// tooth to also verify its OWN counter coexists with the Day-24 one).
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
			t.Errorf("T-SKIP-TELEMETRY-SSoT: the new counter %q is NOT in Counters() (the SSoT must carry it for the bridge to auto-surface)", n)
		}
	}
	// 0 dups (the construction-vs-distinct trap — a dup would panic MustRegister
	// at boot under the bridge).
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("T-SKIP-TELEMETRY-SSoT: duplicate name in Counters(): %q x%d (MustRegister would PANIC at boot)", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("T-SKIP-TELEMETRY-SSoT: %d duplicate names — the §0.f construction-vs-distinct trap (MustRegister PANIC at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("T-SKIP-TELEMETRY-SSoT: distinct names=%d, want %d", len(seen), wantDistinct)
	}
	// The three Day-22 inferrer counters are STILL present (Day 24 grew the
	// slice, did NOT drop any prior counter — the append-only-after-construction
	// contract at registry.go allCounters()).
	for _, n := range []string{
		"supremum.query_txtime_high_water_mark_ns",
		"supremum.compaction.pruning_horizon_effective_ns",
		"supremum.compaction.pruning_horizon_retreat_refused",
	} {
		if _, ok := seen[n]; !ok {
			t.Errorf("T-SKIP-TELEMETRY-SSoT: the Day-22 counter %q is MISSING (Day 24 must append, not replace)", n)
		}
	}
	t.Logf("T-SKIP-TELEMETRY-SSoT PASS: Counters() carries %d DISTINCT (15->16->17), the download-skip + manifest-skip names present, 0 dups, the 3 Day-22 counters preserved — the SSoT grew honestly; the bridge auto-surfaces the 17th WITHOUT an edit (verified by the pkg/metrics sister tooth)", len(cs))
}

// TestTrack24_T_NewCounterNonNilPostInit_Subproc drives a REAL telemetry.Init
// (testMeter) in a fresh subprocess + asserts the new download-skip counter is
// NON-nil post-Init (the rebuildCounters fill held for the 16th counter — the
// omission landmine Day 21 closed for QueryL0ListCapped stays closed for Day
// 24's new counter; the §0.f construction-vs-distinct trap disarmed). RED
// control: a stale tree where rebuildCounters OMITTED the new fill would leave
// it nil post-Init (the var the init() object was assigned to gets reassigned by
// rebuildCounters; without the fill the new assignment is nil).
func TestTrack24_T_NewCounterNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(day24SubprocessMarker) == "newcounters" {
		runDay24NewCountersSubproc(t)
		return
	}
	// Parent: re-invoke the test binary as a subprocess for a fresh process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestTrack24_T_NewCounterNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), day24SubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("T-SKIP-NEW-COUNTERS subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "T-SKIP-NEW-COUNTERS PASS") {
		t.Fatalf("T-SKIP-NEW-COUNTERS subprocess did not pass:\n%s", out)
	}
	t.Logf("T-SKIP-NEW-COUNTERS PASS (subprocess): the download-skip counter is NON-nil post-Init — the rebuildCounters fill held for it (the Day-21 omission landmine stays closed for the 16th)")
}

// runDay24NewCountersSubproc is the subprocess entry. It builds a ManualReader,
// Init's the Meter against it, asserts the new counter is NON-nil, drives it,
// Collects, and asserts the new instrument appears in the OTel Collect output
// (the §6.e "the counter is observed automatically" claim byte-verified — NO
// additional OTel wiring).
func runDay24NewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "track24-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("T-SKIP-NEW-COUNTERS: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	// (a) The new counter is NON-nil post-Init (the rebuildCounters fill).
	if QueryDownloadSkippedFirstSys == nil {
		t.Fatalf("T-SKIP-NEW-COUNTERS: QueryDownloadSkippedFirstSys nil post-Init (the rebuildCounters fill is MISSING — the §0.f omission landmine reopened for the 16th counter)")
	}

	// (b) Drive the counter, then Collect + assert the new instrument appears in
	// the OTel stream (the §6.e "the counter is observed automatically" claim —
	// the ManualReader observes the modeCounter via Value() at telemetry.go).
	QueryDownloadSkippedFirstSys.Add(7)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("T-SKIP-NEW-COUNTERS: Collect: %v", cerr)
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
		t.Errorf("T-SKIP-NEW-COUNTERS: the counter 'supremum.l0.query_download_skipped_first_sys' NOT found in the OTel Collect output (the observable callback did not register — the §6.e auto-observe claim is FALSE)")
	}
	t.Logf("T-SKIP-NEW-COUNTERS PASS: the download-skip counter is NON-nil post-Init + observed by the OTel ManualReader Collect (the §6.e auto-observe claim byte-verified — NO additional OTel wiring)")
}
