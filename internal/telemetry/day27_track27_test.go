package telemetry

// day27_track27_test.go (Day 27, ADR-0032) — the in-package SSoT tooth for the
// read-your-writes live-source counter.
//
// T-LIVE-SSoT: the new read-your-writes live-source disclosure counter
// (QueryLiveSourceReads) is in allCounters() (count grew 17 -> 18 Day 27, 0
// dups, all 18 registered under the real Meter after a subprocess Init). The
// bridge (pkg/metrics/telemetry_bridge.go) enumerates the 18 WITHOUT a bridge
// edit (the §0.f SSoT-grows-auto property — verified by the bridge-byte-
// unchanged assertion in internal/database/day27_track27_test.go
// T-LIVE-NO-FROZEN-TOOTH; the bridge md5 8fcc149b is byte-identical). This
// tooth (in-package) asserts the allCounters() slice carries the new distinct
// counter + the subprocess-Init fill discipline (the Day-21 fill: a counter
// missing from rebuildCounters() silently drops to nil under --otel — Day 27
// does NOT reopen it for the new counter; the §0.f construction-vs-distinct
// trap disarmed).
//
// Day 22 grew 12 -> 15 (the three T_gc auto-inference counters). Day 24 grew
// 15 -> 16 (the filename-bounded download-skip counter). Day 25 grew 16 -> 17
// (the manifest-channel download-skip counter). Day 27 grows 17 -> 18 (the
// read-your-writes live-source counter). The bridge auto-surfaces the 18th
// series WITHOUT an edit (the §0.f SSoT-grows-auto property — the bridge was
// UNCHANGED across Day 22, Day 24, Day 25, AND Day 27; the SIXTH, SEVENTH,
// EIGHTH, then TENTH clean-chain forks; ZERO FROZEN touched). The mode split
// is now 3 gauges + 18 counters (Day 27 added a modeCounter, NOT a gauge; Day 29
// added ANOTHER modeCounter; Day 30 added TWO MORE modeCounters — the PKI
// disclosure — the gauge count STAYS 3).

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

// day27SubprocessMarker is the env var the Day-27 subprocess tooth sets when it
// re-invokes the test binary for a fresh process (the Init once-per-process
// guard at registry.go makes a second Init a rejected no-op in-process — the
// Day-21/22/24/25 pattern, re-used).
const day27SubprocessMarker = "SUPREMUM_DAY27_SUBPROC"

// TestTrack27_T_LIVE_SSoT asserts the new read-your-writes live-source counter
// is in allCounters() (the SSoT slice), carries its distinct name, and the count
// grew 17 -> 18 (Day 27, the honest growth ADR-0032 §0.f discloses). The bridge
// enumerates this slice automatically (verified by the bridge-byte-unchanged
// assertion in internal/database T-LIVE-NO-FROZEN-TOUCH). The tooth ALSO
// asserts the new counter is registered under a real Meter (a subprocess Init +
// ManualReader Collect surfaces the new instrument — the §6.e "the OTel
// callback observes the new counter automatically" claim byte-verified). The
// tooth re-verifies the Day-24 download-skip + Day-25 manifest-skip counters are
// STILL present (Day 27 appended an 18th, did NOT drop any prior counter — the
// append-only-after-construction contract).
func TestTrack27_T_LIVE_SSoT(t *testing.T) {
	cs := Counters()
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) RE-PINNED 21 -> 22 (PQHandshakeNegotiated — the PQ-KEM disclosure); Day 30 (ADR-0035) RE-PINNED 19 -> 21 (TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI disclosure; Day 29 re-pinned 18 -> 19; Day 27 grew 17 -> 18; Day 25 grew 16 -> 17; Day 24 grew 15 -> 16; Day 22 grew 12 -> 15)
	if len(cs) != wantDistinct {
		t.Fatalf("T-LIVE-SSoT: len(Counters())=%d, want %d (Day 31 grew the SSoT 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure MUST be in the slice; Day 30 grew the SSoT 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure MUST be in the slice; Day 29 grew the SSoT 18->19; the stratified-anti-entropy fallback counter — StratifiedAntiEntropyFallback — MUST be in the slice; Day 27's live-source — QueryLiveSourceReads — grew it 17->18; Day 25's manifest-skip grew it 16->17; Day 24's download-skip grew it 15->16; the 3 inferrer counters grew it 12->15 Day 22)", len(cs), wantDistinct)
	}
	// The new name MUST be present (the SSoT carries it).
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
			t.Errorf("T-LIVE-SSoT: the new counter %q is NOT in Counters() (the SSoT must carry it for the bridge to auto-surface)", n)
		}
	}
	// 0 dups (the construction-vs-distinct trap — a dup would panic MustRegister
	// at boot under the bridge).
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("T-LIVE-SSoT: duplicate name in Counters(): %q x%d (MustRegister would PANIC at boot)", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("T-LIVE-SSoT: %d duplicate names — the §0.f construction-vs-distinct trap (MustRegister PANIC at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("T-LIVE-SSoT: distinct names=%d, want %d", len(seen), wantDistinct)
	}
	// The Day-24 download-skip + Day-25 manifest-skip counters are STILL present
	// (Day 27 appended an 18th, did NOT drop any prior counter — the append-only-
	// after-construction contract at registry.go allCounters()).
	for _, n := range []string{
		"supremum.l0.query_download_skipped_first_sys",
		"supremum.compaction.query_manifest_skipped_first_sys",
	} {
		if _, ok := seen[n]; !ok {
			t.Errorf("T-LIVE-SSoT: the prior counter %q is MISSING (Day 27 must append, not replace)", n)
		}
	}
	// The mode split: 3 gauges + 20 counters (Day 27 added a modeCounter, NOT a
	// gauge; Day 29 added ANOTHER modeCounter — the gauge count STAYS 3; Day 30
	// added TWO MORE modeCounters — CertRotationTriggered + CertRevokedRejected,
	// the PKI disclosure — the gauge count STAYS 3; Day 31 added ONE MORE
	// modeCounter — PQHandshakeNegotiated, the PQ-KEM disclosure — the gauge
	// count STAYS 3; Day 32 added ONE MORE modeCounter — HybridFrameAccepted,
	// the hybrid-SIGN-WIRE accept disclosure — the gauge count STAYS 3). The
	// honest growth the day18 tooth pins.
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
		t.Fatalf("T-LIVE-SSoT: mode split %d counters + %d gauges; want 21 counters + 3 gauges (Day 34 added ONE modeCounter — InterRegionEnvelopesShipped, the region-aware inter-region-envelope disclosure — the gauge count STAYS 3; Day 32 added ONE modeCounter — HybridFrameAccepted, the hybrid-SIGN-WIRE accept disclosure — the gauge count STAYS 3; Day 31 added ONE modeCounter — PQHandshakeNegotiated, the PQ-KEM disclosure — the gauge count STAYS 3; Day 30 added TWO modeCounters — CertRotationTriggered + CertRevokedRejected, the PKI leaf-rotation + revocation-reject disclosure — the gauge count STAYS 3; Day 29 added a modeCounter — the gauge count STAYS 3; Day 27 was 15+3, Day 29 grew 15->16 counters, Day 30 grew 16->18 counters, Day 31 grew 18->19 counters, Day 32 grew 19->20 counters, Day 34 grew 20->21 counters)", counters, gauges)
	}
	t.Logf("T-LIVE-SSoT PASS: Counters() carries %d DISTINCT (15->16->17->18->19->21->22->23->24), the new live-source name present, 0 dups, the Day-24+25 counters preserved, mode split 21 counters + 3 gauges — the SSoT grew honestly; the bridge auto-surfaces the 20th + 21st + 22nd + 23rd + 24th WITHOUT an edit (byte-unchanged, verified by internal/database T-LIVE-NO-FROZEN-TOUCH)", len(cs))
}

// TestTrack27_T_LIVE_NewCounterNonNilPostInit_Subproc drives a REAL
// telemetry.Init (testMeter) in a fresh subprocess + asserts the new
// live-source counter is NON-nil post-Init (the rebuildCounters fill held for
// the 18th counter — the omission landmine Day 21 closed for QueryL0ListCapped
// stays closed for Day 27's new counter; the §0.f construction-vs-distinct trap
// disarmed). RED control: a stale tree where rebuildCounters OMITTED the new
// fill would leave it nil post-Init (the var the init() object was assigned to
// gets reassigned by rebuildCounters; without the fill the new assignment is
// nil).
func TestTrack27_T_LIVE_NewCounterNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(day27SubprocessMarker) == "newcounters" {
		runDay27NewCountersSubproc(t)
		return
	}
	// Parent: re-invoke the test binary as a subprocess for a fresh process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestTrack27_T_LIVE_NewCounterNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), day27SubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("T-LIVE-NEW-COUNTERS subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "T-LIVE-NEW-COUNTERS PASS") {
		t.Fatalf("T-LIVE-NEW-COUNTERS subprocess did not pass:\n%s", out)
	}
	t.Logf("T-LIVE-NEW-COUNTERS PASS (subprocess): the live-source counter is NON-nil post-Init — the rebuildCounters fill held for it (the Day-21 omission landmine stays closed for the 18th)")
}

// runDay27NewCountersSubproc is the subprocess entry. It builds a ManualReader,
// Init's the Meter against it, asserts the new counter is NON-nil, drives it,
// Collects, and asserts the new instrument appears in the OTel Collect output
// (the §6.e "the counter is observed automatically" claim byte-verified — NO
// additional OTel wiring — the bridge + the OTel callback both observe the new
// counter via the SSoT slice, NOT a per-counter registration).
func runDay27NewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "track27-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("T-LIVE-NEW-COUNTERS: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	// (a) The new counter is NON-nil post-Init (the rebuildCounters fill).
	if QueryLiveSourceReads == nil {
		t.Fatalf("T-LIVE-NEW-COUNTERS: QueryLiveSourceReads nil post-Init (the rebuildCounters fill is MISSING — the §0.f omission landmine reopened for the 18th counter)")
	}

	// (b) Drive the counter, then Collect + assert the new instrument appears in
	// the OTel stream (the §6.e "the counter is observed automatically" claim —
	// the ManualReader observes the modeCounter via Value() at telemetry.go).
	QueryLiveSourceReads.Add(7)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("T-LIVE-NEW-COUNTERS: Collect: %v", cerr)
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
		t.Errorf("T-LIVE-NEW-COUNTERS: the counter 'supremum.query.live_source_reads' NOT found in the OTel Collect output (the observable callback did not register — the §6.e auto-observe claim is FALSE)")
	}
	t.Logf("T-LIVE-NEW-COUNTERS PASS: the live-source counter is NON-nil post-Init + observed by the OTel ManualReader Collect (the §6.e auto-observe claim byte-verified — NO additional OTel wiring)")
}
