package telemetry

// day22_track22_test.go (Day 22, ADR-0027) — the T_gc auto-inference SSoT tooth.
//
// §2.f  T-INFER-TELEMETRY-SSoT: the 3 new inferrer counters are in allCounters()
// (count grows to 15, 0 dups, all 15 registered under the real Meter after a
// subprocess Init). The bridge (pkg/metrics/telemetry_bridge.go) enumerates
// the 15 WITHOUT a bridge edit (the §0.f SSoT-grows-auto property — verified by
// a sister tooth in pkg/metrics/day22_track22_test.go that scrapes /metrics +
// asserts the 3 new names appear). This tooth (in-package) asserts the
// allCounters() slice carries the 3 new distinct counters + the subprocess-Init
// fill discipline (the Day-21 fill: a counter missing from rebuildCounters()
// silently drops to nil under --otel — Day 22 does NOT reopen it for the 3 new
// counters; the §0.f construction-vs-distinct trap disarmed).
//
// The subprocess teeth (T-DEDUP-FILL, T-OMISSION-FIRED, T-OTEL-EXPORT) live in
// day21_track21_test.go (the Day-21 pattern). This tooth adds the Day-22
// analogues: a subprocess Init that asserts the 3 new counters are NON-nil
// post-Init (the rebuildCounters fill held for the inferrer counters — the
// omission landmine Day 21 closed stays closed for the 3 new ones).

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

// day22SubprocessMarker is the env var the Day-22 subprocess teeth set when they
// re-invoke the test binary for a fresh process (the Init once-per-process guard
// at registry.go:42 makes a second Init a rejected no-op in-process — the
// Day-21 pattern, re-used).
const day22SubprocessMarker = "SUPREMUM_DAY22_SUBPROC"

// TestTrack22_T_SSoT asserts the 3 new inferrer counters are in allCounters()
// (the SSoT slice), carry their distinct names, and the count grew 12 -> 15 (Day 22)
// (the honest growth ADR-0027 §0.f discloses). The bridge enumerates this slice
// automatically (verified by the sister tooth in pkg/metrics). The tooth ALSO
// asserts the 3 new counters are registered under a real Meter (a subprocess
// Init + ManualReader Collect surfaces the 3 new instruments — the §6.e "the
// OTel callback observes the new gauges automatically" claim byte-verified).
func TestTrack22_T_SSoT(t *testing.T) {
	cs := Counters()
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) RE-PINNED 21 -> 22 (PQHandshakeNegotiated — the PQ-KEM disclosure); Day 30 (ADR-0035) RE-PINNED 19 -> 21 (TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI disclosure; Day 29 re-pinned 18 -> 19; Day 27 had re-pinned 17 -> 18; Day 25 had re-pinned 16 -> 17; Day 24 had re-pinned 15 -> 16; Day 22 had grown 12 -> 15)
	if len(cs) != wantDistinct {
		t.Fatalf("T-INFER-TELEMETRY-SSoT: len(Counters())=%d, want %d (Day 31 grew the SSoT 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure; Day 30 grew the SSoT 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure; Day 29 re-pinned the SSoT 18->19; the stratified-anti-entropy fallback counter — StratifiedAntiEntropyFallback — grew the SSoT Day 29; Day 27's live-source — QueryLiveSourceReads — grew it Day 27; Day 25's manifest-skip — QueryManifestSkippedFirstSys — grew it Day 25; Day 24's download-skip — QueryDownloadSkippedFirstSys — grew it Day 24; the 3 inferrer counters grew it Day 22)", len(cs), wantDistinct)
	}
	// The 3 new names MUST be present (the SSoT carries them).
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
			t.Errorf("T-INFER-TELEMETRY-SSoT: the new counter %q is NOT in Counters() (the SSoT must carry it for the bridge to auto-surface)", n)
		}
	}
	// 0 dups (the construction-vs-distinct trap — a dup would panic MustRegister
	// at boot under the bridge).
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("T-INFER-TELEMETRY-SSoT: duplicate name in Counters(): %q x%d (MustRegister would PANIC at boot)", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("T-INFER-TELEMETRY-SSoT: %d duplicate names — the §0.f construction-vs-distinct trap (MustRegister PANIC at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("T-INFER-TELEMETRY-SSoT: distinct names=%d, want %d", len(seen), wantDistinct)
	}
	t.Logf("T-INFER-TELEMETRY-SSoT PASS: Counters() carries %d DISTINCT (16->17 Day 25; 15->16 Day 24; 12->15 Day 22), the 3 inferrer names present, 0 dups — the SSoT grew honestly; the bridge auto-surfaces the 17th (manifest-skip) WITHOUT an edit (verified by the pkg/metrics sister tooth)", len(cs))
}

// TestTrack22_T_NewCountersNonNilPostInit_Subproc drives a REAL telemetry.Init
// (testMeter) in a fresh subprocess + asserts the 3 new counters are NON-nil
// post-Init (the rebuildCounters fill held for the inferrer counters — the
// omission landmine Day 21 closed for QueryL0ListCapped stays closed for the 3
// new ones; the §0.f construction-vs-distinct trap disarmed). RED control: a
// stale tree where rebuildCounters OMITTED the 3 new fills would leave them nil
// post-Init (the var the init() object was assigned to gets reassigned by
// rebuildCounters; without the fill the new assignment is nil).
func TestTrack22_T_NewCountersNonNilPostInit_Subproc(t *testing.T) {
	if os.Getenv(day22SubprocessMarker) == "newcounters" {
		runDay22NewCountersSubproc(t)
		return
	}
	// Parent: re-invoke the test binary as a subprocess for a fresh process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestTrack22_T_NewCountersNonNilPostInit_Subproc$")
	cmd.Env = append(os.Environ(), day22SubprocessMarker+"=newcounters")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("T-INFER-NEW-COUNTERS subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "T-INFER-NEW-COUNTERS PASS") {
		t.Fatalf("T-INFER-NEW-COUNTERS subprocess did not pass:\n%s", out)
	}
	t.Logf("T-INFER-NEW-COUNTERS PASS (subprocess): the 3 inferrer counters are NON-nil post-Init — the rebuildCounters fill held for them (the Day-21 omission landmine stays closed)")
}

// runDay22NewCountersSubproc is the subprocess entry. It builds a ManualReader,
// Init's the Meter against it, asserts the 3 new counters are NON-nil, drives
// the retreat-refuse counter + the two gauges, Collects, and asserts the 3 new
// instruments appear in the OTel Collect output (the §6.e "gauges observed
// automatically" claim byte-verified — NO additional OTel wiring).
func runDay22NewCountersSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "track22-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("T-INFER-NEW-COUNTERS: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)

	// (a) The 3 new counters are NON-nil post-Init (the rebuildCounters fill).
	if QueryTxTimeHighWaterMark == nil {
		t.Fatalf("T-INFER-NEW-COUNTERS: QueryTxTimeHighWaterMark nil post-Init (the rebuildCounters fill is MISSING — the §0.f omission landmine reopened)")
	}
	if PruningHorizonEffective == nil {
		t.Fatalf("T-INFER-NEW-COUNTERS: PruningHorizonEffective nil post-Init (the rebuildCounters fill is MISSING)")
	}
	if PruningHorizonRetreatRefused == nil {
		t.Fatalf("T-INFER-NEW-COUNTERS: PruningHorizonRetreatRefused nil post-Init (the rebuildCounters fill is MISSING)")
	}

	// (b) Drive the 2 gauges + the retreat-refuse counter, then Collect + assert
	// the 3 new instruments appear in the OTel stream (the §6.e "gauges observed
	// automatically" claim — the PeriodicReader/ManualReader observes modeGauge
	// via Value() -> GaugeValue() at telemetry.go:209; NO additional wiring).
	QueryTxTimeHighWaterMark.Set(7_000_000)
	PruningHorizonEffective.Set(6_500_000)
	PruningHorizonRetreatRefused.Add(3)

	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("T-INFER-NEW-COUNTERS: Collect: %v", cerr)
	}
	// The 3 new names MUST appear in the OTel Collect output (the gauges as a
	// Gauge instrument; the counter as a Sum). The §6.e claim: the OTel callback
	// observes them automatically.
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
			t.Errorf("T-INFER-NEW-COUNTERS: the gauge %q NOT found in the OTel Collect output (the §6.e auto-observe claim is FALSE — the observable callback did not register the gauge under the Meter)", n)
		}
	}
	if !foundCounter {
		t.Errorf("T-INFER-NEW-COUNTERS: the counter 'supremum.compaction.pruning_horizon_retreat_refused' NOT found in the OTel Collect output (the observable callback did not register)")
	}
	t.Logf("T-INFER-NEW-COUNTERS PASS: the 3 inferrer counters are NON-nil post-Init + observed by the OTel ManualReader Collect (the gauges via Value()->GaugeValue() at telemetry.go:209; the §6.e auto-observe claim byte-verified — NO additional OTel wiring)")
}
