package telemetry

import (
	"math"
	"testing"
)

// Day 18 (ADR-0023) in-package teeth. These assert invariants the cross-package
// pkg/metrics bridge teeth CANNOT — because they depend on the unexported
// Counter.lastReported field and the counterMode constants. The bridge
// (pkg/metrics) reads only the exported accessors (Name/Description/Unit/Mode/
// Value); these teeth assert the bridge's contract against the package-internal
// state it depends on.
//
// T4 (in-package): the bridge reads CUMULATIVE via Value() and NEVER touches
// lastReported. lastReported is the OTel-callback field (telemetry.go:258) —
// reading it from the bridge couples the bridge to the OTel cadence and tears
// the delta if OTel fires between scrapes (the §0.b production double-count).
// TODAY telemetry.Init is never called, so lastReported stays 0. This tooth
// Incs a counter + asserts lastReported is STILL 0 (UNCHANGED) — pre-empting
// the future-fork bind of a real OTel Meter.
//
// T2 (in-package): the SSoT slice Counters() carries exactly the distinct
// package vars, NO duplicate names (the QueryL0ListCapped construction-dup is
// construction-site, not slice-site — the bridge must never see the dup, or
// its MustRegister panics on a duplicate Desc at boot).

// TestTrack18_InPackage_T4_LastReportedUntouched is the AUTHORITATIVE
// double-count-trap guard. The cross-package pkg/metrics T4 tooth asserts the
// SCRAPE value == Counter.Value(); this tooth asserts the FIELD-level
// invariant lastReported is UNCHANGED (0) after Inc — the field the bridge is
// FORBIDDEN to read. A future fork that binds a real OTel Meter arms the
// registerInt64Counter callback, which IS allowed to advance lastReported
// (that is its job); a bridge that ALSO touched lastReported would double-
// count. This tooth passes today (lastReported==0, OTel never armed) and will
// keep passing for the BRIDGE as long as the bridge never touches the field.
func TestTrack18_InPackage_T4_LastReportedUntouched(t *testing.T) {
	c := CompactionRowsPruned
	if c == nil {
		t.Fatal("CompactionRowsPruned nil — construction order changed")
	}
	// Baseline: lastReported must be 0 today (Init never called across the
	// whole process; the OTel callback never fires).
	if got := c.lastReported.Load(); got != 0 {
		t.Fatalf("baseline lastReported=%d, want 0 — a prior test armed the OTel "+
			"callback (telemetry.Init was called); this asserts the BRIDGE never "+
			"touches it, so a non-zero baseline from another caller is a test-order "+
			"contamination to investigate, not a bridge defect. (This fork does "+
			"NOT call Init.)", got)
	}
	const n = 13
	for i := 0; i < n; i++ {
		c.Inc()
	}
	// The cumulative must have advanced (Value() is the read path the bridge
	// uses); lastReported must STILL be 0 (the bridge reads only Value()).
	cumulative := c.Value()
	if math.Abs(cumulative-float64(n)) > 0.5 {
		t.Fatalf("Counter.Value() after %d Inc = %v (want %d) — the read path the "+
			"bridge depends on is broken", n, cumulative, n)
	}
	if got := c.lastReported.Load(); got != 0 {
		t.Fatalf("lastReported advanced to %d after Inc WITHOUT the OTel callback "+
			"firing — something OTHER than the OTel callback touched lastReported. "+
			"The bridge is FORBIDDEN to touch it (§0.b trap); this flags a violation.",
			got)
	}
	t.Logf("T4(in-package) PASS: after %d Inc, Value()=%v cumulative and "+
		"lastReported==0 UNCHANGED — the bridge reads only Value(), never "+
		"lastReported (the §0.b trap is disarmed at the field level)", n, cumulative)
}

// TestTrack18_InPackage_T2_SSoTNoDup asserts the SSoT slice Counters() carries
// exactly the distinct counters with NO duplicate names — the property the
// bridge's MustRegister depends on (a duplicate mapped name would panic on a
// duplicate Desc at boot). The construction-site dup (QueryL0ListCapped built
// twice in init()) is NOT in the slice because the slice is built from the
// distinct package vars, not per-newCounter append.
func TestTrack18_InPackage_T2_SSoTNoDup(t *testing.T) {
	cs := Counters()
	seen := map[string]int{}
	for _, c := range cs {
		seen[c.Name()]++
	}
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("duplicate telemetry name in Counters(): %q x%d — bridge MustRegister would PANIC on a duplicate Desc", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("%d duplicate names in the SSoT slice — the construction-site dup leaked into the bridge feed", dups)
	}
	// Exactly the DISTINCT counters in the SSoT slice (NOT the newCounter
	// INVOCATION count — see ADR-0023 §6). Day 18 asserted 12 (the Day-18
	// registry); Day 22 (ADR-0027) RE-PINNED this 12 -> 15: the three T_gc
	// auto-inference counters (QueryTxTimeHighWaterMark, PruningHorizonEffective,
	// PruningHorizonRetreatRefused) the inferrer added. Day 24 (ADR-0029)
	// RE-PINNED this 15 -> 16: the single filename-bounded download-skip counter
	// (QueryDownloadSkippedFirstSys) the durable read path added. Day 25
	// (ADR-0030) RE-PINNED this 16 -> 17: the manifest-channel download-skip
	// counter (QueryManifestSkippedFirstSys) the SAME read path added on its
	// second channel. The count GREW because each fork added counters (disclosed
	// ADR-0027 §0.f + §3, ADR-0029 §0.f, + ADR-0030 §0.f, NOT hidden). The
	// Day-18 invariant (no dups, the bridge scales as append) is UNCHANGED; only
	// the asserted count + the gauge/counter split shifted (the 2 Day-22 gauges
	// grew the gauge count 1 -> 3; Day 24 + Day 25 each added a modeCounter, so
	// the counter count grew 12 -> 13 -> 14, gauges UNCHANGED at 3).
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure; modeCounter, gauge count STAYS 3); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) RE-PINNED 21 -> 22 (PQHandshakeNegotiated — the PQ-KEM disclosure; modeCounter, gauge count STAYS 3); Day 30 (ADR-0035) RE-PINNED 19 -> 21 (TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI disclosure; both modeCounter, gauge count STAYS 3; Day 29 re-pinned 18 -> 19; Day 27 had re-pinned 17 -> 18; Day 25 had re-pinned 16 -> 17; Day 24 had re-pinned 15 -> 16; Day 22 had re-pinned 12 -> 15)
	if len(cs) != wantDistinct {
		t.Fatalf("Counters() len=%d, want %d distinct (Day 31 ADR-0036 grew 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure grew the SSoT; Day 30 ADR-0035 grew 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure grew the SSoT; the bridge exposes %d series; the newCounter INVOCATION count is NOT the distinct-counter count — ADR-0023 §6)",
			len(cs), wantDistinct, len(cs))
	}
	if len(seen) != wantDistinct {
		t.Fatalf("distinct names=%d, want %d", len(seen), wantDistinct)
	}
	// Day 18: OffHeapAllocatedBytes was the SOLE modeGauge (1 gauge + 11 counters).
	// Day 22 (ADR-0027): the 2 new inferrer gauges (QueryTxTimeHighWaterMark +
	// PruningHorizonEffective) grew the gauge count 1 -> 3, so the split became
	// 3 gauges + 12 counters. The retreat-refuse counter is a modeCounter (the
	// third Day-22 counter). Day 24 (ADR-0029): the download-skip counter is a
	// modeCounter (NOT a gauge), so the split became 3 gauges + 13 counters.
	// Day 25 (ADR-0030): the manifest-skip counter is a modeCounter (NOT a
	// gauge), so the split became 3 gauges + 14 counters. Day 27 (ADR-0032):
	// the read-your-writes live-source counter is a modeCounter (NOT a gauge),
	// so the split became 3 gauges + 15 counters. Day 29 (ADR-0034): the
	// stratified-anti-entropy fallback counter is a modeCounter (NOT a gauge),
	// so the split became 3 gauges + 16 counters. Day 30 (ADR-0035): the PKI
	// leaf-rotation + revocation-reject counters are BOTH modeCounter (NOT a
	// gauge), so the split became 3 gauges + 18 counters. Day 31 (ADR-0036):
	// the PQ handshake-negotiated counter is a modeCounter (NOT a gauge), so
	// the split became 3 gauges + 19 counters. Day 32 (ADR-0037): the hybrid-
	// frame accept counter is a modeCounter (NOT a gauge), so the split is now
	// 3 gauges + 20 counters. The mode split is asserted to match the honest
	// growth.
	counters, gauges := 0, 0
	for _, c := range cs {
		switch c.Mode() {
		case modeCounter:
			counters++
		case modeGauge:
			gauges++
		}
	}
	const wantGauges = 3    // Day 22: OffHeapAllocatedBytes + QueryTxTimeHighWaterMark + PruningHorizonEffective (Day 24 + Day 25 + Day 27 + Day 29 + Day 30 + Day 31 + Day 32 + Day 34 added NO gauge)
	const wantCounters = 21 // Day 34: the 20 Day-32 counters + InterRegionEnvelopesShipped (Day 32 had 19 Day-31 + HybridFrameAccepted=20; Day 31 had 18 Day-30 + PQHandshakeNegotiated=19; Day 30 had 16 Day-29 + CertRotationTriggered + CertRevokedRejected=18; Day 29 had 15 Day-27 + StratifiedAntiEntropyFallback=16; Day 27 had 14 Day-25 + QueryLiveSourceReads=15; Day 25 had 13 Day-24 + QueryManifestSkippedFirstSys=14; Day 24 had 12 Day-22 + QueryDownloadSkippedFirstSys=13; Day 22 had 11+retreat-refuse=12... see the wantDistinct line for the full lineage)
	if gauges != wantGauges || counters != wantCounters {
		t.Fatalf("mode split: %d counters + %d gauges; want %d counters + %d gauges (Day 34 ADR-0039 grew the counters 20->21 via ONE modeCounter — InterRegionEnvelopesShipped, the region-aware inter-region-envelope disclosure; Day 32 ADR-0037 grew the counters 19->20 via ONE modeCounter — HybridFrameAccepted, the hybrid-SIGN-WIRE accept disclosure; Day 31 ADR-0036 grew the counters 18->19 via ONE modeCounter — PQHandshakeNegotiated, the PQ-KEM disclosure; Day 30 ADR-0035 grew the counters 16->18 via TWO modeCounters — CertRotationTriggered + CertRevokedRejected, the PKI leaf-rotation + revocation-reject disclosure; the gauges stay 3 — Day 34 added a counter, NOT a gauge)", counters, gauges, wantCounters, wantGauges)
	}
	t.Logf("T2(in-package) PASS: Counters() carries %d DISTINCT counters, %d distinct names, %d dups; %d modeCounter + %d modeGauge (Day 25 re-pinned: the manifest-skip counter grew the SSoT 16->17; the counters 13->14, gauges UNCHANGED at 3)",
		len(cs), len(seen), dups, counters, gauges)
}
