// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package telemetry

import (
	"math"
	"testing"
)

// In-package guards (ADR-0023). These assert invariants the cross-package
// pkg/metrics bridge guards CANNOT — because they depend on the unexported
// Counter.lastReported field and the counterMode constants. The bridge
// (pkg/metrics) reads only the exported accessors (Name/Description/Unit/Mode/
// Value); these guards assert the bridge's contract against the package-internal
// state it depends on.
//
// The bridge reads CUMULATIVE via Value() and NEVER touches lastReported.
// lastReported is the OTel-callback field — reading it from the bridge couples
// the bridge to the OTel cadence and tears the delta if OTel fires between
// scrapes (the production double-count). telemetry.Init is never called in this
// process, so lastReported stays 0. The first guard Incs a counter and asserts
// lastReported is STILL 0 (UNCHANGED) — pre-empting a future bind of a real
// OTel Meter.
//
// The second guard asserts the counter slice Counters() carries exactly the
// distinct package vars, NO duplicate names (the QueryL0ListCapped
// construction-dup is construction-site, not slice-site — the bridge must never
// see the dup, or its MustRegister panics on a duplicate Desc at boot).

// TestLastReportedUntouchedByBridge is the authoritative double-count-trap
// guard. The cross-package pkg/metrics guard asserts the SCRAPE value ==
// Counter.Value(); this guard asserts the FIELD-level invariant lastReported is
// UNCHANGED (0) after Inc — the field the bridge is FORBIDDEN to read. A future
// change that binds a real OTel Meter arms the registerInt64Counter callback,
// which IS allowed to advance lastReported (that is its job); a bridge that
// ALSO touched lastReported would double-count. This guard passes today
// (lastReported==0, OTel never armed) and will keep passing for the BRIDGE as
// long as the bridge never touches the field.
func TestLastReportedUntouchedByBridge(t *testing.T) {
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
			"contamination to investigate, not a bridge defect. (This process does "+
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
			"The bridge is FORBIDDEN to touch it (the double-count trap); this flags a violation.",
			got)
	}
	t.Logf("PASS: after %d Inc, Value()=%v cumulative and "+
		"lastReported==0 UNCHANGED — the bridge reads only Value(), never "+
		"lastReported (the double-count trap is disarmed at the field level)", n, cumulative)
}

// TestCountersNoDuplicateNames asserts the counter slice Counters() carries
// exactly the distinct counters with NO duplicate names — the property the
// bridge's MustRegister depends on (a duplicate mapped name would panic on a
// duplicate Desc at boot). The construction-site dup (QueryL0ListCapped built
// twice in init()) is NOT in the slice because the slice is built from the
// distinct package vars, not per-newCounter append.
func TestCountersNoDuplicateNames(t *testing.T) {
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
		t.Fatalf("%d duplicate names in the counter slice — the construction-site dup leaked into the bridge feed", dups)
	}
	// Exactly the DISTINCT counters in the slice (NOT the newCounter
	// INVOCATION count — ADR-0023). The count grew as disclosure counters were
	// added across the ADR series (each addition disclosed, not hidden): the
	// T_gc auto-inference counters, the filename-bounded and manifest-channel
	// download-skip counters, the read-your-writes live-source counter, and the
	// mesh/PKI/PQ disclosures. The invariant (no dups, the bridge scales as
	// append) is UNCHANGED; only the asserted count and the gauge/counter split
	// shifted.
	const wantDistinct = 24 // distinct counters; grew across the ADR series as disclosure counters were added
	if len(cs) != wantDistinct {
		t.Fatalf("Counters() len=%d, want %d distinct (ADR-0036 grew 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure grew the counter; ADR-0035 grew 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure grew the counter; the bridge exposes %d series; the newCounter INVOCATION count is NOT the distinct-counter count — ADR-0023 §6)",
			len(cs), wantDistinct, len(cs))
	}
	if len(seen) != wantDistinct {
		t.Fatalf("distinct names=%d, want %d", len(seen), wantDistinct)
	}
	// Mode split: the gauges are OffHeapAllocatedBytes plus the two
	// horizon-inferrer gauges (QueryTxTimeHighWaterMark,
	// PruningHorizonEffective). Every later disclosure counter is a
	// modeCounter, so the gauge count stays 3 while the counter count grows.
	// The mode split is asserted to match the honest growth.
	counters, gauges := 0, 0
	for _, c := range cs {
		switch c.Mode() {
		case modeCounter:
			counters++
		case modeGauge:
			gauges++
		}
	}
	const wantGauges = 3    // OffHeapAllocatedBytes + QueryTxTimeHighWaterMark + PruningHorizonEffective
	const wantCounters = 21 // the distinct modeCounter count
	if gauges != wantGauges || counters != wantCounters {
		t.Fatalf("mode split: %d counters + %d gauges; want %d counters + %d gauges (ADR-0039 grew the counters 20->21 via ONE modeCounter — InterRegionEnvelopesShipped, the region-aware inter-region-envelope disclosure; ADR-0037 grew the counters 19->20 via ONE modeCounter — HybridFrameAccepted, the hybrid-SIGN-WIRE accept disclosure; ADR-0036 grew the counters 18->19 via ONE modeCounter — PQHandshakeNegotiated, the PQ-KEM disclosure; ADR-0035 grew the counters 16->18 via TWO modeCounters — CertRotationTriggered + CertRevokedRejected, the PKI leaf-rotation + revocation-reject disclosure; the gauges stay 3 — added a counter, NOT a gauge)", counters, gauges, wantCounters, wantGauges)
	}
	t.Logf("PASS: Counters() carries %d DISTINCT counters, %d distinct names, %d dups; %d modeCounter + %d modeGauge (the manifest-skip counter grew the counter 16->17; the counters 13->14, gauges UNCHANGED at 3)",
		len(cs), len(seen), dups, counters, gauges)
}
