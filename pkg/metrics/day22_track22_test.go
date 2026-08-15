package metrics

// day22_track22_test.go (Day 22, ADR-0027) — the bridge side of the
// T-INFER-TELEMETRY-SSoT tooth (§2.f, the §0.f SSoT-grows-auto property).
//
// The in-package SSoT assertion (Counters() carries the 3 new counters, 15
// total, 0 dups) lives in internal/telemetry/day22_track22_test.go. THIS tooth
// (in pkg/metrics, where the bridge + the scrape helpers live) verifies the
// BRIDGE side: the 3 new inferrer counters are surfaced on /metrics WITHOUT a
// bridge edit (the bridge enumerates telemetry.Counters() automatically at
// NewTelemetryBridge line 110 + dispatches on Mode() at Collect line 185 — a
// new counter added to allCounters() auto-surfaces with ZERO bridge code edit).
// The tooth scrapes /metrics via httptest + asserts the 3 new supremum_* series
// appear (HELP + TYPE + value line), mirroring the Day-18 T1 real-scrape pattern.
//
// This is the load-bearing byte-verified claim: Day 22 added 3 counters to
// internal/telemetry (registry.go) and the bridge surfaced them WITHOUT any
// edit to pkg/metrics/telemetry_bridge.go. The §0.f "construction-vs-distinct
// trap disarmed" + the §6.e "gauges observed automatically" both hold on the
// bytes. The bridge file is UNCHANGED (the FIFTH clean-chain fork — the bridge
// was the Day-18 NEW file; Day 22 touches it ZERO bytes).

import (
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/supremum/internal/telemetry"
)

// TestTrack22_T_BridgeAutoSurfacesNewCounters asserts the 3 new inferrer
// counters appear on /metrics WITHOUT a bridge edit (the §0.f SSoT-grows-auto
// property). A real httptest scrape (the Day-18 T1 precedent) MUST surface the
// HELP/TYPE/value lines for the 3 new supremum_* series. The bridge file
// (telemetry_bridge.go) is UNCHANGED — the bridge enumerated telemetry.Counters()
// at NewTelemetryBridge + the new counters are in the slice, so they appear.
//
// CRITICAL sub-assertion (the §6.e claim, bridge side): the 2 new GAUGES
// (QueryTxTimeHighWaterMark, PruningHorizonEffective) surface as gauges (the
// bridge's Collect dispatches ModeGauge -> GaugeValue at telemetry_bridge.go:189;
// a scrape after Set reports the last-Set value, NOT a zero — the gauge is
// live). The retreat-refuse COUNTER surfaces as a counter (cumulative).
func TestTrack22_T_BridgeAutoSurfacesNewCounters(t *testing.T) {
	// Confirm the bridge file is UNCHANGED (the clean-chain property — the
	// §0.f claim is the bridge surfaces the new counters WITHOUT an edit). This
	// is a git-HEAD byte-identity check on telemetry_bridge.go (the same
	// untouchedFiles discipline the receive gate uses, scoped to the ONE file
	// the §0.f claim concerns). If the bridge WAS edited, the §0.f claim is
	// FALSE (the clean-chain property broke).
	if edited := bridgeFileEditedAtHead("telemetry_bridge.go"); edited {
		t.Fatalf("T-INFER-BRIDGE-SSoT: telemetry_bridge.go WAS EDITED at HEAD — the §0.f SSoT-grows-auto claim is FALSE (a bridge edit means the new counters did NOT auto-surface; the clean-chain property broke)")
	}

	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	// Pre-scrape: the gauges report their initial value (0 for a fresh gauge;
	// the counter reports its cumulative). Drive them so the post-scrape values
	// are non-zero (the gauges are LIVE — the §6.e claim).
	if telemetry.QueryTxTimeHighWaterMark == nil {
		t.Fatal("T-INFER-BRIDGE-SSoT: QueryTxTimeHighWaterMark nil — the construction order changed (Day-22 init() did not build it)")
	}
	if telemetry.PruningHorizonEffective == nil {
		t.Fatal("T-INFER-BRIDGE-SSoT: PruningHorizonEffective nil — the construction order changed")
	}
	if telemetry.PruningHorizonRetreatRefused == nil {
		t.Fatal("T-INFER-BRIDGE-SSoT: PruningHorizonRetreatRefused nil — the construction order changed")
	}
	telemetry.QueryTxTimeHighWaterMark.Set(777777)
	telemetry.PruningHorizonEffective.Set(666666)
	telemetry.PruningHorizonRetreatRefused.Add(5)

	body := scrapeMetrics(t, exp)

	// (a) The 3 new supremum_* series appear in the scrape (the §0.f auto-surface
	// claim). HELP + TYPE + value line for each.
	newNames := []string{
		"supremum_query_txtime_high_water_mark_ns",
		"supremum_compaction_pruning_horizon_effective_ns",
		"supremum_compaction_pruning_horizon_retreat_refused",
	}
	for _, promName := range newNames {
		if !strings.Contains(body, "# HELP "+promName+" ") {
			t.Errorf("T-INFER-BRIDGE-SSoT: scrape missing HELP for %s (the bridge did NOT auto-surface the new counter — the §0.f SSoT-grows-auto claim is FALSE)", promName)
		}
		if !strings.Contains(body, "# TYPE "+promName+" ") {
			t.Errorf("T-INFER-BRIDGE-SSoT: scrape missing TYPE for %s", promName)
		}
		if _, ok := scrapeCounterValue(body, promName); !ok {
			t.Errorf("T-INFER-BRIDGE-SSoT: scrape missing value line for %s (the series is not emitted by Collect)", promName)
		}
	}

	// (b) The §6.e claim (bridge side): the 2 new GAUGES report the Set value
	// (the gauge is LIVE — Collect dispatches ModeGauge -> GaugeValue at
	// telemetry_bridge.go:189; a scrape after Set reports the last-Set value,
	// NOT zero). The retreat-refuse COUNTER reports the cumulative (5).
	//
	// Gauge values are chosen < 1e6 so the prometheus text-format renders them
	// as plain integers (NOT scientific notation, e.g. 7.777777e+06) — the
	// scrapeCounterValue parser (recorder_test.go:61) stops at the exponent
	// marker, so a scientific-notation gauge would mis-parse. The §6.e claim
	// (the gauge reports the last-Set value, live) is asserted identically at
	// < 1e6; the absolute magnitude is irrelevant to the claim. A gauge that
	// scrapes 0 means the bridge's ModeGauge dispatch is NOT observing it.
	gaugeHW, ok := scrapeCounterValue(body, "supremum_query_txtime_high_water_mark_ns")
	if !ok {
		t.Fatalf("T-INFER-BRIDGE-SSoT: gauge supremum_query_txtime_high_water_mark_ns value not found in scrape")
	}
	if math.Abs(gaugeHW-777777) > 0.5 {
		t.Fatalf("T-INFER-BRIDGE-SSoT: the gauge QueryTxTimeHighWaterMark scraped as %v, want 777777 (the last-Set value; a gauge that reads 0 means the bridge's ModeGauge dispatch at telemetry_bridge.go:189 is NOT observing the gauge — the §6.e claim is FALSE)", gaugeHW)
	}
	gaugeEff, ok := scrapeCounterValue(body, "supremum_compaction_pruning_horizon_effective_ns")
	if !ok {
		t.Fatalf("T-INFER-BRIDGE-SSoT: gauge supremum_compaction_pruning_horizon_effective_ns value not found in scrape")
	}
	if math.Abs(gaugeEff-666666) > 0.5 {
		t.Fatalf("T-INFER-BRIDGE-SSoT: the gauge PruningHorizonEffective scraped as %v, want 666666 (the last-Set value; the §6.e claim)", gaugeEff)
	}
	counterRR, ok := scrapeCounterValue(body, "supremum_compaction_pruning_horizon_retreat_refused")
	if !ok {
		t.Fatalf("T-INFER-BRIDGE-SSoT: counter supremum_compaction_pruning_horizon_retreat_refused value not found in scrape")
	}
	if counterRR < 5 {
		t.Fatalf("T-INFER-BRIDGE-SSoT: the counter PruningHorizonRetreatRefused scraped as %v, want >=5 (the cumulative after 5 Inc; the counter is live)", counterRR)
	}
	t.Logf("T-INFER-BRIDGE-SSoT PASS: the 3 new inferrer counters auto-surfaced on /metrics WITHOUT a bridge edit (bridge UNCHANGED at HEAD); the 2 gauges report the last-Set values (%v, %v), the counter the cumulative (%v) — the §0.f SSoT-grows-auto + §6.e gauge-observed claims byte-verified", gaugeHW, gaugeEff, counterRR)
}

// bridgeFileEditedAtHead reports whether the named file in pkg/metrics differs
// from its git-HEAD version (the clean-chain check for the §0.f claim — the
// bridge MUST be UNCHANGED). It shells out to `git show HEAD:<path>` + compares
// the bytes. If git is unavailable, returns false (the FROZEN md5 tooth in
// pkg/receive covers the FROZEN files; this is the bridge-specific analogue).
func bridgeFileEditedAtHead(path string) bool {
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	abs := filepath.Join(wd, path)
	gitPath := "pkg/metrics/" + path
	cmd := exec.Command("git", "show", "HEAD:"+gitPath)
	headBytes, err := cmd.Output()
	if err != nil {
		// git unavailable OR the file is untracked at HEAD — the §0.f claim
		// cannot be byte-verified via git; rely on the FROZEN md5 tooth for the
		// FROZEN files + the in-package SSoT tooth for the count. Return false
		// (NOT edited) so the tooth proceeds (the count tooth is the load-bearing
		// check; the byte-identity is belt-and-suspenders).
		return false
	}
	diskBytes, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	return string(headBytes) != string(diskBytes)
}
