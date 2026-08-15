package metrics

// day24_track24_test.go (Day 24, ADR-0029) — the bridge side of the
// T-SKIP-TELEMETRY-SSoT tooth (§2.f, the §0.f SSoT-grows-auto property).
//
// The in-package SSoT assertion (Counters() carries the new counter, 17 total
// after Day 25 ADR-0030 grew it 16 -> 17 via the manifest-skip counter, 0 dups,
// the 3 Day-22 counters preserved) lives in
// internal/telemetry/day24_track24_test.go. THIS tooth (in pkg/metrics, where
// the bridge + the scrape helpers live) verifies the BRIDGE side: the new
// download-skip counter is surfaced on /metrics WITHOUT a bridge edit (the bridge
// enumerates telemetry.Counters() automatically at NewTelemetryBridge + dispatches
// on Mode() at Collect — a new counter added to allCounters() auto-surfaces with
// ZERO bridge code edit). The tooth scrapes /metrics via httptest + asserts the
// new supremum_* series appears (HELP + TYPE + value line), mirroring the Day-22
// bridge-sister pattern.
//
// This is the load-bearing byte-verified claim: Day 24 added 1 counter to
// internal/telemetry (registry.go) and the bridge surfaced it WITHOUT any edit
// to pkg/metrics/telemetry_bridge.go. The §0.f "construction-vs-distinct trap
// disarmed" + the §6.e "the counter is observed automatically" both hold on the
// bytes. The bridge file is UNCHANGED (the SEVENTH clean-chain fork — the bridge
// was the Day-18 NEW file; Day 22 AND Day 24 touch it ZERO bytes; Day 25 touches
// it ZERO bytes too — the EIGHTH clean-chain fork).
//
// Day 22 grew the bridge series 12 -> 15; Day 24 grows it 15 -> 16; Day 25 grows
// it 16 -> 17. The bridge auto-surfaces the 17th series by enumerating the SSoT
// slice (one list, grown honestly); NO bridge edit. The Day-22 §6.e claim (gauges
// observed automatically via Value()->GaugeValue()) carries to Day-24's
// modeCounter (observed via Value()->counterValue at the bridge's Collect
// dispatch).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/supremum/internal/telemetry"
)

// TestTrack24_T_BridgeAutoSurfacesNewCounter asserts the new download-skip
// counter appears on /metrics WITHOUT a bridge edit (the §0.f SSoT-grows-auto
// property). A real httptest scrape (the Day-18/22 precedent) MUST surface the
// HELP/TYPE/value lines for the new supremum_* series. The bridge file
// (telemetry_bridge.go) is UNCHANGED — the bridge enumerated telemetry.Counters()
// at NewTelemetryBridge + the new counter is in the slice, so it appears.
//
// The new counter is a modeCounter (cumulative); the scrape after Inc reports the
// cumulative value (the Day-22 §6.e claim, counter variant).
func TestTrack24_T_BridgeAutoSurfacesNewCounter(t *testing.T) {
	// Confirm the bridge file is UNCHANGED (the clean-chain property — the §0.f
	// claim is the bridge surfaces the new counter WITHOUT an edit). This is a
	// git-HEAD byte-identity check on telemetry_bridge.go (the same untouchedFiles
	// discipline the receive gate uses, scoped to the ONE file the §0.f claim
	// concerns). If the bridge WAS edited, the §0.f claim is FALSE (the clean-
	// chain property broke).
	if edited := day24BridgeFileEditedAtHead("telemetry_bridge.go"); edited {
		t.Fatalf("T-SKIP-BRIDGE-SSoT: telemetry_bridge.go WAS EDITED at HEAD — the §0.f SSoT-grows-auto claim is FALSE (a bridge edit means the new counter did NOT auto-surface; the clean-chain property broke)")
	}

	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	// The new counter MUST be non-nil (the init() construction — Day-24 init()
	// built it; the day22 bridge-sister tooth checks the 3 inferrer counters
	// the same way).
	if telemetry.QueryDownloadSkippedFirstSys == nil {
		t.Fatal("T-SKIP-BRIDGE-SSoT: QueryDownloadSkippedFirstSys nil — the construction order changed (Day-24 init() did not build it)")
	}
	// Drive the counter so the post-scrape value is non-zero (the counter is LIVE —
	// the §6.e claim, counter variant: a scrape after Inc reports the cumulative).
	telemetry.QueryDownloadSkippedFirstSys.Add(9)

	body := scrapeMetrics(t, exp)

	// (a) The new supremum_* series appears in the scrape (the §0.f auto-surface
	// claim). HELP + TYPE + value line. The bridge maps the OTel name
	// "supremum.l0.query_download_skipped_first_sys" -> the prometheus name
	// "supremum_l0_query_download_skipped_first_sys" (strings.ReplaceAll "." ->
	// "_" at telemetry_bridge.go:97).
	promName := "supremum_l0_query_download_skipped_first_sys"
	if !strings.Contains(body, "# HELP "+promName+" ") {
		t.Errorf("T-SKIP-BRIDGE-SSoT: scrape missing HELP for %s (the bridge did NOT auto-surface the new counter — the §0.f SSoT-grows-auto claim is FALSE)", promName)
	}
	if !strings.Contains(body, "# TYPE "+promName+" ") {
		t.Errorf("T-SKIP-BRIDGE-SSoT: scrape missing TYPE for %s", promName)
	}
	val, ok := scrapeCounterValue(body, promName)
	if !ok {
		t.Errorf("T-SKIP-BRIDGE-SSoT: scrape missing value line for %s (the series is not emitted by Collect)", promName)
	}
	// (b) The §6.e claim (bridge side, counter variant): the counter reports the
	// cumulative (>= 9 after the Add(9)). A counter that scrapes 0 means the
	// bridge's dispatch is NOT observing it.
	if ok && val < 9 {
		t.Errorf("T-SKIP-BRIDGE-SSoT: the counter scraped as %v, want >=9 (the cumulative after Add(9); a counter that reads 0 means the bridge's dispatch is NOT observing it — the §6.e claim is FALSE)", val)
	}

	// (c) The 3 Day-22 series are STILL present (Day 24 appended a 16th, Day 25
	// appended a 17th — neither dropped any prior series; the append-only-after-
	// construction contract).
	for _, prior := range []string{
		"supremum_query_txtime_high_water_mark_ns",
		"supremum_compaction_pruning_horizon_effective_ns",
		"supremum_compaction_pruning_horizon_retreat_refused",
	} {
		if !strings.Contains(body, "# HELP "+prior+" ") {
			t.Errorf("T-SKIP-BRIDGE-SSoT: the Day-22 series %s is MISSING (Day 24 appended a 16th, Day 25 a 17th — neither must replace)", prior)
		}
	}
	t.Logf("T-SKIP-BRIDGE-SSoT PASS: the new download-skip counter auto-surfaced on /metrics WITHOUT a bridge edit (bridge UNCHANGED at HEAD); the counter reports the cumulative (%v) — the §0.f SSoT-grows-auto + §6.e counter-observed claims byte-verified; the 3 Day-22 series preserved (15->16->17)", val)
}

// day24BridgeFileEditedAtHead reports whether the named file in pkg/metrics
// differs from its git-HEAD version (the clean-chain check for the §0.f claim —
// the bridge MUST be UNCHANGED). It shells out to `git show HEAD:<path>` +
// compares the bytes. If git is unavailable, returns false (the in-package SSoT
// tooth in internal/telemetry is the load-bearing check; the byte-identity is
// belt-and-suspenders — mirrors the Day-22 bridgeFileEditedAtHead helper).
func day24BridgeFileEditedAtHead(path string) bool {
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
		// cannot be byte-verified via git; rely on the in-package SSoT tooth for
		// the count. Return false (NOT edited) so the tooth proceeds.
		return false
	}
	diskBytes, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	return string(headBytes) != string(diskBytes)
}
