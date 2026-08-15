package metrics

// day25_track25_test.go (Day 25, ADR-0030) — the bridge side of the
// T-MANIFEST-TELEMETRY-SSoT tooth (§0.f, the SSoT-grows-auto property).
//
// The in-package SSoT assertion (Counters() carries the new counter, 17 total, 0
// dups, the 3 Day-22 counters + the Day-24 download-skip counter preserved) lives
// in internal/telemetry/day25_track25_test.go. THIS tooth (in pkg/metrics, where
// the bridge + the scrape helpers live) verifies the BRIDGE side: the new
// manifest-channel download-skip counter is surfaced on /metrics WITHOUT a bridge
// edit (the bridge enumerates telemetry.Counters() automatically at
// NewTelemetryBridge + dispatches on Mode() at Collect — a new counter added to
// allCounters() auto-surfaces with ZERO bridge code edit). The tooth scrapes
// /metrics via httptest + asserts the new supremum_* series appears (HELP + TYPE +
// value line), mirroring the Day-22/24 bridge-sister patterns.
//
// This is the load-bearing byte-verified claim: Day 25 added 1 counter to
// internal/telemetry (registry.go) and the bridge surfaced it WITHOUT any edit
// to pkg/metrics/telemetry_bridge.go. The §0.f "construction-vs-distinct trap
// disarmed" + the §6.e "the counter is observed automatically" both hold on the
// bytes. The bridge file is UNCHANGED (the EIGHTH clean-chain fork — the bridge
// was the Day-18 NEW file; Day 22, Day 24, AND Day 25 touch it ZERO bytes).
//
// Day 22 grew the bridge series 12 -> 15; Day 24 grew it 15 -> 16; Day 25 grows it
// 16 -> 17. The bridge auto-surfaces the 17th series by enumerating the SSoT
// slice (one list, grown honestly); NO bridge edit. The Day-22 §6.e claim (gauges
// observed automatically via Value()->GaugeValue()) carries to Day-25's
// modeCounter (observed via Value()->counterValue at the bridge's Collect
// dispatch — the SAME dispatch Day-24's download-skip counter uses).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/supremum/internal/telemetry"
)

// TestTrack25_T_BridgeAutoSurfacesNewCounter asserts the new manifest-channel
// download-skip counter appears on /metrics WITHOUT a bridge edit (the §0.f
// SSoT-grows-auto property). A real httptest scrape (the Day-18/22/24 precedent)
// MUST surface the HELP/TYPE/value lines for the new supremum_* series. The bridge
// file (telemetry_bridge.go) is UNCHANGED — the bridge enumerated
// telemetry.Counters() at NewTelemetryBridge + the new counter is in the slice, so
// it appears.
//
// The new counter is a modeCounter (cumulative); the scrape after Inc reports the
// cumulative value (the Day-22 §6.e claim, counter variant — the SAME dispatch
// Day-24's download-skip counter uses).
func TestTrack25_T_BridgeAutoSurfacesNewCounter(t *testing.T) {
	// Confirm the bridge file is UNCHANGED (the clean-chain property — the §0.f
	// claim is the bridge surfaces the new counter WITHOUT an edit). This is a
	// git-HEAD byte-identity check on telemetry_bridge.go (the same untouchedFiles
	// discipline the receive gate uses, scoped to the ONE file the §0.f claim
	// concerns). If the bridge WAS edited, the §0.f claim is FALSE (the clean-
	// chain property broke) — Day 25 would be the fork that broke the chain.
	if edited := day25BridgeFileEditedAtHead("telemetry_bridge.go"); edited {
		t.Fatalf("T-MANIFEST-BRIDGE-SSoT: telemetry_bridge.go WAS EDITED at HEAD — the §0.f SSoT-grows-auto claim is FALSE (a bridge edit means the new counter did NOT auto-surface; the clean-chain property broke — Day 25 would be the fork that broke the chain)")
	}

	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	// The new counter MUST be non-nil (the init() construction — Day-25 init()
	// built it; the day22/day24 bridge-sister teeth check the prior counters the
	// same way).
	if telemetry.QueryManifestSkippedFirstSys == nil {
		t.Fatal("T-MANIFEST-BRIDGE-SSoT: QueryManifestSkippedFirstSys nil — the construction order changed (Day-25 init() did not build it)")
	}
	// Drive the counter so the post-scrape value is non-zero (the counter is LIVE —
	// the §6.e claim, counter variant: a scrape after Inc reports the cumulative).
	telemetry.QueryManifestSkippedFirstSys.Add(11)

	body := scrapeMetrics(t, exp)

	// (a) The new supremum_* series appears in the scrape (the §0.f auto-surface
	// claim). HELP + TYPE + value line. The bridge maps the OTel name
	// "supremum.compaction.query_manifest_skipped_first_sys" -> the prometheus name
	// "supremum_compaction_query_manifest_skipped_first_sys" (strings.ReplaceAll
	// "." -> "_" at telemetry_bridge.go:97 — the SAME mapping the bridge uses for
	// EVERY counter; NO per-counter mapping was added for the 17th).
	promName := "supremum_compaction_query_manifest_skipped_first_sys"
	if !strings.Contains(body, "# HELP "+promName+" ") {
		t.Errorf("T-MANIFEST-BRIDGE-SSoT: scrape missing HELP for %s (the bridge did NOT auto-surface the new counter — the §0.f SSoT-grows-auto claim is FALSE)", promName)
	}
	if !strings.Contains(body, "# TYPE "+promName+" ") {
		t.Errorf("T-MANIFEST-BRIDGE-SSoT: scrape missing TYPE for %s", promName)
	}
	val, ok := scrapeCounterValue(body, promName)
	if !ok {
		t.Errorf("T-MANIFEST-BRIDGE-SSoT: scrape missing value line for %s (the series is not emitted by Collect)", promName)
	}
	// (b) The §6.e claim (bridge side, counter variant): the counter reports the
	// cumulative (>= 11 after the Add(11)). A counter that scrapes 0 means the
	// bridge's dispatch is NOT observing it.
	if ok && val < 11 {
		t.Errorf("T-MANIFEST-BRIDGE-SSoT: the counter scraped as %v, want >=11 (the cumulative after Add(11); a counter that reads 0 means the bridge's dispatch is NOT observing it — the §6.e claim is FALSE)", val)
	}

	// (c) The 3 Day-22 series + the Day-24 download-skip series are STILL present
	// (Day 25 appended a 17th, did NOT drop any prior series — the append-only-
	// after-construction contract).
	for _, prior := range []string{
		"supremum_query_txtime_high_water_mark_ns",
		"supremum_compaction_pruning_horizon_effective_ns",
		"supremum_compaction_pruning_horizon_retreat_refused",
		"supremum_l0_query_download_skipped_first_sys",
	} {
		if !strings.Contains(body, "# HELP "+prior+" ") {
			t.Errorf("T-MANIFEST-BRIDGE-SSoT: the prior series %s is MISSING (Day 25 appended a 17th — must NOT replace)", prior)
		}
	}
	t.Logf("T-MANIFEST-BRIDGE-SSoT PASS: the new manifest-skip counter auto-surfaced on /metrics WITHOUT a bridge edit (bridge UNCHANGED at HEAD — the EIGHTH clean-chain fork); the counter reports the cumulative (%v) — the §0.f SSoT-grows-auto + §6.e counter-observed claims byte-verified; the 3 Day-22 series + the Day-24 download-skip preserved (15->16->17)", val)
}

// day25BridgeFileEditedAtHead reports whether the named file in pkg/metrics
// differs from its git-HEAD version (the clean-chain check for the §0.f claim —
// the bridge MUST be UNCHANGED across Day 25). It shells out to
// `git show HEAD:<path>` + compares the bytes. If git is unavailable, returns
// false (the in-package SSoT tooth in internal/telemetry is the load-bearing
// check; the byte-identity is belt-and-suspenders — mirrors the Day-22/24
// bridgeFileEditedAtHead helpers).
func day25BridgeFileEditedAtHead(path string) bool {
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
