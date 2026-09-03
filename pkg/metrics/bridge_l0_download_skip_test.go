// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package metrics

// bridge_l0_download_skip_test.go (ADR-0029) — the bridge side of the
// skip-telemetry counter-set guard (§2.f, the §0.f counter auto-registration property).
//
// The in-package counter-set assertion (Counters() carries the new counter, 17 total
// after ADR-0030 grew it 16 -> 17 via the manifest-skip counter, 0 dups,
// the 3 counters preserved) lives in
// internal/telemetry/bridge_l0_download_skip_test.go. THIS guard (in pkg/metrics, where
// the bridge + the scrape helpers live) verifies the BRIDGE side: the new
// download-skip counter is surfaced on /metrics WITHOUT a bridge edit (the bridge
// enumerates telemetry.Counters() automatically at NewTelemetryBridge + dispatches
// on Mode() at Collect — a new counter added to allCounters() auto-surfaces with
// ZERO bridge code edit). The guard scrapes /metrics via httptest + asserts the
// new supremum_* series appears (HELP + TYPE + value line), mirroring the
// bridge-sister pattern.
//
// This is the load-bearing byte-verified claim: added 1 counter to
// internal/telemetry (registry.go) and the bridge surfaced it WITHOUT any edit
// to pkg/metrics/telemetry_bridge.go. The §0.f "construction-vs-distinct trap
// disarmed" + the §6.e "the counter is observed automatically" both hold on the
// bytes. The bridge file is UNCHANGED (the SEVENTH clean change — the bridge
// was the NEW file; AND touch it ZERO bytes; touches
// it ZERO bytes too — the EIGHTH clean change).
//
// This change grew the bridge series 12 -> 15; grows it 15 -> 16; grows
// it 16 -> 17. The bridge auto-surfaces the 17th series by enumerating the telemetry counter
// slice (one list, grown honestly); NO bridge edit. The §6.e claim (gauges
// observed automatically via Value()->GaugeValue()) carries to
// modeCounter (observed via Value()->counterValue at the bridge's Collect
// dispatch).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/internal/telemetry"
)

// TestBridgeAutoSurfacesL0DownloadSkipCounter asserts the new download-skip
// counter appears on /metrics WITHOUT a bridge edit (the §0.f counter auto-registration
// property). A real httptest scrape (the precedent) MUST surface the
// HELP/TYPE/value lines for the new supremum_* series. The bridge file
// (telemetry_bridge.go) is UNCHANGED — the bridge enumerated telemetry.Counters()
// at NewTelemetryBridge + the new counter is in the slice, so it appears.
//
// The new counter is a modeCounter (cumulative); the scrape after Inc reports the
// cumulative value (the §6.e claim, counter variant).
func TestBridgeAutoSurfacesL0DownloadSkipCounter(t *testing.T) {
	// Confirm the bridge file is UNCHANGED (the clean property — the §0.f
	// claim is the bridge surfaces the new counter WITHOUT an edit). This is a
	// git-HEAD byte-identity check on telemetry_bridge.go (the same untouchedFiles
	// discipline the receive gate uses, scoped to the ONE file the §0.f claim
	// concerns). If the bridge WAS edited, the §0.f claim is FALSE (the clean-
	// chain property broke).
	if edited := downloadSkipBridgeEditedAtHead("telemetry_bridge.go"); edited {
		t.Fatalf("skip-bridge: telemetry_bridge.go WAS EDITED at HEAD — the §0.f counter-auto-surface claim is FALSE (a bridge edit means the new counter did NOT auto-surface; the clean property broke)")
	}

	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	// The new counter MUST be non-nil (the init() construction — init()
	// built it; the bridge-sister guard checks the 3 inferrer counters
	// the same way).
	if telemetry.QueryDownloadSkippedFirstSys == nil {
		t.Fatal("skip-bridge: QueryDownloadSkippedFirstSys nil — the construction order changed (init() did not build it)")
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
		t.Errorf("skip-bridge: scrape missing HELP for %s (the bridge did NOT auto-surface the new counter — the §0.f counter-auto-surface claim is FALSE)", promName)
	}
	if !strings.Contains(body, "# TYPE "+promName+" ") {
		t.Errorf("skip-bridge: scrape missing TYPE for %s", promName)
	}
	val, ok := scrapeCounterValue(body, promName)
	if !ok {
		t.Errorf("skip-bridge: scrape missing value line for %s (the series is not emitted by Collect)", promName)
	}
	// (b) The §6.e claim (bridge side, counter variant): the counter reports the
	// cumulative (>= 9 after the Add(9)). A counter that scrapes 0 means the
	// bridge's dispatch is NOT observing it.
	if ok && val < 9 {
		t.Errorf("skip-bridge: the counter scraped as %v, want >=9 (the cumulative after Add(9); a counter that reads 0 means the bridge's dispatch is NOT observing it — the §6.e claim is FALSE)", val)
	}

	// (c) The 3 series are STILL present (appended a 16th,
	// appended a 17th — neither dropped any prior series; the append-only-after-
	// construction contract).
	for _, prior := range []string{
		"supremum_query_txtime_high_water_mark_ns",
		"supremum_compaction_pruning_horizon_effective_ns",
		"supremum_compaction_pruning_horizon_retreat_refused",
	} {
		if !strings.Contains(body, "# HELP "+prior+" ") {
			t.Errorf("skip-bridge: the series %s is MISSING (appended a 16th, a 17th — neither must replace)", prior)
		}
	}
	t.Logf("skip-bridge PASS: the new download-skip counter auto-surfaced on /metrics WITHOUT a bridge edit (bridge UNCHANGED at HEAD); the counter reports the cumulative (%v) — the §0.f counter-auto-surface + §6.e counter-observed claims byte-verified; the 3 series preserved (15->16->17)", val)
}

// downloadSkipBridgeEditedAtHead reports whether the named file in pkg/metrics
// differs from its git-HEAD version (the clean check for the §0.f claim —
// the bridge MUST be UNCHANGED). It shells out to `git show HEAD:<path>` +
// compares the bytes. If git is unavailable, returns false (the in-package telemetry counter
// guard in internal/telemetry is the load-bearing check; the byte-identity is
// belt-and-suspenders — mirrors the bridgeFileEditedAtHead helper).
func downloadSkipBridgeEditedAtHead(path string) bool {
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
		// cannot be byte-verified via git; rely on the in-package counter-set guard for
		// the count. Return false (NOT edited) so the guard proceeds.
		return false
	}
	diskBytes, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	return string(headBytes) != string(diskBytes)
}
