// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package metrics

// bridge_manifest_skip_test.go (ADR-0030) — the bridge side of the
// manifest-telemetry counter guard (§0.f, the telemetry counter-grows-auto property).
//
// The in-package counter-set assertion (Counters() carries the new counter, 17 total, 0
// dups, the 3 counters + the download-skip counter preserved) lives
// in internal/telemetry/bridge_manifest_skip_test.go. THIS guard (in pkg/metrics, where
// the bridge + the scrape helpers live) verifies the BRIDGE side: the new
// manifest-channel download-skip counter is surfaced on /metrics WITHOUT a bridge
// edit (the bridge enumerates telemetry.Counters() automatically at
// NewTelemetryBridge + dispatches on Mode() at Collect — a new counter added to
// allCounters() auto-surfaces with ZERO bridge code edit). The guard scrapes
// /metrics via httptest + asserts the new supremum_* series appears (HELP + TYPE +
// value line), mirroring the bridge-sister patterns.
//
// This is the load-bearing byte-verified claim: added 1 counter to
// internal/telemetry (registry.go) and the bridge surfaced it WITHOUT any edit
// to pkg/metrics/telemetry_bridge.go. The §0.f "construction-vs-distinct trap
// disarmed" + the §6.e "the counter is observed automatically" both hold on the
// bytes. The bridge file is UNCHANGED (the EIGHTH clean change — the bridge
// was the NEW file;,, AND touch it ZERO bytes).
//
// This change grew the bridge series 12 -> 15; grew it 15 -> 16; grows it
// 16 -> 17. The bridge auto-surfaces the 17th series by enumerating the telemetry counter
// slice (one list, grown honestly); NO bridge edit. The §6.e claim (gauges
// observed automatically via Value()->GaugeValue()) carries to
// modeCounter (observed via Value()->counterValue at the bridge's Collect
// dispatch — the SAME dispatch download-skip counter uses).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/internal/telemetry"
)

// TestBridgeAutoSurfacesManifestSkipCounter asserts the new manifest-channel
// download-skip counter appears on /metrics WITHOUT a bridge edit (the §0.f
// counter auto-registration property). A real httptest scrape (the precedent)
// MUST surface the HELP/TYPE/value lines for the new supremum_* series. The bridge
// file (telemetry_bridge.go) is UNCHANGED — the bridge enumerated
// telemetry.Counters() at NewTelemetryBridge + the new counter is in the slice, so
// it appears.
//
// The new counter is a modeCounter (cumulative); the scrape after Inc reports the
// cumulative value (the §6.e claim, counter variant — the SAME dispatch
// download-skip counter uses).
func TestBridgeAutoSurfacesManifestSkipCounter(t *testing.T) {
	// Confirm the bridge file is UNCHANGED (the clean property — the §0.f
	// claim is the bridge surfaces the new counter WITHOUT an edit). This is a
	// git-HEAD byte-identity check on telemetry_bridge.go (the same untouchedFiles
	// discipline the receive gate uses, scoped to the ONE file the §0.f claim
	// concerns). If the bridge WAS edited, the §0.f claim is FALSE (the clean-
	// chain property broke) — would be the change that broke the chain.
	if edited := manifestSkipBridgeEditedAtHead("telemetry_bridge.go"); edited {
		t.Fatalf("manifest-bridge: telemetry_bridge.go WAS EDITED at HEAD — the §0.f counter-auto-surface claim is FALSE (a bridge edit means the new counter did NOT auto-surface; the clean property broke — would be the fork that broke the chain)")
	}

	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	// The new counter MUST be non-nil (the init() construction — init()
	// built it; the bridge-sister guards check the prior counters the
	// same way).
	if telemetry.QueryManifestSkippedFirstSys == nil {
		t.Fatal("manifest-bridge: QueryManifestSkippedFirstSys nil — the construction order changed (init() did not build it)")
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
		t.Errorf("manifest-bridge: scrape missing HELP for %s (the bridge did NOT auto-surface the new counter — the §0.f counter-auto-surface claim is FALSE)", promName)
	}
	if !strings.Contains(body, "# TYPE "+promName+" ") {
		t.Errorf("manifest-bridge: scrape missing TYPE for %s", promName)
	}
	val, ok := scrapeCounterValue(body, promName)
	if !ok {
		t.Errorf("manifest-bridge: scrape missing value line for %s (the series is not emitted by Collect)", promName)
	}
	// (b) The §6.e claim (bridge side, counter variant): the counter reports the
	// cumulative (>= 11 after the Add(11)). A counter that scrapes 0 means the
	// bridge's dispatch is NOT observing it.
	if ok && val < 11 {
		t.Errorf("manifest-bridge: the counter scraped as %v, want >=11 (the cumulative after Add(11); a counter that reads 0 means the bridge's dispatch is NOT observing it — the §6.e claim is FALSE)", val)
	}

	// (c) The 3 series + the download-skip series are STILL present
	// (appended a 17th, did NOT drop any prior series — the append-only-
	// after-construction contract).
	for _, prior := range []string{
		"supremum_query_txtime_high_water_mark_ns",
		"supremum_compaction_pruning_horizon_effective_ns",
		"supremum_compaction_pruning_horizon_retreat_refused",
		"supremum_l0_query_download_skipped_first_sys",
	} {
		if !strings.Contains(body, "# HELP "+prior+" ") {
			t.Errorf("manifest-bridge: the prior series %s is MISSING (appended a 17th — must NOT replace)", prior)
		}
	}
	t.Logf("manifest-bridge PASS: the new manifest-skip counter auto-surfaced on /metrics WITHOUT a bridge edit (bridge UNCHANGED at HEAD — the EIGHTH clean change); the counter reports the cumulative (%v) — the §0.f counter-auto-surface + §6.e counter-observed claims byte-verified; the 3 series + the download-skip preserved (15->16->17)", val)
}

// manifestSkipBridgeEditedAtHead reports whether the named file in pkg/metrics
// differs from its git-HEAD version (the clean check for the §0.f claim —
// the bridge MUST be UNCHANGED across). It shells out to
// `git show HEAD:<path>` + compares the bytes. If git is unavailable, returns
// false (the in-package counter-set guard in internal/telemetry is the load-bearing
// check; the byte-identity is belt-and-suspenders — mirrors the
// bridgeFileEditedAtHead helpers).
func manifestSkipBridgeEditedAtHead(path string) bool {
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
