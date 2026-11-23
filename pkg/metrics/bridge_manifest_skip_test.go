// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

// These tests verify that the manifest-channel download-skip instrument from
// ADR-0030 appears in a real Prometheus scrape. Earlier pruning and download-skip
// series must remain present after the registry grows.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/internal/telemetry"
)

// TestBridgeAutoSurfacesManifestSkipCounter checks the manifest-skip counter's
// metadata and cumulative value. No collector specific to this counter is
// needed because NewTelemetryBridge enumerates telemetry.Counters.
func TestBridgeAutoSurfacesManifestSkipCounter(t *testing.T) {
	if edited := manifestSkipBridgeEditedAtHead("telemetry_bridge.go"); edited {
		t.Fatalf("telemetry_bridge.go differs from HEAD")
	}

	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	if telemetry.QueryManifestSkippedFirstSys == nil {
		t.Fatal("QueryManifestSkippedFirstSys is nil")
	}
	telemetry.QueryManifestSkippedFirstSys.Add(11)

	body := scrapeMetrics(t, exp)

	promName := "supremum_compaction_query_manifest_skipped_first_sys"
	if !strings.Contains(body, "# HELP "+promName+" ") {
		t.Errorf("scrape missing HELP for %s", promName)
	}
	if !strings.Contains(body, "# TYPE "+promName+" ") {
		t.Errorf("scrape missing TYPE for %s", promName)
	}
	val, ok := scrapeCounterValue(body, promName)
	if !ok {
		t.Errorf("scrape missing value line for %s; Collect did not emit the series", promName)
	}
	if ok && val < 11 {
		t.Errorf("manifest-skip counter = %v, want at least 11 after Add(11)", val)
	}

	for _, prior := range []string{
		"supremum_query_txtime_high_water_mark_ns",
		"supremum_compaction_pruning_horizon_effective_ns",
		"supremum_compaction_pruning_horizon_retreat_refused",
		"supremum_l0_query_download_skipped_first_sys",
	} {
		if !strings.Contains(body, "# HELP "+prior+" ") {
			t.Errorf("scrape no longer contains earlier series %s", prior)
		}
	}
	t.Logf("manifest-skip counter has cumulative value %v", val)
}

// manifestSkipBridgeEditedAtHead reports whether path in pkg/metrics differs
// from its HEAD version. It returns false when Git or the file is unavailable
// so the scrape assertions still run.
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
		return false
	}
	diskBytes, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	return string(headBytes) != string(diskBytes)
}
