// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

// These tests cover the Prometheus side of the pruning-horizon instruments
// introduced by ADR-0027. NewTelemetryBridge enumerates telemetry.Counters, so
// the three instruments need no individual collector implementation. Scraping
// the HTTP handler verifies their metadata and current values.

import (
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/internal/telemetry"
)

// TestBridgeAutoSurfacesNewCounters checks that the three pruning-horizon
// instruments appear in a scrape without individual bridge support. The two
// gauges must report the values supplied through Set, while the retreat-refused
// instrument must behave as a cumulative counter.
func TestBridgeAutoSurfacesNewCounters(t *testing.T) {
	if edited := bridgeFileEditedAtHead("telemetry_bridge.go"); edited {
		t.Fatalf("telemetry_bridge.go differs from HEAD")
	}

	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	// Non-zero samples distinguish live instruments from absent or unwired ones.
	if telemetry.QueryTxTimeHighWaterMark == nil {
		t.Fatal("QueryTxTimeHighWaterMark is nil")
	}
	if telemetry.PruningHorizonEffective == nil {
		t.Fatal("PruningHorizonEffective is nil")
	}
	if telemetry.PruningHorizonRetreatRefused == nil {
		t.Fatal("PruningHorizonRetreatRefused is nil")
	}
	telemetry.QueryTxTimeHighWaterMark.Set(777777)
	telemetry.PruningHorizonEffective.Set(666666)
	telemetry.PruningHorizonRetreatRefused.Add(5)

	body := scrapeMetrics(t, exp)

	newNames := []string{
		"supremum_query_txtime_high_water_mark_ns",
		"supremum_compaction_pruning_horizon_effective_ns",
		"supremum_compaction_pruning_horizon_retreat_refused",
	}
	for _, promName := range newNames {
		if !strings.Contains(body, "# HELP "+promName+" ") {
			t.Errorf("scrape missing HELP for %s", promName)
		}
		if !strings.Contains(body, "# TYPE "+promName+" ") {
			t.Errorf("scrape missing TYPE for %s", promName)
		}
		if _, ok := scrapeCounterValue(body, promName); !ok {
			t.Errorf("scrape missing value line for %s; Collect did not emit the series", promName)
		}
	}

	// The small integer samples avoid exponent notation, which the test's
	// deliberately simple scrape parser does not support.
	gaugeHW, ok := scrapeCounterValue(body, "supremum_query_txtime_high_water_mark_ns")
	if !ok {
		t.Fatalf("scrape missing QueryTxTimeHighWaterMark value")
	}
	if math.Abs(gaugeHW-777777) > 0.5 {
		t.Fatalf("QueryTxTimeHighWaterMark = %v, want the last Set value 777777", gaugeHW)
	}
	gaugeEff, ok := scrapeCounterValue(body, "supremum_compaction_pruning_horizon_effective_ns")
	if !ok {
		t.Fatalf("scrape missing PruningHorizonEffective value")
	}
	if math.Abs(gaugeEff-666666) > 0.5 {
		t.Fatalf("PruningHorizonEffective = %v, want the last Set value 666666", gaugeEff)
	}
	counterRR, ok := scrapeCounterValue(body, "supremum_compaction_pruning_horizon_retreat_refused")
	if !ok {
		t.Fatalf("scrape missing PruningHorizonRetreatRefused value")
	}
	if counterRR < 5 {
		t.Fatalf("PruningHorizonRetreatRefused = %v, want at least 5 after Add(5)", counterRR)
	}
	t.Logf("pruning gauges = (%v, %v); retreat-refused counter = %v", gaugeHW, gaugeEff, counterRR)
}

// bridgeFileEditedAtHead reports whether path in pkg/metrics differs from its
// HEAD version. It returns false when Git or the file is unavailable so the
// scrape assertions still run.
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
		return false
	}
	diskBytes, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	return string(headBytes) != string(diskBytes)
}
