// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

import (
	"strings"
	"testing"
)

// TestExportersRegister constructs three independent Exporters. Reusing the
// global Prometheus registerer would panic on the second set of identical
// instrument names; separate registries must coexist and scrape successfully.
func TestExportersRegister(t *testing.T) {
	var exporters []*Exporter
	for i := 0; i < 3; i++ {
		// Duplicate names within one registry panic; separate registries do not.
		e := NewExporter()
		exporters = append(exporters, e)
	}
	for i, e := range exporters {
		body := scrapeMetrics(t, e)
		if !strings.Contains(body, "sovereign_ingest_latency_seconds") {
			t.Fatalf("exporter %d scrape missing sovereign_ingest_latency_seconds", i)
		}
	}
	t.Logf("constructed and scraped %d independent registries", len(exporters))
}

// TestSevenSeriesScrapeable checks that every sovereign_* metric family has
// HELP and TYPE metadata in a fresh Exporter's scrape.
func TestSevenSeriesScrapeable(t *testing.T) {
	e := NewExporter()
	body := scrapeMetrics(t, e)
	want := []string{
		"sovereign_ingest_latency_seconds",
		"sovereign_verify_seconds",
		"sovereign_ingest_verdicts_total",
		"sovereign_ingest_pps",
		"sovereign_convergence_lag_seconds",
		"sovereign_gossip_rounds_total",
		"sovereign_convergence_roots_equal",
	}
	for _, name := range want {
		if !strings.Contains(body, "# HELP "+name) {
			t.Fatalf("scrape missing # HELP for %s", name)
		}
		if !strings.Contains(body, "# TYPE "+name) {
			t.Fatalf("scrape missing # TYPE for %s", name)
		}
	}
	t.Logf("all seven sovereign_* metric families have HELP and TYPE metadata")
}
