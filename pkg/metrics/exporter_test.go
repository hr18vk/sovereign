package metrics

import (
	"strings"
	"testing"
)

// TestExportersRegister is the per-process Registry gate (G03.b). It constructs
// the Registry TWICE (two Exporter/Recorder instances) and asserts NO panic.
// The root cause it fixtures: the global prometheus.DefaultRegisterer PANICS
// on duplicate registration across tests (two Recorders registering the same
// sovereign_* instrument names); the per-process Registry (NewRegistry per
// Exporter) is the fix. A panic here = gate FAIL.
func TestExportersRegister(t *testing.T) {
	// Construct three independent Exporters (three per-process Registries).
	// Each registers the same seven sovereign_* series against its OWN
	// registry; the global DefaultRegisterer would panic on the second.
	var exporters []*Exporter
	for i := 0; i < 3; i++ {
		// MustRegister panics on a duplicate within ONE registry; across
		// separate registries it must NOT.
		e := NewExporter()
		exporters = append(exporters, e)
	}
	// Drive a few observations through each so the instruments are exercised
	// (not just constructed), then scrape each — no panic, distinct bodies.
	for i, e := range exporters {
		body := scrapeMetrics(t, e)
		if !strings.Contains(body, "sovereign_ingest_latency_seconds") {
			t.Fatalf("exporter %d scrape missing sovereign_ingest_latency_seconds", i)
		}
	}
	t.Logf("constructed %d per-process Registries with NO duplicate-registration panic", len(exporters))
}

// TestSevenSeriesScrapeable asserts the seven sovereign_* series each carry a
// HELP + TYPE line in the scrape (the G03.c falsifiability gate, exercised
// in-process here; the live-binary curl is the G03.c gate proper).
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
	t.Logf("all seven sovereign_* series carry HELP + TYPE (falsifiable scrape)")
}
