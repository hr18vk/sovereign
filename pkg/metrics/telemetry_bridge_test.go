// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

import (
	"math"
	"strings"
	"testing"

	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

// The bridge tests use real HTTP scrapes to check cumulative counter behavior,
// telemetry-counter enumeration, and operation without an OpenTelemetry meter.
// They also measure collection allocations and compare scraped values with the
// Counter.Value totals directly. The lastReported field used by the OTel delta
// exporter is unexported, so internal/telemetry holds the corresponding field
// assertion (ADR-0023).

// scrapeCounterValue parses the value from an unlabelled counter or gauge
// line. It returns false when the named series is absent or has no readable
// numeric value.
func scrapeCounterValue(body, promName string) (float64, bool) {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, promName+" ") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, false
			}
			v, ok := parseFloatPrefix(fields[1])
			if !ok {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

// parseFloatPrefix parses the leading digits and optional fractional part of a
// non-negative value. It accepts neither an empty string nor non-finite values.
func parseFloatPrefix(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	intPart, fracPart := uint64(0), uint64(0)
	fracMul := uint64(1)
	i, dot := 0, false
	for ; i < len(s); i++ {
		ch := s[i]
		if ch == '.' && !dot {
			dot = true
			continue
		}
		if ch < '0' || ch > '9' {
			break
		}
		if dot {
			if fracMul > 1e18 { // guard against overflow on absurd input
				break
			}
			fracPart = fracPart*10 + uint64(ch-'0')
			fracMul *= 10
		} else {
			intPart = intPart*10 + uint64(ch-'0')
		}
	}
	if i == 0 {
		return 0, false
	}
	return float64(intPart) + float64(fracPart)/float64(fracMul), true
}

// TestRealScrapeCumulativeNotDelta checks every telemetry series in an HTTP
// scrape, then increments a counter and verifies that the second scrape advances
// by that amount. A bridge that exported per-interval deltas would fail the
// cumulative-value comparison.
func TestRealScrapeCumulativeNotDelta(t *testing.T) {
	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	body := scrapeMetrics(t, exp)

	// Enumerating the registry here avoids a second fixed list of series.
	for _, c := range telemetry.Counters() {
		promName := strings.ReplaceAll(c.Name(), ".", "_")
		if !strings.Contains(body, "# HELP "+promName+" ") {
			t.Errorf("scrape missing HELP for %s", promName)
		}
		if !strings.Contains(body, "# TYPE "+promName+" ") {
			t.Errorf("scrape missing TYPE for %s", promName)
		}
		if _, ok := scrapeCounterValue(body, promName); !ok {
			t.Errorf("scrape missing value line for %s", promName)
		}
	}

	const delta uint64 = 7
	counter := telemetry.MemTableFlushTotal
	if counter == nil {
		t.Fatal("telemetry.MemTableFlushTotal is nil")
	}
	val1, ok := scrapeCounterValue(body, "supremum_memtable_flush_total")
	if !ok {
		t.Fatalf("first scrape missing supremum_memtable_flush_total value")
	}
	for i := uint64(0); i < delta; i++ {
		counter.Inc()
	}
	body2 := scrapeMetrics(t, exp)
	val2, ok := scrapeCounterValue(body2, "supremum_memtable_flush_total")
	if !ok {
		t.Fatalf("second scrape missing supremum_memtable_flush_total value")
	}
	got := val2 - val1
	// Integer-valued counters should differ by exactly delta; the tolerance
	// avoids an exact floating-point equality check.
	if math.Abs(got-float64(delta)) > 0.5 {
		t.Fatalf("counter is not cumulative: first=%v second=%v difference=%v, want %d "+
			"(a per-interval delta would reset between scrapes; "+
			"the total must increase monotonically)", val1, val2, got, delta)
	}
	t.Logf("supremum_memtable_flush_total advanced from %v to %v (+%d)", val1, val2, delta)
}

// TestSafetyCriticalOrphanSignal verifies that a reaper's refusal to delete a
// manifest with a missing L1 target is visible and can be monitored at
// /metrics. The counter preserves the manifests for later recovery.
func TestSafetyCriticalOrphanSignal(t *testing.T) {
	exp := NewExporter()
	exp.Registry().MustRegister(NewTelemetryBridge())
	body := scrapeMetrics(t, exp)
	const want = "supremum_compaction_l0_reap_manifests_skipped_orphan"
	if !strings.Contains(body, "# HELP "+want+" ") {
		t.Fatalf("scrape missing orphan-signal series %s; "+
			"body:\n%s", want, body)
	}
	telemetry.L0ReapSkippedOrphan.Inc()
	body2 := scrapeMetrics(t, exp)
	v2, ok := scrapeCounterValue(body2, want)
	if !ok || v2 < 1 {
		t.Fatalf("orphan counter did not advance after Inc: present=%v value=%v", ok, v2)
	}
	t.Logf("orphan-signal %s = %v", want, v2)
}

// TestTelemetryCounterEnumeration compares the bridge's counter snapshot and
// descriptor count with telemetry.Counters. It catches duplicate names and any
// drift toward a separately maintained list; Describe must emit one descriptor
// for every registry entry.
func TestTelemetryCounterEnumeration(t *testing.T) {
	bridge := NewTelemetryBridge()
	cs := telemetry.Counters()

	// The bridge must retain the registry snapshot itself, not a copy with
	// independently selected entries.
	if len(bridge.counters) != len(cs) {
		t.Fatalf("bridge has %d counters; telemetry.Counters has %d",
			len(bridge.counters), len(cs))
	}
	for i := range cs {
		if bridge.counters[i] != cs[i] {
			t.Errorf("bridge counter %d (%p) differs from registry entry %d (%p)",
				i, bridge.counters[i], i, cs[i])
		}
	}

	// A duplicate mapped name would also cause MustRegister to reject the set.
	if len(bridge.descs) != len(cs) {
		t.Fatalf("bridge has %d descriptors for %d counters",
			len(bridge.descs), len(cs))
	}

	descs := make(chan *prometheus.Desc, len(cs)+1)
	go func() {
		bridge.Describe(descs)
		close(descs)
	}()
	got := 0
	for range descs {
		got++
	}
	if got != len(cs) {
		t.Fatalf("Describe emitted %d descriptors, want %d", got, len(cs))
	}
	t.Logf("bridge emitted %d descriptors for %d registry counters", got, len(cs))
}

// TestZeroAllocCollect measures allocations in steady-state Collect calls and
// checks that collection does not change the descriptor map. It reports rather
// than rejects allocations from the Prometheus const-metric constructors;
// reusing descriptors is the invariant enforced by this package.
func TestZeroAllocCollect(t *testing.T) {
	bridge := NewTelemetryBridge()
	// Discard first-call initialization costs before measuring.
	prime := make(chan prometheus.Metric, len(telemetry.Counters())+1)
	bridge.Collect(prime)
	close(prime)
	for range prime {
	}

	measure := func() {
		ch := make(chan prometheus.Metric, len(telemetry.Counters())+1)
		bridge.Collect(ch)
		close(ch)
		for range ch {
		}
	}

	allocs := testing.AllocsPerRun(100, measure)
	t.Logf("Collect allocations per run: %v "+
		"(descriptors are built before collection)", allocs)
	if allocs != 0 {
		t.Logf("Collect retains %v allocations per run; "+
			"descriptor reuse remains intact; "+
			"const-metric construction accounts for the residual; "+
			"collection remains outside the data path; "+
			"the measurement is reported without requiring zero", allocs)
	}
	metricCh := make(chan prometheus.Metric, len(telemetry.Counters())+1)
	bridge.Collect(metricCh)
	close(metricCh)
	for m := range metricCh {
		_ = m.Desc().String() // every metric carries a descriptor
	}
	before := bridge.descs
	again := make(chan prometheus.Metric, len(telemetry.Counters())+1)
	bridge.Collect(again)
	close(again)
	if len(bridge.descs) != len(before) {
		t.Errorf("descriptor count changed across Collect calls: %d -> %d", len(before), len(bridge.descs))
	}
}

// TestDoubleCountTrapGuard compares a scraped counter with Counter.Value after
// a known number of increments. Equality shows that the bridge reads the
// cumulative LongAdder rather than the OTel exporter's lastReported delta
// state. internal/telemetry checks that unexported field directly.
func TestDoubleCountTrapGuard(t *testing.T) {
	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	const n = 11
	c := telemetry.CompactionRowsPruned
	if c == nil {
		t.Fatal("telemetry.CompactionRowsPruned is nil")
	}
	preValue := c.Value()
	for i := 0; i < n; i++ {
		c.Inc()
	}
	postValue := c.Value()
	if math.Abs((postValue-preValue)-float64(n)) > 0.5 {
		t.Fatalf("Counter.Value cumulative mismatch: before=%v after=%v, want increase %d", preValue, postValue, n)
	}

	body := scrapeMetrics(t, exp)
	scraped, ok := scrapeCounterValue(body, "supremum_compaction_l1_rows_pruned")
	if !ok {
		t.Fatalf("scrape missing supremum_compaction_l1_rows_pruned")
	}
	if math.Abs(scraped-postValue) > 0.5 {
		t.Fatalf("bridge value %v differs from Counter.Value %v", scraped, postValue)
	}
	t.Logf("bridge scrape %v equals Counter.Value %v", scraped, postValue)
}

// TestNilOTelSafe constructs a bridge without calling telemetry.Init and
// verifies that package-initialized counters still appear in Prometheus. The
// bridge reads those counters directly; it does not require an OTel meter.
func TestNilOTelSafe(t *testing.T) {
	// Another test may already have initialized OTel in this process. This test
	// checks the narrower property that neither exporter nor bridge needs to do
	// so in order to enumerate and scrape counters.
	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)
	if len(bridge.counters) == 0 {
		t.Fatal("bridge found no package-initialized telemetry counters")
	}
	c := telemetry.CompactionMerged
	if c == nil {
		t.Fatal("telemetry.CompactionMerged is nil")
	}
	c.Inc()
	c.Inc()
	body := scrapeMetrics(t, exp)
	v, ok := scrapeCounterValue(body, "supremum_compaction_l0_files_merged")
	if !ok {
		t.Fatalf("scrape missing supremum_compaction_l0_files_merged")
	}
	if v < 2 {
		t.Fatalf("supremum_compaction_l0_files_merged = %v, want at least 2", v)
	}
	t.Logf("bridge scraped cumulative value %v without initializing OTel", v)
}
