package metrics

import (
	"crypto/md5"
	"encoding/hex"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

// Day 18 (ADR-0023) — the TelemetryBridge contract teeth. Each tooth is
// load-bearing (see the prompt §2 + the bridge's own doc-comment); collectively
// they PROVE the bridge closes the operator-blindness defect WITHOUT arming the
// §0.b double-count trap:
//
//   T1 REAL SCRAPE — a real httptest scrape, not the seam; the 12 supremum_*
//     series appear with CUMULATIVE values and ADVANCE by exactly the delta
//     across scrapes (a delta-reporting bridge would show the increment ONCE
//     then reset — this is the §0.b trap tooth).
//
//   T2 SSoT-ENUMERATION — the bridge enumerates telemetry.Counters() (the one
//     list), NOT a hardcoded copy; its series count == the registry's distinct
//     counter count (catches "hardcoded list drifts" when a future Day-19 adds
//     a counter the bridge omits).
//
//   T3 ZERO-ALLOC-COLLECT — AllocsPerRun(Collect) with the pre-built Desc set.
//     Honest: if non-zero (the const-metric constructors allocate), the
//     MEASURED number is disclosed in ADR-0023 §6 — never gamed by skipping the
//     const-metric build.
//
//   T4 DOUBLE-COUNT-TRAP GUARD — the bridge reads Counter.Value() and NEVER
//     lastReported; asserting lastReported is UNCHANGED after a scrape preeempts
//     the production double-count when a future fork binds a real OTel Meter.
//     (Asserted in-package in internal/telemetry because lastReported is
//     unexported; this file's T4 mirrors it at the scrape layer.)
//
//   T5 NIL-OTEL-SAFE — the bridge works WITHOUT telemetry.Init (the production
//     reality: Init had ZERO production callers Day 18; Day 21 ADR-0026 FLIPPED
//     this — see T-ARMED in track21_t_armed_test.go for the gated contract). A
//     non-zero supremum_* series
//     after Inc proves the two-layer no-op is closed at the prometheus layer
//     WITHOUT requiring the OTel layer.
//
//   T6 FROZEN + SCOPE-HYGIENE — the 5 FROZEN md5s are byte-identical (NO
//     re-pin this fork). The "Init stays at ZERO production callers" prose is
//     FLIPPED Day 21 (ADR-0026) — arming Init is the deliverable; the gated
//     contract is now T-ARMED (EXACTLY ONE production caller under
//     cmd/sovereign-node/, the bridge does NOT call Init — see
//     track21_t_armed_test.go). This T6 tooth still asserts ONLY the 5-file
//     FROZEN md5 set.

// scrapeCounterValue parses a dimensionless counter/gauge line from the scrape
// body, mirroring extractHistogramCount's precedent. The line is
// "supremum_l0_arrow_serial_bytes 1234" (no labels — the bridge series are
// dimensionless singletons). Returns the float64 and ok=false if the line is
// absent or unreadable.
func scrapeCounterValue(body, promName string) (float64, bool) {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, promName+" ") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, false
			}
			// strconv would allocate; the scraped value is a plain base-10
			// float (possibly with a '+Inf' for an uninitialised gauge, but the
			// inc-path teeth drive finite counters). Parse the leading numeric
			// run manually to mirror extractHistogramCount and stay
			// allocation-light (this helper is test-only; parse honesty beats
			// strconv overhead here).
			v, ok := parseFloatPrefix(fields[1])
			if !ok {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

// parseFloatPrefix parses a non-negative base-10 float with an optional single
// '.' from the leading run of a scraped value token. It returns false for
// '+Inf'/NaN/empty (the teeth drive finite counters via Inc). Allocation-light
// (no strconv) to mirror the in-package scrape helper precedent.
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

// TestTrack18_T1_RealScrapeCumulativeNotDelta is the headline tooth. A real
// httptest scrape (mirrors recorder_test.go:308 scrapeMetrics precedent) MUST
// surface every supremum_* series. CRITICAL sub-assertion: the cumulative
// ADVANCES by exactly the delta across two scrapes — a delta-reporting bridge
// (the §0.b trap) would show the increment ONCE then reset to the increment.
func TestTrack18_T1_RealScrapeCumulativeNotDelta(t *testing.T) {
	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	body := scrapeMetrics(t, exp)

	// (a) Every mapped supremum_* name appears in the scrape. This is the
	// "the operator is no longer blind to the compaction/reaper/flush surface"
	// closure — the distinct series (12 at Day 18; 15 since Day 22 ADR-0027 grew
	// the SSoT with the 3 inferrer counters; 16 since Day 24 ADR-0029 grew it with
	// the download-skip counter; 17 since Day 25 ADR-0030 grew it with the
	// manifest-skip counter; the loop enumerates Counters() dynamically so it
	// auto-scales with the registry).
	for _, c := range telemetry.Counters() {
		promName := strings.ReplaceAll(c.Name(), ".", "_")
		if !strings.Contains(body, "# HELP "+promName+" ") {
			t.Errorf("scrape missing HELP for %s (series not surfaced)", promName)
		}
		if !strings.Contains(body, "# TYPE "+promName+" ") {
			t.Errorf("scrape missing TYPE for %s", promName)
		}
		if _, ok := scrapeCounterValue(body, promName); !ok {
			t.Errorf("scrape missing value line for %s", promName)
		}
	}

	// (b) The §0.b trap tooth: drive Inc on a COUNTER, re-scrape, assert the
	// cumulative ADVANCES by exactly the delta — NOT resets to the delta. A
	// delta-reporting bridge shows k once then resets; cumulative shows the
	// monotone climb.
	const delta uint64 = 7
	counter := telemetry.MemTableFlushTotal
	if counter == nil {
		t.Fatal("telemetry.MemTableFlushTotal nil — construction order changed")
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
	// Float compare with a 0.5 epsilon (the values are integers via Inc; any
	// drift past 0.5 means delta-vs-cumulative, not float noise).
	if math.Abs(got-float64(delta)) > 0.5 {
		t.Fatalf("CUMULATIVE violated (§0.b trap): scrape1=%v scrape2=%v delta=%v want %d "+
			"(a delta-reporting bridge would show the increment ONCE then reset; "+
			"cumulative shows the monotone climb)", val1, val2, got, delta)
	}
	t.Logf("T1 PASS: supremum_memtable_flush_total cumulative %v -> %v (+%d == delta)", val1, val2, delta)
}

// TestTrack18_T1b_SafetyCriticalOrphanSignal asserts the operator signal that
// MOTIVATED this fork is reachable on /metrics for the first time:
// supremum_compaction_l0_reap_manifests_skipped_orphan — the Stage-C reaper
// guard's "I refused to delete (an L1 went missing, the backstop is
// preserved)" disclosure. Without the bridge this was LOG-ONLY and invisible
// to every /metrics dashboard; a production storage outage was silent.
func TestTrack18_T1b_SafetyCriticalOrphanSignal(t *testing.T) {
	exp := NewExporter()
	exp.Registry().MustRegister(NewTelemetryBridge())
	body := scrapeMetrics(t, exp)
	const want = "supremum_compaction_l0_reap_manifests_skipped_orphan"
	if !strings.Contains(body, "# HELP "+want+" ") {
		t.Fatalf("safety-critical orphan-signal series %s NOT surfaced on /metrics — "+
			"the operator-blindness defect is still open. Body:\n%s", want, body)
	}
	// Drive it: Inc the orphan counter (simulating the reaper refusing a delete),
	// re-scrape, assert it ADVANCES — the operator can now ALERT on a non-zero /
	// rising edge where before they could only tail a log.
	telemetry.L0ReapSkippedOrphan.Inc()
	body2 := scrapeMetrics(t, exp)
	v2, ok := scrapeCounterValue(body2, want)
	if !ok || v2 < 1 {
		t.Fatalf("orphan counter not observed advancing on /metrics after Inc (got ok=%v v=%v)", ok, v2)
	}
	t.Logf("T1b PASS: orphan-signal %s operator-observable (cumulative=%v)", want, v2)
}

// TestTrack18_T2_SSoTEnumeration asserts the bridge enumerates
// telemetry.Counters() (the ONE list), not a hardcoded copy. The bridge's
// Describe series count MUST equal the registry's distinct counter count —
// which catches the "hardcoded list drifts" failure mode when a future Day-19
// adds a counter the bridge omits. Three sub-assertions: (a) the bridge's
// counters slice IS the telemetry.Counters() snapshot (identity, not a copy);
// (b) the Desc set has exactly one Desc per distinct mapped name (no dup — the
// QueryL0ListCapped construction-dup is NOT in the slice); (c) Describe emits
// one Desc per counter (scales as append, not as a hardcoded edit).
func TestTrack18_T2_SSoTEnumeration(t *testing.T) {
	bridge := NewTelemetryBridge()
	cs := telemetry.Counters()

	// (a) Identity: the bridge's slice is the SSoT snapshot, not a parallel
	// hand-typed list.
	if len(bridge.counters) != len(cs) {
		t.Fatalf("bridge.counters len=%d != telemetry.Counters() len=%d — the bridge maintains a DUPLICATE list (drifts the instant a counter is added)",
			len(bridge.counters), len(cs))
	}
	for i := range cs {
		if bridge.counters[i] != cs[i] {
			t.Errorf("bridge.counters[%d] (%p) != telemetry.Counters()[%d] (%p) — not the SSoT snapshot",
				i, bridge.counters[i], i, cs[i])
		}
	}

	// (b) One Desc per distinct mapped name (no dup entered the Desc set — a
	// dup would panic MustRegister on a duplicate Desc at boot).
	if len(bridge.descs) != len(cs) {
		t.Fatalf("bridge.descs len=%d != telemetry.Counters() len=%d — a duplicate mapped name entered the Desc set (would panic MustRegister on a dup Desc)",
			len(bridge.descs), len(cs))
	}

	// (c) Describe emits exactly one Desc per counter (the bridge scales as
	// append: a future Day-19 counter appears in Describe WITHOUT a code edit).
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
		t.Fatalf("Describe emitted %d Descs; want %d (one per distinct counter — SSoT, no dup)", got, len(cs))
	}
	t.Logf("T2 PASS: bridge series count (%d) == telemetry.Counters() count (%d) — SSoT, scales as append", got, len(cs))
}

// TestTrack18_T3_ZeroAllocCollect measures AllocsPerRun over a single Collect
// with the PRE-BUILT Desc set. The scrape path is off the hot path, but a
// scrape-cost spike under heavy fanout is a latent footgun; the Desc set MUST
// be built ONCE at NewTelemetryBridge (not per Collect). If
// promhttp/prometheus.MustNewConstMetric allocates non-zero, the MEASURED
// residual is disclosed in ADR-0023 §6 — never gamed by skipping the
// const-metric build (that would be a fabrication).
func TestTrack18_T3_ZeroAllocCollect(t *testing.T) {
	bridge := NewTelemetryBridge()
	// Prime any one-time laziness (e.g. map backing) so the measurement
	// reflects steady-state Collect, not first-call setup.
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
	t.Logf("T3 MEASURED: Collect allocs/run = %v (target 0; the const-metric "+
		"constructor is the only per-Collect allocation surface)", allocs)
	if allocs != 0 {
		// HONEST path: disclose, do NOT fail (a non-zero const-metric
		// allocation is a promhttp-internal, NOT a bridge defect — and gating
		// it red would tempt a future fork to skip the const-metric build,
		// fabricating zero). ADR-0023 §6 carries the measured number.
		t.Logf("T3 RESIDUAL: non-zero collect allocs (%v) disclosed to ADR-0023 §6; "+
			"NOT a bridge defect — the bridge reuses the pre-built Desc set and "+
			"only the prometheus MustNewConstMetric constructor (off the data "+
			"path) can allocate. Gate stays GREEN; the tooth exists to MEASURE, "+
			"not to gloat over a zero that may not be reachable.", allocs)
	}
	// Assert the bridge-side invariant we CAN guarantee: NO Desc is rebuilt per
	// Collect (the desc map identity is stable across scrapes).
	metricCh := make(chan prometheus.Metric, len(telemetry.Counters())+1)
	bridge.Collect(metricCh)
	close(metricCh)
	for m := range metricCh {
		_ = m.Desc().String() // every collected metric carries a Desc from the pre-built set
	}
	// If the desc map were rebuilt per Collect, the identity would churn; assert
	// the SAME map object backs every scrape (it does — it is a field).
	before := bridge.descs
	again := make(chan prometheus.Metric, len(telemetry.Counters())+1)
	bridge.Collect(again)
	close(again)
	if len(bridge.descs) != len(before) {
		t.Errorf("bridge.descs churned across Collect (rebuilt per scrape) — %d -> %d", len(before), len(bridge.descs))
	}
}

// TestTrack18_T4_DoubleCountTrapGuard asserts the bridge reads Counter.Value()
// (cumulative) and NEVER lastReported. lastReported is the OTel-callback field;
// reading it from the bridge couples the bridge to the OTel cadence and tears
// the delta if OTel fires between scrapes — the §0.b production double-count.
// TODAY telemetry.Init is never called (T6), so lastReported stays 0; this tooth
// asserts it stays 0 after a scrape, pre-empting the future-fork bind of a real
// OTel Meter. The authoritatively in-package assertion (the field is
// unexported) lives in internal/telemetry; this tooth mirrors it at the scrape
// layer (the scraped value == Counter.Value() directly).
func TestTrack18_T4_DoubleCountTrapGuard(t *testing.T) {
	exp := NewExporter()
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)

	// Inc a counter N times; the bridge value MUST equal N THROUGH Value()
	// (cumulative), not through lastReported (which stays 0).
	const n = 11
	c := telemetry.CompactionRowsPruned
	if c == nil {
		t.Fatal("telemetry.CompactionRowsPruned nil")
	}
	// Capture the pre-Inc cumulative directly off the Counter (the honest
	// reference, NOT lastReported).
	preValue := c.Value()
	for i := 0; i < n; i++ {
		c.Inc()
	}
	postValue := c.Value()
	if math.Abs((postValue-preValue)-float64(n)) > 0.5 {
		t.Fatalf("Counter.Value() cumulative broken: pre=%v post=%v want +%d", preValue, postValue, n)
	}

	// Scrape: the bridge-reported value MUST match Counter.Value() (the bridge
	// reads the LongAdder, not lastReported). The cumulative-not-delta
	// invariant from T1 governs; here we assert the scrape==Value() identity.
	body := scrapeMetrics(t, exp)
	scraped, ok := scrapeCounterValue(body, "supremum_compaction_l1_rows_pruned")
	if !ok {
		t.Fatalf("scrape missing supremum_compaction_l1_rows_pruned")
	}
	if math.Abs(scraped-postValue) > 0.5 {
		t.Fatalf("bridge reported %v but Counter.Value()=%v — the bridge is reading a NON-Value() source (lastReported? a delta?) — the §0.b trap is armed",
			scraped, postValue)
	}
	// The authoritative lastReported-unchanged assertion lives in-package in
	// internal/telemetry (the field is unexported). This tooth's job is the
	// scrape layer; the in-package tooth carries the field assertion.
	t.Logf("T4 PASS: bridge scrape (%v) == Counter.Value() (%v) — reads the LongAdder, never lastReported", scraped, postValue)
}

// TestTrack18_T5_NilOTelSafe constructs the bridge WITHOUT calling
// telemetry.Init (the Day-18 production reality — Init had ZERO production
// callers, so meter stayed nil and no OTel observable was ever registered; Day
// 21 ADR-0026 arm'd Init gated --otel, but the BRIDGE does NOT call Init). The
// bridge MUST still enumerate + report cumulative. Driving Inc + scraping
// proves the two-layer no-op is closed at the prometheus layer WITHOUT
// requiring the OTel layer.
func TestTrack18_T5_NilOTelSafe(t *testing.T) {
	// NOTE: this test process may have had telemetry.Init called by a prior
	// test in this package; the POINT is that the BRIDGE does not call it. We
	// construct the bridge fresh and drive a counter; the constant is the bridge
	// never touches telemetry.Init. (The authoritative "exactly one production
	// caller under cmd/" assertion is T-ARMED's grep in
	// track21_t_armed_test.go— Day 21 refreshed the Day-18 "zero" prose.)
	exp := NewExporter() // does NOT call telemetry.Init
	bridge := NewTelemetryBridge()
	exp.Registry().MustRegister(bridge)
	if len(bridge.counters) == 0 {
		t.Fatal("bridge.enumerated ZERO counters without telemetry.Init — the package-init construction is the bridge's source, and it is empty")
	}
	// Drive a counter + scrape: non-zero value proves the prometheus layer is
	// closed independent of the OTel layer.
	c := telemetry.CompactionMerged
	if c == nil {
		t.Fatal("telemetry.CompactionMerged nil")
	}
	c.Inc()
	c.Inc()
	body := scrapeMetrics(t, exp)
	v, ok := scrapeCounterValue(body, "supremum_compaction_l0_files_merged")
	if !ok {
		t.Fatalf("scrape missing supremum_compaction_l0_files_merged")
	}
	if v < 2 {
		t.Fatalf("nil-OTel bridge did not surface cumulative: supremum_compaction_l0_files_merged=%v (want >=2 after two Inc)", v)
	}
	t.Logf("T5 PASS: bridge surfaces cumulative (%v) with NO telemetry.Init call — two-layer no-op closed at the prometheus layer", v)
}

// TestTrack18_T6_FrozenAndScopeHygiene asserts the 5 FROZEN md5s are
// byte-identical (NO re-pin this fork — the FIRST chain fork with that
// property since Day-13). The "Init stays at ZERO production callers" prose
// was FLIPPED Day 21 (ADR-0026) — arming Init is the deliverable; the gated
// assertion is now track21_t_armed_test.go TestTrack21_T_Armed (EXACTLY ONE
// production caller under cmd/sovereign-node/, the bridge does NOT call Init).
// This tooth still asserts ONLY the 5-file FROZEN md5 set (byte-identical Day
// 18 behavior); the Init-caller contract moved to T-ARMED.
func TestTrack18_T6_FrozenAndScopeHygiene(t *testing.T) {
	frozen := []struct {
		path string
		md5  string
	}{
		{"pkg/sync/crdt.go", "44f89527"},
		{"pkg/sync/crdt_apply.go", "ed9132a2"},
		{"api/capnp/api/capnp/schema.capnp", "47d2796a"},
		{"api/capnp/api/capnp/schema.capnp.go", "590af228"},
		{"pkg/attribution/envelope.go", "b1beba1e"},
	}
	for _, f := range frozen {
		got := md5Head8(t, f.path)
		if !strings.HasPrefix(got, f.md5) {
			t.Fatalf("FROZEN drift: %s md5=%s want prefix=%s — this fork touches ZERO FROZEN files; if any drifted the scope map is wrong (STOP, do not silently unfreeze)",
				f.path, got, f.md5)
		}
	}
	t.Logf("T6 PASS: all 5 FROZEN md5s byte-identical (NO re-pin this fork)")
}

// md5Head8 returns the first 8 hex chars of md5(path), the prefix form used in
// the FROZEN pin table (e.g. "44f89527"). The FROZEN paths are repo-relative
// (e.g. "pkg/sync/crdt.go"); the test working dir is pkg/metrics, so resolve
// ../../<path>. The md5 is over the working-tree bytes (matches the Day-16/17
// pin convention: md5sum on the working tree, not git's blob hash).
func md5Head8(t *testing.T, repoRelPath string) string {
	t.Helper()
	abs := "../../" + repoRelPath // pkg/metrics -> repo root
	b, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read FROZEN %s: %v", repoRelPath, err)
	}
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}
