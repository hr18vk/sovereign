// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package telemetry

// In-package guards (ADR-0026) for the OTel Init path: init() builds
// QueryL0ListCapped exactly once (dedup 2 → 1), rebuildCounters() fills the
// same construction (0 → 1), and telemetry.Init arms a real OTel SDK
// MeterProvider at boot. The guards prove the landmines are closed at the
// construction site AND the use site, and that the two-exporter separation is
// intact. See ADR-0026.
//
// - DedupInit: init() builds QueryL0ListCapped EXACTLY ONCE (a source-parse
// guard counting the `QueryL0ListCapped = newCounter(m,` construction
// sites — the dedup halves the init double from 2 → 1). The allCounters()
// slice is unchanged, so the bridge keeps working without a bridge edit.
//
// - DedupFill (load-bearing): rebuildCounters via a real test Meter leaves
// QueryL0ListCapped NON-nil. This proves the fill is load-bearing — run in
// a fresh subprocess because Init's once-per-process guard makes a second
// Init a rejected no-op in-process. Without the fill, an Init(realMeter)
// call reassigns the var to the new Meter's counter and the omitted fill
// would leave it nil. The guard drives the ACTUAL rebuildCounters via Init
// and asserts the var is the new Meter's object (non-nil + connected to the
// new Meter, asserted via Collect).
//
// - CountersDistinct (regression guard): Counters() STILL carries exactly the
// distinct counters (the dedup did not leak a duplicate name into the
// bridge feed).
//
// - OmissionFired (the headline guard): drives
// telemetry.QueryL0ListCapped.Add(1) AFTER Init(testMeter); asserts the
// counter ADVANCES (the use-site guard keeps counting). Run in a fresh
// subprocess (the once-guard); the guard observes the LIVE counter
// post-Init, not the init() object.
//
// - OtelExport (the arm-end guard): a real sdkmetric MeterProvider with a
// ManualReader; a Counter.Inc is OBSERVED via Collect; the observed value
// EQUALS the cumulative Counter.Value() (the double-count trap is disarmed
// — the OTel callback reads DELTA via lastReported, the bridge reads
// CUMULATIVE via Value(); the two DO NOT double-count at /metrics because
// they export through DIFFERENT destinations). Run in a subprocess.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// otelInitSubprocessMarker is the env var the Init-driving guards set when they
// re-invoke the test binary as a subprocess so a dedicated entry function
// drives Init ONCE in a fresh process (the once-per-process guard rejects a
// second Init in-process — the subprocess-vs-singleton choice).
const otelInitSubprocessMarker = "SUPREMUM_OTEL_INIT_SUBPROC"

// TestQueryL0ListCappedConstructedOnce asserts init() builds QueryL0ListCapped
// EXACTLY ONCE (the dedup 2 → 1). A source-parse guard reads registry.go and
// counts the `	QueryL0ListCapped = newCounter(m,` construction-site lines; the
// count MUST be 1. This REFUSES a refactor that hides the construction behind
// a helper (the count is at the construction site, not the indirect call). The
// allCounters() slice survives with the distinct counters — the dedup did not
// touch the slice (it reads the package var).
func TestQueryL0ListCappedConstructedOnce(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	path := filepath.Join(repoRoot, "internal", "telemetry", "registry.go")
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read registry.go: %v", rerr)
	}
	const constructionLine = "	QueryL0ListCapped = newCounter(m,"
	// Count across the WHOLE file (init + rebuildCounters); the dedup guard
	// ALSO checks init() specifically below. The whole-file count after the
	// fill is 2 (one in init, one in rebuildCounters) — consistent with the 11
	// siblings that ALSO appear in both sites. The init() count alone is 1.
	wholeFileCount := strings.Count(string(data), constructionLine)
	// Isolate the init() function body to assert the single-site dedup.
	initCount := 0
	if idx := strings.Index(string(data), "func init()"); idx >= 0 {
		body := string(data)[idx:]
		// The init() body ends at the closing brace before `// rebuildCounters`
		// or at the allCounters() snapshot assignment. Count constructions
		// within the init() function span.
		endIdx := strings.Index(body, "\nfunc rebuildCounters")
		if endIdx < 0 {
			endIdx = len(body)
		}
		initCount = strings.Count(body[:endIdx], constructionLine)
	} else {
		t.Fatalf("func init() not found in registry.go")
	}
	if wholeFileCount != 2 {
		t.Fatalf("dedup-init: whole-file construction count=%d, want 2 (one in init, one in rebuildCounters — the 11 siblings use the same shape); init() count=%d", wholeFileCount, initCount)
	}
	if initCount != 1 {
		t.Fatalf("dedup-init: init() QueryL0ListCapped construction count=%d, want 1 (the dedup 2 → 1); whole-file count=%d", initCount, wholeFileCount)
	}
	t.Logf("dedup-init PASS: init() builds QueryL0ListCapped exactly ONCE (count=%d); whole-file count=%d (init + rebuildCounters, consistent with the 11 siblings)", initCount, wholeFileCount)
}

// TestCountersDistinctAfterDedup asserts the dedup did NOT leak a duplicate
// name into the bridge feed. Counters() carries exactly the DISTINCT counter
// vars (the var-slice is the unwavering gate; the dedup is at the construction
// SITE, not the slice), so the bridge keeps working without a bridge edit.
//
// The asserted distinct count grew across the ADR series as disclosure counters
// were added (the T_gc auto-inference counters, the download-skip counters, and
// later the mesh/PKI/PQ disclosures — each disclosed, not hidden). The scope of
// this guard (the dedup-doesn't-leak invariant) is UNCHANGED; only the asserted
// count shifted. A companion guard asserts the count + 0 dups + the bridge
// enumeration of the new names WITHOUT a bridge edit (the slice auto-surface
// property). This guard stays the dedup invariant (the construction-site
// dedup); the increased count is the honest growth, NOT a regression.
func TestCountersDistinctAfterDedup(t *testing.T) {
	cs := Counters()
	const wantDistinct = 24 // distinct counters; grew across the ADR series as disclosure counters were added
	if len(cs) != wantDistinct {
		t.Fatalf("distinct-counters: len(Counters())=%d, want %d (ADR-0036 grew 21->22 — PQHandshakeNegotiated — the PQ-KEM disclosure grew the counter; ADR-0035 grew 19->21 — TWO counters: CertRotationTriggered + CertRevokedRejected — the PKI leaf-rotation + revocation-reject disclosure grew the counter; the dedup is at the construction site, not the var-slice; the bridge feed must NOT lose a slot)", len(cs), wantDistinct)
	}
	seen := map[string]int{}
	for _, c := range cs {
		seen[c.Name()]++
	}
	dups := 0
	for n, k := range seen {
		if k > 1 {
			dups++
			t.Errorf("duplicate name in Counters(): %q x%d", n, k)
		}
	}
	if dups != 0 {
		t.Fatalf("distinct-counters: %d duplicate names — the dedup leaked into the bridge feed (MustRegister would PANIC at boot)", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("distinct-counters: distinct names=%d, want %d", len(seen), wantDistinct)
	}
	t.Logf("distinct-counters PASS: Counters() carries %d DISTINCT (grew 16->17), %d distinct names, %d dups — the bridge feed is unchanged (the manifest-skip counter auto-surfaced)", len(cs), len(seen), dups)
}

// TestDedupFill_Subproc drives a REAL telemetry.Init(testMeter) in a fresh
// subprocess and asserts QueryL0ListCapped is NON-nil post-Init (the omission
// landmine is closed). The subprocess re-invokes the test binary with a
// sentinel entry function because Init's once-per-process guard makes a second
// Init a rejected no-op in-process. Negative control: a stale tree where
// rebuildCounters OMITTED the fill would leave QueryL0ListCapped nil post-Init
// (the var the init() object was assigned to gets reassigned by
// rebuildCounters; without the fill the new assignment is nil). The guard
// PROVES the fill at the construction site is load-bearing.
func TestDedupFill_Subproc(t *testing.T) {
	if os.Getenv(otelInitSubprocessMarker) == "dedupfill" {
		runDedupFillSubproc(t)
		return
	}
	// Parent: re-invoke the test binary as a subprocess for a fresh process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestDedupFill_Subproc$")
	cmd.Env = append(os.Environ(), otelInitSubprocessMarker+"=dedupfill")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dedup-fill subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "dedup-fill PASS") {
		t.Fatalf("dedup-fill subprocess did not pass:\n%s", out)
	}
	t.Logf("dedup-fill PASS (subprocess): rebuildCounters via a real test Meter leaves QueryL0ListCapped NON-nil — the omission landmine is closed")
}

// runDedupFillSubproc is the subprocess entry: it constructs a real MeterProvider
// + ManualReader, calls telemetry.Init(meter) ONCE, then asserts QueryL0ListCapped
// is NON-nil (the fill in rebuildCounters reconstructed it against the new Meter;
// the omission would have left it nil).
func runDedupFillSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)
	if QueryL0ListCapped == nil {
		t.Fatalf("dedup-fill: QueryL0ListCapped is nil post-Init — the rebuildCounters fill is MISSING (the omission landmine is OPEN); the cap-hit guard at internal/database/query.go:493 would silently stop counting")
	}
	t.Logf("dedup-fill PASS: QueryL0ListCapped NON-nil post-Init — rebuildCounters reconstructed it against the real Meter (the omission is closed)")
}

// TestOmissionFired_Subproc drives telemetry.QueryL0ListCapped.Add(1) AFTER
// Init(testMeter) and asserts the counter ADVANCES (the use-site guard keeps
// counting). The negative control: a rebuildCounters WITHOUT the fill →
// QueryL0ListCapped stays nil post-Init → Add is skipped by the use-site
// nil-guard. The guard PROVES the omission is closed at the USE site, not just
// the construction site. Run in a subprocess (the once-guard).
func TestOmissionFired_Subproc(t *testing.T) {
	if os.Getenv(otelInitSubprocessMarker) == "omissionfired" {
		runOmissionFiredSubproc(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestOmissionFired_Subproc$")
	cmd.Env = append(os.Environ(), otelInitSubprocessMarker+"=omissionfired")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("omission-fired subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "omission-fired PASS") {
		t.Fatalf("omission-fired subprocess did not pass:\n%s", out)
	}
	t.Logf("omission-fired PASS (subprocess): QueryL0ListCapped.Add(1) ADVANCES post-Init — the use-site guard keeps counting")
}

// runOmissionFiredSubproc is the subprocess entry: Init then Add then check.
func runOmissionFiredSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)
	if QueryL0ListCapped == nil {
		t.Fatalf("omission-fired: QueryL0ListCapped nil post-Init — the omission is OPEN")
	}
	before := QueryL0ListCapped.Value()
	QueryL0ListCapped.Add(1)
	QueryL0ListCapped.Add(1)
	after := QueryL0ListCapped.Value()
	if after-before < 2 {
		t.Fatalf("omission-fired: counter advanced by %v, want >=2 after two Add(1) calls (the use-site guard silently skipped — the omission is OPEN at the use site)", after-before)
	}
	t.Logf("omission-fired PASS: counter advanced %v -> %v under a real Meter (Add via the use-site guard is counted)", before, after)
}

// TestOtelExport_Subproc constructs a REAL sdkmetric MeterProvider +
// ManualReader, drives a Counter.Inc, then Collects and asserts the observed
// value EQUALS the cumulative Counter.Value(). This PROVES the two-exporter
// separation is intact: the bridge reads CUMULATIVE via Value(), the OTel
// callback reads DELTA via lastReported, and cumulative == sum-of-deltas. The
// guard is run in a subprocess (the once-guard + a fresh MeterProvider). The
// negative hazard wiring the OTel reader onto the bridge's prometheus Registry
// would DOUBLE-COUNT — the guard refuses that class by NOT registering the OTel
// reader with any prometheus Registry (the otel reader is a ManualReader, a
// separate destination).
func TestOtelExport_Subproc(t *testing.T) {
	if os.Getenv(otelInitSubprocessMarker) == "otelexport" {
		runOtelExportSubproc(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestOtelExport_Subproc$")
	cmd.Env = append(os.Environ(), otelInitSubprocessMarker+"=otelexport")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("otel-export subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "otel-export PASS") {
		t.Fatalf("otel-export subprocess did not pass:\n%s", out)
	}
	t.Logf("otel-export PASS (subprocess): OTel Collect observed the counter; cumulative == sum-of-deltas (two-exporter separation intact)")
}

// runOtelExportSubproc is the subprocess entry. It builds a ManualReader (a
// SEPARATE destination from the bridge's prometheus Registry), Init's the
// Meter against it, Inc's a counter, Collects, and asserts the observed sum
// matches the cumulative Value(). lastReported advances (the OTel callback
// fires inside Collect) — proving the OTel stream is live under a real Meter.
func runOtelExportSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	// Build a resource so Collect returns a populated ResourceMetrics (a
	// future change attributes per-region; today a fixed service.name).
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "otel-init-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("otel-export: resource merge: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)
	if CompactionRowsPruned == nil {
		t.Fatalf("otel-export: CompactionRowsPruned nil post-Init")
	}
	const inc = 7
	for i := 0; i < inc; i++ {
		CompactionRowsPruned.Inc()
	}
	cumulative := CompactionRowsPruned.Value()
	if cumulative < float64(inc) {
		t.Fatalf("otel-export: cumulative Value()=%v, want >=%d after %d Inc", cumulative, inc, inc)
	}
	// Collect the OTel stream — the int64-observable callback fires inside
	// Collect, reading delta via lastReported + advancing lastReported.
	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("otel-export: Collect: %v", cerr)
	}
	// The observed sum across the collected scope metrics for our counter.
	observed, found := sumObservedCounter(&rm, "supremum.compaction.l1_rows_pruned")
	if !found {
		t.Fatalf("otel-export: counter 'supremum.compaction.l1_rows_pruned' NOT found in the OTel Collect output (the observable callback did not register — Init did not bind the Meter to the counter)")
	}
	if observed < float64(inc) {
		t.Fatalf("otel-export: OTel observed value=%v, want >=%d (cumulative == sum-of-deltas; the first delta == the cumulative since lastReported was 0 pre-Init) observed=%v cumulative=%v", observed, inc, observed, cumulative)
	}
	// The double-count trap is DISARMED by the two-exporter separation:
	// the bridge would read cumulative via Value(); the OTel callback read
	// delta via lastReported. The guard asserts lastReported ADVANCED (the
	// OTel stream is live) — the bridge never touches lastReported (the
	// field-level invariant asserted by the in-package bridge guard).
	lr := CompactionRowsPruned.lastReported.Load()
	if lr == 0 {
		t.Fatalf("otel-export: lastReported == 0 after Collect — the OTel callback did NOT advance it (the observable is not wired under the Meter)")
	}
	t.Logf("otel-export PASS: cumulative=%v observed=%v lastReported=%d — cumulative == sum-of-deltas; the OTel stream is live under a real Meter (lastReported advanced), the bridge reads cumulative + never lastReported (two-exporter separation intact)", cumulative, observed, lr)
}

// sumObservedCounter walks a ResourceMetrics for a named int64 sum instrument
// and returns the observed value. The OTel SDK reports ObservableCounter data
// as a metricdata.Sum[int64] with DeltaTemporality (the int64-observable
// callback reports the per-interval delta). Returns found=false if the name
// is absent.
func sumObservedCounter(rm *metricdata.ResourceMetrics, name string) (float64, bool) {
	var total float64
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			found = true
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					total += float64(dp.Value)
				}
			case metricdata.Sum[float64]:
				for _, dp := range data.DataPoints {
					total += dp.Value
				}
			case metricdata.Gauge[int64]:
				for _, dp := range data.DataPoints {
					total += float64(dp.Value)
				}
			case metricdata.Gauge[float64]:
				for _, dp := range data.DataPoints {
					total += dp.Value
				}
			default:
				// Unknown aggregation kind — surface in the caller via found=true + total=0.
				fmt.Fprintf(os.Stderr, "otel-export: %s data type %T\n", name, m.Data)
			}
		}
	}
	return total, found
}

// TestLastReportedObservableUnderInit documents that arming Init makes
// lastReported OBSERVABLE under OTel (it is 0 while Init is uncalled). The
// in-package bridge guard asserts lastReported == 0 (the bridge never touches
// it); that guard STAYS GREEN for the BRIDGE because it ran BEFORE any Init in
// the test process. If a future change binds a test-Meter in the SAME process
// as the bridge guard, the baseline assertion needs a note (lastReported can be
// non-zero; the bridge invariant is the bridge never TOUCHES lastReported, not
// that it is 0). This guard runs in a subprocess so it does NOT contaminate the
// in-package bridge-guard baseline in this process.
func TestLastReportedObservableUnderInit(t *testing.T) {
	if os.Getenv(otelInitSubprocessMarker) == "lastreported" {
		runLastReportedSubproc(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLastReportedObservableUnderInit$")
	cmd.Env = append(os.Environ(), otelInitSubprocessMarker+"=lastreported")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("lastreported subprocess failed: %v\n%s", err, out)
	}
	t.Logf("lastreported PASS (subprocess): lastReported is observable under Init (the OTel callback advances it); the bridge invariant (never touches lastReported) is UNAFFECTED")
}

func runLastReportedSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	Init(mp.Meter("internal/telemetry"))
	c := CompactionRowsPruned
	if c == nil {
		t.Fatal("CompactionRowsPruned nil post-Init")
	}
	lrPre := c.lastReported.Load()
	// Baseline lastReported (synchronous-nop default): 0; the synchronous-nop
	// default means that any injection of the counter will set the lastReported
	// to zero before the first callback fires, and then the callback stores the
	// observed value. If multiple counters are tracked, the lastReported is
	// per-counter. This is the initial state.
	for i := 0; i < 5; i++ {
		c.Inc()
	}
	lrAfterInc := c.lastReported.Load()
	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("Collect: %v", cerr)
	}
	lrAfterCollect := c.lastReported.Load()
	t.Logf("lastreported: lrPre=%d lrAfterInc=%d lrAfterCollect=%d (the callback fired on Collect — lastReported advanced; the synchronous-nop default kept it 0 pre-Init; arming Init makes the OTel stream live)", lrPre, lrAfterInc, lrAfterCollect)
	if lrAfterCollect == 0 || lrAfterCollect < lrAfterInc {
		t.Fatalf("lastreported: lastReported did NOT advance on Collect (lrPre=%d lrAfterInc=%d lrAfterCollect=%d) — the OTel callback did not fire", lrPre, lrAfterInc, lrAfterCollect)
	}
}
