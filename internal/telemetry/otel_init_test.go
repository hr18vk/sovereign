// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package telemetry

// These tests cover OpenTelemetry initialization and the QueryL0ListCapped
// registry invariants (ADR-0026). init constructs the counter once,
// rebuildCounters binds counters to the Meter supplied to Init, and the
// counters remain usable afterward.
//
// Init may run only once per process, so tests that need a real MeterProvider
// reinvoke the test binary. The subprocesses check registration, counter
// updates, and collection. They also verify that OpenTelemetry's delta stream
// and the Prometheus bridge's cumulative reads remain independent: the OTel
// callback advances lastReported, while the bridge reads Value.

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

// otelInitSubprocessMarker selects the subprocess entry point. Each mode gets
// a fresh process because Init accepts only its first call.
const otelInitSubprocessMarker = "SUPREMUM_OTEL_INIT_SUBPROC"

// TestQueryL0ListCappedConstructedOnce checks that init constructs
// QueryL0ListCapped once and rebuildCounters constructs it once. Counting the
// construction sites makes duplicate registration visible even though
// allCounters contains each package variable only once.
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
	// Both construction functions use the same package variable. init must
	// contain one construction site, and the whole file must contain two.
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
		t.Fatalf("QueryL0ListCapped construction count=%d, want 2 (one in init and one in rebuildCounters); init count=%d", wholeFileCount, initCount)
	}
	if initCount != 1 {
		t.Fatalf("init QueryL0ListCapped construction count=%d, want 1; whole-file count=%d", initCount, wholeFileCount)
	}
	t.Logf("init QueryL0ListCapped construction count=%d; whole-file count=%d", initCount, wholeFileCount)
}

// TestCountersDistinctAfterDedup checks the registry cardinality and rejects
// duplicate metric names. Counters enumerates package variables rather than
// construction calls, so rebuilding the instruments must not add duplicate
// series to the Prometheus bridge.
func TestCountersDistinctAfterDedup(t *testing.T) {
	cs := Counters()
	const wantDistinct = 25
	if len(cs) != wantDistinct {
		t.Fatalf("len(Counters())=%d, want %d", len(cs), wantDistinct)
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
		t.Fatalf("Counters() contains %d duplicate names; Prometheus registration would fail", dups)
	}
	if len(seen) != wantDistinct {
		t.Fatalf("distinct names=%d, want %d", len(seen), wantDistinct)
	}
	t.Logf("Counters() contains %d metrics and %d distinct names; duplicate names=%d", len(cs), len(seen), dups)
}

// TestDedupFill_Subproc initializes a real Meter in a fresh subprocess and
// checks that rebuildCounters leaves QueryL0ListCapped non-nil. Without that
// construction, the package variable would be nil after Init and the query
// cap-hit path would stop recording increments.
func TestDedupFill_Subproc(t *testing.T) {
	if os.Getenv(otelInitSubprocessMarker) == "dedupfill" {
		runDedupFillSubproc(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDedupFill_Subproc$")
	cmd.Env = append(os.Environ(), otelInitSubprocessMarker+"=dedupfill")
	cmd.Args = append(cmd.Args, "-test.v")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dedup-fill subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "dedup-fill pass") {
		t.Fatalf("dedup-fill subprocess did not pass:\n%s", out)
	}
	t.Logf("dedup-fill subprocess passed with QueryL0ListCapped bound to the test Meter")
}

// runDedupFillSubproc constructs a MeterProvider and ManualReader, calls Init,
// and checks the counter allocated by rebuildCounters.
func runDedupFillSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)
	if QueryL0ListCapped == nil {
		t.Fatalf("QueryL0ListCapped is nil after Init; rebuildCounters did not reconstruct it")
	}
	t.Logf("dedup-fill pass: rebuildCounters reconstructed QueryL0ListCapped against the test Meter")
}

// TestOmissionFired_Subproc checks increments on the counter rebuilt by Init,
// rather than the object originally allocated during package initialization.
// This exercises the nil guard used by the query cap-hit path.
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
	if !strings.Contains(string(out), "omission-fired pass") {
		t.Fatalf("omission-fired subprocess did not pass:\n%s", out)
	}
	t.Logf("omission-fired subprocess passed: QueryL0ListCapped advances after Init")
}

// runOmissionFiredSubproc initializes the registry, adds two increments, and
// checks the cumulative value.
func runOmissionFiredSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)
	if QueryL0ListCapped == nil {
		t.Fatalf("QueryL0ListCapped is nil after Init")
	}
	before := QueryL0ListCapped.Value()
	QueryL0ListCapped.Add(1)
	QueryL0ListCapped.Add(1)
	after := QueryL0ListCapped.Value()
	if after-before < 2 {
		t.Fatalf("counter advanced by %v after two Add(1) calls, want at least 2", after-before)
	}
	t.Logf("omission-fired pass: counter advanced from %v to %v under a real Meter", before, after)
}

// TestOtelExport_Subproc uses a real MeterProvider and ManualReader to check
// that OpenTelemetry observes increments and advances lastReported. The
// ManualReader is separate from the Prometheus registry, whose bridge continues
// to read cumulative values through Value.
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
	if !strings.Contains(string(out), "otel-export pass") {
		t.Fatalf("otel-export subprocess did not pass:\n%s", out)
	}
	t.Logf("otel-export subprocess passed: OpenTelemetry observed the counter and advanced lastReported")
}

// runOtelExportSubproc increments a counter, collects the OpenTelemetry delta,
// and checks that the callback advanced lastReported. Value remains the
// cumulative reading used by the Prometheus bridge.
func runOtelExportSubproc(t *testing.T) {
	mr := sdkmetric.NewManualReader()
	// Attach a fixed service name to the collected resource.
	res, rerr := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0",
			attribute.String("service.name", "otel-init-probe"),
		),
	)
	if rerr != nil {
		t.Fatalf("merge OpenTelemetry resource: %v", rerr)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	meter := mp.Meter("internal/telemetry")
	Init(meter)
	if CompactionRowsPruned == nil {
		t.Fatalf("CompactionRowsPruned is nil after Init")
	}
	const inc = 7
	for i := 0; i < inc; i++ {
		CompactionRowsPruned.Inc()
	}
	cumulative := CompactionRowsPruned.Value()
	if cumulative < float64(inc) {
		t.Fatalf("cumulative Value()=%v after %d Inc calls, want at least %d", cumulative, inc, inc)
	}
	// Collect invokes the int64 observable callback, which reports a delta and
	// advances lastReported.
	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("collect OpenTelemetry metrics: %v", cerr)
	}
	observed, found := sumObservedCounter(&rm, "supremum.compaction.l1_rows_pruned")
	if !found {
		t.Fatalf("counter supremum.compaction.l1_rows_pruned is absent from OpenTelemetry output")
	}
	if observed < float64(inc) {
		t.Fatalf("OpenTelemetry observed value=%v, want at least %d after increments; observed=%v cumulative=%v", observed, inc, observed, cumulative)
	}
	// A nonzero lastReported shows that collection ran the callback. The bridge
	// does not use this field; it reads the cumulative value independently.
	lr := CompactionRowsPruned.lastReported.Load()
	if lr == 0 {
		t.Fatalf("lastReported is zero after Collect; the OpenTelemetry callback did not advance it")
	}
	t.Logf("otel-export pass: cumulative=%v observed=%v lastReported=%d", cumulative, observed, lr)
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
				// Keep found=true so the caller reports the unexpected zero total.
				fmt.Fprintf(os.Stderr, "otel-export: %s data type %T\n", name, m.Data)
			}
		}
	}
	return total, found
}

// TestLastReportedObservableUnderInit checks that OpenTelemetry collection
// advances lastReported after Init. It runs in a subprocess so the bridge test
// in the parent process retains its zero baseline.
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
		t.Fatalf("last-reported subprocess failed: %v\n%s", err, out)
	}
	t.Logf("last-reported subprocess passed: collection advanced lastReported after Init")
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
	// Inc updates only the stripes. The collector callback advances the separate
	// lastReported field when it observes their cumulative value.
	for i := 0; i < 5; i++ {
		c.Inc()
	}
	lrAfterInc := c.lastReported.Load()
	var rm metricdata.ResourceMetrics
	if cerr := mr.Collect(context.Background(), &rm); cerr != nil {
		t.Fatalf("collect OpenTelemetry metrics: %v", cerr)
	}
	lrAfterCollect := c.lastReported.Load()
	t.Logf("lastReported before Inc=%d, after Inc=%d, after Collect=%d", lrPre, lrAfterInc, lrAfterCollect)
	if lrAfterCollect == 0 || lrAfterCollect < lrAfterInc {
		t.Fatalf("lastReported did not advance on Collect: before Inc=%d, after Inc=%d, after Collect=%d", lrPre, lrAfterInc, lrAfterCollect)
	}
}
