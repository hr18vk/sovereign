// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

// These tests cover pruning-horizon inference (ADR-0027). Resolver.AsOf records
// the highest transaction time it observes. The compactor derives an effective
// horizon of max(operatorFloor, observedFrontier-backoff) and never lowers the
// horizon once set. A refused retreat increments a counter and writes a log.
//
// The tests exercise the package-private Resolver and L1Compactor methods as
// well as DominancePrune. The LocalFS round trip is in pkg/durability, and the
// counter registration and OpenTelemetry export tests are in internal/telemetry.
//
// The equivalence test supplies the same inferred horizon to its reference and
// to DominancePrune. It therefore checks pruning behavior at that horizon, not
// the inference arithmetic: an incorrect horizon would reach both sides. The
// floor tests check the arithmetic directly, and the LocalFS test checks a
// round trip at the inferred horizon (ADR-0020 §6a, ADR-0027 §7).

import (
	"bytes"
	"context"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/telemetry"
)

// TestInferAsOfObserves checks that the query-time frontier advances to the
// highest observed transaction time and does not retreat for a historical read.
// AsOf records the observation before listing storage, so an empty lister can
// drive the test even though every query returns ErrEntityNotFound.
func TestInferAsOfObserves(t *testing.T) {
	// The empty list lets AsOf finish with ErrEntityNotFound after recording the
	// query time; a nil lister would panic instead.
	r := NewResolver(noopLister22{}, noopLister22{}, NewJemallocAllocator(), "local", DefaultResolverConfig())
	ctx := context.Background()
	const entity = "alpha"
	vt := time.Unix(0, 500)

	// A fresh Resolver has not observed a query time.
	if got := r.QueryTxTimeFrontier(); got != 0 {
		t.Fatalf("fresh Resolver frontier = %d, want 0", got)
	}

	// Each increasing query time advances the frontier despite the empty result.
	increasing := []int64{1000, 5000, 50_000, 500_000}
	for _, txNs := range increasing {
		_, _ = r.AsOf(ctx, entity, vt, time.Unix(0, txNs))
		if got := r.QueryTxTimeFrontier(); got != txNs {
			t.Fatalf("frontier after AsOf(txTime=%d) = %d, want %d", txNs, got, txNs)
		}
	}
	if got := r.QueryTxTimeFrontier(); got != increasing[len(increasing)-1] {
		t.Fatalf("frontier after increasing queries = %d, want %d", got, increasing[len(increasing)-1])
	}

	// A query into the past must not lower the high-water mark.
	const forensic = 1
	highWater := r.QueryTxTimeFrontier()
	_, _ = r.AsOf(ctx, entity, vt, time.Unix(0, forensic))
	if got := r.QueryTxTimeFrontier(); got != highWater {
		t.Fatalf("frontier after AsOf(txTime=%d) = %d, want previous high-water mark %d", forensic, got, highWater)
	}
	t.Logf("frontier advanced to %d and remained unchanged after a query at %d", highWater, forensic)
}

// TestInferAsOfObservesConcurrentRace checks the atomic maximum with concurrent
// AsOf calls. Run with -race to check the compare-and-swap loop for data races.
func TestInferAsOfObservesConcurrentRace(t *testing.T) {
	r := NewResolver(noopLister22{}, noopLister22{}, NewJemallocAllocator(), "local", DefaultResolverConfig())
	ctx := context.Background()
	const entity = "alpha"
	vt := time.Unix(0, 500)

	const goroutines = 32
	const perG = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	// Track the largest query time supplied by any goroutine for comparison with
	// the Resolver's independently updated frontier.
	var maxTx atomic.Int64
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < perG; i++ {
				txNs := int64(g*1000 + i + 1)
				_, _ = r.AsOf(ctx, entity, vt, time.Unix(0, txNs))
				// Update the expected maximum atomically.
				for {
					cur := maxTx.Load()
					if txNs <= cur {
						break
					}
					if maxTx.CompareAndSwap(cur, txNs) {
						break
					}
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	got := r.QueryTxTimeFrontier()
	want := maxTx.Load()
	if got != want {
		t.Fatalf("frontier = %d, want maximum query time %d across %d goroutines × %d AsOf calls", got, want, goroutines, perG)
	}
	t.Logf("%d concurrent AsOf calls left the frontier at the maximum query time %d", goroutines*perG, got)
}

// noopLister22 returns an empty object list so AsOf reaches ErrEntityNotFound
// after recording its query time. It also implements S3Downloader, although the
// empty-list path does not call Download.
type noopLister22 struct{}

func (noopLister22) ListObjects(ctx context.Context, bucket, prefix string, max int) ([]string, error) {
	return nil, nil
}
func (noopLister22) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	// Return an error instead of panicking if a future query path downloads from
	// this empty store.
	return io.NopCloser(strings.NewReader("")), errNoDownload22
}

var errNoDownload22 = &errSimple22{"noopLister22: no download (the empty-list path never calls this)"}

type errSimple22 struct{ msg string }

func (e *errSimple22) Error() string { return e.msg }

// TestInferAlloc compares allocation counts for the same steady-state AsOf
// call. Once the frontier has reached the query time, observation takes the
// no-advance atomic path. Both measurements include observation, so equal counts
// check allocation stability rather than isolating its cost (ADR-0027 §6).
func TestInferAlloc(t *testing.T) {
	r := NewResolver(noopLister22{}, noopLister22{}, NewJemallocAllocator(), "local", DefaultResolverConfig())
	ctx := context.Background()
	const entity = "alpha"
	vt := time.Unix(0, 500)
	tx := time.Unix(0, 1_000_000)

	// Warm one-time state before measuring steady-state allocations.
	for i := 0; i < 10; i++ {
		_, _ = r.AsOf(ctx, entity, vt, tx)
	}

	// The frontier already equals tx, so subsequent observations take the
	// no-advance path.
	const runs = 100
	allocsWithSeam := testing.AllocsPerRun(runs, func() {
		_, _ = r.AsOf(ctx, entity, vt, tx)
	})

	allocsControl := testing.AllocsPerRun(runs, func() {
		_, _ = r.AsOf(ctx, entity, vt, tx)
	})

	t.Logf("AsOf allocations: with observation = %v, control = %v", allocsWithSeam, allocsControl)
	if allocsWithSeam != allocsControl {
		t.Fatalf("allocation counts differ: with observation = %v, control = %v, delta = %v",
			allocsWithSeam, allocsControl, allocsWithSeam-allocsControl)
	}
	t.Logf("steady-state AsOf allocations: with observation = %v, control = %v", allocsWithSeam, allocsControl)
}

// TestInferMonotone checks that SetInferredHorizon never lowers the pruning
// horizon. Candidates 200 and 300 follow larger values and must be refused;
// PruningHorizonRetreatRefused records those two refusals.
func TestInferMonotone(t *testing.T) {
	// NewL1Compactor captures the operator floor. SetInferredHorizon updates the
	// configuration field read by DominancePrune independently of the pruning
	// enable flag.
	cfg := CompactionConfig{
		L0FilesPerEntityTrigger: 8,
		MaxL1FilesPerEntity:     4,
		EnableDominancePruning:  true,
		PruningHorizonInt64Ns:   100,
		PruneBackoffInt64Ns:     0,
	}
	c := NewL1Compactor(nil, nil, nil, NewJemallocAllocator(), "local", cfg)

	// The counter is global, so compare its value before and after the sequence.
	preRefused := int64(0)
	if telemetry.PruningHorizonRetreatRefused != nil {
		preRefused = int64(telemetry.PruningHorizonRetreatRefused.Value())
	}

	sequence := []int64{100, 500, 200, 800, 300}
	expected := []int64{100, 500, 500, 800, 800}
	for i, cand := range sequence {
		got := c.SetInferredHorizon(cand)
		if got != expected[i] {
			t.Fatalf("step %d: SetInferredHorizon(%d) = %d, want %d; candidate %d after previous horizon %d must leave horizon %d",
				i, cand, got, expected[i], cand, expected[i-1], expected[i])
		}
		if c.cfg.PruningHorizonInt64Ns != expected[i] {
			t.Fatalf("step %d: PruningHorizonInt64Ns = %d, want %d", i, c.cfg.PruningHorizonInt64Ns, expected[i])
		}
	}

	postRefused := int64(0)
	if telemetry.PruningHorizonRetreatRefused != nil {
		postRefused = int64(telemetry.PruningHorizonRetreatRefused.Value())
	}
	if delta := postRefused - preRefused; delta != 2 {
		t.Fatalf("PruningHorizonRetreatRefused advanced by %d, want 2", delta)
	}
	t.Logf("horizon sequence %v produced effective horizons %v and two retreat refusals", sequence, expected)
}

// TestInferMonotoneRedControlNoClamp demonstrates the failure the clamp
// prevents. This negative control assigns every candidate directly, allowing a
// retreat from 500 to 200; the production setter must hold the horizon at 500.
func TestInferMonotoneRedControlNoClamp(t *testing.T) {
	setUnclamped := func(c *L1Compactor, cand int64) int64 {
		c.cfg.PruningHorizonInt64Ns = cand
		return cand
	}
	cfg := CompactionConfig{EnableDominancePruning: true, PruningHorizonInt64Ns: 100}
	c := NewL1Compactor(nil, nil, nil, NewJemallocAllocator(), "local", cfg)
	setUnclamped(c, 500)
	if c.cfg.PruningHorizonInt64Ns != 500 {
		t.Fatalf("negative control setup: horizon = %d, want 500", c.cfg.PruningHorizonInt64Ns)
	}
	// Once rows are removed at horizon 500, lowering the horizon to 200 cannot
	// recover them for historical queries.
	setUnclamped(c, 200)
	if c.cfg.PruningHorizonInt64Ns != 200 {
		t.Fatalf("negative control horizon = %d, want unclamped retreat to 200", c.cfg.PruningHorizonInt64Ns)
	}
	t.Logf("negative control accepted the retreat from 500 to %d", c.cfg.PruningHorizonInt64Ns)
}

// TestInferFloor checks max(operatorFloor, observedFrontier-backoff). Separate
// compactors are required because each one captures its operator floor at
// construction. The cases cover an inferred horizon above the floor, a floor
// above the inferred horizon, and a stale low floor.
func TestInferFloor(t *testing.T) {
	// The inferred horizon, 5000-500, is above the 1000 floor.
	cfg1 := CompactionConfig{
		EnableDominancePruning: true,
		PruningHorizonInt64Ns:  1000,
		PruneBackoffInt64Ns:    500,
	}
	c1 := NewL1Compactor(nil, nil, nil, NewJemallocAllocator(), "local", cfg1)
	got1 := c1.EffectiveHorizon(5000)
	const want1 int64 = 4500
	if got1 != want1 {
		t.Fatalf("EffectiveHorizon(5000) with floor 1000 and backoff 500 = %d, want %d", got1, want1)
	}

	// The 6000 operator floor is above the inferred horizon.
	cfg2 := CompactionConfig{
		EnableDominancePruning: true,
		PruningHorizonInt64Ns:  6000,
		PruneBackoffInt64Ns:    500,
	}
	c2 := NewL1Compactor(nil, nil, nil, NewJemallocAllocator(), "local", cfg2)
	got2 := c2.EffectiveHorizon(5000)
	const want2 int64 = 6000
	if got2 != want2 {
		t.Fatalf("EffectiveHorizon(5000) with floor 6000 and backoff 500 = %d, want %d", got2, want2)
	}

	// A stale floor below the inferred horizon does not lower the result.
	cfg3 := CompactionConfig{
		EnableDominancePruning: true,
		PruningHorizonInt64Ns:  100,
		PruneBackoffInt64Ns:    500,
	}
	c3 := NewL1Compactor(nil, nil, nil, NewJemallocAllocator(), "local", cfg3)
	got3 := c3.EffectiveHorizon(5000)
	const want3 int64 = 4500
	if got3 != want3 {
		t.Fatalf("EffectiveHorizon(5000) with stale floor 100 and backoff 500 = %d, want %d", got3, want3)
	}

	t.Logf("effective horizons for floors 1000, 6000, and 100: %d, %d, %d", want1, want2, want3)
}

// TestInferFloorRedControlIgnoreOperatorFloor shows why the maximum with the
// operator floor is necessary. Omitting it produces 4500, below the configured
// floor of 6000 and potentially admitting pruning the operator disallowed.
func TestInferFloorRedControlIgnoreOperatorFloor(t *testing.T) {
	ignoreFloor := func(c *L1Compactor, observed int64) int64 {
		return observed - c.inferrer.backoffNs
	}
	cfg := CompactionConfig{EnableDominancePruning: true, PruningHorizonInt64Ns: 6000, PruneBackoffInt64Ns: 500}
	c := NewL1Compactor(nil, nil, nil, NewJemallocAllocator(), "local", cfg)
	got := ignoreFloor(c, 5000)
	const wrong int64 = 4500
	if got != wrong {
		t.Fatalf("negative control: want observed minus backoff %d, got %d", wrong, got)
	}
	if got >= c.inferrer.operatorFloor {
		t.Fatalf("negative control horizon = %d, want value below operator floor %d", got, c.inferrer.operatorFloor)
	}
	t.Logf("negative control produced %d below operator floor %d; EffectiveHorizon returned %d", got, c.inferrer.operatorFloor, c.EffectiveHorizon(5000))
}

// TestInferEquiv compares DominancePrune with the reference implementation at
// horizons derived from max(operatorFloor, observedFrontier-backoff). Both
// implementations receive the same horizon, so these cases check pruning
// equivalence rather than inference arithmetic. TestInferFloor covers the
// arithmetic, and the LocalFS test covers the storage round trip (ADR-0027 §7).
func TestInferEquiv(t *testing.T) {
	const cases = 10_000
	r := newRandSeeded(22)

	// Keep the floor and backoff fixed while varying the observed frontier, as
	// happens when a workload advances the query-time high-water mark.
	const operatorFloor int64 = 100
	const backoff int64 = 50

	for c := 0; c < cases; c++ {
		n := r.Intn(2001) // 0..2000 rows
		// Include frontiers below and above the floor, at the floor, and near the
		// upper end of the int64 range.
		frontierChoices := []int64{0, 50, 100, 130, 200, 500, 1000, 1 << 62}
		observedFrontier := frontierChoices[r.Intn(len(frontierChoices))]
		horizon := inferEffectiveEquivalence(operatorFloor, backoff, observedFrontier)

		raw := make([]mergedRowT, n)
		for i := 0; i < n; i++ {
			sys := int64(r.Intn(501)) // 0..500, overlapping the horizon range
			vs := int64(r.Intn(301))
			veWidth := 1 + r.Intn(300)
			ve := vs + int64(veWidth) // half-open interval [vs, ve)
			ast := int64(r.Intn(501))
			raw[i] = mkRow(sys, vs, ve, ast, 'x')
		}
		// DominancePrune requires composite-key order. With a constant tag this
		// orders rows by system time, valid-time start, and assertion time.
		sort.SliceStable(raw, func(i, j int) bool {
			return bytesCompare(raw[i].frag[:], raw[j].frag[:]) < 0
		})

		refRows := cloneRows(raw)
		sweepRows := cloneRows(raw)
		refOut := dominancePruneReference(refRows, horizon)
		sweepOut := DominancePrune(sweepRows, horizon)

		if !survivorsByteIdentical(refOut, sweepOut) {
			t.Fatalf("case %d: prune results differ (floor=%d backoff=%d frontier=%d horizon=%d rows=%d)\nreference survivors: %s\nsweep survivors:     %s\nrows: %s",
				c, operatorFloor, backoff, observedFrontier, horizon, len(raw), survivorFragsHex(refOut), survivorFragsHex(sweepOut), rowsFragsHex(raw))
		}
	}
	t.Logf("%d randomized cases produced byte-identical survivors at inferred horizons", cases)
}

// inferEffectiveEquivalence mirrors L1Compactor.EffectiveHorizon without
// constructing a compactor for every randomized case. The floor tests exercise
// the production method directly.
func inferEffectiveEquivalence(operatorFloor, backoff, observedFrontier int64) int64 {
	inferred := observedFrontier - backoff
	if inferred < operatorFloor {
		return operatorFloor
	}
	return inferred
}

// TestInferRetreatCounterLoud checks that a refused retreat leaves the horizon
// unchanged, increments PruningHorizonRetreatRefused, and writes a warning log.
func TestInferRetreatCounterLoud(t *testing.T) {
	cfg := CompactionConfig{
		EnableDominancePruning: true,
		PruningHorizonInt64Ns:  1000,
		PruneBackoffInt64Ns:    0,
	}
	c := NewL1Compactor(nil, nil, nil, NewJemallocAllocator(), "local", cfg)

	preRefused := int64(0)
	if telemetry.PruningHorizonRetreatRefused != nil {
		preRefused = int64(telemetry.PruningHorizonRetreatRefused.Value())
	}

	// Capture the process-global logger output and restore it after the calls.
	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	c.SetInferredHorizon(5000)
	retreated := c.SetInferredHorizon(100)
	log.SetOutput(origOut)
	if retreated != 5000 {
		t.Fatalf("SetInferredHorizon(100) after 5000 returned %d, want 5000", retreated)
	}

	postRefused := int64(0)
	if telemetry.PruningHorizonRetreatRefused != nil {
		postRefused = int64(telemetry.PruningHorizonRetreatRefused.Value())
	}
	if delta := postRefused - preRefused; delta != 1 {
		t.Fatalf("PruningHorizonRetreatRefused advanced by %d, want 1", delta)
	}

	logText := buf.String()
	if !strings.Contains(logText, "retreat refused") {
		t.Fatalf("refused retreat did not write a warning log; captured output %q", logText)
	}
	t.Logf("retreat from 5000 to 100 was refused, counted, and logged")
}

// TestInferRetreatCounterGreen checks that an advancing horizon sequence does
// not increment the retreat-refusal counter.
func TestInferRetreatCounterGreen(t *testing.T) {
	cfg := CompactionConfig{EnableDominancePruning: true, PruningHorizonInt64Ns: 100, PruneBackoffInt64Ns: 0}
	c := NewL1Compactor(nil, nil, nil, NewJemallocAllocator(), "local", cfg)
	preRefused := int64(0)
	if telemetry.PruningHorizonRetreatRefused != nil {
		preRefused = int64(telemetry.PruningHorizonRetreatRefused.Value())
	}
	for _, h := range []int64{100, 200, 300, 400, 500, 1000, 5000} {
		c.SetInferredHorizon(h)
	}
	postRefused := int64(0)
	if telemetry.PruningHorizonRetreatRefused != nil {
		postRefused = int64(telemetry.PruningHorizonRetreatRefused.Value())
	}
	if delta := postRefused - preRefused; delta != 0 {
		t.Fatalf("advancing horizons changed PruningHorizonRetreatRefused by %d, want 0", delta)
	}
	t.Logf("advancing horizons left PruningHorizonRetreatRefused unchanged")
}
