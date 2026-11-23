// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Sweep phase jitter (ADR-0066) derives a deterministic per-node offset from a
// domain-separated PCG stream. These tests cover repeatability, phase spread,
// selector independence, disabled behavior, and overlap within the responder
// service window.
//
// Fault injection can align every phase or reuse a zero-seeded PCG stream. The
// first case must fail the concurrent in-degree model; the second must fail the
// uniformity check. Per-connection TLS decryption serializes in-process request
// arrivals, so digestRespondDropped is not a useful desynchronization signal in
// these tests. Arrival overlap is the phase-sensitive observable here.

import (
	"bytes"
	"context"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestOutboundSweepJitterDeterminism checks that sweepPhaseOffset is a pure
// function of node ID and tick, returns an offset in [0, tick), and uses a PCG
// stream distinct from both inter-region fan-out and the intra-region view.
// Fixed offsets for one node guard the derivation against accidental changes.
func TestOutboundSweepJitterDeterminism(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_POLL_MIGRATION") == "j38wrong" {
		sweepPhaseWrongStreamBugInject.Store(true)
		defer sweepPhaseWrongStreamBugInject.Store(false)
		t.Log("fault injection: phase derivation uses intraViewPCGStream; pinned offsets must change")
	}
	if os.Getenv("SOVEREIGN_TEST_FAULT_POLL_MIGRATION") == "j38fixed" {
		sweepPhaseFixedBugInject.Store(true)
		defer sweepPhaseFixedBugInject.Store(false)
		t.Log("fault injection: phase offset ignores the tick; the range check must fail")
	}
	if sweepPhaseJitterPCGStream == 0 {
		t.Fatalf("sweepPhaseJitterPCGStream is zero, which is reserved for inter-region fan-out")
	}
	if sweepPhaseJitterPCGStream == intraViewPCGStream {
		t.Fatalf("sweepPhaseJitterPCGStream equals intraViewPCGStream")
	}
	for i := 0; i < 4096; i++ {
		id := selectorSimNodeID(i)
		for _, tick := range []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 400 * time.Millisecond} {
			a := sweepPhaseOffset(id, tick)
			b := sweepPhaseOffset(id, tick)
			if a != b {
				t.Fatalf("node %d derived %v then %v at tick %v", i, a, b, tick)
			}
			if a < 0 || a >= tick {
				t.Fatalf("node %d derived offset %v outside [0, %v)", i, a, tick)
			}
		}
	}
	id := selectorSimNodeID(0)
	// The three expected values are the same absolute PCG draw reduced modulo
	// each tick. They detect changes to the stream constant or seed chain that
	// would redistribute phases in a running fleet. Selecting the wrong stream
	// also changes these values, which the constant comparisons cannot detect.
	for _, pin := range []struct {
		tick time.Duration
		want time.Duration
	}{
		{50 * time.Millisecond, 41157649 * time.Nanosecond},
		{100 * time.Millisecond, 91157649 * time.Nanosecond},
		{400 * time.Millisecond, 91157649 * time.Nanosecond},
	} {
		if got := sweepPhaseOffset(id, pin.tick); got != pin.want {
			t.Fatalf("node 0 phase at tick %v is %v, want %v; check the PCG stream and seed derivation", pin.tick, got, pin.want)
		}
	}
	t.Logf("node 0 phases: 50ms=41.157649ms 100ms=91.157649ms 400ms=91.157649ms")
}

// TestOutboundSweepJitterSpread checks uniformity across 16 bins for 4096
// nodes. Distinct offsets are not required because collisions are valid; the
// chi-square statistic measures the spread needed to desynchronize responders.
// Reusing a zero-seeded PCG stream collapses every node into one bin and must
// exceed the critical value.
func TestOutboundSweepJitterSpread(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_JITTER") == "rj2" {
		sweepPhaseFrozenZeroBugInject.Store(true)
		defer sweepPhaseFrozenZeroBugInject.Store(false)
		t.Log("fault injection: every node uses a zero-seeded PCG stream")
	}
	const tick = 100 * time.Millisecond
	const fleet = 4096
	const bins = 16
	counts := make([]int, bins)
	for i := 0; i < fleet; i++ {
		ph := sweepPhaseOffset(selectorSimNodeID(i), tick)
		counts[int(int64(ph)*bins/int64(tick))]++
	}
	exp := float64(fleet) / float64(bins)
	chi2 := 0.0
	lo, hi := counts[0], counts[0]
	for _, c := range counts {
		if c < lo {
			lo = c
		}
		if c > hi {
			hi = c
		}
		d := float64(c) - exp
		chi2 += d * d / exp
	}
	crit := selectorChi2Crit(bins-1, 0.001)
	t.Logf("fleet=%d bins=%d bin_width=%.1fms chi2=%.1f critical=%.1f alpha=0.001 min=%d max=%d", fleet, bins, float64(tick)/float64(bins)/1e6, chi2, crit, lo, hi)
	if chi2 >= crit {
		t.Errorf("phase distribution chi2=%.1f exceeds critical value %.1f; offsets are not uniform across one tick", chi2, crit)
	}
}

// TestOutboundSweepJitterIndegreeModel models the arrivals that overlap each
// responder service window W. Per-round in-degree is phase-independent because
// Select depends on the round and node ID, so overlap is the useful signal.
//
// Two builds of duration W overlap when their starts differ by less than W. For
// desynchronized phases this gives w_eff = 2W/T - (W/T)^2 and a Poisson(f*w_eff)
// family. Pooling per-arrival counts size-biases the sample toward busy victims:
// E = p*E[k(k-1)]/E[k] = p*f for a near-Poisson draw. With all phases aligned,
// p=1 and the pooled mean is f; f-1 is instead the per-victim-round mean.
//
// W=2ms is the model's service-window parameter. The test checks the timing
// model; it does not measure wide-area responder drops.
func TestOutboundSweepJitterIndegreeModel(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_JITTER") == "rj1" {
		sweepPhaseAlignBugInject.Store(true)
		defer sweepPhaseAlignBugInject.Store(false)
		t.Log("fault injection: every phase is aligned at zero")
	}
	const W = 2 * time.Millisecond
	const T = 100 * time.Millisecond
	const rounds = 10
	l := selectorFindLayout(t, "N1000-333-333-334")
	ids, regions := buildSelectorPopulation(&l)
	edges := selectorRumorGraph(ids, regions, rounds, -1)
	phase := make([]time.Duration, len(ids))
	for i := range ids {
		phase[i] = sweepPhaseOffset(ids[i], T)
	}
	var buckets [3]int64 // {0 partners, 1 partner, >=2 partners}
	var samples, partnerSum int64
	var indegSum, victimRounds int64
	for r := 0; r < rounds; r++ {
		perVictim := make([][]time.Duration, len(ids))
		for p := range ids {
			for _, v := range edges[p][r] {
				if regions[v] == regions[p] {
					perVictim[v] = append(perVictim[v], phase[p])
				}
			}
		}
		for _, arr := range perVictim {
			if len(arr) == 0 {
				continue
			}
			indegSum += int64(len(arr))
			victimRounds++
			sort.Slice(arr, func(i, j int) bool { return arr[i] < arr[j] })
			for i := range arr {
				partners := 0
				for j := range arr {
					if j != i {
						d := arr[j] - arr[i]
						if d < 0 {
							d = -d
						}
						if d < W {
							partners++
						}
					}
				}
				if partners >= 2 {
					buckets[2]++
				} else {
					buckets[partners]++
				}
				samples++
				partnerSum += int64(partners)
			}
		}
	}
	wT := float64(W) / float64(T)
	// Sum(2*closePairs)/Sum(arrivals) is a ratio of sums, not the mean of
	// per-victim means. Busy victims therefore contribute more arrivals:
	// E = p*E[k(k-1)]/E[k] = p*f when Var(k) is approximately E[k].
	// The per-victim-round mean would be f-1 and is the wrong reference here.
	lambda := float64(intraViewSize) * (2*wT - wT*wT)
	mean := float64(partnerSum) / float64(samples)
	p0 := math.Exp(-lambda)
	p1 := lambda * p0
	p2 := 1 - p0 - p1
	e0 := p0 * float64(samples)
	e1 := p1 * float64(samples)
	e2 := p2 * float64(samples)
	chi2 := (float64(buckets[0])-e0)*(float64(buckets[0])-e0)/e0 +
		(float64(buckets[1])-e1)*(float64(buckets[1])-e1)/e1 +
		(float64(buckets[2])-e2)*(float64(buckets[2])-e2)/e2
	crit := selectorChi2Crit(2, 0.001)
	meanIndeg := float64(indegSum) / float64(victimRounds)
	t.Logf("N=%d rounds=%d samples=%d victim_rounds=%d mean_indegree=%.2f lambda=%.3f W=%s T=%s mean_overlap=%.3f chi2=%.1f critical=%.1f buckets=%d/%d/%d expected=%.0f/%.0f/%.0f",
		len(ids), rounds, samples, victimRounds, meanIndeg, lambda, W, T, mean, chi2, crit, buckets[0], buckets[1], buckets[2], e0, e1, e2)
	if chi2 >= crit {
		t.Errorf("arrival overlap does not match Poisson(%.3f): chi2=%.1f exceeds critical value %.1f; mean=%.3f", lambda, chi2, crit, mean)
	}
	if mean > 1.0 {
		t.Errorf("overlap mean %.3f exceeds 1.0 (%.2fx the model lambda %.3f); check for residual phase synchronization", mean, 1.0/lambda, lambda)
	}
	if float64(buckets[2]) > 1.5*e2 {
		t.Errorf("two-or-more-overlap bucket is %d, exceeding 1.5 times the expected %.0f", buckets[2], e2)
	}
}

// jitterSweepLineRe fixes the base sweep log format. Jitter changes scheduling
// without adding fields. With optional suffixes disabled, slowest_inter is the
// final field; the hybrid post-quantum harness used here enables none of them.
var jitterSweepLineRe = regexp.MustCompile(`^mesh: sweep round=([0-9]+) shipped_env=([0-9]+) entries=([0-9]+) misses=([0-9]+) relay_misses=([0-9]+) pending=([0-9]+) dur_ms=([0-9]+) slowest_ms=([0-9]+) slowest_inter=(\S+)$`)

// jitterConvergeViaRealLoop runs SweepLoop on both gossipers and polls their
// roots until three consecutive 60 ms samples are equal and nonzero. The loops
// supply real sweeps; polling alone would not advance convergence.
func jitterConvergeViaRealLoop(t *testing.T, h *PQHybridHarness) (rootA, rootB [32]byte) {
	t.Helper()
	loopCtx, cancel := context.WithCancel(h.ctx)
	doneA := make(chan struct{})
	doneB := make(chan struct{})
	go func() { h.gA.SweepLoop(loopCtx, 20*time.Millisecond); close(doneA) }()
	go func() { h.gB.SweepLoop(loopCtx, 20*time.Millisecond); close(doneB) }()
	// Always join the loops before returning, including after t.Fatalf. Otherwise
	// a later SetRoundReporter or SweepLoop could overlap a sweep from this arm.
	defer func() {
		cancel()
		<-doneA
		<-doneB
	}()
	// Race instrumentation can make a sweep longer than the normal deadline.
	deadline := time.Now().Add(time.Duration(30*jitterRaceScale) * time.Second)
	stable := 0
	for time.Now().Before(deadline) {
		// MerkleRootFromShards avoids building a State snapshot for every poll.
		ra := h.engineA.MerkleRootFromShards()
		rb := h.engineB.MerkleRootFromShards()
		if ra == rb && ra != [32]byte{} {
			stable++
			if stable >= 3 {
				return ra, rb
			}
		} else {
			stable = 0
		}
		time.Sleep(60 * time.Millisecond)
	}
	t.Fatalf("ticker-driven mesh did not converge and stabilize within 30s")
	return [32]byte{}, [32]byte{}
}

// TestOutboundSweepJitterOffByteIdentity compares otherwise identical harnesses
// with jitter enabled and disabled. Fixed seeds give corresponding nodes the
// same identities, including OriginNodeID in their dots. The test requires equal
// converged roots, zero phase derivations in the disabled arm, unchanged sweep
// log fields, and a first-fire delay equal to the known phase offset.
//
// TestOutboundSweepJitterSelectChainInvariant separately checks selector seed
// independence. The ordinary two-node and partition-heal tests cover the default
// disabled configuration.
func TestOutboundSweepJitterOffByteIdentity(t *testing.T) {
	seedA := bytesRepeat(0xA1, 32) // Fixed seeds make corresponding node IDs equal.
	seedB := bytesRepeat(0xB2, 32)
	hOff := newPQHybridHarnessSeeded(t, false, false, seedA, seedB)
	defer hOff.close()
	hOn := newPQHybridHarnessSeeded(t, false, false, seedA, seedB)
	defer hOn.close()
	hOn.gA.SetSweepPhaseJitter(true)
	hOn.gB.SetSweepPhaseJitter(true)

	var bufOff, bufOn bytes.Buffer
	// Register restoration before redirecting the process-wide logger so a fatal
	// assertion cannot capture output from later tests.
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	log.SetOutput(&bufOff)
	hOff.insertEvents(t, 1000)
	offRootA, offRootB := jitterConvergeViaRealLoop(t, hOff)
	log.SetOutput(&bufOn)
	hOn.insertEvents(t, 1000)
	onRootA, onRootB := jitterConvergeViaRealLoop(t, hOn)
	log.SetOutput(os.Stderr)

	if onRootA != offRootA || onRootB != offRootB {
		t.Fatalf("jitter changed converged content: enabled roots A=%x B=%x, disabled roots A=%x B=%x", onRootA, onRootB, offRootA, offRootB)
	}
	t.Logf("enabled and disabled jitter converged to identical roots A=%x B=%x after 1000 events", onRootA, onRootB)
	if d := hOff.gA.sweepPhaseDerives.Load(); d != 0 {
		t.Fatalf("disabled gossiper A derived a phase %d times, want 0", d)
	}
	if d := hOff.gB.sweepPhaseDerives.Load(); d != 0 {
		t.Fatalf("disabled gossiper B derived a phase %d times, want 0", d)
	}
	if hOn.gA.sweepPhaseDerives.Load() == 0 || hOn.gB.sweepPhaseDerives.Load() == 0 {
		t.Fatalf("enabled gossipers did not both derive phases: A=%d B=%d", hOn.gA.sweepPhaseDerives.Load(), hOn.gB.sweepPhaseDerives.Load())
	}
	// Keep the pointer first to minimize the struct's leading pointer data.
	for _, arm := range []struct {
		buf  *bytes.Buffer
		name string
	}{{&bufOff, "OFF"}, {&bufOn, "ON"}} {
		sweeps := 0
		for _, ln := range strings.Split(arm.buf.String(), "\n") {
			idx := strings.Index(ln, "mesh: sweep ")
			if idx < 0 {
				continue // Skip unrelated log messages and their timestamp prefixes.
			}
			sweeps++
			if !jitterSweepLineRe.MatchString(ln[idx:]) {
				t.Fatalf("%s arm emitted a sweep line outside the base format: %q", arm.name, ln[idx:])
			}
		}
		if sweeps == 0 {
			t.Fatalf("%s arm captured no sweep lines", arm.name)
		}
		t.Logf("%s arm emitted %d sweep lines in the base format", arm.name, sweeps)
	}

	// Choose a tick for which node B's known phase is at least 0.3T. The allowed
	// difference is ±0.25T, so a missing phase delay lies outside the band even
	// though ordinary sweep and scheduler delays may affect both arms.
	var Tstar time.Duration
	var phiB time.Duration
	for k := 1; k <= 16; k++ {
		cand := time.Duration(k) * 400 * time.Millisecond
		phi := sweepPhaseOffset(hOn.identB.NodeID, cand)
		if phi >= 3*cand/10 {
			Tstar, phiB = cand, phi
			break
		}
	}
	if Tstar == 0 {
		t.Fatalf("no tick in 400ms*1..16 gives node B a phase of at least 0.3T")
	}
	// Record at least 17 fires so the epoch check can average 16 later rounds.
	const wantFires = 17 // fire 0 + 16 round-2+ fires
	measureFires := func(h *PQHybridHarness, jitter bool) []time.Duration {
		t.Helper()
		h.gB.SetSweepPhaseJitter(jitter)
		var mu sync.Mutex
		var stamps []time.Time
		h.gB.SetRoundReporter(func() {
			mu.Lock()
			defer mu.Unlock()
			stamps = append(stamps, time.Now())
		})
		loopCtx, cancel := context.WithCancel(h.ctx)
		loopDone := make(chan struct{})
		start := time.Now()
		go func() { h.gB.SweepLoop(loopCtx, Tstar); close(loopDone) }()
		// Allow two extra ticks, scaled for the race detector's longer sweeps.
		deadline := start.Add(time.Duration((wantFires+2)*jitterRaceScale) * Tstar)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := len(stamps)
			mu.Unlock()
			if n >= wantFires {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		<-loopDone
		mu.Lock()
		defer mu.Unlock()
		out := make([]time.Duration, len(stamps))
		for i, s := range stamps {
			out[i] = s.Sub(start)
		}
		if len(out) < wantFires {
			t.Fatalf("reported only %d sweeps within %d ticks (T=%v)", len(out), wantFires+2, Tstar)
		}
		return out
	}
	offFires := measureFires(hOff, false)
	onFires := measureFires(hOn, true)
	offFire1, onFire1 := offFires[0], onFires[0]
	t.Logf("T=%v phi_B=%v disabled_first=%v enabled_first=%v later_fires=%d", Tstar, phiB, offFire1, onFire1, len(onFires)-1)
	// The broad disabled-arm band catches a gross scheduling error. The zero
	// derivation counter above is the direct check for phase code on that path.
	if offFire1 < Tstar/2 || offFire1 > 3*Tstar/2 {
		t.Errorf("disabled first sweep fired at %v, outside [0.5T, 1.5T] with T=%v", offFire1, Tstar)
	}
	if d := onFire1 - offFire1 - phiB; d < -Tstar/4 || d > Tstar/4 {
		t.Errorf("first-fire difference %v minus known phase %v is %v, outside ±0.25T with T=%v", onFire1-offFire1, phiB, d, Tstar)
	}
	// Launch skew and load drift can shift every fire in a run together, so
	// averaging does not remove that common-mode error. The epoch assertion uses
	// a fixed tolerance rather than deriving its band from per-fire variance.
	// Sigma remains a diagnostic for variation between individual fires.
	//
	// The ticker epoch must be the warm expiry at T+phi, placing later fires at
	// k*T+phi. Creating the ticker after the first sweep would instead fold that
	// sweep's duration dur0 into every later fire. The differenced residual
	// r_j = (on_j-off_j)-phiB preserves that systematic dur0 offset while the
	// 16-sample average reduces independent per-fire variation.
	const tier1EpochMeanBandNs = 5_000_000 // Fixed ±5ms tolerance for the mean residual.
	k := len(onFires) - 1                  // Later fires have indexes 1 through k.
	if k < 16 {
		t.Fatalf("measured %d later fires, need at least 16 for the epoch assertion", k)
	}
	res := make([]float64, k)
	for j := 1; j <= k; j++ {
		res[j-1] = float64(onFires[j]-offFires[j]) - float64(phiB)
	}
	var sumR float64
	for _, r := range res {
		sumR += r
	}
	meanR := sumR / float64(k)
	var sqR float64
	for _, r := range res {
		d := r - meanR
		sqR += d * d
	}
	sigma := math.Sqrt(sqR / float64(k-1)) // Per-fire spread, logged for diagnosis.
	band := float64(tier1EpochMeanBandNs)
	t.Logf("k=%d mean_residual=%v per_fire_sigma=%v band=±%v", k, time.Duration(meanR), time.Duration(sigma), time.Duration(band))
	if meanR < -band || meanR > band {
		t.Errorf("mean later-fire residual %v (k=%d, per-fire sigma=%v) exceeds band ±%v; later fires appear shifted by the first sweep duration. Anchor the ticker at the warm expiry before the first sweep", time.Duration(meanR), k, time.Duration(sigma), time.Duration(band))
	}
	// The timing loop must not introduce phase derivation on the disabled path.
	if d := hOff.gB.sweepPhaseDerives.Load(); d != 0 {
		t.Fatalf("disabled gossiper B derived a phase %d times after the timing loop, want 0", d)
	}
}

// TestOutboundSweepJitterSelectChainInvariant checks that two independent
// TopologyManagers return identical selections for 16 rounds with the same node
// IDs and registries. Phase derivation has no TopologyManager input, so enabling
// jitter cannot change this result. The enabled/disabled root comparison also
// covers accidental coupling of the phase to the selector seed chain.
func TestOutboundSweepJitterSelectChainInvariant(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_POLL_MIGRATION") == "j38clock" {
		selectSeedClockMixBugInject.Store(true)
		defer selectSeedClockMixBugInject.Store(false)
		t.Log("fault injection: the selector seed includes the clock; independent managers must diverge")
	}
	l := selectorFindLayout(t, "N1000-333-333-334")
	ids, regions := buildSelectorPopulation(&l)
	m1 := buildArmedManager(0, ids, regions)
	m2 := buildArmedManager(0, ids, regions)
	for r := 1; r <= 16; r++ {
		m1.SetSeed(selectorRoundSeed(uint64(r), ids[0]))
		m2.SetSeed(selectorRoundSeed(uint64(r), ids[0]))
		a := m1.Select(context.Background())
		b := m2.Select(context.Background())
		if len(a) != len(b) {
			t.Fatalf("round %d selected %d and %d peers in independent managers", r, len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("round %d position %d differs between independent managers: %x and %x", r, i, a[i], b[i])
			}
		}
	}
	t.Logf("independent managers returned identical selections for 16 rounds")
}
