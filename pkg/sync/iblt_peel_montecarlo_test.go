// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// IBLT peel Monte Carlo tests measure failure probability against difference
// size across the bucket counts and k values used by reconciliation. The grid
// locates the 1% crossing and reports the 0.1% crossing where seed counts can
// resolve it. A zero-failure run of N seeds supplies only the approximate 3/N
// upper bound: 3e-4 at 10^4 seeds and 3e-5 at 10^5 seeds. It does not establish
// a 1e-7 failure rate.
//
// Trials use heap NewIBLTWithSeed tables and the production Insert, Subtract,
// and Peel methods. Arena backing does not change placement, and heap tables
// also cover sizes above the 21,845-bucket arena ceiling. Uint64ToSeed and
// splitmix64-derived keys make trials reproducible; splitmix64 is a bijection,
// so distinct inputs produce distinct keys.
//
// Placement is process-global only for construction. Each scheme block sets
// SetIBLTSchemeV2 before creating its tables and restores the v1 default on
// cleanup, allowing parallel trials within a block. v1 arithmetic progression
// remains the default; --iblt-v2 selects decorrelated placement.
//
// The v2 grid uses per-k 2-core thresholds, not a universal clean guarantee.
// It requires at least 50% failures at beta=0.85, a measured 1% crossing in
// beta=[1.0,1.15], and at most 5% failures at beta=1.15. At beta=2 it reports
// either the measured failure fraction or the 3/N bound for zero failures.
// A crossing below 1.0 contradicts the model on the undersized side; one above
// 1.15 shows that finite tables need more margin than the model predicts.
//
// Every trial also checks for decoded keys outside the inserted difference.
// Shared keys cancel exactly in this remote-subset shape, however, so it does
// not exercise negative counts or unequal multiplicities. Large bucket counts
// whose transition lies beyond D=10,000 are reported without a crossing claim.
// The v1 curve is report-only; its B² stopping-set floor has a separate
// always-on comparison at D=400, B=1024. The measured v2 floor near beta=2 is
// 1.11e-3, so the v2 comparison uses 5e-3 rather than requiring zero failures.
//
// The k=1 arm is the negative control: collapsing every key to one index
// raises failure probability toward 1-exp(-D²/2B). The always-on smoke test
// requires at least 20 failures among 64 trials at B=128, D=20, while the
// k=4 margin point must have none.
//
// RUN_PEEL_MONTECARLO=1 enables the full grid. RUN_PEEL_MC_SEEDS overrides the
// default 10^4 seeds per point. TestIBLT_V2VsV1FloorGuard and
// TestIBLT_PeelMonteCarloSmoke run without an environment gate.

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// ibltTwoCoreThresholdC contains the Goodrich–Mitzenmacher 2-core threshold
// for each supported k. The grid evaluates bands around each value rather
// than applying one constant to every configuration.
var ibltTwoCoreThresholdC = map[int]float64{
	3: 1.222,
	4: 1.295,
	5: 1.425,
	7: 1.721,
}

// peelMCSplitmix64 applies the splitmix64 finalizer. It is a bijection on
// uint64, so derived test keys remain distinct and uniformly distributed.
func peelMCSplitmix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	x ^= x >> 31
	return x
}

// peelMCEnvInt reads an integer environment override and returns deflt when
// it is unset, malformed, or below floor.
func peelMCEnvInt(name string, floor, deflt int) int {
	v := os.Getenv(name)
	if v == "" {
		return deflt
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < floor {
		return deflt
	}
	return n
}

// runPeelMCTrial inserts d difference keys and d shared keys into local,
// inserts only the shared keys into remote, then subtracts and peels. It
// reports an incomplete peel or wrong decoded count as fail, and a successfully
// peeled key outside the difference set as wrong. Shared keys cancel exactly,
// so the difference table is count-identical to insert-only; this shape checks
// the production Subtract path but does not exercise unequal multiplicities.
// (seedWord, d) determines the complete trial.
func runPeelMCTrial(buckets, k, d int, seedWord uint64) (fail, wrong bool) {
	seed := Uint64ToSeed(seedWord)
	local := NewIBLTWithSeed(buckets, k, seed)
	remote := NewIBLTWithSeed(buckets, k, seed) // same seed: shared keys cancel exactly
	want := make(map[uint64]struct{}, d)
	for i := 0; i < d; i++ {
		key := peelMCSplitmix64(uint64(i)*0x9E3779B97F4A7C15 ^ seedWord)
		want[key] = struct{}{}
		local.Insert(key)
	}
	// d shared keys (the converged rest of the keyset): in both tables,
	// cancelling to pure-zero buckets — the production A−B shape. Their
	// stream is disjoint from the diff keys (different multiplier term
	// and complemented seed term under the splitmix bijection).
	for i := 0; i < d; i++ {
		key := peelMCSplitmix64((uint64(i)+0xA5A5)*0x9E3779B97F4A7C15 ^ ^seedWord)
		local.Insert(key)
		remote.Insert(key)
	}
	diff, err := local.Subtract(remote)
	if err != nil {
		return true, false
	}
	localHas, remoteHas, err := diff.Peel()
	if err != nil {
		return true, false
	}
	if len(localHas)+len(remoteHas) != d {
		return false, true
	}
	for _, key := range localHas {
		if _, ok := want[key]; !ok {
			return false, true
		}
	}
	for _, key := range remoteHas {
		if _, ok := want[key]; !ok {
			return false, true
		}
	}
	return false, false
}

// measurePeelMCFailFraction runs deterministic trials in parallel at one
// (buckets, k, d) point. The caller has already selected the construction
// scheme for the entire block. Each seed incorporates the point and trial
// index, keeping grid cells independent and reruns reproducible.
func measurePeelMCFailFraction(buckets, k, d, seeds, workers int) (fails, wrongs int) {
	if workers < 1 {
		workers = 1
	}
	var failCount, wrongCount atomic.Int64
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				trial := int(next.Add(1)) - 1
				if trial >= seeds {
					return
				}
				seedWord := uint64(trial+1)*0x9E3779B97F4A7C15 ^
					uint64(buckets)*0x27D4EB2F165667C5 ^
					uint64(k)*0x165667C5849EAD1 ^
					uint64(d)*0x9E3779B1
				fl, wr := runPeelMCTrial(buckets, k, d, seedWord)
				if fl {
					failCount.Add(1)
				}
				if wr {
					wrongCount.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	return int(failCount.Load()), int(wrongCount.Load())
}

// peelMCWorkers uses at least four workers and at most 64, bounded above by
// GOMAXPROCS. Trials share only atomic work and result counters.
func peelMCWorkers() int {
	w := runtime.GOMAXPROCS(0)
	if w < 4 {
		w = 4
	}
	if w > 64 {
		w = 64
	}
	return w
}

// TestIBLT_V2VsV1FloorGuard compares the default v1 placement with opt-in v2
// at D=400, B=1024, k=4. Under uniform keys, the v1 pair-collision model is
// approximately 1-exp(-C(D,2)*4/B²), or 26% failure; this test requires at
// least 15%. At the same point v2 must remain at or below 5e-3.
//
// The v2 threshold accounts for the measured 1.11e-3 floor over 10^5 seeds at
// D=395, B=1024, near beta=2. Requiring zero failures would contradict that
// measurement, while 5e-3 still detects a collapse toward the v1 floor.
func TestIBLT_V2VsV1FloorGuard(t *testing.T) {
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	const seeds = 4000
	workers := peelMCWorkers()

	// The default v1 scheme must reproduce its pair-collision floor.
	SetIBLTSchemeV2(false)
	fV1, wV1 := measurePeelMCFailFraction(1024, 4, 400, seeds, workers)
	fracV1 := float64(fV1) / float64(seeds)
	t.Logf("v1 B=1024 k=4 D=400: fail=%d/%d (%.4f) wrong=%d; pair-collision model approximately 0.26", fV1, seeds, fracV1, wV1)
	if wV1 != 0 {
		t.Errorf("v1 decoded %d keys outside the inserted difference at D=400/B=1024", wV1)
	}
	if fracV1 < 0.15 {
		t.Errorf("v1 failure fraction %.4f is below 0.15 at D=400/B=1024; the expected pair-collision floor did not reproduce", fracV1)
	}

	// The opt-in v2 scheme must remain well below the v1 failure fraction.
	SetIBLTSchemeV2(true)
	fV2, wV2 := measurePeelMCFailFraction(1024, 4, 400, seeds, workers)
	fracV2 := float64(fV2) / float64(seeds)
	t.Logf("v2 B=1024 k=4 D=400: fail=%d/%d (%.4f) wrong=%d beta=%.2f resolution-3/N=%.1e threshold=0.005 v1=%.4f", fV2, seeds, fracV2, wV2, 1024.0/(1.295*400), 3.0/float64(seeds), fracV1)
	if wV2 != 0 {
		t.Errorf("v2 decoded %d keys outside the inserted difference at D=400/B=1024", wV2)
	}
	// The 5e-3 threshold is above the measured 1.11e-3 floor and far below
	// v1's approximately 0.26 failure fraction. It detects a collapse in the
	// decorrelated stream, but not a partial regression between those rates;
	// resolving that band requires the higher-seed grid.
	if fracV2 > 5e-3 {
		t.Errorf("v2 failed %d/%d at D=400/B=1024 (%.4f), above the 0.005 threshold and toward v1's pair-collision floor", fV2, seeds, fracV2)
	}
}

// peelMCPoint is one measured grid cell.
type peelMCPoint struct {
	k, B, d int
	beta    float64
	fails   int
	wrongs  int
	seeds   int
}

// TestIBLT_PeelEnvelopeMonteCarlo runs the full grid only when
// RUN_PEEL_MONTECARLO=1. It checks the 1% crossing and beta=2 margins for v2
// and reports the v1 curve for comparison. At 10^5 seeds, a zero-failure margin
// has a 3/N bound of 3e-5; the grid does not claim 1e-7 resolution.
func TestIBLT_PeelEnvelopeMonteCarlo(t *testing.T) {
	if os.Getenv("RUN_PEEL_MONTECARLO") != "1" {
		t.Skip("set RUN_PEEL_MONTECARLO=1 to run the full peel-probability grid")
	}
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	seeds := peelMCEnvInt("RUN_PEEL_MC_SEEDS", 100, 10000)
	workers := peelMCWorkers()
	buckets := []int{1024, 2048, 4096, 8192, 16384, 21845}
	ks := []int{3, 4, 5, 7}
	// beta=B/(c_k*D) samples the transition at 0.85 through 1.15, the
	// undersized side at 0.55, and the sizing margin at 2.0.
	betas := []float64{0.55, 0.85, 1.0, 1.05, 1.15, 1.4, 2.0}
	schemes := []struct {
		name string
		v2   bool
	}{{"v1", false}, {"v2", true}}
	results := map[string]map[int]map[int]map[float64]peelMCPoint{}
	pointAt := func(scheme string, k, B int, beta float64) *peelMCPoint {
		m1 := results[scheme]
		if m1 == nil {
			return nil
		}
		m2 := m1[k]
		if m2 == nil {
			return nil
		}
		p, ok := m2[B][beta]
		if !ok {
			return nil
		}
		return &p
	}
	t.Logf("grid: 2 schemes x k=%v x B=%v x beta=%v, seeds=%d/point, workers=%d — D derived as round(B/(c_k*beta)), clamped to the range [10,10000]", ks, buckets, betas, seeds, workers)
	for _, sch := range schemes {
		SetIBLTSchemeV2(sch.v2)
		for _, k := range ks {
			cK := ibltTwoCoreThresholdC[k]
			for _, B := range buckets {
				dStar := float64(B) / cK
				for _, beta := range betas {
					d := int(math.Round(dStar / beta))
					if d < 10 || d > 10000 {
						continue // outside the grid's supported difference range
					}
					fails, wrongs := measurePeelMCFailFraction(B, k, d, seeds, workers)
					if results[sch.name] == nil {
						results[sch.name] = map[int]map[int]map[float64]peelMCPoint{}
					}
					if results[sch.name][k] == nil {
						results[sch.name][k] = map[int]map[float64]peelMCPoint{}
					}
					if results[sch.name][k][B] == nil {
						results[sch.name][k][B] = map[float64]peelMCPoint{}
					}
					results[sch.name][k][B][beta] = peelMCPoint{k: k, B: B, d: d, beta: beta, fails: fails, wrongs: wrongs, seeds: seeds}
					t.Logf("%s B=%d k=%d D=%d (beta=%.2f): fail=%d/%d (%.5f) wrong=%d", sch.name, B, k, d, beta, fails, seeds, float64(fails)/float64(seeds), wrongs)
					if wrongs != 0 {
						t.Errorf("%s B=%d k=%d D=%d: peel returned %d keys outside the inserted difference", sch.name, B, k, d, wrongs)
					}
				}
			}
		}
	}

	// v2 uses per-k transition bands. v1 is report-only because its pair-
	// collision floor differs from the 2-core model.
	for _, k := range ks {
		cK := ibltTwoCoreThresholdC[k]
		for _, B := range buckets {
			dStar := float64(B) / cK
			if dStar/0.85 > 10000 {
				// The transition or its beta=0.85 flank lies beyond the D
				// range. Log the omitted crossing checks and retain the
				// in-range margin measurement.
				t.Logf("v2 B=%d k=%d: D*=%.0f puts the crossing or beta=0.85 flank outside the D range; no crossing assertion at this size", B, k, dStar)
			} else {
				hi := pointAt("v2", k, B, 0.85)
				lo := pointAt("v2", k, B, 1.15)
				if hi == nil || lo == nil {
					t.Fatalf("missing grid points at B=%d k=%d for beta=0.85 or 1.15", B, k)
				}
				if frac := float64(hi.fails) / float64(hi.seeds); frac < 0.5 {
					t.Errorf("v2 B=%d k=%d D=%d beta=0.85: failure fraction %.4f; want at least 0.50 on the undersized side", B, k, hi.d, frac)
				}
				if frac := float64(lo.fails) / float64(lo.seeds); frac > 0.05 {
					t.Errorf("v2 B=%d k=%d D=%d beta=1.15: failure fraction %.4f exceeds 0.05; finite tables need more margin than modeled", B, k, lo.d, frac)
				}
				// Find the first ascending beta with failure at or below 1%.
				firstClean := -1.0
				for _, beta := range betas {
					p := pointAt("v2", k, B, beta)
					if p == nil {
						continue
					}
					if float64(p.fails)/float64(p.seeds) <= 0.01 {
						firstClean = beta
						break
					}
				}
				if firstClean < 0 {
					t.Errorf("v2 B=%d k=%d: no grid point through beta=2.0 reached the 1%% failure threshold", B, k)
				} else if firstClean < 1.0 || firstClean > 1.15 {
					t.Errorf("v2 B=%d k=%d: 1%% crossing at beta=%.2f, outside [1.0,1.15]: %s", B, k, firstClean, func() string {
						if firstClean < 1.0 {
							return "failure remains high below the modeled threshold"
						}
						return "the finite-size threshold is higher than modeled"
					}())
				} else {
					t.Logf("v2 B=%d k=%d: 1%% crossing at beta=%.2f within [1.0,1.15]", B, k, firstClean)
				}
			}
			// beta=2.0 is the margin measurement at every bucket count.
			m := pointAt("v2", k, B, 2.0)
			if m == nil {
				t.Fatalf("missing v2 margin point at B=%d k=%d beta=2.0", B, k)
			}
			if m.fails != 0 {
				frac := float64(m.fails) / float64(m.seeds)
				if m.seeds >= 100000 {
					t.Errorf("v2 margin B=%d k=%d D=%d beta=2.0: %d/%d failures (%.6f) exceed the 1e-5 target at this seed count", B, k, m.d, m.fails, m.seeds, frac)
				} else {
					t.Logf("v2 margin B=%d k=%d D=%d beta=2.0: %d/%d failures (%.6f); this seed count cannot resolve the 1e-5 target", B, k, m.d, m.fails, m.seeds, frac)
				}
			} else {
				t.Logf("v2 margin B=%d k=%d D=%d beta=2.0: 0/%d failures; approximate 3/N upper bound %.1e", B, k, m.d, m.seeds, 3.0/float64(m.seeds))
			}
		}
	}
	// v1 is the default; its measured curve is reported without applying the
	// v2 2-core crossing assertions.
	t.Logf("v1(default) curve recorded for comparison with opt-in v2; the D=400/B=1024 floor guard supplies the v1 threshold check")
}

// TestIBLT_PeelMonteCarloSmoke runs a small always-on check. The k=4 margin
// point must peel all 64 trials, while the k=1 single-index control must fail
// at least 20 of 64. This shows that the harness responds to placement
// degeneracy instead of accepting every placement scheme.
func TestIBLT_PeelMonteCarloSmoke(t *testing.T) {
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	// B=128, k=4, D=10 gives beta=9.9 and must peel all 64 trials without
	// returning an unexpected key.
	SetIBLTSchemeV2(true)
	fails, wrongs := measurePeelMCFailFraction(128, 4, 10, 64, 4)
	if fails != 0 || wrongs != 0 {
		t.Fatalf("k=4 margin point: fails=%d wrong=%d among 64 trials at B=128/D=10; want 0/0", fails, wrongs)
	}
	// With k=1 and D=20, the collision model is approximately
	// 1-exp(-D^2/2B)=0.77. At least 20 failures among 64 deterministic trials
	// demonstrates that the check detects collapsed placement.
	f1, w1 := measurePeelMCFailFraction(128, 1, 20, 64, 4)
	if w1 != 0 {
		t.Fatalf("k=1 control returned %d keys outside the inserted difference", w1)
	}
	if f1 < 20 {
		t.Fatalf("k=1 control failed %d/64 trials; want at least 20 to demonstrate sensitivity to collapsed placement", f1)
	}
	SetIBLTSchemeV2(false)
	t.Logf("k=4 margin point: 0/64 failures; k=1 control: %d/64 failures", f1)
}
