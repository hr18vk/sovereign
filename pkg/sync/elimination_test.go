// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// Elimination stack tests cover zero-allocation push/pop operations, LIFO
// order, concurrent value conservation, slot layout, and scaling measurements.
// The scaling gate is superseded by the sharded stack gate and is skipped.

// elimTestPoolSize is 2× the maximum working set so the ElimNodePool
// never exhausts during a test. The elimination array converts push/pop
// pairs into direct exchanges (nodes returned to pool immediately), so
// the high-water mark of live nodes is bounded by the number of pushes
// that have not yet been popped (or eliminated). 2× is generous headroom.
const elimTestPoolSize = 1 << 16 // 65536 nodes

// elimTestDuration is the wall-clock duration of each goroutine's
// work loop in the linearizability stress test. Long enough to exercise
// millions of operations across 64 goroutines; short enough for CI.
const elimTestDuration = 200 * time.Millisecond

// ---------------------------------------------------------------------------
// 1. Zero-GC verification
// ---------------------------------------------------------------------------

// TestEliminationHotPathZeroAllocations measures an alternating push/pop pair
// with testing.AllocsPerRun. The node pool and slot array are preallocated, so
// the measured operation must not allocate on the Go heap.
func TestEliminationHotPathZeroAllocations(t *testing.T) {
	stack := NewEliminationStack()
	pool := NewElimNodePool(elimTestPoolSize)
	prng := &ElimPRNG{}

	// Warm the PRNG so its first next() call (which seeds from the
	// stamp counter) happens outside the measured closure.
	_ = prng.next()

	const iterations = 1000

	allocs := testing.AllocsPerRun(iterations, func() {
		stack.push(pool, prng, 42)
		v, ok := stack.pop(pool, prng)
		if !ok || v != 42 {
			t.Fatalf("elimination push/pop mismatch: got (%d, %v), want (42, true)", v, ok)
		}
	})

	if allocs != 0 {
		t.Fatalf(
			"elimination push/pop allocated %.2f objects per run, want 0. "+
				"Iterations: %d. "+
				"Measured allocs/op: %.2f",
			allocs, iterations, allocs,
		)
	}
}

// ---------------------------------------------------------------------------
// 2. LINEARIZABILITY / CORRECTNESS
// ---------------------------------------------------------------------------

// TestEliminationLinearizability runs concurrent alternating pushes and pops.
// Once they finish, the number of values drained from the stack must equal the
// total push count minus the total successful pop count. A lost or duplicated
// exchange breaks this conservation check.
func TestEliminationLinearizability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping linearizability stress in short mode")
	}

	const numGoroutines = 64
	stack := NewEliminationStack()
	pool := NewElimNodePool(elimTestPoolSize)

	// Each goroutine uses a disjoint value range. Its net surplus is the number
	// of pushes minus all successful pops, including pops of other ranges.

	type goroutineStats struct {
		netSurplus int64          // total pushed - popped
		surplus    map[uint64]int // value -> surplus count
		popped     atomic.Uint64  // total successful pops
	}

	stats := make([]goroutineStats, numGoroutines)
	for i := range stats {
		stats[i].surplus = make(map[uint64]int)
	}

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	start := make(chan struct{})

	for gid := 0; gid < numGoroutines; gid++ {
		gid := gid
		go func() {
			defer wg.Done()
			prng := &ElimPRNG{}
			_ = prng.next() // warm seed

			stats := &stats[gid]
			base := uint64(gid) * 1000
			var val uint64 = base
			var localPushed, localPopped int64

			deadline := time.Now().Add(elimTestDuration)
			for time.Now().Before(deadline) {
				// Push a value in this goroutine's range.
				v := base + (val % 1000)
				stack.push(pool, prng, v)
				localPushed++
				stats.surplus[v]++

				// The pop may return a value from any goroutine.
				pv, ok := stack.pop(pool, prng)
				if ok {
					localPopped++
					stats.popped.Add(1)
					// A pop in this goroutine's range decrements its surplus.
					if pv >= base && pv < base+1000 {
						stats.surplus[pv]--
						if stats.surplus[pv] == 0 {
							delete(stats.surplus, pv)
						}
					}
					// Popping another goroutine's range is valid; the final check
					// compares global counts rather than per-value ownership.
					_ = pv
				}
				val++
			}
			// Net surplus includes all pops, including values from other
			// goroutines. The final check uses these global totals.
			atomic.AddInt64(&stats.netSurplus, localPushed-localPopped)
		}()
	}

	close(start)
	wg.Wait()

	// Drain the central stack after the workers finish. Total pushes minus
	// total successful pops must equal the number drained.
	prng := &ElimPRNG{}
	_ = prng.next()

	var drainedCount int64
	for {
		_, ok := stack.pop(pool, prng)
		if !ok {
			break
		}
		drainedCount++
	}

	// Compute total net surplus across all goroutines.
	var totalNetSurplus int64
	var totalPopped int64
	for i := range stats {
		totalNetSurplus += atomic.LoadInt64(&stats[i].netSurplus)
		totalPopped += int64(stats[i].popped.Load())
	}

	// Total pushed = total popped + drained.
	// This is the fundamental stack invariant.
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Elimination linearizability stress test                         ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Goroutines:         %16d\n", numGoroutines)
	fmt.Printf("  Total popped:       %16d\n", totalPopped)
	fmt.Printf("  Drained from stack: %16d\n", drainedCount)
	fmt.Printf("  Net surplus:        %16d\n", totalNetSurplus)
	fmt.Printf("  GOMAXPROCS:         %16d\n", runtime.GOMAXPROCS(0))
	fmt.Println()

	// Every pushed value was either popped or remains to be drained, so
	// drainedCount must equal totalNetSurplus.
	if drainedCount != totalNetSurplus {
		t.Fatalf(
			"drained count %d != net surplus %d. "+
				"The exchange count differs by %d. "+
				"Check value collection and slot ownership.",
			drainedCount, totalNetSurplus, drainedCount-totalNetSurplus,
		)
	}

	t.Logf(
		"value conservation passed: drained=%d net surplus=%d "+
			"(popped=%d, GOMAXPROCS=%d)",
		drainedCount, totalNetSurplus, totalPopped, runtime.GOMAXPROCS(0),
	)
}

// TestEliminationSequentialCorrectness pushes 1,000 values and checks LIFO
// order, then verifies that the stack is empty.
func TestEliminationSequentialCorrectness(t *testing.T) {
	stack := NewEliminationStack()
	pool := NewElimNodePool(1024)
	prng := &ElimPRNG{}
	_ = prng.next()

	const N uint64 = 1000
	for i := uint64(0); i < N; i++ {
		stack.push(pool, prng, i)
	}

	for i := N - 1; ; i-- {
		v, ok := stack.pop(pool, prng)
		if !ok {
			t.Fatalf("unexpected empty pop at iteration %d", N-1-i)
		}
		if v != i {
			t.Fatalf("LIFO violation: popped %d, expected %d", v, i)
		}
		if i == 0 {
			break
		}
	}

	_, ok := stack.pop(pool, prng)
	if ok {
		t.Fatal("stack not empty after popping all elements")
	}
}

// TestEliminationSlotSize verifies ElimSlot is exactly 128 bytes (two
// cache lines) so adjacent slots never false-share. This is the
// structural precondition for the elimination array's performance.
func TestEliminationSlotSize(t *testing.T) {
	size := unsafe.Sizeof(ElimSlot{})
	if size != 128 {
		t.Fatalf(
			"ElimSlot size = %d bytes, expected 128 (two 64-byte cache lines). "+
				"Incorrect padding will cause false sharing between slots, "+
				"defeating the elimination array's spatial isolation.",
			size,
		)
	}
}

// ---------------------------------------------------------------------------
// 3. Linear scaling verification
// ---------------------------------------------------------------------------

// elimScalingOpsPerGoroutine is the number of push/pop pairs each
// goroutine executes in the scaling benchmark. 50K pairs = 100K ops per
// goroutine. At 64 goroutines that's 6.4M ops total — enough to saturate
// the L1/L2 hierarchy and reach steady-state contention.
const elimScalingOpsPerGoroutine = 50_000

// elimBenchmarkScaling measures alternating push/pop throughput with the
// requested goroutine count. Each worker performs elimScalingOpsPerGoroutine
// pairs for every b.N iteration.
func elimBenchmarkScaling(b *testing.B, goroutines int) {
	stack := NewEliminationStack()
	pool := NewElimNodePool(goroutines*4 + elimTestPoolSize)

	b.ReportAllocs()
	b.ResetTimer()

	// Each b.N iteration spawns `goroutines` workers, each doing
	// elimScalingOpsPerGoroutine push/pop pairs.
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(goroutines)

		for g := 0; g < goroutines; g++ {
			go func(id int) {
				defer wg.Done()
				prng := &ElimPRNG{}
				_ = prng.next()
				base := uint64(id) * 1000

				for j := 0; j < elimScalingOpsPerGoroutine; j++ {
					v := base + uint64(j%1000)
					stack.push(pool, prng, v)
					_, _ = stack.pop(pool, prng)
				}
			}(g)
		}
		wg.Wait()
	}
}

// elimBenchmarkScaling4/8/16/32 are the tiered-core-count benchmarks.
// Each measures throughput at a specific GOMAXPROCS level. The CI gate
// compares them to compute parallel efficiency.

func elimBenchmarkScaling4(b *testing.B)  { elimBenchmarkScaling(b, 4) }
func elimBenchmarkScaling8(b *testing.B)  { elimBenchmarkScaling(b, 8) }
func elimBenchmarkScaling16(b *testing.B) { elimBenchmarkScaling(b, 16) }
func elimBenchmarkScaling32(b *testing.B) { elimBenchmarkScaling32internal(b) }

// elimBenchmarkScaling32internal ramps GOMAXPROCS to 32 for the
// scaling measurement, then restores the original value.
func elimBenchmarkScaling32internal(b *testing.B) {
	orig := runtime.GOMAXPROCS(32)
	defer runtime.GOMAXPROCS(orig)
	elimBenchmarkScaling(b, 32)
}

// TestEliminationCrucibleScalingGate contains the former scaling check for the
// single-locus elimination stack. It measured throughput at 4, 8, 16, and 32
// cores and required at least 1,000,000 ops/s with 85% parallel efficiency.
// The sharded allocator supersedes this design, so the test is skipped.
func TestEliminationCrucibleScalingGate(t *testing.T) {
	// The sharded allocator replaced the single-locus design measured here.
	// TestScalingGate covers the current implementation.
	t.Skip("single-locus scaling check superseded by TestScalingGate")

	if testing.Short() {
		t.Skip("Skipping scaling verification in short mode")
	}

	// Detect core count. The verification requires >= 4 physical cores to
	// run meaningfully. On a 2-core CI box, skip with a clear message.
	ncpu := runtime.NumCPU()
	if ncpu < 4 {
		t.Skipf("Skipping scaling verification: NumCPU=%d < 4, no multi-core scaling to verify", ncpu)
	}

	// Available core tiers, capped to the machine's physical capability.
	tiers := []int{}
	for _, p := range []int{4, 8, 16, 32} {
		if p <= ncpu {
			tiers = append(tiers, p)
		}
	}
	if len(tiers) < 2 {
		t.Skipf("Skipping scaling verification: only %d eligible tiers (need >= 2)", len(tiers))
	}

	type tierResult struct {
		goroutines int
		opsPerSec  float64
	}

	results := make([]tierResult, len(tiers))

	for i, g := range tiers {
		orig := runtime.GOMAXPROCS(g)

		var benchFn func(*testing.B)
		switch g {
		case 4:
			benchFn = elimBenchmarkScaling4
		case 8:
			benchFn = elimBenchmarkScaling8
		case 16:
			benchFn = elimBenchmarkScaling16
		case 32:
			benchFn = elimBenchmarkScaling32
		default:
			benchFn = func(b *testing.B) { elimBenchmarkScaling(b, g) }
		}

		br := testing.Benchmark(benchFn)
		runtime.GOMAXPROCS(orig)

		// Throughput = total ops / wall time. Each b.N spawns `g`
		// goroutines doing elimScalingOpsPerGoroutine push/pop PAIRS
		// = 2 * elimScalingOpsPerGoroutine ops. NsPerOp is per b.N unit
		// (which is one full "spawn all goroutines + wait" cycle).
		opsPerCycle := float64(g) * 2.0 * float64(elimScalingOpsPerGoroutine)
		nsPerCycle := float64(br.NsPerOp())
		opsPerSec := opsPerCycle / (nsPerCycle / 1e9)

		results[i] = tierResult{goroutines: g, opsPerSec: opsPerSec}
	}

	// Print the scaling table.
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Elimination Backoff Array — Graviton scaling verification            ║")
	fmt.Println("║  Linear scaling check (1M ops/s at >=85% efficiency, 32 cores)       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════╝")
	fmt.Printf("  %-12s %18s %18s %12s\n", "GOMAXPROCS", "Throughput (ops/s)", "Speedup vs 4c", "Efficiency")
	fmt.Println("  ────────────────────────────────────────────────────────────────────")

	baseOps := results[0].opsPerSec
	for _, r := range results {
		speedup := r.opsPerSec / baseOps
		efficiency := speedup / float64(r.goroutines/tiers[0])
		fmt.Printf("  %-12d %18.0f %18.2fx %11.1f%%\n",
			r.goroutines, r.opsPerSec, speedup, efficiency*100)
	}
	fmt.Printf("  NumCPU: %d, GOMAXPROCS at test entry: %d\n",
		ncpu, runtime.GOMAXPROCS(0))
	fmt.Println()

	// Gate (a): At the highest tier, throughput must be >= 1,000,000 ops/sec.
	maxTier := results[len(results)-1]
	if maxTier.opsPerSec < 1_000_000 {
		t.Errorf(
			"throughput at %d cores = %.0f ops/s. "+
				"The minimum is 1,000,000 ops/s. "+
				"Check elimination contention behavior.",
			maxTier.goroutines, maxTier.opsPerSec,
		)
	}

	// Gate (b): Parallel efficiency at the highest tier must be >= 85%.
	// efficiency = throughput(max) / (throughput(base) * (max/base))
	// This is the architecture's ≥85% efficiency-at-32-cores gate.
	maxOps := maxTier.opsPerSec
	efficiency := maxOps / (baseOps * float64(maxTier.goroutines/tiers[0]))

	if efficiency < 0.85 {
		t.Errorf(
			"parallel efficiency at %d cores = %.1f%%, want at least 85%%. "+
				"Check the slot sizing and spin budget. "+
				"(throughput_%d=%.0f, throughput_%d=%.0f, "+
				"expected >= %.0f)",
			maxTier.goroutines, efficiency*100,
			maxTier.goroutines, maxOps, tiers[0], baseOps,
			baseOps*float64(maxTier.goroutines/tiers[0])*0.85,
		)
	}

	if maxTier.opsPerSec >= 1_000_000 && efficiency >= 0.85 {
		t.Logf(
			"scaling passed: %.0f ops/s at %d cores "+
				"(%.1f%% efficiency). "+
				"The legacy threshold was met.",
			maxTier.opsPerSec, maxTier.goroutines, efficiency*100,
		)
	}
}
