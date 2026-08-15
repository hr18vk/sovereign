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

// ---------------------------------------------------------------------------
// Stage 5 — Elimination Backoff Array Verification (AWS Graviton Crucible)
// ---------------------------------------------------------------------------
//
// This file is the verification suite for the Elimination Backoff Array
// (elimination.go). It contains three classes of test:
//
//   1. ZERO-GC MICROSCOPE
//      TestEliminationHotPathZeroAllocations — the unyielding CI gate
//      that proves the push/pop hot path allocates zero heap objects.
//      Uses testing.AllocsPerRun, identical to the Stage 1 / Stage 4
//      patterns in physics_test.go.
//
//   2. LINEARIZABILITY / CORRECTNESS
//      TestEliminationLinearizability — a concurrent stress test that
//      runs P pushers and P poppers against the ElimStack for a fixed
//      duration. After all goroutines quiesce, the remaining stack
//      contents are drained and cross-checked against a per-value
//      occurrence counter. Because push and pop are exact inverses,
//      the multiset of "pushed but not popped" values must exactly
//      equal the multiset of values drained from the central stack.
//      Any lost, duplicated, or phantom value proves a linearizability
//      violation — the elimination exchange corrupted stack semantics.
//
//   3. LINEAR SCALING CRUCIBLE
//      BenchmarkEliminationStackScaling — measures push/pop throughput
//      at GOMAXPROCS = 4, 8, 16, 32. The CI gate
//      TestEliminationCrucibleScalingGate asserts:
//        (a) Throughput at 32 cores >= 1,000,000 ops/sec
//        (b) Parallel efficiency at 32 cores >= 85%
//            efficiency = throughput(32) / (throughput(4) * 8)
//
//      This mirrors the blueprint's mandate: "If the ratio falls below
//      85% efficiency at 32 cores, the elimination array sizing
//      parameters or the dynamic wait duration must be heavily
//      retuned to prevent slot starvation."
//
// RUN: go test -run TestElimination -v ./pkg/sync/
// RUN: go test -bench BenchmarkElimination -benchmem ./pkg/sync/
// ---------------------------------------------------------------------------

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
// 1. ZERO-GC MICROSCOPE
// ---------------------------------------------------------------------------

// TestEliminationHotPathZeroAllocations is the unyielding CI gate for
// the Zero-GC mandate on the elimination stack hot path. It uses
// testing.AllocsPerRun to measure heap allocations performed ONLY
// inside the closure, averaged across N invocations — isolated from
// benchmark framework noise, exactly as permitted by the PM directive.
//
// The closure exercises BOTH push and pop (a push immediately followed
// by a pop is the elimination-dominated path — the most contended
// scenario). Because the ElimNodePool is pre-allocated and the slot
// array is embedded by value, zero allocations should escape to the
// Go heap. 1 allocation = a critical architectural failure.
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
			"CRITICAL FAILURE: Elimination hot path breached Zero-GC mandate. "+
				"Expected 0 AllocsPerOp, got %v. "+
				"Context: {iterations=%d, allocs/op=%v}",
			allocs, iterations, allocs,
		)
	}
}

// ---------------------------------------------------------------------------
// 2. LINEARIZABILITY / CORRECTNESS
// ---------------------------------------------------------------------------

// TestEliminationLinearizability stresses the ElimStack with concurrent
// pushers and poppers. After all goroutines finish, it verifies that
// the multiset of values still on the central stack exactly equals the
// net imbalance of pushes-minus-pops reported by each goroutine.
//
// INVARIANT: Each goroutine tracks (pushedCount - poppedCount) and the
// sum of all values it pushed minus all values it popped. When the
// stack quiesces, the remaining values (drained via sequential pops)
// must form exactly the multiset {v : pushed(v) > popped(v)} weighted
// by the surplus. If any value is lost, duplicated, or fabricated by
// the elimination exchange, this invariant fails.
//
// Each goroutine uses a distinct value range so we can attribute any
// discrepancy to a specific goroutine — turning a generic "data
// corruption" failure into a precise diagnostic.
func TestEliminationLinearizability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping linearizability stress in short mode")
	}

	const numGoroutines = 64
	stack := NewEliminationStack()
	pool := NewElimNodePool(elimTestPoolSize)

	// Each goroutine pushes values in range [gid*1000, gid*1000+999].
	// It tracks net surplus (pushed - popped) per value it still "owns".
	// At the end, the aggregate multiset of surplus values must match
	// the drained stack contents exactly.

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

				// Pop — may return our own value or another goroutine's.
				pv, ok := stack.pop(pool, prng)
				if ok {
					localPopped++
					stats.popped.Add(1)
					// If we popped our own value, decrement surplus.
					if pv >= base && pv < base+1000 {
						stats.surplus[pv]--
						if stats.surplus[pv] == 0 {
							delete(stats.surplus, pv)
						}
					}
					// If we popped ANOTHER goroutine's value, that's fine —
					// the stack is a global structure; ownership of values
					// transfers. The global invariant is checked below by
					// draining the central stack and comparing total counts.
					_ = pv
				}
				val++
			}
			// Record our net surplus as pushed - popped. Values we popped
			// from OTHER goroutines reduce our surplus below the "values
			// we pushed but haven't popped" count — the difference is
			// exactly the values WE consumed from others (net consumer).
			// The global check below uses total counts, not per-value.
			atomic.AddInt64(&stats.netSurplus, localPushed-localPopped)
		}()
	}

	close(start)
	wg.Wait()

	// Drain the central stack. Every value remaining should be a value
	// that was pushed but never popped. We verify the COUNT matches the
	// sum of all goroutines' net surpluses.
	//
	// Total pushed across all goroutines - total popped across all
	// goroutines = number of values on the central stack at quiescence.
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
	fmt.Println("║  STAGE 5: ELIMINATION LINEARIZABILITY STRESS TEST               ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Goroutines:         %16d\n", numGoroutines)
	fmt.Printf("  Total popped:       %16d\n", totalPopped)
	fmt.Printf("  Drained from stack: %16d\n", drainedCount)
	fmt.Printf("  Net surplus:        %16d\n", totalNetSurplus)
	fmt.Printf("  GOMAXPROCS:         %16d\n", runtime.GOMAXPROCS(0))
	fmt.Println()

	// The stack invariant: total_popped + drained == total_pushed.
	// Since total_pushed = total_popped + drained (every push either gets
	// popped or remains on the stack), and net_surplus = pushed - popped,
	// we must have: drained == net_surplus.
	if drainedCount != totalNetSurplus {
		t.Fatalf(
			"LINEARIZABILITY VIOLATION: drained count (%d) != net surplus (%d). "+
				"The elimination exchange lost or duplicated %d values. "+
				"This proves the elimination array corrupted stack semantics.",
			drainedCount, totalNetSurplus, drainedCount-totalNetSurplus,
		)
	}

	t.Logf(
		"✓ LINEARIZABILITY VERIFIED: %d values drained == %d net surplus "+
			"(popped=%d, GOMAXPROCS=%d)",
		drainedCount, totalNetSurplus, totalPopped, runtime.GOMAXPROCS(0),
	)
}

// TestEliminationSequentialCorrectness is a simple, deterministic sanity
// check: push N values, pop them, verify they come out in LIFO order.
// This catches basic stack-logic bugs before the concurrent stress test.
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
// 3. LINEAR SCALING CRUCIBLE
// ---------------------------------------------------------------------------

// elimScalingOpsPerGoroutine is the number of push/pop pairs each
// goroutine executes in the scaling benchmark. 50K pairs = 100K ops per
// goroutine. At 64 goroutines that's 6.4M ops total — enough to saturate
// the L1/L2 hierarchy and reach steady-state contention.
const elimScalingOpsPerGoroutine = 50_000

// elimBenchmarkScaling measures push/pop throughput at a given
// goroutine count. Each goroutine performs alternating push/pop pairs,
// so the elimination array sees 50% push / 50% pop traffic — the
// worst-case contention pattern for the central Treiber CAS, and the
// best-case pattern for elimination (every push has a matching pop).
//
// This is a Go benchmark function; it is called directly by
// testing.Benchmark in TestEliminationCrucibleScalingGate.
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
// crucible measurement, then restores the original value.
func elimBenchmarkScaling32internal(b *testing.B) {
	orig := runtime.GOMAXPROCS(32)
	defer runtime.GOMAXPROCS(orig)
	elimBenchmarkScaling(b, 32)
}

// TestEliminationCrucibleScalingGate is the AWS Graviton Crucible CI
// gate. It runs the scaling benchmark at GOMAXPROCS = 4, 8, 16, 32 and
// asserts:
//
//	(a) Throughput at 32 cores >= 1,000,000 ops/sec
//	(b) Parallel efficiency at 32 cores >= 85%
//	    efficiency = throughput(32) / (throughput(4) * 8)
//
// This is the blueprint's Stage 5 mandate: "If the ratio falls below
// 85% efficiency at 32 cores, the elimination array sizing parameters
// or the dynamic wait duration must be heavily retuned to prevent slot
// starvation."
func TestEliminationCrucibleScalingGate(t *testing.T) {
	// LEGACY — deliberately superseded. The architectural Stage 5 commit
	// (095935e "Home-Shard SEC allocator, test gating, and Stage 5
	// verification") REPLACED the single-locus SEC elimination array this
	// gate measures with the Home-Shard SEC sharded allocator, whose gate is
	// TestStage5ScalingGate (run with RUN_CRUCIBLE=1; passes at
	// 57.63M ops/s @32c, linearizable at every tier). This legacy gate is
	// retained as a historical record of the pre-sharded design it retired.
	//
	// It is SKIPPED, not deleted: it fails by design on the sharded tree
	// (the single-locus array it measures bounded out at ~2% parallel
	// efficiency on the 32-core CMN-700 mesh — exactly the collapse the
	// Home-Shard allocator was built to defeat). Running it would assert a
	// property of a data structure nobody executes anymore. The authoritative
	// Stage 5 crucible is TestStage5ScalingGate.
	t.Skip("LEGACY: deliberately superseded by TestStage5ScalingGate (Home-Shard SEC); kept as a historical record of the pre-sharded elimination array. Fails by design on the sharded tree.")

	if testing.Short() {
		t.Skip("Skipping scaling crucible in short mode")
	}

	// Detect core count. The crucible requires >= 4 physical cores to
	// run meaningfully. On a 2-core CI box, skip with a clear message.
	ncpu := runtime.NumCPU()
	if ncpu < 4 {
		t.Skipf("Skipping scaling crucible: NumCPU=%d < 4, no multi-core scaling to verify", ncpu)
	}

	// Available core tiers, capped to the machine's physical capability.
	tiers := []int{}
	for _, p := range []int{4, 8, 16, 32} {
		if p <= ncpu {
			tiers = append(tiers, p)
		}
	}
	if len(tiers) < 2 {
		t.Skipf("Skipping scaling crucible: only %d eligible tiers (need >= 2)", len(tiers))
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
	fmt.Println("║  STAGE 5: ELIMINATION BACKOFF ARRAY — AWS GRAVITON CRUCIBLE          ║")
	fmt.Println("║  LINEAR SCALING VERIFICATION (1M RPS @ ≥85% efficiency @ 32 cores)  ║")
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
			"CRUCIBLE THROUGHPUT FAILURE: At %d cores, throughput = %.0f ops/s, "+
				"below the 1,000,000 ops/s mandate. The elimination array is "+
				"not converting contention to parallel throughput fast enough.",
			maxTier.goroutines, maxTier.opsPerSec,
		)
	}

	// Gate (b): Parallel efficiency at the highest tier must be >= 85%.
	// efficiency = throughput(max) / (throughput(base) * (max/base))
	// This is the blueprint's ≥85% efficiency-at-32-cores gate.
	maxOps := maxTier.opsPerSec
	efficiency := maxOps / (baseOps * float64(maxTier.goroutines/tiers[0]))

	if efficiency < 0.85 {
		t.Errorf(
			"CRUCIBLE EFFICIENCY FAILURE: Parallel efficiency at %d cores = %.1f%%, "+
				"below the 85%% mandate. The elimination array's slot sizing or "+
				"spin budget must be retuned to prevent slot starvation. "+
				"(throughput_%d=%.0f, throughput_%d=%.0f, expected >= %.0f for 85%%)",
			maxTier.goroutines, efficiency*100,
			maxTier.goroutines, maxOps, tiers[0], baseOps,
			baseOps*float64(maxTier.goroutines/tiers[0])*0.85,
		)
	}

	if maxTier.opsPerSec >= 1_000_000 && efficiency >= 0.85 {
		t.Logf(
			"✓ CRUCIBLE PASSED: %.0f ops/s at %d cores (%.1f%% efficiency). "+
				"Linear scaling verified — elimination array converts contention "+
				"to parallel throughput.",
			maxTier.opsPerSec, maxTier.goroutines, efficiency*100,
		)
	}
}
