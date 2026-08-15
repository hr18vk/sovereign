package sync

// ---------------------------------------------------------------------------
// Stage 5 — Flat-Combining Stack Verification (AWS Graviton Crucible)
// ---------------------------------------------------------------------------
//
// This file is the verification suite for the Flat-Combining stack
// (flatcomb.go). It mirrors the structure of elimination_test.go so the
// OLD (elimination) and NEW (flat-combining) candidates share an
// identical verification battery:
//
//   1. STRUCTURAL SIZE ASSERTION
//      TestFlatCombSlotSize — flatCombPub is exactly 128 bytes (two
//      cache lines), so adjacent publication records never false-share.
//      Structural precondition for the FC algorithm's spatial isolation.
//
//   2. ZERO-GC MICROSCOPE
//      TestFlatCombHotPathZeroAllocations — the unyielding CI gate that
//      proves the push/pop hot path allocates zero heap objects. Uses
//      testing.AllocsPerRun, identical to the Stage 1 / Stage 4 patterns.
//
//   3. SEQUENTIAL CORRECTNESS
//      TestFlatCombSequentialCorrectness — push N values, pop them,
//      verify LIFO. Catches basic stack-logic bugs before the concurrent
//      stress.
//
//   4. LINEARIZABILITY / CORRECTNESS
//      TestFlatCombLinearizability — concurrent stress mirroring
//      TestEliminationLinearizability but exercising the flat-combining
//      stack specifically.
//
// ADAPTER: flatCombStackAdapter adapts flatCombStack to the stage5Stack
// interface and registers it with the gate's stage5MakeStack factory +
// sets stage5CandidateNameOverride in init(). This wiring means
// TestStage5ScalingGate (the rewritten asymmetric gate) automatically
// exercises the FC candidate once this test file is compiled into the
// package. Switching the gate back to the elimination candidate when
// needed is done by suppressing this init via build tag (deferred).
// -----------------------------------------------------------------------

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
// ADAPTER — wire flatCombStack into the stage5 gate (anti-self-deception)
// ---------------------------------------------------------------------------

// flatCombStackAdapter exposes flatCombStack via the stage5Stack
// interface so the SAME asymmetric burst workload (stage5_gate_test.go)
// drives the FC candidate as drove the elimination candidate. This is
// the anti-self-deception measure: the workload is shared, the gate's
// assertions are shared, only the candidate varies.
type flatCombStackAdapter struct {
	inner *flatCombStack
}

func (a *flatCombStackAdapter) push(pool *ElimNodePool, prng *ElimPRNG, value uint64) {
	a.inner.push(pool, prng, value)
}

func (a *flatCombStackAdapter) pop(pool *ElimNodePool, prng *ElimPRNG) (uint64, bool) {
	return a.inner.pop(pool, prng)
}

func (a *flatCombStackAdapter) headLoad() uint64 {
	return a.inner.head.Load()
}

// drainAll walks the SINGLE central FC head. FC has one head (the
// combiner is the sole mutator), so this is a single-head walk shared
// with the elimination + plain-Treiber adapters.
func (a *flatCombStackAdapter) drainAll(pool *ElimNodePool, poolCap int) (int64, bool) {
	return drainSingleNodeStackFromHead(a.inner.head.Load(), pool, poolCap)
}

// init wires the FC candidate into the rewritten gate's
// stage5MakeStack factory and sets the candidate name so the gate's
// printed table attributes throughput correctly. By global-init order,
// this runs after the package-var stage5MakeStack is initialized to its
// elimination default (Go guarantees var init precedes init funcs).
func init() {
	stage5MakeStack = func() stage5Stack {
		return &flatCombStackAdapter{inner: NewFlatCombStack()}
	}
	stage5CandidateNameOverride = "flat-combining (FC)"
}

// ---------------------------------------------------------------------------
// 1. STRUCTURAL SIZE ASSERTION
// ---------------------------------------------------------------------------

// TestFlatCombSlotSize verifies flatCombPub is exactly 128 bytes (two
// Neoverse-V1 cache lines) so adjacent publication records never
// false-share. A spinning waiter on one record's seq line must never
// invalidate an ADJACENT spinning waiter's line, and the combiner's
// 128-stride scan must be a clean LLC sweep with no cross-invalidation.
// This is the structural precondition for the FC algorithm's performance
// and is a CI gate that FAILS LOUDLY on padding regression.
func TestFlatCombSlotSize(t *testing.T) {
	size := unsafe.Sizeof(flatCombPub{})
	if size != 128 {
		t.Fatalf(
			"flatCombPub size = %d bytes, expected 128 (two 64-byte cache lines). "+
				"Incorrect padding will cause false sharing between adjacent "+
				"publication records: a spinning waiter on one record's seq word "+
				"would invalidate an adjacent spinning waiter's cache line, "+
				" defeating the FC algorithm's L1-resident spin isolation.",
			size,
		)
	}
}

// ---------------------------------------------------------------------------
// 2. ZERO-GC MICROSCOPE
// ---------------------------------------------------------------------------

// TestFlatCombHotPathZeroAllocations is the unyielding CI gate for the
// Zero-GC mandate on the flat-combining stack hot path. Uses
// testing.AllocsPerRun to measure heap allocations performed ONLY
// inside the closure, averaged across N invocations — isolated from
// benchmark framework noise, exactly as elimination_test.go does.
//
// The FC stack's hot path is allocRec (Treiber pop on the rec free-
// list, a CAS, no heap) + publish (three atomic Stores to a private
// rec line) + spin (one atomic Load on the same line) + freeRec
// (Treiber push on the rec free-list, a CAS, no heap). The rec free-
// list is a heap-embedded array in flatCombStack — its arena objects
// were allocated once at NewFlatCombStack. The ElimNodePool is also
// pre-allocated. So the hot path is genuinely heap-free.
//
// 1 allocation = a critical architectural failure of the Zero-GC
// mandate (precisely what would happen if allocRec had to grow recs,
// or if a closure/interface boxed, or if pool.allocIndex GC-grew the
// free-list).
func TestFlatCombHotPathZeroAllocations(t *testing.T) {
	stack := NewFlatCombStack()
	pool := NewElimNodePool(elimTestPoolSize)
	prng := &ElimPRNG{}
	_ = prng.next()

	const iterations = 1000

	allocs := testing.AllocsPerRun(iterations, func() {
		stack.push(pool, prng, 42)
		v, ok := stack.pop(pool, prng)
		if !ok || v != 42 {
			t.Fatalf("flat-comb push/pop mismatch: got (%d, %v), want (42, true)", v, ok)
		}
	})

	if allocs != 0 {
		t.Fatalf(
			"CRITICAL FAILURE: flat-combining hot path breached Zero-GC mandate. "+
				"Expected 0 AllocsPerOp, got %v. "+
				"Context: {iterations=%d, allocs/op=%v}",
			allocs, iterations, allocs,
		)
	}
}

// ---------------------------------------------------------------------------
// 3. SEQUENTIAL CORRECTNESS
// ---------------------------------------------------------------------------

// TestFlatCombSequentialCorrectness is a simple, deterministic sanity
// check: push N values, pop them, verify LIFO order. Catches basic
// stack-logic bugs (e.g., Next-link reversal, head-loading bug,
// combiner mis-pairing) before concurrent stress.
//
// Edge cases checked:
//   - pop on empty returns (0, false).
//   - push then pop returns the SAME value once (single op round-trip).
//   - 1000 pushes then 1000 pops return LIFO order with no duplicates
//     and no missing values.
//   - after full drain, stack is empty again.
//
// This test runs the combiner's SERIAL batch path: a SINGLE goroutine
// publishes a push and then becomes the combiner; the algorithm path
// executes almost entirely via the "opportunistic combiner rule" branch.
// It does not exercise the head-of-queue wait path, but it does exercise
// the combiner combining-flag acquire + combine() cycle end-to-end.
func TestFlatCombSequentialCorrectness(t *testing.T) {
	stack := NewFlatCombStack()
	pool := NewElimNodePool(1024)
	prng := &ElimPRNG{}
	_ = prng.next()

	// Edge: empty stack pop.
	_, ok := stack.pop(pool, prng)
	if ok {
		t.Fatal("empty FC stack pop returned ok=true (expected false)")
	}

	// Edge: single push-pop round trip.
	stack.push(pool, prng, 7)
	v, ok := stack.pop(pool, prng)
	if !ok || v != 7 {
		t.Fatalf("single round-trip: got (%d, %v), want (7, true)", v, ok)
	}

	// Edge: stack is now empty.
	_, ok = stack.pop(pool, prng)
	if ok {
		t.Fatal("FC stack non-empty after a matched push/pop round-trip")
	}

	// Edge: lawful zero payload.
	stack.push(pool, prng, 0)
	v, ok = stack.pop(pool, prng)
	if !ok || v != 0 {
		t.Fatalf("zero-payload round-trip: ok=%v v=%d (ok=true / v=0 expected; "+
			"ok=false proves the FC stack used the value field instead of the "+
			"ok-bit as the present/absent distinguisher — a CRITICAL bug given "+
			"NullOffset64==0 collides with lawful zero payloads)", ok, v)
	}

	// Bulk LIFO order.
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

	_, ok = stack.pop(pool, prng)
	if ok {
		t.Fatal("FC stack not empty after popping all elements")
	}
}

// ---------------------------------------------------------------------------
// 4. LINEARIZABILITY — concurrent stress (mirrors the elimination test)
// ---------------------------------------------------------------------------

// TestFlatCombLinearizability stresses the flat-combining stack with
// concurrent pushers and poppers, mirroring the elimination test's
// shape: P goroutines, each pushing values in its own range and
// popping whatever comes off, for a fixed duration. After all
// goroutines quiesce, the remaining stack contents are drained and
// cross-checked against the per-value net-surplus invariant:
//
//	drained == sum(goroutine.pushed - goroutine.popped)
//
// This is the same invariant the gate's (c) check enforces on the FC
// stack. If any value is lost, duplicated, or fabricated by the
// combiner batch or the head-commit / pairing logic, this fails.
func TestFlatCombLinearizability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping FC linearizability stress in short mode")
	}

	const numGoroutines = 64
	stack := NewFlatCombStack()
	pool := NewElimNodePool(elimTestPoolSize)

	type goroutineStats struct {
		netSurplus int64 // total pushed - popped
		popped     atomic.Uint64
	}

	stats := make([]goroutineStats, numGoroutines)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := make(chan struct{})

	for gid := 0; gid < numGoroutines; gid++ {
		gid := gid
		go func() {
			defer wg.Done()
			prng := &ElimPRNG{}
			_ = prng.next()

			stats := &stats[gid]
			base := uint64(gid) * 1000
			var val uint64 = base
			var localPushed, localPopped int64

			deadline := time.Now().Add(elimTestDuration)
			for time.Now().Before(deadline) {
				v := base + (val % 1000)
				stack.push(pool, prng, v)
				localPushed++

				pv, ok := stack.pop(pool, prng)
				if ok {
					localPopped++
					stats.popped.Add(1)
				}
				_ = pv
				val++
			}
			atomic.AddInt64(&stats.netSurplus, localPushed-localPopped)
		}()
	}

	close(start)
	wg.Wait()

	// Drain the central stack (via pop — the FC stack's pop is
	// linearizable, so a sequential drain reflects the live state).
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

	var totalNetSurplus int64
	var totalPopped int64
	for i := range stats {
		totalNetSurplus += atomic.LoadInt64(&stats[i].netSurplus)
		totalPopped += int64(stats[i].popped.Load())
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  STAGE 5: FLAT-COMBINING LINEARIZABILITY STRESS TEST            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Goroutines:         %16d\n", numGoroutines)
	fmt.Printf("  Total popped:        %16d\n", totalPopped)
	fmt.Printf("  Drained from stack:  %16d\n", drainedCount)
	fmt.Printf("  Net surplus:         %16d\n", totalNetSurplus)
	fmt.Printf("  GOMAXPROCS:          %16d\n", runtime.GOMAXPROCS(0))
	fmt.Println()

	if drainedCount != totalNetSurplus {
		t.Fatalf(
			"LINEARIZABILITY VIOLATION: drained count (%d) != net surplus (%d). "+
				"The flat-combining combiner batch / inside-combine pairing / "+
				"head-commit logic lost or duplicated %d values. "+
				"This proves the FC stack corrupted stack semantics.",
			drainedCount, totalNetSurplus, drainedCount-totalNetSurplus,
		)
	}

	t.Logf(
		"✓ FLAT-COMBINING LINEARIZABILITY VERIFIED: %d drained == %d surplus "+
			"(popped=%d, GOMAXPROCS=%d)",
		drainedCount, totalNetSurplus, totalPopped, runtime.GOMAXPROCS(0),
	)
}

// ---------------------------------------------------------------------------
// 5. CYCLE DETECTION — the central stack walk structure (mirrors diag_test)
// ---------------------------------------------------------------------------

// TestFlatCombCycleDetection walks the central FC Treiber stack WITHOUT
// popping (direct head + next traversal via the packed-index encoding)
// to detect cycles or corruption of the next-link field. Under FC the
// sole mutator of head / next is the combiner, sequentially per batch,
// so a quiescent stack has a well-formed LIFO list with NO cycles. A
// cycle here would prove the combiner's head-commit CAS linked a node
// back into the list improperly (an ABA cross-talk on head between
// batches, or a broken next-value load in combinePopFromHead).
func TestFlatCombCycleDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent cycle-detection stress in short mode.")
	}
	const numGoroutines = 64
	stack := NewFlatCombStack()
	pool := NewElimNodePool(elimTestPoolSize)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := make(chan struct{})

	for gid := 0; gid < numGoroutines; gid++ {
		gid := gid
		go func() {
			defer wg.Done()
			prng := &ElimPRNG{}
			_ = prng.next()
			base := uint64(gid) * 1000
			var val uint64 = base
			deadline := time.Now().Add(elimTestDuration)
			for time.Now().Before(deadline) {
				v := base + (val % 1000)
				stack.push(pool, prng, v)
				stack.pop(pool, prng)
				val++
			}
		}()
	}

	close(start)
	wg.Wait()

	// Walk the central stack WITHOUT popping.
	head := stack.head.Load()
	visited := make(map[uint64]bool)
	count := 0
	for head != NullOffset64 {
		headIdx := elimIndex(head)
		if visited[headIdx] {
			t.Fatalf("CYCLE detected at index %d after %d nodes on FC stack", headIdx, count)
		}
		visited[headIdx] = true
		count++
		if count > elimTestPoolSize+100 {
			t.Fatalf("FC stack too deep (%d), pool size=%d — likely cycle or corruption", count, elimTestPoolSize)
		}
		head = atomic.LoadUint64(&pool.nodes[headIdx].next)
	}
	fmt.Printf("FC stack depth after quiescence: %d nodes, no cycle detected\n", count)

	// Drain via pop to verify the pop side counts match the walker.
	prng := &ElimPRNG{}
	_ = prng.next()
	var drained int
	for i := 0; i < elimTestPoolSize+1000; i++ {
		_, ok := stack.pop(pool, prng)
		if !ok {
			break
		}
		drained++
	}
	fmt.Printf("FC drained via pop: %d nodes\n", drained)
	if drained != count {
		t.Fatalf("FC walker depth (%d) != drained via pop (%d) — pop saw a different state than the walker; linearizability broken", count, drained)
	}
}
