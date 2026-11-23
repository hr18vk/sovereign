// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// The flat-combining tests cover record layout, allocation-free push and pop,
// sequential LIFO behavior, concurrent conservation of values and cycle
// detection. The adapter selects this implementation for the shared scaling
// gate, so it runs the same workload as the elimination stack.

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// flatCombStackAdapter exposes flatCombStack through the scaling gate's stack
// interface. The workload and assertions are shared with the other stack
// implementations.
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

// drainAll walks the single central head using the same helper as the
// elimination and plain Treiber adapters.
func (a *flatCombStackAdapter) drainAll(pool *ElimNodePool, poolCap int) (int64, bool) {
	return drainSingleNodeStackFromHead(a.inner.head.Load(), pool, poolCap)
}

// init selects flat combining for the scaling gate. Package variable
// initialization completes first, so this replaces the elimination default.
func init() {
	makeGateStack = func() gateStack {
		return &flatCombStackAdapter{inner: NewFlatCombStack()}
	}
	gateCandidateNameOverride = "flat-combining (FC)"
}

// ---------------------------------------------------------------------------
// 1. Structural size assertion
// ---------------------------------------------------------------------------

// TestFlatCombSlotSize checks that each publication record occupies two
// 64-byte cache lines. This padding keeps adjacent spinning waiters from
// invalidating one another's sequence lines.
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
// 2. Zero-GC verification
// ---------------------------------------------------------------------------

// TestFlatCombHotPathZeroAllocations measures a push/pop pair with
// testing.AllocsPerRun. Publication records and the node pool are allocated up
// front, so acquiring, publishing, acknowledging and releasing a request must
// not add a heap allocation.
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
			"flat-combining push/pop allocated %v objects per run; want 0. "+
				"Iterations: %d. "+
				"Allocations per run: %v",
			allocs, iterations, allocs,
		)
	}
}

// ---------------------------------------------------------------------------
// 3. Sequential correctness
// ---------------------------------------------------------------------------

// TestFlatCombSequentialCorrectness checks empty pops, a zero payload and
// LIFO order over 1,000 values. One goroutine publishes and combines each
// request, exercising the opportunistic combiner path without a contested
// waiter.
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
		t.Fatalf("zero-payload round trip returned ok=%v, value=%d; want true, 0; "+
			"the result must distinguish a stored zero from an empty stack using "+
			"the ok bit rather than the value, since NullOffset64 is also zero; "+
			"ok=false would lose that distinction", ok, v)
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
// 4. Linearizability — concurrent stress (mirrors the elimination test)
// ---------------------------------------------------------------------------

// TestFlatCombLinearizability runs concurrent producers and consumers for a
// fixed duration. After they finish, draining the stack must account for every
// operation:
//
//	drained == sum(goroutine.pushed - goroutine.popped)
//
// A mismatch means the combiner, pairing logic or central-head commits lost
// or duplicated values.
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
	fmt.Println("║  Flat-combining linearizability stress test                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Goroutines:         %16d\n", numGoroutines)
	fmt.Printf("  Total popped:        %16d\n", totalPopped)
	fmt.Printf("  Drained from stack:  %16d\n", drainedCount)
	fmt.Printf("  Net surplus:         %16d\n", totalNetSurplus)
	fmt.Printf("  GOMAXPROCS:          %16d\n", runtime.GOMAXPROCS(0))
	fmt.Println()

	if drainedCount != totalNetSurplus {
		t.Fatalf(
			"flat-combining conservation mismatch: drained count %d != net surplus %d; "+
				"the combiner batch, local pairing or central-head commits changed "+
				"the value count by %d; "+
				"check for lost or duplicated values",
			drainedCount, totalNetSurplus, drainedCount-totalNetSurplus,
		)
	}

	t.Logf(
		"flat-combining conservation verified: %d drained == %d surplus "+
			"(popped=%d, GOMAXPROCS=%d)",
		drainedCount, totalNetSurplus, totalPopped, runtime.GOMAXPROCS(0),
	)
}

// ---------------------------------------------------------------------------
// 5. Cycle detection — the central stack walk structure (mirrors diag_test)
// ---------------------------------------------------------------------------

// TestFlatCombCycleDetection follows packed next links without popping after
// concurrent use. A repeated index or excessive depth indicates a corrupt
// central list. The subsequent pop drain must visit the same number of nodes
// as the walk.
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

	// Walk the central stack without popping.
	head := stack.head.Load()
	visited := make(map[uint64]bool)
	count := 0
	for head != NullOffset64 {
		headIdx := elimIndex(head)
		if visited[headIdx] {
			t.Fatalf("cycle detected at index %d after %d nodes on FC stack", headIdx, count)
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
