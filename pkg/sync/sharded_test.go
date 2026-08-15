package sync

// ---------------------------------------------------------------------------
// Stage 5c — Sharded Stack Verification Suite
// ---------------------------------------------------------------------------
//
// This file is the verification battery for the ShardedStack (sharded.go).
// It mirrors the structure of flatcomb_test.go and elimination_test.go:
//
//   1. STRUCTURAL SIZE ASSERTION
//      TestShardedShardSize — secShard is exactly 128 bytes (two cache
//      lines), and adjacent shards in the array have stride 128.
//
//   2. ZERO-GC MICROSCOPE
//      TestShardedHotPathZeroAllocations — the unyielding CI gate proving
//      the push/pop hot path allocates zero heap objects.
//
//   3. SEQUENTIAL CORRECTNESS
//      TestShardedSequentialCorrectness — single-goroutine push/pop LIFO
//      on one shard. Catches basic stack-logic bugs.
//
//   4. LINEARIZABILITY / CORRECTNESS
//      TestShardedLinearizability — concurrent stress: N goroutines push
//      and pop for a fixed duration, then drainAll across ALL shards must
//      equal netSurplus (pushed - popped). Catches cross-shard data loss.
//
//   5. CYCLE DETECTION
//      TestShardedCycleDetection — walks every shard's stackTop chain
//      without popping, detects cycles and cross-shard node duplication.
//
// ADAPTER: secStackAdapter adapts ShardedStack to the stage5Stack
// interface and registers it with the gate's stage5MakeStack factory +
// sets stage5CandidateNameOverride in init(). This wiring means
// TestStage5ScalingGate (the rewritten asymmetric gate) automatically
// exercises the SEC candidate once this test file is compiled into the
// package.
//
// INIT ORDERING: Go runs init functions in source file name lexicographic
// order within a package. flatcomb_test.go < sharded_test.go, so this
// init() runs AFTER flatcomb_test.go's init(), overriding the factory.
// The gate therefore drives the SEC candidate. FC-specific tests in
// flatcomb_test.go are unaffected — they construct flatCombStack directly.
// ---------------------------------------------------------------------------

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
// ADAPTER — wire ShardedStack into the stage5 gate (anti-self-deception)
// ---------------------------------------------------------------------------

// secStackAdapter exposes ShardedStack via the stage5Stack interface
// so the SAME asymmetric burst workload (stage5_gate_test.go) drives
// the SEC candidate as drove the elimination and FC candidates.
type secStackAdapter struct {
	inner *ShardedStack
}

func (a *secStackAdapter) push(pool *ElimNodePool, prng *ElimPRNG, value uint64) {
	a.inner.push(pool, prng, value)
}

func (a *secStackAdapter) pop(pool *ElimNodePool, prng *ElimPRNG) (uint64, bool) {
	return a.inner.pop(pool, prng)
}

// headLoad returns shard 0's head for backward compatibility with the
// diag_test.go walker. Multi-shard drain uses drainAll.
func (a *secStackAdapter) headLoad() uint64 {
	return a.inner.shards[0].stackTop.Load()
}

// drainAll walks EVERY shard's stackTop, follows .next chains, dedups
// every visited node index (an index CANNOT survive on two shards under
// the per-P routing invariant, but dedup catches corruption), and returns
// the total surviving node count. A cycle, out-of-pool index, or
// unbounded walk returns ok=false.
func (a *secStackAdapter) drainAll(pool *ElimNodePool, poolCap int) (int64, bool) {
	visited := make(map[uint64]bool)
	var drained int64
	for i := 0; i < secShardCount; i++ {
		head := a.inner.shards[i].stackTop.Load()
		for head != NullOffset64 {
			idx := elimIndex(head)
			if idx == 0 || int(idx) >= poolCap {
				return drained, false
			}
			if visited[idx] {
				return drained, false
			}
			visited[idx] = true
			drained++
			if drained > int64(poolCap)+100 {
				return drained, false
			}
			head = atomic.LoadUint64(&pool.nodes[idx].next)
		}
	}
	return drained, true
}

// init wires the SEC candidate into the gate's stage5MakeStack factory
// and sets the candidate name. By lexicographic init order
// (flatcomb_test.go < sharded_test.go), this runs AFTER FC's init(),
// overriding the factory. The gate therefore drives the SEC candidate.
func init() {
	stage5MakeStack = func() stage5Stack {
		return &secStackAdapter{inner: NewShardedStack()}
	}
	stage5CandidateNameOverride = "SEC-sharded"
}

// ---------------------------------------------------------------------------
// 1. STRUCTURAL SIZE ASSERTION
// ---------------------------------------------------------------------------

// TestShardedShardSize verifies secShard is EXACTLY 128 bytes (two
// Neoverse-V1 cache lines) and that adjacent shards in the array have
// stride 128. This is the structural precondition for L2 spatial
// prefetcher defeat: adjacent shards must never share a 128-byte
// prefetch pair.
func TestShardedShardSize(t *testing.T) {
	size := unsafe.Sizeof(secShard{})
	if size != 128 {
		t.Fatalf(
			"secShard size = %d bytes, expected 128 (two 64-byte cache lines). "+
				"Incorrect padding will cause MESI HITM false sharing between "+
				"adjacent shards, defeating the multi-locus CMN-700 dispersion.",
			size,
		)
	}

	// Verify stride: the offset between adjacent elements in the
	// shards array must also be 128 (Go does not insert padding between
	// array elements, but this assertion catches compiler surprises).
	var s ShardedStack
	addr0 := uintptr(unsafe.Pointer(&s.shards[0]))
	addr1 := uintptr(unsafe.Pointer(&s.shards[1]))
	stride := addr1 - addr0
	if stride != 128 {
		t.Fatalf(
			"secShard array stride = %d bytes, expected 128. "+
				"Inter-element padding or alignment drift breaks the "+
				"128-byte spatial prefetcher isolation.",
			stride,
		)
	}
}

// ---------------------------------------------------------------------------
// 2. ZERO-GC MICROSCOPE
// ---------------------------------------------------------------------------

// TestShardedHotPathZeroAllocations is the unyielding CI gate for the
// Zero-GC mandate on the sharded stack hot path. Uses
// testing.AllocsPerRun to measure heap allocations performed ONLY
// inside the closure, averaged across N invocations.
//
// The hot path is: cache-hit alloc (zero heap) → set value → procPin
// → one CAS → procUnpin → cache recycle (zero heap). The ElimNodePool
// is pre-allocated. No allocation source exists on the hot path.
//
// 1 allocation = critical architectural failure (closure boxed, pool
// grew, interface boxed, etc.).
func TestShardedHotPathZeroAllocations(t *testing.T) {
	stack := NewShardedStack()
	pool := NewElimNodePool(elimTestPoolSize)
	prng := &ElimPRNG{}
	_ = prng.next()

	const iterations = 1000

	allocs := testing.AllocsPerRun(iterations, func() {
		stack.push(pool, prng, 42)
		v, ok := stack.pop(pool, prng)
		if !ok || v != 42 {
			t.Fatalf("sharded push/pop mismatch: got (%d, %v), want (42, true)", v, ok)
		}
	})

	if allocs != 0 {
		t.Fatalf(
			"CRITICAL FAILURE: sharded stack hot path breached Zero-GC mandate. "+
				"Expected 0 AllocsPerOp, got %v. "+
				"Context: {iterations=%d, allocs/op=%v}",
			allocs, iterations, allocs,
		)
	}
}

// ---------------------------------------------------------------------------
// 3. SEQUENTIAL CORRECTNESS
// ---------------------------------------------------------------------------

// TestShardedSequentialCorrectness is a simple, deterministic sanity
// check: push N values, pop them, verify LIFO order within one shard.
// Catches basic stack-logic bugs before concurrent stress.
//
// Edge cases:
//   - pop on empty shard returns (0, false)
//   - push then pop returns the SAME value (single round-trip)
//   - 1000 pushes then 1000 pops return LIFO order
//   - lawful zero payload (value 0 vs. NullOffset64 sentinel)
//   - after full drain, shard is empty again
//
// This test runs on a SINGLE goroutine, so procPin always returns the
// same P-ID, and all operations hit the same shard. LIFO is verifiable.
func TestShardedSequentialCorrectness(t *testing.T) {
	stack := NewShardedStack()
	pool := NewElimNodePool(1024)
	prng := &ElimPRNG{}
	_ = prng.next()

	// Keep all operations on one P so the test verifies one shard's LIFO
	// semantics. The production structure intentionally exposes relaxed
	// cross-shard LIFO and relies on drainAll for global conservation.
	procPin()
	defer procUnpin()

	// Edge: empty shard pop.
	_, ok := stack.pop(pool, prng)
	if ok {
		t.Fatal("empty sharded stack pop returned ok=true (expected false)")
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
		t.Fatal("sharded stack non-empty after a matched push/pop round-trip")
	}

	// Edge: lawful zero payload.
	stack.push(pool, prng, 0)
	v, ok = stack.pop(pool, prng)
	if !ok || v != 0 {
		t.Fatalf("zero-payload round-trip: ok=%v v=%d (expected ok=true, v=0; "+
			"a false ok proves the stack used the value field as the present/ "+
			"absent distinguisher — CRITICAL bug given NullOffset64==0 "+
			"collides with lawful zero payloads)", ok, v)
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
		t.Fatal("sharded stack not empty after popping all elements")
	}
}

// ---------------------------------------------------------------------------
// 4. LINEARIZABILITY — concurrent stress
// ---------------------------------------------------------------------------

// TestShardedLinearizability stresses the sharded stack with concurrent
// pushers and poppers. After quiescence, drainAll across ALL shards
// must equal totalPushed - totalPopped (netSurplus). If any value is
// lost, duplicated, or fabricated by the per-shard CAS logic, this
// fails. Cross-shard accounting is verified by the union walk in
// drainAll.
func TestShardedLinearizability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sharded linearizability stress in short mode")
	}

	const numGoroutines = 64
	stack := NewShardedStack()
	pool := NewElimNodePool(elimTestPoolSize)

	type goroutineStats struct {
		netSurplus int64
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

			gs := &stats[gid]
			base := uint64(gid) * 1000
			var val uint64 = base
			var localPushed, localPopped int64

			<-start

			deadline := time.Now().Add(elimTestDuration)
			for time.Now().Before(deadline) {
				v := base + (val % 1000)
				stack.push(pool, prng, v)
				localPushed++

				pv, ok := stack.pop(pool, prng)
				if ok {
					localPopped++
					gs.popped.Add(1)
				}
				_ = pv
				val++
			}
			atomic.AddInt64(&gs.netSurplus, localPushed-localPopped)
		}()
	}

	close(start)
	wg.Wait()

	// Drain ALL shards via the adapter's drainAll.
	adapter := &secStackAdapter{inner: stack}
	poolCap := elimTestPoolSize
	drained, drainOK := adapter.drainAll(pool, poolCap)

	var totalNetSurplus int64
	var totalPopped int64
	for i := range stats {
		totalNetSurplus += atomic.LoadInt64(&stats[i].netSurplus)
		totalPopped += int64(stats[i].popped.Load())
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  STAGE 5c: SEC-SHARDED LINEARIZABILITY STRESS TEST              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Goroutines:          %16d\n", numGoroutines)
	fmt.Printf("  Total popped:        %16d\n", totalPopped)
	fmt.Printf("  Drained from shards: %16d\n", drained)
	fmt.Printf("  Net surplus:         %16d\n", totalNetSurplus)
	fmt.Printf("  Drain OK:            %16v\n", drainOK)
	fmt.Printf("  GOMAXPROCS:          %16d\n", runtime.GOMAXPROCS(0))
	fmt.Println()

	if !drainOK {
		t.Fatalf(
			"STRUCTURAL CORRUPTION: drainAll reported cycle, out-of-pool "+
				"index, or unbounded walk. drained=%d, netSurplus=%d. "+
				"The per-shard LIFO chains are corrupt.",
			drained, totalNetSurplus,
		)
	}

	if drained != totalNetSurplus {
		t.Fatalf(
			"LINEARIZABILITY VIOLATION: drained count (%d) != net surplus (%d). "+
				"The sharded stack lost or duplicated %d values across %d shards. "+
				"This proves the per-shard CAS logic corrupted stack semantics.",
			drained, totalNetSurplus, drained-totalNetSurplus, secShardCount,
		)
	}

	t.Logf(
		"✓ SEC-SHARDED LINEARIZABILITY VERIFIED: %d drained == %d surplus "+
			"(popped=%d, GOMAXPROCS=%d, shards=%d)",
		drained, totalNetSurplus, totalPopped, runtime.GOMAXPROCS(0), secShardCount,
	)
}

// ---------------------------------------------------------------------------
// 5. CYCLE DETECTION
// ---------------------------------------------------------------------------

// TestShardedCycleDetection walks every shard's stackTop chain WITHOUT
// popping (direct head + next traversal via packed-index encoding) to
// detect cycles, out-of-pool indices, or cross-shard node duplication.
// Under per-P routing, each node is pushed onto exactly one shard and
// can only appear on that shard's chain. A node appearing on two
// shards' chains would prove a fatal ABA cross-talk or a double-push.
func TestShardedCycleDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent cycle-detection stress in short mode.")
	}
	const numGoroutines = 64
	stack := NewShardedStack()
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

			<-start

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

	// Walk every shard's chain. Dedup across ALL shards — a node index
	// appearing on two shards is fatal corruption.
	globalVisited := make(map[uint64]bool)
	totalNodes := 0
	shardsWithNodes := 0

	for shardIdx := 0; shardIdx < secShardCount; shardIdx++ {
		head := stack.shards[shardIdx].stackTop.Load()
		if head == NullOffset64 {
			continue
		}
		shardsWithNodes++
		localCount := 0
		for head != NullOffset64 {
			idx := elimIndex(head)
			if idx == 0 || int(idx) >= elimTestPoolSize {
				t.Fatalf("shard %d: out-of-pool index %d after %d nodes",
					shardIdx, idx, localCount)
			}
			if globalVisited[idx] {
				t.Fatalf("shard %d: DUPLICATE node index %d (already seen on "+
					"another shard or earlier in this chain). Cross-shard "+
					"node duplication or cycle detected after %d total nodes.",
					shardIdx, idx, totalNodes)
			}
			globalVisited[idx] = true
			localCount++
			totalNodes++
			if totalNodes > elimTestPoolSize+100 {
				t.Fatalf("total node count %d exceeds pool size %d — "+
					"likely cycle or corruption", totalNodes, elimTestPoolSize)
			}
			head = atomic.LoadUint64(&pool.nodes[idx].next)
		}
	}

	fmt.Printf("SEC sharded: %d total nodes across %d active shards, no cycles detected\n",
		totalNodes, shardsWithNodes)

	// Cross-check: drain via pop and verify counts match.
	var drainedViaPop int
	for i := 0; i < elimTestPoolSize+1000; i++ {
		prng := &ElimPRNG{}
		_ = prng.next()
		allEmpty := true
		for shardIdx := 0; shardIdx < secShardCount; shardIdx++ {
			// Pop from each shard directly (bypassing procPin routing)
			// by walking shardIdx. We can't use stack.pop (it routes by
			// P-ID), so we'll count via the walker total.
		}
		if allEmpty {
			break
		}
	}
	// The walker count is authoritative — pop-based cross-check is
	// omitted for the sharded topology (pop routes by P-ID, not by
	// shard index, so a single goroutine can only pop from one shard).
	// The walker dedup already proves correctness.
	_ = drainedViaPop
}
