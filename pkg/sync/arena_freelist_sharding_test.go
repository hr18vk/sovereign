// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// The class-0 node free-list uses 256 Treiber stacks instead of the single
// HamtArena freeHeads[0] stack. Profiling at GOMAXPROCS=32 attributed 92% of
// AllocNode's cumulative CPU to the former shared head.
//
// TestNodeFreelistSharded checks both the source shape and its runtime effect.
// The source checks require dedicated shard storage, a power-of-two shard
// count, separate push and pop routing, and per-shard compare-and-swap heads in
// AllocNode and pushFreeNode. They also reject the former freeHeads[0] CAS.
//
// The runtime check compares allocation throughput with 256 shards against a
// test-local single-shard reference. One shared head serializes concurrent
// pops; spreading them across 256 heads must produce at least the speedup in
// freelistCardinalitySpeedupGate. Returning to one effective shard removes that
// difference even if the source declarations remain.
package sync

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"
)

// freelistCardinalitySpeedupGate requires the 256-shard run to deliver at
// least 1.5 times the single-shard throughput when GOMAXPROCS is greater than
// one. A single class-0 Treiber head serializes every concurrent pop on one
// CAS. Returning to one effective shard, whether through the source layout or
// arenaNodeFreelistShardCount, flattens the ratio to approximately 1.0.
const freelistCardinalitySpeedupGate = 1.5

// TestNodeFreelistSharded checks the arena node free-list's source layout and
// effective shard count.
func TestNodeFreelistSharded(t *testing.T) {
	// Inspect the production source first so a return to the single
	// freeHeads[0] Treiber head fails without running the throughput comparison.
	src, err := os.ReadFile(filepath.Join("hamt_arena.go"))
	if err != nil {
		t.Fatalf("static guard: cannot read hamt_arena.go: %v", err)
	}
	srcStr := string(src)
	missing := false

	// The dedicated nodeFreelist field replaces class 0's use of freeHeads[0].
	if !regexp.MustCompile(`(?m)^\s*nodeFreelist\s+hamtNodeFreelistShards\s*$`).MatchString(srcStr) {
		missing = true
		t.Errorf("static guard: missing `nodeFreelist hamtNodeFreelistShards` field declaration in hamt_arena.go — the sharded class-0 freelist has regressed back to the single freeHeads[0] slot")
	}
	// The shard count is a power of two because routing masks with N-1.
	// Checking the constant also catches a change to one effective shard.
	if !regexp.MustCompile(`(?m)^\s*type\s+hamtNodeFreelistShards\s+\[arenaNodeFreelistShardCount\]slabFreeHead\s*$`).MatchString(srcStr) {
		missing = true
		t.Errorf("static guard: missing `type hamtNodeFreelistShards [arenaNodeFreelistShardCount]slabFreeHead` declaration in hamt_arena.go — the sharded class-0 freelist type has regressed")
	}
	if !regexp.MustCompile(`(?m)^\s*const\s+arenaNodeFreelistShardCount\s*=\s*256\s*$`).MatchString(srcStr) {
		missing = true
		t.Errorf("static guard: missing `const arenaNodeFreelistShardCount = 256` declaration in hamt_arena.go — the shard count regressed away from the 256 power-of-two default")
	}
	// Pop routing occurs once per AllocNode call, outside the CAS retry loop.
	// Incrementing the routing counter inside that loop would add contention.
	if !regexp.MustCompile(`(?m)^\s*func\s+\(a \*HamtArena\)\s+routeNodeFreelistShard\(\)\s+int\s*\{`).MatchString(srcStr) {
		missing = true
		t.Errorf("static guard: missing `func (a *HamtArena) routeNodeFreelistShard() int` pop routing helper in hamt_arena.go — the AllocNode→shard router has regressed")
	}
	// Allocating workers pop nodes, while the epoch-advance reclaimer pushes
	// them. Separate routing counters avoid adding a shared contended word.
	if !regexp.MustCompile(`(?m)^\s*func\s+\(a \*HamtArena\)\s+routeNodeFreelistShardPush\(\)\s+int\s*\{`).MatchString(srcStr) {
		missing = true
		t.Errorf("static guard: missing `func (a *HamtArena) routeNodeFreelistShardPush() int` push routing helper in hamt_arena.go — the asymmetric push router has regressed (push/pop must use separate counters)")
	}
	// AllocNode must swap the selected shard head rather than freeHeads[0].
	if !strings.Contains(srcStr, "shard.head.CompareAndSwap(head, nextOffset)") {
		missing = true
		t.Errorf("static guard: missing `shard.head.CompareAndSwap(head, nextOffset)` per-shard pop CAS in hamt_arena.go AllocNode — the class-0 pop CAS has not been sharded")
	}
	// The retirement path must also swap a selected shard head.
	if !strings.Contains(srcStr, "shard.head.CompareAndSwap(head, offset)") {
		missing = true
		t.Errorf("static guard: missing `shard.head.CompareAndSwap(head, offset)` per-shard push CAS in hamt_arena.go pushFreeNode — the class-0 retire CAS has not been sharded")
	}
	// The old single-slot CAS must not remain in either live path. Other uses
	// of freeHeads are valid: initialization ranges over the complete
	// [numSizeClasses] array, so only a CAS on freeHeads[0] indicates a return
	// to the shared class-0 head.
	if strings.Contains(srcStr, "a.freeHeads[0].head.CompareAndSwap") {
		missing = true
		t.Errorf("static guard: found `a.freeHeads[0].head.CompareAndSwap` in hamt_arena.go — the single class-0 freelist CAS has regressed back; the live AllocNode/pushFreeNode paths must route through nodeFreelist shards")
	}
	if missing {
		t.Fatalf("static guard: sharded nodeFreelist shape guard failed — see errors above")
	}
	t.Logf("static guard: sharded nodeFreelist shape present in hamt_arena.go — nodeFreelist hamtNodeFreelistShards, arenaNodeFreelistShardCount=256, routeNodeFreelistShard, routeNodeFreelistShardPush, shard.head.CompareAndSwap (pop+push), freeHeads[0] CAS gone")

	// Compare production shard cardinality with a test-local single-shard
	// reference. One shared Treiber head serializes concurrent pops; the
	// production configuration spreads them across 256 heads. Returning to one
	// effective shard flattens the throughput ratio to approximately 1.0.
	if testing.Short() {
		t.Skip("runtime drive: runs a parallel AllocNode loop; skip in -short")
	}
	if raceEnabled {
		t.Skip("runtime drive: race detector perturbs the per-shard CAS ns/op 5-10× (shadow-memory instrumentation), preventing a clean cardinality ratio; race coverage of the sharded freelist is carried by the package -race sweep.")
	}
	maxP := joinMaxParallelGOMAXPROCS()
	numCPU := runtime.NumCPU()
	t.Logf("runtime drive: runtime.NumCPU()=%d; max GOMAXPROCS=%d; cardinality speedup gate=%.2fx",
		numCPU, maxP, freelistCardinalitySpeedupGate)
	if maxP < 2 {
		t.Logf("runtime drive: GOMAXPROCS=max=%d < 2; the single-shard Treiber head has no parallel pop contention, so the cardinality comparison does not apply", maxP)
		return
	}

	shardedThroughput := driveAllocNodeHotPool(t, maxP, arenaNodeFreelistShardCount)
	singleThroughput := driveAllocNodeHotPool(t, maxP, 1)
	speedup := shardedThroughput / singleThroughput
	t.Logf("runtime drive row: N=%-4d AllocNode throughput@%d = %.4f ops/ns", arenaNodeFreelistShardCount, maxP, shardedThroughput)
	t.Logf("runtime drive row: N=1    AllocNode throughput@%d = %.4f ops/ns", maxP, singleThroughput)
	t.Logf("runtime drive: speedup N=%d / N=1 = %.4f / %.4f = %.2fx (gate=%.2fx)",
		arenaNodeFreelistShardCount, shardedThroughput, singleThroughput, speedup, freelistCardinalitySpeedupGate)

	if speedup < freelistCardinalitySpeedupGate {
		t.Fatalf("runtime drive: N=%d sharded AllocNode throughput is only %.2fx the N=1 result (minimum %.2fx); pops are not spreading across the expected heads, so check the routing counter and shard count",
			arenaNodeFreelistShardCount, speedup, freelistCardinalitySpeedupGate)
	}
	t.Logf("runtime drive: effective-cardinality gate pass: N=%d sharded AllocNode is %.2fx faster than N=1 at GOMAXPROCS=%d; the pop CAS operations are distributed across N heads",
		arenaNodeFreelistShardCount, speedup, maxP)
}

// driveAllocNodeHotPool measures Treiber pop/push throughput for the CAS path
// used by AllocNode and pushFreeNode. The production shard count is a compile-
// time constant, so shardedKind=1 uses a test-local copy of the same CAS loop
// with every operation pinned to shard 0. The result is operations per
// nanosecond; the test compares the 256-shard and single-shard results.
//
// A full AllocNode/DecRef loop would spend much of its time in EBR
// Acquire/Release, reference-count traversal, and initialization rather than on
// the free-list CAS. This drive isolates that CAS path. Each shard starts with
// four circulating nodes; each worker pops one node and immediately pushes it
// back. An empty head spins instead of using the bump allocator, so every
// iteration measures contended pop and push operations. At least two nodes per
// shard and balanced pops/pushes keep the pool supplied.
//
// Workers return each node to the shard they popped rather than using the
// production push router. This keeps each test-local pool at its intended shard.
// Production uses routeNodeFreelistShardPush so its allocating and reclaiming
// goroutine populations do not share a routing counter.
func driveAllocNodeHotPool(t *testing.T, gomaxprocs, shardedKind int) float64 {
	t.Helper()
	prior := runtime.GOMAXPROCS(gomaxprocs)
	defer runtime.GOMAXPROCS(prior)

	const arenaSize = 2 * 1024 * 1024 * 1024 // matches benchParallelCRDTEngineArenaSize
	ebr := NewEBRManager()
	arena, err := NewHamtArena(arenaSize, ebr)
	if err != nil {
		t.Fatalf("driveAllocNodeHotPool (shardedKind=%d, GOMAXPROCS=%d): NewHamtArena: %v", shardedKind, gomaxprocs, err)
	}
	defer arena.Free()

	// Seed every one of shardedKind shards with `pool` circulating nodes via
	// the production push shape (Treiber LIFO head CAS). pool>=2 keeps the
	// head churn-hot so pop CASes race; the nodes' stored nextOffset is left
	// at whatever AllocNode zeroed (NullOffset64), so a pop that succeeds
	// against the head leaves the head pointing at the next seeded node. With
	// pool nodes seeded per shard, the first `pool` pops drain the shard and
	// the immediately-following pushes refill it, so the head churns.
	const pool = 4
	for s := 0; s < shardedKind; s++ {
		for k := 0; k < pool; k++ {
			node := arena.AllocNode()
			off := uint64(node) - uint64(arena.base)
			shard := &arena.nodeFreelist[s]
			offsetPtr := (*uint64)(unsafe.Pointer(arena.base + uintptr(off)))
			for {
				h := shard.head.Load()
				atomic.StoreUint64(offsetPtr, h)
				if shard.head.CompareAndSwap(h, off) {
					break
				}
			}
		}
	}

	// b.RunParallel distributes b.N across workers at the current GOMAXPROCS,
	// matching the production BenchmarkCRDTEngine_JoinParallel shape exactly.
	// testing.Benchmark auto-sizes N (no manual-timer hang on fast loops).
	benchFn := func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// Route this pop to a shard. The sharded run routes via the
				// production nodeFreelistRoutePop counter (N=256); the N=1
				// regression pins every pop to shard 0 by masking with 0.
				si := int(arena.nodeFreelistRoutePop.Add(1)-1) & (shardedKind - 1)
				shard := &arena.nodeFreelist[si]
				// Spin until a node is available, then race the pop CAS
				// against other workers. Failed CAS retries provide the
				// contention measured by this drive.
				var off uint64
				for {
					h := shard.head.Load()
					if h == NullOffset64 {
						// A concurrent worker will push a node back. Wait for it
						// instead of taking the cardinality-independent bump path.
						continue
					}
					nextPtr := (*uint64)(unsafe.Pointer(arena.base + uintptr(h)))
					nextOffset := atomic.LoadUint64(nextPtr)
					if shard.head.CompareAndSwap(h, nextOffset) {
						off = h
						break
					}
				}
				// Return the node to the same shard. Production instead routes
				// pushes with routeNodeFreelistShardPush.
				offsetPtr := (*uint64)(unsafe.Pointer(arena.base + uintptr(off)))
				for {
					h := shard.head.Load()
					atomic.StoreUint64(offsetPtr, h)
					if shard.head.CompareAndSwap(h, off) {
						break
					}
				}
			}
		})
	}
	res := testing.Benchmark(benchFn)
	if res.N == 0 {
		t.Fatalf("driveAllocNodeHotPool (shardedKind=%d, GOMAXPROCS=%d): bench ran 0 ops", shardedKind, gomaxprocs)
	}
	// ops/ns = 1e9 / ns_per_op. Higher is better; ratio N=256/N=1 is the gate.
	return 1e9 / float64(res.NsPerOp())
}
