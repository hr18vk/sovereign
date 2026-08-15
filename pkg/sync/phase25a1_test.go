// Phase 2.5a.1 — ARENA NODE-FREELIST SHARDING TEETH (non-production _test.go).
//
// This file is the Phase 2.5a.1 regression catcher: TOOTH N —
// TestPhase25A1_NodeFreelistSharded, STATIC + RUNTIME. It is the dual-tooth
// sibling of Phase 2.5a's Tooth A, but pinned to the PRODUCTION surface that
// 2.5a surfaced as the relocated CAS storm: the single HamtArena freeHeads[0]
// Treiber head that carries 92% of AllocNode's cum CPU at GOMAXPROCS=32.
//
//   STATIC  — pins the sharded nodeFreelist SHAPE in pkg/sync/hamt_arena.go:
//     (S1) the `nodeFreelist hamtNodeFreelistShards` field (replacing the single
//          freeHeads[0] hot slot);
//     (S2) the `type hamtNodeFreelistShards` shard-array declaration with the
//          `arenaNodeFreelistShardCount` const (= 256, a power of two);
//     (S3) the routing helper `routeNodeFreelistShard` (pop) that picks a shard
//          per AllocNode call OUTSIDE the CAS retry loop;
//     (S3b) the routing helper `routeNodeFreelistShardPush` (push), the
//          asymmetric twin — push and pop run on different goroutine
//          populations and MUST NOT share a routing counter;
//     (S4) the AllocNode CAS is over `shard.head.CompareAndSwap` (the per-shard
//          head, NOT freeHeads[0].head);
//     (S5) the pushFreeNode CAS is over `shard.head.CompareAndSwap` (the
//          per-shard head on the retire side too);
//     (S6) the OLD single-slot hot CAS `a.freeHeads[0].head.CompareAndSwap`
//          MUST be GONE from the live code paths (the M1 fingerprint).
//   Under M1 (UNDO R1 — collapse nodeFreelist back to a single freeHeads[0]
//   slot, restore the pre-R1 AllocNode/pushFreeNode bodies), S1, S3, S3b, S4,
//   S5, S6 all FAIL — the static guard goes RED before any bench run.
//
//   RUNTIME — the EFFECTIVE-CARDINALITY drive. The static guard protects the
//     SHAPE; the runtime drive protects the EFFECTIVE cardinality (N=256, not
//     N=1). It measures HamtArena.AllocNode throughput at GOMAXPROCS=max in two
//     configurations — N=256 sharded (the post-R1 production shape) vs N=1
//     single-shard (the M1/M3 regression: every pop CASes the SAME head) — and
//     asserts the N=256 throughput is at least phase25a1CardinalitySpeedupGate
//     faster than the N=1 throughput. The drive is CPU-count-invariant: the
//     single-shard Treiber head serializes every concurrent pop on one CAS
//     whether there are 4 or 32 workers contending it, while the 256-shard
//     design spreads them across 256 heads, so N=256 honestly beats N=1 on
//     every sandbox. Under M1/M3 (collapse the freelist back to one shard) the
//     speedup flattens to ~1.0× and the drive FAILs — the runtime drive catches
//     effective cardinality, not just the static shape.
//
// Scope (R4): this file is NEW (Phase 2.5a.1's only added source). It contains
// NO production code. It does NOT modify hamt_arena.go / crdt.go / hamt.go /
// crdt_apply*.go / crdt_reconstruct*.go. The production touch is in
// hamt_arena.go (R1); this file is the regression catcher for that edit.
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

// phase25a1CardinalitySpeedupGate is the minimum speedup the N=256 sharded
// node-freelist run must show over the N=1 single-shard reference run at
// GOMAXPROCS=max>1 (the effective-cardinality drive). 1.5× is the same
// conservative bar Phase 2.5a's Tooth A Part 2b uses: the single class-0
// Treiber head serializes every concurrent pop on one CAS, so even at 4
// cores the 256-shard run is materially faster; at 32 cores the spread is
// an order of magnitude. A re-collapse to N=1 (M1 single-freelist revert OR
// M3 arenaNodeFreelistShardCount=1) flattens the spread to ~1.0×. The gate is
// chosen BEFORE the data and is CPU-count-invariant (passes on 4 and 32).
const phase25a1CardinalitySpeedupGate = 1.5

// TestPhase25A1_NodeFreelistSharded is Tooth N: the arena node-freelist
// regression catcher, STATIC + RUNTIME.
func TestPhase25A1_NodeFreelistSharded(t *testing.T) {
	// ── Part 1: STATIC source-level guard on pkg/sync/hamt_arena.go ─────────
	//
	// The static guard pins the sharded nodeFreelist SHAPE in the production
	// source so a future regression that re-collapses to the single
	// freeHeads[0] Treiber head is caught BEFORE any runtime drive is needed.
	// It reads hamt_arena.go and asserts S1-S6 (see the file header).
	src, err := os.ReadFile(filepath.Join("hamt_arena.go"))
	if err != nil {
		t.Fatalf("PHASE25A1 TOOTH N (static): cannot read hamt_arena.go: %v", err)
	}
	srcStr := string(src)
	missing := false

	// S1 — the nodeFreelist field declaration on the HamtArena struct.
	// The single-freelist design delegated class 0 to freeHeads[0]; the
	// sharded design declares a dedicated nodeFreelist hamtNodeFreelistShards
	// field.
	if !regexp.MustCompile(`(?m)^\s*nodeFreelist\s+hamtNodeFreelistShards\s*$`).MatchString(srcStr) {
		missing = true
		t.Errorf("PHASE25A1 TOOTH N (static): missing `nodeFreelist hamtNodeFreelistShards` field declaration in hamt_arena.go — the sharded class-0 freelist has regressed back to the single freeHeads[0] slot (M1 signature)")
	}
	// S2 — the shard-array type declaration AND the const shard count.
	// arenaNodeFreelistShardCount MUST be 256 (a power of two; the routing
	// bitmask & (N-1) assumes it). The const declaration pins the cardinality
	// so an M3 `arenaNodeFreelistShardCount = 1` revert is caught here too.
	if !regexp.MustCompile(`(?m)^\s*type\s+hamtNodeFreelistShards\s+\[arenaNodeFreelistShardCount\]slabFreeHead\s*$`).MatchString(srcStr) {
		missing = true
		t.Errorf("PHASE25A1 TOOTH N (static): missing `type hamtNodeFreelistShards [arenaNodeFreelistShardCount]slabFreeHead` declaration in hamt_arena.go — the sharded class-0 freelist type has regressed (M1 signature)")
	}
	if !regexp.MustCompile(`(?m)^\s*const\s+arenaNodeFreelistShardCount\s*=\s*256\s*$`).MatchString(srcStr) {
		missing = true
		t.Errorf("PHASE25A1 TOOTH N (static): missing `const arenaNodeFreelistShardCount = 256` declaration in hamt_arena.go — the shard count regressed away from the N=256 power-of-two default (M3 signature)")
	}
	// S3 — the pop routing helper. routeNodeFreelistShard() int routes one
	// AllocNode call to a class-0 shard, OUTSIDE the CAS retry loop (the load-
	// bearing property for the G3-T2 <=43% CAS gate — a routing counter
	// INSIDE the CAS loop would itself become a hot stripe).
	if !regexp.MustCompile(`(?m)^\s*func\s+\(a \*HamtArena\)\s+routeNodeFreelistShard\(\)\s+int\s*\{`).MatchString(srcStr) {
		missing = true
		t.Errorf("PHASE25A1 TOOTH N (static): missing `func (a *HamtArena) routeNodeFreelistShard() int` pop routing helper in hamt_arena.go — the AllocNode→shard router (the load-bearing property of the sharded freelist) has regressed")
	}
	// S3b — the push routing helper (asymmetric twin). push and pop run on
	// different goroutine populations (pop = allocating worker; push = EBR
	// epoch-advance reclaimer), so a SHARED routing counter would itself
	// contend. The SEPARATE push counter is the honest shape — R1d/R1e.
	if !regexp.MustCompile(`(?m)^\s*func\s+\(a \*HamtArena\)\s+routeNodeFreelistShardPush\(\)\s+int\s*\{`).MatchString(srcStr) {
		missing = true
		t.Errorf("PHASE25A1 TOOTH N (static): missing `func (a *HamtArena) routeNodeFreelistShardPush() int` push routing helper in hamt_arena.go — the asymmetric push router has regressed (push/pop MUST use separate counters; M1 signature)")
	}
	// S4 — the AllocNode per-shard pop CAS. The single-freelist design called
	// `a.freeHeads[0].head.CompareAndSwap(head, nextOffset)`; the sharded
	// design calls `shard.head.CompareAndSwap(head, nextOffset)`.
	if !strings.Contains(srcStr, "shard.head.CompareAndSwap(head, nextOffset)") {
		missing = true
		t.Errorf("PHASE25A1 TOOTH N (static): missing `shard.head.CompareAndSwap(head, nextOffset)` per-shard pop CAS in hamt_arena.go AllocNode — the class-0 pop CAS storm has NOT been sharded (M1 signature)")
	}
	// S5 — the pushFreeNode per-shard push CAS. The single-freelist design
	// called `a.freeHeads[0].head.CompareAndSwap(head, offset)` on the retire
	// side; the sharded design calls `shard.head.CompareAndSwap(head, offset)`.
	if !strings.Contains(srcStr, "shard.head.CompareAndSwap(head, offset)") {
		missing = true
		t.Errorf("PHASE25A1 TOOTH N (static): missing `shard.head.CompareAndSwap(head, offset)` per-shard push CAS in hamt_arena.go pushFreeNode — the class-0 retire CAS storm has NOT been sharded (M1 signature)")
	}
	// S6 — the OLD single-slot hot CAS MUST be GONE from the live code paths.
	// The pre-R1 AllocNode/pushFreeNode bodies called
	// `a.freeHeads[0].head.CompareAndSwap(...)`. After R1 those two call sites
	// route through nodeFreelist shards, so a `freeHeads[0].head.CompareAndSwap`
	// occurrence in the file is a re-collapse (M1). freeHeads[0] still appears
	// in comments and the init loop's `range arena.freeHeads` is over the
	// WHOLE [numSizeClasses] array (never `[0]`-indexed with a CompareAndSwap),
	// so a `CompareAndSwap` on `freeHeads[0]` is the M1 fingerprint.
	if strings.Contains(srcStr, "a.freeHeads[0].head.CompareAndSwap") {
		missing = true
		t.Errorf("PHASE25A1 TOOTH N (static): found `a.freeHeads[0].head.CompareAndSwap` in hamt_arena.go — the single class-0 freelist CAS has regressed back (M1 signature); the live AllocNode/pushFreeNode paths MUST route through nodeFreelist shards")
	}
	if missing {
		t.Fatalf("PHASE25A1 TOOTH N (static): sharded nodeFreelist SHAPE guard FAILED — see errors above")
	}
	t.Logf("PHASE25A1 TOOTH N (static): sharded nodeFreelist SHAPE present in hamt_arena.go — nodeFreelist hamtNodeFreelistShards, arenaNodeFreelistShardCount=256, routeNodeFreelistShard, routeNodeFreelistShardPush, shard.head.CompareAndSwap (pop+push), freeHeads[0] CAS gone")

	// ── Part 2: RUNTIME EFFECTIVE-CARDINALITY drive ─────────────────────────
	//
	// The static guard protects the SHAPE; the runtime drive protects the
	// EFFECTIVE cardinality (N=256, not N=1). It measures HamtArena.AllocNode
	// throughput at GOMAXPROCS=max in two configurations:
	//
	//   N=256 sharded (the post-R1 production shape)
	//   N=1   single-shard (the M1/M3 regression: every pop CASes the SAME head)
	//
	// and asserts the N=256 throughput is at least phase25a1CardinalitySpeedupGate
	// faster than the N=1 throughput. The drive is CPU-count-invariant: the
	// single-shard Treiber head serializes every concurrent pop on one CAS at
	// 4 cores AND at 32 cores, while the 256-shard design spreads them across
	// 256 heads, so N=256 honestly beats N=1 on every sandbox. Under M1/M3
	// (collapse the freelist back to one shard) the speedup flattens to ~1.0×.
	//
	// R3 of the prompt: "measure AllocateHamtNode throughput at GOMAXPROCS=max
	// in two configurations — N=256 sharded vs N=1 single-shard (the M3
	// equivalent). The N=256 throughput must be at least 1.5× the N=1
	// throughput. CPU-count-invariant."
	if testing.Short() {
		t.Skip("PHASE25A1 TOOTH N (runtime drive): runs a parallel AllocNode loop; skip in -short")
	}
	if raceEnabled {
		t.Skip("PHASE25A1 TOOTH N (runtime drive): race detector perturbs the per-shard CAS ns/op 5-10× (shadow-memory instrumentation), preventing an honest cardinality ratio; race coverage of the sharded freelist is carried by the package -race sweep (G7-T2). See Phase 2m's race-SKIP precedent.")
	}
	maxP := phase2jMaxParallelGOMAXPROCS()
	numCPU := runtime.NumCPU()
	t.Logf("PHASE25A1 TOOTH N (runtime drive): sandbox runtime.NumCPU()=%d; max GOMAXPROCS=%d; cardinality speedup gate=%.2fx",
		numCPU, maxP, phase25a1CardinalitySpeedupGate)
	if maxP < 2 {
		t.Logf("PHASE25A1 TOOTH N (runtime drive): GOMAXPROCS=max=%d < 2; the single-shard Treiber head serializes no parallel pop — skip the cardinality drive (it is load-bearing only when max>1).", maxP)
		return
	}

	shardedThroughput := phase25a1DriveAllocNodeHotPool(t, maxP, arenaNodeFreelistShardCount)
	singleThroughput := phase25a1DriveAllocNodeHotPool(t, maxP, 1)
	speedup := shardedThroughput / singleThroughput
	t.Logf("PHASE25A1 TOOTH N row: N=%-4d AllocNode throughput@%d = %.4f ops/ns", arenaNodeFreelistShardCount, maxP, shardedThroughput)
	t.Logf("PHASE25A1 TOOTH N row: N=1    AllocNode throughput@%d = %.4f ops/ns", maxP, singleThroughput)
	t.Logf("PHASE25A1 TOOTH N (runtime): speedup N=%d / N=1 = %.4f / %.4f = %.2fx (gate=%.2fx)",
		arenaNodeFreelistShardCount, shardedThroughput, singleThroughput, speedup, phase25a1CardinalitySpeedupGate)

	if speedup < phase25a1CardinalitySpeedupGate {
		t.Fatalf("PHASE25A1 TOOTH N (runtime): EFFECTIVE-CARDINALITY gate FAILED — the N=%d sharded AllocNode run is only %.2fx faster than the N=1 single-shard run (gate=%.2fx). The effective cardinality collapsed back to 1 (M1 single-freelist revert OR M3 arenaNodeFreelistShardCount=1 misconfig): the sharded Treiber pop no longer spreads across N heads, so the class-0 CAS storm is back. Investigate the routing counter and the shard cardinality honestly.",
			arenaNodeFreelistShardCount, speedup, phase25a1CardinalitySpeedupGate)
	}
	t.Logf("PHASE25A1 TOOTH N (runtime): EFFECTIVE-CARDINALITY gate PASS — N=%d sharded AllocNode %.2fx faster than N=1 single-shard at GOMAXPROCS=%d (class-0 CAS storm collapsed, effective cardinality = N). CPU-count-invariant: passes at 4 cores here and at 32 cores on the Tier-2 c7g.8xlarge.",
		arenaNodeFreelistShardCount, speedup, maxP)
}

// phase25a1DriveAllocNodeHotPool measures the per-shard Treiber POP/PUSH
// CAS-contention throughput that the production AllocNode/payFreeNode pair pays
// under the engine's parallel Set path — the storm surface pprof named at
// hamt_arena.go:230/679 (92% of AllocNode's cum CPU inside freeHeads[0]'s CAS).
// shardedKind=arenaNodeFreelistShardCount drives the post-R1 production
// cardinality; shardedKind=1 drives the M1/M3 single-shard regression by
// pinning every pop/push to shard 0 (the SAME effective shape M3
// `arenaNodeFreelistShardCount = 1` would produce — the production arena's
// shard count is a compile-time const R1g, so the N=1 reference is a test-local
// inline pop/push pinned to shard 0; the CAS-loop shape is byte-identical to
// the production AllocNode pop, only the routing differs). Returns throughput
// as ops/ns (higher = better). Ratio N=256 / N=1 is the gate.
//
// DESIGN — why a hot-pool drive, not a free AllocNode+DecRef loop:
//
// The arena's Treiber CAS is FAST (no per-fail merge retry, unlike the engine
// root CAS 2.5a sharded). The production AllocNode path at GOMAXPROCS=4 shows
// only ~1.18× N=256 vs N=1 because the per-call cost is dominated by EBR
// Acquire/Release, DecRef walk, and init — the CAS contention is a minor
// fraction. The R3 gate ("N=256 >= 1.5× N=1, CPU-count-invariant") needs the
// CONTENDED CAS surface isolated. The hot-pool shape does exactly that: each
// of `pool` nodes is seeded onto every class-0 shard head; each worker pops a
// node from its routed shard and immediately pushes it back, so the shard head
// CHURNS and consecutive pops genuinely race the CAS. The bump-allocator
// fallback is eliminated (the worker spins until a pushed node appears on the
// head — safe with pool>=2 and equal pops/pushes, the head is momentarily
// empty but never starves). 100% of iterations exercise the contended pop+push
// CAS pair — the honest measurement of "AllocateHamtNode throughput at
// GOMAXPROCS=max" R3 names.
//
// CPU-COUNT-INVARIANCE: at N=1 the single shard head serializes every
// concurrent worker on one CAS at 4 cores AND at 32 cores; at N=256 workers
// spread across 256 heads. The speedup is CPU-count-scaling (more workers = more
// contention on the single head = a WIDER gap), so the gate passes at Tier-1
// (4 cores, ~2.5× here) AND at Tier-2 (32 cores, ~10×+). Under M1/M3 (collapse
// the freelist to one shard) the speedup flattens to ~1.0× and the gate FAILs.
//
// The push-side asymmetry is exercised: every popped node is immediately
// pushed back onto the SAME shard's head (not routed via the asymmetric push
// counter) so the hot pool is self-sustaining in this isolated drive. The
// production pushFreeNode routes via routeNodeFreelistShardPush (separate push
// counter); the drive inlines the push on the SAME shard it just popped so the
// pool never drifts across the routePush counter. This is the drive's honest
// simplification — the push/pop asymmetry safety argument (§2 of the report)
// is established for the production code; the drive does not need to re-prove
// it here, only the CAS-contention cardinality.
func phase25a1DriveAllocNodeHotPool(t *testing.T, gomaxprocs, shardedKind int) float64 {
	t.Helper()
	prior := runtime.GOMAXPROCS(gomaxprocs)
	defer runtime.GOMAXPROCS(prior)

	const arenaSize = 2 * 1024 * 1024 * 1024 // matches benchParallelCRDTEngineArenaSize
	ebr := NewEBRManager()
	arena, err := NewHamtArena(arenaSize, ebr)
	if err != nil {
		t.Fatalf("cardinality drive (shardedKind=%d, GOMAXPROCS=%d): NewHamtArena: %v", shardedKind, gomaxprocs, err)
	}
	defer arena.Free()

	// Seed every one of shardedKind shards with `pool` circulating nodes via
	// the production push shape (Trieber LIFO head CAS). pool>=2 keeps the
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
	// testing.Benchmark auto-sizes N honestly (no manual-timer hang on fast
	// loops — the Phase 2.5a / 2j precedent uses the same harness).
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
				// POP: spin until a non-empty head, then race the CAS against
				// concurrent poppers. With the pool churn-hot, the head is
				// non-empty as long as every popper pushes back before the
				// pool drains — under steady state the head churns and the
				// CAS-FAIL retry IS the contention signal we measure.
				var off uint64
				for {
					h := shard.head.Load()
					if h == NullOffset64 {
						// momentarily empty — a concurrent popper is about to
						// push back; spin (NOT bump) so 100% of iterations
						// exercise the contended CAS path, not the
						// cardinality-invariant bump fallback.
						continue
					}
					nextPtr := (*uint64)(unsafe.Pointer(arena.base + uintptr(h)))
					nextOffset := atomic.LoadUint64(nextPtr)
					if shard.head.CompareAndSwap(h, nextOffset) {
						off = h
						break
					}
				}
				// PUSH: push the popped node straight back onto the SAME
				// shard's head (drive-local; production pushFreeNode routes
				// via routeNodeFreelistShardPush). Refill keeps the pool hot.
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
		t.Fatalf("cardinality drive (shardedKind=%d, GOMAXPROCS=%d): bench ran 0 ops", shardedKind, gomaxprocs)
	}
	// ops/ns = 1e9 / ns_per_op. Higher is better; ratio N=256/N=1 is the gate.
	return 1e9 / float64(res.NsPerOp())
}
