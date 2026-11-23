// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests cover variable-size free-list sharding in hamt_arena.go and
// retired-list sharding in reclamation.go.
//
// Variable-size allocation formerly concentrated allocVar/freeVar operations on
// freeHeads[classIdx].head. Profiling the JoinParallel workload at 32 cores
// attributed 57.91% of cumulative CPU to that path. Each variable class now has
// 256 slabFreeHead shards, separate push and pop routes, and a bounded 128-shard
// pop fallback.
//
// EBR retirement formerly concentrated PushBlock/PushHAMT operations on one
// head per epoch, measured at 11.20% cumulative CPU. Each of the three epochs
// now has 256 RetiredList shards with atomic.Pointer[RetiredNode] heads.
// AdvanceEpoch swaps all shard heads before walking any of them, so recursive
// retirement during reclamation cannot add fresh entries to a shard that is
// already being drained.
//
// A five-point JoinParallel comparison used three runs per point on a
// 32-core c7g.8xlarge:
//
//	cores   unsharded                 sharded                    change
//	1       6232 ns, 524 B, 9 alloc   6962 ns, 526 B, 9 alloc   +12% ns, +2 B
//	8       1733 ns, 538 B, 9 alloc   2636 ns, 527 B, 9 alloc   +52% ns, -11 B
//	16      1476 ns, 556 B, 9 alloc   2330 ns, 535 B, 9 alloc   +58% ns, -21 B
//	24      1674 ns, 577 B, 9 alloc   2350 ns, 541 B, 9 alloc   +40% ns, -36 B
//	32      2407 ns, 622 B, 9 alloc   1387 ns, 603 B, 9 alloc   -42% ns, -19 B
//
// Sharding adds routing overhead below 32 cores. At 32 cores, reduced CAS
// contention outweighs that overhead. The runtime test therefore compares
// bytes per operation at GOMAXPROCS=1 and GOMAXPROCS=32 rather than asserting a
// throughput improvement at every core count. Every one of five runs must have
// an inflation ratio no greater than casRetryInflationCeiling. Nanoseconds per
// operation are logged separately.
//
// TestCASStormShardedStatic inspects both production files in every build
// mode. TestCASStormShardedRuntime skips the byte-ratio comparison under the
// race detector because instrumentation changes allocation behavior.
// TestNoZeroGCRegression checks GenerateDelta's zero-allocation contract in
// five runs at GOMAXPROCS=1. TestInversionProof requires 32-core JoinParallel
// latency to be no worse than 16-core latency in each of three runs; the
// measured unsharded and sharded ratios were 1.63 and 0.595 respectively.
package sync

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// casRetryInflationCeiling limits B/op at GOMAXPROCS=32 relative to B/op at
// GOMAXPROCS=1. Contended CAS retries can send allocVar down its bump-allocator
// path, increasing bytes per operation. The measured ratio was 1.187 without
// sharding and 1.146 with sharding. The 1.18 ceiling leaves a small margin over
// the sharded measurement while rejecting the unsharded behavior.
const casRetryInflationCeiling = 1.18

// inversionRatioCeiling limits ns/op at 32 cores relative to ns/op at 16
// cores. A value no greater than one means adding cores does not increase
// latency. Returning to concentrated CAS heads reverses that relationship.
const inversionRatioCeiling = 1.0

// stormRuntimeRuns requires five independent byte-ratio measurements.
const stormRuntimeRuns = 5

// stormInversionRuns uses three measurements at each of 16 and 32 cores.
const stormInversionRuns = 3

// TestCASStormShardedStatic inspects hamt_arena.go and reclamation.go for the
// sharded data structures, routing order, and two-phase retirement drain. It
// runs in every build mode, including -short and -race.
func TestCASStormShardedStatic(t *testing.T) {
	// Read the current source rather than an embed-time snapshot.
	hamtSrc, err := os.ReadFile(filepath.Join("hamt_arena.go"))
	if err != nil {
		alt := filepath.Join("pkg", "sync", "hamt_arena.go")
		hamtSrc, err = os.ReadFile(alt)
		if err != nil {
			t.Fatalf("static check: cannot read hamt_arena.go: %v", err)
		}
	}
	recSrc, err := os.ReadFile(filepath.Join("reclamation.go"))
	if err != nil {
		alt := filepath.Join("pkg", "sync", "reclamation.go")
		recSrc, err = os.ReadFile(alt)
		if err != nil {
			t.Fatalf("static check: cannot read reclamation.go: %v", err)
		}
	}
	hamtStr := string(hamtSrc)
	recStr := string(recSrc)
	missing := false

	// Variable-size classes use varFreelist[classIdx-1], with 256 shard heads
	// per class instead of one freeHeads[classIdx] head.
	if !regexp.MustCompile(`(?m)^\s*varFreelist\s+varFreelistShards\s*$`).MatchString(hamtStr) {
		missing = true
		t.Errorf("static check: missing `varFreelist varFreelistShards` field in hamt_arena.go; variable-size classes are not using sharded free-lists")
	}
	// The power-of-two shard count permits masking with N-1 during the pop
	// sweep. Checking the constant also catches a change to one shard.
	if !regexp.MustCompile(`(?m)^\s*type\s+varFreelistShards\s+\[numVarClasses\]\[arenaVarFreelistShardCount\]slabFreeHead\s*$`).MatchString(hamtStr) {
		missing = true
		t.Errorf("static check: missing `varFreelistShards` array declaration in hamt_arena.go")
	}
	if !regexp.MustCompile(`(?m)^\s*const\s+arenaVarFreelistShardCount\s*=\s*256\s*$`).MatchString(hamtStr) {
		missing = true
		t.Errorf("static check: arenaVarFreelistShardCount must remain 256 in hamt_arena.go")
	}
	// Push and pop use separate cache-line-isolated routing counters, as do the
	// class-0 node free-lists.
	if !regexp.MustCompile(`varFreelistRoutePop\s+atomic\.Uint64`).MatchString(hamtStr) {
		missing = true
		t.Errorf("static check: missing varFreelistRoutePop atomic counter in hamt_arena.go")
	}
	if !regexp.MustCompile(`varFreelistRoutePush\s+atomic\.Uint64`).MatchString(hamtStr) {
		missing = true
		t.Errorf("static check: missing varFreelistRoutePush atomic counter in hamt_arena.go; push and pop require separate counters")
	}
	// The routing helpers select a shard once per allocVar or freeVar call.
	if !regexp.MustCompile(`(?m)^\s*func\s+\(a \*HamtArena\)\s+routeVarFreelistShardPop\(\)\s+int\s*\{`).MatchString(hamtStr) {
		missing = true
		t.Errorf("static check: missing routeVarFreelistShardPop in hamt_arena.go")
	}
	if !regexp.MustCompile(`(?m)^\s*func\s+\(a \*HamtArena\)\s+routeVarFreelistShardPush\(\)\s+int\s*\{`).MatchString(hamtStr) {
		missing = true
		t.Errorf("static check: missing routeVarFreelistShardPush in hamt_arena.go")
	}
	// Variable classes 1 through 16 occupy outer indices 0 through 15. This
	// class-minus-one indexing distinguishes allocVar from class-0 AllocNode.
	if !strings.Contains(hamtStr, "a.varFreelist[classIdx-1]") {
		missing = true
		t.Errorf("static check: missing varFreelist[classIdx-1] indexing in hamt_arena.go; variable-size allocation is not using its shard array")
	}
	// The old per-class CAS must not remain in the allocation or return path.
	if strings.Contains(hamtStr, "a.freeHeads[classIdx].head.CompareAndSwap") {
		missing = true
		t.Errorf("static check: found freeHeads[classIdx].head.CompareAndSwap in hamt_arena.go; variable-size operations must use varFreelist shards")
	}
	// freeHeads retains its [numSizeClasses] layout for the remaining size
	// classes and the layout checks.
	if !regexp.MustCompile(`(?m)^\s*freeHeads\s+\[numSizeClasses\]slabFreeHead\s*$`).MatchString(hamtStr) {
		missing = true
		t.Errorf("static check: missing freeHeads [numSizeClasses]slabFreeHead in hamt_arena.go")
	}

	// Each of the three EBR epochs has its own RetiredList shard array.
	// RetiredList.head is atomic.Pointer[RetiredNode], unlike the Uint64 offsets
	// used by arena free-lists. Keeping RetiredList also preserves the
	// PushBlock/PushHAMT method contracts.
	if !regexp.MustCompile(`retired\s+\[3\]\[arenaRetiredFreelistShardCount\]RetiredList`).MatchString(recStr) {
		missing = true
		t.Errorf("static check: missing retired [3][arenaRetiredFreelistShardCount]RetiredList in reclamation.go")
	}
	// A Uint64 array here would confuse free-list offsets with retired-node
	// pointers.
	if regexp.MustCompile(`retired\s+\[3\]\[.*\]atomic\.Uint64`).MatchString(recStr) {
		missing = true
		t.Errorf("static check: retired lists use atomic.Uint64 in reclamation.go; RetiredList heads must be atomic.Pointer[RetiredNode]")
	}
	// The power-of-two retired-list shard count permits bitmask routing and
	// must not be reduced to one effective shard.
	if !regexp.MustCompile(`(?m)^\s*const\s+arenaRetiredFreelistShardCount\s*=\s*256\s*$`).MatchString(recStr) {
		missing = true
		t.Errorf("static check: arenaRetiredFreelistShardCount must remain 256 in reclamation.go")
	}
	// RetireBlock must keep routing globalEpoch through the three-epoch ring.
	// Combining the epochs would shorten the grace period before reclamation.
	retireBlockBody := parkFuncBody(recStr, "RetireBlock")
	if retireBlockBody == "" {
		missing = true
		t.Errorf("static check: cannot isolate RetireBlock in reclamation.go")
	} else {
		stripped := parkStripGoComments(retireBlockBody)
		// RetireBlock selects the epoch first, then the shard. The list-head
		// CAS remains in RetiredList.PushBlock; this function only dispatches to
		// m.retired[idx][shard].
		modRe := regexp.MustCompile(`idx\s*:=\s*[a-zA-Z_]\w*\s*%\s*3`)
		modLoc := modRe.FindStringIndex(stripped)
		routeRe := regexp.MustCompile(`routeRetiredShard\(\)`)
		routeLoc := routeRe.FindStringIndex(stripped)
		shardAccessRe := regexp.MustCompile(`m\.retired\[idx\]\[shard\]`)
		shardAccessLoc := shardAccessRe.FindStringIndex(stripped)
		if modLoc == nil {
			missing = true
			t.Errorf("static check: RetireBlock does not route with idx := <expr> %% 3; the three-epoch grace period is not preserved")
		}
		if shardAccessLoc == nil {
			missing = true
			t.Errorf("static check: RetireBlock must access m.retired[idx][shard].PushBlock instead of one list per epoch")
		}
		// Shard routing follows epoch selection and precedes the list access.
		if routeLoc == nil {
			missing = true
			t.Errorf("static check: missing routeRetiredShard call in RetireBlock")
		} else if modLoc != nil && routeLoc[0] < modLoc[0] {
			missing = true
			t.Errorf("static check: routeRetiredShard at byte %d precedes epoch selection at byte %d; select the epoch before the shard", routeLoc[0], modLoc[0])
		} else if shardAccessLoc != nil && routeLoc[0] >= shardAccessLoc[0] {
			missing = true
			t.Errorf("static check: routeRetiredShard at byte %d does not precede the shard access at byte %d; routing must occur outside the list CAS loop", routeLoc[0], shardAccessLoc[0])
		}
		// PushBlock still operates on l.head internally. Only the caller's
		// indexing changes, so one-dimensional indexing indicates lost sharding.
		if regexp.MustCompile(`m\.retired\[idx\]\.PushBlock`).MatchString(stripped) {
			missing = true
			t.Errorf("static check: found m.retired[idx].PushBlock in RetireBlock; use the two-dimensional shard index")
		}
		// The CAS retry loop belongs to RetiredList.PushBlock. An infinite loop
		// here would put routing in the retry path and add counter contention.
		if regexp.MustCompile(`\bfor\s*\{`).MatchString(stripped) {
			missing = true
			t.Errorf("static check: found an infinite loop in RetireBlock; keep the CAS retry loop in RetiredList.PushBlock so routing stays outside it")
		}
	}
	// AdvanceEpoch must swap all 256 heads in m.retired[safeIdx] before any
	// freeRetiredList walk. Otherwise recursive RetireBlock calls can add fresh
	// retirees to an unswapped shard and have them reclaimed without a complete
	// grace period.
	advanceBody := parkFuncBody(recStr, "AdvanceEpoch")
	if advanceBody == "" {
		missing = true
		t.Errorf("static check: cannot isolate AdvanceEpoch in reclamation.go")
	} else {
		stripped := parkStripGoComments(advanceBody)
		loopRe := regexp.MustCompile(`for\s+shard\s*:?=\s*[^;]*;[^;]*shard\s*<\s*arenaRetiredFreelistShardCount`)
		if !loopRe.MatchString(stripped) {
			missing = true
			t.Errorf("static check: AdvanceEpoch does not iterate over arenaRetiredFreelistShardCount shards")
		} else if !strings.Contains(stripped, "m.retired[safeIdx][shard].head.Swap(nil)") {
			missing = true
			t.Errorf("static check: AdvanceEpoch does not swap each m.retired[safeIdx][shard] head")
		}
		// The heads array holds the first phase's snapshots. freeRetiredList
		// runs only after every shard has been swapped.
		if !strings.Contains(stripped, "heads[shard]") {
			missing = true
			t.Errorf("static check: AdvanceEpoch lacks heads[shard] snapshots; swap all retired-list heads before walking any of them")
		}
	}

	if missing {
		t.Fatalf("static check: one or more sharding invariants failed")
	}
	t.Logf("static check: found varFreelist[numVarClasses][256]slabFreeHead with separate push/pop routes; retired[3][256]RetiredList with pointer heads, epoch-then-shard routing, and two-phase AdvanceEpoch draining")
}

// TestCASStormShardedRuntime compares JoinParallel B/op at GOMAXPROCS=1 and
// GOMAXPROCS=32. The single-threaded run has no CAS contention and supplies the
// baseline. Each of five contended-to-baseline ratios must remain at or below
// casRetryInflationCeiling.
//
// A Join allocates a CRDTDelta, a seqEntry slice, and a HAMT wrapper through
// allocVar. Retrying a shared free-list head can lead to bump allocation, so
// increased B/op under contention tracks that amplification. Sharding the
// variable classes and retired lists reduces contention on both paths.
//
// Race instrumentation changes allocation behavior, so this comparison is
// skipped under -race; the static test and package race tests still run. This
// test does not assert a latency improvement: routing makes the sharded path
// slower below 32 cores in the recorded comparison, and only the 32-core case
// is faster.
func TestCASStormShardedRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("CAS byte-ratio check: runs JoinParallel at one and maximum GOMAXPROCS; skip in -short")
	}
	if raceEnabled {
		t.Skip("CAS byte-ratio check: race instrumentation changes allocation behavior; package race tests provide concurrency coverage")
	}
	// The ceiling was calibrated at 32 hardware threads. Fewer cores do not
	// produce the contention this ratio measures.
	if n := runtime.NumCPU(); n < 32 {
		t.Skipf("CAS byte-ratio check: the %.3fx ceiling requires 32 cores; host has %d", casRetryInflationCeiling, n)
	}
	maxP := joinMaxParallelGOMAXPROCS()
	numCPU := runtime.NumCPU()
	t.Logf("CAS byte-ratio check: runtime.NumCPU()=%d; max GOMAXPROCS=%d; ceiling=%.3fx across %d runs (B/op@max / B/op@1)",
		numCPU, maxP, casRetryInflationCeiling, stormRuntimeRuns)
	if maxP < 2 {
		t.Logf("CAS byte-ratio check: GOMAXPROCS=max=%d < 2; no parallel pop contention is available", maxP)
		return
	}

	// With no parallel contention, the one-thread run supplies the baseline
	// allocation cost. The maximum-GOMAXPROCS run adds CAS contention.
	ratios := make([]float64, stormRuntimeRuns)
	minRatio := 1e9
	for run := 0; run < stormRuntimeRuns; run++ {
		bopAt1c := driveJoinBytesPerOp(t, 1)
		bopAtMax := driveJoinBytesPerOp(t, maxP)
		ratio := float64(bopAtMax) / float64(bopAt1c)
		ratios[run] = ratio
		if ratio < minRatio {
			minRatio = ratio
		}
		t.Logf("CAS byte-ratio run %d/%d: B/op@1c=%d B/op@%d=%d ratio=%.4fx (ceiling=%.3fx)",
			run+1, stormRuntimeRuns, bopAt1c, maxP, bopAtMax, ratio, casRetryInflationCeiling)
	}
	gateOK := true
	for i, r := range ratios {
		if r > casRetryInflationCeiling {
			gateOK = false
			t.Errorf("CAS byte-ratio run %d: ratio=%.4fx exceeds ceiling %.3fx; sharding did not contain allocation growth under contention", i+1, r, casRetryInflationCeiling)
		}
	}
	t.Logf("CAS byte ratios across %d runs: %.4fx %.4fx %.4fx %.4fx %.4fx (ceiling=%.3fx, min=%.4fx)",
		stormRuntimeRuns, ratios[0], ratios[1], ratios[2], ratios[3], ratios[4], casRetryInflationCeiling, minRatio)
	if !gateOK {
		t.Fatalf("CAS byte-ratio check failed: at least one run exceeded the %.3fx ceiling", casRetryInflationCeiling)
	}
	t.Logf("CAS byte-ratio check passed: all %d runs are at or below %.3fx (min=%.4fx)", stormRuntimeRuns, casRetryInflationCeiling, minRatio)
}

// driveJoinBytesPerOp runs BenchmarkCRDTEngine_JoinParallel at gomaxprocs and
// returns allocated bytes per operation.
func driveJoinBytesPerOp(t *testing.T, gomaxprocs int) int64 {
	t.Helper()
	prior := runtime.GOMAXPROCS(gomaxprocs)
	defer runtime.GOMAXPROCS(prior)

	benchFn := func(b *testing.B) {
		BenchmarkCRDTEngine_JoinParallel(b)
	}
	res := testing.Benchmark(benchFn)
	if res.N == 0 {
		t.Fatalf("JoinParallel byte measurement ran 0 operations at GOMAXPROCS=%d", gomaxprocs)
	}
	return res.AllocedBytesPerOp()
}

// TestInversionProof measures JoinParallel ns/op at 16 and 32 cores three
// times. Each 32-core to 16-core ratio must be no greater than
// inversionRatioCeiling. Concentrating CAS operations on shared heads makes the
// 32-core run slower again. The measured ratio was 1.63 before sharding and
// 0.595 after sharding. Race instrumentation changes timing, so this comparison
// runs only without -race.
func TestInversionProof(t *testing.T) {
	if testing.Short() {
		t.Skipf("JoinParallel latency ratio: runs at 16 and 32 cores %d times; skip in -short", stormInversionRuns)
	}
	if raceEnabled {
		t.Skip("JoinParallel latency ratio: race instrumentation changes timing; run without -race")
	}
	numCPU := runtime.NumCPU()
	maxP := joinMaxParallelGOMAXPROCS()
	t.Logf("JoinParallel latency ratio: runtime.NumCPU()=%d; max GOMAXPROCS=%d; ceiling=%.3fx across %d runs (ns/op@32 / ns/op@16)",
		numCPU, maxP, inversionRatioCeiling, stormInversionRuns)
	if maxP < 32 {
		t.Logf("JoinParallel latency ratio: GOMAXPROCS=max=%d < 32; the 16-core to 32-core comparison is unavailable", maxP)
		return
	}

	ratios := make([]float64, stormInversionRuns)
	worstRatio := 0.0
	for run := 0; run < stormInversionRuns; run++ {
		nsAt16 := driveJoinNsPerOp(t, 16)
		nsAt32 := driveJoinNsPerOp(t, 32)
		ratio := float64(nsAt32) / float64(nsAt16)
		ratios[run] = ratio
		if ratio > worstRatio {
			worstRatio = ratio
		}
		t.Logf("JoinParallel latency run %d/%d: ns/op@16c=%d ns/op@32c=%d ratio=%.4fx (ceiling=%.3fx)",
			run+1, stormInversionRuns, nsAt16, nsAt32, ratio, inversionRatioCeiling)
	}
	gateOK := true
	for i, r := range ratios {
		if r > inversionRatioCeiling {
			gateOK = false
			r := r
			t.Errorf("JoinParallel latency run %d: ratio=%.4fx exceeds ceiling %.3fx; 32-core latency is worse than 16-core latency", i+1, r, inversionRatioCeiling)
		}
	}
	t.Logf("JoinParallel latency ratios across %d runs: %.4fx %.4fx %.4fx (ceiling=%.3fx, worst=%.4fx)",
		stormInversionRuns, ratios[0], ratios[1], ratios[2], inversionRatioCeiling, worstRatio)
	if !gateOK {
		t.Fatalf("JoinParallel latency ratio failed: at least one run exceeded %.3fx", inversionRatioCeiling)
	}
	t.Logf("JoinParallel latency ratio passed: all %d runs are at or below %.3fx (worst=%.4fx)", stormInversionRuns, inversionRatioCeiling, worstRatio)
}

// driveJoinNsPerOp runs BenchmarkCRDTEngine_JoinParallel at gomaxprocs and
// returns nanoseconds per operation.
func driveJoinNsPerOp(t *testing.T, gomaxprocs int) int64 {
	t.Helper()
	prior := runtime.GOMAXPROCS(gomaxprocs)
	defer runtime.GOMAXPROCS(prior)

	benchFn := func(b *testing.B) {
		BenchmarkCRDTEngine_JoinParallel(b)
	}
	res := testing.Benchmark(benchFn)
	if res.N == 0 {
		t.Fatalf("JoinParallel latency measurement ran 0 operations at GOMAXPROCS=%d", gomaxprocs)
	}
	return res.NsPerOp()
}

// TestNoZeroGCRegression checks GenerateDelta's zero-allocation contract in
// five runs at GOMAXPROCS=1. The sharded free-list and retired-list paths use
// atomic operations and do not allocate per operation.
//
// AllocsPerOp is the primary signal. testing.Benchmark also reports a small
// framework allocation background, measured here at 0-36 B/op, so bytes are
// allowed up to the same 48 B/op ceiling used by TestDeltaGenZeroGC. That margin
// accommodates the background while still detecting a per-operation engine
// allocation.
func TestNoZeroGCRegression(t *testing.T) {
	if raceEnabled {
		t.Skip("GenerateDelta allocation check: race instrumentation adds allocations; run at GOMAXPROCS=1 without -race")
	}
	prior := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prior)

	const stormBytesCeiling = 48
	const runs = 5
	for r := 0; r < runs; r++ {
		allocs, bytes := measureGenerateDeltaAllocs(t)
		if allocs != 0 {
			t.Errorf("GenerateDelta allocation run %d/%d: got %d allocs/op, want 0", r+1, runs, allocs)
		}
		if bytes > stormBytesCeiling {
			t.Errorf("GenerateDelta allocation run %d/%d: got %d B/op, maximum %d including benchmark background", r+1, runs, bytes, stormBytesCeiling)
		}
	}
	if t.Failed() {
		t.Fatalf("GenerateDelta allocation check failed")
	}
	t.Logf("GenerateDelta allocation check passed: %d/%d runs report 0 allocs/op and at most %d B/op", runs, runs, stormBytesCeiling)
}

// measureGenerateDeltaAllocs measures GenerateDelta and Release with
// testing.Benchmark after loading 1,000 entries and warming the free-lists.
func measureGenerateDeltaAllocs(t *testing.T) (allocs int64, bytes int64) {
	t.Helper()
	benchFn := func(b *testing.B) {
		oldDir := DataDir
		b.Cleanup(func() { DataDir = oldDir })
		DataDir = b.TempDir()

		engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, 64*1024*1024)
		if err != nil {
			b.Fatalf("NewDeltaCRDTEngine: %v", err)
		}
		b.Cleanup(func() { _ = engine.Close() })
		for i := 0; i < 1000; i++ {
			engine.InsertLocal("e"+itoaLocal(i), CRDTEntry{SystemTime: int64(i)})
		}
		emptyDigest := NewIBLT(1024, 4)
		// Populate the free-lists before measuring allocations.
		for w := 0; w < 64; w++ {
			dW := engine.GenerateDelta(emptyDigest)
			dW.Release()
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			d := engine.GenerateDelta(emptyDigest)
			d.Release()
		}
	}
	res := testing.Benchmark(benchFn)
	return res.AllocsPerOp(), res.AllocedBytesPerOp()
}

// itoaLocal formats an integer without importing strconv in this test file.
func itoaLocal(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := 20
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + (i % 10))
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
