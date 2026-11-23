// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// GenerateDelta allocation tests combine source checks with runtime
// measurements. The source checks cover arena-backed IBLTs and shard roots,
// pooled deltas and participant recycling, the sorted send set, and the
// prebuilt Entries closure. The runtime check requires zero allocations per
// operation and bounds benchmark bookkeeping noise in bytes per operation.
//
// TestBumpOffsetStable separately checks slab recycling. Missing RetireBlock
// calls do not necessarily add measured heap allocations, but they cause the
// arena bump offset to grow across repeated GenerateDelta calls. Runtime
// allocation measurements are skipped under the race detector.
package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestDeltaGenZeroGC checks the GenerateDelta source shape and measures its
// steady-state allocations with testing.Benchmark.
func TestDeltaGenZeroGC(t *testing.T) {
	// Check the production source before measuring allocations.
	srcCrdt, err := os.ReadFile(filepath.Join("crdt.go"))
	if err != nil {
		t.Fatalf("zero-GC delta generation test: cannot read crdt.go: %v", err)
	}
	srcIblt, err := os.ReadFile(filepath.Join("iblt.go"))
	if err != nil {
		t.Fatalf("zero-GC delta generation test: cannot read iblt.go: %v", err)
	}
	crdtStr := string(srcCrdt)
	ibltStr := string(srcIblt)

	// (a) NewArenaIBLT constructor signature at iblt.go.
	r1a := regexp.MustCompile(`func NewArenaIBLT\(numBuckets int, k int, seed maphash\.Seed, arena \*HamtArena\) \*IBLT`)
	if !r1a.MatchString(ibltStr) {
		t.Errorf("zero-GC delta generation test: NewArenaIBLT constructor missing or signature changed in iblt.go — the arena-IBLT constructor was reverted; the bucket array heap-alloc regresses to ~10 allocs/op")
	}
	// The sized digest builder clamps the bucket count and allocates localDigest
	// from the arena. GenerateDigestWithSeed supplies the default bucket count.
	if !strings.Contains(crdtStr, "iblt := NewArenaIBLT(ClampIBLTBuckets(numBuckets), 4, seed, e.arena)") {
		t.Errorf("zero-GC delta generation test: the sized digest builder no longer provisions the localDigest via NewArenaIBLT(ClampIBLTBuckets(numBuckets), 4, seed, e.arena) — the localDigest migrated off the arena backing; the 24 KB bucket slab heap-alloc regresses (the fixed 1024 was parameterized, not taken off the arena)")
	}
	// (c) The diff is routed via subtractArena (arena-backed sibling of Subtract).
	if !strings.Contains(crdtStr, "diff := localDigest.subtractArena(remoteDigest, e.arena)") {
		t.Errorf("zero-GC delta generation test: diff IBLT no longer routed via subtractArena — the Subtract heap-call regresses ~2 allocs/op (struct + 24 KB bucket array)")
	}
	// (d) allShardRootsArena provisions the shard-roots *HAMT slice from e.arena.
	if !strings.Contains(crdtStr, "shardRoots, shardRootsOffset := e.allShardRootsArena()") {
		t.Errorf("zero-GC delta generation test: allShardRootsArena no longer provisions the shard-roots *HAMT slice from e.arena — the make([]*HAMT, N) heap alloc regresses")
	}
	// (e) The CRDTDelta is the arena-pooled shape via e.deltaPool.Get().
	if !strings.Contains(crdtStr, "delta := e.deltaPool.Get().(*CRDTDelta)") {
		t.Errorf("zero-GC delta generation test: GenerateDelta no longer arena-pools the returned *CRDTDelta via e.deltaPool.Get() — the &CRDTDelta{} literal heap-alloc regresses 1 alloc/op")
	}
	// The pool builds the Entries closure once; recycling must preserve it.
	if !strings.Contains(crdtStr, "e.deltaPool.New = func() any {") {
		t.Errorf("deltaPool.New is missing; rebuilding the Entries closure per delta adds an allocation")
	}
	// Extract GenerateDelta up to the next top-level function. Older trees used
	// GenerateDeltaStratified as the boundary, so accept either delimiter.
	genDeltaStart := strings.Index(crdtStr, "func (e *DeltaCRDTEngine) GenerateDelta(remoteDigest *IBLT) *CRDTDelta {")
	if genDeltaStart < 0 {
		t.Fatalf("zero-GC delta generation test: cannot locate GenerateDelta(remoteDigest *IBLT) in crdt.go")
	}
	// The stratified variant no longer exists in current source; the next
	// top-level function is the usual delimiter.
	genDeltaEnd := strings.Index(crdtStr[genDeltaStart:], "func (e *DeltaCRDTEngine) GenerateDeltaStratified(")
	if genDeltaEnd < 0 {
		// Use the next top-level function when the older delimiter is absent.
		genDeltaEnd = strings.Index(crdtStr[genDeltaStart+1:], "\nfunc ")
		if genDeltaEnd < 0 {
			t.Fatalf("cannot find a top-level function after GenerateDelta")
		}
	}
	genDeltaBody := crdtStr[genDeltaStart : genDeltaStart+genDeltaEnd]

	// (g) The heap sendMap is gone from the GenerateDelta hot path.
	if strings.Contains(genDeltaBody, "sendMap := make(map[uint64]struct{})") {
		t.Errorf("zero-GC delta generation test: heap sendMap `make(map[uint64]struct{})` re-appeared in GenerateDelta — the ~3 hmap+bucket allocs/op the sorted-slice + sort.Search replacement eliminated")
	}
	// (h) The per-call Seq carrier is gone on the hot path. The earlier
	// code allocated `seqPtr := new(Seq); *seqPtr = func(...){...}; Entries: *seqPtr`.
	// The pool-prebuilt shape writes the closure in deltaPool.New and reads from
	// struct fields, so `*seqPtr =` (the carrier-deref assignment) and the
	// `Entries: *seqPtr` literal must both be absent from the GenerateDelta body.
	// The word form `seqPtr := new(Seq)` may appear in this explanation, so
	// the source checks match the code-use sites instead.
	if strings.Contains(genDeltaBody, "*seqPtr = func(") {
		t.Errorf("zero-GC delta generation test: `*seqPtr = func(` carrier-deref re-appeared in GenerateDelta — the 1-alloc/op residual the pool-prebuilt Entries closure (deltaPool.New) eliminated")
	}
	if strings.Contains(genDeltaBody, "Entries:      *seqPtr") {
		t.Errorf("zero-GC delta generation test: `Entries: *seqPtr` carrier-read re-appeared in the GenerateDelta return literal — the pool-prebuilt shape is `delta := e.deltaPool.Get().(*CRDTDelta)` with Entries pre-set; no carrier literal")
	}
	// (i) The per-call closure re-assignment `delta.Entries = deltaSeq` is
	// gone on the hot path (the pool-prebuilt shape is preserved across recycles).
	if strings.Contains(genDeltaBody, "delta.Entries = deltaSeq") {
		t.Errorf("zero-GC delta generation test: `delta.Entries = deltaSeq` per-call closure re-assignment re-appeared in GenerateDelta — the 1-alloc/op steady-state capture-env regression the pool-prebuilt (deltaPool.New) shape eliminated")
	}
	// (j) Release preserves the arena-backed delta's pre-built Entries
	// closure across recycles (the recycle-guard).
	if !strings.Contains(crdtStr, "if !d.arenaBacked {\n\t\td.Entries = nil\n\t}") {
		t.Errorf("zero-GC delta generation test: Release no longer preserves the arena-pooled *CRDTDelta's pre-built Entries closure (missing the `if !d.arenaBacked { d.Entries = nil }` recycle-guard). The capture-env would be discarded + rebuilt every cycle = 1 alloc/op")
	}
	// (k) Participant-pool-leak fix — Release returns the participant and
	// GenerateDelta hands it the pool pointer.
	if !strings.Contains(crdtStr, "pp.Put(d.ebrPart)") {
		t.Errorf("zero-GC delta generation test: Release no longer puts the participant back to its pool (`pp.Put(d.ebrPart)` missing) — the Exit-only leak regresses to 1 alloc/op once participantPool dries")
	}
	if !strings.Contains(crdtStr, "delta.participantPoolPtr = &e.participantPool") {
		t.Errorf("zero-GC delta generation test: GenerateDelta no longer populates delta.participantPoolPtr = &e.participantPool — Release cannot route the participant back to the engine's pool")
	}

	if t.Failed() {
		t.Fatalf("zero-GC delta generation test: static guard failed — see errors above (the zero-GC shape in crdt.go/iblt.go regressed)")
	}
	t.Logf("zero-GC delta generation test (static): regex pins present in crdt.go/iblt.go")

	// Measure steady-state allocations after the source checks pass. Race
	// instrumentation perturbs the runtime allocator, so skip this portion
	// under -race.
	if raceEnabled {
		t.Skip("runtime allocation counts are not comparable under -race; source checks already ran")
	}

	res := testing.Benchmark(BenchmarkCRDTEngine_GenerateDelta)
	if res.N == 0 {
		t.Fatalf("zero-GC delta generation test: BenchmarkCRDTEngine_GenerateDelta ran 0 ops; the bench harness is broken")
	}
	allocs := res.AllocsPerOp()
	bytes := res.AllocedBytesPerOp()
	t.Logf("zero-GC delta generation test (runtime): BenchmarkCRDTEngine_GenerateDelta-%d  N=%d  ns/op=%d  B/op=%d  allocs/op=%d  (NumCPU=%d)",
		runtime.NumCPU(), res.N, res.NsPerOp(), bytes, allocs, runtime.NumCPU())
	// AllocsPerOp must be zero. AllocedBytesPerOp can include a small amount of
	// benchmark scheduler and sync.Pool bookkeeping even when the engine does
	// not allocate on each operation. The 48-byte ceiling admits that noise but
	// rejects the 80-byte residual produced by rebuilding the Entries closure
	// and the much larger allocation from a heap-backed IBLT.
	const deltaGenBytesCeiling = 48
	if allocs != 0 {
		t.Errorf("GenerateDelta allocated %d objects per operation, want 0", allocs)
	}
	if bytes > deltaGenBytesCeiling {
		t.Errorf("GenerateDelta allocated %d B/op, ceiling %d; check for heap-backed IBLTs or a rebuilt Entries closure", bytes, deltaGenBytesCeiling)
	}
	if t.Failed() {
		t.Fatalf("zero-GC delta generation test: runtime zero-allocation gate failed — GenerateDelta residual heap escape: allocs/op=%d B/op=%d (ceiling allocs=0, B/op<=48)", allocs, bytes)
	}
	t.Logf("zero-GC delta generation test (runtime): GenerateDelta reads %d B/op and %d allocs/op (the zero-GC gate passes)", bytes, allocs)
}

// TestBumpOffsetStable runs 20,000 GenerateDelta calls after warmup and bounds
// growth of the arena bump offset. Missing RetireBlock or ReleaseLocal calls
// leave slabs unavailable for reuse and make the offset grow even when heap
// allocation counts remain zero. The long single-goroutine loop is skipped
// under -race.
func TestBumpOffsetStable(t *testing.T) {
	if raceEnabled {
		t.Skip("skip the long allocation-recycling loop under -race")
	}
	const forcedN = 20_000

	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, benchCRDTEngineArenaSize)
	if err != nil {
		t.Fatalf("zero-GC delta generation test: NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()
	// Seed the same working set as BenchmarkCRDTEngine_GenerateDelta.
	for i := 0; i < 10000; i++ {
		engine.InsertLocal(fmt.Sprintf("entity-%d", i), CRDTEntry{SystemTime: int64(i)})
	}
	emptyDigest := NewIBLT(1024, 4)
	// Warm the pools before recording the baseline offset.
	for w := 0; w < 2048; w++ {
		dW := engine.GenerateDelta(emptyDigest)
		dW.Release()
	}
	// Baseline bump offset after warmup.
	bumpBefore := engine.arena.bumpOffset.Load()

	for i := 0; i < forcedN; i++ {
		d := engine.GenerateDelta(emptyDigest)
		d.Release()
	}
	bumpAfter := engine.arena.bumpOffset.Load()
	growth := uint64(0)
	if bumpAfter > bumpBefore {
		growth = bumpAfter - bumpBefore
	}
	// A missing retire leaks at least one slab per operation. Normal recycling
	// permits a small offset change because retired-list draining lags by three
	// epochs. The 64 MiB ceiling allows that lag and slab fragmentation while
	// detecting sustained slab loss over the 20,000-operation loop.
	const bumpGrowthCeiling = 64 * 1024 * 1024 // 64 MiB
	if growth > bumpGrowthCeiling {
		t.Fatalf("zero-GC delta generation test: arena bump-offset grew %d bytes over %d GenerateDelta ops (baseline=%d, after=%d) — a dropped EBR RetireBlock (the diff IBLT, sendKeys shard-roots, or localDigest slab) leaks the arena monotonically. Restoring the retirees must collapse growth to <64 MiB (the band's recycle noise floor).",
			growth, forcedN, bumpBefore, bumpAfter)
	}
	t.Logf("zero-GC delta generation test: arena bump-offset stable over %d ops: before=%d after=%d growth=%d (< %d ceiling) — the EBR RetireBlock retirees recycle the slabs at steady state",
		forcedN, bumpBefore, bumpAfter, growth, bumpGrowthCeiling)
}
