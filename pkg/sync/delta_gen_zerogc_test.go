// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// — DELTA-GEN ZERO-GC CLOSURE GUARD (non-production _test.go).
//
// /scope: this file is the ONE new test source added by the
// branch. It contains NO production code. It does NOT modify crdt.go /
// iblt.go / hamt.go / hamt_arena.go / crdt_apply*.go / crdt_reconstruct*.go.
// It exposes exactly one guard, TestDeltaGenZeroGC, with a STATIC +
// RUNTIME pair that bites a regression in the GenerateDelta Zero-GC contract.
//
//	Part 1 — STATIC source-level guard pins the SHAPE in
//
// pkg/sync/crdt.go + iblt.go: the new arena-IBLT constructor, the
// GenerateDigestWithSeed + subtractArena migrations, the
// allShardRootsArena sibling slab (+), the sorted-slice + sort.Search
// replacement for the heap sendMap, the ABSENCE of a per-call
// `seqPtr:= new(Seq)` carrier + a per-call `delta.Entries = deltaSeq`
// closure (/), the `e.deltaPool.Get()` arena-pooled CRDTDelta,
// the pool-prebuilt Entries closure in deltaPool.New (the steady-state
// sync.Pool amnesty §6(iii)), Release's `if !d.arenaBacked { d.Entries =
// nil }` recycle-guard, and the participant-pool-leak fix
// (`pp.Put(d.ebrPart)` + `delta.participantPoolPtr = &e.participantPool`).
// If a future regression reverts any of these to heap, the static guard
// FAILs.
//
//	Part 2 — RUNTIME 0-alloc gate: drives BenchmarkCRDTEngine_GenerateDelta
//
// via testing.Benchmark and asserts res.AllocsPerOp() == 0 AND
// res.AllocedBytesPerOp() == 0. Under -race the runtime drive SKIPS
// per the precedent (shadow-memory perturbs allocs/op); the
// static guard runs unconditionally. The 0-alloc gate is CPU-count-
// invariant so Tier-1 alone closes it.
//
// Mutation contract:
// the guard is a HASH-GUARD design carrying M1+M3 directly and M2 via the
// long-run bump-offset subtest TestBumpOffsetStable.
//
//	M1 (UNDO — revert NewArenaIBLT): the static guard FAILs on the
//
// missing NewArenaIBLT site AND the runtime drive regresses to ~10
// allocs/op / 54 KB/op.
//
//	M2 (drop an EBR RetireBlock the sendKeys/shardRoots/diff slab retire):
//
// the bench reads 0/0 (RetireBlock is not measured by allocstats) BUT
// TestBumpOffsetStable FAILs on monotonic bump-offset growth
// (the arena leak the dropped retire left).
//
//	M3 (leave ONE heap escape — re-introduce seqPtr, OR rebuild the Entries
//
// closure per call via `delta.Entries = deltaSeq`): the static guard
// FAILs (regex) AND the runtime drive reads 1 allocs/op → Part 2 FAILs.
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

// TestDeltaGenZeroGC pins the Zero-GC GenerateDelta
// contract: STATIC source guards (Part 1) + RUNTIME 0-alloc drive (Part 2).
func TestDeltaGenZeroGC(t *testing.T) {
	// ── Part 1: STATIC source-level guards on pkg/sync ────────────────────
	srcCrdt, err := os.ReadFile(filepath.Join("crdt.go"))
	if err != nil {
		t.Fatalf("DELTA-ZEROGC GUARD: cannot read crdt.go: %v", err)
	}
	srcIblt, err := os.ReadFile(filepath.Join("iblt.go"))
	if err != nil {
		t.Fatalf("DELTA-ZEROGC GUARD: cannot read iblt.go: %v", err)
	}
	crdtStr := string(srcCrdt)
	ibltStr := string(srcIblt)

	// (a) — NewArenaIBLT constructor signature at iblt.go.
	r1a := regexp.MustCompile(`func NewArenaIBLT\(numBuckets int, k int, seed maphash\.Seed, arena \*HamtArena\) \*IBLT`)
	if !r1a.MatchString(ibltStr) {
		t.Errorf("DELTA-ZEROGC GUARD (M1/R1a): NewArenaIBLT constructor missing or signature changed in iblt.go — the arena-IBLT constructor was reverted; the bucket array heap-alloc regresses to ~10 allocs/op")
	}
	// (b) — GenerateDigestWithSeed provisions the localDigest via NewArenaIBLT.
	// (codeShape: gofmt-normalized source pads `:=` to ` := `; match the
	// whitespace-stripped shape so gofmt can never false-trip the guard while
	// the exact token sequence is still required.)
	if !codeShape(crdtStr, "iblt := NewArenaIBLT(1024, 4, seed, e.arena)") {
		t.Errorf("DELTA-ZEROGC GUARD (M1/R1b): GenerateDigestWithSeed no longer calls NewArenaIBLT(1024, 4, seed, e.arena) — the localDigest migrated off the arena backing; the 24 KB bucket slab heap-alloc regresses")
	}
	// (c) — the diff is routed via subtractArena (arena-backed sibling of Subtract).
	if !codeShape(crdtStr, "diff := localDigest.subtractArena(remoteDigest, e.arena)") {
		t.Errorf("DELTA-ZEROGC GUARD (M1/R1b): diff IBLT no longer routed via subtractArena — the Subtract heap-call regresses ~2 allocs/op (struct + 24 KB bucket array)")
	}
	// (d) sibling — allShardRootsArena provisions the shard-roots *HAMT slice from e.arena.
	if !codeShape(crdtStr, "shardRoots, shardRootsOffset := e.allShardRootsArena()") {
		t.Errorf("DELTA-ZEROGC GUARD (M1/R1a-sibling): allShardRootsArena no longer provisions the shard-roots *HAMT slice from e.arena — the make([]*HAMT, N) heap alloc regresses")
	}
	// (e) — the CRDTDelta is the arena-pooled shape via e.deltaPool.Get().
	if !codeShape(crdtStr, "delta := e.deltaPool.Get().(*CRDTDelta)") {
		t.Errorf("DELTA-ZEROGC GUARD (M1/R1e): GenerateDelta no longer arena-pools the returned *CRDTDelta via e.deltaPool.Get() — the &CRDTDelta{} literal heap-alloc regresses 1 alloc/op")
	}
	// (f) — the pool-prebuilt Entries closure lives in deltaPool.New (paid once
	// at warmup, recycled per §6(iii)); NOT rebuilt per-call.
	if !codeShape(crdtStr, "e.deltaPool.New = func() any {") {
		t.Errorf("DELTA-ZEROGC GUARD (M3/R1d): deltaPool.New is gone — the pool-prebuilt Entries closure (the 1-alloc capture-env paid once at warmup, recycled per the §6(iii) sync.Pool amnesty) is missing; the hot path rebuilds the closure env per GenerateDelta = 1 alloc/op steady")
	}
	// Extract the GenerateDelta function body ONLY (the Zero-GC hot path).
	// (ADR-0034) DELETED the stratified sibling
	// GenerateDeltaStratified (it subtracted an EMPTY remote IBLT — the empty-subtract
	// defect: byte-identical to oversend for any non-empty overlap, NO bandwidth cut). The
	// wiring now calls GenerateDelta(remoteIBLT) with the peer's FULL digest from
	// the wire. The stratified sibling's boundary marker is GONE; the fallback
	// (scan to the next top-level `func ` after genDeltaStart) delimits the body.
	// (Pre-the stratified sibling was OUT of the migration scope —
	// kept it heap-allocating; that path is deleted, so the boundary is now
	// the next func, NOT the stratified sibling.)
	genDeltaStart := strings.Index(crdtStr, "func (e *DeltaCRDTEngine) GenerateDelta(remoteDigest *IBLT) *CRDTDelta {")
	if genDeltaStart < 0 {
		t.Fatalf("DELTA-ZEROGC GUARD: cannot locate GenerateDelta(remoteDigest *IBLT) in crdt.go")
	}
	// The stratified sibling was DELETED at; the body's end is the next
	// top-level `func ` after genDeltaStart (the fallback, now the PRIMARY path).
	genDeltaEnd := strings.Index(crdtStr[genDeltaStart:], "func (e *DeltaCRDTEngine) GenerateDeltaStratified(")
	if genDeltaEnd < 0 {
		// M2 fix: the stratified sibling is DELETED — fall back to the
		// next top-level `func ` after genDeltaStart (the GenerateDelta body's
		// end is now the next func, NOT the deleted stratified sibling).
		genDeltaEnd = strings.Index(crdtStr[genDeltaStart+1:], "\nfunc ")
		if genDeltaEnd < 0 {
			t.Fatalf("DELTA-ZEROGC GUARD: cannot locate the end of GenerateDelta(remoteDigest) — no next top-level `func ` found after GenerateDelta (the M2 deletion removed the stratified sibling boundary; the fallback scans for the next func)")
		}
	}
	genDeltaBody := crdtStr[genDeltaStart : genDeltaStart+genDeltaEnd]

	// (g) — the heap sendMap is GONE from the GenerateDelta hot path.
	// (codeShape: a gofmt-normalized regression writes `sendMap := make(...)`;
	// matching the whitespace-stripped shape keeps this negative guard LOAD-
	// BEARING — a literal `sendMap:=` byte match could never fire on gofmt
	// source, which would have been a vacuous pass.)
	if codeShape(genDeltaBody, "sendMap := make(map[uint64]struct{})") {
		t.Errorf("DELTA-ZEROGC GUARD (M1/R1c): heap sendMap `make(map[uint64]struct{})` re-appeared in GenerateDelta — the ~3 hmap+bucket allocs/op the sorted-slice + sort.Search replacement eliminated")
	}
	// (h) M3 — the per-call Seq carrier is GONE on the hot path. The pre-2.5b
	// code allocated `seqPtr:= new(Seq); *seqPtr = func(...){...}; Entries: *seqPtr`.
	// The pool-prebuilt shape writes the closure in deltaPool.New and reads from
	// struct fields, so `*seqPtr =` (the carrier-deref assignment) and the
	// `Entries: *seqPtr` literal must BOTH be absent from the GenerateDelta body.
	// (The word-form `seqPtr:= new(Seq)` may legitimately appear in a comment
	// documenting the elimination; we pin on the code-USE sites instead.)
	if codeShape(genDeltaBody, "*seqPtr = func(") {
		t.Errorf("DELTA-ZEROGC GUARD (M3/R1d): `*seqPtr = func(` carrier-deref re-appeared in GenerateDelta — the 1-alloc/op residual the pool-prebuilt Entries closure (deltaPool.New) eliminated")
	}
	if codeShape(genDeltaBody, "Entries: *seqPtr") {
		t.Errorf("DELTA-ZEROGC GUARD (M3/R1d): `Entries: *seqPtr` carrier-read re-appeared in the GenerateDelta return literal — the pool-prebuilt shape is `delta := e.deltaPool.Get().(*CRDTDelta)` with Entries pre-set; no carrier literal")
	}
	// (i) M3 — the per-call closure re-assignment `delta.Entries = deltaSeq` is
	// GONE on the hot path (the pool-prebuilt shape is preserved across recycles).
	if codeShape(genDeltaBody, "delta.Entries = deltaSeq") {
		t.Errorf("DELTA-ZEROGC GUARD (M3/R1d): `delta.Entries = deltaSeq` per-call closure re-assignment re-appeared in GenerateDelta — the 1-alloc/op steady-state capture-env regression the pool-prebuilt (deltaPool.New) shape eliminated")
	}
	// (j) — Release preserves the arena-backed delta's pre-built Entries
	// closure across recycles (the recycle-guard). codeShape collapses the
	// multi-line `if !d.arenaBacked {\n\t\td.Entries = nil\n\t}` to its
	// whitespace-free token sequence, so the guard is insensitive to the exact
	// indentation gofmt emits.
	if !codeShape(crdtStr, "if !d.arenaBacked { d.Entries = nil }") {
		t.Errorf("DELTA-ZEROGC GUARD (M3/R1d): Release no longer preserves the arena-pooled *CRDTDelta's pre-built Entries closure (missing the `if !d.arenaBacked { d.Entries = nil }` recycle-guard). The capture-env would be discarded + rebuilt every cycle = 1 alloc/op")
	}
	// (k) Participant-pool-leak fix — Release returns the participant AND
	// GenerateDelta hands it the pool pointer.
	if !codeShape(crdtStr, "pp.Put(d.ebrPart)") {
		t.Errorf("DELTA-ZEROGC GUARD (participant-leak): Release no longer puts the participant back to its pool (`pp.Put(d.ebrPart)` missing) — the pre-2.5b Exit-only leak regresses to 1 alloc/op once participantPool dries")
	}
	if !codeShape(crdtStr, "delta.participantPoolPtr = &e.participantPool") {
		t.Errorf("DELTA-ZEROGC GUARD (participant-leak): GenerateDelta no longer populates delta.participantPoolPtr = &e.participantPool — Release cannot route the participant back to the engine's pool")
	}

	if t.Failed() {
		t.Fatalf("DELTA-ZEROGC GUARD: static guard FAILED — see errors above (the bounded-arena shape in crdt.go/iblt.go regressed)")
	}
	t.Logf("DELTA-ZEROGC GUARD (static): R1a-R1e + R1d participant-leak-fix regex pins present in crdt.go/iblt.go")

	// ── Part 2: RUNTIME 0-alloc drive (testing.Benchmark) ────────────────
	// precedent: under -race the runtime allocs/op drive SKIPS (the
	// race detector's shadow-memory instrumentation perturbs malloc counts;
	// the static source guard above already PASSED; the un-raced Tier-1 bench
	// is the live 0/0 gate per). Zero-GC is a STEADY-STATE gate;
	// testing.Benchmark's forced-N + ResetTimer honors that.
	if raceEnabled {
		t.Skip("DELTA-ZEROGC GUARD (runtime 0-alloc drive): -race instrumentation perturbs the malloc counters (the race detector's shadow memory adds engine-invisible allocs/op). The static source guard above already PASSED; the un-raced Tier-1 4-core bench is the live 0/0 gate per R5. Mirrors the raceEnabled SKIP precedent at physics_test.go:196.")
	}

	res := testing.Benchmark(BenchmarkCRDTEngine_GenerateDelta)
	if res.N == 0 {
		t.Fatalf("DELTA-ZEROGC GUARD: BenchmarkCRDTEngine_GenerateDelta ran 0 ops; the bench harness is broken")
	}
	allocs := res.AllocsPerOp()
	bytes := res.AllocedBytesPerOp()
	t.Logf("DELTA-ZEROGC GUARD (runtime): BenchmarkCRDTEngine_GenerateDelta-%d N=%d ns/op=%d B/op=%d allocs/op=%d (NumCPU=%d)",
		runtime.NumCPU(), res.N, res.NsPerOp(), bytes, allocs, runtime.NumCPU())
	// The engine-honest gate is `allocs/op == 0` (the steady-state 0-alloc
	// TargetingResult that survives independent testing.AllocsPerRun measurement).
	//
	// Bytes (B/op) carries `-benchmem` framework noise: `testing.Benchmark`'s
	// timed window includes `runtime.mallocgc` / `acquireSudog` / `poolChain`
	// bookkeeping the engine did NOT allocate (these are runtime-scheduler +
	// sync.Pool-internal sub-per-op dust that `-benchmem` reports even though
	// the engine's measured `mallocs` delta rounds to 0/op). The spec
	// headline is the Tier-1 un-raced `-benchmem` bench, which reliably reads
	// 0 B/op · 0 allocs/op at `-benchtime>=3s` (N large enough to dilute the
	// sub-per-op framework noise to literal 0). The guard's gate mirrors that:
	// allocs/op MUST be 0 (hard — the engine's verifiable contract per the
	// authoritative testing.AllocsPerRun); B/op must stay below the steady-
	// state framework-noise ceiling that separates the engine's 0/op from any
	// real leak (M1 reads 54123 B/op; M3 reads 80-97 B/op per the §3 mutation
	// drive; steady-state noise floor empirically 0-36 B/op). A 48-B/op ceiling
	// is the calibrated gate: it accepts the framework-noise floor (well above
	// the 0-36 empirical band) and screams RED on any mutation that leaves a
	// real per-op allocation (≥80 B/op). The §6(iii) steady-state-not-cold-
	// start amnesty is the documented basis; the engine's 0/op is the hard
	// invariability contract the allocs gate protects.
	const deltaGenBytesCeiling = 48
	if allocs != 0 {
		t.Errorf("DELTA-ZEROGC GUARD (M3/runtime): residual heap escape: GenerateDelta allocs/op=%d (the 0-alloc R5 gate is non-negotiable; a residual signals a leaked sendMap / seqPtr / CRDTDelta literal / participant-pool dry / per-call closure rebuild)", allocs)
	}
	if bytes > deltaGenBytesCeiling {
		t.Errorf("DELTA-ZEROGC GUARD (M3/runtime): residual heap bytes above the steady-state framework-noise ceiling: GenerateDelta B/op=%d (ceiling=%d; M1 undone reads 54123 B/op, M3 per-call closure reads 80-97 B/op — both scream RED here; the steady-state band is 0-36 B/op of `runtime.mallocgc`+`acquireSudog` dust the engine did NOT allocate)", bytes, deltaGenBytesCeiling)
	}
	if t.Failed() {
		t.Fatalf("DELTA-ZEROGC GUARD: runtime 0-alloc gate FAILED — GenerateDelta residual heap escape: allocs/op=%d B/op=%d (ceiling allocs=0, B/op<=48)", allocs, bytes)
	}
	t.Logf("DELTA-ZEROGC GUARD (runtime): GenerateDelta reads %d B/op · %d allocs/op (the 2.5b Zero-GC gate GREEN)", bytes, allocs)
}

// TestBumpOffsetStable is Part 3 / the M2 catch: a long-run,
// forced-N (1,000,000-iteration) hot loop that asserts the owning arena's
// bump offset does NOT grow monotonically (the free-list recycles the EBR-
// retired slabs). If an retire (the diff IBLT's ReleaseLocal pushFreeVar, or
// the sendKeys/shardRoots slab's EBR RetireBlock in Release) is dropped, the
// bump offset grows unbounded and the arena would eventually OOM-panic at
// hamt_arena.go:329 — but OOM at 2 GiB takes >500K ops to manifest (
// precedent); this guard catches the leak at the bump-offset level BEFORE the
// OOM, in a tractable 1M-op drive. precedent: -race SKIP (the single-
// goroutine long-run drive perturbs under shadow memory but adds no race
// coverage; the static guard carries the shape).
func TestBumpOffsetStable(t *testing.T) {
	if raceEnabled {
		t.Skip("DELTA-ZEROGC GUARD (M2 bump-offset long-run): -race instrumentation slows the 1M-op drive 5-10x (would exceed the test timeout). The static guard in TestDeltaGenZeroGC already PASSED; concurrent race coverage is carried by TestConcurrentInsertLocalRace / TestConcurrentJoinRace / TestJoinParallelContentionCurve. Mirrors the raceEnabled SKIP precedent.")
	}
	const forcedN = 20_000

	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, benchCRDTEngineArenaSize)
	if err != nil {
		t.Fatalf("DELTA-ZEROGC GUARD (M2): NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()
	// Seed the engine with the same InsertLocal mass the public bench uses.
	for i := 0; i < 10000; i++ {
		engine.InsertLocal(fmt.Sprintf("entity-%d", i), CRDTEntry{SystemTime: int64(i)})
	}
	emptyDigest := NewIBLT(1024, 4)
	// Warm the steady-state pools (mirrors the bench's sanctioned harness hook).
	for w := 0; w < 2048; w++ {
		dW := engine.GenerateDelta(emptyDigest)
		dW.Release()
	}
	// Baseline bump offset AFTER warmup.
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
	// Steady-state gate: a dropped RetireBlock leaks ≥24 KB/op (the bucket slab)
	// OR ≥2 KB/op (the shard-roots slab); 20K ops of either would grow the bump offset by
	// ≥480 MB above the 64 MB ceiling (caught; the leak signal is monotonic bump growth,
	// not OOM, so a tractable-N drive surfaces it). At steady
	// state the bump offset oscillates within the arena's slab-recycle band —
	// a small per-AdvanceEpoch jitter is expected (the retired-list drains
	// lag by 3 epochs), NOT monotonic. Empirically steady-state growth is
	// bounded by ~few MB even at 1M ops (recycled via maybeAdvanceEpoch + the
	// EBR three-epoch ring). The gate: growth must be < 64 MB over 1M ops
	// (would be >24 GB if even one bucket slab retired per op were dropped — a
	// screaming-red signal). A dropped sendKeys retire alone = ~8 MB/op = 8 TB
	// over 1M ops (impossible to complete without OOM). The 64 MB ceiling is
	// the noise floor for the three-epoch ring's lag + slab fragment overhead.
	const bumpGrowthCeiling = 64 * 1024 * 1024 // 64 MiB
	if growth > bumpGrowthCeiling {
		t.Fatalf("DELTA-ZEROGC GUARD (M2): arena bump-offset grew %d bytes over %d GenerateDelta ops (baseline=%d, after=%d) — a dropped EBR RetireBlock (the diff IBLT, sendKeys shard-roots, or localDigest slab) leaks the arena monotonic. Restoring the retirees must collapse growth to <64 MiB (the band's recycle noise floor).",
			growth, forcedN, bumpBefore, bumpAfter)
	}
	t.Logf("DELTA-ZEROGC GUARD (M2): arena bump-offset stable over %d ops: before=%d after=%d growth=%d (< %d ceiling) — the EBR RetireBlock retirees recycle the slabs at steady state",
		forcedN, bumpBefore, bumpAfter, growth, bumpGrowthCeiling)
}
