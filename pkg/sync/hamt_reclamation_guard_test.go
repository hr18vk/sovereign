// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// BenchmarkHAMT_Set must retire each previous root and advance the EBR epoch
// so its arena reaches steady state instead of exhausting memory. One check
// reads the benchmark and requires both calls in its hot loop. A second check
// runs the same reclamation sequence for a fixed 1,000,000 iterations; this
// exceeds the roughly 500,000 iterations at which an earlier 2 GiB arena run
// without reclamation was exhausted.
//
// The fixed-iteration run is skipped under -race because instrumentation makes
// this sequential loop exceed the test timeout. The source check still runs,
// and concurrent race coverage comes from TestConcurrentInsertLocalRace,
// TestConcurrentJoinRace and TestJoinParallelContentionCurve.

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

// TestHAMTSetReclamationGuard checks the benchmark's reclamation calls and
// exercises the same sequence for a fixed number of iterations.
func TestHAMTSetReclamationGuard(t *testing.T) {
	// Read the benchmark source and require the reclamation pair in its hot
	// loop. The separate runtime drive below cannot detect their removal from
	// the benchmark itself.
	src, err := os.ReadFile(filepath.Join("hamt_test.go"))
	if err != nil {
		t.Fatalf("cannot read hamt_test.go: %v", err)
	}
	benchStart := strings.Index(string(src), "func BenchmarkHAMT_Set(")
	if benchStart < 0 {
		t.Fatalf("BenchmarkHAMT_Set not found in hamt_test.go")
	}
	benchBody := string(src[benchStart:])
	// The reclamation contract: retire the previous *HAMT, then advance the
	// epoch so the three-epoch ring recycles slab offsets.
	retireRE := regexp.MustCompile(`(?m)^\s*arena\.ebr\.Retire\(unsafe\.Pointer\(prev\)\)\s*$`)
	advanceRE := regexp.MustCompile(`(?m)^\s*arena\.ebr\.AdvanceEpoch\(\)\s*$`)
	missing := false
	if !retireRE.MatchString(benchBody) {
		missing = true
		t.Errorf("BenchmarkHAMT_Set is missing " +
			"'arena.ebr.Retire(unsafe.Pointer(prev))' — the EBR reclamation " +
			"contract has regressed; the bench will OOM at ~500K ops")
	}
	if !advanceRE.MatchString(benchBody) {
		missing = true
		t.Errorf("BenchmarkHAMT_Set is missing " +
			"'arena.ebr.AdvanceEpoch()' — the epoch-advance contract has " +
			"regressed; the three-epoch ring cannot recycle slab offsets")
	}
	if missing {
		// Stop after reporting the missing calls. The runtime copy is
		// independent of the benchmark and cannot repair this failure.
		t.Fatalf("static guard failed — see errors above")
	}
	t.Logf("static guard: reclamation pair present in BenchmarkHAMT_Set")

	// Exercise the benchmark's steady-state reclamation sequence directly for
	// 1,000,000 iterations. Passing requires the 2 GiB arena to recycle blocks
	// rather than exhaust its bump allocator. This sequential drive adds no
	// race coverage and is skipped when race instrumentation would make it
	// exceed the test timeout.
	if raceEnabled {
		t.Skip("skipping the fixed-iteration arena drive under -race: " +
			"instrumentation would exceed the test timeout; the source check " +
			"above already passed. The fixed-iteration loop is sequential and " +
			"adds no race coverage. The drive runs without instrumentation; " +
			"concurrent coverage is provided by TestConcurrentInsertLocalRace, " +
			"TestConcurrentJoinRace and TestJoinParallelContentionCurve. " +
			"The allocation-free hot path has a separate race-mode guard in " +
			"physics_test.go.")
	}
	const forcedN = 1_000_000

	arena, err := NewHamtArena(2*1024*1024*1024, NewEBRManager())
	if err != nil {
		t.Fatalf("NewHamtArena: %v", err)
	}
	t.Cleanup(func() {
		if e := arena.Free(); e != nil {
			t.Errorf("arena.Free: %v", e)
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
	t.Logf("forced-N drive (N=%d): arena reached steady state, no OOM", forcedN)
}
