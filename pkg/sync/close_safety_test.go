// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package sync

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// — the engine-level Close-safety guards for:
// the arena/EBR teardown use-after-free (Close munmap'd the arena while
// a reclamation / in-flight Join could still touch it).
// Close never flushed the final Lamport high-water (the cold-start drop
// + the general Close-never-flushes gap).
//
// The MECHANISM (a freed arena's reclamation SIGSEGVs) is proven by
// bug-injection. These guards validate the FIX
// at the engine level, where it lives:
// - the closing-flag makes a post-Close arena access fail LOUD (panic), not a
// silent use-after-free;
// - the EBR Quiesce drains in-flight operations before arena.Free;
// - Close persists lastSavedCounter (the true high-water) before Free.
// ────────────────────────────────────────────────────────────────────────────

func newCloseSafetyEngine(t *testing.T, dir string) *DeltaCRDTEngine {
	t.Helper()
	old := DataDir
	DataDir = dir
	t.Cleanup(func() { DataDir = old })
	eng, err := NewDeltaCRDTEngine([16]byte{0x11}, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	return eng
}

// mustPanic runs f and returns its panic message; if f does NOT panic it
// is a guard failure (the fail-loud flag is missing). NOTE: pre-fix, a
// post-Close Join/InsertLocal SIGSEGVs (a fatal fault, NOT a recoverable panic)
// — so reverting the flag turns this guard RED by crashing the test binary,
// which is exactly the regression surfacing.
func mustPanic(t *testing.T, f func()) (msg string) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Error("post-Close access did NOT panic — the fail-loud flag is missing (silent use-after-free)")
			return
		}
		msg = fmt.Sprint(r)
	}()
	f()
	return ""
}

// a post-Close Join must panic LOUD, never silently touch the freed arena.
func TestJoinAfterClosePanicsFailLoud(t *testing.T) {
	eng := newCloseSafetyEngine(t, t.TempDir())
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	msg := mustPanic(t, func() { eng.Join(CRDTDelta{}) })
	if !strings.Contains(msg, "after Close") {
		t.Fatalf("wrong panic: %v", msg)
	}
}

// a post-Close InsertLocal must panic LOUD (it would CAS onto the freed arena).
func TestInsertLocalAfterClosePanicsFailLoud(t *testing.T) {
	eng := newCloseSafetyEngine(t, t.TempDir())
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	msg := mustPanic(t, func() { eng.InsertLocal("k", CRDTEntry{}) })
	if !strings.Contains(msg, "after Close") {
		t.Fatalf("wrong panic: %v", msg)
	}
}

// a post-Close maybeAdvanceEpoch must NOT run the reclamation (the arena is
// freed). This is the in-flight-Join hole: maybeAdvanceEpoch runs AFTER
// participant.Exit, so the Quiesce participant-drain alone does NOT cover it —
// the Closing() skip inside maybeAdvanceEpoch does. Pre-fix this faults
// (freeRetiredList reads the retired HAMT wrapper in the unmapped arena);
// post-fix the Closing() skip makes it a no-op.
func TestMaybeAdvanceEpochAfterCloseDoesNotReclaim(t *testing.T) {
	eng := newCloseSafetyEngine(t, t.TempDir())
	// Retire several HAMT roots WITHOUT advancing the epoch (the default
	// threshold is 64, so these 8 inserts never trigger a reclamation), leaving
	// retired[0] non-empty at Close.
	for i := 0; i < 8; i++ {
		eng.InsertLocal(fmt.Sprintf("k%d", i), CRDTEntry{DotCounter: uint64(i + 1)})
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Force the reclamation of the retired roots NOW (post-Close, arena freed).
	eng.epochAdvanceThreshold = 0 // every maybeAdvanceEpoch advances an epoch
	for i := 0; i < 4; i++ {
		eng.maybeAdvanceEpoch() // post-fix: Closing() skip (no-op). pre-fix: SIGSEGV.
	}
}

// Close must flush the final Lamport high-water even when the persist
// worker never persisted it (the dropped-persist / crash-before-flush gap).
// We advance lastSavedCounter directly (NO NextDot → the worker is never sent
// the value, so it cannot have persisted it), then Close. The fix's
// persistLamport(lastSavedCounter) writes it; without the fix the file is
// absent and recovery reads 0.
func TestCloseFlushesFinalHighWater(t *testing.T) {
	dir := t.TempDir()
	eng := newCloseSafetyEngine(t, dir)
	eng.lastSavedCounter.Store(1001) // the un-persisted high-water (the gap)
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	eng2 := newCloseSafetyEngine(t, dir) // same dir — recovers whatever Close left
	defer func() { _ = eng2.Close() }()
	if got := eng2.LamportCounter(); got != 1001 {
		t.Fatalf("Close did NOT flush the final high-water: recovered Lamport=%d, want 1001", got)
	}
}

// monotone-flush: a STALE engine's Close must NOT regress the persisted
// high-water. An engine that recoverLamport'd from a different DataDir before
// SetDataDir repointed its write path carries a lastSavedCounter LOWER than the
// file's high-water; a naive Close flush of lastSavedCounter would CLOBBER the
// file (TestDurabilityRoundTrip/Steady caught exactly this regression
// when the flush was first added non-monotonically). The flush must write
// max(lastSavedCounter, persisted).
func TestCloseFlushIsMonotone(t *testing.T) {
	dir := t.TempDir()
	// eng1 drives the high-water to 1001 and persists it to dir.
	eng1 := newCloseSafetyEngine(t, dir)
	for i := 0; i < 1001; i++ {
		eng1.NextDot()
	}
	if err := eng1.Close(); err != nil {
		t.Fatalf("eng1.Close: %v", err)
	}

	// eng2 is STALE w.r.t. dir: it recovers 0 from an empty dir, then is
	// repointed at dir. Its Close flush (lastSavedCounter=0) must NOT regress
	// dir's 1001.
	eng2 := newCloseSafetyEngine(t, t.TempDir()) // recovers 0 from the empty dir
	eng2.SetDataDir(dir)                         // repoint the write path; lastSaved stays 0
	if err := eng2.Close(); err != nil {
		t.Fatalf("eng2.Close: %v", err)
	}

	// dir must STILL read 1001 — the stale flush was monotone-suppressed.
	eng3 := newCloseSafetyEngine(t, dir)
	defer func() { _ = eng3.Close() }()
	if got := eng3.LamportCounter(); got != 1001 {
		t.Fatalf("monotone: a stale engine's Close regressed the persisted high-water: got %d, want 1001", got)
	}
}

// edge (a): a PANICKING post-Close Join/InsertLocal must NOT leak an active
// EBR participant back into the pool — a pooled participant with a stale
// active=true would make the NEXT Quiesce block forever (livelock). The
// reorder's deferred `if !exited { participant.Exit() }` is the guard. This
// guard asserts Quiesce returns promptly after a panicking op; reverting the
// deferred Exit makes it hang (caught by the timeout).
func TestPanicPathDoesNotLeakActiveParticipant(t *testing.T) {
	eng := newCloseSafetyEngine(t, t.TempDir())
	if err := eng.Close(); err != nil { // arms Closing + Quiesces + frees
		t.Fatalf("Close: %v", err)
	}
	// A post-Close Join panics at the Closing check; its deferred cleanup must
	// Exit the participant it Enter'd. (Quiesce reads only Go-heap EBR fields,
	// never the freed arena, so calling it here is safe.)
	mustPanic(t, func() { eng.Join(CRDTDelta{}) })
	mustPanic(t, func() { eng.InsertLocal("k", CRDTEntry{}) })

	done := make(chan struct{})
	go func() { eng.ebr.Quiesce(); close(done) }()
	select {
	case <-done:
		// good: no panicking op leaked an active participant.
	case <-time.After(3 * time.Second):
		t.Fatal("edge (a): a panicking op leaked an active EBR participant — the next Quiesce livelocks (the deferred Exit guard is missing)")
	}
}

// Quiesce: Close must BLOCK until an in-flight arena operation (an active
// EBR participant) drains, THEN complete once it quiesces. This is the
// anti-"Free while a Join holds an arena pointer" guard.
func TestCloseQuiesceWaitsForInFlightParticipant(t *testing.T) {
	eng := newCloseSafetyEngine(t, t.TempDir())

	// Simulate an in-flight arena operation: register + Enter a participant and
	// HOLD it active (do not Exit).
	p := eng.ebr.Register()
	p.Enter(eng.ebr)

	closeReturned := make(chan struct{})
	go func() {
		_ = eng.Close()
		close(closeReturned)
	}()

	// While the participant is active, Close's Quiesce MUST block (a broken
	// Quiesce returns in microseconds; 200ms is far above that).
	select {
	case <-closeReturned:
		t.Fatal("Close returned while a participant was active — Quiesce did not drain the in-flight operation")
	case <-time.After(200 * time.Millisecond):
		// good: Close is blocked on the Quiesce
	}

	// Release the participant → Quiesce unblocks → Close completes.
	p.Exit()
	select {
	case <-closeReturned:
		// good: Close completed after quiescence
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the in-flight participant quiesced (Quiesce livelock)")
	}
}

// Regression: the closing-flag must NOT fire during NORMAL operation — a live
// engine's InsertLocal (which gates on Closing()) and the maybeAdvanceEpoch it
// drives run clean (no false panic), and the written state stays readable.
func TestNormalOperationUnaffected(t *testing.T) {
	eng := newCloseSafetyEngine(t, t.TempDir())
	for i := 0; i < 256; i++ {
		// crosses several epoch-advance thresholds, exercising the live
		// maybeAdvanceEpoch + the Closing() check on the hot path.
		eng.InsertLocal(fmt.Sprintf("k%d", i), CRDTEntry{DotCounter: uint64(i + 1)})
	}
	if got := eng.State().Get("k200"); len(got) == 0 {
		t.Fatal("normal operation broken: an InsertLocal'd entry is not readable")
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
