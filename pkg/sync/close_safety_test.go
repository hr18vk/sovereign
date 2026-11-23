// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Close must not unmap the arena while reclamation or an in-flight Join can
// still access it. It must also persist the final Lamport high-water, including
// when the persistence worker has not received that value.
//
// These tests cover the engine-level shutdown contract:
//   - operations after Close panic instead of accessing the freed arena;
//   - EBR quiescence drains in-flight operations before arena.Free;
//   - Close persists lastSavedCounter before freeing the arena.

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

// mustPanic runs f and returns its panic message. A missing panic means the
// closing check did not reject the operation. Without that check, Join and
// InsertLocal can fault while accessing the unmapped arena rather than return a
// recoverable panic.
func mustPanic(t *testing.T, f func()) (msg string) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Error("post-Close access did not panic; the operation could access freed arena memory")
			return
		}
		msg = fmt.Sprint(r)
	}()
	f()
	return ""
}

// TestJoinAfterClosePanicsFailLoud verifies that Join rejects a closed engine
// before it can access the freed arena.
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

// TestInsertLocalAfterClosePanicsFailLoud covers the same closing check on the
// local write path.
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

// TestMaybeAdvanceEpochAfterCloseDoesNotReclaim covers the epoch-advance call
// that follows participant.Exit in Join. Quiesce cannot cover that interval;
// maybeAdvanceEpoch must check Closing before reclaiming retired roots from the
// unmapped arena.
func TestMaybeAdvanceEpochAfterCloseDoesNotReclaim(t *testing.T) {
	eng := newCloseSafetyEngine(t, t.TempDir())
	// Eight inserts stay below the default epoch-advance threshold of 64,
	// leaving retired roots for Close to handle.
	for i := 0; i < 8; i++ {
		eng.InsertLocal(fmt.Sprintf("k%d", i), CRDTEntry{DotCounter: uint64(i + 1)})
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Force repeated epoch advances after the arena has been freed. Each call
	// must return at the Closing check instead of reclaiming retired roots.
	eng.epochAdvanceThreshold = 0
	for i := 0; i < 4; i++ {
		eng.maybeAdvanceEpoch()
	}
}

// TestCloseFlushesFinalHighWater stores a Lamport value without calling
// NextDot, so the persistence worker has not received it. Close must persist
// lastSavedCounter itself; otherwise recovery starts again at zero.
func TestCloseFlushesFinalHighWater(t *testing.T) {
	dir := t.TempDir()
	eng := newCloseSafetyEngine(t, dir)
	eng.lastSavedCounter.Store(1001) // value not sent to the persistence worker
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	eng2 := newCloseSafetyEngine(t, dir) // same dir — recovers whatever Close left
	defer func() { _ = eng2.Close() }()
	if got := eng2.LamportCounter(); got != 1001 {
		t.Fatalf("Close did not persist the final high-water: recovered Lamport=%d, want 1001", got)
	}
}

// TestCloseFlushIsMonotone repoints an engine whose lastSavedCounter is lower
// than the high-water already stored in the destination directory. Close must
// write max(lastSavedCounter, persisted), not replace the stored value with the
// stale counter.
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

	// eng2 recovers zero from an empty directory and is then repointed at dir.
	// Its lower lastSavedCounter must not replace dir's value during Close.
	eng2 := newCloseSafetyEngine(t, t.TempDir()) // recovers 0 from the empty dir
	eng2.SetDataDir(dir)                         // repoint the write path; lastSaved stays 0
	if err := eng2.Close(); err != nil {
		t.Fatalf("eng2.Close: %v", err)
	}

	eng3 := newCloseSafetyEngine(t, dir)
	defer func() { _ = eng3.Close() }()
	if got := eng3.LamportCounter(); got != 1001 {
		t.Fatalf("a stale engine's Close regressed the persisted high-water: got %d, want 1001", got)
	}
}

// TestPanicPathDoesNotLeakActiveParticipant verifies that deferred cleanup
// exits the EBR participant when a post-Close operation panics. Returning a
// still-active participant to the pool would make a later Quiesce wait forever.
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
		t.Fatal("Quiesce blocked after a post-Close panic; the operation did not exit its EBR participant")
	}
}

// TestCloseQuiesceWaitsForInFlightParticipant holds an EBR participant active
// while Close runs. Close must wait for that participant before freeing memory
// that an in-flight operation could still access.
func TestCloseQuiesceWaitsForInFlightParticipant(t *testing.T) {
	eng := newCloseSafetyEngine(t, t.TempDir())

	// Register and enter a participant, then keep it active to represent an
	// in-flight arena operation.
	p := eng.ebr.Register()
	p.Enter(eng.ebr)

	closeReturned := make(chan struct{})
	go func() {
		_ = eng.Close()
		close(closeReturned)
	}()

	// A working Quiesce remains blocked beyond this interval while the
	// participant is active.
	select {
	case <-closeReturned:
		t.Fatal("Close returned while a participant was active; Quiesce did not drain the in-flight operation")
	case <-time.After(200 * time.Millisecond):
	}

	p.Exit()
	select {
	case <-closeReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the in-flight participant quiesced")
	}
}

// TestNormalOperationUnaffected confirms that the Closing check does not
// interfere with live writes or epoch advancement, and that written state
// remains readable.
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
