// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//checkpoint_decouple_test.go — the HALF-A guards (decouple
// the checkpoint flush from the commit path). Three non-vacuous, bug-injection-
// proven guards:
//
//	T-A1 the decouple guard: a parked image flush must NOT block PutLocals.
//	T-A2 the Close-drain guard (I5): Close must wait for an in-flight checkpoint.
//	T-A3 the test-synchrony guard: the drain is load-bearing for the WAL-anchor
// count (without it the async runner reads short).
//
// Every guard carries a NEGATIVE CONTROL / bug-injection so it is falsifiable,
// not a tautology. The park point is the TEST-ONLY LocalFS upload hook
// (SetUploadHookForTest) — the image/index write the register names as the
// stall (the WAL syncHook parks only the 0x05 anchor, NOT the image, so it is
// NOT a substitute).

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestDecoupleCommitNotBlockedByFlush is the decouple guard.
// With the image/index upload PARKED (a slow/blocked flush), the committing
// PutLocal must still return — the checkpoint is a replay-length optimization
// with no business on the durability-ACK path. NEGATIVE CONTROL: with the
// decouple reverted (debugInlineCheckpoint = the pre-inline shape), the
// SAME parked flush DOES block PutLocal — so the guard provably detects the
// coupling it exists to remove.
func TestDecoupleCommitNotBlockedByFlush(t *testing.T) {
	// run parks the FIRST image/index upload and reports whether a PutLocal
	// returns while the park is held. inline selects the pre-decouple shape.
	run := func(t *testing.T, inline bool) (returnedWhileParked bool) {
		walPath := filepath.Join(t.TempDir(), "ta1.wal")
		lfs := newSnapshotStore(t)
		live := newLiveBridge(t, walPath, 1) // K=1: one Put designates a checkpoint
		live.SetSnapshotter(lfs, true)       // recovery image + Arrow index (the flush)
		if inline {
			live.debugInlineCheckpoint.Store(true) // NEGATIVE CONTROL: revert the decouple
		}

		parked := make(chan struct{})        // closed to release the park
		uploadStarted := make(chan struct{}) // closed when the first upload parks
		var once sync.Once
		lfs.SetUploadHookForTest(func() {
			once.Do(func() { close(uploadStarted) })
			<-parked
		})
		defer close(parked) // never leave the background runner parked at teardown

		putReturned := make(chan struct{})
		go func() {
			if _, err := live.PutLocal(utf8EntityID(1), stagedPayload(1), stagedEntry(1)); err != nil {
				t.Errorf("PutLocal: %v", err)
			}
			close(putReturned)
		}()

		// Wait until the checkpoint's flush is actually PARKED (in flight).
		select {
		case <-uploadStarted:
		case <-time.After(10 * time.Second):
			t.Fatalf("inline=%v: checkpoint flush never reached the upload", inline)
		}
		// The flush is now parked. Does the commit return without waiting for it?
		select {
		case <-putReturned:
			returnedWhileParked = true
		case <-time.After(3 * time.Second):
			returnedWhileParked = false
		}
		return returnedWhileParked
	}

	t.Run("Decoupled", func(t *testing.T) {
		if !run(t, false) {
			t.Fatal("DECOUPLE ABSENT: PutLocal blocked behind the parked checkpoint flush — the commit path is still coupled to the flush ")
		}
	})
	t.Run("InlineNegativeControl", func(t *testing.T) {
		if run(t, true) {
			t.Fatal("NEGATIVE CONTROL BROKEN: with the decouple reverted (inline), PutLocal returned despite the parked flush — the guard cannot detect the coupling")
		}
	})
}

// TestDecoupleFlushCompletesAndIsDurable proves the decoupled
// checkpoint still COMPLETES and is DURABLE after the park is released — the
// decouple defers the flush, it does not drop it.
func TestDecoupleFlushCompletesAndIsDurable(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "ta1b.wal")
	lfs := newSnapshotStore(t)
	live := newLiveBridge(t, walPath, 1)
	live.SetSnapshotter(lfs, true)

	parked := make(chan struct{})
	uploadStarted := make(chan struct{})
	var once sync.Once
	lfs.SetUploadHookForTest(func() {
		once.Do(func() { close(uploadStarted) })
		<-parked
	})

	if _, err := live.PutLocal(utf8EntityID(1), stagedPayload(1), stagedEntry(1)); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	<-uploadStarted // the flush is parked mid-write
	close(parked)   // release it
	live.waitCheckpointsIdle()

	// The anchor landed AND the image was written (the flush completed).
	if got := countCheckpoints(t, walPath); got != 1 {
		t.Fatalf("anchor count = %d, want 1 (the decoupled checkpoint must still append its 0x05 anchor)", got)
	}
	wm := live.Engine().LamportCounter()
	exists, err := lfs.SnapshotExists(context.Background(), wm)
	if err != nil {
		t.Fatalf("SnapshotExists: %v", err)
	}
	if !exists {
		t.Fatalf("recovery image missing at ckpt/%d — the decoupled flush did NOT complete after the park released", wm)
	}
}

// TestCloseDrainsCheckpointRunner is the I5 Close-drain guard (the
// lesson). With a checkpoint parked MID-FLUSH and a second PENDING, Close
// must NOT tear down the WAL/engine until both have drained.
//
// NON-VACUOUS: the load-bearing assertion is the post-Close anchor count == 2.
// The PENDING checkpoint (checkpoint 2) only gets its anchor on disk if the
// drain runs it to completion BEFORE Bridge.Close closes the WAL — without the
// drain, wal.Close() lands while checkpoint 2 is still pending and its anchor is
// LOST (count == 1). The "Close does not return while parked" check is a
// secondary observation (the engine Quiesce independently blocks on the
// parked checkpoint's EBR pin); the COUNT is what isolates the drain.
//
// BUG-INJECT (the hazard the drain guards against), demonstrated SAFELY:
// ClosedWalLosesPendingCheckpoint closes the WAL while a checkpoint is still
// pending and shows its anchor is lost. The engine is left OPEN there so the
// pending checkpoint's walk cannot UAF — the drain's unique, isolable value is
// the WAL-close ORDERING, and that is what the bug-inject strips. (Removing the
// drain AND closing the engine under a live checkpoint is the raw UAF: it
// faults the whole test binary with `fatal error: fault`, so it is verified in
// development — flip a skip-drain — not shipped as an always-on crash.)
func TestCloseDrainsCheckpointRunner(t *testing.T) {
	// setup wires a snapshotter-backed bridge at K=1 and drives TWO checkpoints:
	// the first parks mid-flush (its 0x05 anchor is already on disk), the second
	// is PENDING behind the busy runner.
	setup := func(t *testing.T) (live *Bridge, walPath string, parked chan struct{}) {
		walPath = filepath.Join(t.TempDir(), "ta2.wal")
		lfs := newSnapshotStore(t)
		live = newLiveBridge(t, walPath, 1)
		live.SetSnapshotter(lfs, true)
		parked = make(chan struct{})
		uploadStarted := make(chan struct{})
		var once sync.Once
		lfs.SetUploadHookForTest(func() {
			once.Do(func() { close(uploadStarted) })
			<-parked
		})
		for i := 1; i <= 2; i++ {
			if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
				t.Fatalf("PutLocal %d: %v", i, err)
			}
		}
		<-uploadStarted // checkpoint 1 is parked; checkpoint 2 is pending
		return live, walPath, parked
	}

	t.Run("DrainMakesPendingCheckpointDurable", func(t *testing.T) {
		live, walPath, parked := setup(t)
		closeReturned := make(chan struct{})
		go func() { _ = live.Close(); close(closeReturned) }()

		// While checkpoint 1 is parked, Close must not have torn down yet.
		select {
		case <-closeReturned:
			t.Fatal("Close returned while a checkpoint was in flight — the I5 drain is broken (the UAF class)")
		case <-time.After(500 * time.Millisecond):
		}
		close(parked) // release checkpoint 1
		select {
		case <-closeReturned:
		case <-time.After(10 * time.Second):
			t.Fatal("Close did not return after the checkpoint was released")
		}
		// NON-VACUOUS: BOTH anchors durable — the drain ran the in-flight AND the
		// pending checkpoint to completion BEFORE closing the WAL.
		if got := countCheckpoints(t, walPath); got != 2 {
			t.Fatalf("anchor count = %d, want 2 (the drain must run the in-flight AND the pending checkpoint before the WAL close)", got)
		}
	})

	t.Run("ClosedWalLosesPendingCheckpoint", func(t *testing.T) {
		live, walPath, parked := setup(t)
		// THE HAZARD the drain guards against: close the WAL while checkpoint 2
		// is still PENDING. The engine stays OPEN, so checkpoint 2's walk is safe;
		// only the WAL-close ORDERING is stripped — exactly what the drain orders.
		if err := live.WAL().Close(); err != nil {
			t.Fatalf("WAL close: %v", err)
		}
		close(parked)              // checkpoint 1 finishes (its anchor was already durable)
		live.waitCheckpointsIdle() // checkpoint 2 runs: walks the open engine, anchor hits the CLOSED WAL
		if got := live.CheckpointErrors(); got < 1 {
			t.Fatalf("BUG-INJECT VACUOUS: a checkpoint pending across a WAL close did NOT error (CheckpointErrors=%d) — the hazard is not observable", got)
		}
		if got := countCheckpoints(t, walPath); got != 1 {
			t.Fatalf("anchor count after early WAL close = %d, want 1 (checkpoint 2's anchor lost — the I5 drain prevents this by draining BEFORE the WAL close)", got)
		}
	})
}

// TestAsyncCheckpointRequiresDrain is the test-synchrony guard ().
// It proves the drain is LOAD-BEARING for the WAL-anchor count, deterministically
// (no timing race): park checkpoint 1 mid-flush so checkpoint 2 stays PENDING
// behind the busy runner. Reading the WAL WITHOUT draining then yields a SHORT
// count (1, not 2) — exactly the false RED T17/T7 would hit under the decouple.
// After waitCheckpointsIdle the count is exact (2). The pre-drain short count is
// an artifact of ASYNC completion, not an exact-count break — which is precisely
// why T17/T7/T16 now drain before asserting.
func TestAsyncCheckpointRequiresDrain(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "ta3.wal")
	lfs := newSnapshotStore(t)
	live := newLiveBridge(t, walPath, 1)
	live.SetSnapshotter(lfs, true)

	parked := make(chan struct{})
	uploadStarted := make(chan struct{})
	var once sync.Once
	lfs.SetUploadHookForTest(func() {
		once.Do(func() { close(uploadStarted) })
		<-parked
	})

	// Two crossings → two checkpoints. Checkpoint 1 parks mid-flush (its 0x05
	// anchor is already fsync'd, bridge.go:461 precedes the image); checkpoint 2
	// is pending behind the busy runner.
	for i := 1; i <= 2; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	<-uploadStarted // checkpoint 1 parked; checkpoint 2 has NOT run

	// WITHOUT the drain: a SHORT count — the async runner has not appended
	// checkpoint 2's anchor. Deterministic (the park holds checkpoint 2 back).
	if got := countCheckpoints(t, walPath); got != 1 {
		t.Fatalf("pre-drain anchor count = %d, want 1 (checkpoint 2 pending behind the parked checkpoint 1 — async completion made observable)", got)
	}

	close(parked)
	live.waitCheckpointsIdle() // the drain: observe completion before counting
	if got := countCheckpoints(t, walPath); got != 2 {
		t.Fatalf("post-drain anchor count = %d, want 2 (the drain makes async completion observable before the count)", got)
	}
}
