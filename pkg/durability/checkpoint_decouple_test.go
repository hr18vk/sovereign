// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// These tests cover the asynchronous checkpoint runner. A stalled image flush
// must not block a committing write; Close must drain in-flight and pending
// checkpoints; and tests must wait for that drain before counting WAL anchors.
//
// SetUploadHookForTest parks the image or index upload. The WAL sync hook is
// not interchangeable here because it stalls the 0x05 anchor rather than the
// image write. Inline scheduling and an early WAL close provide negative
// controls for the asynchronous and drain behavior.

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestDecoupleCommitNotBlockedByFlush parks an image or index upload and checks
// that PutLocal returns while the upload remains stalled. Checkpoints bound
// replay work but are not part of the mutation's durability acknowledgement.
// The inline negative control must block under the same conditions, showing
// that the asynchronous runner is responsible for the result.
func TestDecoupleCommitNotBlockedByFlush(t *testing.T) {
	// run parks the first image or index upload and reports whether PutLocal
	// returns before the upload is released. inline selects synchronous
	// scheduling.
	run := func(t *testing.T, inline bool) (returnedWhileParked bool) {
		walPath := filepath.Join(t.TempDir(), "decouple.wal")
		lfs := newSnapshotStore(t)
		live := newLiveBridge(t, walPath, 1) // K=1: one Put designates a checkpoint
		live.SetSnapshotter(lfs, true)       // recovery image + Arrow index (the flush)
		if inline {
			live.debugInlineCheckpoint.Store(true) // negative control: schedule the checkpoint inline
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

		// Wait until the checkpoint's upload is in flight before observing
		// PutLocal.
		select {
		case <-uploadStarted:
		case <-time.After(10 * time.Second):
			t.Fatalf("inline=%v: checkpoint flush never reached the upload", inline)
		}
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
			t.Fatal("PutLocal blocked behind the parked checkpoint flush; asynchronous scheduling must keep it off the commit path")
		}
	})
	t.Run("InlineNegativeControl", func(t *testing.T) {
		if run(t, true) {
			t.Fatal("inline negative control: PutLocal returned despite the parked flush, so the test did not exercise the coupling")
		}
	})
}

// TestDecoupleFlushCompletesAndIsDurable releases a parked upload and requires
// the checkpoint runner to finish both its WAL anchor and recovery image.
// Asynchronous scheduling defers the flush without dropping it.
func TestDecoupleFlushCompletesAndIsDurable(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "decouple-durable.wal")
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

	// The anchor landed and the image was written (the flush completed).
	if got := countCheckpoints(t, walPath); got != 1 {
		t.Fatalf("anchor count = %d, want 1 (the decoupled checkpoint must still append its 0x05 anchor)", got)
	}
	wm := live.Engine().LamportCounter()
	exists, err := lfs.SnapshotExists(context.Background(), wm)
	if err != nil {
		t.Fatalf("SnapshotExists: %v", err)
	}
	if !exists {
		t.Fatalf("recovery image missing at ckpt/%d — the decoupled flush did not complete after the park released", wm)
	}
}

// TestCloseDrainsCheckpointRunner parks one checkpoint with another pending,
// then calls Close. Close must wait for both and leave two WAL anchors before
// closing the WAL and engine. Waiting also prevents checkpoint access to closed
// resources.
//
// ClosedWalLosesPendingCheckpoint is the negative control: it closes the WAL
// early but leaves the engine open, isolating anchor loss from memory safety.
// Only the first anchor survives in that run.
func TestCloseDrainsCheckpointRunner(t *testing.T) {
	// setup configures K=1 and drives two checkpoints. The first parks after its
	// 0x05 anchor is durable; the second remains pending behind the runner.
	setup := func(t *testing.T) (live *Bridge, walPath string, parked chan struct{}) {
		walPath = filepath.Join(t.TempDir(), "close-drain.wal")
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
			t.Fatal("Close returned while a checkpoint was in flight; it must drain before releasing resources")
		case <-time.After(500 * time.Millisecond):
		}
		close(parked) // release checkpoint 1
		select {
		case <-closeReturned:
		case <-time.After(10 * time.Second):
			t.Fatal("Close did not return after the checkpoint was released")
		}
		// Both anchors must be durable before Close releases the WAL.
		if got := countCheckpoints(t, walPath); got != 2 {
			t.Fatalf("anchor count = %d, want 2 (the drain must run the in-flight and the pending checkpoint before the WAL close)", got)
		}
	})

	t.Run("ClosedWalLosesPendingCheckpoint", func(t *testing.T) {
		live, walPath, parked := setup(t)
		// Close the WAL while checkpoint 2 is pending but leave the engine open,
		// isolating the lost anchor from checkpoint access to freed engine memory.
		if err := live.WAL().Close(); err != nil {
			t.Fatalf("WAL close: %v", err)
		}
		close(parked)              // checkpoint 1 finishes; its anchor is already durable
		live.waitCheckpointsIdle() // checkpoint 2 walks the open engine and appends to the closed WAL
		if got := live.CheckpointErrors(); got < 1 {
			t.Fatalf("checkpoint pending across WAL close did not report an error; CheckpointErrors=%d", got)
		}
		if got := countCheckpoints(t, walPath); got != 1 {
			t.Fatalf("anchor count after early WAL close=%d, want 1 because the pending checkpoint's anchor is lost", got)
		}
	})
}

// TestAsyncCheckpointRequiresDrain parks the first checkpoint with the second
// pending. The WAL contains one anchor before waitCheckpointsIdle and two after
// it, deterministically showing why asynchronous checkpoint tests must drain
// before counting.
func TestAsyncCheckpointRequiresDrain(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "async-drain.wal")
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

	// Checkpoint 1 parks after its 0x05 anchor is durable; checkpoint 2 remains
	// pending behind the busy runner.
	for i := 1; i <= 2; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	<-uploadStarted

	// The second anchor cannot arrive until the first upload is released.
	if got := countCheckpoints(t, walPath); got != 1 {
		t.Fatalf("pre-drain anchor count=%d, want 1 with checkpoint 2 pending", got)
	}

	close(parked)
	live.waitCheckpointsIdle()
	if got := countCheckpoints(t, walPath); got != 2 {
		t.Fatalf("post-drain anchor count=%d, want 2 after both checkpoints complete", got)
	}
}
