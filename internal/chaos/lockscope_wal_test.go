// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package chaos

// WAL lock-scope tests and controls for unlocked group-commit fsync.
//
// AppendMutations writes records under w.mu and then releases w.mu before
// fsyncing the captured file descriptor via syncFile. Keeping the disk barrier
// outside the mutex prevents concurrent AppendClockAdvance calls on the
// receive path from stalling behind a slow batch fsync.
//
// Each test uses a blocking syncHook so pre- and post-unlock latency differ by
// orders of magnitude: holding w.mu across fsync blocks >= syncBlock (500ms),
// while releasing w.mu before fsync completes in under syncBlock/10 (50ms).
//
// TestWALLockScopeRedControl holds w.mu across w.sync() explicitly to verify
// the timing check detects a mutex-held-across-fsync stall.
//
// Run: go test -run 'TestWALLockScope' -race -count=1 ./internal/chaos/

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// errRiggedSync is the injected fsync failure for the error-contract test.
var errRiggedSync = errors.New("rigged fsync failure")

// syncBlock is how long the rigged fsync blocks. Large enough that the
// pre-fix serialization is unmistakable, small enough to keep the test fast.
const syncBlock = 500 * time.Millisecond

// lockScopeThreshold is the pass/fail line for the concurrent
// AppendClockAdvance latency: 10× below the pre-fix floor (syncBlock) and 10×
// above realistic scheduler noise for one mutex acquire + one small write.
const lockScopeThreshold = syncBlock / 10

// lockScopeMutations builds n distinct WALMutations via NewWALMutation.
func lockScopeMutations(n int) []WALMutation {
	ms := make([]WALMutation, n)
	for i := range ms {
		ms[i] = NewWALMutation("lockscope-key",
			engsync.CausalDot{NodeID: [16]byte{0xD4, 0x1C}, Counter: uint64(i + 1)},
			engsync.CRDTEntry{SystemTime: int64(1_700_000_000 + i)})
	}
	return ms
}

// TestWALLockScopeClockAdvanceNotBlockedByFsync verifies that an
// AppendClockAdvance issued while an AppendMutations fsync is in flight
// completes below the threshold because w.mu is released before fsync.
func TestWALLockScopeClockAdvanceNotBlockedByFsync(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "lockscope.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// syncEntered fires when the batch fsync begins after w.mu is released.
	// Only the first fsync blocks so AppendClockAdvance's own syncFile does not
	// sleep for syncBlock; the measured duration isolates wait time on w.mu.
	var blockOnce sync.Once
	syncEntered := make(chan struct{})
	wal.SetSyncHookForTest(func() error {
		blocked := false
		blockOnce.Do(func() {
			blocked = true
			close(syncEntered)
		})
		if blocked {
			time.Sleep(syncBlock)
		}
		return nil
	})

	var wg sync.WaitGroup
	wg.Add(1)
	var appendErr error
	var appendFailIdx int
	go func() {
		defer wg.Done()
		appendFailIdx, appendErr = wal.AppendMutations(lockScopeMutations(64))
	}()

	<-syncEntered // the fsync is in flight; post-fix the mutex is free.
	start := time.Now()
	advErr := wal.AppendClockAdvance(9_693)
	elapsed := time.Since(start)

	wg.Wait()
	if appendErr != nil {
		t.Fatalf("AppendMutations returned err=%v (firstFailIdx=%d) — the batch must succeed; the test measures lock scope, not an error path", appendErr, appendFailIdx)
	}
	if appendFailIdx != -1 {
		t.Fatalf("AppendMutations firstFailIdx=%d, want -1 (whole batch durable)", appendFailIdx)
	}
	if advErr != nil {
		t.Fatalf("AppendClockAdvance returned err=%v — the concurrent clock advance must succeed", advErr)
	}
	if elapsed >= lockScopeThreshold {
		t.Fatalf("AppendClockAdvance took %v while AppendMutations fsync was in flight (threshold %v, syncBlock %v); w.mu must be unlocked before syncFile",
			elapsed, lockScopeThreshold, syncBlock)
	}
	t.Logf("AppendClockAdvance completed in %v during %v AppendMutations fsync (threshold %v, %.0fx headroom)",
		elapsed, syncBlock, lockScopeThreshold, float64(lockScopeThreshold)/float64(max(elapsed, time.Microsecond)))
}

// holdMuAcrossSyncForTest holds w.mu across w.sync() so the control test can
// verify the lock-contention check detects a mutex held during fsync.
func holdMuAcrossSyncForTest(w *WAL) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sync()
}

// TestWALLockScopeRedControl verifies that holding w.mu across fsync blocks a
// concurrent AppendClockAdvance beyond lockScopeThreshold.
func TestWALLockScopeRedControl(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "lockscope-red.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// Only the first fsync blocks so the measured latency isolates mutex wait.
	var blockOnce sync.Once
	syncEntered := make(chan struct{})
	wal.SetSyncHookForTest(func() error {
		blocked := false
		blockOnce.Do(func() {
			blocked = true
			close(syncEntered)
		})
		if blocked {
			time.Sleep(syncBlock)
		}
		return nil
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Hold w.mu across w.sync() explicitly to verify the timing check.
		_ = holdMuAcrossSyncForTest(wal)
	}()

	<-syncEntered // the fsync is in flight with the mutex held.
	start := time.Now()
	_ = wal.AppendClockAdvance(1002)
	elapsed := time.Since(start)
	wg.Wait()

	if elapsed < lockScopeThreshold {
		t.Fatalf("lock-hold control failed: AppendClockAdvance took only %v while w.mu was held across %v fsync (threshold %v)",
			elapsed, syncBlock, lockScopeThreshold)
	}
	t.Logf("lock-hold control passed: AppendClockAdvance blocked %v behind w.mu held across fsync (>= threshold %v)",
		elapsed, lockScopeThreshold)
}

// TestWALLockScopeDurabilityAndOrderingPreserved verifies that unlocked fsync
// preserves the record stream, sequence stamping, and recorded dots.
func TestWALLockScopeDurabilityAndOrderingPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lockscope-order.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	const n = 128
	want := lockScopeMutations(n)
	if idx, err := wal.AppendMutations(want); err != nil || idx != -1 {
		t.Fatalf("AppendMutations: idx=%d err=%v", idx, err)
	}
	// A real fsync ran (no hook installed), so the records are durable. Close +
	// replay: the stream must come back in exactly the written order with the
	// counters intact.
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rep, err := ReplayWAL(path)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != n {
		t.Fatalf("replayed %d mutations, want %d — unlocked fsync must not drop records", len(rep.Mutations), n)
	}
	for i := range want {
		if rep.Mutations[i].Counter != want[i].Counter {
			t.Fatalf("mutation %d: replayed Counter=%d, want %d — ordering broken while unlocked fsync ran",
				i, rep.Mutations[i].Counter, want[i].Counter)
		}
		if rep.Mutations[i].EntityID != want[i].EntityID {
			t.Fatalf("mutation %d: replayed EntityID=%q, want %q", i, rep.Mutations[i].EntityID, want[i].EntityID)
		}
	}
	t.Logf("record stream preserved across unlocked fsync: %d mutations replayed in exact order", n)
}

// TestWALLockScopeSyncErrorStillFailsWholeBatch verifies that a failing
// fsync after unlocking w.mu still reports (-1, err) for the entire batch.
func TestWALLockScopeSyncErrorStillFailsWholeBatch(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "lockscope-err.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	wal.SetSyncHookForTest(func() error { return errRiggedSync })

	idx, err := wal.AppendMutations(lockScopeMutations(8))
	if idx != -1 {
		t.Fatalf("firstFailIdx=%d, want -1 — a sync failure must report the whole batch un-durable", idx)
	}
	if err == nil {
		t.Fatal("AppendMutations returned nil err under failing fsync")
	}
	t.Logf("batch error contract preserved with unlocked fsync: (-1, %v)", err)
}
