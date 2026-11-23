// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package chaos

// WAL lock-scope regression tests.
//
// During a 100-node NVMe run, the seed's commit_in_flight remained at 1 for more
// than 300 seconds. Its group commit did not return, the quiescence probe did
// not fire, and the run did not meet its convergence objective.
//
// AppendMutations releases w.mu before its fsync, allowing a concurrent
// AppendClockAdvance to proceed. The reverse dependency also matters: when
// AppendClockAdvance held w.mu across fsync, one slow receive-path sync blocked
// the origin's next AppendMutations call at w.mu.Lock. That was a lock-scope
// defect regardless of what caused any particular stall.
//
// These tests exercise the reverse-convoy mechanism and guard against its
// return. They do not establish that the convoy caused the observed 300-second
// stall; distinguishing lock contention from NVMe queueing requires an A/B
// measurement on that hardware. The local test demonstrates the lock dependency,
// not which constraint dominated the fleet run.
//
// The sync hook blocks only the first fsync caller for syncBlock. If the caller
// holds w.mu, the origin's batch waits for at least that interval. Once the
// caller releases the mutex before syncing, the batch can acquire the mutex and
// finish while the first fsync remains blocked.
//
// Run: go test -run 'TestWALReverseConvoy' -race -count=1 ./internal/chaos/

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// TestWALReverseConvoyOriginCommitNotBlockedByReceiveFsync checks the receive
// side of the lock-scope contract. A blocked AppendClockAdvance fsync must not
// prevent the origin's AppendMutations from acquiring w.mu and completing.
func TestWALReverseConvoyOriginCommitNotBlockedByReceiveFsync(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "reverse-convoy-lockscope.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// Block only the first fsync caller. AppendMutations uses the same hook, so an
	// unconditional sleep would measure the batch's own fsync rather than its wait
	// for w.mu. The receive append enters first and closes syncEntered before the
	// batch starts; every later hook call returns immediately.
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

	// Start the receive-path append. Its fsync enters the hook first and sleeps for
	// syncBlock. The batch below measures whether that sleep also holds w.mu.
	var wg sync.WaitGroup
	wg.Add(1)
	var advErr error
	go func() {
		defer wg.Done()
		advErr = wal.AppendClockAdvance(9_999)
	}()

	<-syncEntered // The receive fsync is in flight.
	start := time.Now()
	failIdx, appErr := wal.AppendMutations(lockScopeMutations(64))
	elapsed := time.Since(start)
	wg.Wait()

	if advErr != nil {
		t.Fatalf("AppendClockAdvance err=%v — the receive-path append must succeed; the test measures lock scope, not an error path", advErr)
	}
	if appErr != nil || failIdx != -1 {
		t.Fatalf("AppendMutations idx=%d err=%v — the origin batch must succeed; the test measures lock scope, not an error path", failIdx, appErr)
	}
	if elapsed >= lockScopeThreshold {
		t.Fatalf("origin AppendMutations took %v during a receive-path AppendClockAdvance fsync (threshold %v, injected delay %v); AppendClockAdvance must release w.mu before syncing",
			elapsed, lockScopeThreshold, syncBlock)
	}
	t.Logf("origin AppendMutations completed in %v during a receive-path fsync delayed by %v (threshold %v)",
		elapsed, syncBlock, lockScopeThreshold)
}

// walMixedStreamMutation uses NewWALMutation to build a valid V2 mutation at
// an explicit counter for the mixed-stream test (ADR-0045 §6).
func walMixedStreamMutation(counter uint64) WALMutation {
	return NewWALMutation("mixed-stream-key",
		engsync.CausalDot{NodeID: [16]byte{0xD2, 0x5A}, Counter: counter},
		engsync.CRDTEntry{SystemTime: int64(1_700_000_000 + counter)})
}

// TestWALMixedStreamOrderingPreserved interleaves AppendMutations,
// AppendClockAdvance, AppendMutation, and AppendCheckpoint, then replays the log.
// It checks that every record survives in write order with contiguous sequence
// numbers. Writes and nextSeq increments happen under w.mu; moving only fsync
// outside the critical section cannot reorder the record bytes. Replay restores
// the recorded dots rather than minting new ones (ADR-0045 §4).
func TestWALMixedStreamOrderingPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed-stream-order.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	// Interleave origin group-commits with the receive-path appends. Written seqs:
	//   AppendMutations[c1,c2] -> 0,1
	//   AppendClockAdvance     -> 2
	//   AppendMutation (c3)    -> 3
	//   AppendCheckpoint       -> 4
	//   AppendMutations[c4,c5] -> 5,6
	if idx, err := wal.AppendMutations([]WALMutation{walMixedStreamMutation(1), walMixedStreamMutation(2)}); err != nil || idx != -1 {
		t.Fatalf("AppendMutations#1: idx=%d err=%v", idx, err)
	}
	if err := wal.AppendClockAdvance(1000); err != nil {
		t.Fatalf("AppendClockAdvance: %v", err)
	}
	if err := wal.AppendMutation(walMixedStreamMutation(3)); err != nil {
		t.Fatalf("AppendMutation: %v", err)
	}
	if err := wal.AppendCheckpoint(WALCheckpoint{LamportHigh: 1000}); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if idx, err := wal.AppendMutations([]WALMutation{walMixedStreamMutation(4), walMixedStreamMutation(5)}); err != nil || idx != -1 {
		t.Fatalf("AppendMutations#2: idx=%d err=%v", idx, err)
	}
	// A real fsync ran on every append (no hook), so all 7 records are durable.
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rep, err := ReplayWAL(path)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	// All seven on-disk records are counted by the seq-contiguity check. The
	// checkpoint occupies seq 4 on disk; ReplayWAL records it in FinalCheckpt, not in
	// Ordered (the WALRecCheckpoint cases set FinalCheckpt and append no Ordered
	// entry), so Ordered holds the 5 mutations + the 1 clock-advance = 6 entries.
	const wantRecords = 7
	// ReplayWAL returns an error on any seq gap, so after a successful replay
	// SeqContiguityVerified is always true. The load-bearing check is the record
	// count: a dropped record lowers RecordsVerified. Asserting the flag alone would
	// not catch a missing record.
	if !rep.SeqContiguityVerified || rep.RecordsVerified != wantRecords {
		t.Fatalf("the seq-contiguity check must have run over all %d records (verified=%v n=%d) — a dropped record lowers the count", wantRecords, rep.SeqContiguityVerified, rep.RecordsVerified)
	}
	if !rep.HasCheckpoint || rep.FinalCheckpt.LamportHigh != 1000 {
		t.Fatalf("checkpoint not preserved: HasCheckpoint=%v FinalCheckpt.LamportHigh=%d, want 1000", rep.HasCheckpoint, rep.FinalCheckpt.LamportHigh)
	}

	// The mutation counters must come back in exact written order 1,2,3,4,5 with the
	// clock-advance (value 1000) at Ordered index 2. The Ordered on-disk seqs are
	// [0,1,2,3,5,6] — the gap at 4 is the checkpoint (in FinalCheckpt, not Ordered).
	wantCounters := []uint64{1, 2, 3, 4, 5}
	wantSeqs := []uint64{0, 1, 2, 3, 5, 6}
	if len(rep.Ordered) != len(wantSeqs) {
		t.Fatalf("replayed %d ordered records, want %d (5 mutations + 1 clock-advance; the checkpoint lives in FinalCheckpt)", len(rep.Ordered), len(wantSeqs))
	}
	gotCounters := make([]uint64, 0, len(wantSeqs))
	for i, r := range rep.Ordered {
		if r.Seq != wantSeqs[i] {
			t.Fatalf("Ordered[%d].Seq=%d, want %d — the on-disk seq run must be contiguous and in written order", i, r.Seq, wantSeqs[i])
		}
		switch r.Type {
		case WALRecMutationV2:
			gotCounters = append(gotCounters, r.Mutation.Counter)
		case WALRecClockAdvance:
			if i != 2 || r.Advance != 1000 {
				t.Fatalf("clock-advance at Ordered[%d] Advance=%d, want position 2 value 1000", i, r.Advance)
			}
		default:
			t.Fatalf("unexpected record type 0x%x in Ordered[%d] (checkpoints live in FinalCheckpt, not Ordered)", r.Type, i)
		}
	}
	if len(gotCounters) != len(wantCounters) {
		t.Fatalf("replayed %d mutations, want %d", len(gotCounters), len(wantCounters))
	}
	for i := range wantCounters {
		if gotCounters[i] != wantCounters[i] {
			t.Fatalf("mutation %d: replayed Counter=%d, want %d — ordering broken. The fsync moved out of the lock; the writes + nextSeq++ stayed inside, so the record order must be byte-identical.",
				i, gotCounters[i], wantCounters[i])
		}
	}
	t.Logf("the lock-scope change preserves the mixed stream: all %d on-disk records contiguous (the checkpoint at seq 4 in FinalCheckpt), the %d Ordered records (mutations + clock-advance) in exact written order, none dropped. Only the fsync left the critical section; the ordering floor (write + nextSeq++ under w.mu) did not move.", wantRecords, len(wantSeqs))
}

// TestWALEachAppendPathReleasesLockBeforeFsync drives each of the four append
// methods with a blocked fsync and times a concurrent AppendClockAdvance. Any
// method that holds w.mu while syncing makes the probe wait beyond the threshold;
// releasing the mutex first lets the probe complete.
func TestWALEachAppendPathReleasesLockBeforeFsync(t *testing.T) {
	holders := []struct {
		name   string
		append func(w *WAL) error
	}{
		{"AppendMutations", func(w *WAL) error { _, err := w.AppendMutations(lockScopeMutations(4)); return err }},
		{"AppendMutation", func(w *WAL) error { return w.AppendMutation(lockScopeMutations(1)[0]) }},
		{"AppendCheckpoint", func(w *WAL) error { return w.AppendCheckpoint(WALCheckpoint{LamportHigh: 7}) }},
		{"AppendClockAdvance", func(w *WAL) error { return w.AppendClockAdvance(7) }},
	}
	for _, h := range holders {
		t.Run(h.name, func(t *testing.T) {
			wal, err := OpenWAL(filepath.Join(t.TempDir(), "all-append-paths.wal"))
			if err != nil {
				t.Fatalf("OpenWAL: %v", err)
			}
			t.Cleanup(func() { _ = wal.Close() })
			var blockOnce sync.Once
			syncEntered := make(chan struct{})
			wal.SetSyncHookForTest(func() error {
				blocked := false
				blockOnce.Do(func() { blocked = true; close(syncEntered) })
				if blocked {
					time.Sleep(syncBlock)
				}
				return nil
			})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() { defer wg.Done(); _ = h.append(wal) }()
			<-syncEntered // The holder's fsync is in flight after it releases w.mu.
			start := time.Now()
			advErr := wal.AppendClockAdvance(4242) // the concurrent probe
			elapsed := time.Since(start)
			wg.Wait()
			if advErr != nil {
				t.Fatalf("%s: concurrent AppendClockAdvance err=%v", h.name, advErr)
			}
			if elapsed >= lockScopeThreshold {
				t.Fatalf("%s holds w.mu across its fsync: a concurrent AppendClockAdvance took %v (threshold %v, injected fsync delay %v); the append path must release w.mu before syncing",
					h.name, elapsed, lockScopeThreshold, syncBlock)
			}
			t.Logf("%s releases w.mu before its fsync (concurrent AppendClockAdvance in %v)", h.name, elapsed)
		})
	}
}

// TestWALCloseDoesNotRaceInflightFsync exercises Close while an append is
// syncing after releasing w.mu. Close sets w.f to nil under the mutex, while the
// append continues with its captured file. The append may return nil or a clean
// os.ErrClosed error, but it must not panic or race. Run with -race to check for
// unlocked w.f access.
//
// The hook sleeps for only 10 ms, so the interleaving is bounded and cannot leave
// the test waiting on a channel. This checks file-handle safety; the timing
// contract itself is covered by the lock-scope tests above.
func TestWALCloseDoesNotRaceInflightFsync(t *testing.T) {
	for i := 0; i < 40; i++ {
		wal, err := OpenWAL(filepath.Join(t.TempDir(), "close-inflight-fsync.wal"))
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		var once sync.Once
		entered := make(chan struct{})
		wal.SetSyncHookForTest(func() error {
			once.Do(func() { close(entered) })
			time.Sleep(10 * time.Millisecond)
			return nil
		})
		appendDone := make(chan error, 1)
		go func() { appendDone <- wal.AppendClockAdvance(uint64(i + 1)) }()
		<-entered // The append is inside its fsync after releasing w.mu.
		// Close acquires the free mutex, syncs and closes w.f, and sets it to nil.
		// The append's hook completes independently on the captured-file path.
		if err := wal.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := <-appendDone; err != nil {
			t.Logf("iter %d: append after a concurrent Close returned a clean error (acceptable): %v", i, err)
		}
	}
	t.Logf("40 iterations of Close() racing an in-flight fsync: no panic, no race, no deadlock (the captured-fd pattern holds)")
}
