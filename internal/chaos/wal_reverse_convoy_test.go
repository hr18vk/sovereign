// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package chaos

// The WAL reverse-convoy (a receive-path fsync still holding w.mu) RED→GREEN
// regression test + the mixed-stream ordering witness (ADR-0045).
//
// THE DEFECT: under the 100-node / 34-per-host NVMe load the seed's
// commit_in_flight stuck at 1 for >300s — the origin's PutLocals (the group
// commit) never returned, so the quiescence probe never fired and the
// convergence SLO was INVALID (NOT-QUIESCED).
//
// THE MECHANISM (BYTE-EVIDENT — cited, not re-proven): the origin-side fix was
// ONE-directional. AppendMutations releases w.mu BEFORE its fsync (wal.go: capture
// f:= w.f; w.mu.Unlock(); w.syncFile(f)), so a concurrent AppendClockAdvance is no
// longer starved BY the origin's inject. But the REVERSE was left open:
// AppendClockAdvance (the RECEIVE path — the foreign-advance durability
// seed) still takes w.mu and holds it ACROSS its w.sync(). A slow receive-path
// fsync therefore holds w.mu for its whole duration, and the origin's
// AppendMutations blocks at w.mu.Lock() — one slow fsync becomes a WAL-wide commit
// stall. That asymmetry is the one-directional split, a real defect regardless of
// what caused any specific 300s.
//
// HONESTY LABEL (mandatory): this guard CONFIRMS the byte-evident
// reverse-convoy MECHANISM and GUARDS it against regression. It does NOT, and
// cannot, prove the convoy CAUSED the 300s silicon stall — that causation
// verdict (convoy-dominant vs NVMe-density-dominant) is a silicon A/B
// measurement, NOT a unit test. The words "this proves the root cause of the
// 300s" are FORBIDDEN. A local repro stalls DETERMINISTICALLY because the
// mechanism exists; it says nothing about whether the convoy (vs the device)
// was the binding constraint at silicon.
//
// WHY DETERMINISTIC (not timing luck): the syncHook blocks the FIRST fsync caller
// for a FIXED syncBlock and returns instantly for every later caller. The only
// variable is whether w.mu is free when the origin's AppendMutations asks for it:
//	PRE-FIX: AppendClockAdvance holds w.mu across the blocked fsync → the origin
// stalls the full syncBlock ≥ threshold → RED.
//	POST-FIX: AppendClockAdvance releases w.mu before the blocked fsync → the
// origin's AppendMutations takes the free mutex and completes in
// microseconds → GREEN.
//
// RUN: go test -run 'TestWALReverseConvoy|TestWALMixedStream|TestWALEachAppendPath|TestWALCloseDoesNotRace' -race -count=1./internal/chaos/

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// TestWALReverseConvoyOriginCommitNotBlockedByReceiveFsync is the reverse-convoy guard: a
// receive-path AppendClockAdvance convoying the origin's AppendMutations. It is the
// mirror of the origin-side GREEN test (which proved AppendClockAdvance is not starved
// BY AppendMutations); this proves the origin's AppendMutations is not starved BY a
// receive-path AppendClockAdvance fsync.
func TestWALReverseConvoyOriginCommitNotBlockedByReceiveFsync(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "reverse-convoy-lockscope.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// First-caller-only blocking — load-bearing for the measurement, identical to
	// the origin-side tests. The origin's AppendMutations ALSO routes its fsync through
	// w.syncFile→the hook, so a hook that blocked unconditionally would make the
	// origin sleep syncBlock on its OWN rigged fsync and the test would
	// measure the hook's sleep, not the mutex wait. Gating on "first caller blocks,
	// everyone else returns instantly" isolates exactly one quantity: how long
	// AppendMutations waits for w.mu. Goroutine A's fsync is the first to enter
	// (the origin is timed only after syncEntered closes), so A is the one that
	// blocks.
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

	// Goroutine A — the RECEIVE path. Pre-fix, AppendClockAdvance holds w.mu ACROSS
	// its (blocked) fsync. Its fsync is the first to enter, so it sleeps
	// syncBlock; pre-fix it does so with the mutex HELD.
	var wg sync.WaitGroup
	wg.Add(1)
	var advErr error
	go func() {
		defer wg.Done()
		advErr = wal.AppendClockAdvance(9_999)
	}()

	<-syncEntered // A's fsync is in flight. Pre-fix A still holds w.mu; post-fix it has released it.
	start := time.Now()
	failIdx, appErr := wal.AppendMutations(lockScopeMutations(64))
	elapsed := time.Since(start)
	wg.Wait()

	if advErr != nil {
		t.Fatalf("AppendClockAdvance err=%v — the receive-path append must succeed; the guard measures LOCK SCOPE, not an error path", advErr)
	}
	if appErr != nil || failIdx != -1 {
		t.Fatalf("AppendMutations idx=%d err=%v — the origin batch must succeed; the guard measures LOCK SCOPE, not an error path", failIdx, appErr)
	}
	if elapsed >= lockScopeThreshold {
		t.Fatalf("REVERSE-CONVOY PRESENT: the origin's AppendMutations took %v while a receive-path AppendClockAdvance fsync was in flight (threshold %v, rigged fsync %v). AppendClockAdvance holds w.mu ACROSS its fsync, so one slow receive-path fsync serializes the origin's group-commit — the incomplete one-directional split. FIX: release w.mu before the fsync in AppendClockAdvance (the captured-fd syncFile pattern AppendMutations already uses).",
			elapsed, lockScopeThreshold, syncBlock)
	}
	t.Logf("GREEN — reverse-convoy CLOSED: the origin's AppendMutations completed in %v while a receive-path AppendClockAdvance fsync (%v) was in flight (threshold %v). AppendClockAdvance now releases w.mu before its fsync, so a slow receive-path fsync no longer starves the origin's group-commit.",
		elapsed, syncBlock, lockScopeThreshold)
}

// dzMutation builds one valid V2 WALMutation (the ADR-0045 NewWALMutation
// construction discipline) at an explicit counter, for the mixed-stream test.
func dzMutation(counter uint64) WALMutation {
	return NewWALMutation("mixed-stream-key",
		engsync.CausalDot{NodeID: [16]byte{0xD2, 0x5A}, Counter: counter},
		engsync.CRDTEntry{SystemTime: int64(1_700_000_000 + counter)})
}

// TestWALMixedStreamOrderingPreserved is the replay witness for the
// receive-path functions. The DurabilityAndOrderingPreserved
// test covers only AppendMutations; it also moves the fsync out of the lock in
// AppendClockAdvance, AppendMutation (single), and AppendCheckpoint. This test writes
// a stream that INTERLEAVES all four through their NEW unlocked-fsync paths, then
// replays and asserts the lock-scope change did NOT reorder or drop a single record:
// the on-disk seq run is contiguous and the Ordered stream comes back in EXACT written
// order. (Ordering is fixed by the write + nextSeq++ under w.mu; the fsync is a
// durability barrier, not an ordering primitive — it cannot reorder bytes already
// written. ADR-0045: replay restores the recorded dots, never re-mints.)
func TestWALMixedStreamOrderingPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed-stream-order.wal")
	wal, err := OpenWAL(path)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	// Interleave origin group-commits with the receive-path appends. Written seqs:
	// AppendMutations[c1,c2] -> 0,1
	// AppendClockAdvance -> 2
	// AppendMutation (c3) -> 3
	// AppendCheckpoint -> 4
	// AppendMutations[c4,c5] -> 5,6
	if idx, err := wal.AppendMutations([]WALMutation{dzMutation(1), dzMutation(2)}); err != nil || idx != -1 {
		t.Fatalf("AppendMutations#1: idx=%d err=%v", idx, err)
	}
	if err := wal.AppendClockAdvance(1000); err != nil {
		t.Fatalf("AppendClockAdvance: %v", err)
	}
	if err := wal.AppendMutation(dzMutation(3)); err != nil {
		t.Fatalf("AppendMutation: %v", err)
	}
	if err := wal.AppendCheckpoint(WALCheckpoint{LamportHigh: 1000}); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if idx, err := wal.AppendMutations([]WALMutation{dzMutation(4), dzMutation(5)}); err != nil || idx != -1 {
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
	// All SEVEN on-disk records are counted by the seq-contiguity check. The
	// checkpoint occupies seq 4 on disk; ReplayWAL records it in FinalCheckpt, NOT in
	// Ordered (the WALRecCheckpoint cases set FinalCheckpt and append no Ordered
	// entry), so Ordered holds the 5 mutations + the 1 clock-advance = 6 entries.
	const wantRecords = 7
	// Non-vacuous (the bridge_test.go pattern): OR the flag with the count. ReplayWAL
	// returns an error on any seq gap, so a bare `!SeqContiguityVerified` check after a
	// successful replay would be a TAUTOLOGY (the flag is always true there). The
	// load-bearing check is the COUNT — a dropped record lowers RecordsVerified — gated
	// on the check having run. Asserting the flag alone would be vacuous.
	if !rep.SeqContiguityVerified || rep.RecordsVerified != wantRecords {
		t.Fatalf("the record-loss check must have run over all %d records (verified=%v n=%d) — a dropped record lowers the count", wantRecords, rep.SeqContiguityVerified, rep.RecordsVerified)
	}
	if !rep.HasCheckpoint || rep.FinalCheckpt.LamportHigh != 1000 {
		t.Fatalf("checkpoint not preserved: HasCheckpoint=%v FinalCheckpt.LamportHigh=%d, want 1000", rep.HasCheckpoint, rep.FinalCheckpt.LamportHigh)
	}

	// The mutation counters must come back in EXACT written order 1,2,3,4,5 with the
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
			t.Fatalf("mutation %d: replayed Counter=%d, want %d — ORDERING BROKEN. The fsync moved out of the lock; the writes + nextSeq++ stayed INSIDE, so the record order must be byte-identical.",
				i, gotCounters[i], wantCounters[i])
		}
	}
	t.Logf("GREEN — the lock-scope change preserves the mixed stream: all %d on-disk records contiguous (the checkpoint at seq 4 in FinalCheckpt), the %d Ordered records (mutations + clock-advance) in EXACT written order, none dropped. Only the fsync left the critical section; the ordering floor (write + nextSeq++ under w.mu) did not move.", wantRecords, len(wantSeqs))
}

// TestWALEachAppendPathReleasesLockBeforeFsync closes a coverage gap: the
// lock-scope split must hold for ALL FOUR append paths, not only the two the
// other tests exercise. The reverse-convoy test covers AppendClockAdvance
// (holder) and the origin-side GREEN test covers AppendMutations (holder); this test drives EACH of the
// four as the mutex-holder with a blocked fsync and times a concurrent AppendClockAdvance.
// Pre-fix, the three re-scoped paths (AppendMutation/AppendCheckpoint/AppendClockAdvance)
// held w.mu across the fsync → the probe stalls ≥ threshold. Post-fix, all four release
// first → the probe completes in microseconds. A future regression that re-wraps ANY of
// the four in w.mu across its fsync is caught here.
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
			wal, err := OpenWAL(filepath.Join(t.TempDir(), "dz-allpaths.wal"))
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
			<-syncEntered // the holder's fsync is in flight; post-fix it has already released w.mu
			start := time.Now()
			advErr := wal.AppendClockAdvance(4242) // the concurrent probe
			elapsed := time.Since(start)
			wg.Wait()
			if advErr != nil {
				t.Fatalf("%s: concurrent AppendClockAdvance err=%v", h.name, advErr)
			}
			if elapsed >= lockScopeThreshold {
				t.Fatalf("%s holds w.mu ACROSS its fsync: a concurrent AppendClockAdvance took %v (threshold %v, rigged fsync %v) — the split regressed on this path",
					h.name, elapsed, lockScopeThreshold, syncBlock)
			}
			t.Logf("GREEN — %s releases w.mu before its fsync (concurrent AppendClockAdvance in %v)", h.name, elapsed)
		})
	}
}

// TestWALCloseDoesNotRaceInflightFsync guards the captured-fd safety argument
// (the syncFile doc) an earlier review noted had zero regression coverage. An append that
// has released w.mu and is inside its fsync must survive a concurrent Close() — Close()
// sets w.f = nil under w.mu and the in-flight fsync proceeds on the CAPTURED fd, so the
// outcome is a clean error (os.ErrClosed) or nil, never a panic and never a data race.
// The -race detector is the check for any w.f access after the unlock (the exact bug
// the captured-fd pattern exists to prevent); a future change that reintroduces an
// unlocked w.f read, or drops the captured-fd discipline, trips this test.
//
// The fsync block is BOUNDED (10ms, not a release-channel) so the interleaving is
// exercised without any pre-fix deadlock risk — this is a SAFETY guard (it must not
// panic/race), not the lock-scope polarity guard (that is the reverse-convoy test above).
func TestWALCloseDoesNotRaceInflightFsync(t *testing.T) {
	for i := 0; i < 40; i++ {
		wal, err := OpenWAL(filepath.Join(t.TempDir(), "dz-close.wal"))
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
		<-entered // the append is inside its fsync; post-fix it has ALREADY released w.mu
		// Close races the in-flight fsync. Post-fix Close acquires w.mu freely (the append
		// released it), Syncs + nils w.f, and the append's captured-fd fsync completes
		// independently. No panic, no deadlock, no w.f race.
		if err := wal.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := <-appendDone; err != nil {
			t.Logf("iter %d: append after a concurrent Close returned a clean error (acceptable): %v", i, err)
		}
	}
	t.Logf("GREEN — 40 iterations of Close() racing an in-flight fsync: no panic, no race, no deadlock (the captured-fd pattern holds)")
}
