// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package chaos

// The WAL mutex-over-hold RED→GREEN regression test (ADR-0045).
//
// THE BUG (silicon, 100 nodes / 3 regions / 10K keys):
// AppendMutations held w.mu across BOTH the N-record write loop AND the final
// w.sync(). The write loop is page-cache-fast (microseconds); the fsync is a real
// disk barrier (tens of seconds for the 10K-key inject on the gate's NVMe). Because
// AppendClockAdvance takes the SAME w.mu (wal.go:323), the seed's inject blocked the
// seed's OWN receive path for the entire fsync window: every inbound foreign delta
// needs AppendClockAdvance (the foreign-advance durability seed), so
// cache.record populated late and the round-1 relay lookups missed — the "payload
// miss" storm (260K misses).
//
// THE FIX: write + seq-stamp under w.mu, capture the fd, UNLOCK, then fsync
// the captured fd outside the lock (wal.go AppendMutations + syncFile).
//
// WHY THIS TEST IS LOAD-BEARING (not a "should be faster" assertion): it measures
// the WALL-CLOCK LATENCY of a concurrent AppendClockAdvance while an
// AppendMutations fsync is in flight, using a syncHook that BLOCKS. The hook makes
// the fsync duration deterministic instead of disk-dependent, so the RED and GREEN
// outcomes are separated by ~3 orders of magnitude, not by a flaky margin:
//
//	PRE-FIX (fsync inside the lock): AppendClockAdvance blocks the FULL hold →
// latency >= syncBlock (500ms).
//	POST-FIX (fsync outside the lock): AppendClockAdvance takes the mutex the
// instant the write loop ends → latency is sub-millisecond.
//
// The threshold sits at syncBlock/10 — 50ms — which is 10× above any plausible
// scheduler noise for a single mutex acquisition + one small write, and 10× below
// the pre-fix floor. A run that lands between the two would fail LOUDLY rather than
// pass ambiguously.
//
// RED-CONTROL PROOF (TestWALLockScopeRedControl below): the pre-fix lock
// discipline is re-created EXACTLY — same hook, same concurrency, but the fsync is
// performed while the mutex is held — and the test asserts that arrangement DOES
// block past the threshold. So the measurement apparatus is proven capable of
// detecting the bug; a GREEN main test is therefore evidence about the fix, not
// evidence about a blunt instrument.
//
// RUN: go test -run 'TestWALLockScope' -race -count=1./internal/chaos/

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// errRiggedSync is the injected fsync failure for the error-contract check.
var errRiggedSync = errors.New("rigged fsync failure")

// syncBlock is how long the rigged fsync blocks. Large enough that the
// pre-fix serialization is unmistakable, small enough to keep the test fast.
const syncBlock = 500 * time.Millisecond

// lockScopeThreshold is the pass/fail line for the concurrent
// AppendClockAdvance latency: 10× below the pre-fix floor (syncBlock) and 10×
// above realistic scheduler noise for one mutex acquire + one small write.
const lockScopeThreshold = syncBlock / 10

// lockScopeMutations builds n distinct WALMutations (ADR-0045 shape: the full
// 120-byte entry via NewWALMutation — the one construction discipline).
func lockScopeMutations(n int) []WALMutation {
	ms := make([]WALMutation, n)
	for i := range ms {
		ms[i] = NewWALMutation("lockscope-key",
			engsync.CausalDot{NodeID: [16]byte{0xD4, 0x1C}, Counter: uint64(i + 1)},
			engsync.CRDTEntry{SystemTime: int64(1_700_000_000 + i)})
	}
	return ms
}

// TestWALLockScopeClockAdvanceNotBlockedByFsync is the GREEN half: with the split
// applied, an AppendClockAdvance issued while an AppendMutations fsync is in flight
// completes in well under the threshold, because the mutex was released before the
// fsync.
func TestWALLockScopeClockAdvanceNotBlockedByFsync(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "lockscope.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// syncEntered fires the moment the rigged fsync begins — i.e. the moment the
	// write loop has finished and (post-fix) the mutex has been released. Waiting on
	// it is what makes the test DETERMINISTIC rather than sleep-timed: the clock
	// advance is issued only once the fsync is provably in flight, so a PRE-FIX
	// build cannot pass by racing ahead of the lock being taken.
	//
	// ONLY THE FIRST fsync blocks. This is load-bearing for the measurement:
	// AppendClockAdvance ALSO routes its fsync through the shared syncHook (via
	// w.syncFile — re-routed off w.sync()), so a
	// hook that blocks unconditionally would make the clock advance wait
	// syncBlock on ITS OWN rigged fsync — and the test would measure the
	// hook's sleep instead of the mutex wait, reporting a 500ms "failure" on
	// CORRECTLY-FIXED code. The batch's fsync is the first to enter (the clock
	// advance is issued only after syncEntered closes), so gating on "first caller
	// blocks, everyone else returns instantly" isolates exactly one quantity: how
	// long AppendClockAdvance waits for w.mu.
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

	<-syncEntered // the fsync is in flight; post-fix the mutex is FREE.
	start := time.Now()
	advErr := wal.AppendClockAdvance(9_693)
	elapsed := time.Since(start)

	wg.Wait()
	if appendErr != nil {
		t.Fatalf("AppendMutations returned err=%v (firstFailIdx=%d) — the batch must succeed; the guard measures LOCK SCOPE, not an error path", appendErr, appendFailIdx)
	}
	if appendFailIdx != -1 {
		t.Fatalf("AppendMutations firstFailIdx=%d, want -1 (whole batch durable)", appendFailIdx)
	}
	if advErr != nil {
		t.Fatalf("AppendClockAdvance returned err=%v — the concurrent clock advance must succeed", advErr)
	}
	if elapsed >= lockScopeThreshold {
		t.Fatalf("NOT APPLIED (or regressed): AppendClockAdvance took %v while an AppendMutations fsync was in flight (threshold %v, rigged fsync %v). The WAL mutex is being HELD ACROSS THE FSYNC, so the receive path (AppendClockAdvance — the foreign-advance seed) serializes behind the inject's disk barrier. This is the silicon the run payload-miss root: cache.record populates late because the receive path is mutex-starved. FIX: in AppendMutations, capture f:= w.f + w.mu.Unlock() BEFORE w.syncFile(f).",
			elapsed, lockScopeThreshold, syncBlock)
	}
	t.Logf("GREEN — the split holds: AppendClockAdvance completed in %v while a %v AppendMutations fsync was in flight (threshold %v, %.0f× headroom). The write loop + nextSeq stamping stay under w.mu; only the fsync is outside, so the receive path is NOT starved by the inject's disk barrier.",
		elapsed, syncBlock, lockScopeThreshold, float64(lockScopeThreshold)/float64(max(elapsed, time.Microsecond)))
}

// holdMuAcrossSyncForTest re-creates the pre-split lock discipline in
// explicit test-only code: it holds w.mu ACROSS w.sync(). It is the RedControl's
// over-hold vehicle. The production AppendCheckpoint now releases w.mu before its
// fsync, so the control can no longer borrow a REAL call path
// that over-holds — this helper reproduces that exact discipline (w.mu.Lock →
// w.sync → w.mu.Unlock) so the GREEN test (ClockAdvanceNotBlockedByFsync) retains a
// LIVE apparatus-validation control. It routes through w.sync(), so the same
// first-caller-only blocking hook applies, and the arrangement under test
// (hold-X / time-AppendClockAdvance) is UNCHANGED.
func holdMuAcrossSyncForTest(w *WAL) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sync()
}

// TestWALLockScopeRedControl is the RED half — the bug-inject that proves
// the apparatus works. It re-creates the PRE-FIX lock discipline exactly (fsync
// performed while w.mu is held) and asserts the concurrent AppendClockAdvance DOES
// block past the threshold. If this control ever goes GREEN, the measurement is
// broken (the threshold is too loose, or the hook is not blocking) and the main
// test above proves nothing.
//
// RE-ANCHOR: the control previously borrowed AppendCheckpoint as its
// over-hold vehicle (it held w.mu across w.sync() — byte-identical to the
// pre-split AppendMutations). AppendCheckpoint now releases w.mu before its
// fsync, removing that over-hold, so the control now re-creates the discipline
// EXPLICITLY via holdMuAcrossSyncForTest (w.mu.Lock → w.sync → w.mu.Unlock).
// The arrangement under test is UNCHANGED (hold-X / time-AppendClockAdvance), so
// the control still validates the exact apparatus the GREEN test relies on.
func TestWALLockScopeRedControl(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "lockscope-red.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	// SAME first-caller-only blocking as the GREEN test — and for the same reason,
	// but here it is what makes the control HONEST rather than merely correct. If
	// the hook blocked unconditionally, the concurrent AppendClockAdvance would
	// sleep syncBlock on its OWN fsync and the control would "pass" even with
	// no mutex contention at all — a control that proves nothing. Blocking only the
	// checkpoint's fsync means the latency this control measures is purely the
	// mutex-over-hold, the identical quantity the GREEN test measures.
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
		// The pre-split over-hold, re-created in explicit test-only code now that the
		// production AppendCheckpoint releases w.mu before its fsync: w.mu.Lock → w.sync →
		// w.mu.Unlock — the same mutex-held-across-fsync RELATIONSHIP the GREEN test
		// must detect (the helper omits the validate/encode/write/nextSeq++ steps; it
		// reproduces the lock-scope property, not the full byte sequence).
		_ = holdMuAcrossSyncForTest(wal)
	}()

	<-syncEntered // the fsync is in flight WITH the mutex held.
	start := time.Now()
	_ = wal.AppendClockAdvance(1002)
	elapsed := time.Since(start)
	wg.Wait()

	if elapsed < lockScopeThreshold {
		t.Fatalf("RED CONTROL BROKEN: AppendClockAdvance took only %v behind a mutex HELD ACROSS a %v fsync (threshold %v). The guard's measurement apparatus cannot detect the over-hold, so the GREEN guard proves NOTHING. Check that the syncHook actually blocks and that holdMuAcrossSyncForTest still holds w.mu across w.sync().",
			elapsed, syncBlock, lockScopeThreshold)
	}
	t.Logf("RED CONTROL PASS — with the fsync INSIDE the critical section (the test-only over-hold helper re-creating the pre-split mutex-held-across-fsync scope), the concurrent AppendClockAdvance blocked %v (>= threshold %v): the apparatus DOES detect a mutex-over-hold, so the GREEN result for AppendMutations is evidence about the fix, not about a blunt instrument.",
		elapsed, lockScopeThreshold)
}

// TestWALLockScopeDurabilityAndOrderingPreserved proves the split changed ONLY the
// lock scope — not the record stream, not the seq stamping, not the error contract.
// This is the invariant recovery depends on (ADR-0045: replay restores
// the recorded dots in seq order — the refuted seed-formula era is over).
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
	// replay: the stream must come back in EXACTLY the written order with the
	// counters intact.
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rep, err := ReplayWAL(path)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if len(rep.Mutations) != n {
		t.Fatalf("replayed %d mutations, want %d — the split must not drop records", len(rep.Mutations), n)
	}
	for i := range want {
		if rep.Mutations[i].Counter != want[i].Counter {
			t.Fatalf("mutation %d: replayed Counter=%d, want %d — ORDERING BROKEN. The split moves the fsync out of the lock; the writes + nextSeq++ stay INSIDE, so the record order and seq stamping must be byte-identical. The recorded dots ARE the recovery identity (ADR-0045 — replay restores, never re-mints).",
				i, rep.Mutations[i].Counter, want[i].Counter)
		}
		if rep.Mutations[i].EntityID != want[i].EntityID {
			t.Fatalf("mutation %d: replayed EntityID=%q, want %q", i, rep.Mutations[i].EntityID, want[i].EntityID)
		}
	}
	t.Logf("GREEN — the split preserves the record stream: %d mutations replayed in EXACT written order, counters intact. The fsync moved out of the lock; the ordering floor (writes + nextSeq++ under w.mu) did not move. (The refuted 'recovery seed = Mutations[0].Counter-1' invariant is gone — ADR-0045; the recorded dots are the contract.)", n)
}

// TestWALLockScopeSyncErrorStillFailsWholeBatch proves the ERROR contract is
// byte-identical after the split: a failing fsync still returns (-1, err) — the "treat the
// WHOLE batch as un-durable, caller ACKs all 503" atomicity — even though the fsync
// now happens after the unlock.
func TestWALLockScopeSyncErrorStillFailsWholeBatch(t *testing.T) {
	wal, err := OpenWAL(filepath.Join(t.TempDir(), "lockscope-err.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	wal.SetSyncHookForTest(func() error { return errRiggedSync })

	idx, err := wal.AppendMutations(lockScopeMutations(8))
	if idx != -1 {
		t.Fatalf("firstFailIdx=%d, want -1 — a SYNC failure must report the WHOLE batch un-durable (not a per-record index); the split must not change the error contract", idx)
	}
	if err == nil {
		t.Fatal("AppendMutations returned nil err under a rigged failing fsync — the 503-ALL honesty contract is BROKEN")
	}
	t.Logf("GREEN — the error contract survives the split: a failing fsync (now performed OUTSIDE the lock) still returns (-1, %v) — the whole batch is reported un-durable, byte-identical to the pre-split atomicity the caller's 503-ALL path relies on.", err)
}
