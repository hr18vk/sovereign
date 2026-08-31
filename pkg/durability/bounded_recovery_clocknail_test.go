// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// THE CLOCK NAIL (ADR-0045).
//
// THE DEFECT (RED-PROVEN at git 2ac07ed): BOUNDED crash recovery boots a node
// whose Lamport clock sits BELOW its pre-crash foreign high-water. The chain,
// each link read from bytes at that pre-fix base (the fix moved these lines —
// the citations are the historical defect map, not the current tree):
//
//	L1 bridge.go:378 ckpt.LamportHigh = maxLocalDot
//	L2 merkle_sharded.go:233 maxLocalDot counts ONLY DotNodeID == localNodeID
//		(ignores every foreign dot AND every 0x03 advance)
//	L3 chaos/wal.go:895-901 the WALRecClockAdvance decode appends to
//		out.Advances/out.Ordered and NEVER folds into
//		out.LamportHigh (contrast :882-884, :892-894,
//		:912-914, :927-929)
//	L4 recovery.go:362-364 `if useSnapshot && rec.Seq < cutFrom { continue }`
//		skips EVERY below-cut record — the 0x03 advance
//		case at :391 is inside that same loop, so a
//		below-cut advance is never applied
//	L5 recovery.go:456-460 engine.AdvanceLamportTo(rep.LamportHigh) under a
//		comment asserting rep.LamportHigh covers
//		pre-checkpoint advances. Per L2+L3 it does not.
//
// WHY THIS FILE IS SHAPED THIS WAY: an apparatus that asserts
// `rep.LamportHigh < recordedAdvance` asserts THE DEFECT STILL EXISTS. Under
// the fix (which folds the advance + ClockHigh in 0x05) that apparatus goes
// FALSE, so the same test run post-fix would read as "the defect survives" and
// invite reverting the fix. So the apparatus that pinned the DEFECT lived in a
// throwaway red-baseline test (expected to fail after the fix and deleted with
// it), while the OUTCOME assertion (recovered clock >= recorded advance) lives
// in TestBoundedRecoveryClockNailBelowForeignHighWater and must SURVIVE green.
//
// THE FULL-REPLAY CONTROL IS REPLACED: a full-replay control goes VACUOUS
// under the fix — the final nail covers it whether or not the replay case
// fires. It is replaced by TestControlNoRecordedAdvanceClockHighNail, which
// isolates the verify-failed-frame hole: receiver.go raises the clock BEFORE
// the verify gate (receiver.go:529 → clock/admission.go:102), so a
// verify-failed frame leaves the clock raised with NO 0x03 record on disk.
// Only the checkpoint's ClockHigh can nail that clock.
//
// Scaffolding REUSED from snapshot_test.go / bridge_test.go: newLiveBridge,
// newSnapshotStore, recoverBounded, recoverFull, utf8EntityID, stagedPayload,
// stagedEntry, testArenaSize (64 MiB).

import (
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// b1GapAdvance is the durable foreign high-water. It is orders of magnitude
// above every dot the workload mints, so NO image entry can re-raise the clock
// to it via the crdt.go:1109 Join mitigation.
const b1GapAdvance uint64 = 9_000_000

// b1MutationCount keeps the minted dot set tiny (single digits) so the gap
// between max-dot-in-image and the recorded advance is unambiguous.
const b1MutationCount = 8

// b1Observation is everything the probe measures about one durable log + one
// recovery of it.
type b1Observation struct {
	recoveredClock  uint64  // engine.LamportCounter() after recovery
	liveClock       uint64  // engine.LamportCounter() before the simulated crash
	recordedAdvance uint64  // the 0x03 record's payload value on disk (0 when absent)
	advanceSeq      uint64  // that record's WAL sequence number
	advanceCount    int     // the number of 0x03 records on disk
	cutFrom         uint64  // the cut recovery.go:346-349 computes
	repLamportHigh  uint64  // ReplayWAL's folded high-water
	maxImageDot     uint64  // the largest DotCounter any replayed mutation carries
	bounded         bool    // witness.Bounded (true == the image path ran)
	skewRate        float64 // LamportSnapshot().ObservedInboundRate post-recovery (the fail-open witness)
	skewBound       uint64  // MaxAcceptableDotCounter(LamportSnapshot()) post-recovery
}

// b1Build writes the exact durable record shape the chain needs and kills the
// live engine like a crash. When recordAdvance is true the record order is:
//
//	seq 0..N-1: 0x04 mutations (dots 2..N+1 — all single-digit)
//	seq N: 0x03 clock advance, value = advanceTo
//	seq N+1: 0x05 checkpoint, LamportHigh = maxLocalDot, CutSeq = N+1
//
// so the advance sits STRICTLY BELOW CutSeq — precisely the region the bounded
// path's `rec.Seq < cutFrom` skips. When recordAdvance is false the 0x03 record
// is NEVER written (the verify-failed-frame hole: the clock was raised in
// memory only), and the checkpoint is seq N.
func b1Build(t *testing.T, lfs *LocalFS, advanceTo uint64, recordAdvance bool) (walPath string, liveClock uint64) {
	t.Helper()
	walPath = filepath.Join(t.TempDir(), "b1.wal")
	live := newLiveBridge(t, walPath, 0) // 0 == caller-driven checkpoints
	if lfs != nil {
		live.SetSnapshotter(lfs, true) // recovery image + Arrow index (the snapshotter test config)
	}
	for i := 0; i < b1MutationCount; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	// The production shape: the clock jumps from an inbound header BEFORE the
	// verify gate (receiver.go:529 → clock/admission.go:102). When
	// recordAdvance is true the receive seam then fsyncs the post-Join
	// high-water as a 0x03 record; when false the raise lives ONLY in memory
	// (the verify-failed-frame shape — no dot at or near advanceTo enters
	// state, and no record exists).
	live.Engine().AdvanceLamportTo(advanceTo)
	if recordAdvance {
		if err := live.RecordClockAdvance(); err != nil {
			t.Fatalf("RecordClockAdvance: %v", err)
		}
	}
	liveClock = live.Engine().LamportCounter()
	// Checkpoint LAST so the advance record is below the horizon cut.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	// Crash: no graceful flush beyond the per-record fsyncs already on disk.
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}
	return walPath, liveClock
}

// b1Observe replays the log to read the on-disk record geometry, then recovers
// through the requested path and reports the clock. store == nil selects the
// FULL-replay path; store != nil selects the BOUNDED path.
func b1Observe(t *testing.T, walPath string, liveClock uint64, store *LocalFS) b1Observation {
	t.Helper()
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	obs := b1Observation{liveClock: liveClock, repLamportHigh: rep.LamportHigh}
	for _, rec := range rep.Ordered {
		switch rec.Type {
		case WALRecClockAdvance:
			obs.advanceCount++
			obs.recordedAdvance = rec.Advance
			obs.advanceSeq = rec.Seq
		case WALRecMutation, WALRecMutationV2:
			if rec.Mutation.Counter > obs.maxImageDot {
				obs.maxImageDot = rec.Mutation.Counter
			}
		}
	}
	// GEOMETRY CHECKS (stable under the fix — they describe the on-disk shape,
	// not the defect): a checkpoint must be present and V2, and any advance
	// must sit below the cut.
	if !rep.HasCheckpoint {
		t.Fatalf("apparatus: no checkpoint record on disk — the bounded path cannot engage")
	}
	if !rep.FinalCheckpt.HasCutSeq {
		t.Fatalf("apparatus: checkpoint is legacy 0x02 (no CutSeq) — this probe targets the 0x05 horizon cut")
	}
	obs.cutFrom = rep.FinalCheckpt.CutSeq
	if obs.advanceCount > 0 && obs.advanceSeq >= obs.cutFrom {
		t.Fatalf("apparatus: the 0x03 record sits at seq %d which is NOT below cutFrom %d — the bounded path would replay it and the probe would prove nothing about recovery.go:362-364", obs.advanceSeq, obs.cutFrom)
	}

	if store != nil {
		e, witness := recoverBounded(t, walPath, store)
		obs.recoveredClock = e.LamportCounter()
		obs.bounded = witness.Bounded
		snap := e.LamportSnapshot()
		obs.skewRate = snap.ObservedInboundRate
		obs.skewBound = eng.MaxAcceptableDotCounter(snap)
	} else {
		e, witness := recoverFull(t, walPath)
		obs.recoveredClock = e.LamportCounter()
		obs.bounded = witness.Bounded
		snap := e.LamportSnapshot()
		obs.skewRate = snap.ObservedInboundRate
		obs.skewBound = eng.MaxAcceptableDotCounter(snap)
	}
	return obs
}

// TestBoundedRecoveryClockNailBelowForeignHighWater is THE permanent
// outcome guard. A node crashes with a durable 0x03 advance to 9,000,000
// sitting below the checkpoint's horizon cut. Bounded recovery MUST NOT boot
// with a clock below that value: the advance is the node's own durable promise
// that it has already observed logical time 9,000,000, and a clock below it
// re-mints dots in a range a peer has already used — the exact non-monotonicity
// the foreign-advance record exists to prevent. RED pre-fix; GREEN
// post-fix; NEVER deleted.
func TestBoundedRecoveryClockNailBelowForeignHighWater(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, liveClock := b1Build(t, lfs, b1GapAdvance, true)
	obs := b1Observe(t, walPath, liveClock, lfs)

	if !obs.bounded {
		t.Fatalf("apparatus: witness.Bounded == false — recovery fell back to full replay (image missing/rejected), so this run does NOT exercise recovery.go:362-364. obs=%+v", obs)
	}
	if obs.advanceCount != 1 {
		t.Fatalf("apparatus: want exactly 1 durable 0x03 clock-advance record on disk, got %d — the probe's premise (a durable advance) is unmet", obs.advanceCount)
	}
	// Mitigation-defeat witness: no dot in the image can re-raise the clock, so
	// the recovered clock can ONLY have come from the WAL fold + the checkpoint.
	if obs.maxImageDot >= obs.recordedAdvance {
		t.Fatalf("apparatus: max dot in the image (%d) covers the recorded advance (%d) — the crdt.go:1109 Join mitigation would raise the clock and the gap the probe needs does not exist", obs.maxImageDot, obs.recordedAdvance)
	}

	if obs.recoveredClock < obs.recordedAdvance {
		t.Fatalf(`CLOCK-NAIL CONFIRMED — bounded recovery booted with the Lamport clock BELOW the pre-crash foreign high-water.
 recovered clock = %d (engine.LamportCounter() after RecoverEngineWithSnapshot)
 recorded advance = %d (the durable 0x03 record, seq %d)
 UNDER-SHOOT = %d
 live clock pre-crash = %d
 rep.LamportHigh = %d (the folded WAL high-water)
 maxImageDot = %d (no image entry can re-raise the clock to the advance)
 cutFrom = %d (0x05 CutSeq) — advance seq %d < cutFrom.
 Consequence: the node re-mints dots from %d upward, inside a logical-time range it has already
 durably acknowledged observing — the double-mint class re-opened on the bounded path.`,
			obs.recoveredClock, obs.recordedAdvance, obs.advanceSeq,
			obs.recordedAdvance-obs.recoveredClock, obs.liveClock,
			obs.repLamportHigh, obs.maxImageDot, obs.cutFrom, obs.advanceSeq,
			obs.recoveredClock)
	}
	t.Logf("CLOCK-NAIL GREEN: recovered clock %d >= recorded advance %d (rep.LamportHigh=%d, liveClock=%d)", obs.recoveredClock, obs.recordedAdvance, obs.repLamportHigh, obs.liveClock)

	// Executable proof there is no fail-open window: the clock must have arrived
	// via the CONSTRUCTOR seed, which resets the skew EWMA to 0.0 — so
	// the post-recovery admission envelope is exactly clock + 0 + slack, NOT the
	// ~54M-wide window a naive AdvanceLamportTo(9,000,000) would have opened
	//
	if obs.skewRate != 0 {
		t.Fatalf("FAIL-OPEN: ObservedInboundRate=%v after recovery — the clock did NOT arrive via the EWMA-safe constructor seed (the skew envelope is poisoned)", obs.skewRate)
	}
	if obs.skewBound != b1GapAdvance+1000 {
		t.Fatalf("FAIL-OPEN: post-recovery skew bound=%d, want exactly %d (clock %d + 0 envelope + slack 1000)", obs.skewBound, b1GapAdvance+1000, b1GapAdvance)
	}
}

// (The throwaway red-baseline test that pinned the pre-fix defect geometry was
// committed RED and is DELETED here by the fix: its assertions pinned the
// PRE-FIX defect geometry, so under the fix they fail by design.)

// TestControlNoRecordedAdvanceClockHighNail is the verify-failed-frame hole
// isolator (the replacement for the full-replay control that goes vacuous
// under the fix). The clock is raised to
// 9,000,000 with NO 0x03 record — the receiver.go:529 shape (the clock is
// raised at admission BEFORE the verify gate, so a verify-failed frame leaves
// the clock raised with nothing durable). The WAL fold cannot help: there is
// no record to fold. Only the checkpoint's ClockHigh field can nail this
// clock. RED pre-fix (no ClockHigh exists); GREEN post-fix.
func TestControlNoRecordedAdvanceClockHighNail(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, liveClock := b1Build(t, lfs, b1GapAdvance, false) // NO 0x03 record
	obs := b1Observe(t, walPath, liveClock, lfs)

	if obs.advanceCount != 0 {
		t.Fatalf("apparatus: want ZERO 0x03 records (the clock was raised with no durable record), got %d", obs.advanceCount)
	}
	if !obs.bounded {
		t.Fatalf("apparatus: not the bounded path (obs=%+v)", obs)
	}
	if obs.liveClock != b1GapAdvance {
		t.Fatalf("apparatus: live clock %d != %d — the in-memory raise did not land", obs.liveClock, b1GapAdvance)
	}
	if obs.recoveredClock < b1GapAdvance {
		t.Fatalf(`HOLE CONFIRMED — bounded recovery booted at clock %d BELOW the un-recorded live high-water %d.
 No 0x03 record exists (advanceCount=0), so the WAL fold has nothing to fold: rep.LamportHigh=%d.
 Only the checkpoint's ClockHigh can close this hole.`,
			obs.recoveredClock, b1GapAdvance, obs.repLamportHigh)
	}
	t.Logf("CONTROL GREEN: no 0x03 on disk, yet recovered clock %d >= live high-water %d (nailed via the checkpoint's ClockHigh)", obs.recoveredClock, b1GapAdvance)
	// The ClockHigh path is exactly where a naive fix would AdvanceLamportTo the
	// 9,000,000 and poison the skew EWMA. Prove it did not happen.
	if obs.skewRate != 0 || obs.skewBound != b1GapAdvance+1000 {
		t.Fatalf("FAIL-OPEN on the ClockHigh path: skewRate=%v skewBound=%d, want 0 / %d", obs.skewRate, obs.skewBound, b1GapAdvance+1000)
	}
}

// TestControlMitigatedAdvanceBoundedPathHolds is the falsifiability
// control. Same bounded path, same assertion, same code; only the advance VALUE
// changes. advanceTo == 1 is a no-op against a clock already at max-dot, so
// RecordClockAdvance writes a 0x03 whose value EQUALS the max dot in the image.
// The assertion must PASS on BOTH the pre-fix and post-fix trees — proving the
// outcome guard's assertion is falsifiable in both directions, not a tautology.
func TestControlMitigatedAdvanceBoundedPathHolds(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, liveClock := b1Build(t, lfs, 1, true) // 1 <= the live clock ⇒ a no-op advance
	obs := b1Observe(t, walPath, liveClock, lfs)

	if obs.advanceCount != 1 {
		t.Fatalf("control apparatus: want 1 durable 0x03 record, got %d", obs.advanceCount)
	}
	if obs.recordedAdvance > obs.maxImageDot {
		t.Fatalf("control apparatus: recorded advance %d exceeds max image dot %d — this is the GAP shape, not the MITIGATED shape", obs.recordedAdvance, obs.maxImageDot)
	}
	if !obs.bounded {
		t.Fatalf("control apparatus: witness.Bounded == false — not the bounded path")
	}
	if obs.recoveredClock < obs.recordedAdvance {
		t.Fatalf("CONTROL FAILED: bounded recovery under-nails the clock EVEN WITHOUT a gap (recovered %d < advance %d, maxImageDot %d, rep.LamportHigh %d). The RED would then not be attributable to the gap.", obs.recoveredClock, obs.recordedAdvance, obs.maxImageDot, obs.repLamportHigh)
	}
	t.Logf("CONTROL PASS: bounded recovery, advance %d <= max image dot %d (seq %d, still BELOW cutFrom %d) — recovered clock %d >= advance. liveClock=%d",
		obs.recordedAdvance, obs.maxImageDot, obs.advanceSeq, obs.cutFrom, obs.recoveredClock, liveClock)
}
