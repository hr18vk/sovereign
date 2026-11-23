// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// These tests cover Lamport clock recovery on the bounded replay path
// (ADR-0045 §4 and §5.1). A checkpoint's LamportHigh is the greatest
// local dot, so foreign clock advances do not necessarily appear in it. If WAL
// replay also skips a clock-advance record below CutSeq, the recovered clock
// can start below its pre-crash value and mint counters the node has already
// observed.
//
// Replay now folds 0x03 advances into its high-water, and the 0x05 checkpoint
// carries ClockHigh from the live engine. ClockHigh also covers a frame that
// raised the clock during admission but failed verification before a 0x03
// record was written.
//
// The tests cover both a durable advance below the cut and an in-memory-only
// raise with no WAL record. Shared fixtures come from snapshot_test.go and
// bridge_test.go.

import (
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// clockGapAdvance is far above every dot in the workload, so joining the image
// cannot by itself restore the recorded high-water.
const clockGapAdvance uint64 = 9_000_000

// clockNailMutationCount keeps image dot counters in single digits and the gap
// to the recorded advance unambiguous.
const clockNailMutationCount = 8

// clockNailObservation records the on-disk geometry and the result of one recovery.
type clockNailObservation struct {
	recoveredClock  uint64  // engine.LamportCounter() after recovery
	liveClock       uint64  // engine.LamportCounter() before the simulated crash
	recordedAdvance uint64  // the 0x03 record's payload value on disk (0 when absent)
	advanceSeq      uint64  // that record's WAL sequence number
	advanceCount    int     // the number of 0x03 records on disk
	cutFrom         uint64  // the cut computed in recovery.go
	repLamportHigh  uint64  // ReplayWAL's folded high-water
	maxImageDot     uint64  // the largest DotCounter any replayed mutation carries
	bounded         bool    // witness.Bounded (true == the image path ran)
	skewRate        float64 // LamportSnapshot().ObservedInboundRate after recovery
	skewBound       uint64  // MaxAcceptableDotCounter(LamportSnapshot()) post-recovery
}

// buildClockNailLog writes N mutations, optionally a 0x03 advance, and a final
// 0x05 checkpoint before closing the live engine and WAL. With recordAdvance,
// the advance is at seq N and the checkpoint at seq N+1 with CutSeq=N+1, placing
// the advance in the region bounded replay skips. Without it, only the in-memory
// clock reaches advanceTo and the checkpoint is at seq N.
func buildClockNailLog(t *testing.T, lfs *LocalFS, advanceTo uint64, recordAdvance bool) (walPath string, liveClock uint64) {
	t.Helper()
	walPath = filepath.Join(t.TempDir(), "clock-nail.wal")
	live := newLiveBridge(t, walPath, 0) // 0 == caller-driven checkpoints
	if lfs != nil {
		live.SetSnapshotter(lfs, true) // recovery image and Arrow index
	}
	for i := 0; i < clockNailMutationCount; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	// The production shape: the clock jumps from an inbound header before the
	// verify gate (the clock/admission verify path). When
	// recordAdvance is true the receive seam then fsyncs the post-Join
	// high-water as a 0x03 record; when false the raise lives only in memory
	// (the verify-failed-frame shape — no dot at or near advanceTo enters
	// state, and no record exists).
	live.Engine().AdvanceLamportTo(advanceTo)
	if recordAdvance {
		if err := live.RecordClockAdvance(); err != nil {
			t.Fatalf("RecordClockAdvance: %v", err)
		}
	}
	liveClock = live.Engine().LamportCounter()
	// Checkpoint last so the advance record is below the horizon cut.
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

// observeClockNailRecovery reads the WAL geometry, recovers through the bounded
// path when store is non-nil or full replay otherwise, and records the resulting
// clock and admission envelope.
func observeClockNailRecovery(t *testing.T, walPath string, liveClock uint64, store *LocalFS) clockNailObservation {
	t.Helper()
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	obs := clockNailObservation{liveClock: liveClock, repLamportHigh: rep.LamportHigh}
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
	// The fixture requires a V2 checkpoint, and any advance must lie below its
	// cut so bounded replay cannot restore the advance from the tail.
	if !rep.HasCheckpoint {
		t.Fatalf("setup: WAL has no checkpoint, so bounded recovery cannot engage")
	}
	if !rep.FinalCheckpt.HasCutSeq {
		t.Fatalf("setup: checkpoint lacks CutSeq; test requires a 0x05 horizon cut")
	}
	obs.cutFrom = rep.FinalCheckpt.CutSeq
	if obs.advanceCount > 0 && obs.advanceSeq >= obs.cutFrom {
		t.Fatalf("setup: advance seq %d is not below cut %d; bounded replay would restore it from the tail", obs.advanceSeq, obs.cutFrom)
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

// TestBoundedRecoveryClockNailBelowForeignHighWater places a durable advance to
// 9,000,000 below the checkpoint cut. Bounded recovery must restore at least
// that clock: starting lower would mint counters in a logical-time range the
// node had already acknowledged observing.
func TestBoundedRecoveryClockNailBelowForeignHighWater(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, liveClock := buildClockNailLog(t, lfs, clockGapAdvance, true)
	obs := observeClockNailRecovery(t, walPath, liveClock, lfs)

	if !obs.bounded {
		t.Fatalf("setup: recovery fell back to full replay, so the below-cut case was not exercised; obs=%+v", obs)
	}
	if obs.advanceCount != 1 {
		t.Fatalf("setup: got %d durable clock-advance records, want 1", obs.advanceCount)
	}
	// No image dot may cover the advance, or Join rather than the WAL fold and
	// checkpoint could be responsible for restoring the clock.
	if obs.maxImageDot >= obs.recordedAdvance {
		t.Fatalf("setup: image dot %d covers advance %d, so Join could restore the clock without the WAL fold", obs.maxImageDot, obs.recordedAdvance)
	}

	if obs.recoveredClock < obs.recordedAdvance {
		t.Fatalf(`bounded recovery restored a clock below the durable foreign high-water.
  recovered clock   = %d   (after RecoverEngineWithSnapshot)
  recorded advance  = %d   (durable 0x03 record, seq %d)
  shortfall         = %d
  live clock        = %d
  rep.LamportHigh   = %d   (folded WAL high-water)
  maxImageDot       = %d   (too low for Join to restore the advance)
  cutFrom           = %d   (0x05 CutSeq; advance seq %d is below it)
  The next local mint starts at %d, within a logical-time range already acknowledged on disk.`,
			obs.recoveredClock, obs.recordedAdvance, obs.advanceSeq,
			obs.recordedAdvance-obs.recoveredClock, obs.liveClock,
			obs.repLamportHigh, obs.maxImageDot, obs.cutFrom, obs.advanceSeq,
			obs.recoveredClock)
	}
	t.Logf("recovered clock %d >= recorded advance %d (rep.LamportHigh=%d, liveClock=%d)", obs.recoveredClock, obs.recordedAdvance, obs.repLamportHigh, obs.liveClock)

	// Constructor seeding resets the skew EWMA, so admission starts with an
	// envelope of clock + 0 + slack. A direct AdvanceLamportTo(9,000,000) would
	// instead open an approximately 54-million-counter acceptance window.
	if obs.skewRate != 0 {
		t.Fatalf("ObservedInboundRate=%v after recovery; constructor seeding must reset the skew EWMA", obs.skewRate)
	}
	if obs.skewBound != clockGapAdvance+1000 {
		t.Fatalf("post-recovery skew bound=%d, want %d (clock %d + zero envelope + slack 1000)", obs.skewBound, clockGapAdvance+1000, clockGapAdvance)
	}
}

// TestControlNoRecordedAdvanceClockHighNail raises the clock to 9,000,000
// without writing a 0x03 record, as happens when admission raises the clock for
// a frame that subsequently fails verification. WAL folding cannot restore an
// absent record; the checkpoint's ClockHigh must preserve the value.
func TestControlNoRecordedAdvanceClockHighNail(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, liveClock := buildClockNailLog(t, lfs, clockGapAdvance, false) // no 0x03 record
	obs := observeClockNailRecovery(t, walPath, liveClock, lfs)

	if obs.advanceCount != 0 {
		t.Fatalf("setup: got %d clock-advance records, want none for the in-memory-only raise", obs.advanceCount)
	}
	if !obs.bounded {
		t.Fatalf("setup: recovery did not use the bounded path; obs=%+v", obs)
	}
	if obs.liveClock != clockGapAdvance {
		t.Fatalf("setup: live clock %d != %d after the in-memory raise", obs.liveClock, clockGapAdvance)
	}
	if obs.recoveredClock < clockGapAdvance {
		t.Fatalf("bounded recovery restored clock %d below live high-water %d; with no 0x03 record, checkpoint ClockHigh must supply it (rep.LamportHigh=%d)",
			obs.recoveredClock, clockGapAdvance, obs.repLamportHigh)
	}
	t.Logf("no 0x03 record; checkpoint ClockHigh restored clock %d >= live high-water %d", obs.recoveredClock, clockGapAdvance)
	// Restoring ClockHigh through the constructor must also reset the skew EWMA.
	if obs.skewRate != 0 || obs.skewBound != clockGapAdvance+1000 {
		t.Fatalf("ClockHigh recovery skew envelope: rate=%v bound=%d, want 0/%d", obs.skewRate, obs.skewBound, clockGapAdvance+1000)
	}
}

// TestControlMitigatedAdvanceBoundedPathHolds uses advanceTo=1, which does not
// exceed the image's maximum dot. Bounded recovery must satisfy the same clock
// assertion without relying on the large gap exercised by the other tests.
func TestControlMitigatedAdvanceBoundedPathHolds(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, liveClock := buildClockNailLog(t, lfs, 1, true) // no-op against the live clock
	obs := observeClockNailRecovery(t, walPath, liveClock, lfs)

	if obs.advanceCount != 1 {
		t.Fatalf("control setup: got %d durable 0x03 records, want 1", obs.advanceCount)
	}
	if obs.recordedAdvance > obs.maxImageDot {
		t.Fatalf("control setup: advance %d exceeds image dot %d; this is the gap case, not the control", obs.recordedAdvance, obs.maxImageDot)
	}
	if !obs.bounded {
		t.Fatalf("control setup: recovery did not use the bounded path")
	}
	if obs.recoveredClock < obs.recordedAdvance {
		t.Fatalf("bounded recovery restored clock %d below advance %d without a gap (maxImageDot=%d rep.LamportHigh=%d)",
			obs.recoveredClock, obs.recordedAdvance, obs.maxImageDot, obs.repLamportHigh)
	}
	t.Logf("bounded recovery control: advance %d <= image dot %d (seq %d below cut %d); recovered clock %d, liveClock=%d",
		obs.recordedAdvance, obs.maxImageDot, obs.advanceSeq, obs.cutFrom, obs.recoveredClock, liveClock)
}
