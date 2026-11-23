// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// These tests cover ClockHigh validation during WAL decode (ADR-0045 §4).
// Recovery seeds the constructor with max(rep.LamportHigh, ClockHigh). In an
// unframed 0x05 record, which has no checksum, an unchecked ClockHigh of
// MaxUint64 makes the first NextDot wrap to zero. Subsequent local writes then
// reuse counters and merge as duplicates on peers even though recovery reported
// its integrity checks as armed.
//
// Decode clamps ClockHigh above MaxCredibleClockHigh (1<<60, matching
// maxPlausibleCounter) to the log's durable high-water and reports both the raw
// value and the clamp through Replayed and RecoveryWitness. Boot continues
// because the mutations remain usable; only an unrecorded clock raise is lost.
// A plausible-looking corrupt value below the ceiling remains undetectable in
// this legacy format.

import (
	"encoding/binary"
	"math"
	"os"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// patchFinalCheckpointClockHigh finds the last 0x05 record and overwrites its
// ClockHigh at payload[48:56]. It re-reads the field after writing so a patch
// that did not apply cannot be mistaken for a passing control.
func patchFinalCheckpointClockHigh(t *testing.T, walPath string, val uint64) {
	t.Helper()
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	if len(data) < 8 {
		t.Fatalf("setup: WAL too short for a header")
	}
	off := 8 // fixed header
	lastCkpt := -1
	for off+13 <= len(data) {
		recType := data[off+8]
		payloadLen := int(binary.BigEndian.Uint32(data[off+9 : off+13]))
		if off+13+payloadLen > len(data) {
			break // torn tail — stop, like scanRecords
		}
		if recType == byte(WALRecCheckpointV2) && payloadLen >= 56 {
			lastCkpt = off
		}
		off += 13 + payloadLen
	}
	if lastCkpt < 0 {
		t.Fatalf("setup: no 0x05 record with a ClockHigh field in %s; nothing to patch", walPath)
	}
	fieldOff := lastCkpt + 13 + 48
	before := binary.BigEndian.Uint64(data[fieldOff : fieldOff+8])
	binary.BigEndian.PutUint64(data[fieldOff:fieldOff+8], val)
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write patched WAL: %v", err)
	}
	// Re-read the patched field to verify that the write reached its target.
	verify, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("re-read WAL: %v", err)
	}
	got := binary.BigEndian.Uint64(verify[fieldOff : fieldOff+8])
	if got != val {
		t.Fatalf("patch did not apply: field reads %d, want %d", got, val)
	}
	t.Logf("patched final 0x05 at file offset %d: ClockHigh %d -> %d", fieldOff, before, val)
}

// appendMirroredRawCheckpointForTest appends an unframed, fingerprint-less
// 0x05 checkpoint with the current final checkpoint's root, LamportHigh,
// CutSeq, and ClockHigh. The bridge writes 0x06 CRC-framed checkpoints, so
// patching one of those would correctly fail the CRC check before decode could
// clamp ClockHigh. These tests instead patch the legacy raw record that the
// clamp protects. Mirroring preserves the watermark and therefore the expected
// clamp floor of 9 and first mint of 10.
func appendMirroredRawCheckpointForTest(t *testing.T, walPath string) {
	t.Helper()
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("read final checkpoint to mirror: %v", err)
	}
	if !rep.HasCheckpoint {
		t.Fatalf("setup: no checkpoint to mirror")
	}
	c := rep.FinalCheckpt
	// 56-byte 0x05 payload: root(32)‖watermark(8)‖CutSeq(8)‖ClockHigh(8).
	payload := make([]byte, 56)
	copy(payload[0:32], c.MerkleRoot[:])
	binary.BigEndian.PutUint64(payload[32:40], c.LamportHigh)
	binary.BigEndian.PutUint64(payload[40:48], c.CutSeq)
	binary.BigEndian.PutUint64(payload[48:56], c.ClockHigh)
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("open WAL to append raw checkpoint: %v", err)
	}
	if err := wal.AppendCheckpointRawForTest(payload); err != nil {
		t.Fatalf("AppendCheckpointRawForTest: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("close WAL: %v", err)
	}
}

// clampObservation records the recovery evidence needed by the clamp tests.
type clampObservation struct {
	witness   *RecoveryWitness
	clock     uint64  // engine.LamportCounter() after recovery
	minted    uint64  // the first post-recovery dot's counter
	skewRate  float64 // LamportSnapshot().ObservedInboundRate after recovery
	skewBound uint64  // MaxAcceptableDotCounter after recovery
}

// recoverAndMint recovers a patched log through the bounded path and mints one
// local dot. The new counter must be the floored high-water plus one, neither
// zero after a wrap nor raw ClockHigh plus one.
func recoverAndMint(t *testing.T, walPath string, lfs *LocalFS) clampObservation {
	t.Helper()
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("recovery rejected an incredible ClockHigh instead of clamping it and using intact mutations: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if witness == nil {
		t.Fatalf("nil witness on a successful boot")
	}
	snap := engine.LamportSnapshot()
	clock := engine.LamportCounter() // recovered clock before the next mint
	dot := engine.InsertLocal(utf8EntityID(999), stagedEntry(999))
	return clampObservation{
		witness:   witness,
		clock:     clock,
		minted:    dot.Counter,
		skewRate:  snap.ObservedInboundRate,
		skewBound: eng.MaxAcceptableDotCounter(snap),
	}
}

// TestClockHighClampMaxUint64 checks that MaxUint64 never reaches the engine
// constructor. Recovery must succeed using the log's durable high-water, report
// the raw value and clamp, and mint a nonzero next counter.
func TestClockHighClampMaxUint64(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, liveClock := buildClockNailLog(t, lfs, clockGapAdvance, false) // ClockHigh=9,000,000 on disk, no 0x03
	if liveClock != clockGapAdvance {
		t.Fatalf("setup: live clock %d != %d", liveClock, clockGapAdvance)
	}
	// The unpatched log restores 9,000,000. Append a raw legacy checkpoint and
	// replace its ClockHigh with MaxUint64; editing the framed checkpoint would
	// instead be rejected by its CRC.
	appendMirroredRawCheckpointForTest(t, walPath)
	patchFinalCheckpointClockHigh(t, walPath, math.MaxUint64)
	obs := recoverAndMint(t, walPath, lfs)
	if !obs.witness.ClockHighClamped {
		t.Fatalf("ClockHigh=MaxUint64 reached the engine constructor without a clamp; witness=%+v", obs.witness)
	}
	if obs.witness.ClockHighRaw != math.MaxUint64 {
		t.Fatalf("witness.ClockHighRaw=%d, want %d so the original value remains observable", obs.witness.ClockHighRaw, uint64(math.MaxUint64))
	}
	// Eight mutations leave rep.LamportHigh at 9 and there are no advances. The
	// constructor therefore starts at max(9, 9), and the next counter is 10.
	if obs.clock != 9 {
		t.Fatalf("recovered clock %d, want durable high-water 9 after clamping", obs.clock)
	}
	if obs.minted != 10 {
		t.Fatalf("first post-recovery mint=%d, want 10; zero would indicate a wrapped clock", obs.minted)
	}
	// Constructor seeding must reset the skew rate, leaving bound 9+0+1000.
	if obs.skewRate != 0 || obs.skewBound != 1009 {
		t.Fatalf("constructor seed did not reset the skew envelope: rate=%v bound=%d, want 0/1009", obs.skewRate, obs.skewBound)
	}
	t.Logf("ClockHigh=MaxUint64 clamped to durable high-water; clock=9; first mint=10; skewBound=1009; raw=%d", obs.witness.ClockHighRaw)
}

// TestClockHighClampOneBitFlip flips the top byte to produce 2^63+7
// (9223372036854775815) and checks the same clamp and seed behavior as the
// MaxUint64 case.
func TestClockHighClampOneBitFlip(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, _ := buildClockNailLog(t, lfs, clockGapAdvance, false)
	const flipped = uint64(9223372036854775815)    // 2^63 + 7
	appendMirroredRawCheckpointForTest(t, walPath) // patch raw 0x05, not the 0x06 frame
	patchFinalCheckpointClockHigh(t, walPath, flipped)
	obs := recoverAndMint(t, walPath, lfs)
	if !obs.witness.ClockHighClamped || obs.witness.ClockHighRaw != flipped {
		t.Fatalf("one-bit-flipped ClockHigh %d was not reported clamped; witness=%+v", flipped, obs.witness)
	}
	if obs.clock != 9 || obs.minted != 10 {
		t.Fatalf("clock=%d minted=%d, want 9/10 after clamping 2^63+7", obs.clock, obs.minted)
	}
	if obs.skewRate != 0 || obs.skewBound != 1009 {
		t.Fatalf("skew envelope after clamp: rate=%v bound=%d, want 0/1009", obs.skewRate, obs.skewBound)
	}
	t.Logf("one-bit flip (2^63+7) clamped; clock=9; mint=10; skewBound=1009")
}

// TestClockHighClampBoundary checks both sides of MaxCredibleClockHigh. The
// ceiling itself is valid because checkMutationRecord rejects only values above
// maxPlausibleCounter; ceiling+1 must clamp.
func TestClockHighClampBoundary(t *testing.T) {
	t.Run("CeilingValueAccepted", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, _ := buildClockNailLog(t, lfs, clockGapAdvance, false)
		appendMirroredRawCheckpointForTest(t, walPath)
		patchFinalCheckpointClockHigh(t, walPath, MaxCredibleClockHigh)
		obs := recoverAndMint(t, walPath, lfs)
		if obs.witness.ClockHighClamped {
			t.Fatalf("ClockHigh at MaxCredibleClockHigh (%d) was clamped; the ceiling itself is valid", MaxCredibleClockHigh)
		}
		if obs.clock != MaxCredibleClockHigh || obs.minted != MaxCredibleClockHigh+1 {
			t.Fatalf("boundary: clock=%d minted=%d, want %d/%d without alteration", obs.clock, obs.minted, uint64(MaxCredibleClockHigh), uint64(MaxCredibleClockHigh)+1)
		}
	})
	t.Run("CeilingPlusOneClamped", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, _ := buildClockNailLog(t, lfs, clockGapAdvance, false)
		appendMirroredRawCheckpointForTest(t, walPath)
		patchFinalCheckpointClockHigh(t, walPath, MaxCredibleClockHigh+1)
		obs := recoverAndMint(t, walPath, lfs)
		if !obs.witness.ClockHighClamped || obs.clock != 9 || obs.minted != 10 {
			t.Fatalf("MaxCredibleClockHigh+1: clamped=%v clock=%d minted=%d, want true/9/10", obs.witness.ClockHighClamped, obs.clock, obs.minted)
		}
	})
}

// TestClockHighClampLegitimateLargeSurvives checks an uncorrupted ClockHigh of
// 9,000,000 with no 0x03 record. Although far above the log's mutation
// high-water, it is below MaxCredibleClockHigh and must pass through unchanged.
// TestControlNoRecordedAdvanceClockHighNail covers the same fixture; this test
// additionally requires ClockHighClamped=false.
func TestClockHighClampLegitimateLargeSurvives(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, _ := buildClockNailLog(t, lfs, clockGapAdvance, false) // legitimate, unpatched 9M
	obs := recoverAndMint(t, walPath, lfs)
	if obs.witness.ClockHighClamped {
		t.Fatalf("legitimate ClockHigh=%d was clamped; raw=%d", clockGapAdvance, obs.witness.ClockHighRaw)
	}
	if obs.clock != clockGapAdvance || obs.minted != clockGapAdvance+1 {
		t.Fatalf("control: clock=%d minted=%d, want %d/%d", obs.clock, obs.minted, clockGapAdvance, clockGapAdvance+1)
	}
	t.Logf("legitimate ClockHigh=9,000,000 passed through unclamped; mint=%d", obs.minted)
}
