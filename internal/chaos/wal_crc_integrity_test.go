// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package chaos

// ═══════════════════════════════════════════════════════════════════════════
// WAL CRC32C integrity tests.
//
// Production WAL records are wrapped in WALRecChecksummed (0x06):
// innerType ‖ innerPayload ‖ crc32c. These tests verify content-corruption
// detection, backward compatibility with legacy 0x01/0x04/0x05 records,
// torn-tail truncation, replay equivalence, and zero additional allocations.
// ═══════════════════════════════════════════════════════════════════════════

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// walCRCNodeID is a fixed non-zero node identity for the WAL negative-control tests.
var walCRCNodeID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// walCRCMutation builds a WALMutation at a synthetic dot (no live engine needed —
// the WAL negative-control tests exercise encode/replay, not the CRDT core).
func walCRCMutation(i int) WALMutation {
	return NewWALMutation(stagedEntityID(i), eng.CausalDot{NodeID: walCRCNodeID, Counter: uint64(i + 1)}, stagedEntry(i))
}

// walCRCCheckpoint builds a horizon-cut (0x05) checkpoint at the given watermark.
func walCRCCheckpoint(watermark uint64) WALCheckpoint {
	var root [32]byte
	for i := range root {
		root[i] = byte(0xA0 + i)
	}
	return WALCheckpoint{
		MerkleRoot:  root,
		LamportHigh: watermark,
		CutSeq:      watermark + 1,
		HasCutSeq:   true,
		ClockHigh:   watermark, // a credible (<= ceiling) live clock
	}
}

// walCRCInnerSpan returns the [start,end) file offsets of the first record's
// innerPayload (excluding the 13-byte header, innerType byte, and 4-byte CRC).
func walCRCInnerSpan(t *testing.T, data []byte) (start, end int) {
	t.Helper()
	if len(data) < 8+13 {
		t.Fatalf("setup: WAL too short for a record (%d bytes)", len(data))
	}
	if data[8+8] != byte(WALRecChecksummed) {
		t.Fatalf("setup: first record type is 0x%x, want 0x06 — production must write CRC-framed", data[8+8])
	}
	payloadLen := int(binary.BigEndian.Uint32(data[8+9 : 8+13]))
	start = 8 + 13 + 1            // header + innerType
	end = 8 + 13 + payloadLen - 4 // exclude the CRC trailer
	if end <= start {
		t.Fatalf("setup: innerPayload empty (start=%d end=%d)", start, end)
	}
	return start, end
}

// TestWALCorruptDetect verifies that a flipped innerPayload byte in a 0x06
// record fails with ErrWALCorrupt, while disabling the comparison via
// walCRC32Skip allows the corrupted payload through.
func TestWALCorruptDetect(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "t1.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := w.AppendMutation(walCRCMutation(0)); err != nil {
		t.Fatalf("AppendMutation 0: %v", err)
	}
	if err := w.AppendMutation(walCRCMutation(1)); err != nil {
		t.Fatalf("AppendMutation 1: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Sanity: the uncorrupted log replays clean (2 mutations).
	pre, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("clean replay: %v", err)
	}
	if len(pre.Mutations) != 2 {
		t.Fatalf("clean replay: want 2 mutations, got %d", len(pre.Mutations))
	}

	// Corrupt one byte in the first record's innerPayload (the last content byte —
	// inside the entry, far from the length prefix so a bare decode would succeed).
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	_, end := walCRCInnerSpan(t, data)
	flipAt := end - 1
	orig := data[flipAt]
	data[flipAt] ^= 0xFF
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted WAL: %v", err)
	}

	// The CRC catches the corruption -> ErrWALCorrupt.
	if _, err := ReplayWAL(walPath); !errors.Is(err, ErrWALCorrupt) {
		t.Fatalf("want ErrWALCorrupt for a corrupted 0x06 record, got %v", err)
	}

	// Fault-injection control: disable the CRC comparison to confirm it is
	// the checksum comparison catching the corruption.
	walCRC32Skip.Store(true)
	defer walCRC32Skip.Store(false)
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("fault-injection: with CRC compare skipped the corrupted record must replay, got err=%v", err)
	}
	if len(rep.Mutations) != 2 {
		t.Fatalf("fault-injection: expected 2 replayed mutations with CRC skipped, got %d", len(rep.Mutations))
	}
	t.Logf("corrupt 0x06 returned ErrWALCorrupt; with CRC skip enabled the corrupted payload (offset %d was 0x%02x) replayed", flipAt, orig)
}

// TestWALFormatEvolution builds a WAL mixing legacy 0x01, bare 0x04, bare 0x05,
// and CRC-framed 0x06 records, verifying that ReplayWAL reads all of them cleanly.
func TestWALFormatEvolution(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "t2.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	// 0x01 legacy mutation.
	if err := w.AppendMutationV1ForTest(walCRCMutation(0)); err != nil {
		t.Fatalf("AppendMutationV1ForTest: %v", err)
	}
	// 0x04 bare V2 mutation (no CRC frame).
	if err := w.AppendMutationV2ForTest(walCRCMutation(1)); err != nil {
		t.Fatalf("AppendMutationV2ForTest: %v", err)
	}
	// 0x05 bare checkpoint (raw 56-byte payload: root‖watermark‖cutseq‖clockhigh).
	ckpt2 := walCRCCheckpoint(2)
	rawCkpt := make([]byte, 56)
	copy(rawCkpt[0:32], ckpt2.MerkleRoot[:])
	binary.BigEndian.PutUint64(rawCkpt[32:40], 2)
	binary.BigEndian.PutUint64(rawCkpt[40:48], 3)
	binary.BigEndian.PutUint64(rawCkpt[48:56], 2)
	if err := w.AppendCheckpointRawForTest(rawCkpt); err != nil {
		t.Fatalf("AppendCheckpointRawForTest: %v", err)
	}
	// 0x06 CRC-framed mutation (the new production default).
	if err := w.AppendMutation(walCRCMutation(2)); err != nil {
		t.Fatalf("AppendMutation (0x06): %v", err)
	}
	// 0x06 CRC-framed clock advance.
	if err := w.AppendClockAdvance(50); err != nil {
		t.Fatalf("AppendClockAdvance (0x06): %v", err)
	}
	// 0x06 CRC-framed checkpoint.
	if err := w.AppendCheckpoint(walCRCCheckpoint(3)); err != nil {
		t.Fatalf("AppendCheckpoint (0x06): %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("mixed 0x01/0x04/0x05/0x06 log must replay cleanly, got %v", err)
	}

	// All three mutations present (0x01 legacy, 0x04, 0x06-framed 0x04).
	if len(rep.Mutations) != 3 {
		t.Fatalf("want 3 mutations, got %d", len(rep.Mutations))
	}
	// The legacy 0x01 record is marked Legacy; the 0x04/0x06 ones are not.
	if !rep.Mutations[0].Legacy {
		t.Fatalf("0x01 record must be marked Legacy=true")
	}
	if rep.Mutations[1].Legacy || rep.Mutations[2].Legacy {
		t.Fatalf("0x04/0x06 records must not be marked Legacy")
	}
	// The clock advance (0x06-wrapped 0x03) decoded.
	if len(rep.Advances) != 1 || rep.Advances[0] != 50 {
		t.Fatalf("want Advances=[50], got %v", rep.Advances)
	}
	// A checkpoint is present (the last one, the 0x06-framed 0x05).
	if !rep.HasCheckpoint {
		t.Fatalf("want a checkpoint present")
	}
	// Seq contiguity held across all six records.
	if !rep.SeqContiguityVerified || rep.RecordsVerified != 6 {
		t.Fatalf("want 6 records verified contiguous, got %d (verified=%v)", rep.RecordsVerified, rep.SeqContiguityVerified)
	}
	t.Logf("mixed 6-record log (0x01/0x04/0x05/0x06x3) replayed cleanly; 3 mutations, 1 advance, checkpoint present")
}

// walCRCSink prevents compiler dead-code elimination of CRC32C calls in alloc checks.
var walCRCSink uint32

// TestWALTornTailPreserved verifies that a truncated final 0x06 record drops
// cleanly as a crash boundary while a complete record with corrupted content
// fails with ErrWALCorrupt.
func TestWALTornTailPreserved(t *testing.T) {
	build := func() string {
		walPath := filepath.Join(t.TempDir(), "t3.wal")
		w, err := OpenWAL(walPath)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		for i := 0; i < 3; i++ {
			if err := w.AppendMutation(walCRCMutation(i)); err != nil {
				t.Fatalf("AppendMutation %d: %v", i, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		return walPath
	}

	t.Run("TornTailTruncatesCleanly", func(t *testing.T) {
		walPath := build()
		data, err := os.ReadFile(walPath)
		if err != nil {
			t.Fatalf("read WAL: %v", err)
		}
		// Walk to the third (final) record, then truncate it within its payload.
		off := 8
		for r := 0; r < 2; r++ {
			pl := int(binary.BigEndian.Uint32(data[off+9 : off+13]))
			off += 13 + pl
		}
		torn := data[:off+13+6] // header + only 6 of the payload bytes
		if err := os.WriteFile(walPath, torn, 0o644); err != nil {
			t.Fatalf("write torn WAL: %v", err)
		}
		rep, err := ReplayWAL(walPath)
		if err != nil {
			t.Fatalf("torn tail must not error, got %v", err)
		}
		if len(rep.Mutations) != 2 {
			t.Fatalf("want the 2 leading mutations intact (torn record dropped), got %d", len(rep.Mutations))
		}
	})

	t.Run("CompleteButCorruptIsCorruption", func(t *testing.T) {
		walPath := build()
		data, err := os.ReadFile(walPath)
		if err != nil {
			t.Fatalf("read WAL: %v", err)
		}
		// Corrupt the final record's innerPayload with framing intact.
		off := 8
		for r := 0; r < 2; r++ {
			pl := int(binary.BigEndian.Uint32(data[off+9 : off+13]))
			off += 13 + pl
		}
		payloadLen := int(binary.BigEndian.Uint32(data[off+9 : off+13]))
		lastContent := off + 13 + payloadLen - 4 - 1 // last innerPayload byte (pre-CRC)
		data[lastContent] ^= 0xFF
		if err := os.WriteFile(walPath, data, 0o644); err != nil {
			t.Fatalf("write corrupted WAL: %v", err)
		}
		if _, err := ReplayWAL(walPath); !errors.Is(err, ErrWALCorrupt) {
			t.Fatalf("complete-but-corrupt record must return ErrWALCorrupt, got %v", err)
		}
	})
}

// TestWALReplayDeterminism verifies that bare (0x04/0x05) and CRC-framed (0x06)
// encodings produce field-identical Replayed structs even though on-disk bytes differ.
func TestWALReplayDeterminism(t *testing.T) {
	ckpt := walCRCCheckpoint(5)
	build := func(framed bool) (path string, raw []byte) {
		path = filepath.Join(t.TempDir(), "t6.wal")
		w, err := OpenWAL(path)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		for i := 0; i < 5; i++ {
			m := walCRCMutation(i)
			var err error
			if framed {
				err = w.AppendMutation(m) // 0x06 CRC-framed
			} else {
				err = w.AppendMutationV2ForTest(m) // bare 0x04
			}
			if err != nil {
				t.Fatalf("append %d: %v", i, err)
			}
		}
		if framed {
			if err := w.AppendCheckpoint(ckpt); err != nil { // 0x06-wrapped 0x05
				t.Fatalf("AppendCheckpoint: %v", err)
			}
		} else {
			// bare 0x05 with the same content (root‖watermark‖cutseq‖clockhigh).
			raw56 := make([]byte, 56)
			copy(raw56[0:32], ckpt.MerkleRoot[:])
			binary.BigEndian.PutUint64(raw56[32:40], ckpt.LamportHigh)
			binary.BigEndian.PutUint64(raw56[40:48], ckpt.CutSeq)
			binary.BigEndian.PutUint64(raw56[48:56], ckpt.ClockHigh)
			if err := w.AppendCheckpointRawForTest(raw56); err != nil {
				t.Fatalf("AppendCheckpointRawForTest: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		raw, err = os.ReadFile(path)
		if err != nil {
			t.Fatalf("read WAL: %v", err)
		}
		return path, raw
	}

	legacyPath, legacyRaw := build(false)
	framedPath, framedRaw := build(true)

	// The two on-disk logs must differ (one is 0x06-framed, one bare).
	if bytes.Equal(legacyRaw, framedRaw) {
		t.Fatalf("legacy and framed logs are byte-identical on disk")
	}

	repLegacy, err := ReplayWAL(legacyPath)
	if err != nil {
		t.Fatalf("replay legacy: %v", err)
	}
	repFramed, err := ReplayWAL(framedPath)
	if err != nil {
		t.Fatalf("replay framed: %v", err)
	}
	// The Replayed struct is identical for identical content.
	if !reflect.DeepEqual(repLegacy, repFramed) {
		t.Fatalf("replay diverged between bare and 0x06 framing:\nlegacy=%+v\nframed=%+v", repLegacy, repFramed)
	}
	if len(repLegacy.Mutations) != 5 || !repLegacy.HasCheckpoint {
		t.Fatalf("setup: want 5 mutations + a checkpoint, got %d mutations, HasCheckpoint=%v", len(repLegacy.Mutations), repLegacy.HasCheckpoint)
	}
	t.Logf("identical content produced identical Replayed structs across bare and 0x06 encodings (on-disk %d vs %d bytes)", len(legacyRaw), len(framedRaw))
}

// TestWALCRCZeroAlloc verifies that CRC32C computation uses zero allocations via
// the package-level Castagnoli table and measures append allocation parity.
func TestWALCRCZeroAlloc(t *testing.T) {
	// A representative innerType‖innerPayload buffer (a 0x04 mutation's content).
	m := walCRCMutation(0)
	rec, err := encodeMutationV2Record(0, m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	inner := rec[8:] // type(1)‖payload — the CRC-covered region
	if allocs := testing.AllocsPerRun(2000, func() {
		walCRCSink = crc32.Checksum(inner, castagnoliTable)
	}); allocs != 0 {
		t.Fatalf("CRC32C allocs/op = %v, want 0 (package-level table)", allocs)
	}

	// Compare allocations between bare 0x04 and single-allocation 0x06-framed append.
	walPath := filepath.Join(t.TempDir(), "t7.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer w.Close()
	framedAllocs := testing.AllocsPerRun(200, func() {
		_ = w.AppendMutation(walCRCMutation(0)) // 0x06 CRC-framed
	})
	barePath := filepath.Join(t.TempDir(), "t7bare.wal")
	wb, err := OpenWAL(barePath)
	if err != nil {
		t.Fatalf("OpenWAL bare: %v", err)
	}
	defer wb.Close()
	bareAllocs := testing.AllocsPerRun(200, func() {
		_ = wb.AppendMutationV2ForTest(walCRCMutation(0)) // bare 0x04
	})
	t.Logf("CRC32C = 0 allocs/op; append allocs: bare 0x04 = %.1f, 0x06-framed = %.1f", bareAllocs, framedAllocs)
}

// TestWALCorruptChecksummedCheckpoint verifies that a corrupted 0x06 checkpoint
// fails with ErrWALCorrupt, while disabling the CRC check allows the ClockHigh
// sanity clamp to trigger fallback clamping instead.
func TestWALCorruptChecksummedCheckpoint(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "c2.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := w.AppendMutation(walCRCMutation(0)); err != nil {
		t.Fatalf("AppendMutation: %v", err)
	}
	if err := w.AppendCheckpoint(walCRCCheckpoint(1)); err != nil { // 0x06-wrapped 0x05
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Locate the 2nd record (the checkpoint) and overwrite its ClockHigh field
	// (innerPayload[48:56]) with MaxUint64.
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	pl1 := int(binary.BigEndian.Uint32(data[8+9 : 8+13]))
	ckptOff := 8 + 13 + pl1 // start of the checkpoint record
	if data[ckptOff+8] != byte(WALRecChecksummed) {
		t.Fatalf("setup: checkpoint record is type 0x%x, want 0x06", data[ckptOff+8])
	}
	clockHighOff := ckptOff + 13 + 1 + 48 // header + innerType + ClockHigh offset
	for i := 0; i < 8; i++ {
		data[clockHighOff+i] = 0xFF
	}
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted WAL: %v", err)
	}

	// The CRC catches the corrupted 0x06 checkpoint -> ErrWALCorrupt.
	if _, err := ReplayWAL(walPath); !errors.Is(err, ErrWALCorrupt) {
		t.Fatalf("want ErrWALCorrupt for a corrupt 0x06 checkpoint, got %v", err)
	}

	// With the CRC skipped, the legacy ClockHigh clamp catches the corrupted field.
	walCRC32Skip.Store(true)
	defer walCRC32Skip.Store(false)
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("with CRC skipped, clamp must handle corrupted ClockHigh without error, got %v", err)
	}
	if !rep.ClockHighClamped {
		t.Fatalf("with CRC skipped, expected ClockHighClamped=true on corrupted ClockHigh")
	}
	t.Logf("corrupt 0x06 checkpoint returned ErrWALCorrupt; with CRC skipped, ClockHighClamped triggered")
}

// TestWALFirstRecordSeqGuard verifies that a single-record WAL whose first
// record sequence is non-zero is rejected with ErrWALSeqGap even though its
// inner payload CRC is intact.
func TestWALFirstRecordSeqGuard(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "c5.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := w.AppendMutation(walCRCMutation(0)); err != nil { // the only record, seq 0
		t.Fatalf("AppendMutation: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Corrupt the first (only) record's seq (outer header bytes [8:16]) to non-zero.
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	binary.BigEndian.PutUint64(data[8:16], 7) // first record seq 0 -> 7
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted WAL: %v", err)
	}

	// The CRC only covers the payload, so the first-record seq guard must catch this.
	if _, err := ReplayWAL(walPath); !errors.Is(err, ErrWALSeqGap) {
		t.Fatalf("non-zero first-record seq must return ErrWALSeqGap, got %v", err)
	}
	t.Logf("non-zero first-record seq rejected by first-record seq guard")
}
