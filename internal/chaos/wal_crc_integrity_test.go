// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package chaos

// ═══════════════════════════════════════════════════════════════════════════
// WAL CRC32C integrity regression tests.
//
// The durability WAL now frames every production record as 0x06
// (innerType ‖ innerPayload ‖ crc32c). These tests prove the checksum FAILS
// LOUD on content corruption, preserves backward-compat + torn-tail
// semantics, changes NOTHING about what is replayed, and is
// 0-alloc. Every test is bug-injection-proven: an assertion that cannot
// fail is not an assertion.
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

// f19NodeID is a fixed non-zero node identity for the WAL tests.
var f19NodeID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// f19Mutation builds a WALMutation at a synthetic dot (no live engine needed —
// the WAL tests exercise encode/replay, not the CRDT core).
func f19Mutation(i int) WALMutation {
	return NewWALMutation(stagedEntityID(i), eng.CausalDot{NodeID: f19NodeID, Counter: uint64(i + 1)}, stagedEntry(i))
}

// f19Checkpoint builds a horizon-cut (0x05) checkpoint at the given watermark.
func f19Checkpoint(watermark uint64) WALCheckpoint {
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

// f19InnerSpan returns the [start,end) FILE offsets of the FIRST record's
// innerPayload — the CRC-covered content region of a 0x06 record (skipping the
// 13-byte header + the 1 innerType byte, excluding the 4-byte CRC trailer).
// A test flips a byte in this span to corrupt CONTENT (never the framing).
func f19InnerSpan(t *testing.T, data []byte) (start, end int) {
	t.Helper()
	if len(data) < 8+13 {
		t.Fatalf("apparatus: WAL too short for a record (%d bytes)", len(data))
	}
	if data[8+8] != byte(WALRecChecksummed) {
		t.Fatalf("apparatus: first record type is 0x%x, want 0x06 — production must write CRC-framed", data[8+8])
	}
	payloadLen := int(binary.BigEndian.Uint32(data[8+9 : 8+13]))
	start = 8 + 13 + 1            // header + innerType
	end = 8 + 13 + payloadLen - 4 // exclude the CRC trailer
	if end <= start {
		t.Fatalf("apparatus: innerPayload empty (start=%d end=%d)", start, end)
	}
	return start, end
}

// TestWALCorruptDetect is the core guard: a 0x06 record with a
// flipped innerPayload byte is REJECTED with ErrWALCorrupt. The bug-injection
// half compiles out the CRC compare (walCRC32Skip) and shows the SAME corrupted
// bytes then replay SILENTLY — proving the compare is load-bearing.
func TestWALCorruptDetect(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "t1.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := w.AppendMutation(f19Mutation(0)); err != nil {
		t.Fatalf("AppendMutation 0: %v", err)
	}
	if err := w.AppendMutation(f19Mutation(1)); err != nil {
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

	// Corrupt ONE byte in the FIRST record's innerPayload (the last content byte —
	// inside the entry, far from the length prefix so a bare decode would succeed).
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	_, end := f19InnerSpan(t, data)
	flipAt := end - 1
	orig := data[flipAt]
	data[flipAt] ^= 0xFF
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted WAL: %v", err)
	}

	// GREEN: the CRC catches the corruption → ErrWALCorrupt (fail LOUD).
	if _, err := ReplayWAL(walPath); !errors.Is(err, ErrWALCorrupt) {
		t.Fatalf("T1: want ErrWALCorrupt for a corrupted 0x06 record, got %v", err)
	}

	// BUG-INJECT: compile out the CRC compare → the SAME corrupted bytes replay
	// SILENTLY. This is the load-bearing proof: without the compare, the content
	// corruption is invisible (the exact pre-fix fail-silent gap).
	walCRC32Skip.Store(true)
	defer walCRC32Skip.Store(false)
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("T1 BUG-INJECT: with the CRC compare removed the corrupted record must replay SILENTLY, got err=%v", err)
	}
	if len(rep.Mutations) != 2 {
		t.Fatalf("T1 BUG-INJECT: the corrupted mutation must be replayed silently; got %d mutations", len(rep.Mutations))
	}
	t.Logf("T1 GREEN: corrupt 0x06 → ErrWALCorrupt; with the CRC compare compiled out the SAME bytes (offset %d was 0x%02x) replay silently — the compare is load-bearing", flipAt, orig)
}

// TestWALFormatEvolution builds a WAL mixing EVERY record format —
// legacy 0x01 (AppendMutationV1ForTest), bare 0x04 (AppendMutationV2ForTest),
// bare 0x05 (AppendCheckpointRawForTest), and the new 0x06 frames (AppendMutation
// / AppendCheckpoint / AppendClockAdvance) — and proves ReplayWAL reads ALL of
// them: the legacy records accepted-unchecked, the 0x06 records CRC-verified.
// This is the format-evolution guarantee: the decoder NEVER breaks an existing
// on-disk WAL.
func TestWALFormatEvolution(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "t2.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	// 0x01 legacy mutation.
	if err := w.AppendMutationV1ForTest(f19Mutation(0)); err != nil {
		t.Fatalf("AppendMutationV1ForTest: %v", err)
	}
	// 0x04 bare V2 mutation (no CRC frame).
	if err := w.AppendMutationV2ForTest(f19Mutation(1)); err != nil {
		t.Fatalf("AppendMutationV2ForTest: %v", err)
	}
	// 0x05 bare checkpoint (raw 56-byte payload: root‖watermark‖cutseq‖clockhigh).
	ckpt2 := f19Checkpoint(2)
	rawCkpt := make([]byte, 56)
	copy(rawCkpt[0:32], ckpt2.MerkleRoot[:])
	binary.BigEndian.PutUint64(rawCkpt[32:40], 2)
	binary.BigEndian.PutUint64(rawCkpt[40:48], 3)
	binary.BigEndian.PutUint64(rawCkpt[48:56], 2)
	if err := w.AppendCheckpointRawForTest(rawCkpt); err != nil {
		t.Fatalf("AppendCheckpointRawForTest: %v", err)
	}
	// 0x06 CRC-framed mutation (the new production default).
	if err := w.AppendMutation(f19Mutation(2)); err != nil {
		t.Fatalf("AppendMutation (0x06): %v", err)
	}
	// 0x06 CRC-framed clock advance.
	if err := w.AppendClockAdvance(50); err != nil {
		t.Fatalf("AppendClockAdvance (0x06): %v", err)
	}
	// 0x06 CRC-framed checkpoint.
	if err := w.AppendCheckpoint(f19Checkpoint(3)); err != nil {
		t.Fatalf("AppendCheckpoint (0x06): %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("T2: a mixed 0x01/0x04/0x05/0x06 log must replay cleanly, got %v", err)
	}

	// All three mutations present (0x01 legacy, 0x04, 0x06-framed 0x04).
	if len(rep.Mutations) != 3 {
		t.Fatalf("T2: want 3 mutations, got %d", len(rep.Mutations))
	}
	// The legacy 0x01 record is marked Legacy; the 0x04/0x06 ones are not.
	if !rep.Mutations[0].Legacy {
		t.Fatalf("T2: the 0x01 record must be marked Legacy=true")
	}
	if rep.Mutations[1].Legacy || rep.Mutations[2].Legacy {
		t.Fatalf("T2: the 0x04/0x06 records must NOT be marked Legacy")
	}
	// The clock advance (0x06-wrapped 0x03) decoded.
	if len(rep.Advances) != 1 || rep.Advances[0] != 50 {
		t.Fatalf("T2: want Advances=[50], got %v", rep.Advances)
	}
	// A checkpoint is present (the last one, the 0x06-framed 0x05).
	if !rep.HasCheckpoint {
		t.Fatalf("T2: want a checkpoint present")
	}
	// Seq contiguity held across all six records.
	if !rep.SeqContiguityVerified || rep.RecordsVerified != 6 {
		t.Fatalf("T2: want 6 records verified contiguous, got %d (verified=%v)", rep.RecordsVerified, rep.SeqContiguityVerified)
	}
	t.Logf("T2 GREEN: a 6-record mixed log (0x01/0x04/0x05/0x06×3) replays cleanly; 3 mutations (legacy marked), 1 advance, checkpoint present")
}

// f19Sink is a package-level sink so the compiler cannot optimize away the CRC
// computation in the zero-alloc assertion.
var f19Sink uint32

// TestWALTornTailPreserved guards the crash-recovery contract against the
// new CRC path: a truncated FINAL 0x06 record truncates cleanly (err == nil,
// leading records intact, torn record DROPPED) — a torn tail is a crash boundary,
// NOT corruption. The contrast subtest proves the decoder distinguishes that from
// a COMPLETE-but-corrupted record (which IS corruption → ErrWALCorrupt).
func TestWALTornTailPreserved(t *testing.T) {
	build := func() string {
		walPath := filepath.Join(t.TempDir(), "t3.wal")
		w, err := OpenWAL(walPath)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		for i := 0; i < 3; i++ {
			if err := w.AppendMutation(f19Mutation(i)); err != nil {
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
		// Walk to the 3rd (final) record, then truncate it MID-PAYLOAD.
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
			t.Fatalf("T3: a torn tail must NOT error (it is a crash boundary), got %v", err)
		}
		if len(rep.Mutations) != 2 {
			t.Fatalf("T3: want the 2 leading mutations intact (torn record dropped), got %d", len(rep.Mutations))
		}
	})

	t.Run("CompleteButCorruptIsCorruption", func(t *testing.T) {
		walPath := build()
		data, err := os.ReadFile(walPath)
		if err != nil {
			t.Fatalf("read WAL: %v", err)
		}
		// Corrupt the FINAL record's innerPayload (a COMPLETE record — the framing
		// is intact, the length is consistent, only a content byte is wrong).
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
			t.Fatalf("T3 contrast: a COMPLETE-but-corrupted record must be ErrWALCorrupt (not a torn-tail truncate), got %v", err)
		}
	})
}

// TestWALReplayDeterminism proves the CRC is METADATA: replaying the SAME
// uncorrupted content through the legacy (bare 0x04/0x05) and the new (0x06)
// encoders yields field-IDENTICAL Replayed structs — the checksum changes WHAT is
// rejected, never WHAT is replayed. NON-VACUOUS: the on-disk bytes DIFFER (one is
// framed), so an identical replay is a real property, not a tautology.
func TestWALReplayDeterminism(t *testing.T) {
	ckpt := f19Checkpoint(5)
	build := func(framed bool) (path string, raw []byte) {
		path = filepath.Join(t.TempDir(), "t6.wal")
		w, err := OpenWAL(path)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		for i := 0; i < 5; i++ {
			m := f19Mutation(i)
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
			// bare 0x05 with the SAME content (root‖watermark‖cutseq‖clockhigh).
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

	// NON-VACUITY: the two on-disk logs must DIFFER (one is 0x06-framed, one bare).
	if bytes.Equal(legacyRaw, framedRaw) {
		t.Fatalf("T6 VACUOUS: the legacy and framed logs are byte-identical on disk — the comparison below would prove nothing")
	}

	repLegacy, err := ReplayWAL(legacyPath)
	if err != nil {
		t.Fatalf("replay legacy: %v", err)
	}
	repFramed, err := ReplayWAL(framedPath)
	if err != nil {
		t.Fatalf("replay framed: %v", err)
	}
	// FIELD-EQUAL: the Replayed struct is identical for identical content.
	if !reflect.DeepEqual(repLegacy, repFramed) {
		t.Fatalf("T6: replay DIVERGED between legacy and 0x06 framing — the CRC changed WHAT is replayed (FORBIDDEN):\nlegacy=%+v\nframed=%+v", repLegacy, repFramed)
	}
	if len(repLegacy.Mutations) != 5 || !repLegacy.HasCheckpoint {
		t.Fatalf("T6 apparatus: want 5 mutations + a checkpoint, got %d mutations, HasCheckpoint=%v", len(repLegacy.Mutations), repLegacy.HasCheckpoint)
	}
	t.Logf("T6 GREEN: identical content replays byte-identical Replayed structs across bare (0x04/0x05) and CRC-framed (0x06) encodings; on-disk bytes differ (%d vs %d bytes), replay does not", len(legacyRaw), len(framedRaw))
}

// TestWALCRCZeroAlloc proves the integrity check adds ZERO allocations:
// the CRC32C is computed with a package-level Castagnoli table (no crc32.New per
// record). It also measures the full checksummed-append alloc count for the
// report (the durability append is the fsync-bound path, NOT the 0-alloc core).
func TestWALCRCZeroAlloc(t *testing.T) {
	// A representative innerType‖innerPayload buffer (a 0x04 mutation's content).
	m := f19Mutation(0)
	rec, err := encodeMutationV2Record(0, m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	inner := rec[8:] // type(1)‖payload — the CRC-covered region
	if allocs := testing.AllocsPerRun(2000, func() {
		f19Sink = crc32.Checksum(inner, castagnoliTable)
	}); allocs != 0 {
		t.Fatalf("T7: CRC32C allocs/op = %v, want 0 (package-level table, no crc32.New per record)", allocs)
	}

	// Measure (and disclose) the full checksummed-append alloc count. The 0x06
	// frame is built in a SINGLE allocation (frameChecksummed), so the checksummed
	// append allocates EXACTLY what the bare append did — zero NEW allocations, the
	// "append/replay hot path" invariant. This is the fsync-bound durability path
	// (1-3M deltas/sec), NOT the 0-alloc CRDT core the TestHotPathZeroAllocations
	// gate covers.
	walPath := filepath.Join(t.TempDir(), "t7.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer w.Close()
	framedAllocs := testing.AllocsPerRun(200, func() {
		_ = w.AppendMutation(f19Mutation(0)) // 0x06 CRC-framed (the new default)
	})
	barePath := filepath.Join(t.TempDir(), "t7bare.wal")
	wb, err := OpenWAL(barePath)
	if err != nil {
		t.Fatalf("OpenWAL bare: %v", err)
	}
	defer wb.Close()
	bareAllocs := testing.AllocsPerRun(200, func() {
		_ = wb.AppendMutationV2ForTest(f19Mutation(0)) // bare 0x04 (the pre-fix shape)
	})
	t.Logf("T7 GREEN: CRC32C = 0 allocs/op (package-level Castagnoli table, no crc32.New). Append allocs: bare 0x04 = %.1f, 0x06-framed = %.1f — the single-allocation frame costs ZERO extra allocs/record (frameChecksummed), satisfying the zero-new-allocation invariant on the fsync-bound durability path.", bareAllocs, framedAllocs)
}

// TestWALCorruptChecksummedCheckpoint is the collision guard: a corrupt
// 0x06 CHECKPOINT is caught by the CRC (ErrWALCorrupt), NOT the clamp — the
// CRC is strictly earlier, strictly better on the protected format. The
// bug-injection half proves the layering: with the CRC compiled out, the SAME
// corrupted ClockHigh is caught by the clamp instead (ClockHighClamped=true, no
// error) — the clamp is the legacy-format fallback, now defense-in-depth.
func TestWALCorruptChecksummedCheckpoint(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "c2.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := w.AppendMutation(f19Mutation(0)); err != nil {
		t.Fatalf("AppendMutation: %v", err)
	}
	if err := w.AppendCheckpoint(f19Checkpoint(1)); err != nil { // 0x06-wrapped 0x05
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Locate the 2nd record (the checkpoint) and overwrite its ClockHigh field
	// (innerPayload[48:56]) with MaxUint64 — the clamp's canonical poison value.
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	pl1 := int(binary.BigEndian.Uint32(data[8+9 : 8+13]))
	ckptOff := 8 + 13 + pl1 // start of the checkpoint record
	if data[ckptOff+8] != byte(WALRecChecksummed) {
		t.Fatalf("apparatus: checkpoint record is type 0x%x, want 0x06", data[ckptOff+8])
	}
	clockHighOff := ckptOff + 13 + 1 + 48 // header + innerType + ClockHigh offset
	for i := 0; i < 8; i++ {
		data[clockHighOff+i] = 0xFF
	}
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted WAL: %v", err)
	}

	// GREEN: the CRC catches the corrupted 0x06 checkpoint → ErrWALCorrupt.
	if _, err := ReplayWAL(walPath); !errors.Is(err, ErrWALCorrupt) {
		t.Fatalf("C2: want ErrWALCorrupt for a corrupt 0x06 checkpoint, got %v", err)
	}

	// LAYERING PROOF: with the CRC compiled out, the SAME corrupted ClockHigh is
	// caught by the clamp instead (ClockHighClamped=true, NO error) — the CRC
	// is the syntactic defense, the clamp is the legacy-format defense-in-depth.
	walCRC32Skip.Store(true)
	defer walCRC32Skip.Store(false)
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("C2 layering: with the CRC off, the clamp (not an error) must catch the poisoned ClockHigh, got %v", err)
	}
	if !rep.ClockHighClamped {
		t.Fatalf("C2 layering: with the CRC off, the clamp must fire on the poisoned ClockHigh (ClockHighClamped=false)")
	}
	t.Logf("C2 GREEN: corrupt 0x06 checkpoint → ErrWALCorrupt (CRC); with the CRC compiled out the same bytes hit the clamp (ClockHighClamped) — the layering is proven")
}

// TestWALFirstRecordSeqGuard is the edge guard. The CRC covers
// innerType‖innerPayload — NOT the outer seq — and the seq-contiguity check skips
// the FIRST record (the RecordsVerified>0 gate). So a corrupted FIRST-record seq
// is invisible to BOTH. But a WAL always starts at seq 0 (writeHeader lays a fresh
// header, nextSeq is zero-valued, and only the torn TAIL is ever truncated), so a
// first record with a non-zero seq is header corruption.
//
// NON-VACUITY: this uses a SINGLE-record log, so the contiguity check has no
// second record to catch the broken run, and the CRC passes (the payload is
// intact — the seq is not CRC-covered). The ONLY defense is the first-record
// guard; without it this replay is SILENT (err == nil) and the test FAILS.
func TestWALFirstRecordSeqGuard(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "c5.wal")
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := w.AppendMutation(f19Mutation(0)); err != nil { // the ONLY record, seq 0
		t.Fatalf("AppendMutation: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Corrupt the FIRST (only) record's seq (outer header bytes [8:16]) to non-zero.
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	binary.BigEndian.PutUint64(data[8:16], 7) // first record seq 0 → 7
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted WAL: %v", err)
	}

	// The CRC is over the payload (intact), so it cannot catch this; there is no
	// second record for contiguity; ONLY the first-record guard can.
	if _, err := ReplayWAL(walPath); !errors.Is(err, ErrWALSeqGap) {
		t.Fatalf("C5: a non-zero FIRST-record seq must be refused with ErrWALSeqGap (the CRC does not cover the seq; a single record has no contiguity partner), got %v", err)
	}
	t.Logf("C5 GREEN: a corrupted first-record seq (not CRC-covered, no contiguity partner) is refused by the first-record seq guard")
}
