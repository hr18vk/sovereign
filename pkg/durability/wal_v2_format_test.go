// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Tests for the full-fidelity WAL format and its compatibility edges
// (ADR-0045 §4 and ADR-0053). They cover complete entry restoration, state
// fingerprints, mixed legacy and current records, torn tails, and unknown
// record types.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// Full and bounded recovery must preserve every entry field.

// TestTailRoundTripsAllTenFields writes entries with temporal and H3 fields on
// both sides of a checkpoint. Bounded and full recovery must reproduce every
// entry exactly, including its original dot, and return the live Merkle root.
// A legacy 80-byte tail record cannot satisfy this contract because it omits
// ValidTimeStart, ValidTimeEnd, AssertionTime, DecisionTime, and H3Index.
func TestTailRoundTripsAllTenFields(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t6.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	for i := 0; i < 3; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), temporalEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	for i := 3; i < 6; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), temporalEntry(i)); err != nil {
			t.Fatalf("PutLocal tail %d: %v", i, err)
		}
	}
	liveEntries := collectEntries(t, live.Engine())
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	assertRecovered := func(t *testing.T, rec *eng.DeltaCRDTEngine, path string) {
		t.Helper()
		ents := collectEntries(t, rec)
		if len(ents) != 6 {
			t.Fatalf("%s: recovered %d entities, want 6", path, len(ents))
		}
		for i := 0; i < 6; i++ {
			id := utf8EntityID(i)
			got, want := ents[id], liveEntries[id]
			if len(got) != 1 || len(want) != 1 {
				t.Fatalf("%s: entity %s carries %d dots (live %d), want exactly 1", path, id, len(got), len(want))
			}
			if got[0] != want[0] {
				t.Errorf("%s: entity %s entry mismatch —\n  got  %+v\n  want %+v\n  (a WAL replay that loses temporal/H3 bytes is not a round-trip)",
					path, id, got[0], want[0])
			}
		}
		if got := rec.State().MerkleRoot(); got != liveRoot {
			t.Errorf("%s: root %x != live %x", path, got, liveRoot)
		}
	}

	recB, witnessB := recoverBounded(t, walPath, lfs)
	if !witnessB.Bounded {
		t.Fatalf("bounded path did not engage")
	}
	assertRecovered(t, recB, "bounded")

	recF, _ := recoverFull(t, walPath)
	assertRecovered(t, recF, "full")
}

// A fingerprint must distinguish equal roots with different entry bytes.

// TestFingerprintRejectsEqualRootWrongBytes changes ValidTimeStart while
// preserving the entry's dot. The Merkle roots must remain equal because they
// contain only dots, while StateFingerprint must distinguish the entries.
// Independently constructed engines with identical content must also produce
// equal fingerprints regardless of insertion order.
func TestFingerprintRejectsEqualRootWrongBytes(t *testing.T) {
	nodeID := testNodeID()
	base := exactRec(utf8EntityID(1), nodeID, 5, stagedDigest(1))
	alt := base
	alt.Entry.ValidTimeStart = 42 // different temporal bytes, same dot

	a := engineWith(t, nodeID, 1, base)
	b := engineWith(t, nodeID, 1, alt)

	if a.State().MerkleRoot() != b.State().MerkleRoot() {
		t.Fatalf("roots %x and %x differ despite equal dots", a.State().MerkleRoot(), b.State().MerkleRoot())
	}
	if StateFingerprint(a) == StateFingerprint(b) {
		t.Errorf("fingerprints are equal for entries with different ValidTimeStart")
	}

	// Control: identical content, independently constructed (different engine,
	// different insertion order across two entities) → same fingerprint.
	c1 := exactRec(utf8EntityID(1), nodeID, 5, stagedDigest(1))
	c2 := exactRec(utf8EntityID(2), nodeID, 6, stagedDigest(2))
	x := engineWith(t, nodeID, 1, c1, c2)
	y := engineWith(t, nodeID, 1, c2, c1) // reverse insertion order
	if StateFingerprint(x) != StateFingerprint(y) {
		t.Errorf("identical states have different fingerprints after reversed insertion order")
	}
}

// Mixed formats, torn tails, and unknown record types.

// TestMixedFormatTornTailUnknownType covers three format edges:
//
//   - A legacy 0x01 and full 0x04 record can share a log. Recovery counts the
//     legacy record, exposes fields it never stored as zero, and preserves all
//     fields of the full record.
//   - Replay stops at a torn tail. OpenWAL removes the partial bytes, preserves
//     NextSeq, and accepts a subsequent append.
//   - An unknown 0x7F type returns an error rather than being skipped. An older
//     binary therefore cannot silently misread a newer log format.
func TestMixedFormatTornTailUnknownType(t *testing.T) {
	nodeID := testNodeID()

	t.Run("MixedFormat", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "t12mix.wal")
		w, err := OpenWAL(walPath)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		// Legacy 0x01 record: only the 5-field subset exists on disk.
		if err := WALAsChaos(w).AppendMutationV1ForTest(WALMutation{
			EntityID: utf8EntityID(1),
			NodeID:   nodeID,
			Counter:  2,
			Entry:    WALEntry{PayloadDigest: stagedDigest(1), SystemTime: 2000},
		}); err != nil {
			t.Fatalf("AppendMutationV1ForTest: %v", err)
		}
		// Full 0x04 record with all ten fields live.
		wantE2 := temporalEntry(7)
		if err := w.AppendMutation(NewWALMutation(utf8EntityID(2), eng.CausalDot{NodeID: nodeID, Counter: 3}, wantE2)); err != nil {
			t.Fatalf("AppendMutation: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		// The legacy entry has zero values for fields absent from its record
		// and receives a synthesized local origin. The full entry is unchanged.
		wantE1 := exactRec(utf8EntityID(1), nodeID, 2, stagedDigest(1))
		wantE2.DotNodeID = nodeID
		wantE2.DotCounter = 3
		wantE2.OriginNodeID = nodeID
		wantRoot := referenceRoot(t, nodeID, wantE1, SnapshotRecord{EntityID: utf8EntityID(2), Entry: wantE2})

		rec, witness := recoverFull(t, walPath)
		ents := collectEntries(t, rec)
		if got := ents[utf8EntityID(1)]; len(got) != 1 || got[0] != wantE1.Entry {
			t.Errorf("legacy record = %+v, want five stored fields, zero for the rest, and local origin: %+v", got, wantE1.Entry)
		}
		if got := ents[utf8EntityID(2)]; len(got) != 1 || got[0] != wantE2 {
			t.Errorf("V2 record: got %+v, want full-fidelity %+v", got, wantE2)
		}
		if witness.LegacyRecords != 1 {
			t.Errorf("LegacyRecords = %d, want 1", witness.LegacyRecords)
		}
		if got := rec.State().MerkleRoot(); got != wantRoot {
			t.Errorf("recovered root %x differs from reference root %x", got, wantRoot)
		}
	})

	t.Run("TornTailMixed", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "t12torn.wal")
		w, err := OpenWAL(walPath)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		if err := w.AppendMutation(handMutation(utf8EntityID(1), nodeID, 2, stagedDigest(1))); err != nil {
			t.Fatalf("append v2: %v", err)
		}
		if err := WALAsChaos(w).AppendMutationV1ForTest(WALMutation{
			EntityID: utf8EntityID(2), NodeID: nodeID, Counter: 3,
			Entry: WALEntry{PayloadDigest: stagedDigest(2), SystemTime: 3000},
		}); err != nil {
			t.Fatalf("append v1: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		// Crash mid-write: 5 garbage bytes at EOF (a partial record header).
		f, err := os.OpenFile(walPath, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("open append: %v", err)
		}
		if _, err := f.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}); err != nil {
			t.Fatalf("append garbage: %v", err)
		}
		_ = f.Close()

		rep, err := ReplayWAL(walPath)
		if err != nil {
			t.Fatalf("ReplayWAL rejected a torn tail: %v", err)
		}
		if len(rep.Mutations) != 2 {
			t.Fatalf("torn-tail replay got %d mutations, want 2 (the clean prefix)", len(rep.Mutations))
		}
		// Reopen: the tear is truncated, nextSeq survives, the next append lands.
		w2, err := OpenWAL(walPath)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		if got := w2.NextSeq(); got != 2 {
			t.Fatalf("NextSeq after torn-tail reopen = %d, want 2 (records carry seqs 0,1; the next append gets 2 — monotonic across the truncation)", got)
		}
		if err := w2.AppendMutation(handMutation(utf8EntityID(3), nodeID, 4, stagedDigest(3))); err != nil {
			t.Fatalf("post-truncation append: %v", err)
		}
		if err := w2.Close(); err != nil {
			t.Fatalf("close2: %v", err)
		}
		assertSeqsUnique(t, walPath)
	})

	t.Run("UnknownTypeHardErrors", func(t *testing.T) {
		dir := t.TempDir()
		hdrWAL := filepath.Join(dir, "hdr.wal")
		hw, err := OpenWAL(hdrWAL)
		if err != nil {
			t.Fatalf("OpenWAL hdr: %v", err)
		}
		_ = hw.Close()
		raw, err := os.ReadFile(hdrWAL)
		if err != nil {
			t.Fatalf("read hdr: %v", err)
		}
		// Use sequence zero so the first-record sequence check passes and this
		// subtest reaches the unknown-type dispatch (ADR-0053). A nonzero leading
		// sequence would be rejected earlier for a different reason.
		rec := make([]byte, 13+4)
		binary.BigEndian.PutUint64(rec[0:8], 0)
		rec[8] = 0x7F
		binary.BigEndian.PutUint32(rec[9:13], 4)
		copy(rec[13:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
		badPath := filepath.Join(dir, "bad.wal")
		if err := os.WriteFile(badPath, append(raw[:8:8], rec...), 0o644); err != nil {
			t.Fatalf("write bad: %v", err)
		}
		if _, err := ReplayWAL(badPath); err == nil {
			t.Fatalf("ReplayWAL accepted unknown record type 0x7F")
		} else if !strings.Contains(err.Error(), "unknown record type") {
			t.Fatalf("error = %v, want the unknown-record-type refusal", err)
		}
	})
}
