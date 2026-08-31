// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//wal_v2_format_test.go — the guards (ADR-0045).
//
// The round-trip guard is written against the OLD API only (no new witness
// fields, no StateFingerprint), so its RED is a HEAD-revert: on HEAD the
// tail replay re-mints via InsertLocal from the 80-byte record and the five
// temporal/H3 fields come back ZERO. The fingerprint/format-edge guards
// reference the new check/fields; their REDs are bug-injects, each named in
// the guard's doc comment.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ---------------------------------------------------------------------------
// full/bounded entry round-trip: all ten fields survive the WAL tail
// ---------------------------------------------------------------------------

// TestTailRoundTripsAllTenFields: three quiescent puts,
// a checkpoint, three TAIL puts whose entries carry all five temporal/H3
// fields, crash, recover — and EVERY recovered entry must equal the live entry
// byte-for-byte (CRDTEntry is ==-comparable; one comparison covers all ten
// fields), on the BOUNDED path AND on the FULL path (store == nil: the tail is
// then restored from the WAL ALONE — the path where the pre-§6 80-byte record
// was the only source and the loss was total). The tri-temporal moat and the
// H3 index either survive a crash or they do not — this guard watches both
// doors.
//
// RED on HEAD: the tail records are 80-byte (0x01); replay re-mints via
// InsertLocal with ValidTimeStart/End, AssertionTime, DecisionTime, H3Index
// ZERO — and the dot itself is re-minted, so the entry equality fires (dot
// mismatch or zeroed temporal fields) on the first tail entity.
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
				t.Errorf("%s: entity %s entry mismatch —\n got %+v\n want %+v\n (a WAL replay that loses temporal/H3 bytes is NOT a round-trip)",
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

// ---------------------------------------------------------------------------
// equal root, wrong bytes ⇒ the second check REJECTS
// ---------------------------------------------------------------------------

// TestFingerprintRejectsEqualRootWrongBytes: the
// Merkle root folds ONLY dots, so two states can share a root while carrying
// different bytes (the pre-§6 WAL made this real: replayed entries had zeroed
// temporal fields and matching roots). StateFingerprint (the second check)
// folds the entityID + ALL TEN fields of every entry — it MUST discriminate
// what the root cannot. This guard is what makes the round-trip guard
// non-vacuous: it proves the check can fail.
//
// Three assertions: (1) the PREMISE — the two states' Merkle roots are EQUAL
// (the root really is blind to the flipped field); (2) the ORACLE — the
// fingerprints DIFFER; (3) the CONTROL — two independently-built engines with
// IDENTICAL content fingerprint EQUAL (the check is deterministic and
// order-independent, not a random distinguisher).
//
// RED (bug-inject): make StateFingerprint fold only the dot (drop entityID +
// the 120-byte encoding from the per-entry hash) → the fingerprints collide →
// assertion (2) fires.
func TestFingerprintRejectsEqualRootWrongBytes(t *testing.T) {
	nodeID := testNodeID()
	base := exactRec(utf8EntityID(1), nodeID, 5, stagedDigest(1))
	alt := base
	alt.Entry.ValidTimeStart = 42 // different temporal bytes, SAME dot

	a := engineWith(t, nodeID, 1, base)
	b := engineWith(t, nodeID, 1, alt)

	if a.State().MerkleRoot() != b.State().MerkleRoot() {
		t.Fatalf("PREMISE BROKEN: roots differ (%x vs %x) — the guard requires the root to be blind to the temporal bytes", a.State().MerkleRoot(), b.State().MerkleRoot())
	}
	if StateFingerprint(a) == StateFingerprint(b) {
		t.Errorf("ORACLE BLIND: fingerprints equal for byte-different states — the second check is not a state-integrity verification")
	}

	// Control: identical content, independently constructed (different engine,
	// different insertion order across two entities) → SAME fingerprint.
	c1 := exactRec(utf8EntityID(1), nodeID, 5, stagedDigest(1))
	c2 := exactRec(utf8EntityID(2), nodeID, 6, stagedDigest(2))
	x := engineWith(t, nodeID, 1, c1, c2)
	y := engineWith(t, nodeID, 1, c2, c1) // reverse insertion order
	if StateFingerprint(x) != StateFingerprint(y) {
		t.Errorf("CONTROL FAILED: identical states fingerprint differently (order-dependent or nondeterministic — the check would flap)")
	}
}

// ---------------------------------------------------------------------------
// format and durability edges: mixed formats, torn tail, unknown type
// ---------------------------------------------------------------------------

// TestMixedFormatTornTailUnknownType: the four
// format-edge contracts in one place:
//
//	(a) MIXED: a legacy 0x01 record and a full 0x04 record in ONE log replay
//
// correctly — the legacy one marked (witness.LegacyRecords), its five
// unpersisted fields UNKNOWN-surfaced-as-zero; the V2 one's full bytes
// intact.
//
//	(b) TORN TAIL on a mixed log: replay stops at the tear; OpenWAL truncates
//
// it; NextSeq stays monotonic across the reopen; the next append lands
// clean.
//
//	(c) UNKNOWN TYPE BYTE: a record with type 0x7F is a loud error, never a
//
// skip — the downgrade contract (an old binary cannot read a V2 log; a
// corrupt type byte is never silently misparsed). This is the FIRST test
// to cover ReplayWAL's default case (wal.go) — it had ZERO coverage.
//
// RED (bug-injects): (a) drop the `legacyRecords++` in recovery.go's replay
// loop → the witness count assertion fires; (c) turn the default case's error
// into a `continue` → replay SUCCEEDS on a garbage type and the error
// assertion fires.
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

		// The recovered expectations: e1 is the legacy shape (temporal fields
		// UNKNOWN-zero, origin synthesized); e2 keeps every byte.
		wantE1 := exactRec(utf8EntityID(1), nodeID, 2, stagedDigest(1))
		wantE2.DotNodeID = nodeID
		wantE2.DotCounter = 3
		wantE2.OriginNodeID = nodeID
		wantRoot := referenceRoot(t, nodeID, wantE1, SnapshotRecord{EntityID: utf8EntityID(2), Entry: wantE2})

		rec, witness := recoverFull(t, walPath)
		ents := collectEntries(t, rec)
		if got := ents[utf8EntityID(1)]; len(got) != 1 || got[0] != wantE1.Entry {
			t.Errorf("legacy record: got %+v, want the 5-field shape %+v (temporal UNKNOWN-as-zero, origin synthesized)", got, wantE1.Entry)
		}
		if got := ents[utf8EntityID(2)]; len(got) != 1 || got[0] != wantE2 {
			t.Errorf("V2 record: got %+v, want full-fidelity %+v", got, wantE2)
		}
		if witness.LegacyRecords != 1 {
			t.Errorf("MARKER: LegacyRecords=%d, want 1 (the legacy record must be COUNTED, not silently zero-filled)", witness.LegacyRecords)
		}
		if got := rec.State().MerkleRoot(); got != wantRoot {
			t.Errorf("ROOT: %x != reference %x", got, wantRoot)
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
			t.Fatalf("ReplayWAL on torn tail: %v (a torn TAIL must be tolerated)", err)
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
		// A fabricated record with an unknown type byte after a REAL header.
		// (C5): the seq is 0, not 1 — this subtest isolates the
		// UNKNOWN-TYPE defect. added a first-record-must-be-seq-0 guard
		// (wal.go) that fires on a non-zero leading seq BEFORE the type dispatch;
		// a seq=1 record would trip that header-corruption guard and never reach
		// the unknown-type refusal this test asserts. seq=0 keeps a SINGLE defect
		// (the unknown type byte) so the assertion below tests exactly what it
		// claims. (The C5 first-record guard has its own dedicated guard.)
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
			t.Fatalf("an unknown record type byte must HARD-ERROR (the downgrade contract), not replay")
		} else if !strings.Contains(err.Error(), "unknown record type") {
			t.Fatalf("error = %v, want the unknown-record-type refusal", err)
		}
	})
}
