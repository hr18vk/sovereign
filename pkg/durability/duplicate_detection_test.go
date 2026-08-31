// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//duplicate_detection_test.go (ADR-0045): the
// `entries_skipped == 0` arming term as a corruption-controlled KILL SWITCH.
//
// THE CLAIM: decodeSnapshotImage neither dedups nor
// rejects duplicate records. Duplicate ONE image record and bump recordCount at
// image[13:21]: the image Join skips the duplicate (entries_skipped=1), the
// pre-tail arming term `entries_skipped == 0` goes false, and the fingerprint
// check — the ONLY check that folds the entry BYTES (state_fingerprint.go:
// the fold covers all ten CRDTEntry fields; the Merkle root folds
// (DotNodeID, DotCounter) only) — is DISARMED. A dot-invisible corruption
// (here: a ValidTimeEnd flip) that the fingerprint would have refused then
// BOOTS; the post-tail root check stays armed (postTailArmed) but is
// structurally blind to the corrupted bytes.
//
// THE VERDICT: CONFIRMED at RED — the pre-fix run of TestDU_Attack below BOOTED
// with the corrupted ValidTimeEnd live in state (the t.Fatalf evidence line).
// THE FIX: a skipped image record REFUSES the boot (ErrRecoveryImageDuplicate,
// recovery.go) — a faithful image is the canonical sort of a unique-keyed map
// walk (encodeSnapshotImage) and CANNOT contain a duplicate (entityID, dot), so
// a skip means the on-disk bytes are not writer-producible. Refuse, never
// disarm.

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// duFixture builds a live bridge with n staged entries, checkpoints through the
// snapshotter (image + fingerprinted 0x05 anchor), closes, and returns the
// store, the WAL path, the image path, and the image bytes as written.
func duFixture(t *testing.T, n int) (lfs *LocalFS, walPath, imgPath string, img []byte) {
	t.Helper()
	lfs = newSnapshotStore(t)
	walPath = filepath.Join(t.TempDir(), "du.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)
	for i := 0; i < n; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	imgPath, img = b6CkptSoleImage(t, lfs)
	// (C3): the bridge wrote a v3 image (whole-image CRC32C trailer).
	// These guards corrupt/duplicate the image and must have it SURVIVE decode so
	// the DOWNSTREAM check (fingerprint / duplicate-detection) is the one that
	// fires — the v3 CRC is the decode-time defense proven separately (T4). So the
	// returned image is downgraded to the legacy v2 form (no CRC): strip the 4-byte
	// trailer, set the version byte to 2. The header (root/cutSeq/watermark) and the
	// record offsets are unchanged. (TestCleanImageBoots does NOT touch img, so
	// it still exercises a clean v3 image end-to-end.)
	if len(img) >= 5 && img[4] == snapshotVersionV3 {
		img = append([]byte(nil), img[:len(img)-4]...) // strip the CRC trailer
		img[4] = snapshotVersionV2
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("wal close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}
	return lfs, walPath, imgPath, img
}

// duRecord0Span locates record 0's wire span and the absolute offset of its
// ValidTimeEnd low byte, walking the documented layout (snapshot.go:107-122):
// 61-byte header, then per record 2B entityID-len ‖ entityID ‖ 120-byte entry
// with ValidTimeEnd at entry[88:96].
func duRecord0Span(t *testing.T, img []byte) (recStart, recEnd, vteLowByte int) {
	t.Helper()
	if len(img) < snapshotHeaderSize+2 {
		t.Fatalf("image too small: %d", len(img))
	}
	eidLen := int(binary.BigEndian.Uint16(img[snapshotHeaderSize : snapshotHeaderSize+2]))
	recStart = snapshotHeaderSize
	recEnd = snapshotHeaderSize + 2 + eidLen + crdtEntryWireSize
	if recEnd > len(img) {
		t.Fatalf("record 0 overruns image: end=%d len=%d", recEnd, len(img))
	}
	return recStart, recEnd, recStart + 2 + eidLen + 95
}

// duCorruptRecord0 flips ValidTimeEnd's low byte in record 0 (0 → 1):
// dot-invisible (the root folds dots only), fingerprint-visible.
func duCorruptRecord0(t *testing.T, img []byte) {
	t.Helper()
	_, _, vtePos := duRecord0Span(t, img)
	orig := img[vtePos]
	img[vtePos] ^= 0x01
	if img[vtePos] == orig {
		t.Fatalf("VACUOUS: the flip did not change the byte")
	}
}

// TestCorruptionWithoutDuplicateRefused is the CONTROL: the exact
// corruption the attack hides, WITHOUT the duplicate, must be refused by the
// fingerprint check. If this does not refuse, the attack test proves nothing
// about the kill switch (the check never covered this corruption class).
func TestCorruptionWithoutDuplicateRefused(t *testing.T) {
	lfs, walPath, imgPath, img := duFixture(t, 6)
	duCorruptRecord0(t, img)
	if err := os.WriteFile(imgPath, img, 0o640); err != nil {
		t.Fatalf("write corrupted image: %v", err)
	}
	_, _, _, _, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
		t.Fatalf("BASELINE BROKEN: want ErrRecoveryFingerprintMismatch for a dot-invisible ValidTimeEnd flip, got %v", err)
	}
}

// TestDuplicateDisarmsKillSwitch is the verification guard.
// Post-fix it asserts REFUSAL with ErrRecoveryImageDuplicate. Pre-fix (and
// under the I9 injection that neuters the refuse) it documents the confirmed
// kill switch: the boot SUCCEEDS, entries_skipped==1, the post-tail check is
// armed yet blind, and the corrupted ValidTimeEnd is live in state.
func TestDuplicateDisarmsKillSwitch(t *testing.T) {
	lfs, walPath, imgPath, img := duFixture(t, 6)
	recStart, recEnd, _ := duRecord0Span(t, img)

	// THE ATTACK: corrupt record 0's ValidTimeEnd, then duplicate the
	// (corrupted) record 0 span at EOF and bump recordCount at image[13:21].
	duCorruptRecord0(t, img)
	dup := make([]byte, 0, len(img)+(recEnd-recStart))
	dup = append(dup, img...)
	dup = append(dup, img[recStart:recEnd]...)
	n := binary.BigEndian.Uint64(dup[13:21])
	binary.BigEndian.PutUint64(dup[13:21], n+1)

	// PREMISE (the claim's load-bearing half, proven from bytes): the decoder
	// ACCEPTS the duplicated image — no dedup, no rejection.
	dec, err := decodeSnapshotImage(dup)
	if err != nil {
		t.Fatalf("REFUTED at the decode layer: duplicated image refused: %v", err)
	}
	if uint64(len(dec.Records)) != n+1 {
		t.Fatalf("REFUTED at the decode layer: want %d records, got %d", n+1, len(dec.Records))
	}
	if dec.Records[n].EntityID != dec.Records[0].EntityID || dec.Records[n].Entry.Dot() != dec.Records[0].Entry.Dot() {
		t.Fatalf("PREMISE BROKEN: appended record is not a duplicate of record 0")
	}
	if err := os.WriteFile(imgPath, dup, 0o640); err != nil {
		t.Fatalf("write attack image: %v", err)
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err == nil {
		// PRE-FIX / INJECTION BEHAVIOR — the confirmed kill switch. Gather the
		// evidence before failing so the RED run prints the whole shape.
		skipped := engine.Stats()["entries_skipped"]
		ents := collectEntries(t, engine)
		var vte int64 = -1
		if es := ents[utf8EntityID(0)]; len(es) == 1 {
			vte = es[0].ValidTimeEnd
		}
		_ = wal.Close()
		_ = engine.Close()
		t.Fatalf("CONFIRMED: the attack BOOTED — entries_skipped=%d, PostTailRootArmed=%v (armed but dot-blind), recovered ValidTimeEnd=%d (corrupted value 1 live in state). The entries_skipped disarm was a corruption-controlled kill switch; the refuse (ErrRecoveryImageDuplicate) is neutered or absent",
			skipped, witness.PostTailRootArmed, vte)
	}
	if !errors.Is(err, ErrRecoveryImageDuplicate) {
		t.Fatalf("want ErrRecoveryImageDuplicate, got %v", err)
	}
}

// TestCleanImageBoots guards the fix against over-refusal: an unmodified
// image boots, both checks armed, every entry intact.
func TestCleanImageBoots(t *testing.T) {
	lfs, walPath, _, _ := duFixture(t, 6)
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("clean image must boot: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if !witness.PostTailRootArmed {
		t.Fatalf("clean checkpoint-final bounded boot must arm the post-tail root check")
	}
	if !witness.IntegrityChecksArmed {
		t.Fatalf("clean fingerprinted bounded boot must arm the pre-tail checks")
	}
	if got := len(collectEntries(t, engine)); got != 6 {
		t.Fatalf("want 6 entities, got %d", got)
	}
}
