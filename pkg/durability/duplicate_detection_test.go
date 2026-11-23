// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Duplicate image records must not disable fingerprint verification. The
// fingerprint folds all ten CRDTEntry fields, whereas the Merkle root folds only
// DotNodeID and DotCounter. If recovery merely skipped a duplicate, the
// entries_skipped arming condition would disable the only check that can detect
// a ValidTimeEnd change which leaves the root unchanged.
//
// Recovery therefore rejects a duplicate with ErrRecoveryImageDuplicate.
// encodeSnapshotImage canonically sorts records from a map keyed by entity and
// dot, so a writer-produced image cannot contain duplicates. A clean image must
// still boot with both root and fingerprint checks armed.

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
	imgPath, img = soleCheckpointImage(t, lfs)
	// Corrupting a v3 image would trip its whole-image CRC before duplicate or
	// fingerprint handling. Most cases here use the legacy v2 encoding to reach
	// those later checks: remove the four-byte trailer and change only the
	// version byte. TestCleanImageBoots ignores img and retains v3 coverage.
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
// ValidTimeEnd low byte, walking the documented layout: 61-byte header, then per
// record 2B entityID-len ‖ entityID ‖ 120-byte entry with ValidTimeEnd at
// entry[88:96].
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

// duCorruptRecord0 changes ValidTimeEnd's low byte in record zero. This alters
// the fingerprint without changing the dot-only Merkle root.
func duCorruptRecord0(t *testing.T, img []byte) {
	t.Helper()
	_, _, vtePos := duRecord0Span(t, img)
	orig := img[vtePos]
	img[vtePos] ^= 0x01
	if img[vtePos] == orig {
		t.Fatalf("the flip did not change the byte; test is not exercising the corruption")
	}
}

// TestCorruptionWithoutDuplicateRefused establishes that the fingerprint detects
// the same ValidTimeEnd change when no duplicate is present. Without this
// control, the duplicate test could not attribute its result to duplicate
// handling rather than to the corruption being invisible.
func TestCorruptionWithoutDuplicateRefused(t *testing.T) {
	lfs, walPath, imgPath, img := duFixture(t, 6)
	duCorruptRecord0(t, img)
	if err := os.WriteFile(imgPath, img, 0o640); err != nil {
		t.Fatalf("write corrupted image: %v", err)
	}
	_, _, _, _, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
		t.Fatalf("want ErrRecoveryFingerprintMismatch for a dot-invisible ValidTimeEnd flip, got %v", err)
	}
}

// TestDuplicateDisarmsKillSwitch appends a corrupted record to an image and
// increments its record count. The decoder accepts the structurally valid
// input, but recovery must reject the duplicate rather than skip it and disable
// fingerprint verification.
func TestDuplicateDisarmsKillSwitch(t *testing.T) {
	lfs, walPath, imgPath, img := duFixture(t, 6)
	recStart, recEnd, _ := duRecord0Span(t, img)

	// Change ValidTimeEnd, append the corrupted record at EOF, and increment
	// recordCount at image[13:21] to match the added record.
	duCorruptRecord0(t, img)
	dup := make([]byte, 0, len(img)+(recEnd-recStart))
	dup = append(dup, img...)
	dup = append(dup, img[recStart:recEnd]...)
	n := binary.BigEndian.Uint64(dup[13:21])
	binary.BigEndian.PutUint64(dup[13:21], n+1)

	// The decoder accepts the structurally valid duplicate. Recovery, rather than
	// the lower-level decoder, owns the writer-producibility check.
	dec, err := decodeSnapshotImage(dup)
	if err != nil {
		t.Fatalf("duplicated image refused at decode layer: %v", err)
	}
	if uint64(len(dec.Records)) != n+1 {
		t.Fatalf("duplicated image decode layer: want %d records, got %d", n+1, len(dec.Records))
	}
	if dec.Records[n].EntityID != dec.Records[0].EntityID || dec.Records[n].Entry.Dot() != dec.Records[0].Entry.Dot() {
		t.Fatalf("premise broken: appended record is not a duplicate of record 0")
	}
	if err := os.WriteFile(imgPath, dup, 0o640); err != nil {
		t.Fatalf("write attack image: %v", err)
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err == nil {
		// Report whether the duplicate was skipped and whether the altered value
		// reached engine state before failing the boot assertion.
		skipped := engine.Stats()["entries_skipped"]
		ents := collectEntries(t, engine)
		var vte int64 = -1
		if es := ents[utf8EntityID(0)]; len(es) == 1 {
			vte = es[0].ValidTimeEnd
		}
		_ = wal.Close()
		_ = engine.Close()
		t.Fatalf("recovery accepted a duplicate image record: entries_skipped=%d, PostTailRootArmed=%v, recovered ValidTimeEnd=%d; want ErrRecoveryImageDuplicate",
			skipped, witness.PostTailRootArmed, vte)
	}
	if !errors.Is(err, ErrRecoveryImageDuplicate) {
		t.Fatalf("want ErrRecoveryImageDuplicate, got %v", err)
	}
}

// TestCleanImageBoots checks that an unmodified image still boots with both
// integrity checks armed and every entity intact.
func TestCleanImageBoots(t *testing.T) {
	lfs, walPath, _, _ := duFixture(t, 6)
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("clean image must boot: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if !witness.PostTailRootArmed {
		t.Fatalf("clean checkpoint-final bounded boot must arm the post-tail root oracle")
	}
	if !witness.IntegrityChecksArmed {
		t.Fatalf("clean fingerprinted bounded boot must arm the pre-tail oracles")
	}
	if got := len(collectEntries(t, engine)); got != 6 {
		t.Fatalf("want 6 entities, got %d", got)
	}
}
