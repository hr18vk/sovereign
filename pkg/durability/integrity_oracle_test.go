// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Recovery fingerprint tests. A Merkle root covers only DotNodeID and
// DotCounter, and the post-tail root comparison runs only for a final
// checkpoint. Neither can detect changed entry bytes in an image with a WAL
// tail. The fingerprinted 0x05 checkpoint and the image header's CutSeq and root
// binding close that gap.
//
// After the image Join, recovery compares both root and fingerprint when the
// binding matches, the anchor has a fingerprint, and no image records were
// skipped. A binding mismatch falls back to exact-WAL replay; a mismatch in an
// armed integrity check refuses the boot. These tests cover non-dot corruption,
// a post-checkpoint tail, writer/reader fingerprint agreement, and legacy or
// truncated checkpoint lengths.

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// buildCheckpointTail writes pre-checkpoint mutations, takes a snapshotter-
// backed checkpoint, appends a mutation tail, and closes the live engine and
// WAL. It returns the WAL path, image-key watermark, and final live root.
func buildCheckpointTail(t *testing.T, lfs *LocalFS, pre, tail int) (walPath string, wm uint64, liveRoot [32]byte) {
	t.Helper()
	walPath = filepath.Join(t.TempDir(), "checkpoint-tail.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)
	for i := 0; i < pre; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	for i := 0; i < tail; i++ {
		if _, err := live.PutLocal(utf8EntityID(pre+i), stagedPayload(pre+i), stagedEntry(pre+i)); err != nil {
			t.Fatalf("PutLocal tail %d: %v", i, err)
		}
	}
	liveRoot = live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}
	// The image key is the checkpoint's LamportHigh (the maxLocalDot watermark).
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if !rep.HasCheckpoint || !rep.FinalCheckpt.HasCutSeq {
		t.Fatalf("apparatus: want a 0x05 checkpoint on disk")
	}
	return walPath, rep.FinalCheckpt.LamportHigh, liveRoot
}

// corruptFirstImageValidTimeEnd flips a ValidTimeEnd byte in the first image
// record. The Merkle root folds only DotNodeID and DotCounter, so this change
// leaves the root intact while altering the state fingerprint.
func corruptFirstImageValidTimeEnd(t *testing.T, lfs *LocalFS, wm uint64) {
	t.Helper()
	key := filepath.Join(lfs.Root(), "ckpt", strconv.FormatUint(wm, 10))
	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("read image %s: %v", key, err)
	}
	// Header size by format version: v1 = 21 (magic+version+lamport+count);
	// v2/v3 = 61 (+ cutSeq + root). The version byte is at [4].
	var hdr int
	switch data[4] {
	case 1:
		hdr = 21
	case 2:
		hdr = 61
	case 3:
		// A v3 byte flip is rejected by its CRC before fingerprint handling.
		// These tests need the fingerprint to handle the corruption, so they use
		// the legacy v2 encoding without a checksum. Removing the trailer and
		// changing the version byte leaves LamportHigh, CutSeq, MerkleRoot, and
		// the record layout untouched, preserving the anchor binding.
		hdr = 61
		data = append([]byte(nil), data[:len(data)-4]...) // strip the CRC trailer
		data[4] = 2
	default:
		t.Fatalf("apparatus: unknown snapshot version %d", data[4])
	}
	if len(data) < hdr+2 {
		t.Fatalf("apparatus: image too short for a record header (%d bytes)", len(data))
	}
	eidLen := int(binary.BigEndian.Uint16(data[hdr : hdr+2]))
	off := hdr + 2 + eidLen + 88 // ValidTimeEnd[0] within the 120-byte entry
	if off >= len(data) {
		t.Fatalf("apparatus: corruption offset %d past EOF %d", off, len(data))
	}
	data[off] ^= 0xFF
	if err := os.WriteFile(key, data, 0o640); err != nil {
		t.Fatalf("rewrite corrupted image: %v", err)
	}
	t.Logf("corrupted one byte at offset %d (record 0 ValidTimeEnd) of %s", off, key)
}

// merkleRootFromImage joins an image into a probe engine and returns its root,
// providing an independent comparison with the checkpoint anchor.
func merkleRootFromImage(t *testing.T, img *SnapshotImage) [32]byte {
	t.Helper()
	eng.DataDir = t.TempDir()
	e, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, testArenaSize)
	if err != nil {
		t.Fatalf("probe engine ctor: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	e.Join(snapshotDelta(img))
	return e.MerkleRootFromShards()
}

// TestNonDotCorruptionBootRefused changes ValidTimeEnd in a final-checkpoint
// image. The corrupted image must still reproduce the anchor root, proving the
// corruption is outside the root's coverage, and recovery must reject it with
// ErrRecoveryFingerprintMismatch rather than a decode or I/O error.
func TestNonDotCorruptionBootRefused(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, wm, _ := buildCheckpointTail(t, lfs, 6, 0) // final checkpoint with no tail
	corruptFirstImageValidTimeEnd(t, lfs, wm)

	// Premise (the root-oracle blindness, proven not claimed): the corrupted
	// image must still decode and must reproduce the anchor root — i.e. the
	// corruption is in bytes the root never folds.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	img, err := lfs.LoadSnapshotImage(context.Background(), wm)
	if err != nil {
		t.Fatalf("corrupted image must still decode (structure intact): %v", err)
	}
	if got := merkleRootFromImage(t, img); got != rep.FinalCheckpt.MerkleRoot {
		t.Fatalf("premise broken: the corruption moved the root (%x != anchor %x) — it is not a non-dot corruption; pick a byte the root does not fold", got, rep.FinalCheckpt.MerkleRoot)
	}

	// The assertion: recovery must refuse to boot on the corrupted image.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err == nil {
		_ = wal.Close()
		_ = engine.Close()
		t.Fatalf("recovery accepted a ValidTimeEnd-corrupted image with a matching root; want ErrRecoveryFingerprintMismatch (witness=%+v)", witness)
	}

	// Require the fingerprint sentinel: a decode failure, I/O error, or root
	// mismatch would not demonstrate that non-dot corruption was detected. The
	// independent root comparison above rules out the root-only check.
	if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
		t.Fatalf("want ErrRecoveryFingerprintMismatch for non-dot image corruption, got %v", err)
	}
	if errors.Is(err, ErrRecoveryRootMismatch) {
		t.Fatalf("got ErrRecoveryRootMismatch after proving the corrupted image root matches: %v", err)
	}
	t.Logf("fingerprint check refused non-dot image corruption: %v", err)
}

// TestCrashMidInjectOracleArmed repeats the corruption with a WAL tail after
// the checkpoint. The post-tail root comparison is not armed in this shape, so
// the fingerprint must detect the corruption. Its clean sibling must boot with
// IntegrityChecksArmed set and reproduce the live root.
func TestCrashMidInjectOracleArmed(t *testing.T) {
	t.Run("corrupt_image_with_tail", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, wm, _ := buildCheckpointTail(t, lfs, 6, 3) // a 3-record tail after the checkpoint
		corruptFirstImageValidTimeEnd(t, lfs, wm)

		engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
		if err == nil {
			_ = wal.Close()
			_ = engine.Close()
			t.Fatalf("recovery accepted a corrupted image with a post-checkpoint tail; want ErrRecoveryFingerprintMismatch (witness=%+v)", witness)
		}
		// The refusal must come from the fingerprint check rather than an
		// incidental decode, I/O, or dot-only root error.
		if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
			t.Fatalf("want ErrRecoveryFingerprintMismatch with a post-checkpoint tail, got %v", err)
		}
		if errors.Is(err, ErrRecoveryRootMismatch) {
			t.Fatalf("got ErrRecoveryRootMismatch for non-dot corruption with a tail: %v", err)
		}
		t.Logf("fingerprint check refused corrupted image with a post-checkpoint tail: %v", err)
	})

	t.Run("clean_image_with_tail", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, _, liveRoot := buildCheckpointTail(t, lfs, 6, 3)
		engine, witness := recoverBounded(t, walPath, lfs)
		if !witness.Bounded {
			t.Fatalf("clean mid-inject: witness.Bounded=false — the intact image must be used")
		}
		// A clean boot demonstrates coverage only if the fingerprint check was
		// armed despite the tail and then passed.
		if !witness.IntegrityChecksArmed {
			t.Fatalf("clean image with a tail booted with IntegrityChecksArmed=false")
		}
		if got := engine.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("clean image and tail recovered root %x, want live root %x", got, liveRoot)
		}
	})
}

// TestFingerprintWriterReaderAgreement compares fingerprintRecords over image
// records with StateFingerprint over the same records joined into an engine.
// These writer and reader paths must agree or clean recovery would report a
// false mismatch.
//
// Removing one entry must change the result. That comparison prevents two
// constant or content-insensitive folds from passing the agreement check.
func TestFingerprintWriterReaderAgreement(t *testing.T) {
	nodeID := testNodeID()
	const n = 64
	recs := make([]SnapshotRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, exactRec(utf8EntityID(i), nodeID, uint64(i+2), stagedDigest(i)))
	}

	// Writer: fold the image records directly (the checkpoint-path fold).
	writerFP := fingerprintRecords(recs)
	// Reader: fold the same records joined into a live engine (the boot-path fold).
	readerFP := StateFingerprint(engineWith(t, nodeID, 1, recs...))
	if writerFP != readerFP {
		t.Fatalf("writer and reader fingerprints differ: fingerprintRecords=%x StateFingerprint=%x", writerFP, readerFP)
	}

	droppedFP := StateFingerprint(engineWith(t, nodeID, 1, recs[:n-1]...))
	if droppedFP == readerFP {
		t.Fatalf("dropping one entry left fingerprint unchanged at %x; the fold is not content-sensitive", droppedFP)
	}
}

// TestLegacyAndTruncatedCheckpoint covers 0x05 checkpoint length handling.
// Valid lengths are 48 bytes for root, LamportHigh, and CutSeq; 56 bytes with
// ClockHigh; and 88 bytes with a state fingerprint.
//
// A legacy 48-byte record must boot with LegacyCheckpoint set and fingerprint
// checks disarmed because it carries no fingerprint. A 40-byte record is below
// the minimum and ReplayWAL must reject it rather than parse partial fields.
func TestLegacyAndTruncatedCheckpoint(t *testing.T) {
	t.Run("Legacy48_Boots_FingerprintDisarmed", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "legacy-checkpoint.wal")
		// Two real mutations via the live path so the boot rebuilds real state.
		live := newLiveBridge(t, walPath, 0)
		for i := 0; i < 2; i++ {
			if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
				t.Fatalf("PutLocal %d: %v", i, err)
			}
		}
		// Carry the real rebuilt root so the post-tail comparison cannot refuse
		// this legacy-checkpoint boot for an unrelated reason.
		liveRoot := live.Engine().MerkleRootFromShards()
		payload := make([]byte, 48)
		copy(payload[0:32], liveRoot[:])
		binary.BigEndian.PutUint64(payload[32:40], 2) // LamportHigh: the two mutations
		binary.BigEndian.PutUint64(payload[40:48], 3) // CutSeq: past both mutation seqs
		if err := live.WAL().AppendCheckpointRawForTest(payload); err != nil {
			t.Fatalf("AppendCheckpointRawForTest: %v", err)
		}
		if err := live.WAL().Close(); err != nil {
			t.Fatalf("WAL close: %v", err)
		}
		if err := live.Engine().Close(); err != nil {
			t.Fatalf("engine close: %v", err)
		}

		engine, witness := recoverFull(t, walPath) // nil store → full replay
		_ = engine.Close()
		if !witness.LegacyCheckpoint {
			t.Fatalf("legacy 48-byte checkpoint did not set LegacyCheckpoint; witness=%+v", witness)
		}
		if witness.IntegrityChecksArmed {
			t.Fatalf("legacy checkpoint without a fingerprint armed IntegrityChecksArmed")
		}
	})

	t.Run("Truncated40_HardReject", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "truncated-checkpoint.wal")
		w, err := OpenWAL(walPath)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		payload := make([]byte, 40) // root‖LamportHigh — below the 48-byte 0x05 minimum
		binary.BigEndian.PutUint64(payload[32:40], 4)
		if err := w.AppendCheckpointRawForTest(payload); err != nil {
			t.Fatalf("AppendCheckpointRawForTest: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if _, err := ReplayWAL(walPath); err == nil {
			t.Fatalf("ReplayWAL accepted a truncated 40-byte 0x05 checkpoint")
		} else if !strings.Contains(err.Error(), "short V2 checkpoint") {
			t.Fatalf("error = %v, want the short-V2-checkpoint refusal", err)
		}
	})
}
