// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// B2 — THE ARMED ORACLE (ADR-0045; the BINDING §15.16
// Revision 1, §11.5-§11.9).
//
// THE DEFECT: recovery.go's ONLY integrity check (the root assertion) is
// (a) BLIND to everything but (DotNodeID, DotCounter) — "same dots, wrong
// bytes" is undetectable, and
// (b) gated on `checkpointFinal`, which is FALSE whenever a post-checkpoint
// mutation tail exists — the crash-mid-inject shape the silicon gate
// exists to test. On that shape the check NEVER arms: the crash-leg
// PASS was taken with the integrity check switched OFF.
//
// The fix: the 0x05 record carries the state fingerprint; the
// image header carries the anchor's CutSeq+root (the BINDING); the pre-tail
// check compares root AND fingerprint immediately after the image Join (where
// the rebuilt state IS the image), armed only when the binding matched, the
// anchor carries a fingerprint, and the image Join skipped nothing; a binding
// mismatch DISARMS + falls back to exact-WAL replay (NEVER fatal); an armed
// mismatch IS fatal.
//
// T-C2: one corrupted non-dot byte, final checkpoint ⇒ boot REFUSED, and the
// root check provably stays blind. T-C3: the crash-mid-inject shape — the
// check arms WITH a tail.

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

// b2BuildMidInject writes `pre` mutations, takes a snapshotter-backed
// checkpoint, writes `tail` post-checkpoint mutations, and crashes (per-record
// fsyncs only). Returns the WAL path, the checkpoint's image key watermark,
// and the FINAL live root.
func b2BuildMidInject(t *testing.T, lfs *LocalFS, pre, tail int) (walPath string, wm uint64, liveRoot [32]byte) {
	t.Helper()
	walPath = filepath.Join(t.TempDir(), "b2.wal")
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

// b2CorruptFirstRecordByte flips ONE byte of the first image record's
// ValidTimeEnd field (entry offset 88) on disk. The flip is dot-invisible:
// the Merkle root folds only DotNodeID+DotCounter, so the corrupted image
// produces the SAME root — only a payload-folding check can see it.
func b2CorruptFirstRecordByte(t *testing.T, lfs *LocalFS, wm uint64) {
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
		// (C3): the production image is now v3 (whole-image CRC32C
		// trailer). A v3 byte-flip is caught by the CRC at DECODE (that is T4's
		// guard) and never reaches the fingerprint check. THIS guard's premise is
		// that the corruption STILL DECODES so the FINGERPRINT — the "same dots,
		// wrong bytes" check — is the one that fires. To preserve that premise we
		// downgrade the image to the legacy v2 form (strip the 4-byte CRC trailer,
		// set version=2): v2 has no checksum, so the corruption decodes and the
		// fingerprint remains the EXERCISED defense on the unprotected format.
		// The header (LamportHigh/CutSeq/MerkleRoot) is untouched, so the anchor
		// binding still holds; only the CRC trailer + version byte change.
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

// b2RootFromImage joins a (possibly corrupted) image into a probe engine and
// returns its Merkle root — the proof that a non-dot corruption is INVISIBLE
// to the root check.
func b2RootFromImage(t *testing.T, img *SnapshotImage) [32]byte {
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

// TestNonDotCorruptionBootRefused is T-C2 — the load-bearing Blocker-2
// guard. Persist a checkpoint, corrupt exactly ONE non-dot byte of the image
// on disk (ValidTimeEnd), recover. The check MUST REFUSE the boot. The second
// half is the whole point: the corruption is provably INVISIBLE to the Merkle
// root (the corrupted image reproduces the anchor root exactly), so a boot that
// succeeded would prove the root-only check structurally blind to "same dots,
// wrong bytes".
//
// RED on the pre-fix tree: no fingerprint exists on disk and the root assertion
// passes (dots unchanged), so recovery BOOTS — the assertion below fires.
// GREEN post-fix: the armed fingerprint check fires ErrRecoveryFingerprintMismatch.
func TestNonDotCorruptionBootRefused(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, wm, _ := b2BuildMidInject(t, lfs, 6, 0) // final checkpoint, NO tail
	b2CorruptFirstRecordByte(t, lfs, wm)

	// PREMISE (the root-check blindness, proven not claimed): the corrupted
	// image must STILL decode and MUST reproduce the anchor root — i.e. the
	// corruption is in bytes the root never folds.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	img, err := lfs.LoadSnapshotImage(context.Background(), wm)
	if err != nil {
		t.Fatalf("corrupted image must still decode (structure intact): %v", err)
	}
	if got := b2RootFromImage(t, img); got != rep.FinalCheckpt.MerkleRoot {
		t.Fatalf("PREMISE BROKEN: the corruption moved the root (%x != anchor %x) — it is NOT a non-dot corruption; pick a byte the root does not fold", got, rep.FinalCheckpt.MerkleRoot)
	}

	// THE ASSERTION: recovery must REFUSE to boot on the corrupted image.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err == nil {
		_ = wal.Close()
		_ = engine.Close()
		t.Fatalf(`B2 RED — recovery BOOTED on a byte-corrupted image (witness=%+v).
 The image's ValidTimeEnd was flipped on disk; the root assertion cannot see it
 (roots match); NO fingerprint check exists on disk to fire. The boot succeeded
 on state the durable checkpoint never promised — the exact "same dots, wrong
 bytes" blindness Blocker 2 exists to close.`, witness)
	}

	// THE TIGHTENED ASSERTION (no-test-lies): it is NOT enough that SOME error
	// fired — a decode failure, an IO error, or the dot-only root check would
	// also satisfy `err != nil` while the fingerprint check sat silent. The
	// error MUST be the fingerprint sentinel. The premise above proved the
	// corruption is dot-invisible, so the root check CANNOT have fired; the
	// fingerprint sentinel is the only refusal that proves the "same dots,
	// wrong bytes" check is live.
	if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
		t.Fatalf("B2 T-C2: want ErrRecoveryFingerprintMismatch (the payload check must fire), got: %v", err)
	}
	if errors.Is(err, ErrRecoveryRootMismatch) {
		t.Fatalf("B2 T-C2: got ErrRecoveryRootMismatch — but the premise proved the corruption is dot-invisible, so the DOT check firing means the wrong check ran: %v", err)
	}
	t.Logf("B2 T-C2 GREEN: the fingerprint check (not the root check, not an incidental error) refused the boot: %v", err)
}

// TestCrashMidInjectOracleArmed is T-C3 — the arming guard. The
// crash-mid-inject shape (checkpoint, then a mutation tail, then crash) is the
// shape the silicon gate exists to test — and pre-fix it is EXACTLY the shape
// on which the root assertion NEVER arms (checkpointFinal == false). Corrupt
// one image byte on that shape: pre-fix the boot SUCCEEDS (check disarmed);
// post-fix the pre-tail check arms on the binding match and REFUSES. The clean
// sibling subtest proves the same shape boots when the image is intact — the
// check arms and PASSES, it does not merely refuse everything.
func TestCrashMidInjectOracleArmed(t *testing.T) {
	t.Run("corrupt_image_with_tail_REFUSED", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, wm, _ := b2BuildMidInject(t, lfs, 6, 3) // a 3-record tail after the checkpoint
		b2CorruptFirstRecordByte(t, lfs, wm)

		engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
		if err == nil {
			_ = wal.Close()
			_ = engine.Close()
			t.Fatalf(`B2 RED — mid-inject crash with a corrupted image BOOTED (witness=%+v).
 checkpointFinal == false (the tail exists), so the ONLY integrity verification never armed —
 the exact disarmed-check shape on which the run's crash leg reported PASS.`, witness)
		}
		// Tightened (no-test-lies): the refusal must be the fingerprint check
		// arming on the mid-inject shape — not a decode/IO error and not the root
		// check (the corruption is dot-invisible by construction).
		if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
			t.Fatalf("B2 T-C3 corrupt: want ErrRecoveryFingerprintMismatch (check armed WITH a tail), got: %v", err)
		}
		if errors.Is(err, ErrRecoveryRootMismatch) {
			t.Fatalf("B2 T-C3 corrupt: got ErrRecoveryRootMismatch — the dot check cannot see this corruption: %v", err)
		}
		t.Logf("B2 T-C3 corrupt-armed GREEN: the fingerprint check armed WITH a tail and refused: %v", err)
	})

	t.Run("clean_image_with_tail_BOOTS", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, _, liveRoot := b2BuildMidInject(t, lfs, 6, 3)
		engine, witness := recoverBounded(t, walPath, lfs)
		if !witness.Bounded {
			t.Fatalf("clean mid-inject: witness.Bounded=false — the intact image must be used")
		}
		// THE ANTI-LIE ASSERTION: the check must have ARMED on this crash-mid-
		// inject shape (a tail follows the checkpoint). Pre-fix, checkpointFinal
		// was false here and the check silently never ran — so a "PASS" with the
		// check OFF was exactly that lie. If IntegrityChecksArmed is false
		// the clean boot proves nothing about the check.
		if !witness.IntegrityChecksArmed {
			t.Fatalf("clean mid-inject: witness.IntegrityChecksArmed=false — the integrity verification must ARM on the crash-mid-inject shape; a disarmed PASS is the lie Blocker 2 exists to kill (the run's check-OFF pass)")
		}
		if got := engine.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("clean mid-inject: recovered root %x != live %x — the intact image + tail must rebuild the live state", got, liveRoot)
		}
	})
}

// TestFingerprintWriterReaderAgreement is T-C4 — the fold-agreement guard.
// The checkpoint's fingerprint is produced by TWO different code paths that MUST
// agree on the same logical state: the WRITER (fingerprintRecords over the
// captured image records, bridge.go) and the READER (StateFingerprint walking
// the live engine's shards). If they disagreed, EVERY clean boot would
// false-positive a fingerprint mismatch and refuse a healthy node. The B2 clean
// boot proves this end-to-end; this test proves it DIRECTLY, isolating the fold
// from the WAL/image machinery so a regression localizes to the fold itself.
//
// The drop-one control is the fold's FALSIFIABILITY guard: removing one entry
// MUST change the fingerprint. A fold that returned a constant (or were
// insensitive to a dropped entry) would "agree" vacuously and detect no
// corruption — an agreement assertion without this control can pass on a
// do-nothing fold.
func TestFingerprintWriterReaderAgreement(t *testing.T) {
	nodeID := testNodeID()
	const n = 64
	recs := make([]SnapshotRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, exactRec(utf8EntityID(i), nodeID, uint64(i+2), stagedDigest(i)))
	}

	// WRITER: fold the image records directly (the checkpoint-path fold).
	writerFP := fingerprintRecords(recs)
	// READER: fold the SAME records joined into a live engine (the boot-path fold).
	readerFP := StateFingerprint(engineWith(t, nodeID, 1, recs...))
	if writerFP != readerFP {
		t.Fatalf("writer/reader fold DISAGREE: fingerprintRecords=%x StateFingerprint=%x — every clean boot would false-positive a fingerprint mismatch", writerFP, readerFP)
	}

	// DROP-ONE CONTROL: a state missing ONE entry MUST fingerprint differently.
	droppedFP := StateFingerprint(engineWith(t, nodeID, 1, recs[:n-1]...))
	if droppedFP == readerFP {
		t.Fatalf("DROP-ONE CONTROL FAILED: dropping one entry left the fingerprint unchanged (%x) — the fold is not content-sensitive and would detect no corruption", droppedFP)
	}
}

// TestLegacyAndTruncatedCheckpoint is T-C5 — the 0x05 length-discrimination
// guard. The 0x05 record is variable-length: 48 bytes (legacy, pre-—
// root‖LamportHigh‖CutSeq, no ClockHigh, no Fingerprint), 56 (ClockHigh, no
// Fingerprint), 88 (Fingerprint). Two contracts, both about the decoder NEVER
// silently misparsing length:
//
//	(a) LEGACY 48-byte: boots FINE — the fingerprint check DISARMS (there is
//
// no fingerprint to compare) and the witness DISCLOSES the degradation
// (LegacyCheckpoint=true, IntegrityChecksArmed=false) rather than crashing
// or silently arming. This is the "old log on a new binary" contract.
//
//	(b) TRUNCATED 40-byte: below the 48-byte 0x05 minimum — ReplayWAL must
//
// HARD-ERROR, never parse a short record as if it were whole.
//
// RED (bug-inject): (a) if the decoder set HasFingerprint on a 48-byte record,
// the boot would compare against a zero fingerprint and FALSE-REFUSE — the
// LegacyCheckpoint/IntegrityChecksArmed assertions catch it; (b) if the decoder
// dropped its `len < 48` guard, ReplayWAL would parse the 40-byte record and the
// hard-error assertion would fire.
func TestLegacyAndTruncatedCheckpoint(t *testing.T) {
	t.Run("Legacy48_Boots_FingerprintDisarmed", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "b5legacy.wal")
		// Two real mutations via the live path so the boot rebuilds real state.
		live := newLiveBridge(t, walPath, 0)
		for i := 0; i < 2; i++ {
			if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
				t.Fatalf("PutLocal %d: %v", i, err)
			}
		}
		// The legacy 48-byte 0x05 must carry the REAL rebuilt root, or the
		// post-tail root assertion (which arms on a final checkpoint with no
		// advances) would refuse the boot for the WRONG reason.
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
			t.Fatalf("legacy 48-byte 0x05 must set witness.LegacyCheckpoint (the fingerprint check had nothing to compare); got %+v", witness)
		}
		if witness.IntegrityChecksArmed {
			t.Fatalf("legacy 48-byte 0x05 must leave the fingerprint check DISARMED (no fingerprint to compare) — IntegrityChecksArmed=true would mean a comparison against a zero fingerprint, a false-refuse waiting to happen")
		}
	})

	t.Run("Truncated40_HardReject", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "b5trunc.wal")
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
			t.Fatalf("a truncated 40-byte 0x05 must HARD-ERROR at replay (the no-silent-misparse contract), not replay")
		} else if !strings.Contains(err.Error(), "short V2 checkpoint") {
			t.Fatalf("error = %v, want the short-V2-checkpoint refusal", err)
		}
	})
}
