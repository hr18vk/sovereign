// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// ═══════════════════════════════════════════════════════════════════════════
// (register) — snapshot image CRC32C integrity guards.
//
// The recovery image is now v3: the SAME 61-byte header + record stream, PLUS a
// trailing whole-image CRC32C (Castagnoli). These guards prove the checksum FAILS
// LOUD on content corruption (T4), preserves v2 backward-compat + round-trip
// byte-exactness (T5), and — critically — that the CRC does NOT retire the
// fingerprint check (T-C4: a CRC-VALID but content-SWAPPED image still
// trips the fingerprint). Every guard is bug-injection-proven ([VACUOUS]==FAIL).
//
// THE FAIL-LOUD SPLIT (the fork's crux): a corrupt SNAPSHOT is a DERIVED-CACHE
// rot → the LOUD exact-WAL fallback (the WAL is the truth), NEVER a boot-refusal
// and NEVER a silent use of rotten bytes. (Contrast the WAL: corruption there is
// a boot-REFUSAL, proven in internal/chaos/wal_crc_integrity_test.go.)
// ═══════════════════════════════════════════════════════════════════════════

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// f19Image builds a small populated snapshot image for the unit-level guards.
func f19Image() *SnapshotImage {
	var root [32]byte
	for i := range root {
		root[i] = byte(0xB0 + i)
	}
	return &SnapshotImage{
		LamportHigh: 42,
		CutSeq:      7,
		MerkleRoot:  root,
		Records: []SnapshotRecord{
			{EntityID: utf8EntityID(0), Entry: stagedEntry(0)},
			{EntityID: utf8EntityID(1), Entry: stagedEntry(1)},
			{EntityID: utf8EntityID(2), Entry: stagedEntry(2)},
		},
	}
}

// TestSnapshotCorruptDetect is the core snapshot guard: a v3 image with
// a flipped body byte is REJECTED with ErrSnapshotCorrupt. The bug-injection half
// (snapshotCRC32Skip) compiles out the CRC compare → the SAME bytes decode
// SILENTLY — proving the compare is load-bearing.
func TestSnapshotCorruptDetect(t *testing.T) {
	t.Run("BodyByteCorrupt_Detects", func(t *testing.T) {
		buf, err := encodeSnapshotImage(f19Image())
		if err != nil {
			t.Fatalf("encodeSnapshotImage: %v", err)
		}
		if buf[4] != snapshotVersionV3 {
			t.Fatalf("apparatus: encode must emit v3, got version %d", buf[4])
		}
		// Corrupt the LAST content byte (the final record's H3Index high byte) —
		// inside the CRC-covered body, NOT the 4-byte CRC trailer.
		buf[len(buf)-5] ^= 0xFF
		if _, err := decodeSnapshotImage(buf); !errors.Is(err, ErrSnapshotCorrupt) {
			t.Fatalf("T4: want ErrSnapshotCorrupt for a corrupted v3 image, got %v", err)
		}
		// BUG-INJECT: compile out the CRC compare → the SAME corrupted image decodes
		// SILENTLY. This is the load-bearing proof (the pre-fix fail-silent gap).
		snapshotCRC32Skip.Store(true)
		defer snapshotCRC32Skip.Store(false)
		dec, err := decodeSnapshotImage(buf)
		if err != nil {
			t.Fatalf("T4 BUG-INJECT: with the CRC compare removed the corrupted image must decode SILENTLY, got %v", err)
		}
		if len(dec.Records) != 3 {
			t.Fatalf("T4 BUG-INJECT: the corrupted image must decode %d records silently, got %d", 3, len(dec.Records))
		}
	})

	t.Run("MerkleRootCorrupt_Detects", func(t *testing.T) {
		buf, err := encodeSnapshotImage(f19Image())
		if err != nil {
			t.Fatalf("encodeSnapshotImage: %v", err)
		}
		// Corrupt a MerkleRoot HEADER byte (root is at [29:61]) — the security-
		// critical field. The whole-image CRC covers the header too.
		buf[30] ^= 0xFF
		if _, err := decodeSnapshotImage(buf); !errors.Is(err, ErrSnapshotCorrupt) {
			t.Fatalf("T4: want ErrSnapshotCorrupt for a header (MerkleRoot) corruption, got %v", err)
		}
	})

	t.Run("ShortCRCTrailer_Detects", func(t *testing.T) {
		buf, err := encodeSnapshotImage(f19Image())
		if err != nil {
			t.Fatalf("encodeSnapshotImage: %v", err)
		}
		// A v3 image missing its CRC trailer (truncated by 4) is corruption, NOT a
		// torn tail (a snapshot is written whole — it has no torn-tail concept).
		trunc := buf[:len(buf)-4]
		trunc[4] = snapshotVersionV3 // still claims v3
		if _, err := decodeSnapshotImage(trunc); !errors.Is(err, ErrSnapshotCorrupt) {
			t.Fatalf("T4: want ErrSnapshotCorrupt for a v3 image missing its CRC trailer, got %v", err)
		}
	})
}

// TestRecoveryExactWALFallback is the FAIL-LOUD contract at the
// recovery layer: a CRC-corrupt v3 image must NOT brick the node (the WAL is the
// truth) and must NOT be silently used. RecoverEngineWithSnapshot must take the
// LOUD exact-WAL fallback (recovery.go: the suspect image is DISCARDED, state is
// rebuilt from the WAL, and the fallback is surfaced on the witness). All three
// halves are asserted: boot-succeeds-from-WAL, image-not-used, fallback-signaled.
func TestRecoveryExactWALFallback(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, wm, liveRoot := b2BuildMidInject(t, lfs, 6, 3) // 6 pre-checkpoint + 3 tail

	// Corrupt a body byte of the v3 image IN PLACE (it stays v3; the CRC trailer is
	// now stale). This is the "rot" the CRC exists to catch at DECODE.
	key := filepath.Join(lfs.Root(), "ckpt", strconv.FormatUint(wm, 10))
	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("read image %s: %v", key, err)
	}
	if data[4] != snapshotVersionV3 {
		t.Fatalf("apparatus: want a v3 image on disk, got version %d", data[4])
	}
	// Flip a byte in record 0's entry body (CRC-covered region, NOT the trailer).
	hdr := snapshotHeaderSize
	eidLen := int(binary.BigEndian.Uint16(data[hdr : hdr+2]))
	bodyByte := hdr + 2 + eidLen + 90 // a temporal field inside record 0's entry
	if bodyByte >= len(data)-4 {
		t.Fatalf("apparatus: corruption offset %d past the CRC trailer (len %d)", bodyByte, len(data))
	}
	data[bodyByte] ^= 0xFF
	if err := os.WriteFile(key, data, 0o640); err != nil {
		t.Fatalf("write corrupted image: %v", err)
	}

	// RECOVER. The corrupt image must trigger the exact-WAL fallback, NOT a refusal.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("T4 RECOVERY: a corrupt snapshot must NOT brick the node (the WAL is the truth) — got a boot-refusal: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if witness == nil {
		t.Fatalf("T4 RECOVERY: nil witness on a successful boot")
	}
	// (a) fallback SIGNALED: the witness records the exact-WAL fallback.
	if !witness.ExactWALFallback {
		t.Fatalf("T4 RECOVERY: witness.ExactWALFallback=false — a CRC-corrupt image must force the exact-WAL fallback (witness=%+v)", witness)
	}
	// (b) image NOT used: the bounded path must be OFF (the suspect image discarded).
	if witness.Bounded {
		t.Fatalf("T4 RECOVERY: witness.Bounded=true — the rotten image must NOT be used (witness=%+v)", witness)
	}
	// (c) boot SUCCEEDS from the WAL: the recovered state equals the live state
	// (all 9 local mutations replayed from the WAL; the fallback is lossless here).
	if got := engine.State().MerkleRoot(); got != liveRoot {
		t.Fatalf("T4 RECOVERY: recovered root %x != live %x — the exact-WAL fallback must rebuild the full state from the WAL", got, liveRoot)
	}
	t.Logf("T4 RECOVERY GREEN: CRC-corrupt v3 image → loud exact-WAL fallback (not a refusal, not a silent use); state rebuilt from WAL, root re-equals live (%x)", liveRoot[:8])
}

// encodeV2ImageForTest produces the LEGACY v2 image (no CRC trailer) by encoding
// as v3 and stripping the trailer + resetting the version byte — so the v2 body
// is byte-identical to what a pre-binary wrote (no duplicated layout).
func encodeV2ImageForTest(t *testing.T, image *SnapshotImage) []byte {
	t.Helper()
	v3, err := encodeSnapshotImage(image)
	if err != nil {
		t.Fatalf("encodeSnapshotImage: %v", err)
	}
	v2 := append([]byte(nil), v3[:len(v3)-4]...) // strip the CRC trailer
	v2[4] = snapshotVersionV2
	return v2
}

// TestSnapshotBackwardCompat proves the format evolution never breaks
// an existing on-disk image: a legacy v2 image (no CRC) still decodes
// (disclosed-UNPROTECTED), a v3 image with a good CRC decodes, and a populated
// image round-trips byte-exact.
func TestSnapshotBackwardCompat(t *testing.T) {
	t.Run("V2LegacyDecodes_Unprotected", func(t *testing.T) {
		img := f19Image()
		v2 := encodeV2ImageForTest(t, img)
		if v2[4] != snapshotVersionV2 {
			t.Fatalf("apparatus: want a v2 image, got version %d", v2[4])
		}
		dec, err := decodeSnapshotImage(v2)
		if err != nil {
			t.Fatalf("T5: a legacy v2 image must still decode (backward-compat), got %v", err)
		}
		if len(dec.Records) != len(img.Records) || dec.LamportHigh != img.LamportHigh || dec.CutSeq != img.CutSeq {
			t.Fatalf("T5: v2 decode lost content: %d records (want %d), lh=%d cut=%d", len(dec.Records), len(img.Records), dec.LamportHigh, dec.CutSeq)
		}
	})

	t.Run("V3GoodCRCDecodes", func(t *testing.T) {
		buf, err := encodeSnapshotImage(f19Image())
		if err != nil {
			t.Fatalf("encodeSnapshotImage: %v", err)
		}
		if _, err := decodeSnapshotImage(buf); err != nil {
			t.Fatalf("T5: a v3 image with a good CRC must decode, got %v", err)
		}
	})

	t.Run("RoundTripByteExact", func(t *testing.T) {
		img := f19Image()
		buf1, err := encodeSnapshotImage(img)
		if err != nil {
			t.Fatalf("encode 1: %v", err)
		}
		dec, err := decodeSnapshotImage(buf1)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		// Re-encode the decoded image: canonical (sorted) + deterministic CRC, so a
		// faithful round-trip is BYTE-EXACT.
		buf2, err := encodeSnapshotImage(dec)
		if err != nil {
			t.Fatalf("encode 2: %v", err)
		}
		if !bytes.Equal(buf1, buf2) {
			t.Fatalf("T5: round-trip NOT byte-exact (%d vs %d bytes)", len(buf1), len(buf2))
		}
		// And the decoded CONTENT matches the original (field-exact).
		if len(dec.Records) != len(img.Records) || dec.MerkleRoot != img.MerkleRoot {
			t.Fatalf("T5: decoded content diverged from the original image")
		}
	})
}

// TestValidCRCSwapStillCaughtByFingerprint is the LAYERING guard
// (the C3 resolution): it proves the snapshot CRC and the fingerprint
// check are COMPLEMENTARY, not redundant.
//
// - The CRC catches on-disk ROT: bytes that fail to decode (T4). Cheap, at decode.
// - The fingerprint catches a VALID-BUT-WRONG image: a well-formed image (passes
// the CRC) whose decoded bytes do not match the checkpoint's recorded state.
//
// This guard builds the latter: corrupt a dot-invisible byte (ValidTimeEnd), then
// RECOMPUTE the CRC so the image is CRC-VALID but content-SWAPPED. The CRC passes
// (it is honestly valid for the swapped bytes); the fingerprint check MUST STILL
// fire at recovery. If the CRC had silently retired the fingerprint, this boot
// would succeed — the exact regression the layering must prevent.
func TestValidCRCSwapStillCaughtByFingerprint(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, wm, _ := b2BuildMidInject(t, lfs, 6, 0) // final checkpoint, fingerprinted, no tail

	key := filepath.Join(lfs.Root(), "ckpt", strconv.FormatUint(wm, 10))
	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("read image %s: %v", key, err)
	}
	if data[4] != snapshotVersionV3 {
		t.Fatalf("apparatus: want a v3 image, got version %d", data[4])
	}
	// Corrupt a DOT-INVISIBLE byte: record 0's ValidTimeEnd (entry[88:96]). The
	// Merkle root folds only (DotNodeID,DotCounter), so the root is unchanged; the
	// header (and its binding root/CutSeq) is untouched; only the fingerprint —
	// which folds the full 120-byte entry — can see it.
	hdr := snapshotHeaderSize
	eidLen := int(binary.BigEndian.Uint16(data[hdr : hdr+2]))
	vteOff := hdr + 2 + eidLen + 88 // ValidTimeEnd low byte within record 0's entry
	if vteOff >= len(data)-4 {
		t.Fatalf("apparatus: corruption offset %d past the CRC trailer (len %d)", vteOff, len(data))
	}
	data[vteOff] ^= 0xFF
	// THE SWAP: recompute the CRC over the corrupted body so the image is
	// CRC-VALID but content-WRONG. The CRC now honestly vouches for rotten bytes.
	binary.BigEndian.PutUint32(data[len(data)-4:], crc32.Checksum(data[:len(data)-4], snapshotCastagnoliTable))
	if err := os.WriteFile(key, data, 0o640); err != nil {
		t.Fatalf("write swapped image: %v", err)
	}

	// RECOVER. The CRC must PASS (valid), and the FINGERPRINT must fire.
	_, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if wal != nil {
		defer func() { _ = wal.Close() }()
	}
	// NOT the CRC (the image is CRC-valid — the CRC did its job and found nothing).
	if errors.Is(err, ErrSnapshotCorrupt) {
		t.Fatalf("T-C4: got ErrSnapshotCorrupt, but the image is CRC-VALID (a swap, not rot) — the CRC should NOT fire here; the fingerprint should: %v", err)
	}
	// The fingerprint check MUST fire (the "same dots, wrong bytes" detector).
	if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
		t.Fatalf("T-C4: want ErrRecoveryFingerprintMismatch for a CRC-valid-but-swapped image (the fingerprint must NOT be retired by the CRC), got %v (witness=%+v)", err, witness)
	}
	t.Logf("T-C4 GREEN: a CRC-valid-but-content-swapped v3 image passed the CRC and was caught by the FINGERPRINT check — the CRC did NOT retire the fingerprint (rot vs swap layering holds): %v", err)
}

// TestWALCorruptBootRefused is the OTHER half of the fail-LOUD split
// (the contrast to T4's snapshot fallback): a corrupt WAL record is the
// AUTHORITATIVE-truth corruption with NO fallback — it must REFUSE the boot
// (ErrWALCorrupt propagates out of ReplayWAL → RecoverEngineWithSnapshot), never
// a silent boot and never an exact-WAL "fallback" (there is nothing to fall back
// TO; the WAL is the floor). This is the boot-REFUSAL behavior the snapshot path
// deliberately does NOT take.
func TestWALCorruptBootRefused(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, _, _ := b2BuildMidInject(t, lfs, 6, 3)

	// Corrupt a content byte in the FIRST WAL record's innerPayload (the record is
	// a 0x06 frame: header(13) at offset 8, then innerType(1) ‖ innerPayload ‖
	// crc(4)). Flip the last content byte so the framing stays intact but the
	// content no longer matches the CRC.
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	if data[8+8] != byte(WALRecChecksummed) {
		t.Fatalf("apparatus: first WAL record is type 0x%x, want 0x06 (production writes CRC-framed)", data[8+8])
	}
	payloadLen := int(binary.BigEndian.Uint32(data[8+9 : 8+13]))
	lastContent := 8 + 13 + payloadLen - 4 - 1 // last innerPayload byte (pre-CRC)
	data[lastContent] ^= 0xFF
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write corrupted WAL: %v", err)
	}

	// RECOVER. The corrupt WAL must REFUSE the boot.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if engine != nil {
		_ = engine.Close()
	}
	if wal != nil {
		_ = wal.Close()
	}
	if !errors.Is(err, ErrWALCorrupt) {
		t.Fatalf("WAL corruption must REFUSE the boot with ErrWALCorrupt (the WAL is the truth, no fallback), got err=%v witness=%+v", err, witness)
	}
	t.Logf("WAL fail-LOUD GREEN: a corrupt WAL record REFUSED the boot with ErrWALCorrupt (no fallback, no silent boot): %v", err)
}
