// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Snapshot image integrity tests (ADR-0053).
//
// Version 3 appends a Castagnoli CRC32C over the header and record stream. These
// tests cover corruption detection, v2 compatibility, byte-exact round trips,
// and the separate fingerprint check for a CRC-valid image with altered content.
//
// A corrupt snapshot is a derived-cache failure: recovery reports an exact-WAL
// fallback rather than refusing to boot. A corrupt WAL instead refuses the boot
// because there is no remaining authoritative source from which to rebuild.

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

// testSnapshotImage builds a small populated snapshot image for the unit tests.
func testSnapshotImage() *SnapshotImage {
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

// TestSnapshotCorruptDetect checks that changing a body or root byte in a v3
// image returns ErrSnapshotCorrupt. With snapshotCRC32Skip set, the same altered
// body decodes, demonstrating that rejection comes from the CRC comparison.
func TestSnapshotCorruptDetect(t *testing.T) {
	t.Run("BodyByteCorrupt_Detects", func(t *testing.T) {
		buf, err := encodeSnapshotImage(testSnapshotImage())
		if err != nil {
			t.Fatalf("encodeSnapshotImage: %v", err)
		}
		if buf[4] != snapshotVersionV3 {
			t.Fatalf("apparatus: encode must emit v3, got version %d", buf[4])
		}
		// Corrupt the last content byte (the final record's H3Index high byte) —
		// inside the CRC-covered body, not the 4-byte CRC trailer.
		buf[len(buf)-5] ^= 0xFF
		if _, err := decodeSnapshotImage(buf); !errors.Is(err, ErrSnapshotCorrupt) {
			t.Fatalf("decodeSnapshotImage returned %v for a corrupted v3 body, want ErrSnapshotCorrupt", err)
		}
		// Skipping only the comparison lets the same corrupted bytes decode.
		snapshotCRC32Skip.Store(true)
		defer snapshotCRC32Skip.Store(false)
		dec, err := decodeSnapshotImage(buf)
		if err != nil {
			t.Fatalf("decode with CRC comparison skipped failed: %v", err)
		}
		if len(dec.Records) != 3 {
			t.Fatalf("with CRC comparison skipped, want %d records, got %d", 3, len(dec.Records))
		}
	})

	t.Run("MerkleRootCorrupt_Detects", func(t *testing.T) {
		buf, err := encodeSnapshotImage(testSnapshotImage())
		if err != nil {
			t.Fatalf("encodeSnapshotImage: %v", err)
		}
		// Corrupt a MerkleRoot header byte (root is at [29:61]) — a security-
		// critical field. The whole-image CRC covers the header too.
		buf[30] ^= 0xFF
		if _, err := decodeSnapshotImage(buf); !errors.Is(err, ErrSnapshotCorrupt) {
			t.Fatalf("decodeSnapshotImage returned %v for a corrupted MerkleRoot, want ErrSnapshotCorrupt", err)
		}
	})

	t.Run("ShortCRCTrailer_Detects", func(t *testing.T) {
		buf, err := encodeSnapshotImage(testSnapshotImage())
		if err != nil {
			t.Fatalf("encodeSnapshotImage: %v", err)
		}
		// A v3 image missing its CRC trailer (truncated by 4) is corruption, not a
		// torn tail (a snapshot is written whole — it has no torn-tail concept).
		trunc := buf[:len(buf)-4]
		trunc[4] = snapshotVersionV3 // still claims v3
		if _, err := decodeSnapshotImage(trunc); !errors.Is(err, ErrSnapshotCorrupt) {
			t.Fatalf("decodeSnapshotImage returned %v for a short CRC trailer, want ErrSnapshotCorrupt", err)
		}
	})
}

// TestRecoveryExactWALFallback corrupts a stored v3 image and verifies that
// recovery discards it, reports ExactWALFallback, and rebuilds the live state
// from the WAL. The corrupt image must neither prevent boot nor be used.
func TestRecoveryExactWALFallback(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, wm, liveRoot := buildCheckpointTail(t, lfs, 6, 3) // 6 pre-checkpoint + 3 tail

	// Corrupt a body byte of the v3 image in place (it stays v3; the CRC trailer is
	// now stale). This is the corruption the CRC exists to catch at decode.
	key := filepath.Join(lfs.Root(), "ckpt", strconv.FormatUint(wm, 10))
	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("read image %s: %v", key, err)
	}
	if data[4] != snapshotVersionV3 {
		t.Fatalf("apparatus: want a v3 image on disk, got version %d", data[4])
	}
	// Flip a byte in record 0's entry body (CRC-covered region, not the trailer).
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

	// RECOVER. The corrupt image must trigger the exact-WAL fallback, not a refusal.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("recovery with a corrupt snapshot failed: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if witness == nil {
		t.Fatalf("recovery returned a nil witness")
	}
	if !witness.ExactWALFallback {
		t.Fatalf("ExactWALFallback is false after CRC corruption: %+v", witness)
	}
	if witness.Bounded {
		t.Fatalf("bounded recovery used the corrupt image: %+v", witness)
	}
	if got := engine.State().MerkleRoot(); got != liveRoot {
		t.Fatalf("recovered root %x differs from live root %x", got, liveRoot)
	}
	t.Logf("corrupt snapshot triggered exact-WAL fallback and restored root %x", liveRoot[:8])
}

// encodeV2ImageForTest constructs the legacy representation by removing the v3
// checksum and changing the version byte. The remaining bytes share the current
// encoder's layout.
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

// TestSnapshotBackwardCompat checks that v2 images still decode without a
// checksum, valid v3 images decode, and re-encoding a decoded image produces
// identical bytes and preserves its content.
func TestSnapshotBackwardCompat(t *testing.T) {
	t.Run("V2LegacyDecodes_Unprotected", func(t *testing.T) {
		img := testSnapshotImage()
		v2 := encodeV2ImageForTest(t, img)
		if v2[4] != snapshotVersionV2 {
			t.Fatalf("apparatus: want a v2 image, got version %d", v2[4])
		}
		dec, err := decodeSnapshotImage(v2)
		if err != nil {
			t.Fatalf("decoding legacy v2 image failed: %v", err)
		}
		if len(dec.Records) != len(img.Records) || dec.LamportHigh != img.LamportHigh || dec.CutSeq != img.CutSeq {
			t.Fatalf("v2 decode returned %d records (want %d), LamportHigh %d, CutSeq %d", len(dec.Records), len(img.Records), dec.LamportHigh, dec.CutSeq)
		}
	})

	t.Run("V3GoodCRCDecodes", func(t *testing.T) {
		buf, err := encodeSnapshotImage(testSnapshotImage())
		if err != nil {
			t.Fatalf("encodeSnapshotImage: %v", err)
		}
		if _, err := decodeSnapshotImage(buf); err != nil {
			t.Fatalf("decoding v3 image with a valid CRC failed: %v", err)
		}
	})

	t.Run("RoundTripByteExact", func(t *testing.T) {
		img := testSnapshotImage()
		buf1, err := encodeSnapshotImage(img)
		if err != nil {
			t.Fatalf("encode 1: %v", err)
		}
		dec, err := decodeSnapshotImage(buf1)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		// Re-encode the decoded image: canonical (sorted) + deterministic CRC, so a
		// faithful round-trip is byte-exact.
		buf2, err := encodeSnapshotImage(dec)
		if err != nil {
			t.Fatalf("encode 2: %v", err)
		}
		if !bytes.Equal(buf1, buf2) {
			t.Fatalf("round-trip encodings differ: %d bytes before, %d after", len(buf1), len(buf2))
		}
		if len(dec.Records) != len(img.Records) || dec.MerkleRoot != img.MerkleRoot {
			t.Fatalf("decoded image content differs from the original")
		}
	})
}

// TestValidCRCSwapStillCaughtByFingerprint changes ValidTimeEnd and recomputes
// the checksum. The resulting image passes its CRC but differs from the state
// recorded by the checkpoint. The Merkle root cannot detect this because the
// dots are unchanged; recovery must return ErrRecoveryFingerprintMismatch
// instead (ADR-0045 §4).
func TestValidCRCSwapStillCaughtByFingerprint(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, wm, _ := buildCheckpointTail(t, lfs, 6, 0) // final checkpoint, fingerprinted, no tail

	key := filepath.Join(lfs.Root(), "ckpt", strconv.FormatUint(wm, 10))
	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("read image %s: %v", key, err)
	}
	if data[4] != snapshotVersionV3 {
		t.Fatalf("apparatus: want a v3 image, got version %d", data[4])
	}
	// Corrupt a dot-invisible byte: record 0's ValidTimeEnd (entry[88:96]). The
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
	// The swap: recompute the CRC over the corrupted body so the image is
	// CRC-valid but content-wrong. The CRC now vouches for corrupted bytes.
	binary.BigEndian.PutUint32(data[len(data)-4:], crc32.Checksum(data[:len(data)-4], snapshotCastagnoliTable))
	if err := os.WriteFile(key, data, 0o640); err != nil {
		t.Fatalf("write swapped image: %v", err)
	}

	// The recomputed checksum is valid, so the fingerprint must detect the
	// changed temporal bytes rather than ErrSnapshotCorrupt.
	_, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if wal != nil {
		defer func() { _ = wal.Close() }()
	}
	if errors.Is(err, ErrSnapshotCorrupt) {
		t.Fatalf("CRC-valid image returned ErrSnapshotCorrupt: %v", err)
	}
	if !errors.Is(err, ErrRecoveryFingerprintMismatch) {
		t.Fatalf("error = %v, want ErrRecoveryFingerprintMismatch (witness=%+v)", err, witness)
	}
	t.Logf("fingerprint detected altered temporal bytes after the CRC passed: %v", err)
}

// TestWALCorruptBootRefused flips a content byte in a checksummed WAL record.
// ReplayWAL must propagate ErrWALCorrupt through RecoverEngineWithSnapshot and
// refuse the boot. Unlike a corrupt derived snapshot, a corrupt WAL has no
// alternate authoritative source for exact replay.
func TestWALCorruptBootRefused(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, _, _ := buildCheckpointTail(t, lfs, 6, 3)

	// Corrupt a content byte in the first WAL record's innerPayload (the record is
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

	// Corrupting the authoritative WAL must refuse recovery.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if engine != nil {
		_ = engine.Close()
	}
	if wal != nil {
		_ = wal.Close()
	}
	if !errors.Is(err, ErrWALCorrupt) {
		t.Fatalf("WAL corruption must refuse the boot with ErrWALCorrupt (the WAL is the truth, no fallback), got err=%v witness=%+v", err, witness)
	}
	t.Logf("corrupt WAL record refused boot with ErrWALCorrupt: %v", err)
}
