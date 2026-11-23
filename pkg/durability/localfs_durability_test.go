// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// These tests cover checkpoint replay metadata and local-object durability.
//
// LegacyCheckpoint describes the final checkpoint record: a 0x02 record is
// legacy, and a 0x05 record is legacy when it has no fingerprint. Earlier
// records do not affect the value.
//
// LocalFS publishes an upload by syncing a temporary file, renaming it, and
// syncing the parent directory. ListObjects excludes temporary files left by
// interrupted uploads, and ReapUploadOrphans removes them. This matters for
// compaction because a temporary filename sorts before Arrow filenames.

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
)

// ---------------------------------------------------------------------------
// LegacyCheckpoint witness tests
// ---------------------------------------------------------------------------

// rawLegacy48Checkpoint builds the 48-byte legacy 0x05 payload (root ||
// LamportHigh || CutSeq — no ClockHigh, no Fingerprint).
func rawLegacy48Checkpoint(root [32]byte, lamportHigh, cutSeq uint64) []byte {
	p := make([]byte, 48)
	copy(p[0:32], root[:])
	binary.BigEndian.PutUint64(p[32:40], lamportHigh)
	binary.BigEndian.PutUint64(p[40:48], cutSeq)
	return p
}

// TestLegacyCheckpointTracksFinalRecord verifies that the witness describes
// the final checkpoint record rather than any earlier record.
func TestLegacyCheckpointTracksFinalRecord(t *testing.T) {
	var rootA, rootB [32]byte
	rootA[0] = 0xAA
	rootB[0] = 0xBB

	build := func(t *testing.T, records ...func(t *testing.T, w *WAL)) *Replayed {
		t.Helper()
		walPath := filepath.Join(t.TempDir(), "dn.wal")
		w, err := OpenWAL(walPath)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		for _, r := range records {
			r(t, w)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		rep, err := ReplayWAL(walPath)
		if err != nil {
			t.Fatalf("ReplayWAL: %v", err)
		}
		return rep
	}
	legacy05 := func(t *testing.T, w *WAL) {
		if err := w.AppendCheckpointRawForTest(rawLegacy48Checkpoint(rootA, 5, 5)); err != nil {
			t.Fatalf("raw legacy 0x05: %v", err)
		}
	}
	full05 := func(t *testing.T, w *WAL) {
		if err := w.AppendCheckpoint(WALCheckpoint{MerkleRoot: rootB, LamportHigh: 9, CutSeq: 9, ClockHigh: 9, HasCutSeq: true, HasFingerprint: true, Fingerprint: [32]byte{0x42}}); err != nil {
			t.Fatalf("fingerprinted 0x05: %v", err)
		}
	}
	legacy02 := func(t *testing.T, w *WAL) {
		if err := w.AppendCheckpoint(WALCheckpoint{MerkleRoot: rootB, LamportHigh: 9}); err != nil {
			t.Fatalf("legacy 0x02: %v", err)
		}
	}

	t.Run("LegacyThenFingerprinted_IsFalse", func(t *testing.T) {
		rep := build(t, legacy05, full05)
		if rep.LegacyCheckpoint {
			t.Fatalf("final checkpoint has a fingerprint but LegacyCheckpoint is true")
		}
	})
	t.Run("FingerprintedThenLegacy_IsTrue", func(t *testing.T) {
		rep := build(t, full05, legacy05)
		if !rep.LegacyCheckpoint {
			t.Fatalf("final checkpoint has no fingerprint but LegacyCheckpoint is false")
		}
	})
	t.Run("Final02_IsTrue", func(t *testing.T) {
		rep := build(t, full05, legacy02)
		if !rep.LegacyCheckpoint {
			t.Fatalf("final legacy 0x02 checkpoint must set LegacyCheckpoint")
		}
	})
	t.Run("FingerprintedOnly_IsFalse", func(t *testing.T) {
		rep := build(t, full05)
		if rep.LegacyCheckpoint {
			t.Fatalf("fingerprinted checkpoint unexpectedly marked legacy")
		}
	})
}

// ---------------------------------------------------------------------------
// Publish durability tests
// ---------------------------------------------------------------------------

// TestOrphanWedgesCompactionAndReaperClosesIt verifies that ListObjects hides
// temporary uploads and ReapUploadOrphans removes them. Compaction must succeed
// while an orphan is present beside the entity's L0 files.
func TestOrphanWedgesCompactionAndReaperClosesIt(t *testing.T) {
	ctx := context.Background()
	lfs := newSnapshotStore(t)
	alloc := database.NewJemallocAllocator()
	entity := "d-o-wedge-entity"
	// Write real L0 Arrow files through the production flusher.
	writeNCheckpoints(t, alloc, lfs, entity, 5)

	hash8 := database.EntityHash8(entity)
	l0dir := filepath.Join(lfs.Root(), "l0", database.EntityHash8Hex(entity))
	if _, err := os.Stat(l0dir); err != nil {
		t.Fatalf("L0 directory missing for entity: %v", err)
	}

	// Plant an interrupted upload containing partial data; its name sorts before
	// the Arrow files.
	orphan := filepath.Join(l0dir, ".upload-1863045766")
	if err := os.WriteFile(orphan, []byte("torn-partial-upload"), 0o640); err != nil {
		t.Fatalf("plant orphan: %v", err)
	}
	// Confirm that the temporary file is absent from object listings.
	keys, err := lfs.ListObjects(ctx, "", "l0/", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, k := range keys {
		if strings.Contains(k, ".upload-") {
			t.Fatalf("temporary upload appeared in ListObjects: %s", k)
		}
	}

	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "test", database.DefaultCompactionConfig())
	if _, err := compactor.CompactionByHash8(ctx, hash8); err != nil {
		t.Fatalf("CompactionByHash8 failed with a .upload-* orphan under l0/<hash8>/: %v", err)
	}

	// A second temporary file created after construction is removed on demand.
	orphan2 := filepath.Join(l0dir, ".upload-99999")
	if err := os.WriteFile(orphan2, []byte("torn"), 0o640); err != nil {
		t.Fatalf("plant orphan2: %v", err)
	}
	reaped, err := lfs.ReapUploadOrphans(ctx)
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if reaped != 2 {
		t.Fatalf("reaper removed %d orphans, want 2 (the planted pair)", reaped)
	}
	for _, p := range []string{orphan, orphan2} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("orphan %s survived the reaper", p)
		}
	}
	t.Logf("temporary files excluded from listings and %d removed", reaped)
}

// TestParentDirFsyncInThePublishPath checks that each successful Upload issues
// one parent-directory sync and leaves the object available for download.
func TestParentDirFsyncInThePublishPath(t *testing.T) {
	lfs := newSnapshotStore(t)
	before := uploadDirSyncs.Load()
	if err := lfs.Upload(context.Background(), "ckpt/7", strings.NewReader("image-bytes"), 11); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	after := uploadDirSyncs.Load()
	if after-before != 1 {
		t.Fatalf("one Upload produced %d directory syncs, want 1", after-before)
	}
	// Verify that the published object is available for download.
	rc, err := lfs.Download(context.Background(), "", "ckpt/7")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer rc.Close()
	t.Logf("parent-directory sync counter advanced from %d to %d", before, after)
}

// TestDirFsyncCost reports the parent-directory sync cost on the test
// filesystem. Each upload performs one such sync after publishing its object.
func TestDirFsyncCost(t *testing.T) {
	dir := t.TempDir()
	const iters = 200
	// Warm the page cache and directory entry before measuring.
	if err := fsyncParentDir(dir); err != nil {
		t.Fatalf("warm fsync: %v", err)
	}
	start := time.Now()
	for i := 0; i < iters; i++ {
		if err := fsyncParentDir(dir); err != nil {
			t.Fatalf("fsync %d: %v", i, err)
		}
	}
	d := time.Since(start)
	t.Logf("%d parent-directory syncs in %s: %.1f µs/sync on this filesystem (one per upload; a checkpoint publishes 1 image + N L0 partitions)", iters, d, float64(d.Microseconds())/iters)
}
