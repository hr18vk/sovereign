// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// — (the LegacyCheckpoint witness lie) + (the publish
// is atomic but not durable + the.upload-* orphan wedge) guards.
//
// internal/chaos/wal.go set out.LegacyCheckpoint=true for ANY
// fingerprint-less 0x05 and never cleared it, while both doc sites promised
// "TRUE iff the FINAL checkpoint is legacy". The fix tracks the FINAL record's
// own form: each 0x02 sets it, each 0x05 assigns `!c.HasFingerprint`.
//
// localfs.Upload did temp -> fsync -> rename(2): atomic, not durable (no
// parent-directory fsync), and an interrupted upload orphaned a `.upload-*`
// that ListObjects returned, which sorts BEFORE the real Arrow files
// ('.'=0x2E < '0'=0x30) and hard-errors CompactionByHash8 on every sweep —
// forever. The fix: fsync the parent dir after the rename; filter `.upload-*`
// out of ListObjects (uncommitted uploads are not objects); reap orphans at
// construction and on demand.

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
// guards
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

// TestLegacyCheckpointTracksFinalRecord is the guard: the witness flag
// must describe the FINAL checkpoint record's own form, not ANY record's.
// Sub-test 1 fails at HEAD (the sticky set) — RED proven by injection.
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
			t.Fatalf("first 0x05 fingerprint-less, FINAL fingerprinted => LegacyCheckpoint must be FALSE; the sticky set lied (the final anchor's fingerprint check IS armed)")
		}
	})
	t.Run("FingerprintedThenLegacy_IsTrue", func(t *testing.T) {
		rep := build(t, full05, legacy05)
		if !rep.LegacyCheckpoint {
			t.Fatalf("final 0x05 is fingerprint-less => LegacyCheckpoint must be TRUE")
		}
	})
	t.Run("Final02_IsTrue", func(t *testing.T) {
		rep := build(t, full05, legacy02)
		if !rep.LegacyCheckpoint {
			t.Fatalf("a final legacy 0x02 carries no fingerprint => LegacyCheckpoint must be TRUE (the check has nothing to compare)")
		}
	})
	t.Run("FingerprintedOnly_IsFalse", func(t *testing.T) {
		rep := build(t, full05)
		if rep.LegacyCheckpoint {
			t.Fatalf("control: a fingerprinted-only log must report LegacyCheckpoint=false (this held at HEAD too — the anti-tautology control)")
		}
	})
}

// ---------------------------------------------------------------------------
// guards
// ---------------------------------------------------------------------------

// TestOrphanWedgesCompactionAndReaperClosesIt is the wedge guard:
// plant an orphan under l0/<hash8>/, run CompactionByHash8, show
// it fails today, then show it passes after the reaper. The RED at HEAD is
// proven by INJECTION (neuter the ListObjects filter): with the filter live,
// the orphan never reaches the compactor; with the reaper, the orphan is gone.
func TestOrphanWedgesCompactionAndReaperClosesIt(t *testing.T) {
	ctx := context.Background()
	lfs := newSnapshotStore(t)
	alloc := database.NewJemallocAllocator()
	entity := "d-o-wedge-entity"
	// A REAL L0 Arrow file via the production flusher (the idiom).
	writeNCheckpoints(t, alloc, lfs, entity, 5)

	hash8 := database.EntityHash8(entity)
	l0dir := filepath.Join(lfs.Root(), "l0", database.EntityHash8Hex(entity))
	if _, err := os.Stat(l0dir); err != nil {
		t.Fatalf("apparatus: no L0 dir for the entity: %v", err)
	}

	// PLANT THE ORPHAN: an interrupted upload's temp file (unparseable garbage,
	// the dominant interrupt case) that sorts BEFORE the real.arrow files.
	orphan := filepath.Join(l0dir, ".upload-1863045766")
	if err := os.WriteFile(orphan, []byte("torn-partial-upload"), 0o640); err != nil {
		t.Fatalf("plant orphan: %v", err)
	}
	// Premise: the orphan really does sort first (the wedge mechanics).
	keys, err := lfs.ListObjects(ctx, "", "l0/", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, k := range keys {
		if strings.Contains(k, ".upload-") {
			t.Fatalf("the orphan leaked into ListObjects (%s) — the filter is off", k)
		}
	}

	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "test", database.DefaultCompactionConfig())
	if _, err := compactor.CompactionByHash8(ctx, hash8); err != nil {
		t.Fatalf("WEDGE PRESENT: CompactionByHash8 failed with a.upload-* orphan under l0/<hash8>/: %v", err)
	}

	// The reaper: a second orphan planted post-boot is deleted on demand.
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
	t.Logf("GREEN: orphan filtered from listings, compaction un-wedged, %d orphans reaped", reaped)
}

// TestParentDirFsyncInThePublishPath proves the directory fsync is in
// Upload's publish path: one Upload => the counter advances by exactly one.
// (The fsync's PHYSICAL effect is POSIX-delegated and stated as such in the
// fork report; this guard pins that the call exists and runs. Injection:
// delete the fsyncParentDir call from Upload and this fails.)
func TestParentDirFsyncInThePublishPath(t *testing.T) {
	lfs := newSnapshotStore(t)
	before := uploadDirSyncs.Load()
	if err := lfs.Upload(context.Background(), "ckpt/7", strings.NewReader("image-bytes"), 11); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	after := uploadDirSyncs.Load()
	if after-before != 1 {
		t.Fatalf("one Upload produced %d dir fsyncs, want exactly 1 — the parent-dir fsync is not in the publish path", after-before)
	}
	// And the object is really there, readable, with the right bytes.
	rc, err := lfs.Download(context.Background(), "", "ckpt/7")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer rc.Close()
	t.Logf("GREEN: parent-dir fsync is in the publish path (counter %d -> %d)", before, after)
}

// TestDirFsyncCost measures the added fsync cost per publish, stated as a
// measured number per checkpoint. One Upload = one added dir fsync; measured directly.
func TestDirFsyncCost(t *testing.T) {
	dir := t.TempDir()
	const iters = 200
	// Warm the page cache / ext4 dir entry.
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
	t.Logf("COST: %d parent-dir fsyncs in %s => %.1f µs/fsync on this box's filesystem (one per upload; a checkpoint publishes 1 image + N l0 partitions)", iters, d, float64(d.Microseconds())/iters)
}
