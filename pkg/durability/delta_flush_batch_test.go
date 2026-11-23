// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Tests for decoupled, delta-only checkpoints (ADR-0050) and checkpoint CRC32C
// handling (ADR-0053). They cover query-tier upload counts, durable reads after
// a delta flush, and recovery through the binding and image fallback paths.
//
// The work metric is the l0/ per-entity upload count (uploadL0Uploads). Each
// upload writes and syncs one file and its parent directory. A full flush
// overwrites the same keys as a delta flush, so distinct-file counts cannot
// distinguish them; upload counts can. The ckpt/ recovery image is excluded
// because every checkpoint writes one image.

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"

	"github.com/hr18vk/sovereign/internal/database"
)

// TestDeltaFlushFsyncCount measures l0/ uploads for a full first checkpoint,
// an unchanged checkpoint, and a checkpoint with new entities. A second bridge
// with debugFullQueryFlush enabled provides the full-flush comparison: its
// unchanged checkpoint must upload every entity, while the delta path uploads
// none.
func TestDeltaFlushFsyncCount(t *testing.T) {
	const N = 50 // base entities
	const M = 10 // new entities in the delta
	uploads := func() int64 { return uploadL0UploadsCount() }

	walPath := filepath.Join(t.TempDir(), "tb1.wal")
	lfs := newSnapshotStore(t)
	live := newLiveBridge(t, walPath, 0) // K=0: caller-driven checkpoints
	live.SetSnapshotter(lfs, true)

	// Checkpoint 1: N inserts → full flush (first checkpoint, lastFlushedDot nil).
	for i := 0; i < N; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	before := uploads()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("checkpoint 1: %v", err)
	}
	if c1 := uploads() - before; c1 != N {
		t.Fatalf("checkpoint 1 (first flush) uploaded %d l0 files, want %d (the full first flush)", c1, N)
	}

	// Checkpoint 2: no changes → delta flush must upload zero query-tier files.
	// (The recovery image at ckpt/ is still written — it is not an l0/ upload.)
	before = uploads()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("checkpoint 2: %v", err)
	}
	if c2 := uploads() - before; c2 != 0 {
		t.Fatalf("checkpoint 2 (no change) uploaded %d l0 files, want 0 (the delta flush must skip unchanged entities; got the O(N) re-flush)", c2)
	}

	// Checkpoint 3: M new entities → delta flush uploads exactly M.
	for i := N; i < N+M; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	before = uploads()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("checkpoint 3: %v", err)
	}
	if c3 := uploads() - before; c3 != M {
		t.Fatalf("checkpoint 3 uploaded %d l0 files, want %d (the delta — only the new entities)", c3, M)
	}

	// Force the full-flush comparison. Its unchanged checkpoint must upload all
	// N entities, in contrast to zero uploads on the delta path.
	walPath2 := filepath.Join(t.TempDir(), "tb1full.wal")
	lfs2 := newSnapshotStore(t)
	live2 := newLiveBridge(t, walPath2, 0)
	live2.SetSnapshotter(lfs2, true)
	live2.debugFullQueryFlush.Store(true) // fault injection: revert to the O(N) full flush
	for i := 0; i < N; i++ {
		if _, err := live2.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal(full) %d: %v", i, err)
		}
	}
	if err := live2.AppendCheckpoint(); err != nil {
		t.Fatalf("full checkpoint 1: %v", err)
	}
	before = uploads()
	if err := live2.AppendCheckpoint(); err != nil { // no change — but full flush
		t.Fatalf("full checkpoint 2: %v", err)
	}
	if got := uploads() - before; got != N {
		t.Fatalf("full-flush no-change checkpoint uploaded %d l0 files, want %d; the comparison no longer distinguishes full from delta", got, N)
	}
}

// TestDeltaFlushDurableReadCorrect checks both kinds of entity after a delta
// checkpoint. The changed entity must resolve to its newer file, while an
// unchanged entity still resolves to its older file. A second subtest advances
// an entity's flush watermark without writing its delta; the durable read must
// then expose the missing update by returning the stale value.
func TestDeltaFlushDurableReadCorrect(t *testing.T) {
	ctx := context.Background()
	const base = int64(1_700_000_000_000_000_000)
	const openEnd = int64(9_000_000_000_000_000_000)

	payloadA1, payloadA2, payloadB := "alpha-v1", "alpha-v2", "beta"
	digestA1 := sha256.Sum256([]byte(payloadA1))
	digestA2 := sha256.Sum256([]byte(payloadA2))
	digestB := sha256.Sum256([]byte(payloadB))
	// entryAt: SystemTime/AssertionTime = sys; a wide valid window so the row
	// qualifies at the query's validTime. PutLocal stamps the digest from the
	// payload (step 1 of the physical order).
	entryAt := func(sys int64) eng.CRDTEntry {
		return eng.CRDTEntry{SystemTime: sys, ValidTimeStart: base, ValidTimeEnd: openEnd, AssertionTime: sys}
	}

	// setup returns a snapshotter-backed bridge (index on, K=0 caller-driven) +
	// a durable-only resolver (no live source — it reads the Arrow L0 tier).
	setup := func(t *testing.T) (*Bridge, *database.Resolver) {
		walPath := filepath.Join(t.TempDir(), "tb2.wal")
		lfs := newSnapshotStore(t)
		live := newLiveBridge(t, walPath, 0)
		live.SetSnapshotter(lfs, true)
		alloc := database.NewJemallocAllocator()
		cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
		return live, database.NewResolver(lfs, lfs, alloc, "tb2", cfg)
	}
	readDigest := func(t *testing.T, res *database.Resolver, entity string) [32]byte {
		ev, err := res.AsOf(ctx, entity, time.Unix(0, base+50), time.Unix(0, base+1_000_000))
		if err != nil {
			t.Fatalf("AsOf(%s): %v", entity, err)
		}
		if ev == nil {
			t.Fatalf("AsOf(%s): nil dominant", entity)
		}
		return ev.PayloadDigest
	}

	t.Run("ChangedAndUnchangedBothReadLatest", func(t *testing.T) {
		live, res := setup(t)
		if _, err := live.PutLocal("entity-A", payloadA1, entryAt(base)); err != nil {
			t.Fatalf("PutLocal A1: %v", err)
		}
		if _, err := live.PutLocal("entity-B", payloadB, entryAt(base)); err != nil {
			t.Fatalf("PutLocal B: %v", err)
		}
		if err := live.AppendCheckpoint(); err != nil { // checkpoint 1: full (A@base, B)
			t.Fatalf("checkpoint 1: %v", err)
		}
		// Update A (later SystemTime ⇒ new dot); B is unchanged.
		if _, err := live.PutLocal("entity-A", payloadA2, entryAt(base+1000)); err != nil {
			t.Fatalf("PutLocal A2: %v", err)
		}
		if err := live.AppendCheckpoint(); err != nil { // checkpoint 2: delta (only A)
			t.Fatalf("checkpoint 2: %v", err)
		}
		// The changed entity A reads its UPDATE; the unchanged entity B still reads.
		if got := readDigest(t, res, "entity-A"); got != digestA2 {
			t.Fatalf("changed entity A durable digest = %x, want %x (the delta flush lost the update)", got[:8], digestA2[:8])
		}
		if got := readDigest(t, res, "entity-B"); got != digestB {
			t.Fatalf("unchanged entity B durable digest = %x, want %x (the delta flush must not lose an unchanged entity)", got[:8], digestB[:8])
		}
	})

	t.Run("DroppedDeltaGoesStale", func(t *testing.T) {
		live, res := setup(t)
		if _, err := live.PutLocal("entity-A", payloadA1, entryAt(base)); err != nil {
			t.Fatalf("PutLocal A1: %v", err)
		}
		if err := live.AppendCheckpoint(); err != nil { // checkpoint 1: A@base durable
			t.Fatalf("checkpoint 1: %v", err)
		}
		dotA2, err := live.PutLocal("entity-A", payloadA2, entryAt(base+1000))
		if err != nil {
			t.Fatalf("PutLocal A2: %v", err)
		}
		// Fault injection: advance A's flush watermark to its new dot without flushing —
		// the lost-delta defect class. planQueryTierDelta now (wrongly) sees A as clean.
		live.lastFlushedMu.Lock()
		if live.lastFlushedDot == nil {
			live.lastFlushedDot = make(map[string]eng.CausalDot)
		}
		live.lastFlushedDot["entity-A"] = dotA2
		live.lastFlushedMu.Unlock()
		if err := live.AppendCheckpoint(); err != nil { // checkpoint 2: A skipped (lost delta)
			t.Fatalf("checkpoint 2: %v", err)
		}
		// The durable read is stale (only checkpoint 1's value) — the negative control detects it.
		if got := readDigest(t, res, "entity-A"); got != digestA1 {
			t.Fatalf("dropped delta returned %x, want stale value %x; the fault no longer exposes a lost delta", got[:8], digestA1[:8])
		}
	})
}

// TestDeltaCheckpointRecovery checks crash recovery with decoupled delta
// checkpoints. An intact image and WAL must reproduce the live root. A torn
// final image must be rejected in favor of exact-WAL replay, which must
// reproduce the same root without using image state.
func TestDeltaCheckpointRecovery(t *testing.T) {
	const N = 20
	ctx := context.Background()

	// build runs N utf8 entities through a snapshotter-backed bridge at K=1 (the
	// decoupled periodic path), drains the background runner, captures the live
	// root, then crashes (close WAL+engine directly — the buildWorkload kill-9
	// convention; the mutations are already fsync'd durable).
	build := func(t *testing.T) (walPath string, lfs *LocalFS, liveRoot [32]byte) {
		walPath = filepath.Join(t.TempDir(), "tb3.wal")
		lfs = newSnapshotStore(t)
		live := newLiveBridge(t, walPath, 1)
		live.SetSnapshotter(lfs, true)
		for i := 0; i < N; i++ {
			if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
				t.Fatalf("PutLocal %d: %v", i, err)
			}
		}
		live.waitCheckpointsIdle() // let the decoupled checkpoints complete
		liveRoot = live.Engine().State().MerkleRoot()
		if err := live.WAL().Close(); err != nil {
			t.Fatalf("live WAL close: %v", err)
		}
		if err := live.Engine().Close(); err != nil {
			t.Fatalf("live engine close: %v", err)
		}
		return walPath, lfs, liveRoot
	}

	t.Run("DecoupledDeltaRecoversRoot", func(t *testing.T) {
		walPath, lfs, liveRoot := build(t)
		rec, witness := recoverBounded(t, walPath, lfs)
		if got := rec.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("recovered root %x differs from live root %x after decoupled delta checkpoints", got, liveRoot)
		}
		if got := countDots(t, rec); got != N {
			t.Fatalf("recovered %d dots, want %d", got, N)
		}
		if witness.ExactWALFallback {
			t.Logf("note: exact-WAL fallback was taken (bounded path declined); root still re-equals — acceptable but unexpected for a clean checkpoint")
		}
	})

	t.Run("TornImageFallsBack", func(t *testing.T) {
		walPath, lfs, liveRoot := build(t)
		// Kill-9 mid-flush leaves a torn image at the final checkpoint key. Find
		// the final watermark from the WAL and overwrite its image with garbage.
		rep, err := ReplayWAL(walPath)
		if err != nil {
			t.Fatalf("ReplayWAL: %v", err)
		}
		if !rep.HasCheckpoint {
			t.Fatalf("no checkpoint anchor in the WAL — the decoupled checkpoint never persisted one")
		}
		wm := rep.FinalCheckpt.LamportHigh
		torn := []byte("SNSP-torn-truncated-garbage-not-a-valid-image")
		if err := lfs.Upload(ctx, snapshotKey(wm), strings.NewReader(string(torn)), int64(len(torn))); err != nil {
			t.Fatalf("corrupt image: %v", err)
		}
		// Recovery must refuse the torn image and fall back to exact-WAL replay.
		rec, witness := recoverBounded(t, walPath, lfs)
		if !witness.ExactWALFallback {
			t.Fatalf("ExactWALFallback=false after a torn image; recovery must not use the image")
		}
		if got := rec.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("recovered root %x differs from live root %x after torn-image fallback", got, liveRoot)
		}
		if got := countDots(t, rec); got != N {
			t.Fatalf("recovered %d dots after fallback, want %d", got, N)
		}
	})
}
