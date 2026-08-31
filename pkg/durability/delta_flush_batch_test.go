// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//delta_flush_batch_test.go — the HALF-B guards (the
// query-tier DELTA flush that kills the O(N^2) cross-checkpoint re-flush).
//
//	T-B1 the fsync-count guard: the query-tier upload WORK drops from O(N) per
// checkpoint to O(Δ) (0 on a no-change checkpoint).
//	T-B2 the correctness guard: after a delta checkpoint, a durable read returns
// the latest for BOTH a changed AND an unchanged entity.
//	T-B3 the recovery guard: a crash with the decoupled+delta checkpoint path
// re-attains the root (the binding/phantom/missing-image fallback, I2).
//
// The work metric is the l0/ per-entity upload count (uploadL0Uploads): each
// upload is ONE file carrying BOTH fsyncs (tmp.Sync localfs.go:150 +
// fsyncParentDir:172), and a full re-flush OVERWRITES the same per-entity keys
// — so the distinct-file COUNT cannot distinguish full from delta, but the
// upload WORK can. The ckpt/ recovery image is excluded (always 1/checkpoint).

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

// TestDeltaFlushFsyncCount proves the query-tier flush is DELTA-ONLY:
// the per-checkpoint l0/ upload count drops from O(N) to O(Δ). NEGATIVE CONTROL:
// with debugFullQueryFlush forcing the pre-full flush, a no-change
// checkpoint re-uploads ALL N entities (the O(N) regression the guard exists to
// catch) — so the delta assertion (0) genuinely distinguishes the two shapes.
func TestDeltaFlushFsyncCount(t *testing.T) {
	const N = 50 // base entities
	const M = 10 // new entities in the delta
	uploads := func() int64 { return uploadL0UploadsCount() }

	walPath := filepath.Join(t.TempDir(), "tb1.wal")
	lfs := newSnapshotStore(t)
	live := newLiveBridge(t, walPath, 0) // K=0: caller-driven checkpoints
	live.SetSnapshotter(lfs, true)

	// Checkpoint 1: N inserts → FULL flush (first checkpoint, lastFlushedDot nil).
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
		t.Fatalf("checkpoint 1 (first flush) uploaded %d l0 files, want %d (the FULL first flush)", c1, N)
	}

	// Checkpoint 2: NO changes → DELTA flush must upload ZERO query-tier files.
	// (The recovery image at ckpt/ is still written — it is not an l0/ upload.)
	before = uploads()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("checkpoint 2: %v", err)
	}
	if c2 := uploads() - before; c2 != 0 {
		t.Fatalf("checkpoint 2 (no change) uploaded %d l0 files, want 0 (the DELTA flush must skip unchanged entities; got the O(N) re-flush)", c2)
	}

	// Checkpoint 3: M NEW entities → DELTA flush uploads exactly M.
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
		t.Fatalf("checkpoint 3 uploaded %d l0 files, want %d (the DELTA — only the new entities)", c3, M)
	}

	// NEGATIVE CONTROL: force the full flush (debugFullQueryFlush) and show a
	// no-change checkpoint re-uploads ALL N — the pre-O(N) shape.
	walPath2 := filepath.Join(t.TempDir(), "tb1full.wal")
	lfs2 := newSnapshotStore(t)
	live2 := newLiveBridge(t, walPath2, 0)
	live2.SetSnapshotter(lfs2, true)
	live2.debugFullQueryFlush.Store(true) // BUG-INJECT: revert to the O(N) full flush
	for i := 0; i < N; i++ {
		if _, err := live2.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal(full) %d: %v", i, err)
		}
	}
	if err := live2.AppendCheckpoint(); err != nil {
		t.Fatalf("full checkpoint 1: %v", err)
	}
	before = uploads()
	if err := live2.AppendCheckpoint(); err != nil { // NO change — but full flush
		t.Fatalf("full checkpoint 2: %v", err)
	}
	if got := uploads() - before; got != N {
		t.Fatalf("NEGATIVE CONTROL BROKEN: full-flush no-change checkpoint uploaded %d l0 files, want %d (the O(N) re-flush) — the guard cannot distinguish delta from full", got, N)
	}
}

// TestDeltaFlushDurableReadCorrect is the correctness guard: after a
// DELTA checkpoint, a durable (Arrow L0) read must return the latest state for
// BOTH a changed AND an unchanged entity. The resolver's per-entity prefix merge
// (max-SystemTime dominance) makes an unchanged entity's older file suffice; the
// changed entity's newer file must win. BUG-INJECT: advance an entity's flush
// watermark WITHOUT flushing it (a lost delta) → the durable read goes STALE →
// the guard catches it.
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
	// a DURABLE-ONLY resolver (NO live source — it reads the Arrow L0 tier).
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
		if err := live.AppendCheckpoint(); err != nil { // checkpoint 1: FULL (A@base, B)
			t.Fatalf("checkpoint 1: %v", err)
		}
		// Update A (later SystemTime ⇒ new dot); B is UNCHANGED.
		if _, err := live.PutLocal("entity-A", payloadA2, entryAt(base+1000)); err != nil {
			t.Fatalf("PutLocal A2: %v", err)
		}
		if err := live.AppendCheckpoint(); err != nil { // checkpoint 2: DELTA (only A)
			t.Fatalf("checkpoint 2: %v", err)
		}
		// The changed entity A reads its UPDATE; the unchanged entity B still reads.
		if got := readDigest(t, res, "entity-A"); got != digestA2 {
			t.Fatalf("changed entity A durable digest = %x, want %x (the delta flush LOST the update)", got[:8], digestA2[:8])
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
		// BUG-INJECT: advance A's flush watermark to its NEW dot WITHOUT flushing —
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
		// The durable read is STALE (only checkpoint 1's value) — the guard detects it.
		if got := readDigest(t, res, "entity-A"); got != digestA1 {
			t.Fatalf("BUG-INJECT BROKEN: a dropped delta did NOT go stale (got %x, want the stale %x) — the guard cannot detect a lost delta", got[:8], digestA1[:8])
		}
	})
}

// TestDeltaCheckpointRecovery is the recovery guard (I2, check ON):
// the decoupled + delta checkpoint path must NOT break crash recovery.:
// decoupled periodic checkpoints + a crash re-attain the root (the recovery
// image stays FULL and bound). a torn final image — the kill-9-mid-flush
// result — must fall back to exact-WAL replay and STILL re-attain the root (the
// binding/decode fallback, recovery.go). The WAL is authoritative throughout.
func TestDeltaCheckpointRecovery(t *testing.T) {
	const N = 20
	ctx := context.Background()

	// build runs N utf8 entities through a snapshotter-backed bridge at K=1 (the
	// DECOUPLED periodic path), drains the background runner, captures the live
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
			t.Fatalf("ROOT MISMATCH: recovered %x != live %x — the decoupled+delta checkpoint path broke recovery (I2)", got, liveRoot)
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
		// Kill-9 mid-flush leaves a TORN image at the final checkpoint key. Find
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
		// Recovery must REFUSE the torn image and fall back to exact-WAL replay.
		rec, witness := recoverBounded(t, walPath, lfs)
		if !witness.ExactWALFallback {
			t.Fatalf("MARKER: ExactWALFallback=false — a torn kill-9 image was used SILENTLY (the I2 fallback did not fire)")
		}
		if got := rec.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("ROOT MISMATCH after torn-image fallback: recovered %x != live %x (the WAL alone must rebuild the live state)", got, liveRoot)
		}
		if got := countDots(t, rec); got != N {
			t.Fatalf("recovered %d dots after fallback, want %d", got, N)
		}
	})
}
