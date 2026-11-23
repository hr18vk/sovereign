// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Tests for bounded recovery from a checkpoint image and its WAL tail.
// Full-replay controls omit the snapshot store while using the same WAL. The
// suite covers replay counts, missing and corrupt images, root equality,
// concurrent checkpoint capture, foreign dots, and comparative recovery cost.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// utf8EntityID derives a UTF-8 entity ID from an integer. The binary suffix in
// stagedEntityID can contain NUL bytes, which MemTable.Write rejects, while the
// CRDT engine itself accepts arbitrary string keys. These tests use valid UTF-8
// so both the HAMT and the query index can store the IDs.
func utf8EntityID(i int) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(i))
	return "entity-" + hex.EncodeToString(b[:])
}

// newSnapshotStore builds a LocalFS in a fresh temp dir and returns it (and the
// dir for cleanup). It is the snapshot store for these tests.
func newSnapshotStore(t *testing.T) *LocalFS {
	t.Helper()
	root := filepath.Join(t.TempDir(), "snapstore")
	lfs, err := NewLocalFS(root)
	if err != nil {
		t.Fatalf("NewLocalFS: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return lfs
}

// buildWorkload writes pre mutations, a checkpoint, and post mutations before
// closing the engine and WAL. It returns the WAL path, final live root,
// checkpoint watermark, and final Lamport counter. The snapshot is written when
// lfs is non-nil.
func buildWorkload(t *testing.T, pre, post int, lfs *LocalFS) (walPath string, liveRoot [32]byte, ckptLamport, finalLamport uint64) {
	t.Helper()
	walPath = filepath.Join(t.TempDir(), "workload.wal")
	live := newLiveBridge(t, walPath, 0)
	if lfs != nil {
		live.SetSnapshotter(lfs, true) // recovery image + Arrow index
	}
	for i := 0; i < pre; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	ckptLamport = live.Engine().LamportCounter()
	for i := 0; i < post; i++ {
		if _, err := live.PutLocal(utf8EntityID(pre+i), stagedPayload(pre+i), stagedEntry(pre+i)); err != nil {
			t.Fatalf("PutLocal post %d: %v", i, err)
		}
	}
	liveRoot = live.Engine().State().MerkleRoot()
	finalLamport = live.Engine().LamportCounter()
	// Kill the live engine + WAL exactly like a crash (no graceful flush beyond
	// the per-mutation fsync + the checkpoint fsync already on disk).
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}
	return walPath, liveRoot, ckptLamport, finalLamport
}

// recoverBounded recovers via the bounded path and closes the recovered
// engine/scratch on test cleanup.
func recoverBounded(t *testing.T, walPath string, store SnapshotStore) (*eng.DeltaCRDTEngine, *RecoveryWitness) {
	t.Helper()
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, store, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngineWithSnapshot: %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = engine.Close() })
	return engine, witness
}

// recoverFull recovers via the back-compat full-replay path (store == nil).
func recoverFull(t *testing.T, walPath string) (*eng.DeltaCRDTEngine, *RecoveryWitness) {
	t.Helper()
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, nil, testArenaSize)
	if err != nil {
		t.Fatalf("RecoverEngine (full): %v", err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	t.Cleanup(func() { _ = engine.Close() })
	return engine, witness
}

// TestRecovery_BoundedReplay_MWitness verifies that a checkpoint image reduces
// ReplayedRecords from pre+post to just the post-checkpoint tail. A nil store
// forces full replay as the control. Both paths must reproduce the live root,
// and bounded recovery must also resume at the final Lamport counter.
func TestRecovery_BoundedReplay_MWitness(t *testing.T) {
	const pre, post = 512, 16

	t.Run("bounded", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, liveRoot, ckptLamport, finalLamport := buildWorkload(t, pre, post, lfs)
		engine, witness := recoverBounded(t, walPath, lfs)

		if !witness.Bounded {
			t.Fatalf("witness.Bounded=false, want true (snapshot present at ckpt/%d)", ckptLamport)
		}
		if witness.ReplayedRecords != post {
			t.Fatalf("witness.ReplayedRecords=%d, want %d (the post-checkpoint tail; the snapshot absorbed the %d pre-checkpoint records)",
				witness.ReplayedRecords, post, pre)
		}
		if witness.ReplayedRecords == pre+post {
			t.Fatalf("bounded recovery replayed all %d records instead of using the snapshot", pre+post)
		}
		if got := engine.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("bounded recovery Merkle mismatch:\n  live=%x\n  got =%x", liveRoot, got)
		}
		if got := engine.LamportCounter(); got != finalLamport {
			t.Fatalf("bounded recovery Lamport mismatch: live=%d got=%d", finalLamport, got)
		}
	})

	// With a nil store, the same WAL and on-disk image must take the full-replay
	// path and report every mutation in ReplayedRecords.
	t.Run("full_replay_control", func(t *testing.T) {
		lfs := newSnapshotStore(t) // image exists on disk...
		walPath, liveRoot, _, _ := buildWorkload(t, pre, post, lfs)
		// ...but recovered WITHOUT the store — the image is ignored.
		engine, witness := recoverFull(t, walPath)

		if witness.Bounded {
			t.Fatalf("control witness.Bounded=true, want false (store==nil must full-replay)")
		}
		if witness.ReplayedRecords != pre+post {
			t.Fatalf("control witness.ReplayedRecords=%d, want %d (full replay of pre+post)",
				witness.ReplayedRecords, pre+post)
		}
		if got := engine.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("full-replay control Merkle mismatch:\n  live=%x\n  got =%x", liveRoot, got)
		}
	})
}

// TestRecovery_MissingSnapshot_FallbackFullReplay covers a checkpoint whose
// image is absent or cannot be decoded. Recovery must rebuild through full WAL
// replay and report why the snapshot was not used.
func TestRecovery_MissingSnapshot_FallbackFullReplay(t *testing.T) {
	const pre, post = 256, 16

	t.Run("no_image_at_watermark", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, liveRoot, ckptLamport, _ := buildWorkload(t, pre, post, lfs)
		// Delete the recovery image so SnapshotExists(ckpt) == false, leaving the
		// WAL checkpoint anchor in place (the dangling-anchor state).
		ckptKey := fmt.Sprintf("ckpt/%d", ckptLamport)
		_ = os.Remove(filepath.Join(lfs.Root(), filepath.FromSlash(ckptKey)))
		exists, err := lfs.SnapshotExists(context.Background(), ckptLamport)
		if err != nil {
			t.Fatalf("SnapshotExists: %v", err)
		}
		if exists {
			t.Fatalf("precondition: image still present after Remove")
		}

		engine, witness := recoverBounded(t, walPath, lfs)
		if witness.Bounded {
			t.Fatalf("witness.Bounded=true, want false (image absent → must fall back)")
		}
		if witness.FallbackReason == "" {
			t.Fatalf("witness.FallbackReason empty — the fallback reason must be reported")
		}
		if witness.ReplayedRecords != pre+post {
			t.Fatalf("fallback ReplayedRecords=%d, want %d (full replay)", witness.ReplayedRecords, pre+post)
		}
		if got := engine.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("fallback Merkle mismatch:\n  live=%x\n  got =%x", liveRoot, got)
		}
	})

	// Corrupt image: decode refuses the torn bytes (bad magic), recovery falls
	// back to full replay rather than rebuilding on a suspect image.
	t.Run("corrupt_image", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, liveRoot, ckptLamport, _ := buildWorkload(t, pre, post, lfs)
		ckptKey := filepath.Join(lfs.Root(), filepath.FromSlash(fmt.Sprintf("ckpt/%d", ckptLamport)))
		// Overwrite the image with garbage (keep it non-empty so SnapshotExists
		// stays true → forces the decode-failure fallback branch).
		if err := os.WriteFile(ckptKey, []byte("GARBAGE-not-a-snapshot"), 0o640); err != nil {
			t.Fatalf("overwrite image: %v", err)
		}

		engine, witness := recoverBounded(t, walPath, lfs)
		if witness.Bounded {
			t.Fatalf("witness.Bounded=true, want false (corrupt image → must fall back)")
		}
		if witness.FallbackReason == "" {
			t.Fatalf("witness.FallbackReason empty — corrupt-image fallback must be reported")
		}
		if got := engine.State().MerkleRoot(); got != liveRoot {
			t.Fatalf("fallback Merkle mismatch (corrupt image):\n  live=%x\n  got =%x", liveRoot, got)
		}
	})
}

// TestSnapshot_Determinism_PreVsPostCheckpoint_MerkleEqual compares bounded and
// full recovery over the same origin-only WAL. Their roots must both equal the
// live root even though bounded recovery replays only the post-checkpoint
// records. Foreign-dot recovery is covered separately below.
func TestSnapshot_Determinism_PreVsPostCheckpoint_MerkleEqual(t *testing.T) {
	const pre, post = 256, 24

	lfs := newSnapshotStore(t)
	walPath, liveRoot, ckptLamport, finalLamport := buildWorkload(t, pre, post, lfs)
	_ = ckptLamport

	engineA, witnessA := recoverBounded(t, walPath, lfs) // bounded
	engineB, witnessB := recoverFull(t, walPath)         // full

	if !witnessA.Bounded {
		t.Fatalf("engineA (bounded) witness.Bounded=false, want true")
	}
	if witnessB.Bounded {
		t.Fatalf("engineB (full) witness.Bounded=true, want false")
	}
	// A replays only post; B replays pre+post. Same dot set, different cost.
	if witnessA.ReplayedRecords != post {
		t.Fatalf("engineA ReplayedRecords=%d, want %d", witnessA.ReplayedRecords, post)
	}
	if witnessB.ReplayedRecords != pre+post {
		t.Fatalf("engineB ReplayedRecords=%d, want %d", witnessB.ReplayedRecords, pre+post)
	}

	rootA := engineA.State().MerkleRoot()
	rootB := engineB.State().MerkleRoot()
	if rootA != rootB {
		t.Fatalf("bounded root %x differs from full-replay root %x\n"+
			"The snapshot Join and post-checkpoint replay diverged from full replay.",
			rootA, rootB)
	}
	if rootA != liveRoot {
		t.Fatalf("live root %x differs from bounded root %x", liveRoot, rootA)
	}
	if got := engineA.LamportCounter(); got != finalLamport {
		t.Fatalf("bounded recovery Lamport mismatch: live=%d got=%d", finalLamport, got)
	}
}

// TestSnapshot_ConcurrentPutLocalAndCheckpoint_EBRSafe overlaps PutLocal with
// AppendCheckpoint. AppendCheckpoint holds the EBR pin while capturing the
// shards and writing their image; SnapshotToLSM receives that captured state
// and does not perform a second State walk. After the writers stop, full replay
// must reproduce the live root without a race report or panic.
func TestSnapshot_ConcurrentPutLocalAndCheckpoint_EBRSafe(t *testing.T) {
	runConcurrentCheckpoint(t)
}

func runConcurrentCheckpoint(t *testing.T) {
	t.Helper()
	walPath := filepath.Join(t.TempDir(), "concurrent.wal")
	lfs := newSnapshotStore(t)
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)

	var stop atomic.Bool
	var writers sync.WaitGroup
	var ckpters sync.WaitGroup
	var writes atomic.Int64
	var ckpts atomic.Int64
	var writeErr atomic.Pointer[error]
	var ckptErr atomic.Pointer[error]

	// Seed some state so the snapshot has a non-empty dot set to extract.
	for i := 0; i < 50; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("seed PutLocal %d: %v", i, err)
		}
	}

	const nWriters = 6
	for w := 0; w < nWriters; w++ {
		writers.Add(1)
		go func(seed int) {
			defer writers.Done()
			for i := 0; !stop.Load(); i++ {
				e := utf8EntityID(seed*1000 + (i % 997))
				if _, err := live.PutLocal(e, stagedPayload(seed*1000+i), stagedEntry(seed*1000+i)); err != nil {
					we := err
					writeErr.Store(&we)
					return
				}
				writes.Add(1)
			}
		}(w)
	}

	ckpters.Add(1)
	go func() {
		defer ckpters.Done()
		for !stop.Load() {
			if err := live.AppendCheckpoint(); err != nil {
				ce := err
				ckptErr.Store(&ce)
				return
			}
			ckpts.Add(1)
			runtime.Gosched()
		}
	}()

	// Let the churn run long enough to overlap extract with writes, bounded by
	// wall time so the test is deterministic in duration. 100ms is enough to
	// trip a missing EBR pin under -race (the detector needs one overlapping
	// access) and fast enough for the plain-CI line.
	time.Sleep(100 * time.Millisecond)
	stop.Store(true)
	writers.Wait()
	ckpters.Wait()

	if p := writeErr.Load(); p != nil {
		t.Fatalf("concurrent PutLocal failed: %v", *p)
	}
	if p := ckptErr.Load(); p != nil {
		t.Fatalf("concurrent AppendCheckpoint failed: %v", *p)
	}
	if writes.Load() == 0 || ckpts.Load() == 0 {
		t.Fatalf("no churn happened: writes=%d ckpts=%d", writes.Load(), ckpts.Load())
	}
	t.Logf("overlapped %d writes with %d checkpoints", writes.Load(), ckpts.Load())

	// Quiesce: stop writers, take a final snapshot-free checkpoint so the last WAL
	// record is a clean anchor with no post-ckpt mutations, then recover via full
	// replay and assert the recovered root equals the live root (the concurrent
	// extracts must not have corrupted the durable dot set).
	live.SetSnapshotter(nil, false)
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("final quiescent AppendCheckpoint: %v", err)
	}
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	recovered, _ := recoverFull(t, walPath)
	if got := recovered.State().MerkleRoot(); got != liveRoot {
		t.Fatalf("live root %x differs from root after concurrent checkpoints %x", liveRoot, got)
	}
}

// BenchmarkRecovery_BoundedVsFull compares full and bounded recovery over the
// same WAL and snapshot. Timing and allocations measure the full recovery call;
// ReplayedRecords independently checks that the bounded path processes only the
// post-checkpoint tail.
func BenchmarkRecovery_BoundedVsFull(b *testing.B) {
	const pre, post = 8192, 64 // pre large, post small → the ratio is stark

	// Build the WAL and snapshot once (outside the timed loop). Each iteration
	// recovers from the same durable state (the WAL is read-only across
	// recoveries; recoveries append nothing).
	walPath := filepath.Join(b.TempDir(), "bench.wal")
	storeRoot := filepath.Join(b.TempDir(), "snapstore")
	lfs, err := NewLocalFS(storeRoot)
	if err != nil {
		b.Fatalf("NewLocalFS: %v", err)
	}
	buildWorkloadBench(b, walPath, pre, post, lfs)

	b.Run("Full", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			engine, wal, _, witness, rerr := RecoverEngineWithSnapshot(testNodeID(), walPath, nil, testArenaSize)
			if rerr != nil {
				b.Fatalf("recover full: %v", rerr)
			}
			if witness.ReplayedRecords != pre+post {
				b.Fatalf("full ReplayedRecords=%d want %d", witness.ReplayedRecords, pre+post)
			}
			_ = engine.State().MerkleRoot() // force the read so work isn't elided
			_ = wal.Close()
			_ = engine.Close()
		}
	})

	b.Run("Bounded", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			engine, wal, _, witness, rerr := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
			if rerr != nil {
				b.Fatalf("recover bounded: %v", rerr)
			}
			if !witness.Bounded {
				b.Fatalf("bounded path not taken (snapshot missing?)")
			}
			if witness.ReplayedRecords != post {
				b.Fatalf("bounded ReplayedRecords = %d, want post-checkpoint count %d", witness.ReplayedRecords, post)
			}
			_ = engine.State().MerkleRoot()
			_ = wal.Close()
			_ = engine.Close()
		}
	})
}

// buildWorkloadBench is the Benchmark variant of buildWorkload (no *testing.T).
func buildWorkloadBench(b *testing.B, walPath string, pre, post int, lfs *LocalFS) {
	b.Helper()
	b.StopTimer()
	defer b.StartTimer()
	eng.DataDir = b.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, testArenaSize)
	if err != nil {
		b.Fatalf("NewDeltaCRDTEngine live: %v", err)
	}
	defer func() { _ = engine.Close() }()
	wal, err := OpenWAL(walPath)
	if err != nil {
		b.Fatalf("OpenWAL: %v", err)
	}
	defer func() { _ = wal.Close() }()
	bridge := NewBridge(engine, wal, 0)
	bridge.SetSnapshotter(lfs, true)
	for i := 0; i < pre; i++ {
		if _, err := bridge.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			b.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	if err := bridge.AppendCheckpoint(); err != nil {
		b.Fatalf("AppendCheckpoint: %v", err)
	}
	for i := 0; i < post; i++ {
		if _, err := bridge.PutLocal(utf8EntityID(pre+i), stagedPayload(pre+i), stagedEntry(pre+i)); err != nil {
			b.Fatalf("PutLocal post %d: %v", i, err)
		}
	}
}

// TestRecoveryForeignAdvance_BoundedRestoresForeignDots verifies the state that
// full replay cannot reconstruct. A foreign Join adds entries to the engine and
// advances its clock, but the WAL records only local mutations and that clock
// advance. A checkpoint image contains both local and foreign dots, so bounded
// recovery must reproduce the live root and clock. With the store omitted, full
// replay must instead produce a different root because the foreign entries are
// absent until they arrive through gossip again.
//
// The trailing local mutation occurs before AppendCheckpoint. Consequently the
// checkpoint's CutSeq covers the entire WAL and bounded recovery replays zero
// records; the image supplies every mutation.
func TestRecoveryForeignAdvance_BoundedRestoresForeignDots(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "foreign-bounded.wal")
	const K = 8 // origin mutations (counters 2..9, seed=1, NextDot Add(1))

	// Build the live workload once: origin mutations, a real foreign Join
	// (advances clock + merges foreign state), RecordClockAdvance, a checkpoint
	// with a snapshot image, then one trailing origin mutation. The live root
	// is origin+foreign; the live clock is post-trailing-mutation. Crash.
	live := newLiveBridge(t, walPath, 0)

	// The snapshotter must be active before the checkpoint. This workload is
	// built inline because buildWorkload does not interleave a foreign Join.
	lfs := newSnapshotStore(t)
	live.SetSnapshotter(lfs, true)

	for i := 0; i < K; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	if got := live.Engine().LamportCounter(); got != uint64(K+1) {
		t.Fatalf("pre-Join lamport %d != %d (origin mint assumption wrong)", got, K+1)
	}

	// Join entries from a distinct node ID. This advances the live clock and
	// adds dots that the origin-only WAL does not record as mutations.
	const F = 5
	eng.DataDir = t.TempDir()
	foreign, err := eng.NewDeltaCRDTEngine(foreignNodeID(), 100, testArenaSize)
	if err != nil {
		t.Fatalf("foreign engine ctor: %v", err)
	}
	t.Cleanup(func() { _ = foreign.Close() })
	for i := 0; i < F; i++ {
		foreign.InsertLocal(utf8EntityID(1000+i), stagedEntry(1000+i))
	}
	liveDigest := live.Engine().GenerateDigest()
	delta := foreign.GenerateDelta(liveDigest)
	defer delta.Release() // must release (crdt.go documents the EBR participant exit): exits the carried EBR participant so foreign.Close's Quiesce doesn't hang on the leak
	live.Engine().Join(*delta)
	// Record the foreign clock advance at the receive seam so the
	// WAL carries it — without this, the clock advance is un-recorded and the
	// recovery seed (whichever path) would mis-resume.
	if err := live.RecordClockAdvance(); err != nil {
		t.Fatalf("RecordClockAdvance: %v", err)
	}

	// One trailing origin mutation after the foreign Join — its counter must
	// re-mint identically on either recovery path (the seed is exact).
	if _, err := live.PutLocal(utf8EntityID(K), stagedPayload(K), stagedEntry(K)); err != nil {
		t.Fatalf("trailing PutLocal: %v", err)
	}
	liveRoot := live.Engine().State().MerkleRoot() // origin + foreign
	liveLamport := live.Engine().LamportCounter()

	// AppendCheckpoint writes one SnapshotRecord per entry, including the
	// foreign dots, at the current checkpoint watermark.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	// The ckpt watermark (the snapshot's LamportHigh) — the live clock at the
	// checkpoint, which the snapshot's image + the recovery Join must land on.
	ckptLamport := live.Engine().LamportCounter()
	_ = ckptLamport // captured for the witness assert below (the pre-crash value)

	// Kill the live engine + WAL exactly like a crash.
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// Bounded recovery joins the image, which includes foreign dots.
	t.Run("bounded_restores_foreign_dots", func(t *testing.T) {
		recovered, witness := recoverBounded(t, walPath, lfs)

		if !witness.Bounded {
			t.Fatalf("bounded: witness.Bounded=false, want true (snapshot image at ckpt/%d)", ckptLamport)
		}
		// The checkpoint's pre-walk CutSeq follows every mutation and the
		// clock-advance record, so the replay tail is empty. Replaying any
		// record here would re-apply state already absorbed by the image.
		if witness.ReplayedRecords != 0 {
			t.Errorf("bounded ReplayedRecords = %d, want 0 below the checkpoint CutSeq", witness.ReplayedRecords)
		}

		// The checkpoint watermark restores the live Lamport counter.
		if got := recovered.LamportCounter(); got != liveLamport {
			t.Fatalf("recovered Lamport counter = %d, want live counter %d\n"+
				"The snapshot load and checkpoint watermark did not resume the live clock.",
				got, liveLamport)
		}

		// Joining the image restores both local and foreign dots, so the root
		// covers the same state as the live engine.
		recoveredRoot := recovered.State().MerkleRoot()
		if recoveredRoot != liveRoot {
			t.Fatalf("bounded recovery root %x differs from live root %x\n"+
				"Bounded recovery did not restore the foreign dots captured by the snapshot. "+
				"The recovered state should include both origin and foreign entries. "+
				"Check that the image carries the full dot set, that Join restores those entries, "+
				"and that the checkpoint watermark resumes correctly. "+
				"The recovered root must equal the live root.",
				recoveredRoot, liveRoot)
		}
	})

	// Omitting the store leaves the same WAL but prevents the image from being
	// loaded. The WAL carries local mutations and clock advances, not foreign
	// entries, so this full-replay control must produce a different root.
	t.Run("full_replay_control_diverges", func(t *testing.T) {
		recovered, witness := recoverFull(t, walPath)

		if witness.Bounded {
			t.Fatalf("full-replay control reports Bounded=true with a nil store")
		}

		// The recorded clock advance restores the live counter even though the
		// foreign entries themselves are absent from the WAL.
		if got := recovered.LamportCounter(); got != liveLamport {
			t.Fatalf("full-replay control clock = %d, want live counter %d", got, liveLamport)
		}

		// Full replay restores only local mutations, so its root must differ
		// from the live root that also includes the foreign Join. Equal roots
		// would mean the test did not establish that distinction.
		recoveredRoot := recovered.State().MerkleRoot()
		if recoveredRoot == liveRoot {
			t.Fatalf("full-replay root %x unexpectedly equals the live root\n"+
				"Full replay cannot restore foreign dots because the WAL carries local mutations and clock advances, "+
				"not foreign CRDTEntries. Equal roots mean either the foreign Join did not merge state or the WAL "+
				"captured foreign deltas. The bounded-recovery comparison depends on this control diverging. "+
				"If both roots are equal, the fixture did not establish "+
				"the distinction between replay and image recovery.",
				recoveredRoot)
		}
		t.Logf("full-replay root %x differs from live root %x because foreign entries are absent from the WAL", recoveredRoot, liveRoot)
	})
}
