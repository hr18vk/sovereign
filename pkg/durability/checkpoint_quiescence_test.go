// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//checkpoint_quiescence_test.go — the $0 reproduction of the
// The crash-leg failure (silicon, 2026-08-31, 3× c7gd): a NON-QUIESCENT
// checkpoint — taken while concurrent PutLocals are still committing — leaks
// post-watermark dots into the snapshot image; bounded recovery then re-mints
// those SAME mutations at FRESH counters, DOUBLE-DOTTING every leaked entity and
// permanently diverging the recovered root from the live root.
//
// THE SILICON SIGNATURE: the seed recovered from ckpt/9201 + replayed
// 808 post-checkpoint records (the 8 hard-timeout batches' 800 keys + 8 clock
// advances) and came up with root 2e135b3a… ≠ the pre-crash converged root
// d1406abf… that all 99 peers still held — a PERMANENT 1-vs-99 split that never
// re-converged in the 240s extended poll. The recovered seed walked 10,800 dots
// for 10,000 injected keys: the 800 leaked tail keys, double-dotted.
//
// NOTE ON CITATIONS: the line numbers in the mechanism below reference the
// PRE-recovery.go/bridge.go — the code the RED was captured against.
// Post-the checkpoint derives root+watermark+image from ONE pinned walk
// (no T1/T2 gap) and replay RESTORES recorded dots (never re-mints), so the
// mechanism described is exactly what this fork DELETED.
//
// THE MECHANISM (the flaw in snapshot.go's "Recovery is CORRECT regardless"
// comment,:365-369):
//
//	1. AppendCheckpoint (bridge.go:334) reads LamportHigh (the watermark) at T1
// and fsyncs the WAL anchor; SnapshotToLSM then walks the live HAMT at T2>T1.
//	2. Concurrent PutLocals (the timed-out batches, still committing) mint dots in
// (T1,T2] → the image captures entities with DotCounter > watermark.
//	3. Recovery seeds rebuiltInitial = watermark (recovery.go:226), then Join(image)
// (:256). Join's per-entry AdvanceLamportTo(entry.Dot) is a monotone MAX: it
// jumps the clock to the image's MAX dot (the highest LEAKED counter), NOT the
// watermark. The explicit AdvanceLamportTo(watermark) (:257) is then a no-op.
//	4. The replay filter skips mutations with Counter ≤ watermark (:301) but
// REPLAYS the leaked ones (Counter > watermark) via InsertLocal (:311), which
// RE-MINTS from NextDot() = maxLeakedDot+1… — FRESH counters, NOT the recorded
// DotCounter the image already carries.
//	5. Join's dot-union therefore does NOT dedup them (different DotCounter): each
// leaked entity keeps its image dot AND gains a phantom re-mint dot.
//
// The comment's correctness argument ("Join's dot-union dedups them (same
// DotNodeID+Counter)") holds ONLY when the checkpoint is QUIESCENT: no dot leaks
// past the watermark, so Join lands the clock exactly AT the watermark and the
// re-mint reproduces the recorded counters. Checkpointing at quiescence passes
// the crash leg; checkpointing mid-ingest fails it. EVERY
// pre-existing bounded-recovery test (snapshot_test.go buildWorkload) checkpoints
// at quiescence — sequential pre-mutations, then AppendCheckpoint, then post —
// so none create the leak. THIS test is the coverage hole, filled.
//
// The repro is DETERMINISTIC, not a race: it splits AppendCheckpoint into its two
// physical halves and commits the "timed-out tail" BETWEEN them —
//
//	wal.AppendCheckpoint(anchor@wm) → PutLocal(tail) → SnapshotToLSM(stale wm)
//
// which is EXACTLY the T1-watermark/T2-image window AppendCheckpoint opens under
// concurrent load, with the interleaving forced by construction instead of left
// to a scheduler.

import (
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// countDots sums len(entries) over every entity — the LIVE dot count. An
// add-wins entity carries one dot per concurrent write; a double-minted entity
// carries two. This is the observable that distinguishes DOUBLE-MINT (recovered
// dots > live dots) from DATA-LOSS (recovered dots < live dots).
func countDots(t *testing.T, engine *eng.DeltaCRDTEngine) int {
	t.Helper()
	total := 0
	engine.State().ForEach(func(_ string, entries []eng.CRDTEntry) bool {
		total += len(entries)
		return true
	})
	return total
}

// TestRecovery_NonQuiescentCheckpoint_DoubleMint is the RED guard. It builds the
// the failure condition (a checkpoint whose image leaks the post-watermark tail),
// recovers via the bounded path, and asserts the DURABILITY CONTRACT: the
// recovered root, live dot count, and Lamport high-water MUST equal the live
// engine's. Under the defect all three diverge — the guard fails RED with the
// exact double-mint arithmetic. The fix turns it GREEN.
func TestRecovery_NonQuiescentCheckpoint_DoubleMint(t *testing.T) {
	const pre, post = 100, 50
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "leak.wal")
	live := newLiveBridge(t, walPath, 0) // caller-driven checkpoints

	// pre keys commit normally; the clock lands at start+pre.
	for i := 0; i < pre; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}

	// THE LEAK, deterministic. Read the watermark + root (AppendCheckpoint's T1),
	// fsync the WAL anchor, then commit the "timed-out tail" (which lands in
	// (T1,T2] under concurrent load), THEN take the snapshot image stamped with
	// the STALE watermark — capturing the tail in the image while the replay
	// filter still treats it as post-watermark.
	wm := live.Engine().LamportCounter()
	rootAtWm := live.Engine().State().MerkleRoot()
	if err := live.WAL().AppendCheckpoint(WALCheckpoint{MerkleRoot: rootAtWm, LamportHigh: wm}); err != nil {
		t.Fatalf("WAL.AppendCheckpoint: %v", err)
	}
	for i := pre; i < pre+post; i++ { // the tail: counters (wm, wm+post]
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal post %d: %v", i, err)
		}
	}
	// The T2 image: stamped watermark wm, but captures ALL pre+post entities.
	if err := writeImageForTest(live.Engine(), wm, lfs); err != nil {
		t.Fatalf("SnapshotToLSM: %v", err)
	}

	liveRoot := live.Engine().State().MerkleRoot()
	finalLamport := live.Engine().LamportCounter()
	liveDots := countDots(t, live.Engine())
	if liveDots != pre+post {
		t.Fatalf("setup: live dot count %d, want %d (one dot per entity)", liveDots, pre+post)
	}

	// Kill exactly like a crash (per-mutation + checkpoint fsyncs already on disk).
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// Recover via the bounded path (the non-final-checkpoint path, so
	// the root-equality assertion is SCOPED OUT at recovery — the divergence is
	// silent there and only this guard catches it).
	engine, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false — the bounded path did not engage; the repro is not exercising that code path")
	}
	if witness.ReplayedRecords != post {
		t.Fatalf("witness.ReplayedRecords=%d, want %d (the post-watermark tail)", witness.ReplayedRecords, post)
	}

	recRoot := engine.State().MerkleRoot()
	recLamport := engine.LamportCounter()
	recDots := countDots(t, engine)

	// THE DURABILITY CONTRACT. Each is a separate assertion so the failure names
	// the exact divergence (double-mint vs data-loss vs clock drift).
	if recDots != liveDots {
		t.Errorf("DOUBLE-MINT: recovered live-dot count %d != live %d (+%d phantom dots — the %d leaked tail entities each carry their image dot AND a re-minted dot)",
			recDots, liveDots, recDots-liveDots, post)
	}
	if recLamport != finalLamport {
		t.Errorf("CLOCK OVERSHOOT: recovered LamportHigh %d != live %d (+%d — Join(image) jumped the clock to the leaked max dot, then the re-mint ran ABOVE it)",
			recLamport, finalLamport, recLamport-finalLamport)
	}
	if recRoot != liveRoot {
		t.Errorf("ROOT DIVERGENCE (the crash-leg failure): recovered root != live root\n live=%x\n got =%x\n — the recovered node is PERMANENTLY divergent from every peer that kept the live root",
			liveRoot, recRoot)
	}
}

// TestRecovery_QuiescentCheckpoint_RootMatches is the GREEN control — the SAME
// bounded-recovery path with the checkpoint taken at QUIESCENCE (no tail leaks
// into the image, because AppendCheckpoint runs atomically after all pre
// mutations commit). It MUST pass: it proves the harness is sound and the defect
// is SPECIFICALLY the non-quiescent leak, not bounded recovery in general. This
// is the quiescent path (checkpoint after quiescence → crash leg PASSED).
func TestRecovery_QuiescentCheckpoint_RootMatches(t *testing.T) {
	const pre, post = 100, 50
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "quiescent.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false) // the bridge's AppendCheckpoint writes the image (mt=nil: skip the Arrow index)

	for i := 0; i < pre; i++ {
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	// QUIESCENT checkpoint: anchor + snapshot are atomic (no concurrent commit in
	// the T1/T2 window — single-threaded, nothing in flight).
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	for i := pre; i < pre+post; i++ { // the post-checkpoint tail, replayed + re-minted
		if _, err := live.PutLocal(stagedEntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal post %d: %v", i, err)
		}
	}
	liveRoot := live.Engine().State().MerkleRoot()
	finalLamport := live.Engine().LamportCounter()
	liveDots := countDots(t, live.Engine())

	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	engine, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded || witness.ReplayedRecords != post {
		t.Fatalf("witness = %+v, want Bounded=true ReplayedRecords=%d", witness, post)
	}
	if got := countDots(t, engine); got != liveDots {
		t.Fatalf("quiescent control: recovered dots %d != live %d — bounded recovery is broken EVEN at quiescence (a WORSE bug than the non-quiescent leak)", got, liveDots)
	}
	if got := engine.LamportCounter(); got != finalLamport {
		t.Fatalf("quiescent control: recovered Lamport %d != live %d", got, finalLamport)
	}
	if got := engine.State().MerkleRoot(); got != liveRoot {
		t.Fatalf("quiescent control: recovered root != live root\n live=%x\n got =%x", liveRoot, got)
	}
}
