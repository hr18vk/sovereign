// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// A checkpoint whose watermark and image come from separate walks can include
// dots minted after the watermark. On the older recovery path, joining that
// image advanced the clock to the greatest included dot; replay then inserted
// the same post-watermark mutations at newly minted counters. The dot union
// could not deduplicate them, leaving two dots per affected entity and a
// recovered Merkle root different from every peer that retained the live state.
//
// One measured crash run recovered from ckpt/9201 and replayed 808 records:
// 800 keys from eight timed-out batches and eight clock advances. The recovered
// root began 2e135b3a rather than d1406abf, and 10,000 injected keys produced
// 10,800 dots. The node remained split from the other 99 peers throughout a
// 240-second poll. A checkpoint taken after quiescence did not have this
// interleaving and recovered correctly.
//
// AppendCheckpoint now captures root, watermark, and image in one pinned walk,
// and replay restores recorded dots. The first test below forces the old
// interleaving with a separate WAL anchor, tail writes, and image write; the
// second is the quiescent control. The forced sequence is deterministic rather
// than dependent on goroutine scheduling.

import (
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// countDots sums the entries held for every entity. Because an add-wins entity
// holds one dot per concurrent write, duplicate minting increases this count
// while lost mutations decrease it.
func countDots(t *testing.T, engine *eng.DeltaCRDTEngine) int {
	t.Helper()
	total := 0
	engine.State().ForEach(func(_ string, entries []eng.CRDTEntry) bool {
		total += len(entries)
		return true
	})
	return total
}

// TestRecovery_NonQuiescentCheckpoint_DoubleMint forces an image to contain
// post-watermark dots, then recovers through the bounded path. The recovered
// root, dot count, and Lamport high-water must equal the live engine's values;
// separate assertions distinguish duplicate dots, clock drift, and root drift.
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

	// Force the split-walk interleaving: write the anchor at wm, commit the tail,
	// then capture an image that includes the tail but still carries wm.
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
	// The later image contains all pre+post entities under the earlier watermark.
	if err := writeImageForTest(live.Engine(), wm, lfs); err != nil {
		t.Fatalf("SnapshotToLSM: %v", err)
	}

	liveRoot := live.Engine().State().MerkleRoot()
	finalLamport := live.Engine().LamportCounter()
	liveDots := countDots(t, live.Engine())
	if liveDots != pre+post {
		t.Fatalf("setup: live dot count %d, want %d (one dot per entity)", liveDots, pre+post)
	}

	// Close the live resources; every mutation and the anchor are already fsynced.
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// This non-final checkpoint does not arm recovery's root equality check, so
	// the test compares all three observations explicitly.
	engine, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false; the test did not exercise bounded recovery")
	}
	if witness.ReplayedRecords != post {
		t.Fatalf("witness.ReplayedRecords=%d, want %d (the post-watermark tail)", witness.ReplayedRecords, post)
	}

	recRoot := engine.State().MerkleRoot()
	recLamport := engine.LamportCounter()
	recDots := countDots(t, engine)

	// Keep the assertions separate so a failure identifies duplicate minting,
	// clock drift, or root divergence directly.
	if recDots != liveDots {
		t.Errorf("recovered dot count %d != live %d (%+d dots across %d post-watermark entities)",
			recDots, liveDots, recDots-liveDots, post)
	}
	if recLamport != finalLamport {
		t.Errorf("recovered Lamport high-water %d != live %d (%+d after joining the image and replaying the tail)",
			recLamport, finalLamport, recLamport-finalLamport)
	}
	if recRoot != liveRoot {
		t.Errorf("recovered root differs from live root; peers retaining live state would not converge\n  live=%x\n  got =%x",
			liveRoot, recRoot)
	}
}

// TestRecovery_QuiescentCheckpoint_RootMatches is the control with no writes in
// flight during AppendCheckpoint. It checks that bounded recovery restores the
// same root, dot count, and Lamport clock when the image has no post-watermark
// entries.
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
	// With no writes in flight, the anchor and image describe the same state.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	for i := pre; i < pre+post; i++ { // the post-checkpoint tail, restored from recorded dots
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
		t.Fatalf("quiescent control: recovered dots %d != live %d; bounded recovery changed state without concurrent writes", got, liveDots)
	}
	if got := engine.LamportCounter(); got != finalLamport {
		t.Fatalf("quiescent control: recovered Lamport %d != live %d", got, finalLamport)
	}
	if got := engine.State().MerkleRoot(); got != liveRoot {
		t.Fatalf("quiescent control: recovered root != live root\n  live=%x\n  got =%x", liveRoot, got)
	}
}
