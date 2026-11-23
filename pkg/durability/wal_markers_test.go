// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Tests for recovery witness fields and entry restoration (ADR-0045 §5).
// They cover phantom local dots, sequence-based tail selection, fallback when
// an image is unavailable, and preservation of local and foreign origins.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestUnloggedSnapshotPhantomDiscardsImage verifies rejection of a local dot in
// an image when that dot has no durable WAL identity. Such an image describes
// state the log cannot justify, so recovery discards the entire image and
// replays the WAL.
//
// Only the stored image is modified; the WAL and live root remain valid. The
// post-checkpoint mutation makes the checkpoint non-final, preventing the root
// comparison from masking a failure of the phantom check. If that check were
// disabled, the phantom would increase the dot count, advance the clock to 777,
// and change the recovered root.
func TestUnloggedSnapshotPhantomDiscardsImage(t *testing.T) {
	nodeID := testNodeID()
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t5.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false) // image only, no Arrow index

	for i := 0; i < 3; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	ckptLamport := live.Engine().LamportCounter() // quiescent: watermark == clock
	// The non-final-making tail: one durable mutation above the checkpoint.
	if _, err := live.PutLocal(utf8EntityID(3), stagedPayload(3), stagedEntry(3)); err != nil {
		t.Fatalf("PutLocal tail: %v", err)
	}
	liveRoot := live.Engine().State().MerkleRoot()
	liveClock := live.Engine().LamportCounter()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// Inject the phantom: a local dot (counter 777) with no WAL identity, added
	// to the stored image after the fact — the compromised-store shape.
	img, err := lfs.LoadSnapshotImage(context.Background(), ckptLamport)
	if err != nil {
		t.Fatalf("LoadSnapshotImage: %v", err)
	}
	img.Records = append(img.Records, exactRec(utf8EntityID(99), nodeID, 777, stagedDigest(99)))
	if err := lfs.WriteSnapshotImage(context.Background(), img); err != nil {
		t.Fatalf("WriteSnapshotImage (phantom): %v", err)
	}

	rec, witness := recoverBounded(t, walPath, lfs)

	// The witness must disclose both the rejected phantom and the fallback.
	if !witness.ExactWALFallback {
		t.Errorf("ExactWALFallback is false after rejecting a phantom image")
	}
	if witness.LocalPhantomsRejected != 1 {
		t.Errorf("LocalPhantomsRejected = %d, want 1", witness.LocalPhantomsRejected)
	}
	if witness.Bounded {
		t.Errorf("Bounded is true after the phantom image was discarded")
	}
	// The three pre-checkpoint mutations and the tail mutation must remain;
	// the injected counter 777 must not appear in either state or clock.
	if got := countDots(t, rec); got != 4 {
		t.Errorf("recovered dot count = %d, want 4", got)
	}
	if witness.ReplayedRecords != 4 {
		t.Errorf("ReplayedRecords = %d, want 4 from the full WAL", witness.ReplayedRecords)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x differs from live root %x", got, liveRoot)
	}
	if got := rec.LamportCounter(); got != liveClock {
		t.Errorf("recovered clock = %d, want live clock %d", got, liveClock)
	}
}

// TestSequenceCutPartition verifies that the replay tail is selected by WAL
// record sequence rather than a scalar counter. CheckpointSeq is read from the
// file independently of ReplayWAL. The three records after the cut must be
// replayed, and the image and tail together must reproduce every dot and the
// live root.
//
// Full replay also processes the records below the cut. It must reach the same
// root, showing that exact-dot restoration is idempotent and that the cut
// reduces work without changing state.
func TestSequenceCutPartition(t *testing.T) {
	nodeID := testNodeID()
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t9.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	for i := 0; i < 3; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	for i := 3; i < 6; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal post %d: %v", i, err)
		}
	}
	liveRoot := live.Engine().State().MerkleRoot()
	liveClock := live.Engine().LamportCounter()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// Read the sequence numbers directly from six mutations and one checkpoint.
	seqs := readWALRecordSeqs(t, walPath)
	if len(seqs) != 7 {
		t.Fatalf("raw WAL holds %d records, want 7 (6 mutations + 1 checkpoint)", len(seqs))
	}
	ckptSeq := seqs[3]

	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded {
		t.Fatalf("bounded recovery was not used")
	}
	if witness.CheckpointSeq != ckptSeq {
		t.Errorf("CheckpointSeq = %d, want on-disk checkpoint sequence %d", witness.CheckpointSeq, ckptSeq)
	}
	if witness.ReplayedRecords != 3 {
		t.Errorf("ReplayedRecords = %d, want the 3 post-cut records", witness.ReplayedRecords)
	}
	if got := countDots(t, rec); got != 6 {
		t.Errorf("recovered dot count = %d, want 6", got)
	}
	for i := 0; i < 6; i++ {
		ents := collectEntries(t, rec)[utf8EntityID(i)]
		if len(ents) != 1 || ents[0].DotNodeID != nodeID || ents[0].DotCounter != uint64(i+2) {
			t.Errorf("entity %d: dots %v, want exactly {(self,%d)}", i, ents, i+2)
		}
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x differs from live root %x", got, liveRoot)
	}
	if got := rec.LamportCounter(); got != liveClock {
		t.Errorf("recovered clock = %d, want live clock %d", got, liveClock)
	}

	// Full replay re-applies the records below the cut. Exact-dot restoration
	// makes that idempotent, so its root must equal the bounded and live roots.
	full, fullWitness := recoverFull(t, walPath)
	if got := full.State().MerkleRoot(); got != liveRoot {
		t.Errorf("full-replay root %x differs from live root %x", got, liveRoot)
	}
	if fullWitness.ReplayedRecords != 6 {
		t.Errorf("full ReplayedRecords = %d, want all 6 mutations", fullWitness.ReplayedRecords)
	}
}

// TestAmbiguousCutReplaysMore removes the image named by a checkpoint. Without
// a bound image, recovery must replay the whole WAL and set ExactWALFallback.
// Replaying already absorbed records is idempotent; omitting durable records
// would lose state.
func TestAmbiguousCutReplaysMore(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t9b.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	for i := 0; i < 3; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	ckptLamport := live.Engine().LamportCounter()
	for i := 3; i < 6; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal post %d: %v", i, err)
		}
	}
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// The ambiguous case: the image the checkpoint points at is gone.
	imgPath := filepath.Join(lfs.Root(), "ckpt", strconv.FormatUint(ckptLamport, 10))
	if err := os.Remove(imgPath); err != nil {
		t.Fatalf("remove image %s: %v", imgPath, err)
	}

	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.ExactWALFallback {
		t.Errorf("ExactWALFallback is false with the checkpoint image missing")
	}
	if witness.Bounded {
		t.Errorf("Bounded is true without a snapshot image")
	}
	if witness.ReplayedRecords != 6 {
		t.Errorf("ReplayedRecords = %d, want all 6 mutations after an ambiguous cut", witness.ReplayedRecords)
	}
	if got := countDots(t, rec); got != 6 {
		t.Errorf("recovered dot count = %d, want 6", got)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x differs from live root %x", got, liveRoot)
	}
}

// TestOriginClassificationSurvivesRecovery checks the origin used by shipDelta
// to select payloadCache for local entries and relayCache for foreign entries.
// Legacy WAL records have no origin field, so restoreEntry synthesizes the local
// origin from their dots. Without that step, local entries recovered from the
// tail would be treated as foreign and their cached payloads would be missed.
//
// Image-restored foreign entries must retain their original node ID. The test
// checks both directions as well as the recovered root.
func TestOriginClassificationSurvivesRecovery(t *testing.T) {
	nodeID := testNodeID()
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t13.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	// 3 local puts below the checkpoint (restored from the image).
	for i := 0; i < 3; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	// 2 foreign dots (image-only, below the checkpoint): utf8EntityID(5000..5001).
	foreignJoinInto(t, live, 100, 2)
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	// 2 local puts above the checkpoint (restored from the WAL tail via
	// restoreEntry — the code path whose origin synthesis this test pins).
	for i := 3; i < 5; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal post %d: %v", i, err)
		}
	}
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false — the bounded path did not engage")
	}
	entries := collectEntries(t, rec)

	// Self direction: every local-origin entry (image-restored and
	// tail-restored) must satisfy shipDelta's self predicate.
	for i := 0; i < 5; i++ {
		id := utf8EntityID(i)
		ents := entries[id]
		if len(ents) != 1 {
			t.Fatalf("local entity %s carries %d dots, want 1", id, len(ents))
		}
		if ents[0].OriginNodeID != nodeID {
			t.Errorf("local entry %s has OriginNodeID %x; shipDelta will select relayCache instead of payloadCache", id, ents[0].OriginNodeID)
		}
	}
	// Foreign direction: the image-restored foreign dots must not be re-origined.
	for i := 0; i < 2; i++ {
		id := utf8EntityID(5000 + i)
		ents := entries[id]
		if len(ents) != 1 {
			t.Fatalf("foreign entity %s carries %d dots, want 1", id, len(ents))
		}
		if ents[0].OriginNodeID != foreignNodeID() {
			t.Errorf("foreign entry %s has OriginNodeID %x, want %x", id, ents[0].OriginNodeID, foreignNodeID())
		}
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x differs from live root %x", got, liveRoot)
	}
}
