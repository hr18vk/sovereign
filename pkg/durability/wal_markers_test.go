// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//wal_markers_test.go — the MARKER guards (ADR-0045): T5, T9,
// T13. These reference the NEW witness fields (ExactWALFallback,
// LocalPhantomsRejected, CheckpointSeq) and the new restoreEntry behavior, so
// they cannot compile against HEAD — their RED artifacts are BUG-INJECTS: a
// one-line neutralization of the mechanism under test, reverted immediately
// after the RED is captured. Each guard's doc comment names the exact inject.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// ---------------------------------------------------------------------------
// T5 — unlogged snapshot phantom: image DISCARDED, fallback marker observable
// ---------------------------------------------------------------------------

// TestUnloggedSnapshotPhantomDiscardsImage guards the unlogged-snapshot phantom
// discard. A local dot in the image with NO durable WAL identity means the image was
// taken from a state the log cannot justify (torn write, compromised store).
// The ruled response: discard the IMAGE (not just the entry), fall back to
// exact-WAL full replay, and leave the marker observable.
//
// The phantom is injected INTO THE STORED IMAGE (not the live engine), so the
// WAL, the checkpoint anchor, and the live root are all clean — the ONLY
// suspect artifact is the image. Recovery must then succeed from the WAL alone
// and the witness must say why.
//
// A post-checkpoint TAIL put is deliberate: it makes the checkpoint non-final,
// which disarms the root-equality anchor — so is the SOLE guard between a
// compromised image and silent corruption. (Without the tail, neutralizing
// still fails recovery via ErrRecoveryRootMismatch and the guard would be
// testing the anchor, not the phantom gate.)
//
// RED (bug-inject): force the check inert (`phantoms > 0` → `false` at
// recovery.go:~237) → the phantom image is USED: both markers stay zero, the
// recovered dot count absorbs the phantom (5 vs live 4), the clock jumps to
// the phantom's 777, and the root diverges — recovery SUCCEEDS on corrupt
// state. Four assertions fire.
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
	// The non-final-making tail: one durable mutation ABOVE the checkpoint.
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

	// Inject the phantom: a LOCAL dot (counter 777) with no WAL identity, added
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

	// THE MARKERS (the guard's point — not the absence of a crash).
	if !witness.ExactWALFallback {
		t.Errorf("MARKER: ExactWALFallback=false — the phantom image was used SILENTLY (R5 violated)")
	}
	if witness.LocalPhantomsRejected != 1 {
		t.Errorf("MARKER: LocalPhantomsRejected=%d, want 1", witness.LocalPhantomsRejected)
	}
	if witness.Bounded {
		t.Errorf("MARKER: Bounded=true after a phantom discard — the witness claims a bounded recovery that did not happen")
	}
	// THE STATE: rebuilt from the WAL alone — the phantom is gone, the durable
	// mutations (3 pre-checkpoint + 1 tail) are all present.
	if got := countDots(t, rec); got != 4 {
		t.Errorf("DOT COUNT: recovered %d != 4 — the phantom was absorbed or durable state was lost", got)
	}
	if witness.ReplayedRecords != 4 {
		t.Errorf("WITNESS: ReplayedRecords=%d, want 4 (full exact-WAL replay of every durable mutation)", witness.ReplayedRecords)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("ROOT: recovered %x != live %x", got, liveRoot)
	}
	if got := rec.LamportCounter(); got != liveClock {
		t.Errorf("CLOCK: recovered %d != live %d — the phantom's counter 777 leaked into the clock", got, liveClock)
	}
}

// ---------------------------------------------------------------------------
// T9 — sequence-cut partition; ambiguity errs toward replaying MORE
// ---------------------------------------------------------------------------

// TestSequenceCutPartition guards the sequence-cut partition. The tail cut is the
// on-disk RECORD SEQUENCE, never a scalar counter. This guard pins the
// partition byte-exactly:
//
// - the witness's CheckpointSeq equals the checkpoint record's RAW on-disk
// seq (parsed from the bytes — ReplayWAL is the code under test, so the
// check is the file itself);
// - exactly the post-cut records are replayed (ReplayedRecords == 3);
// - every pre-cut dot is present via the image, every post-cut dot via the
// exact-dot replay, and the recovered root equals the live root;
// - C1 idempotency: replaying the below-cut records ANYWAY (the full path on
// the same WAL) lands on the SAME root — the cut is a conservative
// optimization, not a correctness dependency.
//
// RED (bug-inject): make the cut swallow the tail (skip every record when
// useSnapshot) → the recovered state has only the image's {2,3,4} → the
// dot-count and root assertions fire. Mirror inject (skip the image Join)
// leaves only {5,6,7} — same assertions fire from the other side.
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

	// The raw-byte check: 6 mutations + 1 checkpoint, checkpoint at index 3.
	seqs := readWALRecordSeqs(t, walPath)
	if len(seqs) != 7 {
		t.Fatalf("raw WAL holds %d records, want 7 (6 mutations + 1 checkpoint)", len(seqs))
	}
	ckptSeq := seqs[3]

	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false — the bounded path did not engage")
	}
	if witness.CheckpointSeq != ckptSeq {
		t.Errorf("CUT: witness.CheckpointSeq=%d != the checkpoint record's on-disk seq %d", witness.CheckpointSeq, ckptSeq)
	}
	if witness.ReplayedRecords != 3 {
		t.Errorf("CUT: ReplayedRecords=%d != 3 (exactly the post-cut records)", witness.ReplayedRecords)
	}
	if got := countDots(t, rec); got != 6 {
		t.Errorf("DOT COUNT: recovered %d != 6", got)
	}
	for i := 0; i < 6; i++ {
		ents := collectEntries(t, rec)[utf8EntityID(i)]
		if len(ents) != 1 || ents[0].DotNodeID != nodeID || ents[0].DotCounter != uint64(i+2) {
			t.Errorf("entity %d: dots %v, want exactly {(self,%d)}", i, ents, i+2)
		}
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("ROOT: recovered %x != live %x", got, liveRoot)
	}
	if got := rec.LamportCounter(); got != liveClock {
		t.Errorf("CLOCK: recovered %d != live %d", got, liveClock)
	}

	// C1 IDEMPOTENCY: the full path replays the below-cut records too — and
	// MUST land on the same root (exact-dot restore makes re-application a
	// no-op). If the cut were load-bearing for CORRECTNESS (not just cost),
	// these roots would differ.
	full, fullWitness := recoverFull(t, walPath)
	if got := full.State().MerkleRoot(); got != liveRoot {
		t.Errorf("C1: full-replay root %x != live %x — re-applying below-cut records changed the state", got, liveRoot)
	}
	if fullWitness.ReplayedRecords != 6 {
		t.Errorf("C1: full path ReplayedRecords=%d, want 6 (replayed EVERYTHING — and still converged)", fullWitness.ReplayedRecords)
	}
}

// TestAmbiguousCutReplaysMore is the second half of T9: when the image
// cannot be bound to the log (here: deleted from the store), the cut is
// meaningless and recovery MUST err toward replaying MORE — the whole log —
// with the fallback marker set. Replaying more is always safe (C1); replaying
// less loses data.
//
// RED (bug-inject): suppress the marker in the missing-image branch
// (`exactWALFallback = true` removed at recovery.go:~187) → recovery still
// succeeds from the full log but the witness CLAIMS a bounded recovery — the
// marker assertions fire.
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

	// The ambiguous case: the image the checkpoint points at is GONE.
	imgPath := filepath.Join(lfs.Root(), "ckpt", strconv.FormatUint(ckptLamport, 10))
	if err := os.Remove(imgPath); err != nil {
		t.Fatalf("remove image %s: %v", imgPath, err)
	}

	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.ExactWALFallback {
		t.Errorf("MARKER: ExactWALFallback=false on a missing image — the fallback was SILENT (R5 violated)")
	}
	if witness.Bounded {
		t.Errorf("MARKER: Bounded=true with no image — the witness claims a bounded recovery that did not happen")
	}
	if witness.ReplayedRecords != 6 {
		t.Errorf("ERR-DIRECTION: ReplayedRecords=%d, want 6 — an ambiguous cut must replay MORE (the whole log), never less", witness.ReplayedRecords)
	}
	if got := countDots(t, rec); got != 6 {
		t.Errorf("DOT COUNT: recovered %d != 6", got)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("ROOT: recovered %x != live %x", got, liveRoot)
	}
}

// ---------------------------------------------------------------------------
// T13 — origin classification survives recovery (the B.15 guard)
// ---------------------------------------------------------------------------

// TestOriginClassificationSurvivesRecovery guards origin classification across recovery.
// shipDelta's SELF predicate (pkg/mesh/gossip.go:1766) is
// `entry.OriginNodeID == nodeID`: SELF entries are served from the
// payloadCache, FOREIGN ones from the relayCache. The WAL's 80-byte entry
// carries OriginNodeID == ZERO in production (the-BLOCKER: bridge.go builds
// the WALEntry from the caller's pre-insert struct), so restoreEntry MUST
// synthesize the origin from the dot (every WAL mutation is local-origin).
// If it ever passed the WAL's zero origin through, every tail-restored entry
// would classify FOREIGN — the relaunched node would miss its own pre-crash
// payloads on every sweep (run-#11's B.15).
//
// Both directions are asserted: tail-restored LOCAL dots classify SELF, and
// image-restored FOREIGN dots classify FOREIGN (recovery must not re-origin
// what it did not mint).
//
// RED (bug-inject): restoreEntry with `OriginNodeID: [16]byte{}` (the
// pass-the-zero-through regression) → both tail-restored local entries
// misclassify FOREIGN and the SELF assertion fires naming them.
func TestOriginClassificationSurvivesRecovery(t *testing.T) {
	nodeID := testNodeID()
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t13.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	// 3 local puts BELOW the checkpoint (restored from the image).
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
	// 2 local puts ABOVE the checkpoint (restored from the WAL tail via
	// restoreEntry — the code path whose origin synthesis this guard pins).
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

	// SELF direction: every local-origin entry (image-restored AND
	// tail-restored) must satisfy shipDelta's SELF predicate.
	for i := 0; i < 5; i++ {
		id := utf8EntityID(i)
		ents := entries[id]
		if len(ents) != 1 {
			t.Fatalf("local entity %s carries %d dots, want 1", id, len(ents))
		}
		if ents[0].OriginNodeID != nodeID {
			t.Errorf("CLASSIFICATION: local entry %s has OriginNodeID=%x — shipDelta (gossip.go:1766) classifies it FOREIGN and it will never be served from the payloadCache (B.15)", id, ents[0].OriginNodeID)
		}
	}
	// FOREIGN direction: the image-restored foreign dots must NOT be re-origined.
	for i := 0; i < 2; i++ {
		id := utf8EntityID(5000 + i)
		ents := entries[id]
		if len(ents) != 1 {
			t.Fatalf("foreign entity %s carries %d dots, want 1", id, len(ents))
		}
		if ents[0].OriginNodeID != foreignNodeID() {
			t.Errorf("CLASSIFICATION: foreign entry %s re-origined to %x (want %x) — recovery must not claim what it did not mint", id, ents[0].OriginNodeID, foreignNodeID())
		}
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("ROOT: recovered %x != live %x", got, liveRoot)
	}
}
