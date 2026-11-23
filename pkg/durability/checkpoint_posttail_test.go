// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// These tests cover the exact-dot checkpoint path (ADR-0045): image watermarks
// under concurrent writes, holes below the recovery cut, arena allocation, EBR
// pinning, and anchors that contain mutations absent from the WAL.
//
// CaptureShardsPinned produces the root, watermark, and image in one EBR-pinned
// walk. It avoids both the arena growth caused by rebuilding State() and the
// skew caused by reading LamportCounter separately from the image. Each test
// names a fault injection that makes its assertion fail if the guarded
// mechanism is removed.

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ckptWatermarks parses the raw WAL and returns every checkpoint's LamportHigh
// in file order. Both checkpoint layouts store MerkleRoot(32) followed by
// LamportHigh(8).
func ckptWatermarks(t *testing.T, walPath string) []uint64 {
	t.Helper()
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL %s: %v", walPath, err)
	}
	var out []uint64
	for off := 8; off < len(data); {
		// Records are now CRC-framed (0x06); walRecordAtForTest verifies the CRC
		// and unwraps to the inner checkpoint payload, so this scanner matches
		// the inner 0x02/0x05 exactly as before, without weakening it (a bad
		// CRC causes Fatalf inside the helper).
		innerType, innerPayload, recLen, complete := walRecordAtForTest(t, data, off)
		if !complete {
			break // torn tail — end of clean records (a crash boundary, not a record)
		}
		// Both checkpoint record types (legacy 0x02, 40-byte payload; horizon
		// 0x05, 48-byte) carry LamportHigh at the same offset.
		if innerType == byte(WALRecCheckpoint) || innerType == byte(WALRecCheckpointV2) {
			// 40 = legacy 0x02 (root+watermark); 48 = 0x05 (+CutSeq);
			// 56 = 0x05 +ClockHigh (no image); 88 = 0x05 +ClockHigh +StateFingerprint
			// (the image-backed form).
			if len(innerPayload) != 40 && len(innerPayload) != 48 && len(innerPayload) != 56 && len(innerPayload) != 88 {
				t.Fatalf("checkpoint record with inner payloadLen=%d, want 40, 48, 56, or 88", len(innerPayload))
			}
			out = append(out, binary.BigEndian.Uint64(innerPayload[32:40]))
		}
		off += recLen
	}
	return out
}

// ---------------------------------------------------------------------------
// Post-watermark local dots
// ---------------------------------------------------------------------------

// TestZeroPostWatermarkDotsInImage checks that no local entry in a checkpoint
// image has DotCounter above image.LamportHigh. Both values come from the same
// walk, whose maximum local dot bounds every entry it captured. Reading the
// watermark before the walk instead would admit later dots; the older path
// leaked 184–3,193 such dots in each of 10 measured images.
//
// The first watermark must be below the final clock, proving that checkpoints
// overlapped writer activity rather than running only after quiescence.
func TestZeroPostWatermarkDotsInImage(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "post-watermark.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	const writers = 6
	const perWriter = 300
	var wg sync.WaitGroup
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				id := g*perWriter + i
				if _, err := live.PutLocal(utf8EntityID(id), stagedPayload(id), stagedEntry(id)); err != nil {
					t.Errorf("PutLocal g%d i%d: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	// Fire checkpoints while the writers run — the interleave is the test.
	for c := 0; c < 12; c++ {
		if err := live.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint %d: %v", c, err)
		}
	}
	wg.Wait()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("final AppendCheckpoint: %v", err)
	}

	wms := ckptWatermarks(t, walPath)
	if len(wms) < 2 {
		t.Fatalf("expected >=2 checkpoint records, got %d", len(wms))
	}
	finalClock := live.Engine().LamportCounter()
	if wms[0] >= finalClock {
		t.Fatalf("first checkpoint watermark %d not below final clock %d — the checkpoints did not interleave with the writes", wms[0], finalClock)
	}

	seen := make(map[uint64]bool)
	for _, wm := range wms {
		if seen[wm] {
			continue // same key re-written by a later checkpoint at the same wm
		}
		seen[wm] = true
		img, err := lfs.LoadSnapshotImage(context.Background(), wm)
		if err != nil {
			t.Fatalf("LoadSnapshotImage ckpt/%d: %v", wm, err)
		}
		leaked := 0
		for _, rec := range img.Records {
			if rec.Entry.DotNodeID == testNodeID() && rec.Entry.DotCounter > wm {
				leaked++
			}
		}
		if leaked != 0 {
			t.Errorf("skew: image ckpt/%d carries %d local dot(s) above its watermark", wm, leaked)
		}
	}
	if img := wms[len(wms)-1]; img != finalClock {
		t.Errorf("final checkpoint watermark %d != final clock %d (the quiesced final walk must see every mint)", img, finalClock)
	}
}

// ---------------------------------------------------------------------------
// Holes below the checkpoint cut
// ---------------------------------------------------------------------------

// TestNoHoleBelowWatermark checks that every local mutation below a
// checkpoint's CutSeq is present in its image. Capturing NextSeq before the walk
// closes the append/walk window: a completed append implies that InsertLocal had
// already run when the walk began. The older record-sequence cut could omit a
// durable dot, as in counter=94 at seq=96 with watermark=95 and checkpoint
// seq=104. Legacy 0x02 logs instead use a recovery repair pass, reported through
// witness.HolesRepaired.
//
// The test compares raw WAL records with the stored images while writers are
// active, then requires bounded recovery to reproduce the live root without a
// fallback or repairs on a V2 log. Dropping entities from the capture callback
// provides a negative control for both observations.
func TestNoHoleBelowWatermark(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "below-watermark.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := g*200 + i
				if _, err := live.PutLocal(utf8EntityID(id), stagedPayload(id), stagedEntry(id)); err != nil {
					t.Errorf("PutLocal g%d i%d: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	for c := 0; c < 8; c++ {
		if err := live.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint %d: %v", c, err)
		}
	}
	wg.Wait()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("final AppendCheckpoint: %v", err)
	}

	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if !rep.HasCheckpoint {
		t.Fatalf("no checkpoint in WAL")
	}
	type dot struct {
		nodeID  [16]byte
		counter uint64
	}
	// The WAL's local mutation dots, with the seq each landed at (from
	// rep.Ordered — WALRecord carries Seq but no checkpoint payload).
	var muts []struct {
		d dot
		s uint64
	}
	for _, rec := range rep.Ordered {
		if (rec.Type == WALRecMutation || rec.Type == WALRecMutationV2) && rec.Mutation.NodeID == testNodeID() {
			muts = append(muts, struct {
				d dot
				s uint64
			}{dot{rec.Mutation.NodeID, rec.Mutation.Counter}, rec.Seq})
		}
	}
	// Every checkpoint (seq, watermark, cut) from the raw bytes — not just the
	// final one: the final checkpoint is quiesced and trivially hole-free; the
	// mid-flight ones are the test's target. The cut is the V2 record's
	// CutSeq horizon (0x05) or, for a legacy 0x02 record, its own seq + 1.
	// Disclosed limit: two checkpoints that observe the same watermark share
	// one image key (the later walk's image overwrites), so for a shared
	// watermark only the surviving (later, strictly larger) image is checkable
	// — an add-wins set grows monotonically, so the surviving image satisfies
	// every "below the cut ⇒ present" obligation the overwritten one did.
	type ckptInfo struct {
		seq, wm, cut uint64
	}
	var ckpts []ckptInfo
	raw, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	for off := 8; off < len(raw); {
		// Records are now 0x06 CRC-framed; walRecordAtForTest
		// verifies the CRC and unwraps to the inner checkpoint payload. The seq
		// is the outer header's (identical framed or not); the watermark + CutSeq
		// come from the inner payload. A bad CRC causes Fatalf inside the helper.
		innerType, innerPayload, recLen, complete := walRecordAtForTest(t, raw, off)
		if !complete {
			break // torn tail — end of clean records (a crash boundary, not a record)
		}
		switch WALRecordType(innerType) {
		case WALRecCheckpoint:
			seq := binary.BigEndian.Uint64(raw[off : off+8])
			ckpts = append(ckpts, ckptInfo{seq, binary.BigEndian.Uint64(innerPayload[32:40]), seq + 1})
		case WALRecCheckpointV2:
			ckpts = append(ckpts, ckptInfo{binary.BigEndian.Uint64(raw[off : off+8]),
				binary.BigEndian.Uint64(innerPayload[32:40]),
				binary.BigEndian.Uint64(innerPayload[40:48])})
		}
		off += recLen
	}
	if len(ckpts) < 2 {
		t.Fatalf("expected >=2 checkpoints, got %d", len(ckpts))
	}

	// The source invariant, by construction on the V2 horizon cut:
	// every local mutation whose WAL record sits below a checkpoint's cut is
	// present in that checkpoint's image. Its append completed before the
	// walk began ⇒ its insert landed before the walk ⇒ the walk saw it.
	totalChecked, totalHoles := 0, 0
	seenWM := make(map[uint64]bool)
	for _, c := range ckpts {
		if seenWM[c.wm] {
			continue
		}
		seenWM[c.wm] = true
		img, err := lfs.LoadSnapshotImage(context.Background(), c.wm)
		if err != nil {
			t.Fatalf("LoadSnapshotImage ckpt/%d: %v", c.wm, err)
		}
		inImage := make(map[dot]bool, len(img.Records))
		for _, rec := range img.Records {
			inImage[dot{rec.Entry.DotNodeID, rec.Entry.DotCounter}] = true
		}
		for _, m := range muts {
			if m.s >= c.cut {
				continue // at or above the horizon: the tail covers it
			}
			totalChecked++
			if !inImage[m.d] {
				totalHoles++
				t.Errorf("hole: WAL local dot (counter=%d, seq=%d) sits below the cut (seq<%d) of checkpoint at watermark %d yet is absent from its image — bounded recovery would lose an ACKed write", m.d.counter, m.s, c.cut, c.wm)
			}
		}
	}
	if totalChecked == 0 {
		t.Fatalf("checked set is empty — the test inspected nothing")
	}
	t.Logf("below-cut source invariant: checkpoints=%d below-cut dots checked=%d holes=%d", len(ckpts), totalChecked, totalHoles)

	// The closure (the original claim was "or recovery restores it regardless"):
	// bounded recovery of the final quiesced checkpoint must reproduce the
	// live state byte-exactly, with zero repairs needed on a V2 log.
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}
	rec, witness := recoverBounded(t, walPath, lfs)
	if witness.ExactWALFallback {
		t.Errorf("unexpected fallback on a clean V2 log+image: %s", witness.FallbackReason)
	}
	if witness.HolesRepaired != 0 {
		t.Errorf("HolesRepaired=%d on a horizon-cut V2 log — the source invariant was violated at checkpoint time (the repair healed it, but the source invariant must hold)", witness.HolesRepaired)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x != live root %x — recovery did not restore the full state", got, liveRoot)
	}
}

// ---------------------------------------------------------------------------
// Checkpoint arena allocation
// ---------------------------------------------------------------------------

// TestCheckpointAllocatesZeroArena requires the arena high-water to remain
// unchanged across M checkpoints and match LastCheckpointArenaHighWater. The
// older path built State() twice per checkpoint; 11 checkpoints exhausted a
// 768 MiB arena with approximately 2,500 live entities. CaptureShardsPinned
// avoids those merged-view allocations.
//
// The 2,000-entity live set would move the high-water by megabytes if State()
// were reintroduced, providing a clear negative control.
func TestCheckpointAllocatesZeroArena(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "checkpoint-arena.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	for i := 0; i < 2000; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	hw0 := live.Engine().Arena().HighWater()
	const M = 12
	for c := 0; c < M; c++ {
		if err := live.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint %d: %v", c, err)
		}
	}
	hw1 := live.Engine().Arena().HighWater()
	if hw1 != hw0 {
		t.Errorf("arena grew across %d checkpoints: high-water %d → %d (+%d bytes) — the checkpoint path is building merged views again (arena growth defect)", M, hw0, hw1, hw1-hw0)
	}
	if got := live.LastCheckpointArenaHighWater(); got != hw0 {
		t.Errorf("witness: LastCheckpointArenaHighWater=%d, want the flat %d", got, hw0)
	}
}

// ---------------------------------------------------------------------------
// EBR pinning against concurrent State calls
// ---------------------------------------------------------------------------

// TestCheckpointWalkPinnedAgainstState runs State() readers and writers during
// 20 checkpoints over 3,000 entities. State() retires merged views and advances
// the EBR epoch while writers retire shard roots. AppendCheckpoint's pin keeps
// those roots from being reclaimed and reused during CaptureShardsPinned;
// without it, the walk could read reclaimed memory.
//
// The final quiesced checkpoint must round-trip through recovery with the live
// root. Removing Acquire/Enter/Release supplies the negative control under the
// race detector.
func TestCheckpointWalkPinnedAgainstState(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "checkpoint-pin.wal")
	// The payload fingerprint fold allocates on the heap, not in the engine
	// arena, but it extends the EBR pin. At 20,000 entries TestFoldCostMeasured
	// measured +3.754 ms, or +49.4%, for walk+capture+fold. During this test's
	// unpaced State() reader, retired merged views cannot be reclaimed while the
	// pin is held: the 20-checkpoint high-water measured 50.9 MB without the fold
	// and 64.4 MB with it. The 128 MiB arena provides headroom instead of the
	// shared 64 MiB default.
	//
	// This pressure comes from the test's deliberate State() loop. The fleet root
	// gauge uses MerkleRootFromShards over CaptureShardsPinned without building
	// State(), and Gossiper.LatestPayload has no callers. State() allocation on
	// the /v1/get read path is a separate issue; this sizing does not address it.
	live := newLiveBridgeArena(t, walPath, 0, 128*1024*1024)
	live.SetSnapshotter(lfs, false)

	for i := 0; i < 3000; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("seed PutLocal %d: %v", i, err)
		}
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		// State() retires merged views and advances epochs against the pinned
		// walk. Keep this reader rather than substituting MerkleRootFromShards,
		// which would remove the reclamation pressure this test exercises.
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = live.Engine().State().MerkleRoot()
			}
		}
	}()
	wg.Add(1)
	go func() { // a writer, so shard roots retire under the walk too
		defer wg.Done()
		for i := 3000; i < 3400; i++ {
			if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
				return
			}
		}
	}()
	for c := 0; c < 20; c++ {
		if err := live.AppendCheckpoint(); err != nil {
			t.Fatalf("AppendCheckpoint %d: %v", c, err)
		}
	}
	close(stop)
	wg.Wait()

	// Quiesce, anchor, and prove the checkpointed state round-trips byte-exact.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("final AppendCheckpoint: %v", err)
	}
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}
	rec, witness := recoverBounded(t, walPath, lfs)
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x != live root %x — the pinned walk captured a torn image", got, liveRoot)
	}
	if witness.ExactWALFallback {
		t.Errorf("unexpected fallback on a clean log+image: %s", witness.FallbackReason)
	}
}

// ---------------------------------------------------------------------------
// Phantom anchors during a batch
// ---------------------------------------------------------------------------

// TestMidBatchPhantomAnchorBootsClean simulates a checkpoint between a batch's
// InsertLocal calls and AppendMutations. Its image contains local dots absent
// from the durable log. Recovery must discard those phantom dots, report
// ExactWALFallback, and boot from exactly the acknowledged writes rather than
// returning ErrRecoveryRootMismatch for the incomplete anchor.
//
// Two local-identity dots are joined directly into the engine without WAL
// appends, constructing the same state deterministically. Removing the
// localPhantomsRejected condition from recovery's root guard supplies the
// negative control.
func TestMidBatchPhantomAnchorBootsClean(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "phantom-anchor.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	dots := make([]eng.CausalDot, 3)
	for i := 0; i < 3; i++ {
		d, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i))
		if err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
		dots[i] = d
	}
	// The "mid-batch" dots: live in the engine, never in the WAL — exactly the
	// InsertLocal→AppendMutations window. Local identity, high counters.
	phantoms := []SnapshotRecord{
		exactRec(utf8EntityID(900), testNodeID(), 900, stagedDigest(900)),
		exactRec(utf8EntityID(901), testNodeID(), 901, stagedDigest(901)),
	}
	live.Engine().Join(snapshotDelta(&SnapshotImage{Records: phantoms}))
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	rec, recWAL, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("boot refused on a non-corrupt log (phantom-anchor false data-loss verdict): %v", err)
	}
	t.Cleanup(func() { _ = recWAL.Close() })
	t.Cleanup(func() { _ = rec.Close() })
	if !witness.ExactWALFallback {
		t.Errorf("ExactWALFallback=false — a phantom-bearing image was used")
	}
	if witness.LocalPhantomsRejected != 2 {
		t.Errorf("LocalPhantomsRejected=%d, want 2", witness.LocalPhantomsRejected)
	}
	if !strings.Contains(witness.FallbackReason, "phantom") {
		t.Errorf("FallbackReason=%q, want it to name the phantom discard", witness.FallbackReason)
	}
	if got := countDots(t, rec); got != 3 {
		t.Errorf("recovered %d dots, want only the 3 acknowledged durable writes; the 2 phantoms must be discarded", got)
	}
	// The recovered state is exactly the three durable dots — the independent
	// reference is built from the PutLocal-returned dots, not the WAL parser.
	ref := make([]SnapshotRecord, 3)
	for i, d := range dots {
		ref[i] = exactRec(utf8EntityID(i), d.NodeID, d.Counter, stagedDigest(i))
	}
	if got, want := rec.State().MerkleRoot(), referenceRoot(t, testNodeID(), ref...); got != want {
		t.Errorf("recovered root %x != reference %x (the durable log's exact state)", got, want)
	}
}

// ---------------------------------------------------------------------------
// Legacy checkpoint with a hole below its cut
// ---------------------------------------------------------------------------

// TestLegacyHoleHealed constructs three durable dots and a legacy 0x02
// checkpoint whose root and image cover only the first two. Dot 3 is at seq 2,
// below the checkpoint's cut at 4. Bounded recovery must use the image, restore
// dot 3 from its WAL record, count one HolesRepaired repair, and reproduce the
// full three-dot root without ErrRecoveryRootMismatch.
//
// Removing holesRepaired == 0 from the root guard would compare the three-dot
// rebuild with the two-dot anchor and fail. Removing the repair pass would
// instead lose dot 3; both are useful negative controls.
func TestLegacyHoleHealed(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "legacy-hole.wal")
	live := newLiveBridge(t, walPath, 0)

	dots := make([]eng.CausalDot, 3)
	for i := 0; i < 3; i++ {
		d, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i))
		if err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
		dots[i] = d
	}
	wm := live.Engine().LamportCounter()
	// The legacy checkpoint anchors only the first two dots and has no CutSeq.
	twoDotRoot := referenceRoot(t, testNodeID(),
		exactRec(utf8EntityID(0), dots[0].NodeID, dots[0].Counter, stagedDigest(0)),
		exactRec(utf8EntityID(1), dots[1].NodeID, dots[1].Counter, stagedDigest(1)))
	if err := live.WAL().AppendCheckpoint(WALCheckpoint{MerkleRoot: twoDotRoot, LamportHigh: wm}); err != nil {
		t.Fatalf("legacy AppendCheckpoint: %v", err)
	}
	// The holed image: dots {1,2} only.
	imgEngine := engineWith(t, testNodeID(), 1,
		exactRec(utf8EntityID(0), dots[0].NodeID, dots[0].Counter, stagedDigest(0)),
		exactRec(utf8EntityID(1), dots[1].NodeID, dots[1].Counter, stagedDigest(1)))
	if err := writeImageForTest(imgEngine, wm, lfs); err != nil {
		t.Fatalf("writeImageForTest: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	rec, recWAL, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("boot refused on a legacy log with a hole (the repair pass must heal it): %v", err)
	}
	t.Cleanup(func() { _ = recWAL.Close() })
	t.Cleanup(func() { _ = rec.Close() })
	if witness.ExactWALFallback {
		t.Errorf("ExactWALFallback=true — the holed image is not torn, it must be used (the WAL record heals the hole)")
	}
	if witness.HolesRepaired != 1 {
		t.Errorf("HolesRepaired=%d, want exactly 1 (dot 3)", witness.HolesRepaired)
	}
	if got := countDots(t, rec); got != 3 {
		t.Errorf("recovered %d dots, want 3 (the holed dot restored)", got)
	}
	want := referenceRoot(t, testNodeID(),
		exactRec(utf8EntityID(0), dots[0].NodeID, dots[0].Counter, stagedDigest(0)),
		exactRec(utf8EntityID(1), dots[1].NodeID, dots[1].Counter, stagedDigest(1)),
		exactRec(utf8EntityID(2), dots[2].NodeID, dots[2].Counter, stagedDigest(2)))
	if got := rec.State().MerkleRoot(); got != want {
		t.Errorf("recovered root %x != the full 3-dot durable state %x", got, want)
	}
}

// TestFoldCostMeasured reports three measurements at 20,000 entries:
// CaptureShardsPinned alone, the walk plus record capture, and the walk plus
// capture plus fingerprinting. The third minus the second isolates the fold's
// per-checkpoint cost. Every arm must visit the same number of records; timings
// are logged without a performance threshold.
func TestFoldCostMeasured(t *testing.T) {
	const entries = 20_000
	eng.DataDir = t.TempDir()
	e, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, testArenaSize)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	defer func() { _ = e.Close() }()
	for i := 0; i < entries; i++ {
		e.InsertLocal(utf8EntityID(i), stagedEntry(i))
	}
	const reps = 5
	// Arm 1: walk only (the pre-fold checkpoint cost).
	var walkOnly time.Duration
	for r := 0; r < reps; r++ {
		start := time.Now()
		n := 0
		_, _ = e.CaptureShardsPinned(func(entityID string, ents []eng.CRDTEntry) bool {
			n += len(ents)
			return true
		})
		walkOnly += time.Since(start)
		if n != entries {
			t.Fatalf("walk covered %d entries, want %d", n, entries)
		}
	}
	// Arm 2: walk + record capture (the image build every checkpoint always did).
	var walkCapture time.Duration
	for r := 0; r < reps; r++ {
		start := time.Now()
		var recs []SnapshotRecord
		_, _ = e.CaptureShardsPinned(func(entityID string, ents []eng.CRDTEntry) bool {
			for i := range ents {
				recs = append(recs, SnapshotRecord{EntityID: entityID, Entry: ents[i]})
			}
			return true
		})
		walkCapture += time.Since(start)
		if len(recs) != entries {
			t.Fatalf("walk+capture covered %d records, want %d", len(recs), entries)
		}
	}
	// Arm 3: walk + capture + fold (the fingerprint). The pure fold
	// cost is arm3 − arm2 — the heap append is not the fold.
	var walkCaptureFold time.Duration
	for r := 0; r < reps; r++ {
		start := time.Now()
		var recs []SnapshotRecord
		_, _ = e.CaptureShardsPinned(func(entityID string, ents []eng.CRDTEntry) bool {
			for i := range ents {
				recs = append(recs, SnapshotRecord{EntityID: entityID, Entry: ents[i]})
			}
			return true
		})
		_ = fingerprintRecords(recs)
		walkCaptureFold += time.Since(start)
		if len(recs) != entries {
			t.Fatalf("walk+capture+fold covered %d records, want %d", len(recs), entries)
		}
	}
	walkMs := float64(walkOnly.Microseconds()) / 1000 / reps
	captureMs := float64(walkCapture.Microseconds()) / 1000 / reps
	bothMs := float64(walkCaptureFold.Microseconds()) / 1000 / reps
	t.Logf("fingerprint fold cost at %d entries (%d reps on this host): walk-only %.3f ms; walk+capture %.3f ms; walk+capture+fold %.3f ms => fold %+.3f ms/checkpoint (%+.1f%% over walk+capture)",
		entries, reps, walkMs, captureMs, bothMs, bothMs-captureMs, 100*(bothMs-captureMs)/captureMs)
}
