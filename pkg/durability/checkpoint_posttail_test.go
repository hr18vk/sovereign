// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//checkpoint_posttail_test.go — the guards (ADR-0045): T18, T19, T20,
// T21, and T22 (the mid-batch anchor handling). The single-pinned-walk design
// kills the skew at its source: ONE EBR-pinned walk (CaptureShardsPinned) produces the
// checkpoint's root, watermark, AND image — no State() (the N1 arena blowup),
// no LamportCounter() watermark (the T1-vs-T2 skew).
//
// RED discipline: every guard here REDs by a ONE-LINE bug-inject on the new
// mechanism (named in each doc comment) — no HEAD-revert is needed because
// the guards reference-only API (CaptureShardsPinned, Arena().HighWater,
// LastCheckpointArenaHighWater).

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

// ckptWatermarks walks the RAW WAL bytes (the code under test is never its own
// check) and returns the LamportHigh of every WALRecCheckpoint record, in
// file order. Checkpoint payload layout: MerkleRoot(32) || LamportHigh(8)
// (wal.go:633-641).
func ckptWatermarks(t *testing.T, walPath string) []uint64 {
	t.Helper()
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL %s: %v", walPath, err)
	}
	var out []uint64
	for off := 8; off < len(data); {
		// (C1): records are now 0x06 CRC-framed; walRecordAtForTest
		// verifies the CRC and unwraps to the inner checkpoint payload, so this
		// scanner matches the inner 0x02/0x05 exactly as before — WITHOUT
		// weakening it (a bad CRC Fatalf's inside the helper).
		innerType, innerPayload, recLen, complete := walRecordAtForTest(t, data, off)
		if !complete {
			break // torn tail — end of clean records (a crash boundary, not a record)
		}
		// Both checkpoint record types (legacy 0x02, 40-byte payload; horizon
		// 0x05, 48-byte) carry LamportHigh at the same offset.
		if innerType == byte(WALRecCheckpoint) || innerType == byte(WALRecCheckpointV2) {
			// 40 = legacy 0x02 (root+watermark); 48 = pre-0x05
			// (+CutSeq); 56 = 0x05 +ClockHigh; 88 = 0x05
			// +ClockHigh +StateFingerprint.
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
// T18 — zero post-watermark local dots in the image (the skew is dead)
// ---------------------------------------------------------------------------

// TestZeroPostWatermarkDotsInImage: under REAL concurrent writer load,
// every checkpoint image must contain ZERO records
// with DotNodeID == local && DotCounter > image.LamportHigh — the watermark is
// the walk's own max-local, so "the image holds a dot above its watermark" is
// impossible by construction. The pre-path leaked 184–3,193 such dots
// per image on 10/10 measured images (the observed skew).
//
// NON-VACUITY: the guard asserts the checkpoints INTERLEAVED with the writes
// (first watermark < final clock) — otherwise "zero leaks" was measured on a
// quiescent engine and proves nothing.
//
// RED (bug-inject): in AppendCheckpoint read the watermark from
// LamportCounter() BEFORE the walk (the old T1c ordering) instead of the
// walk's max-local → writers mint during the walk → the image carries dots
// above the watermark → this guard fires.
func TestZeroPostWatermarkDotsInImage(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t18.wal")
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
	// Fire checkpoints WHILE the writers run — the interleave is the test.
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
		t.Fatalf("NON-VACUITY: first checkpoint watermark %d not below final clock %d — the checkpoints never interleaved with the writes", wms[0], finalClock)
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
			t.Errorf("SKEW: image ckpt/%d carries %d local dot(s) ABOVE its watermark", wm, leaked)
		}
	}
	if img := wms[len(wms)-1]; img != finalClock {
		t.Errorf("final checkpoint watermark %d != final clock %d (the quiesced final walk must see every mint)", img, finalClock)
	}
}

// ---------------------------------------------------------------------------
// T19 — the HOLE direction: every durable local dot ≤ watermark is in the image
// ---------------------------------------------------------------------------

// TestNoHoleBelowWatermark is the hole-direction guard — and the one that
// REFUTED an earlier residual claim. That claim held the
// HOLE direction was "closed only by the exact-dot replay"; this guard's
// first draft caught a LIVE hole on the tree (WAL local dot counter=94
// at seq=96, checkpoint watermark=95 with its record at seq=104 — durable,
// below the legacy record-seq cut, absent from the image: an ACKed write
// bounded recovery would have LOST). The seq cut did NOT close it. The
// closure is the V2 checkpoint record (0x05) carries the PRE-WALK NextSeq
// horizon, so "below the cut ⇒ in the image" holds BY CONSTRUCTION, plus a
// defensive recovery-side repair pass (witness.HolesRepaired) that heals the
// window on legacy 0x02 logs.
//
// The guard asserts BOTH layers on a load-hammered log:
// 1. SOURCE: for every checkpoint, every local mutation below its cut is in
// its image (raw WAL parse vs raw store — the code under test is the
// checkpoint capture, never its own check).
// 2. CLOSURE: bounded recovery of the final checkpoint reproduces the live
// root EXACTLY with HolesRepaired == 0 and no fallback.
//
// NON-VACUITY: the checked-dot count is required nonzero (hundreds here), and
// the checkpoints are proven mid-flight (the writer goroutines race them).
//
// RED (bug-inject): the AppendCheckpoint capture callback drops every 7th
// entity (a synthetic hole below the horizon — the frozen InsertLocal
// mint/CAS window cannot be widened, so the hole is injected at the capture,
// which is code) → the SOURCE invariant fires with the exact dropped
// dots named AND the recovery meter goes nonzero.
func TestNoHoleBelowWatermark(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t19.wal")
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
	// Every checkpoint (seq, watermark, CUT) from the RAW bytes — NOT just the
	// final one: the final checkpoint is quiesced and trivially hole-free; the
	// MID-FLIGHT ones are the guard's target. The cut is the V2 record's
	// CutSeq horizon (0x05) or, for a legacy 0x02 record, its own seq + 1.
	// DISCLOSED LIMIT: two checkpoints that observe the same watermark share
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
		// (C1): records are now 0x06 CRC-framed; walRecordAtForTest
		// verifies the CRC and unwraps to the inner checkpoint payload. The seq
		// is the OUTER header's (identical framed or not); the watermark + CutSeq
		// come from the INNER payload. A bad CRC Fatalf's inside the helper.
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

	// THE SOURCE INVARIANT (by construction on the V2 horizon cut):
	// every local mutation whose WAL record sits BELOW a checkpoint's cut is
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
				t.Errorf("HOLE: WAL local dot (counter=%d, seq=%d) sits BELOW the cut (seq<%d) of checkpoint at watermark %d yet is ABSENT from its image — bounded recovery would lose an ACKed write", m.d.counter, m.s, c.cut, c.wm)
			}
		}
	}
	if totalChecked == 0 {
		t.Fatalf("NON-VACUITY: checked set is empty — the guard inspected nothing")
	}
	t.Logf("T19 source invariant: checkpoints=%d below-cut dots checked=%d holes=%d", len(ckpts), totalChecked, totalHoles)

	// THE CLOSURE (the "or recovery restores it regardless" guarantee):
	// bounded recovery of the final quiesced checkpoint must reproduce the
	// live state byte-exactly, with ZERO repairs needed on a V2 log.
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
		t.Errorf("HolesRepaired=%d on a horizon-cut V2 log — the R9c construction was violated at checkpoint time (the repair healed it, but the source invariant must hold)", witness.HolesRepaired)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x != live root %x — recovery did not restore the full state", got, liveRoot)
	}
}

// ---------------------------------------------------------------------------
// T20 — AppendCheckpoint allocates ZERO arena (N1 stays closed)
// ---------------------------------------------------------------------------

// TestCheckpointAllocatesZeroArena is the TestShardedRootNoArenaGrowth
// shape applied to the checkpoint path. The
// earlier AppendCheckpoint built the merged view TWICE per checkpoint
// (State().MerkleRoot() + SnapshotToLSM's State()); measured on the probe, 11
// checkpoints exhausted a 768 MiB arena at a ~2,500-entity live set. The
// single-pinned-walk path allocates ZERO arena: the bump high-water must be
// FLAT across M checkpoints, and the bridge's witness accessor must report
// exactly that flat value (T20 keeps the CHECK-I RSS bound honest).
//
// NON-VACUITY: the live set is 2,000 entities, so a merged-view build would
// move the high-water by megabytes — flatness is a strong signal, not a
// rounding artifact.
//
// RED (bug-inject): re-read the root via b.engine.State().MerkleRoot() inside
// AppendCheckpoint (the pre-call) → the merged view bump-allocates →
// the high-water moves → this guard fires.
func TestCheckpointAllocatesZeroArena(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t20.wal")
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
		t.Errorf("ARENA GREW across %d checkpoints: high-water %d → %d (+%d bytes) — the checkpoint path is building merged views again (N1)", M, hw0, hw1, hw1-hw0)
	}
	if got := live.LastCheckpointArenaHighWater(); got != hw0 {
		t.Errorf("WITNESS: LastCheckpointArenaHighWater=%d, want the flat %d", got, hw0)
	}
}

// ---------------------------------------------------------------------------
// T21 — the EBR pin is load-bearing (checkpoint walk vs concurrent State())
// ---------------------------------------------------------------------------

// TestCheckpointWalkPinnedAgainstState: /v1/get calls
// engine.State() (control.go:518), which retires the previous merged view and
// advances the EBR epoch; writers CAS-retire shard roots. The checkpoint walk
// reads those SAME shard roots. The pin AppendCheckpoint holds across the walk
// is what makes the read formally race-free instead of
// grace-window-lucky — without it a retired shard root can be reclaimed and
// REUSED mid-walk (garbage records, or the "unexpected fault address" SIGSEGV
// class the probe observed once).
//
// The guard: a State() hammer (the /v1/get pattern) + writers + 20 checkpoints
// over a 3,000-entity live set, run under -race in the battery. GREEN =
// completes clean, the final quiesced checkpoint round-trips through recovery
// byte-exact (the walk captured a self-consistent image).
//
// RED (bug-inject): delete the Acquire/Enter/Release around AppendCheckpoint's
// body → the walk is unpinned. The expected conviction is a -race report or a
// fault; if the box cannot reproduce it, the artifact says so and the pin
// stands on the documented hazard, NOT on a green-by-luck run.
func TestCheckpointWalkPinnedAgainstState(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t21.wal")
	// Fold-era arena sizing (ADR-0045; comment CORRECTED):
	// added the mandated payload-covering
	// fingerprint fold to AppendCheckpoint. The fold allocates ZERO arena
	// (heap-only — it is not a leak), but it extends the EBR pin per checkpoint
	// (SHA-256 over the captured entries; measured +3.754 ms at
	// 20,000 entries, +49.4% — see TestFoldCostMeasured for the in-tree
	// reconciliation of the three published numbers). The pin is FORBIDDEN to
	// narrow, so under
	// this test's unpaced State() hammer (~560 MB/s of merged-view garbage that
	// EBR cannot reclaim while the pin is held) that pin-time is unreclaimable
	// arena: measured high-water over the 20-checkpoint storm is 50.9 MB without
	// the fold vs 64.4 MB with it — over the 64 MiB testArenaSize. 128 MiB
	// restores ~2x headroom for the identical workload and assertions; only the
	// resource is sized for the mandated fold.
	//
	// WHY THIS IS A TEST ARTIFACT (the CORRECTED reason — the earlier text said
	// "production checkpoints are not back-to-back", which is FALSE: measured
	// 80 checkpoint records over 15 watermarks, worst repeat 66). The
	// true reason: production has no concurrent arena-garbage
	// producer on the checkpoint path. The 100-node orchestrator's root gauge is
	// MerkleRootFromShards (pkg/sync/merkle_sharded.go:140) over
	// CaptureShardsPinned (pkg/sync/merkle_sharded.go:210) — a ZERO-arena shard
	// walk, not State(); Gossiper.LatestPayload's State() has ZERO callers (dead
	// code); the only State() hammer is THIS TEST's. (Do NOT cite an ADR number
	// for the sharded root — none exists as a file; the citations are the two
	// functions above.) The pre-existing State() arena growth on the LIVE READ
	// path (per-request /v1/get) is a SEPARATE, still-open production defect —
	// one this resize neither fixes nor clears.
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
	go func() { // the /v1/get pattern: State() churns merged views + epochs
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
// T22 — a mid-PutLocals (phantom-anchor) checkpoint must BOOT, not Fatalf
// ---------------------------------------------------------------------------

// TestMidBatchPhantomAnchorBootsClean covers ADR-0045: a
// checkpoint taken between a batch's InsertLocal calls and its AppendMutations
// fsync anchors a root covering dots the durable log never received.
// Recovery discards that image (phantom local dots); the full-log rebuild then
// legitimately CANNOT equal the torn anchor's root. Before the guard the
// armed root assertion returned ErrRecoveryRootMismatch and main.go:822
// Fatalf'd — the node REFUSED TO BOOT on a log that was not corrupt. Now the
// assertion skips the torn anchor (loudly) and the node boots on exactly the
// durable log: the phantom dots were never fsync'd, never ACKed — losing them
// is the honest un-ACKed-write contract, not corruption.
//
// The scenario is constructed, not raced: two local-identity dots are Joined
// straight into the engine (never WAL-appended) — byte-for-byte the state a
// mid-batch checkpoint observes.
//
// RED (bug-inject): remove `&& localPhantomsRejected == 0` from the root
// assertion → recovery returns ErrRecoveryRootMismatch → the boot-succeeds
// assertion fires with exactly that error.
func TestMidBatchPhantomAnchorBootsClean(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t22.wal")
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
	// The "mid-batch" dots: live in the engine, NEVER in the WAL — exactly the
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
		t.Fatalf("BOOT REFUSED on a non-corrupt log (R9a false data-loss verdict): %v", err)
	}
	t.Cleanup(func() { _ = recWAL.Close() })
	t.Cleanup(func() { _ = rec.Close() })
	if !witness.ExactWALFallback {
		t.Errorf("MARKER: ExactWALFallback=false — a phantom-bearing image was used")
	}
	if witness.LocalPhantomsRejected != 2 {
		t.Errorf("MARKER: LocalPhantomsRejected=%d, want 2", witness.LocalPhantomsRejected)
	}
	if !strings.Contains(witness.FallbackReason, "phantom") {
		t.Errorf("MARKER: FallbackReason=%q, want it to name the phantom discard", witness.FallbackReason)
	}
	if got := countDots(t, rec); got != 3 {
		t.Errorf("recovered %d dots, want exactly the 3 durable ones (the 2 phantoms were never ACKed — honestly lost)", got)
	}
	// The recovered state is EXACTLY the three durable dots — the independent
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
// T23 — legacy 0x02 log with a hole: the repair pass heals it, observably
// ---------------------------------------------------------------------------

// TestLegacyHoleHealed covers the LEGACY leg: a legacy WAL whose
// 0x02 checkpoint cuts at its own record seq, carrying a dot below the cut
// that the image missed (the walk→append window, frozen into an old log). The
// bounded recovery must (a) USE the image (it is not torn — no phantom, no
// watermark mismatch), (b) exact-restore the holed dot from its WAL record,
// (c) count the repair in witness.HolesRepaired, (d) SKIP the root assertion
// for the under-covering anchor (loudly, not ErrRecoveryRootMismatch), and
// (e) reproduce the full durable state byte-exactly.
//
// Construction: 3 real PutLocals (durable); a HAND-WRITTEN legacy checkpoint
// whose root covers only dots {1,2} (the walk "missed" dot 3); an image with
// exactly {1,2}. Dot 3 is at seq 2 < cut 4 — the hole.
//
// RED (bug-inject): remove `&& holesRepaired == 0` from the root-assertion
// guard → the rebuilt (3-dot) root is asserted against the under-covering
// (2-dot) anchor → ErrRecoveryRootMismatch → the boot-succeeds assertion
// fires. (A second valid RED: delete the repair pass → dot 3 is lost → the
// root/dot-count assertions fire.)
func TestLegacyHoleHealed(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t23.wal")
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
	// The LEGACY checkpoint: root of the 2-dot (hole-y) walked state, no CutSeq.
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
		t.Fatalf("BOOT REFUSED on a legacy log with a hole (the repair pass must heal it): %v", err)
	}
	t.Cleanup(func() { _ = recWAL.Close() })
	t.Cleanup(func() { _ = rec.Close() })
	if witness.ExactWALFallback {
		t.Errorf("ExactWALFallback=true — the holed image is not TORN, it must be USED (the WAL record heals the hole)")
	}
	if witness.HolesRepaired != 1 {
		t.Errorf("METER: HolesRepaired=%d, want exactly 1 (dot 3)", witness.HolesRepaired)
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

// TestFoldCostMeasured reconciles three published numbers for
// the fingerprint fold's per-checkpoint cost that disagreed
// (~1.2 ms, 5.142 ms, and +3.754 ms / +49.4% at 20,000
// entries). This measures BOTH halves on THIS tree at that exact scale: the
// CaptureShardsPinned walk alone vs walk+fold. It is a MEASUREMENT (the number
// is reported, never gated), but it is not vacuous: the record counts must
// match or the two passes measured different state.
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
	// Arm 1: walk only (the pre-checkpoint cost).
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
	// Arm 3: walk + capture + FOLD (the fingerprint). The pure fold
	// cost is arm3 − arm2 — the heap append is NOT the fold.
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
	t.Logf("T21 FOLD COST at %d entries (%d reps, this box): walk-only %.3f ms; walk+capture %.3f ms; walk+capture+fold %.3f ms => PURE FOLD %+.3f ms/checkpoint (%+.1f%% over walk+capture) — reconciles the 1.2 / 5.142 / +3.754 ms dispute",
		entries, reps, walkMs, captureMs, bothMs, bothMs-captureMs, 100*(bothMs-captureMs)/captureMs)
}
