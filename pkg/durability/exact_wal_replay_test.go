// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Exact-dot WAL replay tests. The fixtures cover post-checkpoint local writes
// below a higher foreign dot, a reserved counter at the checkpoint watermark,
// mint order differing from append order, image and tail overlap, sequence
// allocation across fsync failures, and root checks with foreign advances.
// Independent reference engines and raw WAL scans keep the assertions separate
// from the recovery implementation under test.

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// engineWith builds an independent reference engine by joining snapshot records
// at their recorded dots. It does not use restoreEntry or the WAL replay loop,
// so a recovery defect cannot be hidden by sharing that implementation.
func engineWith(t *testing.T, nodeID [16]byte, initialCounter uint64, recs ...SnapshotRecord) *eng.DeltaCRDTEngine {
	t.Helper()
	eng.DataDir = t.TempDir()
	e, err := eng.NewDeltaCRDTEngine(nodeID, initialCounter, testArenaSize)
	if err != nil {
		t.Fatalf("engineWith ctor: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if len(recs) > 0 {
		e.Join(snapshotDelta(&SnapshotImage{Records: recs}))
	}
	return e
}

// referenceRoot computes the Merkle root of an independently constructed
// exact-dot state for comparison with recovered state.
func referenceRoot(t *testing.T, nodeID [16]byte, recs ...SnapshotRecord) [32]byte {
	t.Helper()
	return engineWith(t, nodeID, 1, recs...).State().MerkleRoot()
}

// exactRec builds a full snapshot record at an explicit dot for reference
// states, images, and checkpoint fixtures.
func exactRec(entityID string, nodeID [16]byte, counter uint64, digest [32]byte) SnapshotRecord {
	return SnapshotRecord{EntityID: entityID, Entry: eng.CRDTEntry{
		PayloadDigest: digest,
		OriginNodeID:  nodeID,
		DotNodeID:     nodeID,
		DotCounter:    counter,
		SystemTime:    int64(counter) * 1_000,
	}}
}

// handMutation builds the full-fidelity mutation shape production persists.
// NewWALMutation stamps the supplied dot into the 120-byte entry and derives the
// legacy subset from the same values. AppendMutationV1ForTest covers the legacy
// encoding separately in the mixed-format tests.
func handMutation(entityID string, nodeID [16]byte, counter uint64, digest [32]byte) WALMutation {
	return NewWALMutation(entityID,
		eng.CausalDot{NodeID: nodeID, Counter: counter},
		eng.CRDTEntry{PayloadDigest: digest, SystemTime: int64(counter) * 1_000})
}

// readWALRecordSeqs parses raw WAL bytes independently of ReplayWAL and returns
// each record's sequence number in file order. Records follow the 8-byte file
// header as seq(8), type(1), payloadLen(4), and payload, matching
// internal/chaos encodeMutationRecord.
func readWALRecordSeqs(t *testing.T, walPath string) []uint64 {
	t.Helper()
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL %s: %v", walPath, err)
	}
	if len(data) < 8 {
		t.Fatalf("WAL %s too short for the file header: %d bytes", walPath, len(data))
	}
	var seqs []uint64
	for off := 8; off < len(data); {
		if off+13 > len(data) {
			t.Fatalf("truncated record header at offset %d (file %d bytes)", off, len(data))
		}
		seq := binary.BigEndian.Uint64(data[off : off+8])
		payloadLen := binary.BigEndian.Uint32(data[off+9 : off+13])
		seqs = append(seqs, seq)
		off += 13 + int(payloadLen)
	}
	return seqs
}

// assertSeqsUnique requires raw WAL sequence numbers to increase strictly, so
// the checkpoint sequence cut cannot be ambiguous.
func assertSeqsUnique(t *testing.T, walPath string) []uint64 {
	t.Helper()
	seqs := readWALRecordSeqs(t, walPath)
	seen := make(map[uint64]int, len(seqs))
	for i, s := range seqs {
		if prev, dup := seen[s]; dup {
			t.Fatalf("seq %d stamped on both record #%d and record #%d — the recovery cut (Seq > FinalCheckptSeq) is ambiguous", s, prev, i)
		}
		seen[s] = i
		if i > 0 && s <= seqs[i-1] {
			t.Fatalf("seq not monotonic: record #%d seq %d <= record #%d seq %d", i, s, i-1, seqs[i-1])
		}
	}
	return seqs
}

// foreignJoinInto mints n dots in a distinct-origin engine and joins its delta
// into the live bridge. It records the resulting clock advance and returns the
// live clock, which equals the greatest foreign dot.
func foreignJoinInto(t *testing.T, live *Bridge, foreignStart uint64, n int) uint64 {
	t.Helper()
	eng.DataDir = t.TempDir()
	foreign, err := eng.NewDeltaCRDTEngine(foreignNodeID(), foreignStart, testArenaSize)
	if err != nil {
		t.Fatalf("foreign engine ctor: %v", err)
	}
	defer func() { _ = foreign.Close() }()
	for i := 0; i < n; i++ {
		foreign.InsertLocal(utf8EntityID(5000+i), stagedEntry(5000+i))
	}
	delta := foreign.GenerateDelta(live.Engine().GenerateDigest())
	defer delta.Release() // Must release: exits the carried EBR participant so foreign.Close's Quiesce doesn't hang on the leak
	live.Engine().Join(*delta)
	if err := live.RecordClockAdvance(); err != nil {
		t.Fatalf("RecordClockAdvance: %v", err)
	}
	return live.Engine().LamportCounter()
}

// collectEntries deep-copies every entity key and entry slice onto the Go heap.
// ForEach exposes arena-backed strings and slices, which become invalid when
// engine.Close unmaps the arena.
func collectEntries(t *testing.T, engine *eng.DeltaCRDTEngine) map[string][]eng.CRDTEntry {
	t.Helper()
	out := make(map[string][]eng.CRDTEntry)
	engine.State().ForEach(func(entityID string, entries []eng.CRDTEntry) bool {
		cp := make([]eng.CRDTEntry, len(entries))
		copy(cp, entries)
		out[string([]byte(entityID))] = cp
		return true
	})
	return out
}

// writeImageForTest captures live state through CaptureShardsPinned and writes
// an image with a caller-selected watermark. Tests use this to construct stale
// or skewed image and anchor combinations that production checkpointing avoids.
// Entity keys are copied because the EBR pin ends before the image is written.
func writeImageForTest(engine *eng.DeltaCRDTEngine, wm uint64, lfs *LocalFS) error {
	ebr := engine.EBR()
	participant := ebr.Acquire()
	participant.Enter(ebr)
	image := &SnapshotImage{LamportHigh: wm}
	_, _ = engine.CaptureShardsPinned(func(entityID string, entries []eng.CRDTEntry) bool {
		for i := range entries {
			image.Records = append(image.Records, SnapshotRecord{
				EntityID: string([]byte(entityID)),
				Entry:    entries[i],
			})
		}
		return true
	})
	ebr.Release(participant)
	return SnapshotToLSM(context.Background(), nil, lfs, image, nil)
}

// temporalEntry sets all five temporal and H3 fields so overlap tests compare
// the complete recovered entry, not only its dot and payload digest.
func temporalEntry(i int) eng.CRDTEntry {
	e := stagedEntry(i)
	e.ValidTimeStart = int64(i)*1_000 + 1
	e.ValidTimeEnd = int64(i)*1_000 + 2
	e.AssertionTime = int64(i)*1_000 + 3
	e.DecisionTime = int64(i)*1_000 + 4
	e.H3Index = uint64(0x8f00000000000000) + uint64(i)
	return e
}

// ---------------------------------------------------------------------------
// Local tail below a higher foreign dot.
// ---------------------------------------------------------------------------

// TestLocalTailUnderHigherLeakedForeignDot checkpoints at watermark 11, appends
// local dot 12, and then joins foreign dot 1001. The image retains the old
// watermark while containing both the local tail and the foreign entry.
//
// Replay must restore local dot 12 rather than minting above the foreign high
// water. The assertions compare dot count, root, and clock independently so an
// equal number of dots cannot conceal changed dot identities.
func TestLocalTailUnderHigherLeakedForeignDot(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "local-tail.wal")
	live := newLiveBridge(t, walPath, 0)

	// counters 2..11
	for i := 0; i < 10; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	wm := live.Engine().LamportCounter()
	if wm != 11 {
		t.Fatalf("watermark %d != 11 (mint assumption broken)", wm)
	}
	rootAtWm := live.Engine().State().MerkleRoot()
	if err := live.WAL().AppendCheckpoint(WALCheckpoint{MerkleRoot: rootAtWm, LamportHigh: wm}); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	// Dot 12 is appended after the checkpoint but before the image walk.
	if _, err := live.PutLocal(utf8EntityID(10), stagedPayload(10), stagedEntry(10)); err != nil {
		t.Fatalf("PutLocal post-checkpoint: %v", err)
	}
	// The foreign Join advances the clock to 1001, above every local dot.
	if clock := foreignJoinInto(t, live, 1000, 1); clock != 1001 {
		t.Fatalf("post-Join clock %d != 1001", clock)
	}
	// The image retains watermark 11 while containing local dots 2..12 and the
	// foreign dot 1001.
	if err := writeImageForTest(live.Engine(), wm, lfs); err != nil {
		t.Fatalf("SnapshotToLSM: %v", err)
	}

	liveRoot := live.Engine().State().MerkleRoot()
	liveClock := live.Engine().LamportCounter()
	liveDots := countDots(t, live.Engine())
	if liveDots != 12 {
		t.Fatalf("live dot count %d != 12 (11 local + 1 foreign)", liveDots)
	}
	// Crash: per-mutation + checkpoint fsyncs already landed.
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false for the local-tail and foreign-dot fixture")
	}
	if got := countDots(t, rec); got != liveDots {
		t.Errorf("recovered dot count %d differs from live %d; local tail may have been re-minted", got, liveDots)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x differs from live root %x; equal dot counts do not prove equal dots", got, liveRoot)
	}
	if got := rec.LamportCounter(); got != liveClock {
		t.Errorf("recovered clock %d differs from live clock %d", got, liveClock)
	}
}

// ---------------------------------------------------------------------------
// Reserved counter at the checkpoint watermark.
// ---------------------------------------------------------------------------

// TestReservedCounterAtWatermarkSurvivesRecovery models InsertLocal reserving a
// counter before its WAL append completes. The checkpoint carries watermark 5
// and a root for counters 2, 3, and 4; the mutation at counter 5 follows the
// checkpoint record.
//
// A scalar counter cut would discard that durable mutation while still matching
// the checkpoint root. The sequence cut must retain it, and the test compares
// against an independent root that includes counter 5.
func TestReservedCounterAtWatermarkSurvivesRecovery(t *testing.T) {
	nodeID := testNodeID()
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "watermark-counter.wal")

	pre := []SnapshotRecord{
		exactRec(utf8EntityID(1), nodeID, 2, stagedDigest(1)),
		exactRec(utf8EntityID(2), nodeID, 3, stagedDigest(2)),
		exactRec(utf8EntityID(3), nodeID, 4, stagedDigest(3)),
	}
	ckptRoot := referenceRoot(t, nodeID, pre...)

	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	for _, r := range pre {
		if err := w.AppendMutation(handMutation(r.EntityID, nodeID, r.Entry.DotCounter, r.Entry.PayloadDigest)); err != nil {
			t.Fatalf("AppendMutation %v: %v", r.Entry.Dot(), err)
		}
	}
	// Watermark 5 recorded while the counter-5 record is still in flight.
	if err := w.AppendCheckpoint(WALCheckpoint{MerkleRoot: ckptRoot, LamportHigh: 5}); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := w.AppendMutation(handMutation(utf8EntityID(4), nodeID, 5, stagedDigest(4))); err != nil {
		t.Fatalf("AppendMutation reserved: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}

	// The image at the watermark key holds only the pre-reservation dots.
	img := engineWith(t, nodeID, 1, pre...)
	if err := writeImageForTest(img, 5, lfs); err != nil {
		t.Fatalf("SnapshotToLSM: %v", err)
	}

	wantRoot := referenceRoot(t, nodeID, append(pre,
		exactRec(utf8EntityID(4), nodeID, 5, stagedDigest(4)))...)

	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false — the bounded path did not engage")
	}
	if got := countDots(t, rec); got != 4 {
		t.Errorf("recovered %d dots, want 4 including the watermark-counter mutation", got)
	}
	if got := rec.State().MerkleRoot(); got != wantRoot {
		t.Errorf("recovered root %x differs from independent reference %x", got, wantRoot)
	}
	if got := rec.LamportCounter(); got != 5 {
		t.Errorf("recovered clock %d, want 5", got)
	}
	if len(collectEntries(t, rec)[utf8EntityID(4)]) != 1 {
		t.Errorf("reserved-counter mutation %s is absent from recovered state", utf8EntityID(4))
	}
}

// ---------------------------------------------------------------------------
// Mint order differs from append order.
// ---------------------------------------------------------------------------

// TestMintOrderNeAppendOrderExactRestore appends B at counter 3 before A at
// counter 2. Re-minting in append order would change A to counter 4 and reject
// a healthy log through the root anchor. Exact-dot replay must instead restore
// counters 2 and 3 verbatim, preserve the checkpoint root, and report two
// replayed records.
func TestMintOrderNeAppendOrderExactRestore(t *testing.T) {
	nodeID := testNodeID()
	walPath := filepath.Join(t.TempDir(), "append-order.wal")

	recB := exactRec(utf8EntityID(20), nodeID, 3, stagedDigest(20))
	recA := exactRec(utf8EntityID(21), nodeID, 2, stagedDigest(21))
	ckptRoot := referenceRoot(t, nodeID, recA, recB)

	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	// Append order is inverted relative to mint order: B@3 lands before A@2.
	if err := w.AppendMutation(handMutation(recB.EntityID, nodeID, 3, recB.Entry.PayloadDigest)); err != nil {
		t.Fatalf("AppendMutation B: %v", err)
	}
	if err := w.AppendMutation(handMutation(recA.EntityID, nodeID, 2, recA.Entry.PayloadDigest)); err != nil {
		t.Fatalf("AppendMutation A: %v", err)
	}
	if err := w.AppendCheckpoint(WALCheckpoint{MerkleRoot: ckptRoot, LamportHigh: 3}); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}

	// Full-replay path (store == nil): the exact-dot contract.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(nodeID, walPath, nil, testArenaSize)
	if err != nil {
		t.Fatalf("exact-dot recovery rejected append order different from mint order: %v", err)
	}
	defer func() { _ = wal.Close() }()
	defer func() { _ = engine.Close() }()

	if got := countDots(t, engine); got != 2 {
		t.Errorf("recovered %d dots, want 2", got)
	}
	if got := engine.State().MerkleRoot(); got != ckptRoot {
		t.Errorf("recovered root %x differs from checkpoint root %x", got, ckptRoot)
	}
	if got := engine.LamportCounter(); got != 3 {
		t.Errorf("recovered clock %d, want 3", got)
	}
	if witness.ReplayedRecords != 2 {
		t.Errorf("ReplayedRecords=%d, want 2", witness.ReplayedRecords)
	}
	// Check the recorded dot identities as well as their count.
	ents := collectEntries(t, engine)
	if e := ents[recB.EntityID]; len(e) != 1 || e[0].DotCounter != 3 {
		t.Errorf("B restored at counter %v, want exactly 3", e)
	}
	if e := ents[recA.EntityID]; len(e) != 1 || e[0].DotCounter != 2 {
		t.Errorf("A restored at counter %v, want exactly 2", e)
	}
}

// ---------------------------------------------------------------------------
// A dot present in both the image and WAL tail.
// ---------------------------------------------------------------------------

// TestImageTailOverlapImageBytesWin appends counter 4 after the checkpoint and
// then captures an image that also contains it. Recovery must retain one entry
// at the recorded dot rather than minting a duplicate. Repeating recovery 100
// times checks deterministic overlap handling, complete temporal fields, and
// the live root.
//
// Current V2 WAL records and images both carry 120-byte entries, so this fixture
// no longer compares different entry widths. Legacy 80-byte records are covered
// by the mixed-format tests.
func TestImageTailOverlapImageBytesWin(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "image-overlap.wal")
	live := newLiveBridge(t, walPath, 0)

	// Two quiescent temporal puts: counters 2, 3.
	for i := 0; i < 2; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), temporalEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	wm := live.Engine().LamportCounter() // 3
	rootAtWm := live.Engine().State().MerkleRoot()
	if err := live.WAL().AppendCheckpoint(WALCheckpoint{MerkleRoot: rootAtWm, LamportHigh: wm}); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	// The overlap dot: 4 — after the checkpoint record, before the image walk.
	if _, err := live.PutLocal(utf8EntityID(2), stagedPayload(2), temporalEntry(2)); err != nil {
		t.Fatalf("PutLocal overlap: %v", err)
	}
	if err := writeImageForTest(live.Engine(), wm, lfs); err != nil {
		t.Fatalf("SnapshotToLSM: %v", err)
	}

	liveEntries := collectEntries(t, live.Engine())[utf8EntityID(2)]
	if len(liveEntries) != 1 {
		t.Fatalf("live overlap entity carries %d dots, want 1", len(liveEntries))
	}
	liveEntry := liveEntries[0]
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	for iter := 0; iter < 100; iter++ {
		engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
		if err != nil {
			t.Fatalf("iter %d: recover: %v", iter, err)
		}
		got := collectEntries(t, engine)[utf8EntityID(2)]
		if len(got) != 1 {
			_ = wal.Close()
			_ = engine.Close()
			t.Fatalf("iter %d: overlap entity carries %d dots, want exactly 1 (double-mint or loss)", iter, len(got))
		}
		g := got[0]
		if g.DotNodeID != testNodeID() || g.DotCounter != 4 {
			t.Fatalf("iter %d: restored dot = (%x,%d), want (%x,4)", iter, g.DotNodeID, g.DotCounter, testNodeID())
		}
		if g.ValidTimeStart != liveEntry.ValidTimeStart || g.ValidTimeEnd != liveEntry.ValidTimeEnd ||
			g.AssertionTime != liveEntry.AssertionTime || g.DecisionTime != liveEntry.DecisionTime ||
			g.H3Index != liveEntry.H3Index {
			_ = wal.Close()
			_ = engine.Close()
			t.Fatalf("iter %d: temporal or H3 fields changed while resolving the image and WAL overlap at dot 4", iter)
		}
		if got := engine.State().MerkleRoot(); got != liveRoot {
			_ = wal.Close()
			_ = engine.Close()
			t.Fatalf("iter %d: root %x != live %x", iter, got, liveRoot)
		}
		if !witness.Bounded {
			_ = wal.Close()
			_ = engine.Close()
			t.Fatalf("iter %d: not bounded", iter)
		}
		_ = wal.Close()
		_ = engine.Close()
	}
}

// ---------------------------------------------------------------------------
// Sequence uniqueness across an injected fsync failure.
// ---------------------------------------------------------------------------

// riggedFsyncWAL opens a WAL whose sync hook fails on sync-call number
// failOnCall and otherwise returns nil without fsyncing (the record bytes are
// in the page cache regardless; the real fsync happens at Close). The returned
// WAL must be closed by the caller before the path is re-read — this helper
// does not register a cleanup so the caller controls the crash point.
func riggedFsyncWAL(t *testing.T, walPath string, failOnCall int32) *WAL {
	t.Helper()
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	var calls int32
	WALAsChaos(w).SetSyncHookForTest(func() error {
		if atomic.AddInt32(&calls, 1) == failOnCall {
			return errors.New("injected fsync failure")
		}
		return nil
	})
	return w
}

// TestSeqUniqueAcrossFsyncFailure covers mutation, checkpoint, and clock-
// advance appends separately. A failed fsync must still consume the record's
// sequence number because its bytes are already in the file and another fsync
// can flush them. Reusing that sequence number would make the checkpoint cut
// ambiguous between two records.
func TestSeqUniqueAcrossFsyncFailure(t *testing.T) {
	nodeID := testNodeID()

	t.Run("AppendMutation", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "sync-mutation.wal")
		w := riggedFsyncWAL(t, walPath, 2)
		if err := w.AppendMutation(handMutation(utf8EntityID(1), nodeID, 2, stagedDigest(1))); err != nil {
			t.Fatalf("append 1: %v", err)
		}
		if err := w.AppendMutation(handMutation(utf8EntityID(2), nodeID, 3, stagedDigest(2))); err == nil {
			t.Fatalf("the rigged fsync failure did not surface to the caller")
		}
		if err := w.AppendMutation(handMutation(utf8EntityID(3), nodeID, 4, stagedDigest(3))); err != nil {
			t.Fatalf("append 3: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		assertSeqsUnique(t, walPath)
	})

	t.Run("AppendCheckpoint", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "sync-checkpoint.wal")
		w := riggedFsyncWAL(t, walPath, 2)
		rec := exactRec(utf8EntityID(1), nodeID, 2, stagedDigest(1))
		if err := w.AppendMutation(handMutation(rec.EntityID, nodeID, 2, rec.Entry.PayloadDigest)); err != nil {
			t.Fatalf("append 1: %v", err)
		}
		ckptRoot := referenceRoot(t, nodeID, rec)
		if err := w.AppendCheckpoint(WALCheckpoint{MerkleRoot: ckptRoot, LamportHigh: 2}); err == nil {
			t.Fatalf("the rigged fsync failure did not surface to the caller")
		}
		if err := w.AppendMutation(handMutation(utf8EntityID(2), nodeID, 3, stagedDigest(2))); err != nil {
			t.Fatalf("append 3: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		assertSeqsUnique(t, walPath)
	})

	t.Run("AppendClockAdvance", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "sync-clock.wal")
		w := riggedFsyncWAL(t, walPath, 2)
		if err := w.AppendMutation(handMutation(utf8EntityID(1), nodeID, 2, stagedDigest(1))); err != nil {
			t.Fatalf("append 1: %v", err)
		}
		if err := w.AppendClockAdvance(100); err == nil {
			t.Fatalf("the rigged fsync failure did not surface to the caller")
		}
		if err := w.AppendMutation(handMutation(utf8EntityID(2), nodeID, 3, stagedDigest(2))); err != nil {
			t.Fatalf("append 3: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		assertSeqsUnique(t, walPath)
	})
}

// TestSeqCutUnambiguousAfterFsyncFailure places a checkpoint with a failed
// fsync before two mutations. Its bytes and consumed sequence number remain in
// the log, so bounded recovery must replay both later records. Watermark 3 and
// the following counter-3 mutation also ensure the cut uses record sequence
// numbers rather than scalar counters.
func TestSeqCutUnambiguousAfterFsyncFailure(t *testing.T) {
	nodeID := testNodeID()
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "sync-cut.wal")

	rec1 := exactRec(utf8EntityID(1), nodeID, 2, stagedDigest(1))
	rec2 := exactRec(utf8EntityID(2), nodeID, 3, stagedDigest(2))
	rec3 := exactRec(utf8EntityID(3), nodeID, 4, stagedDigest(3))
	ckptRoot := referenceRoot(t, nodeID, rec1)

	w := riggedFsyncWAL(t, walPath, 2)
	if err := w.AppendMutation(handMutation(rec1.EntityID, nodeID, 2, rec1.Entry.PayloadDigest)); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	// The checkpoint reports an fsync error after its bytes and sequence number
	// have been written.
	if err := w.AppendCheckpoint(WALCheckpoint{MerkleRoot: ckptRoot, LamportHigh: 3}); err == nil {
		t.Fatalf("the rigged fsync failure did not surface to the caller")
	}
	if err := w.AppendMutation(handMutation(rec2.EntityID, nodeID, 3, rec2.Entry.PayloadDigest)); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if err := w.AppendMutation(handMutation(rec3.EntityID, nodeID, 4, rec3.Entry.PayloadDigest)); err != nil {
		t.Fatalf("append 3: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	assertSeqsUnique(t, walPath)

	// The image contains only the pre-checkpoint dot even though the failed
	// checkpoint's bytes and sequence number remain in the WAL.
	img := engineWith(t, nodeID, 1, rec1)
	if err := writeImageForTest(img, 3, lfs); err != nil {
		t.Fatalf("SnapshotToLSM: %v", err)
	}

	wantRoot := referenceRoot(t, nodeID, rec1, rec2, rec3)
	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false — the bounded path did not engage")
	}
	if got := countDots(t, rec); got != 3 {
		t.Errorf("recovered %d dots, want 3 including both post-checkpoint mutations", got)
	}
	if got := rec.State().MerkleRoot(); got != wantRoot {
		t.Errorf("recovered root %x differs from independent reference %x", got, wantRoot)
	}
	if got := rec.LamportCounter(); got != 4 {
		t.Errorf("recovered clock %d, want 4", got)
	}
}

// ---------------------------------------------------------------------------
// Root checks with foreign clock advances.
// ---------------------------------------------------------------------------

// TestRootAssertionArmedWithForeignAdvances compares bounded and replay-only
// recovery with foreign advances present. A bound image contains the foreign
// entries, so its rebuilt state is comparable with the checkpoint root: a
// correct anchor must pass and a corrupted anchor must return
// ErrRecoveryRootMismatch.
//
// Replay-only recovery has only local WAL records and cannot reproduce that
// combined root. The same corrupted anchor must therefore not reject the full
// replay; foreign entries arrive again through anti-entropy.
func TestRootAssertionArmedWithForeignAdvances(t *testing.T) {
	build := func(t *testing.T, tamperRoot bool) (walPath string, lfs *LocalFS, liveRoot [32]byte, liveDots int) {
		t.Helper()
		lfs = newSnapshotStore(t)
		walPath = filepath.Join(t.TempDir(), "foreign-advances.wal")
		live := newLiveBridge(t, walPath, 0)
		for i := 0; i < 5; i++ {
			if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
				t.Fatalf("PutLocal %d: %v", i, err)
			}
		}
		if clock := foreignJoinInto(t, live, 100, 1); clock != 101 {
			t.Fatalf("post-Join clock %d != 101", clock)
		}
		liveRoot = live.Engine().State().MerkleRoot()
		ckptRoot := liveRoot
		if tamperRoot {
			ckptRoot[0] ^= 0xFF // the corruption the assertion must catch
		}
		wm := live.Engine().LamportCounter() // 101
		if err := live.WAL().AppendCheckpoint(WALCheckpoint{MerkleRoot: ckptRoot, LamportHigh: wm}); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}
		if err := writeImageForTest(live.Engine(), wm, lfs); err != nil {
			t.Fatalf("SnapshotToLSM: %v", err)
		}
		liveDots = countDots(t, live.Engine())
		if err := live.WAL().Close(); err != nil {
			t.Fatalf("live WAL close: %v", err)
		}
		if err := live.Engine().Close(); err != nil {
			t.Fatalf("live engine close: %v", err)
		}
		return walPath, lfs, liveRoot, liveDots
	}

	t.Run("ArmedAndPasses", func(t *testing.T) {
		walPath, lfs, liveRoot, liveDots := build(t, false)
		rec, witness := recoverBounded(t, walPath, lfs)
		if !witness.Bounded {
			t.Fatalf("witness.Bounded=false — the bounded path did not engage")
		}
		// This checkpoint-final bounded recovery must arm the post-tail root
		// assertion. The legacy 0x02 anchor cannot arm the pre-tail fingerprint
		// check, so the root assertion is the integrity check for this fixture.
		if !witness.PostTailRootArmed {
			t.Fatalf("checkpoint-final bounded recovery did not arm the post-tail root assertion (witness=%+v)", witness)
		}
		if !witness.SeqContiguityVerified {
			t.Fatalf("sequence contiguity was not verified during recovery (witness=%+v)", witness)
		}
		if got := rec.State().MerkleRoot(); got != liveRoot {
			t.Errorf("recovered Merkle root %x, want live root %x", got, liveRoot)
		}
		if got := countDots(t, rec); got != liveDots {
			t.Errorf("recovered %d dots, want %d", got, liveDots)
		}
	})

	t.Run("ArmedAndFires", func(t *testing.T) {
		walPath, lfs, _, _ := build(t, true)
		_, _, _, _, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
		if err == nil {
			t.Fatalf("recovery accepted a corrupted checkpoint anchor with foreign advances; want ErrRecoveryRootMismatch")
		}
		if !errors.Is(err, ErrRecoveryRootMismatch) {
			t.Fatalf("want ErrRecoveryRootMismatch, got: %v", err)
		}
	})

	t.Run("FullPathStaysScoped", func(t *testing.T) {
		walPath, _, _, _ := build(t, true)
		// The WAL holds only origin records, so the rebuilt root legitimately
		// differs from the origin+foreign checkpoint root. Full recovery does not
		// apply the bounded post-tail assertion: it succeeds with the five origin
		// dots, and foreign state can arrive again through gossip.
		rec, _ := recoverFull(t, walPath)
		if got := countDots(t, rec); got != 5 {
			t.Errorf("full recovery returned %d dots, want 5 origin dots", got)
		}
	})
}
