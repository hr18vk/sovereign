// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//exact_wal_replay_test.go — the exact-WAL guards (ADR-0045):
// T2, T3, T4, T10, T14, T15. Every guard in THIS file compiles against HEAD
// recovery.go/wal.go (pre-change..), so its RED is capturable by reverting those
// two files and re-running: the failure is the PREDICTED defect signature
// (double-mint / silent loss / duplicate seq / scoped-off assertion), never a
// compile error. The marker-assertion guards (T5, T9, T13) reference the new
// witness fields and live inwal_markers_test.go with bug-inject REDs.
//
// THE DISCIPLINE: no guard counts without its RED.
// An assertion that cannot fail is not an assertion — every test below names
// its RED mechanism in its doc comment.

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

// engineWith builds a fresh engine and exact-Joins the given records into it
// (the synthetic-delta route — Join honors the recorded dots verbatim). It is
// the INDEPENDENT reference the guards compare recovery against: it never goes
// near restoreEntry, the WAL replay loop, or any code under test, so a recovery
// defect cannot be masked by a shared implementation (a tautology guard).
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

// referenceRoot is the Merkle root of an independently-constructed exact-dot
// state — the check for "recovery reproduced the live state" that does not
// depend on the recovery path producing it.
func referenceRoot(t *testing.T, nodeID [16]byte, recs ...SnapshotRecord) [32]byte {
	t.Helper()
	return engineWith(t, nodeID, 1, recs...).State().MerkleRoot()
}

// exactRec builds a SnapshotRecord carrying a full 120-byte entry at an
// EXPLICIT dot — the building block for hand-constructed reference states,
// images, and checkpoints.
func exactRec(entityID string, nodeID [16]byte, counter uint64, digest [32]byte) SnapshotRecord {
	return SnapshotRecord{EntityID: entityID, Entry: eng.CRDTEntry{
		PayloadDigest: digest,
		OriginNodeID:  nodeID,
		DotNodeID:     nodeID,
		DotCounter:    counter,
		SystemTime:    int64(counter) * 1_000,
	}}
}

// handMutation builds a WALMutation in EXACTLY the shape production persists
// post-a full-fidelity 0x04 record built via NewWALMutation (the one
// construction discipline — the dot is stamped into the full 120-byte entry
// from the engine-returned CausalDot, the legacy subset is derived, and
// AppendMutation's validateV2 gate accepts it). The pre--BLOCKER shape
// (zeroed entry dot/origin) is now LEGACY-only; the T12 mixed-format guard
// exercises it via AppendMutationV1ForTest.
func handMutation(entityID string, nodeID [16]byte, counter uint64, digest [32]byte) WALMutation {
	return NewWALMutation(entityID,
		eng.CausalDot{NodeID: nodeID, Counter: counter},
		eng.CRDTEntry{PayloadDigest: digest, SystemTime: int64(counter) * 1_000})
}

// readWALRecordSeqs parses the RAW WAL bytes (not ReplayWAL — the code under
// test cannot be its own check) and returns every record's on-disk seq in
// file order. Layout: 8-byte file header, then records of
// seq(8) + type(1) + payloadLen(4) + payload (wal.go:encodeMutationRecord).
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

// assertSeqsUnique fails unless the raw WAL's record seqs are strictly
// increasing — no duplicates, no rewinds (contract).
func assertSeqsUnique(t *testing.T, walPath string) []uint64 {
	t.Helper()
	seqs := readWALRecordSeqs(t, walPath)
	seen := make(map[uint64]int, len(seqs))
	for i, s := range seqs {
		if prev, dup := seen[s]; dup {
			t.Fatalf("seq %d stamped on BOTH record #%d and record #%d — the recovery cut (Seq > FinalCheckptSeq) is ambiguous", s, prev, i)
		}
		seen[s] = i
		if i > 0 && s <= seqs[i-1] {
			t.Fatalf("seq not monotonic: record #%d seq %d <= record #%d seq %d", i, s, i-1, seqs[i-1])
		}
	}
	return seqs
}

// foreignJoinInto performs a REAL foreign Join against the live bridge (the
// physics, not a synthetic clock jump): a distinct-origin engine mints
// n dots starting at foreignStart+1, the delta is generated against the live
// digest and Joined, and the clock advance is persisted at the receive seam
// Returns the live clock after the Join (== the foreign max dot).
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
	defer delta.Release() // MUST Release (crdt.go:1595): Exits the carried EBR participant so foreign.Close's Quiesce doesn't hang on the leak
	live.Engine().Join(*delta)
	if err := live.RecordClockAdvance(); err != nil {
		t.Fatalf("RecordClockAdvance: %v", err)
	}
	return live.Engine().LamportCounter()
}

// collectEntries snapshots an engine's full dot set: entityID → one entry per
// dot. BOTH the key strings and the entry slices are deep-copied onto the Go
// heap: ForEach's entityID is a zero-copy string header pointing INTO the mmap
// arena (and the entries slice is arena-backed), so a map built on the raw
// keys turns to garbage the instant engine.Close() unmaps the arena. (Found
// the hard way: T6 compared against a live map collected pre-Close and read
// post-Close — every key read back as NUL bytes.)
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

// writeImageForTest captures eng's live state through the pinned walk
// (CaptureShardsPinned) and writes the image stamped at a CALLER-CHOSEN
// watermark wm. The/2 guards use it to FORGE the pre-skew on
// purpose (T1/T2/T3/T10 build the torn or skewed images the recovery path
// must survive; production AppendCheckpoint can no longer produce them).
// Entity keys are cloned out of the arena (the pin is released before the
// write — the image must not reference arena memory past it).
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

// temporalEntry is a stagedEntry with ALL FIVE temporal/H3 fields set — the
// T10 carrier proving the 120-byte image bytes deterministically win over the
// 80-byte WAL bytes at a shared dot (C2/C3).
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
// T2 — counterexample (i): local tail under a HIGHER leaked foreign dot
// ---------------------------------------------------------------------------

// TestLocalTailUnderHigherLeakedForeignDot is the Fix A
// killer. The timeline:
//
//	10 local puts (counters 2..11); checkpoint at wm=11; local put → dot 12
//	(the leak); a foreign Join lands dot 1001 and advances the clock; the
//	stale-wm image then holds local {2..12} AND foreign {1001}.
//
// RED on HEAD: bounded replay re-mints dot 12 via InsertLocal ABOVE the image's
// max (the foreign 1001) → the recovered node carries 13 dots vs the live 12,
// the root diverges, the clock overshoots. RED under the REJECTED Fix A: the
// image's local 12 is filtered out and the re-mint lands at 1002 → the dot
// COUNT matches the live 12 while the ROOT still diverges (equal cardinality ≠
// equal identity — §2.3(i)). Both RED variants are captured artifacts; this
// guard asserts ALL THREE observables non-fatally so the artifacts show exactly
// which check fired.
func TestLocalTailUnderHigherLeakedForeignDot(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t2.wal")
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
	// The leaked local dot: 12 — minted in the (T1, T2] window.
	if _, err := live.PutLocal(utf8EntityID(10), stagedPayload(10), stagedEntry(10)); err != nil {
		t.Fatalf("PutLocal leaked: %v", err)
	}
	// The foreign Join: clock → 1001; the image's max dot is now FOREIGN.
	if clock := foreignJoinInto(t, live, 1000, 1); clock != 1001 {
		t.Fatalf("post-Join clock %d != 1001", clock)
	}
	// The T2 image walk with the STALE T1 watermark: holds {2..12} ∪ {1001}.
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
		t.Fatalf("witness.Bounded=false — the bounded path did not engage; T2 is not exercising the T2 window")
	}
	// Non-fatal triple: the RED artifact must name every check that fired.
	if got := countDots(t, rec); got != liveDots {
		t.Errorf("DOT COUNT: recovered %d != live %d — the leaked dot was re-minted above the foreign max (double-mint)", got, liveDots)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("ROOT: recovered %x != live %x — equal cardinality is NOT equal identity", got, liveRoot)
	}
	if got := rec.LamportCounter(); got != liveClock {
		t.Errorf("CLOCK: recovered %d != live %d", got, liveClock)
	}
}

// ---------------------------------------------------------------------------
// T3 — counterexample (ii): reserved counter exactly at the watermark
// ---------------------------------------------------------------------------

// TestReservedCounterAtWatermarkSurvivesRecovery covers the reserved-counter-at-watermark counterexample.
// InsertLocal reserves counter N BEFORE the record lands; a checkpoint in that
// window records watermark N with the mutation's record still ABOVE it in the
// log. The refuted scalar cut (Counter <= watermark → skip) silently drops that
// durable mutation; the sequence cut (Seq > FinalCheckptSeq) keeps it.
//
// The scenario is hand-built byte-exactly (this is a WAL-cut contract guard,
// not a race): mutations at counters 2,3,4; checkpoint{root({2,3,4}), wm=5};
// then the reserved mutation at counter 5.
//
// RED on HEAD (the damning part): the scalar cut skips counter 5 AND the
// checkpoint anchor PASSES — the rebuilt root equals the checkpoint root
// because both cover only {2,3,4} — so HEAD returns SUCCESS having silently
// lost a durable write. Root equality is not a completeness check; this guard
// compares against an INDEPENDENT reference root that includes the lost dot.
func TestReservedCounterAtWatermarkSurvivesRecovery(t *testing.T) {
	nodeID := testNodeID()
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t3.wal")

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

	// The image at the watermark key holds ONLY the pre-reservation dots.
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
		t.Errorf("DOT COUNT: recovered %d != 4 — the durable watermark-counter mutation was dropped by the cut", got)
	}
	if got := rec.State().MerkleRoot(); got != wantRoot {
		t.Errorf("ROOT: recovered %x != reference %x — recovered state is not the live state", got, wantRoot)
	}
	if got := rec.LamportCounter(); got != 5 {
		t.Errorf("CLOCK: recovered %d != 5", got)
	}
	if len(collectEntries(t, rec)[utf8EntityID(4)]) != 1 {
		t.Errorf("ENTITY: the reserved-counter mutation %s is absent from the recovered state", utf8EntityID(4))
	}
}

// ---------------------------------------------------------------------------
// T4 — counterexample (iii): mint order ≠ append order
// ---------------------------------------------------------------------------

// TestMintOrderNeAppendOrderExactRestore covers the mint-order≠append-order counterexample. Under
// concurrent mint/append, the WAL can record B@3 BEFORE A@2. HEAD seeds the
// full replay at firstMutation.Counter-1 = 2 and re-mints in APPEND order:
// B→3 (coincides), A→4 — counter set {3,4} ≠ the live {2,3}, so the checkpoint
// anchor fires ErrRecoveryRootMismatch and boot is REFUSED on a healthy log.
// Exact-dot restore replays B@3, A@2 verbatim: no error, root == live.
//
// RED on HEAD: RecoverEngineWithSnapshot returns ErrRecoveryRootMismatch
// (rebuilt {3,4} vs checkpoint {2,3}) — the test's first assertion is that
// recovery SUCCEEDS.
func TestMintOrderNeAppendOrderExactRestore(t *testing.T) {
	nodeID := testNodeID()
	walPath := filepath.Join(t.TempDir(), "t4.wal")

	recB := exactRec(utf8EntityID(20), nodeID, 3, stagedDigest(20))
	recA := exactRec(utf8EntityID(21), nodeID, 2, stagedDigest(21))
	ckptRoot := referenceRoot(t, nodeID, recA, recB)

	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	// Append order INVERTED vs mint order: B@3 lands first, then A@2.
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

	// Full-replay path (store == nil): the contract with exact dots.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(nodeID, walPath, nil, testArenaSize)
	if err != nil {
		t.Fatalf("T4: exact-dot recovery must NOT trip the root anchor on append-order≠mint-order (HEAD re-mints A→4 and fails here): %v", err)
	}
	defer func() { _ = wal.Close() }()
	defer func() { _ = engine.Close() }()

	if got := countDots(t, engine); got != 2 {
		t.Errorf("DOT COUNT: recovered %d != 2", got)
	}
	if got := engine.State().MerkleRoot(); got != ckptRoot {
		t.Errorf("ROOT: recovered %x != live %x — replay re-minted instead of restoring the recorded dots", got, ckptRoot)
	}
	if got := engine.LamportCounter(); got != 3 {
		t.Errorf("CLOCK: recovered %d != 3", got)
	}
	if witness.ReplayedRecords != 2 {
		t.Errorf("WITNESS: ReplayedRecords %d != 2", witness.ReplayedRecords)
	}
	// The dots THEMSELVES (not just their count) are the recorded ones.
	ents := collectEntries(t, engine)
	if e := ents[recB.EntityID]; len(e) != 1 || e[0].DotCounter != 3 {
		t.Errorf("B restored at counter %v, want exactly 3", e)
	}
	if e := ents[recA.EntityID]; len(e) != 1 || e[0].DotCounter != 2 {
		t.Errorf("A restored at counter %v, want exactly 2", e)
	}
}

// ---------------------------------------------------------------------------
// T10 — image/tail exact-dot overlap: the image's bytes win, deterministically
// ---------------------------------------------------------------------------

// TestImageTailOverlapImageBytesWin covers the image/tail exact-dot overlap (C2/C3). One dot
// (counter 4) sits in BOTH the 120-byte image (full temporal bytes) and the
// 80-byte WAL tail (the five temporal/H3 fields zero — restoreEntry's
// documented limitation, closed by). The merge compares DOTS ONLY and
// the EXISTING entry keeps its bytes, so the image MUST be Joined first; and
// the two Joins MUST be separate (a combined delta's unstable sort leaves an
// unspecified winner). This guard recovers 100 times over the SAME on-disk
// artifacts and asserts the image's bytes win EVERY time — a combined-Join
// regression would flap rather than fail once.
//
// RED on HEAD: the tail re-mints dot 4 at counter 5 (InsertLocal), so the
// overlap entity carries TWO dots — the single-dot assertion fires before the
// byte comparison is even reached.
func TestImageTailOverlapImageBytesWin(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t10.wal")
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
			t.Fatalf("iter %d: the 80-byte WAL bytes beat the 120-byte image bytes at dot 4 — C2/C3 ordering regression (image MUST be Joined first, in a SEPARATE Join)", iter)
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
// T14 — seq uniqueness across a rigged fsync failure
// ---------------------------------------------------------------------------

// riggedFsyncWAL opens a WAL whose sync hook fails on sync-call number
// failOnCall and otherwise returns nil WITHOUT fsyncing (the record bytes are
// in the page cache regardless; the real fsync happens at Close). The returned
// WAL must be Closed by the caller before the path is re-read — this helper
// deliberately does NOT register a cleanup so the caller controls the crash
// point.
func riggedFsyncWAL(t *testing.T, walPath string, failOnCall int32) *WAL {
	t.Helper()
	w, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	var calls int32
	WALAsChaos(w).SetSyncHookForTest(func() error {
		if atomic.AddInt32(&calls, 1) == failOnCall {
			return errors.New("T14 rigged fsync failure")
		}
		return nil
	})
	return w
}

// TestSeqUniqueAcrossFsyncFailure runs one
// sub-case per append path — proving one does NOT generalize (HEAD fixed the
// batch path only). A failed fsync MUST still consume the record's seq
// (advance-as-you-write): the bytes are in the file and a neighbour's fsync
// can flush them, so re-stamping the same seq onto the NEXT record makes two
// records share a seq and the recovery cut (Seq > FinalCheckptSeq) silently
// absorbs one of them.
//
// RED on HEAD: AppendMutation/AppendCheckpoint/AppendClockAdvance all bump
// nextSeq only AFTER a successful sync, so the post-failure append REUSES the
// failed record's seq → assertSeqsUnique fires on the raw bytes.
func TestSeqUniqueAcrossFsyncFailure(t *testing.T) {
	nodeID := testNodeID()

	t.Run("AppendMutation", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "t14m.wal")
		w := riggedFsyncWAL(t, walPath, 2)
		if err := w.AppendMutation(handMutation(utf8EntityID(1), nodeID, 2, stagedDigest(1))); err != nil {
			t.Fatalf("append 1: %v", err)
		}
		if err := w.AppendMutation(handMutation(utf8EntityID(2), nodeID, 3, stagedDigest(2))); err == nil {
			t.Fatalf("the rigged fsync failure did not surface to the caller — durability lies")
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
		walPath := filepath.Join(t.TempDir(), "t14c.wal")
		w := riggedFsyncWAL(t, walPath, 2)
		rec := exactRec(utf8EntityID(1), nodeID, 2, stagedDigest(1))
		if err := w.AppendMutation(handMutation(rec.EntityID, nodeID, 2, rec.Entry.PayloadDigest)); err != nil {
			t.Fatalf("append 1: %v", err)
		}
		ckptRoot := referenceRoot(t, nodeID, rec)
		if err := w.AppendCheckpoint(WALCheckpoint{MerkleRoot: ckptRoot, LamportHigh: 2}); err == nil {
			t.Fatalf("the rigged fsync failure did not surface to the caller — durability lies")
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
		walPath := filepath.Join(t.TempDir(), "t14a.wal")
		w := riggedFsyncWAL(t, walPath, 2)
		if err := w.AppendMutation(handMutation(utf8EntityID(1), nodeID, 2, stagedDigest(1))); err != nil {
			t.Fatalf("append 1: %v", err)
		}
		if err := w.AppendClockAdvance(100); err == nil {
			t.Fatalf("the rigged fsync failure did not surface to the caller — durability lies")
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

// TestSeqCutUnambiguousAfterFsyncFailure is the second half of T14: the
// CUT, not just the seq counter. A checkpoint whose fsync FAILED still sits in
// the byte stream with its own seq; bounded recovery must replay EXACTLY the
// post-checkpoint records. The wm=3/counter-3 pair is deliberate (the
// counterexample-(ii) shape): with duplicate seqs (HEAD) a seq cut would
// silently absorb the post-checkpoint record that reuses the checkpoint's seq,
// and with the refuted scalar cut the same record is skipped outright.
//
// RED on HEAD: assertSeqsUnique fires on the raw bytes ([1,2,2,3] — the failed
// checkpoint's seq is reused by the next mutation). If the bytes somehow
// passed, the scalar cut would drop counter 3 and the root assertion fires.
func TestSeqCutUnambiguousAfterFsyncFailure(t *testing.T) {
	nodeID := testNodeID()
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t14cut.wal")

	rec1 := exactRec(utf8EntityID(1), nodeID, 2, stagedDigest(1))
	rec2 := exactRec(utf8EntityID(2), nodeID, 3, stagedDigest(2))
	rec3 := exactRec(utf8EntityID(3), nodeID, 4, stagedDigest(3))
	ckptRoot := referenceRoot(t, nodeID, rec1)

	w := riggedFsyncWAL(t, walPath, 2)
	if err := w.AppendMutation(handMutation(rec1.EntityID, nodeID, 2, rec1.Entry.PayloadDigest)); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	// The checkpoint's fsync "fails" — the caller sees an error, but the record
	// bytes are in the stream with a consumed seq.
	if err := w.AppendCheckpoint(WALCheckpoint{MerkleRoot: ckptRoot, LamportHigh: 3}); err == nil {
		t.Fatalf("the rigged fsync failure did not surface to the caller — durability lies")
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

	// The image holds ONLY the pre-checkpoint dot (the caller believed the
	// checkpoint failed, but its bytes — and the image taken against them —
	// are what they are).
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
		t.Errorf("DOT COUNT: recovered %d != 3 — the cut lost a post-checkpoint record", got)
	}
	if got := rec.State().MerkleRoot(); got != wantRoot {
		t.Errorf("ROOT: recovered %x != reference %x", got, wantRoot)
	}
	if got := rec.LamportCounter(); got != 4 {
		t.Errorf("CLOCK: recovered %d != 4", got)
	}
}

// ---------------------------------------------------------------------------
// T15 — root-equality assertion ARMED with foreign advances present
// ---------------------------------------------------------------------------

// TestRootAssertionArmedWithForeignAdvances covers the root-equality assertion armed with foreign advances present. On HEAD
// the crash-consistency assertion is skipped whenever ANY foreign advance
// exists (`len(rep.Advances) > 0` → SCOPED) — production nodes always have
// advances, so ErrRecoveryRootMismatch structurally could never fire on
// silicon. re-arms it on the BOUNDED path (the image carries the foreign
// entries, so the rebuilt root IS comparable to the checkpoint root) while
// keeping it scoped off on the full path (the WAL holds no foreign entries).
//
// Sub-test A (control): correct anchor + advances → recovery succeeds (no
// false positive). Sub-test B (the guard): a CORRUPTED anchor + advances →
// ErrRecoveryRootMismatch. Sub-test C (scope boundary): the full path on the
// SAME corrupted log still succeeds (foreign state regossips on rejoin).
//
// RED on HEAD: sub-test B — the assertion is scoped off, recovery SUCCEEDS on
// a corrupted anchor; the test expected ErrRecoveryRootMismatch.
func TestRootAssertionArmedWithForeignAdvances(t *testing.T) {
	build := func(t *testing.T, tamperRoot bool) (walPath string, lfs *LocalFS, liveRoot [32]byte, liveDots int) {
		t.Helper()
		lfs = newSnapshotStore(t)
		walPath = filepath.Join(t.TempDir(), "t15.wal")
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
		// L1-d: the arming must be machine-observable. This shape is
		// bounded + checkpoint-final, so the POST-TAIL root assertion is exactly
		// the one that runs — and it must say so. (The anchor here is a legacy
		// 0x02, so the PRE-tail fingerprint check cannot arm; the post-tail root
		// check is the only check on this shape — proving survived Part A.)
		if !witness.PostTailRootArmed {
			t.Fatalf("witness.PostTailRootArmed=false on a bounded+final boot — the R7a re-arming did not survive the re-scope (witness=%+v)", witness)
		}
		if !witness.SeqContiguityVerified {
			t.Fatalf("witness.SeqContiguityVerified=false — the Part-B loss check must run on every boot (witness=%+v)", witness)
		}
		if got := rec.State().MerkleRoot(); got != liveRoot {
			t.Errorf("ROOT: recovered %x != live %x — false positive on an honest anchor", got, liveRoot)
		}
		if got := countDots(t, rec); got != liveDots {
			t.Errorf("DOT COUNT: recovered %d != live %d", got, liveDots)
		}
	})

	t.Run("ArmedAndFires", func(t *testing.T) {
		walPath, lfs, _, _ := build(t, true)
		_, _, _, _, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
		if err == nil {
			t.Fatalf("corrupted checkpoint anchor + foreign advances: recovery SUCCEEDED — the root assertion was SCOPED OFF by len(Advances)>0 (HEAD behavior; R7a re-arms it on the bounded path)")
		}
		if !errors.Is(err, ErrRecoveryRootMismatch) {
			t.Fatalf("want ErrRecoveryRootMismatch, got: %v", err)
		}
	})

	t.Run("FullPathStaysScoped", func(t *testing.T) {
		walPath, _, _, _ := build(t, true)
		// The WAL holds only ORIGIN records; the rebuilt root legitimately
		// differs from the origin+foreign checkpoint root. Scoped off — recovery
		// succeeds with the 5 origin dots and the foreign state regossips on
		// rejoin. This is the boundary the re-arm must NOT cross.
		rec, _ := recoverFull(t, walPath)
		if got := countDots(t, rec); got != 5 {
			t.Errorf("full path: %d dots, want 5 (origin-only)", got)
		}
	})
}
