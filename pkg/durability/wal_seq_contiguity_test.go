// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Tests for WAL sequence contiguity and root-check scoping (ADR-0045 §4).
//
// The post-tail root comparison runs only on the bounded path because replay
// without an image cannot reconstruct foreign entries. Sequence contiguity
// checks every path instead: an append consumes its sequence number only after
// writing the record, and OpenWAL truncates only a torn tail. A gap in a
// complete log therefore indicates a missing record. Unlike a Merkle root,
// contiguity also covers clock advances and checkpoints.

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// walRecordSpans walks a WAL file and returns each record's (seq, fileOff,
// totalLen) — the byte-map the hole-punch and renumber injections need.
func walRecordSpans(t *testing.T, walPath string) (hdrOff []int, seqs []uint64, data []byte) {
	t.Helper()
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	if len(data) < 8 {
		t.Fatalf("apparatus: WAL too short")
	}
	off := 8
	for off+13 <= len(data) {
		payloadLen := int(binary.BigEndian.Uint32(data[off+9 : off+13]))
		if off+13+payloadLen > len(data) {
			break
		}
		hdrOff = append(hdrOff, off)
		seqs = append(seqs, binary.BigEndian.Uint64(data[off:off+8]))
		off += 13 + payloadLen
	}
	return hdrOff, seqs, data
}

// TestSeqContiguityHoleRefused deletes a complete record from the middle of a
// log. Recovery must report ErrWALSeqGap with the expected and observed sequence
// numbers before building state.
func TestSeqContiguityHoleRefused(t *testing.T) {
	walPath := buildPlainLog(t, 6) // seqs 0..5 mutations, 6 = checkpoint

	offs, seqs, data := walRecordSpans(t, walPath)
	if len(offs) != 7 {
		t.Fatalf("apparatus: want 7 records, got %d", len(offs))
	}
	// Splice out record index 3 (seq 3) entirely: [0,off3) ++ [off4, end).
	start, end := offs[3], offs[4]
	punched := append([]byte(nil), data[:start]...)
	punched = append(punched, data[end:]...)
	if err := os.WriteFile(walPath, punched, 0o644); err != nil {
		t.Fatalf("write punched WAL: %v", err)
	}
	// Prove the injection APPLIED: the file shrank by exactly record 3's length.
	if len(punched) != len(data)-(end-start) {
		t.Fatalf("injection did not apply: len %d, want %d", len(punched), len(data)-(end-start))
	}
	_ = seqs

	_, _, _, _, err := RecoverEngineWithSnapshot(testNodeID(), walPath, nil, testArenaSize)
	if err == nil {
		t.Fatalf("recovery accepted a WAL with record 3 deleted")
	}
	if !errors.Is(err, ErrWALSeqGap) {
		t.Fatalf("want ErrWALSeqGap, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected seq 3") || !strings.Contains(err.Error(), "observed 4") {
		t.Fatalf("the error must name expected and observed seqs, got: %v", err)
	}
	t.Logf("deleting record 3 refused boot: %v", err)
}

// TestSeqContiguityRenumberRefused changes one sequence number without removing
// bytes. The same contiguity check must reject the log, so detection does not
// depend on a change in file length.
func TestSeqContiguityRenumberRefused(t *testing.T) {
	walPath := buildPlainLog(t, 6)
	offs, _, data := walRecordSpans(t, walPath)
	if len(offs) != 7 {
		t.Fatalf("apparatus: want 7 records, got %d", len(offs))
	}
	// Renumber record 3's seq 3 -> 42. The run reads 0,1,2,42 -> gap at #4.
	binary.BigEndian.PutUint64(data[offs[3]:offs[3]+8], 42)
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write renumbered WAL: %v", err)
	}
	_, _, _, _, err := RecoverEngineWithSnapshot(testNodeID(), walPath, nil, testArenaSize)
	if err == nil || !errors.Is(err, ErrWALSeqGap) {
		t.Fatalf("renumber: want ErrWALSeqGap, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected seq 3") || !strings.Contains(err.Error(), "observed 42") {
		t.Fatalf("renumber: error must name expected=3 observed=42, got: %v", err)
	}
	t.Logf("renumbering record 3 to 42 refused boot: %v", err)
}

// buildPlainLog writes n local mutations + one checkpoint, no snapshotter,
// no foreign state — the clean control log (boots on every path).
func buildPlainLog(t *testing.T, n int) string {
	t.Helper()
	walPath := t.TempDir() + "/plain.wal"
	live := newLiveBridge(t, walPath, 0)
	for i := 0; i < n; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}
	return walPath
}

// TestSeqContiguityCleanLogBoots verifies that an intact log boots and that the
// witness records the number of records checked. On the store==nil path, the
// post-tail root comparison must remain disabled.
func TestSeqContiguityCleanLogBoots(t *testing.T) {
	walPath := buildPlainLog(t, 6)
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, nil, testArenaSize)
	if err != nil {
		t.Fatalf("clean log refused: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if !witness.SeqContiguityVerified || witness.RecordsVerified != 7 {
		t.Fatalf("SeqContiguityVerified = %v, RecordsVerified = %d; want true and 7", witness.SeqContiguityVerified, witness.RecordsVerified)
	}
	if witness.PostTailRootArmed {
		t.Fatalf("post-tail root check armed on the store==nil path: %+v", witness)
	}
	t.Logf("intact log booted after verifying 7 records; post-tail root check disabled")
}

// TestSeqContiguityReplayCost measures sequence verification while replaying
// 10,000 records. The cost is logged rather than asserted because contiguity
// adds one comparison to a loop that already parses every record header.
func TestSeqContiguityReplayCost(t *testing.T) {
	const n = 10_000
	walPath := t.TempDir() + "/cost.wal"
	live := newLiveBridge(t, walPath, 0)
	for i := 0; i < n; i += 1000 {
		ms := make([]WALMutation, 0, 1000)
		for j := 0; j < 1000; j++ {
			dot := live.Engine().InsertLocal(utf8EntityID(i+j), stagedEntry(i+j))
			ms = append(ms, NewWALMutation(utf8EntityID(i+j), dot, stagedEntry(i+j)))
		}
		if _, err := live.WAL().AppendMutations(ms); err != nil {
			t.Fatalf("AppendMutations: %v", err)
		}
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}
	start := time.Now()
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	d := time.Since(start)
	if !rep.SeqContiguityVerified || rep.RecordsVerified != n {
		t.Fatalf("want %d verified records, got %d (verified=%v)", n, rep.RecordsVerified, rep.SeqContiguityVerified)
	}
	t.Logf("replayed and verified %d records in %s (%.1f ns/record)", rep.RecordsVerified, d, float64(d.Nanoseconds())/float64(rep.RecordsVerified))
}

// TestPartAOracleMovedNotVanished removes an image whose checkpoint includes
// foreign state and no clock-advance records. The intact WAL must boot, the
// invalid post-tail root comparison must stay disabled, and sequence contiguity
// must still be checked.
func TestPartAOracleMovedNotVanished(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := t.TempDir() + "/l1b.wal"
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)
	const localN, foreignN = 6, 4
	for i := 0; i < localN; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	foreignJoinNoAdvance(t, live, 900000, foreignN)
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}
	// Degrade: remove the image (the lost image write).
	dir := lfs.Root() + "/ckpt"
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read ckpt dir: %v", err)
	}
	removed := 0
	for _, e := range ents {
		if !e.IsDir() {
			if err := os.Remove(dir + "/" + e.Name()); err != nil {
				t.Fatalf("remove image: %v", err)
			}
			removed++
		}
	}
	if removed == 0 {
		t.Fatalf("test requires a checkpoint image to remove")
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("intact WAL refused: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if !witness.ExactWALFallback {
		t.Fatalf("ExactWALFallback is false after image loss: %+v", witness)
	}
	if witness.PostTailRootArmed {
		t.Fatalf("post-tail root check armed on replay-only recovery: %+v", witness)
	}
	if !witness.SeqContiguityVerified || witness.RecordsVerified != 7 {
		t.Fatalf("SeqContiguityVerified = %v, RecordsVerified = %d; want true and 7", witness.SeqContiguityVerified, witness.RecordsVerified)
	}
	if witness.IntegrityChecksArmed {
		t.Fatalf("pre-tail integrity checks armed after the image was discarded: %+v", witness)
	}
	t.Logf("boot succeeded; post-tail root check disabled and 7 WAL records verified")
}

// TestStoreNilForeignStateBoots covers full replay when the final checkpoint
// includes foreign state but the WAL has no clock-advance records. The local
// mutations and checkpoint ClockHigh are sufficient to boot. Comparing the
// origin-only rebuilt root with the checkpoint root would be invalid, so
// PostTailRootArmed must be false while sequence verification still runs.
func TestStoreNilForeignStateBoots(t *testing.T) {
	walPath := t.TempDir() + "/l1e.wal"
	live := newLiveBridge(t, walPath, 0) // no snapshotter — store == nil at recovery
	const localN, foreignN = 6, 4
	for i := 0; i < localN; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	foreignJoinNoAdvance(t, live, 900000, foreignN) // foreign state, no 0x03
	liveClock := live.Engine().LamportCounter()
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, nil, testArenaSize)
	if err != nil {
		t.Fatalf("store==nil full replay refused an intact WAL: %v; its checkpoint folded %d foreign entries", err, foreignN)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if witness.Bounded || witness.ExactWALFallback {
		t.Fatalf("store==nil recovery is neither bounded nor a fallback: %+v", witness)
	}
	if witness.PostTailRootArmed {
		t.Fatalf("post-tail root check armed on the store==nil path")
	}
	if !witness.SeqContiguityVerified || witness.RecordsVerified != 7 {
		t.Fatalf("sequence verification = %v over %d records, want true over 7", witness.SeqContiguityVerified, witness.RecordsVerified)
	}
	if got := engine.LamportCounter(); got != liveClock {
		t.Fatalf("recovered clock = %d, want checkpoint ClockHigh %d", got, liveClock)
	}
	state := engine.State()
	for i := 0; i < localN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("local entity %d missing", i)
		}
	}
	t.Logf("store==nil recovery resumed checkpoint ClockHigh %d and restored %d local entries", liveClock, localN)
}

// TestNoTailBackToBackCheckpointBoots writes two checkpoints without an
// intervening local mutation, so both images use the same key. Restoring the
// first image after the second checkpoint simulates a lost image write. Its
// state and root are current, but its older CutSeq fails the anchor binding.
// Recovery must fall back to the intact WAL and skip the invalid post-tail root
// comparison while still checking sequence contiguity.
func TestNoTailBackToBackCheckpointBoots(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := t.TempDir() + "/l1g.wal"
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)
	const localN, foreignN = 6, 1
	for i := 0; i < localN; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	foreignJoinNoAdvance(t, live, 900000, foreignN) // foreign state, no 0x03
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 1: %v", err)
	}
	imgPath, image1 := soleCheckpointImage(t, lfs)
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 2: %v", err)
	}
	imgPath2, image2 := soleCheckpointImage(t, lfs)
	// No local write between checkpoints means maxLocalDot, and therefore the
	// snapshot key, does not change.
	if imgPath != imgPath2 {
		t.Fatalf("checkpoint image keys differ: %s and %s", imgPath, imgPath2)
	}
	// CutSeq occupies bytes [21:29] and the root [29:61]. With no intervening
	// writes, only CutSeq may advance between the images.
	if len(image1) != len(image2) || len(image1) < 61 {
		t.Fatalf("checkpoint image sizes are %d and %d", len(image1), len(image2))
	}
	if string(image1[29:61]) != string(image2[29:61]) {
		t.Fatalf("checkpoint roots differ despite no writes between checkpoints")
	}
	if string(image1[21:29]) == string(image2[21:29]) {
		t.Fatalf("CutSeq did not advance between checkpoints")
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}

	// The incident: checkpoint 2's image write is lost — the key retains
	// image1 (same state, older CutSeq).
	if err := os.WriteFile(imgPath, image1, 0o640); err != nil {
		t.Fatalf("restore image1: %v", err)
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("recovery with a state-identical image whose CutSeq is older than the final checkpoint failed: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if !witness.ExactWALFallback {
		t.Fatalf("CutSeq-stale image did not trigger exact-WAL fallback: %+v", witness)
	}
	if !strings.Contains(witness.FallbackReason, "binding mismatch") {
		t.Fatalf("fallback reason %q does not identify the CutSeq binding mismatch", witness.FallbackReason)
	}
	if witness.PostTailRootArmed {
		t.Fatalf("post-tail root check armed on replay-only fallback")
	}
	if !witness.SeqContiguityVerified {
		t.Fatalf("WAL sequence contiguity was not verified")
	}
	state := engine.State()
	for i := 0; i < localN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("local entity %d missing", i)
		}
	}
	t.Logf("back-to-back checkpoint recovery used exact-WAL fallback and verified sequence contiguity")
}
