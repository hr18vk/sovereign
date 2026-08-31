// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// — Part B guards: the WAL seq-contiguity check, plus the
// L1-b/L1-e/L1-g arming-observability guards for Part A.
//
// WHY SEQ CONTIGUITY IS THE REPLACEMENT ORACLE (ADR-0045). Part A
// scoped the post-tail root assertion to the bounded path — the only place its
// comparand is valid. That REMOVED the only check that ran on the replay-only
// path. The replacement is WAL seq contiguity: every record's seq is consumed
// only AFTER its bytes are in the file (advance-as-you-write, wal.go §— a
// failed Write returns before nextSeq++; a failed fsync never unconsumes), and
// the only Truncate is OpenWAL's torn-TAIL repair, so a gap in the observed
// seqs cannot be produced by any normal or failing append — a gap means a
// record is genuinely GONE. Strictly stronger than what was removed: the root
// folded only dots; contiguity detects the loss of ANY record type (0x03
// advances and 0x05 checkpoints included). Zero format change: the seq was
// already written and already parsed; nothing consumed it for integrity.

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

// TestSeqContiguityHoleRefused is the L1-c guard, variant 1: a record's
// bytes are DELETED from the middle of the log (the record-loss class Part B
// exists to catch). Recovery must REFUSE with ErrWALSeqGap naming the expected
// and observed seq — and must do so BEFORE building any state.
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
		t.Fatalf("L1-c RED-EXPECTATION INVERTED: a WAL with record 3 deleted BOOTED — Part B is not biting (the record-loss hole is silent)")
	}
	if !errors.Is(err, ErrWALSeqGap) {
		t.Fatalf("L1-c: want ErrWALSeqGap, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected seq 3") || !strings.Contains(err.Error(), "observed 4") {
		t.Fatalf("L1-c: the error must name expected AND observed seqs, got: %v", err)
	}
	t.Logf("L1-c GREEN (delete variant): punched record 3 -> boot REFUSED: %v", err)
}

// TestSeqContiguityRenumberRefused is the L1-c guard, variant 2: one
// record's seq field is renumbered (no bytes removed). Same check, same
// refusal — the check is on the seq RUN, not the file length.
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
		t.Fatalf("L1-c renumber: want ErrWALSeqGap, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected seq 3") || !strings.Contains(err.Error(), "observed 42") {
		t.Fatalf("L1-c renumber: error must name expected=3 observed=42, got: %v", err)
	}
	t.Logf("L1-c GREEN (renumber variant): record 3 renumbered to 42 -> boot REFUSED: %v", err)
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

// TestSeqContiguityCleanLogBoots is the no-false-positive control: the
// check runs on every boot; on an intact log it must VERIFY, never fire, and
// the witness must carry the proof (SeqContiguityVerified + the record count).
func TestSeqContiguityCleanLogBoots(t *testing.T) {
	walPath := buildPlainLog(t, 6)
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, nil, testArenaSize)
	if err != nil {
		t.Fatalf("clean log refused: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if !witness.SeqContiguityVerified || witness.RecordsVerified != 7 {
		t.Fatalf("witness must prove the check RAN: SeqContiguityVerified=%v RecordsVerified=%d, want true/7", witness.SeqContiguityVerified, witness.RecordsVerified)
	}
	if witness.PostTailRootArmed {
		t.Fatalf("store==nil path must NOT arm the post-tail root check (Part A) — witness=%+v", witness)
	}
	t.Logf("L1-c control GREEN: intact log boots, check verified 7 records, post-tail root correctly OFF on the replay-only path")
}

// TestSeqContiguityReplayCost measures the check's price on a
// >=10,000-record log: one comparison per record on a path that
// already parses every header. The number is reported, not asserted.
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
	t.Logf("REPLAY COST: %d records replayed+verified in %s (%.1f ns/record) — the contiguity check is one compare per record on the existing parse path", rep.RecordsVerified, d, float64(d.Nanoseconds())/float64(rep.RecordsVerified))
}

// TestPartAOracleMovedNotVanished is L1-b: on the shape (intact WAL,
// lost image, foreign state folded into the anchor, zero 0x03 records) the
// boot must succeed AND the witness must prove the post-tail root check was
// SCOPED OFF (PostTailRootArmed=false) while the seq-contiguity check RAN
// (SeqContiguityVerified=true). Part A is a SCOPING, not a blanket disarm.
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
		t.Fatalf("PREMISE BROKEN: no image to degrade")
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("L1-b: the brick is present — intact WAL refused: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if !witness.ExactWALFallback {
		t.Fatalf("L1-b: want ExactWALFallback=true (the image was lost), witness=%+v", witness)
	}
	if witness.PostTailRootArmed {
		t.Fatalf("L1-b: PostTailRootArmed=true on a replay-only path — Part A did not scope the assertion off (witness=%+v)", witness)
	}
	if !witness.SeqContiguityVerified || witness.RecordsVerified != 7 {
		t.Fatalf("L1-b: the replacement check did not run: SeqContiguityVerified=%v RecordsVerified=%d, want true/7", witness.SeqContiguityVerified, witness.RecordsVerified)
	}
	if witness.IntegrityChecksArmed {
		t.Fatalf("L1-b: IntegrityChecksArmed=true with the image discarded — the pre-tail check must disarm on a fallback (witness=%+v)", witness)
	}
	t.Logf("L1-b GREEN: boot ok; post-tail root SCOPED OFF; seq contiguity VERIFIED over 7 records — the check MOVED, it did not vanish")
}

// TestStoreNilForeignStateBoots is L1-e (the PROBE-7 shape): store == nil,
// foreign state folded into the anchor, zero 0x03 records, checkpoint final.
// It previously bricked with ErrRecoveryRootMismatch. Now it must boot,
// restore every local mutation, keep the ClockHigh nail (the foreign Join's
// clock raise is covered by the checkpoint's ClockHigh even with no 0x03), and
// report the scoping in the witness.
func TestStoreNilForeignStateBoots(t *testing.T) {
	walPath := t.TempDir() + "/l1e.wal"
	live := newLiveBridge(t, walPath, 0) // NO snapshotter — store == nil at recovery
	const localN, foreignN = 6, 4
	for i := 0; i < localN; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	foreignJoinNoAdvance(t, live, 900000, foreignN) // foreign state, NO 0x03
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
		t.Fatalf(`L1-e: store==nil full replay REFUSED an intact WAL: %v
 The WAL records only local mutations; the anchor folded %d foreign entries.
 Previously the len(rep.Advances)==0 disjunct armed the post-tail root check
 with an unsatisfiable comparand — the brick with no image involved at all.`, err, foreignN)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if witness.Bounded || witness.ExactWALFallback {
		t.Fatalf("L1-e: store==nil is neither bounded nor a fallback (witness=%+v)", witness)
	}
	if witness.PostTailRootArmed {
		t.Fatalf("L1-e: PostTailRootArmed=true on the store==nil path — it is not closed")
	}
	if !witness.SeqContiguityVerified || witness.RecordsVerified != 7 {
		t.Fatalf("L1-e: seq check did not run: %v/%d", witness.SeqContiguityVerified, witness.RecordsVerified)
	}
	if got := engine.LamportCounter(); got != liveClock {
		t.Fatalf("L1-e: recovered clock %d != live %d — the ClockHigh nail failed with no 0x03 record", got, liveClock)
	}
	state := engine.State()
	for i := 0; i < localN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("L1-e: local entity %d missing", i)
		}
	}
	t.Logf("L1-e GREEN: store==nil boot on a foreign-state-bearing intact WAL; clock nailed to %d via ClockHigh; %d locals restored", liveClock, localN)
}

// TestNoTailBackToBackCheckpointBoots is L1-g — the shape, the
// B6 guard's blind spot: 6 local writes -> a foreign entry
// Joined with NO 0x03 -> TWO back-to-back checkpoints sharing ckpt/<wm> with no
// writes between -> checkpoint 2's image write LOST (the key keeps image1).
// There is NO tail after checkpoint 2, so checkpointFinal == true and the
// pre-post-tail assertion ARMED on the replay-only fallback path.
//
// The images are SEMANTICALLY IDENTICAL (same state, same root, same
// fingerprint) and differ only in the CutSeq header field, which advances on
// every checkpoint by construction — so the §11.5 binding discards image1 as
// "stale" and the boot then bricked on the intact WAL (measured
// differential: binding ENABLED -> REFUSED; NEUTERED -> BOOTED). Part A must
// make this boot. The binding ITSELF is not fixed here (CutSeq is load-bearing
// for the tail cut; the sound repair — bind the tail cut to the image's OWN
// CutSeq — is a known, deferred gap).
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
	foreignJoinNoAdvance(t, live, 900000, foreignN) // foreign state, NO 0x03
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 1: %v", err)
	}
	imgPath, image1 := b6CkptSoleImage(t, lfs)
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 2: %v", err)
	}
	imgPath2, image2 := b6CkptSoleImage(t, lfs)
	// PREMISE 1: the key repeated (no local write between the checkpoints, so
	// maxLocalDot did not move).
	if imgPath != imgPath2 {
		t.Fatalf("PREMISE BROKEN: two distinct keys %s / %s — the back-to-back shape did not arise", imgPath, imgPath2)
	}
	// PREMISE 2: the images differ ONLY in the CutSeq header field — the
	// snapshot v2 header layout is magic[0:4] version[4] lamportHigh[5:13]
	// recordCount[13:21] cutSeq[21:29] merkleRoot[29:61] (B6-rot's map).
	if len(image1) != len(image2) || len(image1) < 61 {
		t.Fatalf("PREMISE BROKEN: image sizes %d / %d", len(image1), len(image2))
	}
	if string(image1[29:61]) != string(image2[29:61]) {
		t.Fatalf("PREMISE BROKEN: the two images' ROOTS differ — they must be semantically identical (no writes between the checkpoints)")
	}
	if string(image1[21:29]) == string(image2[21:29]) {
		t.Fatalf("PREMISE BROKEN: CutSeq did not advance between the two checkpoints — the binding would not fire and the guard is vacuous")
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("engine close: %v", err)
	}

	// THE INCIDENT: checkpoint 2's image write is lost — the key retains
	// image1 (same state, older CutSeq).
	if err := os.WriteFile(imgPath, image1, 0o640); err != nil {
		t.Fatalf("restore image1: %v", err)
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf(`L1-g: the NO-TAIL back-to-back shape REFUSED an intact WAL: %v
 image1 is semantically identical to the anchor's state (same root); only its
 CutSeq header field is older. Previously the binding discarded it and the
 armed post-tail root check (checkpointFinal=true, advances=0) bricked the
 node — the route into the brick, on the commonest checkpoint shape.`, err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if !witness.ExactWALFallback {
		t.Fatalf("L1-g: the CutSeq-stale (but state-identical) image must trigger the binding fallback (witness=%+v)", witness)
	}
	if !strings.Contains(witness.FallbackReason, "binding mismatch") {
		t.Fatalf("L1-g: fallback for the WRONG reason %q — the CutSeq half of the binding must be what fired", witness.FallbackReason)
	}
	if witness.PostTailRootArmed {
		t.Fatalf("L1-g: PostTailRootArmed=true on a replay-only fallback — the route into the brick is still armed")
	}
	if !witness.SeqContiguityVerified {
		t.Fatalf("L1-g: seq check did not run")
	}
	state := engine.State()
	for i := 0; i < localN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("L1-g: local entity %d missing", i)
		}
	}
	t.Logf("L1-g GREEN: no-tail back-to-back shape boots (binding discarded the CutSeq-stale image; post-tail root scoped off; seq contiguity verified)")
}
