// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// B6 — THE IMAGE/ANCHOR BINDING GUARD (ADR-0045).
//
// WHY THIS FILE EXISTS: shipped the binding check at recovery.go:266
// with NO test anywhere in the repository. Proven by injection —
// rewriting the predicate to a self-comparison
// (`img.CutSeq != img.CutSeq || img.MerkleRoot != img.MerkleRoot`, i.e. ALWAYS
// FALSE) left pkg/durability, internal/chaos, pkg/mesh, pkg/receive and
// cmd/sovereign-node fully green. A guard that cannot fail is not a guard.
//
// WHY IT IS LOAD-BEARING: ARMED the integrity verification (Blocker 2). The
// binding check is now the ONLY thing between a survivable image-write incident
// and a cluster-wide FALSE DATA-LOSS verdict, because the stale-image shape is
// reachable by construction, not by bad luck:
//
// 1. bridge.go:399 fsyncs the ANCHOR (wal.AppendCheckpoint) and only THEN, at
//:446, writes the IMAGE (SnapshotToLSM). The window between them spans a
// serialize + write + fsync + rename.
// 2. drainCheckpoints:513 LOGS AND CONTINUES when that image write fails
// ("writes are durable; the caller's ACK is unaffected"). The durable
// anchor survives; the image it names does not.
// 3. The image key ckpt/<maxLocalDot> REPEATS: drainCheckpoints runs one
// AppendCheckpoint per pending crossing with NO intervening local write.
// Measured: 80 checkpoint records over 15 distinct watermarks,
// worst repeat 66.
//
// So after a lost image write the key holds an EARLIER checkpoint's image while
// the durable anchor describes a later one. That image is STALE BUT VALID — not
// corrupt. Without the binding check the armed check compares the anchor's root
// and fingerprint against the wrong image, mismatches, and main.go:829 Fatalfs a
// node whose WAL is perfectly intact.
//
// WHY THIS GUARD JOINS A FOREIGN DELTA. Two back-to-back checkpoints with no
// intervening write describe the SAME state, so their roots and fingerprints are
// equal and a stale image is genuinely harmless — a guard built that way would
// pass with the binding deleted. A FOREIGN entry changes the state, and therefore
// the root and the fingerprint, so the two images become distinguishable.
//
// CORRECTION. An earlier version of this comment
// claimed the foreign Join is required because it moves the root "WITHOUT
// advancing maxLocalDot", i.e. that it is what makes the ckpt key REPEAT. That is
// FALSE and is not why the Join is here: `cutSeq:= b.wal.NextSeq()` advances on
// EVERY checkpoint, and the image key is derived from the watermark, so key reuse
// is governed by whether a LOCAL write intervened — not by the foreign Join. The
// Join's real and only job is to make image1 != image2 so the staleness is
// OBSERVABLE. PREMISE 1 below proves the key actually collided; PREMISE 2 proves
// the images actually differ. Neither is assumed from this prose.
//
// THE DISJUNCTION IS TOOTHED PER HALF (the rule this file initially violated).
// recovery.go:266 is
// `img.CutSeq != …CutSeq || img.MerkleRoot != …MerkleRoot`. Deleting the
// MerkleRoot half left the whole pkg/durability package GREEN — measured by
// injection — because the stale-image shape moves BOTH fields at
// once. TestHeaderRootRotBindingCatchesRootHalf below isolates the root half
// by patching ONLY the image header's root bytes, leaving CutSeq correct.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// b6CkptSoleImage asserts the ckpt/ directory holds EXACTLY ONE image and
// returns its path and bytes. Uniqueness is the premise the whole defect rests
// on: it proves the second checkpoint OVERWROTE the first at the same key
// instead of writing a new one.
func b6CkptSoleImage(t *testing.T, lfs *LocalFS) (path string, data []byte) {
	t.Helper()
	dir := filepath.Join(lfs.Root(), "ckpt")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read ckpt dir: %v", err)
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) != 1 {
		t.Fatalf("apparatus: want exactly 1 checkpoint image in %s, got %d (%v) — the key-collision premise does not hold in this configuration", dir, len(names), names)
	}
	path = filepath.Join(dir, names[0])
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read image %s: %v", path, err)
	}
	return path, data
}

// TestStaleImageBindingDisarmsNotBricks is the missing §11.5 guard.
//
// Construction (mirrors production exactly): checkpoint at state S1 → a FOREIGN
// delta arrives (state becomes S2; maxLocalDot unchanged, so the image key does
// NOT move) → checkpoint at state S2, overwriting ckpt/W in place → a local
// tail (the crash-mid-inject shape) → crash → the S2 image write is LOST
// (restore S1's bytes over the key, which is what a swallowed ENOSPC or a
// kill -9 between bridge.go:399 and:446 leaves on disk).
//
// RED (binding check absent or neutered): the anchor describes S2, the image is
// S1, the checks are ARMED ⇒ ErrRecoveryRootMismatch / ErrRecoveryFingerprint-
// Mismatch ⇒ boot REFUSED on a node whose WAL is intact. A false data-loss
// verdict, cluster-wide, from one survivable disk incident.
// GREEN: the binding detects image≠anchor, DISARMS both checks, and falls back
// to exact-WAL replay. The node boots; the foreign state re-arrives by
// anti-entropy.
func TestStaleImageBindingDisarmsNotBricks(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "b6.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)

	const preN, tailN, foreignN = 6, 3, 4

	for i := 0; i < preN; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	// Checkpoint 1 — anchor A1 describes S1; image1 lands at ckpt/W.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 1: %v", err)
	}
	imgPath, image1 := b6CkptSoleImage(t, lfs)

	// A FOREIGN delta arrives by gossip. This changes the state (and therefore
	// the root and the fingerprint) WITHOUT advancing maxLocalDot — the only way
	// the ckpt key can repeat across two DIFFERENT states.
	foreignJoinInto(t, live, 900000, foreignN)

	// Checkpoint 2 — anchor A2 describes S2 and OVERWRITES ckpt/W in place.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 2: %v", err)
	}
	imgPath2, image2 := b6CkptSoleImage(t, lfs)

	// PREMISE 1 (the key collision, proven from bytes not asserted from prose):
	// the second checkpoint must have reused the SAME key.
	if imgPath2 != imgPath {
		t.Fatalf("PREMISE BROKEN: checkpoint 2 wrote a NEW key (%s != %s) — no collision, so the stale-image shape cannot arise this way", imgPath2, imgPath)
	}
	// PREMISE 2 (the states really differ): if image1 == image2 the staleness is
	// invisible to any check and the guard would pass with the binding deleted.
	if string(image1) == string(image2) {
		t.Fatalf("PREMISE BROKEN: image1 == image2 (%d bytes) — the foreign Join did not change the checkpointed state, so this guard would be VACUOUS", len(image1))
	}

	// The local tail: the crash-mid-inject shape the silicon gate tests.
	for i := 0; i < tailN; i++ {
		if _, err := live.PutLocal(utf8EntityID(preN+i), stagedPayload(preN+i), stagedEntry(preN+i)); err != nil {
			t.Fatalf("PutLocal tail %d: %v", i, err)
		}
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// THE INCIDENT: checkpoint 2's image write is lost. The durable anchor (A2,
	// describing S2) survives; the key holds S1's image.
	if err := os.WriteFile(imgPath, image1, 0o640); err != nil {
		t.Fatalf("restore stale image: %v", err)
	}

	// PREMISE 3 (stale but VALID, not corrupt): the stale image must still
	// decode. If it did not, a decode error — not the binding — would explain
	// any survival below.
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("ReplayWAL: %v", err)
	}
	if !rep.HasCheckpoint || !rep.FinalCheckpt.HasCutSeq {
		t.Fatalf("apparatus: want a 0x05 anchor with a CutSeq on disk")
	}
	if _, err := lfs.LoadSnapshotImage(context.Background(), rep.FinalCheckpt.LamportHigh); err != nil {
		t.Fatalf("PREMISE BROKEN: the stale image must still DECODE (stale-but-valid, not corrupt): %v", err)
	}

	// THE ASSERTION.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf(`B6 RED — recovery REFUSED to boot on a STALE-BUT-VALID image: %v
 The WAL is intact. The anchor describes S2; the key holds S1's image because
 checkpoint 2's image write was lost (bridge.go:399 fsyncs the anchor BEFORE
:446 writes the image, and drainCheckpoints:513 swallows the failure). With the
 checks ARMED and no binding check, this is a FALSE DATA-LOSS verdict that
 Fatalfs a healthy node cluster-wide on one survivable disk incident.`, err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()

	// It must have fallen back for the RIGHT reason. A watermark mismatch or a
	// phantom discard would also produce a fallback while the binding sat
	// silent — the wrong-sentinel control (the B2 idiom).
	if !witness.ExactWALFallback {
		t.Fatalf("B6: witness.ExactWALFallback=false — the stale image must trigger the exact-WAL fallback (witness=%+v)", witness)
	}
	if !strings.Contains(witness.FallbackReason, "binding mismatch") {
		t.Fatalf("B6: the fallback fired for the WRONG reason — want the image/anchor BINDING, got %q. A watermark/phantom fallback would mask a dead binding check.", witness.FallbackReason)
	}
	if witness.Bounded {
		t.Fatalf("B6: witness.Bounded=true — the stale image must be DISCARDED, not used (witness=%+v)", witness)
	}
	// The whole point of §11.5: DISARM, do not brick.
	if witness.IntegrityChecksArmed {
		t.Fatalf("B6: witness.IntegrityChecksArmed=true on a discarded image — the checks must DISARM when the binding fails, or they judge state the anchor never described")
	}
	// The WAL is the truth: every LOCAL entity must be back.
	state := engine.State()
	for i := 0; i < preN+tailN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("B6: local entity %d missing after exact-WAL fallback — the WAL is the truth and it recorded every local mutation", i)
		}
	}
	// MEASURE the foreign absence rather than printing the constant that was fed
	// in. An earlier version of this log printed foreignN, which asserts nothing:
	// it would read identically if every foreign entry had survived.
	foreignPresent := 0
	for i := 0; i < foreignN; i++ {
		if len(state.Get(utf8EntityID(5000+i))) > 0 {
			foreignPresent++
		}
	}
	if foreignPresent != 0 {
		t.Fatalf("B6: %d/%d foreign entities survived an exact-WAL replay — the WAL records only LOCAL mutations, so foreign state cannot come back this way; the image was not actually discarded", foreignPresent, foreignN)
	}
	t.Logf("B6 GREEN: stale-but-valid image DISARMED the checks and fell back to exact-WAL (%s); %d/%d local entities restored; %d/%d foreign entries measured absent (they re-arrive by anti-entropy)",
		witness.FallbackReason, preN+tailN, preN+tailN, foreignN-foreignPresent, foreignN)
}

// TestHeaderRootRotBindingCatchesRootHalf tooths the SECOND half of the
// recovery.go:266 disjunction in isolation.
//
// WHY IT IS NEEDED: deleting the `img.MerkleRoot !=
// rep.FinalCheckpt.MerkleRoot` half of the binding leaves the entire
// pkg/durability package GREEN — including TestB6 above (measured by injection). The stale-image shape
// moves CutSeq and MerkleRoot together, so the CutSeq half alone catches it and
// the root half is dead weight no test can distinguish from a correct guard. The
// rule is that each half of a disjunctive guard gets its own
// guard; this file initially violated it.
//
// THE SHAPE: the image is the CORRECT one for the anchor — same CutSeq — but its
// header's 32 root bytes have rotted. `cutSeq:= b.wal.NextSeq()` advances on
// every checkpoint, so a same-CutSeq/different-root image cannot arise from
// ordinary checkpoint sequencing; it arises from BIT ROT, and the snapshot format
// has NO checksum of any kind (pkg/durability/snapshot.go carries zero
// crc/checksum/adler references), so the header root is the
// only thing standing between a rotted image and the recovery path. Patching the
// bytes directly is therefore modelling the real threat, not manufacturing one.
func TestHeaderRootRotBindingCatchesRootHalf(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "b6rot.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)

	const preN, tailN = 6, 3

	for i := 0; i < preN; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	// A recorded 0x03 keeps the recovery.go:649 post-tail assertion DISARMED, so
	// this guard isolates the:266 binding and cannot be confused with.
	foreignJoinInto(t, live, 900000, 4)
	for i := 0; i < tailN; i++ {
		if _, err := live.PutLocal(utf8EntityID(preN+i), stagedPayload(preN+i), stagedEntry(preN+i)); err != nil {
			t.Fatalf("PutLocal tail %d: %v", i, err)
		}
	}
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	imgPath, image := b6CkptSoleImage(t, lfs)

	// (C3): the production image is now v3 (whole-image CRC32C trailer).
	// A v3 header-root rot is caught by the CRC at DECODE (that is T4's guard) and
	// never reaches the binding check. THIS guard proves the BINDING's MerkleRoot
	// half catches a root mismatch — so it must run on the UNPROTECTED legacy v2
	// format (no CRC), where the rotted root still decodes and the binding is the
	// exercised defense. Downgrade: strip the 4-byte CRC trailer, set version=2.
	// (The v3 rot→CRC→fallback path is covered by the new snapshot integrity guards.)
	if len(image) >= 5 && image[4] == snapshotVersionV3 {
		image = append([]byte(nil), image[:len(image)-4]...) // strip the CRC trailer
		image[4] = snapshotVersionV2
	}

	// The snapshot v2 header (snapshot.go, encodeSnapshotImage): magic[0:4]
	// version[4] lamportHigh[5:13] recordCount[13:21] cutSeq[21:29]
	// merkleRoot[29:61]. Patch ONLY the root. CutSeq is left byte-identical, so
	// the first half of the disjunction CANNOT fire and only the root half can
	// catch this.
	const rootOff, rootEnd, cutSeqOff, cutSeqEnd = 29, 61, 21, 29
	if len(image) < rootEnd {
		t.Fatalf("apparatus: image is %d bytes, shorter than the %d-byte v2 header", len(image), rootEnd)
	}
	rotted := append([]byte(nil), image...)
	for i := rootOff; i < rootEnd; i++ {
		rotted[i] ^= 0xFF
	}
	// PREMISE: exactly the root moved. If CutSeq also changed, the CutSeq half
	// would fire and this guard would be a duplicate of TestB6 above.
	if string(rotted[cutSeqOff:cutSeqEnd]) != string(image[cutSeqOff:cutSeqEnd]) {
		t.Fatalf("PREMISE BROKEN: CutSeq bytes changed — this guard must isolate the ROOT half")
	}
	if string(rotted[rootOff:rootEnd]) == string(image[rootOff:rootEnd]) {
		t.Fatalf("PREMISE BROKEN: the root bytes did not change — nothing was rotted")
	}
	if err := os.WriteFile(imgPath, rotted, 0o640); err != nil {
		t.Fatalf("write rotted image: %v", err)
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf(`B6-rot RED — a header-root-rotted image REFUSED the boot instead of disarming: %v
 The WAL is intact and the anchor is durable. A rotted image must be DISCARDED
 (exact-WAL fallback), never treated as a data-loss verdict.`, err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()

	if witness == nil {
		t.Fatalf("B6-rot: nil witness on a successful boot")
	}
	if !witness.ExactWALFallback {
		t.Fatalf("B6-rot: witness.ExactWALFallback=false — a rotted header root must be caught by the:266 binding's MerkleRoot half and force the fallback (witness=%+v)", witness)
	}
	if !strings.Contains(witness.FallbackReason, "binding mismatch") {
		t.Fatalf("B6-rot: fallback fired for the WRONG reason — want the image/anchor BINDING, got %q. If this says anything else, the MerkleRoot half is still untoothed.", witness.FallbackReason)
	}
	if witness.Bounded {
		t.Fatalf("B6-rot: witness.Bounded=true — a rotted image must not be used (witness=%+v)", witness)
	}
	if witness.IntegrityChecksArmed {
		t.Fatalf("B6-rot: witness.IntegrityChecksArmed=true on a discarded image")
	}
	state := engine.State()
	for i := 0; i < preN+tailN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("B6-rot: local entity %d missing after exact-WAL fallback", i)
		}
	}
	t.Logf("B6-rot GREEN: header root rot (CutSeq byte-identical) caught by the binding's MerkleRoot half ⇒ %q; %d/%d local entities restored",
		witness.FallbackReason, preN+tailN, preN+tailN)
}

// TestControlBindingMatchesOracleArmed is the falsifiability control for
// the guard above. IDENTICAL construction, minus the lost image write. The
// binding matches, so the image is USED and the checks must ARM and PASS. If
// this test failed, B6's green would prove only that the check is off
// everywhere; if this test passed while B6's assertions were deleted, the
// binding would be untested again.
func TestControlBindingMatchesOracleArmed(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "b6ctl.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, true)

	const preN, tailN, foreignN = 6, 3, 4

	for i := 0; i < preN; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal pre %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 1: %v", err)
	}
	foreignJoinInto(t, live, 900000, foreignN)
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 2: %v", err)
	}
	for i := 0; i < tailN; i++ {
		if _, err := live.PutLocal(utf8EntityID(preN+i), stagedPayload(preN+i), stagedEntry(preN+i)); err != nil {
			t.Fatalf("PutLocal tail %d: %v", i, err)
		}
	}
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("B6 control: an INTACT image/anchor pair must boot: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()

	if witness.ExactWALFallback {
		t.Fatalf("B6 control: witness.ExactWALFallback=true on a MATCHING binding — the image must be used (reason=%q)", witness.FallbackReason)
	}
	if !witness.Bounded {
		t.Fatalf("B6 control: witness.Bounded=false — a matching binding must take the bounded/image path (witness=%+v)", witness)
	}
	if !witness.IntegrityChecksArmed {
		t.Fatalf("B6 control: witness.IntegrityChecksArmed=false — with a matching binding, a fingerprint on the anchor and nothing skipped, the checks MUST arm; otherwise B6's green proves only that the check is off everywhere")
	}
	// L1-d (the other direction): this control has a post-checkpoint
	// TAIL, so the POST-tail root assertion must NOT have armed (the checkpoint
	// does not pin the final root) — while the PRE-tail checks did. If both
	// were ever observed armed/unarmed together on every shape, one of them is
	// not load-bearing.
	if witness.PostTailRootArmed {
		t.Fatalf("B6 control: witness.PostTailRootArmed=true with a post-checkpoint tail (checkpointFinal=false) — the post-tail assertion must NOT arm when the anchor does not pin the final root (witness=%+v)", witness)
	}
	// The bounded path carries the foreign dots in the image, so the recovered
	// root must equal the FULL live root — foreign entries included.
	if got := engine.State().MerkleRoot(); got != liveRoot {
		t.Fatalf("B6 control: recovered root %x != live %x — the bound image + tail must rebuild the live state exactly", got, liveRoot)
	}
	t.Logf("B6 control GREEN: matching binding ⇒ image used, checks ARMED, root re-equals the live root")
}
