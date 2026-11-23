// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Image-to-anchor binding tests. A checkpoint anchor is synced before its
// image is serialized and written, and drainCheckpoints logs an image-write
// failure without failing the caller. If that write is lost, the image key can
// retain an earlier valid image while the anchor describes a later state.
//
// Comparing that image with the new anchor would produce a false integrity
// failure even though the WAL is intact. The binding check instead discards the
// image and replays the WAL. Repeated checkpoints can reuse ckpt/<maxLocalDot>
// when no local write advances the watermark, so the fixtures verify both key
// reuse and a real state change rather than assuming either.
//
// The two binding comparisons need separate coverage. The stale-image fixture
// changes CutSeq and MerkleRoot together; TestHeaderRootRotBindingCatchesRootHalf
// changes only the root and leaves CutSeq intact.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// soleCheckpointImage returns the only image under ckpt/ and fails if the
// directory holds zero or multiple images. Uniqueness proves that the second
// checkpoint replaced the first at the same key instead of writing another.
func soleCheckpointImage(t *testing.T, lfs *LocalFS) (path string, data []byte) {
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

// TestStaleImageBindingDisarmsNotBricks restores the first image after two
// checkpoints have reused its key for different states. A foreign delta makes
// those states distinct without advancing maxLocalDot, and a local tail follows
// the second checkpoint.
//
// The anchor describes the second state while the key holds the first. Recovery
// must report a binding mismatch, discard the image, disarm its integrity
// checks, and rebuild every local write from the intact WAL. Foreign entries are
// absent until anti-entropy supplies them again.
func TestStaleImageBindingDisarmsNotBricks(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "stale-image.wal")
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
	imgPath, image1 := soleCheckpointImage(t, lfs)

	// The foreign delta changes the root and fingerprint without advancing
	// maxLocalDot, so the next checkpoint reuses the key for a different state.
	foreignJoinInto(t, live, 900000, foreignN)

	// Checkpoint 2 — anchor A2 describes S2 and OVERWRITES ckpt/W in place.
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint 2: %v", err)
	}
	imgPath2, image2 := soleCheckpointImage(t, lfs)

	// Premise 1 (the key collision, proven from bytes): the second checkpoint
	// must have reused the same key.
	if imgPath2 != imgPath {
		t.Fatalf("premise broken: checkpoint 2 wrote a new key (%s != %s) — no collision, so the stale-image shape cannot arise this way", imgPath2, imgPath)
	}
	// Premise 2 (the states really differ): if image1 == image2 the staleness
	// is invisible to any oracle and the test would pass with the binding
	// deleted.
	if string(image1) == string(image2) {
		t.Fatalf("premise broken: image1 == image2 (%d bytes) — the foreign Join did not change the checkpointed state, so this test would pass without the binding", len(image1))
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

	// The incident: checkpoint 2's image write is lost. The durable anchor (A2,
	// describing S2) survives; the key holds S1's image.
	if err := os.WriteFile(imgPath, image1, 0o640); err != nil {
		t.Fatalf("restore stale image: %v", err)
	}

	// Premise 3 (stale but valid, not corrupt): the stale image must still
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
		t.Fatalf("premise broken: the stale image must still decode (stale-but-valid, not corrupt): %v", err)
	}

	// The assertion.
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf(`recovery refused to boot on a stale-but-valid image: %v
  The WAL is intact. The anchor describes S2; the key holds S1's image because
  checkpoint 2's image write was lost (the anchor fsync happens before the
  image write, and drainCheckpoints swallows the failure). With the
  oracles armed and no binding check, this is a false data-loss verdict that
  refuses a healthy node cluster-wide on one survivable disk incident.`, err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()

	// Check the fallback reason so a watermark mismatch or phantom rejection
	// cannot masquerade as a successful binding check.
	if !witness.ExactWALFallback {
		t.Fatalf("witness.ExactWALFallback=false — the stale image must trigger the exact-WAL fallback (witness=%+v)", witness)
	}
	if !strings.Contains(witness.FallbackReason, "binding mismatch") {
		t.Fatalf("the fallback fired for the wrong reason — want the image/anchor binding, got %q. A watermark/phantom fallback would mask a dead binding check.", witness.FallbackReason)
	}
	if witness.Bounded {
		t.Fatalf("witness.Bounded=true — the stale image must be discarded, not used (witness=%+v)", witness)
	}
	// A discarded image must not leave checks armed against unrelated state.
	if witness.IntegrityChecksArmed {
		t.Fatalf("witness.IntegrityChecksArmed=true on a discarded image — the oracles must disarm when the binding fails, or they judge state the anchor never described")
	}
	// The WAL is the truth: every local entity must be back.
	state := engine.State()
	for i := 0; i < preN+tailN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("local entity %d missing after exact-WAL fallback — the WAL recorded every local mutation", i)
		}
	}
	// Measure the foreign absence rather than printing the constant that was fed
	// in. An earlier version of this log printed foreignN, which asserts nothing:
	// it would read identically if every foreign entry had survived.
	foreignPresent := 0
	for i := 0; i < foreignN; i++ {
		if len(state.Get(utf8EntityID(5000+i))) > 0 {
			foreignPresent++
		}
	}
	if foreignPresent != 0 {
		t.Fatalf("%d/%d foreign entities survived an exact-WAL replay — the WAL records only local mutations, so foreign state cannot come back this way; the image was not actually discarded", foreignPresent, foreignN)
	}
	t.Logf("stale-but-valid image disarmed the oracles and fell back to exact-WAL (%s); %d/%d local entities restored; %d/%d foreign entries measured absent (they re-arrive by anti-entropy)",
		witness.FallbackReason, preN+tailN, preN+tailN, foreignN-foreignPresent, foreignN)
}

// TestHeaderRootRotBindingCatchesRootHalf isolates the MerkleRoot comparison
// from the CutSeq comparison. The image has the anchor's CutSeq but different
// root bytes, so only the root comparison can reject it.
//
// Current v3 images reject this corruption through their CRC32C before the
// binding runs. The fixture therefore uses the legacy v2 encoding, which has no
// checksum and exercises the binding itself. The v3 decode path is covered by
// the snapshot integrity tests.
func TestHeaderRootRotBindingCatchesRootHalf(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "root-rot.wal")
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
	// A recorded 0x03 keeps the post-tail assertion disarmed, so this test
	// isolates the binding and cannot be confused with the recovery determinism check.
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

	imgPath, image := soleCheckpointImage(t, lfs)

	// The production image is now v3 (whole-image CRC32C trailer, ADR-0053).
	// A v3 header-root rot is caught by the CRC at decode and never reaches the
	// binding check. This test proves the binding's MerkleRoot half catches a
	// root mismatch — so it must run on the unprotected legacy v2 format (no
	// CRC), where the rotted root still decodes and the binding is the exercised
	// defense. Downgrade: strip the 4-byte CRC trailer, set version=2.
	// (The v3 rot→CRC→fallback path is covered by the snapshot integrity tests.)
	if len(image) >= 5 && image[4] == snapshotVersionV3 {
		image = append([]byte(nil), image[:len(image)-4]...) // strip the CRC trailer
		image[4] = snapshotVersionV2
	}

	// The snapshot v2 header (snapshot.go, encodeSnapshotImage): magic[0:4]
	// version[4] lamportHigh[5:13] recordCount[13:21] cutSeq[21:29]
	// merkleRoot[29:61]. Patch only the root. CutSeq is left byte-identical, so
	// the first half of the disjunction cannot fire and only the root half can
	// catch this.
	const rootOff, rootEnd, cutSeqOff, cutSeqEnd = 29, 61, 21, 29
	if len(image) < rootEnd {
		t.Fatalf("apparatus: image is %d bytes, shorter than the %d-byte v2 header", len(image), rootEnd)
	}
	rotted := append([]byte(nil), image...)
	for i := rootOff; i < rootEnd; i++ {
		rotted[i] ^= 0xFF
	}
	// Premise: exactly the root moved. If CutSeq also changed, the CutSeq half
	// would fire and this test would duplicate the test above.
	if string(rotted[cutSeqOff:cutSeqEnd]) != string(image[cutSeqOff:cutSeqEnd]) {
		t.Fatalf("premise broken: CutSeq bytes changed — this test must isolate the root half")
	}
	if string(rotted[rootOff:rootEnd]) == string(image[rootOff:rootEnd]) {
		t.Fatalf("premise broken: the root bytes did not change — nothing was rotted")
	}
	if err := os.WriteFile(imgPath, rotted, 0o640); err != nil {
		t.Fatalf("write rotted image: %v", err)
	}

	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf(`a header-root-rotted image refused the boot instead of disarming: %v
  The WAL is intact and the anchor is durable. A rotted image must be discarded
  (exact-WAL fallback), never treated as a data-loss verdict.`, err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()

	if witness == nil {
		t.Fatalf("nil recovery witness after header-root corruption")
	}
	if !witness.ExactWALFallback {
		t.Fatalf("witness.ExactWALFallback=false — a rotted header root must be caught by the binding's MerkleRoot half and force the fallback (witness=%+v)", witness)
	}
	if !strings.Contains(witness.FallbackReason, "binding mismatch") {
		t.Fatalf("fallback fired for the wrong reason — want the image/anchor binding, got %q. If this says anything else, the MerkleRoot half is still untested.", witness.FallbackReason)
	}
	if witness.Bounded {
		t.Fatalf("witness.Bounded=true — a rotted image must not be used (witness=%+v)", witness)
	}
	if witness.IntegrityChecksArmed {
		t.Fatalf("witness.IntegrityChecksArmed=true on a discarded image")
	}
	state := engine.State()
	for i := 0; i < preN+tailN; i++ {
		if len(state.Get(utf8EntityID(i))) == 0 {
			t.Fatalf("local entity %d missing after header-root fallback", i)
		}
	}
	t.Logf("header root rot (CutSeq byte-identical) caught by the binding's MerkleRoot half ⇒ %q; %d/%d local entities restored",
		witness.FallbackReason, preN+tailN, preN+tailN)
}

// TestControlBindingMatchesOracleArmed retains the newest image instead of
// restoring a stale one. Recovery must use it, arm the fingerprint checks, and
// reproduce the live root including foreign entries. The post-checkpoint tail
// also verifies that the post-tail root comparison remains disarmed.
func TestControlBindingMatchesOracleArmed(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "binding-control.wal")
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
		t.Fatalf("an intact image/anchor pair must boot: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()

	if witness.ExactWALFallback {
		t.Fatalf("witness.ExactWALFallback=true on a matching binding — the image must be used (reason=%q)", witness.FallbackReason)
	}
	if !witness.Bounded {
		t.Fatalf("witness.Bounded=false — a matching binding must take the bounded/image path (witness=%+v)", witness)
	}
	if !witness.IntegrityChecksArmed {
		t.Fatalf("matching image and anchor did not arm the pre-tail integrity checks")
	}
	// This control has a post-checkpoint tail, so the checkpoint does not pin
	// the final root. The pre-tail integrity checks must be armed and the
	// post-tail root assertion must remain disarmed.
	if witness.PostTailRootArmed {
		t.Fatalf("post-tail root assertion armed although the checkpoint does not pin the final root (witness=%+v)", witness)
	}
	// The bounded path carries the foreign dots in the image, so the recovered
	// root must equal the live root — foreign entries included.
	if got := engine.State().MerkleRoot(); got != liveRoot {
		t.Fatalf("recovered root %x, want live root %x for the bound image and tail", got, liveRoot)
	}
	t.Logf("matching binding used the image, armed integrity checks, and recovered the live root")
}
