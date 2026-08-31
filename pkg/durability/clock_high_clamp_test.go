// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// — the ClockHigh clamp guards.
//
// THE DEFECT (ADR-0045): added the 8-byte
// ClockHigh to the 0x05 anchor and seeded the engine constructor from it
// (recovery.go: rebuiltInitial = max(rep.LamportHigh, ClockHigh)). The record
// has no checksum and the field had NO credibility check: byte-patching
// payload[48:56] of a real 6-mutation log showed that
// ClockHigh=MaxUint64 was ACCEPTED, the node BOOTED armed=true, and the first
// NextDot (lamportCounter.Add(1), crdt.go:854) WRAPPED TO 0 — after which every
// local dot re-issues a used counter, merge keeps the existing entry on an
// equal dot, and every post-recovery write is silently dropped on every peer
// while IntegrityChecksArmed=true certifies the boot. Fail-SILENT.
//
// THE FIX: clamp at DECODE (internal/chaos/wal.go, the 0x05 case) — a ClockHigh
// above MaxCredibleClockHigh (1<<60, the same ceiling as recovery's
// maxPlausibleCounter) is floored to the log's own durable high-water (the
// pre-seed semantics: safe, because a ClockHigh above every recorded
// value only ever covers a raise that produced NO mutation) and reported LOUD
// (Replayed.ClockHighClamped/ClockHighRaw → witness + a log line).
//
// WHY FLOOR, NOT REFUSE: the WAL's mutations are intact; refusing to boot
// bricks a recoverable node (the class this fork exists to kill). The floor
// loses only the un-recorded raise, which no dot ever lived at. The residual —
// a plausible-looking corrupt value BELOW the ceiling is undetectable without
// a per-record checksum — is a known, disclosed gap, not closed.

import (
	"encoding/binary"
	"math"
	"os"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// patchFinalCheckpointClockHigh walks the WAL file, finds the LAST 0x05
// record, and overwrites its ClockHigh (payload[48:56]) in place. It Fatalfs
// unless EXACTLY the targeted bytes changed — an injection that did not apply
// is indistinguishable from a passing control (the injection-must-apply rule).
func patchFinalCheckpointClockHigh(t *testing.T, walPath string, val uint64) {
	t.Helper()
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL: %v", err)
	}
	if len(data) < 8 {
		t.Fatalf("apparatus: WAL too short for a header")
	}
	off := 8 // fixed header
	lastCkpt := -1
	for off+13 <= len(data) {
		recType := data[off+8]
		payloadLen := int(binary.BigEndian.Uint32(data[off+9 : off+13]))
		if off+13+payloadLen > len(data) {
			break // torn tail — stop, like scanRecords
		}
		if recType == byte(WALRecCheckpointV2) && payloadLen >= 56 {
			lastCkpt = off
		}
		off += 13 + payloadLen
	}
	if lastCkpt < 0 {
		t.Fatalf("PREMISE BROKEN: no 0x05 record with a ClockHigh field in %s — nothing to patch", walPath)
	}
	fieldOff := lastCkpt + 13 + 48
	before := binary.BigEndian.Uint64(data[fieldOff : fieldOff+8])
	binary.BigEndian.PutUint64(data[fieldOff:fieldOff+8], val)
	if err := os.WriteFile(walPath, data, 0o644); err != nil {
		t.Fatalf("write patched WAL: %v", err)
	}
	// Prove the patch LANDED and landed on the field: re-read, re-walk, verify.
	verify, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("re-read WAL: %v", err)
	}
	got := binary.BigEndian.Uint64(verify[fieldOff : fieldOff+8])
	if got != val {
		t.Fatalf("PATCH DID NOT APPLY: field reads %d, want %d", got, val)
	}
	t.Logf("patched final 0x05 at file offset %d: ClockHigh %d -> %d", fieldOff, before, val)
}

// appendMirroredRawCheckpointForTest appends a RAW (unframed, no-CRC) 0x05
// checkpoint that MIRRORS the log's current final checkpoint (same MerkleRoot,
// LamportHigh watermark, CutSeq, ClockHigh), making it the new FINAL record.
//
// (C2): the bridge now writes 0x06 CRC-framed checkpoints, and patching
// a FRAMED checkpoint's ClockHigh trips the CRC (ErrWALCorrupt) BEFORE the
// clamp runs — which is the CORRECT layering (the CRC is the syntactic defense on
// the protected format; the clamp is the defense on the UNPROTECTED legacy
// format). To keep exercising the CLAMP, the guards patch a RAW 0x05 (the
// format the clamp guards). The mirrored values keep the log's recovery shape
// identical (same watermark ⇒ same clamp floor ⇒ clock=9 / mint=10 as before).
// The raw record is the 56-byte fingerprint-less form — the clamp guards do not
// exercise the fingerprint check.
func appendMirroredRawCheckpointForTest(t *testing.T, walPath string) {
	t.Helper()
	rep, err := ReplayWAL(walPath)
	if err != nil {
		t.Fatalf("read final checkpoint to mirror: %v", err)
	}
	if !rep.HasCheckpoint {
		t.Fatalf("apparatus: no checkpoint to mirror")
	}
	c := rep.FinalCheckpt
	// 56-byte 0x05 payload: root(32)‖watermark(8)‖CutSeq(8)‖ClockHigh(8).
	payload := make([]byte, 56)
	copy(payload[0:32], c.MerkleRoot[:])
	binary.BigEndian.PutUint64(payload[32:40], c.LamportHigh)
	binary.BigEndian.PutUint64(payload[40:48], c.CutSeq)
	binary.BigEndian.PutUint64(payload[48:56], c.ClockHigh)
	wal, err := OpenWAL(walPath)
	if err != nil {
		t.Fatalf("open WAL to append raw checkpoint: %v", err)
	}
	if err := wal.AppendCheckpointRawForTest(payload); err != nil {
		t.Fatalf("AppendCheckpointRawForTest: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("close WAL: %v", err)
	}
}

// clampObservation is what one corrupt-ClockHigh recovery must show.
type clampObservation struct {
	witness   *RecoveryWitness
	clock     uint64  // engine.LamportCounter() after recovery
	minted    uint64  // the first post-recovery dot's counter
	skewRate  float64 // LamportSnapshot().ObservedInboundRate (the fail-open witness)
	skewBound uint64  // MaxAcceptableDotCounter post-recovery
}

// recoverAndMint replays a patched log on the bounded path, then mints ONE
// local dot — the wrap-or-not witness. The guard's core assertion: the minted
// counter is the floored high-water + 1, never 0 (wrap) and never raw+1.
func recoverAndMint(t *testing.T, walPath string, lfs *LocalFS) clampObservation {
	t.Helper()
	engine, wal, _, witness, err := RecoverEngineWithSnapshot(testNodeID(), walPath, lfs, testArenaSize)
	if err != nil {
		t.Fatalf("recovery REFUSED a WAL whose only defect is an incredible ClockHigh — the clamp must FLOOR, not brick: %v", err)
	}
	defer func() { _ = wal.Close(); _ = engine.Close() }()
	if witness == nil {
		t.Fatalf("nil witness on a successful boot")
	}
	snap := engine.LamportSnapshot()
	clock := engine.LamportCounter() // PRE-mint: the recovered clock itself
	dot := engine.InsertLocal(utf8EntityID(999), stagedEntry(999))
	return clampObservation{
		witness:   witness,
		clock:     clock,
		minted:    dot.Counter,
		skewRate:  snap.ObservedInboundRate,
		skewBound: eng.MaxAcceptableDotCounter(snap),
	}
}

// TestClockHighClampMaxUint64 is row 1 of the table: a ClockHigh of
// MaxUint64 must NOT reach the engine constructor. The boot must succeed on
// the log's own evidence, the witness must report the clamp, and the first
// post-recovery mint must NOT wrap to 0.
func TestClockHighClampMaxUint64(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, liveClock := b1Build(t, lfs, b1GapAdvance, false) // ClockHigh=9,000,000 on disk, no 0x03
	if liveClock != b1GapAdvance {
		t.Fatalf("apparatus: live clock %d != %d", liveClock, b1GapAdvance)
	}
	// Baseline sanity: the unpatched log nails the clock to 9,000,000 (the B1
	// control shape). Then patch to MaxUint64.
	// (C2): the bridge's checkpoint is 0x06-CRC-framed; patching IT would
	// trip the CRC (the correct new defense). The clamp is the LEGACY-format
	// defense, so we append a raw 0x05 mirror and patch THAT.
	appendMirroredRawCheckpointForTest(t, walPath)
	patchFinalCheckpointClockHigh(t, walPath, math.MaxUint64)
	obs := recoverAndMint(t, walPath, lfs)
	if !obs.witness.ClockHighClamped {
		t.Fatalf("ClockHigh=MaxUint64 was ACCEPTED without a clamp — the wrap poison reached the engine constructor (witness=%+v)", obs.witness)
	}
	if obs.witness.ClockHighRaw != math.MaxUint64 {
		t.Fatalf("witness.ClockHighRaw=%d, want %d (the raw value must be reported, not laundered)", obs.witness.ClockHighRaw, uint64(math.MaxUint64))
	}
	// The floor: rep.LamportHigh for this log is 9 (8 mutations at dots 2..9,
	// checkpoint LamportHigh=9, no advances). The clamped ClockHigh is 9, the
	// seed is max(9,9)=9, the first mint is 10 — NOT 0 (the wrap) and NOT
	// anywhere near MaxUint64.
	if obs.clock != 9 {
		t.Fatalf("recovered clock %d, want 9 (the floored durable high-water) — the clamp floor is wrong", obs.clock)
	}
	if obs.minted != 10 {
		t.Fatalf("first post-recovery mint = %d, want 10 — 0 would be the WRAP (every later write silently dropped cluster-wide)", obs.minted)
	}
	// The clamp must arrive via the constructor seed — no skew-EWMA poison
	// (the §11.1 fail-open window). Floor 9 ⇒ bound 9 + 0 + 1000.
	if obs.skewRate != 0 || obs.skewBound != 1009 {
		t.Fatalf("the floored clock did NOT arrive via the constructor seed — skewRate=%v skewBound=%d, want 0 / 1009 (a fail-open accept window is open)", obs.skewRate, obs.skewBound)
	}
	t.Logf("L0 GREEN: ClockHigh=MaxUint64 clamped to the durable high-water; boot ok; clock=9; first mint=10 (no wrap); skewBound=1009 (no fail-open); witness raw=%d", obs.witness.ClockHighRaw)
}

// TestClockHighClampOneBitFlip is row 2 of the table: a single flipped
// top byte (0x80) turns ClockHigh into 2^63+7 — the measured
// 9223372036854775815. Same obligations as the MaxUint64 row.
func TestClockHighClampOneBitFlip(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, _ := b1Build(t, lfs, b1GapAdvance, false)
	const flipped = uint64(9223372036854775815)    // 2^63 + 7 — the measured one-bit corruption
	appendMirroredRawCheckpointForTest(t, walPath) // (C2): patch a raw 0x05, not the 0x06 frame
	patchFinalCheckpointClockHigh(t, walPath, flipped)
	obs := recoverAndMint(t, walPath, lfs)
	if !obs.witness.ClockHighClamped || obs.witness.ClockHighRaw != flipped {
		t.Fatalf("one-bit-flipped ClockHigh %d not reported clamped (witness=%+v)", flipped, obs.witness)
	}
	if obs.clock != 9 || obs.minted != 10 {
		t.Fatalf("clock=%d minted=%d, want 9/10 — the 2^63+7 poison survived", obs.clock, obs.minted)
	}
	if obs.skewRate != 0 || obs.skewBound != 1009 {
		t.Fatalf("skew envelope poisoned: rate=%v bound=%d, want 0/1009", obs.skewRate, obs.skewBound)
	}
	t.Logf("L0 GREEN: one-bit flip (2^63+7) clamped; clock=9; mint=10; no wrap, no fail-open")
}

// TestClockHighClampBoundary pins the exact ceiling: the ceiling VALUE
// itself is credible (consistent with checkMutationRecord's `>`
// maxPlausibleCounter, which admits a counter of exactly 1<<60); one above it
// is not. A clamp whose boundary is untested is a magic number.
func TestClockHighClampBoundary(t *testing.T) {
	t.Run("CeilingValueAccepted", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, _ := b1Build(t, lfs, b1GapAdvance, false)
		appendMirroredRawCheckpointForTest(t, walPath) // (C2): raw 0x05, not the 0x06 frame
		patchFinalCheckpointClockHigh(t, walPath, MaxCredibleClockHigh)
		obs := recoverAndMint(t, walPath, lfs)
		if obs.witness.ClockHighClamped {
			t.Fatalf("boundary: ClockHigh == MaxCredibleClockHigh (%d) was CLAMPED — the ceiling itself must be credible (match maxPlausibleCounter semantics)", MaxCredibleClockHigh)
		}
		if obs.clock != MaxCredibleClockHigh || obs.minted != MaxCredibleClockHigh+1 {
			t.Fatalf("boundary: clock=%d minted=%d, want %d/%d — a credible value must pass through verbatim", obs.clock, obs.minted, uint64(MaxCredibleClockHigh), uint64(MaxCredibleClockHigh)+1)
		}
	})
	t.Run("CeilingPlusOneClamped", func(t *testing.T) {
		lfs := newSnapshotStore(t)
		walPath, _ := b1Build(t, lfs, b1GapAdvance, false)
		appendMirroredRawCheckpointForTest(t, walPath) // (C2): raw 0x05, not the 0x06 frame
		patchFinalCheckpointClockHigh(t, walPath, MaxCredibleClockHigh+1)
		obs := recoverAndMint(t, walPath, lfs)
		if !obs.witness.ClockHighClamped || obs.clock != 9 || obs.minted != 10 {
			t.Fatalf("boundary: MaxCredibleClockHigh+1 must clamp (clamped=%v clock=%d minted=%d, want true/9/10)", obs.witness.ClockHighClamped, obs.clock, obs.minted)
		}
	})
}

// TestClockHighClampLegitimateLargeSurvives is the no-false-positive
// control through the clamp lens: the B1 shape (ClockHigh = 9,000,000 with no
// 0x03 record — a real, un-corrupted value orders of magnitude above the log's
// high-water) must pass through UNCLAMPED and still nail the clock. This is
// the same shape TestControlNoRecordedAdvanceClockHighNail asserts; this
// guard adds the explicit not-clamped witness so a future over-eager clamp
// cannot regress the legitimate case without failing here.
func TestClockHighClampLegitimateLargeSurvives(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath, _ := b1Build(t, lfs, b1GapAdvance, false) // NO patch — the honest 9M
	obs := recoverAndMint(t, walPath, lfs)
	if obs.witness.ClockHighClamped {
		t.Fatalf("false positive: a legitimate ClockHigh=%d was clamped (raw=%d) — the ceiling misfires on the B1 shape", b1GapAdvance, obs.witness.ClockHighRaw)
	}
	if obs.clock != b1GapAdvance || obs.minted != b1GapAdvance+1 {
		t.Fatalf("control: clock=%d minted=%d, want %d/%d — the legitimate nail regressed", obs.clock, obs.minted, b1GapAdvance, b1GapAdvance+1)
	}
	t.Logf("L0 GREEN: legitimate ClockHigh=9,000,000 unclamped; clock nailed; mint=%d", obs.minted)
}
