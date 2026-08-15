package attribution

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ──────────────────────────────────────────────────────────────────────────
// Day 32 (ADR-0037): the hybrid-PQ SIGN-WIRE teeth.
//
// Day 31 (ADR-0036) disclosed that the v1 wire (MarshalBatchEnvelope) carries
// ONE 64-byte Ed25519 originSig — under --hybrid-verify EVERY v1 frame is
// REJECTED (the honest NOT-YET). Day 32 adds a NEW frame shape (the
// HybridEnvelope) carrying BOTH the [64] Ed25519 + the [3309] ML-DSA-65 sigs
// over the SAME batchWire, dispatched by a NEW magic (WireHybridPQMagic)
// WITHOUT a FROZEN-envelope.go touch (the Day-29 digest-frame mold — new magic
// in a non-FROZEN file). These teeth prove the wire shape:
//
//	T-PQ-HYBRID-FRAME-WIRE-SHAPE  — the 4 magics (WireV1Magic /
//	                               WireDigestMagic / WireHybridPQMagic / the
//	                               RelayEnvelope's uint16-LE version prefix
//	                               2|3) are pairwise bit-distinct, so the
//	                               4-way DispatchFrame is unambiguous.
//	T-PQ-HYBRID-FRAME-MARSHAL     — MarshalHybridFrame + UnmarshalHybridFrame
//	                               round-trip the header fields (originNodeID,
//	                               edSig, pqSig, originSeq, batchCount) +
//	                               the verbatim batchWire.
//	T-PQ-HYBRID-FRAME-IS-HYBRID   — IsHybridFrame identifies a hybrid frame
//	                               (the dispatch peek) + rejects a v1 batch /
//	                               a digest / a relay frame (the 4-way
//	                               dispatch is unambiguous).
//	T-PQ-HYBRID-FRAME-UNSIGNED    — a zero edSig OR a zero pqSig is
//	                               ErrHybridUnsigned (BOTH sigs is the
//	                               contract; a frame with one sig is a
//	                               classical-only frame the hybrid verifier
//	                               rejects, NOT a hybrid frame).
//	T-PQ-HYBRID-FRAME-MALFORMED   — a too-short wire / a bad magic / a bad
//	                               version is ErrHybridMalformed (the cheap
//	                               pre-verify reject; the parser touches ONLY
//	                               the header).
//	T-PQ-HYBRID-FRAME-HEADER-LEN  — HybridEnvelopeHeaderLen is the EXACT
//	                               offset at which batchWire begins (the
//	                               no-off-by-one tooth; the [3309] pqSig slot
//	                               is the dominant term).
// ──────────────────────────────────────────────────────────────────────────

// TestPQ_HybridFrameWireShape (T-PQ-HYBRID-FRAME-WIRE-SHAPE) proves the 4 magics
// (WireV1Magic / WireDigestMagic / WireHybridPQMagic / the RelayEnvelope's
// uint16-LE version prefix 2|3) are pairwise bit-distinct, so the 4-way
// DispatchFrame (batch / digest / hybrid / relay) is unambiguous — a hybrid
// frame is never handed to the relay parser (which would DropMalformed it), the
// batch path (which would ErrBatchMalformed it), or the digest sink (which
// would state-loss it).
func TestPQ_HybridFrameWireShape(t *testing.T) {
	// The three big-endian 4-byte magics.
	mBatch := WireV1Magic
	mDigest := WireDigestMagic
	mHybrid := WireHybridPQMagic
	if mBatch == mDigest || mBatch == mHybrid || mDigest == mHybrid {
		t.Fatalf("T-PQ-HYBRID-FRAME-WIRE-SHAPE: the three big-endian magics are NOT pairwise distinct — batch=%#x digest=%#x hybrid=%#x", mBatch, mDigest, mHybrid)
	}
	// The RelayEnvelope's uint16-LE version prefix (2 or 3) is a DIFFERENT
	// encoding (uint16-LE, NOT uint32-BE), so its first bytes are 0x02/0x03;
	// the three big-endian magics all start with 0x53 ('S'). Assert the
	// leading bytes are distinct so the relay parser never sees a hybrid
	// frame's 0x53 + the hybrid dispatch never sees a relay's 0x02/0x03.
	if byte(mHybrid>>24) != 0x53 {
		t.Fatalf("T-PQ-HYBRID-FRAME-WIRE-SHAPE: WireHybridPQMagic leading byte=%#x, want 0x53 ('S' — the SAME leading byte WireV1Magic + WireDigestMagic use)", byte(mHybrid>>24))
	}
	// The hybrid's SECOND byte (0x48 'H') separates it from SBAT (0x42 'B') +
	// SDST (0x44 'D') — the pairwise bit-distinctness past the shared 'S'.
	if byte(mHybrid>>16) != 0x48 {
		t.Fatalf("T-PQ-HYBRID-FRAME-WIRE-SHAPE: WireHybridPQMagic second byte=%#x, want 0x48 ('H' — separates SHYB from SBAT's 0x42 + SDST's 0x44 past the shared 'S')", byte(mHybrid>>16))
	}
	// RelayEnvelope version prefix bytes (2|3) vs the hybrid's leading 0x53.
	if byte(mHybrid>>24) == 0x02 || byte(mHybrid>>24) == 0x03 {
		t.Fatalf("T-PQ-HYBRID-FRAME-WIRE-SHAPE: WireHybridPQMagic leading byte collides with the RelayEnvelope's uint16-LE version prefix (2|3)")
	}
	t.Logf("T-PQ-HYBRID-FRAME-WIRE-SHAPE PASS: the 4 magics are pairwise bit-distinct (batch=%#x digest=%#x hybrid=%#x; relay=uint16-LE 2|3) — the 4-way DispatchFrame is unambiguous", mBatch, mDigest, mHybrid)
}

// TestPQ_HybridFrameMarshal (T-PQ-HYBRID-FRAME-MARSHAL) proves
// MarshalHybridFrame + UnmarshalHybridFrame round-trip the header fields
// (originNodeID, edSig, pqSig, originSeq, batchCount) + the verbatim batchWire.
// The tooth marshals a hybrid frame with known fields + asserts the parsed
// envelope returns each field byte-identical + the batchWire aliases the
// original slice (no copy — the no-hash-then-reconstruct-gap property).
func TestPQ_HybridFrameMarshal(t *testing.T) {
	var originNodeID [OriginNodeIDSize]byte
	copy(originNodeID[:], []byte("origin-node-id-"))
	var edSig [OriginSigSize]byte
	for i := range edSig {
		edSig[i] = byte(0x40 + i)
	}
	var pqSig [PQSignatureSize]byte
	for i := range pqSig {
		pqSig[i] = byte(0x80 + (i & 0x7F))
	}
	var originSeq uint64 = 0xCAFEBABEDEADBEEF
	var batchCount uint16 = 42
	batchWire := []byte("the marshaled CRDTDeltaBatch wire — verbatim bytes BOTH sigs cover via the 120-byte SHAKE256 pad")

	frame := MarshalHybridFrame(originNodeID, edSig, pqSig, originSeq, batchCount, batchWire)

	// The frame begins with the magic (big-endian) so IsHybridFrame identifies
	// it (the dispatch peek).
	if !IsHybridFrame(frame) {
		t.Fatalf("T-PQ-HYBRID-FRAME-MARSHAL: IsHybridFrame=false on a marshaled hybrid frame, want true (the dispatch peek)")
	}

	env, err := UnmarshalHybridFrame(frame)
	if err != nil {
		t.Fatalf("UnmarshalHybridFrame: %v", err)
	}
	if env.OriginNodeID() != originNodeID {
		t.Fatalf("T-PQ-HYBRID-FRAME-MARSHAL: originNodeID mismatch — got %x, want %x", env.OriginNodeID(), originNodeID)
	}
	if env.EdSig() != edSig {
		t.Fatalf("T-PQ-HYBRID-FRAME-MARSHAL: edSig mismatch — got %x, want %x", env.EdSig(), edSig)
	}
	gotPQ := env.PQSig()
	if gotPQ != pqSig {
		t.Fatalf("T-PQ-HYBRID-FRAME-MARSHAL: pqSig mismatch — got %x... (len %d), want %x... (len %d)", gotPQ[:8], len(gotPQ), pqSig[:8], len(pqSig))
	}
	if env.OriginSeq() != originSeq {
		t.Fatalf("T-PQ-HYBRID-FRAME-MARSHAL: originSeq mismatch — got %d, want %d", env.OriginSeq(), originSeq)
	}
	if env.BatchCount() != batchCount {
		t.Fatalf("T-PQ-HYBRID-FRAME-MARSHAL: batchCount mismatch — got %d, want %d", env.BatchCount(), batchCount)
	}
	// The batchWire is the verbatim bytes from HybridEnvelopeHeaderLen onward.
	if !bytes.Equal(env.BatchWire(), batchWire) {
		t.Fatalf("T-PQ-HYBRID-FRAME-MARSHAL: batchWire mismatch — got %q, want %q (the verbatim bytes BOTH sigs cover + the FROZEN ApplyCRDTDeltaBatch decodes)", env.BatchWire(), batchWire)
	}
	t.Logf("T-PQ-HYBRID-FRAME-MARSHAL PASS: MarshalHybridFrame + UnmarshalHybridFrame round-trip the header fields + the verbatim batchWire")
}

// TestPQ_HybridFrameIsHybrid (T-PQ-HYBRID-FRAME-IS-HYBRID) proves IsHybridFrame
// identifies a hybrid frame + rejects a v1 batch / a digest / a relay frame
// (the dispatch peek is unambiguous — the 4-way DispatchFrame is load-bearing).
func TestPQ_HybridFrameIsHybrid(t *testing.T) {
	// A hybrid frame (magic first).
	hybrid := MarshalHybridFrame([OriginNodeIDSize]byte{}, [OriginSigSize]byte{0xAA, 0xBB}, [PQSignatureSize]byte{0xCC}, 1, 1, []byte("batch"))
	if !IsHybridFrame(hybrid) {
		t.Fatalf("T-PQ-HYBRID-FRAME-IS-HYBRID: IsHybridFrame=false on a hybrid frame, want true")
	}
	// A v1 BatchEnvelope (WireV1Magic first).
	batch := make([]byte, 8)
	binary.BigEndian.PutUint32(batch[0:4], WireV1Magic)
	if IsHybridFrame(batch) {
		t.Fatalf("T-PQ-HYBRID-FRAME-IS-HYBRID: IsHybridFrame=true on a v1 BatchEnvelope, want false (the 4-way dispatch is unambiguous)")
	}
	// A digest frame (WireDigestMagic first).
	digest := make([]byte, 8)
	binary.BigEndian.PutUint32(digest[0:4], WireDigestMagic)
	if IsHybridFrame(digest) {
		t.Fatalf("T-PQ-HYBRID-FRAME-IS-HYBRID: IsHybridFrame=true on a digest frame, want false (the 4-way dispatch is unambiguous)")
	}
	// A relay frame (uint16-LE version prefix 2 first — the FROZEN RelayEnvelope).
	relay := make([]byte, 8)
	binary.LittleEndian.PutUint16(relay[0:2], 2)
	if IsHybridFrame(relay) {
		t.Fatalf("T-PQ-HYBRID-FRAME-IS-HYBRID: IsHybridFrame=true on a relay frame, want false (the 4-way dispatch is unambiguous — a hybrid frame is never handed to the relay parser)")
	}
	t.Logf("T-PQ-HYBRID-FRAME-IS-HYBRID PASS: IsHybridFrame identifies a hybrid frame + rejects a v1 batch / a digest / a relay frame")
}

// TestPQ_HybridFrameUnsigned (T-PQ-HYBRID-FRAME-UNSIGNED) proves a zero edSig OR
// a zero pqSig is ErrHybridUnsigned (BOTH sigs is the contract; a frame with
// one sig is a classical-only frame the hybrid verifier rejects, NOT a hybrid
// frame). The tooth marshals a frame with a zero edSig + asserts Unmarshal
// rejects it, then a zero pqSig + asserts Unmarshal rejects it.
func TestPQ_HybridFrameUnsigned(t *testing.T) {
	var zeroEd [OriginSigSize]byte
	var zeroPQ [PQSignatureSize]byte
	var goodEd [OriginSigSize]byte
	goodEd[0] = 0xFF
	var goodPQ [PQSignatureSize]byte
	goodPQ[0] = 0xFF
	batchWire := []byte("batch")

	// Zero edSig, good pqSig -> ErrHybridUnsigned.
	frame := MarshalHybridFrame([OriginNodeIDSize]byte{}, zeroEd, goodPQ, 1, 1, batchWire)
	if _, err := UnmarshalHybridFrame(frame); err != ErrHybridUnsigned {
		t.Fatalf("T-PQ-HYBRID-FRAME-UNSIGNED: UnmarshalHybridFrame with a zero edSig returned err=%v, want ErrHybridUnsigned (BOTH sigs is the contract)", err)
	}
	// Good edSig, zero pqSig -> ErrHybridUnsigned.
	frame = MarshalHybridFrame([OriginNodeIDSize]byte{}, goodEd, zeroPQ, 1, 1, batchWire)
	if _, err := UnmarshalHybridFrame(frame); err != ErrHybridUnsigned {
		t.Fatalf("T-PQ-HYBRID-FRAME-UNSIGNED: UnmarshalHybridFrame with a zero pqSig returned err=%v, want ErrHybridUnsigned (BOTH sigs is the contract)", err)
	}
	t.Logf("T-PQ-HYBRID-FRAME-UNSIGNED PASS: a zero edSig OR a zero pqSig is ErrHybridUnsigned (BOTH sigs is the contract)")
}

// TestPQ_HybridFrameMalformed (T-PQ-HYBRID-FRAME-MALFORMED) proves a too-short
// wire / a bad magic / a bad version is ErrHybridMalformed (the cheap pre-verify
// reject; the parser touches ONLY the header). The tooth asserts each case.
func TestPQ_HybridFrameMalformed(t *testing.T) {
	// Too short (less than HybridEnvelopeHeaderLen).
	short := make([]byte, HybridEnvelopeHeaderLen-1)
	if _, err := UnmarshalHybridFrame(short); err != ErrHybridMalformed {
		t.Fatalf("T-PQ-HYBRID-FRAME-MALFORMED: UnmarshalHybridFrame on a too-short wire returned err=%v, want ErrHybridMalformed", err)
	}
	// Bad magic (NOT WireHybridPQMagic).
	badMagic := make([]byte, HybridEnvelopeHeaderLen)
	binary.BigEndian.PutUint32(badMagic[0:4], WireV1Magic) // the BATCH magic, not the hybrid
	badMagic[4] = WireHybridPQVersion
	if _, err := UnmarshalHybridFrame(badMagic); err != ErrHybridMalformed {
		t.Fatalf("T-PQ-HYBRID-FRAME-MALFORMED: UnmarshalHybridFrame on a bad-magic wire returned err=%v, want ErrHybridMalformed", err)
	}
	// Bad version (NOT WireHybridPQVersion).
	badVer := MarshalHybridFrame([OriginNodeIDSize]byte{}, [OriginSigSize]byte{0xFF}, [PQSignatureSize]byte{0xFF}, 1, 1, []byte("batch"))
	badVer[4] = WireHybridPQVersion + 1 // a version the parser does not honor
	if _, err := UnmarshalHybridFrame(badVer); err != ErrHybridMalformed {
		t.Fatalf("T-PQ-HYBRID-FRAME-MALFORMED: UnmarshalHybridFrame on a bad-version wire returned err=%v, want ErrHybridMalformed", err)
	}
	t.Logf("T-PQ-HYBRID-FRAME-MALFORMED PASS: a too-short wire / a bad magic / a bad version is ErrHybridMalformed (the cheap pre-verify reject)")
}

// TestPQ_HybridFrameHeaderLen (T-PQ-HYBRID-FRAME-HEADER-LEN) proves
// HybridEnvelopeHeaderLen is the EXACT offset at which batchWire begins (the
// no-off-by-one tooth; the [3309] pqSig slot is the dominant term). The tooth
// marshals a frame + asserts the batchWire begins at HybridEnvelopeHeaderLen +
// the total frame length is HybridEnvelopeHeaderLen + len(batchWire).
func TestPQ_HybridFrameHeaderLen(t *testing.T) {
	if HybridEnvelopeHeaderLen != 4+1+8+2+OriginNodeIDSize+OriginSigSize+PQSignatureSize {
		t.Fatalf("T-PQ-HYBRID-FRAME-HEADER-LEN: HybridEnvelopeHeaderLen=%d, want %d (4+1+8+2+16+64+3309 — the no-off-by-one tooth)", HybridEnvelopeHeaderLen, 4+1+8+2+OriginNodeIDSize+OriginSigSize+PQSignatureSize)
	}
	batchWire := []byte("the batch wire begins at HybridEnvelopeHeaderLen")
	frame := MarshalHybridFrame([OriginNodeIDSize]byte{}, [OriginSigSize]byte{0xFF}, [PQSignatureSize]byte{0xFF}, 1, 1, batchWire)
	if len(frame) != HybridEnvelopeHeaderLen+len(batchWire) {
		t.Fatalf("T-PQ-HYBRID-FRAME-HEADER-LEN: frame len=%d, want %d (HybridEnvelopeHeaderLen + len(batchWire))", len(frame), HybridEnvelopeHeaderLen+len(batchWire))
	}
	env, err := UnmarshalHybridFrame(frame)
	if err != nil {
		t.Fatalf("UnmarshalHybridFrame: %v", err)
	}
	if !bytes.Equal(env.BatchWire(), batchWire) {
		t.Fatalf("T-PQ-HYBRID-FRAME-HEADER-LEN: batchWire mismatch — the offset HybridEnvelopeHeaderLen is wrong (got %q, want %q)", env.BatchWire(), batchWire)
	}
	t.Logf("T-PQ-HYBRID-FRAME-HEADER-LEN PASS: HybridEnvelopeHeaderLen=%d is the EXACT offset at which batchWire begins (the [3309] pqSig slot is the dominant term)", HybridEnvelopeHeaderLen)
}
