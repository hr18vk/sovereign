// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package attribution

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// These tests cover the hybrid post-quantum frame format in ADR-0037:
// dispatch, round trips, unsigned frames, malformed headers, and the header
// length that locates batchWire.

// TestPQ_HybridFrameWireShape checks that the batch, digest, and hybrid magic
// values differ from one another and from the RelayEnvelope version prefix.
// DispatchFrame can therefore route each frame shape to the intended parser.
func TestPQ_HybridFrameWireShape(t *testing.T) {
	// The three big-endian 4-byte magics.
	mBatch := WireV1Magic
	mDigest := WireDigestMagic
	mHybrid := WireHybridPQMagic
	if mBatch == mDigest || mBatch == mHybrid || mDigest == mHybrid {
		t.Fatalf("hybrid frame wire shape: magics are not pairwise distinct — batch=%#x digest=%#x hybrid=%#x", mBatch, mDigest, mHybrid)
	}
	if byte(mHybrid>>24) != 0x53 {
		t.Fatalf("hybrid frame wire shape: WireHybridPQMagic leading byte=%#x, want 0x53 ('S')", byte(mHybrid>>24))
	}
	if byte(mHybrid>>16) != 0x48 {
		t.Fatalf("hybrid frame wire shape: WireHybridPQMagic second byte=%#x, want 0x48 ('H')", byte(mHybrid>>16))
	}
	if byte(mHybrid>>24) == 0x02 || byte(mHybrid>>24) == 0x03 {
		t.Fatalf("hybrid frame wire shape: WireHybridPQMagic leading byte collides with RelayEnvelope version prefix (2|3)")
	}
	t.Logf("hybrid frame wire shape: 4 dispatch prefixes distinct (batch=%#x digest=%#x hybrid=%#x; relay=uint16-LE 2|3)", mBatch, mDigest, mHybrid)
}

// TestPQ_HybridFrameMarshal verifies that MarshalHybridFrame and
// UnmarshalHybridFrame round-trip all header fields and the verbatim batchWire.
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

	if !IsHybridFrame(frame) {
		t.Fatalf("hybrid frame marshal: IsHybridFrame=false on marshaled hybrid frame, want true")
	}

	env, err := UnmarshalHybridFrame(frame)
	if err != nil {
		t.Fatalf("UnmarshalHybridFrame: %v", err)
	}
	if env.OriginNodeID() != originNodeID {
		t.Fatalf("hybrid frame marshal: originNodeID mismatch — got %x, want %x", env.OriginNodeID(), originNodeID)
	}
	if env.EdSig() != edSig {
		t.Fatalf("hybrid frame marshal: edSig mismatch — got %x, want %x", env.EdSig(), edSig)
	}
	gotPQ := env.PQSig()
	if gotPQ != pqSig {
		t.Fatalf("hybrid frame marshal: pqSig mismatch — got %x... (len %d), want %x... (len %d)", gotPQ[:8], len(gotPQ), pqSig[:8], len(pqSig))
	}
	if env.OriginSeq() != originSeq {
		t.Fatalf("hybrid frame marshal: originSeq mismatch — got %d, want %d", env.OriginSeq(), originSeq)
	}
	if env.BatchCount() != batchCount {
		t.Fatalf("hybrid frame marshal: batchCount mismatch — got %d, want %d", env.BatchCount(), batchCount)
	}
	if !bytes.Equal(env.BatchWire(), batchWire) {
		t.Fatalf("hybrid frame marshal: batchWire mismatch — got %q, want %q", env.BatchWire(), batchWire)
	}
	t.Logf("hybrid frame marshal: header fields and verbatim batchWire round-tripped")
}

// TestPQ_HybridFrameIsHybrid verifies that IsHybridFrame identifies a hybrid
// frame and rejects v1 batch, digest, and relay frames.
func TestPQ_HybridFrameIsHybrid(t *testing.T) {
	hybrid := MarshalHybridFrame([OriginNodeIDSize]byte{}, [OriginSigSize]byte{0xAA, 0xBB}, [PQSignatureSize]byte{0xCC}, 1, 1, []byte("batch"))
	if !IsHybridFrame(hybrid) {
		t.Fatalf("hybrid frame is-hybrid: IsHybridFrame=false on hybrid frame, want true")
	}
	batch := make([]byte, 8)
	binary.BigEndian.PutUint32(batch[0:4], WireV1Magic)
	if IsHybridFrame(batch) {
		t.Fatalf("hybrid frame is-hybrid: IsHybridFrame=true on v1 BatchEnvelope, want false")
	}
	digest := make([]byte, 8)
	binary.BigEndian.PutUint32(digest[0:4], WireDigestMagic)
	if IsHybridFrame(digest) {
		t.Fatalf("hybrid frame is-hybrid: IsHybridFrame=true on digest frame, want false")
	}
	relay := make([]byte, 8)
	binary.LittleEndian.PutUint16(relay[0:2], 2)
	if IsHybridFrame(relay) {
		t.Fatalf("hybrid frame is-hybrid: IsHybridFrame=true on relay frame, want false")
	}
	t.Logf("hybrid frame is-hybrid: IsHybridFrame identifies hybrid frame and rejects v1 batch, digest, and relay frames")
}

// TestPQ_HybridFrameUnsigned verifies that UnmarshalHybridFrame returns
// ErrHybridUnsigned when either edSig or pqSig is zero.
func TestPQ_HybridFrameUnsigned(t *testing.T) {
	var zeroEd [OriginSigSize]byte
	var zeroPQ [PQSignatureSize]byte
	var goodEd [OriginSigSize]byte
	goodEd[0] = 0xFF
	var goodPQ [PQSignatureSize]byte
	goodPQ[0] = 0xFF
	batchWire := []byte("batch")

	frame := MarshalHybridFrame([OriginNodeIDSize]byte{}, zeroEd, goodPQ, 1, 1, batchWire)
	if _, err := UnmarshalHybridFrame(frame); err != ErrHybridUnsigned {
		t.Fatalf("hybrid frame unsigned: zero edSig returned err=%v, want ErrHybridUnsigned", err)
	}
	frame = MarshalHybridFrame([OriginNodeIDSize]byte{}, goodEd, zeroPQ, 1, 1, batchWire)
	if _, err := UnmarshalHybridFrame(frame); err != ErrHybridUnsigned {
		t.Fatalf("hybrid frame unsigned: zero pqSig returned err=%v, want ErrHybridUnsigned", err)
	}
	t.Logf("hybrid frame unsigned: zero edSig or zero pqSig rejected with ErrHybridUnsigned")
}

// TestPQ_HybridFrameMalformed verifies that a truncated header, wrong magic,
// or unknown version returns ErrHybridMalformed.
func TestPQ_HybridFrameMalformed(t *testing.T) {
	short := make([]byte, HybridEnvelopeHeaderLen-1)
	if _, err := UnmarshalHybridFrame(short); err != ErrHybridMalformed {
		t.Fatalf("hybrid frame malformed: short wire returned err=%v, want ErrHybridMalformed", err)
	}
	badMagic := make([]byte, HybridEnvelopeHeaderLen)
	binary.BigEndian.PutUint32(badMagic[0:4], WireV1Magic)
	badMagic[4] = WireHybridPQVersion
	if _, err := UnmarshalHybridFrame(badMagic); err != ErrHybridMalformed {
		t.Fatalf("hybrid frame malformed: bad magic returned err=%v, want ErrHybridMalformed", err)
	}
	badVer := MarshalHybridFrame([OriginNodeIDSize]byte{}, [OriginSigSize]byte{0xFF}, [PQSignatureSize]byte{0xFF}, 1, 1, []byte("batch"))
	badVer[4] = WireHybridPQVersion + 1
	if _, err := UnmarshalHybridFrame(badVer); err != ErrHybridMalformed {
		t.Fatalf("hybrid frame malformed: bad version returned err=%v, want ErrHybridMalformed", err)
	}
	t.Logf("hybrid frame malformed: short wire, bad magic, and bad version rejected with ErrHybridMalformed")
}

// TestPQ_HybridFrameHeaderLen verifies that HybridEnvelopeHeaderLen matches
// the exact byte offset where batchWire begins.
func TestPQ_HybridFrameHeaderLen(t *testing.T) {
	if HybridEnvelopeHeaderLen != 4+1+8+2+OriginNodeIDSize+OriginSigSize+PQSignatureSize {
		t.Fatalf("hybrid frame header len: got %d, want %d", HybridEnvelopeHeaderLen, 4+1+8+2+OriginNodeIDSize+OriginSigSize+PQSignatureSize)
	}
	batchWire := []byte("the batch wire begins at HybridEnvelopeHeaderLen")
	frame := MarshalHybridFrame([OriginNodeIDSize]byte{}, [OriginSigSize]byte{0xFF}, [PQSignatureSize]byte{0xFF}, 1, 1, batchWire)
	if len(frame) != HybridEnvelopeHeaderLen+len(batchWire) {
		t.Fatalf("hybrid frame header len: frame len=%d, want %d", len(frame), HybridEnvelopeHeaderLen+len(batchWire))
	}
	env, err := UnmarshalHybridFrame(frame)
	if err != nil {
		t.Fatalf("UnmarshalHybridFrame: %v", err)
	}
	if !bytes.Equal(env.BatchWire(), batchWire) {
		t.Fatalf("hybrid frame header len: batchWire mismatch — got %q, want %q", env.BatchWire(), batchWire)
	}
	t.Logf("hybrid frame header len: HybridEnvelopeHeaderLen=%d verified as exact batchWire start offset", HybridEnvelopeHeaderLen)
}
