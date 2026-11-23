// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package attribution also defines batch, digest, and hybrid wire envelopes.
// This file contains their framing; relay envelopes are in envelope.go.
//
// BatchEnvelope amortizes signature verification over self-originated deltas.
// A sequential Ed25519 VerifyCRDTFrame call costs about 60.19 us on the
// 32-core c8g.8xlarge baseline with circl v1.6.4. One signature per delta
// cannot reach one million deltas per second on one core. Signing a batch of
// N deltas reduces the verification component to 60.19/N us per delta, while
// decoding, applying, and network costs remain (ADR-0014 and ADR-0015).
//
// The origin signs the marshaled CRDTDeltaBatch wire directly:
//
//	batchSig = identity.SignCRDTFrame(originSeed, batchWire)
//	verify   = identity.VerifyCRDTFrame(originPub, batchWire, batchSig)
//
// Ed25519 already hashes the message with SHA-512 as part of RFC 8032, so an
// additional batch-root hash is unnecessary. Direct signing also reuses the
// existing verification path and covers the exact bytes that
// ApplyCRDTDeltaBatch decodes. There is no separately reconstructed payload
// between verification and application.
//
// BatchEnvelope is for deltas signed by their origin. A relay does not have
// another origin's private key, so it cannot produce that origin's batch
// signature. Foreign deltas instead use RelayEnvelope: each relay adds a
// SignHop signature over the inner wire and the preceding relay material.
//
// BatchEnvelope has the following wire layout. The receiver parses the header
// before verification and leaves batchWire opaque until verification succeeds.
//
//	[4]  magic         (uint32 big-endian, WireV1Magic)
//	[1]  version       (uint8, WireV1Version)
//	[8]  originSeq     (uint64 big-endian, monotonic per origin)
//	[2]  batchCount    (uint16 big-endian)
//	[16] originNodeID  (key for Directory.Lookup)
//	[64] originSig     (Ed25519 signature over batchWire)
//	[...] batchWire    (marshaled CRDTDeltaBatch capnp frame)
//
// originSeq advances by one for each batch. PeerBucket.Accept consumes the
// difference between successive values, so fixed-size batches still drain the
// origin's rate budget. batchCount is informational; the apply path obtains
// the authoritative count from CRDTDeltaBatch.Events().Len(). A zero originSig
// is rejected during parsing. batchWire is the exact signed byte sequence
// passed to ApplyCRDTDeltaBatch.
package attribution

import (
	"encoding/binary"
	"errors"
)

// WireV1Magic routes a frame to the batch parser after the receiver removes
// the length prefix. Its big-endian encoding begins with 0x53, whereas a
// RelayEnvelope begins with little-endian version 2 or 3 (0x02 or 0x03).
// A batch frame therefore cannot be mistaken for a relay frame.
const WireV1Magic uint32 = 0x53424154 // "SBAT" — Sovereign BATch (big-endian on the wire)

// WireV1Version identifies the BatchEnvelope layout. UnmarshalBatchEnvelope
// rejects any other version with ErrBatchMalformed.
const WireV1Version uint8 = 1

// BatchEnvelopeHeaderLen is the fixed size of the BatchEnvelope header
// (everything before the variable-length batchWire). It is the offset at which
// batchWire begins and the minimum length a frame must reach to parse a header.
// Kept in sync with the layout above: 4 + 1 + 8 + 2 + 16 + 64 = 95.
const BatchEnvelopeHeaderLen = 4 + 1 + 8 + 2 + OriginNodeIDSize + OriginSigSize

// ErrBatchMalformed is returned by UnmarshalBatchEnvelope when the wire is too
// short for a header, the magic does not match WireV1Magic, or the version does
// not match WireV1Version. It is the cheap pre-verify reject (the parser touches
// only the header; a malformed batchWire is deferred to the post-verify apply).
var ErrBatchMalformed = errors.New("attribution: malformed batch envelope header")

// ErrBatchUnsigned is returned when the parsed header carries a zero originSig
// — no unsigned batch is accepted (the same rule as envelope.go's
// zero-originSig rule: a zero originSig is a DropVerify, never an Accept).
var ErrBatchUnsigned = errors.New("attribution: batch envelope carries a zero origin signature")

// BatchEnvelope holds a parsed batch header and aliases the original wire.
// The origin signature covers batchWire, and ApplyCRDTDeltaBatch decodes those
// same bytes. UnmarshalBatchEnvelope parses only the fixed-size header;
// payload decoding and its errors belong to the post-verification apply path.
type BatchEnvelope struct {
	originNodeID [OriginNodeIDSize]byte
	originSig    [OriginSigSize]byte
	originSeq    uint64
	batchCount   uint16
	wire         []byte // the full envelope wire (header + batchWire); owned by the caller
}

// MarshalBatchEnvelope builds a batch wire from the origin identity fields
// and a marshaled CRDTDeltaBatch. The caller, normally mesh ShipBatch, creates
// batchWire with the capnp API and signs it with identity.SignCRDTFrame before
// calling this function. The returned slice is a new allocation owned by the
// caller.
//
// originSeq is the per-origin sequence passed to PeerBucket.Accept on receipt.
// batchCount is informational; CRDTDeltaBatch.Events().Len() is authoritative.
// originSig covers batchWire directly. A zero signature is serialized but
// rejected by the receiver's parser.
func MarshalBatchEnvelope(originNodeID [OriginNodeIDSize]byte, originSig [OriginSigSize]byte, originSeq uint64, batchCount uint16, batchWire []byte) []byte {
	out := make([]byte, BatchEnvelopeHeaderLen+len(batchWire))
	binary.BigEndian.PutUint32(out[0:4], WireV1Magic)
	out[4] = WireV1Version
	binary.BigEndian.PutUint64(out[5:13], originSeq)
	binary.BigEndian.PutUint16(out[13:15], batchCount)
	copy(out[15:15+OriginNodeIDSize], originNodeID[:])
	copy(out[15+OriginNodeIDSize:BatchEnvelopeHeaderLen], originSig[:])
	copy(out[BatchEnvelopeHeaderLen:], batchWire)
	return out
}

// UnmarshalBatchEnvelope parses a complete frame after the transport has
// removed its length prefix. It reads the fixed header and retains the wire;
// it does not decode batchWire. A short header, wrong magic, or wrong version
// returns ErrBatchMalformed. A zero originSig returns ErrBatchUnsigned.
//
// The returned envelope aliases wire. The caller must not modify wire for the
// lifetime of the envelope.
func UnmarshalBatchEnvelope(wire []byte) (*BatchEnvelope, error) {
	if len(wire) < BatchEnvelopeHeaderLen {
		return nil, ErrBatchMalformed
	}
	if binary.BigEndian.Uint32(wire[0:4]) != WireV1Magic {
		return nil, ErrBatchMalformed
	}
	if wire[4] != WireV1Version {
		return nil, ErrBatchMalformed
	}
	env := &BatchEnvelope{
		originSeq:  binary.BigEndian.Uint64(wire[5:13]),
		batchCount: binary.BigEndian.Uint16(wire[13:15]),
		wire:       wire,
	}
	copy(env.originNodeID[:], wire[15:15+OriginNodeIDSize])
	copy(env.originSig[:], wire[15+OriginNodeIDSize:BatchEnvelopeHeaderLen])
	if env.originSig == ([OriginSigSize]byte{}) {
		return nil, ErrBatchUnsigned
	}
	return env, nil
}

// BatchWire returns the signed CRDTDeltaBatch bytes that the receiver passes
// to ApplyCRDTDeltaBatch. The slice aliases the envelope's wire and must not
// be modified.
func (e *BatchEnvelope) BatchWire() []byte {
	return e.wire[BatchEnvelopeHeaderLen:]
}

// OriginNodeID returns the identity that Directory.Lookup resolves to the
// origin's Ed25519 public key. The rate gate zero-extends the same identity to
// 32 bytes when selecting the origin's bucket.
func (e *BatchEnvelope) OriginNodeID() [OriginNodeIDSize]byte { return e.originNodeID }

// OriginSeq returns the origin's monotonic per-batch sequence. PeerBucket.Accept
// charges the difference between successive values, so fixed-size batches
// continue to drain the origin's rate budget. BatchCount cannot serve this
// purpose because it does not increase between equal-sized batches.
func (e *BatchEnvelope) OriginSeq() uint64 { return e.originSeq }

// OriginSig returns the origin's 64-byte Ed25519 signature over batchWire.
// The receiver passes it to identity.VerifyCRDTFrame, covering every delta in
// the batch with one verification. UnmarshalBatchEnvelope rejects a zero value.
func (e *BatchEnvelope) OriginSig() [OriginSigSize]byte { return e.originSig }

// BatchCount returns the count declared in the header. It is informational;
// ApplyCRDTDeltaBatch uses CRDTDeltaBatch.Events().Len() as the authoritative
// count. The header value is available before capnp decoding.
func (e *BatchEnvelope) BatchCount() uint16 { return e.batchCount }

// IsBatchFrame is the dispatch discriminator a receiver peeks after the length
// prefix is stripped: it reads the first 4 bytes of the post-prefix frame body
// and returns true iff they match WireV1Magic (big-endian). It is a no-copy
// peek (it reads the slice header, never allocates). A false return routes the
// frame to the existing RelayEnvelope path (HandleFrame); a true return routes
// it to HandleBatchFrame. The RelayEnvelope's first 2 bytes are its uint16
// little-endian version (2 or 3), so its first 4 bytes never equal WireV1Magic
// (big-endian) — the dispatch is unambiguous.
//
// The peek reads the post-length-prefix body (ReadFrame already stripped the
// 4-byte length prefix), not the length prefix itself (the length prefix is
// common to both wire shapes and carries no type information).
func IsBatchFrame(frame []byte) bool {
	return len(frame) >= 4 && binary.BigEndian.Uint32(frame[0:4]) == WireV1Magic
}

// WireDigestMagic identifies a stratified anti-entropy digest after the
// transport removes the length prefix (ADR-0034). Its 0x53 leading byte differs
// from the RelayEnvelope version prefix, and the complete value differs from
// WireV1Magic, so batch, digest, and relay frames reach different parsers.
//
// A StrataEstimator and its remote IBLT are unsigned advisory data, not state.
// GenerateDelta uses the digest to select entries; a failed peel or an invalid
// subtraction falls back to sending every entry. A forged digest can otherwise
// change the selected set, causing oversend or delaying entries that a peer
// needs. It cannot directly inject state because the resulting deltas still
// travel as signed RelayEnvelope frames through the receive verification path.
const WireDigestMagic uint32 = 0x53445354 // "SDST" — Sovereign DiGeST (big-endian on the wire)

// IsDigestFrame reports whether a post-length-prefix frame starts with
// WireDigestMagic. The check does not allocate. Dispatch tries batch, digest,
// and hybrid recognition before falling back to the relay parser; a digest
// belongs to the mesh's digest sink rather than HandleFrame.
func IsDigestFrame(frame []byte) bool {
	return len(frame) >= 4 && binary.BigEndian.Uint32(frame[0:4]) == WireDigestMagic
}

// PutDigestFrame writes WireDigestMagic into the first four bytes of dst.
// buildDigestFrame uses it to tag a marshaled StrataEstimator for digest
// dispatch. The caller must provide at least four bytes.
func PutDigestFrame(dst []byte) {
	binary.BigEndian.PutUint32(dst[0:4], WireDigestMagic)
}

// Hybrid frames (ADR-0037) carry a 64-byte randomized-nonce Ed25519 signature
// and a 3309-byte ML-DSA-65 signature over the same 120-byte SHAKE256 pad of a
// self-originated batchWire. HandleHybridFrame resolves both public keys with
// Directory.LookupBoth and requires both verifications in VerifyBatchHybrid.
//
// Hybrid signing and verification are opt-in through --hybrid-sign and
// --hybrid-verify. A v1 batch carries only an Ed25519 signature and is rejected
// when hybrid verification is required. The default configuration uses v1.
// Hybrid frames have their own dispatch magic and enter the receive gate stack
// rather than the mesh's advisory digest sink.
//
// The hybrid header extends BatchEnvelope with pqSig:
//
//	[4]    magic        (uint32 big-endian, WireHybridPQMagic, "SHYB")
//	[1]    version      (uint8, WireHybridPQVersion)
//	[8]    originSeq    (uint64 big-endian, monotonic per origin)
//	[2]    batchCount   (uint16 big-endian, informational)
//	[16]   originNodeID (key for Directory.LookupBoth)
//	[64]   edSig        (randomized-nonce Ed25519 signature over the pad)
//	[3309] pqSig        (ML-DSA-65 signature over the same pad)
//	[...]  batchWire    (marshaled CRDTDeltaBatch capnp frame)
//
// SignCRDTFrame_Hybrid constructs the 120-byte SHAKE256 pad from batchWire.
// The hybrid verifier checks edSig first and pqSig second; a zero value for
// either signature is rejected during parsing. originSeq serves the same rate
// gate as BatchEnvelope. The pad is only signed and verified: the receiver
// passes the original batchWire, not the pad, to ApplyCRDTDeltaBatch.

// WireHybridPQMagic routes a post-length-prefix frame to HandleHybridFrame
// (ADR-0037). "SHYB" differs from the batch and digest magics, and its 0x53
// leading byte differs from the RelayEnvelope version prefix. The four frame
// shapes therefore have unambiguous dispatch; TestPQ_HybridFrameWireShape
// checks those distinctions.
const WireHybridPQMagic uint32 = 0x53485942 // "SHYB" — Sovereign HYBrid (big-endian on the wire)

// WireHybridPQVersion identifies the hybrid frame layout.
// UnmarshalHybridFrame rejects any other version with ErrHybridMalformed.
const WireHybridPQVersion uint8 = 1

// PQSignatureSize is the 3309-byte ML-DSA-65 signature size from FIPS 204.
// It mirrors mldsa.MLDSA65SignatureSize so this framing file need not import
// filippo.io/mldsa only for the constant. SignCRDTFrame_Hybrid returns an array
// of the same size, exercised by TestPQ_HybridSignThenVerify. The ML-DSA-65
// signature is 51.7 times the size of a 64-byte Ed25519 signature.
const PQSignatureSize = 3309

// HybridEnvelopeHeaderLen is the offset of batchWire and the shortest valid
// hybrid frame: 4 + 1 + 8 + 2 + 16 + 64 + 3309 = 3404 bytes. The corresponding
// classical BatchEnvelope header is 95 bytes.
const HybridEnvelopeHeaderLen = 4 + 1 + 8 + 2 + OriginNodeIDSize + OriginSigSize + PQSignatureSize

// ErrHybridMalformed is returned by UnmarshalHybridFrame for a short header,
// wrong magic, or unsupported version. Payload decoding remains the apply
// path's responsibility after signature verification.
var ErrHybridMalformed = errors.New("attribution: malformed hybrid-PQ envelope header")

// ErrHybridUnsigned is returned when either edSig or pqSig is zero. Hybrid
// verification requires both signatures; a frame with only one is rejected
// during parsing, just as ErrBatchUnsigned rejects an unsigned classical batch.
var ErrHybridUnsigned = errors.New("attribution: hybrid-PQ envelope carries a zero Ed25519 or ML-DSA-65 signature")

// HybridEnvelope is the opt-in hybrid-PQ batch format used with --hybrid-sign.
// It aliases the original wire, whose batchWire is covered by both signatures
// through the 120-byte SHAKE256 pad. UnmarshalHybridFrame parses only the
// header; ApplyCRDTDeltaBatch decodes the original payload after verification.
type HybridEnvelope struct {
	originNodeID [OriginNodeIDSize]byte
	edSig        [OriginSigSize]byte
	pqSig        [PQSignatureSize]byte
	originSeq    uint64
	batchCount   uint16
	wire         []byte // the full envelope wire (header + batchWire); owned by the caller
}

// MarshalHybridFrame builds a hybrid wire from the origin identity, both
// signatures, and a marshaled CRDTDeltaBatch. mesh ShipBatchHybrid creates
// batchWire with the capnp API and obtains edSig and pqSig from
// identity.SignCRDTFrame_Hybrid, which signs its 120-byte SHAKE256 pad.
// The returned slice is a new allocation owned by the caller.
//
// originSeq is the per-origin sequence used by PeerBucket.Accept. batchCount
// is informational; CRDTDeltaBatch.Events().Len() is authoritative. A zero
// signature is serialized but rejected by UnmarshalHybridFrame.
func MarshalHybridFrame(originNodeID [OriginNodeIDSize]byte, edSig [OriginSigSize]byte, pqSig [PQSignatureSize]byte, originSeq uint64, batchCount uint16, batchWire []byte) []byte {
	out := make([]byte, HybridEnvelopeHeaderLen+len(batchWire))
	binary.BigEndian.PutUint32(out[0:4], WireHybridPQMagic)
	out[4] = WireHybridPQVersion
	binary.BigEndian.PutUint64(out[5:13], originSeq)
	binary.BigEndian.PutUint16(out[13:15], batchCount)
	copy(out[15:15+OriginNodeIDSize], originNodeID[:])
	copy(out[15+OriginNodeIDSize:15+OriginNodeIDSize+OriginSigSize], edSig[:])
	copy(out[15+OriginNodeIDSize+OriginSigSize:HybridEnvelopeHeaderLen], pqSig[:])
	copy(out[HybridEnvelopeHeaderLen:], batchWire)
	return out
}

// UnmarshalHybridFrame parses a complete hybrid frame after transport length
// prefix removal. It reads the fixed header and retains the wire without
// decoding batchWire. Short headers, wrong magic, and unsupported versions
// return ErrHybridMalformed; a zero signature returns ErrHybridUnsigned.
//
// The returned envelope aliases wire. The caller must not modify wire for the
// lifetime of the envelope.
func UnmarshalHybridFrame(wire []byte) (*HybridEnvelope, error) {
	if len(wire) < HybridEnvelopeHeaderLen {
		return nil, ErrHybridMalformed
	}
	if binary.BigEndian.Uint32(wire[0:4]) != WireHybridPQMagic {
		return nil, ErrHybridMalformed
	}
	if wire[4] != WireHybridPQVersion {
		return nil, ErrHybridMalformed
	}
	edOff := 15 + OriginNodeIDSize
	pqOff := edOff + OriginSigSize
	env := &HybridEnvelope{
		originSeq:  binary.BigEndian.Uint64(wire[5:13]),
		batchCount: binary.BigEndian.Uint16(wire[13:15]),
		wire:       wire,
	}
	copy(env.originNodeID[:], wire[15:15+OriginNodeIDSize])
	copy(env.edSig[:], wire[edOff:edOff+OriginSigSize])
	copy(env.pqSig[:], wire[pqOff:HybridEnvelopeHeaderLen])
	if env.edSig == ([OriginSigSize]byte{}) || env.pqSig == ([PQSignatureSize]byte{}) {
		return nil, ErrHybridUnsigned
	}
	return env, nil
}

// BatchWire returns the original CRDTDeltaBatch bytes. Both signatures cover
// their 120-byte SHAKE256 pad, and ApplyCRDTDeltaBatch decodes this original
// payload after verification. The returned slice aliases the envelope's wire
// and must not be modified.
func (e *HybridEnvelope) BatchWire() []byte {
	return e.wire[HybridEnvelopeHeaderLen:]
}

// OriginNodeID returns the [16]byte origin identity the receiver resolves to
// both the Ed25519 and ML-DSA-65 public keys via the grown Directory.LookupBoth
// (ADR-0037). It is the key the hybrid verify keys on (both sigs over
// the batchWire's pad) and (zero-extended to 32 bytes) the key the rate gate
// buckets the origin under — the same dual role BatchEnvelope's OriginNodeID
// plays, carried forward to the hybrid frame.
func (e *HybridEnvelope) OriginNodeID() [OriginNodeIDSize]byte { return e.originNodeID }

// OriginSeq returns the origin's monotonic per-batch sequence. As with
// BatchEnvelope, PeerBucket.Accept charges the difference between successive
// values rather than using the fixed batch size.
func (e *HybridEnvelope) OriginSeq() uint64 { return e.originSeq }

// EdSig returns the 64-byte randomized-nonce Ed25519 signature over the
// 120-byte SHAKE256 pad of batchWire — the classical half of the hybrid contract,
// verified by VerifyCRDTFrame inside the hybrid gate (checked first so invalid
// classical frames skip PQ verification). A zero edSig is rejected pre-verify
// by UnmarshalHybridFrame.
func (e *HybridEnvelope) EdSig() [OriginSigSize]byte { return e.edSig }

// PQSig returns the 3309-byte ML-DSA-65 signature over the same 120-byte
// SHAKE256 pad of batchWire — the PQ half of the hybrid contract, verified by
// VerifyCRDTFrame_PostQuantum inside the hybrid gate (the expensive ~74us 4c
// gate that runs only after the classical verify passes). A zero pqSig is
// rejected pre-verify by UnmarshalHybridFrame (the unsigned-hybrid negative
// control — both sigs is the contract; a frame with one sig is a classical-only
// frame the hybrid verifier rejects, not a hybrid frame).
func (e *HybridEnvelope) PQSig() [PQSignatureSize]byte { return e.pqSig }

// BatchCount returns the informational count in the hybrid header. As with
// BatchEnvelope, the apply path uses CRDTDeltaBatch.Events().Len() instead.
func (e *HybridEnvelope) BatchCount() uint16 { return e.batchCount }

// IsHybridFrame is the dispatch discriminator a receiver peeks after the length
// prefix is stripped: it reads the first 4 bytes of the post-prefix frame body
// and returns true iff they match WireHybridPQMagic (big-endian). It is a
// no-copy peek (it reads the slice header, never allocates — sibling to
// IsBatchFrame + IsDigestFrame). A true return routes the frame to the hybrid
// path (Receiver.HandleHybridFrame, the 4th DispatchFrame arm); a false return
// leaves it for the batch/digest/relay arms. The four magics (WireV1Magic /
// WireDigestMagic / WireHybridPQMagic / the RelayEnvelope's uint16-LE version
// prefix 2|3) are pairwise bit-distinct (the first byte 0x53/0x53/0x53/0x02|0x03
// — the hybrid's 0x48 second byte separates it from SBAT's 0x42 + SDST's 0x44),
// so the dispatch order is unambiguous and a hybrid frame never reaches the
// relay parser (which would DropMalformed it) or the batch path (which would
// ErrBatchMalformed it).
//
// The peek reads the post-length-prefix body (ReadFrame already stripped the
// 4-byte length prefix), not the length prefix itself (the length prefix is
// common to all wire shapes and carries no type information).
func IsHybridFrame(frame []byte) bool {
	return len(frame) >= 4 && binary.BigEndian.Uint32(frame[0:4]) == WireHybridPQMagic
}
