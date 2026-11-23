// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package attribution implements signed envelopes for CRDT delta transport.
// A RelayEnvelope carries the inner origin signature and one signature for
// each relay hop. Checking the hop limit before any of those signatures keeps
// a forged deep envelope from consuming verification work proportional to its
// declared depth.
//
// Inbound frames cross these checks in order:
//
//	[wire] -> PeerBucket.Accept(pub, counter)      // per-peer rate cap
//	       -> if Keep: IngressHLCScalarCap.Admit    // clock cap
//	       -> if accept: RelayEnvelope.Open         // hop limit, relay signatures
//	       -> if envelope ok: VerifyCRDTFrame       // inner origin signature
//	       -> if verify ok: engine.Join / ApplyCRDTDeltaEvent
//
// Benchmarks on a 32-core c8g.8xlarge measured about 36 ns for the rate check,
// 3.1 ns for the clock check, and 60.2 us for an Ed25519 verification. Open
// compares the hop count with the caller's bound and returns immediately when
// it is exceeded. Otherwise it verifies the relay chain; the caller verifies
// the inner origin signature before applying the delta.
//
// The package uses identity.VerifyCRDTFrame and circl's Ed25519 implementation.
// It does not import pkg/sync, pkg/clock, or pkg/admission: Open returns the
// verified inner wire, and the caller applies it. The outer envelope has its
// own deterministic length-prefixed layout. It carries the inner capnp
// CRDTDeltaEvent unchanged, so this package does not depend on the capnp
// schema or its generator.
package attribution

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/ed25519"

	"github.com/hr18vk/sovereign/pkg/identity"
)

// verifyHook replaces identity.VerifyCRDTFrame in tests that count calls.
// A nil hook selects the production verification path. verifyHookMu protects
// both setting the hook and reading it in Open.
var (
	verifyHookMu sync.Mutex
	verifyHook   func(pub ed25519.PublicKey, msg, sig []byte) bool
)

// verifyCostPerHop32c is the measured Ed25519 verification latency on a
// 32-core c8g.8xlarge (Graviton4, CPU part 0xd4f). BenchmarkVerifyCRDTFrame_32c
// ran with GOMAXPROCS=32, -cpu=32 -benchtime=3s -count=3 and measured 60,198,
// 59,595, and 60,841 ns/op, for a mean of approximately 60,211 ns/op.
// MaxHopsForBudget divides the caller's duration budget by this cost.
const verifyCostPerHop32c = 60211 // nanoseconds, measured on c8g.8xlarge at 32 cores

// envelopeVersion identifies the outer framing, independently of the version
// inside the capnp CRDTDeltaEvent.
//
// Version 2 introduced a 64-byte originSig header field. The inner event has
// originNodeID but no origin signature, so the outer header carries that
// signature without changing the capnp schema. The receiver resolves the
// origin public key through the identity Directory and verifies originSig
// against the inner wire returned by Open.
//
// Version 3 adds 8-byte dotCounter and 16-byte originNodeID mirrors. Earlier
// versions required a roughly 1 us capnp decode before the rate and clock
// gates could reject a frame; fixed-offset header reads avoid that work. The
// inner frame remains unchanged, and the receiver compares both mirrors with
// the decoded inner fields on the accept path.
const envelopeVersion uint16 = 3

// The version 3 wire format uses fixed-size little-endian header fields:
//
//	[2]  envelopeVersion
//	[2]  hopCount
//	[4]  innerLen
//	[64] originSig         (signature over innerWire, verified by the caller)
//	[8]  dotCounter        (mirror of CRDTDeltaEvent.DotCounter)
//	[16] originNodeID      (mirror of CRDTDeltaEvent.OriginNodeID)
//	[innerLen] innerWire   (verbatim capnp CRDTDeltaEvent)
//	then for each of hopCount hops:
//	  [32] relayPub        (Ed25519 public key)
//	  [64] sig             (Ed25519 signature over the signed material)
//	  [8]  wallUSec         (relay timestamp in microseconds)
//
// Open checks the declared hop count before verifying any hop. The rate and
// clock gates read the two mirror fields without decoding the inner frame,
// and the accept path checks them against that frame after decoding it.
// Each relay signs innerWire || precedingHopsSigMaterial || hopIndex ||
// wallUSec, binding its signature to the inner frame and the preceding chain.
//
// OriginSigSize is the size of the origin signature field introduced in
// version 2. It equals SigSize but distinguishes the origin signature checked
// by the caller from a relay signature checked by Open.
const (
	PubSize          = 32 // ed25519.PublicKeySize
	SigSize          = 64 // ed25519.SignatureSize
	OriginSigSize    = 64 // origin Ed25519 signature (verified by caller, not Open)
	WallSize         = 8  // int64 microseconds
	DotCounterSize   = 8  // uint64 — the cheap-gate mirror of the inner capnp DotCounter (v3)
	OriginNodeIDSize = 16 // [16]byte — the cheap-gate mirror of the inner capnp OriginNodeID (v3)
	HopSize          = PubSize + SigSize + WallSize
	HeaderLen        = 2 + 2 + 4 + OriginSigSize + DotCounterSize + OriginNodeIDSize // version + hopCount + innerLen + originSig + dotCounter + originNodeID
)

// ErrHopBoundExceeded is returned by Open when the hop count exceeds the
// configured bound. Open performs no signature verification in this case.
// Callers can distinguish this depth rejection from ErrVerify.
var ErrHopBoundExceeded = errors.New("attribution: relay hop-count exceeds bound (dropped before Verify)")

// ErrVerify is returned by Open when an outer relay signature fails Ed25519
// verification. Hop-limit failures return ErrHopBoundExceeded instead.
var ErrVerify = errors.New("attribution: envelope signature verification failed")

// ErrMalformed is returned when wire bytes do not conform to the envelope
// framing, including a short header, truncated hop record, or inner length
// larger than the available buffer. Parsing fails before signature
// verification.
var ErrMalformed = errors.New("attribution: malformed envelope framing")

// Hop records one relay's public key, signature, and physical timestamp in
// microseconds. The public key uses a fixed-size array rather than circl's
// non-comparable slice type, and the timestamp is available to the clock cap.
type Hop struct {
	RelayPub [PubSize]byte // the relay peer's Ed25519 pubkey (canonical copy)
	Sig      [SigSize]byte // the relay's Ed25519 sig over the signed material
	WallUSec int64         // the relay's physical timestamp (microseconds)
}

// RelayEnvelope wraps a capnp CRDTDeltaEvent without re-serializing it. Open
// returns those same inner bytes after checking the relay chain. Constructors
// copy the input slices, and Open does not mutate the envelope, so an envelope
// can be opened concurrently.
//
// Versions 2 and 3 carry originSig, the origin's Ed25519 signature over the
// inner wire. Open does not verify it. After Open succeeds, the caller resolves
// originPub through the identity Directory and calls VerifyCRDTFrame.
// NewRelayEnvelope leaves originSig zero for compatibility with out-of-band
// origin verification; the production receiver rejects a zero signature.
type RelayEnvelope struct {
	innerWire    []byte
	originSig    [OriginSigSize]byte
	dotCounter   uint64                 // v3 mirror of the inner capnp DotCounter (the cheap-gate field)
	originNodeID [OriginNodeIDSize]byte // v3 mirror of the inner capnp OriginNodeID (the cheap-gate field)
	version      uint16                 // the on-wire envelopeVersion this envelope was parsed from (2 or 3); 0 for a build-side envelope not yet Marshaled
	hops         []Hop
}

// MaxHopsForBudget converts a duration budget into a relay hop limit using
// the measured verification cost. An N-hop envelope needs N outer relay
// verifications plus the caller's inner origin verification, so the bound is
// floor(budget / verifyCostPerHop32c) - 1.
//
// Negative results are clamped to zero. A budget below one verification cost,
// including a non-positive budget, therefore admits only a direct origin frame.
// For example, a 1 ms budget yields floor(1_000_000 / 60_211) - 1 = 15 hops.
func MaxHopsForBudget(budget time.Duration) int {
	if budget <= 0 {
		return 0
	}
	cost := int64(verifyCostPerHop32c)
	n := int64(budget) / cost
	n-- // -1 for the inner origin Verify
	if n < 0 {
		n = 0
	}
	return int(n)
}

// NewRelayEnvelope constructs an envelope from innerWire and ordered relay
// hops. Hop 0 is the first relay after the origin; the last is closest to the
// receiver. The constructor copies both inputs, so the caller retains ownership
// of its slices.
//
// originSig remains zero for compatibility with callers that verify the origin
// out of band. Production senders use NewSignedRelayEnvelope or
// NewSignedRelayEnvelopeV3 to carry the signature on the wire; the production
// receiver rejects a zero signature.
func NewRelayEnvelope(innerWire []byte, hops []Hop) *RelayEnvelope {
	inner := make([]byte, len(innerWire))
	copy(inner, innerWire)
	hs := make([]Hop, len(hops))
	copy(hs, hops)
	return &RelayEnvelope{innerWire: inner, hops: hs}
}

// NewSignedRelayEnvelope constructs an envelope whose header carries the
// origin's 64-byte Ed25519 signature over innerWire. The origin computes
// originSig with ed25519.Sign(originPriv, innerWire). After Open verifies the
// relay hops, the receiver resolves originPub through the identity Directory
// and verifies originSig against the returned inner wire.
//
// The constructor copies innerWire, hops, and originSig. It does not populate
// the version 3 mirror fields.
func NewSignedRelayEnvelope(innerWire []byte, originSig [OriginSigSize]byte, hops []Hop) *RelayEnvelope {
	e := NewRelayEnvelope(innerWire, hops)
	e.originSig = originSig
	return e
}

// NewSignedRelayEnvelopeV3 adds dotCounter and originNodeID to the signed
// envelope header. The origin already has these values from constructing the
// inner CRDTDeltaEvent, so the builder need not import or decode the capnp
// schema. The early admission gates read the mirrors directly; the receiver
// compares them with the decoded inner fields before accepting the frame.
//
// A forwarding relay retains both mirrors unchanged and appends its own hop.
// The constructor copies every input, including innerWire and hops.
func NewSignedRelayEnvelopeV3(innerWire []byte, originSig [OriginSigSize]byte, dotCounter uint64, originNodeID [OriginNodeIDSize]byte, hops []Hop) *RelayEnvelope {
	e := NewRelayEnvelope(innerWire, hops)
	e.originSig = originSig
	e.dotCounter = dotCounter
	e.originNodeID = originNodeID
	return e
}

// OriginSig returns the origin signature carried in version 2 and 3 headers.
// After Open succeeds, the receiver passes it to VerifyCRDTFrame with the
// resolved origin public key and returned inner wire. NewRelayEnvelope leaves
// it zero, which the production receiver rejects. Open does not check it.
func (e *RelayEnvelope) OriginSig() [OriginSigSize]byte { return e.originSig }

// DotCounter returns the v3 mirror of CRDTDeltaEvent.DotCounter. The rate and
// clock gates read it without decoding the inner frame. It is zero for a v2
// envelope, whose receiver decodes the inner frame instead. The accept path
// checks the mirror against the decoded value.
func (e *RelayEnvelope) DotCounter() uint64 { return e.dotCounter }

// OriginNodeID returns the v3 mirror of CRDTDeltaEvent.OriginNodeID, which
// Directory.Lookup uses to resolve the origin keys. It is zero for a v2
// envelope, whose receiver decodes the inner frame instead. The accept path
// checks the mirror against the decoded value.
func (e *RelayEnvelope) OriginNodeID() [OriginNodeIDSize]byte { return e.originNodeID }

// HopCount returns the number of relay hops in the envelope. It is the O(1)
// header read the depth check runs against.
func (e *RelayEnvelope) HopCount() int { return len(e.hops) }

// Version returns the wire version recorded by UnmarshalRelayEnvelope: 2 or
// 3. It is zero on a newly constructed envelope until that envelope is parsed.
// Marshal always writes the current version 3 format. Receivers use the parsed
// version to select header mirrors for v3 or capnp decoding for v2.
func (e *RelayEnvelope) Version() uint16 { return e.version }

// InnerWire returns the inner CRDT-delta bytes. They are not authenticated
// until Open and the caller's origin-signature check have both succeeded. The
// returned slice aliases the envelope and must not be modified.
func (e *RelayEnvelope) InnerWire() []byte { return e.innerWire }

// Hops returns a copy of the relay records for rebuilding the signed-material
// prefix when forwarding a frame. Changes to the returned slice do not affect
// the envelope. The records are not authenticated until Open succeeds.
func (e *RelayEnvelope) Hops() []Hop {
	hs := make([]Hop, len(e.hops))
	copy(hs, e.hops)
	return hs
}

// Open verifies the envelope's relay provenance against the configured hop
// bound and returns the verified inner wire bytes. It is the third admission
// gate. The verify order is:
//
//  1. O(1) depth check: if len(hops) > maxHops, return ErrHopBoundExceeded
//     without any Ed25519 Verify (the reject-before-Verify defense).
//  2. Outer hops: for each hop in order, verify the relay's Ed25519 sig
//     over the signed material (innerWire || preceding hops' sig material
//     || hopIndex || wallUSec) via identity.VerifyCRDTFrame. A failure
//     returns ErrVerify and the inner wire is never reached.
//  3. Inner origin: after all outer hops pass, the caller verifies the
//     inner origin sig on the returned innerWire. The -1 in
//     MaxHopsForBudget reserves budget for this inner Verify.
//
// On success, returns (innerWire, hopCount, nil). On any failure, returns
// (nil, 0, err). The caller (ingestion pipeline) does:
//
//	inner, _, err := envelope.Open(maxHops)
//	if err != nil { drop }
//	if !identity.VerifyCRDTFrame(originPub, inner, originSig) { drop }
//	engine.ApplyCRDTDeltaEvent(inner)
//
// The package never calls Join / ApplyCRDTDeltaEvent (keeps pkg/sync out of
// the dep set). Open is safe for concurrent use: it reads the immutable
// envelope state and allocates only per-call scratch buffers for the signed
// material.
func (e *RelayEnvelope) Open(maxHops int) ([]byte, int, error) {
	// 1. O(1) depth check before any crypto. A forged deep envelope is
	// dropped in nanoseconds, zero Verifies.
	n := len(e.hops)
	if n > maxHops {
		return nil, 0, ErrHopBoundExceeded
	}

	// 2. Verify each outer relay hop in order. The signed material for hop
	// i is the concatenation of the inner wire, the signed material of all
	// preceding hops, the hop index, and this hop's wall timestamp. This
	// binds each relay's signature to the exact inner frame and the exact
	// prefix of relay hops it attests — a relay cannot splice its sig onto
	// a different frame or a different prefix.
	var preceding []byte
	verifyHookMu.Lock()
	hook := verifyHook
	verifyHookMu.Unlock()
	for i, hop := range e.hops {
		material := SignedMaterial(e.innerWire, preceding, uint16(i), hop.WallUSec)
		var ok bool
		if hook != nil {
			ok = hook(ed25519.PublicKey(hop.RelayPub[:]), material, hop.Sig[:])
		} else {
			ok = identity.VerifyCRDTFrame(ed25519.PublicKey(hop.RelayPub[:]), material, hop.Sig[:])
		}
		if !ok {
			return nil, 0, fmt.Errorf("%w: outer relay hop %d", ErrVerify, i)
		}
		// The preceding-material accumulator is the signed material of
		// this hop, so the next hop's material transitively binds the
		// whole prefix.
		preceding = material
	}

	// 3. Return the verified inner wire. The inner origin sig is verified
	// by the caller after all outer hops pass — the ordering proves
	// outer-before-inner (TestEnvelope_TamperedOriginSig).
	return e.innerWire, n, nil
}

// SignedMaterial constructs the deterministic byte string a relay signs (and
// Open verifies) for one hop: innerWire || preceding || hopIndex || wallUSec.
// hopIndex is a uint16 little-endian so a relay cannot reorder hops without
// breaking the signature; wallUSec is int64 little-endian so the clock cap
// can check the relay's physical timestamp. The preceding slice is the
// signed material of all prior hops, transitively binding the chain of
// custody.
func SignedMaterial(innerWire, preceding []byte, hopIndex uint16, wallUSec int64) []byte {
	var idx [2]byte
	binary.LittleEndian.PutUint16(idx[:], hopIndex)
	var wall [WallSize]byte
	binary.LittleEndian.PutUint64(wall[:], uint64(wallUSec))
	out := make([]byte, 0, len(innerWire)+len(preceding)+2+WallSize)
	out = append(out, innerWire...)
	out = append(out, preceding...)
	out = append(out, idx[:]...)
	out = append(out, wall[:]...)
	return out
}

// SignHop is the build-side helper a relay uses to produce a Hop record. It
// signs the deterministic material (innerWire || preceding || hopIndex ||
// wallUSec) with the relay's Ed25519 private key. It is the inverse of
// Open's per-hop Verify. Production relays call this before appending the
// Hop to the envelope; tests call it to build the A->B->C->D relay chain.
//
// preceding is the signed material of all prior hops (empty for the first
// relay after the origin). It is the same accumulator Open threads through
// the verify loop, so a Hop built by SignHop verifies under Open.
func SignHop(relayPriv ed25519.PrivateKey, relayPub [PubSize]byte, innerWire, preceding []byte, hopIndex uint16, wallUSec int64) Hop {
	material := SignedMaterial(innerWire, preceding, hopIndex, wallUSec)
	sig := ed25519.Sign(relayPriv, material)
	var h Hop
	h.RelayPub = relayPub
	copy(h.Sig[:], sig)
	h.WallUSec = wallUSec
	return h
}

// headerLenV2 is the 72-byte v2 header: version, hopCount, innerLen, and
// originSig. Deriving it from HeaderLen by subtracting the v3 mirror fields
// keeps the two layouts consistent.
const headerLenV2 = HeaderLen - DotCounterSize - OriginNodeIDSize

// Marshal serializes the current version 3 wire format. It writes hopCount
// before the hop records, places originSig at [8:72], dotCounter at [72:80],
// and originNodeID at [80:96], then copies innerWire unchanged. The returned
// slice is a new allocation owned by the caller.
func (e *RelayEnvelope) Marshal() []byte {
	n := len(e.hops)
	out := make([]byte, HeaderLen+len(e.innerWire)+n*HopSize)
	binary.LittleEndian.PutUint16(out[0:2], envelopeVersion)
	binary.LittleEndian.PutUint16(out[2:4], uint16(n))
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(e.innerWire)))
	copy(out[8:8+OriginSigSize], e.originSig[:])
	off := 8 + OriginSigSize
	binary.LittleEndian.PutUint64(out[off:off+DotCounterSize], e.dotCounter)
	off += DotCounterSize
	copy(out[off:off+OriginNodeIDSize], e.originNodeID[:])
	off = copy(out[HeaderLen:], e.innerWire)
	for i, hop := range e.hops {
		base := HeaderLen + off + i*HopSize
		copy(out[base:base+PubSize], hop.RelayPub[:])
		copy(out[base+PubSize:base+PubSize+SigSize], hop.Sig[:])
		binary.LittleEndian.PutUint64(out[base+PubSize+SigSize:base+HopSize], uint64(hop.WallUSec))
	}
	return out
}

// UnmarshalRelayEnvelope parses a version 2 or 3 envelope and checks that the
// buffer contains the declared header, inner wire, and hop records. It does
// not verify signatures; Open performs the relay checks afterward.
//
// The returned envelope exposes originSig and, for v3, the gate-field mirrors.
// The caller verifies originSig after Open and compares the mirrors with the
// decoded inner frame on the accept path. A v2 envelope leaves both mirrors
// zero so the receiver decodes those fields from the inner frame instead.
// Unsupported versions and truncated buffers return ErrMalformed.
func UnmarshalRelayEnvelope(wire []byte) (*RelayEnvelope, error) {
	if len(wire) < 2 {
		return nil, ErrMalformed
	}
	ver := binary.LittleEndian.Uint16(wire[0:2])
	hdrLen, ok := headerLenForVersion(ver)
	if !ok {
		return nil, fmt.Errorf("%w: envelope version %d unsupported (want %d or %d)", ErrMalformed, ver, envelopeVersion, envelopeVersionV2)
	}
	if len(wire) < hdrLen {
		return nil, ErrMalformed
	}
	n := int(binary.LittleEndian.Uint16(wire[2:4]))
	innerLen := int(binary.LittleEndian.Uint32(wire[4:8]))
	need := hdrLen + innerLen + n*HopSize
	if len(wire) < need {
		return nil, ErrMalformed
	}
	var originSig [OriginSigSize]byte
	copy(originSig[:], wire[8:8+OriginSigSize])
	var dotCounter uint64
	var originNodeID [OriginNodeIDSize]byte
	if ver == envelopeVersion {
		off := 8 + OriginSigSize
		dotCounter = binary.LittleEndian.Uint64(wire[off : off+DotCounterSize])
		off += DotCounterSize
		copy(originNodeID[:], wire[off:off+OriginNodeIDSize])
	}
	inner := make([]byte, innerLen)
	copy(inner, wire[hdrLen:hdrLen+innerLen])
	hops := make([]Hop, n)
	for i := 0; i < n; i++ {
		base := hdrLen + innerLen + i*HopSize
		h := Hop{}
		copy(h.RelayPub[:], wire[base:base+PubSize])
		copy(h.Sig[:], wire[base+PubSize:base+PubSize+SigSize])
		h.WallUSec = int64(binary.LittleEndian.Uint64(wire[base+PubSize+SigSize : base+HopSize]))
		hops[i] = h
	}
	return &RelayEnvelope{innerWire: inner, originSig: originSig, dotCounter: dotCounter, originNodeID: originNodeID, version: ver, hops: hops}, nil
}

// envelopeVersionV2 identifies the earlier 72-byte header without mirror
// fields. Receivers decode its gate fields from the inner capnp frame.
const envelopeVersionV2 uint16 = 2

// headerLenForVersion returns 96 for v3 and 72 for v2. The boolean is false
// for unsupported versions. Both values derive from the shared size constants.
func headerLenForVersion(ver uint16) (int, bool) {
	switch ver {
	case envelopeVersion:
		return HeaderLen, true
	case envelopeVersionV2:
		return headerLenV2, true
	default:
		return 0, false
	}
}

// RelayEnvelopeVersion returns the current wire version, 3. Callers can use
// it instead of duplicating the version constant when encoding or dispatching
// envelopes. Version 2 remains accepted for compatibility.
func RelayEnvelopeVersion() uint16 { return envelopeVersion }

// HeaderLenForVersion exposes the supported wire header sizes to pkg/receive.
// It returns 96 for v3, 72 for v2, and (0, false) for other versions, allowing
// raw-frame readers such as readLastHop to locate hop records without
// duplicating the layout.
func HeaderLenForVersion(ver uint16) (int, bool) {
	return headerLenForVersion(ver)
}
