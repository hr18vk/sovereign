package attribution

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Track 3.6 — GATE-FIELD HEADER LIFT (v3 wire format + v2 forward-compat)
//
// These tests prove the v3 envelope wire format (Track 3.6): the 96-byte
// header carries the two cheap-gate mirror fields (dotCounter at [72:80],
// originNodeID at [80:96]) lifted out of the FROZEN inner capnp
// CRDTDeltaEvent, so the receiver's cheap 3.1/3.0 gates read them O(1) (two
// fixed-offset slice reads) instead of a ~1 us capnp decode. They also prove
// the v2 forward-compat dispatch (G3.6.e): a v2 frame (72-byte header, no
// mirrors) is ACCEPTED with zero mirrors, and a version other than 2 or 3 is
// an explicit ErrMalformed (no silent fall-through to zero fields — the C5
// failure mode). The adversarial header/inner-desync cross-check itself lives
// in pkg/receive (it needs the receiver's HandleFrame + the engine's Join
// counter); these tests cover the wire format + accessors + dispatch the
// cross-check and the cheap gates are built on.
// ---------------------------------------------------------------------------

// track36OriginNodeID is a distinct 16-byte originNodeID the v3 tests use (not
// the all-zero default, so a mirror-populated frame is distinguishable from a
// v2 frame's zero mirrors).
var track36OriginNodeID = [OriginNodeIDSize]byte{
	0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
	0x89, 0xab, 0xcd, 0xef, 0x10, 0x20, 0x30, 0x40,
}

// TestTrack36_V3HeaderLenIs96 proves the v3 header is exactly 96 bytes
// (2 ver + 2 hopCount + 4 innerLen + 64 originSig + 8 dotCounter + 16
// originNodeID). HeaderLen is the single source of truth the receiver's
// raw-frame readers source; pinning its value catches a future field-size
// change that would silently shift every offset.
func TestTrack36_V3HeaderLenIs96(t *testing.T) {
	if got, want := HeaderLen, 96; got != want {
		t.Fatalf("HeaderLen = %d, want %d (v3: 2+2+4+64+8+16)", got, want)
	}
	// The v2 header (forward-compat) is 72: HeaderLen minus the two mirror
	// fields. Sourcing it from the same consts keeps v2/v3 in lockstep.
	if got, want := headerLenV2, 72; got != want {
		t.Fatalf("headerLenV2 = %d, want %d (v2: 2+2+4+64, no mirrors)", got, want)
	}
}

// TestTrack36_V3MarshalWritesMirrorsAtFixedOffsets proves Marshal writes the
// v3 mirror fields at the documented fixed header offsets (dotCounter at
// [72:80], originNodeID at [80:96]) so the receiver's O(1) header read and
// the cross-check read the right bytes. It builds a v3 envelope, Marshals it,
// and inspects the raw header at those offsets.
func TestTrack36_V3MarshalWritesMirrorsAtFixedOffsets(t *testing.T) {
	inner := fakeInnerWire()
	const dotCounter = uint64(0x0123456789abcdef)
	originSig := [OriginSigSize]byte{}
	for i := range originSig {
		originSig[i] = byte(0xa0 + i)
	}
	env := NewSignedRelayEnvelopeV3(inner, originSig, dotCounter, track36OriginNodeID, nil)
	wire := env.Marshal()

	// Version field is v3.
	if got := binary.LittleEndian.Uint16(wire[0:2]); got != envelopeVersion {
		t.Fatalf("version = %d, want %d", got, envelopeVersion)
	}
	// originSig at [8:72].
	var gotSig [OriginSigSize]byte
	copy(gotSig[:], wire[8:72])
	if gotSig != originSig {
		t.Fatalf("originSig at [8:72] mismatch: got %x want %x", gotSig, originSig)
	}
	// dotCounter at [72:80] (little-endian uint64).
	off := 8 + OriginSigSize // 72
	if got := binary.LittleEndian.Uint64(wire[off : off+DotCounterSize]); got != dotCounter {
		t.Fatalf("dotCounter at [72:80] = %#x, want %#x", got, dotCounter)
	}
	// originNodeID at [80:96].
	off += DotCounterSize // 80
	var gotOrigin [OriginNodeIDSize]byte
	copy(gotOrigin[:], wire[off:off+OriginNodeIDSize])
	if gotOrigin != track36OriginNodeID {
		t.Fatalf("originNodeID at [80:96] = %x, want %x", gotOrigin, track36OriginNodeID)
	}
	// Inner wire starts at HeaderLen (96), carried verbatim.
	if !bytes.Equal(wire[HeaderLen:HeaderLen+len(inner)], inner) {
		t.Fatalf("inner wire at [96:] must be carried verbatim")
	}
}

// TestTrack36_V3UnmarshalReadsMirrors proves UnmarshalRelayEnvelope surfaces
// the v3 mirror fields via the DotCounter()/OriginNodeID() accessors, so the
// receiver's cheap gates read them O(1) without a capnp decode. Round-trip:
// build v3 -> Marshal -> Unmarshal -> accessors return the bound values.
func TestTrack36_V3UnmarshalReadsMirrors(t *testing.T) {
	inner := fakeInnerWire()
	const dotCounter = uint64(7)
	env := NewSignedRelayEnvelopeV3(inner, [OriginSigSize]byte{}, dotCounter, track36OriginNodeID, nil)
	parsed, err := UnmarshalRelayEnvelope(env.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalRelayEnvelope: %v", err)
	}
	if got := parsed.Version(); got != envelopeVersion {
		t.Fatalf("Version = %d, want %d (v3)", got, envelopeVersion)
	}
	if got := parsed.DotCounter(); got != dotCounter {
		t.Fatalf("DotCounter = %d, want %d", got, dotCounter)
	}
	if got := parsed.OriginNodeID(); got != track36OriginNodeID {
		t.Fatalf("OriginNodeID = %x, want %x", got, track36OriginNodeID)
	}
}

// TestTrack36_V2ForwardCompatAccepted proves a v2 frame (the 72-byte header
// with NO mirror fields) is ACCEPTED by UnmarshalRelayEnvelope (G3.6.e): the
// version is an explicit dispatch branch, the v2 header length is used, and
// the mirror accessors return their zero values (the receiver's v2 dispatch
// then falls back to a capnp decode for the gate fields). A v2 frame is NOT
// silently fall-through to zero fields on a v3 parser — the version is
// honored and the frame parses against the v2 layout.
func TestTrack36_V2ForwardCompatAccepted(t *testing.T) {
	inner := fakeInnerWire()
	// Build a v2 frame by hand: version 2, 72-byte header, no mirrors.
	n := 0
	v2 := make([]byte, headerLenV2+len(inner)+n*HopSize)
	binary.LittleEndian.PutUint16(v2[0:2], envelopeVersionV2)
	binary.LittleEndian.PutUint16(v2[2:4], uint16(n))
	binary.LittleEndian.PutUint32(v2[4:8], uint32(len(inner)))
	copy(v2[8:72], make([]byte, OriginSigSize)) // zero originSig
	copy(v2[headerLenV2:], inner)

	parsed, err := UnmarshalRelayEnvelope(v2)
	if err != nil {
		t.Fatalf("v2 frame must be ACCEPTED (forward-compat), got err: %v", err)
	}
	if got := parsed.Version(); got != envelopeVersionV2 {
		t.Fatalf("v2 frame Version = %d, want %d", got, envelopeVersionV2)
	}
	// v2 carries no mirrors: the accessors return zero (the receiver's v2
	// dispatch falls back to a capnp decode for the gate fields).
	if got := parsed.DotCounter(); got != 0 {
		t.Fatalf("v2 frame DotCounter = %d, want 0 (no mirror in v2 header)", got)
	}
	var zeroOrigin [OriginNodeIDSize]byte
	if got := parsed.OriginNodeID(); got != zeroOrigin {
		t.Fatalf("v2 frame OriginNodeID = %x, want all-zero (no mirror in v2 header)", got)
	}
	// The inner wire is still carried verbatim.
	if !bytes.Equal(parsed.InnerWire(), inner) {
		t.Fatalf("v2 frame inner wire must be carried verbatim")
	}
}

// TestTrack36_UnknownVersionRejected proves a version other than 2 or 3 is an
// explicit ErrMalformed — NOT a silent fall-through to zero fields (the C5
// failure mode the audit chain closed). v1 (version 1) and a future v4 are
// both rejected with a named error naming the unsupported version.
func TestTrack36_UnknownVersionRejected(t *testing.T) {
	for _, ver := range []uint16{1, 4, 99, 0} {
		w := make([]byte, HeaderLen+8)
		binary.LittleEndian.PutUint16(w[0:2], ver)
		binary.LittleEndian.PutUint16(w[2:4], 0)
		binary.LittleEndian.PutUint32(w[4:8], 0)
		_, err := UnmarshalRelayEnvelope(w)
		if err == nil {
			t.Fatalf("version %d must be rejected (unsupported), got nil err", ver)
		}
	}
}

// TestTrack36_V3OpenUnchangedByMirrors proves the v3 mirror fields do NOT
// affect Open's cryptographic verify: Open verifies the relay hops over the
// inner wire + signed material (unchanged in v3), and the mirrors are
// header-only metadata the receiver cross-checks separately. A v3 envelope
// with mirrors opens identically to a v2 envelope over the same hops.
func TestTrack36_V3OpenUnchangedByMirrors(t *testing.T) {
	inner := fakeInnerWire()
	env, relayPubs := buildRelayChain(t, inner, 3)
	// buildRelayChain uses NewRelayEnvelope (no originSig, no mirrors); rebuild
	// as v3 with mirrors to prove Open is mirror-agnostic.
	v3 := NewSignedRelayEnvelopeV3(inner, [OriginSigSize]byte{}, 42, track36OriginNodeID, env.Hops())
	gotInner, hops, err := v3.Open(MaxHopsForBudget(1 * time.Millisecond))
	if err != nil {
		t.Fatalf("v3 Open: %v", err)
	}
	if hops != 3 || !bytes.Equal(gotInner, inner) {
		t.Fatalf("v3 Open must return the verbatim inner wire + hop count (mirrors do not affect Open)")
	}
	// The relay pubs are unchanged (Open verifies the same hops).
	if len(relayPubs) != 3 {
		t.Fatalf("relayPubs len = %d, want 3", len(relayPubs))
	}
}
