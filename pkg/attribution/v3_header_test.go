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
	"time"
)

// The v3 header is 96 bytes: dotCounter occupies [72:80] and originNodeID
// occupies [80:96]. Reading these mirrors from fixed offsets avoids decoding
// the inner capnp CRDTDeltaEvent on the early rejection paths. Version 2 uses
// a 72-byte header without mirrors; the receiver accepts it and obtains the
// gate fields from the inner frame instead. Other versions return ErrMalformed.
//
// The header/inner consistency check is in pkg/receive, where HandleFrame can
// also check the engine's Join counter. These tests cover the wire layout,
// accessors, and version dispatch used by that check.

// testOriginNodeID is a distinct 16-byte originNodeID the v3 tests use (not
// the all-zero default, so a mirror-populated frame is distinguishable from a
// v2 frame's zero mirrors).
var testOriginNodeID = [OriginNodeIDSize]byte{
	0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67,
	0x89, 0xab, 0xcd, 0xef, 0x10, 0x20, 0x30, 0x40,
}

// TestV3HeaderLenIs96 checks the v3 header size: 2 bytes for the version,
// 2 for hopCount, 4 for innerLen, 64 for originSig, 8 for dotCounter, and 16
// for originNodeID. The receiver's raw-frame readers use HeaderLen, so this
// assertion catches a field-size change that would shift every later offset.
func TestV3HeaderLenIs96(t *testing.T) {
	if got, want := HeaderLen, 96; got != want {
		t.Fatalf("HeaderLen = %d, want %d (v3: 2+2+4+64+8+16)", got, want)
	}
	// The v2 header (forward-compat) is 72: HeaderLen minus the two mirror
	// fields. Sourcing it from the same consts keeps v2/v3 in lockstep.
	if got, want := headerLenV2, 72; got != want {
		t.Fatalf("headerLenV2 = %d, want %d (v2: 2+2+4+64, no mirrors)", got, want)
	}
}

// TestV3MarshalWritesMirrorsAtFixedOffsets proves Marshal writes the v3
// mirror fields at the documented fixed header offsets (dotCounter at [72:80],
// originNodeID at [80:96]) so the receiver's O(1) header read and the
// cross-check read the right bytes. It builds a v3 envelope, marshals it,
// and inspects the raw header at those offsets.
func TestV3MarshalWritesMirrorsAtFixedOffsets(t *testing.T) {
	inner := fakeInnerWire()
	const dotCounter = uint64(0x0123456789abcdef)
	originSig := [OriginSigSize]byte{}
	for i := range originSig {
		originSig[i] = byte(0xa0 + i)
	}
	env := NewSignedRelayEnvelopeV3(inner, originSig, dotCounter, testOriginNodeID, nil)
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
	if gotOrigin != testOriginNodeID {
		t.Fatalf("originNodeID at [80:96] = %x, want %x", gotOrigin, testOriginNodeID)
	}
	// Inner wire starts at HeaderLen (96), carried verbatim.
	if !bytes.Equal(wire[HeaderLen:HeaderLen+len(inner)], inner) {
		t.Fatalf("inner wire at [96:] must be carried verbatim")
	}
}

// TestV3UnmarshalReadsMirrors proves UnmarshalRelayEnvelope surfaces the v3
// mirror fields via the DotCounter()/OriginNodeID() accessors, so the
// receiver's cheap gates read them O(1) without a capnp decode. Round-trip:
// build v3 -> Marshal -> Unmarshal -> accessors return the bound values.
func TestV3UnmarshalReadsMirrors(t *testing.T) {
	inner := fakeInnerWire()
	const dotCounter = uint64(7)
	env := NewSignedRelayEnvelopeV3(inner, [OriginSigSize]byte{}, dotCounter, testOriginNodeID, nil)
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
	if got := parsed.OriginNodeID(); got != testOriginNodeID {
		t.Fatalf("OriginNodeID = %x, want %x", got, testOriginNodeID)
	}
}

// TestV2ForwardCompatAccepted checks that UnmarshalRelayEnvelope recognizes
// the 72-byte v2 header. Its mirror accessors return zero values, and the
// receiver's v2 branch decodes the gate fields from the inner capnp frame.
// Parsing follows the explicit v2 layout rather than treating absent mirrors
// as v3 values.
func TestV2ForwardCompatAccepted(t *testing.T) {
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
		t.Fatalf("v2 frame must be accepted (forward-compat), got err: %v", err)
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

// TestUnknownVersionRejected checks that versions other than 2 and 3 return
// an error instead of being parsed with a known header layout.
func TestUnknownVersionRejected(t *testing.T) {
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

// TestV3OpenUnchangedByMirrors checks that the v3 mirror fields do not enter
// the relay signed material. Open verifies the same relay chain and returns
// the same inner wire; the receiver checks the mirrors separately.
func TestV3OpenUnchangedByMirrors(t *testing.T) {
	inner := fakeInnerWire()
	env, relayPubs := buildRelayChain(t, inner, 3)
	// buildRelayChain uses NewRelayEnvelope (no originSig, no mirrors); rebuild
	// as v3 with mirrors to prove Open is mirror-agnostic.
	v3 := NewSignedRelayEnvelopeV3(inner, [OriginSigSize]byte{}, 42, testOriginNodeID, env.Hops())
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
