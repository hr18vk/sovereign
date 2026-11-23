// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package fuzz

import (
	"encoding/binary"
	"hash/maphash"

	"github.com/hr18vk/sovereign/pkg/attribution"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// The constructors below feed both the targets' f.Add calls and the committed
// testdata/fuzz corpus. TestSeedCorpusMatchesBuilders checks their file counts,
// numeric order, and bytes against these builders, while TestSeedCorpusIsValid
// checks that committed inputs do not panic the default call paths.
//
// Each target has a well-formed input and small malformed inputs. Parsers with
// wire-controlled lengths also receive extreme values; on 64-bit builds these
// exercise rejection paths rather than reproduce a crash. The 32-bit relay
// limitation is documented in doc.go.

// fuzzSeed is the deterministic maphash.Seed the corpus builders reuse so the
// committed corpus is byte-stable across runs (maphash.MakeSeed is randomized
// per-process; a fixed seed makes the corpus reproducible). It is not the seed
// the production mesh uses; it is a corpus-stability constant.
var fuzzSeed = func() maphash.Seed {
	// Construct a seed from a fixed backing word (Uint64ToSeed is the inverse of
	// SeedToUint64 — the iblt_wire.go public round-trip pair). A fixed word
	// yields a bitwise-stable seed, which yields a byte-stable marshaled corpus.
	return eng.Uint64ToSeed(0x4441593333000001) // fixed seed constant + stable tail
}()

// validBatchEnvelope builds a well-formed BatchEnvelope wire (the happy-path
// seed for the batch arm). The originSig is non-zero (UnmarshalBatchEnvelope
// rejects a zero sig with ErrBatchUnsigned — a non-zero sig establishes the
// happy-path coverage of the full header parse, not the unsigned-reject branch).
// The batchWire body is a small opaque blob (the unmarshaler does not decode it;
// the O(1) header parse leaves batchWire as an aliasing sub-slice).
func validBatchEnvelope() []byte {
	var nodeID [attribution.OriginNodeIDSize]byte
	var sig [attribution.OriginSigSize]byte
	for i := range sig {
		sig[i] = byte(0xA0 + (i % 0x5F)) // a non-zero, non-uniform sig
	}
	body := []byte("opaque-batch-wire-body")
	return attribution.MarshalBatchEnvelope(nodeID, sig, 1, 1, body)
}

// validHybridFrame builds a well-formed HybridEnvelope wire (the happy-path seed
// for the hybrid arm). Both edSig and pqSig are non-zero (UnmarshalHybridFrame
// rejects a zero edSig or a zero pqSig with ErrHybridUnsigned — non-zero sigs
// establish the happy-path coverage of the full header parse, including the
// 3309-byte pqSig slot that dominates the header size).
func validHybridFrame() []byte {
	var nodeID [attribution.OriginNodeIDSize]byte
	var edSig [attribution.OriginSigSize]byte
	var pqSig [attribution.PQSignatureSize]byte
	for i := range edSig {
		edSig[i] = byte(0xB0 + (i % 0x4F))
	}
	for i := range pqSig {
		pqSig[i] = byte(0xC0 + (i % 0x3F))
	}
	body := []byte("opaque-hybrid-batch-wire-body")
	return attribution.MarshalHybridFrame(nodeID, edSig, pqSig, 1, 1, body)
}

// validRelayEnvelope builds a well-formed v3 RelayEnvelope wire (the happy-path
// seed for the relay arm). 0 hops (an origin frame — the rate gate skips, no
// last-hop read), a non-zero originSig, and a small inner wire. The inner wire
// is opaque (UnmarshalRelayEnvelope copies it; the gate-stack capnp decode is
// not the unmarshaler's job — the fuzz drives the unmarshal route, not the full
// gate stack).
func validRelayEnvelope() []byte {
	var originSig [attribution.OriginSigSize]byte
	for i := range originSig {
		originSig[i] = byte(0xD0 + (i % 0x2F))
	}
	var originNodeID [attribution.OriginNodeIDSize]byte
	inner := []byte("opaque-inner-capnp-wire")
	env := attribution.NewSignedRelayEnvelopeV3(inner, originSig, 42, originNodeID, nil)
	return env.Marshal()
}

// validStrataEstimator builds a well-formed StrataEstimator wire (the happy-path
// seed for the digest arm's SE half). A NewStrataEstimator with the fixed fuzz
// seed; the 32 strata are empty (no Inserts) so the marshaled body is the 13-byte
// header + 32 × the 80-bucket / k=3 IBLT blob. This is the largest happy-path
// seed (~52KB) — the digest arm's coverage of the per-stratum UnmarshalIBLT loop.
func validStrataEstimator() []byte {
	se := eng.NewStrataEstimator(fuzzSeed)
	b, _ := eng.MarshalStrataEstimator(se)
	return b
}

// validIBLT builds a well-formed IBLT wire (the happy-path seed for the IBLT
// unmarshaler target). An 80-bucket / k=3 IBLT with the fixed fuzz seed (the
// strataIBLTBuckets / strataK production params) — the minimal valid shape the
// production SE carries per stratum.
func validIBLT() []byte {
	ib := eng.NewIBLTWithSeed(80, 3, fuzzSeed)
	b, _ := eng.MarshalIBLT(ib)
	return b
}

// truncatedMagic returns a four-byte big-endian magic with no body. The prefix
// selects the corresponding DispatchFrame branch but is too short for its
// fixed-size envelope header.
func truncatedMagic(magicBE uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, magicBE)
	return out
}

// lengthBombIBLT declares numBuckets=0xFFFFFFFF. On 64-bit this exceeds
// maxIBLTBuckets; on 32-bit its int conversion is negative. The combined count
// check therefore returns ErrIBLTTooLarge before allocation on either width.
// Unlike the relay length seed, this input does not expose a 32-bit panic.
func lengthBombIBLT() []byte {
	out := make([]byte, 18)                             // ibltWireHeaderLen: magic(4)+numBuckets(4)+k(2)+seed(8)
	binary.LittleEndian.PutUint32(out[0:4], 0x49424C31) // 'IBL1'
	binary.LittleEndian.PutUint32(out[4:8], 0xFFFFFFFF) // the length-bomb
	binary.LittleEndian.PutUint16(out[8:10], 3)         // a valid k
	binary.LittleEndian.PutUint64(out[10:18], 0)        // a zero seed
	return out
}

// lengthBombRelay builds a v3 header whose innerLen is 0xFFFFFFFF. On 64-bit,
// the declared body exceeds the input and parsing returns ErrMalformed. On
// 32-bit, converting innerLen to int yields -1; the bounds check passes and
// make([]byte, innerLen) panics with a negative length before allocation. This
// is the relay-only 32-bit limitation described in doc.go.
func lengthBombRelay() []byte {
	// v3 header: version(2, LE = 3) + hopCount(2, LE = 0) + innerLen(4, LE = 0xFFFFFFFF)
	out := make([]byte, 96)                             // HeaderLen for v3
	binary.LittleEndian.PutUint16(out[0:2], 3)          // envelopeVersion v3
	binary.LittleEndian.PutUint16(out[2:4], 0)          // 0 hops
	binary.LittleEndian.PutUint32(out[4:8], 0xFFFFFFFF) // the length-bomb innerLen
	return out
}

// dispatchSeeds covers the batch, digest, and hybrid discriminators as well as
// the default relay route. Bare estimator bytes take the default route because
// DispatchFrame recognizes a digest by WireDigestMagic, not by the estimator's
// own wire magic. Extreme lengths and tiny inputs add malformed shapes.
func dispatchSeeds() [][]byte {
	return [][]byte{
		validBatchEnvelope(),
		validHybridFrame(),
		append([]byte{}, validStrataEstimator()...), // bare estimator bytes use the default route
		validRelayEnvelope(),
		truncatedMagic(attribution.WireV1Magic),
		truncatedMagic(attribution.WireDigestMagic),
		truncatedMagic(attribution.WireHybridPQMagic),
		lengthBombIBLT(),
		lengthBombRelay(),
		{0xAB}, // 1-byte adversarial
		{},     // 0-byte adversarial
	}
}

// batchSeeds supplies a valid BatchEnvelope, a truncated WireV1Magic, and
// empty or one-byte inputs. The fixed-size header has no wire-controlled
// allocation length.
func batchSeeds() [][]byte {
	return [][]byte{
		validBatchEnvelope(),
		truncatedMagic(attribution.WireV1Magic),
		{},     // 0-byte
		{0x53}, // 1-byte (the 'S' of "SBAT")
	}
}

// hybridSeeds is the FuzzUnmarshalHybridFrame corpus. A valid HybridEnvelope, a
// truncated WireHybridPQMagic, and the 1B/0B shapes. The hybrid header is
// fixed-size (3404 B) so the length-bomb class does not apply; the truncated
// magic exercises the short-header reject.
func hybridSeeds() [][]byte {
	return [][]byte{
		validHybridFrame(),
		truncatedMagic(attribution.WireHybridPQMagic),
		{},     // 0-byte
		{0x53}, // 1-byte ('S' of "SHYB")
	}
}

// relaySeeds is the FuzzUnmarshalRelayEnvelope corpus. A valid v3 envelope, a
// valid v2 envelope (the forward-compat branch), a lengthBombRelay (the OOM
// shape, no crash on 64-bit), a truncated version prefix, and the 1B/0B shapes.
func relaySeeds() [][]byte {
	v2 := validRelayEnvelope()
	// Mutate the v3 frame into a v2 frame by rewriting the version to 2 (the
	// forward-compat branch — headerLenForVersion(2) returns the 72-byte v2
	// header, and UnmarshalRelayEnvelope parses against that layout). A v2 frame
	// is shorter than v3 (no mirror fields); rewriting only the version keeps
	// the buffer long enough for the v2 header parse.
	if len(v2) >= 2 {
		v2 = append([]byte{}, v2...)
		v2[0] = 2
		v2[1] = 0
	}
	return [][]byte{
		validRelayEnvelope(),
		v2,                // the v2 forward-compat branch
		lengthBombRelay(), // the OOM shape (no crash on 64-bit)
		{0x03, 0x00},      // truncated v3 version prefix
		{},                // 0-byte
		{0x02},            // 1-byte (v2 version low byte)
	}
}

// strataSeeds supplies a valid estimator, a truncated magic, a header with 33
// strata instead of 32, and empty or one-byte inputs. The wrong count returns
// ErrMalformedStrata.
func strataSeeds() [][]byte {
	wrongCount := make([]byte, 13)                             // strataWireHeaderLen
	binary.LittleEndian.PutUint32(wrongCount[0:4], 0x53545241) // 'STRA'
	wrongCount[4] = 33                                         // invalid stratum count
	binary.LittleEndian.PutUint64(wrongCount[5:13], 0)
	return [][]byte{
		validStrataEstimator(),
		truncatedMagicLE(0x53545241), // 'STRA' is little-endian on the SE wire
		wrongCount,
		{},     // 0-byte
		{0x53}, // 1-byte
	}
}

// ibltSeeds supplies a valid IBLT, a truncated magic, an excessive bucket
// count, k=0, and empty or one-byte inputs. The oversized count is rejected
// before allocation; k=0 returns a malformed-input error.
func ibltSeeds() [][]byte {
	kBad := make([]byte, 18)
	binary.LittleEndian.PutUint32(kBad[0:4], 0x49424C31) // 'IBL1'
	binary.LittleEndian.PutUint32(kBad[4:8], 4)          // a small valid numBuckets
	binary.LittleEndian.PutUint16(kBad[8:10], 0)         // k=0 → out of range
	binary.LittleEndian.PutUint64(kBad[10:18], 0)
	return [][]byte{
		validIBLT(),
		truncatedMagicLE(0x49424C31), // 'IBL1'
		lengthBombIBLT(),
		kBad,
		{},     // 0-byte
		{0x49}, // 1-byte
	}
}

// truncatedMagicLE returns the first 4 bytes of a little-endian magic with no
// body (the IBLT/SE wires are little-endian, sibling to the big-endian batch
// /hybrid/digest magics). magicLE is the magic in native uint32 order; the
// little-endian PutUint32 emits the bytes the wire expects.
func truncatedMagicLE(magicLE uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, magicLE)
	return out
}
