package fuzz

import (
	"encoding/binary"
	"hash/maphash"

	"github.com/hr18vk/supremum/pkg/attribution"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// seeds_test.go is the SINGLE SOURCE OF TRUTH for the Day-33 fuzz seed corpus.
// Every fuzz target's f.Add(...) calls AND the on-disk testdata/fuzz/ corpus
// files derive from the constructors below (the desync discipline — one builder,
// no drift between the in-process seeds and the committed corpus). A seed that
// the corpus materializes but a target does not Add is a coverage hole; a seed
// a target Adds but the corpus does not carry is an unreproducible finding.
//
// The desync discipline is ENFORCED by TestSeedCorpusMatchesBuilders
// (T-FUZZ-CORPUS-BYTE-IDENTITY in seed_corpus_test.go): it re-derives the corpus
// from the per-target aggregators below (dispatchSeeds / batchSeeds / hybridSeeds
// / relaySeeds / strataSeeds / ibltSeeds + the build-tagged bugInjectSeeds) and
// asserts the on-disk files match byte-for-byte (count + per-index bytes), so a
// hand-broken seed OR a builder mutated without regenerating the corpus fails the
// tooth (Law II). The SISTER tooth TestSeedCorpusIsValid (T-FUZZ-CORPUS-
// REPRODUCIBLE) enforces a DIFFERENT property — no committed seed PANICS the
// matching unmarshaler (a seed that crashes is a corpus defect); it does NOT
// assert byte-equality (the §33 /ruthless-auditor finding: the prior docstring
// over-claimed it did). The two teeth are distinct falsifiable properties.
//
// The corpus is the M4 MINIMUM: (a) the valid magic + a well-formed body (the
// happy-path seed establishing each arm's coverage); (b) a TRUNCATED magic (the
// first 4 bytes + NO body — the length-bomb-empty shape); (c) a length-bomb (a
// valid magic + a uint32 length field of 0xFFFFFFFF — the OOM shape; on 64-bit
// this is a COVERAGE seed that returns an error, NOT a crash — the residual is
// 32-bit-build only, disclosed in doc.go); (d) a 1-byte and 0-byte input (the
// smallest adversarial shapes). The corpus COUNT is a NUMBER in the report (Law V).

// fuzzSeed is the deterministic maphash.Seed the corpus builders reuse so the
// committed corpus is byte-stable across runs (maphash.MakeSeed is randomized
// per-process; a fixed seed makes the corpus reproducible — Law II). It is NOT
// the seed the production mesh uses; it is a corpus-stability constant.
var fuzzSeed = func() maphash.Seed {
	// Construct a seed from a fixed backing word (Uint64ToSeed is the inverse of
	// SeedToUint64 — the iblt_wire.go public round-trip pair). A fixed word → a
	// bitwise-stable seed → a byte-stable marshaled corpus.
	return eng.Uint64ToSeed(0x4441593333000001) // "DAY33" + a stable tail
}()

// validBatchEnvelope builds a well-formed BatchEnvelope wire (the happy-path
// seed for the batch arm). The originSig is NON-ZERO (UnmarshalBatchEnvelope
// rejects a zero sig with ErrBatchUnsigned — a non-zero sig establishes the
// happy-path coverage of the full header parse, NOT the unsigned-reject branch).
// The batchWire body is a small opaque blob (the unmarshaler does NOT decode it
// — the O(1) header parse leaves batchWire as an aliasing sub-slice).
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
// for the hybrid arm). BOTH edSig AND pqSig are NON-ZERO (UnmarshalHybridFrame
// rejects a zero edSig OR a zero pqSig with ErrHybridUnsigned — non-zero sigs
// establish the happy-path coverage of the full header parse, INCLUDING the
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
// NOT the unmarshaler's job — the fuzz drives the UNMARSHAL route, not the full
// gate stack, per Edit A's unit-isolation mandate).
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

// truncatedMagic returns the first 4 bytes of the given 4-byte magic with NO body
// (the length-bomb-empty shape — a magic prefix that passes the IsXFrame peek but
// is too short for the header parse, exercising the "short header" reject branch
// of every unmarshaler). magicBE is the magic in big-endian byte order.
func truncatedMagic(magicBE uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, magicBE)
	return out
}

// lengthBombIBLT builds an IBLT wire with a valid magic + a uint32 numBuckets of
// 0xFFFFFFFF (the OOM shape). On a 64-bit build `int(uint32(0xFFFFFFFF)) ==
// 4294967295` → the bounds guard `len(wire) < 18 + 4294967295*20` is TRUE →
// ErrMalformedDigest (NO crash). On a 32-bit build `int(uint32(0xFFFFFFFF)) ==
// -1` → the guard is DEFEATED → a multi-GB make() → OOM-kill (the residual
// disclosed in doc.go). The seed is a COVERAGE seed on the engine's 64-bit
// target (exercises the length-field + the bounds-guard path), NOT a crash
// reproducer.
func lengthBombIBLT() []byte {
	out := make([]byte, 18)                             // ibltWireHeaderLen: magic(4)+numBuckets(4)+k(2)+seed(8)
	binary.LittleEndian.PutUint32(out[0:4], 0x49424C31) // 'IBL1'
	binary.LittleEndian.PutUint32(out[4:8], 0xFFFFFFFF) // the length-bomb
	binary.LittleEndian.PutUint16(out[8:10], 3)         // a valid k
	binary.LittleEndian.PutUint64(out[10:18], 0)        // a zero seed
	return out
}

// lengthBombRelay builds a v3 RelayEnvelope wire with a valid version + a
// uint32 innerLen of 0xFFFFFFFF (the relay-arm OOM shape, same class as
// lengthBombIBLT). On 64-bit the bounds guard `len(wire) < 96 + 4294967295 +
// n*104` is TRUE → ErrMalformed (NO crash); on 32-bit the innerLen cast
// underflows → guard DEFEATED → a 4GB make() → OOM-kill.
func lengthBombRelay() []byte {
	// v3 header: version(2, LE = 3) + hopCount(2, LE = 0) + innerLen(4, LE = 0xFFFFFFFF)
	out := make([]byte, 96)                             // HeaderLen for v3
	binary.LittleEndian.PutUint16(out[0:2], 3)          // envelopeVersion v3
	binary.LittleEndian.PutUint16(out[2:4], 0)          // 0 hops
	binary.LittleEndian.PutUint32(out[4:8], 0xFFFFFFFF) // the length-bomb innerLen
	return out
}

// dispatchSeeds is the FuzzDispatchFrame seed corpus — one well-formed frame per
// arm (the 4 magics) + the adversarial shapes. DispatchFrame peeks the first 4
// bytes and routes; a seed per magic establishes each arm's coverage, and the
// adversarial seeds exercise the truncation + length-bomb + tiny-input reject
// paths across ALL arms (a 0-byte frame routes to the default relay arm +
// UnmarshalRelayEnvelope rejects it).
func dispatchSeeds() [][]byte {
	return [][]byte{
		validBatchEnvelope(),
		validHybridFrame(),
		append([]byte{}, validStrataEstimator()...), // a digest frame is bare SE bytes (no DispatchFrame magic wrap)
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

// batchSeeds is the FuzzUnmarshalBatchEnvelope corpus. A valid BatchEnvelope +
// a truncated WireV1Magic + a length-bomb-shaped header (a magic + version +
// a huge originSeq is harmless — the header is fixed-size, so the length-bomb
// class does NOT apply to the batch unmarshaler; the seed is a max-fields
// header instead) + the 1B/0B shapes.
func batchSeeds() [][]byte {
	return [][]byte{
		validBatchEnvelope(),
		truncatedMagic(attribution.WireV1Magic),
		{},     // 0-byte
		{0x53}, // 1-byte (the 'S' of "SBAT")
	}
}

// hybridSeeds is the FuzzUnmarshalHybridFrame corpus. A valid HybridEnvelope +
// a truncated WireHybridPQMagic + the 1B/0B shapes. The hybrid header is
// fixed-size (3404B) so the length-bomb class does NOT apply; the truncated
// magic exercises the short-header reject.
func hybridSeeds() [][]byte {
	return [][]byte{
		validHybridFrame(),
		truncatedMagic(attribution.WireHybridPQMagic),
		{},     // 0-byte
		{0x53}, // 1-byte ('S' of "SHYB")
	}
}

// relaySeeds is the FuzzUnmarshalRelayEnvelope corpus. A valid v3 envelope + a
// valid v2 envelope (the forward-compat branch) + a lengthBombRelay (the OOM
// shape, 64-bit no-crash) + a truncated version prefix + the 1B/0B shapes.
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
		lengthBombRelay(), // the OOM shape (64-bit no-crash)
		{0x03, 0x00},      // truncated v3 version prefix
		{},                // 0-byte
		{0x02},            // 1-byte (v2 version low byte)
	}
}

// strataSeeds is the FuzzUnmarshalStrataEstimator corpus. A valid SE + a
// truncated strataWireMagic + a wrong-strataCount header (a valid magic +
// strataCount=33, NOT 32 → ErrMalformedStrata) + the 1B/0B shapes.
func strataSeeds() [][]byte {
	wrongCount := make([]byte, 13)                             // strataWireHeaderLen
	binary.LittleEndian.PutUint32(wrongCount[0:4], 0x53545241) // 'STRA'
	wrongCount[4] = 33                                         // NOT the strataCount(32)
	binary.LittleEndian.PutUint64(wrongCount[5:13], 0)
	return [][]byte{
		validStrataEstimator(),
		truncatedMagicLE(0x53545241), // 'STRA' is little-endian on the SE wire
		wrongCount,
		{},     // 0-byte
		{0x53}, // 1-byte ('S' of "STRA")
	}
}

// ibltSeeds is the FuzzUnmarshalIBLT corpus. A valid IBLT + a truncated
// ibltWireMagic + a lengthBombIBLT (the OOM shape, 64-bit no-crash) + a
// k-out-of-range header (k=0 → ErrMalformed) + the 1B/0B shapes.
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
		{0x49}, // 1-byte ('I' of "IBL1")
	}
}

// truncatedMagicLE returns the first 4 bytes of a little-endian magic with NO
// body (the IBLT/SE wires are little-endian, sibling to the big-endian batch
// /hybrid/digest magics). magicLE is the magic in native uint32 order; the
// little-endian PutUint32 emits the bytes the wire expects.
func truncatedMagicLE(magicLE uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, magicLE)
	return out
}
