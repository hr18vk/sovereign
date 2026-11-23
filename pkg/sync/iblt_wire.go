// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package sync serializes IBLT digests for mesh anti-entropy exchanges. The
// deterministic little-endian format uses a fixed header and a flat bucket
// array rather than a Cap'n Proto schema:
//
//	[4] magic        uint32  'IBL1' or 'IBL2'
//	[4] numBuckets   uint32
//	[2] k            uint16
//	[8] seed         uint64  (maphash.Seed backing word)
//	[numBuckets * 20] buckets (Count int32 | KeySum uint64 | HashSum uint64)
//
// GenerateDelta rebuilds its local digest with the remote seed, so preserving
// the backing word is necessary for common keys to cancel during subtraction.
// A rejected or mismatched digest selects the full-keyset fallback.
//
// maphash.Seed has no public accessor for its backing word. SeedToUint64 and
// Uint64ToSeed use unsafe.Pointer for that single conversion; size checks and
// round-trip tests guard the assumed eight-byte layout.
package sync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"unsafe"
)

// ibltWireMagicV1 and IBLTWireMagicV2 identify arithmetic-progression and
// decorrelated placement respectively. Seed and bucket fields alone cannot
// distinguish the schemes, so UnmarshalIBLT accepts only the magic for the
// process's selected scheme. Cross-scheme subtraction would not cancel common
// keys. Rejection instead selects the full-keyset fallback, which still
// converges through Join but wastes bandwidth until peers use the same scheme.
// Unknown or truncated input is rejected rather than decoded as empty buckets.
const (
	ibltWireMagicV1 uint32 = 0x49424C31 // 'IBL1' — the legacy double-hash scheme
	// IBLTWireMagicV2 is exported: the mesh responder's request-peek gate
	// (pkg/mesh digest.go) compares the peeked [0:8] (magic + numBuckets, one
	// read) against it before adopting the requester's size.
	IBLTWireMagicV2 uint32 = 0x49424C32 // 'IBL2' — the k-decorrelated scheme
)

// ibltActiveWireMagic returns the only frame tag the process accepts: IBL2
// when --iblt-v2 selected decorrelated placement at initialization, IBL1
// otherwise. MarshalIBLT instead uses each table's captured scheme.
func ibltActiveWireMagic() uint32 {
	if ibltSchemeV2Enabled.Load() {
		return IBLTWireMagicV2
	}
	return ibltWireMagicV1
}

// ibltWireHeaderLen is the fixed header before the variable-length bucket
// array: magic(4) + numBuckets(4) + k(2) + seed(8) = 18.
const ibltWireHeaderLen = 4 + 4 + 2 + 8

// The seed conversion functions support only an eight-byte maphash.Seed.
// Their runtime size checks and TestIBLTWire_SeedSizeIsEight detect a
// toolchain layout change before the backing word is serialized.
var _ = unsafe.Sizeof(maphash.Seed{})

const ibltSeedSize = 8 //nolint:unused // documented invariant; assert pair below

// SeedToUint64 extracts the backing word of a maphash.Seed. It is the
// inverse of Uint64ToSeed and is deliberately the one place the engine
// reaches into the opaque Seed layout. Callers must pair every To with a
// matching From and must not assume the word's meaning beyond round-trip
// fidelity. The test TestIBLTWire_SeedRoundTrip pins the round-trip.
func SeedToUint64(s maphash.Seed) uint64 {
	if unsafe.Sizeof(s) != ibltSeedSize {
		panic("iblt_wire: maphash.Seed size drift — re-audit SeedToUint64/Uint64ToSeed")
	}
	return *(*uint64)(unsafe.Pointer(&s))
}

// Uint64ToSeed is the inverse of SeedToUint64: it reconstructs a maphash.Seed
// from its serialized backing word. A seed reconstructed this way is bitwise
// identical to the original and produces identical hashes via maphash.Hash
// (the hash internals key off the backing word alone), which is what
// GenerateDigestWithSeed requires.
func Uint64ToSeed(w uint64) maphash.Seed {
	var s maphash.Seed
	if unsafe.Sizeof(s) != ibltSeedSize {
		panic("iblt_wire: maphash.Seed size drift — re-audit SeedToUint64/Uint64ToSeed")
	}
	*(*uint64)(unsafe.Pointer(&s)) = w
	return s
}

// bucketWireLen is the on-wire size of one Bucket: Count int32 (4) +
// KeySum uint64 (8) + HashSum uint64 (8) = 20.
const bucketWireLen = 4 + 8 + 8

// maxFrameSizeBytes mirrors the 16 MiB ReadFrame limit in pkg/receive. It is
// duplicated because pkg/receive imports pkg/sync, so sharing the constant by
// import would create a cycle. internal/chaos/loopback_convergence_test.go
// checks that the two values remain equal (ADR-0041).
const maxFrameSizeBytes = 16 << 20

// maxIBLTBuckets limits decoded tables to the 16 MiB ingress budget using
// Bucket's 24-byte heap size: 16<<20 / 24 = 699050. UnmarshalIBLT rejects a
// larger count with ErrIBLTTooLarge before allocating its bucket slice.
//
// Using the 20-byte wire size instead would permit 1.2× heap amplification.
// For example, 838,859 buckets occupy 16,777,180 wire bytes plus the 18-byte
// header, but require 20,131,616 heap bytes (about 19.2 MiB). The heap-derived
// bound rejects that input. It also rejects counts before n*bucketWireLen can
// overflow on a 32-bit target; bucketWireLen remains in the separate truncated-
// input check. Deriving the value from unsafe.Sizeof keeps it current if the
// in-memory layout changes.
var maxIBLTBuckets = int(maxFrameSizeBytes / unsafe.Sizeof(Bucket{})) // == 699050

// ErrIBLTTooLarge reports a decoded bucket count above maxIBLTBuckets. It is
// distinct from pkg/receive's ErrFrameTooLarge so callers can distinguish an
// oversized transport frame from a digest whose bucket allocation would exceed
// the heap bound (ADR-0041).
var ErrIBLTTooLarge = errors.New("iblt_wire: IBLT numBuckets exceeds the 16 MiB heap bound (ErrIBLTTooLarge)")

// MarshalIBLT serializes t into the deterministic digest format. The frame
// magic comes from t's captured placement scheme. It returns a newly allocated
// buffer owned by the caller; wire serialization is outside the arena-backed
// GenerateDelta path.
func MarshalIBLT(t *IBLT) ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("iblt_wire: MarshalIBLT: nil digest")
	}
	n := t.NumBuckets()
	if n < 0 {
		return nil, fmt.Errorf("iblt_wire: MarshalIBLT: negative numBuckets=%d", n)
	}
	buf := make([]byte, ibltWireHeaderLen+n*bucketWireLen)
	// The magic declares the table's captured scheme (per-table, not
	// per-process — a table built under v1 marshals 'IBL1' even if the
	// process flag flips later; placement and tag stay coherent).
	magic := ibltWireMagicV1
	if t.schemeV2 != 0 {
		magic = IBLTWireMagicV2
	}
	binary.LittleEndian.PutUint32(buf[0:4], magic)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(n))
	binary.LittleEndian.PutUint16(buf[8:10], uint16(t.K()))
	binary.LittleEndian.PutUint64(buf[10:18], SeedToUint64(t.Seed()))
	for i := 0; i < n; i++ {
		off := ibltWireHeaderLen + i*bucketWireLen
		binary.LittleEndian.PutUint32(buf[off:off+4], uint32(t.buckets[i].Count))
		binary.LittleEndian.PutUint64(buf[off+4:off+12], t.buckets[i].KeySum)
		binary.LittleEndian.PutUint64(buf[off+12:off+20], t.buckets[i].HashSum)
	}
	return buf, nil
}

// strataWireMagic distinguishes a whole StrataEstimator frame from an
// individual IBLT frame. UnmarshalStrataEstimator returns ErrMalformedStrata
// for another tag or a truncated header instead of accepting empty strata.
const strataWireMagic uint32 = 0x53545241 // 'STRA'

// strataWireHeaderLen is magic(4) + strataCount(1) + seed(8). Each following
// stratum is a self-delimiting MarshalIBLT frame. The outer seed reconstructs
// the estimator before decoding; GenerateStrataEstimator also uses this
// authoritative copy. Per-stratum frames retain their own seed fields.
const strataWireHeaderLen = 4 + 1 + 8

// ErrMalformedStrata reports a short header, wrong magic or stratum count, or
// an invalid embedded IBLT. Decoding fails before GenerateDelta can subtract a
// partially reconstructed estimator.
var ErrMalformedStrata = fmt.Errorf("iblt_wire: malformed strata estimator wire")

// MarshalStrataEstimator writes a 13-byte header followed by the 32 strata in
// array order, each encoded by MarshalIBLT. It allocates one output buffer and
// temporary per-stratum frames. A nil estimator is an error, not an encoding of
// an empty difference.
func MarshalStrataEstimator(se *StrataEstimator) ([]byte, error) {
	if se == nil {
		return nil, fmt.Errorf("iblt_wire: MarshalStrataEstimator: nil estimator")
	}
	// Precompute the total size so the output needs one allocation and each
	// marshaled stratum can be copied into place. Read the seed through the
	// public accessor rather than the unexported field.
	seed := se.Seed()
	total := strataWireHeaderLen
	strataBytes := make([][]byte, strataCount)
	for i := 0; i < strataCount; i++ {
		b, err := MarshalIBLT(se.strata[i])
		if err != nil {
			return nil, fmt.Errorf("iblt_wire: MarshalStrataEstimator: stratum %d: %w", i, err)
		}
		strataBytes[i] = b
		total += len(b)
	}
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], strataWireMagic)
	buf[4] = byte(strataCount)
	binary.LittleEndian.PutUint64(buf[5:13], SeedToUint64(seed))
	off := strataWireHeaderLen
	for i := 0; i < strataCount; i++ {
		copy(buf[off:], strataBytes[i])
		off += len(strataBytes[i])
	}
	return buf, nil
}

// UnmarshalStrataEstimator reconstructs a heap estimator from the outer seed,
// then replaces each newly allocated stratum with its decoded wire state. The
// result is garbage-collected normally; StrataEstimator has no arena lifecycle.
//
// The header must specify exactly 32 strata, and every embedded IBLT must
// decode successfully. Any failure returns ErrMalformedStrata rather than a
// partial estimator whose Estimate call would compare mismatched strata.
func UnmarshalStrataEstimator(wire []byte) (*StrataEstimator, error) {
	if len(wire) < strataWireHeaderLen {
		return nil, fmt.Errorf("%w: short header: got %d bytes, want >= %d", ErrMalformedStrata, len(wire), strataWireHeaderLen)
	}
	if got := binary.LittleEndian.Uint32(wire[0:4]); got != strataWireMagic {
		return nil, fmt.Errorf("%w: magic mismatch: got %#x, want %#x", ErrMalformedStrata, got, strataWireMagic)
	}
	n := int(wire[4])
	if n != strataCount {
		return nil, fmt.Errorf("%w: strataCount=%d, want %d (no silent truncation — a wrong count makes Estimate subtract compare wrong strata)", ErrMalformedStrata, n, strataCount)
	}
	seed := Uint64ToSeed(binary.LittleEndian.Uint64(wire[5:13]))
	se := NewStrataEstimator(seed)
	off := strataWireHeaderLen
	for i := 0; i < strataCount; i++ {
		stratum, err := UnmarshalIBLT(wire[off:])
		if err != nil {
			return nil, fmt.Errorf("%w: stratum %d: %v", ErrMalformedStrata, i, err)
		}
		// Replace the empty preallocated stratum with the sender's decoded
		// bucket state. The unused heap stratum is garbage-collected normally.
		se.strata[i] = stratum
		// UnmarshalIBLT consumes header + numBuckets*bucketWireLen bytes.
		// Recompute that length from the decoded bucket count because the
		// decoder does not return a consumed count.
		nb := stratum.NumBuckets()
		off += ibltWireHeaderLen + nb*bucketWireLen
	}
	return se, nil
}

// UnmarshalIBLT decodes a heap-allocated remote digest. subtractArena reads
// the other table's buckets regardless of their backing, so no arena is needed
// for this reconstruction. Calling Release on the result is safe and is a
// no-op for its heap storage.
func UnmarshalIBLT(wire []byte) (*IBLT, error) {
	if len(wire) < ibltWireHeaderLen {
		return nil, fmt.Errorf("iblt_wire: UnmarshalIBLT: short header: got %d bytes, want >= %d", len(wire), ibltWireHeaderLen)
	}
	// The frame must use the process's selected placement scheme. Otherwise
	// the decoded cells would contain keys placed under one scheme while
	// isPure and Peel recompute indices under another. Reject the frame so the
	// caller uses its full-keyset fallback.
	got := binary.LittleEndian.Uint32(wire[0:4])
	if want := ibltActiveWireMagic(); got != want {
		return nil, fmt.Errorf("iblt_wire: UnmarshalIBLT: magic mismatch: got %#x, want %#x (scheme lockstep: v2 rejects 'IBL1'=%#x, v1 rejects 'IBL2'=%#x; refusing silent fall-through or cross-scheme parse)", got, want, ibltWireMagicV1, IBLTWireMagicV2)
	}
	n := int(binary.LittleEndian.Uint32(wire[4:8]))
	// Reject before allocation or size multiplication. The upper bound covers
	// heap amplification and 32-bit length overflow; n<0 also handles a
	// uint32-to-int sign conversion on 32-bit targets. ErrIBLTTooLarge
	// identifies the digest-bound rejection at either boundary (ADR-0041).
	if n < 0 || n > maxIBLTBuckets {
		return nil, fmt.Errorf("%w: numBuckets=%d exceeds maxIBLTBuckets=%d (the 16 MiB ingress cap / sizeof(Bucket) heap bound — kills the 1.2× amplification + the 32-bit n*bucketWireLen wrap)", ErrIBLTTooLarge, n, maxIBLTBuckets)
	}
	k := int(binary.LittleEndian.Uint16(wire[8:10]))
	if k <= 0 || k > ibltMaxK {
		return nil, fmt.Errorf("iblt_wire: UnmarshalIBLT: k=%d out of range [1, %d]", k, ibltMaxK)
	}
	if len(wire) < ibltWireHeaderLen+n*bucketWireLen {
		return nil, fmt.Errorf("iblt_wire: UnmarshalIBLT: short bucket array: got %d bytes, want %d for %d buckets", len(wire), ibltWireHeaderLen+n*bucketWireLen, n)
	}
	seed := Uint64ToSeed(binary.LittleEndian.Uint64(wire[10:18]))
	t := NewIBLTWithSeed(n, k, seed)
	for i := 0; i < n; i++ {
		off := ibltWireHeaderLen + i*bucketWireLen
		t.buckets[i].Count = int32(binary.LittleEndian.Uint32(wire[off : off+4]))
		t.buckets[i].KeySum = binary.LittleEndian.Uint64(wire[off+4 : off+12])
		t.buckets[i].HashSum = binary.LittleEndian.Uint64(wire[off+12 : off+20])
	}
	return t, nil
}
