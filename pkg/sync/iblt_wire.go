// Package sync — iblt_wire is the production IBLT-digest marshal seam for the
// mesh gossip anti-entropy round.
//
// WHY THIS FILE EXISTS. pkg/sync.IBLT has NO Marshal/Encode/Decode/Wire
// method (grep-verified: zero hits). The chaos mesh (internal/chaos) passes
// the digest *IBLT by POINTER in-process, so it never serializes the seed or
// the bucket array. The production gossip wire (pkg/mesh) crosses a real TCP+TLS
// socket, so the digest MUST be serialized. This file is that serialization,
// a NEW CALLER of the frozen IBLT's public accessors (NumBuckets, K, Seed,
// the buckets []Bucket slice header), WITHOUT touching iblt.go (which is NOT
// in the FROZEN md5-locked set but is the engine's hot-path structure and is
// left byte-identical by the Track-12.2 lock discipline the Day-2 prompt
// inherits).
//
// WIRE FORMAT (deterministic, little-endian, auditable; NOT capnp — a digest
// is a flat bucket array, a fixed-size header is simpler and cheaper than a
// schema round-trip, and this keeps the IBLT wire off the FROZEN capnp
// schema's surface area entirely):
//
//	[4] magic        uint32  'IBL1' = 0x49424C31  (version tag / reject of foreign bytes)
//	[4] numBuckets   uint32
//	[2] k            uint16
//	[8] seed         uint64  (the maphash.Seed backing word; see SeedToUint64)
//	[numBuckets * 20] buckets  (Count int32 LE | KeySum uint64 LE | HashSum uint64 LE)
//
// The seed is the load-bearing field: GenerateDelta(remoteDigest) rebuilds the
// local digest via e.GenerateDigestWithSeed(remoteDigest.Seed()) so both
// digests hash keys identically before subtract. A wrong seed on reconstruction
// makes subtract compare buckets hashed under DIFFERENT seeds — the peel
// yields garbage, and the honest outcome is the delta loopback (oversend,
// convergence slower but still correct by CRDT idempotency). Correctness is
// preserved; the seed round-trip is the performance/cleanliness invariant.
//
// unsafe usage: maphash.Seed is an opaque struct{s uint64} (size 8 on every
// Go platform the engine targets, verified by the compile-time assert below +
// TestIBLTWire_SeedSizeIsEight). There is no public accessor for the backing
// word, so we read/write 8 bytes via unsafe.Pointer exactly the way the
// HamtArena allocation paths use unsafe.Slice/unsafe.Sizeof. Go 1.26.1 is the
// pinned toolchain; a future Go that changes Seed's layout trips the
// compile-time assert and the test, never a silent wire skew.
package sync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"unsafe"
)

// ibltWireMagic is the version tag on the digest wire. A foreign/truncated
// buffer that does not begin with this tag is an explicit ErrMalformedDigest,
// never a silent fall-through to zero buckets (the C5-class failure mode).
const ibltWireMagic uint32 = 0x49424C31 // 'IBL1'

// ibltWireHeaderLen is the fixed header before the variable-length bucket
// array: magic(4) + numBuckets(4) + k(2) + seed(8) = 18.
const ibltWireHeaderLen = 4 + 4 + 2 + 8

// Compile-time guard: if a future Go changes maphash.Seed's layout the
// constant below fails to compile (the unsafe.Sizeof in a const initializer
// is rejected), surfacing the break at build time instead of producing a
// silently-wrong wire. unsafe.Sizeof on a concrete type is a compile-time
// constant expression in Go (not a runtime call).
var _ = unsafe.Sizeof(maphash.Seed{})

const ibltSeedSize = 8 //nolint:unused // documented invariant; assert pair below

// SeedToUint64 extracts the backing word of a maphash.Seed. It is the
// inverse of Uint64ToSeed and is deliberately the ONE place the engine
// reaches into the opaque Seed layout. Callers MUST pair every To with a
// matching From and MUST NOT assume the word's meaning beyond round-trip
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

// maxFrameSizeBytes is the shared 16 MiB ingress cap — the SAME constant as
// pkg/receive/receiver.go:75 `const maxFrameSize = 16 << 20` (the ReadFrame cap
// receiver.go:988 `if frameLen > maxFrameSize` enforces). It is DUPLICATED here
// as a literal (NOT imported) because pkg/receive already imports pkg/sync
// (receiver.go:50, alias `eng`) — importing pkg/receive back into pkg/sync
// would close a bidirectional import cycle that fails to compile (the
// premise-audit's option-(a)-is-an-import-cycle-trap finding; ADR-0041). The
// literal is LOCKSTEP-tracked: a future maxFrameSize change in receiver.go MUST
// be mirrored here; the T-LOOP-IBLT-BOUND-LOCKSTEP tooth
// (internal/chaos/day36_loopback_test) cross-checks the two at test time (it
// imports both packages and asserts equality — the test-time equivalent of a
// build-time cross-package const assert, which Go does not support across an
// import cycle).
const maxFrameSizeBytes = 16 << 20

// maxIBLTBuckets is the upper bound on numBuckets a wire UnmarshalIBLT will
// accept: the largest n whose HEAP slab (n * sizeof(Bucket) = n * 24) stays
// within the 16 MiB ingress cap = maxFrameSizeBytes / unsafe.Sizeof(Bucket{}) =
// 16<<20 / 24 = 699050 (integer division: 16777216 / 24 = 699050.67 -> 699050).
// A wire claiming n > maxIBLTBuckets is REJECTED with ErrIBLTTooLarge BEFORE
// the alloc path (NewIBLTWithSeed at iblt.go:77 — the make([]Bucket, n) site).
// This kills:
//
//	(1) the 1.2× heap amplification — n=838859 (the max-through-ReadFrame
//	    shape: 838859*20 = 16,777,180 wire bytes + 18 header <= 16 MiB) drives
//	    make([]Bucket, 838859) = 838859*24 = 20,131,616 bytes ≈ 19.2 MiB heap;
//	    838859 > 699050 -> REJECTED (the T-LOOP-IBLT-BOUND tooth's headline
//	    case); AND
//	(2) the 32-bit n*bucketWireLen wrap — on a future 32-bit/WASM target, n in
//	    [107374183, 2147483647] wraps the product n*20 to a small/negative,
//	    defeating `len(wire) < 18 + n*20`; the bound rejects n > 699050 BEFORE
//	    the product check. This is DEFENSE-IN-DEPTH, NOT a P0 fix — the arm64
//	    production target's 64-bit int + the ReadFrame cap already neutralize
//	    the OOM (the architect's byte-trace, ADR-0041 §approved-sequencing (0)).
//
// THE DENOMINATOR IS THE HEAP BUCKET SIZE (sizeof(Bucket)=24), NOT the wire
// bucket size (bucketWireLen=20). Bounding by the wire size leaves a 24/20=1.2×
// heap headroom the n=838859 attack exploits: the prompt's
// maxFrameSize/bucketWireLen formula (= 838860) would let n=838859 through
// (838859 <= 838860), FAILING the T-LOOP-IBLT-BOUND tooth (n=838859 ->
// ErrIBLTTooLarge). The heap-size denominator is the LOAD-BEARING CORRECTION
// the Day-36 premise-audit surfaced (ADR-0041 §premise-audit M1). The on-wire
// bucketWireLen=20 is KEPT for the existing short-array bounds check below
// (it rejects a TRUNCATED wire whose declared n is small but whose actual bytes
// are fewer — a distinct failure mode from the heap bomb).
//
// It is a package var (computed once at init), NOT a const, because
// unsafe.Sizeof(Bucket{}) is not a compile-time constant expression — Bucket{}
// is a composite literal, and the Go spec restricts Sizeof's const-ness to
// type-or-constant arguments (see the maphash.Seed guard at line 64, the same
// idiom). It never mutates; reading it in UnmarshalIBLT is a single load of a
// package-level int. If a future Go changes Bucket's in-memory layout, this var
// recomputes at init and the bound stays correct automatically (no manual
// re-audit — the advantage of the sizeof-derived var over a hardcoded literal).
var maxIBLTBuckets = int(maxFrameSizeBytes / unsafe.Sizeof(Bucket{})) // == 699050

// ErrIBLTTooLarge is the sentinel returned by UnmarshalIBLT when the wire's
// numBuckets exceeds maxIBLTBuckets (the 16 MiB ingress cap / sizeof(Bucket)
// heap bound). It is a DISTINCT sentinel from pkg/receive's ErrFrameTooLarge
// (a different layer — the transport frame cap — for clear attribution: a
// caller surfacing the error knows whether the frame was oversized at the
// transport boundary OR the IBLT bucket count was oversized at the digest
// unmarshal boundary). NEW in Edit 0 (Day 36 ADR-0041); iblt_wire.go is NOT in
// the FROZEN md5-pin set (verify via TestGate_FrozenMD5), so the edit is
// streak-neutral — the Day-29 44f89527 streak is PRESERVED.
var ErrIBLTTooLarge = errors.New("iblt_wire: IBLT numBuckets exceeds the 16 MiB heap bound (ErrIBLTTooLarge)")

// MarshalIBLT serializes an IBLT digest into the deterministic wire format
// documented above. It reads only public accessors + the buckets slice header
// (the Bucket fields are exported: Count int32, KeySum uint64, HashSum
// uint64). The returned []byte is owned by the caller (a fresh heap buffer;
// the gossip path is NOT the GenerateDelta hot path and is correctly allowed
// to allocate — the Zero-GC gate is the sync/apply hot path, not the gossiper
// wire marshal).
func MarshalIBLT(t *IBLT) ([]byte, error) {
	if t == nil {
		return nil, fmt.Errorf("iblt_wire: MarshalIBLT: nil digest")
	}
	n := t.NumBuckets()
	if n < 0 {
		return nil, fmt.Errorf("iblt_wire: MarshalIBLT: negative numBuckets=%d", n)
	}
	buf := make([]byte, ibltWireHeaderLen+n*bucketWireLen)
	binary.LittleEndian.PutUint32(buf[0:4], ibltWireMagic)
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

// strataWireMagic is the version tag on the StrataEstimator digest wire. It is
// DISTINCT from ibltWireMagic ('IBL1') so a per-stratum IBLT blob is never
// silently parsed as a whole-estimator frame (and vice versa): a foreign/
// truncated buffer that does not begin with this tag is an explicit
// ErrMalformedStrata, never a fall-through to zero strata (the C5-class
// failure mode the IBLT wire refuses). The value spells 'STRA' big-endian.
const strataWireMagic uint32 = 0x53545241 // 'STRA'

// strataWireHeaderLen is the fixed header before the variable-length stratum
// IBLT array: strataWireMagic(4) + strataCount(1) + seed(8) = 13. Each stratum
// follows as a self-delimiting MarshalIBLT blob (its own 18-byte header carries
// its numBuckets/k/seed), so the array needs NO length prefix per stratum —
// UnmarshalIBLT consumes exactly the bytes MarshalIBLT emitted, and the loop
// advances by the parsed length. The seed is hoisted into the strata header so
// the receiver can reconstruct a NewStrataEstimator with the sender's seed
// BEFORE unmarshaling strata (the strata IBLTs ALSO carry the seed per
// MarshalIBLT, belt-and-braces; the hoisted copy is the authoritative one the
// receiver's GenerateStrataEstimator(remote.Seed()) keys off — the load-bearing
// field per the iblt_wire.go seed round-trip comment).
const strataWireHeaderLen = 4 + 1 + 8

// ErrMalformedStrata is returned by UnmarshalStrataEstimator when the wire is
// too short for a header, the magic does not match strataWireMagic, the
// strataCount is not strataCount (32), or a per-stratum UnmarshalIBLT fails
// (short bucket array / magic mismatch / k out of range). It is the
// coarse-diff analog of ErrMalformedDigest — the cheap reject before the peer
// commits a GenerateDelta subtract against a garbage remote IBLT.
var ErrMalformedStrata = fmt.Errorf("iblt_wire: malformed strata estimator wire")

// MarshalStrataEstimator serializes a StrataEstimator into a deterministic wire
// format: a 13-byte header (magic + strataCount + seed) followed by strataCount
// self-delimiting MarshalIBLT blobs (one per stratum, highest to lowest or
// lowest to highest — the order is the array order, which is stable because
// NewStrataEstimator populates strata[0..strataCount-1] in index order and
// Estimate subtracts in index order; the wire preserves that order). It is a
// SIBLING to MarshalIBLT — it calls MarshalIBLT per stratum and does NOT touch
// iblt.go or the FROZEN IBLT struct. The returned []byte is owned by the caller
// (a fresh heap buffer; the gossip digest-exchange is NOT the GenerateDelta hot
// path and is correctly allowed to allocate — the Zero-GC gate is the sync/apply
// hot path, not the gossiper digest marshal). A nil estimator is an explicit
// error (a nil digest on the wire is a protocol violation, not a zero-diff
// signal — the oversend fallback is the honest zero-diff path, never a nil).
func MarshalStrataEstimator(se *StrataEstimator) ([]byte, error) {
	if se == nil {
		return nil, fmt.Errorf("iblt_wire: MarshalStrataEstimator: nil estimator")
	}
	// Pre-size: header + sum of each stratum's wire size. Computing each
	// stratum's size up front (header + numBuckets*bucketWireLen) lets us
	// allocate the whole buffer once and copy each MarshalIBLT blob in, rather
	// than concatenating N buffers (which would allocate N+1 times). The seed
	// is read via the public Seed() accessor (the StrataEstimator.seed field is
	// unexported; the wire codec reaches it only through the public seam, the
	// same discipline MarshalIBLT observes for the IBLT seed).
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

// UnmarshalStrataEstimator parses MarshalStrataEstimator's wire format into a
// heap-allocated StrataEstimator. It reconstructs the seed from the header
// (Uint64ToSeed), allocates a NewStrataEstimator with that seed, then overwrites
// each stratum's IBLT via UnmarshalIBLT (NewStrataEstimator pre-allocates 32
// IBLTs with the SAME seed; the wire's per-stratum blobs carry the bucket
// contents that overwrote the sender's pre-inserted empty strata, so the
// receiver's strata reflect the sender's exact bucket state). The caller does
// NOT need to Release the returned estimator (it is heap-shaped; StrataEstimator
// has no Release/EBR lifecycle — it is a short-lived digest, not a pinned root).
//
// The strataCount in the header MUST equal strataCount (32); a mismatch is an
// ErrMalformedStrata (no silent truncation to a different stratum count — the
// Estimate subtract would compare wrong strata and yield garbage). A per-stratum
// UnmarshalIBLT failure (short array / magic mismatch / k out of range) is also
// an ErrMalformedStrata — the receiver's honest path on a malformed digest is
// the oversend fallback (GenerateDelta against an empty IBLT), NOT a decode of
// partial strata.
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
		// NewStrataEstimator pre-allocated se.strata[i] with the same seed +
		// strataIBLTBuckets/strataK; replace it with the wire-decoded stratum
		// (the wire carries the sender's actual bucket state after Insert).
		// The pre-allocated stratum is GC'd normally (heap-shaped, no EBR).
		se.strata[i] = stratum
		// Advance by the consumed length: UnmarshalIBLT read exactly the bytes
		// MarshalIBLT emitted (header + numBuckets*bucketWireLen), which we
		// recompute from the parsed numBuckets so the loop advances even though
		// UnmarshalIBLT does not return a consumed-count.
		nb := stratum.NumBuckets()
		off += ibltWireHeaderLen + nb*bucketWireLen
	}
	return se, nil
}

// UnmarshalIBLT parses MarshalIBLT's wire format into a heap-allocated IBLT
// (NewIBLTWithSeed — the arena-backed constructor NewArenaIBLT requires the
// owning engine's arena, which the gossiper does not have for a remote digest;
// the heap shape is exactly what subtractArena reads off `other.buckets`,
// whether `other` is heap- or arena-backed, so the subtract result is
// byte-identical). The caller MUST Release the returned IBLT (Release is a
// no-op on a heap IBLT, so the call is safe and documents lifecycle parity
// with the arena path the chaos mesh already follows).
func UnmarshalIBLT(wire []byte) (*IBLT, error) {
	if len(wire) < ibltWireHeaderLen {
		return nil, fmt.Errorf("iblt_wire: UnmarshalIBLT: short header: got %d bytes, want >= %d", len(wire), ibltWireHeaderLen)
	}
	if got := binary.LittleEndian.Uint32(wire[0:4]); got != ibltWireMagic {
		return nil, fmt.Errorf("iblt_wire: UnmarshalIBLT: magic mismatch: got %#x, want %#x (refusing silent fall-through to zero buckets)", got, ibltWireMagic)
	}
	n := int(binary.LittleEndian.Uint32(wire[4:8]))
	// Edit 0 (Day 36 ADR-0041): bound-tightening BEFORE the alloc path. The
	// combined check folds the existing n < 0 guard (catches the 0xFFFFFFFF
	// sign-flip on a 32-bit int target directly) WITH the new heap-bound check
	// (catches the WIDE positive range that overflows n*bucketWireLen on 32-bit
	// AND the 838859 heap-bomb shape on arm64). On the 64-bit production target
	// int(uint32) is always >= 0, so the n < 0 disjunct is dead but harmless
	// (defense-in-depth for a future 32-bit/WASM arc); the n > maxIBLTBuckets
	// disjunct is the live reject on arm64. Both return ErrIBLTTooLarge (NOT
	// the old "negative numBuckets" error) so callers attribute the reject to
	// the bound, not the sign-flip. The bound fires BEFORE NewIBLTWithSeed (the
	// make([]Bucket, n) alloc at iblt.go:77), so a rejected wire never reaches
	// the heap slab — the 19.2 MiB amplification is killed at the parse
	// boundary, not the alloc boundary.
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
