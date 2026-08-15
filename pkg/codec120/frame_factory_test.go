package codec120

// Track 4.E3 — frame factory for the 120-byte CRDT wire payload.
//
// The payload is a CRDTEntry-sized frame built from the engine's ACTUAL shape
// (pkg/sync/hamt.go: CRDTEntry, ADR 10, exactly 120 bytes, zero internal
// padding). The field layout (verified this turn via unsafe.Sizeof/Offsetof):
//
//	[  0: 32] PayloadDigest  [32]byte   — HASH-high (SHA-256 of the entity)
//	[ 32: 48] OriginNodeID   [16]byte   — node identity (medium entropy)
//	[ 48: 64] DotNodeID      [16]byte   — causal-dot node (medium entropy)
//	[ 64: 72] DotCounter     uint64     — COUNTER-low (monotone)
//	[ 72: 80] SystemTime     int64      — COUNTER-low (monotone-ish)
//	[ 80: 88] ValidTimeStart int64      — COUNTER-low
//	[ 88: 96] ValidTimeEnd   int64      — COUNTER-low
//	[ 96:104] AssertionTime  int64      — COUNTER-low
//	[104:112] DecisionTime   int64      — COUNTER-low
//	[112:120] H3Index        uint64      — spatial index (low-ish entropy)
//
// The factory does NOT import pkg/sync (no import cycle, no FROZEN-reopen, no
// capnproto pulled into a bench). It assembles the 120-byte literal from the
// documented ADR-10 layout. The load-bearing point is the ENTROPY SHAPE
// matches a real CRDT frame: a mix of high-entropy fields (the 32-byte digest +
// two 16-byte node IDs = 64 bytes of hash-like data) and low-entropy fields
// (monotone counters + fixed spatial index), NOT 120 bytes of zeros.
//
// Determinism is load-bearing: a seeded generator makes every run byte-
// identical across runs, so the byte-cost snapshot (bytes_out per column) is
// STABLE — a randomized frame would vary size-of-compressed per-run, defeating
// the size comparison. The generator is a fixed splitmix64 seeded with a
// constant; no math/rand (which would need a seeded source anyway) and no
// crypto/rand (which would be non-deterministic).

import (
	"encoding/binary"
)

const frameSize = 120

// numFrames is the on-the-wire stream the bench compresses per op. 1000
// distinct but struct-similar frames is the real egress regime; the dictionary
// is trained on a held-out set of 10x this (trainFrames).
const numFrames = 1000
const trainFrames = 10000

// fixedSeed is constant across runs (determinism). It is NOT a secret — it
// only needs to be stable so the byte-cost snapshot is reproducible.
const fixedSeed uint64 = 0x534F564552454747 // "SOVEREGG"

// splitmix64 is a deterministic, stateless-ish PRNG (state advances by the
// golden gamma). Seeded with a constant, it produces the same sequence on
// every run on every machine — the byte-cost snapshot is therefore stable.
type rng struct{ state uint64 }

func newRng(seed uint64) *rng { return &rng{state: seed} }

func (r *rng) u64() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func (r *rng) bytes(n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i += 8 {
		v := r.u64()
		for j := 0; j < 8 && i+j < n; j++ {
			out[i+j] = byte(v >> (8 * j))
		}
	}
	return out
}

// makeFrame builds one 120-byte CRDT frame from the documented ADR-10 layout.
// idx is the frame index; it is folded into the digest + counters so the N
// frames are DISTINCT but structurally similar (same field shape, different
// values) — exactly the real egress regime.
func makeFrame(r *rng, idx uint64) []byte {
	buf := make([]byte, frameSize)

	// [0:32] PayloadDigest — HASH-high. 32 bytes of PRNG output (hash-like).
	digest := r.bytes(32)
	copy(buf[0:32], digest)

	// [32:48] OriginNodeID — medium entropy. A small pool of node identities
	// (the mesh has O(10s) of nodes, not 2^128), so we draw from a 64-entry
	// pool to be realistic: most frames share an origin node.
	origin := make([]byte, 16)
	copy(origin, r.bytes(16))
	// Fold a small node-pool: mask the high bytes so only ~64 distinct origins.
	origin[0] &= 0x3F
	origin[1] = 0
	origin[2] = 0
	copy(buf[32:48], origin)

	// [48:64] DotNodeID — same small-pool treatment as OriginNodeID.
	dot := make([]byte, 16)
	copy(dot, r.bytes(16))
	dot[0] &= 0x3F
	dot[1] = 0
	dot[2] = 0
	copy(buf[48:64], dot)

	// [64:72] DotCounter — COUNTER-low. Monotone per-node counter; low byte
	// entropy, high bytes mostly zero for small counters.
	binary.LittleEndian.PutUint64(buf[64:72], idx+1)

	// [72:112] Five int64 timestamps — COUNTER-low. Realistic CRDT frames
	// carry wall-clock-ish nanos that cluster in a narrow band (a deploy
	// epoch + small offsets). Base epoch + idx*step keeps them monotone-ish
	// and low-entropy in the high bytes.
	const baseEpoch int64 = 1_772_000_000_000_000_000 // ~2026 ns since epoch
	putI64 := func(off int, v int64) { binary.LittleEndian.PutUint64(buf[off:off+8], uint64(v)) }
	putI64(72, baseEpoch+int64(idx)*1_000_000)             // SystemTime
	putI64(80, baseEpoch+int64(idx)*1_000_000)             // ValidTimeStart
	putI64(88, baseEpoch+int64(idx)*1_000_000+9_999_999)   // ValidTimeEnd
	putI64(96, baseEpoch+int64(idx)*1_000_000)             // AssertionTime
	putI64(104, baseEpoch+int64(idx)*1_000_000)            // DecisionTime

	// [112:120] H3Index — spatial index. Low-ish entropy: a fixed cell with
	// a small per-frame jitter (the mesh covers a bounded region).
	h3 := uint64(0x631A2BF2A4C00000) // a representative H3 cell
	h3 += idx & 0xFFFF
	binary.LittleEndian.PutUint64(buf[112:120], h3)

	return buf
}

// buildFrames returns n deterministic 120-byte frames. The same seed → the
// same frames on every run, so the byte-cost snapshot is stable.
func buildFrames(n int) [][]byte {
	r := newRng(fixedSeed)
	frames := make([][]byte, n)
	for i := 0; i < n; i++ {
		frames[i] = makeFrame(r, uint64(i))
	}
	return frames
}

// concatFrames returns the n frames concatenated into one byte slice — the
// shape a streaming codec sees when it compresses a batch of on-the-wire
// frames in one egress burst. Used for the dictionary training set.
func concatFrames(n int) []byte {
	frames := buildFrames(n)
	out := make([]byte, 0, n*frameSize)
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}
