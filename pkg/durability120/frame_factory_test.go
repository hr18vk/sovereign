package durability120

// Track 4.E5 — the 120-byte CRDT frame factory for the durability-latency gate.
//
// This is the SAME 120-byte payload BOTH halves of E5 must write:
//   - Half A (NVMe WAL fsync): the frame is encoded into a WALMutation and
//     AppendMutation'd (write + fsync) — the engine's REAL durability byte.
//   - Half B (S3 Express PutObject): the frame is the 120-byte Body of a
//     PutObject to a directory bucket — the S3 Express durability byte.
// Keeping the payload byte-identical across both halves makes the comparison a
// LATENCY comparison (not a bandwidth one — E3 settled bandwidth).
//
// LAYOUT (the ADR-10 CRDTEntry shape, 120 bytes, zero internal padding — the
// same shape pkg/codec120/frame_factory_test.go assembles; reconstructed here
// from REAL fixed-size fields, NOT imported from codec120, which is test-only
// and importing a test package across packages is a smell):
//
//	[  0: 32] PayloadDigest  [32]byte   — HASH-high (SHA-256-like)
//	[ 32: 48] OriginNodeID   [16]byte   — node identity (medium entropy)
//	[ 48: 64] DotNodeID      [16]byte   — causal-dot node (medium entropy)
//	[ 64: 72] DotCounter     uint64     — COUNTER-low (monotone)
//	[ 72: 80] SystemTime     int64      — COUNTER-low (monotone-ish)
//	[ 80: 88] ValidTimeStart int64      — COUNTER-low
//	[ 88: 96] ValidTimeEnd   int64      — COUNTER-low
//	[ 96:104] AssertionTime  int64      — COUNTER-low
//	[104:112] DecisionTime   int64      — COUNTER-low
//	[112:120] H3Index        uint64     — spatial index (low-ish entropy)
//
// ANTI-FAB (the E3 factory's load-bearing point, carried forward): the ENTROPY
// SHAPE matters. A real CRDT frame is a MIX of high-entropy fields (the 32-byte
// digest + two 16-byte node IDs = 64 bytes of hash-like data) and low-entropy
// fields (monotone counters + a fixed-ish spatial index), NOT 120 bytes of
// zeros. The S3 put rides a compressed TLS record and the NVMe fsync writes a
// page; BOTH behave differently on real entropy than on zeros. So the factory
// fills the digest + node IDs from a PRNG and the counters from monotone
// arithmetic — never make([]byte, 120) of zeros.
//
// DETERMINISM is load-bearing: a seeded splitmix64 makes every run byte-
// identical across runs given an equal seed, so the latency CDF is STABLE (a
// randomized frame would vary per-run and the CDF would not be reproducible).
// No math/rand (needs a seeded source anyway) and no crypto/rand (non-deterministic).

import (
	"encoding/binary"
	"testing"
)

// frameSize is the ADR-10 CRDTEntry size: exactly 120 bytes, zero padding.
const frameSize = 120

// fixedSeed is the constant seed for the determinism self-test and the
// canonical frame. It is NOT a secret — it only needs to be stable so the
// frame (and therefore the latency CDF) is reproducible across runs.
const fixedSeed uint64 = 0x534F564552454747 // "SOVEREGG"

// splitmix64 is a deterministic PRNG (state advances by the golden gamma).
// Seeded with a constant, it produces the same sequence on every run on every
// machine — the frame is therefore byte-identical across runs given equal seed.
type rng struct{ state uint64 }

func newRng(seed uint64) *rng { return &rng{state: seed} }

func (r *rng) u64() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// fillBytes writes n bytes of PRNG output into out (hash-like, high entropy).
func (r *rng) fillBytes(out []byte) {
	for i := 0; i < len(out); i += 8 {
		v := r.u64()
		for j := 0; j < 8 && i+j < len(out); j++ {
			out[i+j] = byte(v >> (8 * j))
		}
	}
}

// MakeFrame120 builds one 120-byte CRDT frame from the documented ADR-10 layout.
// seed is folded into the PRNG state AND into the counters so two frames at
// differing seeds are DISTINCT but structurally similar (same field shape,
// different values) — exactly the real durability regime. Two frames at the
// SAME seed are byte-identical (the determinism contract).
//
// Returns a [120]byte value (not a slice) so the caller can take its address
// for a zero-copy io.Reader without an allocation.
func MakeFrame120(seed uint64) [frameSize]byte {
	var buf [frameSize]byte
	r := newRng(seed)

	// [0:32] PayloadDigest — HASH-high. 32 bytes of PRNG output (hash-like).
	r.fillBytes(buf[0:32])

	// [32:48] OriginNodeID — medium entropy. A small pool of node identities
	// (the mesh has O(10s) of nodes, not 2^128); mask the top 2 bits of byte 0
	// so only ~64 distinct origins, matching a real mesh. The remaining 15
	// bytes vary fully (a node id is not all-zero past byte 0 in practice).
	r.fillBytes(buf[32:48])
	buf[32] &= 0x3F

	// [48:64] DotNodeID — same small-pool treatment as OriginNodeID.
	r.fillBytes(buf[48:64])
	buf[48] &= 0x3F

	// [64:72] DotCounter — COUNTER-low. Monotone per-node counter; fold the
	// seed in so distinct seeds give distinct (but low-entropy) counters.
	binary.LittleEndian.PutUint64(buf[64:72], seed+1)

	// [72:112] Five int64 timestamps — COUNTER-low. Realistic CRDT frames carry
	// wall-clock-ish nanos that cluster in a narrow band (a deploy epoch + small
	// offsets). Base epoch + seed*step keeps them monotone-ish and low-entropy
	// in the high bytes.
	const baseEpoch int64 = 1_772_000_000_000_000_000 // ~2026 ns since epoch
	putI64 := func(off int, v int64) { binary.LittleEndian.PutUint64(buf[off:off+8], uint64(v)) }
	putI64(72, baseEpoch+int64(seed)*1_000_000)           // SystemTime
	putI64(80, baseEpoch+int64(seed)*1_000_000)           // ValidTimeStart
	putI64(88, baseEpoch+int64(seed)*1_000_000+9_999_999) // ValidTimeEnd
	putI64(96, baseEpoch+int64(seed)*1_000_000)           // AssertionTime
	putI64(104, baseEpoch+int64(seed)*1_000_000)          // DecisionTime

	// [112:120] H3Index — spatial index. Low-ish entropy: a fixed cell with a
	// small per-seed jitter (the mesh covers a bounded region).
	h3 := uint64(0x631A2BF2A4C00000) // a representative H3 cell
	h3 += seed & 0xFFFF
	binary.LittleEndian.PutUint64(buf[112:120], h3)

	return buf
}

// MakeFrame120Bytes returns the 120-byte frame as a slice (for callers that
// need []byte, e.g. an io.Reader body). The slice is a fresh copy; the caller
// may mutate it without affecting the determinism of future calls.
func MakeFrame120Bytes(seed uint64) []byte {
	f := MakeFrame120(seed)
	out := make([]byte, frameSize)
	copy(out, f[:])
	return out
}

// TestFrame120Determinism asserts the determinism contract BEFORE any latency
// number is recorded: two frames at the same seed are byte-equal; two frames
// at differing seeds differ in >= 80 bytes (the high-entropy digest + node IDs
// alone span 64 bytes, plus the counters/timestamps/H3 differ). This runs on
// the 4c canonical box pre-flight and on the 32c box in the harness; it is the
// gate that the CDF rests on a STABLE payload.
func TestFrame120Determinism(t *testing.T) {
	a := MakeFrame120(fixedSeed)
	b := MakeFrame120(fixedSeed)
	if a != b {
		t.Fatalf("determinism violated: same seed produced different frames")
	}

	c := MakeFrame120(fixedSeed + 1)
	diffs := 0
	for i := 0; i < frameSize; i++ {
		if a[i] != c[i] {
			diffs++
		}
	}
	if diffs < 80 {
		t.Fatalf("distinct-seed frames differ in only %d bytes (want >= 80); "+
			"the entropy shape is wrong (likely zeros) and the CDF would not be "+
			"reproducible across distinct payloads", diffs)
	}

	// Size invariant: the frame is EXACTLY 120 bytes (the ADR-10 CRDTEntry).
	if len(a) != frameSize {
		t.Fatalf("frame size = %d, want %d", len(a), frameSize)
	}
}
