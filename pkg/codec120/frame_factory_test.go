// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package codec120

// Frame factory for the 120-byte CRDT frame payload.
//
// The byte layout mirrors the flat CRDTEntry struct in pkg/sync/hamt.go
// (ADR-0010), which occupies 120 bytes with no internal padding:
//
//	[  0: 32] PayloadDigest  [32]byte   — high-entropy digest bytes
//	[ 32: 48] OriginNodeID   [16]byte   — node identity
//	[ 48: 64] DotNodeID      [16]byte   — causal-dot node identity
//	[ 64: 72] DotCounter     uint64     — increasing counter
//	[ 72: 80] SystemTime     int64      — system timestamp
//	[ 80: 88] ValidTimeStart int64      — valid-time start
//	[ 88: 96] ValidTimeEnd   int64      — valid-time end
//	[ 96:104] AssertionTime  int64      — assertion timestamp
//	[104:112] DecisionTime   int64      — decision timestamp
//	[112:120] H3Index        uint64     — spatial index
//
// The factory builds frames locally rather than importing pkg/sync, keeping
// Cap'n Proto out of this benchmark. The synthetic payload combines hash-like
// bytes, constrained node IDs, counters, and a spatial index so its compression
// behavior is more representative than a zero-filled buffer.
//
// A fixed SplitMix64 seed makes the frames reproducible across runs. This keeps
// encoded sizes comparable without crypto/rand or a seeded math/rand source.

import (
	"encoding/binary"
)

const frameSize = 120

// numFrames is the number of distinct frames cycled through by the benchmark.
// The dictionary uses trainFrames frames from the same generator and seed, so
// the training and benchmark streams overlap.
const numFrames = 1000
const trainFrames = 10000

// fixedSeed makes the frame stream reproducible; it is not a secret.
const fixedSeed uint64 = 0x534F564552454747 // "SOVEREGG"

// rng implements SplitMix64. Advancing state by the golden gamma produces the
// same sequence on every platform for a given seed.
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

// makeFrame builds one 120-byte frame in the CRDTEntry layout. The generator
// varies digest and identity fields, while idx varies counters and timestamps.
// Every frame retains the same field structure.
func makeFrame(r *rng, idx uint64) []byte {
	buf := make([]byte, frameSize)

	// [0:32] PayloadDigest: 32 bytes of hash-like generator output.
	digest := r.bytes(32)
	copy(buf[0:32], digest)

	// [32:48] OriginNodeID: constrain the leading three bytes to model node
	// IDs with shared structure; the remaining bytes come from the generator.
	origin := make([]byte, 16)
	copy(origin, r.bytes(16))
	origin[0] &= 0x3F
	origin[1] = 0
	origin[2] = 0
	copy(buf[32:48], origin)

	// [48:64] DotNodeID uses the same leading-byte constraints as OriginNodeID.
	dot := make([]byte, 16)
	copy(dot, r.bytes(16))
	dot[0] &= 0x3F
	dot[1] = 0
	dot[2] = 0
	copy(buf[48:64], dot)

	// [64:72] DotCounter increases with the frame index; its high bytes remain
	// zero in this stream.
	binary.LittleEndian.PutUint64(buf[64:72], idx+1)

	// [72:112] Five int64 timestamps cluster around a fixed epoch and advance
	// with the frame index. ValidTimeEnd has a small positive offset.
	const baseEpoch int64 = 1_772_000_000_000_000_000 // nanoseconds since the Unix epoch
	putI64 := func(off int, v int64) { binary.LittleEndian.PutUint64(buf[off:off+8], uint64(v)) }
	putI64(72, baseEpoch+int64(idx)*1_000_000)           // SystemTime
	putI64(80, baseEpoch+int64(idx)*1_000_000)           // ValidTimeStart
	putI64(88, baseEpoch+int64(idx)*1_000_000+9_999_999) // ValidTimeEnd
	putI64(96, baseEpoch+int64(idx)*1_000_000)           // AssertionTime
	putI64(104, baseEpoch+int64(idx)*1_000_000)          // DecisionTime

	// [112:120] H3Index varies a representative cell over a bounded range.
	h3 := uint64(0x631A2BF2A4C00000) // a representative H3 cell
	h3 += idx & 0xFFFF
	binary.LittleEndian.PutUint64(buf[112:120], h3)

	return buf
}

// buildFrames returns n deterministic 120-byte frames. A fresh generator
// seeded with fixedSeed reproduces the same sequence on every call.
func buildFrames(n int) [][]byte {
	r := newRng(fixedSeed)
	frames := make([][]byte, n)
	for i := 0; i < n; i++ {
		frames[i] = makeFrame(r, uint64(i))
	}
	return frames
}

// concatFrames returns n frames in one contiguous slice for dictionary history.
func concatFrames(n int) []byte {
	frames := buildFrames(n)
	out := make([]byte, 0, n*frameSize)
	for _, f := range frames {
		out = append(out, f...)
	}
	return out
}
