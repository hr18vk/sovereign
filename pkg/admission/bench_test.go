package admission

import (
	"math"
	"testing"
)

// BenchmarkPeerBucket_32c measures the honest-peer Admit path cost
// (ns/op, B/op, allocs/op). The "_32c" suffix is the ROADMAP target gear
// tag; the HONEST gear for this run is 4c (GOMAXPROCS=4, CPU part
// 0xd40) — the 32c re-run is PENDING Track 4 Karpenter c8g
// provisioning. Do NOT relabel a 4c number as 32c.
//
// The honest-peer Admit ns/op MUST be sub-us (it runs BEFORE 3.0's
// IngressHLCScalarCap.Admit, which is itself sub-us, AND before the
// 71.4 us/op VerifyCRDTFrame wall, Track 1.1 PROVEN commit 6db6132). A
// sharded-map lookup + one [32]byte copy + a handful of arithmetic ops
// under a per-shard mutex should measure in the tens-of-ns range.
func BenchmarkPeerBucket_32c(b *testing.B) {
	bucket := NewPeerBucket()
	pub := makePub(1)
	pb := pubBytes(pub)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Honest peer: Counter advances by 1 per frame (modest delta).
		_ = bucket.Accept(pb, uint64(i+1))
	}
}

// BenchmarkPeerBucket_Attacker_32c measures the drop-decision path cost
// for the MaxUint64 attacker. After the attacker's bucket is drained
// (budget 0), every subsequent Accept is a Drop decision — the path a
// Sybil burst takes. It MUST be cheaper than the honest accept path
// (no budget deduction math on the drop tail) and far cheaper than the
// 71.4 us Verify wall, so a Sybil burst is dropped in sub-us before
// Verify. Honest 4c gear tag.
func BenchmarkPeerBucket_Attacker_32c(b *testing.B) {
	bucket := NewPeerBucket()
	pub := makePub(2)
	pb := pubBytes(pub)

	// Drain the attacker's bucket first: a MaxUint64 ratchet pins
	// budget to 0 so the benchmark loop measures the steady-state Drop.
	_ = bucket.Accept(pb, 1)
	_ = bucket.Accept(pb, math.MaxUint64)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bucket.Accept(pb, math.MaxUint64)
	}
}
