// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package admission

import (
	"math"
	"testing"
)

// BenchmarkPeerBucket_32c measures Accept's cost in ns/op, B/op, and
// allocs/op. The benchmark name is retained for compatibility; every result
// must still report the GOMAXPROCS setting and hardware used for that run.
//
// Accept runs before IngressHLCScalarCap.Admit and VerifyCRDTFrame. Its map
// lookup, key copy, and arithmetic under a per-shard mutex should keep this
// inexpensive gate well below the signature verification cost (ADR-0002).
// The loop leaves the watermark pending, so it includes charging decisions
// until the remaining budget cannot cover the next counter, followed by
// over-budget drops.
func BenchmarkPeerBucket_32c(b *testing.B) {
	bucket := NewPeerBucket()
	pub := makePub(1)
	pb := pubBytes(pub)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Submit consecutive absolute counters without committing the watermark.
		_, _ = bucket.Accept(pb, uint64(i+1))
	}
}

// BenchmarkPeerBucket_Attacker_32c measures repeated rejection of a
// MaxUint64 counter. The gap exceeds the peer's remaining budget, so each
// ratchet returns Drop before signature verification without changing the
// budget or the committed watermark.
func BenchmarkPeerBucket_Attacker_32c(b *testing.B) {
	bucket := NewPeerBucket()
	pub := makePub(2)
	pb := pubBytes(pub)

	// Create the peer with a small charge, then measure the over-budget path.
	_, _ = bucket.Accept(pb, 1)
	_, _ = bucket.Accept(pb, math.MaxUint64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bucket.Accept(pb, math.MaxUint64)
	}
}
