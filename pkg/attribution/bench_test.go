// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package attribution

import (
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// BenchmarkEnvelope_HopBoundCheck_32c measures the hop-count rejection path.
// Open compares len(hops) with maxHops and returns ErrHopBoundExceeded before
// signature verification, so the benchmark reports the cost of that integer
// comparison and its allocations.
//
// The _32c suffix names the 32-core c8g.8xlarge baseline used for comparison.
// Results on other hosts describe the host running the benchmark.
//
// The 1000-hop envelope exceeds the 15-hop bound derived from a 1 ms budget.
// Every iteration therefore returns before Verify. For scale, the measured
// Ed25519 verification cost on the 32-core baseline is about 60.2 us.
func BenchmarkEnvelope_HopBoundCheck_32c(b *testing.B) {
	inner := fakeInnerWire()
	// The depth check rejects these invalid hop records before verification.
	garbageHops := make([]Hop, 1000)
	env := NewRelayEnvelope(inner, garbageHops)
	maxHops := MaxHopsForBudget(1 * time.Millisecond) // 15

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := env.Open(maxHops)
		if err != ErrHopBoundExceeded {
			b.Fatalf("bench must hit the depth-exceed branch, got err=%v", err)
		}
	}
}

// BenchmarkEnvelope_Open_3Hops_32c measures three outer relay verifications
// and the hop-count check for an A->B->C->D chain. The caller's inner origin
// verification is not included. On the 32-core c8g.8xlarge baseline, the three
// outer verifications cost approximately 3 x 60.2 us; other hosts measure
// their own verification cost. MaxHopsForBudget uses the baseline cost.
func BenchmarkEnvelope_Open_3Hops_32c(b *testing.B) {
	inner := fakeInnerWire()
	// Build a fresh 3-hop relay chain once (keygen is expensive and not
	// part of the measured path).
	env := buildRelayChainBench(b, inner, 3)
	maxHops := MaxHopsForBudget(1 * time.Millisecond) // 15, admits 3 hops

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := env.Open(maxHops)
		if err != nil {
			b.Fatalf("3-hop open must succeed, got %v", err)
		}
	}
}

// buildRelayChainBench builds an N-hop chain with fresh keys. It accepts a
// testing.TB so benchmarks can share genKey, and omits the relay public keys
// because the benchmarks do not use them.
func buildRelayChainBench(b testing.TB, innerWire []byte, nHops int) *RelayEnvelope {
	relayPubs := make([]ed25519.PublicKey, nHops)
	relayPrivs := make([]ed25519.PrivateKey, nHops)
	for i := 0; i < nHops; i++ {
		relayPubs[i], relayPrivs[i] = genKey(b)
	}
	hops := make([]Hop, nHops)
	var preceding []byte
	for i := 0; i < nHops; i++ {
		wall := int64(1_700_000_000_000_000 + i*1000)
		hops[i] = SignHop(relayPrivs[i], pubArray(relayPubs[i]), innerWire, preceding, uint16(i), wall)
		preceding = SignedMaterial(innerWire, preceding, uint16(i), wall)
	}
	return NewRelayEnvelope(innerWire, hops)
}
