package attribution

import (
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// BenchmarkEnvelope_HopBoundCheck_32c measures the O(1) hop-count check
// ns/op (read hop count, compare to bound) — the reject-before-Verify
// defense that runs BEFORE any crypto, before 3.0's clock cap is even
// relevant on the depth axis. It MUST be sub-us and 0-alloc: it is a single
// integer compare (len(hops) > maxHops) that returns ErrHopBoundExceeded
// without touching Ed25519.
//
// GEAR TAG (HONEST): GOMAXPROCS=4, CPU part 0xd40 (Cortex-A76-class,
// Graviton3-era). This is NOT c8g.8xlarge at 32c. The function name retains
// the _32c suffix per the Phase 3 roadmap's naming convention (the TARGET
// gear for the published bar); the HONEST gear tag is this comment and the
// commit message. Do NOT relabel a 4c number as a 32c number.
//
// The bench builds a 1000-hop envelope (the §1.D3.E attacker shape) and
// sets the bound to 15 (MaxHopsForBudget(1ms)), so every Open hits the
// depth-exceed branch and returns instantly — zero Verify calls. The
// reported ns/op is the O(1) depth-check cost; it must be orders of
// magnitude below the 60.2 us per-Verify cost (Track 4 c8g 32c sweep).
func BenchmarkEnvelope_HopBoundCheck_32c(b *testing.B) {
	inner := fakeInnerWire()
	// 1000 garbage hops — the depth check rejects before any Verify.
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

// BenchmarkEnvelope_Open_3Hops_32c measures the full A->B->C->D open: 3
// outer relay Verifies + the O(1) depth check. The inner origin Verify is
// the caller's job (Track 1.1) and is NOT included here, so this bench
// measures 3 Verifies ~= 3 x 60.2 us @ 32c (the ALREADY-PROVEN 32c
// per-Verify cost from the Track 4 sweep). On this 4c box the per-Verify
// cost differs from the 32c number; the bench is tagged 4c honestly and
// the 60.2 us figure is the PROVEN 32c publication number, not a 4c
// re-measurement.
//
// GEAR TAG (HONEST): 4c (GOMAXPROCS=4, CPU part 0xd40). Do NOT relabel 4c
// as 32c. The 60.2 us per-Verify is the PROVEN 32c number (Track 4 sweep,
// committed artifact); 3.2's hop-count bound is sized against it, not a 4c
// re-measurement.
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

// buildRelayChainBench is the bench-package variant of buildRelayChain that
// takes a testing.TB (so it can call genKey from a benchmark) and returns
// only the envelope (the bench does not need the relay pubkeys). It builds
// an N-hop relay chain with fresh keys.
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
