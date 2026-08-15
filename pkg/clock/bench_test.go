package clock

import (
	"testing"
)

// noopAdvancer is a LogicalAdvancer whose AdvanceLamportTo is a no-op,
// isolating the controller's own cost (clock read + epsilon compare +
// interface call) from the engine's CAS loop. The real engine's
// AdvanceLamportTo is a bounded CAS (crdt.go:1640-1685) that is itself
// sub-us on the accept path; the noop gives a clean lower bound on the
// controller overhead so the Admit ns/op is attributable to the gate
// alone.
type noopAdvancer struct{}

func (noopAdvancer) AdvanceLamportTo(uint64) {}

// BenchmarkIngressHLCScalarCap_32c measures the Admit path cost
// (ns/op, B/op, allocs/op). The "_32c" suffix is the ROADMAP target
// gear tag; the HONEST gear for this run is 4c (GOMAXPROCS=4, CPU part
// 0xd40) — the 32c re-run is PENDING Track 4 Karpenter c8g
// provisioning. Do NOT relabel a 4c number as 32c.
//
// The Admit ns/op MUST be demonstrably < 71.4 us/op (the VerifyCRDTFrame
// wall, Track 1.1 PROVEN commit 6db6132). A reject-path Admit of
// ~tens of ns satisfies this trivially; the ingestion seam is verified
// by comparing the reported ns/op against the 71.4 us Verify wall.
func BenchmarkIngressHLCScalarCap_32c(b *testing.B) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	cap := NewIngressHLCScalarCap(clock, noopAdvancer{})

	// Accept-path frame: 1500 us-future (within epsilon).
	const incomingPhysical = t0 + 1500
	const incomingLogical uint64 = 42

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cap.Admit(incomingPhysical, incomingLogical)
	}
}

// BenchmarkIngressHLCScalarCap_Reject_32c measures the reject path —
// the path a Byzantine-time burst takes. It MUST be cheaper than the
// accept path (no AdvanceLamportTo call) and far cheaper than the 71.4
// us Verify wall, so a burst is dropped in sub-us before Verify.
func BenchmarkIngressHLCScalarCap_Reject_32c(b *testing.B) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	cap := NewIngressHLCScalarCap(clock, noopAdvancer{})

	// Reject-path frame: 3000 us-future (beyond epsilon).
	const incomingPhysical = t0 + 3000
	const incomingLogical uint64 = 42

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cap.Admit(incomingPhysical, incomingLogical)
	}
}
