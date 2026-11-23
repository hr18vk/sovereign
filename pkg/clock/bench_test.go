// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package clock

import (
	"testing"
)

// noopAdvancer is a LogicalAdvancer whose AdvanceLamportTo is a no-op.
// Admit does not use the advancer, so these benchmarks measure only the
// synthetic clock read and drift comparison.
type noopAdvancer struct{}

func (noopAdvancer) AdvanceLamportTo(uint64) {}

// BenchmarkIngressHLCScalarCap_32c measures the cost and allocations of Admit
// for a frame 1500 microseconds ahead of the local clock, within the bound.
func BenchmarkIngressHLCScalarCap_32c(b *testing.B) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	cap := NewIngressHLCScalarCap(clock, noopAdvancer{})

	// Accept-path frame: 1500 us-future (within epsilon).
	const incomingPhysical = t0 + 1500

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cap.Admit(incomingPhysical)
	}
}

// BenchmarkIngressHLCScalarCap_Reject_32c measures rejection of a frame 3000
// microseconds ahead of the local clock. Accept and reject run the same drift
// check; only the comparison outcome differs.
func BenchmarkIngressHLCScalarCap_Reject_32c(b *testing.B) {
	const t0 int64 = 1_700_000_000_000_000
	clock := NewSyntheticClock(t0)
	cap := NewIngressHLCScalarCap(clock, noopAdvancer{})

	// Reject-path frame: 3000 us-future (beyond epsilon).
	const incomingPhysical = t0 + 3000

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cap.Admit(incomingPhysical)
	}
}
