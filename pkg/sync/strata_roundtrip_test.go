package sync_test

import (
	eng "github.com/hr18vk/supremum/pkg/sync"
	"hash/maphash"
	"testing"
)

func TestStrataEstimatorWireRoundTrip(t *testing.T) {
	seed := hashJudgeSeed(t)
	local := eng.NewStrataEstimator(seed)
	// Insert a spread of keys across strata (varying trailing-zero counts).
	for i := 0; i < 5000; i++ {
		local.Insert(uint64(i*7 + 1))
	}
	wire, err := eng.MarshalStrataEstimator(local)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	t.Logf("wire size = %d bytes (32 strata x ~1.6KB)", len(wire))
	remote, err := eng.UnmarshalStrataEstimator(wire)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// The round-tripped estimator must estimate |A-A|==0 against an identical
	// estimator (self-diff = the M3 no-op premise, here proving the wire
	// preserved the bucket state).
	if got := local.Estimate(remote); got != 0 {
		t.Fatalf("self-diff after round-trip = %d, want 0 (wire did not preserve bucket state)", got)
	}
	// Seed round-trip fidelity (the load-bearing field).
	if local.Seed() != remote.Seed() {
		t.Fatalf("seed drifted across wire: local=%v remote=%v", local.Seed(), remote.Seed())
	}
}

func hashJudgeSeed(t *testing.T) maphash.Seed {
	t.Helper()
	return maphash.MakeSeed()
}
