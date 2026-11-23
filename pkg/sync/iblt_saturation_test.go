// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// TestIBLT_SaturationDependsOnDiffSize checks whether a 1024-bucket digest
// saturates on total keyset size or symmetric-difference size. Subtract cancels
// common keys bucket by bucket, so a 1200-key engine with a small peer difference
// should usually return only that difference rather than the full keyset.
//
// Peeling is probabilistic: a non-peelable cluster makes GenerateDelta return
// the full keyset. For every deterministic seed, this test accepts either the
// exact difference after a successful peel or the full keyset after a failed
// peel; a partial or otherwise incorrect delta fails the test. Small differences
// must peel for a plurality of seeds, while a saturated difference must always
// take the full-keyset fallback.
func TestIBLT_SaturationDependsOnDiffSize(t *testing.T) {
	nodeID := [16]byte{0xF0, 0x20}
	// A 1200-key set exceeds both the approximate 750-key peel threshold and
	// the 1024-bucket table size while keeping the race-detector run bounded.
	// The diff must remain small independently of this oversized keyset.
	const total = 1200
	const seeds = 12
	cases := []struct {
		diff        int
		minPrune    int // >= this many of `seeds` must peel to the minimal delta (the diff-bound)
		minOversend int // >= this many must oversend the full keyset (the saturation pole)
	}{
		// The thresholds allow for process-dependent dots while distinguishing
		// small differences from saturation. A keyset-size bound would produce
		// no pruned results for the small-difference cases.
		{0, seeds, 0},   // converged engines prune on every seed
		{100, 8, 0},     // a small difference prunes on most seeds
		{400, 4, 0},     // near the transition, a plurality is sufficient
		{900, 0, seeds}, // a saturated difference always sends the full keyset
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("diff=%d", tc.diff), func(t *testing.T) {
			engineA := newTestEngine(t, nodeID, 0)
			engineB := newTestEngine(t, nodeID, 0)
			common := total - tc.diff
			// Insert key i into both engines for i < common (same order ⇒ both mint the
			// same counter ⇒ same dot ⇒ same HashCausalDot ⇒ the common keys cancel in
			// the subtract). Keys [common,total) go to A only.
			for i := 0; i < total; i++ {
				entry := CRDTEntry{
					SystemTime:    int64(1_700_000_000 + i),
					H3Index:       uint64(i),
					PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i))),
				}
				eid := fmt.Sprintf("k-%d", i)
				engineA.InsertLocal(eid, entry)
				if i < common {
					engineB.InsertLocal(eid, entry)
				}
			}
			prune, oversend, wrong := 0, 0, 0
			for s := 0; s < seeds; s++ {
				seed := Uint64ToSeed(uint64(s+1) * 0x9E3779B97F4A7C15) // deterministic, well-spread
				digestB := engineB.GenerateDigestWithSeed(seed)        // remote digest for B's keyset
				delta := engineA.GenerateDelta(digestB)
				n := 0
				delta.Entries(func(string, CRDTEntry) bool { n++; return true })
				delta.Release()
				digestB.Release()
				switch {
				case n == tc.diff:
					prune++
				case n == total:
					oversend++
				default:
					wrong++
				}
			}
			t.Logf("keyset=%d |A-B|=%d: exact difference on %d/%d seeds, full keyset on %d, invalid delta on %d",
				total, tc.diff, prune, seeds, oversend, wrong)
			// A failed peel may send the full keyset, never a partial delta.
			if wrong != 0 {
				t.Fatalf("fallback invariant: diff=%d produced %d deltas containing neither the exact difference (%d entries) nor the full keyset (%d entries)",
					tc.diff, wrong, tc.diff, total)
			}
			if prune < tc.minPrune {
				t.Fatalf("keyset=%d diff=%d pruned on %d/%d seeds; want at least %d. A keyset-size bound would send all %d entries instead of the approximately %d-entry difference",
					total, tc.diff, prune, seeds, tc.minPrune, tc.diff, total)
			}
			if oversend < tc.minOversend {
				t.Fatalf("keyset=%d diff=%d used the full-keyset fallback on %d/%d seeds; want %d because this difference saturates the table",
					total, tc.diff, oversend, seeds, seeds)
			}
		})
	}
}
