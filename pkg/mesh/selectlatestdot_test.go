// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"bytes"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestSelectLatestDotDeterministic checks the total order used by
// selectLatestDot. The higher DotCounter wins; equal counters are resolved by
// the smaller DotNodeID under bytes.Compare. Trying several permutations
// ensures that the result does not depend on which entry appears first, so
// peers scanning the same entries select the same latest dot.
func TestSelectLatestDotDeterministic(t *testing.T) {
	// Two entries with equal DotCounter but different DotNodeID. The total
	// order picks the smaller DotNodeID regardless of slice order.
	small := eng.CRDTEntry{DotNodeID: [16]byte{0x00}, DotCounter: 7, OriginNodeID: [16]byte{0x00}}
	large := eng.CRDTEntry{DotNodeID: [16]byte{0x01}, DotCounter: 7, OriginNodeID: [16]byte{0x01}}
	perms := [][]eng.CRDTEntry{
		{small, large},
		{large, small},
		{small, large, small}, // duplicates do not change the deterministic pick
		{large, small, large},
	}
	for i, p := range perms {
		got, ok := selectLatestDot(p)
		if !ok {
			t.Fatalf("perm %d: selectLatestDot returned ok=false on a non-empty slice", i)
		}
		if !bytes.Equal(got.DotNodeID[:], small.DotNodeID[:]) {
			t.Fatalf("perm %d: tie-break picked DotNodeID=%x, want the smaller %x (the total order must pick the smallest DotNodeID on an equal counter, independent of slice order)", i, got.DotNodeID, small.DotNodeID)
		}
	}

	// Two entries with different DotCounter: the higher counter wins regardless
	// of slice order (the primary key).
	lo := eng.CRDTEntry{DotNodeID: [16]byte{0xff}, DotCounter: 3}
	hi := eng.CRDTEntry{DotNodeID: [16]byte{0x00}, DotCounter: 9}
	for i, p := range [][]eng.CRDTEntry{{lo, hi}, {hi, lo}} {
		got, ok := selectLatestDot(p)
		if !ok {
			t.Fatalf("counter perm %d: ok=false", i)
		}
		if got.DotCounter != hi.DotCounter {
			t.Fatalf("counter perm %d: picked DotCounter=%d, want the higher %d (max DotCounter is the primary key)", i, got.DotCounter, hi.DotCounter)
		}
	}

	// Empty slice returns ok=false (the no-entries case handleGet and
	// LatestPayload branch on).
	if _, ok := selectLatestDot(nil); ok {
		t.Fatal("selectLatestDot(nil) returned ok=true; want false for an empty slice")
	}
	t.Logf("selectLatestDot is a pure total order (max DotCounter, ties -> smallest DotNodeID), deterministic across all permutations")
}
