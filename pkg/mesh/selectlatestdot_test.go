package mesh

import (
	"bytes"
	"testing"

	eng "github.com/hr18vk/supremum/pkg/sync"
)

// TestSelectLatestDotDeterministic (G06.5.B) is the pure-function tooth for the
// FIX B tie-break. selectLatestDot must be a TOTAL ORDER over the entry slice:
// the HIGHER DotCounter wins, and on a tie the SMALLER DotNodeID
// (bytes.Compare) wins — INDEPENDENT of slice iteration order. The OLD strict
// `>` tie-break made the pick depend on iteration order (first-encountered
// wins), so two nodes scanning the same equal-counter multi-origin entries
// could return a DIFFERENT "latest". This tooth asserts the SAME result for
// every permutation, which the old `>` fails (it returns whichever entry
// appears first in the slice).
func TestSelectLatestDotDeterministic(t *testing.T) {
	// Two entries with EQUAL DotCounter but DIFFERENT DotNodeID. The total
	// order picks the SMALLER DotNodeID regardless of slice order.
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

	// Two entries with DIFFERENT DotCounter: the HIGHER counter wins regardless
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
	t.Logf("G06.5.B PASS: selectLatestDot is a pure total order (max DotCounter, ties -> smallest DotNodeID), deterministic across all permutations")
}
