// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests bound relay-cache retention as origins advance their sequence
// numbers across sweeps (ADR-0045). Without reference counting, replacing a
// dot's reverse-index entry can leave the previous frame unreachable but still
// stored. Repeating that displacement once per sweep grows memory with sweep
// count rather than with the live dot set.
//
// retainBatch counts the dots associated with each forward entry. Overwriting
// a reverse-index entry decrements the displaced frame's count, and reaching
// zero deletes that frame. A frame therefore remains available while any live
// dot references it, independent of how many later sweeps occur.
//
// Run with: go test -run 'TestRelayCache' -race -count=1 ./pkg/mesh/

import (
	"fmt"
	"testing"
)

// TestRelayCacheBounded retains one dot set under advancing origin sequences.
// The forward map must stay proportional to dots/batchSize, not to the number
// of sweeps. The reverse index continues to hold one entry per live dot.
func TestRelayCacheBounded(t *testing.T) {
	const (
		dots   = 100 // one batch at the production batch size
		sweeps = 200 // advance the origin sequence on every sweep
	)
	c := newRelayCache()
	var origin [16]byte
	origin[0] = 0xF7

	dotCounters := make([]uint64, dots)
	for i := range dotCounters {
		dotCounters[i] = uint64(i + 1)
	}
	frame := make([]byte, 2048) // a realistic batch envelope size

	for s := 1; s <= sweeps; s++ {
		c.retainBatch(origin, uint64(s), dotCounters, frame)
	}

	fwd, rev := c.batchLenForTest()
	// The same 100 dots are live throughout, so at most ceil(dots/batchSize) = 1
	// batch frame is reachable. A small constant slack is allowed for an
	// implementation that keeps the newest plus one in-flight predecessor.
	const wantMax = 4
	if fwd > wantMax {
		t.Fatalf("after %d sweeps over %d dots, forward map holds %d frames, want at most %d; retention must depend on live dots rather than sweep count",
			sweeps, dots, fwd, wantMax)
	}
	if rev != dots {
		t.Fatalf("reverse index: want one entry for each of %d live dots, got %d", dots, rev)
	}
	t.Logf("%d sweeps over %d dots retained %d forward frames (limit %d) and %d reverse entries", sweeps, dots, fwd, wantMax, rev)
}

// TestRelayCachePartialSupersession covers shifting batch boundaries. A new
// batch can supersede only some dots in an older frame. That frame must remain
// available until its last referenced dot moves to a newer sequence, then be
// reclaimed without affecting the remaining frames.
func TestRelayCachePartialSupersession(t *testing.T) {
	c := newRelayCache()
	var origin [16]byte
	origin[0] = 0xF7

	// Sweep 1: seq 10 covers dots 1..10.
	first := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	c.retainBatch(origin, 10, first, []byte("frame-seq-10"))

	// Sweep 2: seq 11 covers dots 6..15 — a partial supersession of seq 10 (dots
	// 6..10 move to seq 11; dots 1..5 still point at seq 10).
	second := []uint64{6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	c.retainBatch(origin, 11, second, []byte("frame-seq-11"))

	// Dots 1..5 must still resolve to seq 10's frame: freeing it here would break
	// the relay for entries nothing else carries.
	if got, _, _, ok := c.lookupBatchCounted(origin, 3); !ok || string(got) != "frame-seq-10" {
		t.Fatalf("premature free: dot 3 still belongs to seq 10 (only dots 6..10 were superseded), but lookupBatch returned ok=%v frame=%q. Freeing a frame while any of its dots still reference it breaks the relay for those entries — the refcount must reach 0 before deletion.", ok, string(got))
	}
	// Dot 8 moved to seq 11 and must resolve to its frame.
	if got, _, _, ok := c.lookupBatchCounted(origin, 8); !ok || string(got) != "frame-seq-11" {
		t.Fatalf("dot 8 was superseded by seq 11 and must resolve to its frame, got ok=%v frame=%q", ok, string(got))
	}
	fwd, _ := c.batchLenForTest()
	if fwd != 2 {
		t.Fatalf("with dots 1..5 on seq 10 and dots 6..15 on seq 11, both frames are still referenced — forward map must hold exactly 2, got %d", fwd)
	}

	// Sweep 3: seq 12 covers dots 1..5 — the last references to seq 10. Now seq 10
	// must be freed.
	third := []uint64{1, 2, 3, 4, 5}
	c.retainBatch(origin, 12, third, []byte("frame-seq-12"))
	fwd, _ = c.batchLenForTest()
	if fwd != 2 {
		t.Fatalf("leak: after the last dots referencing seq 10 were superseded by seq 12, seq 10's frame must be deleted — forward map should hold seq 11 + seq 12 = 2, got %d. Refcount must decrement the displaced seq on every reverse-index overwrite and delete at 0.", fwd)
	}
	if got, _, _, ok := c.lookupBatchCounted(origin, 3); !ok || string(got) != "frame-seq-12" {
		t.Fatalf("dot 3 was superseded by seq 12 and must resolve to its frame, got ok=%v frame=%q", ok, string(got))
	}
	t.Logf("partial supersession preserved referenced frames and reclaimed seq 10 after its last dot moved")
}

// TestRelayCacheMultiOriginIsolation guards the refcount's keying: two origins
// re-minting seqs must not free each other's frames.
func TestRelayCacheMultiOriginIsolation(t *testing.T) {
	c := newRelayCache()
	var a, b [16]byte
	a[0], b[0] = 0xAA, 0xBB
	dotsA := []uint64{1, 2, 3}
	dotsB := []uint64{1, 2, 3} // same dotCounters, different origin
	for s := 1; s <= 50; s++ {
		c.retainBatch(a, uint64(s), dotsA, []byte(fmt.Sprintf("A-%d", s)))
		c.retainBatch(b, uint64(s), dotsB, []byte(fmt.Sprintf("B-%d", s)))
	}
	fwd, rev := c.batchLenForTest()
	if fwd > 8 {
		t.Fatalf("multi-origin: forward map holds %d frames for 2 origins x 3 live dots (want <= 8) — the refcount must be keyed per (origin, seq) and free each origin's orphans independently", fwd)
	}
	if rev != 6 {
		t.Fatalf("multi-origin: reverse index must hold 3 dots x 2 origins = 6 entries, got %d — a shared-dotCounter collision across origins would corrupt the relay", rev)
	}
	if got, _, _, ok := c.lookupBatchCounted(a, 2); !ok || string(got) != "A-50" {
		t.Fatalf("multi-origin: origin A's dot 2 must resolve to A's newest frame, got ok=%v frame=%q", ok, string(got))
	}
	if got, _, _, ok := c.lookupBatchCounted(b, 2); !ok || string(got) != "B-50" {
		t.Fatalf("multi-origin: origin B's dot 2 must resolve to B's newest frame, got ok=%v frame=%q", ok, string(got))
	}
	t.Logf("multi-origin isolation: 2 origins x 50 sweeps retained %d frames and %d reverse entries; each origin resolved to its newest frame", fwd, rev)
}
