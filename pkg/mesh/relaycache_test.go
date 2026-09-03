// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// relaycache_test.go — (ADR-0045): the in-process
// falsification guard for the UNBOUNDED relayCache that breached the memory threshold.
//
// THE BREACH (silicon): max sovereign-node RSS reached 513,588 KB against
// the 512,000 KB threshold. That is a BREACH — an earlier report published both
// numbers without stating the comparison. A threshold exists to be compared against.
//
// THE MECHANISM (verified on the bytes at gossip.go:226-241):
//   - retainBatch copies the frame into batchForward[{origin, originSeq}] (:230);
//   - it then overwrites batchReverse[{origin, dotCounter}] = originSeq for every
//     element (:238), which points those dots at the NEW seq and leaves the OLD
//     seq's frame copy UNREACHABLE — an orphan;
//   - there is ZERO delete site for batchForward or batchReverse anywhere in the
//     tree (grep-confirmed).
// The origin RE-MINTS OriginSeqs every sweep, so a node retaining the same live dot
// set accumulates one orphaned frame copy per sweep, forever: O(sweeps), not
// O(live dots / batchSize).
//
// THE FIX: a per-forward-entry REFCOUNT. retainBatch sets
// refcount[{origin,seq}] = len(dotCounters); each reverse-index overwrite
// decrements the DISPLACED seq's refcount; at 0 the forward entry + refcount are
// deleted. Steady state ≈ live dots ÷ batch size frames per origin (~100 frames ≈
// 2 MB), independent of sweep count.
//
// RUN: go test -run 'TestRelayCache' -race -count=1 ./pkg/mesh/

import (
	"fmt"
	"testing"
)

// TestRelayCacheBounded is the RED→GREEN guard: retain the SAME dot
// set under N advancing OriginSeqs (exactly what the origin does across N sweeps)
// and assert the forward map's cardinality stays O(dots/batchSize) — INDEPENDENT of
// N.
//
// RED on pre-bytes: the forward map grows to N entries (one orphaned frame copy
// per sweep) because nothing ever deletes a displaced seq's frame.
func TestRelayCacheBounded(t *testing.T) {
	const (
		dots   = 100 // one batch's worth of elements (the production batch size)
		sweeps = 200 // the origin re-mints seqs every sweep; reached round 232
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
	// The SAME 100 dots are live throughout, so at most ceil(dots/batchSize) = 1
	// batch frame is reachable. A small constant slack is allowed for an
	// implementation that keeps the newest plus one in-flight predecessor.
	const wantMax = 4
	if fwd > wantMax {
		t.Fatalf("UNBOUNDED RELAY CACHE: after %d sweeps retaining the SAME %d dots, the forward map holds %d frame copies (want <= %d). Each sweep's retainBatch copies a frame under a FRESH OriginSeq (gossip.go:230) while the reverse-index overwrite (:238) re-points every dot at the new seq — orphaning the previous frame — and there is NO delete site for batchForward anywhere in the tree. Growth is therefore O(sweeps), not O(live dots / batchSize).\n\nMEASURED CONSEQUENCE: silicon the run max node RSS = 513,588 KB against the 512,000 KB CHECK-F threshold — a BREACH.\n\nFIX: refcount each forward entry (= len(dotCounters) at retain), decrement the DISPLACED seq on every reverse-index overwrite, delete the forward entry + refcount at 0.",
			sweeps, dots, fwd, wantMax)
	}
	if rev != dots {
		t.Fatalf("The reverse index must hold exactly one entry per LIVE dot (%d), got %d — the reverse index is per-dot and must not grow with sweeps either", dots, rev)
	}
	t.Logf("GREEN — %d sweeps re-minting OriginSeqs over the SAME %d dots leaves %d frame copy/copies in the forward map (<= %d) and exactly %d reverse entries: retention is now O(live dots / batchSize), INDEPENDENT of sweep count. The CHECK-F growth driver is closed.", sweeps, dots, fwd, wantMax, rev)
}

// TestRelayCachePartialSupersession is the harder case a review demanded:
// batch boundaries SHIFT across sweeps (proved they do — 98,488 vs 98,000
// entries), so a new batch supersedes only SOME of a previous batch's dots. The old
// frame must stay alive while ANY of its dots still point at it, and must be freed
// exactly when the last one is displaced — no premature free (which would break the
// relay) and no leak.
func TestRelayCachePartialSupersession(t *testing.T) {
	c := newRelayCache()
	var origin [16]byte
	origin[0] = 0xF7

	// Sweep 1: seq 10 covers dots 1..10.
	first := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	c.retainBatch(origin, 10, first, []byte("frame-seq-10"))

	// Sweep 2: seq 11 covers dots 6..15 — a PARTIAL supersession of seq 10 (dots
	// 6..10 move to seq 11; dots 1..5 still point at seq 10).
	second := []uint64{6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	c.retainBatch(origin, 11, second, []byte("frame-seq-11"))

	// Dots 1..5 MUST still resolve to seq 10's frame: freeing it here would break
	// the relay for entries nothing else carries.
	if got, _, ok := c.lookupBatch(origin, 3); !ok || string(got) != "frame-seq-10" {
		t.Fatalf("PREMATURE FREE: dot 3 still belongs to seq 10 (only dots 6..10 were superseded), but lookupBatch returned ok=%v frame=%q. Freeing a frame while ANY of its dots still reference it breaks the relay for those entries — the refcount must reach 0 before deletion.", ok, string(got))
	}
	// Dot 8 must now resolve to seq 11 (it WAS superseded).
	if got, _, ok := c.lookupBatch(origin, 8); !ok || string(got) != "frame-seq-11" {
		t.Fatalf("Dot 8 was superseded by seq 11 and must resolve to its frame, got ok=%v frame=%q", ok, string(got))
	}
	fwd, _ := c.batchLenForTest()
	if fwd != 2 {
		t.Fatalf("With dots 1..5 on seq 10 and dots 6..15 on seq 11, BOTH frames are still referenced — forward map must hold exactly 2, got %d", fwd)
	}

	// Sweep 3: seq 12 covers dots 1..5 — the LAST references to seq 10. Now seq 10
	// must be freed.
	third := []uint64{1, 2, 3, 4, 5}
	c.retainBatch(origin, 12, third, []byte("frame-seq-12"))
	fwd, _ = c.batchLenForTest()
	if fwd != 2 {
		t.Fatalf("LEAK: after the LAST dots referencing seq 10 were superseded by seq 12, seq 10's frame must be DELETED — forward map should hold seq 11 + seq 12 = 2, got %d. Refcount must decrement the DISPLACED seq on every reverse-index overwrite and delete at 0.", fwd)
	}
	if got, _, ok := c.lookupBatch(origin, 3); !ok || string(got) != "frame-seq-12" {
		t.Fatalf("Dot 3 was superseded by seq 12 and must resolve to its frame, got ok=%v frame=%q", ok, string(got))
	}
	t.Logf("GREEN (partial supersession) — a shifting batch boundary keeps the old frame alive while ANY dot still references it (dots 1..5 → seq 10 resolved correctly), and frees it EXACTLY when the last reference is displaced (forward map 2, not 3): no premature free, no leak. This is the run-#7 shape (98,488 vs 98,000 entries proved boundaries shift).")
}

// TestRelayCacheMultiOriginIsolation guards the refcount's keying: two origins
// re-minting seqs must not free each other's frames.
func TestRelayCacheMultiOriginIsolation(t *testing.T) {
	c := newRelayCache()
	var a, b [16]byte
	a[0], b[0] = 0xAA, 0xBB
	dotsA := []uint64{1, 2, 3}
	dotsB := []uint64{1, 2, 3} // SAME dotCounters, DIFFERENT origin
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
	if got, _, ok := c.lookupBatch(a, 2); !ok || string(got) != "A-50" {
		t.Fatalf("multi-origin: origin A's dot 2 must resolve to A's newest frame, got ok=%v frame=%q", ok, string(got))
	}
	if got, _, ok := c.lookupBatch(b, 2); !ok || string(got) != "B-50" {
		t.Fatalf("multi-origin: origin B's dot 2 must resolve to B's newest frame, got ok=%v frame=%q", ok, string(got))
	}
	t.Logf("GREEN (multi-origin isolation) — 2 origins x 50 sweeps over the SAME dotCounters leave %d frames and %d reverse entries, each origin resolving to its OWN newest frame: the refcount is per-(origin,seq) and origins cannot free each other's retentions.", fwd, rev)
}
