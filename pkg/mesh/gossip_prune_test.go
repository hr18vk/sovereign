// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// A converged pair should exchange almost no entries on the stratified gossip
// path. This test drives two TLS nodes through the normal gossip exchange, then
// checks A's per-peer sweep delta after their Merkle roots match.
//
// Subtracting and peeling the digests cancels their common keys. A saturated
// digest, seed mismatch, or divergent digest input instead makes GenerateDelta
// use the full oversend: all 100 entries, rather than the expected small delta.
// The threshold of 20 separates those outcomes without requiring an exact zero.
//
// This is a loopback test of the prune mechanism, not evidence that the
// multi-region convergence tail is bounded. Far-region exchanges can exceed the
// default 500 ms digest wait and fall back to oversend even when this test
// passes; ADR-0054 records the digest handshake behavior.

import (
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

func TestGossipPathPrunesPostConvergence(t *testing.T) {
	h := newStratifiedHarness(t, true) // stratified exchange over loopback TLS
	defer h.close()
	h.insertEvents(t, 100)

	rounds, converged, ra, rb := h.sweepUntilConverged(t, 30, 20*time.Millisecond)
	if !converged {
		t.Fatalf("did not converge in %d rounds (rootA=%x rootB=%x)", rounds, ra, rb)
	}
	t.Logf("converged in %d rounds (rootA=%x)", rounds, ra[:8])

	// After convergence, A's digest-exchange delta to B should be small rather
	// than the full 100-entry oversend.
	delta := h.gA.generateSweepDelta(h.ctx, h.identB.NodeID)
	n := 0
	delta.Entries(func(string, eng.CRDTEntry) bool { n++; return true })
	delta.Release()
	t.Logf("post-convergence A->B delta = %d (want ~0 pruned; full=100 means the gossip-path peel fails)", n)
	if n > 20 {
		t.Fatalf("gossip path does not prune: post-convergence delta = %d (want ~0)", n)
	}
}
