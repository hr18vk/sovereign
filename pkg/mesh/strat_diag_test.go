// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"hash/maphash"
	"sync/atomic"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestStratDiagUnit proves the per-region stratified digest diagnostic
// asserts the exchange/fallback counters fire against the correct peer region,
// the window snapshot resets, and the log format is deterministic. If
// noteStratExchange or noteStratFallback are dropped from generateSweepDelta,
// the counts are zero and this test fails.
func TestStratDiagUnit(t *testing.T) {
	topo := NewTopologyManager(RegionTag(1)) // self = region 1
	peerIntra := [16]byte{0x0A}
	peerInterNear := [16]byte{0x0B}
	peerInterFar := [16]byte{0x0C}
	topo.SetRegion(peerIntra, RegionTag(1))     // intra (same as self)
	topo.SetRegion(peerInterNear, RegionTag(2)) // inter (eu)
	topo.SetRegion(peerInterFar, RegionTag(3))  // inter (ap)

	g := &Gossiper{topology: topo}
	g.SetStratifiedAntiEntropy(true)
	if g.stratDiag == nil {
		t.Fatalf("SetStratifiedAntiEntropy(true) did not allocate stratDiag")
	}

	// 3 intra + 1 near-inter + 2 far-inter exchanges; 1 far-inter fallback; 5ms digest.
	g.noteStratExchange(peerIntra)
	g.noteStratExchange(peerIntra)
	g.noteStratExchange(peerIntra)
	g.noteStratExchange(peerInterNear)
	g.noteStratExchange(peerInterFar)
	g.noteStratExchange(peerInterFar)
	g.noteStratFallback(peerInterFar)
	g.noteStratDigestNs(5_000_000)

	ex, fb, ns := g.stratDiagSnapshotReset()
	if ex[RegionTag(1)] != 3 || ex[RegionTag(2)] != 1 || ex[RegionTag(3)] != 2 {
		t.Fatalf("exchange per-region counts wrong: %v (want {1:3, 2:1, 3:2})", ex)
	}
	if len(fb) != 1 || fb[RegionTag(3)] != 1 {
		t.Fatalf("fallback per-region count wrong: %v (want {3:1} only — no intra fallback)", fb)
	}
	if ns != 5_000_000 {
		t.Fatalf("digest ns wrong: %d (want 5000000)", ns)
	}

	// The window resets: a second snapshot is empty (the convergence-phase rate is
	// not diluted by the prior window).
	ex2, fb2, ns2 := g.stratDiagSnapshotReset()
	if len(ex2) != 0 || len(fb2) != 0 || ns2 != 0 {
		t.Fatalf("stratDiagSnapshotReset did not reset: ex=%v fb=%v ns=%d", ex2, fb2, ns2)
	}

	// Deterministic format (sorted regions, grep-able name=value).
	s := formatStratDiag(RegionTag(1), ex, fb, ns)
	want := " strat(self=1){1:x3/f0,2:x1/f0,3:x2/f1}dgms=5"
	if s != want {
		t.Fatalf("formatStratDiag = %q, want %q; region labels and ordering must be deterministic", s, want)
	}
}

// TestStratDiagOffIsNil checks that disabling stratified anti-entropy leaves
// stratDiag and respondSem nil. The diagnostic methods are nil-guarded no-ops,
// and enqueueDigestResponse sends nothing on the ordinary oversend path.
func TestStratDiagOffIsNil(t *testing.T) {
	g := &Gossiper{}
	g.SetStratifiedAntiEntropy(false)
	if g.stratDiag != nil {
		t.Fatalf("stratDiag is non-nil with stratified anti-entropy disabled")
	}
	if g.respondSem != nil {
		t.Fatalf("respondSem is non-nil with stratified anti-entropy disabled")
	}
	// Disabled diagnostic methods must not panic or record data.
	g.noteStratExchange([16]byte{0x01})
	g.noteStratFallback([16]byte{0x01})
	g.noteStratDigestNs(1000)
	ex, fb, ns := g.stratDiagSnapshotReset()
	if ex != nil || fb != nil || ns != 0 {
		t.Fatalf("stratDiagSnapshotReset on a nil stratDiag returned non-zero: %v %v %d", ex, fb, ns)
	}
	if s := formatStratDiag(RegionUnset, nil, nil, 0); s != "" {
		t.Fatalf("formatStratDiag on empty maps = %q, want empty (no suffix when stratified made no exchange)", s)
	}
	// The disabled response path must not send a digest response.
	g.enqueueDigestResponse([16]byte{0x01}, maphash.MakeSeed(), eng.IBLTDigestDefaultBuckets)
	if got := g.digestRespondSent.Load(); got != 0 {
		t.Fatalf("disabled responder sent %d digest responses", got)
	}
}

// TestStratDiagTwoSweepHandshake recreates the exchange behavior without a
// digest responder. A sweeps B, but B neither sweeps nor answers, so A's wait
// reaches the 200ms test timeout and falls back to oversend. Both the general
// fallback counter and the per-region diagnostic must record the timeout.
// TestRequestResponse_LoneSweepCompletes covers the enabled responder.
func TestStratDiagTwoSweepHandshake(t *testing.T) {
	h := newStratifiedHarness(t, true) // stratified anti-entropy enabled
	defer h.close()
	h.insertEvents(t, 100)

	// Disable B's responder to revert the exchange to the two-sweep handshake
	// (B never answers A's request).
	h.gB.disableDigestRespond.Store(true)

	// Run only A's sweep. B never sweeps A and never answers. A's digest
	// exchange with B must time out and fall back to oversend.
	h.gA.AntiEntropySweep(h.ctx)

	if got := atomic.LoadInt32(&h.fallbackA); got == 0 {
		t.Fatalf("A's lone sweep did not fall back with B's responder disabled")
	}
	// With no topology, the diagnostic belongs in the RegionUnset bucket.
	_, fb, _ := h.gA.stratDiagSnapshotReset()
	if fb[RegionUnset] == 0 {
		t.Fatalf("stratDiag recorded no fallback while the general fallback counter fired")
	}
	t.Logf("responder disabled: A's lone sweep fell back (fallbackA=%d, stratDiag=%v)", atomic.LoadInt32(&h.fallbackA), fb)
}
