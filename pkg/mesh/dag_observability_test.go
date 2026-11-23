// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests cover two IBLT observability paths (ADR-0055): a completed
// exchange that falls back after a failed peel, and a response dropped because
// the responder semaphore is full. Each counter must increase on its failure
// path and remain unchanged on the corresponding healthy path.
package mesh

import (
	"fmt"
	"hash/maphash"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestOversendCounterFiresOnPeelFailure checks both outcomes of a direct
// generateSweepDelta exchange, bypassing the change gate.
//
// After convergence, the exchange must peel cleanly with PeelErr == nil and
// SendKeyCount == 0, leaving the counter unchanged. A subsequent 1,000-key
// A-only divergence exceeds the fixed 1,024-bucket digest's roughly 700-key
// peel capacity. The resulting PeelErr must increment the counter once.
//
// The deterministic overload is a counter test, not an estimate of the sweep's
// peel-failure rate.
func TestOversendCounterFiresOnPeelFailure(t *testing.T) {
	h := newStratifiedHarness(t, true)
	defer h.close()
	h.gA.SetDigestWaitTimeout(5 * time.Second)
	h.gB.SetDigestWaitTimeout(5 * time.Second)
	h.insertEvents(t, 50)
	if _, converged, ra, rb := h.sweepUntilConverged(t, 40, 20*time.Millisecond); !converged {
		t.Fatalf("setup: 2-node mesh did not converge (rootA=%x rootB=%x)", ra, rb)
	}

	// A converged exchange peels cleanly and leaves the counter unchanged.
	before := h.gA.digestPeelOversends.Load()
	delta := h.gA.generateSweepDelta(h.ctx, h.identB.NodeID)
	if delta == nil {
		t.Fatalf("healthy arm: generateSweepDelta returned nil")
	}
	if delta.PeelErr() != nil {
		t.Fatalf("healthy arm: a converged peer's exchange returned peelErr=%v — the digest does not prune", delta.PeelErr())
	}
	if got := delta.SendKeyCount(); got != 0 {
		t.Fatalf("healthy arm: a converged exchange shipped delta=%d (want 0 — the prune verdict)", got)
	}
	delta.Release()
	if got := h.gA.digestPeelOversends.Load(); got != before {
		t.Fatalf("healthy arm: the oversend counter fired on a clean peel (%d -> %d) — the counter cannot distinguish healthy from oversend", before, got)
	}

	// Exceed the digest's peel capacity with 1,000 A-only keys.
	for i := 0; i < 1000; i++ {
		h.gA.InsertLocalEvents(fmt.Sprintf("dag-big-%d", i), fmt.Sprintf("v-%d", i), eng.CRDTEntry{
			SystemTime: int64(1_800_000_000 + i),
			H3Index:    uint64(i),
		})
	}
	time.Sleep(100 * time.Millisecond) // let the local inserts settle before the exchange
	delta = h.gA.generateSweepDelta(h.ctx, h.identB.NodeID)
	if delta == nil {
		t.Fatalf("defect arm: generateSweepDelta returned nil")
	}
	if delta.PeelErr() == nil {
		t.Fatalf("defect arm: a 1000-key divergence peeled cleanly (SendKeyCount=%d) — the >capacity premise is wrong; the test needs a larger divergence", delta.SendKeyCount())
	}
	delta.Release()
	if got := h.gA.digestPeelOversends.Load(); got != before+1 {
		t.Fatalf("oversend counter test fail: the completed-exchange peel failure did not fire the counter exactly once (%d -> %d, want +1) — the oversend is still invisible", before, got)
	}
	t.Logf("oversend counter test pass: the >capacity oversend fired the committed counter exactly once; the converged exchange stayed quiet with delta=0")
}

// TestResponderDropCounter drives both branches of enqueueDigestResponse.
// With a free responder slot, digestRespondSent increases and the drop counter
// stays fixed. With every slot held, digestRespondDropped increases and the
// sent counter stays fixed.
func TestResponderDropCounter(t *testing.T) {
	h := newStratifiedHarness(t, true)
	defer h.close()

	// With B live and a free responder slot, the response publishes normally.
	sent0 := h.gA.digestRespondSent.Load()
	dropped0 := h.gA.digestRespondDropped.Load()
	h.gA.enqueueDigestResponse(h.identB.NodeID, maphash.MakeSeed(), eng.IBLTDigestDefaultBuckets)
	deadline := time.Now().Add(3 * time.Second) // the responder runs on its own goroutine
	for h.gA.digestRespondSent.Load() == sent0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.gA.digestRespondSent.Load(); got == sent0 {
		t.Fatalf("baseline: the response never shipped (digestRespondSent stuck at %d) — the non-drop arm did not run", sent0)
	}
	if got := h.gA.digestRespondDropped.Load(); got != dropped0 {
		t.Fatalf("baseline: a normal response incremented the drop counter (%d -> %d)", dropped0, got)
	}

	// The drop shape: manually hold all digestRespondMaxConcurrent build slots.
	for i := 0; i < digestRespondMaxConcurrent; i++ {
		h.gA.respondSem <- struct{}{}
	}
	h.gA.enqueueDigestResponse(h.identB.NodeID, maphash.MakeSeed(), eng.IBLTDigestDefaultBuckets)
	if got := h.gA.digestRespondDropped.Load(); got != dropped0+1 {
		t.Fatalf("responder drop test fail: the saturated-bound drop did not fire the counter (%d -> %d, want +1) — the drop is still silent", dropped0, got)
	}
	if got := h.gA.digestRespondSent.Load(); got != sent0+1 {
		t.Fatalf("responder drop test fail: the dropped request also counted as sent (%d, want %d)", got, sent0+1)
	}
	// Release the held slots before the harness closes.
	for i := 0; i < digestRespondMaxConcurrent; i++ {
		<-h.gA.respondSem
	}
	t.Logf("responder drop test pass: free bound ships (+sent, dropped quiet); saturated bound drops (+dropped, sent quiet)")
}
