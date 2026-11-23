// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These negative controls cover per-peer sorting, batch hoisting, and eager
// relay-map initialization. Each arms one fault through
// SOVEREIGN_TEST_FAULT_BOUNDED_GOSSIP and checks its observable effect.
// Ordinary test runs leave the variable unset and skip these controls.

package mesh

import (
	"context"
	"fmt"
	"os"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestNegativeControlSorts restores per-peer shipBatchedDelta walks through
// redPerPeerSortBugInject. A two-peer sweep must capture at least two builds;
// one shared build would mean the injection did not reach the dispatch path.
func TestNegativeControlSorts(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_BOUNDED_GOSSIP") != "sorts" {
		t.Skip("runs only with SOVEREIGN_TEST_FAULT_BOUNDED_GOSSIP=sorts")
	}
	h := newRelaySharedHarness(t, 3, 64)
	defer h.close()
	const A, B, C = 0, 1, 2
	h.connect(t, A, B)
	h.connect(t, A, C)
	for i := range h.nodes {
		h.nodes[i].g.SetBatchSize(100)
	}
	h.waitForEgress(t, A, B, C)
	h.nodes[A].g.redPerPeerSortBugInject.Store(true)
	t.Logf("per-peer sorting fault armed")
	for i := 0; i < 60; i++ {
		h.nodes[A].g.InsertLocalEvents(fmt.Sprintf("sort-fault-key-%d", i), fmt.Sprintf("v-%03d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_400_000 + i), H3Index: uint64(5000 + i)})
	}
	caps := armContentProbe(t, h.nodes[A].g)
	st := h.nodes[A].g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes == 0 {
		t.Fatalf("sweep shipped no envelopes, so the fault control observed no builds")
	}
	if got := len(*caps); got < 2 {
		t.Fatalf("per-peer sorting fault captured %d builds, want at least 2; the fault did not restore per-peer walks", got)
	}
	t.Logf("per-peer sorting fault produced %d builds", len(*caps))
}

// TestNegativeControlHoistAll bypasses the stratified domain check through
// redHoistAllBugInject. The sweep then reuses one shared build for peers that
// need different deltas. At least one peer must have a missing or incorrect
// capture, proving that the per-peer domain assertion can detect this fault.
func TestNegativeControlHoistAll(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_BOUNDED_GOSSIP") != "hoistall" {
		t.Skip("runs only with SOVEREIGN_TEST_FAULT_BOUNDED_GOSSIP=hoistall")
	}
	h := newRelaySharedHarness(t, 3, 64)
	defer h.close()
	const A, B, C = 0, 1, 2
	h.connect(t, A, B)
	h.connect(t, A, C)
	for i := range h.nodes {
		h.nodes[i].g.SetBatchSize(100)
	}
	h.waitForEgress(t, A, B, C)
	var xKeys, yKeys []string
	for i := 0; i < 30; i++ {
		xk := fmt.Sprintf("hoist-fault-x-%d", i)
		yk := fmt.Sprintf("hoist-fault-y-%d", i)
		h.nodes[A].g.InsertLocalEvents(xk, fmt.Sprintf("x-%03d", i), eng.CRDTEntry{SystemTime: int64(1_700_500_000 + i), H3Index: uint64(6000 + i)})
		h.nodes[A].g.InsertLocalEvents(yk, fmt.Sprintf("y-%03d", i), eng.CRDTEntry{SystemTime: int64(1_700_600_000 + i), H3Index: uint64(7000 + i)})
		xKeys = append(xKeys, xk)
		yKeys = append(yKeys, yk)
	}
	if _, _, err := h.nodes[A].g.ShipBatch(context.Background(), h.nodes[B].ident.NodeID, h.eventsOfSet(t, A, yKeys)); err != nil {
		t.Fatalf("pre-seed B: %v", err)
	}
	if _, _, err := h.nodes[A].g.ShipBatch(context.Background(), h.nodes[C].ident.NodeID, h.eventsOfSet(t, A, xKeys)); err != nil {
		t.Fatalf("pre-seed C: %v", err)
	}
	h.holdsBounded(t, B, yKeys)
	h.holdsBounded(t, C, xKeys)
	for i := range h.nodes {
		h.nodes[i].g.SetStratifiedAntiEntropy(true)
	}
	h.nodes[A].g.redHoistAllBugInject.Store(true)
	t.Logf("shared-hoist fault armed for stratified per-peer deltas")
	caps := armContentProbe(t, h.nodes[A].g)
	st := h.nodes[A].g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes == 0 {
		t.Fatalf("sweep shipped no envelopes, so the hoist fault produced no captures")
	}
	byPeer := map[[16]byte][]BuiltEvent{}
	for i := range *caps {
		c := (*caps)[i]
		byPeer[c.peer] = c.buf
		t.Logf("hoistall capture peer=%x n=%d", c.peer, len(c.buf))
	}
	// The s.built latch in batch_hoist.go leaves only the first flushing peer's
	// shared build. At least one peer therefore lacks a correct capture. The
	// capture site stores snapshot copies, so this check does not read arena
	// memory that the second peer's flush may already have released.
	capB, okB := byPeer[h.nodes[B].ident.NodeID]
	capC, okC := byPeer[h.nodes[C].ident.NodeID]
	corruption := !okB || !okC || !sameKeySet(entityIDSet(capB), xKeys) || !sameKeySet(entityIDSet(capC), yKeys)
	if !corruption {
		t.Fatalf("shared-hoist fault produced correct captures (B present=%v set-equal=%v, C present=%v set-equal=%v); the stratified domain fault did not take effect", okB, sameKeySet(entityIDSet(capB), xKeys), okC, sameKeySet(entityIDSet(capC), yKeys))
	}
	t.Logf("shared-hoist fault left incorrect per-peer captures (B present=%v, C present=%v)", okB, okC)
}

// TestNegativeControlEagerMaps restores eager initialization of all five relay
// maps before constructing the Gossiper. After a batch-only exchange, the batch
// maps must be live and the otherwise-unused per-frame map must also be non-nil.
// The package-level fault is cleared during cleanup.
func TestNegativeControlEagerMaps(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_BOUNDED_GOSSIP") != "eagermaps" {
		t.Skip("runs only with SOVEREIGN_TEST_FAULT_BOUNDED_GOSSIP=eagermaps")
	}
	redEagerMapsBugInject.Store(true)
	t.Cleanup(func() { redEagerMapsBugInject.Store(false) })
	t.Logf("eager relay-map fault armed before Gossiper construction")
	h := newRelaySharedHarness(t, 2, 64)
	defer h.close()
	const A, B = 0, 1
	h.connect(t, A, B)
	h.nodes[A].g.SetBatchSize(100)
	h.nodes[B].g.SetBatchSize(100)
	h.waitForEgress(t, A, B)
	var batchKeys []string
	for i := 0; i < 50; i++ {
		k := fmt.Sprintf("eager-map-fault-key-%d", i)
		h.nodes[A].g.InsertLocalEvents(k, fmt.Sprintf("bv-%03d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_700_000 + i), H3Index: uint64(8000 + i)})
		batchKeys = append(batchKeys, k)
	}
	st := h.nodes[A].g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes == 0 {
		t.Fatalf("batch sweep shipped no envelopes, so retention could not initialize the batch maps")
	}
	h.holdsBounded(t, B, batchKeys)
	settleRetainLayers(t, h.nodes[B].g.relay, true, false)
	m, fwd, rev, refs, trueCount := relayMapLiveness(h.nodes[B].g.relay)
	t.Logf("eager-map fault on B: m=%v batchForward=%v batchReverse=%v batchRefs=%v batchTrueCount=%v", m, fwd, rev, refs, trueCount)
	if !fwd || !rev || !refs || !trueCount {
		t.Fatalf("batch retention did not initialize all batch maps (fwd=%v rev=%v refs=%v trueCount=%v)", fwd, rev, refs, trueCount)
	}
	if !m {
		t.Fatalf("eager-map fault left the per-frame map nil; eager initialization did not take effect")
	}
	t.Logf("eager-map fault initialized the unused per-frame map alongside the batch maps")
}
