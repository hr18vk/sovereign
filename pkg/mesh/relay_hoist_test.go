// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests check that relayCache allocates maps only for the kind of frame
// it retains. WireRelayHooks installs both batch and per-frame retainers, so
// allocation must follow received traffic rather than a node's send mode.
//
// A batch sweep from A to B initializes B's four batch maps while its per-frame
// map remains nil. In the mirror case, C sends individual frames to D with
// batch size 1: D initializes its per-frame map and leaves all batch maps nil.
// Exercising both directions prevents one layer from being initialized eagerly
// while the other is lazy. SOVEREIGN_TEST_FAULT_RELAY_CACHE_EAGER restores eager
// allocation as a negative control.

import (
	"context"
	"fmt"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// settleRetainLayers waits for retention to finish before inspecting the maps.
// holdsBounded can observe joined engine state before InspectBatchDots retains
// the batch, because those steps have no happens-before relationship. Polling
// under the relay-cache lock distinguishes an unfinished retain from a missing
// map allocation.
//
// relayMapLiveness reports all five map states while holding the cache lock.
func settleRetainLayers(t *testing.T, c *relayCache, wantBatch, wantFrame bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		m, fwd, rev, refs, trueCount := relayMapLiveness(c)
		if (!wantBatch || (fwd && rev && refs && trueCount)) && (!wantFrame || m) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay layer not initialized within 10s: batch=%v/%v/%v/%v frame=%v", fwd, rev, refs, trueCount, m)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
func relayMapLiveness(c *relayCache) (m, fwd, rev, refs, trueCount bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m != nil, c.batchForward != nil, c.batchReverse != nil, c.batchRefs != nil, c.batchTrueCount != nil
}

// TestRelayEagerMapRetained checks that received frames initialize only the
// relay-cache maps needed by their batch or per-frame representation.
func TestRelayEagerMapRetained(t *testing.T) {
	h := newRelaySharedHarness(t, 4, 64)
	defer h.close()
	const A, B, C, D = 0, 1, 2, 3

	h.connect(t, A, B)
	h.nodes[A].g.SetBatchSize(100)
	h.nodes[B].g.SetBatchSize(100)
	h.waitForEgress(t, A, B)
	var batchKeys []string
	for i := 0; i < 50; i++ {
		k := fmt.Sprintf("lazy-batch-key-%d", i)
		h.nodes[A].g.InsertLocalEvents(k, fmt.Sprintf("bv-%03d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_400_000 + i), H3Index: uint64(5000 + i)})
		batchKeys = append(batchKeys, k)
	}
	st := h.nodes[A].g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes == 0 {
		t.Fatalf("batch sweep shipped no envelopes, so B could not retain a batch")
	}
	h.holdsBounded(t, B, batchKeys)
	settleRetainLayers(t, h.nodes[B].g.relay, true, false)
	m, fwd, rev, refs, trueCount := relayMapLiveness(h.nodes[B].g.relay)
	t.Logf("batch receiver: frame=%v forward=%v reverse=%v refs=%v trueCount=%v", m, fwd, rev, refs, trueCount)
	if !fwd || !rev || !refs || !trueCount {
		t.Fatalf("batch retention did not initialize every batch map: forward=%v reverse=%v refs=%v trueCount=%v", fwd, rev, refs, trueCount)
	}
	if m {
		t.Errorf("batch-only retention initialized the unused per-frame map")
	}

	// The mirror pair retains only per-frame frames. All four batch maps must
	// remain nil, just as the per-frame map did in the batch-only pair.
	h.connect(t, C, D)
	h.nodes[C].g.SetBatchSize(1) // batch size 1 with hybridSign false uses shipDelta
	h.nodes[D].g.SetBatchSize(1)
	h.waitForEgress(t, C, D)
	var frameKeys []string
	for i := 0; i < 50; i++ {
		k := fmt.Sprintf("lazy-frame-key-%d", i)
		h.nodes[C].g.InsertLocalEvents(k, fmt.Sprintf("fv-%03d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_500_000 + i), H3Index: uint64(6000 + i)})
		frameKeys = append(frameKeys, k)
	}
	st2 := h.nodes[C].g.AntiEntropySweep(context.Background())
	if st2.shippedEnvelopes == 0 {
		t.Fatalf("per-frame sweep shipped no envelopes, so D could not retain a frame")
	}
	h.holdsBounded(t, D, frameKeys)
	settleRetainLayers(t, h.nodes[D].g.relay, false, true)
	dm, dfwd, drev, drefs, dtrue := relayMapLiveness(h.nodes[D].g.relay)
	t.Logf("frame receiver: frame=%v forward=%v reverse=%v refs=%v trueCount=%v", dm, dfwd, drev, drefs, dtrue)
	if !dm {
		t.Fatalf("per-frame retention did not initialize the frame map: live=%v", dm)
	}
	if dfwd || drev || drefs || dtrue {
		t.Errorf("frame-only retention initialized batch maps: forward=%v reverse=%v refs=%v trueCount=%v", dfwd, drev, drefs, dtrue)
	}
	if !t.Failed() {
		t.Logf("batch-only and frame-only retention initialized only their respective relay maps")
	}
}
