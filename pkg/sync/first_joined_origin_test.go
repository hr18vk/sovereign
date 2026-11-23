// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// These tests cover a batch whose first element exceeds the Lamport skew bound
// while later elements join. The held element must not enter state or advance
// the clock. The delta passed to Join takes its origin from the first joined
// element, not from the held element at index zero.

import "testing"

func TestBatchApply_SpikeAtIndexZeroJoinsSubset(t *testing.T) {
	engine := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	snap := engine.LamportSnapshot()
	bound := MaxAcceptableDotCounter(snap)
	poison := bound + 1       // over-bound counter at index zero
	consistent := uint64(160) // within the bound
	specs := []skewBatchSpec{
		{entityID: skewBatchEntityID(0), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: poison},
		{entityID: skewBatchEntityID(1), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: consistent},
		{entityID: skewBatchEntityID(2), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: consistent},
	}
	wire := buildSkewBatchFrame(t, specs)
	res, err := engine.ApplyCRDTDeltaBatch(wire)
	if err != nil {
		t.Fatalf("ApplyCRDTDeltaBatch rejected a batch with one held element: %v", err)
	}
	if res.Joined != 2 || res.Held != 1 {
		t.Fatalf("joined=%d held=%d, want 2 and 1; joined dot=%d held dot=%d bound=%d", res.Joined, res.Held, consistent, poison, bound)
	}
	if got := engine.State().Get(skewBatchEntityID(0)); len(got) != 0 {
		t.Fatalf("held first element entered state with %d entries, want 0", len(got))
	}
	for _, i := range []int{1, 2} {
		if got := engine.State().Get(skewBatchEntityID(i)); len(got) != 1 {
			t.Fatalf("joined element %d has %d entries, want 1", i, len(got))
		}
	}
	if got := engine.LamportCounter(); got != consistent {
		t.Fatalf("LamportCounter = %d, want largest joined dot %d", got, consistent)
	}
}

// TestBatchApply_OriginTakenFromFirstJoinedElement gives the held first
// element origin A and the two joined elements origin B. DeltaOriginNodeID
// must be B, proving that origin selection follows reconstruction rather than
// the element's position in the batch.
func TestBatchApply_OriginTakenFromFirstJoinedElement(t *testing.T) {
	engine := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	snap := engine.LamportSnapshot()
	bound := MaxAcceptableDotCounter(snap)
	poison := bound + 1
	consistent := uint64(160)
	specs := []skewBatchSpec{
		{entityID: skewBatchEntityID(0), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: poison},
		{entityID: skewBatchEntityID(1), originNodeID: rtHostB, dotNodeID: rtHostB, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: consistent},
		{entityID: skewBatchEntityID(2), originNodeID: rtHostB, dotNodeID: rtHostB, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: consistent},
	}
	wire := buildSkewBatchFrame(t, specs)
	res, err := engine.ApplyCRDTDeltaBatch(wire)
	if err != nil {
		t.Fatalf("ApplyCRDTDeltaBatch rejected the distinct-origin batch: %v", err)
	}
	if res.Joined != 2 || res.Held != 1 {
		t.Fatalf("joined=%d held=%d, want 2 and 1", res.Joined, res.Held)
	}
	if res.DeltaOriginNodeID != rtHostB {
		t.Errorf("delta origin = %x, want first joined origin %x; held element origin was %x", res.DeltaOriginNodeID, rtHostB, rtHostA)
	}
}
