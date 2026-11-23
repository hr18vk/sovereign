// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// This negative control enables the first-joined-origin fault and verifies
// that a batch with a held first element passes a blank origin to Join.

import (
	"os"
	"testing"
)

// TestFirstJoinedOriginFault_BlankOriginReturns enables the fault that restores
// the old index-zero origin gate. With element zero held for excessive skew,
// the subsequent joined elements must still leave DeltaOriginNodeID blank.
// This distinguishes the fault-injection path from the fixed origin selection.
func TestFirstJoinedOriginFault_BlankOriginReturns(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_FIRST_ORIGIN") != "origin" {
		t.Skip("run with SOVEREIGN_TEST_FAULT_FIRST_ORIGIN=origin to enable this negative control")
	}
	disableFirstJoinedOriginFault.Store(true)
	defer disableFirstJoinedOriginFault.Store(false)
	engine := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	bound := MaxAcceptableDotCounter(engine.LamportSnapshot())
	specs := []skewBatchSpec{
		{entityID: skewBatchEntityID(0), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: bound + 1},
		{entityID: skewBatchEntityID(1), originNodeID: rtHostB, dotNodeID: rtHostB, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: 160},
		{entityID: skewBatchEntityID(2), originNodeID: rtHostB, dotNodeID: rtHostB, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: 160},
	}
	res, err := engine.ApplyCRDTDeltaBatch(buildSkewBatchFrame(t, specs))
	if err != nil || res.Joined != 2 || res.Held != 1 {
		t.Fatalf("fault run: err=%v joined=%d held=%d, want nil, 2, and 1", err, res.Joined, res.Held)
	}
	var wantBlank [16]byte
	if res.DeltaOriginNodeID != wantBlank {
		t.Fatalf("fault injection left delta origin %x, want blank origin from the index-zero gate", res.DeltaOriginNodeID)
	}
	t.Logf("origin fault restored the blank-origin delta for a held first element")
}
