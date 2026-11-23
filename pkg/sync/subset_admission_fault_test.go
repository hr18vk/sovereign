// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// subset_admission_fault_test.go — the admission hardening negative control
// (ADR-0069). The control arms the disableSubsetAdmissionFault package-level
// kill switch and asserts that a whole batch is rejected when the admission
// gate is disabled. The test is env-gated (SOVEREIGN_TEST_FAULT_SUBSET_ADMISSION=subset)
// and skipped in the release test suite. The kill switch lives at package
// scope because the Engine struct is pinned by MD5 hash and takes no field.

import (
	"os"
	"testing"
)

func TestSubsetAdmissionFault_RejectWholeBatchOnSkew(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_SUBSET_ADMISSION") != "subset" {
		t.Skip("SOVEREIGN_TEST_FAULT_SUBSET_ADMISSION=subset: env-gated negative control — the release test suite does not set it")
	}
	disableSubsetAdmissionFault.Store(true) // arm the subset admission no-op
	defer disableSubsetAdmissionFault.Store(false)

	// The Case-3 shape (crdt_lamport_skew_test.go): elements 0 and 2
	// in-window (dot 160 <= the fresh bound 1100), element 1 over-bound.
	engineB3 := setupRTEngine(t, rtHostB, 100)
	boundB3 := MaxAcceptableDotCounter(engineB3.LamportSnapshot())
	case3Specs := []skewBatchSpec{
		{entityID: skewBatchEntityID(0), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: 160},
		{entityID: skewBatchEntityID(1), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: boundB3 + 1},
		{entityID: skewBatchEntityID(2), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: 160},
	}
	resC3, errC3 := engineB3.ApplyCRDTDeltaBatch(buildSkewBatchFrame(t, case3Specs))

	if errC3 == nil {
		t.Errorf("subset admission negative control: nil error {Joined:%d Held:%d} under the armed inject — the admission fired despite the kill switch", resC3.Joined, resC3.Held)
	}
	if resC3.Joined != 0 || resC3.Held != 0 {
		t.Errorf("subset admission negative control: armed inject must return {0,0}+error, got {Joined:%d Held:%d} err=%v", resC3.Joined, resC3.Held, errC3)
	}
	joined := 0
	for _, i := range []int{0, 2} {
		joined += len(engineB3.State().Get(skewBatchEntityID(i)))
	}
	if joined != 0 {
		t.Errorf("subset admission negative control: error returned but %d in-window entries still joined — the reject is cosmetic", joined)
	}
	if post := engineB3.LamportCounter(); post != 100 {
		t.Errorf("subset admission negative control: e.LamportCounter = %d after the armed whole-batch reject, want the unmoved 100 — the reject advances nothing", post)
	}
}
