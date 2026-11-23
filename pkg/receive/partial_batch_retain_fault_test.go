// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

// This negative control enables the retain-on-partial fault described in
// ADR-0070 and verifies that the defect becomes observable. The normal test
// suite leaves the fault disabled; this test runs only when its environment
// variable explicitly requests the control.

import (
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/attribution"
)

// TestPartialBatchFault_RetainOnHoldControl enables disableRetainOnHoldFault
// and submits a batch that joins two elements and holds one for excessive
// Lamport skew. The faulty behavior retains the full origin-signed frame even
// though its held tail is absent from state. A relayer cannot re-sign just the
// joined subset, and replaying the full frame cannot heal that tail. The test
// fails if enabling the fault does not restore this retention call.
func TestPartialBatchFault_RetainOnHoldControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_PARTIAL_RETAIN") != "retain" {
		t.Skip("the negative control runs only under SOVEREIGN_TEST_FAULT_PARTIAL_RETAIN=retain (the test suite never sets it)")
	}
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const n = 3
	const spikeAt = 1
	originPub, originPriv := genKey(t)
	r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	r.disableRetainOnHoldFault.Store(true)
	defer r.disableRetainOnHoldFault.Store(false)
	retained := 0
	var dotsSeen []uint64
	r.onAcceptRelayBatch = func(origin [16]byte, seq uint64, dots []uint64, frame []byte) {
		retained++
		dotsSeen = append(dotsSeen, dots...)
	}
	specs := make([]admissionBatchSpec, n)
	for j := 0; j < n; j++ {
		payload := "retain-fault-" + admissionTestEntityID("retainfault", j)
		dot := uint64(j + 2)
		if j == spikeAt {
			dot = skewBrickDot
		}
		specs[j] = admissionBatchSpec{entityID: admissionTestEntityID("retainfault", j), payload: payload, payloadDigest: admissionTestDigest(payload), dotCounter: dot}
	}
	wire := buildAdmissionBatchWire(t, specs)
	sig := ed25519.Sign(originPriv, wire)
	frame := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArray(sig), 1, uint16(n), wire)
	if v := r.HandleBatchFrame(frame); v.Verdict != Accept {
		t.Fatalf("control premise: partial batch got %v (%v), want Accept with 2 of 3 joined", v.Verdict, v.Reason)
	}
	if got := r.batchSkewHeldTail.Load(); got != 1 {
		t.Fatalf("control premise: batchSkewHeldTail = %d, want 1", got)
	}
	if joined := len(engine.PointGet(admissionTestEntityID("retainfault", 0))) + len(engine.PointGet(admissionTestEntityID("retainfault", 2))); joined != 2 {
		t.Fatalf("control premise: found %d in-window elements in state, want 2", joined)
	}
	if retained != 1 {
		t.Fatalf("retain control: enabled fault caused %d retention calls, want 1", retained)
	}
	if len(dotsSeen) != 2 {
		t.Fatalf("retain control: retention carried %d dots, want 2 joined dots", len(dotsSeen))
	}
	t.Logf("retain control: enabled fault retained the partial batch (calls=%d, joined dots=%v, held dot=%d)", retained, dotsSeen, skewBrickDot)
}
