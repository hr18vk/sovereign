// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

// These tests cover admission watermark commits and relay retention for
// partially applied batches. Failed authentication refunds a pending charge
// without advancing the high-water mark. A batch with skew-held elements is
// not retained; after the window advances, retransmitting the complete batch
// joins and retains it.

import (
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestPendingWatermark_CommitAndRollback checks that authentication failures
// refund charges without committing a high-water mark. It exercises a relay
// signature failure, a batch origin-signature failure, and a hybrid directory
// miss. Re-accepting each rejected sequence must charge its full delta again.
// A successfully applied frame still commits its dot, so its duplicate is free.
func TestPendingWatermark_CommitAndRollback(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const initialBudget = uint64(1) << 20

	// A relay signature failure occurs before the charged identity is authenticated.
	innerA := buildCRDTDeltaWire(t, rcvEntityID, 100)
	originPub, originPriv := genKey(t) // fresh origin keys for the inner sig
	r, bucket, _, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	victimPub, _ := genKey(t)
	_, attackerPriv := genKey(t)
	envImp := buildOneHopAdmissionEnvelope(t, innerA, wallBase, originPub, originPriv, victimPub, attackerPriv)
	v := r.HandleFrame(envImp.Marshal())
	if v.Verdict != DropVerify {
		t.Fatalf("impostor frame verdict = %v (%v), want DropVerify after relay signature verification", v.Verdict, v.Reason)
	}
	if got := bucket.Budget(victimPub[:]); got != initialBudget {
		t.Fatalf("budget after relay signature failure = %d, want %d after the refund", got, initialBudget)
	}
	d, ch := bucket.Accept(victimPub[:], 100)
	if d != admission.Keep || ch != 100 {
		t.Errorf("re-accept after relay signature failure returned decision=%v charged=%d, want Keep/100; a rejected frame must not advance the watermark", d, ch)
	}

	// A nonzero invalid batch origin signature reaches verification after charging.
	var victimOrigin [16]byte
	for i := range victimOrigin {
		victimOrigin[i] = byte(0x40 + i)
	}
	vOPub, _ := genKey(t)
	rb, bucketB, dirB, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, nil)
	if err := dirB.Register(victimOrigin, vOPub); err != nil {
		t.Fatalf("register victim origin: %v", err)
	}
	var rateKey [32]byte
	copy(rateKey[:16], victimOrigin[:]) // batch admission zero-extends the origin node ID
	wireB := buildAdmissionBatchWire(t, []admissionBatchSpec{
		{entityID: admissionTestEntityID("hwmbatch", 0), payload: "hwm-batch-0", payloadDigest: admissionTestDigest("hwm-batch-0"), dotCounter: 2},
		{entityID: admissionTestEntityID("hwmbatch", 1), payload: "hwm-batch-1", payloadDigest: admissionTestDigest("hwm-batch-1"), dotCounter: 3},
	})
	var gs [attribution.OriginSigSize]byte
	for i := range gs {
		gs[i] = 0xAA // nonzero invalid signature; a zero signature is rejected before charging
	}
	vb := rb.HandleBatchFrame(attribution.MarshalBatchEnvelope(victimOrigin, gs, 100, 2, wireB))
	if vb.Verdict != DropVerify {
		t.Fatalf("invalid-signature batch verdict = %v (%v), want DropVerify at origin verification", vb.Verdict, vb.Reason)
	}
	if got := bucketB.Budget(rateKey[:]); got != initialBudget {
		t.Fatalf("budget after batch signature failure = %d, want %d after the refund", got, initialBudget)
	}
	dB, chB := bucketB.Accept(rateKey[:], 100)
	if dB != admission.Keep || chB != 100 {
		t.Errorf("re-accept after batch signature failure returned decision=%v charged=%d, want Keep/100; a rejected batch must not advance the watermark", dB, chB)
	}

	// An unregistered hybrid origin fails directory lookup after charging.
	var hybOrigin [16]byte
	for i := range hybOrigin {
		hybOrigin[i] = byte(0x60 + i)
	}
	var hybKey [32]byte
	copy(hybKey[:16], hybOrigin[:])
	rh, bucketH, _, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, nil)
	rh.SetHybridVerify(true)
	var edG [attribution.OriginSigSize]byte
	var pqG [attribution.PQSignatureSize]byte
	for i := range edG {
		edG[i] = 0xAA
	}
	for i := range pqG {
		pqG[i] = 0xBB
	}
	vc := rh.HandleHybridFrame(attribution.MarshalHybridFrame(hybOrigin, edG, pqG, 100, 2, wireB))
	if vc.Verdict != DropVerify {
		t.Fatalf("hybrid frame with unregistered origin got %v (%v), want DropVerify at directory lookup", vc.Verdict, vc.Reason)
	}
	if got := bucketH.Budget(hybKey[:]); got != initialBudget {
		t.Fatalf("budget after hybrid directory miss = %d, want %d after the refund", got, initialBudget)
	}
	dC, chC := bucketH.Accept(hybKey[:], 100)
	if dC != admission.Keep || chC != 100 {
		t.Errorf("re-accept after hybrid directory miss returned decision=%v charged=%d, want Keep/100; a rejected frame must not advance the watermark", dC, chC)
	}

	// A valid one-hop frame at counter 200 applies successfully. Re-accepting
	// the same counter must be free because the post-verification watermark
	// commits 200; rollback applies only to frames that fail authentication.
	innerX := buildCRDTDeltaWire(t, admissionTestEntityID("hwmctl", 0), 200)
	xPub, xPriv := genKey(t)
	rx, bucketX, _, _ := setupAdmissionTestReceiver(t, wallBase, budgetNS, xPub)
	honestPub, honestPriv := genKey(t)
	envX := buildOneHopAdmissionEnvelope(t, innerX, wallBase, xPub, xPriv, honestPub, honestPriv)
	if vx := rx.HandleFrame(envX.Marshal()); vx.Verdict != Accept {
		t.Fatalf("valid one-hop frame got %v (%v), want Accept", vx.Verdict, vx.Reason)
	}
	dX, chX := bucketX.Accept(honestPub[:], 200)
	if dX != admission.Keep || chX != 0 {
		t.Errorf("re-accept at a committed counter returned decision=%v charged=%d, want Keep/0; a verified and applied frame must commit its watermark", dX, chX)
	}
}

// TestPartialBatch_SkipRetentionForSkewedFrames verifies that a batch with a
// skew-held element is not retained. One Ed25519 signature covers the full
// batch wire, so a relayer cannot re-sign only the joined elements. Replaying
// the full frame cannot merge an element while the skew bound holds it;
// retention would only pin memory after the OriginSeq charge. The sender must
// re-ship after the Lamport window advances, at which point the complete batch
// joins and is retained.
func TestPartialBatch_SkipRetentionForSkewedFrames(t *testing.T) {
	const wallBase = int64(1_700_000_000_000_000)
	const budgetNS = int64(1_000_000_000)
	const n = 3
	const spikeAt = 1

	// A large skew spike holds one element while the other two join.
	originPub, originPriv := genKey(t)
	r, _, _, engine := setupAdmissionTestReceiver(t, wallBase, budgetNS, originPub)
	retained := 0
	var retainedDotsSeen []uint64
	r.onAcceptRelayBatch = func(origin [16]byte, seq uint64, dots []uint64, frame []byte) {
		retained++
		retainedDotsSeen = append(retainedDotsSeen, dots...)
	}
	specs := make([]admissionBatchSpec, n)
	for j := 0; j < n; j++ {
		payload := "partial-" + admissionTestEntityID("partial", j)
		dot := uint64(j + 2)
		if j == spikeAt {
			dot = skewBrickDot
		}
		specs[j] = admissionBatchSpec{entityID: admissionTestEntityID("partial", j), payload: payload, payloadDigest: admissionTestDigest(payload), dotCounter: dot}
	}
	wire1 := buildAdmissionBatchWire(t, specs)
	sig1 := ed25519.Sign(originPriv, wire1)
	frame1 := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArray(sig1), 1, uint16(n), wire1)
	v1 := r.HandleBatchFrame(frame1)
	if v1.Verdict != Accept {
		t.Fatalf("partial batch got %v (%v), want Accept with 2 of 3 joined", v1.Verdict, v1.Reason)
	}
	if got := r.batchSkewHeldTail.Load(); got != 1 {
		t.Fatalf("batchSkewHeldTail = %d, want 1 for the skew spike", got)
	}
	if retained != 0 {
		t.Errorf("partial apply fired the relay retainer %d times (dots %v), want 0; retaining the full frame would pin a held element that never entered state", retained, retainedDotsSeen)
	}
	if joined := len(engine.PointGet(admissionTestEntityID("partial", 0))) + len(engine.PointGet(admissionTestEntityID("partial", 2))); joined != 2 {
		t.Errorf("joined in-window elements = %d, want 2", joined)
	}

	// Use bound+1000 so the window can pass the spike within the 64-frame
	// crawl; skewBrickDot would need about 63 doubling steps. In-window origin
	// frames advance the bound, then the sender's re-ship joins the full batch
	// and triggers retention. The retention rule does not depend on spike size.
	r2, _, dir2, engine2 := setupAdmissionTestReceiver(t, wallBase, budgetNS, nil)
	healPub, healPriv := genKey(t)
	if err := dir2.Register(rcvOriginNodeID, healPub); err != nil {
		t.Fatalf("register re-ship origin: %v", err)
	}
	calls := 0
	var lastDots []uint64
	r2.onAcceptRelayBatch = func(origin [16]byte, seq uint64, dots []uint64, frame []byte) {
		calls++
		lastDots = dots
	}
	spikeSmall := eng.MaxAcceptableDotCounter(engine2.LamportSnapshot()) + 1000
	specs2 := make([]admissionBatchSpec, n)
	for j := 0; j < n; j++ {
		payload := "partial-heal-" + admissionTestEntityID("partialheal", j)
		dot := uint64(j + 2)
		if j == spikeAt {
			dot = spikeSmall
		}
		specs2[j] = admissionBatchSpec{entityID: admissionTestEntityID("partialheal", j), payload: payload, payloadDigest: admissionTestDigest(payload), dotCounter: dot}
	}
	wire2 := buildAdmissionBatchWire(t, specs2)
	sig2 := ed25519.Sign(healPriv, wire2)
	frame2 := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArray(sig2), 1, uint16(n), wire2)
	if v2 := r2.HandleBatchFrame(frame2); v2.Verdict != Accept {
		t.Fatalf("small-spike partial batch got %v (%v), want Accept", v2.Verdict, v2.Reason)
	}
	if got := r2.batchSkewHeldTail.Load(); got != 1 {
		t.Fatalf("batchSkewHeldTail after small spike = %d, want 1", got)
	}
	crawled := 0
	for ; crawled < 64; crawled++ {
		if eng.MaxAcceptableDotCounter(engine2.LamportSnapshot()) > spikeSmall {
			break
		}
		dot := eng.MaxAcceptableDotCounter(engine2.LamportSnapshot())
		inner := buildCRDTDeltaWire(t, admissionTestEntityID("crawl", crawled), dot)
		sig := ed25519.Sign(healPriv, inner)
		counter, originID := decodeGateFields(t, inner)
		env := attribution.NewSignedRelayEnvelopeV3(inner, sigArray(sig), counter, originID, nil)
		if vc := r2.HandleFrame(env.Marshal()); vc.Verdict != Accept {
			t.Fatalf("in-window crawl frame at dot %d got %v (%v), want Accept", dot, vc.Verdict, vc.Reason)
		}
	}
	if eng.MaxAcceptableDotCounter(engine2.LamportSnapshot()) <= spikeSmall {
		t.Fatalf("64-frame crawl did not advance the bound past spike %d", spikeSmall)
	}
	if v3 := r2.HandleBatchFrame(frame2); v3.Verdict != Accept {
		t.Fatalf("re-ship got %v (%v), want Accept after the window covers the spike", v3.Verdict, v3.Reason)
	}
	if got := r2.batchSkewHeldTail.Load(); got != 1 {
		t.Errorf("re-ship held %d more elements, want the Held counter unchanged at 1", got-1)
	}
	joined := 0
	for j := 0; j < n; j++ {
		if len(engine2.PointGet(admissionTestEntityID("partialheal", j))) > 0 {
			joined++
		}
	}
	if joined != n {
		t.Errorf("elements in state after re-ship = %d of %d, want %d", joined, n, n)
	}
	if calls == 0 {
		t.Errorf("re-ship fired the retainer %d times, want at least 1 for a fully joined batch", calls)
	}
	if len(lastDots) != n {
		t.Errorf("last retainer call carried %d dots, want %d for the fully joined batch", len(lastDots), n)
	}
}
