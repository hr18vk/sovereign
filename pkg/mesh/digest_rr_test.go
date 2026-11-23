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
	"time"

	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// digestRRWaitFor polls cond until it holds or the deadline passes. The
// responder runs as a short-lived goroutine, so the observable lags the
// trigger by a goroutine schedule plus a loopback hop. A missed deadline
// fails the test — a non-firing observable is a broken instrument, not a skip.
func digestRRWaitFor(t *testing.T, what string, deadline time.Duration, cond func() bool) {
	t.Helper()
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out (%v) waiting for %s", deadline, what)
}

// TestDigestFrameWireRoundTrip checks the stratified digest frame layout
// (ADR-0054). The role byte and sender seed must round-trip exactly, and the
// SE and IBLT bodies must split at their encoded boundaries. A wrong seed
// makes the responder build an incompatible digest, while an indistinguishable
// role byte would let responses trigger further responses.
func TestDigestFrameWireRoundTrip(t *testing.T) {
	sender := [16]byte{0xAB, 0xCD, 0x01}
	seed := maphash.MakeSeed()
	seBody := []byte("fake-se-body")
	ibltBody := []byte("fake-iblt-body")
	for _, role := range []byte{digestRoleRequest, digestRoleResponse} {
		frame := buildDigestFrame(role, sender, seed, seBody, ibltBody)
		if got := digestFrameRole(frame); got != role {
			t.Fatalf("role round-trip: got %d want %d", got, role)
		}
		if got := digestFrameSender(frame); got != sender {
			t.Fatalf("sender round-trip: got %x want %x", got, sender)
		}
		if got := digestFrameSeed(frame); got != seed {
			t.Fatalf("seed round-trip: header seed does not round-trip (a responder would build under the wrong seed, causing silent peel failure and oversend)")
		}
		gotSE, gotIBLT := digestFrameSplit(frame)
		if string(gotSE) != string(seBody) || string(gotIBLT) != string(ibltBody) {
			t.Fatalf("body split: se=%q iblt=%q (want %q/%q)", gotSE, gotIBLT, seBody, ibltBody)
		}
	}
	// The two roles must be distinguishable, otherwise the no-ping-pong gate is blind.
	if digestRoleRequest == digestRoleResponse {
		t.Fatalf("digestRoleRequest == digestRoleResponse — the no-ping-pong gate cannot distinguish them")
	}
}

// TestRequestResponseLoneSweepCompletes verifies the digest request-response
// path (ADR-0054). A sweeps B, and B answers without running its own sweep.
// A's exchange must complete within the timeout without oversend fallback.
// The digestRespondSent counter confirms that B sent a response rather than
// the exchange being skipped.
func TestRequestResponseLoneSweepCompletes(t *testing.T) {
	h := newStratifiedHarness(t, true) // stratified anti-entropy on both nodes
	defer h.close()
	h.insertEvents(t, 100)

	// Run only A's sweep. B never sweeps A, but B's read loop answers A's request.
	h.gA.AntiEntropySweep(h.ctx)

	// The exchange completed — no oversend fallback on A. A's sweep returns
	// only after the digest exchange resolves or times out; B never sweeps, so
	// the only way A got B's digest is B's response.
	if got := atomic.LoadInt32(&h.fallbackA); got != 0 {
		t.Fatalf("A's lone sweep fell back %d times even though B's responder is enabled; the request-response exchange did not finish before the timeout", got)
	}
	// B actually sent a response (the exchange really happened).
	// digestRespondSent is incremented on B's responder goroutine right after
	// Publish, which is not happens-before A's sweep unblocking — so poll it,
	// don't assume.
	digestRRWaitFor(t, "B's digest response (wire exchange observed)", 2*time.Second, func() bool {
		return h.gB.digestRespondSent.Load() > 0
	})
	t.Logf("A's lone sweep completed the request-response exchange without fallback; B responses=%d", h.gB.digestRespondSent.Load())
}

// TestNoPingPong verifies that a response frame does not trigger another
// response. The request control must still elicit a response, so silence from
// the response arm cannot be caused by a dead connection or responder.
func TestNoPingPong(t *testing.T) {
	h := newStratifiedHarness(t, true) // stratified anti-entropy enabled
	defer h.close()
	h.insertEvents(t, 100)

	// Build a response frame from A (senderID=A) and deliver it to B. A
	// response must not trigger a response.
	seed := maphash.MakeSeed()
	se := h.engineB.GenerateStrataEstimator(seed)
	ib := h.engineB.GenerateDigestWithSeed(seed)
	mSE, err := eng.MarshalStrataEstimator(se)
	if err != nil {
		t.Fatalf("MarshalStrataEstimator: %v", err)
	}
	mIB, err := eng.MarshalIBLT(ib)
	ib.Release()
	if err != nil {
		t.Fatalf("MarshalIBLT: %v", err)
	}
	respFrame := buildDigestFrame(digestRoleResponse, h.identA.NodeID, seed, mSE, mIB)

	// Publish over A's verified connection so the digest identity checks in
	// ADR-0068 see matching sender and connection IDs. The request control
	// below also proves arrival: if the connection failed, its response wait
	// would fail rather than letting the response silence pass unobserved.
	before := h.gB.digestRespondSent.Load()
	if err := h.psA.Publish(h.identB.NodeID, receive.LengthPrefixFrame(respFrame)); err != nil {
		t.Fatalf("response wire drive: %v", err)
	}
	// Give any (buggy) responder a chance to fire, then assert silence.
	time.Sleep(150 * time.Millisecond)
	if got := h.gB.digestRespondSent.Load(); got != before {
		t.Fatalf("a response frame triggered a response (digestRespondSent %d -> %d) — the role byte is not gating the respond path", before, got)
	}

	// A request control must trigger a response; the role check must suppress
	// only responses, not every digest frame.
	reqFrame := buildDigestFrame(digestRoleRequest, h.identA.NodeID, seed, mSE, mIB)
	if err := h.psA.Publish(h.identB.NodeID, receive.LengthPrefixFrame(reqFrame)); err != nil {
		t.Fatalf("request wire drive: %v", err)
	}
	digestRRWaitFor(t, "B's response to a REQUEST", 2*time.Second, func() bool {
		return h.gB.digestRespondSent.Load() > before
	})
	t.Logf("no-ping-pong pass: response left digestRespondSent=%d; request drove it to %d", before, h.gB.digestRespondSent.Load())
}
