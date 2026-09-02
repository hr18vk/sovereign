// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package receive

// skew_reject_retain_test.go — POST-REVIEW guard for a code-review finding:
// a batch that clears signature verification but
// FAILS Apply (the per-element skew bound) must NOT be retained. The pre-fix
// order fired onAcceptRelayBatch BEFORE ApplyCRDTDeltaBatch, so a skew-rejected
// batch was pinned in the relayCache — retained forever, never Joined, never
// re-pointed (the refcount only frees frames whose dots get re-pointed).

import (
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

func TestSkewRejectedBatchNotRetained(t *testing.T) {
	originPub, originPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	originSeed := originPriv.Seed()

	engine, err := eng.NewDeltaCRDTEngine(rcvOriginNodeID, 0, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()
	engine.SetDataDir(t.TempDir())
	dir := identity.NewDirectory()
	if err := dir.Register(rcvOriginNodeID, originPub); err != nil {
		t.Fatalf("Directory.Register: %v", err)
	}
	bucket := admission.NewPeerBucket()
	sc := clock.NewSyntheticClock(1_700_000_000_000_000)
	capGate := clock.NewIngressHLCScalarCap(sc, engine)
	recv := NewReceiver(bucket, capGate, sc, dir, engine, 50_000_000)

	// Arm the relay retainer with a recording hook.
	retained := 0
	recv.SetRelayRetainerBatch(func(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte) {
		retained++
	})

	// A batch whose DotCounters sit FAR beyond the skew bound (AbsoluteSlack
	// = 1000; the engine's clock is fresh): signature-valid, Apply-rejected.
	const n = 4
	batchWire := buildAllocBenchBatchWire(t, n, 1<<40)
	sig, err := identity.SignCRDTFrame(originSeed, batchWire)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], sig)
	frame := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArr, 1, uint16(n), batchWire)

	v := recv.HandleBatchFrame(frame)
	if v.Verdict != DropVerify {
		t.Fatalf("guard premise broken: the skew-violating batch got verdict=%s (want DropVerify) — it never reached the Apply skew gate (reason: %v)", v.Verdict, v.Reason)
	}
	if retained != 0 {
		t.Fatalf("a skew-REJECTED batch was retained (%d retain calls) — pinned in the relayCache forever, never Joined, never re-pointed. The retain must fire only AFTER Apply succeeds.", retained)
	}

	// Control: the SAME-shaped batch inside the skew bound IS retained after a
	// successful Apply (the hook is wired and live, not just never-called).
	recv2 := NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(sc, engine), sc, dir, engine, 50_000_000)
	retained2 := 0
	recv2.SetRelayRetainerBatch(func(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte) {
		retained2++
	})
	batchWire2 := buildAllocBenchBatchWire(t, n, 1)
	sig2, err := identity.SignCRDTFrame(originSeed, batchWire2)
	if err != nil {
		t.Fatalf("SignCRDTFrame 2: %v", err)
	}
	var sigArr2 [attribution.OriginSigSize]byte
	copy(sigArr2[:], sig2)
	frame2 := attribution.MarshalBatchEnvelope(rcvOriginNodeID, sigArr2, 1, uint16(n), batchWire2)
	v2 := recv2.HandleBatchFrame(frame2)
	if v2.Verdict != Accept {
		t.Fatalf("control batch (in-bound) got verdict=%s, want Accept (reason: %v)", v2.Verdict, v2.Reason)
	}
	if retained2 != 1 {
		t.Fatalf("control: an Accepted batch must be retained exactly once, got %d", retained2)
	}
}
