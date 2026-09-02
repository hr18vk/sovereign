// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package receive

// hybrid_batch_retain_test.go — POST-REVIEW guard for
// /code-review finding #5: a HYBRID-signed foreign batch that is Accepted must
// be retained for the relay, exactly like the classical batch path. Pre-fix,
// HandleHybridFrame never fired onAcceptRelayBatch, so hybrid foreign deltas
// propagated one hop and stopped (silent one-hop gap on the opt-in PQ path).

import (
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

func TestHybridBatchRetained(t *testing.T) {
	originPub, originPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	originSeed := originPriv.Seed()
	pqPriv, err := identity.GeneratePreviewKey65(originSeed) // the mesh's seeded ML-DSA-65 keygen (deterministic)
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pqPub := pqPriv.PublicKey()

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
	if err := dir.RegisterPQ(rcvOriginNodeID, pqPub); err != nil {
		t.Fatalf("Directory.RegisterPQ: %v", err)
	}
	bucket := admission.NewPeerBucket()
	sc := clock.NewSyntheticClock(1_700_000_000_000_000)
	capGate := clock.NewIngressHLCScalarCap(sc, engine)
	recv := NewReceiver(bucket, capGate, sc, dir, engine, 50_000_000)
	recv.SetHybridVerify(true)

	retained := 0
	var retainedFrame []byte
	recv.SetRelayRetainerBatch(func(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte) {
		retained++
		retainedFrame = frameBytes
	})

	const n = 4
	batchWire := buildAllocBenchBatchWire(t, n, 1)
	edSig, pqSig, err := identity.SignCRDTFrame_Hybrid(originSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	frame := attribution.MarshalHybridFrame(rcvOriginNodeID, edSig, pqSig, 1, uint16(n), batchWire)

	v := recv.HandleHybridFrame(frame)
	if v.Verdict != Accept {
		t.Fatalf("hybrid batch verdict=%s, want Accept (reason: %v) — the guard's premise (a valid hybrid frame) failed", v.Verdict, v.Reason)
	}
	if retained != 1 {
		t.Fatalf("finding #5: an Accepted hybrid batch was retained %d times, want 1 — the hybrid path never fired the relay retainer (one-hop propagation on the opt-in PQ path)", retained)
	}
	// The retained bytes must be the FULL HYBRID frame (re-publishable onward:
	// the next hop's DispatchFrame routes by the magic byte to ITS
	// HandleHybridFrame, which re-verifies BOTH sigs).
	if !attribution.IsHybridFrame(retainedFrame) {
		t.Fatalf("retained frame is not a hybrid frame (%d bytes) — the onward hop could not route it to HandleHybridFrame", len(retainedFrame))
	}
	if len(retainedFrame) != len(frame) {
		t.Fatalf("retained %d bytes, want the full %d-byte hybrid frame", len(retainedFrame), len(frame))
	}
}
