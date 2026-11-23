// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package identity

import (
	"bytes"
	"testing"

	"filippo.io/mldsa"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// ──────────────────────────────────────────────────────────────────────────
// Hybrid PQ sign tests (ADR-0037): SignCRDTFrame_Hybrid and VerifyBatchHybrid
// round-trip a batch wire under both randomized-nonce Ed25519 and ML-DSA-65
// over a shared 120-byte SHAKE256 pad.
//
//	TestPQ_HybridSignThenVerify       — sign and verify round-trip.
//	TestPQ_HybridSignClassicalReject  — corrupt Ed25519 sig rejected.
//	TestPQ_HybridSignPQReject         — corrupt ML-DSA-65 sig rejected.
//	TestPQ_HybridPadDeterministic     — HashBatchWireToFrame120 deterministic.
//	TestPQ_HybridPadDistinct          — distinct inputs yield distinct pads.
//	TestPQ_HybridPadLen               — pad matches 120-byte ADR-0010 size.
// ──────────────────────────────────────────────────────────────────────────

// hybridSignTestSeed is a 32-byte Ed25519 seed for the hybrid sign tests
// (deterministic; the same seed SignCRDTFrame takes). Not a secret — the tests
// are reproducibility tests, not key-management.
var hybridSignTestSeed = bytes.Repeat([]byte{0x37}, ed25519.SeedSize) // 32 bytes of '7'

// hybridSignMintKeys derives an Ed25519 seed->pubkey and an ML-DSA-65 keypair for
// the hybrid sign tests (the same mint the hybrid_verify_test.go uses, with a
// distinct seed so the tests are independent). Returns edSeed, edPub, pqPriv, pqPub.
func hybridSignMintKeys(t *testing.T) (edSeed []byte, edPub ed25519.PublicKey, pqPriv *mldsa.PrivateKey, pqPub *mldsa.PublicKey) {
	t.Helper()
	edSeed = hybridSignTestSeed
	priv := ed25519.NewKeyFromSeed(edSeed)
	edPub = priv.Public().(ed25519.PublicKey)
	var err error
	pqPriv, err = GeneratePreviewKey65(edSeed)
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pqPub = pqPriv.Public().(*mldsa.PublicKey)
	return edSeed, edPub, pqPriv, pqPub
}

// makeBatchWire mints a deterministic CRDTDeltaBatch-shaped wire seeded by tag
// (a stand-in for the marshaled capnp frame BuildCRDTDeltaBatch produces; the
// hybrid sign/verify is independent of the capnp shape — it signs the verbatim
// []byte, so any byte slice is a faithful stand-in). It mixes high-entropy and
// monotone fields (the frame-factory discipline — not zeros, which would
// misrepresent the real batch wire the sig covers).
func makeBatchWire(t *testing.T, tag byte, n int) []byte {
	t.Helper()
	if n < 1 {
		n = 256
	}
	wire := make([]byte, n)
	// XOR (not OR) the tag into the high byte: OR would mask small tags into
	// the constant's 0x53 high byte (0x53|0x01 == 0x53|0x02 == 0x53, so tags 1
	// and 2 would collide). XOR is injective in the tag for a fixed mask, so
	// every distinct tag produces a distinct initial splitmix64 state (the
	// TestPQ_HybridPadDistinct depends on tags 1 and 2 producing distinct
	// batch wires, so XOR rather than OR is used to mix tag into state.
	state := uint64(tag)<<56 ^ 0x534F564552454747 // "SOVEREGG" high bits XOR tag
	for i := 0; i < n; i += 8 {
		state = state*6364136223846793005 + 1442695040888963407 // splitmix64 step
		end := i + 8
		if end > n {
			end = n
		}
		for j := i; j < end; j++ {
			wire[j] = byte(state >> (8 * (j - i)))
		}
	}
	return wire
}

// TestPQ_HybridSignThenVerify verifies that a batch wire signed under both
// Ed25519 and ML-DSA-65 via SignCRDTFrame_Hybrid verifies via VerifyBatchHybrid.
func TestPQ_HybridSignThenVerify(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 42, 256)
	edSig, pqSig, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	if !VerifyBatchHybrid(edPub, pqPub, batchWire, edSig[:], pqSig[:], "") {
		t.Fatalf("hybrid sign-then-verify: VerifyBatchHybrid=false on dual-signed batch, want true")
	}
	t.Logf("hybrid sign-then-verify: batch signed via SignCRDTFrame_Hybrid verified via VerifyBatchHybrid")
}

// TestPQ_HybridSignClassicalReject verifies that corrupting the Ed25519 signature
// rejects the batch under VerifyBatchHybrid.
func TestPQ_HybridSignClassicalReject(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 7, 256)
	edSig, pqSig, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	edSigCorrupt := edSig
	edSigCorrupt[0] ^= 0xFF
	if VerifyBatchHybrid(edPub, pqPub, batchWire, edSigCorrupt[:], pqSig[:], "") {
		t.Fatalf("hybrid sign classical reject: VerifyBatchHybrid=true with corrupt Ed25519 sig, want false")
	}
	t.Logf("hybrid sign classical reject: corrupt Ed25519 signature rejected")
}

// TestPQ_HybridSignPQReject verifies that corrupting the ML-DSA-65 signature
// rejects the batch under VerifyBatchHybrid.
func TestPQ_HybridSignPQReject(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 99, 256)
	edSig, pqSig, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	pqSigCorrupt := pqSig
	pqSigCorrupt[len(pqSigCorrupt)/2] ^= 0xFF
	if VerifyBatchHybrid(edPub, pqPub, batchWire, edSig[:], pqSigCorrupt[:], "") {
		t.Fatalf("hybrid sign pq reject: VerifyBatchHybrid=true with corrupt ML-DSA-65 sig, want false")
	}
	t.Logf("hybrid sign pq reject: corrupt ML-DSA-65 signature rejected")
}

// TestPQ_HybridPadDeterministic checks that HashBatchWireToFrame120 returns
// identical 120-byte digests across repeated calls on the same input.
func TestPQ_HybridPadDeterministic(t *testing.T) {
	batchWire := makeBatchWire(t, 13, 256)
	pad1 := HashBatchWireToFrame120(batchWire)
	pad2 := HashBatchWireToFrame120(batchWire)
	if pad1 != pad2 {
		t.Fatalf("hybrid pad deterministic: pad1=%x... != pad2=%x...", pad1[:8], pad2[:8])
	}
	t.Logf("hybrid pad deterministic: HashBatchWireToFrame120 produced identical 120-byte digest")
}

// TestPQ_HybridPadDistinct verifies that distinct batch wires yield distinct
// digests and that signatures over batch A do not verify batch B.
func TestPQ_HybridPadDistinct(t *testing.T) {
	batchA := makeBatchWire(t, 1, 256)
	batchB := makeBatchWire(t, 2, 256)
	padA := HashBatchWireToFrame120(batchA)
	padB := HashBatchWireToFrame120(batchB)
	if padA == padB {
		t.Fatalf("hybrid pad distinct: distinct batch wires produced identical pads")
	}
	edSeed, edPub, pqPriv, pqPub := hybridSignMintKeys(t)
	edSigA, pqSigA, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchA, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid (batch A): %v", err)
	}
	if VerifyBatchHybrid(edPub, pqPub, batchB, edSigA[:], pqSigA[:], "") {
		t.Fatalf("hybrid pad distinct: signature over batch A verified batch B, want reject")
	}
	t.Logf("hybrid pad distinct: distinct batch wires yield distinct pads; cross-wire verification rejected")
}

// TestPQ_HybridPadLen verifies that the pad matches the 120-byte ADR-0010 size
// expected by VerifyCRDTFrame_PostQuantum (SHAKE256 reaches >= 120 bytes whereas
// SHA-512 outputs 64 bytes).
func TestPQ_HybridPadLen(t *testing.T) {
	batchWire := makeBatchWire(t, 250, 256)
	pad := HashBatchWireToFrame120(batchWire)
	if len(pad) != hybridFrameSize {
		t.Fatalf("hybrid pad len: len=%d, want %d", len(pad), hybridFrameSize)
	}
	t.Logf("hybrid pad len: pad is %d bytes (SHAKE256 XOF)", hybridFrameSize)
}

// TestPQ_HybridSignBadSeed verifies that SignCRDTFrame_Hybrid rejects a
// non-32-byte Ed25519 seed.
func TestPQ_HybridSignBadSeed(t *testing.T) {
	_, _, pqPriv, _ := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 1, 256)
	badSeed := make([]byte, 16)
	_, _, err := SignCRDTFrame_Hybrid(badSeed, pqPriv, batchWire, "")
	if err != ErrHybridSignBadSeed {
		t.Fatalf("hybrid sign bad seed: returned err=%v, want ErrHybridSignBadSeed", err)
	}
	t.Logf("hybrid sign bad seed: non-32-byte Ed25519 seed rejected")
}

// TestPQ_HybridSignNilPQSk verifies that SignCRDTFrame_Hybrid rejects a nil
// ML-DSA-65 private key.
func TestPQ_HybridSignNilPQSk(t *testing.T) {
	edSeed, _, _, _ := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 1, 256)
	_, _, err := SignCRDTFrame_Hybrid(edSeed, nil, batchWire, "")
	if err != ErrHybridSignNilPQSk {
		t.Fatalf("hybrid sign nil pq key: returned err=%v, want ErrHybridSignNilPQSk", err)
	}
	t.Logf("hybrid sign nil pq key: nil ML-DSA-65 private key rejected")
}

// TestPQ_HybridSignNilBatchWire verifies that SignCRDTFrame_Hybrid rejects an
// empty batch wire.
func TestPQ_HybridSignNilBatchWire(t *testing.T) {
	edSeed, _, pqPriv, _ := hybridSignMintKeys(t)
	_, _, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, nil, "")
	if err != ErrHybridSignNilBatchWire {
		t.Fatalf("hybrid sign nil batch wire: returned err=%v, want ErrHybridSignNilBatchWire", err)
	}
	t.Logf("hybrid sign nil batch wire: empty batch wire rejected")
}

// TestPQ_HybridVerifyNilPQPub verifies that VerifyBatchHybrid rejects a frame
// when the ML-DSA-65 public key is nil.
func TestPQ_HybridVerifyNilPQPub(t *testing.T) {
	edSeed, edPub, pqPriv, _ := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 13, 256)
	edSig, pqSig, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	if VerifyBatchHybrid(edPub, nil, batchWire, edSig[:], pqSig[:], "") {
		t.Fatalf("hybrid verify nil pq pub: returned true with nil pqPub, want false")
	}
	t.Logf("hybrid verify nil pq pub: nil ML-DSA-65 public key rejected")
}
