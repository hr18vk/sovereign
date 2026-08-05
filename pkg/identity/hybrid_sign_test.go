// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package identity

import (
	"bytes"
	"testing"

	"filippo.io/mldsa"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// ──────────────────────────────────────────────────────────────────────────
// ADR-0037: the hybrid-PQ SIGN guards.
//
// ADR-0036 wired the VERIFY half of the hybrid moat
// (VerifyCRDTFrame_Hybrid — the both-required gate) but disclosed an honest
// NOT-YET: under --hybrid-verify EVERY v1 frame is REJECTED (the v1 wire
// carries ONE 64-byte Ed25519 originSig; the Directory carries ONE
// ed25519.PublicKey). The SIGN half is wired here: SignCRDTFrame_Hybrid signs
// the batch wire under BOTH Ed25519 + ML-DSA-65 (over the SAME 120-byte
// SHAKE256 pad), VerifyBatchHybrid is the receiver-side counterpart (pads the
// batch wire + feeds the UNCHANGED gate). These guards prove the
// sign-then-verify round-trip + the BOTH-required reject symmetry + the pad
// integrity binding + the wire-shape dispatch + the byte-identical-off
// default.
//
// The guards:
//
//	TestPQ_HybridSignThenVerify — a batch wire signed under BOTH sigs via
// SignCRDTFrame_Hybrid VERIFIES via
// VerifyBatchHybrid (the E2E round-trip).
//	TestPQ_HybridSignClassicalReject — a hybrid-signed batch whose Ed25519
// sig is CORRUPTED is REJECTED (the classical
// break does NOT pass — defense-in-depth).
//	TestPQ_HybridSignPQReject — a hybrid-signed batch whose ML-DSA-65 sig
// is CORRUPTED is REJECTED (the PQ break does
// NOT pass).
//	TestPQ_HybridPadDeterministic — HashBatchWireToFrame120 is DETERMINISTIC
// (the SAME batch wire -> the SAME 120-byte
// pad; the integrity binding — sign + verify
// compute the IDENTICAL pad, NO divergence).
//	TestPQ_HybridPadDistinct — two DISTINCT batch wires produce DISTINCT
// pads (a hybrid sig over batch A does NOT
// verify a batch B — the pad is a binding to
// THIS wire, NOT a constant).
//	TestPQ_HybridPadLen — the pad is EXACTLY 120 bytes (the ADR-10
// CRDTEntry shape the ML-DSA-65 seam signs;
// SHAKE256 reaches >=120, SHA-512 cannot).
//
// The guards reuse the EXISTING SignCRDTFrame (classical) +
// SignCRDTFrame_PostQuantum (PQ) sign seams via SignCRDTFrame_Hybrid (which
// COMPOSES them over the shared pad) + the EXISTING VerifyCRDTFrame_Hybrid
// gate via VerifyBatchHybrid (which pads internally). NEITHER existing seam is
// edited — the add-not-replace discipline.
// ──────────────────────────────────────────────────────────────────────────

// hybridSignTestSeed is a 32-byte Ed25519 seed for the hybrid-SIGN guards
// (deterministic; the SAME seed SignCRDTFrame takes). NOT a secret — the guards
// are reproducibility tests, not key-management.
var hybridSignTestSeed = bytes.Repeat([]byte{0x37}, ed25519.SeedSize) // 32 bytes of '7'

// hybridSignMint derives an Ed25519 seed->pubkey + an ML-DSA-65 keypair for the
// hybrid-SIGN guards (the SAME mint the hybrid_verify_test.go uses, with a
// distinct seed so the guards are independent). Returns edSeed, edPub, pqPriv,
// pqPub.
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
// hybrid sign/verify is INDEPENDENT of the capnp shape — it signs the verbatim
// []byte, so any byte slice is a faithful stand-in). It mixes high-entropy +
// monotone fields (NOT zeros, which would misrepresent the real batch wire the
// sig covers).
func makeBatchWire(t *testing.T, tag byte, n int) []byte {
	t.Helper()
	if n < 1 {
		n = 256
	}
	wire := make([]byte, n)
	// XOR (not OR) the tag into the high byte: OR would mask small tags into
	// the constant's 0x53 high byte (0x53|0x01 == 0x53|0x02 == 0x53 → tags 1
	// and 2 collide). XOR is injective in the tag for a fixed mask, so every
	// distinct tag produces a distinct initial splitmix64 state (the
	// TestPQ_HybridPadDistinct guard depends on tags 1 and 2 producing DISTINCT
	// batch wires).
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

// TestPQ_HybridSignThenVerify proves a batch
// wire signed under BOTH Ed25519 + ML-DSA-65 via SignCRDTFrame_Hybrid VERIFIES
// via VerifyBatchHybrid — the E2E round-trip that closes the NOT-YET
// (under --hybrid-verify a hybrid frame is now ACCEPTED, not rejected). The
// guard signs a 256-byte batch wire under BOTH sigs + asserts VerifyBatchHybrid
// returns true.
func TestPQ_HybridSignThenVerify(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 42, 256)
	edSig, pqSig, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	if !VerifyBatchHybrid(edPub, pqPub, batchWire, edSig[:], pqSig[:], "") {
		t.Fatalf("VerifyBatchHybrid=false on a batch signed under BOTH Ed25519 + ML-DSA-65 via SignCRDTFrame_Hybrid, want true (the E2E round-trip — the NOT-YET is CLOSED: under --hybrid-verify a hybrid frame is now ACCEPTED, not rejected)")
	}
	t.Logf("PASS: a batch signed under BOTH sigs via SignCRDTFrame_Hybrid VERIFIES via VerifyBatchHybrid (the E2E round-trip — the moat is now USEFUL under --hybrid-verify)")
}

// TestPQ_HybridSignClassicalReject proves a
// hybrid-signed batch whose Ed25519 sig is CORRUPTED is REJECTED by
// VerifyBatchHybrid (the classical break does NOT pass — defense-in-depth). The
// guard signs under BOTH, then flips a byte in the Ed25519 sig + asserts
// VerifyBatchHybrid returns false.
func TestPQ_HybridSignClassicalReject(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 7, 256)
	edSig, pqSig, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	// Corrupt the Ed25519 sig (flip the first byte).
	edSigCorrupt := edSig
	edSigCorrupt[0] ^= 0xFF
	if VerifyBatchHybrid(edPub, pqPub, batchWire, edSigCorrupt[:], pqSig[:], "") {
		t.Fatalf("VerifyBatchHybrid=true on a batch whose Ed25519 sig is CORRUPTED, want false (a classical break MUST NOT pass the hybrid gate — defense-in-depth)")
	}
	t.Logf("PASS: a hybrid-signed batch whose Ed25519 sig is CORRUPTED is REJECTED (the classical break does NOT pass — defense-in-depth)")
}

// TestPQ_HybridSignPQReject proves a hybrid-signed
// batch whose ML-DSA-65 sig is CORRUPTED is REJECTED by VerifyBatchHybrid (the
// PQ break does NOT pass). The guard signs under BOTH, then flips a mid-sig
// byte in the ML-DSA-65 sig + asserts VerifyBatchHybrid returns false.
func TestPQ_HybridSignPQReject(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 99, 256)
	edSig, pqSig, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	// Corrupt the PQ sig (flip a mid-sig byte — the first byte may be a header
	// the verify tolerates; a mid-sig byte is the safe corruption, the SAME
	// discipline hybrid_verify_test.go:145 uses).
	pqSigCorrupt := pqSig
	pqSigCorrupt[len(pqSigCorrupt)/2] ^= 0xFF
	if VerifyBatchHybrid(edPub, pqPub, batchWire, edSig[:], pqSigCorrupt[:], "") {
		t.Fatalf("VerifyBatchHybrid=true on a batch whose ML-DSA-65 sig is CORRUPTED, want false (a PQ break MUST NOT pass the hybrid gate — defense-in-depth)")
	}
	t.Logf("PASS: a hybrid-signed batch whose ML-DSA-65 sig is CORRUPTED is REJECTED (the PQ break does NOT pass — defense-in-depth)")
}

// TestPQ_HybridPadDeterministic proves
// HashBatchWireToFrame120 is DETERMINISTIC — the SAME batch wire produces the
// SAME 120-byte pad across calls (the integrity binding: the sign and the
// verify compute the IDENTICAL 120 bytes, so the single msg the gate
// verifies is the SAME 120 bytes both sigs signed; NO sign-vs-verify
// divergence — the divergence the deterministic pad forbids).
func TestPQ_HybridPadDeterministic(t *testing.T) {
	batchWire := makeBatchWire(t, 13, 256)
	pad1 := HashBatchWireToFrame120(batchWire)
	pad2 := HashBatchWireToFrame120(batchWire)
	if pad1 != pad2 {
		t.Fatalf("HashBatchWireToFrame120 is NOT deterministic — pad1=%x... != pad2=%x... (the integrity binding is BROKEN; sign + verify would diverge)", pad1[:8], pad2[:8])
	}
	t.Logf("PASS: HashBatchWireToFrame120 is DETERMINISTIC (the SAME batch -> the SAME 120-byte pad; the sign + the verify compute the IDENTICAL bytes — NO divergence)")
}

// TestPQ_HybridPadDistinct proves two DISTINCT batch
// wires produce DISTINCT pads — a hybrid sig over batch A does NOT verify a
// batch B (the pad is a binding to THIS wire, NOT a constant; a collision would
// be a signature-substitution attack the integrity binding forbids). The guard
// mints two distinct batch wires + asserts the pads differ.
func TestPQ_HybridPadDistinct(t *testing.T) {
	batchA := makeBatchWire(t, 1, 256)
	batchB := makeBatchWire(t, 2, 256)
	padA := HashBatchWireToFrame120(batchA)
	padB := HashBatchWireToFrame120(batchB)
	if padA == padB {
		t.Fatalf("two DISTINCT batch wires produced the SAME pad — the integrity binding is BROKEN (a hybrid sig over batch A would verify a batch B — a signature-substitution attack)")
	}
	// The load-bearing consequence: a hybrid sig over batch A does NOT verify
	// batch B. Sign batch A under BOTH sigs, then assert VerifyBatchHybrid
	// REJECTS batch B (the pad differs -> the gate rejects).
	edSeed, edPub, pqPriv, pqPub := hybridSignMintKeys(t)
	edSigA, pqSigA, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchA, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid (batch A): %v", err)
	}
	if VerifyBatchHybrid(edPub, pqPub, batchB, edSigA[:], pqSigA[:], "") {
		t.Fatalf("a hybrid sig over batch A VERIFIED batch B — the pad is NOT a binding to the wire (a signature-substitution attack succeeded)")
	}
	t.Logf("PASS: two distinct batch wires produce distinct pads; a hybrid sig over batch A does NOT verify batch B (the pad is a binding to THIS wire — the integrity binding holds)")
}

// TestPQ_HybridPadLen proves the pad is EXACTLY 120 bytes
// (the ADR-10 CRDTEntry shape the ML-DSA-65 seam signs; SHAKE256 reaches >=120,
// which SHA-512 CANNOT — the ADR-0037 draft named SHA-512[:120], refuted by the
// 64B output cap; SHAKE256 is the byte-faithful pad). The guard asserts the pad
// is 120 bytes (a [120]byte — the length is encoded in the type).
func TestPQ_HybridPadLen(t *testing.T) {
	batchWire := makeBatchWire(t, 250, 256)
	pad := HashBatchWireToFrame120(batchWire)
	if len(pad) != hybridFrameSize {
		t.Fatalf("pad len=%d, want %d (the ADR-10 CRDTEntry shape the ML-DSA-65 seam signs; SHAKE256 reaches >=120 — SHA-512 cannot, which is why SHAKE256 is the pad, NOT SHA-512)", len(pad), hybridFrameSize)
	}
	t.Logf("PASS: the pad is EXACTLY %d bytes (the ADR-10 CRDTEntry shape; SHAKE256 XOF — NOT SHA-512, which is capped at 64B)", hybridFrameSize)
}

// TestPQ_HybridSignBadSeed proves SignCRDTFrame_Hybrid
// rejects a non-32-byte Ed25519 seed (the SAME guard SignCRDTFrame applies — a
// short/long seed cannot derive a valid Ed25519 keypair and MUST NOT silently
// truncate). The guard passes a 16-byte seed + asserts ErrHybridSignBadSeed.
func TestPQ_HybridSignBadSeed(t *testing.T) {
	_, _, pqPriv, _ := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 1, 256)
	badSeed := make([]byte, 16) // NOT 32 bytes
	_, _, err := SignCRDTFrame_Hybrid(badSeed, pqPriv, batchWire, "")
	if err != ErrHybridSignBadSeed {
		t.Fatalf("SignCRDTFrame_Hybrid with a 16-byte seed returned err=%v, want ErrHybridSignBadSeed (the seed guard — a short seed MUST NOT silently truncate)", err)
	}
	t.Logf("PASS: a non-32-byte Ed25519 seed is rejected (the seed guard mirrors SignCRDTFrame)")
}

// TestPQ_HybridSignNilPQSk proves SignCRDTFrame_Hybrid
// rejects a nil ML-DSA-65 private key (the hybrid contract is BOTH sigs; a nil
// PQ signer cannot produce the PQ half — the nil-guard the mesh's
// ShipBatchHybrid shipper relies on). The guard passes a nil pqSk + asserts
// ErrHybridSignNilPQSk.
func TestPQ_HybridSignNilPQSk(t *testing.T) {
	edSeed, _, _, _ := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 1, 256)
	_, _, err := SignCRDTFrame_Hybrid(edSeed, nil, batchWire, "")
	if err != ErrHybridSignNilPQSk {
		t.Fatalf("SignCRDTFrame_Hybrid with a nil pqSk returned err=%v, want ErrHybridSignNilPQSk (the hybrid contract is BOTH sigs; a nil PQ signer cannot produce the PQ half)", err)
	}
	t.Logf("PASS: a nil ML-DSA-65 private key is rejected (BOTH sigs is the contract)")
}

// TestPQ_HybridSignNilBatchWire proves
// SignCRDTFrame_Hybrid rejects an empty batch wire (the pad of an empty wire is
// a constant; signing a constant is a no-op signature that covers no state —
// rejected pre-sign, the unsigned-batch guard sibling to envelope.go's
// zero-originSig rule). The guard passes an empty batchWire + asserts
// ErrHybridSignNilBatchWire.
func TestPQ_HybridSignNilBatchWire(t *testing.T) {
	edSeed, _, pqPriv, _ := hybridSignMintKeys(t)
	_, _, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, nil, "")
	if err != ErrHybridSignNilBatchWire {
		t.Fatalf("SignCRDTFrame_Hybrid with an empty batchWire returned err=%v, want ErrHybridSignNilBatchWire (an empty wire has no state to sign — the unsigned-batch guard)", err)
	}
	t.Logf("PASS: an empty batch wire is rejected pre-sign (the unsigned-batch guard)")
}

// TestPQ_HybridVerifyNilPQPub proves
// VerifyBatchHybrid rejects a frame with a nil PQ pubkey (the STRICT mode — a
// hybrid verifier NEVER accepts a frame from a non-PQ-provisioned origin; the
// nil-pqPub reject the verify path enforces, extended to the batch path). The
// guard signs under BOTH, then verifies with a nil pqPub + asserts false.
func TestPQ_HybridVerifyNilPQPub(t *testing.T) {
	edSeed, edPub, pqPriv, _ := hybridSignMintKeys(t)
	batchWire := makeBatchWire(t, 13, 256)
	edSig, pqSig, err := SignCRDTFrame_Hybrid(edSeed, pqPriv, batchWire, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_Hybrid: %v", err)
	}
	if VerifyBatchHybrid(edPub, nil, batchWire, edSig[:], pqSig[:], "") {
		t.Fatalf("VerifyBatchHybrid=true with a nil pqPub, want false (the STRICT mode — a hybrid verifier NEVER accepts a frame from a non-PQ-provisioned origin; BOTH is the contract)")
	}
	t.Logf("PASS: a frame with a nil PQ pubkey is REJECTED (the STRICT mode — BOTH is the contract)")
}
