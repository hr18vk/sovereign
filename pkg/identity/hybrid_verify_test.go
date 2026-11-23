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
// Hybrid verify tests (ADR-0036): the Ed25519 + ML-DSA-65 verification gate.
//
// VerifyCRDTFrame_Hybrid requires both a valid Ed25519 signature and a valid
// ML-DSA-65 signature. The cases cover acceptance and each rejection mode:
//
//	TestPQ_HybridVerifyDual       — both signatures valid -> accept.
//	TestPQ_HybridClassicalReject  — corrupt Ed25519 signature -> reject.
//	TestPQ_HybridPQReject         — corrupt ML-DSA-65 signature -> reject.
//	TestPQ_HybridNilPQReject      — nil ML-DSA-65 public key -> reject.
//	TestPQ_HybridEitherOrControl  — control showing an either-or gate would
//	                                accept a corrupt-classical / valid-PQ
//	                                frame that VerifyCRDTFrame_Hybrid rejects.
//	TestPQ_HybridLenMismatch      — non-120-byte message -> reject.
// ──────────────────────────────────────────────────────────────────────────

// hybridTestSeed is a 32-byte Ed25519 seed for the hybrid tests (deterministic;
// the same seed the SignCRDTFrame path uses). It is not a secret — these are
// reproducibility tests, not key management.
var hybridTestSeed = bytes.Repeat([]byte{0x31}, ed25519.SeedSize) // 32 bytes of '1'

// hybridMintKeys derives an Ed25519 seed→pubkey and an ML-DSA-65 keypair for the
// hybrid tests. The Ed25519 pub is derived via the same path SignCRDTFrame uses
// (ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)); the ML-DSA-65
// keypair is minted via GeneratePreviewKey65 (the production PQ key minter,
// promoted from the pq_preview tag). Returns edSeed, edPub, pqPriv, pqPub.
func hybridMintKeys(t *testing.T) (edSeed []byte, edPub ed25519.PublicKey, pqPriv *mldsa.PrivateKey, pqPub *mldsa.PublicKey) {
	t.Helper()
	edSeed = hybridTestSeed
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

// TestPQ_HybridVerifyDual verifies that a frame signed under both Ed25519 and
// ML-DSA-65 passes VerifyCRDTFrame_Hybrid.
func TestPQ_HybridVerifyDual(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridMintKeys(t)
	frame := makeFrame120(t, 42)
	edSig, err := SignCRDTFrame(edSeed, frame)
	if err != nil {
		t.Fatalf("SignCRDTFrame (classical): %v", err)
	}
	var frame120 [120]byte
	copy(frame120[:], frame)
	pqSig, err := SignCRDTFrame_PostQuantum(pqPriv, frame120, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_PostQuantum (PQ): %v", err)
	}
	if !VerifyCRDTFrame_Hybrid(edPub, pqPub, frame, edSig, pqSig, "") {
		t.Fatalf("hybrid verify dual: VerifyCRDTFrame_Hybrid=false on dual-signed frame, want true")
	}
	t.Logf("hybrid verify dual: dual-signed frame accepted by VerifyCRDTFrame_Hybrid")
}

// TestPQ_HybridClassicalReject verifies that corrupting the Ed25519 signature
// causes VerifyCRDTFrame_Hybrid to reject even when the ML-DSA-65 signature is valid.
func TestPQ_HybridClassicalReject(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridMintKeys(t)
	frame := makeFrame120(t, 7)
	edSig, err := SignCRDTFrame(edSeed, frame)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	var frame120 [120]byte
	copy(frame120[:], frame)
	pqSig, err := SignCRDTFrame_PostQuantum(pqPriv, frame120, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_PostQuantum: %v", err)
	}
	// Corrupt the Ed25519 sig (flip the first byte).
	edSigCorrupt := make([]byte, len(edSig))
	copy(edSigCorrupt, edSig)
	edSigCorrupt[0] ^= 0xFF
	if VerifyCRDTFrame_Hybrid(edPub, pqPub, frame, edSigCorrupt, pqSig, "") {
		t.Fatalf("hybrid classical reject: VerifyCRDTFrame_Hybrid=true with corrupt Ed25519 signature, want false")
	}
	t.Logf("hybrid classical reject: corrupt Ed25519 signature rejected")
}

// TestPQ_HybridPQReject verifies that corrupting the ML-DSA-65 signature causes
// VerifyCRDTFrame_Hybrid to reject even when the Ed25519 signature is valid.
func TestPQ_HybridPQReject(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridMintKeys(t)
	frame := makeFrame120(t, 99)
	edSig, err := SignCRDTFrame(edSeed, frame)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	var frame120 [120]byte
	copy(frame120[:], frame)
	pqSig, err := SignCRDTFrame_PostQuantum(pqPriv, frame120, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_PostQuantum: %v", err)
	}
	// Corrupt a byte in the middle of the ML-DSA-65 signature.
	pqSigCorrupt := make([]byte, len(pqSig))
	copy(pqSigCorrupt, pqSig)
	pqSigCorrupt[len(pqSigCorrupt)/2] ^= 0xFF
	if VerifyCRDTFrame_Hybrid(edPub, pqPub, frame, edSig, pqSigCorrupt, "") {
		t.Fatalf("hybrid pq reject: VerifyCRDTFrame_Hybrid=true with corrupt ML-DSA-65 signature, want false")
	}
	t.Logf("hybrid pq reject: corrupt ML-DSA-65 signature rejected")
}

// TestPQ_HybridNilPQReject verifies that a nil ML-DSA-65 public key is rejected.
func TestPQ_HybridNilPQReject(t *testing.T) {
	edSeed, edPub, _, _ := hybridMintKeys(t)
	frame := makeFrame120(t, 13)
	edSig, err := SignCRDTFrame(edSeed, frame)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	if VerifyCRDTFrame_Hybrid(edPub, nil, frame, edSig, nil, "") {
		t.Fatalf("hybrid nil pq reject: VerifyCRDTFrame_Hybrid=true with nil PQ pubkey, want false")
	}
	t.Logf("hybrid nil pq reject: nil PQ pubkey rejected")
}

// TestPQ_HybridLenMismatch verifies that a message length other than 120 bytes
// is rejected even when the Ed25519 signature alone would verify.
func TestPQ_HybridLenMismatch(t *testing.T) {
	edSeed, edPub, _, pqPub := hybridMintKeys(t)
	frame := make([]byte, 200)
	for i := range frame {
		frame[i] = byte(i)
	}
	edSig, err := SignCRDTFrame(edSeed, frame)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	if !VerifyCRDTFrame(edPub, frame, edSig) {
		t.Fatalf("hybrid len mismatch: precondition failed — VerifyCRDTFrame rejected 200-byte frame, want accept")
	}
	if VerifyCRDTFrame_Hybrid(edPub, pqPub, frame, edSig, nil, "") {
		t.Fatalf("hybrid len mismatch: VerifyCRDTFrame_Hybrid=true on 200-byte frame, want false")
	}
	t.Logf("hybrid len mismatch: 200-byte frame rejected (requires 120 bytes)")
}

// TestPQ_HybridEitherOrControl contrasts VerifyCRDTFrame_Hybrid against an
// either-or policy (edOK || pqOK) on a frame with a corrupted Ed25519 signature
// and valid ML-DSA-65 signature.
func TestPQ_HybridEitherOrControl(t *testing.T) {
	edSeed, edPub, pqPriv, pqPub := hybridMintKeys(t)
	frame := makeFrame120(t, 250)
	edSig, err := SignCRDTFrame(edSeed, frame)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	var frame120 [120]byte
	copy(frame120[:], frame)
	pqSig, err := SignCRDTFrame_PostQuantum(pqPriv, frame120, "")
	if err != nil {
		t.Fatalf("SignCRDTFrame_PostQuantum: %v", err)
	}
	edSigCorrupt := make([]byte, len(edSig))
	copy(edSigCorrupt, edSig)
	edSigCorrupt[0] ^= 0xFF
	bothGate := VerifyCRDTFrame_Hybrid(edPub, pqPub, frame, edSigCorrupt, pqSig, "")
	if bothGate {
		t.Fatalf("hybrid either-or control: both-required gate accepted corrupt classical signature, want reject")
	}
	edOK := VerifyCRDTFrame(edPub, frame, edSigCorrupt)
	var pqFrame [120]byte
	copy(pqFrame[:], frame)
	pqOK := VerifyCRDTFrame_PostQuantum(pqPub, pqFrame, pqSig, "") == nil
	eitherOr := edOK || pqOK
	if !eitherOr {
		t.Fatalf("hybrid either-or control: precondition failed — either-or rejected (edOK=%v pqOK=%v), want accept", edOK, pqOK)
	}
	if bothGate == eitherOr {
		t.Fatalf("hybrid either-or control: bothGate (=%v) matched eitherOr (=%v), want false vs true", bothGate, eitherOr)
	}
	t.Logf("hybrid either-or control: both-required=%v while either-or=%v on corrupt-classical/valid-PQ frame", bothGate, eitherOr)
}

// ─── helpers ───

// makeFrame120 builds a deterministic 120-byte test payload (ADR-0010 CRDTEntry
// size) seeded by tag.
func makeFrame120(t *testing.T, tag byte) []byte {
	t.Helper()
	frame := make([]byte, 120)
	// High-entropy digest (32 bytes) + node IDs (32 bytes) from a tag-seeded
	// splitmix64; monotone counters in the rest.
	state := uint64(tag)<<56 | 0x534F564552454747 // "SOVEREGG" high bits + tag
	for i := 0; i < 64; i += 8 {
		state = state*6364136223846793005 + 1442695040888963407 // splitmix64 step
		binaryLittleEndianPutUint64(frame[i:i+8], state)
	}
	// Monotone counters (low-entropy, the real CRDT-frame shape).
	for i := 64; i < 120; i += 8 {
		binaryLittleEndianPutUint64(frame[i:i+8], uint64(i))
	}
	return frame
}

func binaryLittleEndianPutUint64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}
