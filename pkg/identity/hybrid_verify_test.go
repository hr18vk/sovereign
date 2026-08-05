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
// ADR-0036: the hybrid (Ed25519 + ML-DSA-65) verify guards.
//
// The hybrid verify (hybrid_verify.go VerifyCRDTFrame_Hybrid) is the
// defense-in-depth BOTH-signatures-required gate. The guards:
//
//	TestPQ_HybridVerifyDual — a frame signed under BOTH Ed25519 +
// ML-DSA-65 VERIFIES under the hybrid gate
// (the BOTH-required accept path).
//	TestPQ_HybridClassicalReject — a frame whose Ed25519 sig is CORRUPTED
// is REJECTED (the classical break does NOT
// pass the hybrid gate — defense-in-depth).
//	TestPQ_HybridPQReject — a frame whose ML-DSA-65 sig is CORRUPTED
// is REJECTED (the PQ break does NOT pass).
//	TestPQ_HybridNilPQReject — a frame with a nil PQ pubkey (the honest
// NOT-YET — the Directory does not yet carry
// the peer's ML-DSA-65 key) is REJECTED
// (the STRICT mode: a hybrid verifier NEVER
// accepts a classical-only frame).
//	TestPQ_HybridEitherOrControl — the bug-inject control: an EITHER-or
// gate (return pqOK || edOK) would ACCEPT a
// frame whose classical sig is corrupt but
// PQ is valid — PROVES the BOTH gate is
// load-bearing (the EITHER-or is the
// defense-in-depth INVERSION the BOTH gate
// forbids).
//	TestPQ_HybridLenMismatch — a msg whose length is NOT 120 is
// REJECTED (the PQ seam takes a [120]byte;
// the hybrid honors the STRICTER of the
// two seams — the classical tolerates any
// length, the PQ does not).
//
// The guards reuse the EXISTING SignCRDTFrame (classical) +
// SignCRDTFrame_PostQuantum (PQ) sign seams + the hybrid verify. The hybrid
// SIGN (a frame carries BOTH sigs) is a future change — these guards sign under
// BOTH in-process (the test owns the dual-sign), NOT via a production wire
// shape (which does not exist yet — disclosed ADR-0036 §6).
// ──────────────────────────────────────────────────────────────────────────

// hybridTestSeed is a 32-byte Ed25519 seed for the hybrid guards (deterministic;
// the SAME seed the SignCRDTFrame seam takes). NOT a secret — the guards are
// reproducibility tests, not key-management.
var hybridTestSeed = bytes.Repeat([]byte{0x31}, ed25519.SeedSize) // 32 bytes of '1'

// hybridMintKeys derives an Ed25519 seed→pubkey + an ML-DSA-65 keypair for the
// hybrid guards. The Ed25519 pub is derived via the SAME path SignCRDTFrame uses
// (ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)); the ML-DSA-65
// keypair is minted via GeneratePreviewKey65 (the production PQ key minter).
// Returns edSeed, edPub, pqPriv, pqPub.
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

// TestPQ_HybridVerifyDual proves a frame signed under
// BOTH Ed25519 + ML-DSA-65 VERIFIES under the hybrid gate (the BOTH-required
// accept path). The guard signs a 120-byte frame under BOTH seams + asserts
// VerifyCRDTFrame_Hybrid returns true.
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
		t.Fatalf("VerifyCRDTFrame_Hybrid=false on a frame signed under BOTH Ed25519 + ML-DSA-65, want true (the BOTH-required accept path)")
	}
	t.Logf("PASS: a frame signed under BOTH Ed25519 + ML-DSA-65 VERIFIES under the hybrid gate (the BOTH-required accept path)")
}

// TestPQ_HybridClassicalReject proves a frame
// whose Ed25519 sig is CORRUPTED is REJECTED by the hybrid gate (the classical
// break does NOT pass — defense-in-depth). The guard signs under BOTH, then
// flips a byte in the Ed25519 sig + asserts the hybrid verify returns false.
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
		t.Fatalf("VerifyCRDTFrame_Hybrid=true on a frame whose Ed25519 sig is CORRUPTED, want false (a classical break MUST NOT pass the hybrid gate — defense-in-depth)")
	}
	t.Logf("PASS: a frame whose Ed25519 sig is CORRUPTED is REJECTED by the hybrid gate (the classical break does NOT pass — defense-in-depth)")
}

// TestPQ_HybridPQReject proves a frame whose ML-DSA-65
// sig is CORRUPTED is REJECTED by the hybrid gate (the PQ break does NOT pass).
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
	// Corrupt the PQ sig (flip a mid-sig byte — the first byte may be a header
	// the verify tolerates; a mid-sig byte is the safe corruption).
	pqSigCorrupt := make([]byte, len(pqSig))
	copy(pqSigCorrupt, pqSig)
	pqSigCorrupt[len(pqSigCorrupt)/2] ^= 0xFF
	if VerifyCRDTFrame_Hybrid(edPub, pqPub, frame, edSig, pqSigCorrupt, "") {
		t.Fatalf("VerifyCRDTFrame_Hybrid=true on a frame whose ML-DSA-65 sig is CORRUPTED, want false (a PQ break MUST NOT pass the hybrid gate — defense-in-depth)")
	}
	t.Logf("PASS: a frame whose ML-DSA-65 sig is CORRUPTED is REJECTED by the hybrid gate (the PQ break does NOT pass — defense-in-depth)")
}

// TestPQ_HybridNilPQReject proves a frame with a
// nil PQ pubkey (the honest NOT-YET — the Directory does not yet carry the
// peer's ML-DSA-65 key) is REJECTED (the STRICT mode: a hybrid verifier NEVER
// accepts a classical-only frame; BOTH is the contract). This is the
// receive-path posture under --hybrid-verify today (the v1 envelope carries no
// PQ sig + the Directory carries no PQ pubkey → the hybrid verify rejects).
func TestPQ_HybridNilPQReject(t *testing.T) {
	edSeed, edPub, _, _ := hybridMintKeys(t)
	frame := makeFrame120(t, 13)
	edSig, err := SignCRDTFrame(edSeed, frame)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	// nil PQ pubkey + nil PQ sig — the STRICT mode (the honest NOT-YET).
	if VerifyCRDTFrame_Hybrid(edPub, nil, frame, edSig, nil, "") {
		t.Fatalf("VerifyCRDTFrame_Hybrid=true on a frame with a nil PQ pubkey, want false (the STRICT mode — a hybrid verifier NEVER accepts a classical-only frame; BOTH is the contract; the honest NOT-YET under --hybrid-verify today)")
	}
	t.Logf("PASS: a frame with a nil PQ pubkey is REJECTED (the STRICT mode — a hybrid verifier NEVER accepts a classical-only frame; the honest NOT-YET under --hybrid-verify today)")
}

// TestPQ_HybridLenMismatch proves a msg whose length
// is NOT 120 is REJECTED (the PQ seam takes a [120]byte; the hybrid honors the
// STRICTER of the two seams — the classical tolerates any length, the PQ does
// not). The guard signs a 200-byte frame under the classical seam (which
// accepts any length) + asserts the hybrid verify rejects (the len != 120 guard).
func TestPQ_HybridLenMismatch(t *testing.T) {
	edSeed, edPub, _, pqPub := hybridMintKeys(t)
	// A 200-byte frame (NOT the 120-byte CRDT-frame delta the PQ seam signs).
	frame := make([]byte, 200)
	for i := range frame {
		frame[i] = byte(i)
	}
	edSig, err := SignCRDTFrame(edSeed, frame)
	if err != nil {
		t.Fatalf("SignCRDTFrame: %v", err)
	}
	// The classical verify PASSES on a 200-byte frame (the classical seam
	// tolerates any length) — prove the classical alone accepts it.
	if !VerifyCRDTFrame(edPub, frame, edSig) {
		t.Fatalf("pre-condition failed — VerifyCRDTFrame (classical) rejected the 200-byte frame, want accept (the classical seam tolerates any length; the len-mismatch is the hybrid's STRICTER guard)")
	}
	// The hybrid verify REJECTS the 200-byte frame (the PQ seam takes a
	// [120]byte; the len != 120 guard rejects before the PQ verify).
	if VerifyCRDTFrame_Hybrid(edPub, pqPub, frame, edSig, nil, "") {
		t.Fatalf("VerifyCRDTFrame_Hybrid=true on a 200-byte frame, want false (the hybrid honors the STRICTER of the two seams — the PQ seam takes a [120]byte; a len != 120 is a frame-shape mismatch the hybrid rejects)")
	}
	t.Logf("PASS: a 200-byte frame (len != 120) is REJECTED by the hybrid gate (the hybrid honors the STRICTER of the two seams — the classical tolerates any length, the PQ does not)")
}

// TestPQ_HybridEitherOrControl is the BUG-INJECT
// control that PROVES the BOTH gate is load-bearing: an EITHER-or gate (return
// pqOK || edOK) would ACCEPT a frame whose classical sig is corrupt but PQ is
// valid. The guard constructs the EITHER-or result explicitly + asserts it
// DIFFERS from the BOTH gate (the BOTH gate rejects; the EITHER-or accepts).
// The false headline (EITHER-or) is PROVEN to invert the defense-in-depth the
// BOTH gate enforces.
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
	// Corrupt the Ed25519 sig (classical break). The PQ sig stays VALID.
	edSigCorrupt := make([]byte, len(edSig))
	copy(edSigCorrupt, edSig)
	edSigCorrupt[0] ^= 0xFF
	// The BOTH gate (the hybrid verify) MUST reject (classical corrupt → false).
	bothGate := VerifyCRDTFrame_Hybrid(edPub, pqPub, frame, edSigCorrupt, pqSig, "")
	if bothGate {
		t.Fatalf("the BOTH gate ACCEPTED a frame with a corrupt classical sig, want reject (the BOTH gate is the defense-in-depth gate — a classical break MUST NOT pass)")
	}
	// The EITHER-or gate (the BUG-INJECT inversion) would ACCEPT: classical is
	// corrupt (false) BUT PQ is valid (true) → pqOK || edOK == true. Compute it
	// explicitly to PROVE the inversion (the EITHER-or is the false headline).
	edOK := VerifyCRDTFrame(edPub, frame, edSigCorrupt) // false (corrupt)
	var pqFrame [120]byte
	copy(pqFrame[:], frame)
	pqOK := VerifyCRDTFrame_PostQuantum(pqPub, pqFrame, pqSig, "") == nil // true (valid)
	eitherOr := edOK || pqOK
	if !eitherOr {
		t.Fatalf("pre-condition failed — the EITHER-or gate REJECTED (edOK=%v pqOK=%v), want ACCEPT (the PQ sig is valid; the EITHER-or must accept a frame with a valid PQ sig even when classical is corrupt — the inversion)", edOK, pqOK)
	}
	// The load-bearing assertion: the BOTH gate rejects (bothGate=false) AND
	// the EITHER-or accepts (eitherOr=true) — they DIFFER. The BOTH gate is
	// load-bearing (NOT a tautology; the EITHER-or is the inversion it forbids).
	if bothGate == eitherOr {
		t.Fatalf("the BOTH gate (=%v) == the EITHER-or gate (=%v) — the BOTH gate is NOT load-bearing (a tautology); want BOTH=false AND EITHER-or=true (the BOTH gate forbids the EITHER-or inversion)", bothGate, eitherOr)
	}
	t.Logf("PASS: the BOTH gate rejects (=%v) a classical-corrupt+PQ-valid frame; the EITHER-or gate would accept (=%v) — they DIFFER, PROVING the BOTH gate is load-bearing (the EITHER-or is the defense-in-depth inversion the BOTH gate forbids)", bothGate, eitherOr)
}

// ─── helpers ───

// makeFrame120 mints a deterministic 120-byte frame (the ADR-10 CRDTEntry
// shape the PQ seam signs) seeded by tag. It fills the frame with a mix of
// high-entropy + monotone fields (NOT 120 zeros, which would misrepresent the
// real payload the sig covers).
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
