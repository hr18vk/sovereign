// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package identity

import (
	"filippo.io/mldsa"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// ──────────────────────────────────────────────────────────────────────────
// Hybrid (Ed25519 + ML-DSA-65) verify — the both-signatures-required gate
// (ADR-0036).
//
// A CRDT delta frame under hybrid signing carries two signatures: a
// randomized-nonce Ed25519 signature (SignCRDTFrame, verified by
// VerifyCRDTFrame) and an ML-DSA-65 signature (SignCRDTFrame_PostQuantum,
// verified by VerifyCRDTFrame_PostQuantum). Both signatures must verify.
//
// Requiring edOK && pqOK prevents a compromise in either primitive from bypassing
// the other, whereas an either-or gate would allow a broken primitive to forge
// frames alone (verified by TestPQ_HybridEitherOrControl).
//
// Hybrid verification is opt-in (--hybrid-verify, default false; default
// verification remains classical VerifyCRDTFrame). Under --hybrid-verify, a
// frame missing a post-quantum signature or key is rejected. For batched
// variable-length wires, SignCRDTFrame_Hybrid and VerifyBatchHybrid (ADR-0037,
// hybrid_sign.go) sign and verify over a 120-byte SHAKE256 pad passed to
// VerifyCRDTFrame_Hybrid.
// ──────────────────────────────────────────────────────────────────────────

// VerifyCRDTFrame_Hybrid verifies a 120-byte CRDT delta frame under both
// randomized-nonce Ed25519 and ML-DSA-65 signatures, returning true only when
// both verify.
//
//   - edPub — origin Ed25519 public key.
//   - pqPub — origin ML-DSA-65 public key; nil always rejects.
//   - msg   — 120-byte frame payload (ADR-0010 CRDTEntry size; other lengths reject).
//   - edSig — 64-byte Ed25519 signature.
//   - pqSig — 3309-byte ML-DSA-65 signature.
//   - ctx   — FIPS 204 context string for ML-DSA-65 (ignored by Ed25519).
//
// The classical check runs first so invalid Ed25519 frames short-circuit before
// the ~74 µs ML-DSA-65 check.
func VerifyCRDTFrame_Hybrid(edPub ed25519.PublicKey, pqPub *mldsa.PublicKey, msg, edSig, pqSig []byte, ctx string) bool {
	// (1) Classical check first: short-circuits ML-DSA-65 verification on invalid frames.
	if !VerifyCRDTFrame(edPub, msg, edSig) {
		return false
	}
	// (2) ML-DSA-65 check: nil key or non-120-byte payload rejects.
	if pqPub == nil {
		return false
	}
	if len(msg) != hybridFrameSize {
		return false
	}
	var frame [hybridFrameSize]byte
	copy(frame[:], msg)
	if err := VerifyCRDTFrame_PostQuantum(pqPub, frame, pqSig, ctx); err != nil {
		return false
	}
	return true
}

// hybridFrameSize is the 120-byte frame length required by the ML-DSA-65
// verification API (matching the ADR-0010 CRDTEntry size).
const hybridFrameSize = 120
