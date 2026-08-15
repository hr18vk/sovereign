package identity

import (
	"filippo.io/mldsa"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// ──────────────────────────────────────────────────────────────────────────
// Day 31 (ADR-0036): the hybrid (Ed25519 + ML-DSA-65) verify — the M3
// defense-in-depth BOTH-signatures-required seam.
//
// A CRDT delta frame under hybrid signing carries TWO signatures: a hedged
// Ed25519 sig (eddsa_hedge.go:84 SignCRDTFrame, verified by verify.go:68
// VerifyCRDTFrame — the CLASSICAL side) + an ML-DSA-65 sig (pq_mldsa.go:86
// SignCRDTFrame_PostQuantum, verified by pq_mldsa.go:117
// VerifyCRDTFrame_PostQuantum — the PQ side). The hybrid verify checks BOTH;
// EITHER failure rejects the frame.
//
// WHY BOTH, NOT either-or (defense-in-depth — the load-bearing M3 rationale):
//   - a CLASSICAL break (a future Ed25519 fault) does NOT compromise a PQ
//     frame — the ML-DSA-65 sig still must verify.
//   - a PQ break (a future ML-DSA-65 fault, or a quantum adversary) does NOT
//     compromise a classical frame — the Ed25519 sig still must verify.
//   - an EITHER-or gate (return pqOK || edOK) makes the PQ side a SINGLE point
//     of compromise for the classical frame (the OPPOSITE of defense-in-depth:
//     one break defeats both). The BOTH gate (return edOK && pqOK) is the
//     load-bearing choice — the Day-25 dominant-divergence class Law 5 forbids
//     the false headline; the EITHER-or is the BUG-INJECT control the
//     T-PQ-HYBRID-VERIFY-DUAL tooth PROVES the BOTH gate rejects.
//
// The hybrid verify is an ADD (the Day-19/Day-30 opt-IN precedent): it does NOT
// replace the classical VerifyCRDTFrame seam (the production default stays
// classical-only, byte-identical Day-30). The PRODUCTION wiring is OPT-IN
// (--hybrid-verify, default false — Edit C in main.go gates the receive path's
// call to VerifyCRDTFrame_Hybrid vs VerifyCRDTFrame). A classical-only frame
// (no PQ sig) is REJECTED under hybrid-verify — the STRICT mode (a hybrid
// verifier NEVER accepts a single-sig frame; BOTH is the contract).
//
// The PQ SIGN path (SignCRDTFrame_PostQuantum) is benchmarked but the PRODUCTION
// sign seam (the CRDT delta wire) is NOT wired this fork — the hybrid SIGN (a
// frame carries BOTH sigs) needs the CRDT-delta wire shape changed (a FUTURE
// fork — disclosed ADR-0036 §6; the FROZEN-crdt.go seam is the HONEST question
// a future fork answers). This file wires the VERIFY; the SIGN is the NEXT PQ
// fork. The hybrid verify is exercised by the T-PQ-HYBRID-VERIFY-DUAL tooth
// (which signs under BOTH via the existing SignCRDTFrame + SignCRDTFrame_
// PostQuantum, then verifies + corrupts each side).
// ──────────────────────────────────────────────────────────────────────────

// VerifyCRDTFrame_Hybrid verifies a CRDT delta frame under BOTH the hedged
// Ed25519 signature AND the ML-DSA-65 signature (the defense-in-depth BOTH-
// required gate). It returns true IFF BOTH verify; EITHER failure returns
// false (the frame is REJECTED).
//
//   - edPub   — the origin's Ed25519 public key (the classical side; the SAME
//     key VerifyCRDTFrame takes).
//   - pqPub   — the origin's ML-DSA-65 public key (the PQ side; the SAME key
//     VerifyCRDTFrame_PostQuantum takes). nil → the PQ verify is a no-op
//     reject (a hybrid verifier NEVER accepts a frame with no PQ key — BOTH
//     is the contract).
//   - msg     — the frame bytes (the SAME payload both sigs cover; the
//     classical seam takes a []byte, the PQ seam takes a [120]byte — the
//     hybrid bridges the two by copying msg into a 120-byte array IFF len(msg)
//     == 120, else rejecting; the 120-byte CRDT-frame delta is the ADR-10
//     CRDTEntry shape both seams sign).
//   - edSig   — the Ed25519 signature (64 bytes, R||s per eddsa_hedge.go).
//   - pqSig   — the ML-DSA-65 signature (3309 bytes per pq_mldsa.go).
//   - ctx     — the context string (FIPS 204 domain separation; the SAME ctx
//     the PQ sign used — the classical Ed25519 seam ignores ctx, the PQ seam
//     requires it match).
//
// The function is allocation-free on the reject path (the classical verify is
// the cheap gate; the PQ verify runs only if the classical passed — short-
// circuit AND). The 73.7µs PQ verify (the 4c bench) runs ONLY after the ~60µs
// classical verify passes — the hybrid cost is the SUM, recorded HONESTLY per-
// op (NOT amortized; the Day-25 class). On the accept path BOTH verify; on
// either reject the frame is dropped (the receiver's DropVerify verdict).
func VerifyCRDTFrame_Hybrid(edPub ed25519.PublicKey, pqPub *mldsa.PublicKey, msg, edSig, pqSig []byte, ctx string) bool {
	// (1) CLASSICAL — the cheap gate first (short-circuit AND: a classical
	// reject skips the PQ verify entirely). VerifyCRDTFrame is the circl
	// Ed25519 check + the RejectSmallOrderKey cofactor gate (verify.go:68).
	if !VerifyCRDTFrame(edPub, msg, edSig) {
		return false
	}
	// (2) PQ — the ML-DSA-65 check. A nil PQ key is a hard reject (the hybrid
	// contract is BOTH; a frame with no PQ key is a classical-only frame the
	// hybrid verifier rejects — the STRICT mode). The PQ seam takes a [120]byte
	// frame; bridge the []byte msg to the fixed array (reject if the msg is
	// not the 120-byte CRDT-frame delta the seam signs).
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

// hybridFrameSize is the 120-byte CRDT-frame delta the ML-DSA-65 seam signs
// (the ADR-10 CRDTEntry shape; the SAME 120 the pqecobench frame factory
// mints + the SignCRDTFrame_PostQuantum frame [120]byte param). The hybrid
// verify bridges the []byte classical seam to the [120]byte PQ seam via this
// constant; a msg whose length is NOT 120 is a frame-shape mismatch the hybrid
// verify rejects (the classical seam tolerates any length, the PQ seam does
// not — the hybrid honors the STRICTER of the two).
const hybridFrameSize = 120
