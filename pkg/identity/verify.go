package identity

import (
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"filippo.io/edwards25519"
)

// RejectSmallOrderKey returns true if pub encodes a valid Ed25519 public
// key that is NOT a small-order (torsion) key. It rejects:
//
//   - wrong-length encodings (len(pub) != 32),
//   - non-curve / non-canonical encodings (edwards25519.Point.SetBytes
//     returns an error),
//   - small-order keys where [8]P == identity (the 8 torsion points of
//     order dividing 8).
//
// This is the ZIP-215 cofactor-8 / small-order gate that circl's
// RFC-8032-strict Verify does NOT perform. circl@v1.6.4/sign/ed25519/
// point.go:54 FromBytes enforces canonical-Y only; ed25519.go:325
// isLessThanOrder enforces canonical-S only. Neither rejects small-order
// public keys. This function closes that gap.
//
// edwards25519.Point.SetBytes is strictly MORE permissive than circl's
// FromBytes on canonical-Y (per its doc: "accepts all non-canonical
// encodings of valid points"), so this check is additive strictness —
// it cannot reject a key that circl would accept. The canonical-Y
// rejection is delegated to circl.Verify in VerifyCRDTFrame.
//
// arena-bound: per-call allocates ~3 *edwards25519.Point (the decoded P,
// the cofactor product, and the identity point for comparison). This is
// acceptable for the crypto-verify path (signature verification itself
// allocates far more); if Subphase 1.2 profiling demands sub-µs
// rejection, pool the Points in a sync.Pool.
func RejectSmallOrderKey(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	P, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return false
	}
	cofactor := new(edwards25519.Point).MultByCofactor(P)
	if cofactor.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	return true
}

// VerifyCRDTFrame asserts cryptographic provenance of a CRDT delta frame.
// It is the gate every inbound CRDT frame crosses before admission. It
// enforces full ZIP-215 compliance by composing two checks:
//
//  1. RejectSmallOrderKey — cofactor-8 / small-order rejection +
//     non-curve encoding gate (filippo.io/edwards25519).
//  2. ed25519.Verify — RFC-8032 strict signature check: canonical-Y,
//     canonical-S, valid signature (github.com/cloudflare/circl/sign/
//     ed25519).
//
// The cofactor check runs FIRST because it is cheaper than the signature
// check and rejects small-order keys without computing the verification
// equation. circl's Verify is the RFC-8032 strict path; it does NOT do
// cofactor-8 (verified by reading circl@v1.6.4/sign/ed25519/ed25519.go:
// 318-352 and point.go:54-88). This wrapper closes the ZIP-215 gap.
//
// Returns false for any malformed input, small-order key, non-canonical
// encoding, or invalid signature. Returns true only for a valid
// signature under a full-order public key.
func VerifyCRDTFrame(pub ed25519.PublicKey, msg, sig []byte) bool {
	if !RejectSmallOrderKey(pub) {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
