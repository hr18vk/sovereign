// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build !aws_lc_hedged

// eddsa_hedge.go implements randomized-nonce Ed25519 signing for CRDT delta
// frames using filippo.io/edwards25519 v1.2.0 so signatures verify under
// VerifyCRDTFrame (github.com/cloudflare/circl/sign/ed25519 v1.6.4).
//
// Because circl@v1.6.4/sign/ed25519 exposes deterministic signing only (Sign,
// SignPh, SignWithCtx), SignCRDTFrame constructs (R, s) directly:
//   r = SHA-512(rand || message) mod l  (64 bytes from crypto/rand)
//   R = r * B
//   k = SHA-512(R || A || message) mod l
//   s = r + k * a mod l
//
// Because r hashes only the 64 random bytes and message without the secret-key
// prefix, nonce unpredictability relies entirely on crypto/rand (getrandom on
// Linux); this is randomized-nonce Ed25519, not hedged against RNG failure.
// VerifyCRDTFrame computes the standard RFC 8032 check s*B == R + k*A, so the
// randomized signature verifies under circl.Verify without modification.
//
// Gated by !aws_lc_hedged so an alternative C-backed implementation can share
// the aws_lc_hedged build tag.

package identity

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// ErrHedgeSign is returned when randomized-nonce frame signing fails (for
// example, invalid seed length or crypto/rand failure).
var ErrHedgeSign = errors.New("identity: hedged sign failed")

// SignCRDTFrame produces a randomized-nonce Ed25519 signature over msg using
// the provided 32-byte RFC 8032 Ed25519 seed. The public key A = a*B and
// expanded scalar a = H(seed)[:32] (clamped) match circl's NewKeyFromSeed.
//
// Construction:
//  1. Read 64 random bytes from crypto/rand into rnd.
//  2. r = SHA-512(rnd || msg) mod l (Scalar.SetUniformBytes).
//  3. R = r * B (Point.ScalarBaseMult).
//  4. k = SHA-512(R || A || msg) mod l (Scalar.SetUniformBytes).
//  5. s = r + k * a mod l (Scalar.MultiplyAdd).
//  6. Encode R.Bytes() || s.Bytes() (64 bytes).
//
// Note that step 2 does not include the secret-key prefix, so security against
// nonce reuse depends on crypto/rand; it is not hedged against RNG failure.
// Returns a 64-byte signature or ErrHedgeSign on invalid input or RNG error.
func SignCRDTFrame(seed, msg []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrHedgeSign
	}

	// Derive the public key A using circl's RFC-8032 derivation.
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Decode the public key A to validate point encoding.
	A := new(edwards25519.Point)
	if _, err := A.SetBytes(pub); err != nil {
		return nil, ErrHedgeSign
	}

	// Step 1: Generate 64 random bytes for the randomized nonce.
	rnd := make([]byte, 64)
	if _, err := rand.Read(rnd); err != nil {
		return nil, ErrHedgeSign
	}

	// Step 2: r = SHA-512(rnd || msg) mod l.
	h := sha512.New()
	h.Write(rnd)
	h.Write(msg)
	rHash := h.Sum(nil)

	r := new(edwards25519.Scalar)
	if _, err := r.SetUniformBytes(rHash); err != nil {
		return nil, ErrHedgeSign
	}

	// Step 3: R = r * B
	R := new(edwards25519.Point).ScalarBaseMult(r)

	// Step 4: k = H(R || A || message) mod l
	h.Reset()
	RBytes := R.Bytes()
	h.Write(RBytes[:])
	h.Write(pub)
	h.Write(msg)
	kHash := h.Sum(nil)

	k := new(edwards25519.Scalar)
	if _, err := k.SetUniformBytes(kHash); err != nil {
		return nil, ErrHedgeSign
	}

	// Step 5: s = r + k * a  (mod l)
	// We need the secret scalar 'a' derived from the seed.
	// circl's PrivateKey.Seed() returns the original 32-byte seed.
	// The expanded secret scalar a is H(seed)[:32] with clamping.
	// We can derive it by using edwards25519.Scalar.SetBytesWithClamping
	// on the first 32 bytes of SHA-512(seed).
	seedHash := sha512.Sum512(seed)
	a := new(edwards25519.Scalar)
	if _, err := a.SetBytesWithClamping(seedHash[:32]); err != nil {
		return nil, ErrHedgeSign
	}

	// s = k * a + r  (mod l)
	s := new(edwards25519.Scalar).MultiplyAdd(k, a, r)

	// Step 6: Encode signature as R || s (64 bytes)
	sig := make([]byte, ed25519.SignatureSize)
	copy(sig[:32], RBytes[:])
	copy(sig[32:], s.Bytes())

	return sig, nil
}
