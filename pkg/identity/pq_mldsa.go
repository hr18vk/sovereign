// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package identity

// Package identity provides ML-DSA-65 post-quantum signature operations for
// CRDT frame provenance (ADR-0036). ML-DSA-65 is compiled in the default
// build (the pq_preview tag has been removed from this file so
// VerifyCRDTFrame_PostQuantum is available whenever --hybrid-sign or
// --hybrid-verify is enabled). The pqecobench benchmark package remains gated
// behind -tags pq_preview.
//
// Every filippo.io/mldsa symbol called below was verified against the pinned
// module in go.mod / go.sum. The functions sign and verify fixed 120-byte
// payloads (matching the ADR-0010 CRDTEntry size and HashBatchWireToFrame120
// pad) with &mldsa.Options{Context: ctx} domain separation.

import (
	"crypto/rand"
	"errors"

	"filippo.io/mldsa"
)

// mldsaCachePath is the module-cache path of the pinned mldsa.go, cited at each
// call site below as the grep-verified file and line.
const mldsaCachePath = "filippo.io/mldsa@v0.0.0-20260711112038-ff3f469cee29/mldsa.go"

// GeneratePreviewKey65 derives an ML-DSA-65 private key deterministically from a
// 32-byte seed. The deterministic seed form makes the benchmark byte-identical
// across runs (key generation is a one-time deploy cost, reported separately via
// t.Logf as keygen_ns, not merged into the per-op ns/op). Do not call
// mldsa.GenerateKey in the benchmark — that measures key generation, not
// sign/verify.
//
// mldsa.NewPrivateKey(mldsa.MLDSA65(), seed) — grep-verified:
//
//	mldsa.NewPrivateKey  func NewPrivateKey(params *Parameters, seed []byte) (*PrivateKey, error)
//	mldsa.MLDSA65        func MLDSA65() *Parameters { return mldsa65 }
//	mldsa.PrivateKeySize = 32
//	mldsa.NewPrivateKey  // The seed must be exactly [PrivateKeySize] bytes long.
func GeneratePreviewKey65(seed []byte) (*mldsa.PrivateKey, error) {
	if len(seed) != mldsa.PrivateKeySize {
		return nil, errors.New("pq_preview: seed must be exactly mldsa.PrivateKeySize (32) bytes")
	}
	// mldsa.NewPrivateKey  func NewPrivateKey(params *Parameters, seed []byte) (*PrivateKey, error)
	// mldsa.MLDSA65        func MLDSA65() *Parameters { return mldsa65 }
	return mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
}

// SignCRDTFrame_PostQuantum signs a 120-byte CRDT-frame delta under an ML-DSA-65
// private key with the given context string and returns the 3309-byte FIPS 204
// signature (51.7x the 64-byte Ed25519 signature size).
//
// Signing passes rand.Reader to sk.Sign to select the randomized FIPS 204
// construction with &Options{Context: ctx} domain separation.
func SignCRDTFrame_PostQuantum(sk *mldsa.PrivateKey, frame [120]byte, ctx string) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("pq_preview: nil ML-DSA private key")
	}
	// mldsa.PrivateKey.Sign  func (sk *PrivateKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error)
	// mldsa.Options          type Options struct { Context string }; HashFunc() == 0 → direct-message branch.
	sig, err := sk.Sign(rand.Reader, frame[:], &mldsa.Options{Context: ctx})
	if err != nil {
		return nil, err
	}
	// Size invariant (gear-independent fact): the ML-DSA-65 signature is exactly
	// 3309 bytes. Assert it so a silent upstream change surfaces loudly.
	if len(sig) != mldsa.MLDSA65SignatureSize {
		return nil, errors.New("pq_preview: ML-DSA-65 signature size drift (got non-3309B)")
	}
	return sig, nil
}

// VerifyCRDTFrame_PostQuantum verifies an ML-DSA-65 signature over a 120-byte
// CRDT-frame delta under the given public key and context string, returning nil
// on a valid signature or a non-nil error otherwise.
//
// ML-DSA-65 public keys serialize to 1952 bytes via pk.Bytes().
func VerifyCRDTFrame_PostQuantum(pk *mldsa.PublicKey, frame [120]byte, sig []byte, ctx string) error {
	if pk == nil {
		return errors.New("pq_preview: nil ML-DSA public key")
	}
	// mldsa.Verify  func Verify(pk *PublicKey, message []byte, signature []byte, opts *Options) error
	return mldsa.Verify(pk, frame[:], sig, &mldsa.Options{Context: ctx})
}
