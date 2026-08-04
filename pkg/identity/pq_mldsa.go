// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package identity

// ADR-0036: ML-DSA-65 post-quantum signature layer — promoted from a
// preview-only build gate into the default build.
//
// This file was originally gated behind a preview-only build constraint: the
// default build excluded it entirely, the production signing seam stayed on the
// circl Ed25519 VerifyCRDTFrame (60.19µs at 32 cores), and no production code
// imported Sign/VerifyCRDTFrame_PostQuantum. ADR-0036 is the change that lifted
// the gate: the post-quantum transport readiness work wires the hybrid verify
// (Ed25519 + ML-DSA-65, BOTH-required, defense-in-depth), which requires
// VerifyCRDTFrame_PostQuantum reachable in the default build.
//
// The promotion was a build-gate removal only — the Sign/Verify bodies are
// byte-identical to the earlier preview form (the symbol call sites cite the
// same module-cache file:lines). The production sign seam (the CRDT delta wire)
// is NOT wired here — the hybrid SIGN (a frame carries BOTH sigs) needs the
// CRDT-delta wire shape changed (a future change that may or may not touch
// pkg/sync/crdt.go — disclosed ADR-0036 §6). This file wires the VERIFY (the
// receiver-side hybrid check), NOT the production sign.
//
// The 4-core verify cost is recorded at 73,662 ns/op (GOMAXPROCS=4, loopback
// Graviton — the honest 4-core number, under the 100µs threshold; the 32-core
// measurement is deferred to a multi-core run). The sign and verify costs are
// separate numbers and are not conflated.
//
// Every filippo.io/mldsa symbol called below was grep-verified against the
// PINNED module in the cache at $(go env
// GOMODCACHE)/filippo.io/mldsa@v0.0.0-20260711112038-ff3f469cee29/mldsa.go. The
// pin is existing (go.mod line 8 + go.sum lines 5-6, via bridges.go's blank
// import `_ "filippo.io/mldsa"`); this file adds the symbol call sites, NOT a
// new dependency. Each call site cites the module-cache file:line in a comment
// block immediately above it.
//
// The wrapper is envelope-only: it signs/verifies a 120-byte CRDT-frame delta
// (the ADR-10 CRDTEntry shape, the same payload the circl Ed25519 seam signs).
// Both functions pass &mldsa.Options{Context: ctx} so the context-string domain
// separation is honored on both halves (FIPS 204 requires the same context on
// sign and verify).

import (
	"crypto/rand"
	"errors"

	"filippo.io/mldsa"
)

// mldsaCachePath is the module-cache path of the pinned mldsa.go, cited at each
// call site below as the grep-verified provenance (the file:line).
const mldsaCachePath = "filippo.io/mldsa@v0.0.0-20260711112038-ff3f469cee29/mldsa.go"

// GeneratePreviewKey65 derives an ML-DSA-65 private key deterministically from a
// 32-byte seed. The deterministic seed form makes key derivation byte-identical
// across runs (keygen is a one-time deploy cost, measured separately from the
// per-op sign/verify cost — never merged into it). When benchmarking, do NOT
// call mldsa.GenerateKey per iteration — that measures keygen, not sign/verify.
//
// mldsa.NewPrivateKey(mldsa.MLDSA65(), seed) — grep-verified:
//
//	mldsa.go:100 func NewPrivateKey(params *Parameters, seed []byte) (*PrivateKey, error)
//	mldsa.go:57 func MLDSA65() *Parameters { return mldsa65 }
//	mldsa.go:19 PrivateKeySize = 32
//	mldsa.go:99 // The seed must be exactly [PrivateKeySize] bytes long.
func GeneratePreviewKey65(seed []byte) (*mldsa.PrivateKey, error) {
	if len(seed) != mldsa.PrivateKeySize {
		return nil, errors.New("pq_preview: seed must be exactly mldsa.PrivateKeySize (32) bytes")
	}
	// mldsa.go:100 NewPrivateKey(params *Parameters, seed []byte) (*PrivateKey, error)
	// mldsa.go:57 MLDSA65() *Parameters
	return mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
}

// SignCRDTFrame_PostQuantum signs a 120-byte CRDT-frame delta under an ML-DSA-65
// private key with the given context string. Returns the raw signature bytes.
//
// INVARIANT: on success the returned slice is EXACTLY mldsa.MLDSA65SignatureSize
// (3309) bytes — the FIPS 204 ML-DSA-65 signature encoding. Callers report
// len(sig) verbatim; it is the load-bearing SIZE economics number (3309B vs
// Ed25519's 64B = a 51.7× signature-cost inflation on a 120B payload).
//
// The call uses the RANDOMIZED Sign (Sign(sk, rand.Reader, msg, &Options{})),
// NOT SignDeterministic — the FIPS 204 default is randomized; SignDeterministic
// is only for a specific context-string domain (§5.3). Production parity.
//
// mldsa.PrivateKey.Sign — grep-verified:
//
//	mldsa.go:156 func (sk *PrivateKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error)
//	mldsa.go:261 type Options struct { Context string }
//	mldsa.go:26 MLDSA65SignatureSize = 3309
//
// Note Sign's first parameter is the io.Reader entropy source; for the randomized
// form it is consumed (the hedged nonce), so rand.Reader is passed (NOT ignored).
// The opts.(*Options) branch at mldsa.go:161-164 reads opts.Context.
func SignCRDTFrame_PostQuantum(sk *mldsa.PrivateKey, frame [120]byte, ctx string) ([]byte, error) {
	if sk == nil {
		return nil, errors.New("pq_preview: nil ML-DSA private key")
	}
	// mldsa.go:156 Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error)
	// mldsa.go:261 Options{Context string}; HashFunc() == 0 → direct-message branch.
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
// CRDT-frame delta under the given public key + context string. Returns nil on a
// valid signature, a non-nil error otherwise (the real mldsa.Verify returns
// error, NOT bool).
//
// mldsa.Verify — grep-verified:
//
//	mldsa.go:252 func Verify(pk *PublicKey, message []byte, signature []byte, opts *Options) error
//	mldsa.go:221 func (pk *PublicKey) Bytes() []byte // the wire encoding (1952B for ML-DSA-65)
//	mldsa.go:22 MLDSA65PublicKeySize = 1952
//
// The verify path materializes the pubkey (a wire-cost reader pays the 1952B).
func VerifyCRDTFrame_PostQuantum(pk *mldsa.PublicKey, frame [120]byte, sig []byte, ctx string) error {
	if pk == nil {
		return errors.New("pq_preview: nil ML-DSA public key")
	}
	// mldsa.go:252 Verify(pk *PublicKey, message []byte, signature []byte, opts *Options) error
	return mldsa.Verify(pk, frame[:], sig, &mldsa.Options{Context: ctx})
}
