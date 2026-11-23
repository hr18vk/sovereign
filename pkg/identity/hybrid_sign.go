// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package identity

// Package identity provides the hybrid (Ed25519 + ML-DSA-65) signing API
// complementing VerifyCRDTFrame_Hybrid (ADR-0036, ADR-0037). Because
// VerifyCRDTFrame_Hybrid expects a 120-byte payload while CRDT-delta batch
// wires have variable length, HashBatchWireToFrame120 hashes batchWire to a
// deterministic 120-byte SHAKE256 pad so both signatures cover identical bytes
// while the receiver applies the verbatim batchWire.
//
// Why SHAKE256: SHA-512 outputs 64 bytes rather than 120 bytes, whereas
// SHAKE256 (golang.org/x/crypto/sha3) is a NIST FIPS 202 XOF that outputs
// 120 bytes directly.
//
// Contract:
//   - SignCRDTFrame_Hybrid(edSeed, pqSk, batchWire, ctx) -> edSig [64], pqSig [3309]
//     Both randomized-nonce Ed25519 (SignCRDTFrame) and ML-DSA-65
//     (SignCRDTFrame_PostQuantum) sign the 120-byte pad.
//   - VerifyBatchHybrid(edPub, pqPub, batchWire, edSig, pqSig, ctx) -> bool
//     Recomputes the pad and checks both signatures via VerifyCRDTFrame_Hybrid.
//
// Wire cost: 3,309 bytes per ML-DSA-65 signature (51.7x the 64-byte Ed25519
// signature) plus the 64-byte Ed25519 signature and verbatim batchWire. In
// pkg/pqecobench (GOMAXPROCS=4, 120 B payload), ML-DSA-65 signing measures
// ~585.8 us/op and verification measures ~73.7 us/op.

import (
	"errors"
	"fmt"

	"filippo.io/mldsa"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"golang.org/x/crypto/sha3"
)

// ErrHybridSignBadSeed is returned by SignCRDTFrame_Hybrid when the Ed25519
// seed is not 32 bytes (ed25519.SeedSize). It mirrors SignCRDTFrame's seed
// guard — a short or long seed cannot derive a valid Ed25519 keypair and
// must not silently truncate.
var ErrHybridSignBadSeed = errors.New("identity: hybrid sign Ed25519 seed is not 32 bytes")

// ErrHybridSignNilPQSk is returned when the ML-DSA-65 private key is nil. The
// hybrid contract requires both signatures; a nil PQ signer cannot produce
// the PQ half.
var ErrHybridSignNilPQSk = errors.New("identity: hybrid sign ML-DSA-65 private key is nil")

// ErrHybridSignNilBatchWire is returned when batchWire is empty. The pad of an
// empty wire is a constant; signing a constant is a no-op signature that
// covers no state — rejected pre-sign (the unsigned-batch negative-control
// test, sibling to envelope.go's zero-originSig rule and wire_v1.go's
// ErrBatchUnsigned).
var ErrHybridSignNilBatchWire = errors.New("identity: hybrid sign batch wire is empty")

// HashBatchWireToFrame120 returns the deterministic 120-byte SHAKE256 digest of
// batchWire signed and verified by SignCRDTFrame_Hybrid and VerifyBatchHybrid
// (ADR-0037). Using a single shared helper keeps signer and verifier aligned.
func HashBatchWireToFrame120(batchWire []byte) [hybridFrameSize]byte {
	s := sha3.NewShake256()
	s.Write(batchWire)
	var pad [hybridFrameSize]byte
	s.Read(pad[:])
	return pad
}

// SignCRDTFrame_Hybrid signs a CRDT-delta batch wire under both
// randomized-nonce Ed25519 and ML-DSA-65 (ADR-0037), returning the 64-byte
// Ed25519 signature and 3309-byte ML-DSA-65 signature over the 120-byte
// SHAKE256 pad of batchWire.
//
//   - edSeed    — 32-byte Ed25519 seed passed to SignCRDTFrame.
//   - pqSk      — ML-DSA-65 private key passed to SignCRDTFrame_PostQuantum.
//   - batchWire — marshaled CRDTDeltaBatch wire (must be non-empty).
//   - ctx       — FIPS 204 context string for ML-DSA-65 (ignored by Ed25519).
func SignCRDTFrame_Hybrid(edSeed []byte, pqSk *mldsa.PrivateKey, batchWire []byte, ctx string) (edSig [ed25519.SignatureSize]byte, pqSig [mldsa.MLDSA65SignatureSize]byte, err error) {
	if len(edSeed) != ed25519.SeedSize {
		return edSig, pqSig, ErrHybridSignBadSeed
	}
	if pqSk == nil {
		return edSig, pqSig, ErrHybridSignNilPQSk
	}
	if len(batchWire) == 0 {
		return edSig, pqSig, ErrHybridSignNilBatchWire
	}
	pad := HashBatchWireToFrame120(batchWire)

	// (1) Ed25519 randomized-nonce signature over the pad.
	edSigSlice, serr := SignCRDTFrame(edSeed, pad[:])
	if serr != nil {
		return edSig, pqSig, fmt.Errorf("identity: hybrid sign Ed25519: %w", serr)
	}
	copy(edSig[:], edSigSlice)

	// (2) ML-DSA-65 signature over the same [120]byte pad.
	pqSigSlice, qerr := SignCRDTFrame_PostQuantum(pqSk, pad, ctx)
	if qerr != nil {
		return edSig, pqSig, fmt.Errorf("identity: hybrid sign ML-DSA-65: %w", qerr)
	}
	copy(pqSig[:], pqSigSlice)
	return edSig, pqSig, nil
}

// VerifyBatchHybrid verifies a hybrid-signed CRDT-delta batch wire under both
// randomized-nonce Ed25519 and ML-DSA-65 by hashing batchWire to its 120-byte
// SHAKE256 pad and delegating to VerifyCRDTFrame_Hybrid.
func VerifyBatchHybrid(edPub ed25519.PublicKey, pqPub *mldsa.PublicKey, batchWire, edSig, pqSig []byte, ctx string) bool {
	if len(batchWire) == 0 {
		return false // an empty wire has no pad; a hybrid verifier rejects (the unsigned-batch negative-control test).
	}
	pad := HashBatchWireToFrame120(batchWire)
	return VerifyCRDTFrame_Hybrid(edPub, pqPub, pad[:], edSig, pqSig, ctx)
}
