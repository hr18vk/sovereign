// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package identity provides cryptographic frame signing, verification, and the
// origin key directory for the Sovereign Engine's CRDT synchronization layer.
// It owns the Ed25519 verification path crossed by inbound CRDT delta frames
// and the opt-in ML-DSA-65 hybrid signing and verification paths (ADR-0036,
// ADR-0037).
//
// # ZIP-215 stance
//
// The standard library's crypto/ed25519 is avoided for CRDT verification
// because of small-order torsion malleability. VerifyCRDTFrame uses
// github.com/cloudflare/circl/sign/ed25519 v1.6.4, which enforces canonical-Y
// and canonical-S, combined with explicit cofactor-8 rejection:
//
//  1. RejectSmallOrderKey (filippo.io/edwards25519 v1.2.0) — decodes the
//     public key as a curve point (rejecting non-curve encodings) and
//     rejects small-order keys where [8]P == identity.
//  2. circl/sign/ed25519.Verify — the RFC-8032 strict signature check
//     (canonical-Y, canonical-S, valid signature).
//
// The cofactor check runs first: it is cheaper than the signature check
// and rejects small-order keys without computing the verification
// equation. filippo.io/edwards25519.Point.SetBytes accepts non-canonical Y
// encodings, so RejectSmallOrderKey adds cofactor strictness while
// circl.Verify still enforces canonical-Y.
//
// # Cryptographic bridges
//
//   - github.com/cloudflare/circl v1.6.4 — Ed25519 RFC-8032 strict Verify.
//   - filippo.io/edwards25519 v1.2.0 — cofactor-8 / small-order rejection and
//     randomized-nonce Ed25519 signing (SignCRDTFrame).
//   - filippo.io/mldsa — ML-DSA-65 post-quantum signing and verification
//     (hybrid_sign.go, hybrid_verify.go, pq_mldsa.go; opt-in via
//     --hybrid-sign and --hybrid-verify).
//   - github.com/koblas/cedar-go v0.1.0 — referenced in bridges.go for the
//     build-tagged Cedar authorization benchmark in pkg/authorization.
//   - github.com/awslabs/aws-lc v1.73.0 — stub scaffold behind the
//     aws_lc_hedged build tag (aws_lc_hedged_stub.go).
package identity
