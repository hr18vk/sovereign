// Package identity is the cryptographic identity layer of the Supremum
// Engine's CRDT synchronization substrate. It owns the Ed25519 verification
// bridge that every inbound CRDT delta frame crosses before admission, and
// it inventories the three cryptographic bridges the Phase 3 roadmap pins
// for the cross-host provenance path.
//
// # ZIP-215 stance (Subphase 1.1, Fork-1.b)
//
// The standard library's crypto/ed25519 is banned for CRDT verification
// (PHASE3_READINESS_AUDIT.md §1: small-order torsion malleability). The
// bridge uses github.com/cloudflare/circl/sign/ed25519 v1.6.4, which is
// RFC-8032 strict: it enforces canonical-Y (circl@v1.6.4/sign/ed25519/
// point.go:54 FromBytes) and canonical-S (circl@v1.6.4/sign/ed25519/
// ed25519.go:325 isLessThanOrder). circl does NOT perform a cofactor-8 /
// small-order public-key rejection — its SchemeID enum (ed25519.go:86-92)
// exposes only ED25519, ED25519Ph, ED25519Ctx, none of which add a cofactor
// check. circl is therefore RFC-8032 strict but NOT drop-in ZIP-215.
//
// VerifyCRDTFrame closes the ZIP-215 gap by composing two checks:
//
//  1. RejectSmallOrderKey (filippo.io/edwards25519 v1.2.0) — decodes the
//     public key as a curve point (rejecting non-curve encodings) and
//     rejects small-order keys where [8]P == identity. This is the
//     cofactor-8 / small-order gate.
//  2. circl/sign/ed25519.Verify — the RFC-8032 strict signature check
//     (canonical-Y, canonical-S, valid signature).
//
// The cofactor check runs FIRST: it is cheaper than the signature check
// and rejects small-order keys without computing the verification
// equation. filippo.io/edwards25519.Point.SetBytes is strictly MORE
// permissive than circl.FromBytes on canonical-Y (per its doc: "accepts
// all non-canonical encodings of valid points"), so the cofactor wrapper
// is additive strictness — it cannot produce false negatives for
// legitimate keys. circl.Verify still rejects non-canonical-Y that
// edwards25519 accepts.
//
// # Bridge inventory (Subphase 1.0)
//
//   - github.com/cloudflare/circl v1.6.4 — Ed25519 RFC-8032 strict Verify.
//   - filippo.io/edwards25519 v1.2.0 — cofactor-8 / small-order rejection.
//   - filippo.io/mldsa (pseudo-version) — ML-DSA post-quantum fallback,
//     pinned for Subphase 1.3 (preview-only, build tag pq_preview). NOT
//     exercised this subphase.
//   - github.com/koblas/cedar-go v0.1.0 — Cedar authorization evaluation,
//     pinned for Subphase 1.4 (latency EXPERIMENT). NOT exercised this
//     subphase.
//   - github.com/awslabs/aws-lc v1.73.0 (C library) — CGO bridge scaffold
//     for Subphase 1.2 (hedged signing). The Go binding module
//     github.com/aws/aws-lc-go is repo-not-found; the bridge targets the
//     C library via #cgo directives. STUB only this subphase; real C
//     linkage lands in 1.2.
//
// # Out of scope this subphase
//
// Subphases 1.2 (hedged signing), 1.3 (ML-DSA fallback), 1.4 (cedar bench)
// are NOT started here. Each carries its own gate; do not introduce a
// hedged-signing or ML-DSA claim without a go-doc-proven call site.
package identity
