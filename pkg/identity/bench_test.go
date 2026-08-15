package identity

import (
	"crypto/rand"
	"testing"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// BenchmarkVerifyCRDTFrame_32c measures the per-Verify cost of the full
// ZIP-215 gate (cofactor-8 rejection via filippo.io/edwards25519 +
// RFC-8032 strict Verify via circl) on a 120-byte CRDT delta frame.
//
// GEAR TAG (HONEST): GOMAXPROCS=4, CPU part 0xd40 (Cortex-A76-class,
// Graviton3-era). This is NOT c8g.8xlarge at 32c. The function name
// retains the _32c suffix per the Phase 3 roadmap's naming convention
// (the TARGET gear for the published bar); the HONEST gear tag is this
// comment and the commit message. Do NOT relabel a 4c number as a 32c
// number. The 32c re-run is PENDING Track 4 Karpenter c8g provisioning.
//
// The bench is sequential (for i := 0; i < b.N; i++) rather than
// b.RunParallel because G1.1.n runs with -cpu=4, which already spawns
// 4 GOMAXPROCS workers; b.RunParallel would add a second layer of
// parallelism that confuses the per-op ns reading. The published
// number is the single-thread per-Verify cost at GOMAXPROCS=4.
//
// This number is the input to Subphase 6.2 (relay hop-count bound) and
// Subphase 3.2 (attribution envelope). It must be PROVEN, not estimated.
func BenchmarkVerifyCRDTFrame_32c(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 120) // 120-byte CRDT delta frame per §2.X2
	sig := ed25519.Sign(priv, msg)
	b.ReportAllocs()
	b.SetBytes(int64(len(msg) + len(sig) + len(pub)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyCRDTFrame(pub, msg, sig)
	}
}

// BenchmarkRejectSmallOrderKey_32c isolates the cofactor-8 / small-order
// rejection cost from the signature verification cost. This lets the
// commit message report the two components separately: the cofactor
// gate is the ADDITIVE ZIP-215 strictness over circl's bare Verify.
func BenchmarkRejectSmallOrderKey_32c(b *testing.B) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RejectSmallOrderKey(pub)
	}
}
