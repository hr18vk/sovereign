//go:build !aws_lc_hedged

package identity

import (
	"crypto/rand"
	"testing"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// BenchmarkSignCRDTFrame_Hedged_4c measures the per-Sign cost of the
// hedged (randomized-nonce) EdDSA signing on a 120-byte CRDT delta frame.
// GEAR TAG (HONEST): GOMAXPROCS=4, CPU part 0xd40 (Cortex-A76-class,
// Graviton3-era). This is the _4c measurement per S3. The 32c re-run
// is PENDING Track 4 Karpenter c8g provisioning. Do NOT relabel.
//
// The bench is sequential (for i := 0; i < b.N; i++) because
// GOMAXPROCS=4 already provides the target parallelism; b.RunParallel
// would confound the per-op ns reading. The published number is the
// single-thread per-Sign cost at GOMAXPROCS=4.
func BenchmarkSignCRDTFrame_Hedged_4c(b *testing.B) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 120) // 120-byte CRDT delta frame per §2.X2
	b.ReportAllocs()
	b.SetBytes(int64(len(msg) + ed25519.SignatureSize + ed25519.SeedSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignCRDTFrame(seed, msg)
	}
}

// BenchmarkSignCRDTFrame_Deterministic_4c measures the per-Sign cost of
// the deterministic circl.Sign (control) on a 120-byte CRDT delta frame.
// GEAR TAG (HONEST): GOMAXPROCS=4, CPU part 0xd40. This is the control
// measurement for the hedged overhead comparison.
func BenchmarkSignCRDTFrame_Deterministic_4c(b *testing.B) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		b.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	msg := make([]byte, 120) // 120-byte CRDT delta frame per §2.X2
	b.ReportAllocs()
	b.SetBytes(int64(len(msg) + ed25519.SignatureSize + ed25519.SeedSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(priv, msg)
	}
}
