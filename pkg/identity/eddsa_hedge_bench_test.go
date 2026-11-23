// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build !aws_lc_hedged

package identity

import (
	"crypto/rand"
	"testing"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
)

// BenchmarkSignCRDTFrame_Hedged_4c measures the per-Sign cost of
// randomized-nonce Ed25519 signing on a 120-byte CRDT delta frame at
// GOMAXPROCS=4.
//
// The bench is sequential (for i := 0; i < b.N; i++) because b.RunParallel
// would confound the per-op ns reading.
func BenchmarkSignCRDTFrame_Hedged_4c(b *testing.B) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 120) // 120-byte CRDT delta frame
	b.ReportAllocs()
	b.SetBytes(int64(len(msg) + ed25519.SignatureSize + ed25519.SeedSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignCRDTFrame(seed, msg)
	}
}

// BenchmarkSignCRDTFrame_Deterministic_4c measures the per-Sign cost of
// deterministic circl.Sign on a 120-byte CRDT delta frame at GOMAXPROCS=4 for
// comparison with randomized-nonce signing.
func BenchmarkSignCRDTFrame_Deterministic_4c(b *testing.B) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		b.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	msg := make([]byte, 120) // 120-byte CRDT delta frame
	b.ReportAllocs()
	b.SetBytes(int64(len(msg) + ed25519.SignatureSize + ed25519.SeedSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(priv, msg)
	}
}
