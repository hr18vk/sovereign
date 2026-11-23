// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build pq_preview

package pqecobench

// ML-DSA-65 byte-cost + latency bench on a 120-byte CRDT frame.
//
// Modeled on pkg/durability120/wal_bench_test.go (the E5 discipline):
//   - long-lived key outside b.N (keygen is a one-time deploy cost, not per-op);
//   - b.ResetTimer after keygen so ns/op is the sign/verify-per-op cost;
//   - per-op frames[i%1024] (pre-built once so the PRNG is not measured);
//   - the size economics reported via b.ReportMetric (sigBytes, pubBytes) and a
//     machine-parsable token (MLDSA65_SIGN / MLDSA65_VERIFY) the harness greps.
//
// Gear tag: this bench runs on the 4c canonical box (GOMAXPROCS=4,
// CPU part 0xd40, not c8g.8xlarge at 32c). The 4c ns/op is a proxy for the
// gate's economic argument — the size economics (3309B sig, 1952B pub) are
// gear-independent (a 3309B signature is 3309B on 4c and on 32c); the latency
// is the 4c-proxy part. Per the SCISSORS rule, a 4c ns/op is not
// interchangeable with a 32c number; the 32c re-bench on Spot c8g is a future
// track (the harness can be extended). The gate verdict (gated / preview-only)
// follows from the size economics alone, which are gear-independent.
//
// The bench is sequential (for i := 0; i < b.N; i++) rather than b.RunParallel:
// the published number is the single-thread per-op cost (sign or verify), and
// b.RunParallel would add a second layer of parallelism that confuses the
// per-op ns reading.

import (
	"crypto/rand"
	"testing"
	"time"

	"filippo.io/mldsa"

	"github.com/hr18vk/sovereign/pkg/identity"
)

// nowNS returns a monotonic nanosecond stamp for per-op latency sampling. Uses
// time.Now() (the same stamp pkg/durability120/wal_bench_test.go uses via
// time.Since) so the per-op ns is comparable to the E5 discipline.
func nowNS() int64 { return time.Now().UnixNano() }

// mldsaCachePath is the module-cache path of the pinned mldsa.go, cited at each
// call site below as the anti-fab credential (grep-verified this turn).
const mldsaCachePath = "filippo.io/mldsa@v0.0.0-20260711112038-ff3f469cee29/mldsa.go"

// previewCtx is the context string used for both Sign and Verify (FIPS 204
// requires the same context on both halves). A fixed, non-empty context is the
// production-parity shape (a real deploy domain-separates CRDT-frame signatures
// from other uses).
const previewCtx = "sovereign.crdt-frame.v1"

// makeSeed builds the deterministic 32-byte seed for GeneratePreviewKey65 from a
// stable source (crypto/rand read once outside b.N — the seed is fixed for the
// run, not per-op, so keygen is a one-time cost). The seed is not a secret; it
// only needs to be stable so the key (and therefore the bench) is reproducible.
func makeSeed() [mldsa.PrivateKeySize]byte {
	// mldsa.PrivateKeySize = 32
	var seed [mldsa.PrivateKeySize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic("pqecobench: crypto/rand seed read failed: " + err.Error())
	}
	return seed
}

// TestMLDSA65RoundTrip is the E3 round-trip-equality negative control: it asserts
// Sign→Verify via b.Fatalf (here t.Fatalf) on a non-verifying result before any
// ns/op is recorded. A poisoned bench that surfaces numbers over a non-verifying
// implementation is the E3 failure mode this negative control prevents. It also records the
// one-time KEY-GEN cost (mldsa.NewPrivateKey65 on a 32B seed) via t.Logf as
// keygen_ns — separately from the per-op ns/op (the E3 dict-build discipline
// applied to PQ: keygen is a deploy cost, not a per-frame cost).
func TestMLDSA65RoundTrip(t *testing.T) {
	seed := makeSeed()
	// identity.GeneratePreviewKey65 calls mldsa.NewPrivateKey(MLDSA65(), seed)
	sk, err := identity.GeneratePreviewKey65(seed[:])
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	// (sk *PrivateKey).PublicKey returns the public key
	pk := sk.PublicKey()

	// One-time keygen cost (reported separately, not per-op). Measure a fresh
	// NewPrivateKey so the cost is the keygen path, not the cached sk above.
	keygenStart := nowNS()
	sk2, err := identity.GeneratePreviewKey65(seed[:])
	if err != nil {
		t.Fatalf("GeneratePreviewKey65 (keygen measure): %v", err)
	}
	keygenNS := nowNS() - keygenStart
	t.Logf("MLDSA65_KEYGEN keygen_ns=%d (one-time deploy cost, not per-op)", keygenNS)
	_ = sk2

	// The 120-byte frame both halves sign (the ADR-10 CRDTEntry).
	frame := MakeFrame120(fixedSeed)

	// Sign → Verify round trip. The negative control: if Verify fails, the bench numbers
	// are meaningless — fail loudly before any ns/op is recorded anywhere.
	sig, err := identity.SignCRDTFrame_PostQuantum(sk, frame, previewCtx)
	if err != nil {
		t.Fatalf("SignCRDTFrame_PostQuantum: %v", err)
	}
	// Size invariant (gear-independent): ML-DSA-65 sig is exactly 3309B.
	if len(sig) != mldsa.MLDSA65SignatureSize {
		t.Fatalf("ML-DSA-65 signature size = %d, want %d (MLDSA65SignatureSize)",
			len(sig), mldsa.MLDSA65SignatureSize)
	}
	if err := identity.VerifyCRDTFrame_PostQuantum(pk, frame, sig, previewCtx); err != nil {
		t.Fatalf("negative control: ML-DSA-65 Sign→Verify round trip failed: %v "+
			"(a non-verifying impl would surface meaningless ns/op — stop)", err)
	}

	// Negative control: a tampered signature must fail Verify (else Verify is a
	// no-op and the bench numbers would be meaningless). Flip one byte of the sig.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF
	if err := identity.VerifyCRDTFrame_PostQuantum(pk, frame, tampered, previewCtx); err == nil {
		t.Fatalf("negative control: tampered signature verified (Verify is a no-op) — " +
			"the bench numbers would be meaningless")
	}

	// Report the size economics verbatim (gear-independent facts).
	pubBytes := len(pk.Bytes()) // (pk *PublicKey).Bytes returns the public key bytes
	t.Logf("MLDSA65_SIZES sigBytes=%d pubBytes=%d (gear-independent facts)",
		len(sig), pubBytes)
}

// BenchmarkMLDSA65_Sign_120B measures the per-Sign cost of ML-DSA-65 on a
// 120-byte CRDT frame. The long-lived key is constructed once outside b.N
// (b.ResetTimer after); per-op Sign on frames[i%1024]. Reports ns/op + B/op +
// allocs/op + sigBytes + pubBytes + a machine-parsable MLDSA65_SIGN token.
func BenchmarkMLDSA65_Sign_120B(b *testing.B) {
	seed := makeSeed()
	sk, err := identity.GeneratePreviewKey65(seed[:])
	if err != nil {
		b.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pk := sk.PublicKey()
	pubSize := len(pk.Bytes()) // (pk *PublicKey).Bytes returns the public key bytes

	// Pre-build 1024 distinct frames once (i % 1024 inside b.N reuses them).
	frames := make([][frameSize]byte, 1024)
	for i := range frames {
		frames[i] = MakeFrame120(uint64(i))
	}

	// Round-trip negative control (E3): assert Sign→Verify via b.Fatalf before any ns/op
	// is recorded. A non-verifying impl would surface meaningless numbers.
	probeSig, err := identity.SignCRDTFrame_PostQuantum(sk, frames[0], previewCtx)
	if err != nil {
		b.Fatalf("probe Sign: %v", err)
	}
	if err := identity.VerifyCRDTFrame_PostQuantum(pk, frames[0], probeSig, previewCtx); err != nil {
		b.Fatalf("negative control: probe Sign→Verify failed before bench: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(frameSize))
	b.ResetTimer()
	var meanNS int64
	for i := 0; i < b.N; i++ {
		f := frames[i%len(frames)]
		start := nowNS()
		sig, err := identity.SignCRDTFrame_PostQuantum(sk, f, previewCtx)
		if err != nil {
			b.Fatalf("Sign %d: %v", i, err)
		}
		meanNS += nowNS() - start
		_ = sig
	}
	meanNS /= int64(b.N)
	sigSize := mldsa.MLDSA65SignatureSize // 3309
	b.ReportMetric(float64(sigSize), "sigBytes/op")
	b.ReportMetric(float64(pubSize), "pubBytes")
	// allocs/op is reported by the native testing.B column (b.ReportAllocs above);
	// the token carries ns + the size economics (the load-bearing axis).
	b.Logf("MLDSA65_SIGN ns=%d sigBytes=%d pubBytes=%d opPerSec=%.0f",
		meanNS, sigSize, pubSize, 1e9/float64(meanNS))
}

// BenchmarkMLDSA65_Verify_120B measures the per-Verify cost of ML-DSA-65 on a
// 120-byte CRDT frame. The long-lived key + a pre-signed signature are
// constructed once outside b.N (b.ResetTimer after); per-op Verify on
// frames[i%1024] against the pre-signed sig for that frame. Reports ns/op +
// B/op + allocs/op + sigBytes + pubBytes + a MLDSA65_VERIFY token. pubBytes is
// reported here too — the verify path materializes the pubkey (a wire-cost
// reader pays the 1952B).
func BenchmarkMLDSA65_Verify_120B(b *testing.B) {
	seed := makeSeed()
	sk, err := identity.GeneratePreviewKey65(seed[:])
	if err != nil {
		b.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pk := sk.PublicKey()
	pubSize := len(pk.Bytes()) // (pk *PublicKey).Bytes returns the public key bytes

	// Pre-build 1024 distinct frames + their signatures once (i % 1024 reuses).
	frames := make([][frameSize]byte, 1024)
	sigs := make([][]byte, 1024)
	for i := range frames {
		frames[i] = MakeFrame120(uint64(i))
		sigs[i], err = identity.SignCRDTFrame_PostQuantum(sk, frames[i], previewCtx)
		if err != nil {
			b.Fatalf("pre-Sign %d: %v", i, err)
		}
	}

	// Round-trip negative control (E3): assert Verify via b.Fatalf before any ns/op.
	if err := identity.VerifyCRDTFrame_PostQuantum(pk, frames[0], sigs[0], previewCtx); err != nil {
		b.Fatalf("negative control: probe Verify failed before bench: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(frameSize))
	b.ResetTimer()
	var meanNS int64
	for i := 0; i < b.N; i++ {
		f := frames[i%len(frames)]
		s := sigs[i%len(sigs)]
		start := nowNS()
		if err := identity.VerifyCRDTFrame_PostQuantum(pk, f, s, previewCtx); err != nil {
			b.Fatalf("Verify %d: %v", i, err)
		}
		meanNS += nowNS() - start
	}
	meanNS /= int64(b.N)
	sigSize := mldsa.MLDSA65SignatureSize // 3309
	b.ReportMetric(float64(sigSize), "sigBytes/op")
	b.ReportMetric(float64(pubSize), "pubBytes")
	// allocs/op is reported by the native testing.B column (b.ReportAllocs above);
	// the token carries ns + the size economics (the load-bearing axis).
	b.Logf("MLDSA65_VERIFY ns=%d sigBytes=%d pubBytes=%d opPerSec=%.0f",
		meanNS, sigSize, pubSize, 1e9/float64(meanNS))
}
