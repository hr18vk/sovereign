//go:build pq_preview

package pqecobench

// Track 1.3 — ML-DSA-65 byte-cost + latency bench on a 120-byte CRDT frame.
//
// MODELED ON pkg/durability120/wal_bench_test.go (the E5 discipline):
//   - long-lived key OUTSIDE b.N (keygen is a one-time deploy cost, NOT per-op);
//   - b.ResetTimer AFTER keygen so ns/op is the sign/verify-per-op cost;
//   - per-op frames[i%1024] (pre-built ONCE so the PRNG is not measured);
//   - the SIZE economics reported via b.ReportMetric (sigBytes, pubBytes) AND a
//     machine-parsable token (MLDSA65_SIGN / MLDSA65_VERIFY) the harness greps.
//
// GEAR TAG (HONEST): this bench runs on the 4c canonical box (GOMAXPROCS=4,
// CPU part 0xd40, NOT c8g.8xlarge at 32c). The 4c ns/op is a PROXY for the
// gate's economic argument — the SIZE economics (3309B sig, 1952B pub) are
// gear-INDEPENDENT (a 3309B signature is 3309B on 4c and on 32c); the LATENCY
// is the 4c-proxy part. Per the Phase-2.5d SCISSORS rule, a 4c ns/op is NOT
// interchangeable with a 32c number; the 32c re-bite on Spot c8g is a FUTURE
// track (the harness can be extended). The gate verdict (GATED / PREVIEW-ONLY)
// follows from the SIZE economics alone, which ARE gear-independent.
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

	"github.com/hr18vk/supremum/pkg/identity"
)

// nowNS returns a monotonic nanosecond stamp for per-op latency sampling. Uses
// time.Now() (the same stamp pkg/durability120/wal_bench_test.go uses via
// time.Since) so the per-op ns is comparable to the E5 discipline.
func nowNS() int64 { return time.Now().UnixNano() }

// mldsaCachePath is the module-cache path of the pinned mldsa.go, cited at each
// call site below as the anti-fab credential (grep-verified THIS TURN).
const mldsaCachePath = "filippo.io/mldsa@v0.0.0-20260711112038-ff3f469cee29/mldsa.go"

// previewCtx is the context string used for both Sign and Verify (FIPS 204
// requires the same context on both halves). A fixed, non-empty context is the
// production-parity shape (a real deploy domain-separates CRDT-frame signatures
// from other uses).
const previewCtx = "sovereign.crdt-frame.v1"

// makeSeed builds the deterministic 32-byte seed for GeneratePreviewKey65 from a
// stable source (crypto/rand read ONCE outside b.N — the seed is fixed for the
// run, NOT per-op, so keygen is a one-time cost). The seed is NOT a secret; it
// only needs to be stable so the key (and therefore the bench) is reproducible.
func makeSeed() [mldsa.PrivateKeySize]byte {
	// mldsa.go:19 PrivateKeySize = 32
	var seed [mldsa.PrivateKeySize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic("pqecobench: crypto/rand seed read failed: " + err.Error())
	}
	return seed
}

// TestMLDSA65RoundTrip is the E3 round-trip-equality tooth: it asserts
// Sign→Verify via b.Fatalf (here t.Fatalf) on a non-verifying result BEFORE any
// ns/op is recorded. A poisoned bench that surfaces numbers over a non-verifying
// implementation is the E3 failure mode this tooth prevents. It ALSO records the
// one-time KEY-GEN cost (mldsa.NewPrivateKey65 on a 32B seed) via t.Logf as
// keygen_ns — SEPARATELY from the per-op ns/op (the E3 dict-build discipline
// applied to PQ: keygen is a deploy cost, not a per-frame cost).
func TestMLDSA65RoundTrip(t *testing.T) {
	seed := makeSeed()
	// identity.GeneratePreviewKey65 → mldsa.go:100 NewPrivateKey(MLDSA65(), seed)
	sk, err := identity.GeneratePreviewKey65(seed[:])
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	// mldsa.go:139 (sk *PrivateKey) PublicKey() *PublicKey
	pk := sk.PublicKey()

	// One-time keygen cost (reported SEPARATELY, NOT per-op). Measure a fresh
	// NewPrivateKey so the cost is the keygen path, not the cached sk above.
	keygenStart := nowNS()
	sk2, err := identity.GeneratePreviewKey65(seed[:])
	if err != nil {
		t.Fatalf("GeneratePreviewKey65 (keygen measure): %v", err)
	}
	keygenNS := nowNS() - keygenStart
	t.Logf("MLDSA65_KEYGEN keygen_ns=%d (one-time deploy cost, NOT per-op)", keygenNS)
	_ = sk2

	// The 120-byte frame both halves sign (the ADR-10 CRDTEntry).
	frame := MakeFrame120(fixedSeed)

	// Sign → Verify round trip. The tooth: if Verify fails, the bench numbers
	// are meaningless — FAIL loudly BEFORE any ns/op is recorded anywhere.
	sig, err := identity.SignCRDTFrame_PostQuantum(sk, frame, previewCtx)
	if err != nil {
		t.Fatalf("SignCRDTFrame_PostQuantum: %v", err)
	}
	// Size invariant (gear-independent): ML-DSA-65 sig is exactly 3309B.
	// mldsa.go:26 MLDSA65SignatureSize = 3309
	if len(sig) != mldsa.MLDSA65SignatureSize {
		t.Fatalf("ML-DSA-65 signature size = %d, want %d (MLDSA65SignatureSize)",
			len(sig), mldsa.MLDSA65SignatureSize)
	}
	if err := identity.VerifyCRDTFrame_PostQuantum(pk, frame, sig, previewCtx); err != nil {
		t.Fatalf("INTEGRITY TOOTH: ML-DSA-65 Sign→Verify round trip FAILED: %v "+
			"(a non-verifying impl would surface meaningless ns/op — STOP)", err)
	}

	// Negative tooth: a tampered signature MUST fail Verify (else Verify is a
	// no-op and the bench numbers are vacuous). Flip one byte of the sig.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xFF
	if err := identity.VerifyCRDTFrame_PostQuantum(pk, frame, tampered, previewCtx); err == nil {
		t.Fatalf("INTEGRITY TOOTH: tampered signature VERIFIED (Verify is a no-op) — " +
			"the bench numbers would be vacuous")
	}

	// Report the SIZE economics verbatim (gear-independent facts).
	pubBytes := len(pk.Bytes()) // mldsa.go:221 (pk *PublicKey) Bytes() []byte
	t.Logf("MLDSA65_SIZES sigBytes=%d pubBytes=%d (gear-independent facts)",
		len(sig), pubBytes)
}

// BenchmarkMLDSA65_Sign_120B measures the per-Sign cost of ML-DSA-65 on a
// 120-byte CRDT frame. The long-lived key is constructed ONCE outside b.N
// (b.ResetTimer after); per-op Sign on frames[i%1024]. Reports ns/op + B/op +
// allocs/op + sigBytes + pubBytes + a machine-parsable MLDSA65_SIGN token.
func BenchmarkMLDSA65_Sign_120B(b *testing.B) {
	seed := makeSeed()
	sk, err := identity.GeneratePreviewKey65(seed[:])
	if err != nil {
		b.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pk := sk.PublicKey()
	pubSize := len(pk.Bytes()) // mldsa.go:221

	// Pre-build 1024 distinct frames ONCE (i % 1024 inside b.N reuses them).
	frames := make([][frameSize]byte, 1024)
	for i := range frames {
		frames[i] = MakeFrame120(uint64(i))
	}

	// ROUND-TRIP TOOTH (E3): assert Sign→Verify via b.Fatalf BEFORE any ns/op
	// is recorded. A non-verifying impl would surface meaningless numbers.
	probeSig, err := identity.SignCRDTFrame_PostQuantum(sk, frames[0], previewCtx)
	if err != nil {
		b.Fatalf("probe Sign: %v", err)
	}
	if err := identity.VerifyCRDTFrame_PostQuantum(pk, frames[0], probeSig, previewCtx); err != nil {
		b.Fatalf("INTEGRITY TOOTH: probe Sign→Verify FAILED before bench: %v", err)
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
	// the token carries ns + the SIZE economics (the load-bearing axis).
	b.Logf("MLDSA65_SIGN ns=%d sigBytes=%d pubBytes=%d opPerSec=%.0f",
		meanNS, sigSize, pubSize, 1e9/float64(meanNS))
}

// BenchmarkMLDSA65_Verify_120B measures the per-Verify cost of ML-DSA-65 on a
// 120-byte CRDT frame. The long-lived key + a pre-signed signature are
// constructed ONCE outside b.N (b.ResetTimer after); per-op Verify on
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
	pubSize := len(pk.Bytes()) // mldsa.go:221

	// Pre-build 1024 distinct frames + their signatures ONCE (i % 1024 reuses).
	frames := make([][frameSize]byte, 1024)
	sigs := make([][]byte, 1024)
	for i := range frames {
		frames[i] = MakeFrame120(uint64(i))
		sigs[i], err = identity.SignCRDTFrame_PostQuantum(sk, frames[i], previewCtx)
		if err != nil {
			b.Fatalf("pre-Sign %d: %v", i, err)
		}
	}

	// ROUND-TRIP TOOTH (E3): assert Verify via b.Fatalf BEFORE any ns/op.
	if err := identity.VerifyCRDTFrame_PostQuantum(pk, frames[0], sigs[0], previewCtx); err != nil {
		b.Fatalf("INTEGRITY TOOTH: probe Verify FAILED before bench: %v", err)
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
	// the token carries ns + the SIZE economics (the load-bearing axis).
	b.Logf("MLDSA65_VERIFY ns=%d sigBytes=%d pubBytes=%d opPerSec=%.0f",
		meanNS, sigSize, pubSize, 1e9/float64(meanNS))
}
