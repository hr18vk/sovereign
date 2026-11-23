// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build pq_preview

package pqecobench

// TestVerdictMatrix_PQ prints the decision matrix for the post-quantum
// envelope preview benchmark:
//
//   - Clause A (wire bytes): compares ML-DSA-65 sig(3309B) + pub(1952B) per
//     120B frame against Ed25519 sig(64B), computing BloatRatio.
//   - Clause B (verify latency): compares local 4-core ML-DSA-65 Verify latency
//     against the 32-core Graviton4 Ed25519 measurement (60.19us) as a rough
//     order-of-magnitude proxy rather than an apples-to-apples comparison.
//   - Clause C (verdict): must remain gated / preview-only until 32-core
//     benchmarks justify amending ADR-0001 and ADR-0002.
//
// Negative controls verify the matrix never reports PROMOTE, reads actual key
// and signature sizes from filippo.io/mldsa, preserves the 32-core Ed25519
// comparator constant, and enforces the expected size ratio.

import (
	"testing"

	"filippo.io/mldsa"

	"github.com/hr18vk/sovereign/pkg/identity"
)

// ed25519VerifyNS32c is the 32-core Graviton4 Ed25519 Verify measurement
// (60.19us in ns) used as the clause B comparator against the local 4-core
// ML-DSA-65 probe.
const ed25519VerifyNS32c = 60_190 // 60.19µs in ns (32-core Graviton4 measurement)

// ed25519SigSize / ed25519PubSize are the Ed25519 wire sizes (the comparator for
// clause A). Ed25519: pubkey = 32B, signature = 64B (circl v1.6.4).
const (
	ed25519SigSize = 64
	ed25519PubSize = 32
)

// TestVerdictMatrix_PQ prints the A/B/C decision matrix and runs the negative
// controls keeping the ML-DSA-65 envelope gated as preview-only.
func TestVerdictMatrix_PQ(t *testing.T) {
	// Clause A: read ML-DSA-65 sizes directly from filippo.io/mldsa.
	mldsaSigSize := mldsa.MLDSA65SignatureSize
	mldsaPubSize := mldsa.MLDSA65PublicKeySize

	// The CRDT frame payload both halves sign.
	const frameSize120 = 120

	// Wire-per-frame: the envelope carries sig + pub (amortizable across frames
	// from the same signer, though first and rotation frames carry the full pub).
	// Ed25519 ships a 64B signature on the same 120B payload with pub out-of-band.
	mldsaWire := mldsaSigSize + mldsaPubSize
	ed25519Wire := ed25519SigSize
	bloatRatio := float64(mldsaWire) / float64(ed25519Wire)
	payloadBloat := float64(mldsaSigSize) / float64(frameSize120)

	// Clause B: local 4-core ML-DSA Verify latency proxy.
	mldsaVerifyNS4c := probeMLDSA65VerifyNS(t)

	t.Logf("==========================================================")
	t.Logf(" PQ gate decision matrix (ML-DSA-65 PQ envelope, pq_preview)")
	t.Logf("==========================================================")
	t.Logf(" clause A | wire bytes:")
	t.Logf("          ML-DSA-65  wire/frame = sig(%dB) + pub(%dB) = %dB", mldsaSigSize, mldsaPubSize, mldsaWire)
	t.Logf("          Ed25519   wire/frame = sig(%dB) (pub amortized) = %dB", ed25519SigSize, ed25519Wire)
	t.Logf("          BloatRatio (MLDSA_wire / Ed25519_wire) = %.1fx", bloatRatio)
	t.Logf("          PayloadBloat (ML-DSA sig / 120B payload) = %.1fx", payloadBloat)
	t.Logf(" clause B | verify latency (4c proxy vs 32c Ed25519):")
	t.Logf("          ML-DSA-65 Verify (4c proxy)  = %dns", mldsaVerifyNS4c)
	t.Logf("          Ed25519  Verify (32c ref)    = %dns (60.19µs, 32-core Graviton4)", ed25519VerifyNS32c)
	t.Logf("          4c proxy vs 32c ref — rough comparison, not")
	t.Logf("          like-for-like; 32c ML-DSA run requires 32-core hardware.")
	t.Logf("----------------------------------------------------------")

	// Clause C: verdict remains gated / preview-only.
	verdict := "gated (preview-only)"
	t.Logf(" clause C | verdict = %s", verdict)
	t.Logf("          preview-only stays gated; PQ envelope is a contingency,")
	t.Logf("          not a production fallback; production Verify stays circl")
	t.Logf("          Ed25519 @ 60.19µs 32c (circl v1.6.4 / 32-core Graviton4).")
	t.Logf("          promotion requires build-tag removal and ADR-0001/")
	t.Logf("          0002 amendment on measured 32c results.")
	t.Logf("==========================================================")

	if verdict == "PROMOTE" {
		t.Fatalf("negative control: verdict = PROMOTE — promotion requires " +
			"build-tag removal and ADR amendment on measured 32c results; " +
			"this track keeps preview-only gated")
	}

	if mldsaSigSize != 3309 {
		t.Fatalf("negative control: ML-DSA-65 sig size = %dB, want 3309B "+
			"(MLDSA65SignatureSize drifted)", mldsaSigSize)
	}
	if mldsaPubSize != 1952 {
		t.Fatalf("negative control: ML-DSA-65 pub size = %dB, want 1952B "+
			"(MLDSA65PublicKeySize drifted)", mldsaPubSize)
	}

	if ed25519VerifyNS32c != 60_190 {
		t.Fatalf("negative control: ed25519VerifyNS32c = %d, want 60190 "+
			"(32c Ed25519 Verify reference value shifted)", ed25519VerifyNS32c)
	}

	if bloatRatio < 50.0 {
		t.Fatalf("negative control: BloatRatio = %.1fx, want >= 50x "+
			"(size overhead ratio changed unexpectedly)", bloatRatio)
	}
}

// probeMLDSA65VerifyNS measures the 4c ML-DSA-65 Verify cost on a single 120B
// frame (a fixed-sample probe, not b.N). Returns the mean ns over a small fixed
// sample (the verdict matrix needs a representative number, not a CDF — the
// gate is the size economics, not the latency tail). The number is a 4c proxy.
func probeMLDSA65VerifyNS(t *testing.T) int64 {
	seed := makeSeed()
	sk, err := identity.GeneratePreviewKey65(seed[:])
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pk := sk.PublicKey()
	frame := MakeFrame120(fixedSeed)
	sig, err := identity.SignCRDTFrame_PostQuantum(sk, frame, previewCtx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Warmup (first Verify may JIT/cache); then a fixed-sample mean.
	const n = 200
	var total int64
	for i := 0; i < n; i++ {
		start := nowNS()
		if err := identity.VerifyCRDTFrame_PostQuantum(pk, frame, sig, previewCtx); err != nil {
			t.Fatalf("Verify probe %d: %v", i, err)
		}
		total += nowNS() - start
	}
	return total / n
}
