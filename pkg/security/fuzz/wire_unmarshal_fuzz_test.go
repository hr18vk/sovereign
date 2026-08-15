package fuzz

import (
	"testing"

	"github.com/hr18vk/supremum/pkg/attribution"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// wire_unmarshal_fuzz_test.go is Edit B — FIVE targeted fuzzes, one per
// ingest-path unmarshaler, each asserting the M3 no-panic oracle INDEPENDENTLY.
// A dispatch fuzz (Edit A) could route a malformed Batch magic to the RELAY arm
// (the default) and MISS a Batch-specific crash; the per-unmarshaler fuzzes
// close that hole by driving EACH unmarshaler directly with its own seed corpus
// (the arm-level coverage the prompt's M4 mandates).
//
// Each target's f.Add(...) pulls from the matching seeds_test.go builder (the
// single-source-of-truth corpus) so the in-process seeds AND the committed
// testdata/fuzz/ files stay in lock-step (the SeedCorpusIsValid tooth re-derives
// both from the same builders). Each f.Fuzz asserts ONLY that the unmarshaler
// returns (T, error) without panic — the verdict-value / semantic-correctness
// property is the round-trip teeth's job (TestEnvelope_MarshalRoundTrip et al.),
// NOT this harness's (M3).
//
// Run a single target:
//
//	go test -run='^$' -fuzz=FuzzUnmarshalIBLT -fuzztime=60s ./pkg/security/fuzz/

// FuzzUnmarshalRelayEnvelope drives attribution.UnmarshalRelayEnvelope with the
// relay-arm seed corpus (a valid v3 + a v2 forward-compat + a length-bomb + the
// tiny shapes). UnmarshalRelayEnvelope is FROZEN-adjacent (envelope.go:550,
// convention-frozen NOT md5-pinned) — a panic found here is a THIS-fork fix
// (NOT a streak-breaker per M5; only crdt.go / crdt_apply.go / the 2 capnp
// schema files are the streak-breaker-class md5-FROZEN set).
func FuzzUnmarshalRelayEnvelope(f *testing.F) {
	for _, seed := range relaySeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = attribution.UnmarshalRelayEnvelope(wire)
	})
}

// FuzzUnmarshalBatchEnvelope drives attribution.UnmarshalBatchEnvelope with the
// batch-arm seed corpus. The batch unmarshaler is a pure O(1) header parse
// (length-check → magic → version → fixed-offset copy) — the length-bomb class
// does NOT apply (the header is fixed-size; no wire-field-sized alloc). The fuzz
// exercises the short-header + magic-mismatch + version-mismatch + unsigned-sig
// reject branches.
func FuzzUnmarshalBatchEnvelope(f *testing.F) {
	for _, seed := range batchSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = attribution.UnmarshalBatchEnvelope(wire)
	})
}

// FuzzUnmarshalHybridFrame drives attribution.UnmarshalHybridFrame with the
// hybrid-arm seed corpus. The hybrid unmarshaler is a pure O(1) header parse
// (sibling to the batch, grown by the [3309] pqSig slot) — the length-bomb
// class does NOT apply. The fuzz exercises the short-header + magic + version +
// unsigned-edSig + unsigned-pqSig reject branches.
func FuzzUnmarshalHybridFrame(f *testing.F) {
	for _, seed := range hybridSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = attribution.UnmarshalHybridFrame(wire)
	})
}

// FuzzUnmarshalStrataEstimator drives sync.UnmarshalStrataEstimator with the
// digest-arm SE seed corpus. The SE unmarshaler reads a fixed 13-byte header
// then a 32-iteration per-stratum UnmarshalIBLT loop — the per-stratum loop is
// the crash surface (a malformed stratum IBLT propagates an ErrMalformedStrata,
// NOT a panic, on a well-guarded path). The fuzz exercises the short-header +
// magic + wrong-strataCount + per-stratum-failure reject branches.
func FuzzUnmarshalStrataEstimator(f *testing.F) {
	for _, seed := range strataSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = eng.UnmarshalStrataEstimator(wire)
	})
}

// FuzzUnmarshalIBLT drives sync.UnmarshalIBLT with the IBLT seed corpus — the
// HIGHEST-YIELD arm per the prompt (the count × bucket unbounded-alloc surface).
// The IBLT unmarshaler casts a wire uint32 numBuckets to int (iblt_wire.go:269)
// then guards `len(wire) < 18 + n*20` BEFORE the NewIBLTWithSeed alloc. On the
// engine's 64-bit target the product cannot overflow → the guard HOLDS → the
// length-bomb seed returns ErrMalformedDigest (NO crash). The 32-bit-build
// residual (int(uint32(0xFFFFFFFF)) == -1 defeats the guard → OOM-kill) is
// disclosed in doc.go + ADR-0038 §6, NOT patched this fork. The fuzz exercises
// the short-header + magic + negative-n + k-out-of-range + short-bucket-array
// + length-bomb reject branches on the 64-bit target.
func FuzzUnmarshalIBLT(f *testing.F) {
	for _, seed := range ibltSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = eng.UnmarshalIBLT(wire)
	})
}
