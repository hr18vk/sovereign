// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package fuzz

import (
	"testing"

	"github.com/hr18vk/sovereign/pkg/attribution"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// wire_unmarshal_fuzz_test.go provides five targeted fuzzes, one per
// ingest-path unmarshaler, each asserting the no-panic oracle independently.
// A dispatch fuzz could route a malformed Batch magic to the relay arm
// (the default) and miss a Batch-specific crash; the per-unmarshaler fuzzes
// close that hole by driving each unmarshaler directly with its own seed corpus.
//
// Each target's f.Add calls pull from the matching seeds_test.go builder so the
// in-process seeds and the committed testdata/fuzz/ files stay in lock-step.
// Each f.Fuzz asserts only that the unmarshaler returns (T, error) without
// panic — the verdict-value and semantic-correctness property is the
// round-trip test's job (TestEnvelope_MarshalRoundTrip et al.), not this
// harness's.
//
// Run a single target:
//
//	go test -run='^$' -fuzz=FuzzUnmarshalIBLT -fuzztime=60s ./pkg/security/fuzz/

// FuzzUnmarshalRelayEnvelope drives attribution.UnmarshalRelayEnvelope with v3
// and v2 envelopes, an excessive inner length, a truncated version prefix, and
// empty or one-byte inputs.
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
// (length-check, magic, version, fixed-offset copy) — the length-bomb class
// does not apply because the header is fixed-size with no wire-field-sized
// allocation. The fuzz exercises the short-header, magic-mismatch,
// version-mismatch, and unsigned-sig reject branches.
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
// (sibling to the batch, grown by the pqSig slot) — the length-bomb class does
// not apply. The fuzz exercises the short-header, magic, version,
// unsigned-edSig, and unsigned-pqSig reject branches.
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
// not a panic, on a well-guarded path). The fuzz exercises the short-header,
// magic, wrong-strataCount, and per-stratum-failure reject branches.
func FuzzUnmarshalStrataEstimator(f *testing.F) {
	for _, seed := range strataSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = eng.UnmarshalStrataEstimator(wire)
	})
}

// FuzzUnmarshalIBLT drives sync.UnmarshalIBLT with valid, truncated, oversized,
// and invalid-k inputs. The unmarshaler checks n < 0 || n > maxIBLTBuckets
// before allocating. Thus 0xFFFFFFFF returns ErrIBLTTooLarge on a 64-bit build
// because it exceeds the maximum, and on a 32-bit build because its int
// conversion is negative. The separate 32-bit relay-length limitation does not
// apply to this parser.
func FuzzUnmarshalIBLT(f *testing.F) {
	for _, seed := range ibltSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = eng.UnmarshalIBLT(wire)
	})
}
