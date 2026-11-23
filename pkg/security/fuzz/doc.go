// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package fuzz contains fuzz targets for mesh.DispatchFrame and the wire
// unmarshalers used on receive paths (ADR-0038):
//
//	attribution.UnmarshalRelayEnvelope   — relay envelopes, versions 2 and 3
//	attribution.UnmarshalBatchEnvelope   — batch envelopes
//	attribution.UnmarshalHybridFrame     — hybrid post-quantum frames
//	sync.UnmarshalStrataEstimator        — stratified estimators
//	sync.UnmarshalIBLT                   — individual IBLTs
//
// The six default targets check that a call returns without panicking. They do
// not check semantic correctness, which round-trip tests cover separately.
// DispatchFrame is called with no-op sinks, so its target covers frame
// classification and routing rather than signature verification or CRDT apply.
// The other targets call the unmarshalers directly. A panic is a failing input
// under Go's native fuzzer; no recovery is added to production receive code.
//
// Constructors in seeds_test.go provide well-formed frames, truncated headers,
// extreme length fields where applicable, and empty or one-byte inputs. The
// same constructors seed the in-process targets and the committed corpus under
// testdata/fuzz. Corpus tests compare the files with those builders and check
// that committed inputs do not panic the default targets.
//
// TestBugInjectControlProof is a deterministic negative control behind the
// fuzzbuginject build tag. It contrasts the real IBLT unmarshaler's rejection
// of a short input with an out-of-bounds panic in a copy whose length checks
// are removed. The tag keeps that copy and its control out of default builds.
//
// A run without findings establishes only that the explored inputs did not
// panic. The example -fuzztime values bound individual runs; they do not
// represent a long-running soak.
//
// UnmarshalRelayEnvelope converts its uint32 inner length to int before the
// bounds check. On a 32-bit build, 0xFFFFFFFF becomes -1, so the check passes
// and make([]byte, innerLen) panics with a negative length. On the engine's
// 64-bit builds, that declared length fails the bounds check and returns
// ErrMalformed. UnmarshalIBLT rejects negative and excessive bucket counts
// before allocation on both integer widths.
//
// This package contains tests and documentation only; it does not change the
// receive path or add a recovery boundary around it.
package fuzz
