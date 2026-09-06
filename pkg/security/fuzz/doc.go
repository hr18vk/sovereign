// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Package fuzz is the (ADR-0038) wire-protocol + CRDT-apply FUZZ HARNESS —
// the trust anchor that makes the receiver's "NEVER panics on adversarial input"
// docstring contract (receiver.go's HandleFrame, HandleBatchFrame, and
// HandleHybridFrame) a FALSIFIABLE BINARY instead of a prose claim.
//
// WHY A HARNESS, NOT A FEATURE. The engine's ingest-path crash surface is the
// FOUR-way DispatchFrame router (pkg/mesh/digest.go:176) and the FIVE
// unmarshalers under it:
//
//	attribution.UnmarshalRelayEnvelope (envelope.go:550) — the
//	                                          v1 relay path (2/3 LE version)
//	attribution.UnmarshalBatchEnvelope (wire_v1.go) — the batch
//	attribution.UnmarshalHybridFrame (wire_v1.go) — the hybrid-PQ
//	sync.UnmarshalStrataEstimator (iblt_wire.go:220) — the digest
//	sync.UnmarshalIBLT                   (iblt_wire.go:262) — the per-stratum
//
// Each takes a []byte straight off a peer-TLS socket. Each returns (T, error)
// on a malformed input. The CONTRACT each receiver docstring ships is that the
// caller's gate stack returns a Drop* Verdict on a bad frame — the PROCESS STAYS
// ALIVE. The digest frame, the PQ-verify, and the hybrid
// SIGN frame each ADDED a new magic + a new unmarshaler to that SAME dispatch
// surface WITHOUT a machine-driven adversarial input ever testing the claim —
// the proof-by-prose is now a four-arm-wide claim, each arm unaudited by a
// machine. This harness closes it.
//
// THE ORACLE (load-bearing). Each fuzz target asserts ONE property per
// input: the unmarshaler / DispatchFrame call RETURNS WITHOUT PANIC. It does NOT
// assert the returned T is semantically correct (that is the round-trip guards'
// job — TestEnvelope_MarshalRoundTrip et al. already exist; this harness does
// NOT duplicate them). The bug the fuzz catches is a PANIC: an out-of-bounds
// slice index, a nil-deref, an unbounded make (OOM-kill), or an integer
// overflow that defeats a bounds guard. A native `go test -fuzz` does NOT
// recover — a panic FAILS the fuzz, which is the proof. NO recover guard is
// added to the production receive path (a recover would MASK the crash
// this harness is chartered to surface; the fuzz is the ONLY enforcement).
//
// THE SEED CORPUS (committed, not git-ignored). The testdata/fuzz/FuzzX/
// corpus seed dirs are TRACKED. The minimum corpus per
// target: (a) the valid magic + a well-formed body (the happy-path seed that
// establishes each arm's coverage); (b) a TRUNCATED magic (the first 4 bytes +
// NO body — the length-bomb-empty shape); (c) a length-bomb (a valid magic + a
// uint32 length field of 0xFFFFFFFF — the OOM shape); (d) a 1-byte and 0-byte
// input (the smallest adversarial shapes). The corpus count is a recorded
// number.
//
// THE BUG-INJECT CONTROL (the bug-inject pattern).
// A fuzz that only feeds well-formed frames
// is a TAUTOLOGY; a fuzz that never catches an INJECTED panic is a no-op
// runner. The harness ships a deliberately-injected panic in a COPY of an
// unmarshaler (a build-tagged `fuzzbuginject` target) so the operator can prove
// the fuzzer is load-bearing: run `go test -tags fuzzbuginject -fuzz=FuzzBugInjectControl`
// and the injected panic is caught within seconds. The DEFAULT build (no tag)
// skips that target so the package stays GREEN.
//
// THE HONEST RESIDUAL (disclosed, NOT closed). (1) A fuzz that finds NO panic in
// M hours does NOT prove no bug exists — it proves no panic for M inputs on this
// seed (the honest coverage-discipline line). (2) The design's 72-hour
// PRODUCTION soak is the operator's deployment run, NOT this change's per-change CI
// gate (the -fuzztime NUMBER in the ADR is the per-change gate). (3) Two of the
// five unmarshalers (UnmarshalIBLT iblt_wire.go:269 + UnmarshalRelayEnvelope
// envelope.go:563) cast wire uint32 length fields to `int`; on a 32-BIT build
// `int(uint32(0xFFFFFFFF)) == -1` defeats the bounds guard → multi-GB make →
// OOM-kill. On the engine's 64-bit target (arm64/x86_64, `int`==int64) the
// product cannot overflow → the guards HOLD → NO panic. The 32-bit-build
// length-bomb is a RESIDUAL disclosed here + in ADR-0038 §6, NOT patched in this
// change (the engine targets 64-bit exclusively; a 32-bit hardening is a SEPARATE
// change). The length-bomb seed is a COVERAGE seed on 64-bit (exercises the
// length-field path, returns an error, no crash), NOT a crash reproducer.
//
// SCOPE (ZERO non-test source touched). This package is TEST-TIER: it adds only
// fuzz targets and is a CALLER of the unmarshalers + DispatchFrame, NOT a
// modifier — the engine's merge-law and wire-schema files are untouched. No
// telemetry counter is added: a panic-firing counter would need a recover in the
// production path (a violation), and a malformed-drop counter is a separate
// change, not this harness's.
package fuzz
