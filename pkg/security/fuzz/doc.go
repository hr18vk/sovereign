// Package fuzz is the Day-33 (ADR-0038) wire-protocol + CRDT-apply FUZZ HARNESS —
// the trust anchor that makes the receiver's "NEVER panics on adversarial input"
// docstring contract (receiver.go:350 HandleFrame, :586 HandleBatchFrame, :823
// HandleHybridFrame) a FALSIFIABLE BINARY instead of a prose claim.
//
// WHY A HARNESS, NOT A FEATURE. The engine's ingest-path crash surface is the
// FOUR-way DispatchFrame router (pkg/mesh/digest.go:176) and the FIVE
// unmarshalers under it:
//
//	attribution.UnmarshalRelayEnvelope   (envelope.go:550) — the FROZEN-adjacent
//	                                          v1 relay path (2/3 LE version)
//	attribution.UnmarshalBatchEnvelope   (wire_v1.go:199) — the Day-5 batch
//	attribution.UnmarshalHybridFrame     (wire_v1.go:549) — the Day-32 hybrid-PQ
//	sync.UnmarshalStrataEstimator        (iblt_wire.go:220) — the Day-29 digest
//	sync.UnmarshalIBLT                   (iblt_wire.go:262) — the per-stratum
//
// Each takes a []byte straight off a peer-TLS socket. Each returns (T, error)
// on a malformed input. The CONTRACT each receiver docstring ships is that the
// caller's gate stack returns a Drop* Verdict on a bad frame — the PROCESS STAYS
// ALIVE. Day 29 (the digest frame) + Day 31 (the PQ-verify) + Day 32 (the hybrid
// SIGN frame) each ADDED a new magic + a new unmarshaler to that SAME dispatch
// surface WITHOUT a machine-driven adversarial input ever testing the claim —
// the proof-by-prose is now a four-arm-wide claim, each arm unaudited by a
// machine. Day 33 closes it.
//
// THE ORACLE (M3 — load-bearing). Each fuzz target asserts ONE property per
// input: the unmarshaler / DispatchFrame call RETURNS WITHOUT PANIC. It does NOT
// assert the returned T is semantically correct (that is the round-trip teeth's
// job — TestEnvelope_MarshalRoundTrip et al. already exist; this harness does
// NOT duplicate them). The bug the fuzz catches is a PANIC: an out-of-bounds
// slice index, a nil-deref, an unbounded make() (OOM-kill), or an integer
// overflow that defeats a bounds guard. A native `go test -fuzz` does NOT
// recover — a panic FAILS the fuzz, which is the proof. NO recover() guard is
// added to the production receive path (Law IV — a recover would MASK the crash
// this harness is chartered to surface; the fuzz is the ONLY enforcement).
//
// THE SEED CORPUS (M4 — committed, not git-ignored). The testdata/fuzz/FuzzX/
// corpusseed dirs are TRACKED (Law II reproducibility). The minimum corpus per
// target: (a) the valid magic + a well-formed body (the happy-path seed that
// establishes each arm's coverage); (b) a TRUNCATED magic (the first 4 bytes +
// NO body — the length-bomb-empty shape); (c) a length-bomb (a valid magic + a
// uint32 length field of 0xFFFFFFFF — the OOM shape); (d) a 1-byte and 0-byte
// input (the smallest adversarial shapes). The corpus COUNT is a NUMBER in the
// report (Law V).
//
// THE BUG-INJECT CONTROL (T-FUZZ-BUG-INJECT-CONTROL — the Day-25 Law 5 / Day-31
// T-PQ-KEM-CLASSICAL-CONTROL mold). A fuzz that only feeds well-formed frames
// is a TAUTOLOGY; a fuzz that never catches an INJECTED panic is a no-op
// runner. The harness ships a deliberately-injected panic in a COPY of an
// unmarshaler (a build-tagged `fuzzbuginject` target) so the operator can prove
// the fuzzer is load-bearing: run `go test -tags fuzzbuginject -fuzz=FuzzBugInjectControl`
// and the injected panic is caught within seconds. The DEFAULT build (no tag)
// skips that target so the package stays GREEN.
//
// THE HONEST RESIDUAL (disclosed, NOT closed). (1) A fuzz that finds NO panic in
// M hours does NOT prove no bug exists — it proves no panic for M inputs on this
// seed (the honest coverage-discipline line). (2) The blueprint's 72-hour
// PRODUCTION soak is the operator's deployment run, NOT this fork's per-fork CI
// gate (the -fuzztime NUMBER in the ADR is the per-fork gate). (3) Two of the
// five unmarshalers (UnmarshalIBLT iblt_wire.go:269 + UnmarshalRelayEnvelope
// envelope.go:563) cast wire uint32 length fields to `int`; on a 32-BIT build
// `int(uint32(0xFFFFFFFF)) == -1` defeats the bounds guard → multi-GB make() →
// OOM-kill. On the engine's 64-bit target (arm64/x86_64, `int`==int64) the
// product cannot overflow → the guards HOLD → NO panic. The 32-bit-build
// length-bomb is a RESIDUAL disclosed here + in ADR-0038 §6, NOT patched this
// fork (the engine targets 64-bit exclusively; a 32-bit hardening is a SEPARATE
// fork). The length-bomb seed is a COVERAGE seed on 64-bit (exercises the
// length-field path, returns an error, no crash), NOT a crash reproducer.
//
// SCOPE (M5/M7 — ZERO non-test source touched). This package is TEST-TIER. The
// 4-file md5-FROZEN set (crdt.go 44f89527 + crdt_apply.go + the 2 capnp schema
// files) + the verifier-side 4 (clock/admission/transport) are byte-identical
// pre AND post — the Day-29 44f89527 streak is PRESERVED (NO streak-breaker; the
// harness is a CALLER of the unmarshalers + DispatchFrame, NOT a modifier). The
// new pkg/security/fuzz/* files are enumerated in track36ExemptDay33 (the
// Day-30/31/32 discipline) so the TestTrack36_ScopeTooth EXEMPTS them. SSoT
// STAYS 23 — no counter ships (M6: a panic-firing counter needs a recover in the
// production path = Law IV violation; a malformed-drop counter is a DIFFERENT
// feature fork's scope, NOT the harness fork). The cleanest possible fork.
package fuzz
