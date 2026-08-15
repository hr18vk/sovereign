package fuzz

import (
	"testing"

	"github.com/hr18vk/supremum/pkg/mesh"
	"github.com/hr18vk/supremum/pkg/receive"
)

// dispatch_fuzz_test.go is Edit A — the LOAD-BEARING fuzz target
// FuzzDispatchFrame. It drives the FOUR-way DispatchFrame router
// (pkg/mesh/digest.go:176) with adversarial []byte and asserts the ONE property
// the receiver's docstring contract makes: the call RETURNS WITHOUT PANIC (the
// M3 oracle — the verdict VALUE is not asserted; the PROCESS STAYS ALIVE).
//
// THE frameSink REACHABILITY (the M1 correction the prompt's Edit A did not
// anticipate). DispatchFrame is EXPORTED, but its `recv frameSink` parameter's
// type is the UNEXPORTED interface pkg/mesh/peer.go:174 frameSink. A test in a
// DIFFERENT package (pkg/security/fuzz) CANNOT name `frameSink` in its source.
// Go's STRUCTURAL interface typing resolves this: a type that implements the
// three methods HandleFrame / HandleBatchFrame / HandleHybridFrame each taking a
// []byte and returning a receive.AcceptVerdict SATISFIES frameSink without
// naming it, and a value of that type is assignment-compatible with the
// unexported recv parameter. nopSink below is that type. This is the load-bearing
// reachability fact — without it the dispatch fuzz could not live in
// pkg/security/fuzz (the blueprint's named home).
//
// UNIT-ISOLATION (the Day-12.5 [243c10a] tooth principle). nopSink's three
// methods are NO-OPS that return a fixed AcceptVerdict — they do NOT call the
// real Receiver gate stack. The fuzz therefore drives the UNMARSHAL route (the
// DispatchFrame peek + the IsXFrame discriminators), NOT HandleBatchFrame's
// engine path or HandleFrame's capnp decode + Verify. This isolates the crash
// surface to the dispatch + unmarshal layer (the five unmarshalers + the
// IsXFrame peeks), which is the contract Day 33 makes falsifiable. Driving the
// full Receiver gate stack is a SEPARATE harness's scope (it needs a real
// Receiver + Directory + engine — not a no-panic property harness).

// nopSink is the no-op frameSink stub a FuzzDispatchFrame value passes to
// DispatchFrame. Its three methods return a fixed AcceptVerdict (the verdict
// value is irrelevant to the M3 no-panic oracle — the fuzz asserts the CALL
// returns, not WHAT it returns). It implements mesh.frameSink structurally.
type nopSink struct{}

func (nopSink) HandleFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.Accept}
}
func (nopSink) HandleBatchFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.Accept}
}
func (nopSink) HandleHybridFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.Accept}
}

// nopDigester is the no-op mesh.DigestSink stub a FuzzDispatchFrame value passes
// to DispatchFrame. mesh.DigestSink is EXPORTED (DeliverDigest), so this is a
// plain implementation. A nil digester is ALSO valid (DispatchFrame's
// digest branch is nil-safe — it drops the frame); the fuzz passes a non-nil
// digester so the DeliverDigest arm runs (exercises the digestFrameSplit +
// DeliverDigest path, NOT just the nil-drop).
type nopDigester struct{}

func (nopDigester) DeliverDigest([16]byte, []byte) {}

// Compile-time assert that nopDigester satisfies the EXPORTED mesh.DigestSink.
// frameSink is UNEXPORTED in pkg/mesh, so there is no `var _ mesh.frameSink =
// nopSink{}` form this package can write — the load-bearing conformance proof is
// the mesh.DispatchFrame(..., nopSink{}, ...) call in FuzzDispatchFrame below:
// if nopSink ever stops satisfying the (unexported) frameSink interface, that
// call fails to compile (Go checks structural conformance at the assignment to
// the recv parameter). That compile failure is the reachability guard.
var _ mesh.DigestSink = nopDigester{}

// FuzzDispatchFrame is the LOAD-BEARING headline fuzz target (ADR-0038
// T-FUZZ-DISPATCH-NO-PANIC). It feeds DispatchFrame adversarial []byte seeded
// by dispatchSeeds (the 4 valid magics + the adversarial shapes) and asserts the
// call returns without panic for EVERY input. The native fuzzer mutates the
// seeds; a panic FAILS the fuzz (the proof). Run:
//
//	go test -run='^$' -fuzz=FuzzDispatchFrame -fuzztime=120s ./pkg/security/fuzz/
//
// The -fuzztime NUMBER is the per-fork CI gate (the blueprint's 72-hour is the
// operator's PRODUCTION soak, NOT this fork's gate — disclosed in ADR-0038 §6).
func FuzzDispatchFrame(f *testing.F) {
	for _, seed := range dispatchSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		// The M3 oracle: the call RETURNS — verdict value NOT asserted. A panic
		// (out-of-bounds, nil-deref, OOM) FAILS the fuzz and is recorded.
		_ = mesh.DispatchFrame(wire, [16]byte{}, nopSink{}, nopDigester{})
	})
}
