// Phase 2d — production teeth for the ApplyCRDTDeltaEvent transport wiring.
//
// This file is the biting test the Phase 2d mandate requires. It drives the
// PRODUCTION ApplyCRDTDeltaEvent (pkg/sync/crdt_apply.go) — the FIRST production
// caller of ReconstructEntry — end-to-end through:
//
//	(a) Consistent frame, end-to-end: marshall a CRDTDeltaEvent whose
//	    PayloadDigest == SHA-256(payload), call ApplyCRDTDeltaEvent(wire), assert
//	    the entry is PRESENT in engine.State().Get(entityID) with every contract
//	    field populated from the wire, and Join applied it. Proves the transport
//	    wires the seam to Join correctly for the happy path — every Phase 2c
//	    field-by-field assertion is reused (not weakened) and re-asserted against
//	    the live joined state.
//
//	(b) Mismatched frame, end-to-end rejection: marshall a CRDTDeltaEvent whose
//	    PayloadDigest != SHA-256(payload), call ApplyCRDTDeltaEvent(wire), assert
//	    a *WireIntegrityError is returned with the seam's diagnostic context
//	    (entityID, originNodeID, on-wire/recomputed digests) and the entry is
//	    NOT in engine.State().Get(entityID) — the rejection prevented Join from
//	    applying a corrupt frame. Proves the seam enforces on the LIVE path, not
//	    just in the test-local Phase 2c helper.
//
// TEETH (heightened — production enforcement is now live; the test must bite on
// the live path). The two mandatory mutation proofs:
//
//	Mutation A (routing bypass) — introduce a temporary bypass in
//	  ApplyCRDTDeltaEvent that decodes a frame and calls Join directly, skipping
//	  ReconstructEntry. Build it, run Case 2, confirm Case 2 FAILS because the
//	  mismatched pair reached Join and got applied. Restored before commit.
//
//	Mutation B (integrity-bypass on the live path) — paste a mismatched pair into
//	  the frame, but neuter ReconstructEntry's bytes.Equal check (discard the
//	  result). Run Case 2 again — it must STILL FAIL because the mismatch is no
//	  longer caught at the seam, so the corrupt frame is applied and Case 2's
//	  "entry NOT in state" assertion fires. Restored before commit. This proves
//	  the seam's bite survives the full wire path, not just the test-local Phase
//	  2b helper.
//
// Scope discipline: this file ADDS a test only. It reuses the shared rt*
// sentinels and the production CRDTDeltaEventWireVersion from crdt_apply.go
// (the single source of truth; read directly by name, NOT redefined), and
// rtReconstructDotCounter from crdt_reconstruct_test.go.
// It does not modify crdt_capnp_roundtrip_test.go, crdt_capnp_teeth_test.go,
// crdt_reconstruct.go, or crdt_reconstruct_test.go — the verifier's diff of
// those four files vs Phase 2c must be empty.
package sync

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// buildApplyWireFrame is the Phase 2d test-side wire-byte builder. It assembles a
// CRDTDeltaEvent with a caller-supplied (payload, payloadDigest) pair, MARSHALS
// it to capnp bytes, and returns the []byte — exactly the shape an inbound
// transport frame hands to the production ApplyCRDTDeltaEvent. It mirrors the
// Phase 2c buildReconstructFrame helper but returns wire bytes (not a decoded
// event) so the production decode→ReconstructEntry→Join path is exercised across
// a real marshal/unmarshal-plus-round-trip boundary. Every CRDTEntry contract
// field is stamped with the rt* sentinels shared with the Phase 2c test;
// DotCounter is rtReconstructDotCounter so a zero-fill mutation demonstrably
// changes a nonzero field to zero.
//
// dotCounter lets the test override the dot counter (defaults to a distinct
// nonzero sentinel so the field-equality assertion catches a zero-fill).
func buildApplyWireFrame(t *testing.T, digest [32]byte, payload string, dotCounter uint64) []byte {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaEvent: %v", err)
	}
	ev.SetVersion(CRDTDeltaEventWireVersion)
	if err := ev.SetPayloadDigest(digest[:]); err != nil {
		t.Fatalf("SetPayloadDigest: %v", err)
	}
	if err := ev.SetOriginNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(rtHostA[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(dotCounter)
	ev.SetH3Index(rtH3Index)
	ev.SetSystemTime(rtSystemTime)
	ev.SetValidTimeStart(rtValidTimeStart)
	ev.SetValidTimeEnd(rtValidTimeEnd)
	ev.SetAssertionTime(rtAssertionTime)
	ev.SetDecisionTime(rtDecisionTime)
	if err := ev.SetEntityId(rtEntityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := ev.SetPayload(payload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// TestPhase2d_ApplyCRDTDeltaEvent_Biting is the Phase 2d production biting test.
// It drives ApplyCRDTDeltaEvent on (a) a consistent frame and (b) a mismatched
// frame, asserting the live path wires the seam to Join correctly (Case 1) and
// the seam's rejection prevents Join from applying a corrupt frame (Case 2).
//
// Both mandatory mutation proofs (A and B) MUST make Case 2 fail red when
// applied. Run them by temporarily editing pkg/sync/crdt_apply.go (Mutation A)
// or pkg/sync/crdt_reconstruct.go (Mutation B), running this test, and pasting
// the literal failing line into the Phase 2d report. Restore before commit.
func TestPhase2d_ApplyCRDTDeltaEvent_Biting(t *testing.T) {
	engineB := setupRTEngine(t, rtHostB, 100) // Phase 2g bound-vs-existing-fixture resolution (mandate escalation menu,
	// option (a) — documented): this pre-Phase-2g test mints unrealistically-large
	// eyecatch DotCounter sentinels (chosen for zero-fill-detection, NOT as
	// plausible DotCounters). The Phase 2g production default (AbsoluteSlack=1000)
	// closes A1 on the real wire and is byte-identical to Ruling 2; opting THIS
	// engine into the unbounded slack knob admits the sentinels WITHOUT widening
	// the production default that closes A1. The Phase 2g skew axis is exercised
	// on a fresh engine with the production default in crdt_lamport_skew_test.go.
	engineB.SetLamportAbsoluteSlack(LamportSkewAbsoluteSlackUnbounded)

	// ─────────────────────────────────────────────────────────────────────
	// Case 1: consistent frame, end-to-end.
	//
	//_marshall a CRDTDeltaEvent whose PayloadDigest == SHA-256(payload), call
	// ApplyCRDTDeltaEvent(wire), and assert the entry is PRESENT in
	// engine.State().Get(entityID) with EVERY contract field populated from the
	// wire (the Phase 2c field-by-field assertions reused — not weakened — and
	// re-asserted against the live joined state, not a ReconstructedEntry
	// struct). This proves the transport wires the seam to Join correctly for
	// the happy path.
	// ─────────────────────────────────────────────────────────────────────
	consistentWire := buildApplyWireFrame(t, rtPayloadDigest, rtPayload, rtReconstructDotCounter)
	if err := engineB.ApplyCRDTDeltaEvent(consistentWire); err != nil {
		t.Fatalf("Case 1 (consistent frame): ApplyCRDTDeltaEvent rejected a consistent (payload, payloadDigest) pair: %v — the live path must succeed when SHA-256(payload) == PayloadDigest and all fields read cleanly", err)
	}

	gotConsistent := engineB.State().Get(rtEntityID)
	if len(gotConsistent) == 0 {
		t.Fatalf("Case 1: host B State().Get(%q) returned no entries — Join did NOT apply the validated delta, so the transport did not wire the seam to Join correctly", rtEntityID)
	}
	if len(gotConsistent) != 1 {
		t.Fatalf("Case 1: host B got %d entries for %q, want 1 — Join applied the delta to the wrong cardinality", len(gotConsistent), rtEntityID)
	}
	ce := gotConsistent[0]

	// Entity ID preserved by string (not hash) — C6 catch on the far side: a
	// 16-byte-truncated entityID would have stored the entry under a different
	// key and the State().Get(rtEntityID) above would have returned zero entries.
	t.Logf("Case 1: entityID preserved — State().Get(%q) returned 1 entry", rtEntityID)

	// Every contract field, asserted against the rt* sentinels exactly as in
	// Phase 2c's TestPhase2c_ReconstructEntry_Biting — except now against the
	// entry Join actually stored in host B's state, not a freshly-reconstructed
	// ReconstructedEntry. A zero-fill anywhere (the C5-class silent fall-
	// through) makes the corresponding assertion fire on the LIVE joined state.
	if ce.PayloadDigest != rtPayloadDigest {
		t.Errorf("Case 1 PayloadDigest: got %x, want %x (wire digest must reach Join)", ce.PayloadDigest, rtPayloadDigest)
	}
	if ce.OriginNodeID != rtHostA {
		t.Errorf("Case 1 OriginNodeID: got %x, want %x (must come off the wire, not zero-filled)", ce.OriginNodeID, rtHostA)
	}
	if ce.DotNodeID != rtHostA {
		t.Errorf("Case 1 DotNodeID: got %x, want %x (must come off the wire, not zero-filled)", ce.DotNodeID, rtHostA)
	}
	if ce.DotCounter != rtReconstructDotCounter {
		t.Errorf("Case 1 DotCounter: got %#x, want %#x — MUTATION B CATCH: a zero-fill on the live path makes this fail against the joined state, not just the reconstructed entry", ce.DotCounter, rtReconstructDotCounter)
	}
	if ce.H3Index != rtH3Index {
		t.Errorf("Case 1 H3Index: got %#x, want %#x (must come off the wire, not zero-filled)", ce.H3Index, rtH3Index)
	}
	if ce.SystemTime != rtSystemTime {
		t.Errorf("Case 1 SystemTime: got %#x, want %#x (must come off the wire, not zero-filled)", ce.SystemTime, rtSystemTime)
	}
	if ce.ValidTimeStart != rtValidTimeStart {
		t.Errorf("Case 1 ValidTimeStart: got %#x, want %#x (must come off the wire, not zero-filled)", ce.ValidTimeStart, rtValidTimeStart)
	}
	if ce.ValidTimeEnd != rtValidTimeEnd {
		t.Errorf("Case 1 ValidTimeEnd: got %#x, want %#x (must come off the wire, not zero-filled)", ce.ValidTimeEnd, rtValidTimeEnd)
	}
	if ce.AssertionTime != rtAssertionTime {
		t.Errorf("Case 1 AssertionTime: got %#x, want %#x (must come off the wire, not zero-filled)", ce.AssertionTime, rtAssertionTime)
	}
	if ce.DecisionTime != rtDecisionTime {
		t.Errorf("Case 1 DecisionTime: got %#x, want %#x (must come off the wire, not zero-filled)", ce.DecisionTime, rtDecisionTime)
	}

	// Belt-and-braces: the stored digest MUST equal SHA-256 of the original
	// payload (which we discard per Ruling 3, but the seam validated it before
	// discarding). Reproduce SHA-256(rtPayload) and assert the joined entry's
	// PayloadDigest still satisfies it — pinning that the entry Join stored
	// is the wire-validated one, not a stale-or-substituted digest.
	recomputedConsistent := sha256.Sum256([]byte(rtPayload))
	if !bytes.Equal(recomputedConsistent[:], ce.PayloadDigest[:]) {
		t.Errorf("Case 1: joined PayloadDigest %x != SHA-256(rtPayload) %x — the entry Join stored does not satisfy the integrity property the seam validated", ce.PayloadDigest, recomputedConsistent)
	}

	// ─────────────────────────────────────────────────────────────────────
	// Case 2: mismatched frame, end-to-end rejection.
	//
	// Marsha a CRDTDeltaEvent whose PayloadDigest != SHA-256(payload), call
	// ApplyCRDTDeltaEvent(wire), and assert:
	//   (a) a *WireIntegrityError is returned (errors.As),
	//   (b) the diagnostic context (entityID, originNodeID, on-wire and
	//       recomputed digests) is present,
	//   (c) the entry is NOT in engine.State().Get(entityID) — the rejection
	//       PREVENTED Join from applying the corrupt frame.
	//
	// MUTATION A (routing bypass): a temporary bypass in ApplyCRDTDeltaEvent
	// that decodes + calls Join directly (skipping ReconstructEntry) makes
	// this Case 2 fail: the mismatched pair reaches Join and the entry appears
	// in State().Get — the "entry NOT in state" assertion fires. The bypass is
	// the exact C6-on-the-live-path failure Phase 2d exists to close.
	//
	// MUTATION B (neuter bytes.Equal): pasting the mismatched pair into the
	// frame but neutering ReconstructEntry's bytes.Equal check makes Case 2
	// fail too: the seam no longer catches the mismatch, the corrupt frame is
	// applied, and the "entry NOT in state" assertion fires.
	// ─────────────────────────────────────────────────────────────────────
	wrongDigest := sha256.Sum256([]byte(rtPayload + "mismatched-by-a-buggy-or-tampering-peer"))
	if wrongDigest == rtPayloadDigest {
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			t.Fatalf("Case 2: could not construct a deterministic mismatched digest; give up rather than risk a false green")
		}
	}
	mismatchedWire := buildApplyWireFrame(t, wrongDigest, rtPayload, rtReconstructDotCounter)
	err := engineB.ApplyCRDTDeltaEvent(mismatchedWire)
	if err == nil {
		t.Fatalf("PHASE2d INVARIANT BROKEN: ApplyCRDTDeltaEvent accepted a mismatched (payload, payloadDigest) pair — MUTATION A CATCH: a routing bypass makes this fire (the mismatch reached Join and got applied). wire-integrity gap is LIVE on the wire path: SHA-256(payload) != PayloadDigest but the entry point returned nil")
	}

	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("PHASE2d INVARIANT BROKEN: ApplyCRDTDeltaEvent rejected the mismatched pair with the wrong error type %T; expected *WireIntegrityError (the seam's typed error) so the teeth are specific to the wire-integrity failure", err)
	}

	// Diagnostic context — the Option C payoff, now proven reachable on the
	// LIVE path (not just the test-local Phase 2b/2c helper).
	if wie.EntityID != rtEntityID {
		t.Errorf("Case 2 diagnostic EntityID: got %q, want %q — the error must carry the entityID so a failed frame is attributable on the live path (Option C payoff)", wie.EntityID, rtEntityID)
	}
	if wie.OriginNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic OriginNodeID: got %x, want %x — the error must carry the origin peer id on the live path (Option C payoff)", wie.OriginNodeID, rtHostA)
	}
	if wie.OnWireDigest != wrongDigest {
		t.Errorf("Case 2 diagnostic OnWireDigest: got %x, want %x — the error must carry the digest the wire carried", wie.OnWireDigest, wrongDigest)
	}
	if wie.RecomputedDigest != rtPayloadDigest {
		t.Errorf("Case 2 diagnostic RecomputedDigest: got %x, want %x — the error must carry SHA-256(payload) the seam recomputed from the actual payload bytes", wie.RecomputedDigest, rtPayloadDigest)
	}
	if wie.Kind != WireIntegrityDigestMismatch {
		t.Errorf("Case 2 Kind: got %d, want %d (WireIntegrityDigestMismatch)", wie.Kind, WireIntegrityDigestMismatch)
	}

	// THE CRITICAL LIVE-PATH ASSERTION: the corrupt frame was NOT applied. If a
	// routing bypass (Mutation A) or a neutered bytes.Equal (Mutation B) let
	// the mismatched pair through, Join would have applied a SECOND entry
	// (or a second dotted entry under the same entityID) and this would fail.
	gotMismatched := engineB.State().Get(rtEntityID)
	if len(gotMismatched) != 1 {
		t.Fatalf("PHASE2d INVARIANT BROKEN: after the mismatched frame, State().Get(%q) has %d entries, want exactly 1 (only the consistent Case 1 entry) — MUTATION A/B CATCH: the mismatched frame was applied by Join (bypass or neutered seam), reopening C6 on the live path", rtEntityID, len(gotMismatched))
	}
	// And the one entry present must STILL be the consistent Case 1 entry, not
	// the corrupt mismatched one: its PayloadDigest must be rtPayloadDigest,
	// NOT wrongDigest.
	if gotMismatched[0].PayloadDigest == wrongDigest {
		t.Fatalf("PHASE2d INVARIANT BROKEN: the joined entry's PayloadDigest is the MISMATCHED wrongDigest %x — the corrupt frame reached Join. The seam's rejection did not prevent the apply; C6 is live on the wire path", wrongDigest)
	}
	if gotMismatched[0].PayloadDigest != rtPayloadDigest {
		t.Errorf("Case 2 post-rejection: the surviving entry's PayloadDigest %x != rtPayloadDigest %x — Join must still hold only the consistent Case 1 entry", gotMismatched[0].PayloadDigest, rtPayloadDigest)
	}

	t.Logf("Phase 2d GREEN: ApplyCRDTDeltaEvent rejects a mismatched (payload, payloadDigest) frame with %q and the entry is NOT applied to Join — live wire-integrity enforcement holds, every frame through the seam (Option C).", err.Error())
}
