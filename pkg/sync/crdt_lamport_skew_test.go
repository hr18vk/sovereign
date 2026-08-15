// Phase 2g — the Lamport skew bound (Byzantine A1 closure at the wire).
//
// This file is the production teeth the Phase 2g mandate requires. It drives
// the PRODUCTION ApplyCRDTDeltaEvent + ApplyCRDTDeltaBatch + ReconstructEntryWithSkewBound
// — the THIRD live wire-integrity axis (the first that depends on RECEIVER
// STATE) — across the four cases and three mutation proofs the mandate names,
// plus the concurrency tooth (Ruling 8) that proves the atomic snapshot's
// coherence.
//
// CASES:
//
//	Case 1 — consistent small DotCounter within the bound (happy path): the
//	  bound does NOT break legitimate AdvanceLamportTo; the honest advance
//	  still happens for non-poisoned frames.
//
//	Case 2 — direct far-future stamp (attack vector A1), single-event rejection:
//	  DotCounter == receiver's bound + 1 → *WireIntegrityError{Kind:
//	  WireIntegrityLamportSkewPoisoning} with ALL six new diagnostic fields,
//	  the entry is NOT in State().Get (AdvanceLamportTo never ran, A4 disk
//	  poisoning is prevented by construction), and e.LamportCounter() did NOT
//	  advance.
//
//	Case 3 — batched A1 at element 1, S1a atomic-reject (Phase 2e inheritance,
//	  Ruling 7): a 3-element batch with element 1's DotCounter == bound+1
//	  (elements 0 and 2 consistent) returns an error naming element 1 and
//	  State().Get has ZERO new entries for all 3 entity IDs.
//
//	Case 4 — triply-corrupt frame ordering (O2 contract, Ruling 4): a frame
//	  with digest mismatch + attribution mismatch + skew poison all on one
//	  frame reports the FIRST detected violation. Per Phase 2f's O1 contract,
//	  the attribution check in ReconstructEntry runs BEFORE the digest check,
//	  so a triply-corrupt frame reports WireIntegrityDotOriginMismatch first
//	  — NOT WireIntegrityLamportSkewPoisoning. (The skew check runs AFTER
//	  both, only on a frame clean on both.)
//
// MUTATIONS (run in the verifier's own hands on report-back, restored before
// commit; the comments at each case name the mutation and assert the bite):
//
//	Mutation A (neuter the skew bound) — replace `if rec.Entry.DotCounter > bound`
//	  with `if false && rec.Entry.DotCounter > bound` in crdt_reconstruct_skew.go.
//	  Case 2 FAILS: the poisoned frame reaches Join, AdvanceLamportTo bricks the
//	  receiver's clock, and Case 2's "e.LamportCounter() did NOT advance" /
//	  "entry NOT in State" assertions fire.
//
//	Mutation B (seam bypass — ApplyCRDTDeltaEvent calls ReconstructEntry directly,
//	  skipping the wrapper) — revert the wrapper substitution in crdt_apply.go.
//	  Case 2 FAILS: the bypass routes the poisoned frame to Join, AdvanceLamportTo
//	  bricks the clock; the "e.LamportCounter() did NOT advance" assertion fires.
//
//	Mutation C (re-order the skew check BEFORE ReconstructEntry — O2 regression)
//	  — move the bound computation + DotCounter check in
//	  ReconstructEntryWithSkewBound above the ReconstructEntry call. Case 4
//	  FAILS: the triply-corrupt frame now reports WireIntegrityLamportSkewPoisoning
//	  first (Kind == 3) instead of WireIntegrityDotOriginMismatch (Kind == 2).
//
// CASE 5 (concurrency tooth, Ruling 8 — NOT a mutation):
//
//	Spawn a goroutine doing InsertLocal in a tight loop on the same engine,
//	while the test applies a skew-poisoned frame via the WRAPPER DIRECTLY with a
//	known snapshot. Assert (a) the poisoned frame is rejected (Kind ==
//	LamportSkewPoisoning), and (b) the error's ReceiverLamport field EQUALS the
//	snapshot the test passed — NOT a value that moved during the call. Proves
//	the wrapper is a pure function of (ev, snapshot) and never lazily re-reads
//	e.lamport mid-call; the snapshot's coherence is the load-bearing property
//	of the first receiver-state-dependent integrity check.
//
// Scope discipline: this file ADDS a test only. It reuses the shared rt*
// sentinels, rtPhase2fEntityID, rtHostA/rtHostB, rtSomeOtherNodeID, the build*
// helpers (buildDotOriginWireFrame, buildBatchDotOriginWireFrame), setupRTEngine,
// and the production CRDTDeltaEventWireVersion from crdt_apply.go (the single
// source of truth; read directly by name, NOT redefined, NOT widened —
// alias-by-duplication is the Phase 2h-rejected anti-pattern). The teeth
// exercise a FRESH engine with the
// PRODUCTION lamportSkewAbsoluteSlack=1000 default (NOT the unbounded override
// the legacy tests opt into), so the bound that ACTUALLY closes A1 at the wire
// is what the teeth bite against.
package sync

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// rtPhase2gEntityID is the single-event entityID for the Phase 2g teeth —
// DISTINCT from rtEntityID and rtPhase2fEntityID so ApplyCRDTDeltaEvent writes
// into host B's state under its OWN key, isolating Phase 2g's join from any
// prior apply/dot-origin residue. 40-char (same shape as the legacy entityIDs)
// so a 16-byte-truncation regression still changes both length and content.
const rtPhase2gEntityID = "tenant=acme;ledger=txn;id=phase2g-lamport-skew-bound"

// rtPhase2gPoisonDotCounter is the far-future DotCounter the A1 attack
// stamps — a distinct, deliberately-implausible value chosen so the teeth
// unambiguously catch a poisoned DataLoader frame. It is constructed in the
// test as receiver.bound + 1 (not a hardcoded constant) so the teeth exercise
// the BOUND'S computation, not a magic-number comparison — Ruling 2.
//
// rtPhase2gConsistentDotCounter is the happy-path DotCounter for Case 1 — a
// small, plausible value that stays BELOW the production-default bound
// (lamport + ceil(0*60) + 1000 = 1100 for a fresh engine at lamport 100), so
// the honest AdvanceLamportTo still runs.

// buildPhase2gWireFrame is the single-event wire-byte builder for the Phase 2g
// teeth. It mirrors buildDotOriginWireFrame (so DotNodeID == OriginNodeID ==
// rtHostA by default, the digest is consistent, and the frame is otherwise
// clean — the ONLY corrupt axis is DotCounter) but lets the test plant an
// arbitrary combination of (originNodeID, dotNodeID, digest, payload, dotCounter)
// so Case 4's triply-corrupt frame can plant attribution + digest + skew all at
// once. Per contract the wire frame is a CRDTDeltaEvent (single-event schema).
func buildPhase2gWireFrame(t *testing.T, entityID string, originNodeID, dotNodeID [16]byte, digest [32]byte, payload string, dotCounter uint64) []byte {
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
	if err := ev.SetOriginNodeID(originNodeID[:]); err != nil {
		t.Fatalf("SetOriginNodeID: %v", err)
	}
	if err := ev.SetDotNodeID(dotNodeID[:]); err != nil {
		t.Fatalf("SetDotNodeID: %v", err)
	}
	ev.SetDotCounter(dotCounter)
	ev.SetH3Index(rtH3Index)
	ev.SetSystemTime(rtSystemTime)
	ev.SetValidTimeStart(rtValidTimeStart)
	ev.SetValidTimeEnd(rtValidTimeEnd)
	ev.SetAssertionTime(rtAssertionTime)
	ev.SetDecisionTime(rtDecisionTime)
	if err := ev.SetEntityId(entityID); err != nil {
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

// phase2gBatchSpec is the per-element override spec for buildPhase2gBatchFrame,
// mirroring dotOriginBatchSpec so a planted skew poison can ride on element 1
// of a 3-element batch while elements 0 and 2 stay consistent.
type phase2gBatchSpec struct {
	entityID      string
	originNodeID  [16]byte
	dotNodeID     [16]byte
	payload       string
	payloadDigest [32]byte
	dotCounter    uint64
}

// phase2gBatchEntityID returns a distinct entityID per batch element derived
// from rtPhase2gEntityID so the far-side assertions isolate Phase 2g's batch.
func phase2gBatchEntityID(i int) string {
	return fmt.Sprintf("%s;el=%d", rtPhase2gEntityID, i)
}

// buildPhase2gBatchFrame is the batched wire-byte builder for Phase 2g Case 3.
// It mirrors buildBatchDotOriginWireFrame so the batched A1 frame's per-element
// (originNodeID, dotNodeID, digest, payload, dotCounter) can be planted.
func buildPhase2gBatchFrame(t *testing.T, specs []phase2gBatchSpec) []byte {
	t.Helper()
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("capnp.NewMessage: %v", err)
	}
	batch, err := capnp_schema.NewRootCRDTDeltaBatch(seg)
	if err != nil {
		t.Fatalf("NewRootCRDTDeltaBatch: %v", err)
	}
	if len(specs) == 0 {
		data, err := msg.Marshal()
		if err != nil {
			t.Fatalf("msg.Marshal (empty): %v", err)
		}
		return data
	}
	events, err := batch.NewEvents(int32(len(specs)))
	if err != nil {
		t.Fatalf("NewEvents: %v", err)
	}
	for i, sp := range specs {
		ev := events.At(i)
		ev.SetVersion(CRDTDeltaEventWireVersion)
		if err := ev.SetPayloadDigest(sp.payloadDigest[:]); err != nil {
			t.Fatalf("event %d SetPayloadDigest: %v", i, err)
		}
		if err := ev.SetOriginNodeID(sp.originNodeID[:]); err != nil {
			t.Fatalf("event %d SetOriginNodeID: %v", i, err)
		}
		if err := ev.SetDotNodeID(sp.dotNodeID[:]); err != nil {
			t.Fatalf("event %d SetDotNodeID: %v", i, err)
		}
		ev.SetDotCounter(sp.dotCounter)
		ev.SetH3Index(rtH3Index)
		ev.SetSystemTime(rtSystemTime)
		ev.SetValidTimeStart(rtValidTimeStart)
		ev.SetValidTimeEnd(rtValidTimeEnd)
		ev.SetAssertionTime(rtAssertionTime)
		ev.SetDecisionTime(rtDecisionTime)
		if err := ev.SetEntityId(sp.entityID); err != nil {
			t.Fatalf("event %d SetEntityId: %v", i, err)
		}
		if err := ev.SetPayload(sp.payload); err != nil {
			t.Fatalf("event %d SetPayload: %v", i, err)
		}
	}
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("msg.Marshal: %v", err)
	}
	return data
}

// TestPhase2g_LamportSkewBound_Biting is the Phase 2g production teeth: four
// cases + the concurrency tooth, with three mutation proofs (A/B/C) named at
// the cases they bite and run by temporarily editing crdt_reconstruct_skew.go
// (A, C) or crdt_apply.go (B), running this test, and pasting the literal
// failing line into the Phase 2g report. Restore before commit.
func TestPhase2g_LamportSkewBound_Biting(t *testing.T) {
	// ─────────────────────────────────────────────────────────────────────
	// Case 1 — consistent skew (small DotCounter within bound), happy path.
	//
	// Marshal a frame with DotCounter WELL BELOW the receiver's bound (a fresh
	// engine at lamport 100 with the production-default AbsoluteSlack=1000
	// and zero EWMA has bound = 100 + 0 + 1000 = 1100), call
	// ApplyCRDTDeltaEvent(wire), and assert: (a) no error, (b) Join applied
	// the entry, (c) e.LamportCounter() ADVANCED to the inbound DotCounter
	// (the honest advance still happens for non-poisoned frames — the bound
	// does NOT suppress the legitimate AdvanceLamportTo). Proves the bound
	// doesn't break happy-path Lamport advancing: A1 closure does not
	// regress the honest peer that mints a plausible DotCounter within the
	// rate envelope + slack.
	// ─────────────────────────────────────────────────────────────────────
	engineB1 := setupRTEngine(t, rtHostB, 100)
	// NOTE: NO SetLamportAbsoluteSlack override here — Case 1 exercises the
	// PRODUCTION default bound (AbsoluteSlack=1000), the bound that closes A1.
	const case1DotCounter uint64 = 150 // within bound 1100; a plausible honest peer dot
	case1Wire := buildPhase2gWireFrame(t, rtPhase2gEntityID, rtHostA, rtHostA, rtPayloadDigest, rtPayload, case1DotCounter)
	if err := engineB1.ApplyCRDTDeltaEvent(case1Wire); err != nil {
		t.Fatalf("Case 1 (consistent small DotCounter): ApplyCRDTDeltaEvent rejected a clean frame with DotCounter=%d within the production-default bound (lamport 100 + 0 + 1000 = 1100): %v — the live path must succeed for a plausible honest frame; A1 closure must NOT regress the honest peer", case1DotCounter, err)
	}
	gotC1 := engineB1.State().Get(rtPhase2gEntityID)
	if len(gotC1) != 1 {
		t.Fatalf("Case 1: State().Get(%q) has %d entries, want 1 — Join did NOT apply the validated clean frame; the bound closed A1 AND regressed the honest peer (a Ruling 2 violation: the bound must NOT reject a within-bound frame)", rtPhase2gEntityID, len(gotC1))
	}
	if gotC1[0].DotCounter != case1DotCounter {
		t.Errorf("Case 1 DotCounter: got %#x, want %#x — the consistent inbound DotCounter must reach Join off the wire (not zero-filled, not rejected)", gotC1[0].DotCounter, case1DotCounter)
	}
	if postLamportC1 := engineB1.LamportCounter(); postLamportC1 != case1DotCounter {
		t.Fatalf("Case 1 e.LamportCounter: got %d, want %d — the honest AdvanceLamportTo MUST advance the receiver's clock to the inbound DotCounter for a within-bound frame; the bound does NOT suppress the legitimate advance (a regression would brick honest peers as subtly as A1 bricks receivers)", postLamportC1, case1DotCounter)
	}
	t.Logf("Phase 2g Case 1 GREEN: clean frame with within-bound DotCounter=%d applied; e.Lamport advanced 100 → %d (honest AdvanceLamportTo runs un-suppressed for non-poisoned frames — A1 closure does NOT regress the honest peer).", case1DotCounter, engineB1.LamportCounter())

	// ─────────────────────────────────────────────────────────────────────
	// Case 2 — direct far-future stamp (A1), single-event rejection.
	//
	// Marshal a frame whose DotCounter == receiver's bound + 1 (one past the
	// bound, the smallest provably-poisoned value), call ApplyCRDTDeltaEvent,
	// and assert: (a) error returned, (b) errors.As recovers
	// *WireIntegrityError, (c) wie.Kind == WireIntegrityLamportSkewPoisoning,
	// (d) ALL six new diagnostic fields match the snapshot + inbound frame,
	// (e) the entry is NOT in State().Get (S1a-style atomic-reject —
	// AdvanceLamportTo never ran; A4 disk-state poisoning prevented by
	// construction), and (f) e.LamportCounter() did NOT advance (the poisoned
	// value never reached AdvanceLamportTo).
	//
	// MUTATION A (neuter the skew bound: `if false && rec.Entry.DotCounter > bound`
	//   in crdt_reconstruct_skew.go): Case 2 FAILS — the poisoned frame reaches
	//   Join, AdvanceLamportTo bricks the receiver's clock (e.LamportCounter
	//   jumps to the poisoned far-future value), and the "e.LamportCounter did
	//   NOT advance" + "entry NOT in State" assertions fire. The teeth bite a
	//   neutered bound — A1 closure is not theater.
	//
	// MUTATION B (seam bypass — ApplyCRDTDeltaEvent calls ReconstructEntry
	//   directly, skipping ReconstructEntryWithSkewBound in crdt_apply.go):
	//   Case 2 FAILS — the bypass routes the poisoned frame to Join,
	//   AdvanceLamportTo bricks the clock; the "e.LamportCounter did NOT
	//   advance" assertion fires. The seam bypass bites for the skew concern
	//   exactly the way Phase 2d/2f's bypass teeth bit for digest/attribution.
	// ─────────────────────────────────────────────────────────────────────
	engineB2 := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	snapB2 := engineB2.LamportSnapshot()
	boundB2 := MaxAcceptableDotCounter(snapB2) // 100 + 0 + 1000 = 1100
	case2DotCounter := boundB2 + 1             // smallest provably-poisoned value
	case2Wire := buildPhase2gWireFrame(t, rtPhase2gEntityID, rtHostA, rtHostA, rtPayloadDigest, rtPayload, case2DotCounter)
	errC2 := engineB2.ApplyCRDTDeltaEvent(case2Wire)
	if errC2 == nil {
		t.Fatalf("PHASE2g INVARIANT BROKEN: ApplyCRDTDeltaEvent accepted a far-future-stamped DotCounter=%d (bound=%d, bound+1) — MUTATION A/B CATCH: a neutered bound (`if false && …`) or a seam bypass (call ReconstructEntry directly) makes this fire: A1 is LIVE on the wire (the poisoned DotCounter reached Join and AdvanceLamportTo bricked the clock)", case2DotCounter, boundB2)
	}
	var wieC2 *WireIntegrityError
	if !errors.As(errC2, &wieC2) {
		t.Fatalf("PHASE2g INVARIANT BROKEN: ApplyCRDTDeltaEvent rejected the far-future DotCounter with the wrong error type %T; expected *WireIntegrityError (the seam's typed error)", errC2)
	}
	if wieC2.Kind != WireIntegrityLamportSkewPoisoning {
		t.Fatalf("PHASE2g Case 2 Kind: got %d, want %d (WireIntegrityLamportSkewPoisoning) — the far-future stamp must be classified on the skew axis, not as digest or attribution", wieC2.Kind, WireIntegrityLamportSkewPoisoning)
	}
	// All six new diagnostic fields must be set from the snapshot + inbound frame.
	if wieC2.InboundDotCounter != case2DotCounter {
		t.Errorf("Case 2 diagnostic InboundDotCounter: got %d, want %d — the error must carry the inbound far-future DotCounter", wieC2.InboundDotCounter, case2DotCounter)
	}
	if wieC2.ReceiverLamport != snapB2.Lamport {
		t.Errorf("Case 2 diagnostic ReceiverLamport: got %d, want %d (snapshot.Lamport) — the error must carry the receiver's clock at the atomic snapshot", wieC2.ReceiverLamport, snapB2.Lamport)
	}
	if wieC2.ComputedBound != boundB2 {
		t.Errorf("Case 2 diagnostic ComputedBound: got %d, want %d — the error must carry the bound the wrapper computed (Ruling 2 formula) so a reviewer can reconstruct", wieC2.ComputedBound, boundB2)
	}
	if wieC2.ObservedInboundRate != snapB2.ObservedInboundRate {
		t.Errorf("Case 2 diagnostic ObservedInboundRate: got %g, want %g (snapshot.ObservedInboundRate)", wieC2.ObservedInboundRate, snapB2.ObservedInboundRate)
	}
	if wieC2.HorizonSeconds != snapB2.HorizonSeconds {
		t.Errorf("Case 2 diagnostic HorizonSeconds: got %g, want %g (snapshot.HorizonSeconds)", wieC2.HorizonSeconds, snapB2.HorizonSeconds)
	}
	if wieC2.AbsoluteSlack != snapB2.AbsoluteSlack {
		t.Errorf("Case 2 diagnostic AbsoluteSlack: got %d, want %d (snapshot.AbsoluteSlack)", wieC2.AbsoluteSlack, snapB2.AbsoluteSlack)
	}
	// The Accepting-field attribution should carry the DotNodeID/OriginNodeID off the wire.
	if wieC2.DotNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic DotNodeID: got %x, want %x (rtHostA off the wire)", wieC2.DotNodeID, rtHostA)
	}
	if wieC2.OriginNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic OriginNodeID: got %x, want %x (rtHostA off the wire)", wieC2.OriginNodeID, rtHostA)
	}
	// THE CRITICAL A1/A4 CLOSURE ASSERTIONS: the poisoned frame was NOT applied.
	gotC2 := engineB2.State().Get(rtPhase2gEntityID)
	if len(gotC2) != 0 {
		t.Fatalf("PHASE2g INVARIANT BROKEN: after the far-future frame, State().Get(%q) has %d entries, want ZERO — MUTATION A/B CATCH: the poisoned frame reached Join (the bound was neutered or the seam was bypassed), A4 disk poisoning via AdvanceLamportTo is LIVE (the poisoned DotCounter would persist)", rtPhase2gEntityID, len(gotC2))
	}
	if postLamportC2 := engineB2.LamportCounter(); postLamportC2 != snapB2.Lamport {
		t.Fatalf("PHASE2g INVARIANT BROKEN: e.LamportCounter advanced from %d to %d after a far-future frame — MUTATION A/B CATCH: the poisoned DotCounter reached Join→AdvanceLamportTo and bricked the receiver's clock (A1 LIVE, A4 persists the poisoned value to disk); the receiver can no longer mint a higher dot via NextDot", snapB2.Lamport, postLamportC2)
	}
	t.Logf("Phase 2g Case 2 GREEN: ApplyCRDTDeltaEvent rejects a far-future DotCounter=%d (bound=%d) with %q; entry NOT applied, e.Lamport stayed at %d (A1 closed at the wire; A4 disk-poison prevented by construction).", case2DotCounter, boundB2, errC2.Error(), engineB2.LamportCounter())

	// ─────────────────────────────────────────────────────────────────────
	// Case 3 — batched A1 at element 1, S1a atomic-reject (Phase 2e inheritance,
	// Ruling 7).
	//
	// Build a 3-element CRDTDeltaBatch where elements 0 and 2 carry
	// within-bound DotCounters (consistent, clean) and element 1 carries
	// bound+1 (the smallest provably-poisoned value). Call ApplyCRDTDeltaBatch
	// and assert: (a) an error returned naming element 1, (b) errors.As through
	// the %w wrap recovers *WireIntegrityError with Kind ==
	// WireIntegrityLamportSkewPoisoning, (c) State().Get has ZERO new entries
	// for all 3 entity IDs (S1a atomic-reject for the skew axis — same shape
	// as Phase 2e for digest and Phase 2f for attribution).
	//
	// The SAME atomic snapshot is taken ONCE before the per-element loop
	// (Ruling 7+8); the bound element 1 fails is the SAME bound elements 0
	// and 2 would fail if they were poisoned. (Elements 0 and 2 here use small
	// within-bound DotCounters so they would NOT fail; the test isolates the
	// skew axis at element 1.)
	// ─────────────────────────────────────────────────────────────────────
	engineB3 := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	snapB3 := engineB3.LamportSnapshot()
	boundB3 := MaxAcceptableDotCounter(snapB3) // 100 + 0 + 1000 = 1100
	case3ConsistentDot := uint64(160)          // within-bound, distinct from Case 1 for clarity
	case3PoisonDot := boundB3 + 1              // element 1's far-future stamp
	case3Specs := []phase2gBatchSpec{
		{entityID: phase2gBatchEntityID(0), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: case3ConsistentDot},
		{entityID: phase2gBatchEntityID(1), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: case3PoisonDot},
		{entityID: phase2gBatchEntityID(2), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: case3ConsistentDot},
	}
	case3Wire := buildPhase2gBatchFrame(t, case3Specs)
	errC3 := engineB3.ApplyCRDTDeltaBatch(case3Wire)
	if errC3 == nil {
		t.Fatalf("PHASE2g INVARIANT BROKEN: ApplyCRDTDeltaBatch accepted a batch whose element 1 is far-future-stamped (DotCounter=%d, bound=%d) — the per-element skew check was bypassed or neutered; S1a atomic-reject for the skew axis is LIVE-OPEN", case3PoisonDot, boundB3)
	}
	// The wrap must name element 1.
	if !containsSubstring(errC3.Error(), "element 1") {
		t.Fatalf("PHASE2g Case 3 wrap: error %q does not name element 1 — the percent-w wrap must preserve the failing element index so the far-future stamp is attributable within the batch", errC3.Error())
	}
	var wieC3 *WireIntegrityError
	if !errors.As(errC3, &wieC3) {
		t.Fatalf("PHASE2g Case 3: errors.As did not recover *WireIntegrityError from the wrapped batch error %T; the skew rejection must carry the seam's typed error for the skew axis", errC3)
	}
	if wieC3.Kind != WireIntegrityLamportSkewPoisoning {
		t.Fatalf("PHASE2g Case 3 Kind: got %d, want %d (WireIntegrityLamportSkewPoisoning) — the batched far-future stamp must be classified on the skew axis", wieC3.Kind, WireIntegrityLamportSkewPoisoning)
	}
	if wieC3.InboundDotCounter != case3PoisonDot {
		t.Errorf("Case 3 diagnostic InboundDotCounter: got %d, want %d (element 1's far-future DotCounter)", wieC3.InboundDotCounter, case3PoisonDot)
	}
	// S1a atomic-reject: ZERO new entries for ALL 3 entity IDs (no partial apply).
	for i := 0; i < 3; i++ {
		eid := phase2gBatchEntityID(i)
		got := engineB3.State().Get(eid)
		if len(got) != 0 {
			t.Fatalf("PHASE2g INVARIANT BROKEN: after the atomic-reject of the poisoned batch, State().Get(%q) has %d entries, want ZERO — S1a violated: element %d was partially applied before element 1's skew was detected (the per-element-snapshot loop retook the snapshot mid-batch OR a join-as-you-go regression slipped in)", eid, len(got), i)
		}
	}
	// And the receiver's clock must NOT have advanced on the rejected batch.
	if postLamportC3 := engineB3.LamportCounter(); postLamportC3 != snapB3.Lamport {
		t.Fatalf("PHASE2g INVARIANT BROKEN: e.LamportCounter advanced from %d to %d after a rejected batch containing a far-future element — the consistent element 0/2 was joined before the poisoned element 1 was detected (S1a broken)", snapB3.Lamport, postLamportC3)
	}
	t.Logf("Phase 2g Case 3 GREEN: ApplyCRDTDeltaBatch rejects a 3-element batch whose element 1 is far-future-stamped (DotCounter=%d, bound=%d) with %q; ZERO new entries for all 3 entity IDs and e.Lamport stayed at %d (S1a atomic-reject survives on the skew axis, no partial apply).", case3PoisonDot, boundB3, errC3.Error(), engineB3.LamportCounter())

	// ─────────────────────────────────────────────────────────────────────
	// Case 4 — triply-corrupt frame ordering (O2 contract, Ruling 4).
	//
	// Marshal a frame with ALL THREE corruption axes on one wire read:
	//   (i)  attribution mismatch    — DotNodeID=rtSomeOtherNodeID, OriginNodeID=rtHostA
	//   (ii) digest mismatch         — PayloadDigest != SHA-256(payload)
	//   (iii)skew poison             — DotCounter = bound + 1 (far-future)
	// Call ApplyCRDTDeltaEvent and assert the FIRST detected violation is
	// reported. Per Phase 2f's O1 contract the attribution check in
	// ReconstructEntry runs BEFORE the digest check, so on a
	// multiply-corrupt frame the seam reports WireIntegrityDotOriginMismatch
	// FIRST. The skew wrapper runs AFTER ReconstructEntry (Ruling 4 / O2:
	// skew AFTER digest + attribution), so the triply-corrupt frame reports
	// attribution first — NEVER LamportSkewPoisoning.
	//
	// MUTATION C (re-order the skew check BEFORE ReconstructEntry in
	//   ReconstructEntryWithSkewBound — O2 regression): Case 4 FAILS because
	//   the triply-corrupt frame now reports WireIntegrityLamportSkewPoisoning
	//   first (Kind == 3) instead of WireIntegrityDotOriginMismatch (Kind == 2).
	//   The O2 ordering tooth bites an O2 re-ordering shipped as the public
	//   path — a frame that already fails digest+attribution contributes
	//   nothing to the skew concern, and the contract is a tooth, not
	//   stylistic.
	// ─────────────────────────────────────────────────────────────────────
	engineB4 := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	snapB4 := engineB4.LamportSnapshot()
	boundB4 := MaxAcceptableDotCounter(snapB4) // 1100
	case4DotCounter := boundB4 + 1             // the skew-poison axis
	case4WrongDigest := sha256Sum(t, []byte(rtPayload+"phase2g-triply-corrupt-digest"))
	case4Wire := buildPhase2gWireFrame(t, rtPhase2gEntityID, rtHostA, rtSomeOtherNodeID, case4WrongDigest, rtPayload, case4DotCounter)
	errC4 := engineB4.ApplyCRDTDeltaEvent(case4Wire)
	if errC4 == nil {
		t.Fatalf("PHASE2g INVARIANT BROKEN: ApplyCRDTDeltaEvent accepted a triply-corrupt frame (attribution + digest + skew all corrupt) — the seam must reject on the FIRST detected violation, not silently apply")
	}
	var wieC4 *WireIntegrityError
	if !errors.As(errC4, &wieC4) {
		t.Fatalf("PHASE2g Case 4: errors.As did not recover *WireIntegrityError from %T", errC4)
	}
	// O2 contract: the FIRST reported kind is attribution (Phase 2f's O1 fires
	// attribution before digest in ReconstructEntry; the skew check runs AFTER
	// ReconstructEntry). It MUST NOT be skew.
	if wieC4.Kind != WireIntegrityDotOriginMismatch {
		t.Fatalf("PHASE2g INVARIANT BROKEN: triply-corrupt frame reported Kind=%d (%s), want %d (WireIntegrityDotOriginMismatch) — MUTATION C CATCH: if the skew wrapper re-orders the skew check BEFORE ReconstructEntry, this fires with Kind=WireIntegrityLamportSkewPoisoning (3); the O2 ordering contract (skew AFTER digest+attribution) is LIVE-OPEN", wieC4.Kind, kindName(wieC4.Kind), WireIntegrityDotOriginMismatch)
	}
	if wieC4.Kind == WireIntegrityLamportSkewPoisoning {
		t.Fatalf("PHASE2g Case 4: triply-corrupt frame reported LamportSkewPoisoning — the O2 ordering was REGRESSED; skew must run AFTER digest + attribution, never first on a multiply-corrupt frame")
	}
	// Belt-and-braces: the entry must NOT be applied (attribution rejection is terminal).
	if gotC4 := engineB4.State().Get(rtPhase2gEntityID); len(gotC4) != 0 {
		t.Fatalf("PHASE2g Case 4: State().Get has %d entries after a triply-corrupt frame — the rejection must be terminal (no Join)", len(gotC4))
	}
	t.Logf("Phase 2g Case 4 GREEN: triply-corrupt frame reports WireIntegrityDotOriginMismatch FIRST (Kind=%d), NOT LamportSkewPoisoning — O2 ordering contract holds (skew AFTER digest+attribution; a frame clean on those two is the only one the skew check runs on).", wieC4.Kind)
}

// TestPhase2g_LamportSnapshotCoherence is the Phase 2g concurrency tooth
// (Ruling 8). Phase 2g is the FIRST integrity check depending on RECEIVER
// MUTABLE STATE (e.lamport). The atomic snapshot the caller builds ONCE is
// what makes the bound coherent against a concurrent InsertLocal on the same
// receiver — if the wrapper lazily re-read e.lamport mid-call, the bound's
// ReceiverLamport field would drift from the caller's snapshot while the call
// was in flight, and the bound would be incoherent.
//
// This test spawns a goroutine doing InsertLocal in a tight loop on the engine
// while the test applies a skew-poisoned frame via the WRAPPER DIRECTLY with a
// KNOWN snapshot. It asserts:
//
//	(a) the poisoned frame is rejected (Kind == WireIntegrityLamportSkewPoisoning)
//	    — the bound bites even under concurrent InsertLocal.
//	(b) the error's ReceiverLamport field EQUALS the snapshot.Lamport the test
//	    passed — NOT a value that moved during the call. This proves the
//	    wrapper is a pure function of (ev, snapshot) and never lazily re-reads
//	    e.lamport mid-call; the snapshot's coherence is the load-bearing
//	    property of the first receiver-state-dependent integrity check.
//
// MUTATION (concurrency tooth — NOT one of A/B/C; a separate regression): a
//
//	wrapper that re-reads e.lamport mid-call (e.g. calls e.LamportCounter() to
//	fill ReceiverLamport instead of using snapshot.Lamport) makes assertion (b)
//	FAIL: wie.ReceiverLamport drifts away from the snapshot the test pinned while
//	the InsertLocal goroutine advances the clock in the background. The
//	concurrency tooth catches exactly that slide.
func TestPhase2g_LamportSnapshotCoherence(t *testing.T) {
	engine := setupRTEngine(t, rtHostB, 100) // production defaults

	// Pin the snapshot the test will pass to the wrapper BEFORE the
	// InsertLocal storm starts. The wrapper MUST report THIS value as
	// ReceiverLamport, even though e.lamport moves while the call is in flight.
	snap := engine.LamportSnapshot()
	if snap.Lamport != 100 {
		t.Fatalf("setup: expected fresh engine lamport=100, got %d", snap.Lamport)
	}
	bound := MaxAcceptableDotCounter(snap) // 1100
	poisonDot := bound + 1                 // far-future stamp, bound+1

	// Build the wire frame, then DECODE it so the test can call the wrapper
	// directly with the pinned snapshot (controlling exactly what snapshot
	// crossed the boundary).
	case5Wire := buildPhase2gWireFrame(t, rtPhase2gEntityID, rtHostA, rtHostA, rtPayloadDigest, rtPayload, poisonDot)
	msg, err := capnp.Unmarshal(case5Wire)
	if err != nil {
		t.Fatalf("capnp.Unmarshal: %v", err)
	}
	defer msg.Release()
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		t.Fatalf("ReadRootCRDTDeltaEvent: %v", err)
	}

	// Start the InsertLocal storm concurrently with the apply. InsertLocal
	// calls NextDot → lamportCounter.Add(1), advancing the receiver's clock
	// on every iteration. CausalDotNodeID/CRDTEntry dot/origin stamping makes
	// the storm concurrent-safe; the test does NOT assert on the storm's
	// state (only that it MOVED the clock so a lazy re-read would drift).
	var stop atomic.Bool
	var stormWG sync.WaitGroup
	stormWG.Add(1)
	go func() {
		defer stormWG.Done()
		entry := CRDTEntry{PayloadDigest: rtPayloadDigest, H3Index: rtH3Index}
		for !stop.Load() {
			_ = engine.InsertLocal("phase2g-concurrency-storm", entry)
		}
	}()
	// Let the storm advance the clock STRICTLY above the pinned snapshot so a
	// lazy re-read INSIDE the wrapper WOULD observe a different (higher)
	// lamport than the pinned snapshot — this is what makes the tooth NON-
	// VACUOUS. If the storm starved (the busy-wait never observed a move),
	// the precondition below fires (not the coherence assertion) so the test
	// fails loudly as "storm did not move the clock" rather than passing
	// vacuously with a lazy-read-returns-100 path.
	for engine.LamportCounter() <= snap.Lamport {
		// busy-wait: yield the scheduler so the storm goroutine runs.
	}
	lamportAtApply := engine.LamportCounter()
	if lamportAtApply <= snap.Lamport {
		t.Fatalf("PHASE2g CONCURRENCY TOOTH (precondition): the InsertLocal storm did NOT advance e.Lamport above the pinned snapshot=%d (observed=%d) — the tooth would be vacuous; rerun (the storm goroutine was starved). This is a test-harness scheduling flake, not a Phase 2g defect; document and retry.", snap.Lamport, lamportAtApply)
	}

	// Apply the poisoned frame via the wrapper DIRECTLY with the pinned
	// snapshot — the production callers build the snapshot atomically and
	// pass it; this test does the same to control which snapshot crossed the
	// boundary (the storm is still running, so e.Lamport CONTINUES moving
	// while the apply is in flight — exactly the race a lazy re-read would
	// observe a stale-or-moving value under).
	rec, err := ReconstructEntryWithSkewBound(ev, snap)
	lamportAfterApply := engine.LamportCounter()

	// Stop the storm regardless of the assertion outcome.
	stop.Store(true)
	stormWG.Wait()

	if err == nil {
		t.Fatalf("PHASE2g CONCURRENCY TOOTH BROKEN: ReconstructEntryWithSkewBound accepted a far-future DotCounter=%d (bound=%d) under concurrent InsertLocal — the bound was neutered OR a torn read made the bound incoherently loose", poisonDot, bound)
	}
	if rec != (ReconstructedEntry{}) {
		t.Fatalf("PHASE2g CONCURRENCY TOOTH BROKEN: ReconstructEntryWithSkewBound returned a non-zero rec on rejection — the wrapper must return (ReconstructedEntry{}, *WireIntegrityError) on a skew-poisoned frame (FIX C value-return: the != nil check translates to a non-zero-value check, byte-identical semantics)")
	}
	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("PHASE2g CONCURRENCY TOOTH: errors.As did not recover *WireIntegrityError from %T", err)
	}
	if wie.Kind != WireIntegrityLamportSkewPoisoning {
		t.Fatalf("PHASE2g CONCURRENCY TOOTH: Kind got %d, want %d (WireIntegrityLamportSkewPoisoning) — the bound must reject the far-future frame even under concurrent InsertLocal", wie.Kind, WireIntegrityLamportSkewPoisoning)
	}
	// THE COHERENCE ASSERTION: wie.ReceiverLamport == the pinned
	// snapshot.Lamport, NOT a value the InsertLocal storm moved to during the
	// call. At apply entry the storm had already driven e.Lamport to
	// %d (>= %d); by apply exit it had advanced further to %d. A lazy re-read
	// mid-call would observe one of those HIGHER values and report THAT
	// instead of the pinned snapshot — failing here. The tooth is NON-VACUOUS
	// exactly because the storm demonstrably moved the clock above the
	// snapshot.
	if wie.ReceiverLamport != snap.Lamport {
		t.Fatalf("PHASE2g CONCURRENCY TOOTH BROKEN: wie.ReceiverLamport=%d != pinned snapshot.Lamport=%d (storm drove e.Lamport to %d before the apply and %d after) — the wrapper lazily re-read e.lamport mid-call; under the concurrent InsertLocal storm the bound's ReceiverLamport field drifted from the caller's atomic snapshot. The snapshot is the load-bearing property of the first receiver-state-dependent integrity check; a lazy re-read makes it theater.", wie.ReceiverLamport, snap.Lamport, lamportAtApply, lamportAfterApply)
	}
	if wie.ReceiverLamport != 100 {
		t.Errorf("PHASE2g CONCURRENCY TOOTH (belt): wie.ReceiverLamport=%d, want exactly 100 (the pinned fresh-engine snapshot, not the storm-advanced value)", wie.ReceiverLamport)
	}
	t.Logf("Phase 2g Concurrency Tooth GREEN: under concurrent InsertLocal (e.Lamport advanced to %d before the apply and %d after), ReconstructEntryWithSkewBound reported wie.ReceiverLamport=%d == pinned snapshot.Lamport=%d (NOT a moved value); the snapshot is coherent, the wrapper is a pure function of (ev, snapshot), and the first receiver-state-dependent integrity check's load-bearing property holds.", lamportAtApply, lamportAfterApply, wie.ReceiverLamport, snap.Lamport)
}

// kindName returns a human readable name for a WireIntegrityErrorKind (helper
// for the Case 4 assertion message so the failure names the actual kind seen).
func kindName(k WireIntegrityErrorKind) string {
	switch k {
	case WireIntegrityDigestMismatch:
		return "WireIntegrityDigestMismatch"
	case WireIntegrityFieldUnread:
		return "WireIntegrityFieldUnread"
	case WireIntegrityDotOriginMismatch:
		return "WireIntegrityDotOriginMismatch"
	case WireIntegrityLamportSkewPoisoning:
		return "WireIntegrityLamportSkewPoisoning"
	default:
		return fmt.Sprintf("Kind(%d)", int(k))
	}
}

// sha256Sum is a tiny helper so the Case 4 triply-corrupt frame can compute a
// deterministic mismatched digest without pulling crypto/sha256 into the test's
// import list redundantly with the rest of the file.
func sha256Sum(t *testing.T, b []byte) [32]byte {
	t.Helper()
	d := sha256.Sum256(b)
	if d == rtPayloadDigest {
		// Ensure determinism: a constructed mismatched digest that happens to
		// collide with rtPayloadDigest would not be a "digest mismatch" axis;
		// flip a byte. (rtPayload is fixed so this is unreachable in practice.)
		d[0] ^= 0x01
		if d == rtPayloadDigest {
			t.Fatalf("Case 4: could not construct a deterministic mismatched digest distinct from rtPayloadDigest")
		}
	}
	return d
}
