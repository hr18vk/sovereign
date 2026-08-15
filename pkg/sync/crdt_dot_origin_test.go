// Phase 2f — causal-dot integrity (dot/origin attribution) production teeth.
//
// This file is the biting test the Phase 2f mandate requires. It drives the
// PRODUCTION ApplyCRDTDeltaEvent (pkg/sync/crdt_apply.go) and
// ApplyCRDTDeltaBatch (pkg/sync/crdt_apply_batch.go) — the Phase 2d/2e entry
// points — end-to-end through the dot/origin attribution axis the
// Phase 2c/2d/2e wire-integrity arc proved for PayloadDigest (SHA-256
// cross-validation) but never proved for the causal dot.
//
// HISTORY THIS FILE CLOSES (continuation of the Phase 2e arc on main @ ebfad50):
//
//	Phases 2c/2d/2e proved PayloadDigest == SHA-256(payload) on every inbound
//	frame — single-event via ApplyCRDTDeltaEvent, batched via
//	ApplyCRDTDeltaBatch (S1a atomic-reject). That closed the C6 digest axis.
//	The causal-dot axis (G1) remained open: a buggy or hostile peer could stamp
//	an inbound CRDTDeltaEvent with a DotNodeID that does not equal the frame's
//	OriginNodeID — claiming a dot from a counter-space the origin doesn't own.
//	Phase 2f closes G1 on the SAME seam, with the SAME teeth shape.
//
// THE FOUR PHASE 2f RULINGS THIS TEST ENFORCES:
//
//	Ruling 2 — the check lives in ReconstructEntry (Option C, NOT Join, NOT
//	  capnp.Unmarshal). Case 1/2 prove the live path rejects via the seam.
//	Ruling 4 (O1 ordering) — the dot/origin check runs BEFORE the SHA-256
//	  cross-validation. Case 4 proves a doubly-corrupt frame reports
//	  WireIntegrityDotOriginMismatch FIRST (cheapest-to-detect violation).
//	  Mutation C proves a re-ordering behind the digest check bites the teeth.
//	Ruling 5 — diagnostic context: the WireIntegrityError for the dot/origin
//	  violation carries EntityID + OriginNodeID + DotNodeID + Kind so a failed
//	  frame is attributable. Case 2/3 assert the mismatched pair on the error.
//	Ruling 7 — the batch path inherits the check via ReconstructEntry. Case 3
//	  proves it: a 3-element batch with the MIDDLE element's DotNodeID !=
//	  OriginNodeID is atomic-rejected (S1a), ZERO new entries for all 3.
//
// THE THREE MANDATORY MUTATION PROOFS:
//
//	Mutation A (neuter the dot/origin check): remove the
//	  `if rec.DotNodeID != originNodeID` block in ReconstructEntry. Case 2
//	  FAILS because the seam no longer catches the attribution mismatch, the
//	  frame reconstructs cleanly (digest is consistent), and the foreign-
//	  dotted entry reaches Join -> State().Get(rtEntityID) finds an entry
//	  that should not be there.
//
//	Mutation B (bypass the seam on the dot/origin path): introduce a temporary
//	  bypass in ApplyCRDTDeltaEvent that synthesizes the entry off ev directly,
//	  skipping ReconstructEntry, so the dot/origin mismatch reaches Join. Case
//	  2 FAILS — structurally identical to the Phase 2d Mutation A bypass, now
//	  catching the same class of bypass for the attribution concern.
//
//	Mutation C (re-order the check behind the digest check — O1 regression):
//	  move the dot/origin check to AFTER the SHA-256 cross-validation in
//	  ReconstructEntry. Case 4 FAILS because the doubly-corrupt frame now
//	  reports WireIntegrityDigestMismatch first and the
//	  `wie.Kind == WireIntegrityDotOriginMismatch` assertion fires.
//
// Scope discipline: this file ADDS a test ONLY. It does not modify
// crdt_reconstruct.go's digest-mismatch block, field-unread block, Read() order,
// or any Phase 2/2a/2b/2c/2d/2e test file, crdt_apply.go, crdt_apply_batch.go,
// crdt.go, or hamt.go — the verifier's git diff ebfad50..HEAD on every file in
// the must-be-byte-identical list MUST be empty. It reuses the shared rt*
// sentinels, the production CRDTDeltaEventWireVersion from crdt_apply.go (the
// single source of truth; read directly by name, NOT redefined), and
// rtReconstructDotCounter from crdt_reconstruct_test.go / crdt_apply_test.go
// fixtures (NOT redefined) so the contract teeth pin against the SAME
// surface the prior phases bit on.
package sync

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// rtSomeOtherNodeID is the Phase 2f attribution-mismatch sentinel: a 16-byte
// peer id DISTINCT from rtHostA and rtHostB. A frame whose DotNodeID ==
// rtSomeOtherNodeID but OriginNodeID == rtHostA is a foreign-dotted frame —
// the frame is CLAIMING a dot from rtSomeOtherNodeID's counter-space while
// attributing the origin to rtHostA. This is the C-attrib violation the seam
// catches. Distinctness from BOTH rtHostA (the origin) and rtHostB (the
// receiver) is what makes the mismatch unambiguous — a serializer that
// accidentally swapped DotNodeID with OriginNodeID would still set them equal
// (both rtHostA); only a genuinely-different dot surfaces the violation.
var rtSomeOtherNodeID = [16]byte{
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
}

// buildDotOriginWireFrame is the Phase 2f test-side wire-byte builder. It
// assembles a CRDTDeltaEvent whose DotNodeID and OriginNodeID can be stamped
// INDEPENDENTLY — the exact shape a buggy-or-hostile peer produces when it
// claims a dot from a counter-space the origin doesn't own. It MARSHALS the
// frame to capnp bytes and returns the []byte — exactly the shape an inbound
// transport frame hands to the production ApplyCRDTDeltaEvent.
//
// This mirrors the Phase 2d buildApplyWireFrame and Phase 2e buildBatchWireFrame
// helpers but allows the dot/origin pair to diverge. Every OTHER CRDTEntry
// contract field is stamped with the rt* sentinels; the caller controls
// (originNodeID, dotNodeID, payload, payloadDigest, dotCounter) so a
// doubly-corrupt frame (both dot/origin mismatch AND digest mismatch) can be
// planted for Case 4, and a consistent frame for Case 1. The digest defaults to
// rtPayloadDigest (SHA-256(rtPayload)) so the digest axis is CLEAN unless the
// caller passes a wrongDigest — isolating the attribution concern in Case 2.
func buildDotOriginWireFrame(t *testing.T, entityID string, originNodeID, dotNodeID [16]byte, digest [32]byte, payload string, dotCounter uint64) []byte {
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

// rtPhase2fEntityID is the single-event entityID for Case 1/2/4 — DISTINCT from
// the roundtrip/apply rtEntityID so ApplyCRDTDeltaEvent writes into host B's
// state under its OWN key, isolating Phase 2f's join from any prior test state.
// 40-char (same shape as rtEntityID) so a 16-byte-truncation regression still
// changes both length and content on the far side.
const rtPhase2fEntityID = "tenant=acme;ledger=txn;id=phase2f-dot-origin-attribution"

// rtPhase2fDotCounter is a distinct nonzero DotCounter for the single-event
// Phase 2f frame, distinct from rtReconstructDotCounter so Join-side state is
// unambiguous against any prior apply test residue.
const rtPhase2fDotCounter uint64 = 0x2f2f2f2f2f2f2f2f

func buildBatchDotOriginWireFrame(t *testing.T, specs []dotOriginBatchSpec) []byte {
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
			t.Fatalf("msg.Marshal (empty batch): %v", err)
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

type dotOriginBatchSpec struct {
	entityID      string
	originNodeID  [16]byte
	dotNodeID     [16]byte
	payload       string
	payloadDigest [32]byte
	dotCounter    uint64
}

// phase2fBatchEntityID returns a distinct 40-char entityID per batch element,
// derived from rtPhase2fEntityID so the far-side field-equality assertions
// isolate Phase 2f's batch from the single-event and from Phase 2e's batch.
func phase2fBatchEntityID(i int) string {
	return fmt.Sprintf("%s;el=%d", rtPhase2fEntityID, i)
}

// phase2fBatchDotCounter returns a distinct nonzero DotCounter per element.
func phase2fBatchDotCounter(i int) uint64 {
	return rtPhase2fDotCounter + uint64(i) + 1
}

// TestPhase2f_CausalDotAttribution_Biting is the Phase 2f production teeth.
// It drives the PRODUCTION ApplyCRDTDeltaEvent and ApplyCRDTDeltaBatch on four
// cases — the consistent happy path (1), the single-event attribution mismatch
// (2), the batched attribution mismatch with S1a atomic-reject (3), and the
// doubly-corrupt O1 ordering contract (4). All three mandatory mutations (A
// neuter, B bypass, C re-order) MUST make the relevant case fail red when
// applied; run them by temporarily editing crdt_reconstruct.go (A, C) or
// crdt_apply.go (B), running this test, and pasting the literal failing line
// into the Phase 2f report. Restore before commit.
func TestPhase2f_CausalDotAttribution_Biting(t *testing.T) {
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
	// Case 1 — Consistent attribution, single-event happy path.
	//
	// Marshal a frame whose DotNodeID == OriginNodeID == rtHostA (matching the
	// Phase 2/2c/2d/2e rt* contract), call ApplyCRDTDeltaEvent(wire), and
	// assert: (a) no error, (b) the entry is present in State().Get with
	// DotNodeID == rtHostA and OriginNodeID == rtHostA, and (c) Join applied
	// it. Proves Phase 2f does not break the consistent-attribution happy path.
	// ─────────────────────────────────────────────────────────────────────
	consistentWire := buildDotOriginWireFrame(t, rtPhase2fEntityID, rtHostA, rtHostA, rtPayloadDigest, rtPayload, rtPhase2fDotCounter)
	if err := engineB.ApplyCRDTDeltaEvent(consistentWire); err != nil {
		t.Fatalf("Case 1 (consistent attribution): ApplyCRDTDeltaEvent rejected a frame whose DotNodeID == OriginNodeID == rtHostA: %v — the live path must succeed when attribution is consistent and the digest is consistent", err)
	}

	gotConsistent := engineB.State().Get(rtPhase2fEntityID)
	if len(gotConsistent) == 0 {
		t.Fatalf("Case 1: State().Get(%q) returned no entries — Join did NOT apply the validated delta; the consistent-attribution happy path is broken", rtPhase2fEntityID)
	}
	if len(gotConsistent) != 1 {
		t.Fatalf("Case 1: State().Get(%q) returned %d entries, want 1 — Join applied the delta to the wrong cardinality", rtPhase2fEntityID, len(gotConsistent))
	}
	ce := gotConsistent[0]
	if ce.OriginNodeID != rtHostA {
		t.Errorf("Case 1 OriginNodeID: got %x, want %x — the consistent attribution must reach Join with OriginNodeID off the wire", ce.OriginNodeID, rtHostA)
	}
	if ce.DotNodeID != rtHostA {
		t.Errorf("Case 1 DotNodeID: got %x, want %x — the consistent attribution must reach Join with DotNodeID == OriginNodeID == rtHostA", ce.DotNodeID, rtHostA)
	}
	if ce.DotCounter != rtPhase2fDotCounter {
		t.Errorf("Case 1 DotCounter: got %#x, want %#x — the dot counter must reach Join off the wire (not zero-filled)", ce.DotCounter, rtPhase2fDotCounter)
	}
	// Belt-and-braces: the joined digest MUST equal SHA-256(rtPayload).
	recomputedConsistent := sha256.Sum256([]byte(rtPayload))
	if !bytes.Equal(recomputedConsistent[:], ce.PayloadDigest[:]) {
		t.Errorf("Case 1: joined PayloadDigest %x != SHA-256(rtPayload) %x — the digest axis (Phase 2c) still holds on the Phase 2f path", ce.PayloadDigest, recomputedConsistent)
	}
	t.Logf("Case 1 GREEN: consistent-attribution frame (DotNodeID == OriginNodeID == rtHostA) applied via ApplyCRDTDeltaEvent — entry present in State().Get(%q) with DotNodeID == OriginNodeID == rtHostA.", rtPhase2fEntityID)

	// ─────────────────────────────────────────────────────────────────────
	// Case 2 — Dot/origin attribution mismatch, single-event rejection.
	//
	// Marshal a frame whose DotNodeID = rtSomeOtherNodeID and OriginNodeID =
	// rtHostA (a foreign-dotted frame — the dot is from
	// rtSomeOtherNodeID's counter-space while the origin is claimed as rtHostA),
	// call ApplyCRDTDeltaEvent(wire), and assert:
	//   (a) error returned,
	//   (b) errors.As(err, &wie) recovers the production *WireIntegrityError,
	//   (c) wie.Kind == WireIntegrityDotOriginMismatch,
	//   (d) wie.EntityID == rtPhase2fEntityID, wie.OriginNodeID == rtHostA,
	//       wie.DotNodeID == rtSomeOtherNodeID (Ruling 5 diagnostic context),
	//   (e) the entry is NOT in State().Get(rtPhase2fEntityID) — the rejection
	//       PREVENTED Join from applying the foreign-dotted frame.
	//
	// Mutation A (neuter the dot/origin check): the foreign-dotted entry
	//   reaches Join -> the `entry NOT in State()` assertion fires red.
	// Mutation B (bypass the seam for the dot/origin concern): same red line.
	// ─────────────────────────────────────────────────────────────────────
	mismatchWire := buildDotOriginWireFrame(t, rtPhase2fEntityID, rtHostA, rtSomeOtherNodeID, rtPayloadDigest, rtPayload, rtPhase2fDotCounter)
	err := engineB.ApplyCRDTDeltaEvent(mismatchWire)
	if err == nil {
		t.Fatalf("PHASE2f INVARIANT BROKEN: ApplyCRDTDeltaEvent accepted a frame whose DotNodeID %x != OriginNodeID %x — MUTATION A/B CATCH: a neutered dot/origin check or a seam bypass lets the foreign-dotted frame reach Join and the attribution gap is LIVE on the wire path", rtSomeOtherNodeID, rtHostA)
	}

	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("PHASE2f INVARIANT BROKEN: ApplyCRDTDeltaEvent rejected the foreign-dotted frame with the wrong error type %T; expected *WireIntegrityError (the seam's typed error) so the attribution failure is errors.As-able", err)
	}
	if wie.Kind != WireIntegrityDotOriginMismatch {
		t.Errorf("Case 2 Kind: got %d, want %d (WireIntegrityDotOriginMismatch) — the seam must classify a dot/origin mismatch distinctly from a digest mismatch (Ruling 2)", wie.Kind, WireIntegrityDotOriginMismatch)
	}
	if wie.EntityID != rtPhase2fEntityID {
		t.Errorf("Case 2 diagnostic EntityID: got %q, want %q — the error must carry the entityID so the failed frame is attributable (Ruling 5 diagnostic context)", wie.EntityID, rtPhase2fEntityID)
	}
	if wie.OriginNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic OriginNodeID: got %x, want %x — the error must carry the CLAIMED origin peer id (Ruling 5 — the mismatched pair)", wie.OriginNodeID, rtHostA)
	}
	if wie.DotNodeID != rtSomeOtherNodeID {
		t.Errorf("Case 2 diagnostic DotNodeID: got %x, want %x — the error must carry the CLAIMED dot peer id so BOTH sides of the mismatched pair are named (Ruling 5 — the attribution payoff Option A forfeits)", wie.DotNodeID, rtSomeOtherNodeID)
	}

	// THE CRITICAL LIVE-PATH ASSERTION: the foreign-dotted frame was NOT
	// applied. If a neutered dot/origin check (Mutation A) or a seam bypass
	// (Mutation B) let the foreign-dotted frame reach Join, State().Get would
	// find an entry (Join would have applied a dot from
	// rtSomeOtherNodeID's counter-space to rtHostA's origin) and this fires.
	gotMismatched := engineB.State().Get(rtPhase2fEntityID)
	if len(gotMismatched) != 1 || gotMismatched[0].DotNodeID != rtHostA {
		t.Fatalf("PHASE2f INVARIANT BROKEN: after the mismatched single-event batch, State().Get(%q) has %d entries (DotNodeID of [0] = %x); want exactly 1 entry with DotNodeID == rtHostA — MUTATION A/B CATCH: the foreign-dotted frame (DotNodeID=%x) reached Join despite the attribution mismatch; G1 is LIVE on the single-event live path", rtPhase2fEntityID, len(gotMismatched), func() [16]byte {
			if len(gotMismatched) > 0 {
				return gotMismatched[0].DotNodeID
			}
			return [16]byte{}
		}(), rtSomeOtherNodeID)
	}
	t.Logf("Case 2 GREEN: ApplyCRDTDeltaEvent rejects a foreign-dotted frame (DotNodeID=%x, OriginNodeID=%x) with %q (errors.As → *WireIntegrityError Kind=DotOriginMismatch carrying EntityID/OriginNodeID/DotNodeID) and State().Get still holds only the Case-1 consistent entry.", rtSomeOtherNodeID, rtHostA, err.Error())

	// ─────────────────────────────────────────────────────────────────────
	// Case 3 — Batched dot/origin mismatch at index 1, S1a atomic-reject
	// (Phase 2e inheritance, Ruling 7).
	//
	// Marshal a 3-element CRDTDeltaBatch where element 1 has DotNodeID =
	// rtSomeOtherNodeID, OriginNodeID = rtHostA (the middle element is the
	// foreign-dotted one), elements 0 and 2 consistent; call
	// ApplyCRDTDeltaBatch(wire), and assert:
	//   (a) error returned naming element 1,
	//   (b) errors.As through the %w wrap recovers *WireIntegrityError with
	//       Kind == WireIntegrityDotOriginMismatch,
	//   (c) the diagnostic context (EntityID/OriginNodeID/DotNodeID) names
	//       element 1,
	//   (d) State().Get for all 3 entity IDs has ZERO new entries (S1a — the
	//       same atomic-reject contract Phase 2e's digest check teeth).
	//
	// This is the proof that the dot/origin check SURVIVES the batch path: no
	// new entry point, no batch-specific check — the per-element
	// ReconstructEntry call enforces it identically to the digest axis.
	// ─────────────────────────────────────────────────────────────────────
	// Use a fresh engine to isolate Case 3's batch from Case 1's joined state.
	engineBatch := setupRTEngine(t, rtHostB, 1000)
	// Phase 2g bound-vs-existing-fixture resolution (mandate escalation menu,
	// option (a) — documented): this pre-Phase-2g test mints unrealistically-large
	// eyecatch DotCounter sentinels (chosen for zero-fill-detection, NOT as
	// plausible DotCounters). The Phase 2g production default (AbsoluteSlack=1000)
	// closes A1 on the real wire and is byte-identical to Ruling 2; opting THIS
	// engine into the unbounded slack knob admits the sentinels WITHOUT widening
	// the production default that closes A1. The Phase 2g skew axis is exercised
	// on a fresh engine with the production default in crdt_lamport_skew_test.go.
	engineBatch.SetLamportAbsoluteSlack(LamportSkewAbsoluteSlackUnbounded)

	mismatchedEID := phase2fBatchEntityID(1)
	specs := []dotOriginBatchSpec{
		{entityID: phase2fBatchEntityID(0), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: phase2fBatchDotCounter(0)},
		{entityID: mismatchedEID, originNodeID: rtHostA, dotNodeID: rtSomeOtherNodeID, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: phase2fBatchDotCounter(1)},
		{entityID: phase2fBatchEntityID(2), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: phase2fBatchDotCounter(2)},
	}
	mismatchedBatchWire := buildBatchDotOriginWireFrame(t, specs)
	errBatch := engineBatch.ApplyCRDTDeltaBatch(mismatchedBatchWire)
	if errBatch == nil {
		t.Fatalf("PHASE2f INVARIANT BROKEN: ApplyCRDTDeltaBatch accepted a 3-element batch whose MIDDLE element has DotNodeID %x != OriginNodeID %x — the batch path must inherit the dot/origin check via ReconstructEntry (Ruling 7)", rtSomeOtherNodeID, rtHostA)
	}
	// The wrap names element 1 (the failing index).
	if !containsSubstring(errBatch.Error(), "element 1") {
		t.Errorf("Case 3 wrap: error %q does not name element 1 — the percent-w wrap must preserve the failing element index so the attribution failure is attributable within the batch", errBatch.Error())
	}
	var wieBatch *WireIntegrityError
	if !errors.As(errBatch, &wieBatch) {
		t.Fatalf("PHASE2f INVARIANT BROKEN: ApplyCRDTDeltaBatch rejected the attribution-mismatched batch with the wrong error type %T; expected *WireIntegrityError recoverable via errors.As through the element-index wrap", errBatch)
	}
	if wieBatch.Kind != WireIntegrityDotOriginMismatch {
		t.Errorf("Case 3 Kind: got %d, want %d (WireIntegrityDotOriginMismatch) — the batch path must classify a dot/origin mismatch distinctly (inherited from the seam, Ruling 7)", wieBatch.Kind, WireIntegrityDotOriginMismatch)
	}
	if wieBatch.EntityID != mismatchedEID {
		t.Errorf("Case 3 diagnostic EntityID: got %q, want %q — the error must carry the failing element's entityID so element 1 is attributable on the batch path (Option C payoff)", wieBatch.EntityID, mismatchedEID)
	}
	if wieBatch.OriginNodeID != rtHostA {
		t.Errorf("Case 3 diagnostic OriginNodeID: got %x, want %x — the error must carry claim rtHostA as the origin of the foreign-dotted element 1 (Ruling 5)", wieBatch.OriginNodeID, rtHostA)
	}
	if wieBatch.DotNodeID != rtSomeOtherNodeID {
		t.Errorf("Case 3 diagnostic DotNodeID: got %x, want %x — the error must carry rtSomeOtherNodeID as the foreign dot of element 1 (Ruling 5 — the mismatched pair)", wieBatch.DotNodeID, rtSomeOtherNodeID)
	}
	// S1a atomic-reject: ZERO new entries for ALL three entity IDs.
	for i := 0; i < 3; i++ {
		eid := phase2fBatchEntityID(i)
		got := engineBatch.State().Get(eid)
		if len(got) != 0 {
			t.Fatalf("PHASE2f INVARIANT BROKEN: after the mismatched batch, State().Get(%q) has %d entries, want ZERO — the batch path's S1a atomic-reject (Phase 2e) was NOT inherited by the dot/origin check (Ruling 7): element %d reached Join despite the mid-batch attribution mismatch", eid, len(got), i)
		}
	}
	t.Logf("Case 3 GREEN: ApplyCRDTDeltaBatch rejects a 3-element batch whose element 1 is foreign-dotted with %q (errors.As → *WireIntegrityError Kind=DotOriginMismatch carrying element-1's EntityID/OriginNodeID/DotNodeID) and State().Get has ZERO new entries for all 3 entity IDs — S1a atomic-reject, no partial apply.", errBatch.Error())

	// ─────────────────────────────────────────────────────────────────────
	// Case 4 — Doubly-corrupt frame ordering (O1 contract, Ruling 4).
	//
	// Marshal a frame with BOTH a dot/origin mismatch (DotNodeID =
	// rtSomeOtherNodeID, OriginNodeID = rtHostA) AND a digest mismatch
	// (PayloadDigest != SHA-256(payload)), call ApplyCRDTDeltaEvent(wire), and
	// assert:
	//   (a) error returned,
	//   (b) errors.As recovers *WireIntegrityError,
	//   (c) wie.Kind == WireIntegrityDotOriginMismatch (NOT
	//       WireIntegrityDigestMismatch — the O1 ordering contract: the
	//       dot/origin check runs BEFORE the SHA-256 check),
	//   (d) the entry is NOT in State().Get.
	//
	// Mutation C (re-order the check behind the digest): Case 4 FAILS because
	//   the doubly-corrupt frame now reports WireIntegrityDigestMismatch first
	//   and the wie.Kind assertion fires. This proves O1 is a contract, not an
	//   accident — and that a future "put the digest check first" re-ordering
	//   bites the teeth.
	// ─────────────────────────────────────────────────────────────────────
	wrongDigest := sha256.Sum256([]byte(rtPayload + "phase2f-doubly-corrupt-both-attribution-and-digest"))
	if wrongDigest == rtPayloadDigest {
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			wrongDigest[1] ^= 0x02
		}
	}
	// Fresh engine so Case 4's state assertion is unambiguous.
	engineDoubly := setupRTEngine(t, rtHostB, 2000)
	// Phase 2g bound-vs-existing-fixture resolution (mandate escalation menu,
	// option (a) — documented): this pre-Phase-2g test mints unrealistically-large
	// eyecatch DotCounter sentinels (chosen for zero-fill-detection, NOT as
	// plausible DotCounters). The Phase 2g production default (AbsoluteSlack=1000)
	// closes A1 on the real wire and is byte-identical to Ruling 2; opting THIS
	// engine into the unbounded slack knob admits the sentinels WITHOUT widening
	// the production default that closes A1. The Phase 2g skew axis is exercised
	// on a fresh engine with the production default in crdt_lamport_skew_test.go.
	engineDoubly.SetLamportAbsoluteSlack(LamportSkewAbsoluteSlackUnbounded)

	doublyWire := buildDotOriginWireFrame(t, rtPhase2fEntityID, rtHostA, rtSomeOtherNodeID, wrongDigest, rtPayload, rtPhase2fDotCounter)
	errDoubly := engineDoubly.ApplyCRDTDeltaEvent(doublyWire)
	if errDoubly == nil {
		t.Fatalf("PHASE2f INVARIANT BROKEN: ApplyCRDTDeltaEvent accepted a doubly-corrupt frame (DotNodeID=%x != OriginNodeID=%x AND PayloadDigest != SHA-256(payload)) — the seam must reject on the FIRST detected violation, not silently apply", rtSomeOtherNodeID, rtHostA)
	}
	var wieDoubly *WireIntegrityError
	if !errors.As(errDoubly, &wieDoubly) {
		t.Fatalf("PHASE2f INVARIANT BROKEN: ApplyCRDTDeltaEvent rejected the doubly-corrupt frame with the wrong error type %T; expected *WireIntegrityError", errDoubly)
	}
	if wieDoubly.Kind != WireIntegrityDotOriginMismatch {
		t.Fatalf("PHASE2f O1 ORDERING CONTRACT BROKEN: doubly-corrupt frame reported Kind %d, want %d (WireIntegrityDotOriginMismatch) — MUTATION C CATCH: the dot/origin check must run BEFORE the SHA-256 cross-validation (O1 ordering, Ruling 4); a re-ordering behind the digest check makes this assertion fire red", wieDoubly.Kind, WireIntegrityDotOriginMismatch)
	}
	gotDoubly := engineDoubly.State().Get(rtPhase2fEntityID)
	if len(gotDoubly) != 0 {
		t.Fatalf("PHASE2f INVARIANT BROKEN: after the doubly-corrupt single-event, State().Get(%q) has %d entries, want ZERO — the seam must reject the frame before Join applies it", rtPhase2fEntityID, len(gotDoubly))
	}
	t.Logf("Case 4 GREEN: doubly-corrupt frame (DotNodeID=%x != OriginNodeID=%x AND PayloadDigest != SHA-256(payload)) reports WireIntegrityDotOriginMismatch FIRST — O1 ordering contracts the dot/origin check BEFORE the digest check (Ruling 4); Mutation C bites this assertion.", rtSomeOtherNodeID, rtHostA)
}

// containsSubstring is a tiny helper so the test does not pull strings.Contains
// into the import block for one call (keeping the imports tight, matching the
// repo convention of std-lib-only imports where a single call do not justify a
// package). Equivalent to strings.Contains(s, substr).
func containsSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
