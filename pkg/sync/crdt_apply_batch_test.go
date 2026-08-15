// Phase 2e — production teeth for the ApplyCRDTDeltaBatch batched framing.
//
// This file is the biting test the Phase 2e mandate requires. It drives the
// PRODUCTION ApplyCRDTDeltaBatch (pkg/sync/crdt_apply_batch.go) — the batched
// sibling of Phase 2d's ApplyCRDTDeltaEvent — end-to-end through three cases:
//
//	(a) All-consistent 3-element batch: marshal a CRDTDeltaBatch of three
//	    CRDTDeltaEvent frames each with PayloadDigest == SHA-256(payload), call
//	    ApplyCRDTDeltaBatch(wire), assert each of the 3 entity IDs has exactly 1
//	    entry in engine.State().Get(entityID_j), every CRDTEntry contract field
//	    matches the rt* sentinels per element, and Join applied all 3.
//
//	(b) Mid-batch mismatch at index 1, atomic-reject: marshal a CRDTDeltaBatch
//	    with elements 0 and 2 consistent and element 1 mismatched, call
//	    ApplyCRDTDeltaBatch(wire), assert a *WireIntegrityError is returned
//	    (wrapped so the error names element index 1 and errors.As recovers the
//	    seam's diagnostic context — EntityID/OriginNodeID/on-wire+recomputed
//	    digests/Kind), and engine.State() has ZERO entries for entityID_0,
//	    entityID_1, AND entityID_2 — atomic-reject, no partial apply.
//
//	(c) Empty batch: marshal a 0-element CRDTDeltaBatch, call
//	    ApplyCRDTDeltaBatch(wire), assert no error and State() unchanged.
//
// TEETH (heightened a third time — production enforcement is live on main;
// Phase 2e extends it to batched transport). Three mandatory mutation proofs
// run in the verifier's own hands (see the report):
//
//	Mutation A (per-element routing bypass) — introduce a temporary path in
//	  ApplyCRDTDeltaBatch that decodes element i and calls Join with it
//	  directly, skipping ReconstructEntry for that element. Case 2 FAILS
//	  because the mismatched element 1 reaches Join and is applied; the
//	  "ZERO entries for entityID_1" assertion fires. The bypass is the exact
//	  C6-on-element-k-of-batch-B failure Phase 2e exists to close.
//
//	Mutation B (per-element neutered bytes.Equal) — neuter ReconstructEntry's
//	  bytes.Equal check; run Case 2 with element 1 mismatched. It FAILS
//	  because the seam no longer catches the mismatch, the batch completes
//	  with no error, Join is called, and the atomic-reject assertion (ZERO
//	  entries for entityID_1) fires. Proves the seam's bite survives the batch
//	  path, not just the single-event path.
//
//	Mutation C (partial-apply / S1b regression) — introduce a path that calls
//	  Join PER element as each reconstructs, instead of accumulating and
//	  joining once at the end. Case 2 with element 1 mismatched: element 0
//	  reconstructs and is JOINED before element 1's mismatch is hit; the
//	  assertion "ZERO new entries for entityID_0" FAILS (element 0 was
//	  partially applied). Proves the S1a architecture
//	  (reconstruct-all-then-join-once): a future "per-element Join
//	  optimization" bites the teeth.
//
// Scope discipline: this file ADDS a test only. It reuses the shared rt*
// sentinels and the production CRDTDeltaEventWireVersion from crdt_apply.go
// (the single source of truth; read directly by name, NOT redefined) and
// rtReconstructDotCounter from crdt_reconstruct_test.go.
// It modifies NO existing test or production file — the verifier's diff on
// the Phase 2/2a/2b/2c/2d files must be empty.
package sync

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// batchElementSpec is the per-element override spec for buildBatchWireFrame.
// Each element is stamped with the rt* sentinels (so the far-side field-by-
// field assertions can be reused per element), but its (entityID, payload,
// payloadDigest, dotCounter) are caller-supplied so a mismatch can be planted
// at any index and distinct entity IDs distinguish the joined entries.
type batchElementSpec struct {
	entityID      string
	payload       string
	payloadDigest [32]byte
	dotCounter    uint64
}

// buildBatchWireFrame is the Phase 2e test-side batch wire-byte builder. It
// assembles a CRDTDeltaBatch containing N CRDTDeltaEvent frames (one per spec),
// MARSHALS it to capnp bytes, and returns the []byte — exactly the shape an
// inbound batched transport frame hands to the production ApplyCRDTDeltaBatch.
// It mirrors the Phase 2d buildApplyWireFrame helper but builds a batch rather
// than a single event. Every shared CRDTEntry contract field is stamped with
// the rt* sentinels; per-element overrides are (entityID, payload,
// payloadDigest, dotCounter) so a mismatch can be planted at any index and
// distinct entity IDs keep the joined entries distinguishable in State().
func buildBatchWireFrame(t *testing.T, specs []batchElementSpec) []byte {
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
		// An empty batch is a valid wire frame: the events pointer is left
		// unset (HasEvents() == false) and batch.Events() returns a zero-length
		// list. This is the Case 3 fixture.
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
		if err := ev.SetOriginNodeID(rtHostA[:]); err != nil {
			t.Fatalf("event %d SetOriginNodeID: %v", i, err)
		}
		if err := ev.SetDotNodeID(rtHostA[:]); err != nil {
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

// phase2eEntityID returns a distinct 40-char entityID per batch element index,
// derived from the shared rtEntityID prefix so the far-side field-equality
// assertions against the rt* sentinels stay meaningful (the entityID dimension
// is the per-element distinguisher; every other CRDTEntry field is shared).
func phase2eEntityID(i int) string {
	return fmt.Sprintf("%s;el=%d", rtEntityID, i)
}

// phase2eBatch2DotOffset is a constant dot offset for the consistent elements
// of the Case 2 mismatched batch. Using phase2eDotCounter(i)+offset (instead
// of phase2eDotCounter(i)) means a partial-apply of an early-reconstructed
// element joins a NEW dotted entry under that entityID rather than deduping
// against the Case-1 entry — so the atomic-reject assertion (State().Get has
// exactly 1 entry per entityID) catches a per-element-apply regression
// (Mutation C) as a 2-entry result instead of an invisible dedup.
const phase2eBatch2DotOffset uint64 = 100

// phase2eDotCounter returns a distinct nonzero DotCounter per element index so
// a zero-fill mutation (the C5-class silent fall-through) changes a known
// nonzero field to zero and the per-element DotCounter assertion fires.
func phase2eDotCounter(i int) uint64 {
	return rtReconstructDotCounter + uint64(i)
}

// assertJoinedEntryAssertsPhase2cFields reuses the Phase 2c/2d field-by-field
// contract assertions, parameterized by the element's entityID and dot
// counter so the per-element cases share the same teeth as the single-event
// Phase 2d test (not weakened — the originals' lines are copied, not relaxed).
func assertJoinedEntryAssertsPhase2cFields(t *testing.T, ce CRDTEntry, entityID string, dotCounter uint64) {
	t.Helper()
	if ce.PayloadDigest != rtPayloadDigest {
		t.Errorf("PayloadDigest: got %x, want %x (wire digest must reach Join, per element)", ce.PayloadDigest, rtPayloadDigest)
	}
	if ce.OriginNodeID != rtHostA {
		t.Errorf("OriginNodeID: got %x, want %x (must come off the wire, not zero-filled, per element)", ce.OriginNodeID, rtHostA)
	}
	if ce.DotNodeID != rtHostA {
		t.Errorf("DotNodeID: got %x, want %x (must come off the wire, not zero-filled, per element)", ce.DotNodeID, rtHostA)
	}
	if ce.DotCounter != dotCounter {
		t.Errorf("DotCounter: got %#x, want %#x — MUTATION B CATCH: a zero-fill on the batch path makes this fail against the joined state, per element", ce.DotCounter, dotCounter)
	}
	if ce.H3Index != rtH3Index {
		t.Errorf("H3Index: got %#x, want %#x (must come off the wire, not zero-filled, per element)", ce.H3Index, rtH3Index)
	}
	if ce.SystemTime != rtSystemTime {
		t.Errorf("SystemTime: got %#x, want %#x (must come off the wire, not zero-filled, per element)", ce.SystemTime, rtSystemTime)
	}
	if ce.ValidTimeStart != rtValidTimeStart {
		t.Errorf("ValidTimeStart: got %#x, want %#x (must come off the wire, not zero-filled, per element)", ce.ValidTimeStart, rtValidTimeStart)
	}
	if ce.ValidTimeEnd != rtValidTimeEnd {
		t.Errorf("ValidTimeEnd: got %#x, want %#x (must come off the wire, not zero-filled, per element)", ce.ValidTimeEnd, rtValidTimeEnd)
	}
	if ce.AssertionTime != rtAssertionTime {
		t.Errorf("AssertionTime: got %#x, want %#x (must come off the wire, not zero-filled, per element)", ce.AssertionTime, rtAssertionTime)
	}
	if ce.DecisionTime != rtDecisionTime {
		t.Errorf("DecisionTime: got %#x, want %#x (must come off the wire, not zero-filled, per element)", ce.DecisionTime, rtDecisionTime)
	}
	recomputed := sha256.Sum256([]byte(rtPayload))
	if !bytes.Equal(recomputed[:], ce.PayloadDigest[:]) {
		t.Errorf("joined PayloadDigest %x != SHA-256(rtPayload) %x — the entry Join stored per element does not satisfy the integrity property the seam validated", ce.PayloadDigest, recomputed)
	}
}

// TestPhase2e_ApplyCRDTDeltaBatch_Biting is the Phase 2e production teeth. It
// drives ApplyCRDTDeltaBatch on (1) an all-consistent 3-element batch, (2) a
// mid-batch mismatch at index 1 that must atomic-reject with the seam's
// diagnostic context wrapped to name element index 1 and leave State() with
// ZERO new entries, and (3) an empty batch that must be a no-op. Mutation
// proofs A/B/C (run in the verifier's own hands on report-back) confirm the
// per-element routing bypass, the per-element neutered bytes.Equal, and the
// per-element-apply (S1b) regression all make Case 2 fail red.
func TestPhase2e_ApplyCRDTDeltaBatch_Biting(t *testing.T) {
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
	// Case 1: all-consistent 3-element batch, end-to-end.
	//
	// Build a CRDTDeltaBatch of three events, each consistent
	// (PayloadDigest == SHA-256(payload)), each with a distinct entityID and
	// distinct nonzero DotCounter, call ApplyCRDTDeltaBatch(wire), and assert:
	//   (a) no error,
	//   (b) each of the 3 entity IDs has exactly 1 entry in State().Get,
	//   (c) every CRDTEntry contract field matches the rt* sentinels per element,
	//   (d) Join applied all 3 (State() reflects them).
	// Proves the batch wires the seam to Join correctly for the happy path N=3.
	// ─────────────────────────────────────────────────────────────────────
	var specs1 []batchElementSpec
	for i := 0; i < 3; i++ {
		specs1 = append(specs1, batchElementSpec{
			entityID:      phase2eEntityID(i),
			payload:       rtPayload,
			payloadDigest: rtPayloadDigest,
			dotCounter:    phase2eDotCounter(i),
		})
	}
	consistentBatch := buildBatchWireFrame(t, specs1)
	if err := engineB.ApplyCRDTDeltaBatch(consistentBatch); err != nil {
		t.Fatalf("Case 1 (all-consistent 3-element batch): ApplyCRDTDeltaBatch rejected a consistent batch: %v — the batch path must succeed when every element's SHA-256(payload) == PayloadDigest and all fields read cleanly", err)
	}
	for i := 0; i < 3; i++ {
		eid := phase2eEntityID(i)
		got := engineB.State().Get(eid)
		if len(got) != 1 {
			t.Fatalf("Case 1 element %d: State().Get(%q) has %d entries, want exactly 1 — Join did NOT apply this validated batch element, so the batch did not wire the seam to Join correctly for N=3", i, eid, len(got))
		}
		assertJoinedEntryAssertsPhase2cFields(t, got[0], eid, phase2eDotCounter(i))
	}
	t.Logf("Phase 2e Case 1 GREEN: ApplyCRDTDeltaBatch applied a 3-element consistent batch — all 3 entity IDs present in State() with every CRDTEntry contract field matching the rt* sentinels.")

	// ─────────────────────────────────────────────────────────────────────
	// Case 2: mid-batch mismatch at index 1, atomic-reject.
	//
	// Build a CRDTDeltaBatch with elements 0 and 2 consistent and element 1
	// mismatched (random-wrong digest), call ApplyCRDTDeltaBatch(wire), assert:
	//   (a) error returned,
	//   (b) errors.As reveals the underlying *WireIntegrityError AND the
	//       wrapping names element index 1,
	//   (c) the seam's diagnostic context (EntityID, OriginNodeID, on-wire/
	//       recomputed digests, Kind) is present on the underlying wie,
	//   (d) State() has ZERO entries for entityID_1 AND ZERO for entityID_0
	//       and entityID_2 — atomic-reject, NO partial apply.
	//
	// MUTATION A (per-element routing bypass): a temporary bypass in
	//   ApplyCRDTDeltaBatch that decodes element i and calls Join directly
	//   (skipping ReconstructEntry for element 1) makes Case 2 FAIL: the
	//   mismatched element reaches Join and is applied; the "ZERO entries for
	//   entityID_1" assertion fires. The bypass is the exact C6-on-element-k
	//   failure Phase 2e extends live enforcement to catch.
	//
	// MUTATION B (per-element neutered bytes.Equal): neuter ReconstructEntry's
	//   bytes.Equal; Case 2 with element 1 mismatched FAILS because the seam no
	//   longer catches the mismatch, the batch completes with no error, Join is
	//   called, and the atomic-reject assertion (ZERO entries for entityID_1)
	//   fires.
	//
	// MUTATION C (partial-apply / S1b regression): introduce per-element Join
	//   (join-as-you-go) instead of accumulate-then-join-once; Case 2 with
	//   element 1 mismatched FAILS because element 0 reconstructs and is JOINED
	//   before element 1's mismatch is hit; the "ZERO new entries for
	//   entityID_0" assertion fires (element 0 was partially applied).
	// ─────────────────────────────────────────────────────────────────────
	wrongDigest := sha256.Sum256([]byte(rtPayload + "phase2e-mismatched-element-1-by-a-buggy-or-tampering-peer"))
	if wrongDigest == rtPayloadDigest {
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			t.Fatalf("Case 2: could not construct a deterministic mismatched digest; give up rather than risk a false green")
		}
	}
	mismatchedEID := phase2eEntityID(1)

	specs2 := []batchElementSpec{
		{entityID: phase2eEntityID(0), payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: phase2eDotCounter(0) + phase2eBatch2DotOffset},
		{entityID: mismatchedEID, payload: rtPayload, payloadDigest: wrongDigest, dotCounter: phase2eDotCounter(1) + phase2eBatch2DotOffset},
		{entityID: phase2eEntityID(2), payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: phase2eDotCounter(2) + phase2eBatch2DotOffset},
	}
	mismatchedBatch := buildBatchWireFrame(t, specs2)
	err := engineB.ApplyCRDTDeltaBatch(mismatchedBatch)
	if err == nil {
		t.Fatalf("PHASE2e INVARIANT BROKEN: ApplyCRDTDeltaBatch accepted a batch with element 1 mismatched — MUTATION A CATCH: a per-element routing bypass makes this fire (the mismatch reached Join and got applied). wire-integrity gap is LIVE on the batch path: SHA-256(payload) != PayloadDigest for element 1 but the batch entry point returned nil")
	}

	// The wrapping MUST name element index 1.
	if !strings.Contains(err.Error(), "element 1") {
		t.Fatalf("PHASE2e INVARIANT BROKEN: batch error does not name the failing element index; got %q — the percent-w wrap must preserve the element index so a corrupt element is attributable within the batch", err.Error())
	}

	// errors.As MUST recover the underlying *WireIntegrityError with its full
	// diagnostic context — the Option C payoff, now reachable on the batch path.
	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("PHASE2e INVARIANT BROKEN: ApplyCRDTDeltaBatch rejected the mismatched batch with the wrong error type %T; expected *WireIntegrityError (the seam's typed error) recoverable via errors.As through the element-index wrap", err)
	}
	if wie.EntityID != mismatchedEID {
		t.Errorf("Case 2 diagnostic EntityID: got %q, want %q — the error must carry the mismatched element's entityID so the failed element is attributable on the batch path (Option C payoff)", wie.EntityID, mismatchedEID)
	}
	if wie.OriginNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic OriginNodeID: got %x, want %x — the error must carry the origin peer id of the failing element on the batch path (Option C payoff)", wie.OriginNodeID, rtHostA)
	}
	if wie.OnWireDigest != wrongDigest {
		t.Errorf("Case 2 diagnostic OnWireDigest: got %x, want %x — the error must carry the digest the wire carried for element 1", wie.OnWireDigest, wrongDigest)
	}
	if wie.RecomputedDigest != rtPayloadDigest {
		t.Errorf("Case 2 diagnostic RecomputedDigest: got %x, want %x — the error must carry SHA-256(payload) the seam recomputed for element 1", wie.RecomputedDigest, rtPayloadDigest)
	}
	if wie.Kind != WireIntegrityDigestMismatch {
		t.Errorf("Case 2 Kind: got %d, want %d (WireIntegrityDigestMismatch)", wie.Kind, WireIntegrityDigestMismatch)
	}

	// ── THE CRITICAL BATCH ATOMICITY ASSERTION ──
	// Atomic-reject (S1a): a mid-batch mismatch leaves State() with ZERO new
	// entries for ANY entityID in the rejected batch — no partial apply. Element
	// 0 and element 2 reconstructed cleanly BEFORE element 1's mismatch was
	// hit, but they must NOT have been applied: ApplyCRDTDeltaBatch reconstructs
	// ALL then joins ONCE, and the early return on element 1 short-circuits
	// Join entirely. If a per-element-apply regression (Mutation C) joined
	// element 0 before the mismatch, State().Get(entityID_0) would have 1 entry
	// and this assertion would fire.
	//
	// engineB already holds the three Case-1 consistent entries (entityID_0/1/2
	// for the *consistent* batch). The mismatched batch uses the SAME entityIDs
	// (phase2eEntityID(i)) but element 1 carries a wrong digest and elements
	// 0/2 carry a DIFFERENT dot counter (phase2eDotCounter(i) — same as Case 1
	// by construction, so a successful apply would DEDUP against the Case-1
	// entry rather than add a second). To make the atomic-reject assertion
	// unambiguous, we assert that the joined entries for entityID_0 and
	// entityID_2 are STILL exactly the Case-1 entries (DotCounter ==
	// phase2eDotCounter(i) and PayloadDigest == rtPayloadDigest), proving the
	// mismatched batch did NOT re-apply them, and that entityID_1 STILL holds
	// exactly its Case-1 entry (the mismatched element did NOT reach Join).
	for i := 0; i < 3; i++ {
		eid := phase2eEntityID(i)
		got := engineB.State().Get(eid)
		if len(got) != 1 {
			t.Fatalf("PHASE2e INVARIANT BROKEN: after the mismatched batch, State().Get(%q) has %d entries, want exactly 1 (only the consistent Case-1 entry) — MUTATION A/B/C CATCH: the rejected batch left a partial apply (an element reached Join despite the mid-batch mismatch), reopening C6 / S1b on the batch path", eid, len(got))
		}
		if got[0].PayloadDigest == wrongDigest {
			t.Fatalf("PHASE2e INVARIANT BROKEN: State().Get(%q)[0].PayloadDigest is the MISMATCHED wrongDigest %x — the corrupt element reached Join on the batch path; the seam's atomic rejection did not prevent the apply; C6 is live on element %d of the batch", eid, wrongDigest, i)
		}
		if got[0].PayloadDigest != rtPayloadDigest {
			t.Errorf("Case 2 post-rejection: State().Get(%q)[0].PayloadDigest %x != rtPayloadDigest %x — Join must still hold only the consistent Case-1 entry for element %d", eid, got[0].PayloadDigest, rtPayloadDigest, i)
		}
		if got[0].DotCounter != phase2eDotCounter(i) {
			t.Errorf("Case 2 post-rejection: State().Get(%q)[0].DotCounter %#x != phase2eDotCounter(%d) %#x — the mismatched batch must not have re-applied element %d with a different dot", eid, got[0].DotCounter, i, phase2eDotCounter(i), i)
		}
	}
	t.Logf("Phase 2e Case 2 GREEN: ApplyCRDTDeltaBatch rejects a mid-batch mismatch at element 1 with %q (errors.As → *WireIntegrityError carrying EntityID/OriginNodeID/digests/Kind) and State() has ZERO new entries for entityID_0/1/2 — atomic-reject, no partial apply.", err.Error())

	// ─────────────────────────────────────────────────────────────────────
	// Case 3: empty batch, no-op.
	//
	// Build a 0-element CRDTDeltaBatch, call ApplyCRDTDeltaBatch(wire), assert:
	//   (a) no error,
	//   (b) State() is unchanged (the three Case-1 entries are still exactly
	//       what they were; no zero-field Join, no spurious entry).
	// Defends against "loop over zero elements and silently call Join with an
	// empty delta" behaving as anything other than a no-op. (Join-on-empty-delta
	// is a no-op by construction — pkg/sync/crdt.go Join returns early when the
	// Seq yields zero incoming entries — verified by this case green.)
	// ─────────────────────────────────────────────────────────────────────
	emptyBatch := buildBatchWireFrame(t, nil)
	if err := engineB.ApplyCRDTDeltaBatch(emptyBatch); err != nil {
		t.Fatalf("Case 3 (empty batch): ApplyCRDTDeltaBatch rejected a 0-element batch: %v — an empty batch is a no-op, not an error", err)
	}
	for i := 0; i < 3; i++ {
		eid := phase2eEntityID(i)
		got := engineB.State().Get(eid)
		if len(got) != 1 {
			t.Fatalf("Case 3: after the empty batch, State().Get(%q) has %d entries, want 1 (the Case-1 entry undisturbed) — an empty batch must leave State() unchanged", eid, len(got))
		}
		if got[0].PayloadDigest != rtPayloadDigest {
			t.Errorf("Case 3: State().Get(%q)[0].PayloadDigest %x != rtPayloadDigest %x — the empty batch disturbed the Case-1 entry for element %d", eid, got[0].PayloadDigest, rtPayloadDigest, i)
		}
	}
	t.Logf("Phase 2e Case 3 GREEN: ApplyCRDTDeltaBatch on a 0-element batch is a no-op — no error, State() unchanged.")
}
