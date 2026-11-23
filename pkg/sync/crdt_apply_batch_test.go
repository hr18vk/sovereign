// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Batched reconstruction integrity tests.
//
// The three cases cover a valid three-event batch, a digest mismatch in the
// middle event, and an empty batch. The mismatch case checks the wrapped
// WireIntegrityError and verifies that no event from the rejected batch joins.
// Distinct dot counters distinguish partial application from the entries left
// by the valid batch.
package sync

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
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

// buildBatchWireFrame marshals one CRDTDeltaEvent per spec. Shared fields use
// the rt sentinels; entity ID, payload, digest, and dot counter vary per event
// so fixtures can target a specific index and distinguish joined entries.
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

// applyBatchEntityID returns a distinct 40-char entityID per batch element index,
// derived from the shared rtEntityID prefix so the far-side field-equality
// assertions against the rt* sentinels stay meaningful (the entityID dimension
// is the per-element distinguisher; every other CRDTEntry field is shared).
func applyBatchEntityID(i int) string {
	return fmt.Sprintf("%s;el=%d", rtEntityID, i)
}

// applyBatch2DotOffset gives rejected-batch entries different dots from the
// entries already joined by the valid-batch case. A partial application would
// therefore produce two entries instead of being hidden by dot deduplication.
const applyBatch2DotOffset uint64 = 100

// applyBatchDotCounter returns a distinct nonzero DotCounter for each element
// so missing or zero-filled fields fail the joined-state assertions.
func applyBatchDotCounter(i int) uint64 {
	return rtReconstructDotCounter + uint64(i)
}

// assertJoinedEntryFields checks every CRDTEntry contract field and confirms
// that the stored digest matches the original payload.
func assertJoinedEntryFields(t *testing.T, ce CRDTEntry, entityID string, dotCounter uint64) {
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
		t.Errorf("DotCounter: got %#x, want %#x; joined state must preserve each event's dot", ce.DotCounter, dotCounter)
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

// TestApplyCRDTDeltaBatchRejects checks successful application, atomic
// rejection of a mid-batch digest mismatch with full diagnostic context, and
// empty-batch behavior.
func TestApplyCRDTDeltaBatchRejects(t *testing.T) {
	engineB := setupRTEngine(t, rtHostB, 100)
	// Large sentinels make missing dot fields visible. Unbounded slack admits
	// them here; crdt_lamport_skew_test.go exercises the production bound.
	engineB.SetLamportAbsoluteSlack(LamportSkewAbsoluteSlackUnbounded)

	// Case 1: three valid events join under distinct entity IDs with every
	// contract field preserved.
	var specs1 []batchElementSpec
	for i := 0; i < 3; i++ {
		specs1 = append(specs1, batchElementSpec{
			entityID:      applyBatchEntityID(i),
			payload:       rtPayload,
			payloadDigest: rtPayloadDigest,
			dotCounter:    applyBatchDotCounter(i),
		})
	}
	consistentBatch := buildBatchWireFrame(t, specs1)
	if _, err := engineB.ApplyCRDTDeltaBatch(consistentBatch); err != nil {
		t.Fatalf("Case 1 (all-consistent 3-element batch): ApplyCRDTDeltaBatch rejected a consistent batch: %v — the batch path must succeed when every element's SHA-256(payload) == PayloadDigest and all fields read cleanly", err)
	}
	for i := 0; i < 3; i++ {
		eid := applyBatchEntityID(i)
		got := engineB.State().Get(eid)
		if len(got) != 1 {
			t.Fatalf("Case 1 element %d: State().Get(%q) has %d entries, want exactly 1 — Join did not apply this validated batch element, so the batch did not wire the seam to Join correctly for N=3", i, eid, len(got))
		}
		assertJoinedEntryFields(t, got[0], eid, applyBatchDotCounter(i))
	}
	t.Logf("three valid batch events joined with all CRDTEntry fields preserved")

	// Case 2: a wrong digest at index 1 rejects the batch. The error names the
	// index and preserves WireIntegrityError's entity, origin, digest, and kind
	// fields. No element from this batch may join, including earlier valid ones.
	wrongDigest := sha256.Sum256([]byte(rtPayload + "mismatched-element-1-by-a-buggy-or-tampering-peer"))
	if wrongDigest == rtPayloadDigest {
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			t.Fatalf("Case 2: could not construct a deterministic mismatched digest; give up rather than risk a false green")
		}
	}
	mismatchedEID := applyBatchEntityID(1)

	specs2 := []batchElementSpec{
		{entityID: applyBatchEntityID(0), payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: applyBatchDotCounter(0) + applyBatch2DotOffset},
		{entityID: mismatchedEID, payload: rtPayload, payloadDigest: wrongDigest, dotCounter: applyBatchDotCounter(1) + applyBatch2DotOffset},
		{entityID: applyBatchEntityID(2), payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: applyBatchDotCounter(2) + applyBatch2DotOffset},
	}
	mismatchedBatch := buildBatchWireFrame(t, specs2)
	_, err := engineB.ApplyCRDTDeltaBatch(mismatchedBatch)
	if err == nil {
		t.Fatalf("ApplyCRDTDeltaBatch accepted element 1 with SHA-256(payload) != PayloadDigest; want a digest-mismatch rejection")
	}

	// The wrapping must name element index 1.
	if !strings.Contains(err.Error(), "element 1") {
		t.Fatalf("CRDT reconstruction integrity invariant broken: batch error does not name the failing element index; got %q — the percent-w wrap must preserve the element index so a corrupt element is attributable within the batch", err.Error())
	}

	// errors.As must recover the underlying WireIntegrityError and its complete
	// diagnostic context through the element-index wrapper.
	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("CRDT reconstruction integrity invariant broken: ApplyCRDTDeltaBatch rejected the mismatched batch with the wrong error type %T; expected *WireIntegrityError (the seam's typed error) recoverable via errors.As through the element-index wrap", err)
	}
	if wie.EntityID != mismatchedEID {
		t.Errorf("Case 2 diagnostic EntityID: got %q, want %q; error must identify the mismatched element", wie.EntityID, mismatchedEID)
	}
	if wie.OriginNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic OriginNodeID: got %x, want %x; error must identify the failing element's origin", wie.OriginNodeID, rtHostA)
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

	// Each ID already has its valid Case 1 entry. Different dots in Case 2 make
	// any partial application visible as another entry; unchanged payload and dot
	// checks confirm that only the original entries remain.
	for i := 0; i < 3; i++ {
		eid := applyBatchEntityID(i)
		got := engineB.State().Get(eid)
		if len(got) != 1 {
			t.Fatalf("after rejected batch, State().Get(%q) has %d entries, want only the original Case 1 entry", eid, len(got))
		}
		if got[0].PayloadDigest == wrongDigest {
			t.Fatalf("CRDT reconstruction integrity invariant broken: State().Get(%q)[0].PayloadDigest is the mismatched wrongDigest %x — the corrupt element reached Join on the batch path; the seam's atomic rejection did not prevent the apply; the wire-integrity gap is live on element %d of the batch", eid, wrongDigest, i)
		}
		if got[0].PayloadDigest != rtPayloadDigest {
			t.Errorf("Case 2 post-rejection: State().Get(%q)[0].PayloadDigest %x != rtPayloadDigest %x — Join must still hold only the consistent Case-1 entry for element %d", eid, got[0].PayloadDigest, rtPayloadDigest, i)
		}
		if got[0].DotCounter != applyBatchDotCounter(i) {
			t.Errorf("Case 2 post-rejection: State().Get(%q)[0].DotCounter %#x != applyBatchDotCounter(%d) %#x — the mismatched batch must not have re-applied element %d with a different dot", eid, got[0].DotCounter, i, applyBatchDotCounter(i), i)
		}
	}
	t.Logf("mid-batch mismatch rejected with %q; no new entries joined", err.Error())

	// Case 3: an empty Seq makes Join a no-op and preserves all Case 1 entries.
	emptyBatch := buildBatchWireFrame(t, nil)
	if _, err := engineB.ApplyCRDTDeltaBatch(emptyBatch); err != nil {
		t.Fatalf("Case 3 (empty batch): ApplyCRDTDeltaBatch rejected a 0-element batch: %v — an empty batch is a no-op, not an error", err)
	}
	for i := 0; i < 3; i++ {
		eid := applyBatchEntityID(i)
		got := engineB.State().Get(eid)
		if len(got) != 1 {
			t.Fatalf("Case 3: after the empty batch, State().Get(%q) has %d entries, want 1 (the Case-1 entry undisturbed) — an empty batch must leave State() unchanged", eid, len(got))
		}
		if got[0].PayloadDigest != rtPayloadDigest {
			t.Errorf("Case 3: State().Get(%q)[0].PayloadDigest %x != rtPayloadDigest %x — the empty batch disturbed the Case-1 entry for element %d", eid, got[0].PayloadDigest, rtPayloadDigest, i)
		}
	}
	t.Logf("empty batch returned no error and left state unchanged")
}
