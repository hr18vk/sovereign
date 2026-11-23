// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Causal-dot attribution tests for single events and batches.
//
// ReconstructEntry rejects a frame whose DotNodeID differs from OriginNodeID,
// preventing an origin from claiming a dot in another node's counter space.
// The tests cover acceptance, single-event rejection, atomic batch rejection,
// diagnostic fields, and validation order. Attribution is checked before the
// payload digest, so a frame with both faults reports DotOriginMismatch.
package sync

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// rtSomeOtherNodeID differs from both the sender and receiver. Pairing it with
// OriginNodeID rtHostA creates a frame that attributes a dot to a counter space
// the claimed origin does not own.
var rtSomeOtherNodeID = [16]byte{
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
}

// buildDotOriginWireFrame marshals a CRDTDeltaEvent with independently chosen
// origin and dot node IDs. The caller also controls the payload, digest, and
// dot counter, allowing attribution and digest faults to be isolated or
// combined while all other fields retain their shared sentinels.
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

// rtDotOriginEntityID is the single-event entityID for Cases 1, 2, and 4 —
// distinct from the roundtrip/apply rtEntityID so ApplyCRDTDeltaEvent writes
// into host B's state under its own key, isolating this test's join from any
// prior test state. 40-char (same shape as rtEntityID) so a 16-byte-truncation
// regression still changes both length and content on the far side.
const rtDotOriginEntityID = "tenant=acme;ledger=txn;id=dot-origin-attribution"

// rtDotOriginDotCounter is a distinct nonzero DotCounter for the single-event
// frame, distinct from rtReconstructDotCounter so Join-side state is
// unambiguous against any prior apply test residue.
const rtDotOriginDotCounter uint64 = 0x2f2f2f2f2f2f2f2f

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

// dotOriginBatchEntityID returns a distinct 40-char entityID per batch element,
// derived from rtDotOriginEntityID so the far-side field-equality assertions
// isolate this batch from the single-event and from the prior batch.
func dotOriginBatchEntityID(i int) string {
	return fmt.Sprintf("%s;el=%d", rtDotOriginEntityID, i)
}

// dotOriginBatchDotCounter returns a distinct nonzero DotCounter per element.
func dotOriginBatchDotCounter(i int) uint64 {
	return rtDotOriginDotCounter + uint64(i) + 1
}

// TestCausalDotAttributionRejects covers valid attribution, single-event and
// batch rejection, and attribution-before-digest validation order.
func TestCausalDotAttributionRejects(t *testing.T) {
	engineB := setupRTEngine(t, rtHostB, 100)
	// Unbounded slack admits the large dot sentinels used to detect missing
	// fields; skew enforcement has separate production-default tests.
	engineB.SetLamportAbsoluteSlack(LamportSkewAbsoluteSlackUnbounded)

	// Case 1: matching dot and origin IDs are accepted and joined unchanged.
	consistentWire := buildDotOriginWireFrame(t, rtDotOriginEntityID, rtHostA, rtHostA, rtPayloadDigest, rtPayload, rtDotOriginDotCounter)
	if err := engineB.ApplyCRDTDeltaEvent(consistentWire); err != nil {
		t.Fatalf("Case 1 (consistent attribution): ApplyCRDTDeltaEvent rejected a frame whose DotNodeID == OriginNodeID == rtHostA: %v — the live path must succeed when attribution is consistent and the digest is consistent", err)
	}

	gotConsistent := engineB.State().Get(rtDotOriginEntityID)
	if len(gotConsistent) == 0 {
		t.Fatalf("Case 1: State().Get(%q) returned no entries — Join did not apply the validated delta; the consistent-attribution happy path is broken", rtDotOriginEntityID)
	}
	if len(gotConsistent) != 1 {
		t.Fatalf("Case 1: State().Get(%q) returned %d entries, want 1 — Join applied the delta to the wrong cardinality", rtDotOriginEntityID, len(gotConsistent))
	}
	ce := gotConsistent[0]
	if ce.OriginNodeID != rtHostA {
		t.Errorf("Case 1 OriginNodeID: got %x, want %x — the consistent attribution must reach Join with OriginNodeID off the wire", ce.OriginNodeID, rtHostA)
	}
	if ce.DotNodeID != rtHostA {
		t.Errorf("Case 1 DotNodeID: got %x, want %x — the consistent attribution must reach Join with DotNodeID == OriginNodeID == rtHostA", ce.DotNodeID, rtHostA)
	}
	if ce.DotCounter != rtDotOriginDotCounter {
		t.Errorf("Case 1 DotCounter: got %#x, want %#x — the dot counter must reach Join off the wire (not zero-filled)", ce.DotCounter, rtDotOriginDotCounter)
	}
	// Digest validation remains independent of attribution validation.
	recomputedConsistent := sha256.Sum256([]byte(rtPayload))
	if !bytes.Equal(recomputedConsistent[:], ce.PayloadDigest[:]) {
		t.Errorf("Case 1: joined PayloadDigest %x != SHA-256(rtPayload) %x — the digest axis still holds on this path", ce.PayloadDigest, recomputedConsistent)
	}
	t.Logf("consistent attribution applied for %q with matching dot and origin IDs", rtDotOriginEntityID)

	// Case 2: a foreign dot is rejected with WireIntegrityDotOriginMismatch.
	// The error retains the entity, claimed origin, and dot IDs; Join must not
	// add anything beyond the valid entry from Case 1.
	mismatchWire := buildDotOriginWireFrame(t, rtDotOriginEntityID, rtHostA, rtSomeOtherNodeID, rtPayloadDigest, rtPayload, rtDotOriginDotCounter)
	err := engineB.ApplyCRDTDeltaEvent(mismatchWire)
	if err == nil {
		t.Fatalf("ApplyCRDTDeltaEvent accepted DotNodeID %x with OriginNodeID %x; want attribution rejection before Join", rtSomeOtherNodeID, rtHostA)
	}

	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("ApplyCRDTDeltaEvent rejected the foreign-dotted frame with the wrong error type %T; expected *WireIntegrityError so the attribution failure is errors.As-able", err)
	}
	if wie.Kind != WireIntegrityDotOriginMismatch {
		t.Errorf("Case 2 Kind: got %d, want %d (WireIntegrityDotOriginMismatch) — the seam must classify a dot/origin mismatch distinctly from a digest mismatch", wie.Kind, WireIntegrityDotOriginMismatch)
	}
	if wie.EntityID != rtDotOriginEntityID {
		t.Errorf("Case 2 diagnostic EntityID: got %q, want %q — the error must carry the entityID so the failed frame is attributable", wie.EntityID, rtDotOriginEntityID)
	}
	if wie.OriginNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic OriginNodeID: got %x, want %x — the error must carry the claimed origin peer id", wie.OriginNodeID, rtHostA)
	}
	if wie.DotNodeID != rtSomeOtherNodeID {
		t.Errorf("Case 2 diagnostic DotNodeID: got %x, want %x — the error must carry the claimed dot peer id so both sides of the mismatched pair are named", wie.DotNodeID, rtSomeOtherNodeID)
	}

	// Only the valid Case 1 entry may remain. An additional entry or a foreign
	// DotNodeID would show that the mismatched frame reached Join.
	gotMismatched := engineB.State().Get(rtDotOriginEntityID)
	if len(gotMismatched) != 1 || gotMismatched[0].DotNodeID != rtHostA {
		t.Fatalf("after the mismatched single-event, State().Get(%q) has %d entries (DotNodeID of [0] = %x); want exactly 1 entry with DotNodeID == rtHostA — the foreign-dotted frame (DotNodeID=%x) reached Join despite the attribution mismatch", rtDotOriginEntityID, len(gotMismatched), func() [16]byte {
			if len(gotMismatched) > 0 {
				return gotMismatched[0].DotNodeID
			}
			return [16]byte{}
		}(), rtSomeOtherNodeID)
	}
	t.Logf("foreign dot %x with origin %x rejected with %q; only the valid entry remains", rtSomeOtherNodeID, rtHostA, err.Error())

	// Case 3: a foreign dot in the middle event rejects the entire batch.
	// The wrapped error identifies element 1 and retains its diagnostic fields.
	// A fresh engine makes the zero-new-entry assertion unambiguous.
	engineBatch := setupRTEngine(t, rtHostB, 1000)
	// Unbounded slack admits the large dot sentinels used to detect missing
	// fields; skew enforcement has separate production-default tests.
	engineBatch.SetLamportAbsoluteSlack(LamportSkewAbsoluteSlackUnbounded)

	mismatchedEID := dotOriginBatchEntityID(1)
	specs := []dotOriginBatchSpec{
		{entityID: dotOriginBatchEntityID(0), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: dotOriginBatchDotCounter(0)},
		{entityID: mismatchedEID, originNodeID: rtHostA, dotNodeID: rtSomeOtherNodeID, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: dotOriginBatchDotCounter(1)},
		{entityID: dotOriginBatchEntityID(2), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: dotOriginBatchDotCounter(2)},
	}
	mismatchedBatchWire := buildBatchDotOriginWireFrame(t, specs)
	_, errBatch := engineBatch.ApplyCRDTDeltaBatch(mismatchedBatchWire)
	if errBatch == nil {
		t.Fatalf("ApplyCRDTDeltaBatch accepted middle element with DotNodeID %x != OriginNodeID %x; want atomic rejection", rtSomeOtherNodeID, rtHostA)
	}
	// The wrap names element 1 (the failing index).
	if !containsSubstring(errBatch.Error(), "element 1") {
		t.Errorf("Case 3 wrap: error %q does not name element 1 — the percent-w wrap must preserve the failing element index so the attribution failure is attributable within the batch", errBatch.Error())
	}
	var wieBatch *WireIntegrityError
	if !errors.As(errBatch, &wieBatch) {
		t.Fatalf("ApplyCRDTDeltaBatch rejected the attribution-mismatched batch with the wrong error type %T; expected *WireIntegrityError recoverable via errors.As through the element-index wrap", errBatch)
	}
	if wieBatch.Kind != WireIntegrityDotOriginMismatch {
		t.Errorf("Case 3 Kind: got %d, want %d (WireIntegrityDotOriginMismatch) — the batch path must classify a dot/origin mismatch distinctly (inherited from the seam)", wieBatch.Kind, WireIntegrityDotOriginMismatch)
	}
	if wieBatch.EntityID != mismatchedEID {
		t.Errorf("Case 3 diagnostic EntityID: got %q, want %q — the error must carry the failing element's entityID so element 1 is attributable on the batch path", wieBatch.EntityID, mismatchedEID)
	}
	if wieBatch.OriginNodeID != rtHostA {
		t.Errorf("Case 3 diagnostic OriginNodeID: got %x, want %x — the error must carry claim rtHostA as the origin of the foreign-dotted element 1", wieBatch.OriginNodeID, rtHostA)
	}
	if wieBatch.DotNodeID != rtSomeOtherNodeID {
		t.Errorf("Case 3 diagnostic DotNodeID: got %x, want %x — the error must carry rtSomeOtherNodeID as the foreign dot of element 1", wieBatch.DotNodeID, rtSomeOtherNodeID)
	}
	// Atomic rejection: zero new entries for all three entity IDs.
	for i := 0; i < 3; i++ {
		eid := dotOriginBatchEntityID(i)
		got := engineBatch.State().Get(eid)
		if len(got) != 0 {
			t.Fatalf("after the mismatched batch, State().Get(%q) has %d entries, want zero — the batch path's atomic rejection was not inherited by the dot/origin check: element %d reached Join despite the mid-batch attribution mismatch", eid, len(got), i)
		}
	}
	t.Logf("batch attribution mismatch rejected with %q; no entries joined", errBatch.Error())

	// Case 4: when attribution and digest are both wrong, the reported error is
	// DotOriginMismatch because attribution is checked first. No entry joins.
	wrongDigest := sha256.Sum256([]byte(rtPayload + "doubly-corrupt-both-attribution-and-digest"))
	if wrongDigest == rtPayloadDigest {
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			wrongDigest[1] ^= 0x02
		}
	}
	// Fresh engine so Case 4's state assertion is unambiguous.
	engineDoubly := setupRTEngine(t, rtHostB, 2000)
	// Unbounded slack admits the large dot sentinels used to detect missing
	// fields; skew enforcement has separate production-default tests.
	engineDoubly.SetLamportAbsoluteSlack(LamportSkewAbsoluteSlackUnbounded)

	doublyWire := buildDotOriginWireFrame(t, rtDotOriginEntityID, rtHostA, rtSomeOtherNodeID, wrongDigest, rtPayload, rtDotOriginDotCounter)
	errDoubly := engineDoubly.ApplyCRDTDeltaEvent(doublyWire)
	if errDoubly == nil {
		t.Fatalf("ApplyCRDTDeltaEvent accepted a doubly-corrupt frame (DotNodeID=%x != OriginNodeID=%x and PayloadDigest != SHA-256(payload)) — the seam must reject on the first detected violation, not silently apply", rtSomeOtherNodeID, rtHostA)
	}
	var wieDoubly *WireIntegrityError
	if !errors.As(errDoubly, &wieDoubly) {
		t.Fatalf("ApplyCRDTDeltaEvent rejected the doubly-corrupt frame with the wrong error type %T; expected *WireIntegrityError", errDoubly)
	}
	if wieDoubly.Kind != WireIntegrityDotOriginMismatch {
		t.Fatalf("frame with attribution and digest faults reported Kind %d, want %d (WireIntegrityDotOriginMismatch): attribution must be checked first", wieDoubly.Kind, WireIntegrityDotOriginMismatch)
	}
	gotDoubly := engineDoubly.State().Get(rtDotOriginEntityID)
	if len(gotDoubly) != 0 {
		t.Fatalf("after the doubly-corrupt single-event, State().Get(%q) has %d entries, want zero — the seam must reject the frame before Join applies it", rtDotOriginEntityID, len(gotDoubly))
	}
	t.Logf("frame with DotNodeID=%x != OriginNodeID=%x and a digest mismatch reported WireIntegrityDotOriginMismatch first", rtSomeOtherNodeID, rtHostA)
}

// containsSubstring reports whether s contains substr.
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
