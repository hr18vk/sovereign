// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Tests for the ApplyCRDTDeltaEvent transport wiring.
//
// A valid frame must reach Join with every CRDTEntry field intact. A frame whose
// PayloadDigest differs from SHA-256(payload) must return a WireIntegrityError
// containing the entity, origin, and both digests, without changing the joined
// state. The fixtures reuse the reconstruction test sentinels and the production
// CRDTDeltaEventWireVersion so the complete marshal/decode/apply path is covered.
package sync

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// buildApplyWireFrame marshals a CRDTDeltaEvent from the shared reconstruction
// sentinels and the supplied digest, payload, and dot counter. Returning wire
// bytes exercises the same marshal/decode boundary as an inbound transport
// frame, while nonzero sentinels make accidental zero-filled fields visible.
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

// TestApplyCRDTDeltaEventRejects checks that a valid frame is joined intact and
// that a digest mismatch returns its typed diagnostic without being applied.
func TestApplyCRDTDeltaEventRejects(t *testing.T) {
	engineB := setupRTEngine(t, rtHostB, 100)
	// The shared fixture uses a large dot counter to detect zero-filled fields.
	// Disable the skew bound for this digest-routing test; the separate Lamport
	// skew tests exercise the production bound and its default slack.
	engineB.SetLamportAbsoluteSlack(LamportSkewAbsoluteSlackUnbounded)

	// A consistent frame must reach the joined state with every field preserved.
	consistentWire := buildApplyWireFrame(t, rtPayloadDigest, rtPayload, rtReconstructDotCounter)
	if err := engineB.ApplyCRDTDeltaEvent(consistentWire); err != nil {
		t.Fatalf("Case 1 (consistent frame): ApplyCRDTDeltaEvent rejected a consistent (payload, payloadDigest) pair: %v — the live path must succeed when SHA-256(payload) == PayloadDigest and all fields read cleanly", err)
	}

	gotConsistent := engineB.State().Get(rtEntityID)
	if len(gotConsistent) == 0 {
		t.Fatalf("Case 1: host B State().Get(%q) returned no entries — Join did not apply the validated delta, so the transport did not wire the seam to Join correctly", rtEntityID)
	}
	if len(gotConsistent) != 1 {
		t.Fatalf("Case 1: host B got %d entries for %q, want 1 — Join applied the delta to the wrong cardinality", len(gotConsistent), rtEntityID)
	}
	ce := gotConsistent[0]

	// Looking up the original entity string also catches accidental truncation
	// or substitution of the key during reconstruction.
	t.Logf("Case 1: entityID preserved — State().Get(%q) returned 1 entry", rtEntityID)

	// Assert every contract field against the joined entry, not just the
	// intermediate reconstruction result.
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
		t.Errorf("Case 1 DotCounter: got %#x, want %#x — a zero-fill on the production path makes this fail against the joined state, not just the reconstructed entry", ce.DotCounter, rtReconstructDotCounter)
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

	// Recompute the digest from the original payload to ensure Join stored the
	// validated value rather than a stale or substituted digest.
	recomputedConsistent := sha256.Sum256([]byte(rtPayload))
	if !bytes.Equal(recomputedConsistent[:], ce.PayloadDigest[:]) {
		t.Errorf("Case 1: joined PayloadDigest %x != SHA-256(rtPayload) %x — the entry Join stored does not satisfy the integrity property the seam validated", ce.PayloadDigest, recomputedConsistent)
	}

	// A mismatched digest must produce a typed error with both digests and the
	// frame's attribution. State must still contain only the valid entry above.
	wrongDigest := sha256.Sum256([]byte(rtPayload + "mismatched-by-a-buggy-or-tampering-peer"))
	if wrongDigest == rtPayloadDigest {
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			t.Fatalf("could not construct a digest different from the valid payload digest")
		}
	}
	mismatchedWire := buildApplyWireFrame(t, wrongDigest, rtPayload, rtReconstructDotCounter)
	err := engineB.ApplyCRDTDeltaEvent(mismatchedWire)
	if err == nil {
		t.Fatalf("ApplyCRDTDeltaEvent accepted a payload whose SHA-256 digest differs from PayloadDigest")
	}

	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("ApplyCRDTDeltaEvent returned %T for a digest mismatch; expected *WireIntegrityError", err)
	}

	// The error retains enough context to attribute and diagnose the bad frame.
	if wie.EntityID != rtEntityID {
		t.Errorf("diagnostic EntityID: got %q, want %q; the failed frame must remain attributable", wie.EntityID, rtEntityID)
	}
	if wie.OriginNodeID != rtHostA {
		t.Errorf("diagnostic OriginNodeID: got %x, want %x", wie.OriginNodeID, rtHostA)
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

	// Rejection must happen before Join: a bypass or a disabled digest check
	// would add a second dotted entry under the same entity ID.
	gotMismatched := engineB.State().Get(rtEntityID)
	if len(gotMismatched) != 1 {
		t.Fatalf("after rejecting the mismatched frame, State().Get(%q) returned %d entries; want only the original valid entry", rtEntityID, len(gotMismatched))
	}
	// The surviving entry must be the valid one, not a substitution from the
	// rejected frame.
	if gotMismatched[0].PayloadDigest == wrongDigest {
		t.Fatalf("joined state contains rejected digest %x; integrity rejection must precede Join", wrongDigest)
	}
	if gotMismatched[0].PayloadDigest != rtPayloadDigest {
		t.Errorf("surviving PayloadDigest %x does not match the valid frame digest %x", gotMismatched[0].PayloadDigest, rtPayloadDigest)
	}

	t.Logf("ApplyCRDTDeltaEvent rejected a mismatched frame with %q and did not apply it", err.Error())
}
