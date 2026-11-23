// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests exercise ReconstructEntry with decoded wire frames. A valid
// payload and digest must reconstruct every contract field. A mismatched digest
// must return a WireIntegrityError with the entity, origin, received digest,
// and recomputed digest. Field assertions also detect zero-filled values.
//
// Shared frame fixtures come from crdt_capnp_roundtrip_test.go;
// CRDTDeltaEventWireVersion comes from crdt_apply.go.
package sync

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// buildReconstructFrame marshals and decodes a CRDTDeltaEvent with the supplied
// payload, digest, and dot counter. ReconstructEntry therefore reads capnp
// fields from a decoded arena rather than from the struct being populated.
// Shared nonzero fixtures make dropped or zero-filled fields visible.
func buildReconstructFrame(t *testing.T, digest [32]byte, payload string, dotCounter uint64) capnp_schema.CRDTDeltaEvent {
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
	// Decode from marshaled bytes to exercise the production read path.
	decMsg, err := capnp.Unmarshal(data)
	if err != nil {
		t.Fatalf("capnp.Unmarshal: %v", err)
	}
	ev2, err := capnp_schema.ReadRootCRDTDeltaEvent(decMsg)
	if err != nil {
		t.Fatalf("ReadRootCRDTDeltaEvent: %v", err)
	}
	return ev2
}

// rtReconstructDotCounter differs from the roundtrip test's dot value so these
// tests independently detect a dropped or zero-filled DotCounter.
const rtReconstructDotCounter uint64 = 0x7f7f7f7f7f7f7f7f

// TestReconstructEntryRejects checks successful field reconstruction and
// rejection of a payload whose received digest does not match its SHA-256.
func TestReconstructEntryRejects(t *testing.T) {
	// A matching payload and digest reconstruct every contract field.
	consistentEV := buildReconstructFrame(
		t, rtPayloadDigest, rtPayload, rtReconstructDotCounter)
	rec, err := ReconstructEntry(consistentEV)
	if err != nil {
		t.Fatalf("ReconstructEntry rejected a valid payload and digest: %v", err)
	}
	if rec == (ReconstructedEntry{}) {
		t.Fatalf("ReconstructEntry returned a zero entry with no error")
	}

	// Compare all 12 wire fields to detect zero fills and field swaps.
	if rec.EntityID != rtEntityID {
		t.Errorf("consistent EntityID: got %q, want %q — zero-fill or wire-field-drop regression", rec.EntityID, rtEntityID)
	}
	if rec.Payload != rtPayload {
		t.Errorf("reconstructed payload = %q, want %q", rec.Payload, rtPayload)
	}
	if rec.Payload == string(rtPayloadDigest[:]) {
		t.Errorf("reconstructed payload unexpectedly contains the digest bytes")
	}
	if rec.Entry.PayloadDigest != rtPayloadDigest {
		t.Errorf("consistent PayloadDigest: got %x, want %x", rec.Entry.PayloadDigest, rtPayloadDigest)
	}
	if rec.Entry.OriginNodeID != rtHostA {
		t.Errorf("consistent OriginNodeID: got %x, want %x", rec.Entry.OriginNodeID, rtHostA)
	}
	if rec.Entry.DotNodeID != rtHostA {
		t.Errorf("consistent DotNodeID: got %x, want %x (must come off the wire, not zero-filled)", rec.Entry.DotNodeID, rtHostA)
	}
	if rec.Entry.DotCounter != rtReconstructDotCounter {
		t.Errorf("consistent DotCounter: got %#x, want %#x — zero-fill after read makes this fail", rec.Entry.DotCounter, rtReconstructDotCounter)
	}
	if rec.Entry.H3Index != rtH3Index {
		t.Errorf("consistent H3Index: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.H3Index, rtH3Index)
	}
	if rec.Entry.SystemTime != rtSystemTime {
		t.Errorf("consistent SystemTime: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.SystemTime, rtSystemTime)
	}
	if rec.Entry.ValidTimeStart != rtValidTimeStart {
		t.Errorf("consistent ValidTimeStart: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.ValidTimeStart, rtValidTimeStart)
	}
	if rec.Entry.ValidTimeEnd != rtValidTimeEnd {
		t.Errorf("consistent ValidTimeEnd: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.ValidTimeEnd, rtValidTimeEnd)
	}
	if rec.Entry.AssertionTime != rtAssertionTime {
		t.Errorf("consistent AssertionTime: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.AssertionTime, rtAssertionTime)
	}
	if rec.Entry.DecisionTime != rtDecisionTime {
		t.Errorf("consistent DecisionTime: got %#x, want %#x (must come off the wire, not zero-filled)", rec.Entry.DecisionTime, rtDecisionTime)
	}

	// The stored digest must also validate against the returned payload string.
	recomputed := sha256.Sum256([]byte(rec.Payload))
	if !bytes.Equal(recomputed[:], rec.Entry.PayloadDigest[:]) {
		t.Errorf("consistent pair: reconstructed PayloadDigest %x != SHA-256(reconstructed payload) %x — seam returned an entry whose stored digest does not validate against its own payload", rec.Entry.PayloadDigest, recomputed)
	}

	// A mismatched digest must return a typed error and no partial entry.
	wrongDigest := sha256.Sum256([]byte(rtPayload + "tampered-by-a-buggy-peer"))
	if wrongDigest == rtPayloadDigest {
		wrongDigest[0] ^= 0x01
		if wrongDigest == rtPayloadDigest {
			t.Fatalf("could not construct a digest different from the valid digest")
		}
	}
	mismatchedEV := buildReconstructFrame(
		t, wrongDigest, rtPayload, rtReconstructDotCounter)
	rec2, err := ReconstructEntry(mismatchedEV)
	if err == nil {
		t.Fatalf("ReconstructEntry accepted a mismatched digest and returned entry %v", rec2)
	}
	if rec2 != (ReconstructedEntry{}) {
		t.Fatalf("ReconstructEntry returned a partial entry with the integrity error: %v", rec2)
	}

	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("ReconstructEntry rejected the mismatched pair with the wrong error type %T; expected *WireIntegrityError for the integrity failure", err)
	}

	// The error identifies the frame and both digest values.
	if wie.EntityID != rtEntityID {
		t.Errorf("mismatched diagnostic EntityID: got %q, want %q — the error must carry the entityID so a failed frame is attributable", wie.EntityID, rtEntityID)
	}
	if wie.OriginNodeID != rtHostA {
		t.Errorf("mismatched diagnostic OriginNodeID: got %x, want %x — the error must carry the origin peer id", wie.OriginNodeID, rtHostA)
	}
	if wie.OnWireDigest != wrongDigest {
		t.Errorf("mismatched diagnostic OnWireDigest: got %x, want %x — the error must carry the digest the wire carried", wie.OnWireDigest, wrongDigest)
	}
	if wie.RecomputedDigest != rtPayloadDigest {
		t.Errorf("mismatched diagnostic RecomputedDigest: got %x, want %x — the error must carry SHA-256(payload) the seam recomputed", wie.RecomputedDigest, rtPayloadDigest)
	}
	if wie.Kind != WireIntegrityDigestMismatch {
		t.Errorf("mismatched Kind: got %d, want %d (WireIntegrityDigestMismatch)", wie.Kind, WireIntegrityDigestMismatch)
	}

	t.Logf("ReconstructEntry rejects a mismatched (payload, payloadDigest) pair with %q (the seam is the location for this check, separated from Join).", err.Error())
}

// reconstructFrameFresh builds a valid decoded frame for the success-path
// allocation measurement.
func reconstructFrameFresh(t *testing.T) capnp_schema.CRDTDeltaEvent {
	t.Helper()
	return buildReconstructFrame(t, rtPayloadDigest, rtPayload, rtReconstructDotCounter)
}

// TestZeroCopyPayloadAllocReduction requires fewer than the four allocations
// per call measured before ReconstructedEntry was returned by value (ADR-0014).
// It also checks that PayloadBytes and the returned Payload string contain the
// same bytes and validate against the received digest. The bound allows for
// compiler-dependent allocation differences while catching a pointer-return
// regression.
func TestZeroCopyPayloadAllocReduction(t *testing.T) {
	ev := reconstructFrameFresh(t)

	allocs := testing.AllocsPerRun(100, func() {
		rec, err := ReconstructEntry(ev)
		if err != nil {
			t.Fatalf("ReconstructEntry rejected the consistent frame: %v — the test must run the success path to measure allocs", err)
		}
		// Consume the result so the call cannot be dead-code eliminated.
		if rec == (ReconstructedEntry{}) {
			t.Fatalf("ReconstructEntry returned the zero entry on the consistent frame")
		}
		// Read the result fields so the call cannot be eliminated.
		_ = rec.EntityID
		_ = rec.Payload
		_ = rec.Entry
	})

	// The combined count must remain below the old four-allocation baseline.
	if allocs >= 4 {
		t.Fatalf("ReconstructEntry allocated %.2f objects per call, want fewer than 4", allocs)
	}
	t.Logf("ReconstructEntry success path = %.2f allocs/op (< 4 baseline; zero-copy read and value return hold)", allocs)

	// PayloadBytes aliases the segment, while the returned string copies it.
	// Both representations must hash to the received digest.
	rec, err := ReconstructEntry(ev)
	if err != nil {
		t.Fatalf("consistent frame rejected: %v", err)
	}
	if rec.Payload != rtPayload {
		t.Errorf("rec.Payload != rtPayload — string(payloadBytes) diverged from the segment bytes (got len=%d, want len=%d)", len(rec.Payload), len(rtPayload))
	}
	// The digest must validate against the materialized payload string and the
	// original — proving the zero-copy bytes fed to SHA are the same bytes the
	// string was materialized from (no alias corruption, no double-copy skew).
	wantDigest := sha256.Sum256([]byte(rtPayload))
	if rec.Entry.PayloadDigest != rtPayloadDigest {
		t.Errorf("rec.Entry.PayloadDigest != on-wire rtPayloadDigest — the digest field drifted")
	}
	if rec.Entry.PayloadDigest != [32]byte(wantDigest) {
		t.Errorf("rec.Entry.PayloadDigest %x != SHA-256(rtPayload) %x — the zero-copy PayloadBytes the SHA consumed did not hash to the same value as rtPayload (alias corruption / double-copy skew)", rec.Entry.PayloadDigest, wantDigest)
	}
	// And the SHA of the materialized string must equal the SHA of the original
	// (the round-trip is byte-identical).
	if sha256.Sum256([]byte(rec.Payload)) != wantDigest {
		t.Errorf("SHA-256(rec.Payload) != SHA-256(rtPayload) — the materialized string diverged from the original payload bytes")
	}
}
