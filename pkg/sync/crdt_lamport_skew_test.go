// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Lamport skew-bound tests for wire reconstruction and delta application.
//
// An inbound DotCounter above MaxAcceptableDotCounter is rejected before Join
// can advance the receiver's clock or persist the poisoned value. Single-event
// cases cover valid counters, far-future rejection with diagnostic fields, and
// validation order when attribution, digest, and skew are all invalid.
//
// The batch case checks ADR-0069 subset admission: valid elements join and the
// over-bound element is held. A concurrent InsertLocal test also verifies that
// ReconstructEntryWithSkewBound uses only the supplied atomic snapshot rather
// than rereading the moving receiver clock.
package sync

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// rtSkewEntityID isolates these tests from other apply fixtures. Its length
// also makes entity-ID truncation visible in receiver state.
const rtSkewEntityID = "tenant=acme;ledger=txn;id=lamport-skew-bound"

// Each rejection fixture derives its DotCounter from the receiver's computed
// bound rather than a fixed sentinel. Valid fixtures stay within the default
// bound of 1100 for a fresh engine at Lamport 100.

// buildSkewWireFrame builds a single CRDTDeltaEvent. Its arguments permit
// independent attribution, digest, and skew faults; the other fields use the
// shared sentinels.
func buildSkewWireFrame(t *testing.T, entityID string, originNodeID, dotNodeID [16]byte, digest [32]byte, payload string, dotCounter uint64) []byte {
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

// skewBatchSpec is the per-element override spec for buildSkewBatchFrame,
// mirroring dotOriginBatchSpec so a planted skew poison can ride on element 1
// of a 3-element batch while elements 0 and 2 stay consistent.
type skewBatchSpec struct {
	entityID      string
	originNodeID  [16]byte
	dotNodeID     [16]byte
	payload       string
	payloadDigest [32]byte
	dotCounter    uint64
}

// skewBatchEntityID returns a distinct entityID per batch element derived
// from rtSkewEntityID so the far-side assertions isolate this test's batch.
func skewBatchEntityID(i int) string {
	return fmt.Sprintf("%s;el=%d", rtSkewEntityID, i)
}

// buildSkewBatchFrame builds a batch whose elements can independently vary
// their attribution, digest, payload, and dot counter.
func buildSkewBatchFrame(t *testing.T, specs []skewBatchSpec) []byte {
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

// TestLamportSkewBoundRejects checks valid application, single-event skew
// rejection, batch subset admission, and error precedence.
func TestLamportSkewBoundRejects(t *testing.T) {
	// Case 1: a counter within the default bound (100 + 0 + 1000 = 1100)
	// joins and advances the receiver's Lamport clock normally.
	engineB1 := setupRTEngine(t, rtHostB, 100)
	// Case 1 uses the production default bound of 1100.
	const case1DotCounter uint64 = 150
	case1Wire := buildSkewWireFrame(t, rtSkewEntityID, rtHostA, rtHostA, rtPayloadDigest, rtPayload, case1DotCounter)
	if err := engineB1.ApplyCRDTDeltaEvent(case1Wire); err != nil {
		t.Fatalf("ApplyCRDTDeltaEvent rejected DotCounter=%d within bound 1100: %v", case1DotCounter, err)
	}
	gotC1 := engineB1.State().Get(rtSkewEntityID)
	if len(gotC1) != 1 {
		t.Fatalf("State().Get(%q) has %d entries after valid apply, want 1", rtSkewEntityID, len(gotC1))
	}
	if gotC1[0].DotCounter != case1DotCounter {
		t.Errorf("joined DotCounter: got %#x, want %#x", gotC1[0].DotCounter, case1DotCounter)
	}
	if postLamportC1 := engineB1.LamportCounter(); postLamportC1 != case1DotCounter {
		t.Fatalf("LamportCounter after valid apply: got %d, want inbound dot %d", postLamportC1, case1DotCounter)
	}
	t.Logf("within-bound DotCounter=%d applied; Lamport advanced to %d", case1DotCounter, engineB1.LamportCounter())

	// Case 2: bound+1 is rejected before Join. The error reports the complete
	// snapshot and inbound-dot context, while engine state and Lamport time
	// remain unchanged.
	engineB2 := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	snapB2 := engineB2.LamportSnapshot()
	boundB2 := MaxAcceptableDotCounter(snapB2) // 100 + 0 + 1000 = 1100
	case2DotCounter := boundB2 + 1             // smallest provably-poisoned value
	case2Wire := buildSkewWireFrame(t, rtSkewEntityID, rtHostA, rtHostA, rtPayloadDigest, rtPayload, case2DotCounter)
	errC2 := engineB2.ApplyCRDTDeltaEvent(case2Wire)
	if errC2 == nil {
		t.Fatalf("ApplyCRDTDeltaEvent accepted DotCounter=%d above bound %d; the frame must be rejected before Join", case2DotCounter, boundB2)
	}
	var wieC2 *WireIntegrityError
	if !errors.As(errC2, &wieC2) {
		t.Fatalf("skew rejection returned %T, want *WireIntegrityError", errC2)
	}
	if wieC2.Kind != WireIntegrityLamportSkewPoisoning {
		t.Fatalf("skew rejection Kind: got %d, want %d (WireIntegrityLamportSkewPoisoning)", wieC2.Kind, WireIntegrityLamportSkewPoisoning)
	}
	// All six diagnostic fields come from the snapshot and inbound frame.
	if wieC2.InboundDotCounter != case2DotCounter {
		t.Errorf("Case 2 diagnostic InboundDotCounter: got %d, want %d — the error must carry the inbound far-future DotCounter", wieC2.InboundDotCounter, case2DotCounter)
	}
	if wieC2.ReceiverLamport != snapB2.Lamport {
		t.Errorf("Case 2 diagnostic ReceiverLamport: got %d, want %d (snapshot.Lamport) — the error must carry the receiver's clock at the atomic snapshot", wieC2.ReceiverLamport, snapB2.Lamport)
	}
	if wieC2.ComputedBound != boundB2 {
		t.Errorf("Case 2 diagnostic ComputedBound: got %d, want %d — the error must carry the bound the wrapper computed so a reviewer can reconstruct", wieC2.ComputedBound, boundB2)
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
	// Attribution diagnostics also retain the dot and origin IDs from the wire.
	if wieC2.DotNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic DotNodeID: got %x, want %x (rtHostA off the wire)", wieC2.DotNodeID, rtHostA)
	}
	if wieC2.OriginNodeID != rtHostA {
		t.Errorf("Case 2 diagnostic OriginNodeID: got %x, want %x (rtHostA off the wire)", wieC2.OriginNodeID, rtHostA)
	}
	gotC2 := engineB2.State().Get(rtSkewEntityID)
	if len(gotC2) != 0 {
		t.Fatalf("State().Get(%q) has %d entries after skew rejection, want zero", rtSkewEntityID, len(gotC2))
	}
	if postLamportC2 := engineB2.LamportCounter(); postLamportC2 != snapB2.Lamport {
		t.Fatalf("LamportCounter advanced from %d to %d after skew rejection; rejected dots must not reach AdvanceLamportTo", snapB2.Lamport, postLamportC2)
	}
	t.Logf("DotCounter=%d above bound %d rejected with %q; entry not applied and Lamport remained %d", case2DotCounter, boundB2, errC2.Error(), engineB2.LamportCounter())

	// Case 3: element 1 exceeds the shared snapshot's bound. Elements 0 and 2
	// join, element 1 is held, and the clock advances only to the greatest
	// admitted dot. Processing past the held element prevents prefix starvation.
	engineB3 := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	snapB3 := engineB3.LamportSnapshot()
	boundB3 := MaxAcceptableDotCounter(snapB3) // 100 + 0 + 1000 = 1100
	case3ConsistentDot := uint64(160)          // within-bound, distinct from Case 1 for clarity
	case3PoisonDot := boundB3 + 1              // element 1's far-future stamp
	case3Specs := []skewBatchSpec{
		{entityID: skewBatchEntityID(0), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: case3ConsistentDot},
		{entityID: skewBatchEntityID(1), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: case3PoisonDot},
		{entityID: skewBatchEntityID(2), originNodeID: rtHostA, dotNodeID: rtHostA, payload: rtPayload, payloadDigest: rtPayloadDigest, dotCounter: case3ConsistentDot},
	}
	case3Wire := buildSkewBatchFrame(t, case3Specs)
	resC3, errC3 := engineB3.ApplyCRDTDeltaBatch(case3Wire)
	if errC3 != nil {
		t.Fatalf("ApplyCRDTDeltaBatch returned %v for a skew-only batch; want subset admission", errC3)
	}
	if resC3.Joined != 2 || resC3.Held != 1 {
		t.Fatalf("subset outcome {Joined:%d, Held:%d}, want {2, 1}: dots %d and %d straddle bound %d", resC3.Joined, resC3.Held, case3ConsistentDot, case3PoisonDot, boundB3)
	}
	if got := engineB3.State().Get(skewBatchEntityID(1)); len(got) != 0 {
		t.Fatalf("held element 1 joined (%d entries); dot %d exceeds bound %d", len(got), case3PoisonDot, boundB3)
	}
	for _, i := range []int{0, 2} {
		eid := skewBatchEntityID(i)
		if got := engineB3.State().Get(eid); len(got) != 1 {
			t.Fatalf("in-window element %d has %d entries for %q, want 1 (dot %d <= bound %d)", i, len(got), eid, case3ConsistentDot, boundB3)
		}
	}
	if postLamportC3 := engineB3.LamportCounter(); postLamportC3 != case3ConsistentDot {
		t.Fatalf("LamportCounter after subset apply: got %d, want greatest admitted dot %d; held dot %d must not advance it", postLamportC3, case3ConsistentDot, case3PoisonDot)
	}
	t.Logf("dot %d above bound %d held; batch outcome {Joined:%d, Held:%d}; Lamport advanced to admitted dot %d", case3PoisonDot, boundB3, resC3.Joined, resC3.Held, engineB3.LamportCounter())

	// Case 4: attribution, digest, and skew are all invalid. ReconstructEntry
	// checks attribution before digest (ADR-0045 §7), and the skew wrapper runs
	// afterward, so DotOriginMismatch is the reported error.
	engineB4 := setupRTEngine(t, rtHostB, 100) // fresh; production defaults
	snapB4 := engineB4.LamportSnapshot()
	boundB4 := MaxAcceptableDotCounter(snapB4) // 1100
	case4DotCounter := boundB4 + 1             // the skew-poison axis
	case4WrongDigest := sha256Sum(t, []byte(rtPayload+"triply-corrupt-digest"))
	case4Wire := buildSkewWireFrame(t, rtSkewEntityID, rtHostA, rtSomeOtherNodeID, case4WrongDigest, rtPayload, case4DotCounter)
	errC4 := engineB4.ApplyCRDTDeltaEvent(case4Wire)
	if errC4 == nil {
		t.Fatalf("invariant broken: ApplyCRDTDeltaEvent accepted a triply-corrupt frame (attribution + digest + skew all corrupt) — the seam must reject on the first detected violation, not silently apply")
	}
	var wieC4 *WireIntegrityError
	if !errors.As(errC4, &wieC4) {
		t.Fatalf("Case 4: errors.As did not recover *WireIntegrityError from %T", errC4)
	}
	// Attribution precedes digest validation, and both precede skew validation.
	if wieC4.Kind != WireIntegrityDotOriginMismatch {
		t.Fatalf("multiply-invalid frame reported Kind=%d (%s), want %d (WireIntegrityDotOriginMismatch): attribution must precede digest and skew checks", wieC4.Kind, kindName(wieC4.Kind), WireIntegrityDotOriginMismatch)
	}
	if wieC4.Kind == WireIntegrityLamportSkewPoisoning {
		t.Fatalf("skew reported before attribution on a multiply-invalid frame")
	}
	if gotC4 := engineB4.State().Get(rtSkewEntityID); len(gotC4) != 0 {
		t.Fatalf("State().Get has %d entries after rejection, want zero", len(gotC4))
	}
	t.Logf("multiply-invalid frame reported WireIntegrityDotOriginMismatch (Kind=%d) before skew", wieC4.Kind)
}

// TestLamportSnapshotCoherence calls ReconstructEntryWithSkewBound with a
// pinned snapshot while concurrent InsertLocal calls advance the engine clock.
// The skew error must retain snapshot.Lamport rather than a value reread during
// reconstruction, and the rejected reconstruction must return a zero entry.
func TestLamportSnapshotCoherence(t *testing.T) {
	engine := setupRTEngine(t, rtHostB, 100) // production defaults

	// Pin the snapshot the test will pass to the wrapper before the
	// InsertLocal storm starts. The wrapper must report this value as
	// ReceiverLamport, even though e.lamport moves while the call is in flight.
	snap := engine.LamportSnapshot()
	if snap.Lamport != 100 {
		t.Fatalf("setup: expected fresh engine lamport=100, got %d", snap.Lamport)
	}
	bound := MaxAcceptableDotCounter(snap) // 1100
	poisonDot := bound + 1                 // far-future stamp, bound+1

	// Build the wire frame, then decode it so the test can call the wrapper
	// directly with the pinned snapshot (controlling exactly what snapshot
	// crossed the boundary).
	case5Wire := buildSkewWireFrame(t, rtSkewEntityID, rtHostA, rtHostA, rtPayloadDigest, rtPayload, poisonDot)
	msg, err := capnp.Unmarshal(case5Wire)
	if err != nil {
		t.Fatalf("capnp.Unmarshal: %v", err)
	}
	defer msg.Release()
	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		t.Fatalf("ReadRootCRDTDeltaEvent: %v", err)
	}

	// Each InsertLocal advances the receiver through NextDot. The goroutine's
	// only purpose is to move the clock during reconstruction.
	var stop atomic.Bool
	var stormWG sync.WaitGroup
	stormWG.Add(1)
	go func() {
		defer stormWG.Done()
		entry := CRDTEntry{PayloadDigest: rtPayloadDigest, H3Index: rtH3Index}
		for !stop.Load() {
			_ = engine.InsertLocal("lamport-skew-concurrency-storm", entry)
		}
	}()
	// Wait until the clock is above the snapshot so an implementation that
	// rereads it would observe a different value. Failure to advance is a test
	// scheduling failure, not evidence of snapshot coherence.
	for engine.LamportCounter() <= snap.Lamport {
		// busy-wait: yield the scheduler so the storm goroutine runs.
	}
	lamportAtApply := engine.LamportCounter()
	if lamportAtApply <= snap.Lamport {
		t.Fatalf("concurrency test precondition: the InsertLocal storm did not advance e.Lamport above the pinned snapshot=%d (observed=%d) — the test would not exercise the defect; rerun (the storm goroutine was starved). This is a test-harness scheduling flake, not a defect; document and retry.", snap.Lamport, lamportAtApply)
	}

	// Pass the pinned snapshot directly while the goroutine continues advancing
	// the engine clock. Production callers use the same wrapper contract.
	rec, err := ReconstructEntryWithSkewBound(ev, snap)
	lamportAfterApply := engine.LamportCounter()

	// Stop the storm regardless of the assertion outcome.
	stop.Store(true)
	stormWG.Wait()

	if err == nil {
		t.Fatalf("ReconstructEntryWithSkewBound accepted DotCounter=%d above bound %d under concurrent InsertLocal", poisonDot, bound)
	}
	if rec != (ReconstructedEntry{}) {
		t.Fatalf("ReconstructEntryWithSkewBound returned a non-zero entry on skew rejection; want ReconstructedEntry{}")
	}
	var wie *WireIntegrityError
	if !errors.As(err, &wie) {
		t.Fatalf("concurrency test: errors.As did not recover *WireIntegrityError from %T", err)
	}
	if wie.Kind != WireIntegrityLamportSkewPoisoning {
		t.Fatalf("concurrency test: Kind got %d, want %d (WireIntegrityLamportSkewPoisoning) — the bound must reject the far-future frame even under concurrent InsertLocal", wie.Kind, WireIntegrityLamportSkewPoisoning)
	}
	// The observed clock values before and after reconstruction are both above
	// the snapshot, making an accidental reread visible in ReceiverLamport.
	if wie.ReceiverLamport != snap.Lamport {
		t.Fatalf("ReceiverLamport=%d, want pinned snapshot %d (engine clock was %d before reconstruction and %d after); wrapper must not reread the moving clock", wie.ReceiverLamport, snap.Lamport, lamportAtApply, lamportAfterApply)
	}
	if wie.ReceiverLamport != 100 {
		t.Errorf("concurrency test (belt): wie.ReceiverLamport=%d, want exactly 100 (the pinned fresh-engine snapshot, not the storm-advanced value)", wie.ReceiverLamport)
	}
	t.Logf("Lamport advanced from %d to %d around reconstruction; ReceiverLamport=%d retained pinned snapshot value %d", lamportAtApply, lamportAfterApply, wie.ReceiverLamport, snap.Lamport)
}

// kindName returns a human-readable name for a WireIntegrityErrorKind (helper
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

// sha256Sum returns a digest guaranteed to differ from rtPayloadDigest for the
// mismatched-digest fixture.
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
