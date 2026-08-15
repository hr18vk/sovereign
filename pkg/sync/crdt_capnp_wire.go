// Package sync — crdt_capnp_wire is the production CRDTDeltaEvent marshal seam.
//
// This file is the FIRST non-test producer of the capnp CRDTDeltaEvent wire that
// pkg/receive.Receiver.HandleFrame consumes (crdt_apply.go:113
// ApplyCRDTDeltaEvent → capnp.Unmarshal → ReconstructEntry). Before this file
// the ONLY builder for the wire shape was the test-local
// encodeEntryToCRDTDeltaEvent helper (pkg/sync/crdt_capnp_roundtrip_test.go:156),
// and crdt_apply.go:216 explicitly escalated "no production capnp marshal seam
// exists". This file is that seam.
//
// FROZEN-substrate discipline: this file is a CALLER of the generated capnp
// schema (capnp_schema.NewRootCRDTDeltaEvent, the Set* accessors) and the
// compiled-in version const CRDTDeltaEventWireVersion. It edits NO FROZEN file:
// it imports the FROZEN schema.capnp(.go) the same way crdt_apply.go does and
// produces a byte-identical wire shape to the roundtrip test's builder, so the
// production sink (ReconstructEntryWithSkewBound) decodes it without any schema
// edit (the C5/C6 teeth fire on this wire exactly as they fire on the test
// wire).
//
// Design note (no transport here): this file is codec-only. It produces the
// innerWire []byte the signed-envelope seam signs and length-prefixes in the
// mesh transport (pkg/mesh). Keeping the codec in pkg/sync means the mesh is a
// pure CALLER of engine + codec + identity + envelope; the engine owns the
// Join/Apply sink, this file owns the marshal sink's inverse, and they share
// exactly the FROZEN generated schema as their wire contract.
package sync

import (
	"fmt"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// BuildCRDTDeltaEvent marshals a single (entityID, payload, CRDTEntry) triple
// into the canonical capnp CRDTDeltaEvent wire that ApplyCRDTDeltaEvent
// consumes. It is byte-faithful to the test-local
// encodeEntryToCRDTDeltaEvent (crdt_capnp_roundtrip_test.go:156) whose
// roundtrip the Phase 2 suite proves against ReconstructEntry — promoted so
// the production gossip path produces the SAME wire the production apply path
// decodes, with zero schema edit.
//
// Field mapping onto CRDTDeltaEvent (the 12 contract fields + 1 version tag,
// identical to the roundtrip builder):
//
//	version        <- CRDTDeltaEventWireVersion (forward-compat tag, crdt_apply.go:67)
//	payloadDigest  <- entry.PayloadDigest  ([32]byte -> Data)
//	originNodeID   <- entry.OriginNodeID   ([16]byte -> Data)
//	dotNodeID      <- entry.DotNodeID      ([16]byte -> Data)
//	dotCounter     <- entry.DotCounter     (uint64 -> UInt64)
//	h3Index        <- entry.H3Index        (uint64 -> UInt64)
//	systemTime     <- entry.SystemTime
//	validTimeStart <- entry.ValidTimeStart
//	validTimeEnd   <- entry.ValidTimeEnd
//	assertionTime  <- entry.AssertionTime
//	decisionTime   <- entry.DecisionTime
//	entityId       <- entityID string      (C6: NOT entityIDHash[:16])
//	payload        <- payload string       (C6: bytes, NOT the digest)
//
// The receiver cross-validates PayloadDigest == SHA-256(payload) in
// ReconstructEntry (crdt_reconstruct.go:346), so payload and PayloadDigest MUST
// be consistent — the caller (pkg/mesh) constructs the entry via
// InsertLocal's returned CRDTEntry, then passes the matching payload string
// here. A mismatch is an HONEST DropVerify on the receive side, never a silent
// accept.
func BuildCRDTDeltaEvent(entityID, payload string, entry CRDTEntry) ([]byte, error) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, fmt.Errorf("crdt_capnp_wire: capnp.NewMessage: %w", err)
	}
	ev, err := capnp_schema.NewRootCRDTDeltaEvent(seg)
	if err != nil {
		return nil, fmt.Errorf("crdt_capnp_wire: NewRootCRDTDeltaEvent: %w", err)
	}
	ev.SetVersion(CRDTDeltaEventWireVersion)
	if err := ev.SetPayloadDigest(entry.PayloadDigest[:]); err != nil {
		return nil, fmt.Errorf("crdt_capnp_wire: SetPayloadDigest: %w", err)
	}
	if err := ev.SetOriginNodeID(entry.OriginNodeID[:]); err != nil {
		return nil, fmt.Errorf("crdt_capnp_wire: SetOriginNodeID: %w", err)
	}
	if err := ev.SetDotNodeID(entry.DotNodeID[:]); err != nil {
		return nil, fmt.Errorf("crdt_capnp_wire: SetDotNodeID: %w", err)
	}
	ev.SetDotCounter(entry.DotCounter)
	ev.SetH3Index(entry.H3Index)
	ev.SetSystemTime(entry.SystemTime)
	ev.SetValidTimeStart(entry.ValidTimeStart)
	ev.SetValidTimeEnd(entry.ValidTimeEnd)
	ev.SetAssertionTime(entry.AssertionTime)
	ev.SetDecisionTime(entry.DecisionTime)
	if err := ev.SetEntityId(entityID); err != nil {
		return nil, fmt.Errorf("crdt_capnp_wire: SetEntityId: %w", err)
	}
	if err := ev.SetPayload(payload); err != nil {
		return nil, fmt.Errorf("crdt_capnp_wire: SetPayload: %w", err)
	}
	data, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("crdt_capnp_wire: msg.Marshal: %w", err)
	}
	return data, nil
}
