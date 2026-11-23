// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package sync encodes CRDTDeltaEvent frames for the mesh transport.
//
// BuildCRDTDeltaEvent uses the same generated Cap'n Proto schema and wire
// version as the receive path. The mesh signs and length-prefixes the returned
// bytes; transport framing and delivery remain outside this package.
package sync

import (
	"fmt"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// BuildCRDTDeltaEvent marshals an entity ID, payload, and CRDTEntry into a
// CRDTDeltaEvent frame accepted by ApplyCRDTDeltaEvent.
//
// The frame contains the version tag and all twelve CRDT contract fields:
//
//	version        <- CRDTDeltaEventWireVersion (forward-compat tag)
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
//	entityId       <- entityID string      (not entityIDHash[:16])
//	payload        <- payload string       (bytes, not the digest)
//
// The receiver requires PayloadDigest to equal SHA-256(payload), so callers
// must pass the payload corresponding to entry.PayloadDigest. Inconsistent
// input is rejected during reconstruction rather than joined.
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
