// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Transport wiring for ReconstructEntry.
//
// ApplyCRDTDeltaEvent decodes one CRDTDeltaEvent, validates its digest,
// attribution, and Lamport counter, then joins the reconstructed entry into the
// engine. It retains only PayloadDigest; the payload bytes are discarded after
// validation. Batch decoding lives in crdt_apply_batch.go.
//
// This engine-to-engine path uses capnp.Unmarshal and a single-segment arena so
// it remains portable. The Linux client-ingestion transport uses a different,
// jemalloc-backed arena. ReconstructEntry copies every field out of the Cap'n
// Proto message before the deferred Release, so neither Join nor the Entries
// iterator retains an alias into that message.
package sync

import (
	"fmt"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// CRDTDeltaEventWireVersion is the schema version accepted by the decoder.
// Version mismatches are rejected rather than decoded as zero-valued fields.
// Change this constant when a new wire layout is incompatible with this decoder;
// tests refer to the same symbol so fixtures cannot silently drift.
const CRDTDeltaEventWireVersion uint16 = 1

// ApplyCRDTDeltaEvent decodes and applies one inbound CRDTDeltaEvent.
//
// The frame passes through ReconstructEntryWithSkewBound before Join. A digest,
// attribution, or skew rejection returns its *WireIntegrityError unchanged and
// leaves engine state untouched; callers can use errors.As to inspect the wire
// diagnostics. Decode and version failures return ordinary wrapped errors
// because they may not have entity or digest context.
//
// On success, Join receives a single-entry CRDTDelta containing copies of the
// validated fields. Payload bytes are discarded after the integrity check. The
// Cap'n Proto message is released on every return path.
func (e *DeltaCRDTEngine) ApplyCRDTDeltaEvent(wire []byte) error {
	// Unmarshal borrows the caller's bytes. ReconstructEntry copies every field
	// before returning, and Join consumes only those copies, so the deferred
	// message release cannot invalidate retained data.
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return fmt.Errorf("crdt: decode CRDTDeltaEvent: unmarshal: %w", err)
	}
	defer msg.Release()

	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		return fmt.Errorf("crdt: decode CRDTDeltaEvent: read root: %w", err)
	}

	// Forward-compat guard: the version tag must match the compiled-in wire
	// version. A mismatch is an explicit refusal — never a silent fall-through
	// to zero-received fields.
	if ev.Version() != CRDTDeltaEventWireVersion {
		return fmt.Errorf("crdt: decode CRDTDeltaEvent: wire version mismatch: got %d, want %d — refusing silent fall-through to zero-received fields",
			ev.Version(), CRDTDeltaEventWireVersion)
	}

	// Take one receiver snapshot for both integrity and skew validation.
	// ReconstructEntryWithSkewBound checks the digest and dot attribution before
	// rejecting a counter above the bound. Passing the snapshot in keeps those
	// checks on one view rather than rereading engine fields during validation.
	snapshot := e.LamportSnapshot()
	rec, err := ReconstructEntryWithSkewBound(ev, snapshot)
	if err != nil {
		// Preserve the typed integrity error and its entity, origin, and digest
		// context. A rejected frame never reaches Join.
		return err
	}

	// Join needs only the validated entry and its digest, not the payload bytes.
	// This incoming delta owns no generated HAMT snapshot or EBR participant, so
	// those lifecycle fields remain zero and require no Release call.
	delta := CRDTDelta{
		OriginNodeID: rec.Entry.OriginNodeID,
		Entries:      makeSingleEntrySeq(rec.EntityID, rec.Entry),
	}
	e.Join(delta)
	return nil
}

// makeSingleEntrySeq returns an iterator for one reconstructed entity and
// entry. The entry is captured by value, after ReconstructEntry has copied its
// fixed-size fields out of the Cap'n Proto message, so the iterator retains no
// alias into the wire buffer.
func makeSingleEntrySeq(entityID string, entry CRDTEntry) Seq {
	return func(yield func(id string, e CRDTEntry) bool) {
		yield(entityID, entry)
	}
}
