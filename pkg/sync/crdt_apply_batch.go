// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package sync applies CRDT delta batches to DeltaCRDTEngine.
//
// ApplyCRDTDeltaBatch decodes one CRDTDeltaBatch frame, reconstructs each event
// through the same integrity checks as ApplyCRDTDeltaEvent, and joins the
// accepted entries in one call. A digest, attribution, or wire-read error rejects
// the whole batch without changing engine state. An element beyond the Lamport
// skew bound is held while the remaining valid elements join.
//
// Reconstructed payloads are used for integrity checks and then discarded. Only
// their digests and the other CRDTEntry fields cross into Join.
package sync

import (
	"errors"
	"fmt"
	"sync/atomic"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// batchPair stores one reconstructed entity ID and entry for the final Seq.
// Payload bytes have already been discarded.
type batchPair struct {
	entityID string
	entry    CRDTEntry
}

// BatchApplyResult reports subset admission. Joined counts entries passed to
// the single Join, and Held counts elements rejected by the Lamport skew bound.
// A decode or other integrity failure returns the zero result with an error.
// When all elements are held, Joined is zero and the error is nil; the sender
// can retry on a later sweep after the acceptance window advances.
type BatchApplyResult struct {
	Joined int
	Held   int
	// HeldDots lists held elements' DotCounters in wire order so callers can
	// exclude them from index feeds and relay retention. It is nil when no
	// elements are held.
	HeldDots []uint64
	// DeltaOriginNodeID is the first joined element's origin. In particular,
	// it does not use element zero when that element is held for skew. Join
	// does not read this field; it is exposed for observation by tests.
	DeltaOriginNodeID [16]byte
}

// disableSubsetAdmissionFault restores whole-batch rejection for skew errors
// when set by the gateway fault-injection tests. It is false otherwise.
var disableSubsetAdmissionFault atomic.Bool

// disableFirstJoinedOriginFault restores element-zero origin selection when
// set by fault-injection tests. It is false otherwise.
var disableFirstJoinedOriginFault atomic.Bool

// ApplyCRDTDeltaBatch decodes and applies an inbound CRDTDeltaBatch frame.
// Every event uses ReconstructEntryWithSkewBound with one Lamport snapshot.
// Valid entries join through one Seq. Skew errors hold individual elements;
// other integrity errors reject the batch before Join (ADR-0069).
//
// The Cap'n Proto message remains alive until reconstruction and Join finish.
// Reconstructed entries contain copies of wire data, not arena aliases; payload
// bytes are discarded after their digest is checked.
func (e *DeltaCRDTEngine) ApplyCRDTDeltaBatch(wire []byte) (BatchApplyResult, error) {
	// capnp.Unmarshal returns a message backed by the caller's bytes.
	// Events are views into its shared arena, so one function-scoped Release
	// covers all iterations. Releasing the message per element would invalidate
	// the views used by subsequent iterations.
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return BatchApplyResult{}, fmt.Errorf("crdt: decode CRDTDeltaBatch: unmarshal: %w", err)
	}
	defer msg.Release()

	batch, err := capnp_schema.ReadRootCRDTDeltaBatch(msg)
	if err != nil {
		return BatchApplyResult{}, fmt.Errorf("crdt: decode CRDTDeltaBatch: read root: %w", err)
	}

	events, err := batch.Events()
	if err != nil {
		return BatchApplyResult{}, fmt.Errorf("crdt: decode CRDTDeltaBatch: read events list: %w", err)
	}

	// Accumulate copied (entityID, entry) pairs before Join so a non-skew error
	// cannot leave a partial batch in state. Only PayloadDigest, not the payload
	// bytes, enters the accumulator.
	//
	// One LamportSnapshot supplies the bound for every element (ADR-0045 §7).
	// Taking a new snapshot after each Join would let AdvanceLamportTo change
	// the acceptance criteria partway through the batch.
	snapshot := e.LamportSnapshot()
	n := events.Len()
	held := 0             // number of elements rejected by the skew bound
	var heldDots []uint64 // held DotCounters in wire order; nil when none are held
	accum := make([]batchPair, 0, n)

	var batchOrigin [16]byte
	for i := 0; i < n; i++ {
		ev := events.At(i) // alias into the parent arena — no per-element Release

		// Reject unsupported wire versions rather than reading zero-valued
		// fields. This is a decode error, not a reconstruction integrity error,
		// matching ApplyCRDTDeltaEvent's version handling.
		if ev.Version() != CRDTDeltaEventWireVersion {
			return BatchApplyResult{}, fmt.Errorf("crdt: decode CRDTDeltaBatch: element %d: wire version mismatch: got %d, want %d — refusing silent fall-through to zero-received fields",
				i, ev.Version(), CRDTDeltaEventWireVersion)
		}

		// ReconstructEntryWithSkewBound first performs the wire, attribution,
		// and digest checks, then applies the shared snapshot's skew bound.
		// It copies every field consumed by the accumulator or Join out of the
		// Cap'n Proto arena.
		rec, err := ReconstructEntryWithSkewBound(ev, snapshot)
		if err != nil {
			// Skew holds its element and processing continues so later valid
			// elements can join. Other integrity failures reject the whole batch.
			// Wrapping preserves both the failing index and WireIntegrityError.
			var wie *WireIntegrityError
			if errors.As(err, &wie) && wie.Kind == WireIntegrityLamportSkewPoisoning && !disableSubsetAdmissionFault.Load() {
				held++
				if heldDots == nil {
					heldDots = make([]uint64, 0, 4) // cold: the first held element only — the hot path allocates nothing
				}
				heldDots = append(heldDots, ev.DotCounter())
				continue
			}
			return BatchApplyResult{}, fmt.Errorf("crdt: decode CRDTDeltaBatch: element %d: %w", i, err)
		}

		// rec.Payload is not retained. The delta origin comes from the first
		// element admitted to the accumulator, which may follow held elements
		// (ADR-0070). The fault switch retains element-zero behavior for tests.
		if len(accum) == 0 && !disableFirstJoinedOriginFault.Load() {
			batchOrigin = rec.Entry.OriginNodeID
		} else if i == 0 {
			batchOrigin = rec.Entry.OriginNodeID
		}
		accum = append(accum, batchPair{entityID: rec.EntityID, entry: rec.Entry})
	}

	// Join receives one delta even when the batch is empty or every element is
	// held. Its empty Seq returns without changing state.
	delta := CRDTDelta{
		OriginNodeID: batchOrigin,
		Entries:      makeBatchEntrySeq(accum),
	}
	e.Join(delta)
	return BatchApplyResult{Joined: len(accum), Held: held, HeldDots: heldDots, DeltaOriginNodeID: batchOrigin}, nil
}

// makeBatchEntrySeq yields accumulated entries by value. The slice owns the
// reconstructed CRDTEntry copies, so the closure does not alias the Cap'n Proto
// arena when Join iterates it.
func makeBatchEntrySeq(pairs []batchPair) Seq {
	return func(yield func(id string, e CRDTEntry) bool) {
		for i := range pairs {
			if !yield(pairs[i].entityID, pairs[i].entry) {
				return
			}
		}
	}
}

// InspectBatchDots decodes a CRDTDeltaBatch without changing engine state and
// returns the first event's origin and every event's DotCounter in wire order.
// The receiver uses these identities to index a batch for relay retention.
//
// ReconstructEntry performs wire, attribution, and digest validation, but the
// Lamport skew bound is intentionally not applied during inspection. A decode
// or integrity error discards the accumulated counters; the caller skips
// retention and lets ApplyCRDTDeltaBatch handle rejection.
func InspectBatchDots(wire []byte) (originNodeID [16]byte, dotCounters []uint64, err error) {
	// Events share the message arena, so release it once after the loop rather
	// than invalidating later event views with per-element releases.
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return originNodeID, nil, fmt.Errorf("crdt: InspectBatchDots: decode CRDTDeltaBatch: unmarshal: %w", err)
	}
	defer msg.Release()

	batch, err := capnp_schema.ReadRootCRDTDeltaBatch(msg)
	if err != nil {
		return originNodeID, nil, fmt.Errorf("crdt: InspectBatchDots: decode CRDTDeltaBatch: read root: %w", err)
	}

	events, err := batch.Events()
	if err != nil {
		return originNodeID, nil, fmt.Errorf("crdt: InspectBatchDots: decode CRDTDeltaBatch: read events list: %w", err)
	}

	n := events.Len()
	dotCounters = make([]uint64, 0, n)
	var batchOrigin [16]byte
	for i := 0; i < n; i++ {
		ev := events.At(i) // alias into the parent arena — no per-element Release

		// Match ApplyCRDTDeltaBatch's version guard so inspection and
		// application accept the same batch framing.
		if ev.Version() != CRDTDeltaEventWireVersion {
			return originNodeID, nil, fmt.Errorf("crdt: InspectBatchDots: element %d: wire version mismatch: got %d, want %d — refusing silent fall-through to zero-received fields",
				i, ev.Version(), CRDTDeltaEventWireVersion)
		}

		// Inspection uses the same reconstruction checks as application but no
		// skew bound. Any error prevents the caller from retaining this batch.
		rec, err := ReconstructEntry(ev)
		if err != nil {
			return originNodeID, nil, fmt.Errorf("crdt: InspectBatchDots: element %d: %w", i, err)
		}

		if i == 0 {
			batchOrigin = rec.Entry.OriginNodeID
		}
		dotCounters = append(dotCounters, rec.Entry.DotCounter)
	}
	return batchOrigin, dotCounters, nil
}
