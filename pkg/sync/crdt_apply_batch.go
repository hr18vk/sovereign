// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Batched framing for CRDTDeltaEvent.
//
// This file builds on the single-event production entry point ApplyCRDTDeltaEvent:
// one inbound CRDTDeltaEvent frame → decode → ReconstructEntry → one-element
// CRDTDelta → Join, payload discarded per frame. The wire-integrity
// enforcement is enforced on the LIVE single-event path.
//
//	Batched/multi-frame transport decomposes into three problems: batching
//	(schema), framing (transport), compression (transport). This file is ONLY
//	batching — a new CRDTDeltaBatch schema wrapper
//	(api/capnp/api/capnp/schema.capnp, untouched CRDTDeltaEvent) plus a new
//	production entry point ApplyCRDTDeltaBatch so that ONE decode + ONE Join
//	can move N CRDT-entries through the SAME ReconstructEntry seam atomically.
//	Framing over a real byte-stream, gzip/Snappy, and a real network boundary
//	are deferred work gated on real traffic we do not have.
//
// THE FIVE DESIGN CONSTRAINTS:
//
// 1. New CRDTDeltaBatch wrapper; CRDTDeltaEvent untouched (13 fields, TypeID
// 0xa90774c0daa3fdc7 byte-identical — verified by the regeneration diff).
// 2. New entry point ApplyCRDTDeltaBatch, sibling to ApplyCRDTDeltaEvent.
// EVERY element routes through ReconstructEntry; no per-element bypass
// (Mutation A proves the guards catch one).
// 3. Atomicity: reconstruct ALL elements first into an accumulator, return
// on the FIRST *WireIntegrityError WITHOUT calling Join, and only if all N
// reconstruct cleanly call Join exactly ONCE. Mutations B and C prove the
// seam's bite and the reconstruct-all-then-join-once atomicity both bite a
// regression.
// 4. Join's signature is UNCHANGED (CRDTDelta is not widened to take a batch
// or a slice; []ReconstructedEntry is NOT threaded into Join). The batch's
// atomicity lives in this entry point's reconstruct-all loop, not in Join.
// 5. Payload discarded per element after the integrity check (rec.Payload is
// not retained; only PayloadDigest on CRDTEntry crosses into Join). No
// batched payload retention — audit/replay is future work.
//
// THE REFACTOR CHOICE — two independent methods, chosen over delegation.
//
//	The delegation alternative would have made ApplyCRDTDeltaEvent marshal its
//	single-event frame into a one-element CRDTDeltaBatch and delegate to
//	ApplyCRDTDeltaBatch. That is NOT a one-line behavior-preserving
//	delegation: the single-event test (crdt_apply_test.go buildApplyWireFrame)
//	produces a CRDTDeltaEvent wire frame, not a CRDTDeltaBatch frame, so
//	delegation would force a change to the single-event wire bytes the entry
//	point decodes — changing the single-event path and its test. Two
//	independent methods keep ApplyCRDTDeltaEvent byte-identical (crdt_apply.go
//	is untouched) and add ApplyCRDTDeltaBatch as a separate production method
//	that routes each decoded element through the SAME ReconstructEntry. There
//	are two methods, one seam; the single-event path is untouched.
package sync

import (
	"fmt"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// batchPair is the accumulator entry for the reconstruct-all-then-join-
// once loop: a validated (entityID, CRDTEntry) pair produced by ReconstructEntry
// for one element of a CRDTDeltaBatch. It is a package-level type so
// makeBatchEntrySeq (a free helper) can share it; rec.Payload is already
// discarded before the pair is accumulated.
type batchPair struct {
	entityID string
	entry    CRDTEntry
}

// ApplyCRDTDeltaBatch is the production entry point for an inbound
// CRDTDeltaBatch wire frame. It is the batched sibling of ApplyCRDTDeltaEvent
// one decode, N reconstructs, one Join. Every element of the batch
// routes through ReconstructEntry — there is NO per-element bypass; Mutation A
// in crdt_apply_batch_test.go proves the guards catch a deliberately-bypassed
// temporary build.
//
// CONTRACT (every clause enforced, none optional):
//
// 1. Decodes the wire []byte into a capnp_schema.CRDTDeltaBatch via
// capnp.Unmarshal + ReadRootCRDTDeltaBatch. On decode failure, returns a
// typed error (production — never t.Fatalf). The capnp *Message is
// Released via defer before return.
//
// 2. Iterates ev.Events() (the List(CRDTDeltaEvent) accessor). For each
// element i: routes it through ReconstructEntry. There is NO path that
// decodes an element and calls Join without passing it through the seam —
// the proof is the Mutation A bite in crdt_apply_batch_test.go.
//
// 3. On the FIRST *WireIntegrityError from any element: wraps it so the
// batch-level error also names the failing element index i (preserving the
// seam's diagnostic context via %w — EntityID/OriginNodeID/digests are not
// stripped), returns immediately, and DOES NOT call Join. Atomic-reject: a
// mid-batch mismatch leaves engine.State() exactly as it was before the
// batch apply (zero new entries joined, for any entityID). Mutation C
// proves a per-element-apply regression bites this guard.
//
// 4. On ALL-elements-reconstruct-clean: builds ONE CRDTDelta whose Entries Seq
// yields the accumulated slice of (entityID, entry) pairs and calls
// engine.Join(delta) exactly ONCE. Join's signature is UNCHANGED (no batch
// Join, no []ReconstructedEntry threaded in); the batch's atomicity lives in
// this reconstruct-all-then-join-once loop, not in Join.
//
// 5. Payload discarded per element: rec.Payload is consumed only by the
// seam's integrity check; rec.Entry (carrying PayloadDigest, not payload) is
// what the Seq yields and what Join sees. No batched payload retention;
// audit/replay is future work.
//
// Batch origin semantics: the originating peer of the batch. ApplyCRDTDeltaEvent
// sets CRDTDelta.OriginNodeID from the single event's
// rec.Entry.OriginNodeID. For a multi-element batch, the convention is the
// first element's OriginNodeID — matching the single-event choice and the
// in-process test harness (all batch events share rtHostA). A real
// peer-forwarded batch from multiple OriginNodeIDs is future cross-host-sync
// work.
func (e *DeltaCRDTEngine) ApplyCRDTDeltaBatch(wire []byte) error {
	// ── Decode the wire []byte into a capnp_schema.CRDTDeltaBatch ──
	// Production decode: capnp.Unmarshal returns a *Message backed by the
	// caller's wire bytes (single-segment, zero-copy). The Message owns the
	// ENTIRE batch arena — batch.Events() yields per-element CRDTDeltaEvent
	// views that ALIAS the parent arena (capnp-go v3 StructList[T].At returns
	// T(List(s).Struct(i)), an overlay, not a copy). Therefore the Message MUST
	// outlive every accessor call inside ReconstructEntry for every element;
	// it is Released exactly once, at function scope, after the loop and Join
	// have finished. A per-element Release would UAF the next iteration's reads
	// (the element views share one arena). This is the single-event
	// defer msg.Release() pattern, lifted to the batch: one arena per batch
	// frame, not one per element. (Verified against capnp-go v3 @ v3.1.0-alpha.2
	// list.go StructList.At and the release pattern — authoritative,
	// not guessed.)
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return fmt.Errorf("crdt: decode CRDTDeltaBatch: unmarshal: %w", err)
	}
	defer msg.Release()

	batch, err := capnp_schema.ReadRootCRDTDeltaBatch(msg)
	if err != nil {
		return fmt.Errorf("crdt: decode CRDTDeltaBatch: read root: %w", err)
	}

	events, err := batch.Events()
	if err != nil {
		return fmt.Errorf("crdt: decode CRDTDeltaBatch: read events list: %w", err)
	}

	// ── Reconstruct ALL elements FIRST into an accumulator ──
	// The rule is accumulate before Join. On the FIRST
	// *WireIntegrityError we return WITHOUT calling Join (atomic-reject, no
	// partial apply). Only if every element reconstructs cleanly do we build
	// one CRDTDelta and Join exactly once. Mutation C proves a per-element-apply
	// regression (join-as-you-go) bites the "zero new entries after a mid-batch
	// mismatch" guard. The accumulator stores (entityID, entry) pairs by value
	// (CRDTEntry is a 120-byte value type, ADR-0010); rec.Payload is dropped
	// here — only PayloadDigest crosses into the accumulator.
	//
	// The SAME atomic LamportSnapshot is taken ONCE before the per-element
	// loop and reused for every element — the receiver's clock snapshot must
	// be COHERENT across the whole batch and must NOT race with each element's
	// eventual Join::AdvanceLamportTo update. Building the snapshot in the
	// wrapper-side (per-element) would let element i's Join AdvanceLamportTo
	// move the clock before element i+1's snapshot read, changing the bound
	// mid-batch and defeating the atomic-reject property. The snapshot is built
	// once here (the caller's responsibility) and every element routes through
	// the wrapping seam with it.
	snapshot := e.LamportSnapshot()
	n := events.Len()
	accum := make([]batchPair, 0, n)

	var batchOrigin [16]byte
	for i := 0; i < n; i++ {
		ev := events.At(i) // alias into the parent arena — no per-element Release

		// Forward-compat guard per element: the version tag MUST match the
		// compiled-in wire version. A mismatch is an explicit refusal, never a
		// silent fall-through to zero-received fields (the silent-fall-through
		// failure mode). It is reported as a decode error (not a
		// *WireIntegrityError) so the element index names it; the seam is
		// reserved for wire-read/digest failures, mirroring
		// ApplyCRDTDeltaEvent's version handling.
		if ev.Version() != CRDTDeltaEventWireVersion {
			return fmt.Errorf("crdt: decode CRDTDeltaBatch: element %d: wire version mismatch: got %d, want %d — refusing silent fall-through to zero-received fields",
				i, ev.Version(), CRDTDeltaEventWireVersion)
		}

		// ── Route EVERY element through ReconstructEntryWithSkewBound ──
		// There is no path from a decoded batch element to Join that does not
		// pass through the WRAPPING seam. The wrapper calls ReconstructEntry
		// FIRST (digest + attribution byte-identical to the base seam) and ONLY
		// THEN computes the skew bound for this element from the once-built
		// snapshot (the same snapshot per element; per-element DotCounter is
		// read off the wire, the receiver snapshot is shared). The seam reads
		// every contract field synchronously and copies them into Go-heap
		// CRDTEntry/[16]byte/[32]byte values, so nothing the accumulator or
		// Join consumes still aliases the capnp arena by the time the deferred
		// msg.Release() runs. A per-element bypass here re-opens the
		// digest/attribution gap on element i of the batch (Mutation A in
		// crdt_apply_batch_test.go proves the guards catch a deliberate bypass)
		// and the far-future-stamp attack on element i (the skew-mutation cases
		// in crdt_lamport_skew_test.go).
		rec, err := ReconstructEntryWithSkewBound(ev, snapshot)
		if err != nil {
			// ReconstructEntryWithSkewBound returns *WireIntegrityError on a
			// digest mismatch, attribution mismatch, or a wire-read failure.
			// Wrap it so the batch-level error names the failing element index
			// i while preserving the seam's diagnostic context
			// (EntityID/OriginNodeID/on-wire+recomputed digests) via %w —
			// callers may errors.As the wrapped error to recover the
			// *WireIntegrityError. Do NOT call Join: the seam's rejection is
			// terminal and atomic.
			return fmt.Errorf("crdt: decode CRDTDeltaBatch: element %d: %w", i, err)
		}

		// Payload discarded per element: rec.Payload is consumed only
		// by the seam's SHA-256 check above; it is not retained and does not
		// cross into the accumulator or Join. Only rec.Entry (PayloadDigest, not
		// payload) is accumulated.
		if i == 0 {
			batchOrigin = rec.Entry.OriginNodeID
		}
		accum = append(accum, batchPair{entityID: rec.EntityID, entry: rec.Entry})
	}

	// ── Build ONE CRDTDelta and call Join exactly ONCE ──
	// If accum is empty (Case 3: zero-element batch), the Seq yields nothing
	// and Join is a documented no-op (Join returns early when the Seq yields
	// zero incoming entries — verified against pkg/sync/crdt.go Join). An empty
	// batch is therefore a no-op by construction, not a zero-field Join. We
	// still call Join once with the empty Seq so the single-call shape is
	// uniform; the empty path is exercised by Case 3.
	delta := CRDTDelta{
		OriginNodeID: batchOrigin,
		Entries:      makeBatchEntrySeq(accum),
	}
	e.Join(delta)
	return nil
}

// makeBatchEntrySeq builds a push-based Seq that yields the accumulated
// (entityID, entry) pairs from a CRDTDeltaBatch whose every element
// reconstructed cleanly through ReconstructEntry. It mirrors the
// makeSingleEntrySeq (one pair) sized for the batch (N pairs). Defined as a
// free helper rather than an inline closure so the function literal stays out
// of the CRDTDelta composite literal — the same idiom makeSingleEntrySeq and
// the test-side makeReplaySeq use.
//
// The entries are passed by value via the []batchPair slice (CRDTEntry is a
// 120-byte value type, ADR 10), so the Seq closure owns independent copies of
// the already-validated CRDTEntry values; nothing the closure captures aliases
// the capnp arena by the time Join consumes it. The arena was Released via the
// deferred msg.Release() in the caller, and ReconstructEntry copied every capnp
// Data field into [N]byte arrays on the returned CRDTEntry before that Release
// runs.
func makeBatchEntrySeq(pairs []batchPair) Seq {
	return func(yield func(id string, e CRDTEntry) bool) {
		for i := range pairs {
			if !yield(pairs[i].entityID, pairs[i].entry) {
				return
			}
		}
	}
}

// InspectBatchDots decodes a CRDTDeltaBatch wire READ-ONLY and returns the
// batch's origin nodeID + the per-element DotCounters, WITHOUT Joining. It is
// the read-only sibling of ApplyCRDTDeltaBatch: the SAME capnp decode +
// ReconstructEntry per element (NOT ReconstructEntryWithSkewBound — inspection
// needs no skew-bound check, only the wire-identity origin/dot), but it
// accumulates NO state + calls NO Join. It is used by the receiver's
// HandleBatchFrame to build the relay reverse-index (origin, dotCounter)→OriginSeq
// so shipBatchedDelta's foreign branch can find the batch a foreign entry came
// in. A *WireIntegrityError from ReconstructEntry is returned (the caller skips
// retention on a malformed batch — the Apply path will DropVerify it atomically).
//
// This is a SECOND decode of the same wire in the receiver (once by Inspect,
// once by Apply) — acceptable: capnp unmarshal is ~1us, the batch is small, the
// rate-gate is already O(1)/batch. The decode logic lives in ONE place
// (pkg/sync) via the shared ReconstructEntry, so no maintenance hazard.
//
// The per-element loop mirrors ApplyCRDTDeltaBatch's decode EXACTLY: capnp.Unmarshal
// → ReadRootCRDTDeltaBatch → batch.Events() → events.At(i) → the version guard →
// ReconstructEntry(ev). It reads rec.Entry.OriginNodeID + rec.Entry.DotCounter per
// element (the SAME fields ApplyCRDTDeltaBatch reads) and captures batchOrigin
// from element 0. It returns (batchOrigin, dotCounters,
// nil) on a clean decode; on the FIRST decode/reconstruct failure it returns the
// error + whatever was accumulated so far is discarded (the caller skips retention
// — the Apply path's own decode will DropVerify the same atomically).
func InspectBatchDots(wire []byte) (originNodeID [16]byte, dotCounters []uint64, err error) {
	// ── Decode the wire []byte into a capnp_schema.CRDTDeltaBatch ──
	// The SAME single-arena decode ApplyCRDTDeltaBatch uses: capnp.Unmarshal
	// returns a *Message backed by the caller's wire bytes, and batch.Events()
	// yields per-element views that ALIAS the parent arena. The Message MUST
	// outlive every accessor inside ReconstructEntry for every element; it is
	// Released exactly once, at function scope, after the loop. (See the
	// ApplyCRDTDeltaBatch arena-lifetime comment for the authoritative
	// rationale — InspectBatchDots reuses the identical pattern.)
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

		// Forward-compat guard per element — the SAME guard ApplyCRDTDeltaBatch
		// enforces. A mismatch is a decode error (NOT a
		// *WireIntegrityError) so the element index names it; the seam is
		// reserved for wire-read/digest failures. Mirroring the apply path keeps
		// Inspect + Apply in lockstep: a batch Inspect rejects, Apply rejects too
		// (DropVerify), and the caller skips retention (the honest skip).
		if ev.Version() != CRDTDeltaEventWireVersion {
			return originNodeID, nil, fmt.Errorf("crdt: InspectBatchDots: element %d: wire version mismatch: got %d, want %d — refusing silent fall-through to zero-received fields",
				i, ev.Version(), CRDTDeltaEventWireVersion)
		}

		// ── Route EVERY element through ReconstructEntry ──
		// The SAME seam ApplyCRDTDeltaBatch routes through (the read-only sibling:
		// ReconstructEntry, NOT the skew-bound wrapper — inspection needs no
		// skew check, only the wire-identity origin/dot the relay reverse-index
		// keys on). A *WireIntegrityError (digest mismatch, attribution mismatch,
		// or a wire-read failure) is returned to the caller, which skips
		// retention — the Apply path's own ReconstructEntryWithSkewBound will
		// DropVerify the same batch atomically. rec.Entry.OriginNodeID +
		// rec.Entry.DotCounter are the SAME fields ApplyCRDTDeltaBatch reads
		// (the wire-identity origin + the origin's monotonic dot).
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
