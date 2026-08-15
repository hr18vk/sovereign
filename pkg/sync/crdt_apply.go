// Phase 2d — transport wiring for ReconstructEntry.
//
// History this file closes (continuation of the Phase 2c escalation):
//
//	C6 (audit): PayloadDigest == SHA-256(payload) was assumed, never enforced
//	anywhere on the receive path. af562f3 deleted the symptom. Phase 2a gave the
//	CRDT delta a wire schema carrying both payload and PayloadDigest as
//	independent fields. Phase 2b proved the cross-validation technique test-loc.
//	Phase 2c delivered the production seam, ReconstructEntry, and explicitly
//	ESCALATED the wiring: "No production capnp CRDTDeltaEvent decode → Join path
//	exists." The seam shipped with no production caller; Phase 2c was held (not
//	merged to main) pending exactly this file.
//
// This file is the Phase 2d wiring. It authors the FIRST production entry point
// that decodes an inbound CRDTDeltaEvent wire frame, routes EVERY frame through
// ReconstructEntry (no bypass — see crdt_apply_test.go Mutation A), and on
// success builds a CRDTDelta whose Entries Seq feeds the validated entries into
// Join. Join's signature is UNCHANGED (Ruling 2 — Option B forbidden); the
// payload lifecycle is owned here, not in Join, and the payload bytes are
// DISCARDED after the integrity check (Ruling 3 — only PayloadDigest is stored
// on CRDTEntry, the existing contract). The wire-integrity concern and the merge
// concern stay cleanly separated, exactly as the architect's Option-C ruling
// required.
//
// SCOPE (this phase, and only this phase):
//
//   - Single CRDTDeltaEvent frame per call. The schema is single-event (see
//     api/capnp/api/capnp/schema.capnp — CRDTDeltaEvent is one struct, not a
//     List). Multi-event batched transport, length-prefix framing, and
//     gzip/Snappy are carry-forwards (§6 of this report) — Phase 2d does not
//     author a schema wrapper to hold a List(CRDTDeltaEvent); that is a schema
//     decision belonging to a separate phase.
//
//   - Go-heap capnp decode via capnp.Unmarshal + single-segment arena. The
//     production ingestion transport (internal/transport) is linux-tagged and
//     uses a jemalloc-backed zero-copy arena; THAT path is out of scope here
//     (the entry point below is the engine<->engine sync receive path, not the
//     client->engine ingestion path, and it must be portable off linux). The
//     capnp *Message is Released after ReconstructEntry has read every field
//     (the seam copies the contract fields into Go-heap CRDTEntry/[32]byte
//     values synchronously; nothing the Seq or Join touches still escapes into
//     the capnp arena by the time Release runs), so the release-before-return
//     ordering is UAF-safe.
package sync

import (
	"fmt"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

// CRDTDeltaEventWireVersion is the compiled-in schema version the production
// decoder expects on every inbound CRDTDeltaEvent frame. It is the single
// forward-compat / rolling-upgrade surface the C5 history proved was missing:
// the decoder fails explicitly on mismatch rather than silently falling through
// to zero-received fields (the C5 failure mode the audit chain closed). Bump it
// ONLY when the CRDTDeltaEvent wire layout changes in a way an old decoder
// cannot honor.
//
// Value 1 matches Phase 2a's schema version. This is the ONE source of truth
// for the compiled-in wire version: the Phase 2+ tests read this symbol
// directly (Phase 2h consolidated the prior package-local test duplicate
// crdtDeltaEventWireVersion into this single production symbol so a future
// bump changes exactly one site and a forgotten test site is a compile error,
// not a silent wire-version skew of the kind that bred C5).
const CRDTDeltaEventWireVersion uint16 = 1

// ApplyCRDTDeltaEvent is the production entry point for an inbound
// CRDTDeltaEvent wire frame. It is the seam caller Phase 2c's escalation
// required: it owns the capnp decode→ReconstructEntry→Join boundary, enforcing
// wire integrity on EVERY frame before it reaches Join. It is the FIRST
// production caller of ReconstructEntry.
//
// CONTRACT (Phase 2d — every clause enforced, none optional):
//
//  1. Decodes the wire []byte into a capnp_schema.CRDTDeltaEvent via
//     capnp.Unmarshal + ReadRootCRDTDeltaEvent. On decode failure, returns a
//     typed error (production — never t.Fatalf). The capnp *Message is
//     Released via defer before return.
//
//  2. Routes EVERY decoded frame through ReconstructEntry. There is NO bypass
//     path that decodes a frame and calls Join directly — the proof is the
//     Mutation A bite in crdt_apply_test.go: a deliberately-bypassed temporary
//     build lets a mismatched pair reach Join and the teeth catch it red.
//
//  3. On a *WireIntegrityError from the seam: returns the error WITH the
//     seam's diagnostic context (entityID, originNodeID, on-wire + recomputed
//     digests) and DOES NOT call Join for that frame. The seam's rejection is
//     terminal for the frame.
//
//  4. On success: builds a CRDTDelta whose Entries Seq yields (rec.EntityID,
//     rec.Entry) and calls engine.Join(delta). rec.Payload is DISCARDED here
//     (Ruling 3 — only PayloadDigest is stored on CRDTEntry, the existing
//     contract; payload retention for audit/replay is a separate phase). Join's
//     signature is UNCHANGED — it consumes only (entityID, CRDTEntry) via the
//     Seq, exactly as today (Ruling 2 — Option B not smuggled).
//
// Error handling:
//
//   - Decode failure (capnp.Unmarshal / ReadRootCRDTDeltaEvent) or version
//     mismatch: returns fmt.Errorf("crdt: decode CRDTDeltaEvent: ...") wrapping
//     the underlying error or describing the version mismatch. NOT a
//     *WireIntegrityError — the frame could not be parsed as a CRDTDeltaEvent
//     at all, so there is no entityID/digest context to carry.
//   - Seam rejection: returns the *WireIntegrityError unchanged, so callers
//     may errors.As it and recover the diagnostic context.
//
// The method is a receiver on *DeltaCRDTEngine so it can call engine.Join with
// the reconstructed delta, mirroring how InsertLocal lives on the same engine.
// Multi-frame batching, length-prefix framing, and gzip/Snappy are NOT handled
// here (carry-forwards).
func (e *DeltaCRDTEngine) ApplyCRDTDeltaEvent(wire []byte) error {
	// ── Decode the wire []byte into a capnp_schema.CRDTDeltaEvent ──
	// Production decode: capnp.Unmarshal returns a *Message backed by the
	// caller's wire bytes (single-segment, zero-copy). The Message MUST be
	// Released when we are done; the seam reads every contract field
	// synchronously and copies them into Go-heap CRDTEntry/[32]byte values, so
	// nothing that escapes into Join or the Seq still aliases the arena by the
	// time Release runs. defer.Release is UAF-safe because ReconstructEntry
	// returns before this function returns and Join consumes only the copied
	// Go-heap values.
	msg, err := capnp.Unmarshal(wire)
	if err != nil {
		return fmt.Errorf("crdt: decode CRDTDeltaEvent: unmarshal: %w", err)
	}
	defer msg.Release()

	ev, err := capnp_schema.ReadRootCRDTDeltaEvent(msg)
	if err != nil {
		return fmt.Errorf("crdt: decode CRDTDeltaEvent: read root: %w", err)
	}

	// Forward-compat guard: the version tag MUST match the compiled-in wire
	// version. A mismatch is an explicit refusal — never a silent fall-through
	// to zero-received fields (the C5 failure mode the audit chain closed).
	if ev.Version() != CRDTDeltaEventWireVersion {
		return fmt.Errorf("crdt: decode CRDTDeltaEvent: wire version mismatch: got %d, want %d — refusing silent fall-through to zero-received fields (C5 guard)",
			ev.Version(), CRDTDeltaEventWireVersion)
	}

	// ── Route EVERY frame through ReconstructEntryWithSkewBound ──
	// Phase 2g (Ruling 7+8): the live single-event path now routes through the
	// WRAPPING seam, not through bare ReconstructEntry. The wrapper calls
	// ReconstructEntry FIRST (digest + attribution checks byte-identical to
	// Phase 2c/2f) and ONLY THEN computes the receiver-state-sourced skew bound
	// and rejects on DotCounter > bound (Ruling 4 / O2 ordering: skew AFTER
	// digest+attribution). The atomic LamportSnapshot is built ONCE here (Ruling
	// 8 — the caller's responsibility) so the bound is coherent against a
	// concurrent InsertLocal on this same receiver; the wrapper never lazily
	// re-reads e.lamport mid-call. A bypass here re-opens C6 on the live path
	// AND A1 on the live path (Mutation A/B in crdt_apply_test.go and
	// crdt_lamport_skew_test.go prove the teeth catch both).
	snapshot := e.LamportSnapshot()
	rec, err := ReconstructEntryWithSkewBound(ev, snapshot)
	if err != nil {
		// ReconstructEntry returns *WireIntegrityError on a digest mismatch or
		// a wire-read failure. Return it unchanged so callers may errors.As it
		// and recover the seam's diagnostic context (entityID, originNodeID,
		// on-wire + recomputed digests) — the Option C payoff Option A
		// forfeits. Do NOT call Join: the seam's rejection is terminal.
		return err
	}

	// ── Build the CRDTDelta and call Join, DISCARDING the payload ──
	// rec.Entry holds every CRDTEntry contract field read off the wire and
	// SHA-256-validated against rec.Payload. Per Ruling 3, we DISCARD
	// rec.Payload here — only PayloadDigest is stored on CRDTEntry, the
	// existing contract. The Seq yields (rec.EntityID, rec.Entry); the payload
	// bytes do not cross into Join (Ruling 2 — Join's signature is unchanged;
	// the wire/merge separation is the architect's Option C ruling).
	//
	// The Seq is defined via a free helper (makeSingleEntrySeq, not an inline
	// closure in the composite literal) for the same reason the test's
	// makeReplaySeq is: keeping the function literal out of the composite
	// literal grammar so gofmt/vet parse it unambiguously. CRDTDelta's EBR
	// fields (rootRef/arenaRef/ebrPart) are deliberately left zero — those are
	// populated only by GenerateDelta for the engine's own emitted deltas; a
	// Join-side delta built from reconstructed wire frames owns no HAMT root
	// to retire, so Release() is a no-op on it (the Release guard checks
	// ebrPart != nil first).
	delta := CRDTDelta{
		OriginNodeID: rec.Entry.OriginNodeID,
		Entries:      makeSingleEntrySeq(rec.EntityID, rec.Entry),
	}
	e.Join(delta)
	return nil
}

// makeSingleEntrySeq builds a push-based Seq that yields exactly one
// (entityID, entry) pair — the validated output of ReconstructEntry for a
// single CRDTDeltaEvent frame. It mirrors the test-side makeReplaySeq helper in
// crdt_capnp_roundtrip_test.go but is sized for the single-event wire schema
// (no slice to range over). Defined as a free helper rather than an inline
// closure so the function literal stays out of the CRDTDelta composite
// literal — the same idiom the existing test file uses for makeReplaySeq.
//
// The entry is passed by value (not pointer) so the Seq closure owns an
// independent copy of the already-validated CRDTEntry; nothing the closure
// captures aliases the capnp arena by the time Join consumes it. The arena was
// Released via the deferred msg.Release() in the caller, and the field reads in
// ReconstructEntry copied every capnp Data field into [N]byte arrays on the
// returned CRDTEntry before that Release runs.
func makeSingleEntrySeq(entityID string, entry CRDTEntry) Seq {
	return func(yield func(id string, e CRDTEntry) bool) {
		yield(entityID, entry)
	}
}
