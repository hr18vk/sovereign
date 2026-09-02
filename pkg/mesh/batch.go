// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Package mesh — batch.go is the SEND-side batch builder + the gossip
// ShipBatch path (the arithmetic unlock).
//
// THE AMORTIZATION (load-bearing): the per-frame shipDelta path (gossip.go:262)
// signs ONE Ed25519 per delta — 60.19 us/delta at 32c, a 533K/sec ceiling.
// This change adds a SECOND ship path (ShipBatch) that accumulates up to --batch-size
// self-originated deltas, builds ONE CRDTDeltaBatch wire, signs ONCE, and
// publishes ONCE. The verify cost amortizes from 60.19 us/delta to 60.19/N
// us/delta — the arithmetic unlock for the >=1M/sec headline.
//
// THE SELF-ORIGIN BOUNDARY (encode it, do NOT hide it): ShipBatch covers ONLY
// self-originated deltas (a node batching its OWN N writes). A relayer
// forwarding a FOREIGN delta holds ONLY its own relay seed — it NEVER holds the
// foreign ORIGIN's seed, so it CANNOT re-origin-sign a foreign delta. Relay-
// chained foreign deltas STAY per-frame (the frozen RelayEnvelope v3 hop chain
// in envelope.go — UNTOUCHED). A batch that relayer-signs foreign origins is a
// FORGERY. The per-frame shipDelta is RETAINED as the low-rate / fallback /
// relay path (NOT deleted).
//
// THE CRYPTO-MINIMAL DESIGN: Ed25519 signs the MARSHALED CRDTDeltaBatch WIRE
// DIRECTLY (no SHA-256 batch root). The wire the origin signs is the wire the
// receiver's ApplyCRDTDeltaBatch decodes — the bytes Verify checks ARE the bytes
// the engine Joins (the no-hash-then-reconstruct-gap property, ADR-0010 §2).
package mesh

import (
	"context"
	"fmt"
	"log"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// MaxBatchSize is the upper bound on the number of deltas a single batch
// carries. It is bounded by the capnp CRDTDeltaBatch list length (int32) and by
// the honest amortization floor: a batch larger than the verify/apply crossover
// N* pays more in decode than it saves in verify (the bench table reveals the
// sweet spot). 256 is the conservative ceiling the --batch-size flag enforces;
// the default is 100 (the deliverable's headline N).
const MaxBatchSize = 256

// DefaultBatchSize is the --batch-size default. 100 is the N the
// arithmetic unlock targets: 60.19us/100 ~= 0.60 us/delta verify, amortized
// against the ~36 ns/entry apply floor. A --batch-size of 1 selects the
// per-frame shipDelta path (batching disabled — the back-compat default for a
// node that has not opted into the batch path).
const DefaultBatchSize = 100

// BuiltEvent is the (entityID, payload, entry) triple ShipBatch accumulates
// before building one CRDTDeltaBatch wire. It carries exactly the fields the
// capnp CRDTDeltaEvent setter surface stamps (the 12 contract fields + the
// version tag), so BuildCRDTDeltaBatch assembles the batch LIST directly via the
// generated capnp API (NewRootCRDTDeltaBatch + NewEvents(n) + the ev.At(i).Set*
// loop) — mirroring the crdt_apply_batch_test.go:buildBatchWireFrame reference
// pattern. It does NOT call BuildCRDTDeltaEvent per event (that would build N
// independent single-event messages and discard them; assembling the batch list
// directly builds ONE message with N events in one arena).
type BuiltEvent struct {
	EntityID string
	Payload  string
	Entry    eng.CRDTEntry
}

// BuildCRDTDeltaBatch assembles a CRDTDeltaBatch containing N CRDTDeltaEvent
// frames (one per BuiltEvent), MARSHALS it to capnp bytes, and returns the
// []byte — exactly the shape an inbound batched transport frame hands to the
// frozen ApplyCRDTDeltaBatch (crdt_apply_batch.go:118). It mirrors the
// crdt_apply_batch_test.go:buildBatchWireFrame reference pattern:
//
//	capnp.NewMessage(capnp.SingleSegment(nil))
//	NewRootCRDTDeltaBatch(seg)
//	batch.NewEvents(int32(len(events)))
//	for i, ev := range events { events.At(i).Set* ... }
//	msg.Marshal
//
// Every CRDTDeltaEvent contract field is stamped from the BuiltEvent's CRDTEntry
// (the 12 fields + the version tag), exactly as BuildCRDTDeltaEvent
// (crdt_capnp_wire.go:66) stamps them for the per-frame path — so the batched
// wire and the per-frame wire carry the SAME per-event bytes, and the two paths
// converge to the SAME engine state (the cross-path MerkleRoot determinism
// guard, ADR-0010 §3). It does NOT invent fields; the setter surface is the
// generated capnp API (schema.capnp.go:187-318).
func BuildCRDTDeltaBatch(events []BuiltEvent) ([]byte, error) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: capnp.NewMessage: %w", err)
	}
	batch, err := capnp_schema.NewRootCRDTDeltaBatch(seg)
	if err != nil {
		return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: NewRootCRDTDeltaBatch: %w", err)
	}
	if len(events) == 0 {
		// An empty batch is a valid wire frame: the events pointer is left unset
		// (HasEvents == false) and batch.Events returns a zero-length list
		// — the frozen ApplyCRDTDeltaBatch Case 3 fixture (a no-op Join).
		data, err := msg.Marshal()
		if err != nil {
			return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: marshal empty: %w", err)
		}
		return data, nil
	}
	eventsList, err := batch.NewEvents(int32(len(events)))
	if err != nil {
		return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: NewEvents: %w", err)
	}
	for i, be := range events {
		ev := eventsList.At(i)
		ev.SetVersion(eng.CRDTDeltaEventWireVersion)
		if err := ev.SetPayloadDigest(be.Entry.PayloadDigest[:]); err != nil {
			return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: event %d SetPayloadDigest: %w", i, err)
		}
		if err := ev.SetOriginNodeID(be.Entry.OriginNodeID[:]); err != nil {
			return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: event %d SetOriginNodeID: %w", i, err)
		}
		if err := ev.SetDotNodeID(be.Entry.DotNodeID[:]); err != nil {
			return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: event %d SetDotNodeID: %w", i, err)
		}
		ev.SetDotCounter(be.Entry.DotCounter)
		ev.SetH3Index(be.Entry.H3Index)
		ev.SetSystemTime(be.Entry.SystemTime)
		ev.SetValidTimeStart(be.Entry.ValidTimeStart)
		ev.SetValidTimeEnd(be.Entry.ValidTimeEnd)
		ev.SetAssertionTime(be.Entry.AssertionTime)
		ev.SetDecisionTime(be.Entry.DecisionTime)
		if err := ev.SetEntityId(be.EntityID); err != nil {
			return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: event %d SetEntityId: %w", i, err)
		}
		if err := ev.SetPayload(be.Payload); err != nil {
			return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: event %d SetPayload: %w", i, err)
		}
	}
	data, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("mesh: BuildCRDTDeltaBatch: msg.Marshal: %w", err)
	}
	return data, nil
}

// ShipBatch builds ONE CRDTDeltaBatch wire from the accumulated self-originated
// events, signs it ONCE (identity.SignCRDTFrame(g.owner.Seed, batchWire) — the
// hedged Ed25519 symbol, eddsa_hedge.go:84), wraps it in a BatchEnvelope
// (attribution.MarshalBatchEnvelope — the crypto-minimal envelope, wire_v1.go),
// length-prefixes it (receive.LengthPrefixFrame — forward.go:104), and publishes
// it to peerID (peers.Publish — the TransmitTLSFrame copy-mode writer).
// It returns the per-batch counters (one batch shipped, N entries shipped).
//
// THE ONE SIGNATURE: a single Ed25519 over the marshaled CRDTDeltaBatch wire
// covers ALL N deltas — the 60.19us that now amortizes to 60.19/N us/delta. The
// receiver's HandleBatchFrame verifies this ONE signature (VerifyCRDTFrame)
// then ApplyCRDTDeltaBatch decodes the wire and Joins all N in one decode +
// one Join (the frozen engine path, crdt_apply_batch.go:118).
//
// SELF-ORIGIN ONLY: the events MUST be this node's own writes (the owner's seed
// signs them). A caller that forwards foreign deltas here commits a FORGERY
// (the relay has no foreign origin seed). The per-frame shipDelta is the path
// for relay-chained foreign deltas; ShipBatch is the self-originated high-rate
// path.
func (g *Gossiper) ShipBatch(ctx context.Context, peerID [16]byte, events []BuiltEvent) (shippedBatches, shippedEntries int, err error) {
	if len(events) == 0 {
		return 0, 0, nil
	}
	if len(events) > MaxBatchSize {
		return 0, 0, fmt.Errorf("mesh: ShipBatch: batch size %d exceeds MaxBatchSize %d", len(events), MaxBatchSize)
	}
	if ctx.Err() != nil {
		return 0, 0, ctx.Err()
	}

	// Build + sign + mint the seq ONCE PER SWEEP,
	// then ship the SAME envelope bytes to every selected peer. Measured licence
	// (pkg/mesh/sweep_phase_bench_test.go): per-peer build+sign
	// was 164.42 ms of a 167.28 ms sweep = 98.3% of the compute, at 3,500 signatures
	// per sweep (35 peers x 100 batches). After this change it is 100 — a 35x cut —
	// and the origin's OriginSeq advances by the number of BATCHES rather than
	// batches x peers.
	//
	// WHY THIS IS SOUND ON THE BYTES (verified before coding):
	//   - attribution/wire_v1.go's layout is magic/version/originSeq/batchCount/
	//     originNodeID/originSig/batchWire — there is NO RECIPIENT FIELD, so a signed
	//     batch envelope is PEER-AGNOSTIC by construction;
	//   - the signature covers batchWire ONLY (identity.SignCRDTFrame(seed, batchWire));
	//   - peerID was already used SOLELY as the Publish target.
	// WHY IT IS SAFE UNDER: the receiver's rate gate keys on
	// (originNodeID, OriginSeq). Sending the SAME OriginSeq to N peers means each peer
	// sees a monotone per-origin sequence with no interleave, which is the BEST case
	// for the high-water-mark discipline. Under the PRE-code this change would
	// have been dangerous (a repeated seq was a delta-0 that Dropped once the budget
	// hit zero); made delta-0 an unconditional Keep, so it is safe now and was
	// not before.
	//
	// The cache is keyed by the sweep round + the batch's ordinal within that round,
	// so a second sweep re-signs (fresh content, fresh seq) while every peer inside
	// ONE sweep shares one envelope. It is reset per sweep by AntiEntropySweep, so it
	// cannot grow.
	if pre, ok := g.sweepEnvelope(len(events)); ok {
		if err := g.peers.Publish(peerID, pre); err != nil {
			return 0, 0, fmt.Errorf("mesh: ShipBatch: Publish to %x: %w", peerID, err)
		}
		return 1, len(events), nil
	}

	batchWire, err := BuildCRDTDeltaBatch(events)
	if err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatch: %w", err)
	}

	// THE ONE SIGNATURE — the amortization. One Ed25519 over the marshaled
	// CRDTDeltaBatch wire covers all N deltas.
	sig, err := identity.SignCRDTFrame(g.owner.Seed, batchWire)
	if err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatch: SignCRDTFrame: %w", err)
	}
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], sig)

	// The origin's MONOTONIC per-batch sequence — the rate-gate counter. It
	// advances by 1 per DISTINCT batch (no longer once per peer, so the
	// churn is divided by the fan-out) so the receiver's PeerBucket.Accept drains on
	// the delta between successive batches (a burst of batches drains the
	// origin's budget). It is NOT the BatchCount (a static count would produce
	// a zero delta between same-size batches and the budget would never drain).
	// AntiEntropySweep is single-goroutine (the SweepLoop), so the increment is
	// race-free.
	g.batchSeq++
	originSeq := g.batchSeq

	// The crypto-minimal envelope: the wire the origin signs is the wire the
	// receiver applies (no SHA-256 batch root — sign the wire directly).
	env := attribution.MarshalBatchEnvelope(g.owner.NodeID, sigArr, originSeq, uint16(len(events)), batchWire)
	prefixed := receive.LengthPrefixFrame(env)
	g.cacheSweepEnvelope(len(events), prefixed)
	if err := g.peers.Publish(peerID, prefixed); err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatch: Publish to %x: %w", peerID, err)
	}
	return 1, len(events), nil
}

// ShipBatchHybrid is the (ADR-0037) hybrid-SIGN sibling of ShipBatch:
// it builds ONE CRDTDeltaBatch wire from the accumulated self-originated
// events, signs it ONCE under BOTH Ed25519 + ML-DSA-65 via
// identity.SignCRDTFrame_Hybrid (the [64] edSig + the [3309] pqSig over the
// SAME 120-byte SHAKE256 pad of batchWire), wraps it in a HybridEnvelope
// (attribution.MarshalHybridFrame — the crypto-minimal hybrid envelope,
// wire_v1.go), length-prefixes it (receive.LengthPrefixFrame), and publishes it
// to peerID. It returns the per-batch counters (one batch shipped, N entries
// shipped). It is the SEND-side complement to the receiver's HandleHybridFrame
// (the BOTH-verify gate).
//
// THE TWO SIGNATURES: a single Ed25519 + a single ML-DSA-65 over the 120-byte
// SHAKE256 pad of the marshaled CRDTDeltaBatch wire cover ALL N deltas — the
// 60.19us classical SIGN + the 585.8us ML-DSA-65 SIGN (4c loopback, NOT silicon
// — the SIGN cost, NOT the verify; the 73.7us number is the ML-DSA-65 VERIFY
// bench BenchmarkMLDSA65_Verify_120B-4, a DIFFERENT operation — see the
// /verify-audit honesty fix below) amortize to (60.19 + 585.8)/N us/delta.
// The receiver's HandleHybridFrame verifies BOTH sigs (VerifyBatchHybrid — the
// both-required gate, the ~60us classical verify + the ~73.7us PQ verify, BOTH
// over the SAME pad) then ApplyCRDTDeltaBatch decodes the wire and Joins all
// N in one decode + one Join (the frozen engine path, crdt_apply_batch.go:118 —
// the SAME apply path ShipBatch uses).
//
// SELF-ORIGIN ONLY: the events MUST be this node's own writes (the owner's seed
// + the owner's PQ key sign them). A caller that forwards foreign deltas here
// commits a FORGERY (the relay has no foreign origin seed + no foreign origin
// PQ key — it can ADD a relay hop-sig but CANNOT re-origin-sign a foreign delta
// under EITHER sig). The per-frame shipDelta is the path for relay-chained
// foreign deltas; ShipBatchHybrid is the self-originated high-rate hybrid path,
// the SAME boundary ShipBatch enforces.
//
// ARMED guard: a Gossiper whose owner has NO PQ key (owner.PQPriv == nil —
// NewNodeIdentity, NOT NewNodeIdentityHybrid) returns an error here (the PQ half
// has no signer); the caller (shipBatchedDelta) logs + skips the batch, NOT a
// panic — the v1 batch path + the relay/foreign path are unaffected. The
// deploy discipline: --hybrid-sign arms the gossiper ONLY when the owner was
// constructed via NewNodeIdentityHybrid (cmd wiring).
func (g *Gossiper) ShipBatchHybrid(ctx context.Context, peerID [16]byte, events []BuiltEvent) (shippedBatches, shippedEntries int, err error) {
	if len(events) == 0 {
		return 0, 0, nil
	}
	if len(events) > MaxBatchSize {
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: batch size %d exceeds MaxBatchSize %d", len(events), MaxBatchSize)
	}
	if ctx.Err() != nil {
		return 0, 0, ctx.Err()
	}
	if g.owner.PQPriv == nil {
		// ARMED guard: the owner has no ML-DSA-65 signer. The hybrid arm was
		// armed (--hybrid-sign) but the owner was NOT constructed via
		// NewNodeIdentityHybrid — a deploy misconfiguration. Return an honest
		// error (logged + the batch skipped by the caller); the v1 batch path
		// + the relay/foreign path are unaffected. NOT a panic — a misconfigured
		// flag must not crash the sweep.
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: owner has no ML-DSA-65 private key — construct the owner via NewNodeIdentityHybrid before --hybrid-sign")
	}

	// for the hybrid path (/): consult the
	// per-round memo BEFORE the per-peer build+sign. ShipBatchHybrid previously
	// re-ran BuildCRDTDeltaBatch + SignCRDTFrame_Hybrid (60.19us Ed25519 +
	// 585.8us ML-DSA-65) PER PEER — 3,500 hybrid signs ≈ 2.26s per sweep round
	// at the 35-peer gate shape, while the v1 path memoized. The helpers carry
	// the stratified guard + the batchLen content check, so under
	// --stratified-anti-entropy this consult is always a miss and every peer
	// gets its own build+sign. The memo is shared with the v1 path; a node
	// never mixes the two (shipBatchedDelta routes on the construction-time
	// hybridSign flag), so no position can hold the other frame shape.
	if pre, ok := g.sweepEnvelope(len(events)); ok {
		if err := g.peers.Publish(peerID, pre); err != nil {
			return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: Publish to %x: %w", peerID, err)
		}
		return 1, len(events), nil
	}

	batchWire, err := BuildCRDTDeltaBatch(events)
	if err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: %w", err)
	}

	// THE TWO SIGNATURES — the hybrid amortization. One Ed25519 + one ML-DSA-65
	// over the 120-byte SHAKE256 pad of batchWire covers all N deltas (the SAME
	// pad the receiver recomputes via VerifyBatchHybrid — the symmetric contract).
	edSig, pqSig, err := identity.SignCRDTFrame_Hybrid(g.owner.Seed, g.owner.PQPriv, batchWire, "")
	if err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: SignCRDTFrame_Hybrid: %w", err)
	}

	// The origin's MONOTONIC per-batch sequence — the rate-gate counter. The
	// SAME g.batchSeq ShipBatch advances (the hybrid frame + the v1 frame share
	// the origin's monotonic sequence space — a peer's rate gate sees a hybrid
	// batch + a v1 batch from the SAME origin as successive originSeq values, so
	// the budget drains correctly across frame shapes). AntiEntropySweep is
	// single-goroutine (the SweepLoop), so the increment is race-free.
	g.batchSeq++
	originSeq := g.batchSeq

	// The crypto-minimal hybrid envelope: the wire the origin signs (under BOTH
	// sigs, via the pad) is the wire the receiver applies (no SHA-256 batch root
	// — sign the wire directly via the pad; the apply path consumes the verbatim
	// batchWire, NOT the pad, so Join sees the real bytes).
	env := attribution.MarshalHybridFrame(g.owner.NodeID, edSig, pqSig, originSeq, uint16(len(events)), batchWire)
	prefixed := receive.LengthPrefixFrame(env)
	g.cacheSweepEnvelope(len(events), prefixed) //: memoize for the remaining peers of THIS round (no-op under stratified — the guard)
	if err := g.peers.Publish(peerID, prefixed); err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: Publish to %x: %w", peerID, err)
	}
	return 1, len(events), nil
}

// shipBatchedDelta is the batched sibling of shipDelta (gossip.go:262). It
// drains a CRDTDelta's Entries into MaxBatchSize-sized BuiltEvent slices and
// ships each slice as one signed batch via ShipBatch. A payload miss skips that
// entry (logged, never panicked) — the receiver would DropVerify a mismatched
// payload, so skipping is the honest choice, not a fabrication (the same
// discipline as shipDelta). It returns per-delta counters for the sweepState.
//
// This is the path AntiEntropySweep switches to when --batch-size > 1 (the
// self-originated delta path). The per-frame shipDelta is RETAINED as the
// low-rate / fallback / relay path (NOT deleted).
//
// COUNTER SEMANTICS (ADR-0045/§15.19):
//   - entries — SELF entries actually PUBLISHED in batches (the flush's
//
// ShipBatch return), NOT entries walked. The pre-code ALSO
//
//	  counted every walked entry (the deleted `entries++` at the walk top),
//	  double-counting every shipped entry and making the gate identity
//	  "entries + pending == deliverable set" a tautology. Walked-but-unshipped
//	  entries now break that identity loudly — which is its purpose.
//	- misses — ORPHANED SELF entries only (state carries the dot, no payload
//	  recorded, NO commit in flight): a WAL-failed batch the client never
//	  retried. A real defect; zero at steady state.
//	- relayMisses — FOREIGN entries whose retained relay frame was absent.
//
// Split out of `misses` : the pre-split counter conflated the
//
//	  orphan defect class with the relay-retention class, and a counter that
//	  means two things means nothing. NOT necessarily a defect (the delta
//	  propagates one hop; a relay holding the frame ships it next sweep).
//	- pending — SELF entries withheld because a commit was IN FLIGHT
//
// (commitInFlight > 0): the honest non-defect class.
func (g *Gossiper) shipBatchedDelta(ctx context.Context, peerID [16]byte, delta *eng.CRDTDelta, batchSize int) (shipped, entries, misses, relayMisses, pending int) {
	if batchSize < 1 {
		batchSize = DefaultBatchSize
	}
	if batchSize > MaxBatchSize {
		batchSize = MaxBatchSize
	}
	batch := make([]BuiltEvent, 0, batchSize)
	// The batch dedup (ADR-0045): a per-sweep seen-set keyed on
	// batchKey{origin, originSeq} so the foreign branch Publishes each DISTINCT
	// batch exactly ONCE per peer per sweep — the no-oversend directive.
	// Without it the foreign branch would Publish the same batch frame once PER
	// ENTRY in it (a batch of N foreign entries from the SAME origin+originSeq
	// → N Publishes of the SAME batch envelope per sweep = N× oversend). The
	// map is local to this shipBatchedDelta call (one per peer per sweep); a
	// batch already published to THIS peer THIS sweep is a dedup-skip (counted
	// as shipped ONCE for the first element, then skipped for the rest — NOT a
	// miss, NOT a re-Publish). The seen-set is checked BEFORE lookupBatch so a
	// repeated element short-circuits without a second map read.
	seenBatch := make(map[batchRelayKey]bool)
	// : rewind the sweep-envelope memo cursor for THIS
	// peer. The cache is keyed by BATCH POSITION within the round, so every peer must
	// start reading at position 0. Without this rewind, peer 1 would leave the cursor
	// at 100 and peer 2 would look up slot 100, MISS, re-sign, and overwrite the memo
	// at the wrong index — silently defeating the whole optimization AND corrupting
	// later peers' lookups. (Found by reading the call structure before trusting the
	// build: `go build` was clean, which proves nothing about index discipline.)
	g.sweepEnvIdx = 0
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// (ADR-0037): --hybrid-sign switches the self-originated batch
		// from the v1 ShipBatch (one Ed25519) to ShipBatchHybrid (one Ed25519 +
		// one ML-DSA-65 over the SAME 120-byte SHAKE256 pad, carried in a
		// HybridEnvelope). The relay/foreign path stays per-frame regardless
		// (the self-origin boundary — a relayer holds ONLY its own PQ key;
		// ShipBatchHybrid is self-origin-only, the SAME boundary ShipBatch
		// enforces). A false hybridSign (the DEFAULT) keeps the v1 ShipBatch
		// path byte-identical (— NO
		// hybrid frame is produced). A misconfigured --hybrid-sign on a
		// non-PQ owner returns an error from ShipBatchHybrid (the nil-pqPriv
		// guard) — logged + the batch skipped, NOT a panic (the v1 path + the
		// relay path are unaffected).
		var b, e int
		var err error
		if g.hybridSign {
			b, e, err = g.ShipBatchHybrid(ctx, peerID, batch)
		} else {
			b, e, err = g.ShipBatch(ctx, peerID, batch)
		}
		if err != nil {
			log.Printf("mesh: shipBatchedDelta to %x: %v — batch skipped this round (oversend converges it next sweep)", peerID, err)
			batch = batch[:0]
			return
		}
		shipped += b
		entries += e // entries = SELF entries actually PUBLISHED (the ONLY add —; the walk-top `entries++` that double-counted every shipped entry is deleted)
		batch = batch[:0]
	}
	delta.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		if ctx.Err() != nil {
			return false
		}
		// entries is NOT incremented here: a walked entry is
		// not a shipped entry. The identity the gate reads — entries + pending
		// == deliverable set — has guards only if every walked entry lands in
		// EXACTLY ONE of {entries (shipped), pending, misses, relayMisses,
		// foreign-dedup (counted once per batch in shipped)}.
		// (ADR-0045): branch on origin. SELF → the batch-
		// build path below (the existing shipBatchedDelta behavior, byte-identical
		// for self entries). FOREIGN → relay the retained origin-signed BATCH
		// envelope onward (the self-origin boundary — batch.go:11-18 + the
		// note at :324: a relayer holds ONLY its own relay seed, NEVER the foreign
		// ORIGIN's seed, so it CANNOT re-origin-sign a foreign delta into the
		// batch; a batch that relayer-signs foreign origins is a FORGERY. Foreign
		// deltas STAY in their origin's batch — the relayer re-publishes the
		// WHOLE retained BatchEnvelope byte-identical, the SAME boundary shipDelta
		// enforces per-frame). This mirrors shipDelta's foreign branch
		// (gossip.go:1176-1190) but on the BATCH path: lookupBatch resolves the
		// foreign entry's (origin, dotCounter) → its batch's OriginSeq → the
		// retained BatchEnvelope bytes, then LengthPrefixFrame + Publish (the SAME
		// re-publish byte-identical shape). The DEDUP (the no-oversend
		// requirement, NON-NEGOTIABLE): a per-sweep seen-set (seenBatch, keyed on
		// batchKey{origin, originSeq}) Publishes each DISTINCT batch exactly ONCE
		// per peer per sweep — without it the foreign branch would Publish the
		// same batch frame once PER ENTRY in it (N Publishes of the SAME batch per
		// sweep = N× oversend). The seen-set is checked BEFORE lookupBatch so a
		// repeated element short-circuits without a second map read. This closes
		// the one-hop-relay defect on the BATCH path (the path AntiEntropySweep uses when
		// --batch-size > 1, the production default 100). PRE-FIX this closure
		// routed the WHOLE delta (self + foreign) through cache.lookup (the
		// SELF-only payloadCache), so a receiver sweeping a FOREIGN delta missed
		// every entry, shipped 0, + the foreign delta never propagated past one
		// hop — the silicon-found 100-node convergence blocker (relay_miss=0 on
		// every node; the 3-node shipDelta test passed because it exercised the
		// per-frame path, NOT this batch path).
		if entry.OriginNodeID != g.owner.NodeID {
			flush() // ship any pending SELF batch first so the foreign batch
			// Publish does not interleave a foreign frame into a SELF batch
			// (the batch is self-origin-only by the boundary above).
			// Resolve the foreign entry's (origin, dotCounter) → its batch's
			// OriginSeq + the retained BatchEnvelope bytes. lookupBatch does the
			// reverse-index (relayKey{origin, dotCounter}→originSeq) then the
			// forward-map (batchKey{origin, originSeq}→frame) read. A miss means
			// this node never received that foreign batch → skip this round (the
			// delta propagates one hop, not zero; a relay that DID retain it ships
			// it next sweep).
			frame, originSeq, ok := g.relay.lookupBatch(entry.OriginNodeID, entry.DotCounter)
			if !ok {
				relayMisses++ //: the relay-retention class, split OUT of misses (which is orphan-only now)
				if relayMisses <= missLogCap {
					log.Printf("mesh: relay miss for %s origin=%x dotCounter=%d — foreign delta skipped this round: NO RETAINED FRAME in the relayCache. This node may well have Joined this dot; retention is what is missing, NOT receipt. If EVERY foreign entry misses, the relay retainer is likely UNWIRED (use Gossiper.WireRelayHooks, which installs the per-frame AND batch hooks) — a genuinely-never-received dot is the other cause, and a relay that holds the frame ships it next sweep.", entityID, entry.OriginNodeID, entry.DotCounter)
				}
				return true
			}
			// DEDUP: publish each distinct batch exactly once per peer per sweep.
			// A batch already published to THIS peer THIS sweep (seenBatch hit) is
			// a dedup-skip — counted as shipped ONCE for the first element (the
			// Publish below), then the remaining N-1 elements from the same batch
			// short-circuit here WITHOUT a second Publish. This is NOT a miss (the
			// batch WAS retained + WAS published this sweep); it is the no-oversend
			// discipline. The seen-set keys on batchKey{origin, originSeq} so two
			// DISTINCT batches from the same origin (different originSeq) both ship.
			bk := batchRelayKey{originNodeID: entry.OriginNodeID, originSeq: originSeq}
			if seenBatch[bk] {
				return true // already published this batch to this peer this sweep
			}
			prefixed := receive.LengthPrefixFrame(frame) // the retained frame IS the origin-signed BatchEnvelope; re-publish byte-identical (forward.go:104)
			if err := g.peers.Publish(peerID, prefixed); err != nil {
				log.Printf("mesh: Publish to %x for foreign %s: %v — skipped", peerID, entityID, err)
				return true
			}
			seenBatch[bk] = true // mark this batch published to this peer this sweep
			shipped++
			return true
		}
		payload, ok := g.cache.lookup(entityID, entry.Dot())
		if !ok {
			// a SELF lookup miss while ANY commit is in
			// flight is an entry whose WAL fsync/record has not landed YET — a
			// pending non-event, NOT a defect (the seed counted its own
			// in-flight batches as 73 rounds of "misses"). With NO commit in
			// flight the miss is an ORPHAN: state the origin can never ship (a
			// WAL-failed batch the client never retried) — the REAL defect the
			// counter exists to surface. Nothing ships either way.
			if g.commitInFlight.Load() > 0 {
				pending++
				return true
			}
			misses++
			if misses <= missLogCap {
				log.Printf("mesh: payload miss for %s dot=%v — ORPHANED entry (state carries it, no payload recorded, NO commit in flight): a WAL-failed batch whose client never retried. This is a REAL defect — it must be ZERO at steady state; the entry cannot ship until a retry re-commits it", entityID, entry.Dot())
			}
			return true
		}
		batch = append(batch, BuiltEvent{EntityID: entityID, Payload: payload, Entry: entry})
		if len(batch) >= batchSize {
			flush()
		}
		return true
	})
	flush() // ship the trailing partial batch
	return shipped, entries, misses, relayMisses, pending
}
