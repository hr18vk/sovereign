// Package mesh — batch.go is the SEND-side batch builder + the gossip
// ShipBatch path (the Day-5 arithmetic unlock).
//
// THE AMORTIZATION (load-bearing): the per-frame shipDelta path (gossip.go:262)
// signs ONE Ed25519 per delta — 60.19 us/delta at 32c, a 533K/sec ceiling. Day 5
// adds a SECOND ship path (ShipBatch) that accumulates up to --batch-size
// self-originated deltas, builds ONE CRDTDeltaBatch wire, signs ONCE, and
// publishes ONCE. The verify cost amortizes from 60.19 us/delta to 60.19/N
// us/delta — the arithmetic unlock for the Day-7 >=1M/sec headline.
//
// THE SELF-ORIGIN BOUNDARY (encode it, do NOT hide it): ShipBatch covers ONLY
// self-originated deltas (a node batching its OWN N writes). A relayer
// forwarding a FOREIGN delta holds ONLY its own relay seed — it NEVER holds the
// foreign ORIGIN's seed, so it CANNOT re-origin-sign a foreign delta. Relay-
// chained foreign deltas STAY per-frame (the FROZEN RelayEnvelope v3 hop chain
// in envelope.go — UNTOUCHED). A batch that relayer-signs foreign origins is a
// FORGERY. The per-frame shipDelta is RETAINED as the low-rate / fallback /
// relay path (NOT deleted).
//
// THE CRYPTO-MINIMAL DESIGN: Ed25519 signs the MARSHALED CRDTDeltaBatch WIRE
// DIRECTLY (no SHA-256 batch root). The wire the origin signs is the wire the
// receiver's ApplyCRDTDeltaBatch decodes — the bytes Verify checks ARE the bytes
// the engine Join()s (the no-hash-then-reconstruct-gap property, ADR-0010 §2).
package mesh

import (
	"context"
	"fmt"
	"log"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/identity"
	"github.com/hr18vk/supremum/pkg/receive"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// MaxBatchSize is the upper bound on the number of deltas a single batch
// carries. It is bounded by the capnp CRDTDeltaBatch list length (int32) and by
// the honest amortization floor: a batch larger than the verify/apply crossover
// N* pays more in decode than it saves in verify (the bench table reveals the
// sweet spot). 256 is the conservative ceiling the --batch-size flag enforces;
// the default is 100 (the Day-5 deliverable's headline N).
const MaxBatchSize = 256

// DefaultBatchSize is the --batch-size default. 100 is the N the Day-5
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
// FROZEN ApplyCRDTDeltaBatch (crdt_apply_batch.go:118). It mirrors the
// crdt_apply_batch_test.go:buildBatchWireFrame reference pattern:
//
//	capnp.NewMessage(capnp.SingleSegment(nil))
//	NewRootCRDTDeltaBatch(seg)
//	batch.NewEvents(int32(len(events)))
//	for i, ev := range events { events.At(i).Set* ... }
//	msg.Marshal()
//
// Every CRDTDeltaEvent contract field is stamped from the BuiltEvent's CRDTEntry
// (the 12 fields + the version tag), exactly as BuildCRDTDeltaEvent
// (crdt_capnp_wire.go:66) stamps them for the per-frame path — so the batched
// wire and the per-frame wire carry the SAME per-event bytes, and the two paths
// converge to the SAME engine state (the cross-path MerkleRoot determinism
// tooth, ADR-0010 §3). It does NOT invent fields; the setter surface is the
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
		// (HasEvents() == false) and batch.Events() returns a zero-length list
		// — the FROZEN ApplyCRDTDeltaBatch Case 3 fixture (a no-op Join).
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
// it to peerID (peers.Publish — the Day-1 TransmitTLSFrame copy-mode writer).
// It returns the per-batch counters (one batch shipped, N entries shipped).
//
// THE ONE SIGNATURE: a single Ed25519 over the marshaled CRDTDeltaBatch wire
// covers ALL N deltas — the 60.19us that now amortizes to 60.19/N us/delta. The
// receiver's HandleBatchFrame verifies this ONE signature (VerifyCRDTFrame)
// then ApplyCRDTDeltaBatch decodes the wire and Join()s all N in one decode +
// one Join (the FROZEN engine path, crdt_apply_batch.go:118).
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
	// advances by 1 per ShipBatch so the receiver's PeerBucket.Accept drains on
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
	if err := g.peers.Publish(peerID, prefixed); err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatch: Publish to %x: %w", peerID, err)
	}
	return 1, len(events), nil
}

// ShipBatchHybrid is the Day-32 (ADR-0037) hybrid-SIGN sibling of ShipBatch:
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
// over the SAME pad) then ApplyCRDTDeltaBatch decodes the wire and Join()s all
// N in one decode + one Join (the FROZEN engine path, crdt_apply_batch.go:118 —
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
func (g *Gossiper) shipBatchedDelta(ctx context.Context, peerID [16]byte, delta *eng.CRDTDelta, batchSize int) (shipped, entries, misses int) {
	if batchSize < 1 {
		batchSize = DefaultBatchSize
	}
	if batchSize > MaxBatchSize {
		batchSize = MaxBatchSize
	}
	batch := make([]BuiltEvent, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Day 32 (ADR-0037): --hybrid-sign switches the self-originated batch
		// from the v1 ShipBatch (one Ed25519) to ShipBatchHybrid (one Ed25519 +
		// one ML-DSA-65 over the SAME 120-byte SHAKE256 pad, carried in a
		// HybridEnvelope). The relay/foreign path stays per-frame regardless
		// (the self-origin boundary — a relayer holds ONLY its own PQ key;
		// ShipBatchHybrid is self-origin-only, the SAME boundary ShipBatch
		// enforces). A false hybridSign (the DEFAULT) keeps the v1 ShipBatch
		// path byte-identical Day-31 (T-PQ-HYBRID-OFF-IS-BYTE-IDENTICAL — NO
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
		entries += e
		batch = batch[:0]
	}
	delta.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		if ctx.Err() != nil {
			return false
		}
		entries++
		payload, ok := g.cache.lookup(entityID, entry.Dot())
		if !ok {
			misses++
			log.Printf("mesh: payload miss for %s dot=%v — delta entry skipped this round (oversend converges it next sweep once the origin re-publishes)", entityID, entry.Dot())
			return true
		}
		batch = append(batch, BuiltEvent{EntityID: entityID, Payload: payload, Entry: entry})
		if len(batch) >= batchSize {
			flush()
		}
		return true
	})
	flush() // ship the trailing partial batch
	return shipped, entries, misses
}
