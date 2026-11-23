// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package mesh builds and ships signed batches of CRDT deltas.
//
// The per-frame shipDelta path signs every delta separately: 60.19 µs per
// signature in the 32-core benchmark, a ceiling of 533,000 signatures per
// second. ShipBatch accumulates up to --batch-size self-originated deltas into
// one CRDTDeltaBatch, signs once, and publishes once. The per-entry signature
// cost is therefore 60.19/N µs before decode and apply costs.
//
// ShipBatch signs only the node's own writes. A relayer does not hold the
// origin's seed, so it re-publishes the retained origin-signed envelope instead
// of creating a new batch signature. The per-frame shipDelta path remains
// available for low-rate traffic, fallback, and per-frame relay.
//
// Ed25519 signs the marshaled CRDTDeltaBatch directly, without an intermediate
// SHA-256 batch root. The receiver verifies those bytes before
// ApplyCRDTDeltaBatch decodes and joins them (ADR-0010 §2).
package mesh

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// MaxBatchSize bounds the number of deltas in one batch. The Cap'n Proto list
// length permits more, but batches past the verify/apply crossover spend more
// on decoding than they save on verification. The --batch-size flag enforces
// this ceiling; the default is 100.
const MaxBatchSize = 256

// DefaultBatchSize is the --batch-size default. At 100 events, the 60.19 µs
// signature cost is 0.60 µs per event before the approximately 36 ns/entry
// apply cost. Setting --batch-size=1 selects the per-frame shipDelta path.
const DefaultBatchSize = 100

// BuiltEvent is the (entityID, payload, entry) triple accumulated by ShipBatch.
// It supplies every CRDTDeltaEvent contract field and the wire version.
// BuildCRDTDeltaBatch writes these triples directly into one Cap'n Proto event
// list rather than constructing and discarding a separate message per event.
type BuiltEvent struct {
	EntityID string
	Payload  string
	Entry    eng.CRDTEntry
}

// shipBuildCapture records the post-sort buffer, its destination peer, and the
// walk+accumulate+sort duration. On the shared-build path the buffer content is
// peer-independent, but peer identifies the first peer that triggered the
// build.
type shipBuildCapture struct {
	// Pointer fields come first so the GC's scanned prefix ends after the
	// slice's pointer slot at offset 0. The remaining fields are scalar.
	buf      []BuiltEvent
	peer     [16]byte
	walkSort time.Duration
}

// snapshotBuiltEvents makes an owned copy of a capture's buffer. EntityID and
// Payload are unsafe.String views into arena storage; tests can inspect the
// snapshot after sharedDelta.Release drops the EBR pin. Call sites invoke this
// only behind probe nil checks, so the unarmed path does not allocate here.
func snapshotBuiltEvents(batch []BuiltEvent) []BuiltEvent {
	cp := make([]BuiltEvent, len(batch))
	for i := range batch {
		cp[i] = batch[i]
		cp[i].EntityID = strings.Clone(batch[i].EntityID)
		cp[i].Payload = strings.Clone(batch[i].Payload)
	}
	return cp
}

// shipBuildMetric records {peer, n, walkSort} without a buffer reference. At
// the 700,000-event shape, content captures would retain roughly 106.4 MB for
// each of 35 per-peer buffers.
type shipBuildMetric struct {
	peer     [16]byte
	n        int
	walkSort time.Duration
}

// BuildCRDTDeltaBatch assembles one CRDTDeltaEvent per BuiltEvent and returns
// the marshaled Cap'n Proto batch consumed by ApplyCRDTDeltaBatch. It follows
// the buildBatchWireFrame reference pattern in crdt_apply_batch_test.go:
//
//	capnp.NewMessage(capnp.SingleSegment(nil))
//	NewRootCRDTDeltaBatch(seg)
//	batch.NewEvents(int32(len(events)))
//	for i, ev := range events { events.At(i).Set* ... }
//	msg.Marshal()
//
// It stamps the same 12 contract fields and version tag as
// BuildCRDTDeltaEvent. The batched and per-frame paths therefore carry the same
// event data and converge to the same engine state (ADR-0010 §3).
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
		// — the ApplyCRDTDeltaBatch Case 3 fixture (a no-op Join).
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

// ShipBatch marshals self-originated events into one CRDTDeltaBatch, signs it
// once with identity.SignCRDTFrame, wraps it in a BatchEnvelope, adds a length
// prefix, and publishes it to peerID. It returns one shipped batch and the
// number of entries it carried.
//
// HandleBatchFrame verifies the signature before ApplyCRDTDeltaBatch decodes
// and joins the events. The per-entry signature cost is 60.19/N µs for N
// entries, excluding decode and apply.
//
// The events must be this node's own writes because g.owner.Seed signs them.
// Relays re-publish retained origin-signed envelopes rather than passing
// foreign events to ShipBatch.
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

	// Build, sign, and allocate the sequence once per sweep, then publish the
	// same envelope to every selected peer. In the benchmark, per-peer build+sign
	// took 164.42 ms of a 167.28 ms sweep (98.3%) for 3,500 signatures: 35 peers
	// times 100 batches. Sharing produces 100 signatures and advances OriginSeq
	// by the number of distinct batches rather than batches times peers.
	//
	// A BatchEnvelope contains no recipient field, and its signature covers only
	// batchWire, so the bytes are peer-independent. The receiver's rate gate keys
	// on (originNodeID, OriginSeq); each peer sees the same monotonic per-origin
	// sequence without interleaving. A repeated sequence has delta zero and is
	// retained rather than consuming the admission budget.
	//
	// The cache key is the sweep round and the batch's ordinal within it. Every
	// peer in one sweep shares an envelope, while the next sweep signs fresh
	// content with a fresh sequence. AntiEntropySweep resets the cache each round.
	if pre, ok := g.sweepEnvelope(len(events)); ok {
		if err := g.peers.Publish(peerID, pre); err != nil {
			return 0, 0, fmt.Errorf("mesh: ShipBatch: Publish to %x: %w", peerID, err)
		}
		if !g.bytesBlind.Load() {
			g.sweepShipBytes += int64(len(pre))
		}
		return 1, len(events), nil
	}

	batchWire, err := BuildCRDTDeltaBatch(events)
	if err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatch: %w", err)
	}

	// One Ed25519 signature covers every delta in the marshaled batch.
	sig, err := identity.SignCRDTFrame(g.owner.Seed, batchWire)
	if err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatch: SignCRDTFrame: %w", err)
	}
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], sig)

	// OriginSeq advances once per distinct batch, not once per peer.
	// PeerBucket.Accept drains its budget by the delta between successive
	// sequences. BatchCount cannot serve this purpose because equal-sized
	// batches would produce zero deltas. The single sweep goroutine makes the
	// increment race-free.
	g.batchSeq++
	originSeq := g.batchSeq

	// Sign and apply the same batch bytes; there is no intermediate batch root.
	env := attribution.MarshalBatchEnvelope(g.owner.NodeID, sigArr, originSeq, uint16(len(events)), batchWire)
	prefixed := receive.LengthPrefixFrame(env)
	g.cacheSweepEnvelope(len(events), prefixed)
	if err := g.peers.Publish(peerID, prefixed); err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatch: Publish to %x: %w", peerID, err)
	}
	if !g.bytesBlind.Load() {
		g.sweepShipBytes += int64(len(prefixed))
	}
	return 1, len(events), nil
}

// ShipBatchHybrid is the opt-in hybrid-signing counterpart of ShipBatch
// (ADR-0037). It signs one CRDTDeltaBatch with both Ed25519 and ML-DSA-65 via
// identity.SignCRDTFrame_Hybrid: a [64]byte classical signature and a
// [3309]byte post-quantum signature over the same 120-byte SHAKE256 pad. The
// resulting HybridEnvelope is length-prefixed and published to peerID. It
// returns one batch and its entry count.
//
// The four-core loopback measurements are 60.19 µs for Ed25519 signing and
// 585.8 µs for ML-DSA-65 signing, or (60.19+585.8)/N µs per entry. The separate
// BenchmarkMLDSA65_Verify_120B-4 result of 73.7 µs measures verification, not
// signing. HandleHybridFrame requires both verifications before the same
// ApplyCRDTDeltaBatch path used by ShipBatch decodes and joins the events.
//
// Only the owner's keys can produce these origin signatures. Relays re-publish
// retained origin-signed envelopes rather than forwarding foreign events here.
// If owner.PQPriv is nil, ShipBatchHybrid returns an error and shipBatchedDelta
// skips the batch without panicking; v1 and relay shipping remain available.
// Command wiring enables --hybrid-sign only for NewNodeIdentityHybrid owners.
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
		// armed (--hybrid-sign) but the owner was not constructed via
		// NewNodeIdentityHybrid — a deploy misconfiguration. Return an error
		// (logged + the batch skipped by the caller); the v1 batch path
		// + the relay/foreign path are unaffected. Not a panic — a misconfigured
		// flag must not crash the sweep.
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: owner has no ML-DSA-65 private key — construct the owner via NewNodeIdentityHybrid before --hybrid-sign")
	}

	// Consult the per-round memo before building and signing for another peer.
	// At 35 peers and 100 batches, separate hybrid signatures for every peer
	// would mean 3,500 signing operations and about 2.26 s per sweep. The memo
	// helpers include the batch length and reject sharing under
	// --stratified-anti-entropy, where each peer has different content. The v1
	// and hybrid paths share storage but cannot occupy the same position because
	// shipBatchedDelta selects one frame shape for the Gossiper's lifetime.
	if pre, ok := g.sweepEnvelope(len(events)); ok {
		if err := g.peers.Publish(peerID, pre); err != nil {
			return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: Publish to %x: %w", peerID, err)
		}
		if !g.bytesBlind.Load() {
			g.sweepShipBytes += int64(len(pre))
		}
		return 1, len(events), nil
	}

	batchWire, err := BuildCRDTDeltaBatch(events)
	if err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: %w", err)
	}

	// One Ed25519 and one ML-DSA-65 signature cover the same 120-byte SHAKE256
	// pad that VerifyBatchHybrid recomputes for every delta in the batch.
	edSig, pqSig, err := identity.SignCRDTFrame_Hybrid(g.owner.Seed, g.owner.PQPriv, batchWire, "")
	if err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: SignCRDTFrame_Hybrid: %w", err)
	}

	// Hybrid and v1 frames share g.batchSeq, so an origin presents one monotonic
	// sequence to each peer's rate gate across frame shapes. The single sweep
	// goroutine makes the increment race-free.
	g.batchSeq++
	originSeq := g.batchSeq

	// Both signatures cover a pad derived from batchWire, while the apply path
	// consumes the original batchWire bytes rather than the pad.
	env := attribution.MarshalHybridFrame(g.owner.NodeID, edSig, pqSig, originSeq, uint16(len(events)), batchWire)
	prefixed := receive.LengthPrefixFrame(env)
	g.cacheSweepEnvelope(len(events), prefixed) // memoize for the remaining peers of this round (no-op under stratified — the V3b guard)
	if err := g.peers.Publish(peerID, prefixed); err != nil {
		return 0, 0, fmt.Errorf("mesh: ShipBatchHybrid: Publish to %x: %w", peerID, err)
	}
	if !g.bytesBlind.Load() {
		g.sweepShipBytes += int64(len(prefixed))
	}
	return 1, len(events), nil
}

// shipBatchedDelta ships self-originated entries in signed batches and
// re-publishes retained foreign envelopes. A payload miss skips that entry
// because the receiver would reject a mismatched payload. AntiEntropySweep uses
// this path when --batch-size > 1; shipDelta remains the per-frame path.
//
// Counter semantics (ADR-0045 §2 and §7):
//   - entries counts self entries actually published, not entries walked.
//     Together with pending, misses, relayMisses, and foreign deduplication, it
//     accounts for every deliverable entry without double-counting.
//   - foreignEnv counts distinct foreign envelopes re-published to this peer;
//     foreignRecv sums their decoded element counts. lookupBatchCounted supplies
//     the retained count, not the unsigned informational header. Per-frame relay
//     contributes one. Envelope sizes vary, so foreignRecv cannot be derived
//     from foreignEnv or the self batch size.
//   - misses counts orphaned self entries: the state has a dot but no payload
//     and no commit is in flight. This can result from an unretried WAL failure
//     and should be zero at steady state.
//   - relayMisses counts foreign entries with no retained frame. It is separate
//     from misses because receipt and retention are different conditions; a
//     later retention can make the entry publishable on the next sweep.
//   - pending counts self entries withheld while a commit is in flight.
//
// shipStats uses named fields for the per-peer sweep result. Callers must not
// confuse adjacent counts such as foreignEnv and foreignRecv when checking the
// received-cost budget.
type shipStats struct {
	shipped     int // self batch flushes plus foreign envelope publishes
	entries     int // self entries published in batches; on the per-frame path, elements in re-published foreign batches (keep gossip.go CommitStats in sync)
	foreignEnv  int // distinct retained foreign envelope re-publishes
	foreignRecv int // decoded elements in those envelopes: one per per-frame hit, retained batch count otherwise; bounds the received-cost budget
	misses      int // orphaned self payloads: dot present, payload absent, no commit in flight
	relayMisses int // foreign entries with no retained frame
	pending     int // self entries withheld behind an in-flight commit
	pubErrs     int // peer-Publish failures; prevents defer-window advancement
}

// foreignResolveStatus describes whether a foreign entry can be published and
// how its retained cost should be charged.
type foreignResolveStatus uint8

const (
	frMiss foreignResolveStatus = iota // no retained frame; nothing ships or is received
	frSeen                             // this batch was already published to the peer in this sweep
	frOK                               // publishable frame with its decoded element count
)

// foreignResolve holds one resolution of a foreign entry's retained envelope.
// lookupBatchCounted supplies the decoded count; the envelope header is unsigned
// and cannot describe a hybrid frame. dot keys the one-slot memo shared by the
// walk's cost pre-charge and immediate publish callback, avoiding a second
// unsynchronized lookup between them.
type foreignResolve struct {
	dot       relayKey
	frame     []byte
	originSeq uint64
	count     int
	status    foreignResolveStatus
	perFrame  bool // per-frame cache hit: one element, no originSeq, and no seenBatch mark; the walk deduplicates each dot once per sweep
}

func (g *Gossiper) shipBatchedDelta(ctx context.Context, peerID [16]byte, delta *eng.CRDTDelta, batchSize int) shipStats {
	if batchSize < 1 {
		batchSize = DefaultBatchSize
	}
	if batchSize > MaxBatchSize {
		batchSize = MaxBatchSize
	}
	// Start the walk+sort timer only when a probe is armed. The post-sort
	// capture uses this timestamp; an unarmed production walk takes the nil fast
	// path and records no time.
	var probeT0 time.Time
	if g.shipBuildProbe.Load() != nil || g.shipBuildMetrics.Load() != nil {
		probeT0 = time.Now()
	}
	var ss shipStats // the named-result struct (see its doc)
	batch := make([]BuiltEvent, 0, batchSize)
	// Deduplicate foreign batches by (origin, originSeq) for this peer and sweep
	// (ADR-0045). Otherwise every element of an N-element batch would publish
	// the same envelope again, producing N-fold oversend. The first element
	// publishes and counts the envelope; later elements are dedup-skips, not
	// misses. Resolution consults seenBatch before another batch-cache lookup.
	seenBatch := make(map[batchRelayKey]bool)
	// walkDeferWindow owns the only per-round received-cost budget, charged
	// through costOf up to deferSliceMaxEntries. A second ship-path budget would
	// both truncate disabled-handler traffic and add to the window's cap.
	// forEachShipEntry calls costOf only on escalation rounds, so other rounds
	// have no additional gating here.
	//
	// resolveForeign runs once per offered entry on those rounds. costOf stores
	// its result in memoRes and the callback consumes it immediately, ensuring
	// the charge and publish use the same frame and decoded count without a
	// second lock pair or a concurrent-retain window. Self entries cost one. A
	// foreign batch costs its decoded element count, not the unsigned header
	// count outside the signed batchWire; hybrid envelopes cannot be decoded by
	// UnmarshalBatchEnvelope. A miss or already-published batch costs zero
	// because it adds no received elements.
	resolveForeign := func(entry eng.CRDTEntry) foreignResolve {
		dot := relayKey{entry.OriginNodeID, entry.DotCounter}
		frame, originSeq, count, ok := g.relay.lookupBatchCounted(entry.OriginNodeID, entry.DotCounter)
		if !ok {
			// A per-frame origin stores its envelope in relay.m, which the batch-layer lookup cannot see (ADR-0067).
			// Fall back to that cache for mixed --batch-size deployments.
			// A hit carries one element, has no originSeq, and needs no seenBatch
			// mark because the walk already visits each dot once.
			if pf, ok2 := g.relay.lookup(entry.OriginNodeID, entry.DotCounter); ok2 {
				return foreignResolve{dot: dot, frame: pf, count: 1, status: frOK, perFrame: true}
			}
			return foreignResolve{dot: dot, status: frMiss}
		}
		if seenBatch[batchRelayKey{originNodeID: entry.OriginNodeID, originSeq: originSeq}] {
			return foreignResolve{dot: dot, originSeq: originSeq, status: frSeen}
		}
		return foreignResolve{dot: dot, frame: frame, originSeq: originSeq, count: count, status: frOK}
	}
	var memoRes foreignResolve
	costOf := func(entityID string, entry eng.CRDTEntry) int {
		if entry.OriginNodeID == g.owner.NodeID {
			return 1 // one self-originated element
		}
		memoRes = resolveForeign(entry)
		if memoRes.status != frOK {
			return 0 // relay miss or dedup-skip: nothing is received for it
		}
		return memoRes.count
	}
	// The envelope memo is keyed by batch position within the round, so every
	// peer starts at position zero. Otherwise one peer's final cursor would
	// index past the next peer's entries, causing fresh signatures and writes
	// to the wrong memo positions.
	g.sweepEnvIdx = 0
	// Count failed flushes as peer-Publish failures during the walk.
	publishErrs := 0
	// The post-walk loop supplies DotCounter-sorted chunks; flush does not
	// consume the shared self buffer during the walk.
	flush := func(events []BuiltEvent) {
		if len(events) == 0 {
			return
		}
		// --hybrid-sign selects ShipBatchHybrid for self-originated batches;
		// otherwise ShipBatch produces the v1 envelope (ADR-0037). Foreign relay
		// re-publishes retained envelopes separately and never uses the owner's
		// keys. A missing PQ key returns an error and skips only this batch.
		var b, e int
		var err error
		if g.hybridSign {
			b, e, err = g.ShipBatchHybrid(ctx, peerID, events)
		} else {
			b, e, err = g.ShipBatch(ctx, peerID, events)
		}
		if err != nil {
			publishErrs++ // prevent the defer window from advancing past an unpublished batch
			if !g.deferHandler || publishErrs <= g.effectiveMissLogCap() {
				// Cap repeated per-chunk failures on a congested edge.
				log.Printf("mesh: shipBatchedDelta to %x: %v — batch skipped this round (oversend converges it next sweep)", peerID, err)
			}
			return
		}
		ss.shipped += b
		ss.entries += e // count self entries only after successful publication
	}
	// forEachShipEntry shares defer-window policy with shipDelta. costOf carries
	// the batch received-cost calculation, and publishErrs bounds failure logs.
	g.forEachShipEntry(peerID, delta, costOf, func(entityID string, entry eng.CRDTEntry) bool {
		if ctx.Err() != nil {
			return false
		}
		// A walked entry is not necessarily shipped. Every entry must be
		// accounted for as shipped, pending, a payload miss, a relay miss, or a
		// foreign dedup-skip.
		//
		// Self entries are accumulated for a new origin-signed batch. Foreign
		// entries instead resolve (origin, dotCounter) to a retained BatchEnvelope
		// and re-publish those signed bytes; the relayer cannot sign for the
		// origin (ADR-0045). lookupBatchCounted supplies the frame, OriginSeq, and
		// decoded count, while the per-frame fallback handles mixed batch-size
		// deployments. seenBatch prevents N entries in one batch from causing N
		// publishes to the same peer in one sweep.
		//
		// Looking up foreign payloads in the self-only payloadCache would drop
		// every foreign entry and stop propagation after one hop. This separate
		// relay lookup is therefore required on the default batched path as well
		// as on shipDelta's per-frame path.
		if entry.OriginNodeID != g.owner.NodeID {
			// Self batches are sorted and flushed after the walk, so a foreign
			// publish cannot interleave into one.
			//
			// On an escalation round, costOf has just resolved this entry and
			// memoRes makes the charge and publish use the same frame and decoded
			// count without another lookup or a concurrent-retain window. On other
			// rounds the zero memo fails the dot check and resolves fresh here. A
			// memoized miss remains a miss for this round; a frame retained later
			// can ship on the next sweep but cannot become an uncharged publish.
			res := memoRes
			if res.dot != (relayKey{entry.OriginNodeID, entry.DotCounter}) {
				res = resolveForeign(entry)
			}
			if res.status == frMiss {
				ss.relayMisses++ // relay retention is distinct from an orphaned self payload
				if ss.relayMisses <= g.effectiveMissLogCap() {
					log.Printf("mesh: relay miss for %s origin=%x dotCounter=%d — foreign delta skipped this round: no retained frame in per-frame or batch relay cache (if every foreign entry misses, ensure Gossiper.WireRelayHooks is installed)", entityID, entry.OriginNodeID, entry.DotCounter)
				}
				return true
			}
			// The first element publishes a distinct batch; later elements from
			// that batch are dedup-skips, not misses or additional publishes.
			// Different OriginSeq values identify different batches from one
			// origin and are published separately.
			if res.status == frSeen {
				return true
			}
			bc := res.count                                  // decoded batch count, or one for a per-frame hit
			prefixed := receive.LengthPrefixFrame(res.frame) // re-publish the origin-signed bytes unchanged
			if err := g.peers.Publish(peerID, prefixed); err != nil {
				publishErrs++
				if !g.deferHandler || publishErrs <= g.effectiveMissLogCap() {
					log.Printf("mesh: Publish to %x for foreign %s: %v — skipped", peerID, entityID, err)
				}
				return true
			}
			if !res.perFrame {
				seenBatch[batchRelayKey{originNodeID: entry.OriginNodeID, originSeq: res.originSeq}] = true
			}
			ss.shipped++
			ss.foreignEnv++
			ss.foreignRecv += bc // costOf pre-charged the same decoded count
			return true
		}
		payload, ok := g.cache.lookup(entityID, entry.Dot())
		if !ok {
			// While a commit is in flight, the payload may not be recorded yet;
			// count it as pending rather than orphaned. With no commit in flight,
			// an absent payload can indicate an unretried WAL failure. Neither
			// case publishes uncommitted or unverifiable state.
			if g.commitInFlight.Load() > 0 {
				ss.pending++
				return true
			}
			ss.misses++
			if ss.misses <= g.effectiveMissLogCap() {
				log.Printf("mesh: payload miss for %s dot=%v — orphaned entry (state carries it, no payload cached, no commit in flight; likely unretried WAL failure)", entityID, entry.Dot())
			}
			return true
		}
		// Accumulate the full self diff, then sort by DotCounter before chunking.
		// Ordered chunks let the receiver's join crawl advance its clock window
		// chunk by chunk. In the 6,000-dot hierarchical regional-gateway backlog,
		// this healed in one or two sweeps. Hash-ordered chunks instead had only
		// (1001/6000)^100 ≈ 10^-77.77 probability of containing 100 in-window
		// dots, so atomic batch rejection kept the clock stuck and re-sent the
		// whole backlog.
		//
		// The per-peer sort costs O(D log D) off the receive path. The buffer
		// transiently holds the full self diff: measured sizeof(BuiltEvent) is
		// 152 bytes, about 912 KB at 6,000 events, and is freed on return.
		// Deterministic sorting makes position k contain the same chunk for every
		// peer sharing a delta, preserving envelope-memo behavior for both
		// ShipBatch and ShipBatchHybrid.
		batch = append(batch, BuiltEvent{EntityID: entityID, Payload: payload, Entry: entry})
		return true
	})
	// Ship the accumulated self buffer in DotCounter order, batchSize events
	// per batch.
	slices.SortFunc(batch, func(a, b BuiltEvent) int {
		return cmp.Compare(a.Entry.DotCounter, b.Entry.DotCounter)
	})
	// Probe captures count walk+sort passes and measure their duration. Content
	// captures support byte-equality and domain-fence checks. The serial sweep
	// goroutine is the only writer; an unarmed call performs two atomic loads.
	if p := g.shipBuildProbe.Load(); p != nil {
		// A zero probeT0 means the probe was armed during this call. Record zero
		// rather than time.Since(time.Time{}) for the content capture.
		ws := time.Duration(0)
		if !probeT0.IsZero() {
			ws = time.Since(probeT0)
		}
		*p = append(*p, shipBuildCapture{peer: peerID, buf: snapshotBuiltEvents(batch), walkSort: ws})
	}
	if m := g.shipBuildMetrics.Load(); m != nil {
		*m = append(*m, shipBuildMetric{peer: peerID, n: len(batch), walkSort: time.Since(probeT0)})
	}
	for start := 0; start < len(batch); start += batchSize {
		if ctx.Err() != nil {
			// Stop after cancellation instead of attempting every remaining chunk
			// and logging its context error: 60 chunks at the 6,000-entry backlog,
			// or about 7,000 at a 700,000-entry diff. The next sweep re-ships.
			break
		}
		end := start + batchSize
		if end > len(batch) {
			end = len(batch)
		}
		flush(batch[start:end])
	}
	ss.pubErrs = publishErrs
	return ss
}
