// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Shared batch construction for sweeps with a common delta (ADR-0069 §4).
//
// Without the hoist, shipBatchedDelta walks, resolves, and sorts the same entry
// set for every peer. At 700,000 entries and 35 peers, the benchmark measured
// 30.6 s in walk+sort out of a 35.6 s sweep.
//
// The hoist applies only when stratified anti-entropy and the defer handler are
// disabled, no defer window is armed, and batchSize > 1 or hybridSign is set.
// These conditions guarantee a shared delta. The stratified+batch route keeps
// its per-peer walk because reusing one peer's entries for another would ship
// the wrong set. TestRelaySharedDeltaStratifiedFence guards that boundary;
// SOVEREIGN_TEST_FAULT_HOIST_ALL supplies its fault-injection case.
//
// The shared walk collects each distinct foreign batch once, in walk order, and
// replays it once per peer. Context checks, publish errors, chunk boundaries,
// and ShipBatch/ShipBatchHybrid accounting remain per peer. Walk observations
// are copied into each peer's shipStats, preserving quiescent sweep totals.
//
// Entry fields are values. EntityID and Payload reference arena-backed bytes
// covered by the sharedDelta EBR pin until AntiEntropySweep finishes its peer
// loop. The sorted slice and replay list are read-only during flushing, and the
// serial sweep goroutine is their only writer.

package mesh

import (
	"cmp"
	"context"
	"log"
	"slices"
	"time"

	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// foreignReplayItem is one publishable foreign envelope collected by the shared
// walk. A retained batch carries its decoded element count; a per-frame hit
// carries one element. Per-frame hits are not batch-deduplicated because the
// walk already visits each dot once.
type foreignReplayItem struct {
	frame []byte
	count int
}

// sharedShipSet holds one sweep's sorted self-event buffer, walk-ordered
// foreign replay list, and observation counters. Its zero value is unbuilt. The
// first flushing peer builds it lazily, so a sweep with no eligible peers does
// no walk. The sweep goroutine is the only writer.
type sharedShipSet struct {
	// Pointer-bearing fields come first, so the GC's scanned prefix ends after
	// the second slice's pointer slot at offset 32. The remaining fields are
	// scalar.
	batch       []BuiltEvent
	replay      []foreignReplayItem
	built       bool
	misses      int
	pending     int
	relayMisses int
}

// buildSharedShipEvents walks the delta once, producing the sorted self
// buffer, deduplicated foreign replay list, and walk observations. The hoist
// domain disables the defer handler and all defer windows, so
// forEachShipEntry takes its plain delta.Entries branch and never calls costOf.
// The single probe capture supplies the sorts-per-sweep measurement.
func (g *Gossiper) buildSharedShipEvents(ctx context.Context, peerID [16]byte, delta *eng.CRDTDelta, s *sharedShipSet) {
	var probeT0 time.Time
	if g.shipBuildProbe.Load() != nil || g.shipBuildMetrics.Load() != nil {
		probeT0 = time.Now()
	}
	seenBatch := make(map[batchRelayKey]bool) // collect each distinct batch once per sweep, preserving walk order
	var bmiss, bpend, brelayMiss int
	g.forEachShipEntry(peerID, delta,
		func(entityID string, entry eng.CRDTEntry) int { return 1 }, // unused because the hoist domain disables the defer handler and all defer windows
		func(entityID string, entry eng.CRDTEntry) bool {
			if ctx.Err() != nil {
				return false
			}
			if entry.OriginNodeID != g.owner.NodeID {
				// Resolve and deduplicate foreign envelopes once per sweep instead
				// of once per peer, then collect them for replay.
				frame, originSeq, count, ok := g.relay.lookupBatchCounted(entry.OriginNodeID, entry.DotCounter)
				if ok {
					bk := batchRelayKey{originNodeID: entry.OriginNodeID, originSeq: originSeq}
					if !seenBatch[bk] {
						seenBatch[bk] = true
						s.replay = append(s.replay, foreignReplayItem{frame: frame, count: count})
					}
					return true
				}
				// A per-frame arrival is retained in relay.m rather than the batch
				// layer (ADR-0067). Each hit becomes its own replay item because
				// the walk already deduplicates dots.
				if pf, ok2 := g.relay.lookup(entry.OriginNodeID, entry.DotCounter); ok2 {
					s.replay = append(s.replay, foreignReplayItem{frame: pf, count: 1})
					return true
				}
				brelayMiss++
				if brelayMiss <= g.effectiveMissLogCap() {
					log.Printf("mesh: relay miss for %s origin=%x dotCounter=%d — foreign delta skipped this round: no retained frame in per-frame or batch relay cache (reported once per hoisted sweep)", entityID, entry.OriginNodeID, entry.DotCounter)
				}
				return true
			}
			payload, ok := g.cache.lookup(entityID, entry.Dot())
			if !ok {
				if g.commitInFlight.Load() > 0 {
					bpend++ // withheld while its commit is still in flight
					return true
				}
				bmiss++
				if bmiss <= g.effectiveMissLogCap() {
					log.Printf("mesh: payload miss for %s dot=%v — orphaned entry (state carries it, no payload cached, no commit in flight; likely unretried WAL failure)", entityID, entry.Dot())
				}
				return true
			}
			s.batch = append(s.batch, BuiltEvent{EntityID: entityID, Payload: payload, Entry: entry})
			return true
		})
	// Sort once per sweep with the same DotCounter comparator as batch.go so
	// ordered chunks advance the receiver's clock window (ADR-0067).
	slices.SortFunc(s.batch, func(a, b BuiltEvent) int {
		return cmp.Compare(a.Entry.DotCounter, b.Entry.DotCounter)
	})
	if p := g.shipBuildProbe.Load(); p != nil {
		ws := time.Duration(0)
		if !probeT0.IsZero() {
			ws = time.Since(probeT0)
		}
		*p = append(*p, shipBuildCapture{peer: peerID, buf: snapshotBuiltEvents(s.batch), walkSort: ws})
	}
	if m := g.shipBuildMetrics.Load(); m != nil {
		*m = append(*m, shipBuildMetric{peer: peerID, n: len(s.batch), walkSort: time.Since(probeT0)})
	}
	s.misses, s.pending, s.relayMisses = bmiss, bpend, brelayMiss
	s.built = true
}

// flushSharedShip publishes one shared build to a peer. It rewinds the envelope
// memo, replays foreign envelopes, then flushes self chunks at batchSize
// boundaries, matching the per-peer walk's wire order. Context checks, publish
// errors, and shipped/foreignEnv/foreignRecv accounting remain per peer.
//
// With continuous ingest, the build takes its resolution and pending/miss
// classification from the first flushing peer rather than resolving again for
// each peer. Any resulting omission is retried by the next sweep. The shared
// build belongs to one sweep. SOVEREIGN_TEST_FAULT_HOIST_ALL deliberately
// applies it outside the valid domain to exercise the domain-fence tests.
func (g *Gossiper) flushSharedShip(ctx context.Context, peerID [16]byte, s *sharedShipSet, delta *eng.CRDTDelta, batchSize int) shipStats {
	if batchSize < 1 {
		batchSize = DefaultBatchSize
	}
	if batchSize > MaxBatchSize {
		batchSize = MaxBatchSize
	}
	if !s.built {
		g.buildSharedShipEvents(ctx, peerID, delta, s)
	}
	var ss shipStats
	// Copy walk observations into each peer's shipStats. The counters have no
	// per-peer side effects, and replication preserves quiescent sweep totals.
	ss.misses = s.misses
	ss.pending = s.pending
	ss.relayMisses = s.relayMisses
	// One sorted slice feeds every peer, so rewinding the position-keyed memo
	// lets later peers reuse envelopes built at the same positions for peer 1.
	g.sweepEnvIdx = 0
	publishErrs := 0
	flush := func(events []BuiltEvent) {
		if len(events) == 0 {
			return
		}
		var b, e int
		var err error
		if g.hybridSign {
			b, e, err = g.ShipBatchHybrid(ctx, peerID, events)
		} else {
			b, e, err = g.ShipBatch(ctx, peerID, events)
		}
		if err != nil {
			publishErrs++
			if !g.deferHandler || publishErrs <= g.effectiveMissLogCap() {
				log.Printf("mesh: flushSharedShip to %x: %v — batch skipped this round (oversend converges it next sweep)", peerID, err)
			}
			return
		}
		ss.shipped += b
		ss.entries += e
	}
	for i := range s.replay {
		if ctx.Err() != nil {
			break
		}
		prefixed := receive.LengthPrefixFrame(s.replay[i].frame)
		if err := g.peers.Publish(peerID, prefixed); err != nil {
			publishErrs++
			if !g.deferHandler || publishErrs <= g.effectiveMissLogCap() {
				log.Printf("mesh: Publish to %x for a foreign replay envelope: %v — skipped", peerID, err)
			}
			continue
		}
		if !g.bytesBlind.Load() { // the foreign replay's write is wire bytes
			g.sweepShipBytes += int64(len(prefixed))
		}
		ss.shipped++
		ss.foreignEnv++
		ss.foreignRecv += s.replay[i].count
	}
	for start := 0; start < len(s.batch); start += batchSize {
		if ctx.Err() != nil {
			break // a cancelled flush stops here; the next sweep re-ships (ADR-0067)
		}
		end := start + batchSize
		if end > len(s.batch) {
			end = len(s.batch)
		}
		flush(s.batch[start:end])
	}
	ss.pubErrs = publishErrs
	return ss
}
