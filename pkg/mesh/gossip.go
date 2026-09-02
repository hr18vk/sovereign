// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Package mesh — gossip.go is the anti-entropy sweep that ships signed CRDT
// deltas to peers over the TLS transport.
//
// THE SIGNED-ENVELOPE SEAM (load-bearing): gossip deltas do NOT skip the
// production receive path. Each delta flows the production path the design
// mandates:
//
//	GenerateDelta(theirDigest).Entries(entityID, entry)
//	  -> buildCRDTDeltaEvent(entityID, payload, entry)        // pkg/sync/crdt_capnp_wire.go (NEW, promotes the test builder)
//	  -> identity.SignCRDTFrame(seed, innerWire)               // pkg/identity/eddsa_hedge.go:84 (hedged Ed25519)
//	  -> attribution.NewSignedRelayEnvelopeV3(inner, sig, dot, origin, nil) // envelope.go:315 (0-hop origin frame)
//
// -> receive.LengthPrefixFrame(env.Marshal) // forward.go:104
// -> transport.TransmitTLSFrame(conn, prefixed) // transport.go:142 (copy-mode writer)
//
//	Receive (the sink):
//	  FrameReader.ReadFrame -> Receiver.HandleFrame -> Open -> Directory.Lookup -> VerifyCRDTFrame -> ApplyCRDTDeltaEvent
//
// The mesh routes deltas through the SAME signed-envelope + Ed25519 + join path
// the receive path proves. An unauthenticated gossip wire (plaintext deltagram
// over TLS) would be a security regression vs that receive path; it is forbidden
// (the in-process test orchestrator's appendDeltagram/e.Join is a TEST-only wire,
// never ported). The per-delta SignCRDTFrame cost (~60.19 us @ 32c PROVEN)
// bounds the convergence round; if a 1000-delta sweep exceeds 10 rounds, that
// is an HONEST NEGATIVE recorded verbatim — the batched path (batched deltas,
// one sig per N deltas) is the arithmetic unlock, NOT skipping the signature.
package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// payloadCache holds the payload bytes the origin published so the gossiper can
// put them on the wire alongside the engine's PayloadDigest (which
// ApplyCRDTDeltaEvent cross-validates as SHA-256(payload)). The engine discards
// payload after InsertLocal per the Join contract — so the mesh, not
// the engine, retains it. The cache keys on (entityID, dot) so each causal
// version carries its own payload; an overwrite of an entity re-inserts under a
// new, strictly-higher dot, so the old payload becomes unreachable and is
// garbage-collected lazily by sweepStampedDrops.
//
// CAPACITY DISCIPLINE: the cache is unbounded by intent (a 1000-event
// convergence run does not need eviction). The batched path and a
// production-sized cache (bounded map + LRU) are future work; the honest
// weakness is recorded in ADR-0007.
type payloadCache struct {
	mu sync.Mutex
	m  map[payloadKey]string
	// bytes is the running byte total: the SUM of the
	// retained payload lengths, maintained O(1) at record time so the
	// /debug/memstats RSS decomposition can name this cache's term WITHOUT
	// walking the map. (len(string) counts the UTF-8 bytes — the actual
	// retained memory.)
	bytes int64
}

type payloadKey struct {
	entityID string
	dot      eng.CausalDot
}

func newPayloadCache() *payloadCache { return &payloadCache{m: make(map[payloadKey]string)} }

// record stores the payload for (entityID, dot).
func (c *payloadCache) record(entityID string, dot eng.CausalDot, payload string) {
	c.mu.Lock()
	k := payloadKey{entityID, dot}
	if old, ok := c.m[k]; ok {
		c.bytes -= int64(len(old)) // an exact re-record of the same key must not double-count
	}
	c.m[k] = payload
	c.bytes += int64(len(payload))
	c.mu.Unlock()
}

// lookup returns the payload for (entityID, dot) or "" on a miss. A miss is an
// honest gap: the gossiper cannot put the payload on the wire, so the delta is
// NOT shipped for that entry this round (the receiver would DropVerify the
// SHA-256 mismatch). The caller logs the miss; it is NOT a panic.
func (c *payloadCache) lookup(entityID string, dot eng.CausalDot) (string, bool) {
	c.mu.Lock()
	v, ok := c.m[payloadKey{entityID, dot}]
	c.mu.Unlock()
	return v, ok
}

// relayCache is the (ADR-0045) retention seam. It holds the
// RAW origin-signed relay-envelope bytes for FOREIGN deltas this node received +
// Join'd (via the Receiver's onAcceptRelay hook), keyed by the CRDT identity
// (originNodeID, dotCounter). shipDelta consults it for a foreign entry +
// re-publishes the retained bytes ONWARD — the relay the O(log N) partial-view
// topology design assumes. Before the relay fix a foreign entry hit the ORIGIN-side
// payloadCache.lookup (which holds ONLY self-originated payloads) MISSED + was
// skipped, so foreign deltas propagated AT MOST one hop (the one-hop-relay defect
// that blocked 100-node convergence: a peer that reached a relay node but not
// the origin stayed root-zero). The relayCache is the foreign counterpart to the
// origin-side payloadCache: payloadCache is populated at InsertLocalEvents
// (self-origin), relayCache is populated at HandleFrame-Accept (foreign-receive).
//
// The retained bytes are the FULL relay envelope (innerWire + originSig + hops)
// — re-publishing them onward is correct: the onward receiver's HandleFrame
// re-runs Open (depth gate) + VerifyCRDTFrame (the origin sig is unchanged — the
// origin signed the innerWire, which is byte-identical) + re-keys the rate/
// clock gates on the NEW last-hop sender (this node). No re-origin-signing is
// possible (a relayer cannot sign as the origin) nor needed (the origin sig
// rides on the wire). The honest weakness (recorded in ADR-0007): the cache
// is unbounded + un-evicted (the payloadCache precedent — a convergence run
// does not need eviction); a production-sized bounded+LRU cache is future
// work. Mutex-guarded (the payloadCache precedent): the retain runs on the
// accept-loop goroutine, the lookup runs on the sweep goroutine.
//
// the batch-relay layer (ADR-0045): the per-frame relay above keys on
// (originNodeID, dotCounter)→frame — the relay shipDelta's foreign branch
// consults. The BATCH path (shipBatchedDelta, the production default --batch-size
// 100) receives a batch as ONE BatchEnvelope with ONE Ed25519 over the WHOLE
// batch wire (receiver.go:722), identified by the batch-level OriginSeq
// (env.OriginSeq — the origin's monotonic per-batch sequence, minted at
// batch.go:196, INDEPENDENT of the elements' dotCounters). There is NO per-
// element origin-signed frame in a batch to retain. So the batch layer retains
// the WHOLE batch envelope ONCE per batch (the forward map: batchKey{origin,
// originSeq}→frameBytes) + a REVERSE INDEX (relayKey{origin, dotCounter}→
// originSeq) populated at retention so shipBatchedDelta's foreign branch can
// resolve a foreign entry's (origin, dotCounter) → its batch's OriginSeq → the
// batch envelope bytes to re-publish. The reverse index is O(N) small uint64s
// per batch (one per element), populated once at retain; the lookup is two map
// reads. This mirrors the per-frame relay's contract (retain the verified origin-
// signed bytes, re-publish byte-identical) at the batch granularity. The SAME
// mutex guards both layers (the retain runs on the accept-loop goroutine, the
// lookup runs on the sweep goroutine — the payloadCache precedent).
type relayCache struct {
	mu sync.Mutex
	m  map[relayKey][]byte // per-frame layer: (origin, dotCounter) -> relay envelope

	// batchForward is the BATCH layer's forward map: batchKey{origin, originSeq}
	// -> the WHOLE BatchEnvelope bytes (retained ONCE per batch). The relay
	// re-publishes this full envelope onward the SAME way shipDelta re-publishes
	// the full per-frame relay envelope (gossip.go:1184 LengthPrefixFrame(frame)).
	batchForward map[batchRelayKey][]byte
	// batchReverse is the BATCH layer's reverse index: relayKey{origin,
	// dotCounter} -> originSeq. Populated at retainBatch (one entry per element
	// in the batch) so lookupBatch resolves a foreign entry's (origin,
	// dotCounter) to its batch's OriginSeq, then batchForward to the frame.
	batchReverse map[relayKey]uint64
	// batchRefs is the RETENTION BOUND: a refcount per forward
	// entry = how many reverse-index dots still point at that {origin, originSeq}.
	//
	// WHY IT EXISTS: retainBatch copies a frame per re-minted OriginSeq, and the
	// reverse-index overwrite below re-points a dot at the NEW seq — which made the
	// PREVIOUS seq's frame copy unreachable garbage with NO delete site anywhere in
	// the tree. The origin re-mints seqs every sweep, so growth was O(sweeps): on
	// silicon max node RSS hit 513,588 KB against the 512,000 KB memory
	// threshold — a breach. With the refcount, steady state is O(live dots /
	// batchSize) frames per origin (~100 frames ~ 2 MB), independent of sweep count.
	//
	// A frame is freed EXACTLY when its last referencing dot is displaced — never
	// while any dot still resolves through it (batch boundaries SHIFT across sweeps,
	// so partial supersession is the normal case, not an edge one).
	batchRefs map[batchRelayKey]int

	// running byte totals, maintained O(1) at retain/delete
	// so /debug/memstats names these terms WITHOUT walking the maps. frameBytes
	// is SUM(len(frame)) over the per-frame layer m; batchForwardBytes is
	// SUM(len(frame)) over batchForward — THE TERM: the retention bound is
	// per-origin (~2 MB), deployed at fan-in 99, so only this number says how
	// large the aggregate grew. Both fields sit AFTER the last pointer field so
	// the struct's fieldalignment metric stays at its pre-instrumentation value
	// (non-pointer words contribute no leading pointer data at the tail).
	frameBytes        int64
	batchForwardBytes int64
}

// batchRelayKey is the BATCH layer's forward-map key: the batch's origin nodeID
// + the origin's monotonic per-batch OriginSeq (the SAME pair the receiver's
// batch rate gate keys on at receiver.go:692 —
// PeerBucket.Accept(rateKey, env.OriginSeq)). It is DISTINCT from relayKey
// (origin, dotCounter): a batch is ONE frame with ONE OriginSeq covering N
// dotCounters, so the forward map keys on the batch identity (origin, originSeq)
// while the reverse index bridges (origin, dotCounter)→originSeq. Named
// batchRelayKey (NOT batchKey) to avoid a collision with the test helper
// `func batchKey(i int) string` in batch_insert_test.go (a key-string
// builder for the batch-inject fixtures) — both live in package mesh.
type batchRelayKey struct {
	originNodeID [16]byte
	originSeq    uint64
}

// relayKey is the CRDT identity of a foreign delta: the origin nodeID + the
// origin's monotonic DotCounter (the same pair the receiver's cheap-gate reads
// + the rate gate keys on). It is DISTINCT from payloadKey (entityID, dot): the
// relay cache is keyed by the WIRE identity (originNodeID, dotCounter) the
// receiver hands the retainer, NOT by the (entityID, CausalDot) the sweep
// iterates — shipDelta translates between the two via entry.OriginNodeID +
// entry.DotCounter (the CRDTEntry fields InsertLocal/Join populate). It is ALSO
// the reverse-index key for the BATCH layer (the per-element dotCounter the
// reverse index maps to its batch's OriginSeq).
type relayKey struct {
	originNodeID [16]byte
	dotCounter   uint64
}

func newRelayCache() *relayCache {
	return &relayCache{
		m:            make(map[relayKey][]byte),
		batchForward: make(map[batchRelayKey][]byte),
		batchReverse: make(map[relayKey]uint64),
		batchRefs:    make(map[batchRelayKey]int),
	}
}

// retain stores the verified foreign frame bytes for (originNodeID, dotCounter).
// Called from the Receiver's onAcceptRelay hook (the accept-loop goroutine).
//
// OWNERSHIP: the slice is
// TAKEN, not copied. The only producer is FrameReader.ReadFrame, which returns a
// fresh per-frame `out := make([]byte, frameLen)` (receiver.go:486) — uniquely
// owned by this call chain and never reused by the readLoop. An earlier version
// copied it anyway, citing a "reused reassembly buffer" that does not exist —
// a second heap alloc + memcpy per accepted foreign frame. The CONTRACT this
// now relies on: the caller must not mutate frameBytes after the call (the
// accept loop drops its reference on the next ReadFrame). Any FUTURE caller
// holding a shared/reused buffer MUST copy before calling retain.
// Self-originated frames (originNodeID == this node) are filtered by the caller
// (retainForeign) — retain itself is agnostic (it stores whatever it's handed).
func (c *relayCache) retain(originNodeID [16]byte, dotCounter uint64, frameBytes []byte) {
	c.mu.Lock()
	rk := relayKey{originNodeID, dotCounter}
	if old, ok := c.m[rk]; ok {
		c.frameBytes -= int64(len(old)) // a re-retain of the same dot replaces, it does not add
	}
	c.m[rk] = frameBytes
	c.frameBytes += int64(len(frameBytes))
	c.mu.Unlock()
}

// lookup returns the retained frame bytes for (originNodeID, dotCounter) or nil
// on a miss. A miss is the honest gap: the gossiper cannot fabricate a foreign
// frame, so shipDelta skips that entry this round (the delta propagates one hop,
// not zero — the next sweep re-attempts once the origin re-publishes OR a relay
// that DID retain it ships it). The caller logs the miss; it is NOT a panic.
func (c *relayCache) lookup(originNodeID [16]byte, dotCounter uint64) ([]byte, bool) {
	c.mu.Lock()
	v, ok := c.m[relayKey{originNodeID, dotCounter}]
	c.mu.Unlock()
	return v, ok
}

// retainBatch is the batch-layer retainer. It stores the WHOLE
// BatchEnvelope bytes ONCE (the forward map, keyed by batchKey{origin,
// originSeq}) + populates the reverse index (relayKey{origin, dotCounter}→
// originSeq) for every element's dotCounter in dotCounters — so a later
// lookupBatch(origin, dotCounter) resolves the element's dotCounter to its
// batch's OriginSeq, then the forward map to the frame bytes. Called from the
// Gossiper's RetainForeignBatch (the receiver's onAcceptRelayBatch hook, on the
// accept-loop goroutine). OWNERSHIP: the
// slice is TAKEN, not copied — the SAME contract retain keeps (ReadFrame
// returns a fresh per-frame buffer; the caller must not mutate it after).
// dotCounters is the per-
// element slice the receiver's InspectBatchDots decoded from the batch wire
// (crdt_apply_batch.go InspectBatchDots); the batch's OriginSeq is the origin's
// monotonic per-batch sequence the BatchEnvelope carries (env.OriginSeq).
func (c *relayCache) retainBatch(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte) {
	// A batch with ZERO dots must not be stored at all.
	// No reverse-index entry can ever point at
	// it (the reverse index keys on dotCounters), so lookupBatch can never
	// resolve it — the frame would be unreachable AND never freed (the GC
	// frees only when a refcount hits 0, and a 0-dot store creates no refcount).
	// Honest origins never emit 0-event batches (flush early-returns on empty);
	// this guard is the Byzantine/broken-origin case — a registered-but-broken
	// origin could otherwise pin one frame per batch of its rate budget.
	if len(dotCounters) == 0 {
		return
	}
	c.mu.Lock()
	fwdKey := batchRelayKey{originNodeID, originSeq}
	if old, ok := c.batchForward[fwdKey]; ok {
		c.batchForwardBytes -= int64(len(old)) // a re-retain of the same seq replaces, it does not add
	}
	c.batchForward[fwdKey] = frameBytes
	c.batchForwardBytes += int64(len(frameBytes))
	// Reverse index: one entry per element's dotCounter → this batch's OriginSeq.
	// A later lookupBatch(origin, dotCounter) reads the reverse index to find
	// originSeq, then the forward map to find the frame. O(N) small uint64s per
	// batch (N = len(dotCounters), the batch's element count); the forward map
	// stores the frame ONCE per batch (the dedup the no-oversend directive names —
	// the WHOLE batch envelope retained once, not once per element).
	//
	// — REFCOUNTED RETENTION. Every reverse-index write that
	// DISPLACES an older seq decrements that seq's refcount, and a forward entry is
	// deleted the moment its last referencing dot is gone. Without this, each
	// re-minted OriginSeq left its predecessor's frame copy unreachable with no
	// delete site anywhere in the tree — O(sweeps) growth that breached the memory
	// threshold on silicon (513,588 KB vs the 512,000 KB threshold). Batch boundaries
	// SHIFT across sweeps (98,488 vs 98,000 entries), so PARTIAL
	// supersession is the normal case: the old frame MUST stay alive while any dot
	// still resolves through it, or the relay breaks for those entries.
	for _, dc := range dotCounters {
		rk := relayKey{originNodeID, dc}
		if prevSeq, had := c.batchReverse[rk]; had && prevSeq != originSeq {
			prevKey := batchRelayKey{originNodeID, prevSeq}
			c.batchRefs[prevKey]--
			if c.batchRefs[prevKey] <= 0 {
				c.batchForwardBytes -= int64(len(c.batchForward[prevKey]))
				delete(c.batchForward, prevKey)
				delete(c.batchRefs, prevKey)
			}
		} else if had && prevSeq == originSeq {
			// Re-retaining the SAME seq for a dot already pointing at it: the
			// refcount below would double-count, so skip the increment for this dot.
			continue
		}
		c.batchReverse[rk] = originSeq
		c.batchRefs[fwdKey]++
	}
	c.mu.Unlock()
}

// batchLenForTest reports the BATCH layer's map cardinalities (forward frames,
// reverse dot entries) under the cache's own lock. Test-only accessor for the
// retention-bound guards — there is no production consumer.
func (c *relayCache) batchLenForTest() (forward, reverse int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.batchForward), len(c.batchReverse)
}

// CacheStats is the RSS-attribution snapshot: the mesh
// caches' counts + running byte totals, read production-safe under each cache's
// own lock. WHY IT EXISTS: silicon breached the 512 MB threshold
// (567,616 KB) with the DRIVER UNKNOWN; a /debug/memstats endpoint was added for
// the Go-heap terms, but the mesh caches (payloadCache, relayCache per-frame,
// relayCache batch forward/reverse) were still invisible, so the residual could
// not be attributed. The byte totals are RUNNING counters maintained O(1) at
// retain/delete (never walked), so the read is O(1) and the hot path pays two
// int64 adds it already had the lock for. The term is BatchForwardBytes:
// the retention bound is per-origin (~2 MB), deployed at fan-in 99 — only this
// number says how big the aggregate actually grew.
type CacheStats struct {
	PayloadEntries         int   // payloadCache: origin-side payload count
	PayloadBytes           int64 // payloadCache: SUM(len(payload))
	RelayFrames            int   // relayCache per-frame layer: entry count
	RelayFrameBytes        int64 // relayCache per-frame layer: SUM(len(frame))
	RelayBatchForward      int   // relayCache batch layer: forward frame count
	RelayBatchForwardBytes int64 // relayCache batch layer: SUM(len(frame)) — the term
	RelayBatchReverse      int   // relayCache batch layer: reverse dot-entry count
}

// CacheStats returns the mesh caches' RSS-attribution snapshot. Safe for
// concurrent use with the sweep + accept loops (each term is read under its
// owning cache's mutex). Nil-gossiper AND nil-cache safe (returns the zero
// value): the /debug/memstats handler calls this unconditionally, and a
// struct-literal Gossiper (convergence_metric_test.go builds one, bypassing
// NewGossiper) must not panic the scrape (a nil-cache guard added on review).
func (g *Gossiper) CacheStats() CacheStats {
	if g == nil {
		return CacheStats{}
	}
	var cs CacheStats
	if g.cache != nil {
		g.cache.mu.Lock()
		cs.PayloadEntries = len(g.cache.m)
		cs.PayloadBytes = g.cache.bytes
		g.cache.mu.Unlock()
	}
	if g.relay != nil {
		g.relay.mu.Lock()
		cs.RelayFrames = len(g.relay.m)
		cs.RelayFrameBytes = g.relay.frameBytes
		cs.RelayBatchForward = len(g.relay.batchForward)
		cs.RelayBatchForwardBytes = g.relay.batchForwardBytes
		cs.RelayBatchReverse = len(g.relay.batchReverse)
		g.relay.mu.Unlock()
	}
	return cs
}

// lookupBatch is the batch-layer lookup. It resolves a foreign
// entry's (originNodeID, dotCounter) to its batch's OriginSeq via the reverse
// index, then the OriginSeq to the batch envelope bytes via the forward map.
// Returns the WHOLE BatchEnvelope bytes + the batch's OriginSeq (re-published
// onward byte-identical — the onward receiver's HandleBatchFrame re-runs
// VerifyCRDTFrame over the batch wire + ApplyCRDTDeltaBatch re-Join's; the
// origin sig is unchanged). NOTE (correction): this comment
// previously claimed "the rate gate re-keys on the new last-hop sender" — that is
// FALSE for the BATCH path. HandleBatchFrame keys the rate gate on the ORIGIN +
// env.OriginSeq (receiver.go:743-746); only the PER-FRAME path keys on the
// last-hop pub (receiver.go:497-503), and at the production --batch-size=100 that
// path is unexercised. The false comment is why a relay fan-in was assumed to be
// spread across per-sender buckets when in fact 34 relayers all charged ONE
// origin-keyed bucket — the admission collapse seen on silicon. The rate gate
// KEEPS the origin key by design (re-keying to last-hop would grant every origin
// one budget per relayer = Sybil amplification); the fix instead made the
// origin-keyed accounting correct under non-monotonic arrival.
// The returned originSeq lets the caller dedup per-sweep (shipBatchedDelta's
// per-sweep seen-set keys on batchKey{origin, originSeq} so each distinct batch
// is published exactly once per peer per sweep — the no-oversend
// directive; without it the foreign branch would Publish the same batch once
// PER ENTRY in it = N× oversend). A miss on EITHER map is the honest gap
// (shipBatchedDelta skips that entry this round — the delta propagates one hop,
// not zero; the next sweep re-attempts once a relay that DID retain the batch
// ships it). The caller logs the miss; it is NOT a panic.
func (c *relayCache) lookupBatch(originNodeID [16]byte, dotCounter uint64) (frame []byte, originSeq uint64, ok bool) {
	c.mu.Lock()
	originSeq, ok = c.batchReverse[relayKey{originNodeID, dotCounter}]
	if !ok {
		c.mu.Unlock()
		return nil, 0, false
	}
	frame, ok = c.batchForward[batchRelayKey{originNodeID, originSeq}]
	c.mu.Unlock()
	return frame, originSeq, ok
}

// Gossiper drives the anti-entropy sweep. It owns the PeerSet, the payload
// cache, and the per-node signing identity. InsertLocalEvents is the wrappers
// callers use to both apply a delta locally and record its payload for gossip.
type Gossiper struct {
	// commitInFlight (the starting-line fix) counts the
	// batches currently INSIDE their commit window: InsertLocalEvents /
	// InsertLocalEventsBatch increment it before the state-mutating PutLocal(s)
	// call and decrement it after the payload record loop, on EVERY return
	// path. The sweep's SELF-miss sites (gossip.go shipDelta, batch.go
	// shipBatchedDelta) read it to classify a payloadCache lookup miss:
	// >0 ⇒ the entry is an IN-FLIGHT COMMIT (state visible, WAL mid-flight,
	// record imminent) — a pending non-event, NOT a defect; ==0 ⇒ an ORPHAN
	// (a WAL-failed batch whose record never lands — a REAL defect, counted).
	// The classification is a single atomic load per miss, off the ship
	// decision itself (nothing ships before record either way).
	//
	// THE MASKING BOUND, STATED FULLY: the counter is node-GLOBAL,
	// not per-entry — it cannot
	// distinguish "THIS entry's commit is in flight" from "SOME commit is in
	// flight". Under CONTINUOUS ingest (the production 5.7M-6.0M deltas/s
	// shape) commitInFlight is ~always >0, so an orphan would be classified
	// pending on EVERY sweep — the payloadMisses orphan alarm is silent
	// exactly under load, and 'no orphan escapes detection past one commit
	// window' holds only once ingest GOES IDLE. The instrument is honest
	// where it is used: the convergence check measures convergence
	// POST-quiescence (inject stopped, counter == 0, misses are orphans by
	// construction — that is the 'misses=350000 pending=0' line seen on
	// silicon). A per-entry
	// in-flight marker (the entry's dot carried by the committing batch) is
	// the general fix — a design decision, not a drive-by patch.
	//
	// PLACEMENT: the field
	// originally sat mid-struct (offset 112, sharing the 64-byte line with
	// batchSeq + bridge) while its comment claimed "no other field shares the
	// line pair" — false on the compiler's own layout, and false sharing with
	// the sweep goroutine's batchSeq writes was exactly what the pad existed
	// to prevent. It now leads the struct: offset 0 starts a fresh line, and
	// the trailing 120-byte pad isolates it from every field that follows —
	// 128 struct-relative bytes owned by this atomic alone, in BOTH
	// directions (the repo's stride convention is struct-relative; the runtime
	// does not guarantee 128-aligned heap bases).
	commitInFlight atomic.Int64
	_              [120]byte

	peers   *PeerSet
	cache   *payloadCache
	relay   *relayCache // Foreign-frame retention for onward relay (the payloadCache counterpart for received deltas)
	owner   *NodeIdentity
	engine  *eng.DeltaCRDTEngine
	domains *identity.Directory

	// roundReporter is the gossip-round counter increment seam. It is nil by
	// default (the --selftest path and the cold-scrape path construct a
	// Gossiper with no recorder, so the counter stays 0 as shipped); cmd wires
	// it to metrics.Recorder.IncGossipRound via SetRoundReporter so every
	// executed sweep round increments sovereign_gossip_rounds_total — the
	// datapath-restored signal the silicon partition harness reads.
	roundReporter func()

	// batchSize is the batched-transport knob. A value > 1 switches
	// AntiEntropySweep's self-originated delta path from the per-frame shipDelta
	// (one Ed25519 per delta) to shipBatchedDelta (one Ed25519 per N deltas —
	// the arithmetic unlock). A value of 1 (the zero-value default) keeps the
	// per-frame path (back-compat; the relay/foreign path stays per-frame
	// regardless, per the self-origin boundary). Set via SetBatchSize from
	// cmd's --batch-size flag; clamped to [1, MaxBatchSize].
	batchSize int
	// sweepRound is the monotonic anti-entropy sweep counter.
	// SINGLE-WRITER: incremented only at AntiEntropySweep entry, which runs on the
	// SweepLoop ticker goroutine (the sole caller), so it needs no atomic — the
	// SAME discipline the batchSize/regionAware "wire first, arm later" setters
	// use. It feeds two consumers: the per-node-per-round fan-out seed
	// (topology.SetSeed(round ^ nodeID)) and sweepStats.round (so the log line
	// reports the TRUE round instead of the old hardcoded 1).
	sweepRound uint64
	// sweepEnvCache / sweepEnvRound memoize the
	// build+sign+seq work WITHIN ONE SWEEP so the same signed batch envelope is
	// shipped to every selected peer instead of being rebuilt and re-signed per peer.
	//
	// MEASURED LICENCE (pkg/mesh/sweep_phase_bench_test.go): per-peer build+sign was 98.3% of
	// sweep compute — 3,500 Ed25519 signatures per sweep at 35 peers x 100 batches.
	// This cuts it to 100 (a 35x reduction) and divides the origin's OriginSeq churn
	// by the fan-out.
	//
	// KEYED BY POSITION, NOT CONTENT: sweepEnvIdx counts the DISTINCT batches minted
	// in the current round, so batch i of round R is signed once and reused by every
	// peer in round R. sweepEnvRound guards staleness — when AntiEntropySweep starts
	// round R+1 the cache is dropped, so a later sweep always re-signs fresh content
	// under a fresh seq and the cache can never grow beyond one round's batches.
	//
	// SOUND ONLY BECAUSE STRATIFIED-OFF SHARES ONE DELTA: position ⇒ identical
	// content holds ONLY because the stratified-OFF branch hoists ONE sharedDelta
	// for all peers (the `if !g.stratified` hoist below). With stratified ON each
	// peer's delta is a PER-PEER digest-exchange result and a position-keyed memo
	// serves peer 1's envelope to peer 2 — proven by
	// TestStratifiedMemoServesPerPeerContent (C received B's envelope
	// and starved). sweepEnvelope/cacheSweepEnvelope therefore refuse to serve or
	// store when g.stratified is true. The recorded batchLen is the
	// defensive content check for the OFF path: a length mismatch can never be
	// the same content, so the lookup misses and rebuilds (a length MATCH is not
	// proof of identity — the stratified guard is the real gate).
	//
	// SINGLE-WRITER: touched only from the sweep goroutine (AntiEntropySweep and the
	// ShipBatch calls it makes), the SAME discipline sweepRound/batchSeq already use
	// ("AntiEntropySweep is single-goroutine (the SweepLoop)", batch.go).
	sweepEnvCache map[int]sweepMemoEntry
	sweepEnvRound uint64
	sweepEnvIdx   int

	// batchSeq is this origin's MONOTONIC per-batch sequence number — the
	// rate-gate counter stamped into every BatchEnvelope's originSeq header
	// field and advanced by 1 per ShipBatch call. The receiver's rate gate
	// (PeerBucket.Accept) drains on the DELTA between successive originSeq
	// values from the same origin, so a burst of batches drains the origin's
	// budget (the Sybil-burst isolation the rate gate exists to enforce). It
	// mirrors the per-frame path's dotCounter (the monotonic per-origin
	// sequence the per-frame rate gate keys on). AntiEntropySweep runs under
	// the SweepLoop's single-goroutine discipline (one writer), so the
	// non-atomic increment is race-free; the field is not read off the sweep
	// goroutine.
	batchSeq uint64

	// bridge is the write-through durability seam. It is nil by default
	// (the --selftest path and the in-memory research mode construct a Gossiper
	// with no bridge, so InsertLocalEvents takes the bare engine.InsertLocal
	// path — back-compat, the silicon bench path UNTOUCHED). cmd wires it
	// via SetBridge when --wal-path is set, so the origin write path fsyncs the
	// engine-STAMPED dot to the WAL after InsertLocal. The bridge is OPTIONAL:
	// a nil bridge means durability is OFF (the honest default — durability is
	// opt-in, never claimed by default).
	bridge *durability.Bridge

	// convergence-lag seed (the gauge feeder). lastConvergedAt is the wall
	// time of the sweep at which the engine's MerkleRoot last stabilized
	// across two consecutive sweeps; lastConvergedRoot is that stable root;
	// prevRoot is the prior sweep's root (the compare operand). The lag a
	// production operator reads at /metrics is time.Since(lastConvergedAt):
	// ~0 when the mesh just converged, growing while it diverges. Updated in
	// SweepLoop after every AntiEntropySweep; read off the hot path by the
	// 1s convergence-gauge poller (cmd wiring). Guarded by the SweepLoop's
	// single-goroutine discipline (one writer); the poller reads under the
	// atomic accessors below.
	lastConvergedAt   time.Time
	lastConvergedRoot [32]byte
	prevRoot          [32]byte

	// stratified is the STRATIFIED ANTI-ENTROPY knob (ADR-0034). A
	// zero-value false (the opt-IN default) keeps AntiEntropySweep byte-
	// identical to the existing oversend path (the existing
	// TestTwoNodeConvergence + partition guards stay GREEN). A true
	// value (set via SetStratifiedAntiEntropy, wired from --stratified-anti-
	// entropy) switches the sweep to the two-phase digest-exchange: per
	// peer, SEND the local StrataEstimator + the full local IBLT digest,
	// RECEIVE the peer's, then call GenerateDelta(remoteIBLT) (the fix —
	// the set-reconciliation primitive that subtracts the peer's
	// POPULATED IBLT; the broken GenerateDeltaStratified that subtracted an
	// EMPTY remote IBLT is DELETED) for a MINIMAL delta proportional to
	// |A−B| instead of the full set. The fallback to oversend on a digest
	// timeout / malformed digest / peel failure is the honest path
	// (counted via stratifiedFallbackReporter — the stratified-fallback
	// telemetry counter).
	// GUARD: read + written under the SweepLoop's single-goroutine discipline
	// (the sweep is the only reader; SetStratifiedAntiEntropy is called once
	// at construction before the loop starts — the SetBatchSize precedent).
	stratified bool

	// digestRecvMu guards digestRecv (the per-peer blocking-receive channels
	// the sweep's digest-exchange phase waits on). Each channel is buffered
	// capacity 1: the sweep sends its OWN estimator then blocks on the receive
	// in the SAME round; a peer's estimator arrives within one round-trip.
	// DeliverDigest (digest.go) is the producer (called from the readLoop +
	// serveConn); the sweep is the consumer. A non-blocking send drops a late
	// digest from a prior round (the next round re-exchanges — a digest is
	// advisory, the signed delta is authoritative). The mutex is necessary
	// because DeliverDigest runs on the readLoop/serveConn goroutine while
	// registerDigestRecv runs on the sweep goroutine — the two race on the
	// map (caught in review; the channel send itself is goroutine-safe).
	digestRecvMu sync.Mutex
	digestRecv   map[[16]byte]chan *peerDigest

	// stratifiedFallbackReporter is the disclosure seam: it fires when the
	// digest-exchange phase falls back to oversend (digest timeout, malformed
	// digest, or GenerateDelta's peel failure at crdt.go:1603). It is nil by
	// default (the in-memory test path + the --selftest path construct a
	// Gossiper with no reporter); cmd wires it to the stratified-fallback
	// telemetry counter (StratifiedAntiEntropyFallback.Inc) via
	// SetStratifiedFallbackReporter.
	// Nil-safe: a nil reporter leaves the fallback a silent oversend (the
	// convergence guarantee holds — the counter is the DISCLOSURE, not the
	// mechanism). The counter is the number that lets the operator SEE
	// the mesh converging via oversend vs via the stratified cut.
	stratifiedFallbackReporter func()

	// digestWaitTimeout bounds the synchronous digest-exchange wait. The
	// sweep sends its estimator then blocks on the peer's estimator up to
	// this long; a timeout is the fallback to oversend (NOT a convergence
	// break — the signed delta path is unchanged, the digest only selected
	// WHICH deltas to send). 500ms default (set via the test seam; the
	// production value is generous over a cross-AZ RTT, the honest cold-start
	// bound). A zero value means "no wait" — the sweep falls back to oversend
	// immediately, the byte-identical-when-OFF guard.
	digestWaitTimeout time.Duration

	// hybridSign is the (ADR-0037) hybrid-SIGN opt-IN knob. A zero-value
	// false (the DEFAULT) keeps the self-originated delta path on the v1
	// BatchEnvelope (one Ed25519 per batch) — byte-identical (NO hybrid
	// frame is produced; the receive-side --hybrid-verify gate never sees one).
	// A true value (set via SetHybridSign, wired from --hybrid-sign) switches
	// shipBatchedDelta's self-originated path to ShipBatchHybrid: one Ed25519 +
	// one ML-DSA-65 sig over the SAME 120-byte SHAKE256 pad of batchWire, carried
	// in a HybridEnvelope (attribution.MarshalHybridFrame). The relay/foreign
	// path stays per-frame regardless (the self-origin boundary — a relayer
	// holds ONLY its own seed + its own PQ key; it CANNOT re-origin-sign a
	// foreign delta under EITHER sig, so the hybrid frame is self-origin-only,
	// the SAME boundary BatchEnvelope enforces). GUARD: read + written under the
	// SweepLoop's single-goroutine discipline (the sweep is the only reader;
	// SetHybridSign is called once at construction before the loop starts — the
	// SetBatchSize/SetStratifiedAntiEntropy precedent). opt-IN (NOT opt-OUT) per
	// the opt-IN discipline.
	hybridSign bool

	// topology is the (ADR-0039) region-aware TopologyManager — the peer
	// registry keyed by [16]byte carrying a RegionTag per peer + the Select(ctx)
	// iteration source AntiEntropySweep calls when regionAware is ON. It is nil
	// by default (the opt-IN default — the --selftest path + the in-memory test
	// path + the cold-scrape path construct a Gossiper with no topology, so
	// AntiEntropySweep takes the full-mesh peers.Peers path = byte-identical).
	// cmd wires it via SetTopology when
	// --region-aware is set, so the sweep routes intra-region full-mesh +
	// inter-region fan-out-N (prefer cross-region, seeded-deterministic — the
	// O(log N) rounds convergence the design names). Nil-safe (the
	// SetRoundReporter / SetHybridSign precedent): a nil topology + regionAware
	// false = the full-mesh path, byte-identical to the existing full-mesh path.
	// GUARD: read on the
	// SweepLoop's single-goroutine discipline; SetTopology is called once at
	// construction before the loop starts (the SetStratifiedAntiEntropy
	// precedent — single-writer-before-reader, race-free under the
	// discipline).
	topology *TopologyManager

	// interRegionReporter is the disclosure seam: it fires once per
	// inter-region envelope SHIPPED in the production sweep (every fan-out
	// selection that routes a delta to a CROSS-region peer). It is nil by default
	// (the in-memory test path + the --selftest path construct a Gossiper with no
	// reporter); cmd wires it to the inter-region telemetry counter
	// (InterRegionEnvelopesShipped.Inc) via SetInterRegionReporter. Nil-safe: a
	// nil reporter leaves the inter-region ship silent (the convergence holds —
	// the counter is the DISCLOSURE, not the mechanism — the SetStratified-
	// FallbackReporter precedent). The counter is the number that lets the
	// operator SEE the region-aware path is in USE (not just wired) — the
	// operator-visible proof the fan-out selector routed deltas cross-region.
	// Fires ONLY on the inter-region arm (intra-region full-mesh is the SAME-AZ
	// baseline, NOT a disclosure-worthy event — the disclosure is the CROSS-
	// region fan-out the O(log N) convergence depends on).
	interRegionReporter func()

	// regionAware is the (ADR-0039) region-aware opt-IN knob. A zero-value
	// false (the DEFAULT) keeps AntiEntropySweep on the full-mesh peers.Peers
	// path — byte-identical (the guard). A
	// true value (set via SetRegionAware, wired from --region-aware) switches the
	// sweep's iteration source to topology.Select(ctx) (intra-region full-mesh +
	// inter-region fan-out-N). The knob is INDEPENDENT of topology != nil: BOTH
	// must be true (a topology set with regionAware false = the full-mesh path —
	// the operator can register region tags without arming the selector, the
	// honest "wire first, arm later" discipline). GUARD: read + written under
	// the SweepLoop's single-goroutine discipline (SetRegionAware is called once
	// at construction before the loop starts — the SetStratifiedAntiEntropy /
	// SetHybridSign precedent). opt-IN (NOT opt-OUT) per the discipline.
	// Placed LAST so the 1-byte bool's trailing padding is absorbed (the
	// fieldalignment discipline — manual reorder, NOT -fix; the bool shares no
	// wasted padding with the 8-byte fields above).
	regionAware bool
}

// NewGossiper binds a mesh Gossiper to a PeerSet, the owner's signing identity,
// the engine (GenerateDigest/GenerateDelta source), and the identity Directory
// the receiver resolves origins through. The Directory is shared between the
// gossiper (which Registers peers) and the Receiver (which Lookups them); the
// gossiper populating it is the Directory seam the receive path depends on.
func NewGossiper(peers *PeerSet, owner *NodeIdentity, engine *eng.DeltaCRDTEngine, dir *identity.Directory) *Gossiper {
	g := &Gossiper{
		peers:             peers,
		cache:             newPayloadCache(),
		relay:             newRelayCache(),
		owner:             owner,
		engine:            engine,
		domains:           dir,
		digestRecv:        make(map[[16]byte]chan *peerDigest),
		digestWaitTimeout: 500 * time.Millisecond, // generous over a cross-AZ RTT; the fallback bound
	}
	// Bind the Gossiper as the PeerSet's digest-exchange sink so the
	// readLoop's DispatchFrame routes a WireDigestMagic-tagged frame to
	// DeliverDigest (the sweep's per-peer blocking-receive producer). The
	// Gossiper satisfies digestSink; this is the mesh-internal seam that keeps
	// the digest OFF the receive path (a StrataEstimator is
	// not a CRDTDeltaEvent). Nil-safe: a stratified-OFF Gossiper still binds;
	// DeliverDigest's digestRecvFor returns the channel only when the sweep
	// registered a wait, so a digest that arrives when no sweep is in flight
	// drops cleanly (the next round re-exchanges). The nil-peers guard: the
	// /v1/insert path constructs a Gossiper with a nil PeerSet (the
	// TestControlInsert_WALFailureReturns503 path — InsertLocalEvents touches
	// only g.bridge + g.cache + g.engine, never g.peers); SetDigestSink is
	// skipped then (a nil PeerSet never receives a digest frame).
	if peers != nil {
		peers.SetDigestSink(g)
	}
	return g
}

// SetRoundReporter binds the gossip-round counter increment seam. cmd calls it
// once after NewGossiper with metrics.Recorder.IncGossipRound so every executed
// sweep round increments sovereign_gossip_rounds_total — the datapath-restored
// signal the silicon partition harness reads. It is nil-safe: a
// Gossiper with no reporter (the --selftest path, the cold-scrape path) leaves
// roundReporter nil and SweepLoop's nil-guard makes the increment a no-op, so
// the counter stays 0 exactly as the cold-scrape path shipped.
func (g *Gossiper) SetRoundReporter(fn func()) { g.roundReporter = fn }

// RetainForeign is the (ADR-0045) relay-retention
// callback. The Receiver fires it on every Accept (via SetRelayRetainer) with
// the verified frame's (originNodeID, dotCounter, frameBytes). RetainForeign
// filters FOREIGN vs self (originNodeID != this node's owner.NodeID) + retains
// ONLY foreign frames in the relayCache for onward re-publish by shipDelta. A
// self-originated frame is already in the origin-side payloadCache (populated at
// InsertLocalEvents) + needs no relay copy — skipping it keeps the relayCache
// foreign-only (no self-echo amplification). The retain TAKES OWNERSHIP of the
// slice — it does NOT copy (ReadFrame returns a fresh
// per-frame buffer, so the copy was redundant; the caller must not reuse it).
// Safe to call
// on the accept-loop goroutine (relayCache is mutex-guarded). cmd wires it once
// at construction: `recv.SetRelayRetainer(g.RetainForeign)` (the SetRoundReporter
// + SetClockAdvanceRecorder precedent).
func (g *Gossiper) RetainForeign(originNodeID [16]byte, dotCounter uint64, frameBytes []byte) {
	if g.relay == nil {
		return
	}
	// Self-originated: already in the origin-side payloadCache; do NOT retain
	// (keeps the relayCache foreign-only — a relay never re-ships its OWN delta
	// from a relayed copy, it re-ships it from the payload at InsertLocalEvents).
	if originNodeID == g.owner.NodeID {
		return
	}
	g.relay.retain(originNodeID, dotCounter, frameBytes)
}

// RetainForeignBatch is the (ADR-0045) batch-layer relay-
// retention callback — the batch sibling of RetainForeign. The Receiver fires
// it on every batch Accept (via SetRelayRetainerBatch) with the verified batch's
// (originNodeID, originSeq, dotCounters, batchFrameBytes). RetainForeignBatch
// filters FOREIGN vs self (originNodeID != this node's owner.NodeID) + retains
// ONLY foreign batch envelopes in the relayCache's batch layer (batchForward +
// batchReverse) for onward re-publish by shipBatchedDelta's foreign branch. A
// self-originated batch is already in the origin-side payloadCache (populated at
// InsertLocalEventsBatch) + needs no relay copy — skipping it keeps the batch
// relay foreign-only (no self-echo amplification — the SAME discipline
// RetainForeign keeps for the per-frame layer). The retain TAKES OWNERSHIP of
// the frame bytes — it does NOT copy (the batch frame is a
// fresh per-frame buffer; the caller must not reuse it).
// Safe to call on the accept-loop goroutine (relayCache is mutex-guarded).
// dotCounters is the per-element slice the receiver's eng.InspectBatchDots
// decoded from the batch wire; originSeq is env.OriginSeq (the BatchEnvelope's
// monotonic per-batch sequence).
//
// WIRING: this hook is installed by WireRelayHooks, which is
// the SINGLE seam both cmd/sovereign-node/main.go and the test guard
// call. Do NOT install it directly — the previous docstring here CLAIMED "cmd
// wires it once at construction" and that was FALSE for two silicon runs (main.go
// installed only the per-frame retainer, so at --batch-size=100 the relayCache
// batch layer stayed empty and the relay path was DEAD). A docstring is prose;
// prose is suspect. The only wiring proof is a test that consumes the production
// wiring path.
func (g *Gossiper) RetainForeignBatch(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, batchFrameBytes []byte) {
	if g.relay == nil {
		return
	}
	// Self-originated: already in the origin-side payloadCache; do NOT retain
	// (keeps the batch relay foreign-only — the SAME discipline RetainForeign
	// keeps for the per-frame layer; a node re-ships its OWN batch from the
	// payload at InsertLocalEventsBatch, not a relayed copy).
	if originNodeID == g.owner.NodeID {
		return
	}
	g.relay.retainBatch(originNodeID, originSeq, dotCounters, batchFrameBytes)
}

// sweepMemoEntry is one memoized envelope: the minted batch's length (the
// defensive content check — see the struct comment above) and the signed,
// length-prefixed envelope bytes.
type sweepMemoEntry struct {
	env []byte
	n   int
}

// sweepEnvelope returns the memoized signed envelope for the CURRENT batch position
// in the CURRENT sweep round, if this round already minted it. The
// position advances only when a batch is newly minted, so peer 2..N of a round hit
// the same entries peer 1 created. A round mismatch or a nil map is a miss.
//
// A STRATIFIED sweep NEVER reads the memo — per-peer
// digest deltas make position-keyed content unsound (peer 2 would receive peer
// 1's diff). A batchLen mismatch is likewise a miss (the defensive content
// check): a position whose recorded length differs cannot be the same content.
//
// KNOWN FRAGILITY (disclosed, not fixed): the memo is keyed by POSITION
// with only a LENGTH content check.
// A payload recorded mid-sweep (between two peers' shipBatchedDelta calls) can
// make both build a same-LENGTH, different-CONTENT batch at the same position;
// peer 2 is then served peer 1's envelope. Benign under the full-oversend
// sweep: the served envelope is a valid origin-signed batch, the receiver
// Joins it idempotently, and the omitted element re-ships next round — no
// corruption, no divergence, one round of delay. It becomes load-bearing the
// day the sweep narrows below full oversend (a partial-delta sweep would then
// ship the WRONG peer's diff silently) — at that point the memo must be
// content-keyed (e.g. on the delta's Merkle root) before the narrowing ships.
func (g *Gossiper) sweepEnvelope(batchLen int) ([]byte, bool) {
	if g.stratified {
		return nil, false
	}
	if g.sweepEnvCache == nil || g.sweepEnvRound != g.sweepRound {
		return nil, false
	}
	e, ok := g.sweepEnvCache[g.sweepEnvIdx]
	if !ok || e.n != batchLen {
		return nil, false
	}
	g.sweepEnvIdx++
	return e.env, true
}

// cacheSweepEnvelope memoizes a freshly built+signed envelope at the current batch
// position for reuse by the remaining peers of THIS sweep round.
//
// A STRATIFIED sweep NEVER memoizes — per-peer
// content must be built+signed per peer (the per-peer cost, paid ONLY on
// the opt-in stratified path; correctness outranks cost).
func (g *Gossiper) cacheSweepEnvelope(batchLen int, prefixed []byte) {
	if g.stratified {
		return
	}
	if g.sweepEnvCache == nil {
		g.sweepEnvCache = make(map[int]sweepMemoEntry)
		g.sweepEnvRound = g.sweepRound
	}
	g.sweepEnvCache[g.sweepEnvIdx] = sweepMemoEntry{env: prefixed, n: batchLen}
	g.sweepEnvIdx++
}

// relayHookSink is the structural interface for the receive-side relay-retention
// hook installers — the subset of *receive.Receiver that WireRelayHooks needs. It
// is declared here (the frameSink / dialer precedent) so the wiring
// helper is testable with a spy and carries no new import coupling.
type relayHookSink interface {
	SetRelayRetainer(fn func(originNodeID [16]byte, dotCounter uint64, frameBytes []byte))
	SetRelayRetainerBatch(fn func(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte))
}

// WireRelayHooks installs BOTH relay-retention hooks on the Receiver. It is the
// CLASS ELIMINATION for the wiring-drift bug that cost two
// silicon runs.
//
// THE BUG IT KILLS: cmd/sovereign-node/main.go installed only the PER-FRAME hook
// (`recv.SetRelayRetainer(gossiper.RetainForeign)`), while `SetRelayRetainerBatch`
// had ZERO production callers. Production runs at --batch-size=100, so
// AntiEntropySweep routes through shipBatchedDelta, whose foreign branch consults
// relayCache.lookupBatch — a cache NOTHING ever populated. The batch relay was
// DEAD in production while `TestRelayChainLoadBearing` reported GREEN,
// because that guard installs the hooks IN-TEST. Two docstrings claimed the wiring
// existed. A measured silicon run captured the cost: 373,504-377,776 `relay miss` lines
// per colocated receiver (~80 MB/log), zero cross-region frames on the sampled
// eu/ap nodes, and a hard stall at 64 divergent.
//
// WHY A HELPER AND NOT TWO CALLS IN main.go: a second call site can silently fail
// to be added again (that is exactly what happened when the batch layer landed
// — the per-frame path got its wiring, the batch path did not). One
// function, called by BOTH main.go and the guard, makes the test and the
// binary structurally incapable of drifting: adding a third hook later means
// adding it HERE, where the guard already exercises it.
//
// Call once at construction, before the accept loop starts (the
// SetRoundReporter / SetClockAdvanceRecorder single-writer-before-reader
// discipline). A nil sink is a no-op so a --selftest path can skip wiring.
func (g *Gossiper) WireRelayHooks(r relayHookSink) {
	if r == nil {
		return
	}
	r.SetRelayRetainer(g.RetainForeign)
	r.SetRelayRetainerBatch(g.RetainForeignBatch)
}

// SetBridge binds the write-through durability seam. cmd calls it after
// NewGossiper when --wal-path is set, so InsertLocalEvents routes through the
// bridge (InsertLocal → AppendMutation fsync) instead of bare
// engine.InsertLocal. A nil bridge (the default, and the --wal-path empty
// path) keeps the in-memory origin path UNTOUCHED — durability is opt-in.
// The bridge's engine MUST be the same *eng.DeltaCRDTEngine the Gossiper
// already holds (cmd constructs the bridge around the recovered engine and
// hands that same engine to NewGossiper), so the bridge's PutLocal publishes
// to the exact HAMT the sweep reads.
func (g *Gossiper) SetBridge(b *durability.Bridge) { g.bridge = b }

// BridgeActive reports whether the durability Bridge is bound (g.bridge != nil).
// It is the honest corner of the ACK-before-durability guard in control.go
// handleInsert: a zero CausalDot only means "non-durable origin write" when
// the bridge is actually active. With no bridge (--wal-path empty, the in-
// memory default), InsertLocalEvents returns a real non-zero dot via
// the bare engine.InsertLocal path, so the zero-dot branch is never taken. The
// guard is therefore conservative: it 503\'s only when durability was
// REQUESTED (--wal-path set) and the write failed to durably land.
func (g *Gossiper) BridgeActive() bool { return g.bridge != nil }

// SetBatchSize binds the batched-transport knob. cmd calls it once after
// NewGossiper with the parsed --batch-size flag (default 100, 1=per-frame, max
// 256). A value > 1 switches AntiEntropySweep's self-originated delta path to
// shipBatchedDelta (one Ed25519 per N deltas); a value of 1 keeps the per-frame
// shipDelta path (back-compat). It clamps to [1, MaxBatchSize] so a misconfigured
// flag cannot exceed the capnp list / amortization ceiling.
func (g *Gossiper) SetBatchSize(n int) {
	if n < 1 {
		n = 1
	}
	if n > MaxBatchSize {
		n = MaxBatchSize
	}
	g.batchSize = n
}

// BatchSize returns the configured batch size (test/diagnostic accessor; the
// sweep reads it on every AntiEntropySweep to pick the ship path).
func (g *Gossiper) BatchSize() int { return g.batchSize }

// SetStratifiedAntiEntropy binds the stratified-anti-entropy knob
// (ADR-0034). cmd calls it once after NewGossiper with the parsed
// --stratified-anti-entropy flag (default false). A false value (the zero-value
// default) keeps AntiEntropySweep byte-identical to the existing oversend
// path; a true value switches the sweep to the
// two-phase digest-exchange (send local SE + full IBLT digest, receive peer's,
// call GenerateDelta(remoteIBLT) for a minimal delta — the fix; the broken
// GenerateDeltaStratified that subtracted an EMPTY remote IBLT is DELETED). It mirrors the
// SetBatchSize seam: set once at construction before the SweepLoop starts (the
// single-goroutine discipline makes the non-atomic write race-free; the field
// is not read off the sweep goroutine). opt-IN (NOT opt-OUT) per the
// precedent — opt-OUT would silently flip the existing test behavior; opt-IN
// keeps TestTwoNodeConvergence + partition guards byte-identical by default.
func (g *Gossiper) SetStratifiedAntiEntropy(on bool) { g.stratified = on }

// Stratified reports whether the stratified anti-entropy digest-exchange is
// enabled (test/diagnostic accessor; the sweep reads it on every
// AntiEntropySweep to pick the digest-exchange vs oversend path).
func (g *Gossiper) Stratified() bool { return g.stratified }

// SetHybridSign binds the (ADR-0037) hybrid-SIGN opt-IN knob. cmd calls
// it once after NewGossiper with the parsed --hybrid-sign flag (default false).
// A false value (the zero-value default) keeps the self-originated delta path on
// the v1 BatchEnvelope (one Ed25519 per batch) — byte-identical (NO
// hybrid frame is produced). A true value
// switches shipBatchedDelta's self-originated path to ShipBatchHybrid (one
// Ed25519 + one ML-DSA-65 sig over the SAME 120-byte SHAKE256 pad, carried in a
// HybridEnvelope). It mirrors the SetStratifiedAntiEntropy seam: set once at
// construction before the SweepLoop starts (the single-goroutine discipline
// makes the non-atomic write race-free; the field is not read off the sweep
// goroutine). opt-IN (NOT opt-OUT) per the opt-IN discipline.
//
// ARMED guard: SetHybridSign(true) on a Gossiper whose owner has NO PQ key
// (owner.PQPriv == nil — NewNodeIdentity, NOT NewNodeIdentityHybrid) is a
// misconfiguration: ShipBatchHybrid would fail at sign time (the PQ half has no
// signer). SetHybridSign DOES NOT mint the PQ key here (the key derivation is a
// constructor concern, NOT a flag side-effect — the deploy discipline
// named); the caller MUST construct the owner via NewNodeIdentityHybrid before
// arming. A misconfigured arm is caught at ShipBatchHybrid's nil-pqPriv guard
// (an honest error logged + the batch skipped, NOT a panic — the relay/foreign
// path + the v1 batch path are unaffected).
func (g *Gossiper) SetHybridSign(on bool) { g.hybridSign = on }

// HybridSign returns the configured hybrid-SIGN knob (test/diagnostic accessor;
// shipBatchedDelta reads it on every self-originated batch to pick the ship
// path — v1 BatchEnvelope vs HybridEnvelope).
func (g *Gossiper) HybridSign() bool { return g.hybridSign }

// SetStratifiedFallbackReporter binds the disclosure seam (the
// stratified-fallback telemetry counter). cmd calls it once after NewGossiper with
// StratifiedAntiEntropyFallback.Inc so every digest-exchange fallback to
// oversend (timeout, malformed digest, peel failure at crdt.go:1603)
// increments sovereign_mesh_stratified_fallback_total — the number that
// lets the operator SEE the mesh converging via oversend vs via the stratified
// cut. Nil-safe (the SetRoundReporter precedent): a Gossiper with no reporter
// (the --selftest path, the in-memory test path) leaves the fallback a silent
// oversend — the convergence guarantee holds, the counter is the DISCLOSURE.
func (g *Gossiper) SetStratifiedFallbackReporter(fn func()) { g.stratifiedFallbackReporter = fn }

// SetTopology binds the (ADR-0039) region-aware TopologyManager. cmd
// calls it once after NewGossiper with the TopologyManager built from
// --self-region + the per-peer region tags parsed from --peers' addr@region
// suffixes (the SetRoundReporter / SetHybridSign precedent — a single-line
// setter after construction; NO constructor-arg change = NO existing-caller
// break). Nil is the honest default (a Gossiper with no topology takes the
// full-mesh peers.Peers path = byte-identical).
// SetTopology alone does NOT arm the region-aware sweep — the
// regionAware knob must ALSO be true (the "wire first, arm later" discipline —
// an operator can register region tags without arming the selector).
// Single-writer-before-reader (the SetStratifiedAntiEntropy precedent).
func (g *Gossiper) SetTopology(t *TopologyManager) { g.topology = t }

// SetRegionAware arms the (ADR-0039) region-aware sweep selector. cmd
// calls it once after NewGossiper with the parsed --region-aware flag (default
// false). A false value (the zero-value default) keeps AntiEntropySweep on the
// full-mesh peers.Peers path — byte-identical (the opt-IN
// default); a true value switches the iteration source to
// topology.Select(ctx) (intra-region full-mesh + inter-region fan-out-N). The
// knob is INDEPENDENT of topology != nil: BOTH must be true (a topology set with
// regionAware false = the full-mesh path). opt-IN (NOT opt-OUT) per the
// discipline. Single-writer-before-reader (the
// SetStratifiedAntiEntropy / SetHybridSign precedent).
func (g *Gossiper) SetRegionAware(on bool) { g.regionAware = on }

// RegionAware returns the configured region-aware knob (test/diagnostic
// accessor; AntiEntropySweep reads it on every sweep to pick the topology-
// Select vs full-mesh-Peers path).
func (g *Gossiper) RegionAware() bool { return g.regionAware }

// SetInterRegionReporter binds the disclosure seam (the inter-region telemetry
// counter). cmd calls it once after NewGossiper with
// InterRegionEnvelopesShipped.Inc so every inter-region envelope shipped by the
// region-aware sweep (every fan-out selection that routed a delta to a CROSS-
// region peer) increments sovereign_mesh_inter_region_envelopes_total — the
// number that lets the operator SEE the region-aware path is in USE (not just
// wired). Nil-safe (the SetStratifiedFallbackReporter precedent): a Gossiper
// with no reporter (the --selftest path, the in-memory test path, OR
// --region-aware=false) leaves the inter-region ship silent — the convergence
// guarantee holds, the counter is the DISCLOSURE. Fires ONLY on the inter-region
// arm (intra-region full-mesh is the SAME-AZ baseline, NOT disclosure-worthy).
func (g *Gossiper) SetInterRegionReporter(fn func()) { g.interRegionReporter = fn }

// SetDigestWaitTimeout binds the digest-exchange wait bound (test seam; the
// production default is 500ms in NewGossiper). A shorter value makes the
// fallback fire faster under a slow/stalled peer; a zero value forces the
// fallback immediately (the "no wait" degenerate path the byte-identical-OFF
// guard reduces to). The 2-node test harness sets a short value (loopback RTT
// ~10us) so a missing digest falls back within the tick, NOT a 500ms stall.
func (g *Gossiper) SetDigestWaitTimeout(d time.Duration) { g.digestWaitTimeout = d }

// registerDigestRecv installs (or refreshes) the per-peer blocking-receive
// channel the sweep's digest-exchange phase waits on. The sweep calls it per
// peer per round BEFORE sending its own estimator + blocking on the receive.
// It drains any stale estimator a prior round's late DeliverDigest deposited
// (capacity-1 buffered) so the receive starts from a clean channel. Called on
// the sweep goroutine; DeliverDigest (the producer) runs on the readLoop — the
// digestRecvMu serializes the map access (the channel send is goroutine-safe).
// Returns the channel the sweep blocks on.
func (g *Gossiper) registerDigestRecv(peerID [16]byte) chan *peerDigest {
	g.digestRecvMu.Lock()
	defer g.digestRecvMu.Unlock()
	ch, ok := g.digestRecv[peerID]
	if !ok || ch == nil {
		ch = make(chan *peerDigest, 1)
		g.digestRecv[peerID] = ch
		return ch
	}
	// Drain a stale peerDigest a prior round's late producer deposited so the
	// receive starts clean (a stale digest would make the sweep diff against a
	// PREVIOUS peer state — correct by CRDT idempotency but a wasted round).
	select {
	case <-ch:
	default:
	}
	return ch
}

// digestRecvFor returns the per-peer receive channel for a digest the readLoop
// just received, or nil if the sweep is not currently waiting on this peer
// (stratified OFF, or no round in flight for this peer). Called on the
// readLoop/serveConn goroutine (the producer side); the digestRecvMu serializes
// the map read against the sweep's registerDigestRecv (the consumer side).
func (g *Gossiper) digestRecvFor(peerID [16]byte) chan *peerDigest {
	g.digestRecvMu.Lock()
	defer g.digestRecvMu.Unlock()
	return g.digestRecv[peerID]
}

// reportStratifiedFallback fires the disclosure seam (the stratified-fallback
// telemetry counter) when the digest-exchange phase falls back to oversend. Nil-safe (the
// SetRoundReporter precedent): a Gossiper with no reporter leaves the fallback
// a silent oversend — the convergence guarantee holds, the counter is the
// DISCLOSURE. Called on the sweep goroutine.
func (g *Gossiper) reportStratifiedFallback() {
	if g.stratifiedFallbackReporter != nil {
		g.stratifiedFallbackReporter()
	}
}

// Cache returns the payload cache (test seam + the inject path records into it).
func (g *Gossiper) Cache() *payloadCache { return g.cache }

// selectLatestDot returns the entry with the highest causal dot under a TOTAL
// order: max DotCounter; ties broken by smallest DotNodeID (bytes.Compare). It
// is a PURE function of `entries` — deterministic independent of slice/map
// iteration order. The tie-break is a deterministic pick, NOT a causal claim
// (dots from different origins are not totally ordered by counter alone); the
// choice is documented. Both handleGet and LatestPayload route through this ONE
// selector so the /v1/get response and the standalone accessor can never pick a
// different "latest" for the same entry slice (the total-order root cause).
func selectLatestDot(entries []eng.CRDTEntry) (eng.CRDTEntry, bool) {
	var latest eng.CRDTEntry
	seen := false
	for i := range entries {
		e := &entries[i]
		if !seen {
			latest = *e
			seen = true
			continue
		}
		switch {
		case e.DotCounter > latest.DotCounter:
			latest = *e
		case e.DotCounter == latest.DotCounter:
			if bytes.Compare(e.DotNodeID[:], latest.DotNodeID[:]) < 0 {
				latest = *e
			}
		}
	}
	return latest, seen
}

// LatestPayload returns the cached payload string for the most-recent causal
// dot the engine holds for entityID, or ("", false) when no cached payload
// survives for that dot. It is the read-path accessor the control port's /v1/get
// route uses to report the originator-vs-peer boundary HONESTLY (per the Join contract):
//
//   - On the ORIGINATOR node (the node that InsertLocalEvents-ed the entry) the
//     payload survives in g.cache keyed by (entityID, dot); LatestPayload returns
//     (payload, true).
//   - On a PEER node that received the delta via gossip the payload was discarded
//     after the ReconstructEntry cross-check (crdt_reconstruct.go:346), so the
//     cache has NO entry for that dot; LatestPayload returns ("", false). The
//
// peer's State.Get(entityID) still carries the PayloadDigest — the digest
//
//	survives, the value does NOT.
//
// The accessor READS the existing cache; it mounts NO new retention path. It
// finds the latest dot by scanning engine.PointGet(entityID)
// (point_get.go, the O(log N) per-shard read that replaced State.Get) for the
// entry with the maximum DotCounter (the most-recent write) and looks
// that dot up in the cache. A Get that reports the digest as if it were the
// value is a FABRICATION; this accessor is the seam that keeps the boundary
// visible (ADR-0011 §1.1, §5).
func (g *Gossiper) LatestPayload(entityID string) (payload string, ok bool) {
	entries := g.engine.PointGet(entityID) // point_get.go — O(log N) per-shard, no State arena leak
	latest, ok := selectLatestDot(entries)
	if !ok {
		return "", false
	}
	return g.cache.lookup(entityID, latest.Dot()) // gossip.go:78
}

// PayloadForDot looks up the cached payload for a SPECIFIC dot without
// re-scanning State. It is the single-snapshot seam handleGet uses so the
// response's payload and digest derive from the SAME entry (no TOCTOU between
// scan and lookup). The cache is mutex-guarded (gossip.go:56), so a concurrent
// InsertLocalEvents cache.record is safe to race this lookup — no new data race
// is introduced (confirmed in review).
func (g *Gossiper) PayloadForDot(entityID string, dot eng.CausalDot) (string, bool) {
	return g.cache.lookup(entityID, dot) // gossip.go:78
}

// RegisterPeer registers a peer's CRDT-delta signing pubkey in the Directory
// (the Directory receive-path seam: VerifyCRDTFrame resolves originNodeID -> pubkey
// via Directory.Lookup). It must be called for every peer before the mesh can
// accept that peer's deltas; the in-process test harness and the production
// binary both call it at peer-config time.
func (g *Gossiper) RegisterPeer(peerID [16]byte, pub []byte) error {
	return g.domains.Register(peerID, pub)
}

// InsertLocalEvents stages an event for the engine AND records its payload for
// the gossiper, so a subsequent sweep can put the payload on the wire alongside
// the engine's PayloadDigest. It is the production insertion seam for the mesh:
// it wraps engine.InsertLocal (the engine stamps OriginNodeID/DotNodeID/DotCounter)
// and caches the payload the engine discards. Returns the causal dot the engine
// assigned (so the caller keys the cache consistently).
func (g *Gossiper) InsertLocalEvents(entityID, payload string, entry eng.CRDTEntry) eng.CausalDot {
	// Production contract: the receive path cross-validates PayloadDigest ==
	// SHA-256(payload) in ReconstructEntry (crdt_reconstruct.go:346). The engine
	// discards payload after Join, so for the gossiper to put it on
	// the wire later it caches it; and for that wire to PASS the integrity
	// check the engine entry's PayloadDigest MUST equal SHA-256(payload) by the
	// time InsertLocal stamps the dot. Deriving the digest HERE (from the same
	// payload the cache stores) makes digest and payload consistent by
	// construction — the publisher cannot desync them, which is the only
	// way the receive-side guard stays honest instead of a footgun.
	//
	// When a durability bridge is set (--wal-path), route the origin
	// write through the bridge so the engine-STAMPED dot is fsync'd to the WAL
	// AFTER InsertLocal (the physical order). The bridge's PutLocal does
	// the digest + InsertLocal + AppendMutation in the load-bearing order; the
	// payload cache.record stays AFTER the WAL append (same order as today, so
	// the cache and the durable log stay consistent). A WAL append error is
	// surfaced here as a zero CausalDot — the caller (control.go /v1/insert)
	// MUST treat a zero dot as a failed durable write and NOT ACK the client
	// (the ACK-before-durability contract). A nil bridge keeps the
	// in-memory path: digest + InsertLocal + cache, no WAL.
	if g.bridge != nil {
		// mark the commit window — the entry is visible in
		// state before its payload is recorded, and the sweep must classify a
		// lookup miss inside this window as PENDING, not as a defect.
		g.commitInFlight.Add(1)
		dot, err := g.bridge.PutLocal(entityID, payload, entry)
		if err != nil {
			g.commitInFlight.Add(-1)
			log.Printf("durability: WAL append failed for entity %s: %v (write NOT durable — surfacing as zero dot)", entityID, err)
			return eng.CausalDot{}
		}
		g.cache.record(entityID, dot, payload)
		g.commitInFlight.Add(-1)
		return dot
	}
	g.commitInFlight.Add(1)
	dgst := sha256.Sum256([]byte(payload))
	entry.PayloadDigest = dgst
	dot := g.engine.InsertLocal(entityID, entry) // crdt.go:912 (stamps Dot/Origin)
	g.cache.record(entityID, dot, payload)
	g.commitInFlight.Add(-1)
	return dot
}

// BatchItem is the batch-inject shape Gossiper.InsertLocalEventsBatch accepts
// (ADR-0044). It is the per-entry triple the /v1/batch-insert path
// collects (entityID, payload, bitemporal-stamped CRDTEntry) — the N-item
// generalization of InsertLocalEvents's (entityID, payload, entry) arg triple.
// It mirrors durability.LocalItem field-for-field (the Gossiper builds the
// []LocalItem from the []BatchItem on the durable path); the split keeps the
// mesh package from importing a durability-only DTO while the batch method
// stays the production insertion seam callers reach through the control port.
type BatchItem struct {
	EntityID string
	Payload  string
	Entry    eng.CRDTEntry
}

// InsertLocalEventsBatch is the ADR-0044 batch insertion seam: it
// stages N events for the engine AND records their payloads for the gossiper, so
// a subsequent sweep can put the payloads on the wire alongside the engine's
// PayloadDigest. It is the /v1/batch-insert production path; InsertLocalEvents
// (above) stays byte-identical for /v1/insert. It mirrors InsertLocalEvents's
// two-branch structure: the durable path (g.bridge != nil) routes through
// Bridge.PutLocals (N × InsertLocal + ONE AppendMutations + ONE fsync); the
// in-memory path (g.bridge == nil, the --wal-path="" opt-in research mode) does
// N × bare engine.InsertLocal (back-compat — the bridge-nil branch of
// InsertLocalEvents, looped). The per-item cache.record happens AFTER the WAL
// append on the durable path (the SAME order InsertLocalEvents keeps at
// gossip.go:634 — the cache and the durable log stay consistent).
//
// RETURN CONTRACT (the per-batch 503 signal): on the durable path, PutLocals
// returns (dots, failedFrom, err). A failedFrom != -1 OR a non-nil err means the
// WHOLE batch is un-durable (the WAL atomic-batch model — a Write or Sync failure
// means no subset can be asserted durable). The caller (control.go
// handleBatchInsert) ACKs ALL items as 503 in that case. On success (failedFrom
// == -1, err == nil) the caller ACKs ALL items as 200 with DotHex=dots[i]. The
// in-memory path always returns (dots, -1, nil) — bare InsertLocal cannot fail
// (it mints a non-zero dot for the local node), mirroring InsertLocalEvents's
// bridge-nil branch.
//
// A zero dot in the durable-path dots slice signals InsertLocal returned {}
// (should not happen — InsertLocal always mints a non-zero dot for the local
// node) OR PutLocals returned a batch-level error. The per-batch 503 guard
// (handleBatchInsert) treats the batch-level error as 503 for ALL items.
func (g *Gossiper) InsertLocalEventsBatch(items []BatchItem) (dots []eng.CausalDot, failedFrom int, err error) {
	if g.bridge != nil {
		local := make([]durability.LocalItem, len(items))
		for i, it := range items {
			local[i] = durability.LocalItem{
				EntityID: it.EntityID,
				Payload:  it.Payload,
				Entry:    it.Entry,
			}
		}
		// the commit window opens here — PutLocals mutates
		// state (InsertLocal per item) BEFORE the WAL fsync, and the record loop
		// below lands AFTER it returns. The sweep classifies a payloadCache miss
		// on these entries as PENDING while the marker is held, never as a defect.
		g.commitInFlight.Add(1)
		dots, failedFrom, err = g.bridge.PutLocals(local)
		if err != nil {
			g.commitInFlight.Add(-1)
			log.Printf("durability: WAL batch append failed (%d items): %v (write NOT durable — surfacing as per-batch 503)", len(items), err)
			return dots, failedFrom, err
		}
		// cache.record AFTER the WAL append per item — the SAME order
		// InsertLocalEvents keeps (gossip.go:634): the cache and the durable log
		// stay consistent. On a batch-level failure (failedFrom != -1) the dots
		// were still minted in-memory (InsertLocal ran before the append); we do
		// NOT record them — the caller ACKs all as 503 and the client retries,
		// so recording would cache payloads for entries the durable log does NOT
		// carry (a cache/durable-log desync). The caller's 503-ALL path ignores
		// the dots entirely.
		for i, dot := range dots {
			g.cache.record(items[i].EntityID, dot, items[i].Payload)
		}
		g.commitInFlight.Add(-1)
		return dots, -1, nil
	}
	// In-memory research path (the --wal-path="" opt-in, a non-durable config
	// by design): byte-identical to
	// InsertLocalEvents's bridge-nil branch (gossip.go:637), looped. Bare
	// engine.InsertLocal mints a non-zero dot per item; no WAL, no fsync.
	// The same window marker: InsertLocal precedes record within the loop,
	// so a mid-loop sweep sees in-flight entries — pending, not defects.
	g.commitInFlight.Add(1)
	dots = make([]eng.CausalDot, len(items))
	for i, it := range items {
		dgst := sha256.Sum256([]byte(it.Payload))
		it.Entry.PayloadDigest = dgst
		dot := g.engine.InsertLocal(it.EntityID, it.Entry) // crdt.go:965 (stamps Dot/Origin)
		g.cache.record(it.EntityID, dot, it.Payload)
		dots[i] = dot
	}
	g.commitInFlight.Add(-1)
	return dots, -1, nil
}

// sweepState carries the per-sweep counters the convergence harness and the ADR read.
type sweepState struct {
	round            int
	shippedEnvelopes int
	// shippedEntries counts entries actually PUBLISHED this
	// sweep (self batch entries on the batch path; published frames on the
	// per-frame path). Before this change the batch path ALSO counted every
	// walked entry, double-counting each shipped entry and making the
	// "entries + pending == deliverable set" invariant a tautology (ADR-0045).
	// The identity has guards now: a walked self entry that is neither shipped,
	// pending, nor orphan-missed breaks the sum loudly.
	shippedEntries int
	payloadMisses  int
	// relayMisses counts FOREIGN entries whose retained relay
	// frame was absent — the relay-retention class, split OUT of payloadMisses
	// (which is now orphan-SELF-only). Not necessarily a defect: the delta
	// propagates one hop and a relay holding the frame ships it next sweep.
	relayMisses int
	// payloadPending counts SELF entries the sweep skipped
	// because their commit was IN FLIGHT (visible in state, WAL mid-commit,
	// payload not yet recorded) — a non-defect, kept separate from
	// payloadMisses, which after the fix counts ONLY orphaned entries (a real
	// defect: zero at steady state). The sweep summary line carries both.
	payloadPending int
}

// AntiEntropySweep runs ONE round of the digest->delta->signed-envelope exchange
// against EVERY live peer (sorted by peerID for determinism — the chaos reference
// at partition.go:209 sorts the same way). For each peer:
//
//  1. localDigest := engine.GenerateDigest // crdt.go:1696
//     ship the digest wire (MarshalIBLT) to the peer via a SIGNED control frame.
//
// The peer's reader is the HandleFrame sink; a digest frame is NOT a
// CRDTDeltaEvent, so a direct HandleFrame would DropMalformed it.
//
// The sweep therefore runs the digest-delta exchange over a SEPARATE control
// channel: the Gossiper reads the peer's digest back directly via a synchronous
// RPC.
//
// THE HONEST SIMPLIFICATION: to keep a single atomic unit WITHOUT a
// new control-plane wire protocol, AntiEntropySweep ships the FULL delta
// (GenerateDelta against an EMPTY digest) to each peer every round. This is
// the CRDT-correct oversend (Join is idempotent): every peer receives every
// entry it lacks each round, converging in exactly ONE round when the
// digest exchange would have taken several. It pays N*entries verify cost
// instead of |d|*entries; the batched envelope amortizes that to one
// sig per batch. The honest weakness (oversend vs digested) is recorded in
// ADR-0007 and is the digest-exchange unlock.
//
//  2. For each (entityID, entry) the delta yields:
//
// payload := cache.lookup(entityID, entry.Dot)
//
//	innerWire := engine.BuildCRDTDeltaEvent(entityID, payload, entry) // NEW wire seam
//	sig      := identity.SignCRDTFrame(owner.Seed, innerWire)          // hedged Ed25519
//	env      := attribution.NewSignedRelayEnvelopeV3(innerWire, sig, entry.DotCounter, entry.OriginNodeID, nil) // 0-hop origin
//
// prefixed := receive.LengthPrefixFrame(env.Marshal)
// peers.Publish(peerID, prefixed) // TransmitTLSFrame
//
// The peer's reader goroutine (the peer's readLoop) reassembles the frame and
// runs the HandleFrame receive path, which calls ApplyCRDTDeltaEvent on the
// verified inner wire — convergence.
//
// NOTE on the digest exchange: the FULL-DELTA oversend is the honest
// simplification. It is the SAME property the chaos roundtrip proves
// (idempotent Join converges), and it removes a NEW control-plane wire
// protocol from this sweep's atomic scope (a protocol that would itself need a
// signed control frame + a digest frame-type discriminator on the
// HandleFrame sink). The digest exchange ships with metrics carrying the
// convergence-lag gauge that makes oversend-vs-digested measurable, and the
// real cross-AZ bandwidth budget is what forces the digested sweep.
func (g *Gossiper) AntiEntropySweep(ctx context.Context) sweepState {
	st := sweepState{}
	// (ADR-0039): the region-aware iteration-source swap. When
	// g.topology != nil AND g.regionAware (the OPT-IN — both must be true, the
	// "wire first, arm later" discipline), the iteration source is
	// g.topology.Select(ctx) (intra-region full-mesh + inter-region fan-out-N,
	// prefer cross-region, seeded-deterministic — the O(log N) rounds
	// convergence the design names). Otherwise (the DEFAULT — topology nil OR
	// regionAware false), the iteration source is the full-mesh peers.Peers
	// path — byte-identical. The per-peer
	// BODY (generateSweepDelta → the digest-exchange → GenerateDelta →
	// the batched ship) is BYTE-UNCHANGED by the swap — Select only
	// changes WHICH peers the body runs over, NOT the body itself. The wire
	// shape is byte-identical (the selector chooses WHICH peers to send the
	// SAME batch/digest/hybrid frames to, NOT a new frame shape — the
	// fuzz harness stays load-bearing without re-work).
	var peerIDs [][16]byte
	regionArmed := g.topology != nil && g.regionAware
	// — STAMP THE PER-SWEEP FAN-OUT SEED. Without this the
	// inter-region fan-out tie-break ran on a fixed ZERO seed for every sweep of
	// every run: `SetSeed` had ZERO production callers (topology.go:125 definition
	// + tests only), while topology.go:122's docstring claimed "The SweepLoop calls
	// this before each Select". It does not — SweepLoop has no round counter and
	// never touches the topology. Consequence measured on silicon: the seed
	// shipped cross-region to the SAME 1 eu + 1 ap peer EVERY sweep, so 64 of 66
	// remote nodes were never selected at all (verdict=Accept = 0, frames = 0 on
	// the sampled eu/ap nodes for the entire run).
	//
	// THE SEED MODEL is the documented per-node-per-round one:
	// `round ^ LittleEndian.Uint64(owner.NodeID[:8])`. Both terms are load-bearing:
	//   - the ROUND term rotates a single node's picks ACROSS sweeps (so every
	//     remote peer is eventually selected — the epidemic-spreading property);
	//   - the NODE-ID term de-correlates DISTINCT nodes WITHIN one round (so 34
	//     colocated nodes in the same round fan out to different remote peers
	//     instead of all piling onto the same one).
	// Determinism is PRESERVED (the contract): the seed
	// is a pure function of (round, nodeID), so the same pair reproduces the same
	// selection. This is NOT randomness — it is a rotation.
	//
	// Single-writer discipline: sweepRound is touched only here, on the sweep
	// goroutine (SweepLoop's ticker is the sole caller). It is incremented BEFORE
	// the Select so round 1 is the first sweep's real round, and it feeds st.round
	// so the log line reports the TRUE round instead of the old hardcoded 1.
	g.sweepRound++
	// Drop the previous round's envelope memo. A new round means new
	// content and a new OriginSeq, so nothing from the prior round may be
	// reused; this also bounds the map to ONE round's batches.
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0
	if regionArmed {
		g.topology.SetSeed(g.sweepRound ^ binary.LittleEndian.Uint64(g.owner.NodeID[:8]))
		peerIDs = g.topology.Select(ctx)
	} else {
		peerIDs = g.peers.Peers()
	}
	if len(peerIDs) == 0 {
		return st
	}
	// The sort.Slice runs ONLY on the full-mesh path (the selector's output is
	// already deterministically ordered — intra-first then inter-fan-out; the
	// topology path SKIPS the sort for the intra subset + the inter
	// fan-out is randomized under the seed, NOT sorted — the epidemic-spreading
	// property). Backward-compat: the full-mesh path keeps the sort (byte-
	// identical — the sort is the existing determinism the chaos
	// partition guards depend on).
	if !regionArmed {
		sort.Slice(peerIDs, func(i, j int) bool {
			for k := 0; k < 16; k++ {
				if peerIDs[i][k] != peerIDs[j][k] {
					return peerIDs[i][k] < peerIDs[j][k]
				}
			}
			return false
		})
	}
	// Report the REAL monotonic sweep round. This was the
	// hardcoded literal `st.round = 1`, which is why the silicon logs showed
	// `sweep round=1` seven times — a CONSTANT misread as a stuck counter.
	// The convergence harness greps `sweep round=` as a
	// pattern with no pinned value, and no test pins round=1 (grep-verified), so
	// reporting the true round is safe.
	// sweepRound is uint64 (it feeds the XOR seed); sweepState.round is int (the
	// pre-existing log/telemetry type, left UNCHANGED so no exported or
	// harness-read shape shifts). The conversion is safe for any realistic run:
	// int is 64-bit
	// on every target this engine builds for (arm64/amd64), and a sweep counter
	// would need ~2.9e11 years at a 100ms tick to reach math.MaxInt64.
	st.round = int(g.sweepRound)
	// — THE SWEEP HOIST, stratified-OFF branch ONLY.
	//
	// When stratified anti-entropy is OFF, generateSweepDelta ignores its peerID
	// entirely and returns g.engine.GenerateDelta(emptyDigest) (gossip.go:1336-1340)
	// — the SAME full oversend set for every peer. Running it PER PEER therefore
	// recomputed an identical 700,000-entry delta ~35 times per sweep ('s
	// measured shape at round 232: shipped_env 3,500, entries 700,000, ~3 s of wall
	// time per sweep from the log timestamps).
	//
	// The hoist computes it ONCE and shares it across the selected peers. Verified on
	// the bytes BEFORE coding, because the design required refusing the hoist if
	// anything per-peer depended on it:
	//   - the batch wire layout has NO recipient field (attribution/wire_v1.go:55-92:
	//     magic/version/originSeq/batchCount/originNodeID/originSig/batchWire), so a
	//     signed batch envelope is PEER-AGNOSTIC;
	//   - ShipBatch signs ONLY batchWire (identity.SignCRDTFrame(g.owner.Seed,
	//     batchWire)) and MarshalBatchEnvelope takes no peerID — peerID is used
	//     SOLELY as the Publish target;
	// - CRDTDelta carries an EBR epoch pin + arena-backed slices, and Release
	//     drops that pin. Sharing ONE delta holds ONE pin for the whole sweep instead
	//     of 35 pin/unpin cycles — strictly better for EBR, not merely equivalent.
	// The stratified-ON path is UNTOUCHED: its delta is a per-peer digest-exchange
	// result and MUST stay per-peer.
	var sharedDelta *eng.CRDTDelta
	if !g.stratified {
		sharedDelta = g.generateSweepDelta(ctx, [16]byte{})
		if sharedDelta != nil {
			defer sharedDelta.Release() // ONE pin for the whole sweep (was 1 per peer)
		}
	}
	for _, peerID := range peerIDs {
		if ctx.Err() != nil {
			return st
		}
		// Self-exclusion backstop — a node is NEVER its own peer. The ROOT
		// ingress is applyProvisioning over a shared peerdir that contains this
		// node's own line (fixed there, cmd/sovereign-node/provisioning.go); this
		// is the defensive one-liner that covers ANY future ingress into either
		// iteration source. On silicon: the seed logged 13,204
		// `Publish: no live peer <own-id>` lines — the ps.peers MAP-MISS branch
		// (peer.go:781-787), i.e. self was never a registered peer, it was only
		// ever a SELECTED one. Cost was ~1 wasted ship slot + log noise per sweep
		// (the loop already continues past a failed ship), so this is HYGIENE, not
		// the stall root — recorded honestly in ADR-0045 rather than overclaimed.
		if peerID == g.owner.NodeID {
			continue
		}
		// (ADR-0039): the inter-region disclosure counter fires once
		// per inter-region envelope SHIPPED in the region-aware path (every
		// fan-out selection that routed a delta to a CROSS-region peer). It is
		// the operator-VISIBLE proof the region-aware path is in USE (not just
		// wired) — the number that lets the operator SEE the fan-out
		// selector routed deltas cross-region. Fires ONLY on the inter-region
		// arm (intra-region full-mesh is the SAME-AZ baseline, NOT disclosure-
		// worthy — the disclosure is the CROSS-region fan-out the
		// O(log N) convergence depends on); fires ONLY when regionArmed (the
		// full-mesh path has no inter-region arm — every peer is SAME-region by
		// the sameRegion-default-to-true discipline). Nil-safe (the
		// SetStratifiedFallbackReporter precedent): a nil reporter leaves the
		// inter-region ship silent. The fire is BEFORE the per-peer body so a
		// body that falls back to oversend (the stratified fallback) STILL
		// discloses the inter-region routing — the counter counts the SELECTION,
		// not the delta shape.
		if regionArmed && g.interRegionReporter != nil && g.topology.IsInterRegion(peerID) {
			g.interRegionReporter()
		}
		// stratified anti-entropy (ADR-0034): when --stratified-anti-
		// entropy is ON, the sweep runs the two-phase digest-exchange per
		// peer — SEND the local StrataEstimator + the full local IBLT digest,
		// RECEIVE the peer's, then call GenerateDelta(remoteIBLT) (the fix —
		// the set-reconciliation primitive that subtracts the peer's
		// POPULATED IBLT; the broken GenerateDeltaStratified that subtracted an
		// EMPTY remote IBLT is DELETED) for a MINIMAL delta proportional to
		// |A−B| (the honest diff) instead of the full set. When OFF (the opt-IN
		// default), the sweep is byte-identical to the existing oversend path
		// (GenerateDelta against an empty IBLT — the honest
		// simplification).
		//
		// The digest-exchange is a NEW phase BEFORE the per-peer GenerateDelta
		// (NOT a per-frame inline). The naive "call
		// GenerateDelta(LOCAL IBLT)" is a no-op (self-diff → empty diff → never
		// converges); the remote IBLT MUST come from the peer (the wiring's VALUE
		// is the digest exchange, not the primitive call). The fallback to oversend
		// on a digest timeout /
		// malformed digest / peel failure is the honest path (counted via
		// reportStratifiedFallback — the stratified-fallback telemetry counter).
		// Reuse the hoisted peer-agnostic delta when stratified is OFF; the
		// stratified-ON path still generates per peer (its delta IS per-peer).
		delta := sharedDelta
		if g.stratified {
			delta = g.generateSweepDelta(ctx, peerID)
		}
		// batched transport: when --batch-size > 1, the self-originated
		// delta path ships N deltas per ONE Ed25519 signature (the arithmetic
		// unlock — 60.19us amortized to 60.19/N us/delta). When --batch-size ==
		// 1 (the zero-value default), the per-frame shipDelta path is retained
		// (one Ed25519 per delta — back-compat + the relay/foreign path, which
		// stays per-frame regardless per the self-origin boundary).
		//
		// (ADR-0037): --hybrid-sign FORCES the shipBatchedDelta path even
		// when --batch-size <= 1. The hybrid frame (HybridEnvelope) is a BATCH
		// shape — it carries the marshaled CRDTDeltaBatch wire (BuildCRDTDeltaBatch)
		// + BOTH sigs amortized over the N deltas. A per-frame hybrid would sign
		// the 120-byte pad of a ONE-delta "batch" per frame (no amortization —
		// the 585.8us ML-DSA-65 SIGN per delta, NOT per batch — the SIGN cost; the
		// 73.7us number is the ML-DSA-65 VERIFY bench, a different operation);
		// the batch is the load-bearing shape the hybrid amortization depends
		// on, so --hybrid-sign implies the batch path. When g.hybridSign is true, shipBatchedDelta
		// routes to ShipBatchHybrid (the hybrid envelope); when false, it routes
		// to the v1 ShipBatch (byte-identical). A batchSize of 0 (the
		// zero-value default — the harness + a node that did NOT pass
		// --batch-size) is clamped to DefaultBatchSize inside shipBatchedDelta,
		// so --hybrid-sign with the default batch size ships DefaultBatchSize
		// deltas per hybrid frame (the honest amortization, NOT 1-delta frames).
		// The relay/foreign path (the hops>0 branch above) stays per-frame
		// regardless (the self-origin boundary — a relayer CANNOT re-origin-sign
		// a foreign delta under EITHER sig).
		var shipped, entries, misses, relayMisses, pending int
		if g.batchSize > 1 || g.hybridSign {
			shipped, entries, misses, relayMisses, pending = g.shipBatchedDelta(ctx, peerID, delta, g.batchSize)
		} else {
			shipped, entries, misses, relayMisses, pending = g.shipDelta(ctx, peerID, delta)
		}
		// Release ONLY a per-peer delta here. The hoisted sharedDelta is
		// released ONCE via the defer above — releasing it inside the loop would
		// drop the EBR pin while later peers still read its arena-backed slices.
		if g.stratified {
			delta.Release() // CRDTDelta.Release — EBR epoch pin drop (crdt.go:1367)
		}
		st.shippedEnvelopes += shipped
		st.shippedEntries += entries
		st.payloadMisses += misses
		st.relayMisses += relayMisses
		st.payloadPending += pending
	}
	return st
}

// generateSweepDelta produces the per-peer delta for one sweep round. When
// stratified anti-entropy is OFF (the opt-IN default) it is byte-identical to
// the existing oversend path: GenerateDelta against an empty IBLT yields every
// entry (the peel falls back to "send everything" when the diff is nil — the
// honest simplification). When ON it runs the two-phase digest-exchange:
// register the per-peer recv channel, marshal + send the local
// StrataEstimator + the full local IBLT digest, block on the peer's digest
// (bounded by digestWaitTimeout), then call GenerateDelta(remoteIBLT) (the
// fix — the set-reconciliation primitive that subtracts the peer's
// POPULATED IBLT; the broken GenerateDeltaStratified that subtracted an EMPTY
// remote IBLT is DELETED) for a minimal delta. On a digest
// timeout / malformed digest / nil receive it falls back to the oversend path
// + reports the fallback (the stratified-fallback telemetry counter). The
// returned *CRDTDelta is
// the SAME type shipDelta/shipBatchedDelta consume (wire-zero — no new wire
// format on the delta path; the digest frame is a SEPARATE wire shape that
// never touches the relay envelope).
//
// GUARD: this runs on the SweepLoop's single-goroutine discipline (one sweep
// at a time), so the per-peer channel register/send/receive is race-free; the
// producer (DeliverDigest) runs on the readLoop/serveConn goroutine and is
// serialized against this only by the digestRecvMu (the channel send itself is
// goroutine-safe). The EBR pin in GenerateDelta (crdt.go:1736) is the SAME pin
// the deleted stratified sibling used — already -race-proven.
func (g *Gossiper) generateSweepDelta(ctx context.Context, peerID [16]byte) *eng.CRDTDelta {
	if !g.stratified {
		// OFF: byte-identical to the existing oversend path.
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest) // crdt.go:1603
	}
	// ON: the two-phase digest-exchange (the fixed shape). The digest frame
	// carries BOTH the local
	// StrataEstimator (the dEst sizing hint) AND the local FULL IBLT digest
	// (the POPULATED remote IBLT the peer's `GenerateDelta` subtracts). An
	// earlier draft carried ONLY the SE — the broken `GenerateDeltaStratified`
	// it delegated to subtracted an EMPTY IBLT every round = byte-identical to
	// oversend (the defect; the deleted primitive's body — documented at
	// crdt.go:1920 — created remoteIBLT then NEVER populated it).
	// The fix deletes `GenerateDeltaStratified` + has the
	// wiring call `GenerateDelta(remoteIBLT)` (crdt.go:1603, the correct
	// set-reconciliation primitive) with the peer's FULL IBLT from the wire.
	// Phase i — register the per-peer recv channel (drains a stale peerDigest
	// from a prior round so the receive starts clean), then build + send the
	// local digest frame (SE + full IBLT) to this peer over the peer-TLS
	// data-plane (the WireDigestMagic-tagged frame the peer's readLoop routes
	// to ITS digestSink).
	recvCh := g.registerDigestRecv(peerID)
	// The send-side seed: a fresh maphash.MakeSeed per round (the
	// GenerateDigest precedent at crdt.go:1821). The seed travels in the
	// strata wire header (MarshalStrataEstimator stamps se.Seed) AND is
	// stamped into the local IBLT (GenerateDigestWithSeed takes the seed); the
	// RECEIVER's `GenerateDelta` rebuilds its OWN local IBLT with THIS seed
	// (GenerateDigestWithSeed at crdt.go:1836), so the local + remote IBLTs
	// hash keys identically before the subtract. A fresh seed per round keeps
	// each round's digest independent (a replayed digest from a prior round
	// subtracts against a different seed → the peel fails → the fallback
	// to oversend, the honest path, never a convergence break).
	seed := maphash.MakeSeed()
	localSE := g.engine.GenerateStrataEstimator(seed) // crdt.go:1890 (the dEst hint)
	// The FULL local digest — the load-bearing field. Built via
	// GenerateDigestWithSeed (crdt.go:1836, the FIXED 1024-bucket digest) so
	// its bucket count MATCHES the local digest GenerateDelta builds
	// internally (crdt.go:1610 — GenerateDelta's local is also 1024 via
	// GenerateDigestWithSeed(remote.Seed)); Subtract requires identical
	// bucket counts (iblt.go:377) else diff==nil → the oversend fallback. The
	// 1024-bucket digest is peelable up to ~700 keys (the IBLT load-factor
	// threshold); above that the digest saturates + GenerateDelta falls back
	// to oversend (the honest physical limit of GenerateDelta's
	// FIXED local-digest sizing — disclosed in ADR-0034;
	// the dEst-sized dynamic digest that lifts the limit is a SEPARATE change
	// that generalizes GenerateDelta's local-digest builder, NOT this one).
	localIBLT := g.engine.GenerateDigestWithSeed(seed)      // crdt.go:1836 (the FULL local digest; matches GenerateDelta's local at 1024)
	marshaledSE, err := eng.MarshalStrataEstimator(localSE) // iblt_wire.go (NEW)
	if err != nil {
		// Marshal failure is the fallback (a nil local estimator is a
		// protocol violation; the honest path is oversend, never a crash).
		localIBLT.Release()
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	marshaledIBLT, err := eng.MarshalIBLT(localIBLT) // iblt_wire.go (the full local digest on the wire)
	localIBLT.Release()
	if err != nil {
		// IBLT marshal failure: fallback (the SE alone is unusable — the
		// remote IBLT is the load-bearing subtract operand).
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	digestFrame := buildDigestFrame(g.owner.NodeID, marshaledSE, marshaledIBLT) // digest.go (the WireDigestMagic tag + senderID + SE + IBLT)
	prefixed := receive.LengthPrefixFrame(digestFrame)
	if err := g.peers.Publish(peerID, prefixed); err != nil {
		// Publish failure (peer dropped mid-round): fallback to oversend.
		// The convergence holds — the next round re-dials + re-exchanges.
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	// Phase ii — block on the peer's digest (SE + IBLT), bounded by
	// digestWaitTimeout. A nil IBLT (DeliverDigest on a malformed digest) OR a
	// timeout is the fallback to oversend (the convergence guarantee holds —
	// the signed delta path is unchanged; the digest only selected WHICH deltas
	// to send, and oversend sends ALL of them, a strict superset).
	var remotePD *peerDigest
	timeout := g.digestWaitTimeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	timer := time.NewTimer(timeout)
	select {
	case remotePD = <-recvCh:
		timer.Stop()
	case <-ctx.Done():
		timer.Stop()
		// ctx cancel: return the oversend delta so the caller's delta.Release
		// + shipDelta loop run cleanly (the sweep exits on the next ctx check).
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	case <-timer.C:
		// Timeout: fallback. The peer did not return its digest within the
		// bound — oversend converges it this round (CRDT-idempotent Join).
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	if remotePD == nil || remotePD.iblt == nil {
		// Malformed digest (DeliverDigest delivered a nil-IBLT peerDigest) or
		// a truncated frame: fallback. (remotePD.se may be non-nil for a
		// diagnostic, but a nil IBLT is the load-bearing trigger — the SE
		// alone cannot drive the subtract.)
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	// GenerateDelta(remoteIBLT): the correct set-reconciliation primitive
	// (crdt.go:1603). It builds the LOCAL IBLT (GenerateDigestWithSeed at
	// :1610, POPULATED with this node's keys) + subtracts the POPULATED
	// remoteIBLT (the peer's full digest from the wire) at :1615, then peels
	// the real diff → ships ONLY the |A−B| keys (the bandwidth cut, FOR
	// REAL). Its peel-failure fallback (crdt.go:1679 — diff==nil || peelErr!=nil)
	// yields EVERY entry on a peel failure = FULL oversend-equivalent (NEVER
	// nil/empty), so the delta is ALWAYS a convergence-sufficient superset
	// (the diff is a strict subset of oversend; Join is MERGE-UNION,
	// crdt.go:1089). The participant-pool recycle is already on this path
	// (crdt.go:1736 — the primitive always set participantPoolPtr; the
	// leak was ONLY on the now-deleted stratified sibling).
	return g.engine.GenerateDelta(remotePD.iblt) // crdt.go:1603 (the fix)
}

// shipDelta iterates delta.Entries + publishes each to peerID. It returns per-
// delta counters. (ADR-0045): the entry's ROUTING depends
// on its ORIGIN. A SELF-originated entry (entry.OriginNodeID == this node) is
// shipped from the ORIGIN-SIDE payloadCache (populated at InsertLocalEvents) —
// the existing path: lookup the payload, BuildCRDTDeltaEvent, SignCRDTFrame as
// the origin, wrap in a 0-hop NewSignedRelayEnvelopeV3. A FOREIGN entry
// (entry.OriginNodeID != this node) is RELAYED from the relayCache (populated by
// RetainForeign at HandleFrame-Accept) — re-publish the retained origin-signed
// frame bytes ONWARD, byte-identical; a relayer CANNOT re-origin-sign (it is not
// the origin) + NEED NOT (the origin sig rides on the retained wire; the onward
// receiver's HandleFrame re-runs Open + VerifyCRDTFrame + re-keys the rate/
// clock gates on the new last-hop sender). A miss on EITHER cache skips that
// entry this round (logged, never panicked — the receiver would DropVerify a
// mismatched self payload, + a foreign miss means this node never received that
// delta so it cannot fabricate it). The skip is the honest choice, not a
// fabrication; the next sweep re-attempts once the origin re-publishes (self) or
// a relay that DID retain it ships it (foreign).
// missLogCap bounds the per-ship-call payload/relay-miss
// log lines. The AGGREGATE is unaffected: every miss still increments its counter
// (`misses` for the orphan class, `relayMisses` for the relay-retention class —
// split out in shipDelta), which flows into st.payloadMisses / st.relayMisses and
// the once-per-sweep `sweep round=` summary line in SweepLoop — so the
// OBSERVABILITY is preserved while the VOLUME is not.
//
// WHY: silicon's seed log carried 11,840,818 `payload miss` lines at up to
// 184,253 lines/second — a 2.585 GB log in 242s, ~10 MB/s from ONE node. At 34
// colocated nodes/host that is ≈340 MB/s of log writes, and they land on the EBS
// ROOT volume (~/-mesh/), NOT the NVMe instance-store the WAL correctly uses.
// That self-inflicted I/O is a plausible co-cause of the 30.03s inject timeout,
// and it buried the decisive signal: the whole diagnostic had to be recovered by
// grepping multi-gigabyte logs. A miss storm is EXPECTED during catch-up (the
// ADR-0034 oversend fallback re-ships keys×peers entries while |diff| saturates
// the IBLT), so the honest instrument is "first K per call + the exact count",
// not "one line per miss".
const missLogCap = 8

// sweepHeartbeatRounds (ADR-0045): every Nth
// sweep the `sweep round=` summary line prints EVEN WHEN every counter is 0, so
// a stalled sweep (silence) is distinguishable from a quiet one (heartbeats).
// 100 rounds ≈ one line per 10 s at the default 100 ms tick — far under the
// log-storm class seen on silicon.
const sweepHeartbeatRounds = 100

// CommitInFlight reports how many WAL commits are inside their window RIGHT
// NOW (InsertLocal'd in state, WAL append mid-flight, payloads unrecorded).
// This is the quiescence probe's missing premise (ADR-0045,
// AMENDED): under a write-behind WAL the Merkle root stops changing the moment
// the last InsertLocal lands — LONG BEFORE the commit's fsync returns — so root
// stability is necessary but NOT sufficient for quiescence. A probe that reads
// only the root starts the SLO clock while a commit is still in flight (a run
// declared quiesced at 3.12 s with a ~213 s commit outstanding). The probe must
// additionally require CommitInFlight == 0.
func (g *Gossiper) CommitInFlight() int64 {
	return g.commitInFlight.Load()
}

// CommitStats surfaces the bridge's WAL commit-latency instruments (commit
// count, total and max AppendMutation(s) wall-ns — the group-commit tail,
// ADR-0045's SLO mechanism). A nil bridge (the in-memory config)
// reports zeros: no WAL, no commit latency.
func (g *Gossiper) CommitStats() (count uint64, totalAppendNs, maxAppendNs int64) {
	if g.bridge == nil {
		return 0, 0, 0
	}
	return g.bridge.CommitStats()
}

// COUNTER SEMANTICS (the SAME contract shipBatchedDelta
// documents): entries = entries actually PUBLISHED this call (incremented at the
// two Publish-success sites, never at the walk top); misses = ORPHANED SELF
// entries (a real defect); relayMisses = FOREIGN entries with no retained frame
// (split out of misses — a counter that means two things means nothing);
// pending = SELF entries withheld behind an in-flight commit.
func (g *Gossiper) shipDelta(ctx context.Context, peerID [16]byte, delta *eng.CRDTDelta) (shipped, entries, misses, relayMisses, pending int) {
	delta.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		if ctx.Err() != nil {
			return false
		}
		// entries is NOT incremented here: a walked entry is
		// not a shipped entry. The counter advances at the Publish-success
		// sites only.
		// Branch on origin. SELF → origin-side payload (the
		// existing path, byte-identical to the original for self entries). FOREIGN
		// → relay the retained origin-signed frame onward (the path that
		// closes the one-hop relay defect — foreign deltas now propagate past
		// one hop).
		if entry.OriginNodeID != g.owner.NodeID {
			// DISCLOSED GAP: this
			// per-frame foreign branch consults ONLY the per-frame relay layer
			// (relayCache.m). A foreign delta that ARRIVED as a batch lives in
			// the BATCH layer (batchForward/batchReverse, populated by
			// retainBatch) — invisible here. Homogeneous --batch-size=100 (the
			// convergence-gate config) never exercises this: every node sweeps batched, so
			// foreign entries resolve through shipBatchedDelta's lookupBatch.
			// A MIXED deployment (a --batch-size=1 node receiving batches)
			// would stall those deltas at one hop. The fix (consult lookupBatch
			// here too) is deferred: it changes the ship path with no test
			// coverage for the mixed shape — deferred work, not a drive-by
			// patch.
			frame, ok := g.relay.lookup(entry.OriginNodeID, entry.DotCounter)
			if !ok {
				relayMisses++ // the relay-retention class, split OUT of misses (orphan-only now)
				if relayMisses <= missLogCap {
					log.Printf("mesh: relay miss for %s origin=%x dotCounter=%d — foreign delta skipped this round: NO RETAINED FRAME in the relayCache. This node may well have Joined this dot; retention is what is missing, NOT receipt. If EVERY foreign entry misses, the relay retainer is likely UNWIRED (use Gossiper.WireRelayHooks, which installs the per-frame AND batch hooks) — a genuinely-never-received dot is the other cause, and a relay that holds the frame ships it next sweep.", entityID, entry.OriginNodeID, entry.DotCounter)
				}
				return true
			}
			prefixed := receive.LengthPrefixFrame(frame) // the retained frame IS the origin-signed relay envelope; re-publish byte-identical (forward.go:104)
			if err := g.peers.Publish(peerID, prefixed); err != nil {
				log.Printf("mesh: Publish to %x for foreign %s: %v — skipped", peerID, entityID, err)
				return true
			}
			shipped++
			entries++ // 1 published frame = 1 published entry (per-frame path)
			return true
		}
		// SELF-originated: the existing payloadCache → sign → 0-hop envelope path
		// (byte-identical to the original for self entries).
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
		innerWire, err := eng.BuildCRDTDeltaEvent(entityID, payload, entry) // NEW wire seam
		if err != nil {
			log.Printf("mesh: BuildCRDTDeltaEvent %s: %v — skipped", entityID, err)
			return true
		}
		sig, err := identity.SignCRDTFrame(g.owner.Seed, innerWire) // hedged Ed25519 (eddsa_hedge.go:84)
		if err != nil {
			log.Printf("mesh: SignCRDTFrame %s: %v — skipped", entityID, err)
			return true
		}
		var sigArr [attribution.OriginSigSize]byte
		copy(sigArr[:], sig)
		env := attribution.NewSignedRelayEnvelopeV3( // envelope.go:315 (0-hop origin frame)
			innerWire, sigArr, entry.DotCounter, entry.OriginNodeID, nil)
		prefixed := receive.LengthPrefixFrame(env.Marshal())      // forward.go:104 + envelope.go:504
		if err := g.peers.Publish(peerID, prefixed); err != nil { // TransmitTLSFrame
			log.Printf("mesh: Publish to %x for %s: %v — skipped", peerID, entityID, err)
			return true
		}
		shipped++
		entries++ // 1 published frame = 1 published entry (per-frame path)
		return true
	})
	return shipped, entries, misses, relayMisses, pending
}

// SweepLoop runs AntiEntropySweep on the gossip ticker until ctx is done. The
// tick is the --gossip-tick knob; 100ms is the steady-state default, 50ms is the
// heal-control-plane override (two-knob discipline — one knob, two
// documented workloads; ADR-0007 records both).
func (g *Gossiper) SweepLoop(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = 100 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st := g.AntiEntropySweep(ctx)
			// Print on ANY activity, not just ships: a sweep that is entirely
			// pending (a whole inject in flight) or that saw orphan misses is
			// exactly the sweep an operator needs to SEE.
			//
			// HEARTBEAT (ADR-0045): the earlier
			// condition suppressed the line when every counter was 0, so a
			// fully STALLED sweep (no peers, a dead ticker, a wedged select)
			// was byte-identical in the log to a quiet healthy one — silence
			// was not evidence of quiet. Every sweepHeartbeatRounds-th round
			// prints unconditionally; a gap in the heartbeat now MEANS
			// something. Volume: one line per 100 rounds ≈ one per 10 s at the
			// default 100 ms tick — not the log-storm class seen on silicon.
			if st.shippedEnvelopes > 0 || st.payloadPending > 0 || st.payloadMisses > 0 || st.relayMisses > 0 || st.round%sweepHeartbeatRounds == 0 {
				log.Printf("mesh: sweep round=%d shipped_env=%d entries=%d misses=%d relay_misses=%d pending=%d",
					st.round, st.shippedEnvelopes, st.shippedEntries, st.payloadMisses, st.relayMisses, st.payloadPending)
			}
			// Seed the convergence-lag gauge after the sweep. The lag
			// (time.Since(lastConvergedAt)) is read off the hot path by the
			// 1s poller; this is the single writer.
			g.stampConvergence()
			// Increment the gossip-round counter for the silicon telemetry path
			// (the first increment after datapath restore = the first
			// successful gossip round). Nil-guarded: the --selftest path and the
			// cold-scrape path run with no reporter, so the counter stays 0 as
			// the scrape path shipped.
			if g.roundReporter != nil {
				g.roundReporter()
			}
		}
	}
}

// stampConvergence records the convergence-lag seed: it computes the engine's
// MerkleRoot and, if it equals the prior sweep's root AND differs from the last
// converged root, stamps lastConvergedAt + lastConvergedRoot (the mesh just
// stabilized across two consecutive sweeps). It always advances prevRoot so
// the next sweep compares against this one. Called from SweepLoop (single
// writer) and exposed for the convergence-metric test.
//
// Switched from State.MerkleRoot to
// MerkleRootFromShards. State builds a FULL MERGED HAMT view duplicating
// every live entry into arena nodes that reclaim only on EBR epoch advance —
// at 100 nodes × 10K keys the merged views pile up faster than
// maybeAdvanceEpoch reclaims them → HamtArena OOM (hamt_arena.go:638).
// MerkleRootFromShards computes the BYTE-IDENTICAL root directly from the
// per-shard root HAMTs with NO merged view (zero arena growth) and an EBR
// participant pin (formally race-free, strictly stronger than State's grace
// window). See pkg/sync/merkle_sharded.go. The convergence-lag logic
// (prevRoot compare, lastConvergedRoot stamp) is UNCHANGED — only the root's
// source switched.
func (g *Gossiper) stampConvergence() {
	curRoot := g.engine.MerkleRootFromShards() // merkle_sharded.go (byte-identical to State.MerkleRoot, no merged-view OOM)
	if curRoot == g.prevRoot && curRoot != g.lastConvergedRoot {
		g.lastConvergedAt = time.Now()
		g.lastConvergedRoot = curRoot
	}
	g.prevRoot = curRoot
}

// Converges reports whether the engine's MerkleRoot is stable across a sweep
// (the in-process test harness uses a direct MerkleRoot compare instead; this
// helper is for the silicon telemetry path). Switched to
// MerkleRootFromShards (byte-identical to State.MerkleRoot, no merged-view
// OOM at 100×10K — see pkg/sync/merkle_sharded.go).
func (g *Gossiper) Converges() ([32]byte, error) {
	peers := g.peers.Peers()
	if len(peers) == 0 {
		return [32]byte{}, fmt.Errorf("mesh: Converges: %w", ErrNoPeers)
	}
	return g.engine.MerkleRootFromShards(), nil // merkle_sharded.go
}

// CurrentRoot returns the engine's current MerkleRoot (the local node's view).
// It is the roots-equal gauge feeder: the 1s poller compares it to
// LastConvergedRoot to set sovereign_convergence_roots_equal (1.0 match, 0.0
// diverged). Unlike Converges it does NOT require peers (a single-node mesh
// still has a local root the gauge reads). Switched to
// MerkleRootFromShards — the gauge was the 4th OOM site (it polled State
// every second, same merged-view pile-up as stampConvergence at 100×10K).
func (g *Gossiper) CurrentRoot() [32]byte {
	return g.engine.MerkleRootFromShards() // merkle_sharded.go (byte-identical, no OOM)
}

// LastConvergedAt returns the wall time of the sweep at which the engine's
// MerkleRoot last stabilized across two consecutive sweeps. It is the zero
// Time when the mesh has never converged. The 1s convergence-gauge poller
// reads this off the hot path to feed sovereign_convergence_lag_seconds.
func (g *Gossiper) LastConvergedAt() time.Time { return g.lastConvergedAt }

// LastConvergedRoot returns the stable MerkleRoot the mesh last converged on.
// It is the zero [32]byte when the mesh has never converged.
func (g *Gossiper) LastConvergedRoot() [32]byte { return g.lastConvergedRoot }

// ConvergenceLag returns time.Since(lastConvergedAt): ~0 when the mesh just
// converged, growing while it diverges. It is 0 when the mesh has never
// converged (the zero Time → a lag the poller reports as 0, NOT a false
// "converged" signal; the roots-equal gauge is the binary convergence
// indicator, this is the staleness gauge).
func (g *Gossiper) ConvergenceLag() time.Duration {
	if g.lastConvergedAt.IsZero() {
		return 0
	}
	return time.Since(g.lastConvergedAt)
}
