// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package mesh implements anti-entropy gossip over TLS.
//
// Gossip deltas use the same signed-envelope receive path as other CRDT writes:
//
//	GenerateDelta(remoteDigest).Entries(entityID, entry)
//	  -> eng.BuildCRDTDeltaEvent(entityID, payload, entry)
//	  -> identity.SignCRDTFrame(owner.Seed, innerWire)
//	  -> attribution.NewSignedRelayEnvelopeV3(innerWire, sig, dot, origin, nil)
//	  -> receive.LengthPrefixFrame(env.Marshal())
//	  -> PeerSet.Publish(peerID, prefixed)
//
// The receiver reads the frame, resolves the origin key, verifies the signature,
// and applies the delta. Test orchestrators may join engines directly, but the
// production gossip path never bypasses authentication.
//
// Signing every delta separately can dominate a sweep. Batch envelopes amortize
// that work over multiple deltas without omitting signature verification.
package mesh

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"log"
	"math/rand/v2"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"os"
	"strconv"
)

// payloadCache retains payloads for locally originated dots. The engine keeps
// only PayloadDigest after a join, while ApplyCRDTDeltaEvent requires the
// receiver to check SHA-256(payload) against that digest. Keying by entity and
// dot keeps each causal version distinct; sweepStampedDrops removes stale
// entries lazily. The cache has no explicit size bound or LRU eviction.
type payloadCache struct {
	mu sync.Mutex
	m  map[payloadKey]string
	// bytes is the sum of retained payload lengths. It is updated in O(1) time
	// on each record so /debug/memstats need not walk the map. It excludes map,
	// string-header, and allocator overhead.
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

// lookup returns the payload for an entity and dot. On a miss the gossiper
// skips that entry for this round: without the payload it cannot construct a
// frame whose digest the receiver would accept. The caller records the miss.
func (c *payloadCache) lookup(entityID string, dot eng.CausalDot) (string, bool) {
	c.mu.Lock()
	v, ok := c.m[payloadKey{entityID, dot}]
	c.mu.Unlock()
	return v, ok
}

// relayCache retains verified origin-signed frames received from other nodes.
// shipDelta and shipBatchedDelta republish those bytes so deltas can propagate
// beyond their first hop. payloadCache serves local writes; relayCache serves
// received writes, and a relayer never signs on the origin's behalf.
//
// The per-frame layer maps (originNodeID, dotCounter) to a complete relay
// envelope. An onward receiver still checks the envelope depth and origin
// signature, then applies its admission and clock rules to the new sender.
//
// A batch has one origin signature and one OriginSeq for all of its elements,
// so the batch layer retains the complete envelope once in batchForward.
// batchReverse maps each element's (originNodeID, dotCounter) to that sequence;
// a lookup therefore takes two map reads. Retention runs on accept goroutines
// and lookups on the sweep goroutine, with one mutex protecting both layers.
// Neither layer has an explicit capacity limit or LRU eviction.
type relayCache struct {
	mu sync.Mutex
	m  map[relayKey][]byte // per-frame layer: (origin, dotCounter) -> relay envelope

	// batchForward stores one complete envelope per (origin, originSeq).
	batchForward map[batchRelayKey][]byte
	// batchReverse resolves an element dot to its containing batch sequence.
	batchReverse map[relayKey]uint64
	// batchRefs counts the reverse-index dots that still reference each batch.
	// Moving a dot to a newer sequence decrements the old batch's count, and the
	// old frame is deleted when the count reaches zero. This prevents one
	// unreachable frame per superseded sequence while retaining partially
	// superseded batches whose remaining dots still need them.
	batchRefs map[batchRelayKey]int

	// batchTrueCount records len(dotCounters), which InspectBatchDots decoded
	// from the signed batch wire at retention. It charges relay work by the
	// received element count rather than the unsigned informational header.
	// This also covers hybrid envelopes, whose header cannot be decoded as a v1
	// batch. The count lives and dies with its forward entry; batchRefs is a
	// liveness count, not the batch size.
	batchTrueCount map[batchRelayKey]int

	// frameBytes and batchForwardBytes are running sums of retained frame
	// lengths, updated under mu so CacheStats can read them without walking the
	// maps. Their placement after the pointer fields preserves the struct's GC
	// pointer-data layout.
	frameBytes        int64
	batchForwardBytes int64
	// batchReverseBytes increases by batchReverseEntryFootprint only when a new
	// dot enters the reverse map. Repointing an existing dot changes its sequence
	// without growing the map, so it does not increase this estimate.
	batchReverseBytes int64
}

// batchRelayKey identifies one signed batch by origin and OriginSeq, the same
// identity used by the receiver's batch rate gate. It differs from relayKey,
// which identifies an individual element by origin and dot counter. The name
// also avoids colliding with the package's batchKey test helper.
type batchRelayKey struct {
	originNodeID [16]byte
	originSeq    uint64
}

// relayKey identifies a received delta by origin node and dot counter, matching
// the identity used by receiver admission. Unlike payloadKey, it does not include
// an entity ID: one batch reverse-index entry maps this wire identity to the
// batch's OriginSeq.
type relayKey struct {
	originNodeID [16]byte
	dotCounter   uint64
}

// redEagerMapsBugInject restores eager relay-map allocation for a negative
// control. Its zero value selects the production lazy-allocation path.
var redEagerMapsBugInject atomic.Bool

// meshDigestEBRReleaseBugInject selects deferred EBR release in tests so they
// can distinguish it from the production ReleaseLocal path.
var meshDigestEBRReleaseBugInject atomic.Bool

// releaseMeshDigest releases a digest after MarshalIBLT has copied it to a
// separate heap buffer. The digest is built, marshaled, and released on one
// goroutine and is never published, so ReleaseLocal can return its arena slabs
// directly. Deferred EBR release would retain them until later epoch advances,
// which this digest-build path does not itself trigger.
func releaseMeshDigest(d *eng.IBLT) {
	if meshDigestEBRReleaseBugInject.Load() {
		d.Release()
		return
	}
	d.ReleaseLocal()
}

func newRelayCache() *relayCache {
	// Each layer allocates its maps on first retention. WireRelayHooks installs
	// both retainers regardless of send mode, so receive activity—not the local
	// batch-size setting—determines which maps a node needs. Nil-map lookups are
	// valid and leave an unused layer allocation-free.
	if redEagerMapsBugInject.Load() {
		return &relayCache{
			m:              make(map[relayKey][]byte),
			batchForward:   make(map[batchRelayKey][]byte),
			batchReverse:   make(map[relayKey]uint64),
			batchRefs:      make(map[batchRelayKey]int),
			batchTrueCount: make(map[batchRelayKey]int),
		}
	}
	return &relayCache{}
}

// retain stores a verified foreign frame by origin and dot counter. It takes
// ownership of frameBytes without copying: FrameReader.ReadFrame allocates a
// fresh buffer for each frame, and the caller must not mutate or reuse that
// buffer after retention. A caller with shared storage must copy it first.
// RetainForeign filters out locally originated frames before calling retain.
func (c *relayCache) retain(originNodeID [16]byte, dotCounter uint64, frameBytes []byte) {
	c.mu.Lock()
	// Allocate the per-frame map on its first write; nil-map reads remain valid.
	if c.m == nil {
		c.m = make(map[relayKey][]byte)
	}
	rk := relayKey{originNodeID, dotCounter}
	if old, ok := c.m[rk]; ok {
		c.frameBytes -= int64(len(old)) // a re-retain of the same dot replaces, it does not add
	}
	c.m[rk] = frameBytes
	c.frameBytes += int64(len(frameBytes))
	c.mu.Unlock()
}

// lookup returns the retained frame for an origin and dot counter. On a miss,
// shipDelta skips the entry rather than constructing an unsigned relay frame;
// a later sweep can succeed after an origin or another relay republishes it.
func (c *relayCache) lookup(originNodeID [16]byte, dotCounter uint64) ([]byte, bool) {
	c.mu.Lock()
	v, ok := c.m[relayKey{originNodeID, dotCounter}]
	c.mu.Unlock()
	return v, ok
}

// retainBatch stores one complete batch envelope and indexes every decoded dot
// to its OriginSeq. lookupBatchCounted can then recover both the frame and its
// verified element count. The receiver calls this from its accept goroutine.
// frameBytes follows retain's ownership contract: it is retained without a copy
// and must not be mutated afterward.
func (c *relayCache) retainBatch(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte) {
	// An empty batch has no reverse-index references, so storing its frame would
	// make it permanently unreachable. Rejecting it also prevents a faulty or
	// malicious origin from pinning memory with empty batches.
	if len(dotCounters) == 0 {
		return
	}
	c.mu.Lock()
	// The four batch maps are initialized together because their entries are
	// created and deleted as one retention record.
	if c.batchForward == nil {
		c.batchForward = make(map[batchRelayKey][]byte)
		c.batchReverse = make(map[relayKey]uint64)
		c.batchRefs = make(map[batchRelayKey]int)
		c.batchTrueCount = make(map[batchRelayKey]int)
	}
	fwdKey := batchRelayKey{originNodeID, originSeq}
	if old, ok := c.batchForward[fwdKey]; ok {
		c.batchForwardBytes -= int64(len(old)) // replacement does not add another frame
	}
	c.batchForward[fwdKey] = frameBytes
	c.batchForwardBytes += int64(len(frameBytes))
	c.batchTrueCount[fwdKey] = len(dotCounters)

	// Repointing a dot decrements the previous batch's reference count. A batch
	// is deleted only after its last dot moves elsewhere, so partially superseded
	// batches remain available for their other elements.
	for _, dc := range dotCounters {
		rk := relayKey{originNodeID, dc}
		prevSeq, had := c.batchReverse[rk]
		if had && prevSeq != originSeq {
			prevKey := batchRelayKey{originNodeID, prevSeq}
			c.batchRefs[prevKey]--
			if c.batchRefs[prevKey] <= 0 {
				c.batchForwardBytes -= int64(len(c.batchForward[prevKey]))
				delete(c.batchForward, prevKey)
				delete(c.batchRefs, prevKey)
				delete(c.batchTrueCount, prevKey)
			}
		} else if had && prevSeq == originSeq {
			// Retaining the same dot and sequence again must not add a reference.
			continue
		}
		c.batchReverse[rk] = originSeq
		if !had {
			// Repointing an existing dot does not grow the reverse map.
			c.batchReverseBytes += batchReverseEntryFootprint
		}
		c.batchRefs[fwdKey]++
	}
	c.mu.Unlock()
}

// batchLenForTest returns the forward and reverse map sizes under the cache
// lock. Production code does not use this accessor.
func (c *relayCache) batchLenForTest() (forward, reverse int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.batchForward), len(c.batchReverse)
}

// batchReverseEntryFootprint estimates a reverse-map entry as an 8-byte map
// tophash, a 24-byte relayKey, and an 8-byte OriginSeq. It deliberately excludes
// load-factor slack and allocator overhead, so it is an attribution estimate
// rather than an exact heap measurement.
const batchReverseEntryFootprint = 40

// CacheStats reports entry counts and running byte totals for the mesh caches.
// The byte fields measure retained content, or the documented reverse-entry
// estimate, rather than total process RSS.
type CacheStats struct {
	PayloadEntries         int
	PayloadBytes           int64
	RelayFrames            int
	RelayFrameBytes        int64
	RelayBatchForward      int
	RelayBatchForwardBytes int64
	RelayBatchReverse      int
	RelayBatchReverseBytes int64
}

// CacheStats returns a consistent snapshot under each cache's lock. It is safe
// to call concurrently with sweeps and retention. A nil Gossiper or cache
// yields zero values so the diagnostics handler can call it unconditionally.
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
		cs.RelayBatchReverseBytes = g.relay.batchReverseBytes
		g.relay.mu.Unlock()
	}
	return cs
}

// lookupBatchCounted resolves an element to its retained batch and returns the
// wire-decoded element count alongside the frame. Budget accounting and the
// subsequent publish share this result, so a retention update cannot make the
// charged count and published envelope disagree. Empty batches are rejected at
// retention, making a positive count the normal invariant.
func (c *relayCache) lookupBatchCounted(originNodeID [16]byte, dotCounter uint64) (frame []byte, originSeq uint64, count int, ok bool) {
	c.mu.Lock()
	originSeq, ok = c.batchReverse[relayKey{originNodeID, dotCounter}]
	if !ok {
		c.mu.Unlock()
		return nil, 0, 0, false
	}
	fk := batchRelayKey{originNodeID, originSeq}
	frame, ok = c.batchForward[fk]
	if ok {
		count = c.batchTrueCount[fk]
		if count <= 0 {
			count = 1 // defensive (unreachable: written with len(dotCounters) >= 1 in the same critical section as the frame store, deleted only with it)
		}
	}
	c.mu.Unlock()
	return frame, originSeq, count, ok
}

// Gossiper drives anti-entropy sweeps. It owns the peer set, origin payload
// cache, relay cache, and node signing identity. InsertLocalEvents applies a
// local write and records the payload needed to gossip it later.
type Gossiper struct {
	// commitInFlight counts insert calls between their state mutation and the
	// end of payload recording. A self-payload miss is classified as pending
	// while this is positive and as orphaned when it is zero; neither case ships
	// the entry before its payload is recorded.
	//
	// The counter is node-global, so any active insert can mask an unrelated
	// orphan during continuous ingest. Orphan detection is therefore conclusive
	// only after ingest becomes idle. Per-dot commit markers would be needed to
	// distinguish overlapping commits precisely.
	//
	// The leading field and trailing pad give this atomic a 128-byte
	// struct-relative stride, separating it from batchSeq and other frequently
	// written fields. This does not assume a particular heap-base alignment.
	commitInFlight atomic.Int64
	_              [120]byte

	peers *PeerSet
	// indexFeeder updates the secondary index after an in-memory insert. The
	// durable Bridge feeds the index itself, so this hook stays nil on that path
	// to avoid feeding a write twice. SetIndexFeeder installs it before use.
	indexFeeder func(entityID string, h3Index uint64, systemTime int64)
	cache       *payloadCache
	relay       *relayCache // verified foreign frames retained for onward relay
	owner       *NodeIdentity
	engine      *eng.DeltaCRDTEngine
	domains     *identity.Directory

	// roundReporter increments sovereign_gossip_rounds_total when installed by
	// cmd. The nil default leaves the metric untouched in library and test use.
	roundReporter func()

	// batchSize selects shipBatchedDelta above 1 and shipDelta at 1. SetBatchSize
	// clamps it to [1, MaxBatchSize]. Batching amortizes one Ed25519 signature
	// over multiple locally originated deltas.
	batchSize int
	// sweepRound increments once at AntiEntropySweep entry on the sweep
	// goroutine. It seeds topology selection and supplies the logged round; its
	// single-writer discipline does not require an atomic.
	sweepRound uint64
	// sweepEnvCache reuses signed envelopes within one non-stratified sweep,
	// avoiding an identical build and signature for every selected peer.
	// sweepEnvIdx keys entries by batch position and sweepEnvRound rejects stale
	// rounds; the next sweep discards the map and mints fresh sequences.
	//
	// Position implies identical content only when all peers share one hoisted
	// delta. Stratified sweeps compute peer-specific deltas, so they never read
	// or write this memo. The recorded length is only a defensive mismatch check,
	// not a content identity. Only the sweep goroutine accesses these fields.
	sweepEnvCache map[int]sweepMemoEntry
	sweepEnvRound uint64
	sweepEnvIdx   int

	// batchSeq is the origin's monotonic sequence in each BatchEnvelope.
	// PeerBucket.Accept charges the gap between successive sequences, limiting
	// burst admission by origin. Only the sweep goroutine advances it.
	batchSeq uint64

	// bridge is nil for in-memory operation. When configured through SetBridge,
	// it appends and fsyncs the engine-stamped dot after InsertLocal; durability
	// is therefore opt-in through --wal-path.
	bridge *durability.Bridge

	// The convergence gauge uses the last root that stayed unchanged across two
	// sweeps. lastConvergedAt records when that stability was observed, and
	// prevRoot is the comparison input for the next sweep. SweepLoop is the sole
	// writer; metric readers use the accessors below.
	lastConvergedAt   time.Time
	lastConvergedRoot [32]byte
	prevRoot          [32]byte

	// stratified is false by default, selecting full-delta oversend. When armed
	// before SweepLoop starts, each peer exchange sends a local digest, waits for
	// the peer's digest, and calls GenerateDelta with that populated remote IBLT.
	// Timeouts, malformed digests, and peel failures use the configured fallback
	// path. The flag is read on the sweep goroutine after boot-time wiring.
	stratified bool

	// digestRecvMu protects per-peer wait records shared by the sweep consumer
	// and DeliverDigest producers on connection goroutines. Each channel holds
	// one response; a non-blocking send discards a late response, and the next
	// round exchanges fresh digests. Signed deltas remain authoritative.
	digestRecvMu sync.Mutex
	digestRecv   map[[16]byte]*digestRecvWait
	// digestLatencyDebug is read once from SOVEREIGN_DIGEST_LATENCY_DEBUG and
	// controls per-exchange logs and heartbeat-route wiring. Exchange counters
	// remain active without it. The cumulative and last-round values are atomic
	// for HTTP readers; the prev bases are confined to the sweep goroutine.
	// digestStampBroken counts deposits without a usable build timestamp.
	digestLatencyDebug     bool
	digestExchCompleted    atomic.Int64
	digestExchDrained      atomic.Int64
	digestStampBroken      atomic.Int64
	lastExchDone           atomic.Int64
	lastExchDrained        atomic.Int64
	lastRespDelta          atomic.Int64
	lastSweepRound         atomic.Int64
	prevExchCompleted      int64 // sweep goroutine only
	prevExchDrained        int64 // sweep goroutine only
	prevRespBytes          int64 // sweep goroutine only
	digestResponderDelayMs atomic.Int64

	// SOVEREIGN_EXCH_DEBUG controls the more detailed exchange instrumentation.
	// Rings and aggregates allocate only when l0iArm runs. Phase and previous-
	// busy fields belong to the sweep goroutine; last-byte atomics publish the
	// same round window to the heartbeat handler.
	l0iExchDebug       bool
	l0iSendRing        *l0iRing
	l0iArrivalRing     *l0iRing
	l0iSendAgg         l0iAgg
	l0iArriveAgg       l0iAgg
	l0iPhaseReqNs      int64 // sweep goroutine only (armed)
	l0iPhaseWaitNs     int64 // sweep goroutine only (armed)
	l0iPhaseShipNs     int64 // sweep goroutine only (armed)
	prevReadBusyNs     int64 // sweep goroutine only (armed)
	prevServeBusyNs    int64 // sweep goroutine only (armed)
	lastShipBytes      atomic.Int64
	lastDigestReqBytes atomic.Int64

	// stratifiedFallbackReporter increments the configured fallback metric when
	// a digest exchange falls back to oversend. It is optional; convergence does
	// not depend on telemetry being installed.
	stratifiedFallbackReporter func()

	// digestWaitTimeout bounds the synchronous digest wait before the fallback
	// path runs. NewGossiper defaults it to 500 ms. generateSweepDelta also
	// substitutes 500 ms for a non-positive value.
	digestWaitTimeout time.Duration

	// digestWaitAdaptive is opt-in through --digest-wait-adaptive. It clamps
	// twice the peer's response-latency EWMA plus a margin between the configured
	// floor and cap, and expires stale observations. Command wiring requires
	// stratified anti-entropy and the defer handler; the field is set before the
	// first sweep and read only on that goroutine.
	digestWaitAdaptive bool

	// stratDiag records digest attempts, fallbacks, and elapsed time by peer
	// region for the sweep log. It distinguishes frequent cross-region fallbacks
	// from a successful digest exchange. It is allocated only when stratified
	// mode is enabled and uses a mutex for connection-side producers.
	stratDiag *stratDiagnostics

	// respondSem bounds concurrent digest construction. enqueueDigestResponse
	// takes a slot without blocking the connection loop; if all slots are busy,
	// it drops the response and the requester uses its fallback path. The
	// semaphore is allocated when stratified mode is enabled.
	respondSem chan struct{}

	// respondEnabled is the atomic on/off gate read by connection goroutines.
	// It must be checked instead of respondSem: the semaphore remains allocated
	// after stratified mode is disabled, while this flag stops further answers.
	// Enabling stores true only after the semaphore has been allocated.
	respondEnabled atomic.Bool

	// digestRespondSent counts responses sent by responder goroutines.
	digestRespondSent atomic.Int64

	// respondIndeg optionally records responder occupancy at request arrival
	// when SOVEREIGN_RESPOND_INDEG_DEBUG is enabled. Buckets 0-15 count active
	// builds and bucket 16 records a drop. A nil tracker disables this diagnostic.
	respondIndeg *respondIndegTracker

	// sweepShipBytes counts successful length-prefixed writes made by the sweep:
	// local and relayed envelopes plus root announcements. digestReqBytes counts
	// digest requests. Both are confined to the sweep goroutine; their per-round
	// deltas are copied into sweepState at the end of a sweep.
	sweepShipBytes int64
	digestReqBytes int64
	// digestRespondBytes is atomic because responder goroutines update it. The
	// sweep log publishes both its cumulative value and its per-line delta.
	digestRespondBytes atomic.Int64
	// bytesBlind disables byte accounting in negative-control tests. Production
	// leaves it false.
	bytesBlind atomic.Bool
	// missLogCapOverride is read once from SOVEREIGN_MISS_LOG_CAP. Unset or
	// invalid values leave it zero, selecting the missLogCap default.
	missLogCapOverride int

	// disableDigestRespond suppresses responses in tests, forcing the requester
	// to exercise its timeout fallback. Production leaves it false.
	disableDigestRespond                atomic.Bool
	disableV2HeaderOnlyRequestBugInject atomic.Bool

	// peerRoots holds each peer's latest announced Merkle root while stratified
	// mode is active. A missing or different root triggers a digest exchange; an
	// equal root suppresses it. Comparing roots rather than local root movement
	// lets a node with an older stable root still receive reconciliation traffic.
	// recordPeerRoot and peerRootFor synchronize through peerRootsMu, and each
	// sweep removes entries for peers that are no longer live.
	peerRoots   map[[16]byte][32]byte
	peerRootsMu sync.Mutex

	// prevGateRoot is used only by gateLocalChangeBugInject to model the broken
	// local-change gate. The production mismatch gate does not consult it.
	prevGateRoot [32]byte

	// digestGateSkips counts exchanges suppressed because the roots matched.
	digestGateSkips atomic.Int64

	// digestPeelOversends counts completed exchanges whose subtraction or peel
	// failed and therefore returned the full-keyset fallback delta.
	digestPeelOversends atomic.Int64

	// digestRespondDropped counts requests dropped because every response-build
	// slot was occupied. The requester then follows its fallback path.
	digestRespondDropped atomic.Int64

	// ibltV2 mirrors the opt-in --iblt-v2 setting. Connection and responder
	// goroutines read it, so it is atomic; false selects the v1 digest path.
	ibltV2           atomic.Bool
	ibltV2MinBuckets atomic.Int32
	// digestLadder holds per-peer adaptive bucket sizing on the sweep goroutine.
	// It is allocated by SetIBLTV2 and remains nil when v2 is disabled.
	digestLadder map[[16]byte]digestLadderState
	// These counters record bucket increases after peel failures and decreases
	// after the required clean-peel streak.
	digestLadderEscalations atomic.Int64
	digestLadderDecays      atomic.Int64
	// ibltV2OrphanWarn limits the warning about v2 without stratified mode to
	// one log entry.
	ibltV2OrphanWarn atomic.Bool

	// deferHandler is opt-in. When enabled, digest failures defer full-keyset
	// oversend; repeated failures can arm a bounded rotating slice instead.
	// Command wiring sets it before connection and sweep goroutines start, which
	// orders later reads without additional synchronization. Its state is nil
	// when disabled.
	deferHandler                        bool
	gatewayMode                         bool
	disableEmptyRootSkipBugInject       atomic.Bool
	disableRespondRootAnnounceBugInject atomic.Bool
	// deferState is confined to the sweep goroutine. evictStaleDefers removes
	// departed peers without resetting rotation state for live peers.
	deferState map[[16]byte]peerDeferState
	// digestDefers counts deferred failure rounds; digestDeferEscalations counts
	// rounds that armed a bounded slice. Both appear in the sweep log.
	digestDefers           atomic.Int64
	digestDeferEscalations atomic.Int64
	// deferCrossover permits a guarded full-keyset ship after an
	// ErrIncompletePeel within the configured size and cooldown bounds. It is
	// disabled by default and command wiring requires deferHandler.
	deferCrossover                      atomic.Bool
	singleStrikeGatewayTimeoutBugInject atomic.Bool
	// digestCrossoverShips counts full-keyset ships selected by that crossover.
	digestCrossoverShips atomic.Int64
	// nilDigestBugInject delivers a well-formed frame with a nil IBLT in tests.
	// deferOrphanWarn limits the warning about enabling the defer handler without
	// stratified mode, where none of its branches are reachable, to one entry.
	deferOrphanWarn    atomic.Bool
	nilDigestBugInject atomic.Bool
	// viewOrphanWarn similarly warns once when partial intra-view selection is
	// enabled without a topology and region-aware routing.
	viewOrphanWarn atomic.Bool

	// digestLegacySE includes a StrataEstimator in test frames to exercise
	// compatibility with older SE+IBLT peers. Production sends IBLT-only frames.
	digestLegacySE atomic.Bool

	// disableChangeGate forces an exchange on every sweep in a negative control.
	disableChangeGate atomic.Bool

	// gateLocalChangeBugInject replaces root mismatch with local root movement.
	// This intentionally broken gate can leave a stable, behind node unreconciled.
	gateLocalChangeBugInject atomic.Bool

	// These controls disable individual checks in negative-control tests. Their
	// zero values preserve production behavior: sweep egress verification,
	// digest sender and connection verification, and challenge signature
	// verification respectively.
	disableEgressGateBugInject        atomic.Bool
	disableDigestChannelGateBugInject atomic.Bool
	disableChallengeVerifyBugInject   atomic.Bool
	// disableShipOrderBugInject omits the DotCounter sort for locally originated
	// frames, allowing tests to exercise receiver skew handling on hash order.
	disableShipOrderBugInject atomic.Bool
	// disableNilPeersGuardBugInject removes the nil-PeerSet guard in
	// DeliverDigest so tests can verify that the guard prevents a panic.
	disableNilPeersGuardBugInject atomic.Bool
	// shipBuildProbe captures generated batch contents for small correctness
	// tests. shipBuildMetrics records peer, entry count, and walk/sort duration
	// without retaining buffers, so large benchmarks do not pin the batches they
	// measure. The sweep goroutine writes them and tests read after it returns;
	// both pointers are nil in production.
	// redPerPeerSortBugInject bypasses shared-batch reuse to compare it with the
	// per-peer path. redHoistAllBugInject deliberately ignores the stratified
	// safety guard so tests can detect reuse of peer-specific deltas.
	redPerPeerSortBugInject                 atomic.Bool
	redHoistAllBugInject                    atomic.Bool
	disableDigestRecvRoleGateBugInject      atomic.Bool // test control: admit a request through the response-channel gate
	disableRootAnnounceArrivalGateBugInject atomic.Bool // test control: include root announcements in arrival timing
	shipBuildProbe                          atomic.Pointer[[]shipBuildCapture]
	shipBuildMetrics                        atomic.Pointer[[]shipBuildMetric]

	// hybridSign is opt-in. False keeps local batches on the v1 Ed25519
	// envelope; true adds an ML-DSA-65 signature over the same 120-byte SHAKE256
	// pad and sends a HybridEnvelope. Forwarded batches retain their origin's
	// envelope because a relayer cannot sign for that origin. SetHybridSign runs
	// before the sweep starts.
	hybridSign bool

	// topology stores peer region tags and selects sweep targets when both it
	// and regionAware are set. Selection covers the intra-region mesh plus a
	// seeded cross-region fan-out. A nil topology keeps the full PeerSet path;
	// SetTopology runs before the sweep starts.
	topology *TopologyManager

	// interRegionReporter is called once for each selected cross-region peer
	// before that peer's ship body. It reports routing selection rather than
	// completed envelope writes, and a nil callback disables the metric.
	interRegionReporter func()

	// regionAware selects topology.Select only when a topology is also bound;
	// otherwise AntiEntropySweep iterates the full PeerSet. The switch is set
	// before SweepLoop starts.
	//
	// partialIntraView mirrors the topology's sampling switch for configuration
	// checks and diagnostics. SetPartialIntraView and SetTopology keep the two
	// synchronized, including when the topology is bound after the switch.
	//
	// sweepPhaseDerives records whether an armed SweepLoop computed its phase
	// offset. It remains zero when phase jitter is disabled.
	sweepPhaseDerives atomic.Uint64
	// These counters distinguish sweep iterations rejected before egress,
	// digest frames on unverified connections, frames whose sender does not
	// match the connection, and asynchronous responses rejected by the final
	// egress recheck. All are diagnostic atomics.
	egressUnverifiedDrops atomic.Uint64
	digestUnverifiedDrops atomic.Uint64
	// deliverDigestNilGuardDrops is separate from verification failures: it
	// counts frames received by a Gossiper with no PeerSet. nilGuardLogSeq
	// permits the first eight logs and every thousandth thereafter.
	deliverDigestNilGuardDrops atomic.Uint64
	nilGuardLogSeq             atomic.Uint64
	digestIdentityDrops        atomic.Uint64
	digestRespondEgressDrops   atomic.Uint64
	partialIntraView           bool
	regionAware                bool
	// sweepPhaseJitter is opt-in. When set before SweepLoop starts, each loop
	// entry derives a deterministic node phase and waits tick+phase before its
	// first sweep. False retains a plain ticker with no warm-up offset.
	sweepPhaseJitter bool
}

// NewGossiper binds a PeerSet, node identity, CRDT engine, and identity
// directory. The directory is shared with the receiver: RegisterPeer adds an
// origin's public key, and frame verification resolves the same key on receipt.
func NewGossiper(peers *PeerSet, owner *NodeIdentity, engine *eng.DeltaCRDTEngine, dir *identity.Directory) *Gossiper {
	g := &Gossiper{
		peers:             peers,
		cache:             newPayloadCache(),
		relay:             newRelayCache(),
		owner:             owner,
		engine:            engine,
		domains:           dir,
		digestRecv:        make(map[[16]byte]*digestRecvWait),
		digestWaitTimeout: 500 * time.Millisecond,
	}
	// Read the optional miss-log cap once. Values outside 1..10000 retain the
	// default rather than disabling the bound or overflowing log volume.
	if v, err := strconv.Atoi(os.Getenv("SOVEREIGN_MISS_LOG_CAP")); err == nil && v > 0 && v <= 10000 {
		g.missLogCapOverride = v
	}
	// This setting controls latency log volume, not collection of the exchange
	// counters exposed in sweep logs and the heartbeat route.
	g.digestLatencyDebug = os.Getenv("SOVEREIGN_DIGEST_LATENCY_DEBUG") == "1"
	// Detailed timing rings allocate only when explicitly enabled.
	g.l0iExchDebug = os.Getenv("SOVEREIGN_EXCH_DEBUG") == "1"
	if g.l0iExchDebug {
		g.l0iArm(peers)
	}
	// Digest frames have their own sink because they are not CRDT delta events.
	// DeliverDigest drops a response when no sweep is waiting for it. Insert-only
	// users may construct a Gossiper without a PeerSet, in which case there is no
	// connection sink or challenge directory to configure.
	if peers != nil {
		peers.SetDigestSink(g)
		// The challenge verifier uses the same directory as frame verification.
		// A nil directory leaves verification closed rather than admitting an
		// unauthenticated connection.
		peers.SetChallengeDirectory(dir)
	}
	return g
}

// SetRoundReporter installs the callback that increments
// sovereign_gossip_rounds_total after each executed sweep. A nil callback leaves
// the metric untouched.
func (g *Gossiper) SetRoundReporter(fn func()) { g.roundReporter = fn }

// RetainForeign retains a verified per-frame envelope for onward relay. Local
// origins are excluded because payloadCache already holds their source payloads;
// retaining them here would duplicate storage. The frame buffer is taken without
// a copy and must not be reused by the caller. WireRelayHooks installs this
// callback, and relayCache synchronizes accept-side calls with sweep lookups.
func (g *Gossiper) RetainForeign(originNodeID [16]byte, dotCounter uint64, frameBytes []byte) {
	if g.relay == nil {
		return
	}
	// Locally originated frames are served from payloadCache instead.
	if originNodeID == g.owner.NodeID {
		return
	}
	g.relay.retain(originNodeID, dotCounter, frameBytes)
}

// RetainForeignBatch retains a verified batch envelope and its decoded element
// dots for onward relay. Local batches are excluded because their payloads are
// already available through payloadCache. The frame buffer is taken without a
// copy, and relayCache synchronizes retention with sweep lookups.
//
// WireRelayHooks installs both this callback and RetainForeign. Keeping the two
// installations together prevents a node from accepting batches without making
// them available to its relay path.
func (g *Gossiper) RetainForeignBatch(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, batchFrameBytes []byte) {
	if g.relay == nil {
		return
	}
	// Locally originated batches are served from payloadCache instead.
	if originNodeID == g.owner.NodeID {
		return
	}
	g.relay.retainBatch(originNodeID, originSeq, dotCounters, batchFrameBytes)
}

// sweepMemoEntry records a signed, length-prefixed envelope and its batch
// length. The length is a defensive mismatch check, not a content identity.
type sweepMemoEntry struct {
	env []byte
	n   int
}

// sweepEnvelope reuses an envelope at the current batch position within one
// non-stratified sweep. A new batch position advances only after a miss or new
// build. Stratified sweeps always miss because their deltas are peer-specific.
//
// The position-and-length key has a known limitation: recording a payload
// between two peers can produce different batches of the same length at that
// position, causing the second peer to receive the first envelope. Full-oversend
// sweeps bound the effect to one round of delay because the signed batch is still
// valid and joins are idempotent. A partial-delta implementation must replace
// this with a content key before relying on the memo.
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

// cacheSweepEnvelope stores a new envelope for the remaining peers in this
// non-stratified sweep. Stratified content is always built and signed per peer.
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

// relayHookSink is the subset of receive.Receiver used by WireRelayHooks. The
// structural interface keeps installation testable without adding dependencies.
type relayHookSink interface {
	SetRelayRetainer(fn func(originNodeID [16]byte, dotCounter uint64, frameBytes []byte))
	SetRelayRetainerBatch(fn func(originNodeID [16]byte, originSeq uint64, dotCounters []uint64, frameBytes []byte))
}

// WireRelayHooks installs per-frame and batch retention together. Production
// wiring and relay tests share this helper so one layer cannot be wired while
// the other is accidentally omitted. Call it before the accept loop starts; a
// nil receiver is a no-op.
func (g *Gossiper) WireRelayHooks(r relayHookSink) {
	if r == nil {
		return
	}
	r.SetRelayRetainer(g.RetainForeign)
	r.SetRelayRetainerBatch(g.RetainForeignBatch)
}

// SetIndexFeeder installs the optional secondary-index callback used by
// in-memory inserts. The callback takes primitive values so mesh does not depend
// on the index implementation. Durable writes are fed by Bridge instead; nil
// disables the in-memory feed.
func (g *Gossiper) SetIndexFeeder(fn func(entityID string, h3Index uint64, systemTime int64)) {
	g.indexFeeder = fn
}

// feedIndex synchronously updates derived index state after an in-memory write.
func (g *Gossiper) feedIndex(entityID string, entry eng.CRDTEntry) {
	if g.indexFeeder != nil {
		g.indexFeeder(entityID, entry.H3Index, entry.SystemTime)
	}
}

// SetBridge binds the optional write-through durability bridge. The bridge must
// wrap the same engine passed to NewGossiper so its writes and the sweep observe
// one HAMT. A nil bridge keeps insertion in memory without a WAL.
func (g *Gossiper) SetBridge(b *durability.Bridge) { g.bridge = b }

// BridgeActive reports whether durable insertion is configured. handleInsert
// uses this to interpret a zero dot as a failed durable write; the in-memory
// path returns an ordinary non-zero dot instead.
func (g *Gossiper) BridgeActive() bool { return g.bridge != nil }

// SetBatchSize selects per-frame publishing at 1 and batched publishing above
// 1, clamping the value to [1, MaxBatchSize]. The command's default is 100.
func (g *Gossiper) SetBatchSize(n int) {
	if n < 1 {
		n = 1
	}
	if n > MaxBatchSize {
		n = MaxBatchSize
	}
	g.batchSize = n
}

// BatchSize returns the configured batch size.
func (g *Gossiper) BatchSize() int { return g.batchSize }

// SetStratifiedAntiEntropy selects digest-based reconciliation when on and
// full-delta oversend when off. Production wiring calls it before SweepLoop
// starts. Enabling allocates per-region diagnostics, peer-root state, and the
// bounded responder semaphore once; disabling stops responses through the
// atomic gate without discarding those allocations.
func (g *Gossiper) SetStratifiedAntiEntropy(on bool) {
	g.stratified = on
	if on && g.stratDiag == nil {
		g.stratDiag = newStratDiagnostics()
	}
	if on && g.peerRoots == nil {
		g.peerRoots = make(map[[16]byte][32]byte)
	}
	if on && g.respondSem == nil {
		g.respondSem = make(chan struct{}, digestRespondMaxConcurrent)
	}
	// A responder that observes true also observes the allocated semaphore.
	g.respondEnabled.Store(on)
}

// Stratified reports whether the stratified anti-entropy digest-exchange is
// enabled (test/diagnostic accessor; the sweep reads it on every
// AntiEntropySweep to pick the digest-exchange vs oversend path).
func (g *Gossiper) Stratified() bool { return g.stratified }

// SetHybridSign selects HybridEnvelope for locally originated batches. The
// owner must come from NewNodeIdentityHybrid so it has an ML-DSA-65 private key;
// this setter does not derive one. ShipBatchHybrid reports a missing key and
// skips the batch rather than panicking. False retains the v1 Ed25519 envelope.
func (g *Gossiper) SetHybridSign(on bool) { g.hybridSign = on }

// HybridSign reports whether hybrid signing is enabled.
func (g *Gossiper) HybridSign() bool { return g.hybridSign }

// SetStratifiedFallbackReporter installs the callback for
// sovereign_mesh_stratified_fallback_total. It is called for oversend after a
// digest timeout, malformed response, publish failure, or peel failure. Nil
// disables the metric without changing reconciliation.
func (g *Gossiper) SetStratifiedFallbackReporter(fn func()) { g.stratifiedFallbackReporter = fn }

// SetTopology binds region metadata and gateway health checks. Region-aware
// selection still requires SetRegionAware(true). The partial intra-view setting
// is forwarded on every non-nil bind so rebinding cannot revive stale state.
func (g *Gossiper) SetTopology(t *TopologyManager) {
	g.topology = t
	if t != nil {
		t.SetPartialIntraView(g.partialIntraView)
		if g.owner != nil && g.owner.NodeID != ([16]byte{}) {
			t.SetSelfNodeID(g.owner.NodeID)
		}
		t.SetPeerLiveness(g.isGatewayPeerHealthy)
	}
}

// SetGatewayMode enables gateway-specific sweep behavior, including skipping
// digest exchange after announcing an empty local root. It is disabled by
// default.
func (g *Gossiper) SetGatewayMode(on bool) { g.gatewayMode = on }

// GatewayMode reports whether gateway behavior is enabled.
func (g *Gossiper) GatewayMode() bool { return g.gatewayMode }

// SetRegionAware selects topology-based peer routing when on. A topology must
// also be bound; otherwise the sweep continues to use the full PeerSet. Set it
// before SweepLoop starts.
func (g *Gossiper) SetRegionAware(on bool) { g.regionAware = on }

// RegionAware reports whether topology-based routing is enabled.
func (g *Gossiper) RegionAware() bool { return g.regionAware }

// SetPartialIntraView updates both the Gossiper mirror and any bound topology.
// SetTopology forwards the setting to later binds. Enabling it without region-
// aware routing leaves the full intra-region mesh in use and logs one warning.
func (g *Gossiper) SetPartialIntraView(on bool) {
	g.partialIntraView = on
	if g.topology != nil {
		g.topology.SetPartialIntraView(on)
	}
}

// PartialIntraView reports the local partial-view setting.
func (g *Gossiper) PartialIntraView() bool { return g.partialIntraView }

// SetSweepPhaseJitter enables a deterministic per-node offset derived on each
// SweepLoop entry from the active tick. Configure it before starting the loop.
func (g *Gossiper) SetSweepPhaseJitter(on bool) { g.sweepPhaseJitter = on }

// SweepPhaseJitter reports whether phase jitter is enabled.
func (g *Gossiper) SweepPhaseJitter() bool { return g.sweepPhaseJitter }

// SetInterRegionReporter installs the callback for cross-region peer selection
// in the region-aware sweep. Nil disables the metric; intra-region selections
// do not invoke it.
func (g *Gossiper) SetInterRegionReporter(fn func()) { g.interRegionReporter = fn }

// SetDigestWaitTimeout overrides the 500 ms digest-response wait. Tests can use
// a shorter bound to exercise the fallback quickly. generateSweepDelta replaces
// a non-positive value with 500 ms rather than disabling the wait.
func (g *Gossiper) SetDigestWaitTimeout(d time.Duration) { g.digestWaitTimeout = d }

const (
	// Doubling the EWMA makes one slow sample sufficient to cover the next
	// exchange after the half-weight blend, before adding the margin.
	digestWaitAdaptiveK = 2
	// The margin is twice a roughly 110 ms cross-region RTT plus twice a 3 ms
	// responder-build tail, rounded up. It matters mainly when the EWMA is small.
	digestWaitAdaptiveMargin = 230 * time.Millisecond
	// The cap follows a roughly 15 s loaded sweep span. Longer response tails
	// remain unmeasured; the configured floor takes precedence over this cap.
	digestWaitAdaptiveCap = 15 * time.Second
	// Observations older than approximately one meeting cadence are discarded
	// instead of extending a wait indefinitely.
	digestWaitAdaptiveDecay = 60 * time.Second
)

// SetDigestWaitAdaptive enables per-peer EWMA-based waits. Command wiring also
// requires stratified anti-entropy and the defer handler. Set it before the
// first sweep; subsequent reads are confined to that goroutine.
func (g *Gossiper) SetDigestWaitAdaptive(on bool) { g.digestWaitAdaptive = on }

// digestWaitObserve blends a positive response sample with weight 1/2. The
// first sample, or one after the decay interval, replaces the old EWMA. With a
// single slow sample s, the resulting wait is at least s plus the margin. Both
// call sites run on the sweep goroutine, so the state needs no lock.
func (g *Gossiper) digestWaitObserve(w *digestRecvWait, sample time.Duration) {
	if sample <= 0 {
		return
	}
	now := time.Now()
	if w.ewma <= 0 || now.Sub(w.lastObservedAt) >= digestWaitAdaptiveDecay {
		w.ewma = sample
	} else {
		w.ewma = (w.ewma + sample) / 2
	}
	w.lastObservedAt = now
}

// digestWaitFor returns the configured timeout when no fresh observation is
// available. Otherwise it returns twice the EWMA plus the margin, bounded below
// by the configured timeout and above by the adaptive cap. A configured timeout
// larger than the cap remains the effective floor.
func (g *Gossiper) digestWaitFor(w *digestRecvWait) time.Duration {
	if w.ewma <= 0 || time.Since(w.lastObservedAt) >= digestWaitAdaptiveDecay {
		return g.digestWaitTimeout
	}
	wait := digestWaitAdaptiveK*w.ewma + digestWaitAdaptiveMargin
	if wait <= g.digestWaitTimeout {
		return g.digestWaitTimeout
	}
	waitCap := digestWaitAdaptiveCap
	if waitCap < g.digestWaitTimeout {
		waitCap = g.digestWaitTimeout
	}
	if wait >= waitCap {
		return waitCap
	}
	return wait
}

// digestRecvWait holds a peer's one-slot response channel and adaptive timing
// state. reqSentAt starts the direct completed-exchange measurement. The EWMA
// also accepts build-to-drain samples, which include time spent queued in the
// channel and are therefore conservative latency inputs. All fields except ch
// are confined to the sweep goroutine.
type digestRecvWait struct {
	ch             chan *peerDigest
	reqSentAt      time.Time
	ewma           time.Duration
	lastObservedAt time.Time
}

// DigestLatencySnapshot is the heartbeat route's point-in-time view of the
// latest per-round values and cumulative exchange counters.
type DigestLatencySnapshot struct {
	LastRound          int64
	LastExchDone       int64
	LastExchDrained    int64
	LastRespDeltaBytes int64
	ExchCompletedTotal int64
	ExchDrainedTotal   int64
	RespBytesTotal     int64
	StampBrokenTotal   int64
}

// DigestLatencyStats reads all snapshot fields atomically for HTTP callers.
func (g *Gossiper) DigestLatencyStats() DigestLatencySnapshot {
	return DigestLatencySnapshot{
		LastRound:          g.lastSweepRound.Load(),
		LastExchDone:       g.lastExchDone.Load(),
		LastExchDrained:    g.lastExchDrained.Load(),
		LastRespDeltaBytes: g.lastRespDelta.Load(),
		ExchCompletedTotal: g.digestExchCompleted.Load(),
		ExchDrainedTotal:   g.digestExchDrained.Load(),
		RespBytesTotal:     g.digestRespondBytes.Load(),
		StampBrokenTotal:   g.digestStampBroken.Load(),
	}
}

// registerDigestRecv returns the wait record used for this peer's next digest
// exchange, allocating its one-slot channel on first use. It drains a late
// response from an earlier round before starting a new wait. digestRecvMu
// synchronizes the sweep with DeliverDigest producers.
func (g *Gossiper) registerDigestRecv(peerID [16]byte) *digestRecvWait {
	g.digestRecvMu.Lock()
	defer g.digestRecvMu.Unlock()
	w, ok := g.digestRecv[peerID]
	if !ok || w == nil {
		w = &digestRecvWait{ch: make(chan *peerDigest, 1)}
		g.digestRecv[peerID] = w
		return w
	}
	// Discard a late response from an earlier round before waiting again. Its
	// build-to-drain span includes channel queueing and is a conservative input
	// to the adaptive wait. Drained responses count even when debug logs are off.
	// A missing stamp is counted separately rather than producing a huge or
	// negative duration.
	select {
	case stale := <-w.ch:
		g.digestExchDrained.Add(1)
		if stale != nil && stale.buildStamp != 0 {
			if g.digestLatencyDebug {
				log.Printf("mesh: digest-latency DRAINED peer=%x build_to_drain_ms=%d", peerID, (time.Now().UnixNano()-stale.buildStamp)/1e6)
			}
			if g.digestWaitAdaptive {
				g.digestWaitObserve(w, time.Duration(time.Now().UnixNano()-stale.buildStamp))
			}
		} else {
			g.digestStampBroken.Add(1)
			if g.digestLatencyDebug {
				log.Printf("mesh: digest-latency drained peer=%x BROKEN-STAMP (unstamped deposit skipped)", peerID)
			}
		}
	default:
	}
	return w
}

// digestRecvFor returns the per-peer receive channel for a digest the readLoop
// just received, or nil if the sweep is not currently waiting on this peer
// (stratified OFF, or no round in flight for this peer). Called on the
// readLoop/serveConn goroutine (the producer side); the digestRecvMu serializes
// the map read against the sweep's registerDigestRecv (the consumer side).
func (g *Gossiper) digestRecvFor(peerID [16]byte) chan *peerDigest {
	g.digestRecvMu.Lock()
	defer g.digestRecvMu.Unlock()
	if w := g.digestRecv[peerID]; w != nil {
		return w.ch
	}
	return nil
}

// evictStaleDigestRecv bounds wait records to the live peer set. It runs only
// in the stratified sweep, which is also the only creator of records.
//
// Deletion removes the map reference, not a channel already held by a blocked
// sweep; that wait still ends at its timeout. A late response for an evicted
// peer finds no channel and is dropped. Receive paths never create records, so
// inbound traffic cannot grow this map.
//
// The lock order is digestRecvMu then PeerSet's read lock through isLive. A nil
// PeerSet skips eviction because liveness is unknown. Live entries are retained:
// dropping one could waste an exchange, while a departed entry costs only one
// channel until the next sweep.
func (g *Gossiper) evictStaleDigestRecv() {
	g.digestRecvMu.Lock()
	if g.digestRecv == nil || len(g.digestRecv) == 0 {
		g.digestRecvMu.Unlock()
		return
	}
	if g.peers == nil {
		g.digestRecvMu.Unlock()
		return
	}
	for id := range g.digestRecv {
		if !g.peers.isLive(id) {
			delete(g.digestRecv, id)
		}
	}
	g.digestRecvMu.Unlock()
}

// reportStratifiedFallback invokes the optional fallback metric callback on the
// sweep goroutine. A nil callback leaves reconciliation unchanged.
func (g *Gossiper) reportStratifiedFallback() {
	if g.stratifiedFallbackReporter != nil {
		g.stratifiedFallbackReporter()
	}
}

// stratDiagnostics tracks digest attempts, oversend fallbacks, and elapsed
// digest time by peer region. A high cross-region fallback ratio can indicate
// that the fixed timeout is too short for those links. fallbackByClass adds a
// bounded failure-class breakdown under the same mutex and is emitted only when
// the detailed exchange instrument is armed.
type stratDiagnostics struct {
	mu              sync.Mutex
	exchange        map[RegionTag]int64
	fallback        map[RegionTag]int64
	digestNs        int64
	fallbackByClass [deferClassCount]map[RegionTag]int64
}

func newStratDiagnostics() *stratDiagnostics {
	return &stratDiagnostics{
		exchange: make(map[RegionTag]int64),
		fallback: make(map[RegionTag]int64),
	}
}

// peerRegionTag resolves a peer's diagnostic region, or RegionUnset when no
// topology is bound. This matches IsInterRegion's treatment of unknown regions.
func (g *Gossiper) peerRegionTag(peerID [16]byte) RegionTag {
	if g.topology == nil {
		return RegionUnset
	}
	return g.topology.PeerRegion(peerID)
}

// noteStratExchange records one digest attempt by peer region. It is a no-op
// when stratified diagnostics are not allocated.
func (g *Gossiper) noteStratExchange(peerID [16]byte) {
	d := g.stratDiag
	if d == nil {
		return
	}
	r := g.peerRegionTag(peerID)
	d.mu.Lock()
	d.exchange[r]++
	d.mu.Unlock()
}

// noteStratFallback invokes the optional fallback metric and records the
// fallback by peer region when diagnostics are available.
func (g *Gossiper) noteStratFallback(peerID [16]byte) {
	g.reportStratifiedFallback()
	d := g.stratDiag
	if d == nil {
		return
	}
	r := g.peerRegionTag(peerID)
	d.mu.Lock()
	d.fallback[r]++
	d.mu.Unlock()
}

// noteStratDigestNs adds one peer's digest build and round-trip time.
func (g *Gossiper) noteStratDigestNs(ns int64) {
	d := g.stratDiag
	if d == nil {
		return
	}
	d.mu.Lock()
	d.digestNs += ns
	d.mu.Unlock()
}

// stratDiagSnapshotReset returns the diagnostic window since the previous call
// and starts a new one. Each emitted sweep line therefore describes its own
// interval rather than process-lifetime totals. Nil diagnostics return nil maps.
func (g *Gossiper) stratDiagSnapshotReset() (exchange, fallback map[RegionTag]int64, digestNs int64) {
	d := g.stratDiag
	if d == nil {
		return nil, nil, 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	exchange, fallback, digestNs = d.exchange, d.fallback, d.digestNs
	d.exchange = make(map[RegionTag]int64)
	d.fallback = make(map[RegionTag]int64)
	d.digestNs = 0
	return exchange, fallback, digestNs
}

// formatStratDiag renders ` strat(self=R){peer:xN/fN,...}dgms=N` with regions
// sorted for deterministic logs. It returns an empty suffix when neither map has
// entries.
func formatStratDiag(self RegionTag, exchange, fallback map[RegionTag]int64, digestNs int64) string {
	if len(exchange) == 0 && len(fallback) == 0 {
		return ""
	}
	seen := make(map[RegionTag]bool, len(exchange)+len(fallback))
	tags := make([]int, 0, len(exchange)+len(fallback))
	for r := range exchange {
		if !seen[r] {
			seen[r] = true
			tags = append(tags, int(r))
		}
	}
	for r := range fallback {
		if !seen[r] {
			seen[r] = true
			tags = append(tags, int(r))
		}
	}
	sort.Ints(tags)
	s := fmt.Sprintf(" strat(self=%d){", int(self))
	for i, ti := range tags {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("%d:x%d/f%d", ti, exchange[RegionTag(ti)], fallback[RegionTag(ti)])
	}
	s += fmt.Sprintf("}dgms=%d", digestNs/1e6)
	return s
}

// recordPeerRoot stores a root announced through DeliverDigest. A nil peerRoots
// map means stratified mode is disabled, so the announcement is ignored.
// peerRootsMu synchronizes connection-side writes with sweep-side reads.
func (g *Gossiper) recordPeerRoot(peerID [16]byte, root [32]byte) {
	g.peerRootsMu.Lock()
	if g.peerRoots != nil {
		g.peerRoots[peerID] = root
	}
	g.peerRootsMu.Unlock()
}

// peerRootFor returns a peer's latest announced root. An unknown root causes
// digestGateFire to exchange digests rather than risk a stalled reconciliation.
func (g *Gossiper) peerRootFor(peerID [16]byte) ([32]byte, bool) {
	g.peerRootsMu.Lock()
	defer g.peerRootsMu.Unlock()
	r, ok := g.peerRoots[peerID]
	return r, ok
}

// evictStalePeerRoots removes roots for peers no longer in the PeerSet. Lazy
// eviction at sweep start bounds stale entries within one sweep without adding
// callbacks to peer removal paths.
//
// A live peer is never deleted. A peer that departs just after this pass can
// cause one redundant exchange, which is safer than suppressing reconciliation.
// A rejoined peer's next root announcement repopulates its entry. Nil maps and
// nil PeerSets return without eviction.
func (g *Gossiper) evictStalePeerRoots() {
	g.peerRootsMu.Lock()
	if g.peerRoots == nil || len(g.peerRoots) == 0 {
		g.peerRootsMu.Unlock()
		return
	}
	if g.peers == nil {
		g.peerRootsMu.Unlock()
		return
	}
	for id := range g.peerRoots {
		if !g.peers.isLive(id) {
			delete(g.peerRoots, id)
		}
	}
	g.peerRootsMu.Unlock()
}

// noteDigestGateSkip records an exchange suppressed for an already converged
// peer on the sweep goroutine.
func (g *Gossiper) noteDigestGateSkip() {
	g.digestGateSkips.Add(1)
}

// digestGateFire exchanges digests when the peer root is unknown or differs
// from the local root. Gating on local root movement would be incorrect: a
// behind node can remain unchanged indefinitely while its peers move ahead.
//
// Tests can force every exchange or substitute that broken local-change rule.
// prevGateRoot is used only by the latter negative control.
func (g *Gossiper) digestGateFire(peerID [16]byte, myRoot, prevGateRoot [32]byte) bool {
	if g.disableChangeGate.Load() {
		return true // negative control: exchange unconditionally
	}
	if g.gateLocalChangeBugInject.Load() {
		return myRoot != prevGateRoot // negative control: use local root movement
	}
	proot, known := g.peerRootFor(peerID)
	return !known || proot != myRoot
}

// digestRespondMaxConcurrent bounds concurrent O(S) digest builds. The limit is
// twice the partial view's expected in-degree of 8; when all slots are busy, the
// response is dropped and the requester uses its fallback. Phase jitter also
// reduces synchronized arrivals, but does not remove the need for this bound.
const digestRespondMaxConcurrent = 16

// sweepPhaseJitterPCGStream separates phase derivation from the inter-region
// and intra-view PCG streams that use the same seed. The constant must remain
// stable so recorded node phases are reproducible.
const sweepPhaseJitterPCGStream = 0x5EED0FF5EED0FF5E

// These controls force phase alignment, reuse the intra-view stream, share a
// zero seed, or return a fixed phase in negative-control tests. Production
// leaves them false.
var (
	sweepPhaseAlignBugInject       atomic.Bool
	sweepPhaseFrozenZeroBugInject  atomic.Bool
	sweepPhaseWrongStreamBugInject atomic.Bool
	sweepPhaseFixedBugInject       atomic.Bool
)

// sweepPhaseOffset returns a deterministic phase in [0, tick) from the node ID
// and a domain-separated PCG stream. It shifts when a node sweeps, not what it
// sends, and scales with the active tick.
//
// Aligned sweeps can produce Poisson(f) concurrent requests at one responder.
// Uniform phases reduce overlap by w_eff = 2W/T − (W/T)^2 for service window W
// and tick T, because requests overlap when their phases differ by less than W
// in either direction. The bound complements, rather than replaces, the
// responder semaphore.
func sweepPhaseOffset(nodeID [16]byte, tick time.Duration) time.Duration {
	if tick <= 0 {
		return 0
	}
	if sweepPhaseAlignBugInject.Load() {
		return 0 // negative control: align every node at phase zero
	}
	if sweepPhaseFixedBugInject.Load() {
		return 75 * time.Millisecond // negative control: fixed phase can exceed a short tick
	}
	pcg := rand.NewPCG(binary.LittleEndian.Uint64(nodeID[:8]), sweepPhaseJitterPCGStream)
	if sweepPhaseWrongStreamBugInject.Load() {
		pcg = rand.NewPCG(binary.LittleEndian.Uint64(nodeID[:8]), intraViewPCGStream) // negative control: reuse the intra-view stream
	}
	if sweepPhaseFrozenZeroBugInject.Load() {
		pcg = rand.NewPCG(0, 0) // negative control: use one seed for every node
	}
	return time.Duration(pcg.Uint64() % uint64(tick))
}

// enqueueDigestResponse starts a bounded, asynchronous response to a digest
// request on the connection goroutine. numBuckets comes from a verified v2
// request or the v1 default, allowing the response table to match the request.
// A full semaphore drops the response without blocking the read loop.
func (g *Gossiper) enqueueDigestResponse(peerID [16]byte, seed maphash.Seed, numBuckets int) {
	arrived := time.Now()
	if !g.respondEnabled.Load() {
		return
	}
	if g.disableDigestRespond.Load() {
		return // negative control: suppress the responder
	}
	if g.peers == nil {
		return // an insert-only Gossiper has no connection on which to respond
	}
	sem := g.respondSem
	if sem == nil {
		return // also covers incomplete zero-value test doubles
	}
	if g.respondIndeg != nil {
		g.respondIndeg.record(len(sem))
	}
	select {
	case sem <- struct{}{}:
	default:
		g.digestRespondDropped.Add(1)
		log.Printf("mesh: digest response dropped peer=%x (responder bound %d busy; requester falls back)", peerID, digestRespondMaxConcurrent)
		return
	}
	go g.respondToDigest(sem, peerID, seed, numBuckets, arrived)
}

// respondToDigest builds a local IBLT with the requester's seed and bucket
// count, then sends it on a short-lived goroutine. The requester rebuilds its
// own table with those parameters before subtraction, so the two tables align.
// Peel failure on incompatible frames selects the fallback rather than a wrong
// delta.
func (g *Gossiper) respondToDigest(sem chan struct{}, peerID [16]byte, seed maphash.Seed, numBuckets int, arrived time.Time) {
	defer func() { <-sem }() // release the slot captured by this call
	if d := g.digestResponderDelayMs.Load(); d > 0 {
		// Test delay holds a build slot to model queueing behind slow responders.
		time.Sleep(time.Duration(d) * time.Millisecond)
	}
	// GenerateDigestSizedWithSeed clamps oversized requests to the arena-safe
	// bucket ceiling, and GenerateDelta adopts the response's actual size.
	localIBLT := g.engine.GenerateDigestSizedWithSeed(seed, numBuckets)
	marshaledIBLT, err := eng.MarshalIBLT(localIBLT)
	releaseMeshDigest(localIBLT)
	if err != nil {
		return
	}
	// Responses are IBLT-only unless a compatibility test requests the legacy SE.
	var marshaledSE []byte
	if g.digestLegacySE.Load() {
		localSE := g.engine.GenerateStrataEstimator(seed)
		if marshaledSE, err = eng.MarshalStrataEstimator(localSE); err != nil {
			return
		}
	}
	respRole := digestRoleResponse
	if g.ibltV2.Load() {
		respRole = digestRoleResponseV2
	}
	if g.digestLatencyDebug {
		log.Printf("mesh: digest-latency RESPOND peer=%x arrival_to_build_ms=%d sem_depth=%d", peerID, time.Since(arrived).Milliseconds(), len(sem))
	}
	resp := buildDigestFrame(respRole, g.owner.NodeID, seed, marshaledSE, marshaledIBLT)
	// The request's connection was verified before this asynchronous build, but
	// a reconnect may have replaced it. Recheck the current connection before
	// publishing so a new unverified connection cannot inherit that approval.
	// The negative-control switch disables both this check and ingress gating.
	// A small interval remains before Publish's own map lookup; closing it would
	// require moving this policy into the routing layer.
	if !g.disableDigestChannelGateBugInject.Load() && !g.peers.egressVerified(peerID) {
		g.digestRespondEgressDrops.Add(1)
		log.Printf("mesh: digest response to %x dropped at ship: conn not challenge-verified (response egress gate)", peerID)
		return
	}
	prefixed := receive.LengthPrefixFrame(resp)
	if err := g.peers.Publish(peerID, prefixed); err != nil {
		return // the requester uses its fallback after a mid-round disconnect
	}
	if !g.bytesBlind.Load() {
		g.digestRespondBytes.Add(int64(len(prefixed)))
	}
	g.digestRespondSent.Add(1)
	if g.gatewayMode && g.stratified && g.engine != nil && !g.disableRespondRootAnnounceBugInject.Load() {
		rootAnnounce := receive.LengthPrefixFrame(buildRootAnnounceFrame(g.owner.NodeID, g.engine.MerkleRootFromShards()))
		_ = g.peers.Publish(peerID, rootAnnounce)
	}
	if g.l0iExchDebug {
		// The synchronous send is complete; join this local timestamp to the
		// requester's arrival using peerID and the frame's build stamp.
		g.l0iNoteSendDone(peerID, digestFrameStamp(resp))
	}
}

// Cache returns the payload cache (test seam + the inject path records into it).
func (g *Gossiper) Cache() *payloadCache { return g.cache }

// selectLatestDot chooses the greatest DotCounter and breaks ties by the
// smallest DotNodeID. The result is deterministic for any input order, but the
// tie-break is not a causal ordering across origins. handleGet and LatestPayload
// share this selector so they cannot report different entries as latest.
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

// LatestPayload returns the cached payload for entityID's latest dot. An origin
// can return its locally recorded payload; a peer ordinarily has only the
// PayloadDigest after ReconstructEntry discards the received payload, so its
// lookup returns ("", false). The digest is never presented as the value.
//
// PointGet supplies the candidate entries without constructing a merged state
// snapshot. LatestPayload reads only the existing cache and adds no retention.
func (g *Gossiper) LatestPayload(entityID string) (payload string, ok bool) {
	entries := g.engine.PointGet(entityID)
	latest, ok := selectLatestDot(entries)
	if !ok {
		return "", false
	}
	return g.cache.lookup(entityID, latest.Dot())
}

// PayloadForDot returns the cached payload for a specific dot. handleGet uses
// it with entries from one PointGet result so the payload and digest belong to
// the same entry. The cache mutex permits concurrent insertion and lookup.
func (g *Gossiper) PayloadForDot(entityID string, dot eng.CausalDot) (string, bool) {
	return g.cache.lookup(entityID, dot)
}

// RegisterPeer adds a peer's CRDT signing public key to the shared Directory.
// VerifyCRDTFrame resolves that key by origin node ID, so registration must
// precede acceptance of the peer's deltas.
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
	// ReconstructEntry checks PayloadDigest against SHA-256(payload). Deriving
	// the digest and caching the same payload here keeps the later frame valid
	// after the engine discards the value.
	//
	// Bridge.PutLocal performs the insert and WAL append. Payload recording
	// follows the append so the cache and durable log advance together. A WAL
	// error returns a zero dot, which the HTTP caller must treat as a failed
	// durable write rather than acknowledging it. Without a bridge, insertion
	// uses the in-memory path below.
	if g.bridge != nil {
		// State becomes visible before the payload record; mark that interval so
		// a sweep classifies its cache miss as pending.
		g.commitInFlight.Add(1)
		dot, err := g.bridge.PutLocal(entityID, payload, entry)
		if err != nil {
			g.commitInFlight.Add(-1)
			log.Printf("durability: WAL append failed for entity %s: %v (write not durable; returning zero dot)", entityID, err)
			return eng.CausalDot{}
		}
		g.cache.record(entityID, dot, payload)
		g.commitInFlight.Add(-1)
		return dot
	}
	g.commitInFlight.Add(1)
	dgst := sha256.Sum256([]byte(payload))
	entry.PayloadDigest = dgst
	dot := g.engine.InsertLocal(entityID, entry)
	// Match the Bridge's synchronous post-insert index feed before recording
	// the payload and closing the commit window.
	g.feedIndex(entityID, entry)
	g.cache.record(entityID, dot, payload)
	g.commitInFlight.Add(-1)
	return dot
}

// BatchItem contains one entity, payload, and bitemporal entry for
// InsertLocalEventsBatch. It mirrors durability.LocalItem so durable insertion
// can convert the slice without exposing that durability type in the mesh API.
type BatchItem struct {
	EntityID string
	Payload  string
	Entry    eng.CRDTEntry
}

// InsertLocalEventsBatch inserts each item and records its payload for gossip.
// With a Bridge, PutLocals performs all engine inserts followed by one WAL
// append and fsync, and payload recording follows that append. Without one, it
// uses the same in-memory insert path as InsertLocalEvents for each item.
//
// Durable failure is batch-wide: a non-nil error or failedFrom != -1 means no
// subset is reported durable, and handleBatchInsert returns 503 for every item.
// Success returns one dot per item, failedFrom == -1, and a nil error. The
// in-memory path always returns (dots, -1, nil).
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
		// PutLocals mutates state before the WAL append and before payload
		// recording. Keep the commit marker across that entire interval.
		g.commitInFlight.Add(1)
		dots, failedFrom, err = g.bridge.PutLocals(local)
		if err != nil {
			g.commitInFlight.Add(-1)
			log.Printf("durability: WAL batch append failed (%d items): %v (returning per-batch 503)", len(items), err)
			return dots, failedFrom, err
		}
		// Record only after the append succeeds. If the batch is not durable,
		// caching its payloads would diverge from the WAL; the caller rejects all
		// items and the client can retry them together.
		for i, dot := range dots {
			g.cache.record(items[i].EntityID, dot, items[i].Payload)
		}
		g.commitInFlight.Add(-1)
		return dots, -1, nil
	}
	g.commitInFlight.Add(1)
	dots = make([]eng.CausalDot, len(items))
	for i, it := range items {
		dgst := sha256.Sum256([]byte(it.Payload))
		it.Entry.PayloadDigest = dgst
		dot := g.engine.InsertLocal(it.EntityID, it.Entry)
		g.feedIndex(it.EntityID, it.Entry)
		g.cache.record(it.EntityID, dot, it.Payload)
		dots[i] = dot
	}
	g.commitInFlight.Add(-1)
	return dots, -1, nil
}

// sweepState contains one round's publishing and diagnostic counters.
type sweepState struct {
	round            int
	shippedEnvelopes int
	// shippedEntries counts successful publishes, not entries merely visited by
	// a delta walk. This keeps entries, pending, and misses meaningful.
	shippedEntries int
	// payloadMisses counts orphaned local entries with no cached payload and no
	// active commit. relayMisses separately counts foreign entries for which
	// neither relay layer has a frame; a different relay may supply it later.
	payloadMisses int
	relayMisses   int
	// payloadPending counts local entries skipped while a commit is active and
	// their payloads are not yet recorded.
	payloadPending int
	// foreignEnvelopes counts distinct relayed envelopes. foreignReceived sums
	// their wire-decoded element counts, which is the unit used by relay budgets.
	foreignEnvelopes int
	foreignReceived  int
	// egressUnverified counts peers skipped before publishing because their
	// connections had not completed the verified-key challenge.
	egressUnverified int

	durMs            int64
	slowestPeerMs    int64
	slowestPeerInter bool
	// deferAlarms is bounded per sweep by deferAlarmLogCap.
	deferAlarms int
	// The intra-view fields remain zero unless sampling is active.
	viewDrawn    int
	viewEligible int
	viewXor      uint64
	// firedPeers reached a ship decision; gatedSkips were suppressed by matching
	// roots. The byte fields are per-round deltas of the sweep-owned counters.
	firedPeers     int
	gatedSkips     int
	shippedBytes   int64
	digestReqBytes int64
}

// AntiEntropySweep runs one publishing round. It uses topology.Select when
// region-aware routing is active and a sorted full PeerSet otherwise. The round
// number both seeds topology selection and identifies the returned statistics.
//
// Without stratified anti-entropy, one full delta is shared by the selected
// peers. With it, the sweep announces the local root, exchanges digests only
// for unknown or mismatched peers, and derives peer-specific deltas. Every
// publish still requires a challenge-verified connection. Local writes are
// signed into frames or batches; foreign writes are republished from retained
// origin-signed envelopes. The result counts completed writes separately from
// pending, missing, and gated entries.
func (g *Gossiper) AntiEntropySweep(ctx context.Context) sweepState {
	st := sweepState{}
	// Capture process-lifetime counters here; their differences at the end are
	// this round's byte totals.
	sweepStartShipBytes := g.sweepShipBytes
	sweepStartReqBytes := g.digestReqBytes
	// Warn once about options whose required execution path is disabled, but
	// keep the ordinary oversend sweep running.
	if g.deferHandler && !g.stratified && g.deferOrphanWarn.CompareAndSwap(false, true) {
		log.Printf("mesh: defer-handler is armed without stratified-anti-entropy: every defer site is unreachable and the flag is inert — full-keyset dumps continue on digest failures")
	}
	if g.partialIntraView && (g.topology == nil || !g.regionAware) && g.viewOrphanWarn.CompareAndSwap(false, true) {
		log.Printf("mesh: partial-intra-view is armed without region-aware routing: intra view sampling is inactive and the sweep keeps the full intra-region mesh")
	}
	if g.ibltV2.Load() && !g.stratified && g.ibltV2OrphanWarn.CompareAndSwap(false, true) {
		log.Printf("mesh: --iblt-v2 is armed without stratified-anti-entropy: v2 digest exchange is unreachable and the oversend path is unchanged")
	}
	// Region-aware selection changes only the peer list. Digest construction,
	// signing, and frame formats are the same in either mode.
	var peerIDs [][16]byte
	regionArmed := g.topology != nil && g.regionAware
	// Increment on the sweep goroutine before selection. The seed is
	// round XOR the low 64 bits of nodeID: the round rotates one node's picks,
	// while nodeID decorrelates peers within a round. Selection is deterministic
	// and requires no random input.
	g.sweepRound++
	// Envelopes from an earlier round have stale content and sequences. Resetting
	// the memo also bounds it to one round's batches.
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0
	if regionArmed {
		g.topology.SetSeed(g.sweepRound ^ binary.LittleEndian.Uint64(g.owner.NodeID[:8]))
		peerIDs = g.topology.Select(ctx)
		// Read statistics only after an actual sampled selection, so an inactive
		// view cannot report values left by an earlier draw.
		if g.topology.PartialIntraView() {
			st.viewDrawn, st.viewEligible, st.viewXor = g.topology.LastIntraView()
		}
	} else {
		peerIDs = g.peers.Peers()
	}
	if len(peerIDs) == 0 {
		return st
	}
	// The full PeerSet needs explicit ordering. topology.Select already returns
	// its deterministic intra-region and seeded inter-region order.
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
	// The counter cannot overflow int during a practical run on supported 64-bit
	// targets. The same round number seeds selection and appears in diagnostics.
	st.round = int(g.sweepRound)
	// Non-stratified deltas do not depend on peerID, and signed batch envelopes
	// have no recipient field. Generate the full delta once and hold one EBR pin
	// for the entire sweep rather than rebuilding and repinning it per peer.
	// Stratified deltas are peer-specific and cannot be shared.
	var sharedDelta *eng.CRDTDelta
	// Stratified mode computes one sharded Merkle root and one announcement frame
	// per sweep. prevGateRoot serves only the local-change negative control.
	var myRoot, prevGateRoot [32]byte
	var rootFrame []byte
	if !g.stratified {
		sharedDelta = g.generateSweepDelta(ctx, [16]byte{})
		if sharedDelta != nil {
			defer sharedDelta.Release()
		}
	} else {
		myRoot = g.engine.MerkleRootFromShards()
		rootFrame = receive.LengthPrefixFrame(buildRootAnnounceFrame(g.owner.NodeID, myRoot))
		prevGateRoot = g.prevGateRoot
		g.prevGateRoot = myRoot

		// Bound all peer-keyed state to the current PeerSet without deleting
		// live rotation, response, or root state.
		g.evictStalePeerRoots()
		g.evictStaleDigestRecv()
		g.evictStaleLadder()
		if g.deferHandler {
			g.evictStaleDefers()
		}
	}
	// sharedShip is built on the first peer that actually flushes. It lives under
	// sharedDelta's pin and is written only by this sweep goroutine.
	var sharedShip sharedShipSet
	for _, peerID := range peerIDs {
		if ctx.Err() != nil {
			return st
		}
		// Do not publish to this node even if a provisioning or selection path
		// includes its own ID.
		if peerID == g.owner.NodeID {
			continue
		}
		// Check possession proof before any write in this iteration: root
		// announcements, digest requests, local deltas, and relay frames all stop
		// here for an unverified connection. Routing and connection registration
		// are unchanged. Tests can disable the check to exercise this boundary.
		if !g.disableEgressGateBugInject.Load() && !g.peers.egressVerified(peerID) {
			st.egressUnverified++
			g.egressUnverifiedDrops.Add(1)
			// Log at most once per unverified peer in this sweep, not per frame.
			log.Printf("mesh: sweep egress gate: peer %x skipped — conn not challenge-verified", peerID)
			continue
		}
		// Report selection of a cross-region peer before publishing. The callback
		// measures routing choices, so a later fallback or publish failure does not
		// erase this event.
		if regionArmed && g.interRegionReporter != nil && g.topology.IsInterRegion(peerID) {
			g.interRegionReporter()
		}
		// Stratified mode announces the root and may exchange a populated remote
		// IBLT before GenerateDelta. Non-stratified mode reuses the full shared
		// delta below. A local self-subtraction would be empty; the peer's digest
		// is what makes the delta selective.
		if g.stratified {
			// Announce on every selected peer; a failed write is retried next
			// sweep and does not itself select a fallback. Only successful writes
			// contribute to wire-byte accounting.
			if g.peers.Publish(peerID, rootFrame) == nil && !g.bytesBlind.Load() {
				g.sweepShipBytes += int64(len(rootFrame))
			}
			// GenerateDelta is push-only. An empty node has nothing to push, and
			// the announcement lets a non-empty peer push on its own sweep, so
			// gateway mode need not wait for a response to an empty request.
			if g.gatewayMode && !g.disableEmptyRootSkipBugInject.Load() && myRoot == ([32]byte{}) {
				g.noteDigestGateSkip()
				st.gatedSkips++
				continue
			}
			// Unknown or mismatched roots exchange digests. Matching roots skip
			// the exchange; the announcement above still keeps the peer current.
			if !g.digestGateFire(peerID, myRoot, prevGateRoot) {
				g.noteDigestGateSkip()
				st.gatedSkips++
				continue
			}
		}
		// Non-stratified peers share one delta. Stratified generation can return
		// nil for cancellation or a deferred round; there is then nothing to ship
		// or release, and any aged defer alarm still gets its update.
		delta := sharedDelta
		if g.stratified {
			delta = g.generateSweepDelta(ctx, peerID)
			if delta == nil {
				if g.deferHandler {
					g.deferAlarmIfAged(peerID, &st)
				}
				continue
			}
		}
		// Batching amortizes signatures over local deltas and also relays retained
		// foreign batches. hybridSign forces the batch path even at batchSize <= 1
		// so both signatures can cover the same batch wire. shipBatchedDelta clamps
		// a zero batchSize to DefaultBatchSize. Otherwise shipDelta signs and sends
		// individual frames.
		shipStart := time.Now()
		st.firedPeers++
		var ss shipStats
		if g.batchSize > 1 || g.hybridSign {
			// Shared batches require one peer-independent delta and no active
			// per-peer defer window. The anyDeferWindowArmed check also covers a
			// window left after the handler is disabled. Negative controls can
			// force per-peer walks or deliberately bypass the stratified guard.
			if (!g.stratified || g.redHoistAllBugInject.Load()) && !g.deferHandler && !g.anyDeferWindowArmed() && !g.redPerPeerSortBugInject.Load() {
				ss = g.flushSharedShip(ctx, peerID, &sharedShip, delta, g.batchSize)
			} else {
				ss = g.shipBatchedDelta(ctx, peerID, delta, g.batchSize)
			}
		} else {
			ss = g.shipDelta(ctx, peerID, delta)
		}
		if ms := time.Since(shipStart).Milliseconds(); ms > st.slowestPeerMs {
			st.slowestPeerMs = ms
			st.slowestPeerInter = regionArmed && g.topology != nil && g.topology.IsInterRegion(peerID)
		}
		if g.l0iExchDebug && !l0iPhaseZeroReqShipBugInject.Load() {
			g.l0iPhaseShipNs += time.Since(shipStart).Nanoseconds()
		}
		if g.deferHandler {
			// Advance only after a live-context round with no publish failure;
			// otherwise retain the window for retry. Aged peers log a capped alarm.
			g.finalizeDeferShip(peerID, ss.pubErrs == 0 && ctx.Err() == nil)
			g.deferAlarmIfAged(peerID, &st)
		}
		if g.stratified {
			// Only peer-specific deltas are released here. sharedDelta has one
			// deferred release after all peers finish reading its arena slices.
			delta.Release()
		}
		st.shippedEnvelopes += ss.shipped
		st.shippedEntries += ss.entries
		st.foreignEnvelopes += ss.foreignEnv
		st.foreignReceived += ss.foreignRecv
		st.payloadMisses += ss.misses
		st.relayMisses += ss.relayMisses
		st.payloadPending += ss.pending
	}
	// Convert the process-lifetime counters into this round's deltas.
	st.shippedBytes = g.sweepShipBytes - sweepStartShipBytes
	st.digestReqBytes = g.digestReqBytes - sweepStartReqBytes
	return st
}

// generateSweepDelta produces the delta for one peer in a sweep. Without
// stratified anti-entropy, an empty IBLT makes GenerateDelta return every entry.
// With stratification enabled, it sends a digest request, waits for the peer's
// digest, and subtracts that digest from the local state to select the delta.
// Digest construction, publication, timeout, and decoding failures either defer
// the exchange or fall back to the full delta, depending on configuration.
//
// Digest frames are separate from signed delta envelopes. The returned delta is
// consumed by the ordinary ship paths, so digest selection does not change the
// delta wire format or receive-side verification.
//
// SweepLoop serializes calls on the sending side. DeliverDigest supplies replies
// from connection goroutines through per-peer channels protected by digestRecvMu.
func (g *Gossiper) generateSweepDelta(ctx context.Context, peerID [16]byte) *eng.CRDTDelta {
	if !g.stratified {
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	// Attribute every exchange attempt and its elapsed time to the peer's region.
	g.noteStratExchange(peerID)
	dgStart := time.Now()
	defer func() { g.noteStratDigestNs(time.Since(dgStart).Nanoseconds()) }()
	// Register before publishing so a fast response cannot be missed. Registration
	// also discards a stale response left by an earlier round.
	wait := g.registerDigestRecv(peerID)
	recvCh := wait.ch
	// Both peers build their IBLTs with this seed so corresponding keys occupy
	// the same buckets. A fresh seed makes each round independent; a response
	// from an earlier round cannot be subtracted as though it were current.
	seed := maphash.MakeSeed()
	// V2 requests carry the selected bucket count in their header. The responder
	// adopts that size, and GenerateDelta adopts the response's size, so both
	// subtraction operands have matching layouts. V1 uses the default digest;
	// v2 can adjust the peer's bucket count through its bounded ladder.
	var (
		marshaledIBLT []byte
		err           error
	)
	if g.ibltV2.Load() && !g.disableV2HeaderOnlyRequestBugInject.Load() {
		marshaledIBLT = buildV2DigestRequestBody(g.digestBucketsFor(peerID))
	} else {
		localIBLT := g.engine.GenerateDigestSizedWithSeed(seed, g.digestBucketsFor(peerID))
		marshaledIBLT, err = eng.MarshalIBLT(localIBLT)
		releaseMeshDigest(localIBLT)
		if err != nil {
			// Without a usable request digest, defer this peer or return the full delta.
			if g.deferHandler {
				g.noteDeferTrigger(peerID, deferClassIBLTMarshal)
				return g.deferSliceSource(peerID, nil)
			}
			g.noteStratFallback(peerID)
			emptyDigest := eng.NewIBLT(1, 4)
			return g.engine.GenerateDelta(emptyDigest)
		}
	}
	// Current requests carry only the IBLT. This negative control adds the legacy
	// StrataEstimator so tests can exercise compatibility with older peers.
	var marshaledSE []byte
	if g.digestLegacySE.Load() {
		localSE := g.engine.GenerateStrataEstimator(seed)
		marshaledSE, err = eng.MarshalStrataEstimator(localSE)
		if err != nil {
			// Treat this test-only failure like the other exchange-build failures.
			if g.deferHandler {
				g.noteDeferTrigger(peerID, deferClassSEMarshal)
				return g.deferSliceSource(peerID, nil)
			}
			g.noteStratFallback(peerID)
			emptyDigest := eng.NewIBLT(1, 4)
			return g.engine.GenerateDelta(emptyDigest)
		}
	}
	// The request carries this node's seed so the responder can build a compatible
	// digest immediately. A v2 role prevents a v1 peer from answering a request
	// whose digest layout it cannot interpret.
	requestRole := digestRoleRequest
	if g.ibltV2.Load() {
		requestRole = digestRoleRequestV2
	}
	digestFrame := buildDigestFrame(requestRole, g.owner.NodeID, seed, marshaledSE, marshaledIBLT)
	wait.reqSentAt = time.Now()
	// Request-write timing is collected only when exchange diagnostics are enabled.
	var l0iReqT0 time.Time
	if g.l0iExchDebug {
		l0iReqT0 = time.Now()
	}
	prefixed := receive.LengthPrefixFrame(digestFrame)
	publishErr := g.peers.Publish(peerID, prefixed)
	if g.l0iExchDebug && !l0iPhaseZeroReqShipBugInject.Load() {
		g.l0iPhaseReqNs += time.Since(l0iReqT0).Nanoseconds()
	}
	if publishErr != nil {
		// Without defer handling, return the full delta so the normal publication
		// path can retry. Otherwise record a defer and send nothing on this failed edge.
		if g.deferHandler {
			g.noteDeferTrigger(peerID, deferClassPublish)
			return nil
		}
		g.noteStratFallback(peerID)
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	if !g.bytesBlind.Load() {
		g.digestReqBytes += int64(len(prefixed))
	}
	// Wait for a compatible response. Failure to obtain one falls back to the
	// full delta or enters the configured defer path; signed delivery is unchanged.
	var remotePD *peerDigest
	timeout := g.digestWaitTimeout
	if g.digestWaitAdaptive {
		timeout = g.digestWaitFor(wait)
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	// Measure the selected wait branch only when phase diagnostics are enabled.
	var l0iWaitT0 time.Time
	if g.l0iExchDebug {
		l0iWaitT0 = time.Now()
	}
	timer := time.NewTimer(timeout)
	select {
	case remotePD = <-recvCh:
		if g.l0iExchDebug {
			g.l0iPhaseWaitNs += time.Since(l0iWaitT0).Nanoseconds()
		}
		timer.Stop()
		g.digestExchCompleted.Add(1)
		if g.digestLatencyDebug && !wait.reqSentAt.IsZero() {
			log.Printf("mesh: digest-latency COMPLETED peer=%x span_ms=%d", peerID, time.Since(wait.reqSentAt).Milliseconds())
		}
		// Completed request-to-response spans update the adaptive wait estimate.
		if g.digestWaitAdaptive && !wait.reqSentAt.IsZero() {
			g.digestWaitObserve(wait, time.Since(wait.reqSentAt))
		}
	case <-ctx.Done():
		if g.l0iExchDebug {
			g.l0iPhaseWaitNs += time.Since(l0iWaitT0).Nanoseconds()
		}
		timer.Stop()
		// Cancellation is not a peer failure and must not advance the defer count.
		if g.deferHandler {
			return nil
		}
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	case <-timer.C:
		if g.l0iExchDebug {
			g.l0iPhaseWaitNs += time.Since(l0iWaitT0).Nanoseconds()
		}
		// If cancellation and timeout are both ready, cancellation takes priority.
		if ctx.Err() != nil {
			if g.deferHandler {
				return nil
			}
			emptyDigest := eng.NewIBLT(1, 4)
			return g.engine.GenerateDelta(emptyDigest)
		}
		// A timeout supplies no usable diff. Defer this peer or return the full delta.
		if g.deferHandler {
			g.noteDeferTrigger(peerID, deferClassTimeout)
			return g.deferSliceSource(peerID, nil)
		}
		g.noteStratFallback(peerID)
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	if remotePD == nil || remotePD.iblt == nil {
		// A response without an IBLT cannot select a diff.
		if g.deferHandler {
			g.noteDeferTrigger(peerID, deferClassNilDigest)
			return g.deferSliceSource(peerID, nil)
		}
		g.noteStratFallback(peerID)
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	// GenerateDelta builds the local IBLT with the response's layout and seed,
	// subtracts the remote digest, and peels the difference. If subtraction or
	// peeling fails, the returned delta falls back to every entry rather than
	// risking an incomplete diff. Its accessors expose that outcome for the
	// fallback and defer logic below.
	Delta := g.engine.GenerateDelta(remotePD.iblt)
	if Delta != nil && (Delta.PeelErr() != nil || Delta.DiffNil()) {
		g.digestPeelOversends.Add(1)
		// An incomplete peel can justify a larger v2 digest. A nil diff indicates
		// incompatible configuration instead and does not escalate the ladder.
		if g.ibltV2.Load() && Delta.PeelErr() != nil {
			g.ladderEscalate(peerID)
		}
		if g.deferHandler {
			// A bounded saturation crossover may send the full delta once for this
			// divergence episode. Otherwise defer or escalate a bounded slice;
			// deferSliceSource owns Delta until that decision is complete.
			if g.deferCrossover.Load() && errors.Is(Delta.PeelErr(), eng.ErrIncompletePeel) {
				if s, ok := g.deferCrossoverTry(peerID, Delta); ok {
					log.Printf("mesh: digest crossover peer=%x S=%d (one-shot bounded full-keyset ship on ErrIncompletePeel <= %d, cooldown %s)", peerID, s, deferCrossoverMaxEntries, deferCrossoverCooldown)
					g.digestCrossoverShips.Add(1)
					return Delta
				}
			}
			log.Printf("mesh: digest peel-defer peer=%x peelErr=%v diffNil=%v (deferring or escalating bounded slice)", peerID, Delta.PeelErr(), Delta.DiffNil())
			g.noteDeferTrigger(peerID, deferClassPeel)
			return g.deferSliceSource(peerID, Delta)
		}
		log.Printf("mesh: digest oversend peer=%x peelErr=%v diffNil=%v delta=full-keyset (fallback)", peerID, Delta.PeelErr(), Delta.DiffNil())
	} else if Delta != nil {
		log.Printf("mesh: digest exchange peer=%x delta=%d (peel clean)", peerID, Delta.SendKeyCount())
		// Only a clean exchange clears the peer's consecutive-defer state.
		if g.deferHandler {
			g.resetDeferPeer(peerID)
		}
		// Consecutive clean peels can reduce the v2 bucket count as the diff shrinks.
		if g.ibltV2.Load() {
			g.ladderCleanPeel(peerID)
		}
	}
	return Delta
}

// shipDelta publishes a peer's delta and returns its delivery counters. Entries
// originated by this node are rebuilt from payloadCache and signed by the origin.
// Foreign entries are relayed from retained origin-signed per-frame or batch
// envelopes without modifying their bytes; the next receiver verifies the origin
// signature and applies its own last-hop admission checks.
//
// A missing payload or retained envelope skips that entry for this round. Self
// entries with a commit in flight are counted as pending; other self misses are
// orphaned payloads, and foreign misses are relay-retention misses. A later sweep
// can retry after a local retry or another relay supplies the missing data.
//
// missLogCap bounds messages per ship call without hiding the aggregate counts,
// which still appear in sweep statistics and summary logs.
const missLogCap = 8

// effectiveMissLogCap returns the configured per-call message bound, or the
// default when no positive override is set.
func (g *Gossiper) effectiveMissLogCap() int {
	if g.missLogCapOverride > 0 {
		return g.missLogCapOverride
	}
	return missLogCap
}

// sweepHeartbeatRounds emits a periodic summary even when a round has no
// activity, distinguishing a quiet sweep from a stalled one. At the default
// 100 ms tick, 100 rounds produce approximately one heartbeat every 10 seconds.
const sweepHeartbeatRounds = 100

// CommitInFlight reports commits whose local state is visible but whose WAL
// append and payload recording have not finished. Root stability alone therefore
// does not establish quiescence; callers must also wait for this count to reach 0.
func (g *Gossiper) CommitInFlight() int64 {
	return g.commitInFlight.Load()
}

// CommitStats reports the bridge's commit count and total and maximum append
// latency in nanoseconds. A gossiper without a bridge returns zeros.
func (g *Gossiper) CommitStats() (count uint64, totalAppendNs, maxAppendNs int64) {
	if g.bridge == nil {
		return 0, 0, 0
	}
	return g.bridge.CommitStats()
}

// shipStats counts only successful publications. Misses and pending local
// entries remain separate, as do foreign envelope and received-element counts.
// A retained batch contributes its decoded element count, so self frames equal
// entries minus foreignRecv.
func (g *Gossiper) shipDelta(ctx context.Context, peerID [16]byte, delta *eng.CRDTDelta) shipStats {
	// Defer handling bounds publication-failure messages per call.
	publishErrs := 0
	var ss shipStats
	// costOf charges one received element for a self or per-frame foreign envelope,
	// the decoded count for a retained batch, and zero for misses and duplicates.
	// seenBatch ensures that entries from the same batch do not republish it
	// repeatedly to this peer during one sweep.
	seenBatch := make(map[batchRelayKey]bool)
	resolveTwoLayer := func(entry eng.CRDTEntry) foreignResolve {
		dot := relayKey{entry.OriginNodeID, entry.DotCounter}
		frame, ok := g.relay.lookup(entry.OriginNodeID, entry.DotCounter)
		if ok {
			return foreignResolve{dot: dot, frame: frame, count: 1, status: frOK, perFrame: true}
		}
		bFrame, originSeq, count, ok2 := g.relay.lookupBatchCounted(entry.OriginNodeID, entry.DotCounter)
		if !ok2 {
			return foreignResolve{dot: dot, status: frMiss}
		}
		if seenBatch[batchRelayKey{originNodeID: entry.OriginNodeID, originSeq: originSeq}] {
			return foreignResolve{dot: dot, originSeq: originSeq, status: frSeen}
		}
		return foreignResolve{dot: dot, frame: bFrame, originSeq: originSeq, count: count, status: frOK}
	}
	var memoRes foreignResolve
	costOf := func(entityID string, entry eng.CRDTEntry) int {
		if entry.OriginNodeID == g.owner.NodeID {
			return 1
		}
		memoRes = resolveTwoLayer(entry)
		if memoRes.status != frOK {
			return 0
		}
		return memoRes.count
	}
	// Buffer self-originated events for ordered publication after the walk. The
	// buffer holds one entry per selected event and is released between peers.
	// Truncating it by a fixed cap would repeatedly omit the same tail when the
	// digest-less walk is deterministic, so delta generation must bound the diff.
	var selfShip []BuiltEvent
	g.forEachShipEntry(peerID, delta, costOf, func(entityID string, entry eng.CRDTEntry) bool {
		if ctx.Err() != nil {
			return false
		}
		// Counters advance only after a successful publication below.
		if entry.OriginNodeID != g.owner.NodeID {
			// Look in the per-frame cache first, then the batch cache. A batch hit
			// republishes the retained origin-signed envelope once per peer and sweep.
			// Reuse costOf's lookup when its dot matches, keeping charging and sending
			// on the same resolved bytes; otherwise resolve the entry now.
			res := memoRes
			if res.dot != (relayKey{entry.OriginNodeID, entry.DotCounter}) {
				res = resolveTwoLayer(entry)
			}
			if res.status == frMiss {
				ss.relayMisses++
				if ss.relayMisses <= g.effectiveMissLogCap() {
					log.Printf("mesh: relay miss for %s origin=%x dotCounter=%d — foreign delta skipped this round: no retained frame in per-frame or batch relay cache (if every foreign entry misses, ensure Gossiper.WireRelayHooks is installed)", entityID, entry.OriginNodeID, entry.DotCounter)
				}
				return true
			}
			if res.status == frSeen {
				return true
			}
			// Forward the retained origin-signed envelope without changing its bytes.
			prefixed := receive.LengthPrefixFrame(res.frame)
			if err := g.peers.Publish(peerID, prefixed); err != nil {
				publishErrs++
				if !g.deferHandler || publishErrs <= g.effectiveMissLogCap() {
					log.Printf("mesh: Publish to %x for foreign %s: %v — skipped", peerID, entityID, err)
				}
				return true
			}
			if !g.bytesBlind.Load() {
				g.sweepShipBytes += int64(len(prefixed))
			}
			if res.perFrame {
				ss.shipped++
				ss.entries++
				ss.foreignEnv++
				ss.foreignRecv++
				return true
			}
			// Mark a batch seen only after publication succeeds. Its decoded element
			// count was used by costOf and is the count reported to the receiver.
			seenBatch[batchRelayKey{originNodeID: entry.OriginNodeID, originSeq: res.originSeq}] = true
			ss.shipped++
			ss.entries += res.count
			ss.foreignEnv++
			ss.foreignRecv += res.count
			return true
		}
		payload, ok := g.cache.lookup(entityID, entry.Dot())
		if !ok {
			// A commit in flight can make the state visible before its payload is
			// recorded. With no commit pending, the entry is orphaned and cannot ship.
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
		selfShip = append(selfShip, BuiltEvent{EntityID: entityID, Payload: payload, Entry: entry})
		return true
	})
	// Sort by dot counter so the receiver observes each prefix in order. The
	// negative control skips this sort to exercise unordered-arrival handling.
	if !g.disableShipOrderBugInject.Load() {
		slices.SortFunc(selfShip, func(a, b BuiltEvent) int {
			return cmp.Compare(a.Entry.DotCounter, b.Entry.DotCounter)
		})
	}
	for _, be := range selfShip {
		if ctx.Err() != nil {
			break
		}
		innerWire, err := eng.BuildCRDTDeltaEvent(be.EntityID, be.Payload, be.Entry)
		if err != nil {
			log.Printf("mesh: BuildCRDTDeltaEvent %s: %v — skipped", be.EntityID, err)
			continue
		}
		sig, err := identity.SignCRDTFrame(g.owner.Seed, innerWire)
		if err != nil {
			log.Printf("mesh: SignCRDTFrame %s: %v — skipped", be.EntityID, err)
			continue
		}
		var sigArr [attribution.OriginSigSize]byte
		copy(sigArr[:], sig)
		env := attribution.NewSignedRelayEnvelopeV3(
			innerWire, sigArr, be.Entry.DotCounter, be.Entry.OriginNodeID, nil)
		prefixed := receive.LengthPrefixFrame(env.Marshal())
		if err := g.peers.Publish(peerID, prefixed); err != nil {
			publishErrs++
			if !g.deferHandler || publishErrs <= g.effectiveMissLogCap() {
				log.Printf("mesh: Publish to %x for %s: %v — skipped", peerID, be.EntityID, err)
			}
			continue
		}
		if !g.bytesBlind.Load() {
			g.sweepShipBytes += int64(len(prefixed))
		}
		ss.shipped++
		ss.entries++
	}
	ss.pubErrs = publishErrs
	return ss
}

// SweepLoop runs AntiEntropySweep on each tick until ctx is cancelled. A
// non-positive tick uses the 100 ms default.
func (g *Gossiper) SweepLoop(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = 100 * time.Millisecond
	}
	// Optional phase jitter derives a node-specific offset on every entry, including
	// after restart. The warm timer expires at tick+offset, placing the first sweep
	// in [tick, 2*tick). Offsets spread nodes across a tick but need not be unique.
	var t *time.Ticker
	if g.sweepPhaseJitter {
		g.sweepPhaseDerives.Add(1)
		warm := time.NewTimer(tick + sweepPhaseOffset(g.owner.NodeID, tick))
		select {
		case <-ctx.Done():
			warm.Stop()
			return
		case <-warm.C:
			// Start the ticker before the first sweep so later ticks retain the warm
			// timer's epoch rather than incorporating the first sweep's duration.
			t = time.NewTicker(tick)
			g.sweepOnce(ctx)
		}
	} else {
		t = time.NewTicker(tick)
	}
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.sweepOnce(ctx)
		}
	}
}

// sweepOnce runs one sweep, records its diagnostics, and updates convergence state.
func (g *Gossiper) sweepOnce(ctx context.Context) {
	sweepStart := time.Now()
	st := g.AntiEntropySweep(ctx)
	st.durMs = time.Since(sweepStart).Milliseconds()
	// Log activity, including pending work and misses, and emit a periodic heartbeat
	// when all activity counters are zero.
	if st.shippedEnvelopes > 0 || st.payloadPending > 0 || st.payloadMisses > 0 || st.relayMisses > 0 || st.round%sweepHeartbeatRounds == 0 {
		// Stratified diagnostics cover the interval since the previous summary;
		// taking the snapshot resets that window.
		stratSuffix := ""
		if g.stratDiag != nil {
			self := RegionUnset
			if g.topology != nil {
				self = g.topology.SelfRegion()
			}
			ex, fb, dgNs := g.stratDiagSnapshotReset()
			stratSuffix = formatStratDiag(self, ex, fb, dgNs)
		}
		// Gate skips distinguish suppressed exchanges from an inactive peer set.
		gatedSuffix := ""
		if g.stratified {
			ovsLabel := "oversend="
			if g.deferHandler {
				// With defer handling, this counter records deferred peel failures.
				ovsLabel = "defer-peel="
			}
			gatedSuffix = fmt.Sprintf(" gated=%d %s%d drop=%d", g.digestGateSkips.Load(), ovsLabel, g.digestPeelOversends.Load(), g.digestRespondDropped.Load())
			if g.deferHandler {
				gatedSuffix += fmt.Sprintf(" defer=%d esc=%d", g.digestDefers.Load(), g.digestDeferEscalations.Load())
				gatedSuffix += fmt.Sprintf(" foreign_env=%d foreign_recv=%d", st.foreignEnvelopes, st.foreignReceived)
				if g.deferCrossover.Load() {
					gatedSuffix += fmt.Sprintf(" crossover=%d", g.digestCrossoverShips.Load())
				}
			}
			// Response bytes are cumulative; the exchange and response deltas below
			// cover only the interval since the previous summary. Atomic last-values
			// make the same interval available to the heartbeat handler.
			gatedSuffix += fmt.Sprintf(" fired=%d gated_sweep=%d ship_bytes=%d digest_req_bytes=%d resp_bytes=%d", st.firedPeers, st.gatedSkips, st.shippedBytes, st.digestReqBytes, g.digestRespondBytes.Load())
			doneNow, drainedNow := g.digestExchCompleted.Load(), g.digestExchDrained.Load()
			respNow := g.digestRespondBytes.Load()
			doneDelta, drainedDelta, respDelta := doneNow-g.prevExchCompleted, drainedNow-g.prevExchDrained, respNow-g.prevRespBytes
			g.prevExchCompleted, g.prevExchDrained, g.prevRespBytes = doneNow, drainedNow, respNow
			g.lastExchDone.Store(doneDelta)
			g.lastExchDrained.Store(drainedDelta)
			g.lastRespDelta.Store(respDelta)
			g.lastSweepRound.Store(int64(st.round))
			gatedSuffix += fmt.Sprintf(" exch_done=%d exch_drained=%d resp_delta=%d", doneDelta, drainedDelta, respDelta)
		}
		// Optional diagnostic suffixes reset their own reporting windows where noted.
		l0iSuffix := g.l0iSweepSuffix(&st)
		viewSuffix := ""
		if st.viewEligible > 0 {
			viewSuffix = fmt.Sprintf(" view_intra=%d/%d view_xor=%016x", st.viewDrawn, st.viewEligible, st.viewXor)
		}
		iblt2Suffix := g.iblt2SweepSuffix()
		log.Printf("mesh: sweep round=%d shipped_env=%d entries=%d misses=%d relay_misses=%d pending=%d dur_ms=%d slowest_ms=%d slowest_inter=%v%s%s%s%s%s",
			st.round, st.shippedEnvelopes, st.shippedEntries, st.payloadMisses, st.relayMisses, st.payloadPending, st.durMs, st.slowestPeerMs, st.slowestPeerInter, stratSuffix, gatedSuffix, viewSuffix, iblt2Suffix, l0iSuffix)
	}
	g.stampConvergence()
	if g.roundReporter != nil {
		g.roundReporter()
	}
}

// stampConvergence records the time and root when the sharded Merkle root is
// unchanged across two consecutive sweeps and differs from the last recorded
// converged root. Reading directly from shards avoids constructing a merged view.
// SweepLoop is the single writer of these fields.
func (g *Gossiper) stampConvergence() {
	curRoot := g.engine.MerkleRootFromShards()
	if curRoot == g.prevRoot && curRoot != g.lastConvergedRoot {
		g.lastConvergedAt = time.Now()
		g.lastConvergedRoot = curRoot
	}
	g.prevRoot = curRoot
}

// Converges returns the current sharded Merkle root when at least one peer is
// registered. It returns ErrNoPeers otherwise; it does not compare roots or
// establish stability by itself.
func (g *Gossiper) Converges() ([32]byte, error) {
	peers := g.peers.Peers()
	if len(peers) == 0 {
		return [32]byte{}, fmt.Errorf("mesh: Converges: %w", ErrNoPeers)
	}
	return g.engine.MerkleRootFromShards(), nil
}

// CurrentRoot returns the local node's current sharded Merkle root. Unlike
// Converges, it does not require peers.
func (g *Gossiper) CurrentRoot() [32]byte {
	return g.engine.MerkleRootFromShards()
}

// LastConvergedAt returns when the root last remained unchanged across two
// sweeps, or the zero time if no such stability has been recorded.
func (g *Gossiper) LastConvergedAt() time.Time { return g.lastConvergedAt }

// LastConvergedRoot returns the last root recorded as stable, or a zero root if
// no such stability has been recorded.
func (g *Gossiper) LastConvergedRoot() [32]byte { return g.lastConvergedRoot }

// ConvergenceLag returns the time since the last recorded stable root. It returns
// zero before any stability has been recorded; compare CurrentRoot with
// LastConvergedRoot to determine whether the current root still matches it.
func (g *Gossiper) ConvergenceLag() time.Duration {
	if g.lastConvergedAt.IsZero() {
		return 0
	}
	return time.Since(g.lastConvergedAt)
}
