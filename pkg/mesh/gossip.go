// Package mesh — gossip.go is the anti-entropy sweep that ships signed CRDT
// deltas to peers over the Day-1 TLS transport.
//
// THE SIGNED-ENVELOPE SEAM (load-bearing): gossip deltas do NOT skip the
// production gate stack. Each delta flows the production path the Day-2 prompt
// §0 mandates:
//
//	GenerateDelta(theirDigest).Entries(entityID, entry)
//	  -> buildCRDTDeltaEvent(entityID, payload, entry)        // pkg/sync/crdt_capnp_wire.go (NEW, promotes the test builder)
//	  -> identity.SignCRDTFrame(seed, innerWire)               // pkg/identity/eddsa_hedge.go:84 (hedged Ed25519)
//	  -> attribution.NewSignedRelayEnvelopeV3(inner, sig, dot, origin, nil) // envelope.go:315 (0-hop origin frame)
//	  -> receive.LengthPrefixFrame(env.Marshal())              // forward.go:104
//	  -> transport.TransmitTLSFrame(conn, prefixed)           // transport.go:142 (Day-1 copy-mode writer)
//	Receive (the FROZEN Day-1 sink):
//	  FrameReader.ReadFrame -> Receiver.HandleFrame -> Open -> Directory.Lookup -> VerifyCRDTFrame -> ApplyCRDTDeltaEvent
//
// The mesh routes deltas through the SAME signed-envelope + Ed25519 + join path
// the gate stack proves. An unauthenticated gossip wire (plaintext deltagram
// over TLS) would be a security regression vs that gate stack; it is forbidden
// (the in-process orchestrator's appendDeltagram/e.Join is a TEST-only wire,
// never ported). The per-delta SignCRDTFrame cost (~60.19 us @ 32c PROVEN)
// bounds the convergence round; if a 1000-delta sweep exceeds 10 rounds, that
// is an HONEST NEGATIVE recorded verbatim — Day 5 (batched deltas, one sig
// per N deltas) is the arithmetic unlock, NOT skipping the signature.
package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"hash/maphash"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/durability"
	"github.com/hr18vk/supremum/pkg/identity"
	"github.com/hr18vk/supremum/pkg/receive"
	eng "github.com/hr18vk/supremum/pkg/sync"
)

// payloadCache holds the payload bytes the origin published so the gossiper can
// put them on the wire alongside the engine's PayloadDigest (which
// ApplyCRDTDeltaEvent cross-validates as SHA-256(payload)). The engine discards
// payload after InsertLocal per the Join contract (Ruling 3) — so the mesh, not
// the engine, retains it. The cache keys on (entityID, dot) so each causal
// version carries its own payload; an overwrite of an entity re-inserts under a
// new, strictly-higher dot, so the old payload becomes unreachable and is
// garbage-collected lazily by sweepStampedDrops.
//
// CAPACITY DISCIPLINE: the cache is unbounded by intent for Day 2 (a 1000-event
// convergence gate does not need eviction). The Day-5 batched path and a
// production-sized cache (bounded map + LRU) are carry-forwards; the honest
// weakness is recorded in ADR-0007.
type payloadCache struct {
	mu sync.Mutex
	m  map[payloadKey]string
}

type payloadKey struct {
	entityID string
	dot      eng.CausalDot
}

func newPayloadCache() *payloadCache { return &payloadCache{m: make(map[payloadKey]string)} }

// record stores the payload for (entityID, dot).
func (c *payloadCache) record(entityID string, dot eng.CausalDot, payload string) {
	c.mu.Lock()
	c.m[payloadKey{entityID, dot}] = payload
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

// Gossiper drives the anti-entropy sweep. It owns the PeerSet, the payload
// cache, and the per-node signing identity. InsertLocalEvents is the wrappers
// callers use to both apply a delta locally and record its payload for gossip.
type Gossiper struct {
	peers   *PeerSet
	cache   *payloadCache
	owner   *NodeIdentity
	engine  *eng.DeltaCRDTEngine
	domains *identity.Directory

	// roundReporter is the gossip-round counter increment seam. It is nil by
	// default (the --selftest path and the cold-scrape gate construct a
	// Gossiper with no recorder, so the counter stays 0 as shipped); cmd wires
	// it to metrics.Recorder.IncGossipRound via SetRoundReporter so every
	// executed sweep round increments sovereign_gossip_rounds_total — the
	// datapath-restored signal the silicon partition harness reads (FACT 2).
	roundReporter func()

	// batchSize is the Day-5 batched-transport knob. A value > 1 switches
	// AntiEntropySweep's self-originated delta path from the per-frame shipDelta
	// (one Ed25519 per delta) to shipBatchedDelta (one Ed25519 per N deltas —
	// the arithmetic unlock). A value of 1 (the zero-value default) keeps the
	// per-frame path (back-compat; the relay/foreign path stays per-frame
	// regardless, per the self-origin boundary). Set via SetBatchSize from
	// cmd's --batch-size flag; clamped to [1, MaxBatchSize].
	batchSize int

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

	// bridge is the Day-8 write-through durability seam. It is nil by default
	// (the --selftest path and the in-memory research mode construct a Gossiper
	// with no bridge, so InsertLocalEvents takes the bare engine.InsertLocal
	// path — Day-7 back-compat, the silicon bench path UNTOUCHED). cmd wires it
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

	// stratified is the Day-29 STRATIFIED ANTI-ENTROPY knob (ADR-0034). A
	// zero-value false (the opt-IN default) keeps AntiEntropySweep byte-
	// identical to HEAD's oversend path (the existing TestTwoNodeConvergence +
	// partition teeth stay GREEN — T-STRUCE-OFF-IS-BYTE-IDENTICAL). A true
	// value (set via SetStratifiedAntiEntropy, wired from --stratified-anti-
	// entropy) switches the sweep to the M3 two-phase digest-exchange: per
	// peer, SEND the local StrataEstimator + the full local IBLT digest,
	// RECEIVE the peer's, then call GenerateDelta(remoteIBLT) (the M2 fix —
	// the FROZEN set-reconciliation primitive that subtracts the peer's
	// POPULATED IBLT; the broken GenerateDeltaStratified that subtracted an
	// EMPTY remote IBLT is DELETED) for a MINIMAL delta proportional to
	// |A−B| instead of the full set. The fallback to oversend on a digest
	// timeout / malformed digest / peel failure is the M5 honest path
	// (counted via stratifiedFallbackReporter — the 19th SSoT counter).
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
	// map (the §10 self-audit; the channel send itself is goroutine-safe).
	digestRecvMu sync.Mutex
	digestRecv   map[[16]byte]chan *peerDigest

	// stratifiedFallbackReporter is the M5 disclosure seam: it fires when the
	// digest-exchange phase falls back to oversend (digest timeout, malformed
	// digest, or GenerateDelta's peel failure at crdt.go:1603). It is nil by
	// default (the in-memory test path + the --selftest path construct a
	// Gossiper with no reporter); cmd wires it to the 19th SSoT counter
	// (StratifiedAntiEntropyFallback.Inc) via SetStratifiedFallbackReporter.
	// Nil-safe: a nil reporter leaves the fallback a silent oversend (the
	// convergence guarantee holds — the counter is the DISCLOSURE, not the
	// mechanism). The counter is the Law V number that lets the operator SEE
	// the mesh converging via oversend vs via the stratified cut.
	stratifiedFallbackReporter func()

	// digestWaitTimeout bounds the synchronous digest-exchange wait. The
	// sweep sends its estimator then blocks on the peer's estimator up to
	// this long; a timeout is the M5 fallback to oversend (NOT a convergence
	// break — the signed delta path is unchanged, the digest only selected
	// WHICH deltas to send). 500ms default (set via the test seam; the
	// production value is generous over a cross-AZ RTT, the honest cold-start
	// bound). A zero value means "no wait" — the sweep falls back to oversend
	// immediately, the byte-identical-when-OFF guard.
	digestWaitTimeout time.Duration

	// hybridSign is the Day-32 (ADR-0037) hybrid-SIGN opt-IN knob. A zero-value
	// false (the DEFAULT) keeps the self-originated delta path on the v1
	// BatchEnvelope (one Ed25519 per batch) — byte-identical Day-31 (NO hybrid
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
	// the Day-19/23 opt-IN discipline.
	hybridSign bool

	// topology is the Day-34 (ADR-0039) region-aware TopologyManager — the peer
	// registry keyed by [16]byte carrying a RegionTag per peer + the Select(ctx)
	// iteration source AntiEntropySweep calls when regionAware is ON. It is nil
	// by default (the opt-IN default — the --selftest path + the in-memory test
	// path + the cold-scrape gate construct a Gossiper with no topology, so
	// AntiEntropySweep takes the full-mesh peers.Peers() path = byte-identical
	// Day-33 — T-TOPO-OFF-IS-BYTE-IDENTICAL). cmd wires it via SetTopology when
	// --region-aware is set, so the sweep routes intra-region full-mesh +
	// inter-region fan-out-N (prefer cross-region, seeded-deterministic — the
	// O(log N) rounds convergence the blueprint names). Nil-safe (the
	// SetRoundReporter / SetHybridSign precedent): a nil topology + regionAware
	// false = the full-mesh path, byte-identical to HEAD. GUARD: read on the
	// SweepLoop's single-goroutine discipline; SetTopology is called once at
	// construction before the loop starts (the SetStratifiedAntiEntropy
	// precedent — single-writer-before-reader, race-free under the T-TOPO-RACE
	// discipline).
	topology *TopologyManager

	// interRegionReporter is the Day-34 M6 disclosure seam: it fires once per
	// inter-region envelope SHIPPED in the production sweep (every fan-out
	// selection that routes a delta to a CROSS-region peer). It is nil by default
	// (the in-memory test path + the --selftest path construct a Gossiper with no
	// reporter); cmd wires it to the 24th SSoT counter
	// (InterRegionEnvelopesShipped.Inc) via SetInterRegionReporter. Nil-safe: a
	// nil reporter leaves the inter-region ship silent (the convergence holds —
	// the counter is the DISCLOSURE, not the mechanism — the SetStratified-
	// FallbackReporter precedent). The counter is the Law V number that lets the
	// operator SEE the region-aware path is in USE (not just wired) — the
	// operator-visible proof the fan-out selector routed deltas cross-region.
	// Fires ONLY on the inter-region arm (intra-region full-mesh is the SAME-AZ
	// baseline, NOT a disclosure-worthy event — the disclosure is the CROSS-
	// region fan-out the blueprint's O(log N) convergence depends on).
	interRegionReporter func()

	// regionAware is the Day-34 (ADR-0039) region-aware opt-IN knob. A zero-value
	// false (the DEFAULT) keeps AntiEntropySweep on the full-mesh peers.Peers()
	// path — byte-identical Day-33 (the T-TOPO-OFF-IS-BYTE-IDENTICAL tooth). A
	// true value (set via SetRegionAware, wired from --region-aware) switches the
	// sweep's iteration source to topology.Select(ctx) (intra-region full-mesh +
	// inter-region fan-out-N). The knob is INDEPENDENT of topology != nil: BOTH
	// must be true (a topology set with regionAware false = the full-mesh path —
	// the operator can register region tags without arming the selector, the
	// honest "wire first, arm later" discipline). GUARD: read + written under
	// the SweepLoop's single-goroutine discipline (SetRegionAware is called once
	// at construction before the loop starts — the SetStratifiedAntiEntropy /
	// SetHybridSign precedent). opt-IN (NOT opt-OUT) per the Day-19/23 discipline.
	// Placed LAST so the 1-byte bool's trailing padding is absorbed (the
	// fieldalignment discipline — manual reorder, NOT -fix; the bool shares no
	// wasted padding with the 8-byte fields above).
	regionAware bool
}

// NewGossiper binds a mesh Gossiper to a PeerSet, the owner's signing identity,
// the engine (GenerateDigest/GenerateDelta source), and the identity Directory
// the receiver resolves origins through. The Directory is shared between the
// gossiper (which Registers peers) and the Receiver (which Lookups them); the
// gossiper populating it is the GAP-3 seam the receive path depends on.
func NewGossiper(peers *PeerSet, owner *NodeIdentity, engine *eng.DeltaCRDTEngine, dir *identity.Directory) *Gossiper {
	g := &Gossiper{
		peers:             peers,
		cache:             newPayloadCache(),
		owner:             owner,
		engine:            engine,
		domains:           dir,
		digestRecv:        make(map[[16]byte]chan *peerDigest),
		digestWaitTimeout: 500 * time.Millisecond, // generous over a cross-AZ RTT; the M5 fallback bound
	}
	// Bind the Gossiper as the PeerSet's Day-29 digest-exchange sink so the
	// readLoop's DispatchFrame routes a WireDigestMagic-tagged frame to
	// DeliverDigest (the sweep's per-peer blocking-receive producer). The
	// Gossiper satisfies digestSink; this is the mesh-internal seam that keeps
	// the digest OFF the FROZEN receive gate stack (M4 — a StrataEstimator is
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
// signal the silicon partition harness reads (FACT 2). It is nil-safe: a
// Gossiper with no reporter (the --selftest path, the cold-scrape gate) leaves
// roundReporter nil and SweepLoop's nil-guard makes the increment a no-op, so
// the counter stays 0 exactly as the Day-3 cold-scrape path shipped.
func (g *Gossiper) SetRoundReporter(fn func()) { g.roundReporter = fn }

// SetBridge binds the Day-8 write-through durability seam. cmd calls it after
// NewGossiper when --wal-path is set, so InsertLocalEvents routes through the
// bridge (InsertLocal → AppendMutation fsync) instead of bare
// engine.InsertLocal. A nil bridge (the default, and the --wal-path empty
// path) keeps the Day-7 in-memory origin path UNTOUCHED — durability is opt-in.
// The bridge's engine MUST be the same *eng.DeltaCRDTEngine the Gossiper
// already holds (cmd constructs the bridge around the recovered engine and
// hands that same engine to NewGossiper), so the bridge's PutLocal publishes
// to the exact HAMT the sweep reads.
func (g *Gossiper) SetBridge(b *durability.Bridge) { g.bridge = b }

// BridgeActive reports whether the durability Bridge is bound (g.bridge != nil).
// It is the honest corner of the ACK-before-durability guard in control.go
// handleInsert: a zero CausalDot only means "non-durable origin write" when
// the bridge is actually active. With no bridge (--wal-path empty, the in-
// memory Day-7 default), InsertLocalEvents returns a real non-zero dot via
// the bare engine.InsertLocal path, so the zero-dot branch is never taken. The
// guard is therefore conservative: it 503\'s only when durability was
// REQUESTED (--wal-path set) and the write failed to durably land.
func (g *Gossiper) BridgeActive() bool { return g.bridge != nil }

// SetBatchSize binds the Day-5 batched-transport knob. cmd calls it once after
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

// SetStratifiedAntiEntropy binds the Day-29 stratified-anti-entropy knob
// (ADR-0034). cmd calls it once after NewGossiper with the parsed
// --stratified-anti-entropy flag (default false). A false value (the zero-value
// default) keeps AntiEntropySweep byte-identical to HEAD's oversend path
// (T-STRUCE-OFF-IS-BYTE-IDENTICAL); a true value switches the sweep to the M3
// two-phase digest-exchange (send local SE + full IBLT digest, receive peer's,
// call GenerateDelta(remoteIBLT) for a minimal delta — the M2 fix; the broken
// GenerateDeltaStratified that subtracted an EMPTY remote IBLT is DELETED). It mirrors the
// SetBatchSize seam: set once at construction before the SweepLoop starts (the
// single-goroutine discipline makes the non-atomic write race-free; the field
// is not read off the sweep goroutine). opt-IN (NOT opt-OUT) per the Day-19/23
// precedent — opt-OUT would silently flip the existing test behavior; opt-IN
// keeps TestTwoNodeConvergence + partition teeth byte-identical by default.
func (g *Gossiper) SetStratifiedAntiEntropy(on bool) { g.stratified = on }

// Stratified reports whether the stratified anti-entropy digest-exchange is
// enabled (test/diagnostic accessor; the sweep reads it on every
// AntiEntropySweep to pick the digest-exchange vs oversend path).
func (g *Gossiper) Stratified() bool { return g.stratified }

// SetHybridSign binds the Day-32 (ADR-0037) hybrid-SIGN opt-IN knob. cmd calls
// it once after NewGossiper with the parsed --hybrid-sign flag (default false).
// A false value (the zero-value default) keeps the self-originated delta path on
// the v1 BatchEnvelope (one Ed25519 per batch) — byte-identical Day-31 (NO
// hybrid frame is produced; T-PQ-HYBRID-OFF-IS-BYTE-IDENTICAL). A true value
// switches shipBatchedDelta's self-originated path to ShipBatchHybrid (one
// Ed25519 + one ML-DSA-65 sig over the SAME 120-byte SHAKE256 pad, carried in a
// HybridEnvelope). It mirrors the SetStratifiedAntiEntropy seam: set once at
// construction before the SweepLoop starts (the single-goroutine discipline
// makes the non-atomic write race-free; the field is not read off the sweep
// goroutine). opt-IN (NOT opt-OUT) per the Day-19/23 opt-IN discipline.
//
// ARMED guard: SetHybridSign(true) on a Gossiper whose owner has NO PQ key
// (owner.PQPriv == nil — NewNodeIdentity, NOT NewNodeIdentityHybrid) is a
// misconfiguration: ShipBatchHybrid would fail at sign time (the PQ half has no
// signer). SetHybridSign DOES NOT mint the PQ key here (the key derivation is a
// constructor concern, NOT a flag side-effect — the deploy discipline Day-2
// named); the caller MUST construct the owner via NewNodeIdentityHybrid before
// arming. A misconfigured arm is caught at ShipBatchHybrid's nil-pqPriv guard
// (an honest error logged + the batch skipped, NOT a panic — the relay/foreign
// path + the v1 batch path are unaffected).
func (g *Gossiper) SetHybridSign(on bool) { g.hybridSign = on }

// HybridSign returns the configured hybrid-SIGN knob (test/diagnostic accessor;
// shipBatchedDelta reads it on every self-originated batch to pick the ship
// path — v1 BatchEnvelope vs HybridEnvelope).
func (g *Gossiper) HybridSign() bool { return g.hybridSign }

// SetStratifiedFallbackReporter binds the M5 disclosure seam (the 19th SSoT
// counter). cmd calls it once after NewGossiper with
// StratifiedAntiEntropyFallback.Inc so every digest-exchange fallback to
// oversend (timeout, malformed digest, peel failure at crdt.go:1603)
// increments sovereign_mesh_stratified_fallback_total — the Law V number that
// lets the operator SEE the mesh converging via oversend vs via the stratified
// cut. Nil-safe (the SetRoundReporter precedent): a Gossiper with no reporter
// (the --selftest path, the in-memory test path) leaves the fallback a silent
// oversend — the convergence guarantee holds, the counter is the DISCLOSURE.
func (g *Gossiper) SetStratifiedFallbackReporter(fn func()) { g.stratifiedFallbackReporter = fn }

// SetTopology binds the Day-34 (ADR-0039) region-aware TopologyManager. cmd
// calls it once after NewGossiper with the TopologyManager built from
// --self-region + the per-peer region tags parsed from --peers' addr@region
// suffixes (the SetRoundReporter / SetHybridSign precedent — a single-line
// setter after construction; NO constructor-arg change = NO existing-caller
// break). Nil is the honest default (a Gossiper with no topology takes the
// full-mesh peers.Peers() path = byte-identical Day-33 — T-TOPO-OFF-IS-BYTE-
// IDENTICAL). SetTopology alone does NOT arm the region-aware sweep — the
// regionAware knob must ALSO be true (the "wire first, arm later" discipline —
// an operator can register region tags without arming the selector).
// Single-writer-before-reader (the SetStratifiedAntiEntropy precedent).
func (g *Gossiper) SetTopology(t *TopologyManager) { g.topology = t }

// SetRegionAware arms the Day-34 (ADR-0039) region-aware sweep selector. cmd
// calls it once after NewGossiper with the parsed --region-aware flag (default
// false). A false value (the zero-value default) keeps AntiEntropySweep on the
// full-mesh peers.Peers() path — byte-identical Day-33 (the T-TOPO-OFF-IS-BYTE-
// IDENTICAL tooth); a true value switches the iteration source to
// topology.Select(ctx) (intra-region full-mesh + inter-region fan-out-N). The
// knob is INDEPENDENT of topology != nil: BOTH must be true (a topology set with
// regionAware false = the full-mesh path). opt-IN (NOT opt-OUT) per the
// Day-19/23/29/30/31/32 discipline. Single-writer-before-reader (the
// SetStratifiedAntiEntropy / SetHybridSign precedent).
func (g *Gossiper) SetRegionAware(on bool) { g.regionAware = on }

// RegionAware returns the configured region-aware knob (test/diagnostic
// accessor; AntiEntropySweep reads it on every sweep to pick the topology-
// Select vs full-mesh-Peers path).
func (g *Gossiper) RegionAware() bool { return g.regionAware }

// SetInterRegionReporter binds the Day-34 M6 disclosure seam (the 24th SSoT
// counter). cmd calls it once after NewGossiper with
// InterRegionEnvelopesShipped.Inc so every inter-region envelope shipped by the
// region-aware sweep (every fan-out selection that routed a delta to a CROSS-
// region peer) increments sovereign_mesh_inter_region_envelopes_total — the Law
// V number that lets the operator SEE the region-aware path is in USE (not just
// wired). Nil-safe (the SetStratifiedFallbackReporter precedent): a Gossiper
// with no reporter (the --selftest path, the in-memory test path, OR
// --region-aware=false) leaves the inter-region ship silent — the convergence
// guarantee holds, the counter is the DISCLOSURE. Fires ONLY on the inter-region
// arm (intra-region full-mesh is the SAME-AZ baseline, NOT disclosure-worthy).
func (g *Gossiper) SetInterRegionReporter(fn func()) { g.interRegionReporter = fn }

// SetDigestWaitTimeout binds the digest-exchange wait bound (test seam; the
// production default is 500ms in NewGossiper). A shorter value makes the M5
// fallback fire faster under a slow/stalled peer; a zero value forces the
// fallback immediately (the "no wait" degenerate path the byte-identical-OFF
// guard reduces to). The 2-node gate sets a short value (loopback RTT ~10us)
// so a missing digest falls back within the tick, NOT a 500ms stall.
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

// reportStratifiedFallback fires the M5 disclosure seam (the 19th SSoT counter)
// when the digest-exchange phase falls back to oversend. Nil-safe (the
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
// different "latest" for the same entry slice (the Day-6.5 FIX B root cause).
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
// route uses to report the originator-vs-peer boundary HONESTLY (Ruling 3):
//
//   - On the ORIGINATOR node (the node that InsertLocalEvents-ed the entry) the
//     payload survives in g.cache keyed by (entityID, dot); LatestPayload returns
//     (payload, true).
//   - On a PEER node that received the delta via gossip the payload was discarded
//     after the ReconstructEntry cross-check (crdt_reconstruct.go:346), so the
//     cache has NO entry for that dot; LatestPayload returns ("", false). The
//     peer's State().Get(entityID) still carries the PayloadDigest — the digest
//     survives, the value does NOT.
//
// The accessor READS the existing cache; it mounts NO new retention path. It
// finds the latest dot by scanning engine.State().Get(entityID) (hamt.go:170)
// for the entry with the maximum DotCounter (the most-recent write) and looks
// that dot up in the cache. A Get that reports the digest as if it were the
// value is a FABRICATION; this accessor is the seam that keeps the boundary
// visible (ADR-0011 §1.1, §5).
func (g *Gossiper) LatestPayload(entityID string) (payload string, ok bool) {
	entries := g.engine.State().Get(entityID) // crdt.go:1225 -> hamt.go:170
	latest, ok := selectLatestDot(entries)
	if !ok {
		return "", false
	}
	return g.cache.lookup(entityID, latest.Dot()) // gossip.go:78
}

// PayloadForDot looks up the cached payload for a SPECIFIC dot without
// re-scanning State(). It is the single-snapshot seam handleGet uses so the
// response's payload and digest derive from the SAME entry (no TOCTOU between
// scan and lookup). The cache is mutex-guarded (gossip.go:56), so a concurrent
// InsertLocalEvents cache.record is safe to race this lookup — no new data race
// is introduced (the §10 self-audit).
func (g *Gossiper) PayloadForDot(entityID string, dot eng.CausalDot) (string, bool) {
	return g.cache.lookup(entityID, dot) // gossip.go:78
}

// RegisterPeer registers a peer's CRDT-delta signing pubkey in the Directory
// (the GAP-3 receive-path seam: VerifyCRDTFrame resolves originNodeID -> pubkey
// via Directory.Lookup). It must be called for every peer before the mesh can
// accept that peer's deltas; the in-process gate and the production binary both
// call it at peer-config time.
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
	// discards payload after Join (Ruling 3), so for the gossiper to put it on
	// the wire later it caches it; and for that wire to PASS the integrity
	// check the engine entry's PayloadDigest MUST equal SHA-256(payload) by the
	// time InsertLocal stamps the dot. Deriving the digest HERE (from the same
	// payload the cache stores) makes digest and payload consistent by
	// construction — the publisher cannot desync them, which is the only
	// way the receive-side C6 tooth stays honest instead of a footgun.
	//
	// Day 8: when a durability bridge is set (--wal-path), route the origin
	// write through the bridge so the engine-STAMPED dot is fsync'd to the WAL
	// AFTER InsertLocal (the physical order, §6). The bridge's PutLocal does
	// the digest + InsertLocal + AppendMutation in the load-bearing order; the
	// payload cache.record stays AFTER the WAL append (same order as today, so
	// the cache and the durable log stay consistent). A WAL append error is
	// surfaced here as a zero CausalDot — the caller (control.go /v1/insert)
	// MUST treat a zero dot as a failed durable write and NOT ACK the client
	// (the ACK-before-durability contract). A nil bridge keeps the Day-7
	// in-memory path: digest + InsertLocal + cache, no WAL.
	if g.bridge != nil {
		dot, err := g.bridge.PutLocal(entityID, payload, entry)
		if err != nil {
			log.Printf("durability: WAL append failed for entity %s: %v (write NOT durable — surfacing as zero dot)", entityID, err)
			return eng.CausalDot{}
		}
		g.cache.record(entityID, dot, payload)
		return dot
	}
	dgst := sha256.Sum256([]byte(payload))
	entry.PayloadDigest = dgst
	dot := g.engine.InsertLocal(entityID, entry) // crdt.go:912 (stamps Dot/Origin)
	g.cache.record(entityID, dot, payload)
	return dot
}

// BatchItem is the batch-inject shape Gossiper.InsertLocalEventsBatch accepts
// (ADR-0044, Day 39). It is the per-entry triple the /v1/batch-insert path
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

// InsertLocalEventsBatch is the ADR-0044 (Day 39) batch insertion seam: it
// stages N events for the engine AND records their payloads for the gossiper, so
// a subsequent sweep can put the payloads on the wire alongside the engine's
// PayloadDigest. It is the /v1/batch-insert production path; InsertLocalEvents
// (above) stays byte-identical for /v1/insert. It mirrors InsertLocalEvents's
// two-branch structure: the durable path (g.bridge != nil) routes through
// Bridge.PutLocals (N × InsertLocal + ONE AppendMutations + ONE fsync); the
// in-memory path (g.bridge == nil, the --wal-path="" opt-in research mode) does
// N × bare engine.InsertLocal (Day-7 back-compat — the bridge-nil branch of
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
		dots, failedFrom, err = g.bridge.PutLocals(local)
		if err != nil {
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
		return dots, -1, nil
	}
	// In-memory research path (the --wal-path="" opt-in, NOT a silicon-gate
	// config per the Day-38 architectural ruling): byte-identical to
	// InsertLocalEvents's bridge-nil branch (gossip.go:637), looped. Bare
	// engine.InsertLocal mints a non-zero dot per item; no WAL, no fsync.
	dots = make([]eng.CausalDot, len(items))
	for i, it := range items {
		dgst := sha256.Sum256([]byte(it.Payload))
		it.Entry.PayloadDigest = dgst
		dot := g.engine.InsertLocal(it.EntityID, it.Entry) // crdt.go:965 (stamps Dot/Origin)
		g.cache.record(it.EntityID, dot, it.Payload)
		dots[i] = dot
	}
	return dots, -1, nil
}

// sweepState carries the per-sweep counters the gate and ADR read.
type sweepState struct {
	round            int
	shippedEnvelopes int
	shippedEntries   int
	payloadMisses    int
}

// AntiEntropySweep runs ONE round of the digest->delta->signed-envelope exchange
// against EVERY live peer (sorted by peerID for determinism — the chaos reference
// at partition.go:209 sorts the same way). For each peer:
//
//  1. localDigest := engine.GenerateDigest()                  // crdt.go:1696 (FROZEN)
//     ship the digest wire (MarshalIBLT) to the peer via a SIGNED control frame.
//     The peer's reader is the FROZEN HandleFrame sink; a digest frame is NOT a
//     CRDTDeltaEvent, so a direct HandleFrame would DropMalformed it. Day 2
//     therefore runs the digest-delta exchange over a SEPARATE control channel:
//     the Gossiper reads the peer's digest back directly via a synchronous RPC.
//     THE HONEST SIMPLIFICATION: to keep Day 2 a single atomic unit WITHOUT a
//     new control-plane wire protocol, AntiEntropySweep ships the FULL delta
//     (GenerateDelta against an EMPTY digest) to each peer every round. This is
//     the CRDT-correct oversend (Join is idempotent): every peer receives every
//     entry it lacks each round, converging in exactly ONE round when the
//     digest exchange would have taken several. It pays N*entries verify cost
//     instead of |d|*entries; Day 5's batched envelope amortizes that to one
//     sig per batch. The honest weakness (oversend vs digested) is in ADR-0007
//     and is the Day-3/Day-7 digest-exchange unlock.
//
//  2. For each (entityID, entry) the delta yields:
//     payload := cache.lookup(entityID, entry.Dot())
//     innerWire := engine.BuildCRDTDeltaEvent(entityID, payload, entry) // NEW wire seam
//     sig      := identity.SignCRDTFrame(owner.Seed, innerWire)          // hedged Ed25519
//     env      := attribution.NewSignedRelayEnvelopeV3(innerWire, sig, entry.DotCounter, entry.OriginNodeID, nil) // 0-hop origin
//     prefixed := receive.LengthPrefixFrame(env.Marshal())
//     peers.Publish(peerID, prefixed)                                   // Day-1 TransmitTLSFrame
//
// The peer's reader goroutine (Day 1's readLoop) reassembles the frame and runs
// the FROZEN HandleFrame gate stack, which calls ApplyCRDTDeltaEvent on the
// verified inner wire — convergence.
//
// NOTE on the digest exchange: the FULL-DELTA oversend is the Day-2 honest
// simplification. It is the SAME property the chaos roundtrip proves
// (idempotent Join converges), and it removes a NEW control-plane wire
// protocol from Day-2's atomic scope (a protocol that would itself need a
// signed control frame + a digest frame-type discriminator on the FROZEN
// HandleFrame sink). The digest exchange ships Day-3 (metrics carry the
// convergence-lag gauge that makes oversend-vs-digested measurable) and Day-7
// (the real cross-AZ bandwidth budget forces the digested sweep).
func (g *Gossiper) AntiEntropySweep(ctx context.Context) sweepState {
	st := sweepState{}
	// Day 34 (ADR-0039): the region-aware iteration-source swap. When
	// g.topology != nil AND g.regionAware (the OPT-IN — both must be true, the
	// "wire first, arm later" discipline), the iteration source is
	// g.topology.Select(ctx) (intra-region full-mesh + inter-region fan-out-N,
	// prefer cross-region, seeded-deterministic — the O(log N) rounds
	// convergence the blueprint names). Otherwise (the DEFAULT — topology nil OR
	// regionAware false), the iteration source is the full-mesh peers.Peers()
	// path — byte-identical Day-33 (T-TOPO-OFF-IS-BYTE-IDENTICAL). The per-peer
	// BODY (generateSweepDelta → the Day-29 digest-exchange → GenerateDelta →
	// the Day-5 batched ship) is BYTE-UNCHANGED by the swap — Select only
	// changes WHICH peers the body runs over, NOT the body itself. The wire
	// shape is byte-identical (the selector chooses WHICH peers to send the
	// SAME batch/digest/hybrid frames to, NOT a new frame shape — the Day-33
	// fuzz harness stays load-bearing without re-work, M5).
	var peerIDs [][16]byte
	regionArmed := g.topology != nil && g.regionAware
	if regionArmed {
		peerIDs = g.topology.Select(ctx)
	} else {
		peerIDs = g.peers.Peers()
	}
	if len(peerIDs) == 0 {
		return st
	}
	// The sort.Slice runs ONLY on the full-mesh path (the selector's output is
	// already deterministically ordered — intra-first then inter-fan-out; the
	// Day-34 topology path SKIPS the sort for the intra subset + the inter
	// fan-out is randomized under the seed, NOT sorted — the epidemic-spreading
	// property). Backward-compat: the full-mesh path keeps the sort (byte-
	// identical Day-33 — the sort is the existing determinism the chaos
	// partition teeth depend on).
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
	st.round = 1
	for _, peerID := range peerIDs {
		if ctx.Err() != nil {
			return st
		}
		// Day 34 (ADR-0039) M6: the inter-region disclosure counter fires once
		// per inter-region envelope SHIPPED in the region-aware path (every
		// fan-out selection that routed a delta to a CROSS-region peer). It is
		// the operator-VISIBLE proof the region-aware path is in USE (not just
		// wired) — the Law V number that lets the operator SEE the fan-out
		// selector routed deltas cross-region. Fires ONLY on the inter-region
		// arm (intra-region full-mesh is the SAME-AZ baseline, NOT disclosure-
		// worthy — the disclosure is the CROSS-region fan-out the blueprint's
		// O(log N) convergence depends on); fires ONLY when regionArmed (the
		// full-mesh path has no inter-region arm — every peer is SAME-region by
		// the sameRegion-default-to-true discipline). Nil-safe (the
		// SetStratifiedFallbackReporter precedent): a nil reporter leaves the
		// inter-region ship silent. The fire is BEFORE the per-peer body so a
		// body that falls back to oversend (the M5 stratified fallback) STILL
		// discloses the inter-region routing — the counter counts the SELECTION,
		// not the delta shape.
		if regionArmed && g.interRegionReporter != nil && g.topology.IsInterRegion(peerID) {
			g.interRegionReporter()
		}
		// Day-29 stratified anti-entropy (ADR-0034): when --stratified-anti-
		// entropy is ON, the sweep runs the M3 two-phase digest-exchange per
		// peer — SEND the local StrataEstimator + the full local IBLT digest,
		// RECEIVE the peer's, then call GenerateDelta(remoteIBLT) (the M2 fix —
		// the FROZEN set-reconciliation primitive that subtracts the peer's
		// POPULATED IBLT; the broken GenerateDeltaStratified that subtracted an
		// EMPTY remote IBLT is DELETED) for a MINIMAL delta proportional to
		// |A−B| (the honest diff) instead of the full set. When OFF (the opt-IN
		// default), the sweep is byte-identical to HEAD's oversend path
		// (GenerateDelta against an empty IBLT — the Day-2 honest
		// simplification; T-STRUCE-OFF-IS-BYTE-IDENTICAL).
		//
		// The digest-exchange is a NEW phase BEFORE the per-peer GenerateDelta
		// (M3 — NOT a per-frame inline). The naive "call
		// GenerateDelta(LOCAL IBLT)" is a no-op (self-diff → empty diff → never
		// converges); the remote IBLT MUST come from the peer (the wiring's VALUE
		// is the digest exchange, not the primitive call). The fallback to oversend
		// on a digest timeout /
		// malformed digest / peel failure is the M5 honest path (counted via
		// reportStratifiedFallback — the 19th SSoT counter).
		delta := g.generateSweepDelta(ctx, peerID)
		// Day-5 batched transport: when --batch-size > 1, the self-originated
		// delta path ships N deltas per ONE Ed25519 signature (the arithmetic
		// unlock — 60.19us amortized to 60.19/N us/delta). When --batch-size ==
		// 1 (the zero-value default), the per-frame shipDelta path is retained
		// (one Ed25519 per delta — back-compat + the relay/foreign path, which
		// stays per-frame regardless per the self-origin boundary).
		//
		// Day 32 (ADR-0037): --hybrid-sign FORCES the shipBatchedDelta path even
		// when --batch-size <= 1. The hybrid frame (HybridEnvelope) is a BATCH
		// shape — it carries the marshaled CRDTDeltaBatch wire (BuildCRDTDeltaBatch)
		// + BOTH sigs amortized over the N deltas. A per-frame hybrid would sign
		// the 120-byte pad of a ONE-delta "batch" per frame (no amortization —
		// the 585.8us ML-DSA-65 SIGN per delta, NOT per batch — the SIGN cost; the
		// 73.7us number is the ML-DSA-65 VERIFY bench, a different operation);
		// the batch is the load-bearing shape the hybrid amortization depends
		// on, so --hybrid-sign implies the batch path. When g.hybridSign is true, shipBatchedDelta
		// routes to ShipBatchHybrid (the hybrid envelope); when false, it routes
		// to the v1 ShipBatch (byte-identical Day-31). A batchSize of 0 (the
		// zero-value default — the harness + a node that did NOT pass
		// --batch-size) is clamped to DefaultBatchSize inside shipBatchedDelta,
		// so --hybrid-sign with the default batch size ships DefaultBatchSize
		// deltas per hybrid frame (the honest amortization, NOT 1-delta frames).
		// The relay/foreign path (the hops>0 branch above) stays per-frame
		// regardless (the self-origin boundary — a relayer CANNOT re-origin-sign
		// a foreign delta under EITHER sig).
		var shipped, entries, misses int
		if g.batchSize > 1 || g.hybridSign {
			shipped, entries, misses = g.shipBatchedDelta(ctx, peerID, delta, g.batchSize)
		} else {
			shipped, entries, misses = g.shipDelta(ctx, peerID, delta)
		}
		delta.Release() // CRDTDelta.Release — EBR epoch pin drop (crdt.go:1367)
		st.shippedEnvelopes += shipped
		st.shippedEntries += entries
		st.payloadMisses += misses
	}
	return st
}

// generateSweepDelta produces the per-peer delta for one sweep round. When
// stratified anti-entropy is OFF (the opt-IN default) it is byte-identical to
// HEAD's oversend path: GenerateDelta against an empty IBLT yields every entry
// (the peel falls back to "send everything" when the diff is nil — the Day-2
// honest simplification). When ON it runs the M3 two-phase digest-exchange:
// register the per-peer recv channel, marshal + send the local
// StrataEstimator + the full local IBLT digest, block on the peer's digest
// (bounded by digestWaitTimeout), then call GenerateDelta(remoteIBLT) (the M2
// fix — the FROZEN set-reconciliation primitive that subtracts the peer's
// POPULATED IBLT; the broken GenerateDeltaStratified that subtracted an EMPTY
// remote IBLT is DELETED) for a minimal delta. On a digest
// timeout / malformed digest / nil receive it falls back to the oversend path
// + reports the M5 fallback (the 19th SSoT counter). The returned *CRDTDelta is
// the SAME type shipDelta/shipBatchedDelta consume (wire-zero — no new wire
// format on the delta path; the digest frame is a SEPARATE wire shape that
// never touches the FROZEN envelope).
//
// GUARD: this runs on the SweepLoop's single-goroutine discipline (one sweep
// at a time), so the per-peer channel register/send/receive is race-free; the
// producer (DeliverDigest) runs on the readLoop/serveConn goroutine and is
// serialized against this only by the digestRecvMu (the channel send itself is
// goroutine-safe). The EBR pin in GenerateDelta (crdt.go:1736) is the SAME pin
// the deleted stratified sibling used — already -race-proven (T-STRUCE-RACE).
func (g *Gossiper) generateSweepDelta(ctx context.Context, peerID [16]byte) *eng.CRDTDelta {
	if !g.stratified {
		// OFF: byte-identical HEAD oversend (T-STRUCE-OFF-IS-BYTE-IDENTICAL).
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest) // crdt.go:1603 (FROZEN)
	}
	// ON: the M3 two-phase digest-exchange (the M2-FIXED shape — the
	// Architect's Amendment). The digest frame carries BOTH the local
	// StrataEstimator (the dEst sizing hint) AND the local FULL IBLT digest
	// (the POPULATED remote IBLT the peer's `GenerateDelta` subtracts). The
	// pre-M2 draft carried ONLY the SE — the broken `GenerateDeltaStratified`
	// it delegated to subtracted an EMPTY IBLT every round = byte-identical to
	// oversend (the M2 refutation; the deleted primitive's body — documented in
	// the crdt.go:1920 tombstone — created remoteIBLT then NEVER populated it).
	// The amendment KILLS `GenerateDeltaStratified` + has the
	// wiring call `GenerateDelta(remoteIBLT)` (crdt.go:1603, the FROZEN CORRECT
	// set-reconciliation primitive) with the peer's FULL IBLT from the wire.
	// Phase i — register the per-peer recv channel (drains a stale peerDigest
	// from a prior round so the receive starts clean), then build + send the
	// local digest frame (SE + full IBLT) to this peer over the peer-TLS
	// data-plane (the WireDigestMagic-tagged frame the peer's readLoop routes
	// to ITS digestSink).
	recvCh := g.registerDigestRecv(peerID)
	// The send-side seed: a fresh maphash.MakeSeed() per round (the
	// GenerateDigest precedent at crdt.go:1821). The seed travels in the
	// strata wire header (MarshalStrataEstimator stamps se.Seed()) AND is
	// stamped into the local IBLT (GenerateDigestWithSeed takes the seed); the
	// RECEIVER's `GenerateDelta` rebuilds its OWN local IBLT with THIS seed
	// (GenerateDigestWithSeed at crdt.go:1836), so the local + remote IBLTs
	// hash keys identically before the subtract. A fresh seed per round keeps
	// each round's digest independent (a replayed digest from a prior round
	// subtracts against a different seed → the peel fails → the M5 fallback
	// to oversend, the honest path, never a convergence break).
	seed := maphash.MakeSeed()
	localSE := g.engine.GenerateStrataEstimator(seed) // crdt.go:1890 (the dEst hint)
	// The FULL local digest — the M2 load-bearing field. Built via
	// GenerateDigestWithSeed (crdt.go:1836, the FIXED 1024-bucket digest) so
	// its bucket count MATCHES the local digest GenerateDelta builds
	// internally (crdt.go:1610 — GenerateDelta's local is also 1024 via
	// GenerateDigestWithSeed(remote.Seed())); Subtract requires identical
	// bucket counts (iblt.go:377) else diff==nil → the oversend fallback. The
	// 1024-bucket digest is peelable up to ~700 keys (the IBLT load-factor
	// threshold); above that the digest saturates + GenerateDelta falls back
	// to oversend (the honest physical limit of the FROZEN GenerateDelta's
	// FIXED local-digest sizing — disclosed in T-STRUCE-WIRE-COST + ADR-0034;
	// the dEst-sized dynamic digest that lifts the limit is a SEPARATE fork
	// that unfreezes GenerateDelta's local-digest builder, NOT this one).
	localIBLT := g.engine.GenerateDigestWithSeed(seed)      // crdt.go:1836 (the FULL local digest; matches GenerateDelta's local at 1024)
	marshaledSE, err := eng.MarshalStrataEstimator(localSE) // iblt_wire.go (NEW)
	if err != nil {
		// Marshal failure is the M5 fallback (a nil local estimator is a
		// protocol violation; the honest path is oversend, never a crash).
		localIBLT.Release()
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	marshaledIBLT, err := eng.MarshalIBLT(localIBLT) // iblt_wire.go (the full local digest on the wire)
	localIBLT.Release()
	if err != nil {
		// IBLT marshal failure: M5 fallback (the SE alone is unusable — the
		// remote IBLT is the load-bearing subtract operand).
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	digestFrame := buildDigestFrame(g.owner.NodeID, marshaledSE, marshaledIBLT) // digest.go (the WireDigestMagic tag + senderID + SE + IBLT)
	prefixed := receive.LengthPrefixFrame(digestFrame)
	if err := g.peers.Publish(peerID, prefixed); err != nil {
		// Publish failure (peer dropped mid-round): M5 fallback to oversend.
		// The convergence holds — the next round re-dials + re-exchanges.
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	// Phase ii — block on the peer's digest (SE + IBLT), bounded by
	// digestWaitTimeout. A nil IBLT (DeliverDigest on a malformed digest) OR a
	// timeout is the M5 fallback to oversend (the convergence guarantee holds —
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
		// Timeout: M5 fallback. The peer did not return its digest within the
		// bound — oversend converges it this round (CRDT-idempotent Join).
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	if remotePD == nil || remotePD.iblt == nil {
		// Malformed digest (DeliverDigest delivered a nil-IBLT peerDigest) or
		// a truncated frame: M5 fallback. (remotePD.se may be non-nil for a
		// diagnostic, but a nil IBLT is the load-bearing M5 trigger — the SE
		// alone cannot drive the subtract.)
		g.reportStratifiedFallback()
		emptyDigest := eng.NewIBLT(1, 4)
		return g.engine.GenerateDelta(emptyDigest)
	}
	// GenerateDelta(remoteIBLT): the FROZEN CORRECT set-reconciliation primitive
	// (crdt.go:1603). It builds the LOCAL IBLT (GenerateDigestWithSeed at
	// :1610, POPULATED with this node's keys) + subtracts the POPULATED
	// remoteIBLT (the peer's full digest from the wire) at :1615, then peels
	// the real diff → ships ONLY the |A−B| keys (the bandwidth cut, M2 FOR
	// REAL). Its peel-failure fallback (crdt.go:1679 — diff==nil || peelErr!=nil)
	// yields EVERY entry on a peel failure = FULL oversend-equivalent (NEVER
	// nil/empty), so the delta is ALWAYS a convergence-sufficient superset (M2
	// — the diff is a strict subset of oversend; Join is MERGE-UNION, FROZEN
	// crdt.go:1089). The D2 participant-pool recycle is already on this path
	// (crdt.go:1736 — the FROZEN primitive always set participantPoolPtr; the
	// leak was ONLY on the now-killed stratified sibling).
	return g.engine.GenerateDelta(remotePD.iblt) // crdt.go:1603 (FROZEN, CORRECT — the M2 fix)
}

// shipDelta iterates delta.Entries, builds the signed envelope for each, and
// publishes it to peerID. It returns per-delta counters. A payload miss skips
// that entry (logged, never panicked); the receiver would DropVerify a
// mismatched payload, so skipping is the honest choice, not a fabrication.
func (g *Gossiper) shipDelta(ctx context.Context, peerID [16]byte, delta *eng.CRDTDelta) (shipped, entries, misses int) {
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
		if err := g.peers.Publish(peerID, prefixed); err != nil { // Day-1 TransmitTLSFrame
			log.Printf("mesh: Publish to %x for %s: %v — skipped", peerID, entityID, err)
			return true
		}
		shipped++
		return true
	})
	return shipped, entries, misses
}

// SweepLoop runs AntiEntropySweep on the gossip ticker until ctx is done. The
// tick is the --gossip-tick knob; 100ms is the steady-state default, 50ms is the
// Day-4 heal-control-plane override (C2 two-knob discipline — one knob, two
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
			if st.shippedEnvelopes > 0 {
				log.Printf("mesh: sweep round=%d shipped_env=%d entries=%d misses=%d",
					st.round, st.shippedEnvelopes, st.shippedEntries, st.payloadMisses)
			}
			// Seed the convergence-lag gauge after the sweep. The lag
			// (time.Since(lastConvergedAt)) is read off the hot path by the
			// 1s poller; this is the single writer.
			g.stampConvergence()
			// Increment the gossip-round counter for the silicon telemetry path
			// (FACT 2: the first increment after datapath restore = the first
			// successful gossip round). Nil-guarded: the --selftest path and the
			// cold-scrape gate run with no reporter, so the counter stays 0 as
			// the Day-3 scrape path shipped.
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
// Day 37 (ADR-0042): switched from State().MerkleRoot() to
// MerkleRootFromShards(). State() builds a FULL MERGED HAMT view duplicating
// every live entry into arena nodes that reclaim only on EBR epoch advance —
// at 100 nodes × 10K keys the merged views pile up faster than
// maybeAdvanceEpoch reclaims them → HamtArena OOM (hamt_arena.go:638).
// MerkleRootFromShards() computes the BYTE-IDENTICAL root directly from the
// per-shard root HAMTs with NO merged view (zero arena growth) and an EBR
// participant pin (formally race-free, strictly stronger than State's grace
// window). See pkg/sync/merkle_sharded.go. The convergence-lag logic
// (prevRoot compare, lastConvergedRoot stamp) is UNCHANGED — only the root's
// source switched.
func (g *Gossiper) stampConvergence() {
	curRoot := g.engine.MerkleRootFromShards() // Day 37 ADR-0042 — merkle_sharded.go (byte-identical to State().MerkleRoot(), no merged-view OOM)
	if curRoot == g.prevRoot && curRoot != g.lastConvergedRoot {
		g.lastConvergedAt = time.Now()
		g.lastConvergedRoot = curRoot
	}
	g.prevRoot = curRoot
}

// Converges reports whether the engine's MerkleRoot is stable across a sweep
// (the in-process gate uses a direct MerkleRoot compare instead; this helper is
// for the silicon telemetry path). Day 37 (ADR-0042): switched to
// MerkleRootFromShards (byte-identical to State().MerkleRoot(), no merged-view
// OOM at 100×10K — see pkg/sync/merkle_sharded.go).
func (g *Gossiper) Converges() ([32]byte, error) {
	peers := g.peers.Peers()
	if len(peers) == 0 {
		return [32]byte{}, fmt.Errorf("mesh: Converges: %w", ErrNoPeers)
	}
	return g.engine.MerkleRootFromShards(), nil // Day 37 ADR-0042 — merkle_sharded.go
}

// CurrentRoot returns the engine's current MerkleRoot (the local node's view).
// It is the roots-equal gauge feeder: the 1s poller compares it to
// LastConvergedRoot to set sovereign_convergence_roots_equal (1.0 match, 0.0
// diverged). Unlike Converges it does NOT require peers (a single-node mesh
// still has a local root the gauge reads). Day 37 (ADR-0042): switched to
// MerkleRootFromShards — the gauge was the 4th OOM site (it polled State()
// every second, same merged-view pile-up as stampConvergence at 100×10K).
func (g *Gossiper) CurrentRoot() [32]byte {
	return g.engine.MerkleRootFromShards() // Day 37 ADR-0042 — merkle_sharded.go (byte-identical, no OOM)
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
