// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// This test-only control, when enabled via the jitter determinism test
// environment variable, mixes time.Now() into the intra-view seed chain,
// introducing non-determinism. This causes two independent manager builds to
// draw different views, which deterministic cross-build checks catch by
// asserting 16-round cross-build identity. The phase is a deterministic pure
// function of (nodeID, tick), so a phase mix cannot trigger the fault — the
// threat is clock or build-varying state in the seed chain.
var selectSeedClockMixBugInject atomic.Bool

// topology.go implements the TopologyManager (ADR-0039) — the peer registry
// keyed by [16]byte carrying a RegionTag per peer, plus the Select(ctx)
// iteration source that AntiEntropySweep calls when --region-aware is enabled.
// Select returns intra-region peers (full mesh — all peers with the same region
// as SelfRegion) and inter-region peers (fan-out N, prefer cross-region, random
// tie-break under a seeded rand — the epidemic-spreading property). The
// selector is deterministic under the seed: same seed yields the same Select
// output every run (the fuzz-seed discipline from ADR-0028; a flaky selector
// violates Law IV).
//
// The TopologyManager is a new seam that does not change PeerSet.Peers() (the
// full-mesh list remains the backward-compatibility path when the topology
// selector is off — byte-identical to the previous behavior). It is set on the
// Gossiper via SetTopology after construction (following the SetDigestSink,
// SetRoundReporter, and SetHybridSign precedent — a single-line setter after
// NewGossiper; no constructor-argument change means no existing-caller break).
// Nil by default means the full-mesh Peers() path, byte-identical to the
// previous behavior (the topology-off baseline control).
//
// CONCURRENCY: the TopologyManager is single-writer-before-reader (SetRegion
// registrations happen at boot before the SweepLoop starts; Select reads happen
// on the SweepLoop's single goroutine — the SetDigestSink discipline from
// ADR-0034). The RWMutex guards the peer-regions map; Select takes the RLock
// for the registry snapshot, then runs the seeded rand goroutine-local (the
// rand is not shared across goroutines, so the non-atomic read is race-free —
// the topology-race negative control). A future change that adds live region
// re-tagging (peers migrating regions at runtime) would extend the mutex
// discipline — not this scope.
type TopologyManager struct {
	// regions maps peerID -> RegionTag. A peer not in the map is RegionUnset
	// (the conservative default: an untagged peer routes as same-region as the
	// self-region, so the fan-out selector never accidentally drops a local peer
	// from the full mesh; a peer with no region tag is a local peer, not a
	// foreign peer). Set via SetRegion at boot.
	regions map[[16]byte]RegionTag
	// gateways maps explicitly designated peerID -> true (set by
	// applyProvisioning in --peer-dir file order or by unit tests via SetGateway).
	gateways map[[16]byte]bool
	// effectiveGateways holds the resolved gateway peerIDs (explicit gateways
	// when explicitPeerGateways is true, else the lowest g sorted nodeIDs per
	// region). Rebuilt under t.mu.Lock() so Select and ShouldDialPeer read it
	// under RLock with 0 allocations.
	effectiveGateways map[[16]byte]bool
	// peerLiveness reports whether a gateway peer is live, challenge-verified,
	// and free of active timeout/publish deferral streaks.
	peerLiveness func([16]byte) bool
	// sortedIntraPeers caches the sorted intra-region peers when
	// gatewaysPerRegion > 0 so Select(ctx) copies it in 1 allocation with
	// 0 O(n^2) per-sweep sorts.
	sortedIntraPeers [][16]byte
	// foreignRegions and foreignGatewaysByRegion cache the sorted distinct
	// foreign region tags and each foreign region's sorted gateway peerIDs so
	// Select(ctx) picks live foreign gateways with 0 map allocations.
	foreignRegions          []RegionTag
	foreignGatewaysByRegion [][][16]byte
	mu                      sync.RWMutex
	// seed is the per-sweep seed for the inter-region fan-out tie-break. The
	// seeded rand is deterministic under the seed; the sweep round number is
	// the natural per-sweep seed so the selection varies across rounds but is
	// reproducible per round. Set via SetSeed before each Select call (the
	// SweepLoop stamps the round number into the seed before the sweep).
	seed uint64
	// fanout is the inter-region fan-out N (default 3 — O(log N) rounds to
	// convergence at fan-out 3). Set via SetFanout at boot; clamped to
	// [0, MaxFanout]. 0 = intra-region full mesh only (no inter-region fan-out
	// — the degenerate case where fan-out 0 yields intra-only).
	fanout int
	// gatewaysPerRegion is the hierarchical gateway count g per region
	// (--gateways-per-region; default 0 = off, byte-identical; when > 0,
	// clamped to [1, MaxFanout]).
	gatewaysPerRegion int
	// viewDrawn, viewEligible, and viewXor are the last draw's observability
	// stats — the armed `sweep round=` line's view_intra= and view_xor= tokens
	// (the additive name=value discipline; not an SSoT counter — the registry
	// is hard-pinned). Written by drawIntraView under the lock (once per sweep,
	// the sweep goroutine), read via LastIntraView right after Select.
	viewDrawn    int
	viewEligible int
	viewXor      uint64
	// starveViewPeer (test-only) allows tests to exclude that peer from every intra view
	// this manager draws — the permanently-directed pair that must reproduce the
	// permanent digest-fire. The zero value is the production path (a real nodeID
	// is never all-zero); set via StarveViewPeerOf before the sweeps it must
	// starve (single-writer-before-reader, the SetRegion discipline).
	starveViewPeer [16]byte
	// selfNodeID is this node's own [16]byte identity (set via SetSelfNodeID
	// when hasSelfNodeID is true).
	selfNodeID [16]byte
	// These test-only controls disable the interior-cut and liveness-failover
	// bug injections deterministically (for the hierarchical gateway tests).
	// (test-only) are the deterministic fault-injection controls for the
	// hierarchical gateway tests.
	disableGatewayInteriorCutBugInject      atomic.Bool
	disableGatewayLivenessFailoverBugInject atomic.Bool
	// partialIntraView arms the partial intra view: when true, Select slices
	// the intra set to the rotating min(intraViewSize, n_r-1) subset before
	// the inter fan-out is appended. The zero-value
	// false is the byte-identical full intra mesh. Set via SetPartialIntraView
	// (the Gossiper forwards; cmd wires from --partial-intra-view under the
	// --region-aware orphan guard).
	partialIntraView bool
	// selfRegion is the node's own region tag (the intra/inter split key:
	// peers with the same region are intra = full mesh; peers with a different
	// region are inter = fan-out candidates). A RegionUnset (0) self-region
	// makes every peer intra-region (sameRegion returns true for RegionUnset
	// on either side) = byte-identical to the full-mesh path. Placed last so
	// the 1-byte tag shares no wasted padding with the 8-byte fields above
	// (the fieldalignment discipline — manual reorder, not -fix; the 1-byte
	// tag's trailing padding is not counted toward the struct's useful size).
	selfRegion             RegionTag
	selfGateway            bool
	effectiveSelfGateway   bool
	hasExplicitSelfGateway bool
	explicitPeerGateways   bool
	hasSelfNodeID          bool
}

// MaxFanout is the upper bound on the inter-region fan-out N. The default 3
// yields O(log_3 N) rounds to convergence; a larger fan-out converges faster
// but uses more per-sweep bandwidth (the trade-off the operator dials). 16 is
// a generous ceiling (a 16-fan-out at 100 nodes = 16 inter-region connections
// per sweep per node — still far below the full-mesh 10,000).
const MaxFanout = 16

// DefaultRegionFanout is the default inter-region fan-out N. 3 yields
// O(log_3 100) ≈ 4-5 rounds to convergence at 100 nodes — the loopback gate
// the topology-round-count negative control measures. The operator overrides
// via --region-fanout; the default is the named value.
const DefaultRegionFanout = 3

// intraViewSize is the partial intra view's f. The research's smallest shape
// that clears the responder cap (8 slots originally; 16 = 2f in current engine) — the measured full-mesh intra term already exceeds it 4.1x at
// N=100 → 139x at N=3333. The responder cap rose 8 → 16 = 2f in the current engine — the cap-≥-2f law (a synchronized burst at the Poisson(8) in-degree
// mean saturates 8 slots with ~41% drops).
const intraViewSize = 8

// intraViewPCGStream is the intra view draw's domain-separation constant.
// The inter fan-out consumes rand.NewPCG(seed, 0) (newSeededRand below), so
// the intra view draws from rand.NewPCG(seed, intraViewPCGStream) — a
// distinct second PCG stream at the same seed (domain-separated so intra
// and inter never consume the identical stream at the identical seed). Any non-zero
// value suffices; this one is fixed forever (changing it silently re-draws
// every deployed view — a rotation break, wire-invisible but real).
const intraViewPCGStream = 0x1D5EED5EEDB5EED

// NewTopologyManager constructs a TopologyManager with the node's own region
// tag and the default fan-out. The self-region is the intra/inter split key:
// peers with the same region are intra = full mesh; peers with a different
// region are inter = fan-out candidates. A self-region of RegionUnset (the
// default when --self-region is not set) makes every peer intra-region
// (sameRegion returns true for RegionUnset on either side) = byte-identical
// to the full-mesh path — the zero-value default.
func NewTopologyManager(selfRegion RegionTag) *TopologyManager {
	return &TopologyManager{
		selfRegion: selfRegion,
		regions:    make(map[[16]byte]RegionTag),
		fanout:     DefaultRegionFanout,
	}
}

// SetRegion registers a peer's region tag (called at boot for each configured
// peer, before the SweepLoop starts). A peer not registered is RegionUnset
// (routes as same-region = intra). Idempotent (re-registering a peer
// overwrites the tag — the live-re-tagging discipline a future change would
// extend). Single-writer-before-reader (the SetDigestSink discipline from
// ADR-0034).
func (t *TopologyManager) SetRegion(peerID [16]byte, region RegionTag) {
	t.mu.Lock()
	t.regions[peerID] = region
	if t.gatewaysPerRegion > 0 {
		t.rebuildGatewayCacheLocked()
	}
	t.mu.Unlock()
}

// SetGatewaysPerRegion sets the regional gateway count g per region, clamped
// to [0, MaxFanout]. 0 = off (byte-identical full/flat mesh).
func (t *TopologyManager) SetGatewaysPerRegion(n int) {
	t.mu.Lock()
	if n <= 0 {
		t.gatewaysPerRegion = 0
	} else if n > MaxFanout {
		t.gatewaysPerRegion = MaxFanout
	} else {
		t.gatewaysPerRegion = n
	}
	t.rebuildGatewayCacheLocked()
	t.mu.Unlock()
}

// GatewaysPerRegion returns the configured gateway count g per region (0 = OFF).
func (t *TopologyManager) GatewaysPerRegion() int {
	t.mu.RLock()
	g := t.gatewaysPerRegion
	t.mu.RUnlock()
	return g
}

// SetSelfNodeID records this node's own [16]byte nodeID so fallback lowest-g
// gateway designation can compare selfNodeID against same-region peers without
// mistaking an unset zero [16]byte{} for a real nodeID.
func (t *TopologyManager) SetSelfNodeID(id [16]byte) {
	t.mu.Lock()
	t.selfNodeID = id
	t.hasSelfNodeID = (id != [16]byte{})
	if t.gatewaysPerRegion > 0 {
		t.rebuildGatewayCacheLocked()
	}
	t.mu.Unlock()
}

// SelfNodeID returns the configured selfNodeID.
func (t *TopologyManager) SelfNodeID() [16]byte {
	t.mu.RLock()
	id := t.selfNodeID
	t.mu.RUnlock()
	return id
}

// SetSelfGateway explicitly designates whether this node is a regional gateway
// (called by applyProvisioning in --peer-dir file order or by unit tests).
func (t *TopologyManager) SetSelfGateway(on bool) {
	t.mu.Lock()
	t.selfGateway = on
	t.hasExplicitSelfGateway = true
	if t.gatewaysPerRegion > 0 {
		t.rebuildGatewayCacheLocked()
	}
	t.mu.Unlock()
}

// IsSelfGateway reports whether this node is designated as a regional gateway.
func (t *TopologyManager) IsSelfGateway() bool {
	t.mu.RLock()
	on := t.isSelfGatewayLocked()
	t.mu.RUnlock()
	return on
}

func (t *TopologyManager) isSelfGatewayLocked() bool {
	if t.gatewaysPerRegion <= 0 {
		return false
	}
	return t.effectiveSelfGateway
}

// SetGateway explicitly designates whether peerID is a regional gateway
// (called by applyProvisioning in --peer-dir file order or by unit tests).
func (t *TopologyManager) SetGateway(peerID [16]byte, on bool) {
	t.mu.Lock()
	if t.gateways == nil {
		t.gateways = make(map[[16]byte]bool)
	}
	if on {
		t.gateways[peerID] = true
	} else {
		delete(t.gateways, peerID)
	}
	t.explicitPeerGateways = true
	if t.gatewaysPerRegion > 0 {
		t.rebuildGatewayCacheLocked()
	}
	t.mu.Unlock()
}

// IsGateway reports whether peerID is designated as a regional gateway.
func (t *TopologyManager) IsGateway(peerID [16]byte) bool {
	t.mu.RLock()
	on := t.isGatewayLocked(peerID)
	t.mu.RUnlock()
	return on
}

func (t *TopologyManager) isGatewayLocked(peerID [16]byte) bool {
	if t.gatewaysPerRegion <= 0 {
		return false
	}
	return t.effectiveGateways[peerID]
}

// SetPeerLiveness registers the liveness/health callback used for
// sibling-gateway intra pinning and foreign-gateway dead-gateway eviction.
func (t *TopologyManager) SetPeerLiveness(fn func([16]byte) bool) {
	t.mu.Lock()
	t.peerLiveness = fn
	t.mu.Unlock()
}

// ShouldDialPeer (connection-plane filter) reports whether this node should
// dial peerID at boot:
//   - When gatewaysPerRegion <= 0 or selfRegion == RegionUnset: true (full mesh).
//   - Same-region (or untagged) peers: true (every node dials its local region).
//   - Cross-region peers on an interior node (!IsSelfGateway): false (0 WAN dials).
//   - Cross-region peers on a gateway node (IsSelfGateway): IsGateway(peerID).
func (t *TopologyManager) ShouldDialPeer(peerID [16]byte) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.gatewaysPerRegion <= 0 || t.selfRegion == RegionUnset {
		return true
	}
	if sameRegion(t.selfRegion, t.regions[peerID]) {
		return true
	}
	if !t.isSelfGatewayLocked() {
		return false
	}
	return t.isGatewayLocked(peerID)
}

func (t *TopologyManager) rebuildGatewayCacheLocked() {
	if t.gatewaysPerRegion <= 0 {
		t.effectiveSelfGateway = false
		t.effectiveGateways = nil
		t.sortedIntraPeers = nil
		t.foreignRegions = nil
		t.foreignGatewaysByRegion = nil
		return
	}
	t.effectiveGateways = make(map[[16]byte]bool)
	byReg := make(map[RegionTag][][16]byte)
	intra := make([][16]byte, 0, len(t.regions))
	for peerID, reg := range t.regions {
		if t.hasSelfNodeID && peerID == t.selfNodeID {
			continue
		}
		if sameRegion(t.selfRegion, reg) {
			intra = append(intra, peerID)
		}
		if reg != RegionUnset {
			byReg[reg] = append(byReg[reg], peerID)
		}
	}
	sortPeerIDs(intra)
	t.sortedIntraPeers = intra

	autoSelfGw := false
	if t.hasSelfNodeID && t.selfRegion != RegionUnset {
		byReg[t.selfRegion] = append(byReg[t.selfRegion], t.selfNodeID)
	}
	for reg, list := range byReg {
		sortPeerIDs(list)
		byReg[reg] = list
		limit := t.gatewaysPerRegion
		if limit > len(list) {
			limit = len(list)
		}
		for i := 0; i < limit; i++ {
			id := list[i]
			if t.hasSelfNodeID && id == t.selfNodeID {
				if reg == t.selfRegion {
					autoSelfGw = true
				}
				continue
			}
			if !t.explicitPeerGateways {
				t.effectiveGateways[id] = true
			}
		}
	}
	if t.explicitPeerGateways {
		for id, on := range t.gateways {
			if on {
				t.effectiveGateways[id] = true
			}
		}
	}
	if t.hasExplicitSelfGateway {
		t.effectiveSelfGateway = t.selfGateway
	} else {
		t.effectiveSelfGateway = autoSelfGw
	}

	var fRegs []RegionTag
	for reg := range byReg {
		if crossRegion(t.selfRegion, reg) {
			fRegs = append(fRegs, reg)
		}
	}
	for i := 1; i < len(fRegs); i++ {
		for j := i; j > 0 && fRegs[j] < fRegs[j-1]; j-- {
			fRegs[j], fRegs[j-1] = fRegs[j-1], fRegs[j]
		}
	}
	t.foreignRegions = fRegs
	t.foreignGatewaysByRegion = make([][][16]byte, len(fRegs))
	for idx, reg := range fRegs {
		var gws [][16]byte
		for _, id := range byReg[reg] {
			if t.hasSelfNodeID && id == t.selfNodeID {
				continue
			}
			if t.effectiveGateways[id] {
				gws = append(gws, id)
			}
		}
		sortPeerIDs(gws)
		t.foreignGatewaysByRegion[idx] = gws
	}
}

// SetFanout sets the inter-region fan-out N, clamped to [0, MaxFanout]. Called
// at boot from --region-fanout; the default DefaultRegionFanout (3) is the
// named value. 0 = intra-region full mesh only (the degenerate case).
func (t *TopologyManager) SetFanout(n int) {
	t.mu.Lock()
	if n < 0 {
		t.fanout = 0
	} else if n > MaxFanout {
		t.fanout = MaxFanout
	} else {
		t.fanout = n
	}
	t.mu.Unlock()
}

// SetPartialIntraView arms or disarms the partial intra view. Armed, Select
// slices the intra set to the rotating min(intraViewSize, n_r-1) subset via
// drawIntraView; disarmed (the zero-value default) the intra set is the full
// mesh — byte-identical to the pre-partial-intra-view behavior. The
// Gossiper's SetPartialIntraView forwards here (cmd wires it from
// --partial-intra-view under the --region-aware orphan guard);
// test harnesses arm the manager directly (the sim drives the shipped Select,
// never a re-implementation). Boot-time single-writer-before-reader (the
// SetRegion discipline); the lock is the race-detector's signal.
func (t *TopologyManager) SetPartialIntraView(on bool) {
	t.mu.Lock()
	t.partialIntraView = on
	t.mu.Unlock()
}

// PartialIntraView reports the view knob (test/diagnostic accessor).
func (t *TopologyManager) PartialIntraView() bool {
	t.mu.RLock()
	on := t.partialIntraView
	t.mu.RUnlock()
	return on
}

// StarveViewPeerOf is the test-only 3-region intra-view backdoor negative-control
// seam: the named peer is excluded from every intra view this manager draws —
// the permanently-directed pair that must produce the permanent digest-fire the
// negative control's bounded-fire assertion fails on. The zero value disables
// starvation (the production path; a real nodeID is never all-zero).
func (t *TopologyManager) StarveViewPeerOf(peerID [16]byte) {
	t.mu.Lock()
	t.starveViewPeer = peerID
	t.mu.Unlock()
}

// LastIntraView returns the last armed Select's view stats (drawn, eligible,
// xor). The sweep reads it right after Select to carry the per-sweep view
// observables onto the armed `sweep round=` line (view_intra=%d/%d
// view_xor=%x — the additive name=value discipline; the off path never
// reads it, so the off sweepState stays zero and the off log line is
// byte-identical).
func (t *TopologyManager) LastIntraView() (drawn, eligible int, xor uint64) {
	t.mu.RLock()
	drawn, eligible, xor = t.viewDrawn, t.viewEligible, t.viewXor
	t.mu.RUnlock()
	return
}

// drawIntraView is the shipped view-membership function: the rotating
// partial intra view — exactly min(intraViewSize, n) distinct peers drawn
// from the sorted intra population under the per-sweep seed, via a partial
// Fisher-Yates over a domain-separated PCG stream (rand.NewPCG(seed,
// intraViewPCGStream) — never the inter fan-out's stream 0). The first f
// positions of a partial Fisher-Yates are a uniformly random f-subset (each
// of the C(n, f) subsets equally likely; per-pair p = f/n per round) — the
// intra-view selector kill condition's view extension, validated empirically
// against this function (the sim drives the shipped
// Select), never asserted by construction. Deterministic per (seed,
// registry): same seed yields the same view every run (the deterministic view
// contract — the sorted input and fixed stream make the shuffle reproducible).
//
// The degenerate small region (n ≤ intraViewSize): the view is the whole
// intra set, sorted order preserved — byte-identical to the full mesh even
// with the flag on (the [n_r-1 ≤ f] clause).
//
// starveViewPeer (test-only, 3-region intra-view backdoor negative control):
// the named peer is compacted out of the draw population (swap-to-end before
// the shuffle, so it can never land in the first f positions) — every view
// this manager draws excludes it: the permanently-directed pair. The zero
// value skips the compaction entirely (the production path).
//
// COST: one draw per Select (the sweep path, never the delta hot path); the
// PCG is stack-local (no escape), the shuffle is in-place on Select's own
// scratch — 0 allocs; the stats store is one lock (race-detector signal).
func (t *TopologyManager) drawIntraView(intra [][16]byte, seed uint64) [][16]byte {
	n := len(intra)
	t.mu.RLock()
	starve := t.starveViewPeer
	t.mu.RUnlock()
	// The starve compaction runs before the degenerate check (review
	// finding #6: the early return previously sat first, so a degenerate
	// region n_r-1 <= f silently included the starved peer — violating the
	// seam's "excluded from every intra view this manager draws" contract.
	// With the seam unset — the production path, a real nodeID is never
	// all-zero — this reorder is draw-byte-identical: pop stays n, the
	// loop body never runs, the degenerate branch sees the same n.)
	pop := n
	if starve != ([16]byte{}) {
		for i := 0; i < pop; i++ {
			if intra[i] == starve {
				pop--
				intra[i], intra[pop] = intra[pop], intra[i]
				break
			}
		}
	}
	if pop <= intraViewSize {
		t.recordViewStats(pop, n, intra[:pop])
		return intra[:pop]
	}
	pcgSeed := seed
	if selectSeedClockMixBugInject.Load() {
		pcgSeed ^= uint64(time.Now().UnixNano()) // fault-inject (jitter test env var): the non-deterministic seed contamination — the clock enters the seed chain; two independent builds draw different views, failing identity checks
	}
	pcg := rand.NewPCG(pcgSeed, intraViewPCGStream)
	for i := 0; i < intraViewSize; i++ {
		j := i + int(pcg.Uint64()%uint64(pop-i))
		intra[i], intra[j] = intra[j], intra[i]
	}
	t.recordViewStats(intraViewSize, n, intra[:intraViewSize])
	return intra[:intraViewSize]
}

// recordViewStats stores the last draw's observability stats (the armed
// sweep line's view_intra=/view_xor= tokens). The sweep goroutine is the
// only writer (once per Select); LastIntraView — the same goroutine, right
// after Select — the only reader; the lock/RLock pair is the race
// detector's signal (the SetSeed discipline).
func (t *TopologyManager) recordViewStats(drawn, eligible int, view [][16]byte) {
	var xor uint64
	for _, id := range view {
		xor ^= binary.LittleEndian.Uint64(id[:8])
	}
	t.mu.Lock()
	t.viewDrawn, t.viewEligible, t.viewXor = drawn, eligible, xor
	t.mu.Unlock()
}

// SetSeed stamps the per-sweep seed for the inter-region fan-out tie-break (M2).
// The SweepLoop calls this before each Select with the sweep round number (so
// the selection varies across rounds — epidemic spreading — but is reproducible
// per round). Single-writer-before-reader (the SweepLoop's single goroutine).
func (t *TopologyManager) SetSeed(seed uint64) {
	// No lock needed — the seed is only read by Select on the same goroutine
	// that calls SetSeed (the SweepLoop's single-goroutine discipline). The lock
	// is taken for the race detector's benefit: a naked non-atomic write would
	// surface as a race even though the access is single-goroutine, because the
	// race detector does not know the SweepLoop is single-goroutine.
	t.mu.Lock()
	t.seed = seed
	t.mu.Unlock()
}

// SelfRegion returns the node's own region tag (the intra/inter split key).
func (t *TopologyManager) SelfRegion() RegionTag {
	t.mu.RLock()
	r := t.selfRegion
	t.mu.RUnlock()
	return r
}

// IsInterRegion reports whether peerID is a cross-region peer relative to the
// self-region. The inter-region envelope counter fires once per peer the sweep
// routes a delta to whose region differs from the self-region. A peer not in
// the registry (RegionUnset) is treated as same-region (the conservative
// default — an untagged peer routes as local, not foreign, so the counter never
// fires on an untagged peer). Called on the SweepLoop's single goroutine per
// peer in the selection; the RLock is for the race detector (the access is
// single-goroutine, but the race detector does not know the SweepLoop is
// single-goroutine).
func (t *TopologyManager) IsInterRegion(peerID [16]byte) bool {
	t.mu.RLock()
	r, ok := t.regions[peerID]
	self := t.selfRegion
	t.mu.RUnlock()
	if !ok {
		return false // untagged peer = local (the conservative default)
	}
	return crossRegion(self, r)
}

// PeerRegion returns the peer's registered region tag (RegionUnset=0 for an
// untagged peer — the conservative "local" default, matching IsInterRegion).
// This accessor backs the per-region-pair stratified digest-fallback diagnostic:
// the digest round-trip is bounded by digestWaitTimeout=500ms tuned for a
// cross-AZ RTT, so a high fallback rate on a specific peer-region pair
// identifies the WAN link where the stratified exchange is silently no-opping
// to oversend. Same single-goroutine + RLock discipline as IsInterRegion.
func (t *TopologyManager) PeerRegion(peerID [16]byte) RegionTag {
	t.mu.RLock()
	r := t.regions[peerID] // zero value RegionUnset if the peer is untagged
	t.mu.RUnlock()
	return r
}

// Fanout returns the configured inter-region fan-out N (test/diagnostic
// accessor).
func (t *TopologyManager) Fanout() int {
	t.mu.RLock()
	f := t.fanout
	t.mu.RUnlock()
	return f
}

// Select returns the peerIDs AntiEntropySweep iterates when --region-aware is
// enabled: intra-region peers (full-mesh — all peers with the same region as
// SelfRegion) plus inter-region peers (fan-out N, prefer cross-region, seeded
// random tie-break). The result is ordered intra-first then inter-fan-out — the
// sweep's sort.Slice is skipped for the topology path (the selector's output is
// already deterministically ordered; the full-mesh path keeps the sort for
// backward-compat). The per-peer body (generateSweepDelta → the digest-exchange
// → GenerateDelta → the batched ship) is byte-unchanged by the swap — Select
// only changes which peers the body runs over, not the body itself.
//
// ctx is accepted for forward-compat (a future extension that makes Select
// deadline-aware — e.g. a bounded inter-region probe — reads ctx.Err() here);
// the current Select is synchronous (no I/O), so ctx is not consulted. The
// signature matches the AntiEntropySweep caller's `ctx` so the wiring is one
// line (peerIDs := g.topology.Select(ctx)).
//
// The returned slice is freshly allocated (the one alloc per Select — the
// selector runs once per sweep, not per delta; a sub-microsecond selector is
// the target). A future extension that wants zero-alloc hoists the scratch into the
// TopologyManager (the scratch is owned by the caller, reused across sweeps).
func (t *TopologyManager) Select(ctx context.Context) [][16]byte {
	_ = ctx // forward-compat (no I/O currently); documented above.
	t.mu.RLock()
	self := t.selfRegion
	fanout := t.fanout
	seed := t.seed
	viewArmed := t.partialIntraView // under the RLock (race-detector signal discipline)
	gwPerReg := t.gatewaysPerRegion
	if gwPerReg > 0 && self != RegionUnset {
		selfGw := t.effectiveSelfGateway
		interiorCutBug := t.disableGatewayInteriorCutBugInject.Load()
		if !selfGw && !interiorCutBug {
			out := make([][16]byte, len(t.sortedIntraPeers))
			copy(out, t.sortedIntraPeers)
			t.mu.RUnlock()
			if viewArmed {
				out = t.drawIntraView(out, seed)
			}
			return out
		}
		if selfGw {
			nIntra := len(t.sortedIntraPeers)
			nForeignRegs := len(t.foreignRegions)
			limit := fanout
			if limit > nForeignRegs {
				limit = nForeignRegs
			}
			if limit < 0 {
				limit = 0
			}
			out := make([][16]byte, nIntra, nIntra+limit)
			copy(out, t.sortedIntraPeers)
			starve := t.starveViewPeer
			livenessFn := t.peerLiveness
			livenessBug := t.disableGatewayLivenessFailoverBugInject.Load()
			effGws := t.effectiveGateways
			fGwsByReg := t.foreignGatewaysByRegion
			t.mu.RUnlock()

			isLive := func(id [16]byte) bool {
				if livenessBug || livenessFn == nil {
					return true
				}
				return livenessFn(id)
			}
			if viewArmed {
				out = t.drawGatewayIntraView(out, seed, gwPerReg, starve, effGws, isLive)
			}
			if limit > 0 && nForeignRegs > 0 {
				rng := newSeededRand(seed)
				var regOrderStack [MaxFanout]int
				var regOrder []int
				if nForeignRegs <= MaxFanout {
					regOrder = regOrderStack[:nForeignRegs]
				} else {
					regOrder = make([]int, nForeignRegs)
				}
				for i := 0; i < nForeignRegs; i++ {
					regOrder[i] = i
				}
				for i := 0; i < limit; i++ {
					j := i + int(rng()%uint64(nForeignRegs-i))
					regOrder[i], regOrder[j] = regOrder[j], regOrder[i]
				}
				var liveBuf [MaxFanout][16]byte
				for i := 0; i < limit; i++ {
					gws := fGwsByReg[regOrder[i]]
					if len(gws) == 0 {
						continue
					}
					nLive := 0
					for _, gwID := range gws {
						if isLive(gwID) && nLive < MaxFanout {
							liveBuf[nLive] = gwID
							nLive++
						}
					}
					if nLive > 0 {
						pick := liveBuf[int(rng()%uint64(nLive))]
						out = append(out, pick)
					} else {
						pick := gws[int(rng()%uint64(len(gws)))]
						out = append(out, pick)
					}
				}
			}
			return out
		}
	}
	// Snapshot the peer registry under the RLock (the single read barrier — the
	// SetRegion writes happen at boot before the SweepLoop starts, so the
	// snapshot is stable for the sweep's lifetime; the RLock is for the race
	// detector even though the access is single-goroutine).
	intra := make([][16]byte, 0, len(t.regions))
	interCands := make([][16]byte, 0, len(t.regions))
	interRegions := make([]RegionTag, 0, len(t.regions))
	for peerID, region := range t.regions {
		if sameRegion(self, region) {
			intra = append(intra, peerID)
		} else {
			interCands = append(interCands, peerID)
			interRegions = append(interRegions, region)
		}
	}
	t.mu.RUnlock()
	// Stable-order the intra-region peers by [16]byte (the full-mesh sort
	// discipline — a deterministic order makes the sweep reproducible; the
	// sort is over the intra subset, not the full mesh, so it is O(k log k) for
	// k intra peers — bounded by ≤10/AZ per the connection ceiling
	// (≤45 connections per the architecture).
	sortPeerIDs(intra)
	// The partial intra view — when armed, slice the intra set to the rotating
	// f-subset before the inter fan-out is appended. The per-round intra
	// fan-out drops from n_r-1 to min(intraViewSize, n_r-1); the rotation (the
	// same per-sweep seed chain, a domain-separated PCG stream) keeps the
	// over-rounds union of views equal to the full intra mesh — the
	// every-pair-eventually-checked property required for partition detection
	// across consecutive rounds. OFF (the zero-value default): this check
	// is the only delta on the OFF path — byte-identical full intra mesh. The
	// INTER path is untouched (region.go's one-per-distinct-region law).
	if viewArmed {
		intra = t.drawIntraView(intra, seed)
	}
	// The inter-region fan-out's partial Fisher-Yates shuffle is deterministic
	// under the seed only if its input is deterministically ordered. The map
	// iteration order above is non-deterministic (the Go runtime randomizes map
	// iteration), so the same seed would yield a different selection per call — a
	// Law IV violation (a flaky selector). The fix: sort the inter-region
	// candidates by [16]byte (in lockstep with their regions) before the
	// shuffle, so the shuffle permutes a deterministic input — the same seed
	// yields the same output every run (deterministic shuffle). The shuffle then
	// re-randomizes the deterministic input under the seed — the
	// epidemic-spreading property (a different seed yields a different subset)
	// holds, but the per-seed determinism is preserved. The pair-sort keeps each
	// candidate's region tag in lockstep with its peerID.
	sortInterCandidates(interCands, interRegions)
	// Append the inter-region fan-out (seeded random tie-break). The fan-out is
	// the default 3 (or the operator's --region-fanout); 0 =
	// intra-only (the degenerate case).
	out := pickInterRegionFanout(self, interCands, interRegions, fanout, seed, intra)
	return out
}

// drawGatewayIntraView pins up to min(gwPerReg-1, intraViewSize) live local-region
// sibling gateways at intra[0:kPinned] and draws the remaining
// intraViewSize - kPinned intra peers uniformly via Fisher-Yates from
// intra[kPinned:pop] with zero heap allocations.
func (t *TopologyManager) drawGatewayIntraView(
	intra [][16]byte,
	seed uint64,
	gwPerReg int,
	starve [16]byte,
	effGws map[[16]byte]bool,
	isLive func([16]byte) bool,
) [][16]byte {
	n := len(intra)
	pop := n
	if starve != ([16]byte{}) {
		for i := 0; i < pop; i++ {
			if intra[i] == starve {
				pop--
				intra[i], intra[pop] = intra[pop], intra[i]
				break
			}
		}
	}
	if pop <= intraViewSize {
		t.recordViewStats(pop, n, intra[:pop])
		return intra[:pop]
	}
	maxPinned := gwPerReg - 1
	if maxPinned < 0 {
		maxPinned = 0
	}
	if maxPinned > intraViewSize {
		maxPinned = intraViewSize
	}
	kPinned := 0
	if maxPinned > 0 {
		for i := 0; i < pop && kPinned < maxPinned; i++ {
			id := intra[i]
			if effGws[id] && isLive(id) {
				for j := i; j > kPinned; j-- {
					intra[j] = intra[j-1]
				}
				intra[kPinned] = id
				kPinned++
			}
		}
	}
	pcgSeed := seed
	if selectSeedClockMixBugInject.Load() {
		pcgSeed ^= uint64(time.Now().UnixNano())
	}
	pcg := rand.NewPCG(pcgSeed, intraViewPCGStream)
	for i := kPinned; i < intraViewSize; i++ {
		j := i + int(pcg.Uint64()%uint64(pop-i))
		intra[i], intra[j] = intra[j], intra[i]
	}
	t.recordViewStats(intraViewSize, n, intra[:intraViewSize])
	return intra[:intraViewSize]
}

// sortPeerIDs sorts a slice of [16]byte peerIDs in big-endian byte order (the
// full-mesh sort.Slice discipline used by the backward-compat path). Used here
// for the intra-region subset so the topology path's intra peers are
// deterministically ordered (the inter-fan-out is randomized under the seed,
// not sorted). A simple insertion sort — the intra subset is small (≤10/AZ) so
// O(k²) is cheaper than sort.Slice's reflection overhead at this size, and the
// sort is allocation-free.
func sortPeerIDs(ids [][16]byte) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && lessPeerID(ids[j], ids[j-1]); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}

// lessPeerID reports whether a < b in big-endian byte order (the [16]byte peerID
// sort key used by the full-mesh path).
func lessPeerID(a, b [16]byte) bool {
	for k := 0; k < 16; k++ {
		if a[k] != b[k] {
			return a[k] < b[k]
		}
	}
	return false
}

// sortInterCandidates sorts the inter-region candidate peerIDs and their region
// tags in lockstep by peerID (big-endian byte order). The lockstep sort keeps
// each candidate's region tag aligned with its peerID after the sort — so the
// partial Fisher-Yates shuffle in pickInterRegionFanout permutes a
// deterministically-ordered input (the map-iteration order is non-deterministic,
// which would break per-seed determinism — see the Select comment). An
// insertion sort (the inter subset is small — ≤fanout*regions per sweep) keeps
// it allocation-free.
func sortInterCandidates(peerIDs [][16]byte, regions []RegionTag) {
	if len(peerIDs) != len(regions) {
		return // defensive (should never happen — built in lockstep)
	}
	for i := 1; i < len(peerIDs); i++ {
		for j := i; j > 0 && lessPeerID(peerIDs[j], peerIDs[j-1]); j-- {
			peerIDs[j], peerIDs[j-1] = peerIDs[j-1], peerIDs[j]
			regions[j], regions[j-1] = regions[j-1], regions[j]
		}
	}
}

// newSeededRand returns a deterministic rand source under `seed`. math/rand/v2's
// rand.New(rand.NewPCG(seed, 0)) is goroutine-local and reproducible under the
// seed; v1 rand.Seed is removed in v2. The returned closure yields a uint64 per
// call (the partial Fisher-Yates index source). Goroutine-local (the Select
// caller is the SweepLoop's single goroutine); the rand is not shared across
// goroutines, so the non-atomic read is race-free.
func newSeededRand(seed uint64) func() uint64 {
	rng := rand.New(rand.NewPCG(seed, 0))
	return rng.Uint64
}
