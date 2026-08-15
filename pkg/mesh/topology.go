package mesh

import (
	"context"
	"math/rand/v2"
	"sync"
)

// topology.go is the Day-34 (ADR-0039) TopologyManager — the peer registry
// keyed by [16]byte carrying a RegionTag per peer + the Select(ctx) iteration
// source AntiEntropySweep calls when --region-aware is ON. Select returns
// intra-region peers (full-mesh — all peers with the SAME region as SelfRegion)
// + inter-region peers (fan-out N, prefer cross-region, random tie-break under
// a seeded rand — the epidemic-spreading property). The selector is DETERMINISTIC
// under the seed (M2 — same seed → same Select output EVERY run; the Day-23
// fuzz-seed discipline; a flaky selector is a Law IV violation).
//
// The TopologyManager is a NEW seam — it does NOT change PeerSet.Peers() (the
// full-mesh list stays the BACKWARD-COMPAT path when the topology selector is
// OFF — byte-identical Day-33). It is set on the Gossiper via SetTopology AFTER
// construction (the SetDigestSink / SetRoundReporter / SetHybridSign precedent —
// a single-line setter after NewGossiper; NO constructor-arg change = NO
// existing-caller break). Nil by default = the full-mesh Peers() path = byte-
// identical Day-33 (the T-TOPO-OFF-IS-BYTE-IDENTICAL tooth).
//
// CONCURRENCY: the TopologyManager is single-writer-before-reader (the SetRegion
// registrations happen at boot before the SweepLoop starts; the Select reads
// happen on the SweepLoop's single goroutine — the Day-29 SetDigestSink
// discipline). The RWMutex guards the peer-regions map; Select takes the RLock
// for the registry snapshot, then runs the seeded rand goroutine-local (the rand
// is NOT shared across goroutines, so the non-atomic read is race-free — the
// T-TOPO-RACE discipline). A future fork that adds live region re-tagging
// (peers migrating regions at runtime) extends the mutex discipline — NOT this
// fork's scope.
type TopologyManager struct {
	mu sync.RWMutex
	// regions maps peerID -> RegionTag. A peer NOT in the map is RegionUnset
	// (the honest conservative default — an untagged peer routes as SAME-region
	// as the self-region, so the fan-out selector never accidentally drops a
	// local peer from the full-mesh; a peer with NO region tag is a local peer,
	// NOT a foreign peer). Set via SetRegion at boot (the register seam).
	regions map[[16]byte]RegionTag
	// seed is the per-sweep seed for the inter-region fan-out tie-break (M2 —
	// the seeded rand is DETERMINISTIC under the seed; the sweep round number
	// is the natural per-sweep seed so the selection varies across rounds but
	// is reproducible per round). Set via SetSeed before each Select call (the
	// SweepLoop stamps the round number into the seed before the sweep).
	seed uint64
	// fanout is the inter-region fan-out N (the blueprint's default 3 — the
	// O(log N) rounds convergence at fan-out 3). Set via SetFanout at boot;
	// clamped to [0, MaxFanout]. 0 = intra-region full-mesh only (NO inter-
	// region fan-out — the honest degenerate case; the T-TOPO-CONNECTION-CUT
	// tooth asserts fan-out 0 -> intra-only).
	fanout int
	// selfRegion is the node's own region tag (the intra/inter split key —
	// peers with the SAME region are intra = full-mesh; peers with a DIFFERENT
	// region are inter = fan-out candidates). A RegionUnset (0) self-region
	// makes EVERY peer intra-region (sameRegion returns true for RegionUnset on
	// either side) = byte-identical to the full-mesh path. Placed LAST so the
	// 1-byte tag shares no wasted padding with the 8-byte fields above (the
	// fieldalignment discipline — manual reorder, NOT -fix; the 1-byte tag's
	// trailing padding is NOT counted toward the struct's useful size).
	selfRegion RegionTag
}

// MaxFanout is the upper bound on the inter-region fan-out N. The blueprint's
// default 3 yields O(log_3 N) rounds to convergence; a larger fan-out converges
// faster but burns more per-sweep bandwidth (the trade-off the operator dials).
// 16 is a generous ceiling (a 16-fan-out at 100 nodes = 16 inter-region
// connections per sweep per node — still << the full-mesh 10,000).
const MaxFanout = 16

// DefaultRegionFanout is the blueprint's default inter-region fan-out N. 3
// yields O(log_3 100) ≈ 4-5 rounds to convergence at 100 nodes — the loopback
// gate the T-TOPO-ROUND-COUNT tooth measures. The operator overrides via
// --region-fanout; the default is the blueprint's named value.
const DefaultRegionFanout = 3

// NewTopologyManager constructs a TopologyManager with the node's own region tag
// + the default fan-out. The self-region is the intra/inter split key (peers
// with the SAME region are intra = full-mesh; peers with a DIFFERENT region are
// inter = fan-out candidates). A self-region of RegionUnset (the opt-IN default
// when --self-region is not set) makes EVERY peer intra-region (sameRegion
// returns true for RegionUnset on either side) = byte-identical to the full-mesh
// path — the honest zero-value default.
func NewTopologyManager(selfRegion RegionTag) *TopologyManager {
	return &TopologyManager{
		selfRegion: selfRegion,
		regions:    make(map[[16]byte]RegionTag),
		fanout:     DefaultRegionFanout,
	}
}

// SetRegion registers a peer's region tag (the register seam — called at boot
// for each configured peer, before the SweepLoop starts). A peer NOT registered
// is RegionUnset (routes as SAME-region = intra). Idempotent (re-registering a
// peer overwrites the tag — the live-re-tagging discipline a future fork
// extends). Single-writer-before-reader (the Day-29 SetDigestSink discipline).
func (t *TopologyManager) SetRegion(peerID [16]byte, region RegionTag) {
	t.mu.Lock()
	t.regions[peerID] = region
	t.mu.Unlock()
}

// SetFanout sets the inter-region fan-out N, clamped to [0, MaxFanout]. Called
// at boot from --region-fanout; the default DefaultRegionFanout (3) is the
// blueprint's named value. 0 = intra-region full-mesh only (the honest
// degenerate case).
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

// SetSeed stamps the per-sweep seed for the inter-region fan-out tie-break (M2).
// The SweepLoop calls this before each Select with the sweep round number (so
// the selection varies across rounds — epidemic spreading — but is reproducible
// per round). Single-writer-before-reader (the SweepLoop's single goroutine).
func (t *TopologyManager) SetSeed(seed uint64) {
	// No lock needed — the seed is only read by Select on the SAME goroutine
	// that calls SetSeed (the SweepLoop's single-goroutine discipline). But take
	// the lock anyway for the race-detector's benefit (the T-TOPO-RACE tooth
	// runs under -race; a naked non-atomic write would surface as a race even
	// though the access is single-goroutine, because the race detector does NOT
	// know the SweepLoop is single-goroutine). The lock is the honest signal.
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

// IsInterRegion reports whether peerID is a CROSS-region peer relative to the
// self-region (the M6 disclosure counter's gate — the inter-region envelope
// counter fires once per peer the sweep routes a delta to whose region differs
// from the self-region). A peer NOT in the registry (RegionUnset) is SAME-region
// (the honest conservative default — an untagged peer routes as local, NOT
// foreign, so the counter never fires on an untagged peer). Called on the
// SweepLoop's single goroutine per peer in the selection; the RLock is the
// honest signal to the race detector (the access is single-goroutine, but the
// race detector does NOT know the SweepLoop is single-goroutine — the
// T-TOPO-RACE discipline).
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

// Fanout returns the configured inter-region fan-out N (test/diagnostic
// accessor).
func (t *TopologyManager) Fanout() int {
	t.mu.RLock()
	f := t.fanout
	t.mu.RUnlock()
	return f
}

// Select returns the peerIDs AntiEntropySweep iterates when --region-aware is
// ON: intra-region peers (full-mesh — all peers with the SAME region as
// SelfRegion) + inter-region peers (fan-out N, prefer cross-region, seeded
// random tie-break). The result is ordered intra-first then inter-fan-out — the
// sweep's sort.Slice is SKIPPED for the topology path (the selector's output is
// already deterministically ordered; the full-mesh path keeps the sort for
// backward-compat). The per-peer BODY (generateSweepDelta → the digest-exchange
// → GenerateDelta → the batched ship) is BYTE-UNCHANGED by the swap — Select
// only changes WHICH peers the body runs over, NOT the body itself.
//
// ctx is accepted for forward-compat (a future fork that makes Select
// deadline-aware — e.g. a bounded inter-region probe — reads ctx.Err() here);
// the current Select is synchronous (no I/O), so ctx is not consulted. The
// signature matches the AntiEntropySweep caller's `ctx` so the wiring is ONE
// line (peerIDs := g.topology.Select(ctx)).
//
// The returned slice is freshly allocated (the ONE alloc per Select — the
// selector runs once per sweep, NOT per delta; a sub-microsecond selector is
// the honest target per M4). A future fork that wants zero-alloc hoists the
// scratch into the TopologyManager (the Day-26 zero-alloc ParseManifest
// discipline — the scratch is owned by the caller, reused across sweeps).
func (t *TopologyManager) Select(ctx context.Context) [][16]byte {
	_ = ctx // forward-compat (no I/O this fork); documented above.
	t.mu.RLock()
	self := t.selfRegion
	fanout := t.fanout
	seed := t.seed
	// Snapshot the peer registry under the RLock (the single read barrier — the
	// SetRegion writes happen at boot before the SweepLoop starts, so the
	// snapshot is stable for the sweep's lifetime; the RLock is the honest
	// signal to the race detector even though the access is single-goroutine).
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
	// sort is over the intra subset, NOT the full mesh, so it is O(k log k) for
	// k intra peers — bounded by ≤10/AZ per the blueprint's ≤45-connections
	// ceiling).
	sortPeerIDs(intra)
	// CRITICAL (M2 determinism): the inter-region fan-out's partial Fisher-Yates
	// shuffle is DETERMINISTIC under the seed ONLY IF its INPUT is deterministically
	// ordered. The map-iteration order above is NON-deterministic (the Go runtime
	// randomizes map iteration), so the same seed would yield a DIFFERENT
	// selection per call — a Law IV violation (a flaky selector). The fix: sort
	// the inter-region candidates by [16]byte (in lockstep with their regions)
	// BEFORE the shuffle, so the shuffle permutes a DETERMINISTIC input → the
	// same seed yields the same output EVERY run (T-TOPO-DETERMINISTIC). The
	// shuffle then re-randomizes the deterministic input under the seed — the
	// epidemic-spreading property (a different seed → a different subset) HOLDS,
	// but the per-seed determinism is preserved. The pair-sort keeps each
	// candidate's region tag in lockstep with its peerID.
	sortInterCandidates(interCands, interRegions)
	// Append the inter-region fan-out (seeded random tie-break — M2). The
	// fan-out is the blueprint's default 3 (or the operator's --region-fanout);
	// 0 = intra-only (the honest degenerate case).
	out := pickInterRegionFanout(self, interCands, interRegions, fanout, seed, intra)
	return out
}

// sortPeerIDs sorts a slice of [16]byte peerIDs in big-endian byte order (the
// full-mesh sort.Slice discipline gossip.go:604 uses for the backward-compat
// path). Used here for the intra-region subset so the topology path's intra
// peers are deterministically ordered (the inter-fan-out is randomized under
// the seed, NOT sorted). A simple insertion sort — the intra subset is small
// (≤10/AZ) so O(k²) is cheaper than sort.Slice's reflection overhead at this
// size, and the sort is allocation-free (the Day-26 zero-alloc discipline).
func sortPeerIDs(ids [][16]byte) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && lessPeerID(ids[j], ids[j-1]); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}

// lessPeerID reports whether a < b in big-endian byte order (the [16]byte peerID
// sort key gossip.go:604 uses).
func lessPeerID(a, b [16]byte) bool {
	for k := 0; k < 16; k++ {
		if a[k] != b[k] {
			return a[k] < b[k]
		}
	}
	return false
}

// sortInterCandidates sorts the inter-region candidate peerIDs + their region
// tags IN LOCKSTEP by peerID (big-endian byte order). The lockstep sort keeps
// each candidate's region tag aligned with its peerID after the sort — so the
// partial Fisher-Yates shuffle in pickInterRegionFanout permutes a
// DETERMINISTICALLY-ordered input (the map-iteration order is NON-deterministic,
// which would break per-seed determinism — see the Select comment). An
// insertion sort (the inter subset is small — ≤fanout*regions per sweep) keeps
// it allocation-free (the Day-26 zero-alloc discipline).
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

// newSeededRand returns a deterministic rand source under `seed` (M2 — the
// Day-23 fuzz-seed discipline; math/rand/v2's rand.New(rand.NewPCG(seed, 0)) is
// goroutine-local + reproducible under the seed; v1 rand.Seed is REMOVED in v2).
// The returned closure yields a uint64 per call (the partial Fisher-Yates index
// source). Goroutine-local (the Select caller is the SweepLoop's single
// goroutine — the Day-29 SetDigestSink discipline); the rand is NOT shared
// across goroutines, so the non-atomic read is race-free.
func newSeededRand(seed uint64) func() uint64 {
	rng := rand.New(rand.NewPCG(seed, 0))
	return rng.Uint64
}
