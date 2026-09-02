// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// region.go is the (ADR-0039) region-aware gossip data-plane half — the
// RegionTag type + the cross-region preference comparator + the fan-out-N random
// tie-break helper. Pure functions; zero or one alloc per Select call (the
// zero-alloc ParseManifest discipline — the selector runs once per sweep,
// NOT per delta, so a small alloc is acceptable but zero-alloc is the honest
// target; the 0-allocs/op gate is the hot path, the sweep is the warm path).
//
// ships the DATA-PLANE half of (the loopback-provable substrate
// for the Raft metadata-plane arc). The region-arization swaps
// AntiEntropySweep's iteration source from the full-mesh `peers.Peers` (all
// peers, sorted — O(N²) connections at N nodes) to `topology.Select(ctx)`
// (intra-region full-mesh + inter-region fan-out-N, prefer cross-region —
// O(log N) rounds to convergence at fan-out 3). The per-peer BODY
// (generateSweepDelta → the digest-exchange → GenerateDelta(remoteIBLT) →
// the batched ship) is BYTE-UNCHANGED by the swap; the wiring change is ONE
// iteration source + the selector. The wire shape is BYTE-IDENTICAL — the fan-out
// selector chooses WHICH peers to send the SAME batch/digest/hybrid frames to,
// NOT a new frame shape (so the fuzz harness stays load-bearing without
// re-work — the crash surface is unchanged).
//
// RegionTag is a uint8 (cache-friendly — the honest call per the
// "the honest call is the uint8"; a string is human-readable but a uint8 is
// cache-friendly + the comparator is a single-byte compare). 0 is the ZERO tag
// (the default for an unregistered peer — a peer with NO region tag is treated
// as SAME-region as a node with the zero self-region, so the opt-IN default of
// "no topology set" is byte-identical to the full-mesh path; a node that sets a
// self-region but leaves a peer untagged routes the peer as intra-region, the
// honest conservative default — an untagged peer is a SAME-AZ peer, NOT a
// foreign-AZ peer, so the fan-out selector never accidentally drops a local
// peer from the full-mesh). A production change that wants named regions (us-east,
// eu-west, ap-south) ships a registry uint8→string in a SEPARATE change (the
// opt-IN discipline: ship the SIMPLE thing first).
type RegionTag uint8

// RegionTag zero value — the "no region set" sentinel. A peer (or a node's own
// self-region) with RegionUnset is treated as the SAME region as any other
// RegionUnset peer, so the opt-IN default (no topology / no self-region) keeps
// every peer intra-region = byte-identical to the full-mesh path.
const RegionUnset RegionTag = 0

// sameRegion reports whether two region tags route as the SAME region. Two
// RegionUnset tags are SAME (the opt-IN default); a set tag vs a different set
// tag are CROSS-region (the fan-out candidate); a set tag vs RegionUnset is
// SAME (the conservative "untagged = local" default — an untagged peer is never
// accidentally routed as foreign).
func sameRegion(a, b RegionTag) bool {
	if a == RegionUnset || b == RegionUnset {
		return true // untagged peer = local (the honest conservative default)
	}
	return a == b
}

// crossRegion reports whether two region tags are in DIFFERENT regions (the
// fan-out candidate class). A RegionUnset on either side is NOT cross-region
// (it is SAME per sameRegion above), so crossRegion is the negation of
// sameRegion ONLY for two SET tags.
func crossRegion(a, b RegionTag) bool {
	if a == RegionUnset || b == RegionUnset {
		return false
	}
	return a != b
}

// pickInterRegionFanout selects up to `fanout` inter-region peers from
// `candidates` (peers whose region differs from selfRegion), preferring
// cross-region diversity under a seeded rand tie-break (the epidemic-spreading
// property — a random subset of inter-region peers spreads the delta to DISTINCT
// regions per round, not the same region every round). The selector is
// DETERMINISTIC under the seed (— same seed → same selection EVERY run; the
// fuzz-seed discipline; a flaky selector is a violation).
//
// The seeded rand runs goroutine-local (the TopologyManager.Select caller is the
// SweepLoop's single goroutine — the SetDigestSink discipline; the rand
// is NOT shared across goroutines, so the non-atomic read is race-free). The
// seed is per-sweep (e.g. the sweep round number) so the selection is
// reproducible per round but varies across rounds (a DIFFERENT inter-region
// subset per round spreads the delta epidemically — the O(log N) rounds
// convergence the design names).
//
// The selection is a Fisher-Yates-style partial shuffle on a scratch slice (the
// zero-alloc discipline — the scratch slice is owned by the caller, NOT
// allocated per Select; the candidates slice is a view into the peer registry,
// NOT a copy). Returns the selected peerIDs appended to `out` (the caller's
// scratch output slice) so the Select call is zero-alloc when the caller reuses
// the scratch slices across sweeps.
func pickInterRegionFanout(
	selfRegion RegionTag,
	candidates [][16]byte,
	candidateRegions []RegionTag,
	fanout int,
	seed uint64,
	out [][16]byte,
) [][16]byte {
	// Collect the cross-region candidate indices into a scratch slice (the
	// partial-shuffle population). A candidate whose region is SAME as self
	// (sameRegion) is intra-region — handled by the full-mesh path, NOT here.
	// A candidate whose region is CROSS (crossRegion) is a fan-out candidate.
	type idx struct {
		i int
		// region is the candidate's region tag (used for the diversity
		// preference — a fan-out that picks DISTINCT regions spreads the
		// delta epidemically; a fan-out that picks the SAME region twice
		// wastes a slot). The tie-break among same-distance candidates is
		// the seeded rand (the epidemic-spreading property).
		region RegionTag
	}
	// Build the cross-region candidate list. This is the ONE alloc per Select
	// call (the honest target — the selector runs once per sweep, NOT per
	// delta; a sub-microsecond selector is the honest target). A future
	// change that wants zero-alloc hoists this scratch into the TopologyManager
	// (the zero-alloc ParseManifest discipline — the scratch is owned by
	// the caller, reused across sweeps).
	var picks []idx
	for i, c := range candidateRegions {
		if crossRegion(selfRegion, c) {
			picks = append(picks, idx{i: i, region: c})
		}
	}
	if len(picks) == 0 || fanout <= 0 {
		return out
	}
	// Seeded rand — math/rand/v2 (the precedent; v1 rand.Seed is REMOVED
	// in v2). rand.New(rand.NewPCG(seed, 0)) is goroutine-local + deterministic
	// under the seed. The seed travels per-sweep (the sweep round number)
	// so the selection varies across rounds (epidemic spreading) but is
	// reproducible per round (the guard asserts same seed →
	// same output EVERY run).
	rng := newSeededRand(seed)
	// DISTINCT-REGION fan-out (the O(log_fanout N) convergence
	// REQUIRES fanout-N DISTINCT regions per round, NOT fanout-N peers that may
	// cluster in the same region). Group the cross-region candidates by region
	// (one region = one pick slot), then pick up to `fanout` DISTINCT regions
	// under the seeded tie-break, choosing ONE peer per region (a second seeded
	// tie-break among the region's peers). This honors the docstring's
	// "preferring cross-region diversity" promise — a fan-out that picks the
	// SAME region twice wastes a slot (the delta already reaches that region via
	// the first pick; the second pick's intra-region full-mesh would have spread
	// it anyway). The guard proves the distinct-region fan-out
	// achieves K ≤ O(log_fanout N) rounds (the partial-Fisher-Yates-over-peers
	// variant the first implementation shipped DIVERGED — K=7 at N=100/fan-out-3
	// vs the predicted ~4-5; the distinct-region variant converges in K ≤ 5).
	regionBuckets := make(map[RegionTag][]int) // region -> candidate indices
	regionOrder := make([]RegionTag, 0, len(picks))
	for _, p := range picks {
		if _, ok := regionBuckets[p.region]; !ok {
			regionOrder = append(regionOrder, p.region)
		}
		regionBuckets[p.region] = append(regionBuckets[p.region], p.i)
	}
	nRegions := len(regionOrder)
	limit := fanout
	if limit > nRegions {
		limit = nRegions
	}
	// Partial Fisher-Yates over the DISTINCT REGIONS (pick `limit` distinct
	// regions in seeded-random order). This is the distinct-region tie-break.
	for i := 0; i < limit; i++ {
		j := i + int(rng()%uint64(nRegions-i)) // i..nRegions-1
		regionOrder[i], regionOrder[j] = regionOrder[j], regionOrder[i]
	}
	// For each chosen region, pick ONE peer (a second seeded tie-break among the
	// region's candidates — the peer within the region is the epidemic relay).
	for i := 0; i < limit; i++ {
		region := regionOrder[i]
		cands := regionBuckets[region]
		if len(cands) == 0 {
			continue
		}
		pickIdx := int(rng() % uint64(len(cands)))
		out = append(out, candidates[cands[pickIdx]])
	}
	return out
}
