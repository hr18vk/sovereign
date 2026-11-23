// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// RegionTag identifies a node's region for region-aware gossip (ADR-0039).
// TopologyManager.Select retains the intra-region full mesh and chooses a
// seeded fan-out to other regions. It changes only which peers a sweep contacts;
// digest, delta, batch, and hybrid wire formats are unchanged.
//
// Region selection happens once per sweep rather than per delta. Its temporary
// slices and maps are separate from the zero-allocation write path.
type RegionTag uint8

// RegionUnset marks a peer or node without a configured region. Unset tags
// compare as local to every region, so an incomplete topology keeps peers on the
// intra-region full-mesh path instead of excluding them from a sweep.
const RegionUnset RegionTag = 0

// sameRegion reports whether two tags use the intra-region route. An unset tag
// is local to every tag; two set tags must match.
func sameRegion(a, b RegionTag) bool {
	if a == RegionUnset || b == RegionUnset {
		return true // An untagged peer remains on the full-mesh path.
	}
	return a == b
}

// crossRegion reports whether two set tags differ. It is the negation of
// sameRegion only when neither tag is RegionUnset.
func crossRegion(a, b RegionTag) bool {
	if a == RegionUnset || b == RegionUnset {
		return false
	}
	return a != b
}

// pickInterRegionFanout chooses at most fanout peers, taking no more than one
// peer from each region represented in candidates. candidateRegions supplies
// the corresponding tag for each candidate. A partial Fisher-Yates shuffle and
// the per-region peer choice both use seed, so identical inputs and seed produce
// identical selections; changing the sweep seed rotates the selected peers.
//
// The random source is local to the call. Selected IDs are appended to out,
// which the caller may reuse; region buckets and candidate indices are temporary
// allocations owned by this function.
func pickInterRegionFanout(
	selfRegion RegionTag,
	candidates [][16]byte,
	candidateRegions []RegionTag,
	fanout int,
	seed uint64,
	out [][16]byte,
) [][16]byte {
	// Exclude local candidates, which the full-mesh path already contacts.
	type idx struct {
		i      int
		region RegionTag
	}
	var picks []idx
	for i, c := range candidateRegions {
		if crossRegion(selfRegion, c) {
			picks = append(picks, idx{i: i, region: c})
		}
	}
	if len(picks) == 0 || fanout <= 0 {
		return out
	}
	rng := newSeededRand(seed)
	// Group candidates before shuffling so two fan-out slots cannot select the
	// same region. The first pick already gives that region the delta; another
	// pick there would add less coverage than contacting a new region.
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
	// Partial Fisher-Yates over the distinct regions (pick `limit` distinct
	// regions in seeded-random order). This is the distinct-region tie-break.
	for i := 0; i < limit; i++ {
		j := i + int(rng()%uint64(nRegions-i)) // i..nRegions-1
		regionOrder[i], regionOrder[j] = regionOrder[j], regionOrder[i]
	}
	// For each chosen region, pick one peer (a second seeded tie-break among the
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
