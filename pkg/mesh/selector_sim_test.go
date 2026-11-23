// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests measure the region selector's per-pair uniformity and the
// combined in-degree of colocated nodes (ADR-0063). They call
// (*TopologyManager).Select, pickInterRegionFanout, and their setters directly
// rather than reimplementing selection.
//
// selectorRoundSeed duplicates the inline seed expression in SweepLoop:
// sweepRound XOR the little-endian first eight bytes of owner.NodeID. Rounds
// begin at 1 because SweepLoop increments sweepRound before calling SetSeed.
// Two negative controls replace the round term with a fixed per-node seed or a
// shared zero seed; the statistical checks must reject both correlated shapes.
//
// RUN_SELECTOR_SIM=1 enables the full grid and RUN_SELECTOR_SIM_ROUNDS changes
// its default 10,000 rounds. Small ungated tests exercise the same instruments
// on every test run. Uniformity samples at least 64 nodes with a fixed stride
// at larger layouts. Colocation uses a region's full population because a
// sample would undercount combined in-degree. Select insertion-sorts both
// subsets on every call, which makes the full large-layout grid expensive.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
)

// simWorkerWidth caps selector parallelism at min(64,max(4,GOMAXPROCS)).
// The minimum retains four workers on small machines; the maximum bounds the
// number of live per-node registry maps and their memory use.
func simWorkerWidth() int {
	w := runtime.GOMAXPROCS(0)
	if w < 4 {
		w = 4
	}
	if w > 64 {
		w = 64
	}
	return w
}

// selectorRoundSeed mirrors SweepLoop's seed expression. round is the
// already-incremented sweepRound; nodeID supplies its little-endian first
// eight bytes.
func selectorRoundSeed(round uint64, nodeID [16]byte) uint64 {
	return round ^ binary.LittleEndian.Uint64(nodeID[:8])
}

// selectorSimNodeID derives a deterministic synthetic ID from SHA-256. Using
// digest bytes approximates the uniformly distributed first 16 bytes of the
// Ed25519 public keys used for production NodeIDs; sequential integers would
// give the selector a different input distribution.
func selectorSimNodeID(i int) [16]byte {
	var id [16]byte
	h := sha256.Sum256([]byte(fmt.Sprintf("mesh-sim-node-193478795-%d", i)))
	copy(id[:], h[:16])
	return id
}

// SelectorLayout lists region populations. Tags are 1-based because
// RegionTag(0) is RegionUnset and would route as same-region for every node,
// accidentally producing a full mesh.
type SelectorLayout struct {
	name   string
	counts []int
}

func (l *SelectorLayout) total() int {
	n := 0
	for _, c := range l.counts {
		n += c
	}
	return n
}

// buildSelectorPopulation assigns IDs and region tags in contiguous blocks,
// with region 1 owning the first counts[0] nodes, and so on.
func buildSelectorPopulation(l *SelectorLayout) (ids [][16]byte, regions []RegionTag) {
	n := l.total()
	ids = make([][16]byte, n)
	regions = make([]RegionTag, n)
	tag := RegionTag(1)
	assigned := 0
	for _, c := range l.counts {
		for k := 0; k < c; k++ {
			ids[assigned] = selectorSimNodeID(assigned)
			regions[assigned] = tag
			assigned++
		}
		tag++
	}
	return ids, regions
}

// buildSelectorManager constructs a TopologyManager for node idx. Its registry
// contains every other node with its region tag and excludes self, matching
// production peer registration. DefaultRegionFanout is the production fan-out.
func buildSelectorManager(idx int, ids [][16]byte, regions []RegionTag) *TopologyManager {
	t := NewTopologyManager(regions[idx])
	t.SetFanout(DefaultRegionFanout)
	for j := range ids {
		if j == idx {
			continue
		}
		t.SetRegion(ids[j], regions[j])
	}
	return t
}

// selectorChi2Crit uses the Wilson-Hilferty normal approximation for the
// one-sided chi-square critical value at significance 1-alpha. Its relative
// error is below 0.2% for k>30, covering the candidate counts used here.
func selectorChi2Crit(k int, alpha float64) float64 {
	z := selectorNormalQuantile(1 - alpha)
	kf := float64(k)
	c := 1 - 2/(9*kf) + z*math.Sqrt(2/(9*kf))
	return kf * c * c * c
}

// selectorNormalQuantile uses Acklam's rational approximation to the
// standard-normal quantile, with maximum relative error 1.15e-9.
func selectorNormalQuantile(p float64) float64 {
	a := []float64{-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02, 1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00}
	b := []float64{-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02, 6.680131188771972e+01, -1.328068155288572e+01, 1.0}
	c := []float64{-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00, -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00}
	d := []float64{7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00, 3.754408661907416e+00}
	pLow := 0.02425
	if p < pLow {
		q := math.Sqrt(-2 * math.Log(p))
		return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q + c[5]) / ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q + 1)
	}
	if p > 1-pLow {
		q := math.Sqrt(-2 * math.Log(1-p))
		return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q + c[5]) / ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q + 1)
	}
	q := p - 0.5
	r := q * q
	return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r + a[5]) * q / (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r + b[5])
}

// SelectorUniStats holds one node's per-pair uniformity measurements.
type SelectorUniStats struct {
	chi2           []float64 // per remote region: chi-square statistic over R rounds
	maxdev         []float64 // per remote region: max |count - expected|
	hitmin         []int     // per remote region: fewest picks for any candidate
	hitmax         []int     // per remote region: most picks for any candidate
	dof            []int     // per remote region: candidates - 1
	picksPerRegion []int     // per remote region: total picks over R rounds
	coverRound     uint64    // first round every remote candidate was hit; 0 if censored
	intraCount     int       // measured intra-region list length
}

// runSelectorUniformity measures one node's inter-region picks over rounds
// 1..R using TopologyManager.Select. negCtl 0 uses selectorRoundSeed, 1 removes
// the round term to keep a fixed per-node seed, and 2 uses a shared zero seed.
// Only the seed changes; selection always uses the production implementation.
func runSelectorUniformity(idx int, ids [][16]byte, regions []RegionTag, R uint64, negCtl int) SelectorUniStats {
	mgr := buildSelectorManager(idx, ids, regions)
	idTag := make(map[[16]byte]RegionTag, len(ids))
	for j := range ids {
		idTag[ids[j]] = regions[j]
	}
	our := regions[idx]
	remoteTags := make([]RegionTag, 0, 8)
	seenTag := make(map[RegionTag]bool, 8)
	for j := range regions {
		if regions[j] != our && !seenTag[regions[j]] {
			seenTag[regions[j]] = true
			remoteTags = append(remoteTags, regions[j])
		}
	}
	// ascending tag order — deterministic reporting across runs
	for i := 1; i < len(remoteTags); i++ {
		for j := i; j > 0 && remoteTags[j] < remoteTags[j-1]; j-- {
			remoteTags[j], remoteTags[j-1] = remoteTags[j-1], remoteTags[j]
		}
	}
	tagIdx := make(map[RegionTag]int, len(remoteTags))
	counts := make([]map[[16]byte]int, len(remoteTags))
	seenCand := make([]map[[16]byte]bool, len(remoteTags))
	candCount := make([]int, len(remoteTags))
	for ri, tag := range remoteTags {
		tagIdx[tag] = ri
		counts[ri] = make(map[[16]byte]int, 64)
		seenCand[ri] = make(map[[16]byte]bool, 64)
		for j := range ids {
			if regions[j] == tag {
				candCount[ri]++
			}
		}
	}
	totalRemote := 0
	for ri := range candCount {
		totalRemote += candCount[ri]
	}
	var st SelectorUniStats
	st.chi2 = make([]float64, len(remoteTags))
	st.maxdev = make([]float64, len(remoteTags))
	st.hitmin = make([]int, len(remoteTags))
	st.hitmax = make([]int, len(remoteTags))
	st.dof = make([]int, len(remoteTags))
	st.picksPerRegion = make([]int, len(remoteTags))
	copy(st.dof, candCount)
	for i := range st.dof {
		st.dof[i]--
	}
	ctx := context.Background()
	covered := 0
	id := ids[idx]
	for round := uint64(1); round <= R; round++ {
		var seed uint64
		switch negCtl {
		case 1:
			seed = binary.LittleEndian.Uint64(id[:8]) // fixed per-node seed
		case 2:
			seed = 0 // shared seed forces identical views
		default:
			seed = selectorRoundSeed(round, id)
		}
		mgr.SetSeed(seed)
		sel := mgr.Select(ctx)
		for _, p := range sel {
			tag := idTag[p]
			if tag == our {
				if round == 1 {
					st.intraCount++
				}
				continue
			}
			ri := tagIdx[tag]
			st.picksPerRegion[ri]++
			counts[ri][p]++
			if !seenCand[ri][p] {
				seenCand[ri][p] = true
				covered++
				if covered == totalRemote && st.coverRound == 0 {
					st.coverRound = round
				}
			}
		}
	}
	for ri := range remoteTags {
		m := candCount[ri]
		if st.picksPerRegion[ri] == 0 { // degenerate guard: no draws -> no distribution
			st.dof[ri] = m - 1
			continue
		}
		exp := float64(st.picksPerRegion[ri]) / float64(m)
		var chi2, maxdev float64
		min, max := -1, -1
		distinct := 0
		for _, c := range counts[ri] {
			distinct++
			dev := float64(c) - exp
			chi2 += dev * dev / exp
			if d := math.Abs(dev); d > maxdev {
				maxdev = d
			}
			if min < 0 || c < min {
				min = c
			}
			if c > max {
				max = c
			}
		}
		// The maps contain only selected candidates. Account for every
		// unselected population member explicitly: each contributes exp to
		// chi-square, clamps hitmin to zero, and can raise maxdev to exp.
		unpicked := m - distinct
		chi2 += float64(unpicked) * exp
		if unpicked > 0 {
			min = 0
			if exp > maxdev {
				maxdev = exp
			}
		}
		if min < 0 {
			min = 0
		}
		if max < 0 {
			max = 0
		}
		st.chi2[ri] = chi2
		st.maxdev[ri] = maxdev
		st.hitmin[ri] = min
		st.hitmax[ri] = max
	}
	return st
}

// SelectorColoStats holds one round's combined distribution for a region pair.
type SelectorColoStats struct {
	remote RegionTag
	m      int     // candidates in the remote region
	draws  int     // source-region picks into the remote region this round
	mean   float64 // draws / m
	max    int     // maximum in-degree of any remote candidate
	chi2   float64 // multinomial chi-square over all m candidates
	dof    int
}

// runSelectorColocation combines one round's selections for every node in
// [lo,hi), returning the in-degree distribution for each remote region.
// mgrs[i-lo] is the prebuilt manager for node lo+i and is reused across rounds.
// negCtl 0 uses selectorRoundSeed; negCtl 2 uses a shared zero seed, which makes
// every colocated node choose the same candidates.
func runSelectorColocation(round uint64, lo, hi int, ids [][16]byte, regions []RegionTag, mgrs []*TopologyManager, idTag map[[16]byte]RegionTag, negCtl int) []SelectorColoStats {
	our := regions[lo]
	var remoteTags []RegionTag
	seenTag := make(map[RegionTag]bool, 8)
	for j := range regions {
		if regions[j] != our && !seenTag[regions[j]] {
			seenTag[regions[j]] = true
			remoteTags = append(remoteTags, regions[j])
		}
	}
	for i := 1; i < len(remoteTags); i++ {
		for j := i; j > 0 && remoteTags[j] < remoteTags[j-1]; j-- {
			remoteTags[j], remoteTags[j-1] = remoteTags[j-1], remoteTags[j]
		}
	}
	tagIdx := make(map[RegionTag]int, len(remoteTags))
	candCount := make([]int, len(remoteTags))
	for ri, tag := range remoteTags {
		tagIdx[tag] = ri
		for j := range ids {
			if regions[j] == tag {
				candCount[ri]++
			}
		}
	}
	indeg := make([]map[[16]byte]int, len(remoteTags))
	for ri := range indeg {
		indeg[ri] = make(map[[16]byte]int, 64)
	}
	for i := lo; i < hi; i++ {
		id := ids[i]
		var seed uint64
		if negCtl == 2 {
			seed = 0
		} else {
			seed = selectorRoundSeed(round, id)
		}
		mgrs[i-lo].SetSeed(seed)
		sel := mgrs[i-lo].Select(context.Background())
		for _, p := range sel {
			if tag := idTag[p]; tag != our {
				indeg[tagIdx[tag]][p]++
			}
		}
	}
	out := make([]SelectorColoStats, 0, len(remoteTags))
	for ri, tag := range remoteTags {
		m := candCount[ri]
		draws, max, distinct := 0, 0, 0
		for _, c := range indeg[ri] {
			draws += c
			distinct++
			if c > max {
				max = c
			}
		}
		if draws == 0 {
			out = append(out, SelectorColoStats{remote: tag, m: m, dof: m - 1})
			continue
		}
		exp := float64(draws) / float64(m)
		chi2 := 0.0
		for _, c := range indeg[ri] {
			dev := float64(c) - exp
			chi2 += dev * dev / exp
		}
		chi2 += float64(m-distinct) * exp // include candidates not picked this round
		out = append(out, SelectorColoStats{remote: tag, m: m, draws: draws, mean: exp, max: max, chi2: chi2, dof: m - 1})
	}
	return out
}

// SelectorLegASummary aggregates per-pair uniformity and coverage results.
type SelectorLegASummary struct {
	worstChi2Ratio float64
	worstNode      int
	worstDof       int
	censored       int
	coverMean      float64
	coverMax       uint64
}

// runSelectorLegA measures per-pair uniformity over R rounds for a sampled
// population. It also checks that each intra list contains n_r-1 peers and
// that each remote region receives exactly one pick per node per round.
func runSelectorLegA(t *testing.T, l *SelectorLayout, ids [][16]byte, regions []RegionTag, R uint64, alpha float64) SelectorLegASummary {
	n := len(ids)
	stride := 1
	if n > 100 {
		stride = n / 64
	}
	var sampled []int
	for i := 0; i < n; i += stride {
		sampled = append(sampled, i)
	}
	if n > 100 && len(sampled) < 64 {
		sampled = append(sampled, n-1)
	}
	regionSize := make(map[RegionTag]int, 8)
	for _, r := range regions {
		regionSize[r]++
	}
	t.Logf("selector uniformity layout=%s N=%d sampled=%d/%d stride=%d R=%d alpha=%g", l.name, n, len(sampled), n, stride, R, alpha)
	stats := make([]SelectorUniStats, len(sampled))
	var wg sync.WaitGroup
	sem := make(chan struct{}, simWorkerWidth())
	for k, idx := range sampled {
		wg.Add(1)
		sem <- struct{}{}
		go func(k, idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			stats[k] = runSelectorUniformity(idx, ids, regions, R, 0)
		}(k, idx)
	}
	wg.Wait()
	var sum SelectorLegASummary
	coverSum := uint64(0)
	uncensored := 0
	intraBad, picksBad := 0, 0
	worstChi2 := 0.0
	cells := 0
	for k := range sampled {
		st := stats[k]
		expIntra := regionSize[regions[sampled[k]]] - 1
		if st.intraCount != expIntra {
			intraBad++
		}
		for ri := range st.chi2 {
			if st.picksPerRegion[ri] != int(R) {
				picksBad++
			}
			cells++
			crit := selectorChi2Crit(st.dof[ri], alpha)
			if st.chi2[ri] > worstChi2 {
				worstChi2 = st.chi2[ri]
				sum.worstNode = sampled[k]
				sum.worstDof = st.dof[ri]
			}
			if ratio := st.chi2[ri] / crit; ratio > sum.worstChi2Ratio {
				sum.worstChi2Ratio = ratio
			}
		}
		if st.coverRound == 0 {
			sum.censored++
		} else {
			uncensored++
			coverSum += st.coverRound
			if st.coverRound > sum.coverMax {
				sum.coverMax = st.coverRound
			}
		}
		t.Logf("selector uniformity node=%d intra=%d chi2=%v dof=%v hitmin=%v hitmax=%v maxdev=%v coverRound=%d",
			sampled[k], st.intraCount, st.chi2, st.dof, st.hitmin, st.hitmax, st.maxdev, st.coverRound)
	}
	if uncensored > 0 {
		sum.coverMean = float64(coverSum) / float64(uncensored)
	}
	if intraBad > 0 {
		t.Errorf("%d sampled nodes did not return n_r-1 intra peers", intraBad)
	}
	if picksBad > 0 {
		t.Errorf("%d node-region slots did not receive exactly one pick per round", picksBad)
	}
	t.Logf("selector uniformity summary layout=%s worstChi2Ratio=%.3f node=%d dof=%d crit=%.1f censored=%d/%d coverMean=%.1f coverMax=%d",
		l.name, sum.worstChi2Ratio, sum.worstNode, sum.worstDof, selectorChi2Crit(sum.worstDof, alpha), sum.censored, len(sampled), sum.coverMean, sum.coverMax)
	// Correct across all sampled node-region cells. A separate alpha=0.001
	// threshold per cell would produce frequent false alarms under uniformity;
	// retain per-cell ratios for diagnostics but use the family-wise verdict.
	critCell := selectorChi2Crit(sum.worstDof, alpha)
	critBonf := selectorChi2Crit(sum.worstDof, alpha/float64(cells))
	t.Logf("selector uniformity Bonferroni layout=%s cells=%d worstChi2=%.1f perCellRatio=%.3f familyWiseRatio=%.3f critCell=%.1f critBonf=%.1f",
		l.name, cells, worstChi2, sum.worstChi2Ratio, worstChi2/critBonf, critCell, critBonf)
	if worstChi2 >= critBonf {
		t.Errorf("selector uniformity %s: node %d chi-square %.1f has alpha=%g cells=%d and family-wise critical value %.1f", l.name, sum.worstNode, worstChi2, alpha, cells, critBonf)
	}
	return sum
}

// runSelectorLegBC measures K rounds of combined in-degree for every region's
// full population. It checks one pick per remote region per node, applies a
// Bonferroni chi-square bound across region pairs and rounds, and reports the
// resulting per-node digest-request in-degree against the responder cap.
func runSelectorLegBC(t *testing.T, l *SelectorLayout, ids [][16]byte, regions []RegionTag, idTag map[[16]byte]RegionTag, K uint64, alpha float64) {
	regionSize := make(map[RegionTag]int, 8)
	for _, r := range regions {
		regionSize[r]++
	}
	// deterministic ascending tag order + contiguous spans (the population
	// assigns blocks, so a tag's span is [start, start+size)).
	var tags []RegionTag
	seenTag := make(map[RegionTag]bool, 8)
	for _, r := range regions {
		if !seenTag[r] {
			seenTag[r] = true
			tags = append(tags, r)
		}
	}
	for i := 1; i < len(tags); i++ {
		for j := i; j > 0 && tags[j] < tags[j-1]; j-- {
			tags[j], tags[j-1] = tags[j-1], tags[j]
		}
	}
	spans := make(map[RegionTag][2]int, 8)
	start := 0
	for _, tag := range tags {
		spans[tag] = [2]int{start, start + regionSize[tag]}
		start += regionSize[tag]
	}
	t.Logf("selector colocation layout=%s K=%d rounds, full population per region", l.name, K)
	worstChi2 := 0.0
	worstDof := 0
	worstTag := RegionTag(0)
	cells := 0
	pairMeans := make(map[RegionTag]float64, 8) // dst -> mean in-degree summed over sources
	drawsBad := 0
	for _, tagA := range tags {
		sp := spans[tagA]
		nA := sp[1] - sp[0]
		mgrs := make([]*TopologyManager, nA)
		for i := sp[0]; i < sp[1]; i++ {
			mgrs[i-sp[0]] = buildSelectorManager(i, ids, regions)
		}
		for round := uint64(1); round <= K; round++ {
			pairs := runSelectorColocation(round, sp[0], sp[1], ids, regions, mgrs, idTag, 0)
			for _, ps := range pairs {
				if ps.draws != nA {
					drawsBad++
				}
				crit := selectorChi2Crit(ps.dof, alpha)
				ratio := ps.chi2 / crit
				cells++
				if ps.chi2 > worstChi2 {
					worstChi2 = ps.chi2
					worstDof = ps.dof
					worstTag = tagA
				}
				pairMeans[ps.remote] += ps.mean / float64(K)
				t.Logf("selector colocation round=%d srcRegion=%d dstRegion=%d draws=%d m=%d mean=%.2f max=%d chi2=%.1f crit=%.1f ratio=%.2f",
					round, tagA, ps.remote, ps.draws, ps.m, ps.mean, ps.max, ps.chi2, crit, ratio)
			}
		}
	}
	if drawsBad > 0 {
		t.Errorf("%d round-region cells did not draw exactly n_A remote picks", drawsBad)
	}
	// Apply Bonferroni correction across every round-region cell. At 60 cells,
	// independent alpha=0.001 checks have an expected false-alarm rate near 6%.
	// With n_A draws over approximately n_A candidates, the chi-square upper
	// tail is outside its asymptotic accuracy, so retain raw ratios and maxima
	// for diagnostics and use the correlated negative controls to check power.
	critCell := selectorChi2Crit(worstDof, alpha)
	critBonf := selectorChi2Crit(worstDof, alpha/float64(cells))
	t.Logf("selector colocation summary layout=%s cells=%d worstChi2=%.1f dof=%d perCellRatio=%.3f familyWiseRatio=%.3f critCell=%.1f critBonf=%.1f srcRegion=%d",
		l.name, cells, worstChi2, worstDof, worstChi2/critCell, worstChi2/critBonf, critCell, critBonf, worstTag)
	if worstChi2 >= critBonf {
		t.Errorf("selector colocation %s: combined-pick chi-square %.1f has alpha=%g cells=%d and family-wise critical value %.1f", l.name, worstChi2, alpha, cells, critBonf)
	}
	// Combine the full intra-region term with measured inter-region in-degree
	// and compare the result with digestRespondMaxConcurrent.
	for _, tagB := range tags {
		nB := regionSize[tagB]
		intra := nB - 1
		inter := pairMeans[tagB]
		total := float64(intra) + inter
		t.Logf("digest-request in-degree region=%d: intra=%d interMean=%.3f total=%.1f responderCap=%d ratio=%.1fx",
			tagB, intra, inter, total, digestRespondMaxConcurrent, total/float64(digestRespondMaxConcurrent))
	}
	// runIntraPileup measures the partial intra view separately at f=8 and
	// cap=16; this full-mesh simulation does not reproduce that selector.
	t.Logf("partial intra-view in-degree is measured separately by runIntraPileup against responder cap %d", digestRespondMaxConcurrent)
}

// TestK8SelectorSim runs layouts from 100 to 10,000 nodes for 10,000 rounds by
// default. It measures per-pair uniformity, colocation, direct-pick coverage,
// and digest-request in-degree using the production seed chain and selector.
// RUN_SELECTOR_SIM=1 enables the grid; the micro-smoke remains ungated.
func TestK8SelectorSim(t *testing.T) {
	if os.Getenv("RUN_SELECTOR_SIM") != "1" {
		t.Skip("set RUN_SELECTOR_SIM=1 to run the expensive selector simulation")
	}
	R := uint64(10000)
	if v := os.Getenv("RUN_SELECTOR_SIM_ROUNDS"); v != "" {
		nr, err := strconv.Atoi(v)
		if err != nil || nr < 100 {
			t.Fatalf("RUN_SELECTOR_SIM_ROUNDS must be an integer >= 100, got %q", v)
		}
		R = uint64(nr)
	}
	const alpha = 0.001
	const coloRounds = 10
	// selectorScaleLayouts validates each label against its region counts.
	layouts := selectorScaleLayouts()
	for _, l := range layouts {
		l := l
		t.Run(l.name, func(t *testing.T) {
			ids, regions := buildSelectorPopulation(&l)
			idTag := make(map[[16]byte]RegionTag, len(ids))
			for j := range ids {
				idTag[ids[j]] = regions[j]
			}
			aSum := runSelectorLegA(t, &l, ids, regions, R, alpha)
			if l.total() <= 1000 && aSum.censored > 0 {
				t.Errorf("selector coverage %s: %d sampled nodes did not pick every remote candidate within R=%d", l.name, aSum.censored, R)
			}
			if l.total() > 1000 {
				remote := float64(l.total() - l.counts[0])
				analytic := remote * (math.Log(remote) + 0.5772) / 2
				t.Logf("selector coverage %s: %d sampled nodes censored at R=%d; analytic mean %.0f rounds for %.0f candidates", l.name, aSum.censored, R, analytic, remote)
			}
			runSelectorLegBC(t, &l, ids, regions, idTag, coloRounds, alpha)
		})
	}
}

// TestK8SelectorSimNegativeControl verifies that the uniformity and
// colocation detectors reject fixed per-node and shared-zero seeds on the
// 34/34/32 layout. A passing correlated control invalidates the detector.
func TestK8SelectorSimNegativeControl(t *testing.T) {
	if os.Getenv("RUN_SELECTOR_SIM") != "1" {
		t.Skip("set RUN_SELECTOR_SIM=1 to run selector negative controls")
	}
	const alpha = 0.001
	const R = 1000
	l := SelectorLayout{name: "N100-34-34-32", counts: []int{34, 34, 32}}
	ids, regions := buildSelectorPopulation(&l)
	idTag := make(map[[16]byte]RegionTag, len(ids))
	for j := range ids {
		idTag[ids[j]] = regions[j]
	}
	// Removing the round term must make every sampled node non-uniform.
	t.Logf("fixed per-node seed control: uniformity detector must reject all 8 sampled nodes")
	for _, idx := range []int{0, 13, 34, 47, 68, 80, 90, 99} {
		st := runSelectorUniformity(idx, ids, regions, R, 1)
		for ri := range st.chi2 {
			crit := selectorChi2Crit(st.dof[ri], alpha)
			ratio := st.chi2[ri] / crit
			verdict := "detected"
			if ratio < 2 {
				verdict = "not detected"
			}
			t.Logf("fixed-seed control node=%d slot=%d chi2=%.1f crit=%.1f ratio=%.1fx hitmin=%d hitmax=%d picks=%d: %s",
				idx, ri, st.chi2[ri], crit, ratio, st.hitmin[ri], st.hitmax[ri], st.picksPerRegion[ri], verdict)
			if ratio < 2 {
				t.Fatalf("fixed-seed correlation was not detected at node %d slot %d: chi2=%.1f crit=%.1f", idx, ri, st.chi2[ri], crit)
			}
		}
	}
	// A shared zero seed must put all 34 nodes' picks on one candidate per
	// remote region, and the chi-square detector must reject that distribution.
	t.Logf("shared-zero control: 34 colocated nodes in one round")
	mgrs := make([]*TopologyManager, 34)
	for i := 0; i < 34; i++ {
		mgrs[i] = buildSelectorManager(i, ids, regions)
	}
	pairs := runSelectorColocation(1, 0, 34, ids, regions, mgrs, idTag, 2)
	for _, ps := range pairs {
		crit := selectorChi2Crit(ps.dof, alpha)
		ratio := ps.chi2 / crit
		t.Logf("shared-zero control dstRegion=%d draws=%d m=%d mean=%.2f max=%d chi2=%.1f crit=%.1f ratio=%.1fx",
			ps.remote, ps.draws, ps.m, ps.mean, ps.max, ps.chi2, crit, ratio)
		if ps.max != 34 {
			t.Fatalf("shared-zero maximum=%d, want 34 colocated picks on one candidate", ps.max)
		}
		if ratio < 2 {
			t.Fatalf("shared-zero pile-up was not detected: chi-square ratio=%.2fx", ratio)
		}
	}
}

// TestK8SelectorSimMicroSmoke runs the uniformity instrument on six nodes for
// 40 rounds without an environment gate. It checks list sizes, remote
// coverage, deterministic selection for equal seeds, and rotation of the
// inter-region pick.
func TestK8SelectorSimMicroSmoke(t *testing.T) {
	l := SelectorLayout{name: "micro-6", counts: []int{3, 3}}
	ids, regions := buildSelectorPopulation(&l)
	idTag := make(map[[16]byte]RegionTag, len(ids))
	for j := range ids {
		idTag[ids[j]] = regions[j]
	}
	st := runSelectorUniformity(0, ids, regions, 40, 0)
	if st.intraCount != 2 {
		t.Fatalf("micro intra list=%d, want n_r-1=2", st.intraCount)
	}
	if len(st.chi2) != 1 || st.picksPerRegion[0] != 40 {
		t.Fatalf("micro remote regions=%d picks=%v, want one region with 40 picks", len(st.chi2), st.picksPerRegion)
	}
	if st.coverRound == 0 || st.coverRound > 40 {
		t.Fatalf("micro coverRound=%d, want all three remote candidates within 40 rounds", st.coverRound)
	}
	m1 := buildSelectorManager(0, ids, regions)
	m2 := buildSelectorManager(0, ids, regions)
	s7 := selectorRoundSeed(7, ids[0])
	m1.SetSeed(s7)
	m2.SetSeed(s7)
	if !samePeerSet(m1.Select(context.Background()), m2.Select(context.Background())) {
		t.Fatalf("identical seeds produced different Select outputs")
	}
	distinct := make(map[[16]byte]bool, 3)
	for round := uint64(1); round <= 12; round++ {
		m1.SetSeed(selectorRoundSeed(round, ids[0]))
		for _, p := range m1.Select(context.Background()) {
			if idTag[p] != regions[0] {
				distinct[p] = true
			}
		}
	}
	if len(distinct) < 2 {
		t.Fatalf("round term did not rotate the remote selection across 12 rounds")
	}
}

// The partial intra-view measurements reuse the seed chain and statistical
// checks above, but enable SetPartialIntraView. They cover f=8 view uniformity
// across rounds and the combined in-degree of a region's synchronized draws.
// The selector remains the production implementation throughout.

// buildArmedManager constructs a manager with the partial intra view enabled.
func buildArmedManager(idx int, ids [][16]byte, regions []RegionTag) *TopologyManager {
	mgr := buildSelectorManager(idx, ids, regions)
	mgr.SetPartialIntraView(true)
	return mgr
}

// IntraUniStats measures one node's partial intra view over R rounds.
type IntraUniStats struct {
	n          int     // candidate population (n_r - 1)
	picks      int     // total intra picks over R rounds
	sizeBad    int     // rounds whose view size differs from min(f, n_r-1)
	chi2       float64 // multinomial chi-square over all n candidates
	maxdev     float64
	hitmin     int
	hitmax     int
	dof        int
	coverRound uint64 // first round every intra candidate was hit; 0 if censored
	distinct   int    // distinct view subsets over R rounds
}

// runIntraUniformity measures one node's partial intra view over rounds 1..R.
// negCtl follows runSelectorUniformity: 0 uses the production seed, 1 removes
// the round term, and 2 uses a shared zero seed. Selection remains unchanged.
func runIntraUniformity(idx int, ids [][16]byte, regions []RegionTag, R uint64, negCtl int) IntraUniStats {
	mgr := buildArmedManager(idx, ids, regions)
	idTag := make(map[[16]byte]RegionTag, len(ids))
	for j := range ids {
		idTag[ids[j]] = regions[j]
	}
	our := regions[idx]
	var st IntraUniStats
	for j := range ids {
		if j != idx && regions[j] == our {
			st.n++
		}
	}
	want := minInt(intraViewSize, st.n)
	st.hitmin = int(math.MaxInt64)
	ctx := context.Background()
	id := ids[idx]
	counts := make(map[[16]byte]int, 32)
	seenView := make(map[uint64]bool, 64)
	covered := 0
	for round := uint64(1); round <= R; round++ {
		var seed uint64
		switch negCtl {
		case 1:
			seed = binary.LittleEndian.Uint64(id[:8]) // fixed per-node seed
		case 2:
			seed = 0 // shared seed forces identical views
		default:
			seed = selectorRoundSeed(round, id)
		}
		mgr.SetSeed(seed)
		sel := mgr.Select(ctx)
		view := make([][16]byte, 0, want)
		for _, p := range sel {
			if idTag[p] == our {
				counts[p]++
				view = append(view, p)
			}
		}
		if len(view) != want {
			st.sizeBad++
		}
		st.picks += len(view)
		// Sort at most eight entries, then fingerprint both eight-byte halves
		// of each ID to compare distinct view subsets.
		for i := 1; i < len(view); i++ {
			for j := i; j > 0 && lessID(view[j], view[j-1]); j-- {
				view[j], view[j-1] = view[j-1], view[j]
			}
		}
		seenView[viewFingerprint(view)] = true
		if covered < st.n {
			for _, p := range view {
				if counts[p] == 1 { // this candidate's first pick in the run
					covered++
				}
			}
			if covered == st.n {
				st.coverRound = round
			}
		}
	}
	if st.n == 0 { // degenerate single-node region: nothing to measure
		return st
	}
	st.dof = st.n - 1
	exp := float64(st.picks) / float64(st.n)
	for _, c := range counts {
		dev := math.Abs(float64(c) - exp)
		if dev > st.maxdev {
			st.maxdev = dev
		}
		if c < st.hitmin {
			st.hitmin = c
		}
		if c > st.hitmax {
			st.hitmax = c
		}
		st.chi2 += dev * dev / exp
	}
	if len(counts) < st.n {
		st.hitmin = 0 // candidates never drawn set the minimum to zero
		st.chi2 += float64(st.n-len(counts)) * exp
	}
	st.distinct = len(seenView)
	return st
}

// IntraPileStats holds one round's combined partial-view in-degree for a
// region. Every member selects min(f,m-1) peers, so picks totals m*min(f,m-1)
// across the region's m candidates.
type IntraPileStats struct {
	region   RegionTag
	m        int     // candidate population (the region's node count)
	picks    int     // total in-degrees this round
	chi2     float64 // multinomial chi-square over all m candidates
	maxIn    int     // maximum candidate in-degree
	distinct int     // candidates drawn at least once this round
	dof      int
}

// runIntraPileup measures combined in-degree for one region's synchronized
// partial-view selections. negCtl 0 uses selectorRoundSeed; negCtl 2 uses a
// shared zero seed to force identical permutations. The production armed
// selector is used in both cases.
func runIntraPileup(ids [][16]byte, regions []RegionTag, tag RegionTag, round uint64, negCtl int) IntraPileStats {
	idTag := make(map[[16]byte]RegionTag, len(ids))
	for j := range ids {
		idTag[ids[j]] = regions[j]
	}
	var members []int
	for j := range regions {
		if regions[j] == tag {
			members = append(members, j)
		}
	}
	var st IntraPileStats
	st.region = tag
	st.m = len(members)
	st.dof = st.m - 1
	if st.m == 0 {
		return st
	}
	ctx := context.Background()
	indeg := make(map[[16]byte]int, st.m)
	for _, j := range members {
		mgr := buildArmedManager(j, ids, regions)
		var seed uint64
		switch negCtl {
		case 2:
			seed = 0 // shared zero seed gives every node the same permutation
		default:
			seed = selectorRoundSeed(round, ids[j]) // production round-and-node seed chain
		}
		mgr.SetSeed(seed)
		for _, p := range mgr.Select(ctx) {
			if idTag[p] == tag {
				indeg[p]++
				st.picks++
			}
		}
	}
	if st.picks == 0 { // single-node region: nothing to measure (0/0 chi2 guard)
		return st
	}
	lambda := float64(st.picks) / float64(st.m)
	for _, c := range indeg {
		dev := float64(c) - lambda
		st.chi2 += dev * dev / lambda
		if c > st.maxIn {
			st.maxIn = c
		}
	}
	st.distinct = len(indeg)
	// Never-drawn candidates each contribute lambda to chi-square.
	st.chi2 += float64(st.m-st.distinct) * lambda
	return st
}

// TestK8IntraViewSim measures the partial intra view at four layouts from 100
// to 3,333 nodes. RUN_SELECTOR_SIM_ROUNDS sets the round count, default 10,000.
// Per-node uniformity uses a fixed-stride sample and Bonferroni correction;
// coverage is required through N=1000 and censored tails are reported above
// it. Whole-region pile-up runs unsampled for ten rounds and compares maximum
// in-degree with the responder cap and a family-wise Poisson(f) bound.
func TestK8IntraViewSim(t *testing.T) {
	if os.Getenv("RUN_SELECTOR_SIM") != "1" {
		t.Skip("set RUN_SELECTOR_SIM=1 to run the partial intra-view simulation")
	}
	R := uint64(10000)
	if v := os.Getenv("RUN_SELECTOR_SIM_ROUNDS"); v != "" {
		nr, err := strconv.Atoi(v)
		if err != nil || nr < 100 {
			t.Fatalf("RUN_SELECTOR_SIM_ROUNDS must be an integer >= 100, got %q", v)
		}
		R = uint64(nr)
	}
	const alpha = 0.001
	const pileRounds = 10
	// This helper rebuilds managers per member-round and is too expensive for
	// the 10,000-node layout; selectorScaleGrid covers that layout separately.
	layouts := selectorScaleLayouts()[:4]
	for _, l := range layouts {
		l := l
		t.Run(l.name, func(t *testing.T) {
			ids, regions := buildSelectorPopulation(&l)
			// Per-node uniformity uses a fixed-stride sample.
			n := len(ids)
			stride := 1
			if n > 64 {
				stride = n / 64
			}
			var sampled []int
			for i := 0; i < n; i += stride {
				sampled = append(sampled, i)
			}
			if n > 100 && len(sampled) < 64 {
				sampled = append(sampled, n-1)
			}
			worstChi2, worstNode, worstDof := 0.0, -1, 0
			censored := 0
			for _, idx := range sampled {
				st := runIntraUniformity(idx, ids, regions, R, 0)
				if st.sizeBad > 0 {
					t.Fatalf("intra view %s node=%d: %d/%d rounds did not draw min(f,n_r-1)", l.name, idx, st.sizeBad, R)
				}
				if st.distinct < 2 {
					t.Fatalf("intra view %s node=%d: only %d distinct views over %d rounds", l.name, idx, st.distinct, R)
				}
				if st.chi2 > worstChi2 {
					worstChi2, worstNode, worstDof = st.chi2, idx, st.dof
				}
				if st.coverRound == 0 && l.total() <= 1000 {
					censored++
				}
			}
			critBonf := selectorChi2Crit(worstDof, alpha/float64(len(sampled)))
			t.Logf("intra-view uniformity %s: sampled=%d R=%d worstChi2=%.1f node=%d dof=%d familyWiseCrit=%.1f censored=%d/%d",
				l.name, len(sampled), R, worstChi2, worstNode, worstDof, critBonf, censored, len(sampled))
			if worstChi2 >= critBonf {
				t.Errorf("intra-view uniformity %s: node %d chi-square %.1f reaches the family-wise critical value (alpha=%g samples=%d critical=%.1f)", l.name, worstNode, worstChi2, alpha, len(sampled), critBonf)
			}
			if l.total() <= 1000 && censored > 0 {
				t.Errorf("intra-view coverage %s: %d sampled nodes did not draw every candidate within R=%d", l.name, censored, R)
			}
			// Combined in-degree uses every region member without sampling.
			ourTag := regions[0]
			m := l.counts[0]
			maxIn := 0
			worstPile, worstRound, pileDof := 0.0, -1, 0
			for round := uint64(1); round <= pileRounds; round++ {
				st := runIntraPileup(ids, regions, ourTag, round, 0)
				// Every member draws min(f,m-1) peers, so total picks must be
				// m*min(f,m-1).
				if st.picks != m*minInt(intraViewSize, m-1) {
					t.Fatalf("intra pile-up %s round=%d: drew %d picks, want %d (m=%d min(f,m-1)=%d)", l.name, round, st.picks, m*minInt(intraViewSize, m-1), m, minInt(intraViewSize, m-1))
				}
				if st.chi2 > worstPile {
					worstPile, worstRound, pileDof = st.chi2, int(round), st.dof
				}
				if st.maxIn > maxIn {
					maxIn = st.maxIn
				}
			}
			pileCrit := selectorChi2Crit(pileDof, alpha/float64(pileRounds))
			// Use the smallest k whose Poisson(f) tail times m*K is below
			// alpha. Competing multinomial candidates make this independent-
			// Poisson bound conservative.
			f := intraViewSize
			if m-1 < f {
				f = m - 1
			}
			kCap := 0
			for k := f + 1; k <= m; k++ {
				if selectorPoissonTail(float64(f), k)*float64(m)*float64(pileRounds) < alpha {
					kCap = k
					break
				}
			}
			t.Logf("intra pile-up %s: region=%v m=%d K=%d worstChi2=%.1f round=%d dof=%d BonferroniCrit=%.1f maxIn=%d poissonCap=%d responderCap=%d",
				l.name, ourTag, m, pileRounds, worstPile, worstRound, pileDof, pileCrit, maxIn, kCap, digestRespondMaxConcurrent)
			if maxIn >= digestRespondMaxConcurrent {
				t.Logf("intra pile-up maximum=%d meets responder cap=%d; the cap limits concurrent builds, not a round's static in-degree", maxIn, digestRespondMaxConcurrent)
			}
			if worstPile >= pileCrit {
				t.Errorf("intra pile-up %s: round %d chi-square %.1f reaches critical value %.1f", l.name, worstRound, worstPile, pileCrit)
			}
			if kCap > 0 && maxIn >= kCap {
				t.Errorf("intra pile-up %s: maximum in-degree %d reaches family-wise Poisson cap %d", l.name, maxIn, kCap)
			}
		})
	}
}

// TestK8IntraViewSimNegativeControl requires both partial-view detectors to
// reject correlated seeds. A fixed per-node seed must produce one view subset
// and fail uniformity; a shared zero seed must concentrate in-degree and fail
// the pile-up check.
func TestK8IntraViewSimNegativeControl(t *testing.T) {
	if os.Getenv("RUN_SELECTOR_SIM") != "1" {
		t.Skip("set RUN_SELECTOR_SIM=1 to run partial-view negative controls")
	}
	const alpha = 0.001
	const R = 1000
	l := SelectorLayout{name: "N100-34-34-32", counts: []int{34, 34, 32}}
	ids, regions := buildSelectorPopulation(&l)
	// Removing the round term must leave exactly one subset per sampled node.
	for _, idx := range []int{0, 13, 34, 47, 68, 80, 90, 99} {
		st := runIntraUniformity(idx, ids, regions, R, 1)
		crit := selectorChi2Crit(st.dof, alpha)
		if st.distinct != 1 {
			t.Fatalf("fixed-seed control node=%d produced %d distinct views, want 1", idx, st.distinct)
		}
		if st.chi2 < 2*crit {
			t.Fatalf("fixed-view control was not detected at node=%d: chi2=%.1f crit=%.1f", idx, st.chi2, crit)
		}
		t.Logf("fixed-seed control node=%d chi2=%.1f crit=%.1f ratio=%.1fx distinct=1 detected", idx, st.chi2, crit, st.chi2/crit)
	}
	// A shared zero seed must force the same permutation across the region.
	tag := regions[0]
	st := runIntraPileup(ids, regions, tag, 1, 2)
	crit := selectorChi2Crit(st.dof, alpha)
	if st.maxIn < 2*intraViewSize {
		t.Fatalf("shared-zero control maxIn=%d, want at least %d", st.maxIn, 2*intraViewSize)
	}
	if st.chi2 < 2*crit {
		t.Fatalf("shared-zero pile-up was not detected: chi2=%.1f crit=%.1f", st.chi2, crit)
	}
	t.Logf("shared-zero control region=%v m=%d maxIn=%d chi2=%.1f crit=%.1f ratio=%.1fx detected", tag, st.m, st.maxIn, st.chi2, crit, st.chi2/crit)
}

// TestK8IntraViewSimMicroSmoke exercises every node in a 30-node layout for
// 200 rounds. With nine intra candidates and f=8, it checks exact view size,
// unchanged inter-region selections at equal seeds, complete peer coverage,
// and at least eight of the nine possible view subsets. No environment gate
// is required.
func TestK8IntraViewSimMicroSmoke(t *testing.T) {
	l := SelectorLayout{name: "micro-30", counts: []int{10, 10, 10}}
	ids, regions := buildSelectorPopulation(&l)
	idTag := make(map[[16]byte]RegionTag, len(ids))
	for j := range ids {
		idTag[ids[j]] = regions[j]
	}
	ctx := context.Background()
	for idx := range ids {
		armed := buildArmedManager(idx, ids, regions)
		bare := buildSelectorManager(idx, ids, regions)
		counts := make(map[[16]byte]int, 9)
		seenView := make(map[uint64]bool, 9)
		for round := uint64(1); round <= 200; round++ {
			seed := selectorRoundSeed(round, ids[idx])
			armed.SetSeed(seed)
			sel := armed.Select(ctx)
			bare.SetSeed(seed)
			ref := bare.Select(ctx)
			var aInter, bInter [][16]byte
			view := make([][16]byte, 0, intraViewSize)
			for _, p := range sel {
				if idTag[p] == regions[idx] {
					view = append(view, p)
					counts[p]++
				} else {
					aInter = append(aInter, p)
				}
			}
			for _, p := range ref {
				if idTag[p] != regions[idx] {
					bInter = append(bInter, p)
				}
			}
			if len(view) != intraViewSize {
				t.Fatalf("micro: node %d round %d drew view size %d, want %d — the draw does not cut to f at n_r-1=9", idx, round, len(view), intraViewSize)
			}
			if !viewSameSelection(aInter, bInter) {
				t.Fatalf("micro node=%d round=%d: enabling the partial intra view changed inter picks (armed=%d bare=%d)", idx, round, len(aInter), len(bInter))
			}
			for i := 1; i < len(view); i++ {
				for j := i; j > 0 && lessID(view[j], view[j-1]); j-- {
					view[j], view[j-1] = view[j-1], view[j]
				}
			}
			seenView[viewFingerprint(view)] = true
		}
		for j := range ids {
			if j == idx || regions[j] != regions[idx] {
				continue
			}
			if counts[ids[j]] == 0 {
				t.Fatalf("micro: node %d never drew intra peer %d in 200 rounds — the view does not cover", idx, j)
			}
		}
		if len(seenView) < 8 {
			t.Fatalf("micro: node %d drew only %d distinct view subsets over 200 rounds (>= 8 of the 9 8-of-9 subsets expected) — the view is not rotating across the lattice", idx, len(seenView))
		}
	}
}
