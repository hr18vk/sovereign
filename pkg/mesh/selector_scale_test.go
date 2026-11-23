// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests measure selector coverage and in-degree at layouts up to
// 10,000 nodes (ADR-0065). They use (*TopologyManager).Select and its public
// setters directly; the harness does not reproduce the selection algorithm.
// selectorRoundSeed matches the seed expression in SweepLoop.
//
// Rumor coverage counts the rounds until a delta reaches every node in its
// origin's region through the union of each round's Select results. This is
// multi-hop propagation, distinct from the direct-pick coverage measured by
// the selector simulation. One origin-independent graph serves seven origins.
//
// The synchronized intra-region draws are checked against a Poisson(f)
// reference. Per-round p99 must not exceed the responder cap of 16 (2f), and
// the maximum must remain below a family-wise Poisson tail bound. A flat
// maximum-versus-cap assertion would reject valid Poisson samples. The tests
// also record the overflow fraction and use Bonferroni correction across
// regions and rounds. Small populations do not assert p99 because it then
// coincides with the maximum.
//
// Negative controls cover a one-region starvation partition and a shared-zero
// seed that forces correlated picks. At a three-region layout, starvation
// from every same-region view is not a coverage partition: foreign nodes can
// still select the victim through inter-region fan-out. The multi-region
// control measures that path rather than expecting censoring.
//
// Sweep phase jitter is opt-in and disabled by default (ADR-0066). These
// measurements therefore use the synchronized, jitter-free draw.
//
// SOVEREIGN_TEST_SELECTOR_SCALE=1 enables the expensive scale grid, and
// SOVEREIGN_TEST_SELECTOR_ARMS selects individual measurements. The ungated
// TestSelectorScaleMicroSmoke exercises every instrument on small layouts.

import (
	"context"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// selectorDemersBar returns ceil(2*(log2(n_r)+ln(n_r))), twice the
// conservative Demers f=1 push bound. The f=8 draw is expected to finish
// sooner; this bound detects concentration or skipped candidates rather than
// optimality. Region sizes 333, 1111, and 3333 give bounds 29, 35, and 40.
func selectorDemersBar(nRegion int) int {
	if nRegion < 2 {
		return 1
	}
	return int(math.Ceil(2 * (math.Log2(float64(nRegion)) + math.Log(float64(nRegion)))))
}

// selectorEnvInt reads an integer environment override with a floor. Empty,
// malformed, and sub-floor values use the default.
func selectorEnvInt(name string, floor, deflt int) int {
	v := os.Getenv(name)
	if v == "" {
		return deflt
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < floor {
		return deflt
	}
	return n
}

// selectorArms decodes the comma-separated SOVEREIGN_TEST_SELECTOR_ARMS
// selection. An empty value enables every arm; an unknown value is returned
// so the caller cannot accidentally run an empty grid.
func selectorArms() (map[string]bool, string) {
	m := map[string]bool{}
	v := os.Getenv("SOVEREIGN_TEST_SELECTOR_ARMS")
	if v == "" {
		for _, a := range []string{"A", "B", "C", "D", "E"} {
			m[a] = true
		}
		return m, ""
	}
	for _, a := range strings.Split(v, ",") {
		a = strings.ToUpper(strings.TrimSpace(a))
		switch a {
		case "A", "B", "C", "D", "E":
			m[a] = true
		default:
			// Reject unknown tokens rather than silently selecting zero arms.
			return map[string]bool{}, a
		}
	}
	return m, ""
}

// selectorScaleLayouts returns the scale grid shared with the selector
// simulation. The layout label's node count must equal its region counts.
func selectorScaleLayouts() []SelectorLayout {
	ls := []SelectorLayout{
		{name: "N100-34-34-32", counts: []int{34, 34, 32}},
		{name: "N333-111x3", counts: []int{111, 111, 111}},
		{name: "N1000-333-333-334", counts: []int{333, 333, 334}},
		{name: "N3333-1111x3", counts: []int{1111, 1111, 1111}},
		{name: "N10000-3333-3333-3334", counts: []int{3333, 3333, 3334}},
	}
	// Reject a label that describes a different population from its counts.
	for _, l := range ls {
		sum := 0
		for _, c := range l.counts {
			sum += c
		}
		n := 0
		for _, ch := range strings.TrimPrefix(l.name, "N") {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		if n != sum {
			panic("selectorScaleLayouts sum invariant violated: " + l.name)
		}
	}
	return ls
}

// selectorFindLayout returns a named layout or fails on an invalid test name.
func selectorFindLayout(t *testing.T, name string) SelectorLayout {
	t.Helper()
	for _, l := range selectorScaleLayouts() {
		if l.name == name {
			return l
		}
	}
	t.Fatalf("selector: layout %q not in the grid — harness bug", name)
	return SelectorLayout{}
}

// selectorRumorGraph precomputes Select results for every node and round.
// edges[node][round-1] contains the intra-view and inter-region destinations
// used for delta propagation. Managers are worker-local so at most width are
// live at once. A nonnegative starveIdx removes that peer from every intra
// view; -1 leaves the views unchanged.
func selectorRumorGraph(ids [][16]byte, regions []RegionTag, rounds int, starveIdx int) [][][]int {
	n := len(ids)
	idToIdx := make(map[[16]byte]int, n)
	for i := range ids {
		idToIdx[ids[i]] = i
	}
	edges := make([][][]int, n)
	width := simWorkerWidth()
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < width; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				myIdx := int(next.Add(1)) - 1
				if myIdx >= n {
					return
				}
				mgr := buildArmedManager(myIdx, ids, regions)
				if starveIdx >= 0 {
					mgr.StarveViewPeerOf(ids[starveIdx])
				}
				myEdges := make([][]int, rounds)
				for round := 1; round <= rounds; round++ {
					mgr.SetSeed(selectorRoundSeed(uint64(round), ids[myIdx]))
					sel := mgr.Select(context.Background())
					row := make([]int, 0, 10)
					for _, p := range sel {
						row = append(row, idToIdx[p])
					}
					myEdges[round-1] = row
				}
				edges[myIdx] = myEdges
			}
		}()
	}
	wg.Wait()
	return edges
}

// selectorRumorRounds runs push gossip over the graph. The origin holds the
// delta at round 0; each round spreads it along the selected edges, including
// foreign edges that lead back into the origin's region. It returns the first
// round covering every same-region node, or 0 if coverage exceeds the horizon.
func selectorRumorRounds(edges [][][]int, regions []RegionTag, origin int) int {
	infected := make([]bool, len(edges))
	infected[origin] = true
	want := 0
	for j := range edges {
		if regions[j] == regions[origin] {
			want++
		}
	}
	if want <= 1 {
		return 1 // the origin is its region's only member
	}
	have := 1
	horizon := len(edges[origin])
	for round := 0; round < horizon; round++ {
		// Only nodes infected before this round may spread now. Using a
		// frontier snapshot prevents same-round chaining and preserves the
		// one-sweep-per-hop meaning of the round count.
		frontier := make([]bool, len(infected))
		copy(frontier, infected)
		for i := range edges {
			if !frontier[i] {
				continue
			}
			for _, p := range edges[i][round] {
				if !infected[p] {
					infected[p] = true
					if regions[p] == regions[origin] {
						have++
					}
				}
			}
		}
		if have == want {
			return round + 1
		}
	}
	return 0
}

// SelectorIndegStats summarizes one per-candidate in-degree distribution.
type SelectorIndegStats struct {
	m        int // candidate population
	mean     float64
	p99      int // empirical 99th percentile at sorted index floor(0.99*m)
	max      int
	overflow int     // candidates with in-degree greater than capRef
	chi2     float64 // multinomial chi-square over all m candidates
	dof      int
}

// selectorIndegSummary computes statistics over every candidate, including
// zero-count candidates. lambda is Poisson(f) for intra-region draws and the
// foreign-picker ratio for inter-region draws. capRef is the responder cap
// used only to count overflows.
func selectorIndegSummary(counts []int, lambda float64, capRef int) SelectorIndegStats {
	st := SelectorIndegStats{m: len(counts), dof: len(counts) - 1}
	var sum int
	for _, c := range counts {
		sum += c
	}
	if st.m == 0 || sum == 0 {
		return st
	}
	st.mean = float64(sum) / float64(st.m)
	if lambda <= 0 {
		lambda = st.mean
	}
	sorted := append([]int(nil), counts...)
	sort.Ints(sorted)
	st.max = sorted[len(sorted)-1]
	idx := int(math.Floor(0.99 * float64(st.m)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	st.p99 = sorted[idx]
	for _, c := range counts {
		if c > capRef {
			st.overflow++
		}
		dev := float64(c) - lambda
		st.chi2 += dev * dev / lambda
	}
	return st
}

// selectorDenseOf extracts one region's counts by checking every region tag;
// it does not depend on contiguous population blocks.
func selectorDenseOf(counts []int, regions []RegionTag, tag RegionTag) []int {
	dense := make([]int, 0, 64)
	for i := range counts {
		if regions[i] == tag {
			dense = append(dense, counts[i])
		}
	}
	return dense
}

// selectorPileupViews drives every member of one region through K
// synchronized rounds. negCtl 0 uses selectorRoundSeed; negCtl 2 uses a shared
// zero seed to force correlated draws. Each manager is reused across rounds,
// avoiding a manager rebuild for every member-round pair. It returns member
// indices and each member's intra-region picks by round.
func selectorPileupViews(ids [][16]byte, regions []RegionTag, tag RegionTag, K uint64, negCtl int) ([]int, [][][]int) {
	idToIdx := make(map[[16]byte]int, len(ids))
	for i := range ids {
		idToIdx[ids[i]] = i
	}
	var members []int
	for j := range ids {
		if regions[j] == tag {
			members = append(members, j)
		}
	}
	m := len(members)
	views := make([][][]int, m)
	width := simWorkerWidth()
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < width; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				k := int(next.Add(1)) - 1
				if k >= m {
					return
				}
				j := members[k]
				mgr := buildArmedManager(j, ids, regions)
				rows := make([][]int, K)
				for round := uint64(1); round <= K; round++ {
					var seed uint64
					if negCtl == 2 {
						seed = 0 // shared seed forces identical permutations
					} else {
						seed = selectorRoundSeed(round, ids[j])
					}
					mgr.SetSeed(seed)
					sel := mgr.Select(context.Background())
					row := make([]int, 0, 8)
					for _, p := range sel {
						if regions[idToIdx[p]] == tag {
							row = append(row, idToIdx[p])
						}
					}
					rows[round-1] = row
				}
				views[k] = rows
			}
		}()
	}
	wg.Wait()
	return members, views
}

// selectorPileupCounts returns counts[k], the in-degree of members[k] in one
// round's combined views.
func selectorPileupCounts(views [][][]int, members []int, roundIdx int) []int {
	counts := make([]int, len(members))
	idxOf := make(map[int]int, len(members))
	for k, j := range members {
		idxOf[j] = k
	}
	for k := range views {
		for _, p := range views[k][roundIdx] {
			counts[idxOf[p]]++
		}
	}
	return counts
}

// selectorDistributionalCheck checks each round's p99 against the responder
// cap, its maximum against a family-wise Poisson tail bound, and its
// chi-square statistic against a Bonferroni critical value. cells is the
// region-round family size used for multiplicity correction; overflow counts
// are recorded rather than treated as an independent failure.
func selectorDistributionalCheck(t *testing.T, layoutName string, ids [][16]byte, regions []RegionTag, tag RegionTag, K uint64, cells int, alpha float64) {
	t.Helper()
	members, views := selectorPileupViews(ids, regions, tag, K, 0)
	m := len(members)
	if m < 2 {
		return
	}
	f := minInt(intraViewSize, m-1)
	// Choose the smallest k whose independent-Poisson tail times m*K is below
	// alpha. Competing multinomial candidates make this bound conservative.
	kCap := 0
	for k := f + 1; k <= m; k++ {
		if selectorPoissonTail(float64(f), k)*float64(m)*float64(K) < alpha {
			kCap = k
			break
		}
	}
	worstChi2, worstP99, worstMax := 0.0, 0, 0
	var overflow, samples int64
	picksBad := 0
	for r := 0; r < int(K); r++ {
		dense := selectorPileupCounts(views, members, r)
		picks := 0
		for _, c := range dense {
			picks += c
		}
		if picks != m*f {
			picksBad++
		}
		st := selectorIndegSummary(dense, float64(f), digestRespondMaxConcurrent)
		overflow += int64(st.overflow)
		samples += int64(m)
		if st.chi2 > worstChi2 {
			worstChi2 = st.chi2
		}
		if st.p99 > worstP99 {
			worstP99 = st.p99
		}
		if st.max > worstMax {
			worstMax = st.max
		}
	}
	crit := selectorChi2Crit(m-1, alpha/float64(cells))
	t.Logf("selector in-degree %s region=%d: m=%d K=%d f=%d p99=%d (cap %d) max=%d (family-wise cap %d) chi2=%.1f (critical %.1f, cells %d) overflow=%d/%d (%.5f)",
		layoutName, tag, m, K, f, worstP99, digestRespondMaxConcurrent, worstMax, kCap, worstChi2, crit, cells, overflow, samples, float64(overflow)/float64(samples))
	if picksBad > 0 {
		t.Errorf("selector %s region=%d: %d/%d rounds did not draw m*min(f,m-1) intra peers", layoutName, tag, picksBad, K)
	}
	if worstP99 > digestRespondMaxConcurrent {
		t.Errorf("selector %s region=%d: p99 in-degree %d exceeds responder cap %d", layoutName, tag, worstP99, digestRespondMaxConcurrent)
	}
	if kCap > 0 && worstMax >= kCap {
		t.Errorf("selector %s region=%d: maximum in-degree %d reaches family-wise Poisson cap %d (m=%d K=%d alpha=%g)", layoutName, tag, worstMax, kCap, m, K, alpha)
	}
	if worstChi2 >= crit {
		t.Errorf("selector %s region=%d: chi-square %.1f reaches the family-wise critical value (alpha=%g cells=%d critical=%.1f)", layoutName, tag, worstChi2, alpha, cells, crit)
	}
}

// selectorInterCheck checks the 10,000-node inter-region in-degree maximum
// against a family-wise Poisson bound. Each foreign node makes one selection
// into a distinct region, so lambda is foreign pickers divided by candidates.
// The selector simulation covers the corresponding chi-square measurement.
func selectorInterCheck(t *testing.T, graph [][][]int, regions []RegionTag, tag RegionTag, alpha float64) {
	t.Helper()
	m, foreign := 0, 0
	for _, r := range regions {
		if r == tag {
			m++
		} else {
			foreign++
		}
	}
	if m == 0 || foreign == 0 {
		return
	}
	lambda := float64(foreign) / float64(m)
	horizon := len(graph[0])
	kCap := 0
	for k := int(lambda) + 1; k <= foreign; k++ {
		if selectorPoissonTail(lambda, k)*float64(m)*float64(horizon) < alpha {
			kCap = k
			break
		}
	}
	counts := make([]int, len(regions))
	worst, worstRound := 0, -1
	for r := 0; r < horizon; r++ {
		for i := range counts {
			counts[i] = 0
		}
		for i := range graph {
			if regions[i] == tag {
				continue
			}
			for _, p := range graph[i][r] {
				if regions[p] == tag {
					counts[p]++
				}
			}
		}
		st := selectorIndegSummary(selectorDenseOf(counts, regions, tag), lambda, digestRespondMaxConcurrent)
		if st.max > worst {
			worst, worstRound = st.max, r
		}
	}
	t.Logf("inter-region in-degree region=%d: m=%d lambda=%.4f horizon=%d max=%d (round %d) family-wise cap=%d", tag, m, lambda, horizon, worst, worstRound, kCap)
	if kCap > 0 && worst >= kCap {
		t.Errorf("inter-region region=%d: maximum in-degree %d reaches family-wise Poisson cap %d (lambda=%.3f m=%d horizon=%d)", tag, worst, kCap, lambda, m, horizon)
	}
}

// TestSelectorScaleGrid runs five measurements selected by
// SOVEREIGN_TEST_SELECTOR_ARMS. A completes direct-pick coverage at N=3333 with
// SOVEREIGN_TEST_SELECTOR_TAIL_ROUNDS (default 20,000). B does the same at
// N=10,000 with SOVEREIGN_TEST_SELECTOR_10K_ROUNDS (default 60,000) and reports
// censoring beyond that horizon. C checks multi-hop rumor coverage at
// N=1000/3333/10000. D checks synchronized intra-region in-degree at
// N=3333/10000 over ten rounds per region. E checks the inter-region maximum
// at N=10,000. SOVEREIGN_TEST_SELECTOR_SCALE=1 is required because the grid is
// expensive.
func TestSelectorScaleGrid(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_SELECTOR_SCALE") != "1" {
		t.Skip("set SOVEREIGN_TEST_SELECTOR_SCALE=1 to run the expensive selector scale grid")
	}
	const alpha = 0.001
	const pileK = 10
	arms, badArm := selectorArms()
	if badArm != "" {
		t.Fatalf("SOVEREIGN_TEST_SELECTOR_ARMS: unknown arm %q (valid: A,B,C,D,E) - refusing to run an empty grid", badArm)
	}

	if arms["A"] {
		l := selectorFindLayout(t, "N3333-1111x3")
		R := uint64(selectorEnvInt("SOVEREIGN_TEST_SELECTOR_TAIL_ROUNDS", 100, 20000))
		ids, regions := buildSelectorPopulation(&l)
		t.Logf("direct-pick coverage %s: R=%d, analytic coupon-collector mean %.0f", l.name, R, 2222*(math.Log(2222)+0.5772)/2)
		sum := runSelectorLegA(t, &l, ids, regions, R, alpha)
		if sum.censored > 0 {
			t.Errorf("direct-pick coverage %s: %d sampled nodes remain censored at R=%d (coverMean=%.0f coverMax=%d)", l.name, sum.censored, R, sum.coverMean, sum.coverMax)
		} else {
			t.Logf("direct-pick coverage %s completed: coverMean=%.0f coverMax=%d", l.name, sum.coverMean, sum.coverMax)
		}
	}

	if arms["B"] {
		l := selectorFindLayout(t, "N10000-3333-3333-3334")
		R := uint64(selectorEnvInt("SOVEREIGN_TEST_SELECTOR_10K_ROUNDS", 100, 60000))
		ids, regions := buildSelectorPopulation(&l)
		t.Logf("direct-pick coverage %s: R=%d, analytic coupon-collector mean %.0f, 64-sample tail estimate 43000", l.name, R, 6667*(math.Log(6667)+0.5772)/2)
		sum := runSelectorLegA(t, &l, ids, regions, R, alpha)
		if sum.censored > 0 {
			t.Errorf("direct-pick coverage %s: %d sampled nodes remain censored at R=%d (coverMean=%.0f coverMax=%d); increase R before claiming completion", l.name, sum.censored, R, sum.coverMean, sum.coverMax)
		} else {
			t.Logf("direct-pick coverage %s completed: coverMean=%.0f coverMax=%d", l.name, sum.coverMean, sum.coverMax)
		}
	}

	if arms["C"] || arms["E"] {
		for _, name := range []string{"N1000-333-333-334", "N3333-1111x3", "N10000-3333-3333-3334"} {
			l := selectorFindLayout(t, name)
			ids, regions := buildSelectorPopulation(&l)
			nr := l.counts[0]
			bar := selectorDemersBar(nr)
			horizon := 2*bar + 16
			t.Logf("rumor coverage %s: n_r=%d bar=%d horizon=%d graph-nodes=%d", l.name, nr, bar, horizon, len(ids))
			graph := selectorRumorGraph(ids, regions, horizon, -1)
			c0 := l.counts[0]
			origins := []int{0, c0 / 6, c0 / 3, c0 / 2, c0 - 1, c0 + l.counts[1]/2, len(ids) - 1}
			for _, o := range origins {
				cover := selectorRumorRounds(graph, regions, o)
				t.Logf("rumor coverage %s origin=%d region=%d: cover=%d bar=%d", l.name, o, regions[o], cover, bar)
				if arms["C"] && (cover == 0 || cover > bar) {
					t.Errorf("rumor coverage %s origin=%d: cover=%d (0 means censored at horizon %d), want 1..%d for %d same-region nodes", l.name, o, cover, horizon, bar, nr)
				}
			}
			if arms["E"] && name == "N10000-3333-3333-3334" {
				selectorInterCheck(t, graph, regions, RegionTag(1), alpha)
			}
		}
	}

	if arms["D"] {
		for _, name := range []string{"N3333-1111x3", "N10000-3333-3333-3334"} {
			l := selectorFindLayout(t, name)
			ids, regions := buildSelectorPopulation(&l)
			cells := len(l.counts) * int(pileK)
			for tag := RegionTag(1); int(tag) <= len(l.counts); tag++ {
				selectorDistributionalCheck(t, l.name, ids, regions, tag, pileK, cells, alpha)
			}
		}
	}
}

// TestSelectorScaleNegativeControl verifies the detectors against known-bad
// inputs. In one region, starvation must censor rumor coverage while the
// unmodified graph completes. In three regions, foreign selections must still
// reach the starved victim. A shared zero seed must also concentrate picks
// enough to exceed the distributional p99 bound.
func TestSelectorScaleNegativeControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_SELECTOR_SCALE") != "1" {
		t.Skip("set SOVEREIGN_TEST_SELECTOR_SCALE=1 to run selector negative controls")
	}
	// Starvation partitions a one-region graph.
	lOne := SelectorLayout{name: "one-region-600", counts: []int{600}}
	ids, regions := buildSelectorPopulation(&lOne)
	bar := selectorDemersBar(600)
	graphS := selectorRumorGraph(ids, regions, 2*bar+16, 0)
	if cover := selectorRumorRounds(graphS, regions, 1); cover != 0 {
		t.Fatalf("starved one-region victim was reached in %d rounds; rumor detector missed the partition", cover)
	}
	// The unmodified one-region graph must complete within the same bound.
	graphG := selectorRumorGraph(ids, regions, 2*bar+16, -1)
	coverG := selectorRumorRounds(graphG, regions, 1)
	if coverG == 0 || coverG > bar {
		t.Fatalf("unmodified one-region coverage=%d exceeds the expected 1..%d range", coverG, bar)
	}
	t.Logf("one-region control: starved victim censored, unmodified coverage=%d <= %d", coverG, bar)
	// Foreign selections still reach the starved victim in three regions.
	l3 := SelectorLayout{name: "N100-34-34-32", counts: []int{34, 34, 32}}
	ids3, regions3 := buildSelectorPopulation(&l3)
	bar3 := selectorDemersBar(34)
	graphB := selectorRumorGraph(ids3, regions3, 2*bar3+16, 0)
	coverB := selectorRumorRounds(graphB, regions3, 1)
	if coverB == 0 {
		t.Fatalf("three-region starvation censored the victim; foreign inter-region selections did not provide the expected route")
	}
	t.Logf("three-region control: starved victim reached in %d rounds through foreign selections", coverB)
	// A shared zero seed forces correlated in-degree.
	members, views := selectorPileupViews(ids3, regions3, regions3[0], 3, 2)
	dense := selectorPileupCounts(views, members, 0)
	f := minInt(intraViewSize, len(members)-1)
	st := selectorIndegSummary(dense, float64(f), digestRespondMaxConcurrent)
	if st.max < 2*intraViewSize {
		t.Fatalf("shared-zero control maximum=%d, want at least %d", st.max, 2*intraViewSize)
	}
	if st.p99 <= digestRespondMaxConcurrent {
		t.Fatalf("shared-zero control p99=%d did not exceed responder cap %d", st.p99, digestRespondMaxConcurrent)
	}
	t.Logf("shared-zero control region=%d m=%d: max=%d p99=%d exceeded the distributional bound", regions3[0], len(members), st.max, st.p99)
}

// TestSelectorScaleMicroSmoke exercises every scale instrument on small,
// deterministic layouts. It checks completed rumor coverage, starvation
// censoring, the exact pile-up mean, and detection of the shared-zero seed.
// The passing p99 bound is not asserted on small populations because p99 then
// coincides with the Poisson maximum.
func TestSelectorScaleMicroSmoke(t *testing.T) {
	l := SelectorLayout{name: "micro-30", counts: []int{10, 10, 10}}
	ids, regions := buildSelectorPopulation(&l)
	bar := selectorDemersBar(10)
	graph := selectorRumorGraph(ids, regions, 2*bar+16, -1)
	cover := selectorRumorRounds(graph, regions, 0)
	if cover == 0 || cover > bar {
		t.Fatalf("micro rumor coverage=%d, want 1..%d", cover, bar)
	}
	l1 := SelectorLayout{name: "micro-1region-12", counts: []int{12}}
	ids1, regions1 := buildSelectorPopulation(&l1)
	g1 := selectorRumorGraph(ids1, regions1, 2*selectorDemersBar(12)+16, 0)
	if c := selectorRumorRounds(g1, regions1, 1); c != 0 {
		t.Fatalf("micro starved victim was reached in %d rounds, want censoring", c)
	}
	members, views := selectorPileupViews(ids, regions, RegionTag(1), 6, 0)
	f := minInt(intraViewSize, len(members)-1)
	dense := selectorPileupCounts(views, members, 0)
	st := selectorIndegSummary(dense, float64(f), digestRespondMaxConcurrent)
	if st.mean != float64(f) {
		t.Fatalf("micro pile-up mean=%.3f, want f=%d", st.mean, f)
	}
	if st.max < 1 {
		t.Fatalf("micro pile-up produced no picks")
	}
	// With 34 members, the shared permutation gives maximum m-1=33 > cap 16.
	lF := SelectorLayout{name: "micro-frozen-100", counts: []int{34, 34, 32}}
	idsF, regionsF := buildSelectorPopulation(&lF)
	membersF, viewsF := selectorPileupViews(idsF, regionsF, RegionTag(1), 3, 2)
	denseF := selectorPileupCounts(viewsF, membersF, 0)
	stF := selectorIndegSummary(denseF, float64(minInt(intraViewSize, len(membersF)-1)), digestRespondMaxConcurrent)
	if stF.p99 <= digestRespondMaxConcurrent || stF.max < 2*intraViewSize {
		t.Fatalf("micro shared-zero control was not detected: p99=%d max=%d", stF.p99, stF.max)
	}
	t.Logf("selector micro-smoke: rumor cover=%d (bar=%d), pile-up mean=%.1f, shared-zero max=%d", cover, bar, st.mean, stF.max)
}
