// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// The partial intra-region view tests cover exact view sizes, deterministic
// rotation and pair coverage, disabled behavior, allocation limits, and
// convergence on loopback census meshes (ADR-0063 and ADR-0067). Assertions use
// Select results and sweep counters rather than a separate model of the draw.
//
// TestViewSize and TestViewRotation are deterministic. TestViewConvergence uses
// 100 nodes; TestViewConvergenceRaceFast runs the same assertions on 30 nodes so
// they remain practical under the race detector. The selector simulation tests
// provide the larger statistical runs. These are in-process convergence tests,
// not wide-area latency measurements.

import (
	"context"
	"encoding/binary"
	"fmt"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"math/rand/v2"
	"os"
	"testing"
	"time"
)

// viewRegionSizes counts the nodes in each region.
func viewRegionSizes(regions []RegionTag) map[RegionTag]int {
	m := make(map[RegionTag]int, 8)
	for _, r := range regions {
		m[r]++
	}
	return m
}

// viewSameSelection compares both peer order and membership.
func viewSameSelection(a, b [][16]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestViewSize checks that each round selects exactly min(intraViewSize, n_r-1)
// intra-region peers and one peer per remote region. It also checks deterministic
// output, the whole-set result for small regions, PCG stream separation, and the
// allocation budget for drawIntraView.
func TestViewSize(t *testing.T) {
	ctx := context.Background()
	l := SelectorLayout{name: "N100-34-34-32", counts: []int{34, 34, 32}}
	ids, regions := buildSelectorPopulation(&l)
	idTag := make(map[[16]byte]RegionTag, len(ids))
	for j := range ids {
		idTag[ids[j]] = regions[j]
	}
	rsize := viewRegionSizes(regions)

	// Check every node over 64 rounds: the partial view must not change the
	// inter-region selection.
	const R = 64
	for idx := range ids {
		mgr := buildSelectorManager(idx, ids, regions)
		mgr.SetPartialIntraView(true)
		wantIntra := rsize[regions[idx]] - 1
		if wantIntra > intraViewSize {
			wantIntra = intraViewSize
		}
		for round := uint64(1); round <= R; round++ {
			mgr.SetSeed(selectorRoundSeed(round, ids[idx]))
			sel := mgr.Select(ctx)
			intra, inter := 0, 0
			for _, p := range sel {
				if idTag[p] == regions[idx] {
					intra++
				} else {
					inter++
				}
			}
			if intra != wantIntra {
				t.Fatalf("node %d round %d selected %d intra-region peers, want %d (min(f=%d, n_r-1=%d))", idx, round, intra, wantIntra, intraViewSize, rsize[regions[idx]]-1)
			}
			if inter != 2 {
				t.Fatalf("node %d round %d selected %d inter-region peers, want one for each of two remote regions", idx, round, inter)
			}
		}
	}

	// Independent managers with the same registry and seed must return the same
	// ordered selection.
	{
		m1 := buildSelectorManager(0, ids, regions)
		m2 := buildSelectorManager(0, ids, regions)
		m1.SetPartialIntraView(true)
		m2.SetPartialIntraView(true)
		sd := selectorRoundSeed(7, ids[0])
		m1.SetSeed(sd)
		m2.SetSeed(sd)
		if !viewSameSelection(m1.Select(ctx), m2.Select(ctx)) {
			t.Fatalf("independent managers returned different selections for the same seed and registry")
		}
	}

	// Disabling the view must restore the full intra-region selection.
	{
		mgr := buildSelectorManager(0, ids, regions)
		mgr.SetSeed(selectorRoundSeed(7, ids[0]))
		sel := mgr.Select(ctx)
		intra := 0
		for _, p := range sel {
			if idTag[p] == regions[0] {
				intra++
			}
		}
		if intra != rsize[regions[0]]-1 {
			t.Fatalf("disabled view selected %d intra-region peers, want %d", intra, rsize[regions[0]]-1)
		}
	}

	// A region with no more peers than the view limit returns the whole set in
	// the same order whether the view is enabled or disabled.
	{
		dl := SelectorLayout{name: "degenerate-6", counts: []int{3, 3}}
		dids, dregions := buildSelectorPopulation(&dl)
		on := buildSelectorManager(0, dids, dregions)
		off := buildSelectorManager(0, dids, dregions)
		on.SetPartialIntraView(true)
		sd := selectorRoundSeed(3, dids[0])
		on.SetSeed(sd)
		off.SetSeed(sd)
		if !viewSameSelection(on.Select(ctx), off.Select(ctx)) {
			t.Fatalf("small-region selection changed when the partial view was enabled")
		}
	}

	// The intra-region and inter-region draws use separate PCG streams. Compare
	// their first outputs at several seeds to catch reuse of stream zero.
	for _, sd := range []uint64{0, 1, 42, 0xDEADBEEFCAFEBABE} {
		if rand.NewPCG(sd, intraViewPCGStream).Uint64() == rand.NewPCG(sd, 0).Uint64() {
			t.Fatalf("intra-region PCG stream matches inter-region stream zero at seed %d", sd)
		}
	}

	// Measure drawIntraView on 33 candidates. A stack-local PCG and in-place
	// partial Fisher-Yates keep the draw within one allocation per call.
	{
		var pop [][16]byte
		for j := range ids {
			if regions[j] == regions[0] && j != 0 {
				pop = append(pop, ids[j])
			}
		}
		sortPeerIDs(pop)
		mgr := buildSelectorManager(0, ids, regions)
		allocs := testing.AllocsPerRun(200, func() {
			mgr.drawIntraView(pop, 12345) //nolint:staticcheck // in-place scratch reuse is the measured behavior
		})
		if allocs > 1 {
			t.Fatalf("drawIntraView allocated %g times per call, want at most 1", allocs)
		}
		t.Logf("drawIntraView used %g allocations per call on %d candidates", allocs, len(pop))
	}
	t.Logf("checked %d nodes over %d rounds with exact view sizes up to %d and deterministic selection", len(ids), R, intraViewSize)
}

// TestViewRotation drives every node in a 100-node layout for 120 rounds. It
// requires a distinct view each round, coverage of every intra-region peer, and
// per-peer frequencies within a Bonferroni-adjusted chi-square bound. For one
// ordered pair, the chance of omission throughout is approximately
// (25/33)^120 = 1e-14; the union bound across 3300 pairs is about 3e-11. Fixed
// IDs and seeds make the actual run deterministic.
func TestViewRotation(t *testing.T) {
	const (
		R     = 120
		alpha = 0.001
	)
	ctx := context.Background()
	l := SelectorLayout{name: "N100-34-34-32", counts: []int{34, 34, 32}}
	ids, regions := buildSelectorPopulation(&l)
	idTag := make(map[[16]byte]RegionTag, len(ids))
	for j := range ids {
		idTag[ids[j]] = regions[j]
	}
	rsize := viewRegionSizes(regions)
	worstChi2, worstNode, worstDof := 0.0, -1, 0
	cells := 0
	for idx := range ids {
		mgr := buildSelectorManager(idx, ids, regions)
		mgr.SetPartialIntraView(true)
		nr1 := rsize[regions[idx]] - 1
		counts := make(map[[16]byte]int, nr1)
		distinct := make(map[uint64]bool, R)
		for round := uint64(1); round <= R; round++ {
			mgr.SetSeed(selectorRoundSeed(round, ids[idx]))
			sel := mgr.Select(ctx)
			var view [][16]byte
			for _, p := range sel {
				if idTag[p] == regions[idx] {
					counts[p]++
					view = append(view, p)
				}
			}
			distinct[viewFingerprint(view)] = true
		}
		// A frozen or colliding draw produces fewer than R distinct views.
		if len(distinct) != R {
			t.Fatalf("node %d drew %d distinct views in %d rounds", idx, len(distinct), R)
		}
		for j := range ids {
			if j == idx || regions[j] != regions[idx] {
				continue
			}
			if counts[ids[j]] == 0 {
				t.Fatalf("node %d never selected intra-region peer %d in %d rounds", idx, j, R)
			}
		}
		// Include candidates that were never selected in the chi-square sum.
		exp := float64(len(distinct)*minInt(intraViewSize, nr1)) / float64(nr1)
		var chi2 float64
		picked := 0
		for _, c := range counts {
			picked++
			chi2 += (float64(c) - exp) * (float64(c) - exp) / exp
		}
		chi2 += float64(nr1-picked) * exp
		cells++
		if chi2 > worstChi2 {
			worstChi2, worstNode, worstDof = chi2, idx, nr1-1
		}
	}
	critBonf := selectorChi2Crit(worstDof, alpha/float64(cells))
	t.Logf("nodes=%d rounds=%d worst_chi2=%.1f node=%d dof=%d critical=%.1f alpha=%g/%d cells", len(ids), R, worstChi2, worstNode, worstDof, critBonf, alpha, cells)
	if worstChi2 >= critBonf {
		t.Fatalf("node %d has intra-view chi-square %.1f, exceeding family-wise critical value %.1f", worstNode, worstChi2, critBonf)
	}
}

// minInt returns the smaller of a and b.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestViewOffByteIdentical checks two disabled shapes. A never-armed 30-node
// mesh uses full intra-region selection, converges, and leaves all view counters
// zero. Enabling the view while region awareness is disabled warns once and
// keeps that gossiper on the full-mesh path, although direct topology selection
// still uses the partial view. A second inert sweep verifies that direct
// selection's saved statistics are not attributed to a sweep that made no draw.
func TestViewOffByteIdentical(t *testing.T) {
	m := buildCensusMesh(t, 30)
	defer m.close()
	finishCensusMesh(t, m) // Start accept loops and full-mesh dials.
	censusBatch(t, m, "view-off", 0, 200, 3, 50*time.Millisecond)
	states := censusSweepRound(t, m, 50*time.Millisecond)
	for i, st := range states {
		if st.viewDrawn != 0 || st.viewEligible != 0 || st.viewXor != 0 {
			t.Fatalf("node %d has view counters on a disabled sweep: drawn=%d eligible=%d xor=%x", i, st.viewDrawn, st.viewEligible, st.viewXor)
		}
		if m.nodes[i].g.PartialIntraView() {
			t.Fatalf("node %d reports partial view enabled by default", i)
		}
	}
	// Enable the view while region awareness is disabled.
	n0 := m.nodes[0]
	n0.g.SetRegionAware(false)
	n0.g.SetPartialIntraView(true)
	st := n0.g.AntiEntropySweep(m.ctx)
	if !n0.g.viewOrphanWarn.Load() {
		t.Fatalf("inert sweep did not emit the one-time partial-view warning")
	}
	if st.viewDrawn != 0 || st.viewEligible != 0 {
		t.Fatalf("inert sweep used partial-view counters: drawn=%d eligible=%d", st.viewDrawn, st.viewEligible)
	}
	if !n0.g.topology.PartialIntraView() {
		t.Fatalf("SetPartialIntraView did not update the topology")
	}
	// Direct selection still draws eight of nine intra-region peers, confirming
	// that the gossiper's region-awareness gate caused the inert sweep.
	n0.g.topology.SetSeed(selectorRoundSeed(1, n0.ident.NodeID))
	n0.g.topology.Select(context.Background())
	drw, elig, _ := n0.g.topology.LastIntraView()
	if drw != intraViewSize || elig != 9 {
		t.Fatalf("direct topology draw is (%d/%d), want (%d/9)", drw, elig, intraViewSize)
	}
	// The direct draw populated LastIntraView. The next inert sweep makes no
	// selection, so it must not report those saved counters as its own.
	st2 := n0.g.AntiEntropySweep(m.ctx)
	if st2.viewDrawn != 0 || st2.viewEligible != 0 || st2.viewXor != 0 {
		t.Fatalf("inert sweep reported the direct draw's saved counters: drawn=%d eligible=%d xor=%x", st2.viewDrawn, st2.viewEligible, st2.viewXor)
	}
	// Nodes that were never enabled must not warn.
	for i := 1; i < len(m.nodes); i++ {
		if m.nodes[i].g.viewOrphanWarn.Load() {
			t.Fatalf("node %d emitted a partial-view warning without being enabled", i)
		}
	}
	// Unbinding the topology is valid and must not reset the gossiper's flag.
	last := m.nodes[len(m.nodes)-1]
	last.g.SetPartialIntraView(true)
	last.g.SetTopology(nil)
	if !last.g.PartialIntraView() {
		t.Fatalf("SetTopology(nil) reset the partial-view flag")
	}
}

// viewConvergenceCheck runs the same convergence checks at two sizes. The
// 100-node arm inserts 10,000 keys, saturating the 1024-bucket digest and using
// full-key oversend. The 30-node arm inserts 200 keys so the identical assertions
// remain practical under the race detector.
//
// Every node enables the view before synchronized sweeps. For up to 15 rounds,
// the harness checks fired+gated against the sum of min(f,n_r-1)+2 across nodes,
// checks each node's drawn and eligible counts, and stops when all roots match.
// It computes the full-view count from the same region sizes for comparison.
// Finally it exercises the census batch helper with an armed mesh.
func viewConvergenceCheck(t *testing.T, n, keys int) {
	m := buildCensusMesh(t, n)
	defer m.close()
	finishCensusMesh(t, m) // Start accept loops and full-mesh dials.
	for _, nd := range m.nodes {
		nd.g.SetPartialIntraView(true)
	}
	regionSize := make(map[RegionTag]int, 3)
	for _, nd := range m.nodes {
		regionSize[nd.region]++
	}
	var expectedSelected, offSelected int64
	for _, nd := range m.nodes {
		expectedSelected += int64(minInt(intraViewSize, regionSize[nd.region]-1) + 2)
		offSelected += int64(regionSize[nd.region]-1) + 2
	}
	for i := 0; i < keys; i++ {
		m.nodes[0].g.InsertLocalEvents(fmt.Sprintf("view-conv-%d", i), fmt.Sprintf("v-%d", i), eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		})
	}
	prev := make([]CensusNodeCounters, len(m.nodes))
	for i := range prev {
		prev[i] = readCensusCounters(m.nodes[i])
	}
	convergedAt := -1
	for round := 1; round <= 15; round++ {
		states := censusSweepRound(t, m, 250*time.Millisecond)
		cur := make([]CensusNodeCounters, len(m.nodes))
		for i := range cur {
			cur[i] = readCensusCounters(m.nodes[i])
		}
		var fired, gated int64
		for i := range cur {
			fired += cur[i].exchanges - prev[i].exchanges
			gated += cur[i].gateSkips - prev[i].gateSkips
			wantDrawn := minInt(intraViewSize, regionSize[m.nodes[i].region]-1)
			wantElig := regionSize[m.nodes[i].region] - 1
			if states[i].viewDrawn != wantDrawn || states[i].viewEligible != wantElig {
				t.Fatalf("round %d node %d view=(%d/%d), want (%d/%d)", round, i, states[i].viewDrawn, states[i].viewEligible, wantDrawn, wantElig)
			}
		}
		if fired+gated != expectedSelected {
			t.Fatalf("round %d fired(%d)+gated(%d), want total %d", round, fired, gated, expectedSelected)
		}
		copy(prev, cur)
		root0 := m.nodes[0].engine.MerkleRootFromShards()
		equal := true
		for i := 1; i < len(m.nodes); i++ {
			if m.nodes[i].engine.MerkleRootFromShards() != root0 {
				equal = false
				break
			}
		}
		if equal {
			convergedAt = round
			break
		}
	}
	if convergedAt == -1 {
		t.Fatalf("armed mesh did not converge within the 15-round cap")
	}
	t.Logf("N=%d D=%d converged at round %d; selected %d peers per sweep, compared with %d for the full view", n, keys, convergedAt, expectedSelected, offSelected)
	// Exercise the census batch helper with an armed mesh as well.
	censusBatch(t, m, "view-conv-exercise", 10_000, 50, 4, 250*time.Millisecond)
}

// viewFingerprint sorts view in place and computes FNV-1a over both
// little-endian halves of each ID. Callers pass newly built slices, so sorting
// does not alter a shared selection. One helper keeps view identity comparisons
// independent of selection order.
func viewFingerprint(view [][16]byte) uint64 {
	for i := 1; i < len(view); i++ {
		for j := i; j > 0 && lessID(view[j], view[j-1]); j-- {
			view[j], view[j-1] = view[j-1], view[j]
		}
	}
	h := uint64(14695981039346656037)
	for _, p := range view {
		h = (h ^ binary.LittleEndian.Uint64(p[:8])) * 1099511628211
		h = (h ^ binary.LittleEndian.Uint64(p[8:])) * 1099511628211
	}
	return h
}

// lessID reports lexicographic byte order for node IDs.
func lessID(a, b [16]byte) bool {
	for k := 0; k < 16; k++ {
		if a[k] != b[k] {
			return a[k] < b[k]
		}
	}
	return false
}

// TestViewConvergence runs the 100-node, 10,000-key arm. It skips under the race
// detector because constructing and driving that mesh is substantially more
// expensive there. TestViewConvergenceRaceFast runs the same assertions on 30
// nodes, and the other view tests cover the selector and forwarding paths.
// SOVEREIGN_TEST_INTRA_VIEW_HEAVY=1 overrides the race-detector skip.
func TestViewConvergence(t *testing.T) {
	if viewRaceEnabled && os.Getenv("SOVEREIGN_TEST_INTRA_VIEW_HEAVY") != "1" {
		t.Skip("skip the 100-node, 10000-key convergence arm under -race; TestViewConvergenceRaceFast runs the same assertions on 30 nodes with 200 keys. Set SOVEREIGN_TEST_INTRA_VIEW_HEAVY=1 to run this arm")
	}
	viewConvergenceCheck(t, 100, 10_000)
}

// TestViewConvergenceRaceFast runs the 30-node, 200-key arm in both ordinary
// and race-detector runs. Each region has nine other peers, above the view limit
// of eight, while the smaller divergence avoids the heavy arm's full-key
// oversend. The selection, observability, convergence, and batch assertions are
// the same as in TestViewConvergence.
func TestViewConvergenceRaceFast(t *testing.T) {
	viewConvergenceCheck(t, 30, 200)
}
