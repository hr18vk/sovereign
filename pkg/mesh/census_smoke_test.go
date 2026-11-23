// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// This suite measures in-process sweep wall time as census size increases and
// checks the convergence detector with an excluded node. It extends the
// 1,000-node census measurement of about 3,434 ms per sweep. Partial intra-
// region views address the full-mesh pressure on responder slots (ADR-0063,
// ADR-0067).
//
// SweepLoop records sweepState.durMs inside sweepOnce (ADR-0066), but a manual
// AntiEntropySweep returns durMs == 0. This harness therefore times each manual
// call directly, matching the production loop's measurement boundary.
//
// Nodes communicate over real loopback TLS. The result covers view selection,
// digest construction and exchange, delta generation, and fan-out over loopback;
// it does not include inter-region latency, bandwidth limits, or WAN stalls.
// Full-mesh dialing uses N-1 sockets per node, so file descriptors and memory
// also constrain density. The configured ceiling is 2,000 nodes.
//
// Each timed round inserts fresh divergence and requires at least one digest
// exchange, preventing a skipped round from being reported as a measurement.
// Convergence uses MerkleRootFromShards directly. The negative control excludes
// a node from every dial and requires unequal roots, then dials it in both
// directions and requires convergence.
//
// SOVEREIGN_TEST_CENSUS_SMOKE=1 enables the size ladder;
// SOVEREIGN_TEST_CENSUS_SMOKE_NS overrides its default "333,666" sizes after
// resource checks. TestCensusScalingMicroSmoke always runs the timed round,
// exclusion control, and healing check at N=6.

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// censusSweepRoundTimed releases every node's AntiEntropySweep at one barrier
// and times each call. This measures the same interval that SweepLoop records
// as sweepState.durMs inside sweepOnce (ADR-0066); a manual sweep leaves that
// field zero.
func censusSweepRoundTimed(m *CensusMesh) (walls []time.Duration) {
	walls = make([]time.Duration, len(m.nodes))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range m.nodes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			t0 := time.Now()
			m.nodes[i].g.AntiEntropySweep(m.ctx)
			walls[i] = time.Since(t0)
		}(i)
	}
	close(start)
	wg.Wait()
	return walls
}

// censusWallStats summarizes one round's per-node walls (ms).
func censusWallStats(walls []time.Duration) (mean, p50, p99, maxMs float64) {
	if len(walls) == 0 {
		return 0, 0, 0, 0
	}
	// Convert to floating-point milliseconds before aggregating. Truncating
	// each duration to whole milliseconds would make sub-millisecond sweeps
	// look like zero-length measurements.
	ms := make([]float64, len(walls))
	var sum float64
	for i, w := range walls {
		ms[i] = float64(w) / 1e6
		sum += ms[i]
	}
	sorted := append([]float64(nil), ms...)
	sort.Float64s(sorted)
	pick := func(q float64) float64 {
		idx := int(q * float64(len(sorted)-1))
		return sorted[idx]
	}
	mean = sum / float64(len(ms))
	p50 = pick(0.50)
	p99 = pick(0.99)
	maxMs = sorted[len(sorted)-1]
	return mean, p50, p99, maxMs
}

// censusRootsAllEqual compares every node's MerkleRootFromShards result with
// node 0's root.
func censusRootsAllEqual(m *CensusMesh) bool {
	root0 := m.nodes[0].engine.MerkleRootFromShards()
	for i := 1; i < len(m.nodes); i++ {
		if m.nodes[i].engine.MerkleRootFromShards() != root0 {
			return false
		}
	}
	return true
}

// finishCensusMeshMinus starts every listener and dials every pair except
// those touching excl. The excluded node neither dials nor receives a dial, so
// its state remains empty and provides the negative convergence case.
func finishCensusMeshMinus(t *testing.T, m *CensusMesh, excl int) {
	t.Helper()
	n := len(m.nodes)
	for i := 0; i < n; i++ {
		m.wg.Add(1)
		// The PeerSet-threaded accept loop (ADR-0068).
		go runAcceptLoopWithPeerSet(m.ctx, m.nodes[i].ln, m.nodes[i].recv, m.nodes[i].g, m.wg, m.nodes[i].ps)
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j || i == excl || j == excl {
				continue
			}
			if err := m.nodes[i].ps.Dial(m.ctx, m.nodes[j].addr, "localhost", m.nodes[j].ident.NodeID); err != nil {
				t.Fatalf("dial %d->%d: %v", i, j, err)
			}
			asyncWait(t, m.nodes[i].ps, m.nodes[j].ident.NodeID)
		}
	}
}

// censusHealNode connects excl to every other node in both directions. The
// convergence detector must change from unequal roots while excluded to equal
// roots after these dials and subsequent sweeps.
func censusHealNode(t *testing.T, m *CensusMesh, excl int) {
	t.Helper()
	for j := 0; j < len(m.nodes); j++ {
		if j == excl {
			continue
		}
		if err := m.nodes[excl].ps.Dial(m.ctx, m.nodes[j].addr, "localhost", m.nodes[j].ident.NodeID); err != nil {
			t.Fatalf("heal dial %d->%d: %v", excl, j, err)
		}
		asyncWait(t, m.nodes[excl].ps, m.nodes[j].ident.NodeID)
		if err := m.nodes[j].ps.Dial(m.ctx, m.nodes[excl].addr, "localhost", m.nodes[excl].ident.NodeID); err != nil {
			t.Fatalf("heal dial %d->%d: %v", j, excl, err)
		}
		asyncWait(t, m.nodes[j].ps, m.nodes[excl].ident.NodeID)
	}
}

// censusSmokeInsert inserts n fresh entities on node 0 through
// InsertLocalEvents. A constant SystemTime keeps the ingress skew bound from
// rejecting these writes; causal ordering is carried by dot counters.
func censusSmokeInsert(m *CensusMesh, tag string, first, n int) {
	for i := first; i < first+n; i++ {
		m.nodes[0].g.InsertLocalEvents(fmt.Sprintf("census-%s-%d", tag, i), "v", eng.CRDTEntry{SystemTime: 1_700_000_000})
	}
}

// censusWaitRootsEqual polls all roots until they match or the deadline
// expires. Entries publish on the sweep goroutine but join asynchronously on
// the readLoop goroutine, so the final exchange does not imply immediate
// equality.
func censusWaitRootsEqual(m *CensusMesh, deadline time.Duration) bool {
	quit := time.Now().Add(deadline)
	for time.Now().Before(quit) {
		if censusRootsAllEqual(m) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return censusRootsAllEqual(m)
}

// TestCensusScalingSmoke builds a census mesh at each configured size, checks
// convergence and the fired-plus-gated exchange identity, then times three
// synchronized rounds with fresh divergence. It reports wall time by size but
// does not require monotonic scaling. SOVEREIGN_TEST_CENSUS_SMOKE=1 enables it.
func TestCensusScalingSmoke(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_CENSUS_SMOKE") != "1" {
		t.Skip("census scaling ladder: set SOVEREIGN_TEST_CENSUS_SMOKE=1 to arm. Probe-gated per the design doc density law: the 15 GB 4c box kernel-kills inside the N=200 arm (8.5 GB cumulative RSS — engines from prior arms are retained in-process), so locally cap SOVEREIGN_TEST_CENSUS_SMOKE_NS at ~133; N=333/666 are the 64c box arms (completed there, 445 s). Do not assume an arm fits — probe fd+RAM first")
	}
	// The default sizes have completed on the larger test host. N=1000 has
	// not completed: a 15 GB, four-core host was killed below N=200, while
	// N=333 and N=666 completed on the 64-core host. Higher sizes require an
	// explicit override after checking file descriptors and available memory.
	ns := []int{333, 666}
	if v := os.Getenv("SOVEREIGN_TEST_CENSUS_SMOKE_NS"); v != "" {
		ns = nil
		for _, part := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || n < 6 || n > 2000 {
				t.Fatalf("SOVEREIGN_TEST_CENSUS_SMOKE_NS must be comma-separated ints in [6,2000] (the in-process full-mesh dial bound — the design doc owns the density law), got %q", v)
			}
			ns = append(ns, n)
		}
	}
	for _, N := range ns {
		N := N
		t.Run(fmt.Sprintf("N%d", N), func(t *testing.T) {
			m := buildCensusMesh(t, N)
			defer m.close()
			finishCensusMesh(t, m)
			t.Logf("census scaling N=%d: mesh ready (%d conns, full-mesh dial)", N, N*(N-1))
			// Check convergence and the fired-plus-gated exchange identity.
			censusBatch(t, m, "scale", 0, 100, 3, 250*time.Millisecond)
			// Time three rounds with fresh divergence. Each must fire the
			// digest gate so the duration covers actual exchange work.
			first := 100
			for r := 0; r < 3; r++ {
				censusSmokeInsert(m, fmt.Sprintf("N%d", N), first, 20)
				before := readCensusCounters(m.nodes[0])
				walls := censusSweepRoundTimed(m)
				after := readCensusCounters(m.nodes[0])
				mean, p50, p99, mx := censusWallStats(walls)
				dExch := after.exchanges - before.exchanges
				t.Logf("census scaling N=%d timed-round %d/3: exchanges=%d | wall ms: mean=%.0f p50=%.0f p99=%.0f max=%.0f", N, r+1, dExch, mean, p50, p99, mx)
				if dExch <= 0 {
					t.Errorf("census scaling N=%d round %d: zero fired exchanges after 20 fresh keys — the wall measured a gate-skipped round; the divergence or the gate is broken", N, r+1)
				}
				if mx <= 0 {
					t.Errorf("census scaling N=%d round %d: max wall %.0f ms — the timed round measured nothing", N, r+1, mx)
				}
				first += 20
			}
			// One synchronized round is one gossip hop, so the final divergence
			// needs further rounds to propagate. Drive up to 30 rounds rather
			// than only polling; this distinguishes non-convergence from a mesh
			// that simply has not been given another hop. The bound covers
			// 2*log2(1000)+8 rounds with margin at every configured size.
			settled := false
			for r := 0; r < 30; r++ {
				censusSweepRoundTimed(m)
				if censusWaitRootsEqual(m, 2*time.Second) {
					settled = true
					break
				}
			}
			if !settled {
				t.Errorf("census scaling N=%d: roots did not converge after 30 settling rounds — the smoke mesh is not converging", N)
			}
		})
	}
}

// TestCensusNeverJoinedNegativeControl excludes one node from every dial and
// requires unequal roots, then connects it and requires convergence. This
// checks both directions of the detector. It runs with the scaling smoke and
// takes seconds at N=24.
func TestCensusNeverJoinedNegativeControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_CENSUS_SMOKE") != "1" {
		t.Skip("census scaling negative control: set SOVEREIGN_TEST_CENSUS_SMOKE=1 (it arms with the ladder)")
	}
	const excl = 5
	m := buildCensusMesh(t, 24)
	defer m.close()
	finishCensusMeshMinus(t, m, excl)
	censusSmokeInsert(m, "negctl", 0, 40)
	for r := 0; r < 3; r++ {
		censusSweepRound(t, m, 250*time.Millisecond)
	}
	if censusRootsAllEqual(m) {
		t.Fatalf("never-joined: the never-joined node's root equals the fleet root — the convergence detector does not detect a missing node; the convergence assertion is an assertion that cannot fail")
	}
	t.Logf("census scaling negative control: the never-joined node %d left the roots unequal (the detector fires)", excl)
	censusHealNode(t, m, excl)
	for r := 0; r < 3; r++ {
		censusSweepRound(t, m, 250*time.Millisecond)
	}
	if !censusWaitRootsEqual(m, 20*time.Second) {
		t.Fatalf("never-joined heal: the healed mesh did not converge — the control's healing arm is broken; investigate before trusting the fire arm")
	}
	t.Logf("census scaling negative control: after healing node %d the roots converged (the detector measured both ways)", excl)
}

// TestCensusScalingMicroSmoke always exercises the harness at N=6: the
// excluded-node case, healing, and one timed round that must perform digest
// exchanges. It does not assert a wall-time scaling relationship at this size.
func TestCensusScalingMicroSmoke(t *testing.T) {
	m := buildCensusMesh(t, 6)
	defer m.close()
	finishCensusMeshMinus(t, m, 2)
	censusSmokeInsert(m, "micro", 0, 12)
	for r := 0; r < 2; r++ {
		censusSweepRound(t, m, 100*time.Millisecond)
	}
	if censusRootsAllEqual(m) {
		t.Fatalf("micro: the never-joined node did not leave the roots unequal — the convergence detector is broken")
	}
	censusHealNode(t, m, 2)
	for r := 0; r < 2; r++ {
		censusSweepRound(t, m, 100*time.Millisecond)
	}
	if !censusWaitRootsEqual(m, 10*time.Second) {
		t.Fatalf("micro: the healed mesh did not converge — the heal arm is broken")
	}
	// Insert fresh divergence before one timed round. That round reaches only
	// node 0's direct peers, so two relay rounds follow before the test
	// expects all roots to converge.
	censusSmokeInsert(m, "micro-timed", 100, 6)
	before := readCensusCounters(m.nodes[0])
	walls := censusSweepRoundTimed(m)
	after := readCensusCounters(m.nodes[0])
	mean, p50, p99, mx := censusWallStats(walls)
	t.Logf("census scaling micro-smoke: never-joined fired + healed + timed round: exchanges=%d walls ms mean=%.1f p50=%.1f p99=%.1f max=%.1f", after.exchanges-before.exchanges, mean, p50, p99, mx)
	if after.exchanges-before.exchanges <= 0 {
		t.Fatalf("micro: the timed round fired zero exchanges — the gate did not fire on 6 fresh keys; the wall instrument proves nothing")
	}
	if mx <= 0 {
		t.Fatalf("micro: the timed round measured a zero wall — the stamp is broken")
	}
	for r := 0; r < 2; r++ {
		censusSweepRound(t, m, 100*time.Millisecond)
	}
	if !censusWaitRootsEqual(m, 10*time.Second) {
		t.Fatalf("micro: the timed round's divergence did not converge after the relay rounds — the smoke mesh is not converging")
	}
}
