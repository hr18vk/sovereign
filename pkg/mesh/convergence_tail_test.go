// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh_test

// This harness characterizes convergence rounds for a three-region, fan-out-3
// mesh (ADR-0054). In the measured 100-node WAN runs, the last one or two nodes
// occasionally pushed full convergence past 10 seconds: one run took 10.150 s,
// while passing runs took 6.6–8.7 s. Sweep durations of 2–3 s in us-east-1 and
// 4–6 s in ap-southeast-2 pointed to bandwidth rather than round count.
//
// Loopback delivery cannot reproduce that bandwidth tail. These tests measure
// whether topology selection itself creates a round tail. Each run drives the
// real TopologyManager.Select over a virtual network and records every node's
// first converged round, not only the last round for the mesh.
//
// Inter-region fan-out ties are seeded by round ^ nodeID[:8]. Deriving node IDs
// from a per-run seed varies those choices across runs. Engines are closed at
// the end of each run rather than through t.Cleanup, which would retain every
// run's off-heap arenas until the whole test finished.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/chaos"
	engmesh "github.com/hr18vk/sovereign/pkg/mesh"
	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

// convergenceNodeID derives a deterministic-per-(run,node) 16-byte node ID. The
// run seed de-correlates the fan-out picks across runs (see the header).
func convergenceNodeID(runSeed, nodeIndex int) [16]byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("convergence-node-%d-run-%d", nodeIndex, runSeed)))
	var id [16]byte
	copy(id[:], h[:16])
	return id
}

// convergenceRegionFor assigns node indices round-robin across regions 1–3.
// Region zero is reserved as the unset tag.
func convergenceRegionFor(nodeIndex int) engmesh.RegionTag {
	return engmesh.RegionTag((nodeIndex % 3) + 1)
}

// convergenceRunOnce builds a fresh N-node 3-region fan-out-3 mesh, injects
// numKeys into node 0, and pumps fan-out-3 rounds until all roots equal node
// 0's root (the source's root — node 0 originates everything and never changes)
// or the round cap. Returns the per-node convergence round (0 = never converged
// within the cap) and the max (tail) round.
func convergenceRunOnce(t *testing.T, runSeed, numNodes, numKeys, roundCap int, arenaSize uintptr, quiesce time.Duration, profile chaos.ChaosProfile) (convRound map[[16]byte]int, tailRound int, converged bool) {
	t.Helper()
	ctx := context.Background()

	// --- build engines (seeded IDs) + net + orchestrator + topologies ---
	engines := make(map[[16]byte]*engsync.DeltaCRDTEngine, numNodes)
	nodeIDs := make([][16]byte, numNodes)
	for i := 0; i < numNodes; i++ {
		id := convergenceNodeID(runSeed, i)
		engsync.DataDir = t.TempDir()
		eng, err := engsync.NewDeltaCRDTEngine(id, 0, arenaSize)
		if err != nil {
			t.Fatalf("convergence: NewDeltaCRDTEngine run=%d node=%d: %v", runSeed, i, err)
		}
		engines[id] = eng
		nodeIDs[i] = id
	}
	// Explicit per-run close (not t.Cleanup — see the header).
	defer func() {
		for _, e := range engines {
			_ = e.Close()
		}
	}()
	loopbackSortIDs(nodeIDs)

	net := chaos.NewVirtualNet(profile)
	defer net.Stop()
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("convergence: NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := loopbackBuildTopologies(t, nodeIDs, convergenceRegionFor)

	// --- inject numKeys into node 0 (the single source) ---
	src := nodeIDs[0]
	srcEng := engines[src]
	for k := 0; k < numKeys; k++ {
		srcEng.InsertLocal(fmt.Sprintf("convergence-key-%d", k), loopbackStagedEventEntry(k, src))
	}
	// Guard against a false convergence signal: if the inject silently landed nothing, srcRoot is the
	// empty root and every node's empty root would "converge" to it in round 0
	// — a false tight distribution. Assert the source
	// actually holds the last key (a non-empty convergence target) before
	// any round is trusted.
	if got := srcEng.State().Get(fmt.Sprintf("convergence-key-%d", numKeys-1)); len(got) == 0 {
		t.Fatalf("convergence: source failed to hold the last injected key (convergence-key-%d) — the inject landed nothing and the convergence would be a false signal", numKeys-1)
	}
	srcRoot := srcEng.State().MerkleRoot()

	// --- pump rounds; record the round each node's root first equals srcRoot ---
	convRound = make(map[[16]byte]int, numNodes)
	convRound[src] = 0 // the source is converged by construction
	for round := 1; round <= roundCap; round++ {
		if _, _, _, err := loopbackGossipRound(ctx, net, engines, topos, nodeIDs, round); err != nil {
			t.Fatalf("convergence: gossip round %d run %d: %v", round, runSeed, err)
		}
		loopbackQuiesce(net, quiesce)
		roots, _ := orch.MerkleRoots()
		if len(roots) != numNodes {
			continue // a node vanished; not converged
		}
		for _, id := range nodeIDs {
			if _, done := convRound[id]; done {
				continue
			}
			if roots[id] == srcRoot {
				convRound[id] = round
			}
		}
		if len(convRound) == numNodes {
			break
		}
	}
	converged = len(convRound) == numNodes
	tailRound = 0
	for _, r := range convRound {
		if r > tailRound {
			tailRound = r
		}
	}
	return convRound, tailRound, converged
}

// convergencePercentile returns the p-th percentile of a sorted copy of xs.
// The index is int((len(xs)-1)*p), so this is a distribution summary rather
// than an interpolated percentile.
func convergencePercentile(xs []int, p float64) int {
	if len(xs) == 0 {
		return -1
	}
	cp := make([]int, len(xs))
	copy(cp, xs)
	sort.Ints(cp)
	idx := int(float64(len(cp)-1) * p)
	return cp[idx]
}

// TestConvergenceRoundDistribution reports pooled per-node rounds and per-run
// maximum rounds over many seeds (ADR-0054). A maximum near the expected
// O(log_3 N) hop count, approximately 6–7 rounds with slack at these sizes,
// would leave wall time and bandwidth as the explanation for the WAN tail.
// Every run must converge within the cap. SOVEREIGN_TEST_CONVERGENCE_SEEDS,
// SOVEREIGN_TEST_CONVERGENCE_NODES, and SOVEREIGN_TEST_CONVERGENCE_KEYS adjust
// the workload; the defaults are sized for a four-core machine.
func TestConvergenceRoundDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("convergence distribution harness; skip in -short")
	}
	// Cascade mode uses a 1 ms DeliveryBase, well below the send-phase wall
	// time. Deliveries land during a round and receivers can forward within
	// the same tick, as they can in production.
	convergenceRunDistribution(t, "CASCADE",
		chaos.ChaosProfile{Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond},
		25*time.Millisecond)
}

// TestConvergenceRoundDistributionAtomic isolates topology hop count. A 150 ms
// DeliveryBase exceeds the send-phase duration, so all sends are scheduled
// before any delivery lands. Each round is therefore one fan-out hop. A tight
// distribution supports O(log_fanout N) convergence without a selector tail.
func TestConvergenceRoundDistributionAtomic(t *testing.T) {
	if testing.Short() {
		t.Skip("convergence distribution harness; skip in -short")
	}
	// The 300 ms quiescence window covers DeliveryBase plus jitter, ensuring
	// every scheduled delivery lands before the convergence check.
	convergenceRunDistribution(t, "ATOMIC",
		chaos.ChaosProfile{Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 150 * time.Millisecond},
		300*time.Millisecond)
}

// convergenceRunDistribution runs the convergence-round distribution over the
// configured seeds with the given chaos profile and quiesce, logging the pooled
// per-node round histogram and the per-run tail (max) distribution.
func convergenceRunDistribution(t *testing.T, label string, profile chaos.ChaosProfile, quiesce time.Duration) {
	t.Helper()
	seeds := convergenceEnvInt("SOVEREIGN_TEST_CONVERGENCE_SEEDS", 60)
	numNodes := convergenceEnvInt("SOVEREIGN_TEST_CONVERGENCE_NODES", 30)
	numKeys := convergenceEnvInt("SOVEREIGN_TEST_CONVERGENCE_KEYS", 12)
	roundCap := 20
	arenaSize := uintptr(8 * 1024 * 1024)

	tailRounds := make([]int, 0, seeds)
	nodeRoundHist := make(map[int]int) // convergence round -> count of nodes (pooled)
	for s := 0; s < seeds; s++ {
		convRound, tailRound, converged := convergenceRunOnce(t, 1000+s, numNodes, numKeys, roundCap, arenaSize, quiesce, profile)
		if !converged {
			t.Fatalf("convergence %s distribution run seed=%d did not converge within %d rounds (converged %d/%d) — the harness or the topology is broken (a real defect, not a tail point)",
				label, 1000+s, roundCap, len(convRound), numNodes)
		}
		tailRounds = append(tailRounds, tailRound)
		for _, r := range convRound {
			nodeRoundHist[r]++
		}
	}

	// The tail-round (per-run max) distribution.
	sort.Ints(tailRounds)
	t.Logf("convergence P0.2 [%s] distribution: seeds=%d nodes=%d keys=%d (fan-out-3, 3 regions)", label, seeds, numNodes, numKeys)
	t.Logf("  TAIL (per-run max convergence round): min=%d p50=%d p90=%d p99=%d max=%d",
		tailRounds[0], convergencePercentile(tailRounds, 0.50), convergencePercentile(tailRounds, 0.90), convergencePercentile(tailRounds, 0.99), tailRounds[len(tailRounds)-1])
	// The pooled per-node convergence-round histogram (the shape of the curve).
	t.Logf("  per-node convergence-round histogram (round: nodes):")
	maxR := tailRounds[len(tailRounds)-1]
	for r := 0; r <= maxR; r++ {
		if c := nodeRoundHist[r]; c > 0 {
			t.Logf("    round %2d: %d nodes (%.1f%%)", r, c, 100*float64(c)/float64(seeds*numNodes))
		}
	}
}

// convergenceEnvInt reads an int env override (the distribution scale knobs),
// falling back to def when unset or unparsable.
func convergenceEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// TestCrossRegionLatencyNoRoundTail measures whether slower cross-region links
// create a round tail (ADR-0054). Atomic rounds use no intra-region latency and
// a cross-region delay of two quiescence windows, so those deliveries arrive
// about two rounds late. A fixed per-link delay should add a bounded offset,
// not the 30–50-round straggle implied by the observed WAN t90–t100 delay of
// 2.7–5 s at a 100 ms tick. The test fails if the tail exceeds the bulk by more
// than six rounds.
func TestCrossRegionLatencyNoRoundTail(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-region latency harness; skip in -short")
	}
	numNodes := convergenceEnvInt("SOVEREIGN_TEST_CONVERGENCE_NODES", 30)
	numKeys := convergenceEnvInt("SOVEREIGN_TEST_CONVERGENCE_KEYS", 12)
	seeds := convergenceEnvInt("SOVEREIGN_TEST_CONVERGENCE_SEEDS", 20)
	roundCap := 30
	arenaSize := uintptr(8 * 1024 * 1024)
	quiesce := 60 * time.Millisecond
	// Cross-region one-way latency is two quiescence windows, making those
	// deliveries arrive about two rounds late. Intra-region latency is zero.
	crossRegionDelay := 2 * quiesce

	// region map for the LinkLatency callback (nodeID -> region tag).
	tailRounds := make([]int, 0, seeds)
	bulkRounds := make([]int, 0, seeds) // the round the bulk (all but last) converged
	for s := 0; s < seeds; s++ {
		runSeed := 5000 + s
		regionOf := make(map[[16]byte]engmesh.RegionTag, numNodes)
		for i := 0; i < numNodes; i++ {
			regionOf[convergenceNodeID(runSeed, i)] = convergenceRegionFor(i)
		}
		profile := chaos.ChaosProfile{
			Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 0, DeliveryBase: 0,
			LinkLatency: func(from, to [16]byte) time.Duration {
				if regionOf[from] != regionOf[to] {
					return crossRegionDelay // cross-region
				}
				return 0 // intra-region
			},
		}
		convRound, tailRound, converged := convergenceRunOnce(t, runSeed, numNodes, numKeys, roundCap, arenaSize, quiesce, profile)
		if !converged {
			t.Fatalf("cross-region latency run seed=%d did not converge within %d rounds (%d/%d)", runSeed, roundCap, len(convRound), numNodes)
		}
		tailRounds = append(tailRounds, tailRound)
		// bulk = the 90th-percentile node convergence round this run.
		rs := make([]int, 0, len(convRound))
		for _, r := range convRound {
			rs = append(rs, r)
		}
		bulkRounds = append(bulkRounds, convergencePercentile(rs, 0.90))
	}
	sort.Ints(tailRounds)
	sort.Ints(bulkRounds)
	t.Logf("convergence P0.2 [cross-region latency=%v] seeds=%d nodes=%d", crossRegionDelay, seeds, numNodes)
	t.Logf("  BULK (per-run p90 convergence round): min=%d p50=%d max=%d", bulkRounds[0], convergencePercentile(bulkRounds, 0.5), bulkRounds[len(bulkRounds)-1])
	t.Logf("  TAIL (per-run max convergence round):  min=%d p50=%d p90=%d max=%d", tailRounds[0], convergencePercentile(tailRounds, 0.5), convergencePercentile(tailRounds, 0.9), tailRounds[len(tailRounds)-1])
	tailMax := tailRounds[len(tailRounds)-1]
	bulkMax := bulkRounds[len(bulkRounds)-1]
	// Cross-region delay spans a fixed number of rounds and should not
	// compound per node. A 30–50-round tail would exceed this bound.
	if tailMax > bulkMax+6 {
		t.Fatalf("cross-region latency produced a compounding tail (bulk max=%d, tail max=%d) — latency alone would then be a candidate; expected a bounded offset", bulkMax, tailMax)
	}
	t.Logf("  bounded: tail(max=%d) <= bulk(max=%d)+6 — latency gives a bounded offset, not the silicon tail", tailMax, bulkMax)
}
