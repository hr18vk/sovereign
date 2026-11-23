// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh_test

// The loopback probe reuses the external convergence harness and
// chaos.VirtualNet. The production --gossip-tick default remains 100ms.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/chaos"
)

// TestSiliconScopeSweepIntervalProbe measures convergence rounds and elapsed
// time at 100 nodes and 1,000 keys. The inter-round loopbackQuiesce interval
// drains VirtualNet's time wheel; it is not the production sweep tick. A short
// drain can report partial delivery as divergence. At fan-out 3 this layout
// sends about 300,000 messages per round with 1ms base latency and 2ms jitter,
// so the drain tail exceeds 320ms and loopbackQuiesceWindow provides the floor.
//
// The harness drives rounds directly with loopbackGossipRound rather than
// running SweepLoop. It therefore cannot compare sweep-tick settings. The
// elapsed loopback time is reported separately from the round count, and no
// distributed-fleet latency is inferred from it.
//
// Convergence must occur within loopbackConvRoundCap. The helper also rejects
// an empty-tree root and requires the source's last key on the last node, so
// matching roots alone cannot satisfy the test.
func TestSiliconScopeSweepIntervalProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("sweep-interval probe runs 100 engines; skip in -short")
	}
	loopbackRequires32Cores(t)
	// Drain the VirtualNet time wheel before checking convergence.
	drain := loopbackQuiesceWindow
	ctx := context.Background()
	conv, rounds, wall := siliconProbeConvergenceAtDrain(t, ctx, drain)
	if !conv {
		t.Fatalf("sweep probe did not converge after %d rounds with a %v drain window; compare TestLoopbackConverges100", rounds, drain)
	}
	t.Logf("sweep probe converged in %d rounds and %.3fs (100 nodes, %d keys, %v drain window); fleet wall estimate uses %d × (--gossip-tick + WAN-RTT)",
		rounds, wall, loopbackConvKeys, drain, rounds)
}

// siliconProbeConvergenceAtDrain inserts the keys into node 0 and drives
// gossip rounds with drain intervals until the sharded roots match. It returns
// whether convergence occurred, the round count, and elapsed seconds.
func siliconProbeConvergenceAtDrain(t *testing.T, ctx context.Context, drain time.Duration) (converged bool, rounds int, wall float64) {
	t.Helper()
	engines, nodeIDs := loopbackBuildEngines(t, loopbackNumNodes, loopbackConvArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		// Match the lossless, low-jitter loopback convergence profile.
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("probe: NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := loopbackBuildTopologies(t, nodeIDs, loopbackRegionFor)

	// Insert the source keys exactly as the loopback convergence test does.
	src := nodeIDs[0]
	srcEng := engines[src]
	for k := 0; k < loopbackConvKeys; k++ {
		srcEng.InsertLocal(fmt.Sprintf("loopback-key-%d", k), loopbackStagedEventEntry(k, src))
	}

	want := len(nodeIDs)
	start := time.Now()
	for r := 1; r <= loopbackConvRoundCap; r++ {
		if _, _, _, err := loopbackGossipRound(ctx, net, engines, topos, nodeIDs, r); err != nil {
			return false, r, time.Since(start).Seconds()
		}
		loopbackQuiesce(net, drain) // drain the time wheel, not a sweep tick
		roots, ok := orch.MerkleRoots()
		if !ok {
			continue
		}
		if len(roots) != want { // node count guard (derived from nodeIDs)
			continue
		}
		if loopbackAllEqualVals(roots, nodeIDs) {
			// Reject an empty root and require the last source key on the last
			// node so matching roots alone cannot pass.
			convergedRoot := roots[nodeIDs[0]]
			if convergedRoot == loopbackEmptyRoot(t) {
				t.Fatalf("sweep probe reached the empty-tree root after %d rounds; %d source keys are missing", r, loopbackConvKeys)
			}
			lastNode := nodeIDs[loopbackNumNodes-1]
			if entries := engines[lastNode].PointGet(fmt.Sprintf("loopback-key-%d", loopbackConvKeys-1)); len(entries) == 0 {
				t.Fatalf("sweep probe: last node lacks loopback-key-%d after %d rounds despite matching roots", loopbackConvKeys-1, r)
			}
			return true, r, time.Since(start).Seconds()
		}
	}
	roots, _ := orch.MerkleRoots()
	return loopbackAllEqualVals(roots, nodeIDs) && len(roots) == want, loopbackConvRoundCap, time.Since(start).Seconds()
}
