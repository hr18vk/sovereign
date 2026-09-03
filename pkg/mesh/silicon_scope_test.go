// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh_test

// The sweep-interval probe: a loopback measurement guard that emits the
// convergence round count + wall-time at 100 nodes × 1000 keys. It lives in
// package mesh_test (the EXTERNAL test package) alongside the loopback guards
// because it reuses the loopback helpers (the engine builders, the gossip-round
// driver, the quiesce window, chaos.VirtualNet/Orchestrator) — all reachable
// from package mesh_test. It is test-only (NOT a production sweep change); the
// production default stays 100ms.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/chaos"
)

// ---------------------------------------------------------------------------
// — a LOOPBACK measurement guard that
// EMITS the convergence round count + wall-time at 100 nodes × 1000 keys under
// the fixes (MerkleRootFromShards on the silicon-check path — the
// loopback check MerkleRoots still uses State for its documented small-
// live-set boundary, UNCHANGED). It is a MEASUREMENT, NOT a production change
// (the production --gossip-tick default stays 100ms).
//
// HONEST SCOPE CORRECTION (the first draft was a LIE → caught + rewritten):
//   The first draft probed sweep ticks {50ms, 100ms, 200ms} by varying the
//   inter-round quiesce (quiesce) — BUT quiesce is the chaos
// VirtualNet's TIME-WHEEL DRAIN window, NOT a sweep tick (loopback_convergence_test.go
//   :657-665: "A too-short window reads a PARTIAL delivery as divergence → false
//   FAIL; 500ms lets the wheel drain"). At 100 nodes × 1000 keys × fan-out-3 ≈
//   300K msgs/round @ 1ms base + 2ms jitter, the drain tail is ~320ms+. A 50ms
//   or 100ms quiesce reads a PARTIAL delivery as divergence → the probe reported
//   "did NOT converge at 50ms" NON-DETERMINISTICALLY (it passed with -v's timing
//   slack, failed under the default runner's tighter scheduling) — a FALSE
// NEGATIVE, the worst kind of lie (a green-sometimes guard hiding the real
//   signal). The loopback harness has NO production SweepLoop (rounds are driven
//   manually via gossipRound); the inter-round gap is the DRAIN, not the
//   tick. CONFLATING them is wrong.
//
//   THE HONEST FIX: the probe uses the PROVEN 500ms drain window (the value
//   pumpUntilConverged uses, the value that lets the wheel drain) + EMITS
//   the rounds-to-converge + wall-time as the SILICON-RELEVANT BASELINE. The
//   sweep-tick DIALING (--gossip-tick 50ms vs 100ms vs 200ms) is a SILICON
//   measurement (the production SweepLoop fires the real tick against real WAN
//   RTT) — the loopback cannot honestly probe sub-drain ticks, so it does NOT
// pretend to. The honest-labeling rule (loopback rounds ≠ silicon ms) is HONORED: the
//   probe EMITS the loopback round count (the convergence DEPTH) + DISCLOSES that
//   the silicon wall-time = rounds × (tick + WAN RTT) — the operator dials the
//   tick on silicon where the real SweepLoop runs.
//
// HONEST: the probe asserts the mesh CONVERGES within the round cap at the
// proven drain window (the convergence property — load-bearing, NOT a tautology:
// a tampered Join DIVERGES, caught by TestLoopbackConverges100NegativeControl).
// It EMITS the round count + wall-time; it does NOT assert a "best" tick (that
// is the operator's silicon call). A non-convergence at the proven drain is a
// real regression (the probe catches it).
// ---------------------------------------------------------------------------

func TestSweepIntervalProbe(t *testing.T) {
	if testing.Short() {
		t.Skip(" sweep-interval probe runs 100 engines; skip in -short")
	}
	requires32Cores(t)
	// The PROVEN drain window (quiesceWindow — 500ms, 2s under -race since
	//) — NOT a sweep tick. Using this floor keeps the probe honest: the
	// time-wheel drains before the convergence check, so a non-convergence is a
	// REAL regression, not a partial-delivery false negative (the first draft's
	// lie).
	drain := quiesceWindow
	ctx := context.Background()
	conv, rounds, wall := probeConvergenceAtDrain(t, ctx, drain)
	if !conv {
		t.Fatalf("sweep-probe FAIL: did NOT converge after %d rounds at the proven %v drain window — a non-convergence here is a REAL regression (the drain is long enough to empty the time-wheel; a partial-delivery false negative is ruled out). Compare TestLoopbackConverges100 (the same mesh, must still pass).", rounds, drain)
	}
	// Key-presence guard (the convergence-is-not-root-collision assertion, lifted
	// from TestLoopbackConverges100 :719-727): the converged root must NOT
	// be the empty-tree root, and the source's last key must be present on the
	// last node. WITHOUT this, a root-hash collision false-passes.
	// (probeConvergenceAtDrain performs these guards internally + returns the
	// engine map for the spot-check; the guard is asserted inside the helper.)
	t.Logf("sweep-probe PASS: converged in %d rounds, %.3fs wall (100 nodes × %d keys, %v drain window, MerkleRootFromShards on the silicon-check path). SILICON GUIDANCE: wall_silicon ≈ %d × (--gossip-tick + WAN-RTT); dial --gossip-tick on the 3× c8g.8xlarge re-run (the loopback cannot honestly probe sub-drain ticks — the drain floor dominates).",
		rounds, wall, convKeys, drain, rounds)
}

// probeConvergenceAtDrain builds a 100-node × 1000-key mesh (the
// loopback configuration), injects the keys into node 0, then pumps gossip
// rounds with the proven `drain` quiesce between rounds until convergence,
// returning (converged, rounds, wallSeconds). It reuses the loopback
// helpers byte-faithfully (buildEngines, gossipRound, quiesce,
// the chaos VirtualNet/Orchestrator, buildTopologies) — it is
// pumpUntilConverged + the TestLoopbackConverges100 key-presence
// guards (empty-root + last-key-on-last-node), so a convergence here is NOT a
// root-hash collision (the same anti-tautology discipline the headline guard
// uses).
func probeConvergenceAtDrain(t *testing.T, ctx context.Context, drain time.Duration) (converged bool, rounds int, wall float64) {
	t.Helper()
	engines, nodeIDs := buildEngines(t, convNumNodes, convArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		// The polite, lossless, low-jitter fabric — byte-faithful to
		// TestLoopbackConverges100 (the §3 property is the math).
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("sweep probe: NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := buildTopologies(t, nodeIDs, regionFor)

	// Inject 1000 keys into node 0 (the source) — byte-faithful to the
	// TestLoopbackConverges100 inject (srcEng.InsertLocal per key).
	src := nodeIDs[0]
	srcEng := engines[src]
	for k := 0; k < convKeys; k++ {
		srcEng.InsertLocal(fmt.Sprintf("conv-key-%d", k), stagedEventEntry(k, src))
	}

	want := len(nodeIDs)
	start := time.Now()
	for r := 1; r <= convRoundCap; r++ {
		if _, _, _, err := gossipRound(ctx, net, engines, topos, nodeIDs, r); err != nil {
			return false, r, time.Since(start).Seconds()
		}
		quiesce(net, drain) // the PROVEN drain window (NOT a sweep tick)
		roots, ok := orch.MerkleRoots()
		if !ok {
			continue
		}
		if len(roots) != want { // guard (node count derived from nodeIDs)
			continue
		}
		if allEqualVals(roots, nodeIDs) {
			// Key-presence guards (TestLoopbackConverges100 :719-727) —
			// the convergence is NOT a root-hash collision:
			//  (a) the converged root != the empty-tree root (the keys landed).
			//  (b) the source's LAST key is present on the LAST node (state
			//      replication, not hash collision).
			convergedRoot := roots[nodeIDs[0]]
			if convergedRoot == emptyRoot(t) {
				t.Fatalf("sweep-probe: converged root == empty-tree root after %d rounds — the %d keys never landed (a false-positive convergence)", r, convKeys)
			}
			lastNode := nodeIDs[convNumNodes-1]
			if entries := engines[lastNode].State().Get(fmt.Sprintf("conv-key-%d", convKeys-1)); len(entries) == 0 {
				t.Fatalf("sweep-probe: the source's last key (conv-key-%d) is NOT present on the last node after %d rounds — convergence was root-hash collision, not state replication", convKeys-1, r)
			}
			return true, r, time.Since(start).Seconds()
		}
	}
	roots, _ := orch.MerkleRoots()
	return allEqualVals(roots, nodeIDs) && len(roots) == want, convRoundCap, time.Since(start).Seconds()
}
