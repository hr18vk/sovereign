// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

func gatewayMakeNodeID(region RegionTag, idx int) [16]byte {
	var id [16]byte
	id[0] = byte(region)
	binary.BigEndian.PutUint32(id[12:16], uint32(idx))
	return id
}

// buildGatewayTopology90 constructs a 3-region topology (30 nodes/region = 90
// nodes total, 3 gateways per region, partialIntraView = true, fanout = 3).
// In each region r in {1, 2, 3}, indices 0, 1, 2 are the lowest [16]byte
// nodeIDs and therefore the gateways for region r.
func buildGatewayTopology90(selfRegion RegionTag, selfIdx int) *TopologyManager {
	selfID := gatewayMakeNodeID(selfRegion, selfIdx)
	topo := NewTopologyManager(selfRegion)
	topo.SetFanout(3)
	topo.SetPartialIntraView(true)
	topo.SetGatewaysPerRegion(3)
	topo.SetSelfNodeID(selfID)
	for r := RegionTag(1); r <= 3; r++ {
		for idx := 0; idx < 30; idx++ {
			id := gatewayMakeNodeID(r, idx)
			if id == selfID {
				continue
			}
			topo.SetRegion(id, r)
		}
	}
	return topo
}

// TestGatewayInteriorNodeSelectsIntraOnly verifies the interior-node selection
// behavior for the gateway topology (ADR-0073 §4.2):
//   - ShouldDialPeer returns true for all 29 same-region peers and false for
//     all 60 foreign-region peers (0 cross-region WAN TCP connections).
//   - Across 100 rounds, Select(ctx) selects 8 intra-region peers and 0
//     cross-region peers.
//   - The fault-injection control SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT=interior_cut
//     makes the test fail by allowing cross-region selection.
func TestGatewayInteriorNodeSelectsIntraOnly(t *testing.T) {
	topo := buildGatewayTopology90(RegionTag(1), 10) // idx=10 -> interior node in region 1
	if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "interior_cut" {
		topo.disableGatewayInteriorCutBugInject.Store(true)
	}
	if topo.IsSelfGateway() {
		t.Fatalf("precondition failed: node idx=10 in region 1 must be an interior node (!IsSelfGateway)")
	}

	intraDialAllowed := 0
	foreignDialAllowed := 0
	for r := RegionTag(1); r <= 3; r++ {
		for idx := 0; idx < 30; idx++ {
			if r == 1 && idx == 10 {
				continue
			}
			id := gatewayMakeNodeID(r, idx)
			if topo.ShouldDialPeer(id) {
				if r == 1 {
					intraDialAllowed++
				} else {
					foreignDialAllowed++
				}
			}
		}
	}
	if intraDialAllowed != 29 || foreignDialAllowed != 0 {
		t.Fatalf("ShouldDialPeer mismatch: intraDialAllowed=%d (want 29), foreignDialAllowed=%d (want 0)", intraDialAllowed, foreignDialAllowed)
	}

	ctx := context.Background()
	crossSelected := 0
	for round := uint64(1); round <= 100; round++ {
		topo.SetSeed(round)
		sel := topo.Select(ctx)
		for _, p := range sel {
			if topo.IsInterRegion(p) {
				crossSelected++
			}
		}
		if crossSelected > 0 {
			t.Fatalf("interior node selected cross-region peers (round=%d crossSelected=%d totalSelected=%d)", round, crossSelected, len(sel))
		}
		if len(sel) != intraViewSize {
			t.Fatalf("round=%d len(sel)=%d, want %d intra-only peers", round, len(sel), intraViewSize)
		}
	}
}

// TestGatewayNodeSelectsPinnedSiblingsAndForeignGateways verifies the gateway-node
// selection behavior for the gateway topology (ADR-0073 §4.2):
//   - Pins its 2 live local-region sibling gateways (idx=1, idx=2) at the head
//     of its 8-peer intra view + 6 uniform interior peers (8 intra total).
//   - Selects 1 foreign gateway from each of the 2 foreign regions (10 peers
//     total), and 100% of selected cross-region peers satisfy topo.IsGateway(p).
func TestGatewayNodeSelectsPinnedSiblingsAndForeignGateways(t *testing.T) {
	topo := buildGatewayTopology90(RegionTag(1), 0) // idx=0 -> gateway #0 in region 1
	if !topo.IsSelfGateway() {
		t.Fatalf("precondition failed: node idx=0 in region 1 must be a gateway node (IsSelfGateway)")
	}
	if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "gateway_select" {
		topo.disableGatewayInteriorCutBugInject.Store(true)
		for idx := 0; idx < 30; idx++ {
			topo.SetGateway(gatewayMakeNodeID(RegionTag(2), idx), true)
		}
	}
	sib1 := gatewayMakeNodeID(RegionTag(1), 1)
	sib2 := gatewayMakeNodeID(RegionTag(1), 2)

	ctx := context.Background()
	seenInterior := make(map[[16]byte]bool)
	for round := uint64(1); round <= 100; round++ {
		topo.SetSeed(round)
		sel := topo.Select(ctx)
		if len(sel) != 10 {
			t.Fatalf("round=%d len(sel)=%d, want 10 (8 intra + 2 foreign gateways)", round, len(sel))
		}
		hasSib1, hasSib2 := false, false
		intraCount := 0
		reg2GW, reg3GW := 0, 0
		for _, p := range sel {
			reg := topo.PeerRegion(p)
			if reg == RegionTag(1) {
				intraCount++
				if p == sib1 {
					hasSib1 = true
				} else if p == sib2 {
					hasSib2 = true
				} else {
					seenInterior[p] = true
				}
			} else {
				isOrigGW := p == gatewayMakeNodeID(reg, 0) || p == gatewayMakeNodeID(reg, 1) || p == gatewayMakeNodeID(reg, 2)
				if !topo.IsGateway(p) || !isOrigGW {
					t.Fatalf("round=%d selected non-gateway foreign peer %x in region %d", round, p, reg)
				}
				if reg == RegionTag(2) {
					reg2GW++
				} else if reg == RegionTag(3) {
					reg3GW++
				}
			}
		}
		if !hasSib1 || !hasSib2 || intraCount != 8 || reg2GW != 1 || reg3GW != 1 {
			t.Fatalf("round=%d invariant failed: hasSib1=%v hasSib2=%v intraCount=%d reg2GW=%d reg3GW=%d",
				round, hasSib1, hasSib2, intraCount, reg2GW, reg3GW)
		}
		drawn, eligible, _ := topo.LastIntraView()
		if drawn != 8 || eligible != 29 {
			t.Fatalf("LastIntraView=(%d, %d), want (8, 29)", drawn, eligible)
		}
	}
	if len(seenInterior) < 20 {
		t.Fatalf("interior rotation too narrow: saw %d distinct interior peers across 100 rounds, want >= 20 of 27", len(seenInterior))
	}
}

// TestGatewayDeadGatewayEvictionFailover verifies dead-gateway eviction for the
// gateway topology (ADR-0073 §4.3): when foreign gateway #0 in region 2 (idx=0)
// fails liveness (either via !egressVerified or an active timeout/publish
// deferral streak within 15s in isGatewayPeerHealthy), Select(ctx) on a
// region-1 gateway immediately evicts foreign gateway #0 on the next sweep and
// selects exclusively from live gateways #1 and #2.
// The fault-injection control SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT=gw_liveness
// makes the test fail by continuing to select the dead gateway.
func TestGatewayDeadGatewayEvictionFailover(t *testing.T) {
	topo := buildGatewayTopology90(RegionTag(1), 0)
	if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "gw_liveness" {
		topo.disableGatewayLivenessFailoverBugInject.Store(true)
	}

	g := NewGossiper(nil, nil, nil, nil)
	g.SetDeferHandler(true)
	g.SetTopology(topo)

	deadGW := gatewayMakeNodeID(RegionTag(2), 0)
	liveGW1 := gatewayMakeNodeID(RegionTag(2), 1)
	liveGW2 := gatewayMakeNodeID(RegionTag(2), 2)

	// Trigger 2 consecutive timeout deferrals on deadGW (stamps lastDeferAt = time.Now()
	// and reaches the 2-strike timeout eviction threshold).
	g.noteDeferTrigger(deadGW, deferClassTimeout)
	g.noteDeferTrigger(deadGW, deferClassTimeout)

	ctx := context.Background()
	deadPicks := 0
	live1Picks := 0
	live2Picks := 0
	for round := uint64(1); round <= 60; round++ {
		topo.SetSeed(round)
		sel := topo.Select(ctx)
		for _, p := range sel {
			if topo.PeerRegion(p) == RegionTag(2) {
				switch p {
				case deadGW:
					deadPicks++
				case liveGW1:
					live1Picks++
				case liveGW2:
					live2Picks++
				default:
					t.Fatalf("selected unexpected region-2 peer %x", p)
				}
			}
		}
	}
	if deadPicks != 0 {
		t.Fatalf("dead-gateway eviction violation: selected dead foreign gateway #0 %d times across 60 rounds (want 0; live1=%d live2=%d)",
			deadPicks, live1Picks, live2Picks)
	}
	if live1Picks == 0 || live2Picks == 0 {
		t.Fatalf("failover distribution degenerate: live1=%d live2=%d, want both > 0", live1Picks, live2Picks)
	}

	// Verify automatic recovery after resetDeferPeer clears the deferral streak.
	g.resetDeferPeer(deadGW)
	recoveredPicks := 0
	for round := uint64(101); round <= 160; round++ {
		topo.SetSeed(round)
		for _, p := range topo.Select(ctx) {
			if p == deadGW {
				recoveredPicks++
			}
		}
	}
	if recoveredPicks == 0 {
		t.Fatalf("gateway recovery failed: deadGW was not re-admitted after resetDeferPeer")
	}
}

// TestGatewayEmptySelfRootShortCircuit checks ADR-0072 §6 with an empty node
// in gateway mode and a peer holding 1,000 entries. The empty node publishes
// its root but skips generateSweepDelta, so it sends no digest request and
// records one gated skip. When the peer sweeps back, the empty node must
// receive all 1,000 entries and converge.
// SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT=empty_root_skip disables that shortcut.
func TestGatewayEmptySelfRootShortCircuit(t *testing.T) {
	eng.SetIBLTSchemeV2(true)
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	m := buildDeferMesh(t, DeferOpts{
		stratified:   true,
		deferHandler: true,
		batchSize:    100,
		digestWait:   500 * time.Millisecond,
	})
	defer m.cancel()
	defer m.close()

	m.gA.SetIBLTV2(true)
	m.gB.SetIBLTV2(true)
	m.gA.SetIBLTV2MinBuckets(4096)
	m.gB.SetIBLTV2MinBuckets(4096)
	m.gA.SetGatewayMode(true)
	m.gB.SetGatewayMode(true)
	if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "empty_root_skip" {
		m.gA.disableEmptyRootSkipBugInject.Store(true)
	}

	// Node B holds 1,000 entries; Node A is empty (myRoot == [32]byte{}).
	deferInsert(t, m.gB, "t4-key-%04d", 0, 1000)

	// Step 1: Empty Node A sweeps Node B. It must publish rootFrame to B and
	// short-circuit generateSweepDelta (0 digest requests sent, gatedSkips == 1).
	stA := m.gA.AntiEntropySweep(m.ctx)
	if m.gA.digestReqBytes != 0 || stA.gatedSkips != 1 {
		t.Fatalf("empty-root short-circuit violation: empty node A sent digestReqBytes=%d (want 0), gatedSkips=%d (want 1)",
			m.gA.digestReqBytes, stA.gatedSkips)
	}

	// Wait until B's readLoop records A's root-announce frame (proot[A] == [32]byte{}).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.gB.peerRootsMu.Lock()
		_, known := m.gB.peerRoots[m.identA.NodeID]
		m.gB.peerRootsMu.Unlock()
		if known {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Step 2: Non-empty Node B sweeps empty Node A and pushes all 1,000 entries.
	_ = m.gB.AntiEntropySweep(m.ctx)

	convDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(convDeadline) {
		rA := m.engineA.MerkleRootFromShards()
		rB := m.engineB.MerkleRootFromShards()
		if rA != ([32]byte{}) && rA == rB {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("failed to converge after B swept empty A: rootA=%x rootB=%x",
		m.engineA.MerkleRootFromShards(), m.engineB.MerkleRootFromShards())
}

// TestGatewayIBLTV2MinBucketsSingleRoundPeelAt10K gives two nodes a 10,000-key
// difference and sets --iblt-v2, --defer-handler, --defer-crossover, and
// --iblt-v2-min-buckets 21845. Their first exchange must peel without
// ErrIncompletePeel, digestPeelOversends, crossover, or defer, then converge.
// SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT=min_buckets_zero leaves the minimum at
// zero, forcing the 1,024-bucket default to fail peel and trigger crossover.
func TestGatewayIBLTV2MinBucketsSingleRoundPeelAt10K(t *testing.T) {
	eng.SetIBLTSchemeV2(true)
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	m := buildDeferMesh(t, DeferOpts{
		stratified:   true,
		deferHandler: true,
		batchSize:    100,
		digestWait:   1500 * time.Millisecond,
	})
	defer m.cancel()
	defer m.close()

	m.gA.SetIBLTV2(true)
	m.gB.SetIBLTV2(true)
	m.gA.SetDeferCrossover(true)
	m.gB.SetDeferCrossover(true)
	minB := 21845
	if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "min_buckets_zero" {
		minB = 0
	}
	m.gA.SetIBLTV2MinBuckets(minB)
	m.gB.SetIBLTV2MinBuckets(minB)

	if minB == 21845 {
		if got := m.gA.digestBucketsFor(m.identB.NodeID); got != 21845 {
			t.Fatalf("digestBucketsFor=%d, want 21845", got)
		}
	}

	deferInsert(t, m.gA, "t5-10k-%05d", 0, 10000)

	// Drive 1 sweep from A -> B.
	_ = m.gA.AntiEntropySweep(m.ctx)

	if peelFails := m.gA.digestPeelOversends.Load(); peelFails != 0 {
		t.Fatalf("IBLT v2 minimum-buckets violation: first exchange failed peel at D=10,000 (digestPeelOversends=%d crossover=%d defers=%d, want 0)",
			peelFails, m.gA.digestCrossoverShips.Load(), m.gA.digestDefers.Load())
	}
	if cross := m.gA.digestCrossoverShips.Load(); cross != 0 {
		t.Fatalf("IBLT v2 minimum-buckets violation: crossover=%d, want 0", cross)
	}
	if defers := m.gA.digestDefers.Load(); defers != 0 {
		t.Fatalf("IBLT v2 minimum-buckets violation: digestDefers=%d, want 0", defers)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rA := m.engineA.MerkleRootFromShards()
		rB := m.engineB.MerkleRootFromShards()
		if rA != ([32]byte{}) && rA == rB {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nodes did not converge to D=10,000 after 1 clean peel: rootA=%x rootB=%x",
		m.engineA.MerkleRootFromShards(), m.engineB.MerkleRootFromShards())
}

// TestGatewaySelectNoHotPathAlloc checks a 1,000-node topology split 333,
// 333, and 334 across three regions. drawIntraView must use at most one
// allocation per operation. Select with three gateways per region must use at
// most two for either role, with no map allocation for foreign gateways.
func TestGatewaySelectNoHotPathAlloc(t *testing.T) {
	splits := [3]int{333, 333, 334}
	build1K := func(selfIdx int) *TopologyManager {
		selfID := gatewayMakeNodeID(RegionTag(1), selfIdx)
		topo := NewTopologyManager(RegionTag(1))
		topo.SetFanout(3)
		topo.SetPartialIntraView(true)
		topo.SetGatewaysPerRegion(3)
		topo.SetSelfNodeID(selfID)
		for rIdx, count := range splits {
			r := RegionTag(rIdx + 1)
			for i := 0; i < count; i++ {
				id := gatewayMakeNodeID(r, i)
				if id == selfID {
					continue
				}
				topo.SetRegion(id, r)
			}
		}
		return topo
	}

	gwTopo := build1K(0)
	intTopo := build1K(10)

	pop := make([][16]byte, 332)
	for i := range pop {
		pop[i] = gatewayMakeNodeID(RegionTag(1), i+1)
	}
	var sink [][16]byte
	var round uint64
	drawAllocs := testing.AllocsPerRun(200, func() {
		round++
		sink = intTopo.drawIntraView(pop, round)
	})
	if drawAllocs > 1 {
		t.Fatalf("drawIntraView allocs/op = %v, want <= 1", drawAllocs)
	}

	ctx := context.Background()
	intAllocs := testing.AllocsPerRun(200, func() {
		round++
		intTopo.SetSeed(round)
		sink = intTopo.Select(ctx)
	})
	if intAllocs > 2 {
		t.Fatalf("interior Select(ctx) allocs/op = %v, want <= 2", intAllocs)
	}

	gwAllocs := testing.AllocsPerRun(200, func() {
		round++
		gwTopo.SetSeed(round)
		if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "select_alloc" {
			m := make(map[RegionTag][][16]byte, 4)
			m[RegionTag(2)] = make([][16]byte, 3)
			sink = m[RegionTag(2)]
		}
		sink = gwTopo.Select(ctx)
	})
	if gwAllocs > 2 {
		t.Fatalf("gateway Select(ctx) allocs/op = %v, want <= 2 (0 map allocations)", gwAllocs)
	}
	_ = sink
	t.Logf("drawIntraView=%v allocs/op, interior Select=%v allocs/op, gateway Select=%v allocs/op (N=1,000)",
		drawAllocs, intAllocs, gwAllocs)
}

// TestMeshDigestReleaseLocalRateIndependentArena checks responder digest
// memory use through respondToDigest, GenerateDigestSizedWithSeed, MarshalIBLT,
// and releaseMeshDigest. It performs 100 builds at the
// --iblt-v2-min-buckets 21845 floor on a 64 MiB arena while holding a real
// delta's EBR pin. This shape caused 988 of 1,000 nodes to report
// "HamtArena: OOM" in the run recorded by ADR-0074.
//
//   - With ReleaseLocal: the 512 KiB slab returns to the var freelist at
//     once; the bump high-water growth is bounded independent of the build
//     count — worst case the freed slab sits outside allocVar's 128-of-256
//     shard probe window until at most 64 builds' frees rotate it in
//     (hamt_arena.go): <= 64 x 512 KiB = 32 MiB.
//   - With EBR release forced by
//     SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT=mesh_digest_ebr, every slab stays on
//     the retired list. The responder does not call maybeAdvanceEpoch and the
//     held pin blocks reclamation, so growth is at least 100 x 512 KiB =
//     50 MiB and scales with the inbound rate.
//
// Every build must be counted: digestRespondSent must advance by exactly 100
// (every build was marshaled and published to the verified peer B — a skipped
// build cannot pass the check by allocating nothing).
func TestMeshDigestReleaseLocalRateIndependentArena(t *testing.T) {
	eng.SetIBLTSchemeV2(true)
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })
	if os.Getenv("SOVEREIGN_TEST_FAULT_TOPOLOGY_BOOT") == "mesh_digest_ebr" {
		meshDigestEBRReleaseBugInject.Store(true)
		t.Cleanup(func() { meshDigestEBRReleaseBugInject.Store(false) })
	}

	m := buildDeferMesh(t, DeferOpts{
		stratified:   true,
		deferHandler: true,
		batchSize:    100,
		digestWait:   1500 * time.Millisecond,
	})
	defer m.cancel()
	defer m.close()
	m.gA.SetIBLTV2(true)
	m.gB.SetIBLTV2(true)
	m.gA.SetIBLTV2MinBuckets(21845)
	m.gB.SetIBLTV2MinBuckets(21845)
	deferInsert(t, m.gA, "t9-10k-%05d", 0, 10000)

	const buckets = 21845
	seed := eng.Uint64ToSeed(0x4848F9F9)
	remote := m.engineB.GenerateDigestSizedWithSeed(seed, buckets)
	if remote.NumBuckets() != buckets {
		t.Fatalf("premise: remote digest has %d buckets, want %d", remote.NumBuckets(), buckets)
	}
	pin := m.engineA.GenerateDelta(remote) // holds A's EBR participant until Release (the in-flight ship)

	sentBefore := m.gA.digestRespondSent.Load()
	hwBefore := m.engineA.Arena().HighWater()
	const builds = 100
	for i := 0; i < builds; i++ {
		sem := make(chan struct{}, 1)
		sem <- struct{}{}
		m.gA.respondToDigest(sem, m.identB.NodeID, seed, buckets, time.Now())
	}
	growth := m.engineA.Arena().HighWater() - hwBefore
	sent := m.gA.digestRespondSent.Load() - sentBefore
	pin.Release()
	remote.Release()

	const mib = 1 << 20
	t.Logf("builds=%d sent=%d arena_highwater_growth=%.2f MiB (bound 40 MiB; linear floor %d x 512 KiB = %.0f MiB)",
		builds, sent, float64(growth)/mib, builds, float64(builds)*0.5)
	if sent != builds {
		t.Fatalf("build count mismatch: digestRespondSent advanced %d, want exactly %d (a build was skipped — the arena bound would not hold)", sent, builds)
	}
	if growth > 40*mib {
		t.Fatalf("arena violation: %d responder digest builds at %d buckets under a held EBR pin grew the arena high-water by %.2f MiB (> 40 MiB bound) — the goroutine-local mesh digests are not returning to the freelist (the 1,000-node run rate-scaled OOM)",
			builds, buckets, float64(growth)/mib)
	}

	// Repeat under a fresh held pin. The cumulative total must stay below the
	// same 40 MiB bound after 200 builds. A path that retains every slab would
	// instead require at least 200 x 512 KiB = 100 MiB and exhaust the 64 MiB
	// arena during the first phase.
	remote2 := m.engineB.GenerateDigestSizedWithSeed(seed, buckets)
	pin2 := m.engineA.GenerateDelta(remote2)
	hwMid := m.engineA.Arena().HighWater()
	sentMid := m.gA.digestRespondSent.Load()
	for i := 0; i < builds; i++ {
		sem := make(chan struct{}, 1)
		sem <- struct{}{}
		m.gA.respondToDigest(sem, m.identB.NodeID, seed, buckets, time.Now())
	}
	growth2 := m.engineA.Arena().HighWater() - hwMid
	cumulative := m.engineA.Arena().HighWater() - hwBefore
	sent2 := m.gA.digestRespondSent.Load() - sentMid
	pin2.Release()
	remote2.Release()
	t.Logf("second-phase builds=%d sent=%d growth=%.2f MiB cumulative_over_%d=%.2f MiB (bound 40 MiB; linear floor %.0f MiB)",
		builds, sent2, float64(growth2)/mib, 2*builds, float64(cumulative)/mib, float64(2*builds)*0.5)
	if sent2 != builds {
		t.Fatalf("second-phase build count mismatch: digestRespondSent advanced %d, want exactly %d", sent2, builds)
	}
	if cumulative > 40*mib {
		t.Fatalf("rate-independence violation: %d builds grew the arena high-water by %.2f MiB cumulative (> the same 40 MiB bound that held at %d) — the working set still scales with the inbound digest count",
			2*builds, float64(cumulative)/mib, builds)
	}
}
