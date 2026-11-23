// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"os"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestV2RequestHeaderOnlyWireFrame verifies that with --iblt-v2 enabled,
// generateSweepDelta sends an 8-byte header-only body [IBLTWireMagicV2,
// uint32(numBuckets)] inside digestRoleRequestV2 (49 B unprefixed / 53 B
// length-prefixed wire frame instead of 436,963 B). The responder builds a
// 21,845-bucket response IBLT that peels 10,000 keys in one round with zero
// oversends and zero crossovers.
//
// Fault injection (SOVEREIGN_TEST_FAULT_IBLT_ARENA=v2_req_full_buckets): sets the
// fault-injection flag for the v2 header-only request, causing digestReqBytes to equal
// 436,963 (> 64 B) and making the test fail.
func TestV2RequestHeaderOnlyWireFrame(t *testing.T) {
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
	m.gA.SetIBLTV2MinBuckets(21845)
	m.gB.SetIBLTV2MinBuckets(21845)
	m.gA.SetDeferCrossover(true)
	m.gB.SetDeferCrossover(true)
	if os.Getenv("SOVEREIGN_TEST_FAULT_IBLT_ARENA") == "v2_req_full_buckets" {
		m.gA.disableV2HeaderOnlyRequestBugInject.Store(true)
	}

	deferInsert(t, m.gA, "t2-10k-%05d", 0, 10000)

	st := m.gA.AntiEntropySweep(m.ctx)
	if m.gA.digestReqBytes != 53 {
		t.Fatalf("v2 request wire frame: digestReqBytes=%d, want 53 (4B length prefix + 37B header + 4B seLen + 8B [IBLTWireMagicV2, 21845]; <= 64B)",
			m.gA.digestReqBytes)
	}
	if oversends := m.gA.digestPeelOversends.Load(); oversends != 0 {
		t.Fatalf("expected 0 digestPeelOversends, got %d", oversends)
	}
	if crossovers := m.gA.digestCrossoverShips.Load(); crossovers != 0 {
		t.Fatalf("expected 0 digestCrossoverShips, got %d", crossovers)
	}
	if defers := m.gA.digestDefers.Load(); defers != 0 {
		t.Fatalf("expected 0 digestDefers, got %d (sweepStats=%+v)", defers, st)
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
	t.Fatalf("10K convergence failed after 53B v2 request exchange: rootA=%x rootB=%x",
		m.engineA.MerkleRootFromShards(), m.engineB.MerkleRootFromShards())
}

// TestResponderRootAnnounceQuenchesRedundantSweep verifies that when Node A
// sweeps Node B under gatewayMode + stratified with identical state (rootA ==
// rootB != [32]byte{}, D == 0) but initially empty peerRoots (modeling partial
// intra-view where A selects B while B has not selected A), Node B's
// respondToDigest piggybacks a rootAnnounce frame back to Node A, populating
// A.peerRoots[B] == rootB so Node A's next sweep gates and skips the redundant
// digest exchange (st2.gatedSkips == 1, st2.firedPeers == 0).
//
// Fault injection (SOVEREIGN_TEST_FAULT_IBLT_ARENA=no_respond_root_announce):
// sets the fault-injection flag for the responder root-announce on Node B, leaving
// A.peerRoots[B] unknown after Round 1 so Round 2 fires a redundant exchange
// (st2.firedPeers == 1) and the test fails.
func TestResponderRootAnnounceQuenchesRedundantSweep(t *testing.T) {
	eng.SetIBLTSchemeV2(true)
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	m := buildDeferMesh(t, DeferOpts{
		stratified:   true,
		deferHandler: true,
		batchSize:    100,
		digestWait:   1000 * time.Millisecond,
	})
	defer m.cancel()
	defer m.close()

	m.gA.SetIBLTV2(true)
	m.gB.SetIBLTV2(true)
	m.gA.SetIBLTV2MinBuckets(4096)
	m.gB.SetIBLTV2MinBuckets(4096)
	m.gA.SetGatewayMode(true)
	m.gB.SetGatewayMode(true)
	if os.Getenv("SOVEREIGN_TEST_FAULT_IBLT_ARENA") == "no_respond_root_announce" {
		m.gB.disableRespondRootAnnounceBugInject.Store(true)
	}

	// Seed 1,000 entries on Node A and clone the exact CausalDots into Node B so
	// rootA == rootB != [32]byte{} and D == 0 while peerRoots caches are empty.
	deferInsert(t, m.gA, "t3-key-%04d", 0, 1000)
	emptyIBLT := eng.NewIBLT(1, 4)
	d := m.engineA.GenerateDelta(emptyIBLT)
	m.engineB.Join(*d)
	d.Release()

	rootA := m.engineA.MerkleRootFromShards()
	rootB := m.engineB.MerkleRootFromShards()
	if rootA == ([32]byte{}) || rootA != rootB {
		t.Fatalf("setup failed: rootA=%x rootB=%x (want equal non-zero roots)", rootA, rootB)
	}

	// Round 1: Node A sweeps Node B (peerRoots[B] is initially unknown, so Round 1 fires).
	st1 := m.gA.AntiEntropySweep(m.ctx)
	if st1.firedPeers != 1 || st1.gatedSkips != 0 {
		t.Fatalf("round 1 unexpected stats: firedPeers=%d (want 1) gatedSkips=%d (want 0)",
			st1.firedPeers, st1.gatedSkips)
	}

	// Poll up to 200ms for Node B's piggybacked rootAnnounce to arrive at Node A.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if r, known := m.gA.peerRootFor(m.identB.NodeID); known && r == rootB {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Round 2: Node A sweeps Node B again without Node B ever sweeping Node A.
	st2 := m.gA.AntiEntropySweep(m.ctx)
	if st2.gatedSkips != 1 || st2.firedPeers != 0 {
		r, known := m.gA.peerRootFor(m.identB.NodeID)
		t.Fatalf("responder root-announce piggyback: Round 2 gatedSkips=%d (want 1), firedPeers=%d (want 0), peerRootFor(B)=%x (known=%v)",
			st2.gatedSkips, st2.firedPeers, r, known)
	}
}

// TestTwoStrikeGatewayTimeoutEviction verifies that on a live gateway, one
// deferClassTimeout strike keeps isGatewayPeerHealthy == true (preventing a
// one-strike cold-socket gateway carousel), a second consecutive
// deferClassTimeout strike flips isGatewayPeerHealthy == false, resetDeferPeer
// restores true, and one deferClassPublish strike immediately flips
// isGatewayPeerHealthy == false.
//
// Fault injection (SOVEREIGN_TEST_FAULT_IBLT_ARENA=one_strike_gw_timeout):
// sets the fault-injection flag for the single-strike gateway timeout, evicting gw0
// on one timeout strike and making the test fail.
func TestTwoStrikeGatewayTimeoutEviction(t *testing.T) {
	g := NewGossiper(nil, nil, nil, nil)
	g.SetDeferHandler(true)
	if os.Getenv("SOVEREIGN_TEST_FAULT_IBLT_ARENA") == "one_strike_gw_timeout" {
		g.singleStrikeGatewayTimeoutBugInject.Store(true)
	}

	gw0 := gatewayMakeNodeID(RegionTag(3), 0)

	// Strike 1 (timeout): must stay healthy (two-strike rule).
	g.noteDeferTrigger(gw0, deferClassTimeout)
	if !g.isGatewayPeerHealthy(gw0) {
		t.Fatalf("gateway timeout: gw0 marked unhealthy after 1 timeout strike (want true on strike 1 to prevent cold-socket carousel)")
	}

	// Strike 2 (consecutive timeout): must be evicted (unhealthy).
	g.noteDeferTrigger(gw0, deferClassTimeout)
	if g.isGatewayPeerHealthy(gw0) {
		t.Fatalf("gateway timeout: gw0 still healthy after 2 consecutive timeout strikes (want false)")
	}

	// Reset restores health.
	g.resetDeferPeer(gw0)
	if !g.isGatewayPeerHealthy(gw0) {
		t.Fatalf("gw0 not healthy after resetDeferPeer")
	}

	// Strike 1 (publish error): must evict immediately on 1 strike.
	g.noteDeferTrigger(gw0, deferClassPublish)
	if g.isGatewayPeerHealthy(gw0) {
		t.Fatalf("gw0 still healthy after 1 deferClassPublish strike (want immediate 1-strike eviction on socket publish error)")
	}
}
