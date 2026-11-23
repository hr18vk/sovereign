// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"crypto/sha256"
	"hash/maphash"
	"os"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// waitDeclinedVerified polls until declPC (or the PeerSet's challengeVerified
// counter) reaches wantVerified.
func waitChallengeVerifiedCount(t *testing.T, ps *PeerSet, want uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ps.challengeVerified.Load() >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("PeerSet challengeVerified=%d, want >= %d within 3s", ps.challengeVerified.Load(), want)
}

// TestOB31SequentialBothWaysDialNoOverwriteConverges checks that B reuses the
// live peer installed when A first dialed it. B's subsequent dial of A must not
// replace that peerConn or open another connection. Stratified sweeps in both
// directions must converge without dropped digests or deferred exchanges.
func TestOB31SequentialBothWaysDialNoOverwriteConverges(t *testing.T) {
	eng.SetIBLTSchemeV2(true)
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	m := buildDeferMesh(t, DeferOpts{
		stratified:   true,
		deferHandler: true,
		batchSize:    10,
		digestWait:   150 * time.Millisecond,
	})
	defer m.cancel()
	m.gA.SetIBLTV2(true)
	m.gB.SetIBLTV2(true)
	m.gA.SetDeferCrossover(true)
	m.gB.SetDeferCrossover(true)
	m.gA.SetDigestWaitAdaptive(true)
	m.gB.SetDigestWaitAdaptive(true)

	if os.Getenv("SOVEREIGN_TEST_FAULT_DIAL_GATING") == "dial_overwrite" {
		m.psB.disableDialPeerIDCheckBugInject.Store(true)
		m.psA.disableDeclinedVerifyBugInject.Store(true)
	}

	m.psB.mu.RLock()
	pcBefore := m.psB.peers[m.identA.NodeID]
	m.psB.mu.RUnlock()
	if pcBefore == nil {
		t.Fatalf("precondition failed: psB.peers[A] is nil after A->B dial")
	}

	// Sequential second dial: B dials A's listen address after A's inbound conn is already live.
	if err := m.psB.Dial(m.ctx, m.addrA, "localhost", m.identA.NodeID); err != nil {
		t.Fatalf("sequential B.Dial(A): %v", err)
	}
	// Give any erroneously dialed second connection time to reach A's accept loop.
	time.Sleep(50 * time.Millisecond)

	m.psB.mu.RLock()
	pcAfter := m.psB.peers[m.identA.NodeID]
	m.psB.mu.RUnlock()

	deferInsert(t, m.gA, "challenge-seq-a-%04d", 0, 20)
	deferInsert(t, m.gB, "challenge-seq-b-%04d", 0, 20)

	for r := 0; r < 4; r++ {
		deferSweepRound(t, m)
	}
	m.close()
	latencySyncResponders(t, m)

	if pcBefore != pcAfter {
		t.Fatalf("sequential B.Dial(A) replaced live peer %p with %p; digestSeamDropsA=%d digestDefersB=%d",
			pcBefore, pcAfter, m.psA.digestSeamDrops.Load(), m.gB.digestDefers.Load())
	}
	if drops := m.psA.digestSeamDrops.Load() + m.psB.digestSeamDrops.Load(); drops != 0 {
		t.Fatalf("sequential dial: digestSeamDrops=%d (A=%d B=%d), want 0",
			drops, m.psA.digestSeamDrops.Load(), m.psB.digestSeamDrops.Load())
	}
	if defers := m.gA.digestDefers.Load() + m.gB.digestDefers.Load(); defers != 0 {
		t.Fatalf("sequential dial: digestDefers=%d (A=%d B=%d), want 0",
			defers, m.gA.digestDefers.Load(), m.gB.digestDefers.Load())
	}
	if rA, rB := m.engineA.MerkleRootFromShards(), m.engineB.MerkleRootFromShards(); rA != rB {
		t.Fatalf("sequential dial: Merkle roots diverged: A=%x B=%x", rA[:8], rB[:8])
	}
}

// TestOB31SimultaneousBothWaysDialDeclinedVerifiedConverges checks simultaneous
// outbound dials. Each accept loop declines the duplicate inbound connection, and
// ArmDeclinedInbound must authenticate that connection so both directions can
// exchange digests and converge. A peer presenting B's TLS identity without B's
// Ed25519 private key must fail verification and have its digest frame dropped.
func TestOB31SimultaneousBothWaysDialDeclinedVerifiedConverges(t *testing.T) {
	eng.SetIBLTSchemeV2(true)
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	m := buildDeferMesh(t, DeferOpts{
		stratified:   true,
		deferHandler: true,
		batchSize:    10,
		digestWait:   150 * time.Millisecond,
	})
	defer m.cancel()
	m.gA.SetIBLTV2(true)
	m.gB.SetIBLTV2(true)
	m.gA.SetDeferCrossover(true)
	m.gB.SetDeferCrossover(true)
	m.gA.SetDigestWaitAdaptive(true)
	m.gB.SetDigestWaitAdaptive(true)

	if os.Getenv("SOVEREIGN_TEST_FAULT_DIAL_GATING") == "sim_decline" {
		m.psA.disableDeclinedVerifyBugInject.Store(true)
		m.psB.disableDeclinedVerifyBugInject.Store(true)
	}

	// Force the simultaneous both-ways dial topology deterministically:
	// 1. B dials A while A already holds psA.peers[B]. A's RegisterInbound
	//    declines B's duplicate connection (myPC == nil on A) and arms declPC.
	m.psB.disableDialPeerIDCheckBugInject.Store(true)
	if err := m.psB.Dial(m.ctx, m.addrA, "localhost", m.identA.NodeID); err != nil {
		t.Fatalf("B.Dial(A): %v", err)
	}
	m.psB.disableDialPeerIDCheckBugInject.Store(false)

	// 2. A dials B with a fresh outbound connection while B holds psB.peers[A].
	//    B's RegisterInbound declines A's duplicate connection (myPC == nil on B)
	//    and arms declPC. Both registered peers are now outbound connections
	//    whose remote server declined the corresponding inbound connection.
	m.psA.mu.Lock()
	delete(m.psA.byAddr, m.addrB)
	m.psA.mu.Unlock()
	m.psA.disableDialPeerIDCheckBugInject.Store(true)
	if err := m.psA.Dial(m.ctx, m.addrB, "localhost", m.identB.NodeID); err != nil {
		t.Fatalf("A.Dial(B) simultaneous: %v", err)
	}
	m.psA.disableDialPeerIDCheckBugInject.Store(false)

	awaitVerified(t, m.psA, m.identB.NodeID)
	awaitVerified(t, m.psB, m.identA.NodeID)
	if os.Getenv("SOVEREIGN_TEST_FAULT_DIAL_GATING") != "sim_decline" {
		// The initial one-way dial contributes one verification on each PeerSet.
		// Each declined connection adds outbound and declPC verification, so both
		// PeerSets must reach at least two verified connections.
		waitChallengeVerifiedCount(t, m.psA, 2)
		waitChallengeVerifiedCount(t, m.psB, 2)
	} else {
		time.Sleep(50 * time.Millisecond)
	}

	// Both sides must record a decline caused by an existing live edge.
	m.psA.challengeDeclinedMu.Lock()
	declLiveA := len(m.psA.challengeDeclinedLiveEdge)
	m.psA.challengeDeclinedMu.Unlock()
	m.psB.challengeDeclinedMu.Lock()
	declLiveB := len(m.psB.challengeDeclinedLiveEdge)
	m.psB.challengeDeclinedMu.Unlock()
	if declLiveA == 0 || declLiveB == 0 {
		t.Fatalf("expected E1-LIVE declines on both A (%d) and B (%d)", declLiveA, declLiveB)
	}

	deferInsert(t, m.gA, "challenge-sim-a-%04d", 0, 20)
	deferInsert(t, m.gB, "challenge-sim-b-%04d", 0, 20)

	for r := 0; r < 4; r++ {
		deferSweepRound(t, m)
	}

	if drops := m.psA.digestSeamDrops.Load() + m.psB.digestSeamDrops.Load(); drops != 0 {
		t.Fatalf("declined simultaneous-dial connections dropped digests: digestSeamDrops=%d (A=%d B=%d), want 0",
			drops, m.psA.digestSeamDrops.Load(), m.psB.digestSeamDrops.Load())
	}
	if defers := m.gA.digestDefers.Load() + m.gB.digestDefers.Load(); defers != 0 {
		t.Fatalf("declined simultaneous-dial sweeps deferred: digestDefers=%d (A=%d B=%d), want 0",
			defers, m.gA.digestDefers.Load(), m.gB.digestDefers.Load())
	}
	if rA, rB := m.engineA.MerkleRootFromShards(), m.engineB.MerkleRootFromShards(); rA != rB {
		t.Fatalf("simultaneous dial: Merkle roots diverged: A=%x B=%x", rA[:8], rB[:8])
	}

	// An impostor with B's certificate identity but without B's Ed25519 private
	// key must fail the declined-connection challenge. DigestConnVerified then
	// drops its digest frames.
	seedM := sha256.Sum256([]byte("challenge-impostor-M"))
	identM, err := NewNodeIdentity(seedM[:])
	if err != nil {
		t.Fatalf("NewNodeIdentity M: %v", err)
	}
	// Re-use B's cert/key paths (already issued in m.dir/nodeB) via a fresh
	// PeerSet owned by identM (wrong Ed25519 key for B's NodeID).
	identM.NodeID = m.identB.NodeID
	engM := newTestEngine(t, identM.NodeID, t.TempDir())
	psM := NewPeerSet(m.psB.dialer, m.recvB, identM, engM)
	psM.disableDialPeerIDCheckBugInject.Store(true)
	if err := psM.Dial(m.ctx, m.addrA, "localhost", m.identA.NodeID); err != nil {
		t.Fatalf("impostor M.Dial(A): %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	forgedAnnounce := buildRootAnnounceFrame(m.identB.NodeID, m.engineB.MerkleRootFromShards())
	if err := psM.Publish(m.identA.NodeID, receive.LengthPrefixFrame(forgedAnnounce)); err != nil {
		t.Fatalf("impostor M.Publish: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.psA.digestSeamDrops.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := m.psA.digestSeamDrops.Load(); got < 1 {
		t.Fatalf("impostor digest frame on a declined connection was not dropped: digestSeamDrops=%d, want at least 1", got)
	}

	m.close()
	latencySyncResponders(t, m)
}

// TestOB31RequestDoesNotPolluteResponseChannel sends an unsolicited V2 request
// while B has a persistent response channel for A but is not sweeping.
// DeliverDigest must not enqueue that request as a response. B's next sweep must
// therefore report no drained exchange and must not inflate its adaptive digest
// wait EWMA.
func TestOB31RequestDoesNotPolluteResponseChannel(t *testing.T) {
	eng.SetIBLTSchemeV2(true)
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	m := buildDeferMesh(t, DeferOpts{
		stratified:   true,
		deferHandler: true,
		batchSize:    10,
		digestWait:   50 * time.Millisecond,
	})
	defer m.cancel()
	m.gA.SetIBLTV2(true)
	m.gB.SetIBLTV2(true)
	m.gA.SetDeferCrossover(true)
	m.gB.SetDeferCrossover(true)
	m.gA.SetDigestWaitAdaptive(true)
	m.gB.SetDigestWaitAdaptive(true)

	if os.Getenv("SOVEREIGN_TEST_FAULT_DIAL_GATING") == "req_pollute" {
		m.gB.disableDigestRecvRoleGateBugInject.Store(true)
	}

	// Step 1: B sweeps A once to create w.ch in m.gB.digestRecv[A].
	deferInsert(t, m.gB, "challenge-pollute-b-%04d", 0, 5)
	m.gB.AntiEntropySweep(m.ctx)

	// Step 2: While B is idle (not waiting in a sweep), A sends a digestRoleRequestV2 to B.
	seed := maphash.MakeSeed()
	ibltA := m.engineA.GenerateDigestSizedWithSeed(seed, eng.IBLTDigestDefaultBuckets)
	ibltBytes, err := eng.MarshalIBLT(ibltA)
	ibltA.Release()
	if err != nil {
		t.Fatalf("MarshalIBLT: %v", err)
	}
	reqFrame := buildDigestFrame(digestRoleRequestV2, m.identA.NodeID, seed, nil, ibltBytes)
	m.gB.DeliverDigest(m.identA.NodeID, reqFrame)

	// Step 3: Let the unsolicited request sit for 120 ms, then trigger B's next sweep of A.
	time.Sleep(120 * time.Millisecond)
	deferInsert(t, m.gB, "challenge-pollute-b2-%04d", 0, 5)
	m.gB.AntiEntropySweep(m.ctx)

	m.gB.digestRecvMu.Lock()
	var ewma time.Duration
	if w := m.gB.digestRecv[m.identA.NodeID]; w != nil {
		ewma = w.ewma
	}
	m.gB.digestRecvMu.Unlock()

	m.close()
	latencySyncResponders(t, m)

	if drained := m.gB.digestExchDrained.Load(); drained != 0 {
		t.Fatalf("unsolicited digestRoleRequestV2 entered the response channel: digestExchDrained=%d, want 0 (ewma=%v)",
			drained, ewma)
	}
	if ewma >= 80*time.Millisecond {
		t.Fatalf("unsolicited request inflated adaptive digestWait EWMA to %v, want below 80ms",
			ewma)
	}
}

// TestOB31RootAnnounceDoesNotIncrementArriveBroken enables exchange diagnostics
// and delivers a root announcement, whose build stamp is zero by design. That
// frame must not increment ArriveBrokenTotal. An unstamped V2 response, which
// requires a build stamp, must increment the same counter exactly once.
func TestOB31RootAnnounceDoesNotIncrementArriveBroken(t *testing.T) {
	l0iArmEnv(t)
	eng.SetIBLTSchemeV2(true)
	t.Cleanup(func() { eng.SetIBLTSchemeV2(false) })

	m := buildDeferMesh(t, DeferOpts{
		stratified:   true,
		deferHandler: true,
		batchSize:    1,
		digestWait:   100 * time.Millisecond,
	})
	defer m.cancel()
	m.gA.SetIBLTV2(true)
	m.gB.SetIBLTV2(true)

	if os.Getenv("SOVEREIGN_TEST_FAULT_DIAL_GATING") == "root_broken" {
		m.gB.disableRootAnnounceArrivalGateBugInject.Store(true)
	}

	// Deliver a 73-byte root-announce frame (which carries buildStamp == 0 by design).
	rootAnn := buildRootAnnounceFrame(m.identA.NodeID, m.engineA.MerkleRootFromShards())
	m.gB.DeliverDigest(m.identA.NodeID, rootAnn)

	if broken := m.gB.l0iArriveAgg.broken.Load(); broken != 0 {
		m.close()
		latencySyncResponders(t, m)
		t.Fatalf("digestRoleRootAnnounce incremented ArriveBrokenTotal=%d, want 0", broken)
	}

	// Verify a genuinely unstamped (buildStamp == 0) response frame still increments ArriveBrokenTotal.
	seed := maphash.MakeSeed()
	ibltA := m.engineA.GenerateDigestSizedWithSeed(seed, eng.IBLTDigestDefaultBuckets)
	ibltBytes, err := eng.MarshalIBLT(ibltA)
	ibltA.Release()
	if err != nil {
		t.Fatalf("MarshalIBLT: %v", err)
	}
	digestStampBugInject.Store(true)
	unstampedResp := buildDigestFrame(digestRoleResponseV2, m.identA.NodeID, seed, nil, ibltBytes)
	digestStampBugInject.Store(false)
	m.gB.DeliverDigest(m.identA.NodeID, unstampedResp)

	m.close()
	latencySyncResponders(t, m)

	if broken := m.gB.l0iArriveAgg.broken.Load(); broken != 1 {
		t.Fatalf("expected genuinely unstamped digestRoleResponseV2 to increment ArriveBrokenTotal=1, got %d", broken)
	}
}
