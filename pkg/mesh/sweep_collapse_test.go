// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// sweep_collapse_test.go — the sweep-collapse regression test (ADR-0070,
// finding A-F1): the sweep-at-ceiling re-derives challengeDeclinedGlobal from
// the map's sum while a live-edge reservation spends the global map-lessly
// (the B-3 shape), so an adversarial live-edge flood (fresh marks via E1
// re-dials) has its spent answers erased every sweep: the window restarts
// per second and the flood sustains ~65,536 signs/s, not the expected ~109.
// The test asserts the fixed behavior — the spends survive the sweep — so
// its own FAIL lines at the current tip are the regression's negative
// control (the review artifacts in the shipping-seams work directory).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/crypto"
)

func TestSweepRetainsLiveEdgeSpends(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	root := t.TempDir()
	caPath, err := ca.WriteCAPEM(root)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newEclipseNode(t, ca, caPath, root, "f43sweep", 0xB8, false, false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)
	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	leafPath, leafKey := quintetLeafPair(t, ca, root, identHex(chIdent.NodeID), "e1-real-nodeid")

	// Stage the drivable window (the test needs the ceiling knob at
	// wire-reachable scale; the default
	// 65536 is untouched and other composition tests read the same value).
	savedCeil := challengeAnswerGlobalCeiling
	savedSweep := challengeDeclinedSweepInterval
	savedTTL := challengeDeclinedReservationTTL
	challengeAnswerGlobalCeiling = 8
	challengeDeclinedSweepInterval = time.Millisecond
	defer func() {
		challengeAnswerGlobalCeiling = savedCeil
		challengeDeclinedSweepInterval = savedSweep
		challengeDeclinedReservationTTL = savedTTL
	}()

	live := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer live.Close()
	quintetSendChallenges(t, live, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, live, 10*time.Second); m != 1 {
		t.Fatalf("(A-F1) premise: the live-edge settle got %d answers, want 1 (the connected arm)", m)
	}
	margin := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer margin.Close()
	quintetSendChallenges(t, margin, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, margin, 10*time.Second); m != 1 {
		t.Fatalf("(A-F1) premise: the margin got %d answers, want 1 (the stateless arm serves the both-ways-dial handshake)", m)
	}

	// The collapse drive: 9 challenges over a third declined conn — 7
	// reserve, the 8th hits the ceiling (drop + the sweep fires), and the
	// 9th must still drop (the spends survived).
	flood := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer flood.Close()
	quintetSendChallenges(t, flood, chIdent.NodeID, 9)
	floodAnswers := quintetCountResponses(t, flood)
	drops := a.ps.challengeAnswerBudgetDrops.Load()
	if floodAnswers > 7 {
		t.Errorf("(A-F1) the collapse: the ceiling-8 window served %d of the 9 flood challenges, want at most 7 — the sweep-at-ceiling re-derived the global from the map's sum while the live-edge reservations spent it map-lessly, so the erase restarts the window every sweep and the adversarial live-edge flood sustains ~65,536 signs/s instead of the expected ~109 (the regression's negative control; peer.go's sweep vs the B-3 map-less reserve)", floodAnswers)
	}
	if drops < 2 {
		t.Errorf("(A-F1) the spends must survive: drops=%d, want at least 2 — the 9th challenge must still drop (the ceiling window holds until the records expire by TTL); one drop means the sweep erased the in-window spends", drops)
	}

	// The window-restart leg (both trees): with the TTL driven to 1 ms the
	// records expire and a fresh window serves the both-ways-dial
	// handshake again — the recovery the TTL exists for.
	challengeDeclinedReservationTTL = time.Millisecond
	time.Sleep(3 * time.Millisecond)
	heal := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer heal.Close()
	quintetSendChallenges(t, heal, chIdent.NodeID, 2)
	if m := quintetCountResponsesBounded(t, heal, 10*time.Second); m != 2 {
		t.Errorf("(A-F1) the window restart: after the TTL expiry the fresh window must serve the both-ways-dial handshake, got %d of 2", m)
	}
}
