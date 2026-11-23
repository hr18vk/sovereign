// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover challenge-answer reservations on declined connections
// (ADR-0070). A duplicate connection from a peer with a live edge is declined
// by RegisterInbound but is still served statelessly. Re-verification on that
// connection must not exhaust the peer's per-key answer allowance.
//
// Reservations for connections without a verified node identity expire after
// challengeDeclinedReservationTTL, allowing later challenges to start a fresh
// allowance. Direct calls to the refund helper cover absent, live, and
// disconnected records without decrementing a counter twice.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/crypto"
)

// TestN2DeclinedPolicy checks challenge answers after a peer re-dials an
// existing live edge. One challenge over the registered connection establishes
// the connected path. Challenges over two declined connections must all receive
// answers: one on the first connection and 70 on the second.
//
// The per-key record accounts for all 71 declined-connection answers, but its
// ordinary limit of 64 must not reject a peer whose live edge is already
// verified. The global counter also records all 71 answers, and the drop counter
// remains zero.
func TestN2DeclinedPolicy(t *testing.T) {
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
	a := newEclipseNode(t, ca, caPath, root, "declined-policy", 0xB6, false, false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)

	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	leafPath, leafKey := quintetLeafPair(t, ca, root, identHex(chIdent.NodeID), "registered-nodeid")

	// The first dial registers the live edge. Its challenge uses the connected
	// path and does not consume a declined-connection reservation.
	live := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer live.Close()
	quintetSendChallenges(t, live, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, live, 10*time.Second); m != 1 {
		t.Fatalf("registered connection received %d challenge answers, want 1", m)
	}

	// A second dial with the same node ID is declined because the live edge
	// exists. Its single challenge must still receive an answer so an ordinary
	// both-ways dial is not starved by the reservation budget.
	margin := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer margin.Close()
	quintetSendChallenges(t, margin, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, margin, 10*time.Second); m != 1 {
		t.Errorf("declined connection received %d answers to one challenge, want 1", m)
	}

	// Seventy challenges arrive on another declined connection. The registered
	// edge already proves this peer's identity, so re-verification on declined
	// connections must not consume its ordinary per-key answer allowance.
	flood := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer flood.Close()
	quintetSendChallenges(t, flood, chIdent.NodeID, 70)
	floodAnswers := quintetCountResponses(t, flood)
	if floodAnswers != 70 {
		t.Errorf("live-edge peer received %d answers to 70 declined-connection challenges, want 70", floodAnswers)
	}

	// Read the exact server-side accounting under its mutex. All 71 stateless
	// answers are recorded per key and globally, and none is dropped. The live
	// edge exempts these challenges from the ordinary per-key limit, not from
	// accounting.
	nodeKey := suspectKeyForNodeID(chIdent.NodeID)
	a.ps.challengeDeclinedMu.Lock()
	perKey := a.ps.challengeDeclinedByKey[nodeKey].count
	global := a.ps.challengeDeclinedGlobal
	a.ps.challengeDeclinedMu.Unlock()
	drops := a.ps.challengeAnswerBudgetDrops.Load()
	if perKey != 71 {
		t.Errorf("declined-connection per-key count is %d, want 71 answers recorded without applying the ordinary limit", perKey)
	}
	if global != 71 {
		t.Errorf("declined-connection global count is %d, want all 71 stateless answers", global)
	}
	if drops != 0 {
		t.Errorf("challenge-answer drops=%d, want 0 for a peer with a verified live edge", drops)
	}
}

// TestN2TTLRecoveryUnderflowGuard first exercises a connection whose node ID
// cannot be decoded. Its address-keyed allowance permits 64 of 65 challenges.
// After the test shortens the reservation TTL and lets the record expire, the
// next challenge must receive an answer and create a fresh count of one.
//
// The second part calls refundDeclinedReservation directly because a socket
// cannot reliably interleave expiry between reservation and signing. Refunding
// an absent record changes nothing, refunding a live record decrements both
// counters once, and refunding a disconnected record changes neither counter.
func TestN2TTLRecoveryUnderflowGuard(t *testing.T) {
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
	a := newEclipseNode(t, ca, caPath, root, "reservation-ttl", 0xC6, false, false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)
	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	declCert, declKey := quintetLeafPair(t, ca, root, "seams-ttl-not-a-nodeid", "declined")
	c1 := quintetChallengerDial(t, caPath, a.addr, declCert, declKey)
	defer c1.Close()
	quintetSendChallenges(t, c1, chIdent.NodeID, 65)
	if answers := quintetCountResponses(t, c1); answers != 64 {
		t.Errorf("address-keyed connection received %d answers to 65 challenges, want 64 at the per-key limit", answers)
	}
	// The server keys this record by the client's address, which is the client's
	// local address on the other end of the socket.
	addrKey := c1.LocalAddr().String()
	a.ps.challengeDeclinedMu.Lock()
	before := a.ps.challengeDeclinedByKey[addrKey].count
	a.ps.challengeDeclinedMu.Unlock()
	if before != 64 {
		t.Fatalf("address-keyed reservation count=%d, want 64", before)
	}
	// Shorten the TTL for the test and restore it afterward. Sleeping 3 ms puts
	// the record beyond its 1 ms lifetime.
	origTTL := challengeDeclinedReservationTTL
	challengeDeclinedReservationTTL = time.Millisecond
	defer func() { challengeDeclinedReservationTTL = origTTL }()
	time.Sleep(3 * time.Millisecond)
	quintetSendChallenges(t, c1, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, c1, 10*time.Second); m != 1 {
		t.Errorf("challenge after reservation expiry received %d answers, want 1 from a fresh allowance", m)
	}
	a.ps.challengeDeclinedMu.Lock()
	after := a.ps.challengeDeclinedByKey[addrKey].count
	a.ps.challengeDeclinedMu.Unlock()
	if after != 1 {
		t.Errorf("address-keyed count after expiry=%d, want 1 for the new reservation", after)
	}

	// Drive the refund helper directly because socket timing cannot reliably
	// place lazy reclamation between reservation and signing. An absent record
	// changes nothing, a live record decrements both counters once, and a
	// disconnected record changes neither counter. In particular, a refund after
	// reclamation must not decrement the global counter twice and underflow it.
	guardKey := "reservation-refund-key"
	a.ps.challengeDeclinedMu.Lock()
	gBase := a.ps.challengeDeclinedGlobal
	delete(a.ps.challengeDeclinedByKey, guardKey) // a clean slate for the shape
	a.ps.challengeDeclinedMu.Unlock()
	a.ps.refundDeclinedReservation(guardKey, true)
	a.ps.challengeDeclinedMu.Lock()
	res, ok := a.ps.challengeDeclinedByKey[guardKey]
	gAbsent := a.ps.challengeDeclinedGlobal
	a.ps.challengeDeclinedMu.Unlock()
	if ok || res.count != 0 || gAbsent != gBase {
		t.Errorf("absent-record refund changed state: present=%v count=%d global before=%d after=%d, want unchanged", ok, res.count, gBase, gAbsent)
	}
	a.ps.challengeDeclinedMu.Lock()
	a.ps.challengeDeclinedByKey[guardKey] = declinedRes{count: 2, lastUnixNano: time.Now().UnixNano()}
	a.ps.challengeDeclinedGlobal += 2
	a.ps.challengeDeclinedMu.Unlock()
	a.ps.refundDeclinedReservation(guardKey, true)
	a.ps.challengeDeclinedMu.Lock()
	res = a.ps.challengeDeclinedByKey[guardKey]
	gLive := a.ps.challengeDeclinedGlobal
	a.ps.challengeDeclinedMu.Unlock()
	if res.count != 1 || gLive != gBase+1 {
		t.Errorf("live-record refund left count=%d global=%d, want 1 and %d after one decrement", res.count, gLive, gBase+1)
	}
	a.ps.refundDeclinedReservation(guardKey, false)
	a.ps.challengeDeclinedMu.Lock()
	gEdge := a.ps.challengeDeclinedGlobal
	res = a.ps.challengeDeclinedByKey[guardKey]
	a.ps.challengeDeclinedMu.Unlock()
	if gEdge != gBase+1 || res.count != 1 {
		t.Errorf("disconnected-record refund changed state: global=%d want %d, per-key=%d want 1", gEdge, gBase+1, res.count)
	}
}
