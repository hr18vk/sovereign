// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These negative controls arm shipping-seam fault injections and verify that
// the intended defect is observable. Each runs only when
// SOVEREIGN_TEST_FAULT_SEAMS selects its fault; ordinary test runs skip them.

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/crypto"
)

// TestNegativeControlDeclinedPolicyControl disables the per-connection declined
// budget policy. With a live edge already installed, two more dials are declined
// and their challenges must consume the peer's lifetime per-key reservation.
// That reservation can eventually prevent the peer's handshake challenges from
// being answered. The control fails unless the injected policy change records
// the expected reservations.
func TestNegativeControlDeclinedPolicyControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_SEAMS") != "declpolicy" {
		t.Skip("this negative control runs only under SOVEREIGN_TEST_FAULT_SEAMS=declpolicy")
	}
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
	a := newEclipseNode(t, ca, caPath, root, "declined-policy-control", 0xB7, false, false)
	a.ps.disableDeclinedPolicyBugInject.Store(true)
	defer a.ps.disableDeclinedPolicyBugInject.Store(false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)

	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	leafPath, leafKey := quintetLeafPair(t, ca, root, identHex(chIdent.NodeID), "registered-nodeid")

	live := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer live.Close()
	quintetSendChallenges(t, live, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, live, 10*time.Second); m != 1 {
		t.Fatalf("control premise: the live-edge settle got %d answers, want 1 (the registered conn's challenge must be answered)", m)
	}

	margin := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer margin.Close()
	quintetSendChallenges(t, margin, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, margin, 10*time.Second); m != 1 {
		t.Fatalf("control premise: the margin got %d answers, want 1 (the stateless arm must serve the both-ways-dial handshake)", m)
	}

	const floodN = 5
	flood := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer flood.Close()
	quintetSendChallenges(t, flood, chIdent.NodeID, floodN)
	floodAnswers := quintetCountResponses(t, flood)

	nodeKey := suspectKeyForNodeID(chIdent.NodeID)
	a.ps.challengeDeclinedMu.Lock()
	perKey := a.ps.challengeDeclinedByKey[nodeKey].count
	global := a.ps.challengeDeclinedGlobal
	a.ps.challengeDeclinedMu.Unlock()
	drops := a.ps.challengeAnswerBudgetDrops.Load()
	if perKey != floodN+1 {
		t.Fatalf("declined-policy fault recorded %d per-key reservations, want %d (one margin plus %d flood challenges)", perKey, floodN+1, floodN)
	}
	if floodAnswers != floodN {
		t.Errorf("declined-policy fault answered %d flood challenges, want %d; this flood stays below the per-key cap", floodAnswers, floodN)
	}
	if drops != 0 {
		t.Errorf("declined-policy fault recorded %d drops at floodN=%d, want 0 below the per-key cap of 64", drops, floodN)
	}
	if global != floodN+1 {
		t.Errorf("global reservation count is %d, want %d", global, floodN+1)
	}
	t.Logf("declined-policy fault recorded perKey=%d, global=%d, drops=%d", perKey, global, drops)
}

// TestNegativeControlSweepRetainControl disables retention of live-edge budget
// records. The driven sweep then erases each reservation window before the
// global ceiling can bind. Nine challenges must all be answered with zero drops
// while the ceiling is eight; fewer answers mean the fault did not take effect.
func TestNegativeControlSweepRetainControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_SEAMS") != "sweepretain" {
		t.Skip("this negative control runs only under SOVEREIGN_TEST_FAULT_SEAMS=sweepretain")
	}
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
	a := newEclipseNode(t, ca, caPath, root, "sweep-retain-control", 0xB9, false, false)
	a.ps.disableLiveEdgeRecordBugInject.Store(true)
	defer a.ps.disableLiveEdgeRecordBugInject.Store(false)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)
	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	leafPath, leafKey := quintetLeafPair(t, ca, root, identHex(chIdent.NodeID), "registered-nodeid")
	savedCeil := challengeAnswerGlobalCeiling
	savedSweep := challengeDeclinedSweepInterval
	challengeAnswerGlobalCeiling = 8
	challengeDeclinedSweepInterval = time.Millisecond
	defer func() {
		challengeAnswerGlobalCeiling = savedCeil
		challengeDeclinedSweepInterval = savedSweep
	}()
	live := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer live.Close()
	quintetSendChallenges(t, live, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, live, 10*time.Second); m != 1 {
		t.Fatalf("control premise: the live-edge settle got %d answers, want 1", m)
	}
	margin := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer margin.Close()
	quintetSendChallenges(t, margin, chIdent.NodeID, 1)
	if m := quintetCountResponsesBounded(t, margin, 10*time.Second); m != 1 {
		t.Fatalf("control premise: the margin got %d answers, want 1", m)
	}
	flood := quintetChallengerDial(t, caPath, a.addr, leafPath, leafKey)
	defer flood.Close()
	quintetSendChallenges(t, flood, chIdent.NodeID, 9)
	floodAnswers := quintetCountResponses(t, flood)
	if floodAnswers != 9 {
		t.Fatalf("sweep-retain fault answered %d of 9 challenges, want 9; erasing each reservation window should bypass the ceiling of 8", floodAnswers)
	}
	if got := a.ps.challengeAnswerBudgetDrops.Load(); got != 0 {
		t.Errorf("sweep-retain fault recorded %d drops, want 0", got)
	}
	t.Logf("sweep-retain fault answered all 9 challenges with ceiling=8 and zero drops")
}
