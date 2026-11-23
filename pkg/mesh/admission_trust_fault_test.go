// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These negative controls exercise the admission and challenge-budget fault
// injections from ADR-0069. Each arms a test-only fault and requires the
// corresponding defect to become observable; otherwise the control fails.
// SOVEREIGN_TEST_FAULT_ADMISSION_QUINTET selects a control. Ordinary test runs
// leave it unset and skip all three.

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/hr18vk/sovereign/pkg/crypto"
)

// TestNegativeControlBudgetControl disables both challenge-answer budget arms.
// The connected-arm flood must then receive all 100 answers.
func TestNegativeControlBudgetControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_ADMISSION_QUINTET") != "budget" {
		t.Skip("runs only with SOVEREIGN_TEST_FAULT_ADMISSION_QUINTET=budget")
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

	a := newEclipseNode(t, ca, caPath, root, "budget-control-node", 0xA9, false, false)
	a.ps.disableChallengeAnswerBudgetBugInject.Store(true) // Disable both budget checks.
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)

	chIdent, err := NewNodeIdentity(quintetSeed(t))
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	certPath, keyPath := quintetLeafPair(t, ca, root, identHex(chIdent.NodeID), "budget-control")
	conn := quintetChallengerDial(t, caPath, a.addr, certPath, keyPath)
	defer conn.Close()

	quintetSendChallenges(t, conn, chIdent.NodeID, 100)
	if answers := quintetCountResponses(t, conn); answers != 100 {
		t.Errorf("budget fault answered %d of 100 challenges, want 100; a budget check remained active", answers)
	}
}

// TestNegativeControlOrderControl compares one ordinary shipDelta round with a
// round whose sorting fault is armed. The sink records arrival dots before
// admission, including refused frames. Ordinary arrivals must be ascending; the
// faulted round must contain at least one descent. Skew-refusal totals vary with
// delta-walk order and the time-dependent admission bound, so they are logged
// rather than used as the fault observable.
func TestNegativeControlOrderControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_ADMISSION_QUINTET") != "order" {
		t.Skip("runs only with SOVEREIGN_TEST_FAULT_ADMISSION_QUINTET=order")
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

	dots1, skew1 := quintetOrderLeg(t, ca, caPath, root, "order-control-sorted", 0xAC, 0xAD, false)
	t.Logf("ordinary round: %d arrivals, %d skew refusals", len(dots1), skew1)
	if len(dots1) == 0 {
		t.Fatalf("ordinary round recorded no arrivals")
	}
	for i := 1; i < len(dots1); i++ {
		if dots1[i] < dots1[i-1] {
			t.Errorf("ordinary round arrived out of order at %d: %d -> %d", i, dots1[i-1], dots1[i])
			break
		}
	}

	dots2, skew2 := quintetOrderLeg(t, ca, caPath, root, "order-control-fault", 0xAE, 0xAF, true)
	descents := 0
	for i := 1; i < len(dots2); i++ {
		if dots2[i] < dots2[i-1] {
			descents++
		}
	}
	t.Logf("order-fault round: %d arrivals, %d descents, %d skew refusals", len(dots2), descents, skew2)
	if descents == 0 {
		t.Errorf("order-fault round arrived in ascending order across %d frames (skew=%d); the sorting fault did not take effect", len(dots2), skew2)
	}
}

// TestNegativeControlNilGuardControl bypasses the nil-PeerSet guard. DeliverDigest
// must panic when the fault is armed; recovering that panic proves the injection
// reaches the unguarded dereference.
func TestNegativeControlNilGuardControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_ADMISSION_QUINTET") != "nilguard" {
		t.Skip("runs only with SOVEREIGN_TEST_FAULT_ADMISSION_QUINTET=nilguard")
	}
	g := &Gossiper{}
	g.disableNilPeersGuardBugInject.Store(true) // Bypass the nil-peer guard.
	panicked := false
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				panicked = true
				t.Logf("nil-guard fault produced the expected panic: %v", rec)
			}
		}()
		g.DeliverDigest([16]byte{0x01}, make([]byte, 512))
	}()
	if !panicked {
		t.Errorf("nil-guard fault did not panic; the bypass did not reach the unguarded dereference")
	}
}

// quintetOrderLeg builds an A<->B pair, mints 3,000 keys on B while partitioned,
// reconnects them, and optionally disables B's ship-order sorting. After one
// sweep and sink drain, it returns A's arrival sequence and skew-refusal count.
func quintetOrderLeg(t *testing.T, ca *crypto.MeshCA, caPath, root, prefix string, regA, regB byte, armInject bool) ([]uint64, uint64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newEclipseNode(t, ca, caPath, root, prefix+"A", regA, false, false)
	b := newEclipseNode(t, ca, caPath, root, prefix+"B", regB, false, false)
	if err := a.dir.Register(b.ident.NodeID, b.ident.Pub); err != nil {
		t.Fatalf("register B in A: %v", err)
	}
	if err := b.dir.Register(a.ident.NodeID, a.ident.Pub); err != nil {
		t.Fatalf("register A in B: %v", err)
	}
	eclipseMint(b, prefix, 3000)
	eclipseWire(t, ctx, a, b)
	if armInject {
		b.g.disableShipOrderBugInject.Store(true) // Restore hash-order shipping.
	}
	var sweepWG sync.WaitGroup
	sweepWG.Add(2)
	go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
	go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
	sweepWG.Wait()
	eclipseDrain(t, a)
	_, skew, _, _ := eclipseDrain(t, a)
	return a.sink.arrivalSnapshot(), skew
}

// arrivalSnapshot copies the dot sequence recorded by EclipseSink.HandleFrame.
// The copy lets the test inspect ordering after the serve goroutines finish.
func (s *EclipseSink) arrivalSnapshot() []uint64 {
	s.arrivalMu.Lock()
	defer s.arrivalMu.Unlock()
	out := make([]uint64, len(s.arrivalDots))
	copy(out, s.arrivalDots)
	return out
}
