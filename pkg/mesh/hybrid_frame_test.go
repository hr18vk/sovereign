// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// hybrid_frame_test.go — the hybrid end-to-end guard (ADR-0045): the
// (Ed25519 + ML-DSA-65) sign/verify path had NEVER executed end-to-end — both
// flags default false and no launcher passes them. A 2-node in-process harness
// proves the seam; this guard is the 3-NODE real-TCP convergence required before
// hybrid mode may be described as working.
//
// Shape: the asymmetric_dial_test.go real-TCP stack (TLS transport, the
// accept-loop fix registration, batch relay), but every node's identity is the HYBRID
// constructor (NewNodeIdentityHybrid — PQ key minted from the same seed), every
// Directory registers BOTH the classical and PQ pubkeys, every gossiper runs
// SetHybridSign(true), every receiver runs SetHybridVerify(true). A injects 100
// keys; all three sweep; convergence + the hybrid-accept counters are the gate.
//
// RED (config-inject): drop the SetHybridSign(true) arm → the senders
// emit v1 frames → the receivers' BOTH-sigs gate REJECTS them → B/C stay
// root-zero → the convergence assertion fires (roots …/00…/00…). The RED is
// stronger than a counter miss: it proves the verify gate genuinely REQUIRES
// the hybrid frame, i.e. the GREEN run's convergence came THROUGH the hybrid
// path, not around it.

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

func TestB7_ThreeNodeHybridConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP 3-node hybrid convergence test (binds loopback ports)")
	}
	const numNodes = 3
	const keys = 100

	dir := t.TempDir()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("CA WriteCAPEM: %v", err)
	}

	type node struct {
		ident     *NodeIdentity
		eng       *eng.DeltaCRDTEngine
		dir       *identity.Directory
		recv      *receive.Receiver
		ps        *PeerSet
		tr        *transport.TLSConnections
		g         *Gossiper
		ln        net.Listener
		addr      string
		hybridAcc int64
	}
	nodes := make([]*node, numNodes)
	for i := 0; i < numNodes; i++ {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand seed %d: %v", i, err)
		}
		id, err := NewNodeIdentityHybrid(seed) // the hybrid arm: PQ keypair onboard
		if err != nil {
			t.Fatalf("NewNodeIdentityHybrid %d: %v", i, err)
		}
		leaf, err := ca.IssueLeaf(identHex(id.NodeID))
		if err != nil {
			t.Fatalf("IssueLeaf %d: %v", i, err)
		}
		cp, kp, err := leaf.WritePEM(filepath.Join(dir, fmt.Sprintf("node%d", i)))
		if err != nil {
			t.Fatalf("WritePEM %d: %v", i, err)
		}
		tr, err := transport.NewTLSTransport(cp, kp, caPath)
		if err != nil {
			t.Fatalf("NewTLSTransport %d: %v", i, err)
		}
		arenaDir := filepath.Join(dir, fmt.Sprintf("eng%d", i))
		engN := newTestEngine(t, id.NodeID, arenaDir)
		d := identity.NewDirectory()
		recv := receive.NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engN), clock.NewSystemClock(), d, engN, 50_000_000)
		recv.SetHybridVerify(true) // the receive-side BOTH-sigs gate (ADR-0036)
		ps := NewPeerSet(tr, recv, id, engN)
		g := NewGossiper(ps, id, engN, d)
		g.SetHybridSign(true) // the send-side hybrid arm (ADR-0037)
		g.SetBatchSize(DefaultBatchSize)
		recv.SetRelayRetainer(g.RetainForeign)
		recv.SetRelayRetainerBatch(g.RetainForeignBatch)
		nodes[i] = &node{ident: id, eng: engN, dir: d, recv: recv, ps: ps, g: g, tr: tr}
	}
	// Cross-register classical + PQ pubkeys (a missing PQ pubkey would
	// DropVerify every hybrid frame — the verify side of the guard).
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}
			if err := nodes[i].dir.Register(nodes[j].ident.NodeID, nodes[j].ident.Pub); err != nil {
				t.Fatalf("register %d in %d: %v", j, i, err)
			}
			if err := nodes[i].dir.RegisterPQ(nodes[j].ident.NodeID, nodes[j].ident.PQPub); err != nil {
				t.Fatalf("registerPQ %d in %d: %v", j, i, err)
			}
		}
	}
	// Wire the hybrid-accept counters (closures capture the per-node counters).
	for i := range nodes {
		n := nodes[i]
		n.recv.SetHybridAcceptReporter(func() { atomic.AddInt64(&n.hybridAcc, 1) })
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	// All three listen; B and C dial A (the symmetric star — the accept fix makes A's
	// accept-registered inbound edges publishable, so one dial per pair is a
	// full edge). Sweep on all three.
	for i := 0; i < numNodes; i++ {
		ln, err := nodes[i].tr.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %d: %v", i, err)
		}
		nodes[i].ln = ln
		nodes[i].addr = ln.Addr().String()
		wg.Add(1)
		go runAcceptLoopWithPeerSet(ctx, ln, nodes[i].recv, nil, &wg, nodes[i].ps)
	}
	defer wg.Wait()
	defer func() {
		for _, n := range nodes {
			if n.ln != nil {
				n.ln.Close()
			}
		}
	}()
	for j := 1; j < numNodes; j++ {
		if err := nodes[j].ps.Dial(ctx, nodes[0].addr, "localhost", nodes[0].ident.NodeID); err != nil {
			t.Fatalf("dial %d->A: %v", j, err)
		}
		asyncWait(t, nodes[j].ps, nodes[0].ident.NodeID)
	}

	// A injects the keys (the seed); all three sweep.
	for i := 0; i < keys; i++ {
		eid := fmt.Sprintf("b7-key-%d", i)
		payload := fmt.Sprintf("value-%d", i)
		nodes[0].g.InsertLocalEvents(eid, payload, eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		})
	}
	for i := range nodes {
		go nodes[i].g.SweepLoop(ctx, 20*time.Millisecond)
	}

	const slo = 10 * time.Second
	deadline := time.Now().Add(slo)
	converged := false
	var roots [3][32]byte
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		for i := range nodes {
			roots[i] = nodes[i].eng.State().MerkleRoot()
		}
		if roots[0] == roots[1] && roots[1] == roots[2] {
			converged = true
			break
		}
	}
	if !converged {
		t.Fatalf("B7: hybrid mesh did NOT converge in %s (roots %x / %x / %x) — the hybrid sign/verify path broke convergence", slo, roots[0], roots[1], roots[2])
	}
	// THE EXECUTION PROOF (not just convergence): hybrid frames were ACCEPTED on
	// B and C (the counter fires only from the BOTH-sigs-verified seam). Without
	// this the guard would pass on the v1 path and prove nothing about hybrid.
	for i := 1; i < numNodes; i++ {
		if got := atomic.LoadInt64(&nodes[i].hybridAcc); got == 0 {
			t.Errorf("node %d accepted ZERO hybrid frames — the mesh converged but the hybrid path never EXECUTED (the wired-but-never-exercised defect class)", i)
		}
	}
	t.Logf("B7 GREEN: 3-node hybrid mesh converged %d keys (root %x); hybrid accepts B=%d C=%d",
		keys, roots[0], atomic.LoadInt64(&nodes[1].hybridAcc), atomic.LoadInt64(&nodes[2].hybridAcc))
}
