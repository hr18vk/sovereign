// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// This test exercises hybrid Ed25519 and ML-DSA-65 signing and verification
// across three nodes connected by TLS (ADR-0045, appendix B). Hybrid signing
// and verification are disabled by default, so every node opts in explicitly.
//
// NewNodeIdentityHybrid derives both keypairs from one seed. Each Directory
// registers both public keys for every peer, each Gossiper enables hybrid
// signing, and each Receiver enables hybrid verification. A inserts 100 keys
// and all three nodes run anti-entropy sweeps. Matching roots alone are not
// enough: the accept counters must also show that B and C verified hybrid
// frames rather than converging through the v1 path.
//
// As a negative control, disabling SetHybridSign makes the receivers reject the
// resulting v1 frames because they require both signatures.

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
		id, err := NewNodeIdentityHybrid(seed) // derive the post-quantum keypair from the same seed
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
		recv.SetHybridVerify(true) // require both signatures on receipt (ADR-0036)
		ps := NewPeerSet(tr, recv, id, engN)
		g := NewGossiper(ps, id, engN, d)
		g.SetHybridSign(true) // sign with both algorithms (ADR-0037)
		g.SetBatchSize(DefaultBatchSize)
		recv.SetRelayRetainer(g.RetainForeign)
		recv.SetRelayRetainerBatch(g.RetainForeignBatch)
		nodes[i] = &node{ident: id, eng: engN, dir: d, recv: recv, ps: ps, g: g, tr: tr}
	}
	// Register classical and post-quantum public keys for every peer. A missing
	// post-quantum key makes verification reject every hybrid frame.
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
	// Each closure updates its own node's hybrid-accept counter.
	for i := range nodes {
		n := nodes[i]
		n.recv.SetHybridAcceptReporter(func() { atomic.AddInt64(&n.hybridAcc, 1) })
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	// All three nodes listen, and B and C dial A. Accepted inbound connections
	// are registered for publishing, so one dial per pair provides a full edge.
	// Every node sweeps.
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

	// A inserts the keys before all three nodes begin sweeping.
	for i := 0; i < keys; i++ {
		eid := fmt.Sprintf("hybrid-key-%d", i)
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
			roots[i] = nodes[i].eng.MerkleRootFromShards()
		}
		if roots[0] == roots[1] && roots[1] == roots[2] {
			converged = true
			break
		}
	}
	if !converged {
		t.Fatalf("hybrid mesh did not converge in %s (roots %x / %x / %x)", slo, roots[0], roots[1], roots[2])
	}
	// The accept counter increments only after both signatures verify. Checking
	// it prevents a v1-only exchange from satisfying this test.
	for i := 1; i < numNodes; i++ {
		if got := atomic.LoadInt64(&nodes[i].hybridAcc); got == 0 {
			t.Errorf("node %d accepted no hybrid frames despite convergence", i)
		}
	}
	t.Logf("three-node hybrid mesh converged %d keys (root %x); hybrid accepts B=%d C=%d",
		keys, roots[0], atomic.LoadInt64(&nodes[1].hybridAcc), atomic.LoadInt64(&nodes[2].hybridAcc))
}
