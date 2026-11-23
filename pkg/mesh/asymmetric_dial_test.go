// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Real-TCP tests for connection symmetry and foreign-delta relay (ADR-0045).
//
// chaos.VirtualNet models mailboxes and bypasses PeerSet.Dial and the accept
// loop, so these tests use transport.NewTLSTransport, real listeners, and the
// production sweep path. A deterministic staggered boot reproduces the
// asymmetric edges seen when the seed's boot dial raced the other listeners in
// the 100-node run.
//
// PeerSet.Publish consults ps.peers. An outbound Dial registers its peer, and
// the accept loop registers an inbound peer under the node ID in its TLS leaf
// CN. Thus a B-to-A connection is publishable in both directions. Without the
// accept-side registration, A could serve B's frames but could not publish its
// own deltas to B.
//
// The relay-chain test separately requires B to retain A's signed envelopes and
// forward them to C, which has no direct connection to A. A relay-disabled
// control on the same topology must not converge.

import (
	"context"
	"crypto/rand"
	"fmt"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"net"
	"os"
	"path/filepath"
	"sync"
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

// peerLiveForTest reports whether peerID is registered as live in ps.peers (the
// map Publish consults). It reads ps.mu directly (the precedent asyncWait sets).
func (ps *PeerSet) peerLiveForTest(peerID [16]byte) bool {
	ps.mu.RLock()
	_, ok := ps.peers[peerID]
	ps.mu.RUnlock()
	return ok
}

// TestAsymDialAcceptDoesNotRegister checks the smallest asymmetric edge: after
// B dials A and A accepts the connection, A must register B in ps.peers. Two
// nodes, no sweep, and a direct map assertion isolate accept-side registration
// from relay behavior. TestAsymStaggeredConverges covers their integration.
func TestAsymDialAcceptDoesNotRegister(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP asymmetric dial test (binds loopback ports)")
	}
	dir := t.TempDir()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("CA WriteCAPEM: %v", err)
	}
	seedA := make([]byte, ed25519.SeedSize)
	seedB := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seedA); err != nil {
		t.Fatalf("rand seedA: %v", err)
	}
	if _, err := rand.Read(seedB); err != nil {
		t.Fatalf("rand seedB: %v", err)
	}
	identA, err := NewNodeIdentity(seedA)
	if err != nil {
		t.Fatalf("NewNodeIdentity A: %v", err)
	}
	identB, err := NewNodeIdentity(seedB)
	if err != nil {
		t.Fatalf("NewNodeIdentity B: %v", err)
	}
	leafA, err := ca.IssueLeaf(identHex(identA.NodeID))
	if err != nil {
		t.Fatalf("IssueLeaf A: %v", err)
	}
	certPathA, keyPathA, err := leafA.WritePEM(filepath.Join(dir, "nodeA"))
	if err != nil {
		t.Fatalf("WritePEM A: %v", err)
	}
	leafB, err := ca.IssueLeaf(identHex(identB.NodeID))
	if err != nil {
		t.Fatalf("IssueLeaf B: %v", err)
	}
	certPathB, keyPathB, err := leafB.WritePEM(filepath.Join(dir, "nodeB"))
	if err != nil {
		t.Fatalf("WritePEM B: %v", err)
	}

	trA, err := transport.NewTLSTransport(certPathA, keyPathA, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport A: %v", err)
	}
	trB, err := transport.NewTLSTransport(certPathB, keyPathB, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport B: %v", err)
	}
	lnA, err := trA.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer lnA.Close()
	addrA := lnA.Addr().String()

	// Engines + Directories + Receivers + PeerSets (the production gate stack).
	arenaDirA := filepath.Join(dir, "engA")
	arenaDirB := filepath.Join(dir, "engB")
	if err := os.MkdirAll(arenaDirA, 0o755); err != nil {
		t.Fatalf("mkdir engA: %v", err)
	}
	if err := os.MkdirAll(arenaDirB, 0o755); err != nil {
		t.Fatalf("mkdir engB: %v", err)
	}
	engineA := newTestEngine(t, identA.NodeID, arenaDirA)
	engineB := newTestEngine(t, identB.NodeID, arenaDirB)
	dirA := identity.NewDirectory()
	dirB := identity.NewDirectory()
	if err := dirA.Register(identB.NodeID, identB.Pub); err != nil {
		t.Fatalf("Register B in A: %v", err)
	}
	if err := dirB.Register(identA.NodeID, identA.Pub); err != nil {
		t.Fatalf("Register A in B: %v", err)
	}
	recvA := receive.NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engineA), clock.NewSystemClock(), dirA, engineA, 50_000_000)
	recvB := receive.NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engineB), clock.NewSystemClock(), dirB, engineB, 50_000_000)
	psA := NewPeerSet(trA, recvA, identA, engineA)
	psB := NewPeerSet(trB, recvB, identB, engineB)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, lnA, recvA, nil, &wg, psA) // A listens and registers inbound peers; B does not listen.
	// Teardown: close the listener FIRST (unblocks runAcceptLoop's ln.Accept →
	// the loop returns → wg.Done), then cancel the ctx (unblocks serveTestConn
	// readers), then wg.Wait. LIFO defer order = wait, cancel, close-listener.
	defer wg.Wait()
	defer cancel()
	defer lnA.Close()

	// B dials A. B's outbound path registers A; A's accept path must register B
	// under the node ID from B's TLS leaf CN.
	if err := psB.Dial(ctx, addrA, "localhost", identA.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	asyncWait(t, psB, identA.NodeID) // B registered A through its outbound path.
	// Allow A's accept loop to serve the connection and register B.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if psA.peerLiveForTest(identB.NodeID) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !psA.peerLiveForTest(identB.NodeID) {
		t.Fatalf("A accepted B's connection but did not register B in A.ps.peers; the B->A edge is not publishable from A")
	}
	t.Logf("A registered B from the accept side; the B->A edge is publishable in both directions")
}

// TestAsymStaggeredConverges starts A first, lets its boot dials to B and C
// fail, then starts B and C and has them dial A. A injects 100 keys; all three
// Merkle roots must converge. Accept-side registration lets A publish directly
// to B and C, while the wired relay retainers cover the forwarding path.
func TestAsymStaggeredConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP staggered-boot convergence test (binds loopback ports)")
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
		ident *NodeIdentity
		eng   *eng.DeltaCRDTEngine
		dir   *identity.Directory
		recv  *receive.Receiver
		ps    *PeerSet
		g     *Gossiper
		tr    *transport.TLSConnections
		ln    net.Listener
		addr  string
	}
	nodes := make([]*node, numNodes)
	for i := 0; i < numNodes; i++ {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand seed %d: %v", i, err)
		}
		id, err := NewNodeIdentity(seed)
		if err != nil {
			t.Fatalf("NewNodeIdentity %d: %v", i, err)
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
		if err := os.MkdirAll(arenaDir, 0o755); err != nil {
			t.Fatalf("mkdir eng%d: %v", i, err)
		}
		engN := newTestEngine(t, id.NodeID, arenaDir)
		d := identity.NewDirectory()
		recv := receive.NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engN), clock.NewSystemClock(), d, engN, 50_000_000)
		ps := NewPeerSet(tr, recv, id, engN)
		g := NewGossiper(ps, id, engN, d)
		// Retain accepted foreign frames for shipDelta to re-publish. This is the
		// production wiring used by cmd/sovereign-node.
		recv.SetRelayRetainer(g.RetainForeign)
		// DefaultBatchSize routes self-originated deltas through shipBatchedDelta
		// and inbound batches through HandleBatchFrame. A ships one batch of 100;
		// B and C retain the envelope with RetainForeignBatch, and
		// shipBatchedDelta can re-publish it with per-sweep deduplication. Keep
		// both retainers wired because per-frame and batch relay use different
		// cache layers.
		g.SetBatchSize(DefaultBatchSize)
		recv.SetRelayRetainerBatch(g.RetainForeignBatch)
		nodes[i] = &node{ident: id, eng: engN, dir: d, recv: recv, ps: ps, g: g, tr: tr}
	}
	// Cross-register public keys so signature verification does not obscure the
	// connection and relay behavior under test.
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}
			if err := nodes[i].dir.Register(nodes[j].ident.NodeID, nodes[j].ident.Pub); err != nil {
				t.Fatalf("Register %d in %d: %v", j, i, err)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	// A listens before B and C, so A's boot dials are refused.
	lnA, err := nodes[0].tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	nodes[0].ln = lnA
	nodes[0].addr = lnA.Addr().String()
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, lnA, nodes[0].recv, nil, &wg, nodes[0].ps)

	// ReconnectLoop mirrors production retry behavior. The refused dial uses a
	// placeholder port; the test isolates accept-side registration rather than
	// the absence of retries.
	for j := 1; j < numNodes; j++ {
		placeholder := bumpPort(nodes[0].addr, 1)
		dialErr := nodes[0].ps.Dial(ctx, placeholder, "localhost", nodes[j].ident.NodeID)
		if dialErr == nil {
			t.Fatalf("A's boot dial to B/C succeeded at placeholder port %s; want connection refused", placeholder)
		}
		go nodes[0].ps.ReconnectLoop(ctx, placeholder, "localhost", nodes[j].ident.NodeID, 50*time.Millisecond, 2*time.Second)
	}

	// Only A injects events.
	for i := 0; i < keys; i++ {
		eid := fmt.Sprintf("asym-key-%d", i)
		payload := fmt.Sprintf("value-%d", i)
		entry := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		}
		nodes[0].g.InsertLocalEvents(eid, payload, entry)
	}

	// Start A's sweep, then start B and C and have them dial A.
	go nodes[0].g.SweepLoop(ctx, 20*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // let A sweep a few rounds against empty ps.peers
	for j := 1; j < numNodes; j++ {
		lnJ, err := nodes[j].tr.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %d: %v", j, err)
		}
		nodes[j].ln = lnJ
		nodes[j].addr = lnJ.Addr().String()
		wg.Add(1)
		go runAcceptLoopWithPeerSet(ctx, lnJ, nodes[j].recv, nil, &wg, nodes[j].ps)
		if err := nodes[j].ps.Dial(ctx, nodes[0].addr, "localhost", nodes[0].ident.NodeID); err != nil {
			t.Fatalf("dial %d->A: %v", j, err)
		}
		asyncWait(t, nodes[j].ps, nodes[0].ident.NodeID)
		go nodes[j].g.SweepLoop(ctx, 20*time.Millisecond)
	}
	// Deferred calls run in reverse order: close listeners to unblock Accept,
	// cancel the context to stop readers and sweeps, then wait for the loops.
	defer wg.Wait()
	defer cancel()
	defer func() {
		for _, n := range nodes {
			if n.ln != nil {
				n.ln.Close()
			}
		}
	}()

	const slo = 10 * time.Second
	deadline := time.Now().Add(slo)
	converged := false
	var ra, rb, rc [32]byte
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		ra = nodes[0].eng.MerkleRootFromShards()
		rb = nodes[1].eng.MerkleRootFromShards()
		rc = nodes[2].eng.MerkleRootFromShards()
		if ra == rb && rb == rc {
			converged = true
			break
		}
	}
	if !converged {
		t.Fatalf("A injected %d keys but roots did not converge within %s after B and C dialed A (rootA=%x rootB=%x rootC=%x); check accept-side peer registration and relay retention", keys, slo, ra, rb, rc)
	}
	t.Logf("all three roots converged to %x within %s", ra, slo)
}

// bumpPort returns addr with its port incremented by n (a guaranteed-closed
// placeholder for the staggered-boot refused dial).
func bumpPort(addr string, n int) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", p+n))
}

// TestRelayChainLoadBearing isolates foreign-envelope relay on an A-to-B-to-C
// chain with no direct A-to-C edge. TestAsymStaggeredConverges cannot isolate
// relay because A can publish directly to both other nodes.
//
// B dials A and C dials B, making both directions publishable on those edges.
// Only A injects, so C can receive A's deltas only if B retains and re-publishes
// their signed envelopes. The enabled case must converge. The disabled control
// leaves both retainers nil: B may join A's deltas, but its relay lookup misses
// and C must remain unconverged. Running both cases on one topology shows that
// convergence depends on retention rather than another path.
func TestRelayChainLoadBearing(t *testing.T) {
	for _, relay := range []bool{false /* negative control */, true /* relay enabled */} {
		relay := relay
		name := "RelayDisabled"
		if relay {
			name = "RelayEnabled"
		}
		t.Run(name, func(t *testing.T) {
			runRelayChain(t, relay)
		})
	}
}

// runRelayChain builds an A-to-B-to-C chain with no direct A-to-C edge, seeds
// A, and expects convergence only when relay retention is enabled.
func runRelayChain(t *testing.T, relay bool) {
	t.Helper()
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
		ident *NodeIdentity
		eng   *eng.DeltaCRDTEngine
		dir   *identity.Directory
		recv  *receive.Receiver
		ps    *PeerSet
		g     *Gossiper
		tr    *transport.TLSConnections
		ln    net.Listener
		addr  string
	}
	const numNodes = 3 // A=0 (origin), B=1 (relay), C=2 (sink)
	nodes := make([]*node, numNodes)
	for i := 0; i < numNodes; i++ {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand seed %d: %v", i, err)
		}
		id, err := NewNodeIdentity(seed)
		if err != nil {
			t.Fatalf("NewNodeIdentity %d: %v", i, err)
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
		if err := os.MkdirAll(arenaDir, 0o755); err != nil {
			t.Fatalf("mkdir eng%d: %v", i, err)
		}
		engN := newTestEngine(t, id.NodeID, arenaDir)
		d := identity.NewDirectory()
		recv := receive.NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engN), clock.NewSystemClock(), d, engN, 50_000_000)
		ps := NewPeerSet(tr, recv, id, engN)
		g := NewGossiper(ps, id, engN, d)
		// Enable both cache layers together in the relay case and leave both nil
		// in the control. The batch retainer is required on this chain because
		// SetBatchSize sends A's writes through shipBatchedDelta; the per-frame
		// retainer covers frames arriving through shipDelta.
		if relay {
			recv.SetRelayRetainer(g.RetainForeign)
			recv.SetRelayRetainerBatch(g.RetainForeignBatch)
		}
		// A ships one batch to B. With retention enabled, HandleBatchFrame and
		// RetainForeignBatch preserve the signed envelope so B's next sweep can
		// re-publish it to C. With retention disabled, B's relay lookup misses
		// and C cannot converge.
		g.SetBatchSize(DefaultBatchSize)
		nodes[i] = &node{ident: id, eng: engN, dir: d, recv: recv, ps: ps, g: g, tr: tr}
	}
	// Cross-register every public key so signature verification does not
	// masquerade as a relay failure.
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}
			if err := nodes[i].dir.Register(nodes[j].ident.NodeID, nodes[j].ident.Pub); err != nil {
				t.Fatalf("Register %d in %d: %v", j, i, err)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	// Deferred calls close listeners, cancel the context, then join the loops.
	defer wg.Wait()
	defer cancel()
	defer func() {
		for _, n := range nodes {
			if n.ln != nil {
				n.ln.Close()
			}
		}
	}()

	// All three nodes listen. B dials A and C dials B; neither A nor C dials the
	// other, so the only path from A to C passes through B. Start listeners in
	// chain order so each dial target is available.
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
	// B dials A, so A registers B and can publish to it.
	if err := nodes[1].ps.Dial(ctx, nodes[0].addr, "localhost", nodes[0].ident.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	// C dials B, so B registers C and can publish to it. C never dials A.
	if err := nodes[2].ps.Dial(ctx, nodes[1].addr, "localhost", nodes[1].ident.NodeID); err != nil {
		t.Fatalf("dial C->B: %v", err)
	}
	// Let TLS handshakes and accept-side registrations settle before sweeping.
	time.Sleep(100 * time.Millisecond)

	// Only A injects, so C can receive these events only through B's relay.
	const keys = 25
	for i := 0; i < keys; i++ {
		eid := fmt.Sprintf("asym-relay-key-%d", i)
		payload := fmt.Sprintf("value-%d", i)
		entry := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		}
		nodes[0].g.InsertLocalEvents(eid, payload, entry)
	}

	// B must sweep to relay A's deltas to C. C's sweeps can pull from B, but B
	// already has the only copy outside A.
	for i := 0; i < numNodes; i++ {
		go nodes[i].g.SweepLoop(ctx, 20*time.Millisecond)
	}

	const slo = 10 * time.Second
	deadline := time.Now().Add(slo)
	converged := false
	var ra, rb, rc [32]byte
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		ra = nodes[0].eng.MerkleRootFromShards()
		rb = nodes[1].eng.MerkleRootFromShards()
		rc = nodes[2].eng.MerkleRootFromShards()
		if ra == rb && rb == rc && ra != ([32]byte{}) {
			converged = true
			break
		}
	}
	if relay {
		if !converged {
			t.Fatalf("relay enabled: A injected %d keys but roots did not converge within %s (rootA=%x rootB=%x rootC=%x); C has no direct A edge, so check RetainForeignBatch, relayCache lookup, and shipBatchedDelta", keys, slo, ra, rb, rc)
		}
		t.Logf("relay enabled: all three roots converged to %x within %s across the A-to-B-to-C chain", ra, slo)
		return
	}
	// The disabled control must not converge. Convergence would reveal another
	// A-to-C path and invalidate the relay-specific assertion.
	if converged {
		t.Fatalf("relay disabled but roots converged to %x within %s; C received A's deltas without B's retained envelopes, so the chain does not isolate relay", ra, slo)
	}
	t.Logf("relay-disabled control did not converge within %s (rootA=%x rootB=%x rootC=%x); B had no retained envelope to forward", slo, ra, rb, rc)
}

// TestCloseDoneExactOnce exercises closeDone concurrently on 64 peerConns with
// 32 goroutines each. Both readLoop's exit defer and ReleaseInbound call this
// guard, so pc.done must close exactly once and later calls must be no-ops.
// Replacing closeDoneOnce.Do with a bare close(pc.done) makes this test panic,
// providing a direct negative control for double-close protection (ADR-0045 §2).
//
// Run with: go test -run TestCloseDoneExactOnce -race -count=1 ./pkg/mesh/
func TestCloseDoneExactOnce(t *testing.T) {
	const goroutines = 32
	const peerConns = 64
	for c := 0; c < peerConns; c++ {
		pc := &peerConn{done: make(chan struct{})}
		var wg sync.WaitGroup
		wg.Add(goroutines)
		start := make(chan struct{})
		for g := 0; g < goroutines; g++ {
			go func() {
				defer wg.Done()
				<-start // release all goroutines together
				pc.closeDone()
			}()
		}
		close(start)
		wg.Wait()
		select {
		case <-pc.done:
		default:
			t.Fatalf("peerConn %d: pc.done is open after %d closeDone calls", c, goroutines)
		}
		// A later call must also be a no-op rather than a second close.
		pc.closeDone()
	}
	t.Logf("%d peerConns x %d goroutines: closeDone closed each channel once without panic or double-close", peerConns, goroutines)
}
