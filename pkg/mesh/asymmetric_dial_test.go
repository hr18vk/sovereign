// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// asymmetric_dial_test.go — ADR-0045: the real-TCP RED→GREEN harness
// for the asymmetric PeerSet + broken-relay roots of the 100-node blocker.
//
// This test is MANDATORY BEFORE any mesh
// fix code, because it is the ONLY thing that proves the accept-loop-symmetry fix
// + the foreign-relay fix actually work instead of assuming they do. The
// loopback (loopback_convergence_test.go, the 11 GREEN guards) uses chaos.VirtualNet
// — a mailbox model that BYPASSES the entire pkg/mesh PeerSet/Dial/Accept stack
// where the bug lives. A net.Pipe/VirtualNet test for this bug would PASS GREEN on
// the BUGGY code = a test that LIES. This test exercises the REAL stack
// (transport.NewTLSTransport → PeerSet.Dial → the accept loop → Gossiper sweep)
// with a DETERMINISTIC staggered boot, so it reproduces the asymmetric dial the
// 100-node silicon hit, at 3 nodes, cheaply + reproducibly + with the FULL log.
//
// THE BUG IT REPRODUCES (Root 1, the cardinality cliff):
//   - ps.peers (the map Publish queries for "live peer") is populated ONLY on
//     outbound Dial (peer.go:389). The accept loop (serveConnWithDigest /
//     serveTestConn) serves frames for a connection it NEVER registers in ps.peers.
//   - So a connection B→A is a publishable edge for B, NOT for A. At 100 nodes
//     the seed's boot dial races 99 listeners; a failed dial leaves the peer
//     absent from ps.peers → Publish: no live peer → the peer never receives.
//   - At 3 nodes the existing gossip_test dials BOTH directions (line 191-194),
//     so the asymmetry never bites → PASSES. THIS test deliberately does NOT dial
//     both directions: it brings A up FIRST, lets A's boot dial to B/C FAIL (B/C
//     not listening yet), then brings B/C up to dial A. On the buggy code, A's
//     accept loop serves B/C's inbound frames but never registers B/C in A's
//     ps.peers → A's sweep Publish to B/C returns "no live peer" → B/C never
//     receive A's keys → RED (convergence fails). After the accept fix, A's accept loop
//     registers B/C (keyed by the real nodeID from the TLS leaf CN) → A's Publish
//     to B/C succeeds → B/C receive → GREEN.
//
// This file is the harness + the RED assertion. The accept + relay fixes turn it GREEN.

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

// TestAsymDialAcceptDoesNotRegister RED-reproduces Root 1: after B dials A
// (A's accept loop serves B's conn), A's ps.peers does NOT contain B. This is the
// atomic unit of the 100-node cliff — a single asymmetric edge. It MUST FAIL on
// current code (the accept loop never registers) + PASS after The accept fix.
//
// It is deliberately MINIMAL (2 nodes, no sweep, no inject) so the failure is
// unambiguous: the assertion is directly on A's ps.peers, not on convergence
// (which would confound Root 1 + Root 2). Convergence is the INTEGRATION test
// below (TestAsymStaggeredConverges); this is the UNIT test that pins Root 1.
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
	go runAcceptLoopWithPeerSet(ctx, lnA, recvA, nil, &wg, psA) // A listens + registers inbound (the accept fix); B does NOT.
	// Teardown: close the listener FIRST (unblocks runAcceptLoop's ln.Accept →
	// the loop returns → wg.Done), then cancel the ctx (unblocks serveTestConn
	// readers), then wg.Wait. LIFO defer order = wait, cancel, close-listener.
	defer wg.Wait()
	defer cancel()
	defer lnA.Close()

	// B dials A (B→A). A's accept loop serves the conn. The asymmetric edge:
	// B's ps.peers gets A (B's outbound registers A); A's ps.peers SHOULD get B
	// (from the accept side), but on the buggy code it does NOT.
	if err := psB.Dial(ctx, addrA, "localhost", identA.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	asyncWait(t, psB, identA.NodeID) // B registered A (B's outbound) — must hold.
	// Give A's accept loop a moment to serve B's conn + (after the accept fix) register B.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if psA.peerLiveForTest(identB.NodeID) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// THE RED ASSERTION (Root 1, atomic): A's ps.peers does NOT contain B.
	// Buggy code: A's accept loop served B's conn but never registered B → FAIL.
	// After the accept fix: A's accept loop registers B (real nodeID from the TLS leaf CN)
	// → psA.peers[B] present → PASS (GREEN).
	if !psA.peerLiveForTest(identB.NodeID) {
		t.Fatalf("RED — Root 1 reproduced: A's accept loop served B's inbound conn but A.ps.peers does NOT contain B (the asymmetric graph — a B→A edge is publishable for B, not for A). The accept-symmetry fix must register the inbound peer in the accept loop keyed by the real nodeID from the TLS leaf CN, so a connection becomes a bidirectional publishable edge.")
	}
	t.Logf("GREEN — A registered B from the accept side (accept-symmetry fix landed): the B→A edge is now publishable for A too.")
}

// TestAsymStaggeredConverges is the INTEGRATION gate: 3 nodes, A up first,
// A's boot dial to B/C fails (refused), then B/C come up + dial A. A injects keys;
// the sweep must converge all 3 roots. RED on current code (A can't Publish to
// B/C: not in ps.peers + the relay is broken), GREEN after the accept + relay fixes. This is
// the 3-node mirror of the 100-node silicon gate — cheap, deterministic, full log.
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
		// the relay fix: wire the receive-side relay-retention hook so a foreign
		// delta each node Accepts is retained in its relayCache for onward
		// re-publish by shipDelta. Without this the test would assert the
		// pre-fix behavior (foreign deltas propagate one hop then stop) — the
		// exact RED the harness was staged to catch. The production wiring
		// mirrors cmd/main.go's recv.SetRelayRetainer(gossiper.RetainForeign).
		recv.SetRelayRetainer(g.RetainForeign)
		// the batch-relay layer: arm the BATCH path (--batch-size=100, the
		// production default main.go:330) so AntiEntropySweep routes the self-
		// originated delta to shipBatchedDelta (NOT per-frame shipDelta) + the
		// peers receive via HandleBatchFrame. This makes the test exercise the
		// BATCH relay (the path the 100-node silicon blocker lives on) instead of
		// the per-frame path a batchSize=0 default would take. With 100 keys +
		// batch-size 100 the seed ships ONE batch of 100 → B/C receive via
		// HandleBatchFrame → InspectBatchDots + retain the whole BatchEnvelope
		// (RetainForeignBatch) → shipBatchedDelta's foreign branch relays the
		// retained batch onward (lookupBatch + per-sweep dedup) → all 3 roots
		// converge. The BATCH retainer (SetRelayRetainerBatch) is the load-bearing
		// wiring for the batch relay; the per-frame retainer above stays too (both
		// paths must work — a per-frame foreign delta a peer forwards still uses
		// RetainForeign). SetBatchSize(DefaultBatchSize) is the production knob.
		g.SetBatchSize(DefaultBatchSize)
		recv.SetRelayRetainerBatch(g.RetainForeignBatch)
		nodes[i] = &node{ident: id, eng: engN, dir: d, recv: recv, ps: ps, g: g, tr: tr}
	}
	// Cross-register all pubkeys (the Directory verification anchor — a delta from
	// an unregistered origin is DropVerify'd, which would confound Root 1/2).
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

	// A (node 0) listens FIRST. B, C do NOT listen yet (the stagger — A's boot
	// dial to B/C will be refused, reproducing the 100-node race at 3 nodes).
	lnA, err := nodes[0].tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	nodes[0].ln = lnA
	nodes[0].addr = lnA.Addr().String()
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, lnA, nodes[0].recv, nil, &wg, nodes[0].ps)

	// A dials B + C at boot. Both refused (B/C not listening). A's ReconnectLoop
	// is spawned (main.go:1387) so the test mirrors production: the retry IS
	// present, Root 1 is about the accept side not registering, not the retry
	// being absent. Use a guaranteed-closed placeholder port for the refused dial.
	for j := 1; j < numNodes; j++ {
		placeholder := bumpPort(nodes[0].addr, 1)
		dialErr := nodes[0].ps.Dial(ctx, placeholder, "localhost", nodes[j].ident.NodeID)
		if dialErr == nil {
			t.Fatalf("expected A's boot dial to B/C to be refused (the stagger), got nil — port %s unexpectedly listening", placeholder)
		}
		go nodes[0].ps.ReconnectLoop(ctx, placeholder, "localhost", nodes[j].ident.NodeID, 50*time.Millisecond, 2*time.Second)
	}

	// A injects `keys` events (the seed — A is the 100-node seed's stand-in).
	for i := 0; i < keys; i++ {
		eid := fmt.Sprintf("asym-key-%d", i)
		payload := fmt.Sprintf("value-%d", i)
		entry := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		}
		nodes[0].g.InsertLocalEvents(eid, payload, entry)
	}

	// Start A's sweep. Then bring B + C up LATE: they listen + dial A (succeed,
	// A accepts). B/C start their own sweeps.
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
		// B/C dial A — the asymmetric edge. A's accept loop serves these conns.
		if err := nodes[j].ps.Dial(ctx, nodes[0].addr, "localhost", nodes[0].ident.NodeID); err != nil {
			t.Fatalf("dial %d->A: %v", j, err)
		}
		asyncWait(t, nodes[j].ps, nodes[0].ident.NodeID) // B/C registered A (their outbound).
		go nodes[j].g.SweepLoop(ctx, 20*time.Millisecond)
	}
	// Teardown: close listeners FIRST (unblocks each runAcceptLoop's ln.Accept →
	// the loops return → wg.Done), then cancel ctx (unblocks serveTestConn
	// readers + the sweep loops), then wg.Wait. LIFO defer order.
	defer wg.Wait()
	defer cancel()
	defer func() {
		for _, n := range nodes {
			if n.ln != nil {
				n.ln.Close()
			}
		}
	}()

	// THE GREEN GATE: poll all 3 Merkle roots until equal (the convergence SLO,
	// the 3-node mirror of the 100-node gate). RED on current code: A can't
	// Publish to B/C (Root 1) → B/C stay root-zero → timeout → FAIL. GREEN after
	// the accept fix (A's accept loop registers B/C → A Publish succeeds → converge).
	const slo = 10 * time.Second
	deadline := time.Now().Add(slo)
	converged := false
	var ra, rb, rc [32]byte
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		ra = nodes[0].eng.State().MerkleRoot()
		rb = nodes[1].eng.State().MerkleRoot()
		rc = nodes[2].eng.State().MerkleRoot()
		if ra == rb && rb == rc {
			converged = true
			break
		}
	}
	if !converged {
		t.Fatalf("RED — Root 1 reproduced at 3 nodes: A injected %d keys + swept, B/C came up + dialed A, but the roots did NOT converge within %s (rootA=%x rootB=%x rootC=%x). A's accept loop served B/C's inbound conns but never registered them in A.ps.peers → A's Publish to B/C returned 'no live peer' → B/C stayed root-zero. The accept-loop-symmetry fix must register the inbound peer; the relay fix carries deltas through hops. This is the 3-node mirror of the 100-node GATE-1 blocker.", keys, slo, ra, rb, rc)
	}
	t.Logf("GREEN — all 3 roots converged (root=%x) within %s: the accept-symmetry fix + the relay fix closed the asymmetric + relay gaps.", ra, slo)
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

// TestRelayChainLoadBearing is the proof that the relay fix
// (relay foreign deltas via the embedded envelope) is LOAD-BEARING, not a
// lying-GREEN test. The 3-node staggered test (TestAsymStaggeredConverges)
// passes on the accept fix ALONE — A reaches B/C directly via the now-symmetric edges, so
// the relay fix's path is never exercised. A test that passes without exercising
// the fix is a test that LIES GREEN (the exact failure mode
// the loopback-bypass caveat warns about). This test constructs
// the ONE topology where the relay fix is the ONLY path: a relay CHAIN A→B→C where the
// sink C has NO direct edge to the origin A.
//
//   - Edges: B dials A (A registers B → A can Publish to B = the accept fix). C dials B
//     (B registers C → B can Publish to C = the accept fix). A does NOT dial C + C does
//     NOT dial A → NO A↔C edge. The ONLY path A's delta reaches C is: A ships
//     to B (direct, the accept fix), B RELAYS the foreign frame to C (the relay fix).
//   - Only A injects (the seed). So C's receipt of A's deltas is PURELY via B's
//     relay — the relay fix is load-bearing, not incidental.
//   - The relay-DISABLED sub-test (relayRetainer=nil = byte-identical pre-fix)
//     MUST FAIL: B receives + Join's A's deltas but does NOT retain them → B's
//     shipDelta for A's foreign entries hits relay.lookup MISS → skip → C stays
//     root-zero → RED. The relay-ENABLED sub-test MUST PASS: B retains A's
//     frames + relays them to C → C converges → GREEN. The RED→GREEN delta on
//     the SAME topology, toggling ONLY the relay retainer, is the proof the relay fix
//
// is load-bearing (the fault-injection control — the chaos digestReleaseRoundTrip test hang
// + RedControl precedent: a guard that passes both ways is a tautology).
func TestRelayChainLoadBearing(t *testing.T) {
	for _, relay := range []bool{false /* negative control */, true /* GREEN */} {
		relay := relay
		name := "RelayDISABLED_REDcontrol"
		if relay {
			name = "RelayENABLED"
		}
		t.Run(name, func(t *testing.T) {
			runRelayChain(t, relay)
		})
	}
}

// runRelayChain builds the A→B→C relay chain (C has no direct edge to A), seeds
// A, + asserts convergence iff relay is enabled. The topology GUARANTEES the relay fix
// is the only path A's deltas reach C; the relay flag toggles the retainer.
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
		// The relay toggle: relay=true wires the retainer (GREEN); relay=false
		// passes nil (byte-identical pre-fix — the negative control). BOTH the
		// per-frame retainer (RetainForeign — shipDelta) AND the BATCH retainer
		// (RetainForeignBatch — shipBatchedDelta) are toggled together: the batch
		// path is armed below (SetBatchSize) so AntiEntropySweep routes the self-
		// delta to shipBatchedDelta + peers receive via HandleBatchFrame, so it is
		// the BATCH retainer that is load-bearing on THIS topology (the A→B→C
		// chain, the 100-node silicon blocker's path). The per-frame retainer stays
		// wired too so the test stays honest about BOTH paths (a per-frame foreign
		// frame a peer forwards still routes through RetainForeign).
		if relay {
			recv.SetRelayRetainer(g.RetainForeign)
			recv.SetRelayRetainerBatch(g.RetainForeignBatch)
		}
		// the batch-relay layer: arm the BATCH path (--batch-size=100, the
		// production default main.go:330) so AntiEntropySweep routes the self-
		// delta to shipBatchedDelta (NOT per-frame shipDelta) + peers receive via
		// HandleBatchFrame. This makes the A→B→C relay chain exercise the BATCH
		// relay (the path the 100-node silicon blocker lives on): A ships ONE batch
		// of `keys` to B → B's HandleBatchFrame InspectBatchDots + RetainForeignBatch
		// retains the whole BatchEnvelope → B's shipBatchedDelta foreign branch
		// lookups the batch + re-publishes it (deduped per-sweep) to C → C's
		// HandleBatchFrame Join's it → C converges. With relay=false the batch
		// retainer is nil → shipBatchedDelta's foreign branch relay-miss → C stays
		// root-zero (the negative control). This is the REAL-TCP batch-relay proof with
		// a negative control — the gate to launch the 100-node silicon run.
		g.SetBatchSize(DefaultBatchSize)
		nodes[i] = &node{ident: id, eng: engN, dir: d, recv: recv, ps: ps, g: g, tr: tr}
	}
	// Cross-register ALL pubkeys in ALL directories (the verification anchor —
	// a delta from an unregistered origin is DropVerify'd, which would confound
	// the relay proof with a Root-1/verify artifact, not a relay miss).
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
	// Teardown: listeners FIRST → cancel → wg.Wait (LIFO).
	defer wg.Wait()
	defer cancel()
	defer func() {
		for _, n := range nodes {
			if n.ln != nil {
				n.ln.Close()
			}
		}
	}()

	// ALL THREE listen (the chain needs A, B, C all accepting). A↔B (B dials A),
	// B↔C (C dials B). NO A↔C edge (neither dials the other) — the relay-only
	// path. Bring them up in chain order so each dialer's target is already
	// listening: A first, then B (dials A), then C (dials B).
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
	// B dials A (A registers B → A→B publishable).
	if err := nodes[1].ps.Dial(ctx, nodes[0].addr, "localhost", nodes[0].ident.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	// C dials B (B registers C → B→C publishable). C does NOT dial A.
	if err := nodes[2].ps.Dial(ctx, nodes[1].addr, "localhost", nodes[1].ident.NodeID); err != nil {
		t.Fatalf("dial C->B: %v", err)
	}
	// Let the TLS handshakes + the inbound registrations settle before the
	// sweep starts (so A's first sweep already has B in ps.peers).
	time.Sleep(100 * time.Millisecond)

	// A (the origin/seed) injects `keys` events. B + C inject NOTHING — so C's
	// receipt of A's deltas is PURELY via B's relay (the load-bearing path).
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

	// ALL THREE sweep (B must sweep to relay A's deltas to C; C sweeps to pull
	// from B — though C's sweep Publishes to B, B already has A's deltas, so the
	// load-bearing direction is B→C).
	for i := 0; i < numNodes; i++ {
		go nodes[i].g.SweepLoop(ctx, 20*time.Millisecond)
	}

	// THE GATE: poll all 3 Merkle roots until equal. relay=true → GREEN (B
	// relays A's deltas to C → C converges). relay=false → RED (B does not
	// retain A's frames → shipDelta foreign miss → C stays root-zero). The
	// negative control proves the relay fix is load-bearing (the topology has no other path).
	const slo = 10 * time.Second
	deadline := time.Now().Add(slo)
	converged := false
	var ra, rb, rc [32]byte
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		ra = nodes[0].eng.State().MerkleRoot()
		rb = nodes[1].eng.State().MerkleRoot()
		rc = nodes[2].eng.State().MerkleRoot()
		if ra == rb && rb == rc && ra != ([32]byte{}) {
			converged = true
			break
		}
	}
	if relay {
		if !converged {
			t.Fatalf("RED (relay ENABLED but no convergence) — UNEXPECTED: A injected %d keys, B should relay them to C, but roots did NOT converge within %s (rootA=%x rootB=%x rootC=%x). A↔B + B↔C edges present, NO A↔C edge, so C reaches A ONLY via B's relay. If this fails, the relay fix is NOT working even when wired — a real regression, not a control. Check RetainForeign + the relayCache lookup + shipDelta's foreign branch.", keys, slo, ra, rb, rc)
		}
		t.Logf("GREEN (relay ENABLED) — all 3 roots converged (root=%x) within %s on the A→B→C chain with NO A↔C edge: B relayed A's foreign deltas to C (the relay fix load-bearing — the embedded envelope propagated the full hop).", ra, slo)
		return
	}
	// relay == false: the negative control. Convergence here would mean the relay fix is NOT
	// load-bearing (C reached A another way — the test is a tautology). The
	// EXPECTED outcome is RED (C root-zero): B Join'd A's deltas but did not
	// retain them → shipDelta foreign miss → C never received A's keys.
	if converged {
		t.Fatalf("RED CONTROL BROKEN — relay DISABLED but roots converged (root=%x) within %s: C reached A's deltas WITHOUT B's relay, so the A→B→C topology does NOT make the relay fix load-bearing (the test is a tautology — there is another path A→C). Tighten the topology: ensure NO A↔C edge (neither dials the other) + NO ReconnectLoop that re-dials C to A.", ra, slo)
	}
	t.Logf("RED CONTROL PASS (relay DISABLED) — roots did NOT converge within %s (rootA=%x rootB=%x rootC=%x): B Join'd A's deltas but, with the retainer nil, did NOT retain them → shipDelta foreign relay miss → C stayed root-zero. This is the byte-identical pre-relay-fix behavior, proving the relay fix is load-bearing on this topology (the RED half of the RED→GREEN proof).", slo, ra, rb, rc)
}

// TestCloseDoneExactOnce is the regression test for the silicon-found
// `panic: close of closed channel`. It proves the
// sync.Once-guarded closeDone closes pc.done EXACTLY ONCE across N racing
// goroutines — the invariant the readLoop's exit defer + ReleaseInbound BOTH
// rely on (both route through closeDone).
//
// THE BUG (the 2026-08-20T223556Z 100-node silicon run): the readLoop had
// `defer close(pc.done)` UNGUARDED; ReleaseInbound had a select-guarded close.
// When both fired on the same peerConn (the accept-loop churn at 100 nodes),
// the second close panicked → the node died on boot → 1/100-live.
//
// RED-CONTROL PROOF: on the UNFIXED code (closeDone = bare `close(pc.done)`,
// no Once) this test PANICS on the first concurrent close; on the FIXED code
// (closeDone = `closeDoneOnce.Do(func{ close(pc.done) })`) it is clean for
// all goroutines. This is premise-correct (it tests the actual invariant the
// fix establishes — "close exactly once across racing closers" — NOT a
// specific unverified two-goroutine race), + deterministic (the Once makes the
// first-closer win + the rest no-op, every run).
//
// RUN: go test -run TestCloseDoneExactOnce -race -count=1 ./pkg/mesh/
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
				<-start // release all goroutines simultaneously (maximize the race)
				pc.closeDone()
			}()
		}
		close(start) // fire all goroutines at once
		wg.Wait()
		// EXACTLY-ONCE assertion: the channel is closed (receivable) + closed once.
		select {
		case <-pc.done:
		default:
			t.Fatalf("peerConn %d: pc.done NOT closed after %d closeDone() calls", c, goroutines)
		}
		// A second closeDone AFTER the race must be a no-op (NOT a panic) — the
		// Once is what makes this safe. On the unfixed code this would panic.
		pc.closeDone()
	}
	t.Logf("GREEN — %d peerConns × %d goroutines each, all closeDone() calls closed pc.done EXACTLY ONCE (no panic, no double-close): the sync.Once invariant holds.", peerConns, goroutines)
}
