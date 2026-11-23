// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// The two-node convergence test exchanges signed CRDT deltas over TLS 1.3
// loopback connections. Each node registers the other's public key, inserts
// half of 1,000 events, and must reach the same sharded Merkle root within ten
// sweep rounds. The test uses the production receive path rather than joining
// the engines directly.
package mesh

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"io"
	"log"
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

// TestTwoNodeConvergence_InMemory requires two nodes to converge within ten
// rounds over real TLS connections. Each nodeID is the first 16 bytes of its
// signing public key and is also the leaf certificate's CommonName, so the same
// identity covers TLS, frame verification, and the CRDT engine.
//
// A loopback listener exercises receive.NewFrameReader and
// transport.TransmitTLSFrame with their concrete *tls.Conn APIs. The test is
// in-process: frames cross the kernel and TLS record layers on one machine,
// not a multi-machine network.
func TestTwoNodeConvergence_InMemory(t *testing.T) {
	// 1. Dev CA + two leaves.
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}

	// 2. Two NodeIdentity (fresh seeds).
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

	// 3. Build both engines + gate stacks. Use a per-arena temp dir so the two
	//    engine Lamport-recovery files do not collide.
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
	// Each node registers the other node's CRDT-delta public key.
	if err := dirB.Register(identA.NodeID, identA.Pub); err != nil {
		t.Fatalf("Register A in B: %v", err)
	}
	if err := dirA.Register(identB.NodeID, identB.Pub); err != nil {
		t.Fatalf("Register B in A: %v", err)
	}

	// Per-node gate stack (the transport wiring, reused here).
	bucketA := admission.NewPeerBucket()
	capA := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engineA)
	recvA := receive.NewReceiver(bucketA, capA, clock.NewSystemClock(), dirA, engineA, 50_000_000)

	bucketB := admission.NewPeerBucket()
	capB := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engineB)
	recvB := receive.NewReceiver(bucketB, capB, clock.NewSystemClock(), dirB, engineB, 50_000_000)

	// Each node needs a TLS leaf signed by the dev CA.
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

	// 4. Loopback TLS listeners.
	lnA, err := trA.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer lnA.Close()
	lnB, err := trB.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer lnB.Close()
	addrA := lnA.Addr().String()
	addrB := lnB.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(4)

	// Each TLS leaf CommonName is identHex(nodeID), which is also used for SNI.
	psA := NewPeerSet(trA, recvA, identA, engineA)
	psB := NewPeerSet(trB, recvB, identB, engineB)
	// Register accepted connections and run their connection challenges. A nil
	// digester selects the oversend path used by this test.
	go runAcceptLoopWithPeerSet(ctx, lnA, recvA, nil, &wg, psA)
	go runAcceptLoopWithPeerSet(ctx, lnB, recvB, nil, &wg, psB)
	gA := NewGossiper(psA, identA, engineA, dirA)
	gB := NewGossiper(psB, identB, engineB, dirB)
	// Exercise RegisterPeer as well as the direct Directory registrations above.
	_ = gA.RegisterPeer(identB.NodeID, identB.Pub)
	_ = gB.RegisterPeer(identA.NodeID, identA.Pub)

	if err := psA.Dial(ctx, addrB, "localhost", identB.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	if err := psB.Dial(ctx, addrA, "localhost", identA.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	// Wait for both reader goroutines to have plumbed through the TLS handshake.
	asyncWait(t, psA, identB.NodeID)
	asyncWait(t, psB, identA.NodeID)
	wg.Add(0)

	// 5. Inject 1000 events split 500/500. Use a recognizable payload per (entity,dot)
	//    whose SHA-256 the receiver cross-validates against the engine's digest.
	const total = 1000
	for i := 0; i < total; i++ {
		eid := fmt.Sprintf("civic-%d", i)
		payload := fmt.Sprintf("value-%d", i)
		entry := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		}
		if i%2 == 0 {
			gA.InsertLocalEvents(eid, payload, entry)
		} else {
			gB.InsertLocalEvents(eid, payload, entry)
		}
	}

	// 6. Sweep until convergence or gate limit. Race-clean (the -race flag is
	//    external; this loop does the convergence detect).
	const maxRounds = 10
	round := 0
	converged := false
	tick := 20 * time.Millisecond // faster than the 100 ms steady-state default, since this is an in-process gate (not labeled 32c/silicon)
	// Run several quick sweep rounds; each round both gossipers oversend.
	for round = 0; round < maxRounds; round++ {
		// Run both sweeps concurrently (true parallelism on a real box). The
		// delta oversend path is CRDT-idempotent.
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); gA.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); gB.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
		// Let async readers drain.
		time.Sleep(tick)
		ra := engineA.MerkleRootFromShards()
		rb := engineB.MerkleRootFromShards()
		t.Logf("round %d: rootA=%x rootB=%x", round, ra, rb)
		if ra == rb {
			converged = true
			break
		}
	}
	_ = tick
	if !converged {
		ra := engineA.MerkleRootFromShards()
		rb := engineB.MerkleRootFromShards()
		t.Logf("roots after %d rounds: rootA=%x rootB=%x", maxRounds, ra, rb)
		t.Fatalf("two-node convergence did not complete within %d rounds: rootA=%x rootB=%x", maxRounds, ra, rb)
	}
	// Equal roots alone are insufficient: both engines must contain every key.
	gotA := cardinality(t, engineA)
	gotB := cardinality(t, engineB)
	t.Logf("converged in %d rounds; entries A=%d B=%d (target both=%d)", round+1, gotA, gotB, total)
	if gotA != total || gotB != total {
		t.Fatalf("converged roots but incomplete state: A=%d B=%d, want both=%d", gotA, gotB, total)
	}
	log.Printf("two-node convergence passed in %d rounds over TLS 1.3 loopback (in-process)", round+1)
}

// newTestEngine gives each engine a separate DataDir for its Lamport recovery
// file. The 64 MiB arena is sized for the test, not a throughput benchmark.
func newTestEngine(t *testing.T, nodeID [16]byte, dataDir string) *eng.DeltaCRDTEngine {
	t.Helper()
	eng.DataDir = dataDir // package-global DataDir copied into e.dataDir at construction; the persist file is lamport_<nodeID>.dat so two engines with distinct nodeIDs do not collide
	e, err := eng.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine %x: %v", nodeID, err)
	}
	return e
	// Do not close the engine from this helper. Some serveTestConn goroutines
	// are not WaitGroup-tracked and can briefly outlive their test; closing here
	// could unmap the arena during an in-flight join. The engine therefore lives
	// until the test process exits. Tests that require an earlier close register
	// their own cleanup, as newHoistGossiper does.
}

// runAcceptLoop mirrors the node's accept loop so tests use the same frame
// reassembly and receiver dispatch as production. digester routes digest frames
// to the Gossiper; a nil digester drops them, which is the expected behavior
// when stratified anti-entropy is disabled.
func runAcceptLoop(ctx context.Context, ln net.Listener, recv any, digester DigestSink, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			return
		}
		// This legacy helper leaves inbound connections unregistered. Tests that
		// need a publishable inbound edge use runAcceptLoopWithPeerSet instead.
		go serveTestConn(ctx, conn, recv, digester, nil)
	}
}

// runAcceptLoopWithPeerSet also registers inbound connections in the PeerSet.
// This makes an accepted connection publishable in both directions, as required
// by tests that dial from only one side.
func runAcceptLoopWithPeerSet(ctx context.Context, ln net.Listener, recv any, digester DigestSink, wg *sync.WaitGroup, peerSet *PeerSet) {
	defer wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			return
		}
		go serveTestConn(ctx, conn, recv, digester, peerSet)
	}
}

// serveTestConn mirrors serveConnWithDigest: it completes the TLS handshake,
// registers inbound connections when peerSet is non-nil, and dispatches batch,
// digest, hybrid, and relay frames through DispatchFrame.
//
// Digest frames are accepted only on a challenge-verified connection whose
// registered identity matches the frame's claimed sender. Connection challenges
// are handled before ordinary dispatch. A nil peerSet preserves the legacy test
// path without registration; those connections cannot pass digest verification.
func serveTestConn(ctx context.Context, conn net.Conn, recv any, digester DigestSink, peerSet *PeerSet) {
	defer conn.Close()
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer
	}
	var inboundNodeID [16]byte
	var myPC *PeerConnHandle
	var declNodeID [16]byte
	var declPC *PeerConnHandle
	var tc *tls.Conn
	if t, ok := conn.(*tls.Conn); ok {
		tc = t
		if err := tc.Handshake(); err != nil {
			return
		}
		if peerSet != nil {
			// Release the exact handle returned by registration, including when the
			// listener accepted a connection for an already-connected identity.
			inboundNodeID, myPC = peerSet.RegisterInbound(tc)
			defer peerSet.ReleaseInboundConn(inboundNodeID, myPC)
			if myPC == nil {
				declNodeID, declPC = peerSet.ArmDeclinedInbound(tc)
			}
		}
	}
	sr := recv.(frameSink)
	fr := receive.NewFrameReader(conn)
	// Match the production connection loop's dispatch-busy accounting.
	noteServeBusy := func(t0 time.Time) {
		if peerSet != nil {
			peerSet.NoteDispatchBusy(L0ILoopServe, time.Since(t0).Nanoseconds())
		}
	}
	for {
		if ctx.Err() != nil {
			return
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if err != io.EOF {
				// net error on a closed peer is expected at teardown
			}
			return
		}
		busyT0 := time.Now()
		// Connection challenges are handled by the PeerSet bound to this connection,
		// not by ordinary frame dispatch. Declined connections use their separate
		// challenge handle; unregistered legacy connections have no challenge state.
		if peerSet != nil && IsChallengeFrame(frame) {
			if myPC != nil {
				peerSet.HandleConnChallengeFrame(myPC, tc, frame)
			} else {
				peerSet.HandleDeclinedChallengeFrame(declPC, tc, frame)
			}
			noteServeBusy(busyT0)
			continue
		}
		// DispatchFrame routes batch, digest, and relay frames as production does.
		// Digest delivery additionally requires a verified connection and uses its
		// registered identity rather than trusting the frame's claimed sender.
		dispatchID := inboundNodeID
		if frameIsDigest(frame) {
			activePC := myPC
			activeID := inboundNodeID
			if activePC == nil {
				activePC = declPC
				activeID = declNodeID
			}
			if peerSet == nil || !peerSet.DigestConnVerified(activePC) {
				noteServeBusy(busyT0)
				continue
			}
			dispatchID = activeID
		}
		_ = DispatchFrame(frame, dispatchID, sr, digester)
		noteServeBusy(busyT0)
	}
}

// asyncWait polls until the peer's reader goroutine has its conn live.
func asyncWait(t *testing.T, ps *PeerSet, peerID [16]byte) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ps.mu.RLock()
		_, ok := ps.peers[peerID]
		ps.mu.RUnlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("peer %x not live within 3s", peerID)
}

// identHex renders nodeID as hex (the leaf CommonName + the SNI).
func identHex(id [16]byte) string {
	const hexd = "0123456789abcdef"
	b := make([]byte, 32)
	for i, v := range id {
		b[2*i] = hexd[v>>4]
		b[2*i+1] = hexd[v&0x0f]
	}
	return string(b)
}

// cardinality counts the 1,000 known test keys reachable through PointGet.
func cardinality(t *testing.T, e *eng.DeltaCRDTEngine) int {
	t.Helper()
	// PointGet avoids constructing a merged state snapshot for every key.
	n := 0
	for i := 0; i < 1000; i++ {
		if got := e.PointGet(fmt.Sprintf("civic-%d", i)); len(got) > 0 {
			n++
		}
	}
	return n
}
