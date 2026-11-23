// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover out-of-band peer directory provisioning and peer identity
// reconciliation (ADR-0040). They exercise topology keying, certificate Common
// Name decoding, unprovisioned defaults, concurrent peer-map access, and
// reconnection over loopback TLS.
//
// Configuration parsing and provisioning are covered in
// cmd/sovereign-node/provisioning_test.go.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"

	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/receive"
)

// nopFrameSink keeps the reconnect test independent of receiver setup. The
// server sends no frames; if one did arrive, the sink would drop it because
// this test checks connection recovery rather than frame delivery.
type nopFrameSink struct{}

func (nopFrameSink) HandleFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.DropMalformed}
}
func (nopFrameSink) HandleBatchFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.DropMalformed}
}
func (nopFrameSink) HandleHybridFrame([]byte) receive.AcceptVerdict {
	return receive.AcceptVerdict{Verdict: receive.DropMalformed}
}

// TestT_OOB_PROVISION_RETIRES_SURROGATE contrasts address-surrogate and real
// node-ID keys in the topology registry. AntiEntropySweep selects IDs from this
// registry and passes them to Publish. A surrogate selects no connection when
// PeerSet holds the real node ID or the zero ID, so the sweep cannot ship to
// that peer. Registering the real node ID makes the same selection usable.
//
// The first half checks that Select omits the real ID when only the surrogate is
// registered. The second registers the real ID, as applyProvisioning does, and
// checks both inter-region classification and selection.
func TestT_OOB_PROVISION_RETIRES_SURROGATE(t *testing.T) {
	selfRegion := RegionTag(1)
	peerRegion := RegionTag(2) // Different from selfRegion, so this peer is inter-region.
	peerNodeID := [16]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	// This fixed ID stands in for the address-derived surrogate used when no
	// directory entry supplies the real node ID.
	surrogate := [16]byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}

	// Registering only the surrogate leaves the real node ID unknown to both
	// IsInterRegion and Select.
	topoNegativeControl := NewTopologyManager(selfRegion)
	topoNegativeControl.SetRegion(surrogate, peerRegion)
	topoNegativeControl.SetSeed(1)
	if topoNegativeControl.IsInterRegion(peerNodeID) {
		t.Fatalf("surrogate-only topology classifies real node ID %x as inter-region", peerNodeID)
	}
	selRed := topoNegativeControl.Select(context.Background())
	for _, id := range selRed {
		if id == peerNodeID {
			t.Fatalf("surrogate-only topology selected real node ID %x; registered surrogate is %x", peerNodeID, surrogate)
		}
	}
	t.Logf("surrogate-only topology omitted real node ID %x from Select", peerNodeID)

	// applyProvisioning registers the real node ID, enabling inter-region
	// selection for the provisioned peer.
	topo := NewTopologyManager(selfRegion)
	topo.SetRegion(peerNodeID, peerRegion)
	topo.SetSeed(1)
	if !topo.IsInterRegion(peerNodeID) {
		t.Fatalf("real node ID %x has IsInterRegion=%v, want true for self=%d peer=%d", peerNodeID, topo.IsInterRegion(peerNodeID), selfRegion, peerRegion)
	}
	sel := topo.Select(context.Background())
	found := false
	for _, id := range sel {
		if id == peerNodeID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("topology registered real node ID %x but Select returned %d other peer IDs", peerNodeID, len(sel))
	}
	t.Logf("provisioned topology classified and selected real node ID %x as inter-region", peerNodeID)
}

// TestT_OOB_RECONCILE checks that reconcilePeerID decodes a certificate Common
// Name containing the 32-character hexadecimal node ID and re-keys peerConn.
// crypto.NewMeshCA and IssueLeaf provide the certificate over a real TLS
// connection. A Common Name that does not decode to 16 bytes must be rejected.
//
// Reconciliation changes only the routing maps. It does not register a directory
// public key, so an unprovisioned peer's deltas still fail verification
// (ADR-0040 §6).
func TestT_OOB_RECONCILE(t *testing.T) {
	realNodeID := [16]byte{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}

	// IssueLeaf copies the supplied node ID string into the certificate CN.
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	leaf, err := ca.IssueLeaf(identHex(realNodeID))
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	conn := dialLeafTLS(t, leaf)
	defer conn.Close()

	pc := &peerConn{addr: "127.0.0.1:0", conn: conn, peerID: [16]byte{}}
	ps := &PeerSet{peers: make(map[[16]byte]*peerConn), byAddr: make(map[string]*peerConn)}
	got, ok := ps.reconcilePeerID(pc, conn)
	if !ok {
		t.Fatalf("reconcilePeerID returned ok=false for a hexadecimal node ID; decoded %x", got)
	}
	if got != realNodeID {
		t.Fatalf("reconcilePeerID decoded %x, want %x", got, realNodeID)
	}
	t.Logf("reconcilePeerID decoded certificate CN %q as %x", identHex(realNodeID), got)

	// A 16-byte Common Name cannot decode into a 16-byte node ID: hex decoding
	// requires 32 characters. If x509 rejects the raw non-ASCII name, use 16
	// ASCII characters, which decode to only eight bytes.
	rawCN := string(realNodeID[:])
	leafNegativeControl, err := ca.IssueLeaf(rawCN)
	if err != nil {
		asciiCN := "0123456789abcdef"
		leafNegativeControl, err = ca.IssueLeaf(asciiCN)
		if err != nil {
			t.Fatalf("could not issue certificate with 16-character Common Name %q: %v", asciiCN, err)
		}
	}
	connNegativeControl := dialLeafTLS(t, leafNegativeControl)
	defer connNegativeControl.Close()
	pcNegativeControl := &peerConn{addr: "127.0.0.1:0", conn: connNegativeControl, peerID: [16]byte{}}
	psNegativeControl := &PeerSet{peers: make(map[[16]byte]*peerConn), byAddr: make(map[string]*peerConn)}
	gotNegativeControl, okNegativeControl := psNegativeControl.reconcilePeerID(pcNegativeControl, connNegativeControl)
	if okNegativeControl {
		t.Fatalf("reconcilePeerID accepted a Common Name shorter than 32 hexadecimal characters and returned %x", gotNegativeControl)
	}
	t.Logf("reconcilePeerID rejected a Common Name that does not decode to 16 bytes")
}

// TestT_OOB_OFF_BYTE_IDENTICAL checks the unprovisioned topology defaults. An
// unregistered peer is not classified as inter-region, and an empty registry
// returns no selected IDs. With region awareness disabled, AntiEntropySweep
// consequently uses its full-mesh Peers path. The command tests cover the empty
// --peer-dir configuration directly.
func TestT_OOB_OFF_BYTE_IDENTICAL(t *testing.T) {
	topo := NewTopologyManager(RegionTag(1))
	peerNodeID := [16]byte{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
	// With no SetRegion call, the peer is absent from the registry.
	if topo.IsInterRegion(peerNodeID) {
		t.Fatalf("unregistered peer %x is classified as inter-region", peerNodeID)
	}
	sel := topo.Select(context.Background())
	if len(sel) != 0 {
		t.Fatalf("empty topology selected %d peer IDs, want 0", len(sel))
	}
	t.Logf("unregistered peer uses intra-region classification; empty topology selected no peers")
}

// TestT_OOB_RACE runs concurrent sweeps and peer-map snapshots on two connected
// gossipers. The harness completes its dials before auto-reconciliation is
// enabled, so this test exercises steady-state access rather than a concurrent
// re-key. Publish and Peers read ps.peers while independent sweeps run.
//
// The real receivers and gossipers serialize writes per peer and allow the read
// loops to shut down cleanly. Run with -race to check these accesses.
func TestT_OOB_RACE(t *testing.T) {
	// Both peers are in region 1; this test exercises concurrent peer-map access
	// rather than inter-region selection.
	h := newRegionFanoutHarness(t, true, RegionTag(1), RegionTag(1))
	// The harness has already dialed with real node IDs. Enable reconciliation
	// for subsequent dials; these rounds exercise steady-state read paths.
	h.psA.SetAutoReconcile(true)
	h.psB.SetAutoReconcile(true)
	defer h.close()

	// Give each sweep a modest set of events to ship.
	h.insertEvents(t, 100)

	// Reconciliation finished during setup. These rounds exercise steady-state
	// Publish, Peers, and Select access; the race detector checks their reads of
	// ps.peers.
	const rounds = 5
	for round := 0; round < rounds; round++ {
		h.topoA.SetSeed(uint64(round) + 1)
		h.topoB.SetSeed(uint64(round) + 1)
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); h.gA.AntiEntropySweep(h.ctx) }()
		go func() { defer sweepWG.Done(); h.gB.AntiEntropySweep(h.ctx) }()
		// Add concurrent read-lock snapshots alongside the sweeps.
		go func() { defer sweepWG.Done(); _ = h.psA.Peers(); _ = h.psB.Peers() }()
		sweepWG.Add(1) // account for the Peers goroutine
		sweepWG.Wait()
	}
	t.Logf("completed %d rounds of concurrent sweeps and peer snapshots", rounds)
}

// dialLeafTLS serves leaf on a loopback TLS listener and returns the client
// connection after its handshake. ConnectionState then exposes the server
// certificate whose Common Name reconcilePeerID must decode.
func dialLeafTLS(t *testing.T, leaf *crypto.Leaf) *tls.Conn {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath, err := leaf.WritePEM(filepath.Join(dir, "leaf"))
	if err != nil {
		t.Fatalf("dialLeafTLS: WritePEM: %v", err)
	}
	// Load the leaf into a tls.Certificate for the listener.
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("dialLeafTLS: LoadX509KeyPair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dialLeafTLS: tls.Listen: %v", err)
	}
	// Accept + complete the server handshake in a goroutine.
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Drain briefly so the dialer's read does not get an immediate EOF
		// before ConnectionState is populated; then close.
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		_ = c.Close()
	}()
	// This helper tests Common Name decoding rather than certificate chain
	// verification. Skipping verification also permits the deliberately invalid
	// Common Name used by the negative control.
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, // This test reads the CN; certificate verification is covered elsewhere.
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dialLeafTLS: dialer.Dial: %v", err)
	}
	_ = ln.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("dialLeafTLS: dialer.Dial returned %T, want *tls.Conn", conn)
	}
	// Force the handshake on the dial side so ConnectionState is populated.
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("dialLeafTLS: Handshake: %v", err)
	}
	return tlsConn
}

// reconnectHealDialer creates a fresh loopback TLS listener for each Dial and
// retains the accepted server connections. Closing one simulates a peer dropping
// without calling ClosePeer; the next Dial represents the peer returning.
// Loopback TLS provides the *tls.Conn required by PeerSet, unlike net.Pipe.
type reconnectHealDialer struct {
	t       *testing.T
	leaf    *crypto.Leaf
	mu      sync.Mutex
	accepts []net.Conn // the server-side accepted conns (the test closes to drop)
}

func (d *reconnectHealDialer) Dial(network, addr, serverName string) (*tls.Conn, error) {
	d.t.Helper()
	dir := d.t.TempDir()
	certPath, keyPath, err := d.leaf.WritePEM(filepath.Join(dir, "leaf"))
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	// Complete the server handshake explicitly; Accept returns a TLS connection
	// whose handshake is lazy. Then block in Read so the connection stays live
	// until either side closes it. Closing the server side also gives the client
	// readLoop an EOF, exercising the ordinary disconnect path.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			ln.Close()
			return
		}
		tc, ok := c.(*tls.Conn)
		if !ok {
			_ = c.Close()
			return
		}
		if herr := tc.Handshake(); herr != nil {
			_ = tc.Close()
			return
		}
		accepted <- tc
		// Hold the accepted connection open until EOF or the read deadline.
		_ = tc.SetReadDeadline(time.Now().Add(60 * time.Second))
		buf := make([]byte, 1)
		_, _ = tc.Read(buf) // blocks until EOF (the drop) or the 60s deadline
		_ = tc.Close()
	}()
	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, // This test checks reconnect liveness, not certificate verification.
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
	}}
	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	_ = ln.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("reconnectHealDialer: dialer.Dial returned %T, want *tls.Conn", conn)
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	// Wait for the server handshake before returning so the test can close the
	// accepted connection.
	select {
	case c := <-accepted:
		d.mu.Lock()
		d.accepts = append(d.accepts, c)
		d.mu.Unlock()
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("reconnectHealDialer: server-side handshake did not complete within 2s")
	}
	return tlsConn, nil
}

// TestT_OOB_RECONNECT_HEALS closes the server side of a live TLS connection and
// waits for the client readLoop to close pc.done and remove the dead peer-map
// entries. ReconnectLoop must then dial a fresh connection and install a new
// peerConn with an open done channel.
//
// The test retains the original peerConn pointer so it can observe the drop after
// map removal. Reusing that pointer as a successful reconnect would fail the
// freshness check, and a Dial implementation that mistakes a dead connection for
// a live one would reach the timeout.
func TestT_OOB_RECONNECT_HEALS(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	if _, err := ca.WriteCAPEM(dir); err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	seedB := make([]byte, ed25519.SeedSize)
	for i := range seedB {
		seedB[i] = 0xBB
	}
	identB, err := NewNodeIdentity(seedB)
	if err != nil {
		t.Fatalf("NewNodeIdentity B: %v", err)
	}
	dirB := t.TempDir()
	leafB, err := ca.IssueLeaf(identHex(identB.NodeID)) // CN is the 32-character node ID.
	if err != nil {
		t.Fatalf("IssueLeaf B: %v", err)
	}
	_ = dirB
	peerNodeID := identB.NodeID

	d := &reconnectHealDialer{t: t, leaf: leafB}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	if err := ps.Dial(context.Background(), "127.0.0.1:9999", "localhost", peerNodeID); err != nil {
		t.Fatalf("initial Dial: %v", err)
	}
	// Both maps must reference the live connection with done still open.
	ps.mu.RLock()
	pc0, ok0 := ps.byAddr["127.0.0.1:9999"]
	pc0peers, ok0peers := ps.peers[peerNodeID]
	ps.mu.RUnlock()
	if !ok0 || pc0 == nil {
		t.Fatalf("after Dial, byAddr entry is missing: ok=%v pc=%v", ok0, pc0)
	}
	if !ok0peers || pc0peers == nil {
		t.Fatalf("after Dial, peers entry is missing: ok=%v pc=%v", ok0peers, pc0peers)
	}
	select {
	case <-pc0.done:
		t.Fatalf("after Dial, peer done channel is already closed")
	default:
	}
	t.Logf("initial Dial installed a live peer in both maps")

	// Close the accepted server connection. The client readLoop then observes EOF,
	// closes pc0.done, removes the dead map entries, and closes its connection.
	// Retain pc0 because the maps no longer contain it after cleanup.
	var dropped net.Conn
	d.mu.Lock()
	if len(d.accepts) > 0 {
		dropped = d.accepts[0]
		d.accepts = d.accepts[1:]
	}
	d.mu.Unlock()
	if dropped == nil {
		t.Fatalf("dialer captured no accepted server connection to close")
	}
	_ = dropped.Close()

	// Wait for both the retained connection's done channel and removal from the
	// address and node-ID maps.
	healDeadline := time.Now().Add(5 * time.Second)
	doneClosed, mapsReaped := false, false
	for time.Now().Before(healDeadline) {
		select {
		case <-pc0.done:
			doneClosed = true
		default:
		}
		ps.mu.RLock()
		_, inAddr := ps.byAddr["127.0.0.1:9999"]
		_, inPeers := ps.peers[peerNodeID]
		ps.mu.RUnlock()
		mapsReaped = !inAddr && !inPeers
		if doneClosed && mapsReaped {
			goto dropped
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("after 5s: pc0.done closed=%v, dead map entries removed=%v", doneClosed, mapsReaped)
dropped:
	t.Logf("readLoop closed the dropped connection and removed both dead map entries")

	// ReconnectLoop finds no live edge after cleanup and establishes a fresh
	// connection within the bounded wait below.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ps.ReconnectLoop(ctx, "127.0.0.1:9999", "localhost", peerNodeID, 50*time.Millisecond, 500*time.Millisecond)

	// A fresh peerConn and open done channel distinguish recovery from retention
	// of the dead pc0.
	healedDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(healedDeadline) {
		ps.mu.RLock()
		pc, ok := ps.byAddr["127.0.0.1:9999"]
		ps.mu.RUnlock()
		if ok && pc != nil && pc != pc0 {
			select {
			case <-pc.done:
				// Keep waiting if the replacement also disconnects.
			default:
				t.Logf("ReconnectLoop installed a fresh live peer connection")
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ReconnectLoop did not install a fresh live peer within 8s after the drop")
}
