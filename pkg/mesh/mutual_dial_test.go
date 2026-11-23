// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Mutual-dial tests for inbound registration and connection cleanup (ADR-0045).
//
// Dial keeps an existing live peer, while an unguarded RegisterInbound can replace
// that peer and close its done channel. ReconnectLoop then dials again, and the
// peer's accept path can repeat the eviction in the other direction. These tests
// reproduce that cycle with two TLS nodes on loopback TCP.
//
// The staggered-boot case covers the opposite requirement: when no live outbound
// connection exists, RegisterInbound must install the inbound connection. The
// churn test also checks that releasing a superseded inbound connection cannot
// close the newer registration.
//
// Run with: go test -run 'TestMutualDial' -race -count=1 ./pkg/mesh/

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"

	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// mutualNode is one real-TCP node: a TLS transport, a listener, a PeerSet.
type mutualNode struct {
	ident *NodeIdentity
	tr    *transport.TLSConnections
	ps    *PeerSet
	ln    interface{ Close() error }
	addr  string
}

// newMutualPair mints two CA-signed real-TCP nodes sharing one mesh CA. It
// returns them plus a per-node dial counter installed via a counting dialer
// wrapper, so the negative-control tests can measure the dial rate (the storm's
// observable).
func newMutualPair(t *testing.T) (a, b *mutualNode, dialsA, dialsB *int64) {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	var ca1, cb1 int64
	mk := func(name string, counter *int64) *mutualNode {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand seed %s: %v", name, err)
		}
		ident, err := NewNodeIdentity(seed)
		if err != nil {
			t.Fatalf("NewNodeIdentity %s: %v", name, err)
		}
		leaf, err := ca.IssueLeaf(identHexMutual(ident.NodeID))
		if err != nil {
			t.Fatalf("IssueLeaf %s: %v", name, err)
		}
		certPath, keyPath, err := leaf.WritePEM(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("WritePEM %s: %v", name, err)
		}
		tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
		if err != nil {
			t.Fatalf("NewTLSTransport %s: %v", name, err)
		}
		return &mutualNode{
			ident: ident,
			tr:    tr,
			ps:    NewPeerSet(&countingDialer{inner: tr, count: counter}, nopFrameSink{}, ident, nil),
		}
	}
	a = mk("mutualA", &ca1)
	b = mk("mutualB", &cb1)
	return a, b, &ca1, &cb1
}

// countingDialer wraps the real TLS dialer and counts every dial that succeeds or
// fails. The storm's observable is the dial rate, so counting at the dialer seam
// (rather than parsing logs) is the measurement.
type countingDialer struct {
	inner *transport.TLSConnections
	count *int64
}

func (d *countingDialer) Dial(network, addr, serverName string) (*tls.Conn, error) {
	atomic.AddInt64(d.count, 1)
	return d.inner.Dial(network, addr, serverName)
}

// identHexMutual is the local hex helper (identHex lives in the AST test file;
// duplicated under a distinct name so this file stays self-contained if that file
// is ever split out).
func identHexMutual(id [16]byte) string { return fmt.Sprintf("%x", id) }

// liveEdgeCount reports how many of ps.peers entries are live (done open). It
// reads ps.mu directly (the precedent peerLiveForTest sets).
func (ps *PeerSet) liveEdgeCountForTest() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	n := 0
	for _, pc := range ps.peers {
		if pc == nil {
			continue
		}
		select {
		case <-pc.done:
		default:
			n++
		}
	}
	return n
}

// doneClosedForTest reports whether the peerConn currently registered for peerID
// has had its done channel closed (i.e. was evicted/killed).
func (ps *PeerSet) doneClosedForTest(peerID [16]byte) (registered bool, closed bool) {
	ps.mu.RLock()
	pc, ok := ps.peers[peerID]
	ps.mu.RUnlock()
	if !ok || pc == nil {
		return false, false
	}
	select {
	case <-pc.done:
		return true, true
	default:
		return true, false
	}
}

// TestMutualDialLiveOutboundNotEvicted runs both dial orders and a simultaneous
// dial. RegisterInbound must decline to replace a live outbound peerConn, leaving
// its done channel open while both nodes retain a publishable edge. Checking done
// directly detects the eviction that would trigger ReconnectLoop; a dial count
// alone could hide it behind unrelated timing.
func TestMutualDialLiveOutboundNotEvicted(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP mutual-dial test (binds loopback ports)")
	}
	for _, order := range []string{"A-then-B", "B-then-A", "simultaneous"} {
		t.Run(order, func(t *testing.T) {
			a, b, _, _ := newMutualPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var wg sync.WaitGroup

			for _, n := range []*mutualNode{a, b} {
				ln, err := n.tr.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen: %v", err)
				}
				n.ln = ln
				n.addr = ln.Addr().String()
				wg.Add(1)
				go runAcceptLoopWithPeerSet(ctx, ln, nopFrameSink{}, nil, &wg, n.ps)
			}
			t.Cleanup(func() {
				cancel()
				_ = a.ln.Close()
				_ = b.ln.Close()
				wg.Wait()
			})

			dialAB := func() error { return a.ps.Dial(ctx, b.addr, "localhost", b.ident.NodeID) }
			dialBA := func() error { return b.ps.Dial(ctx, a.addr, "localhost", a.ident.NodeID) }

			switch order {
			case "A-then-B":
				if err := dialAB(); err != nil {
					t.Fatalf("dial A->B: %v", err)
				}
				time.Sleep(120 * time.Millisecond) // let B's accept loop register A
				if err := dialBA(); err != nil {
					t.Fatalf("dial B->A: %v", err)
				}
			case "B-then-A":
				if err := dialBA(); err != nil {
					t.Fatalf("dial B->A: %v", err)
				}
				time.Sleep(120 * time.Millisecond)
				if err := dialAB(); err != nil {
					t.Fatalf("dial A->B: %v", err)
				}
			case "simultaneous":
				start := make(chan struct{})
				var dw sync.WaitGroup
				dw.Add(2)
				var eAB, eBA error
				go func() { defer dw.Done(); <-start; eAB = dialAB() }()
				go func() { defer dw.Done(); <-start; eBA = dialBA() }()
				close(start)
				dw.Wait()
				if eAB != nil || eBA != nil {
					t.Fatalf("simultaneous dials: A->B=%v B->A=%v", eAB, eBA)
				}
			}
			// Let both accept loops complete their RegisterInbound calls.
			time.Sleep(250 * time.Millisecond)

			// The assertion: neither side's registered edge to its peer may be a
			// closed (killed) conn. Before E1, RegisterInbound evicted the live
			// outbound and closed its done — that is the storm trigger.
			regA, closedA := a.ps.doneClosedForTest(b.ident.NodeID)
			regB, closedB := b.ps.doneClosedForTest(a.ident.NodeID)
			if !regA || !regB {
				t.Fatalf("[%s] mutual-dial setup: A-registers-B=%v B-registers-A=%v; both nodes must register an edge before eviction can be checked", order, regA, regB)
			}
			if closedA || closedB {
				t.Fatalf("[%s] mutual dial closed a live edge: A-to-B closed=%v, B-to-A closed=%v; RegisterInbound must decline replacement when the existing peerConn is live", order, closedA, closedB)
			}
			// Both sides must still have a live publishable edge (the data plane).
			if la, lb := a.ps.liveEdgeCountForTest(), b.ps.liveEdgeCountForTest(); la < 1 || lb < 1 {
				t.Fatalf("[%s] mutual dial left too few live edges: A=%d B=%d, want at least one on each node", order, la, lb)
			}
			t.Logf("[%s] mutual dial preserved live outbound edges: A=%d B=%d",
				order, a.ps.liveEdgeCountForTest(), b.ps.liveEdgeCountForTest())
		})
	}
}

// TestMutualDialStaggeredBoot checks the asymmetric-boot case. A has no outbound
// connection to B, so RegisterInbound must install B's inbound connection rather
// than applying the live-edge decline unconditionally.
func TestMutualDialStaggeredBoot(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP staggered-boot test (binds loopback ports)")
	}
	a, b, _, _ := newMutualPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	// A listens first. B does not listen at all in this test — only B dials A, so
	// A's ps.peers can be populated only by the accept-side RegisterInbound.
	lnA, err := a.tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	a.ln = lnA
	a.addr = lnA.Addr().String()
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, lnA, nopFrameSink{}, nil, &wg, a.ps)
	t.Cleanup(func() { cancel(); _ = lnA.Close(); wg.Wait() })

	if err := b.ps.Dial(ctx, a.addr, "localhost", a.ident.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	// Poll for A's inbound registration.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reg, closed := a.ps.doneClosedForTest(b.ident.NodeID); reg && !closed {
			t.Logf("staggered boot: RegisterInbound installed B's inbound connection because A had no live outbound edge")
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	reg, closed := a.ps.doneClosedForTest(b.ident.NodeID)
	t.Fatalf("staggered boot: after B dialed A, A's inbound registration is registered=%v closed=%v, want true and false; RegisterInbound must accept an inbound peer when no live edge exists", reg, closed)
}

// TestMutualDialChurnRacesRegistration is a churn test for use with the race
// detector. It races Dial and RegisterInbound in both
// directions. After the churn settles, both nodes must still have a live edge.
// This catches both eviction of a live registration and an identity-blind
// ReleaseInbound closing a newer peerConn after its own registration was
// superseded.
func TestMutualDialChurnRacesRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP churn test (binds loopback ports)")
	}
	a, b, dialsA, dialsB := newMutualPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	for _, n := range []*mutualNode{a, b} {
		ln, err := n.tr.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		n.ln = ln
		n.addr = ln.Addr().String()
		wg.Add(1)
		go runAcceptLoopWithPeerSet(ctx, ln, nopFrameSink{}, nil, &wg, n.ps)
	}
	t.Cleanup(func() { cancel(); _ = a.ln.Close(); _ = b.ln.Close(); wg.Wait() })

	const iterations = 12
	for i := 0; i < iterations; i++ {
		start := make(chan struct{})
		var dw sync.WaitGroup
		dw.Add(2)
		go func() { defer dw.Done(); <-start; _ = a.ps.Dial(ctx, b.addr, "localhost", b.ident.NodeID) }()
		go func() { defer dw.Done(); <-start; _ = b.ps.Dial(ctx, a.addr, "localhost", a.ident.NodeID) }()
		close(start)
		dw.Wait()
		time.Sleep(40 * time.Millisecond) // let the accept loops run their registrations
	}
	// Let the last registrations + any accept-goroutine exits settle.
	time.Sleep(400 * time.Millisecond)

	regA, closedA := a.ps.doneClosedForTest(b.ident.NodeID)
	regB, closedB := b.ps.doneClosedForTest(a.ident.NodeID)
	dA, dB := atomic.LoadInt64(dialsA), atomic.LoadInt64(dialsB)
	if !regA || !regB || closedA || closedB {
		t.Fatalf("churn left a dead or missing edge after %d iterations: A-registers-B=%v closed=%v; B-registers-A=%v closed=%v (dials A=%d B=%d); inbound replacement and release must preserve the newer live peerConn",
			iterations, regA, closedA, regB, closedB, dA, dB)
	}
	t.Logf("%d mutual-dial churn iterations preserved live edges in both directions (dials A=%d B=%d)",
		iterations, dA, dB)
}
