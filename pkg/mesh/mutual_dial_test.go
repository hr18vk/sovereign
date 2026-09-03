// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// mutual_dial_test.go — (ADR-0045): the in-process
// falsification test for the MUTUAL-EVICTION storm, written BEFORE the fix.
//
// THE RULE this file exists to satisfy: every root-cause hypothesis gets an
// in-process falsification test BEFORE fix code or silicon. An earlier pass
// violated it — it accepted "ReconnectLoop storm = PRIMARY" as framing, shipped a
// fix against that framing, and spent a 100-node silicon run to learn that
// `mesh: reconnect` = 0 on every node (the ReconnectLoop FAILURE path never
// fired, so the storm was never backoff-shaped). A two-node test would have
// refuted the framing for free.
//
// THE ROOT THIS FILE PINS (byte-verified, the two registration paths are ASYMMETRIC):
//
//	Dial            (peer.go:344-358): select <-existing.done → DEAD: replace
//	                                   default               → LIVE: return nil   ← GUARDED
//	RegisterInbound (peer.go:542-550): evicts ps.peers[real] UNCONDITIONALLY      ← UNGUARDED
//
// RegisterInbound's own comment claims it follows "the SAME discipline Dial uses at
// peer.go:389". That claim is FALSE on the bytes, and making it true is the fix.
//
// THE STORM MECHANISM (what these guards reproduce at 2 nodes):
//  1. A and B dial each other (the colocated boot shape — 34 nodes/host all dial
//     all, so mutual dials are the NORM, not an edge case).
//  2. B's accept loop calls RegisterInbound for A's inbound conn. That
//     UNCONDITIONALLY evicts B's own LIVE outbound peerConn to A and cancels its
//     readLoop → B's pc.done closes.
//  3. B's ReconnectLoop (or the next Dial) sees DEAD → re-dials A immediately. The
//     success path has NO backoff floor, so the re-dial is unthrottled.
//  4. A's accept loop registers that new inbound, evicting A's live outbound → 1.
//     Silicon measured ~700 dials/sec/node sustained for 4 minutes (127,163 dials
//     on one eu-west-1 node for 99 peers).
//
// WHAT MUST NOT BREAK: the asymmetric-graph repair itself. On a STAGGERED boot
// (A up first, its dial to B refused, then B comes up and dials A) A has NO
// outbound conn to B, so RegisterInbound MUST still register — that is the
// asymmetric-graph fix the 100-node cliff needed. TestMutualDialStaggeredBoot
// pins that direction, so the fix cannot pass by simply never registering.
//
// RUN: go test -run 'TestMutualDial' -race -count=1 ./pkg/mesh/

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
// wrapper, so the guards can measure the dial RATE (the storm's observable).
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

// countingDialer wraps the real TLS dialer and counts every dial that SUCCEEDS or
// fails. The storm's observable is the dial RATE, so counting at the dialer seam
// (rather than parsing logs) is the honest measurement.
type countingDialer struct {
	inner *transport.TLSConnections
	count *int64
}

func (d *countingDialer) Dial(network, addr, serverName string) (*tls.Conn, error) {
	atomic.AddInt64(d.count, 1)
	return d.inner.Dial(network, addr, serverName)
}

// identHexMutual is the local hex helper (identHex lives in asymmetric_dial_test.go;
// duplicated under a distinct name so this file stays self-contained if that file
// is ever split out).
func identHexMutual(id [16]byte) string { return fmt.Sprintf("%x", id) }

// liveEdgeCount reports how many of ps.peers entries are LIVE (done open). It
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

// TestMutualDialLiveOutboundNotEvicted is THE RED TEST for.
//
// A and B both listen, then BOTH dial each other. Each side ends up with:
//   - an OUTBOUND peerConn (from its own Dial), and
//   - an inbound conn that its accept loop hands to RegisterInbound.
//
// PRE-(current code): RegisterInbound evicts the live outbound peerConn
// unconditionally → the outbound pc.done CLOSES → RED. That closed done is the
// trigger the ReconnectLoop wakes on, which is the storm's engine.
// POST-: the guard declines registration when a live edge exists → the outbound
// pc.done stays OPEN → GREEN, and the pair still has exactly one live edge per
// direction.
//
// The assertion is on pc.done — the CAUSAL trigger — not on a dial count, because
// a dial count could be held down by unrelated timing. A closed done on a healthy
// conn is unambiguous: something killed a live edge.
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

			// THE ASSERTION: neither side's registered edge to its peer may be a
			// CLOSED (killed) conn. Before the fix, RegisterInbound evicted the live
			// outbound and closed its done — that is the storm trigger.
			regA, closedA := a.ps.doneClosedForTest(b.ident.NodeID)
			regB, closedB := b.ps.doneClosedForTest(a.ident.NodeID)
			if !regA || !regB {
				t.Fatalf("[%s] PREMISE BROKEN: after mutual dials, A-registers-B=%v B-registers-A=%v — both must have SOME edge registered; the guard cannot measure eviction without one", order, regA, regB)
			}
			if closedA || closedB {
				t.Fatalf("[%s] MUTUAL EVICTION (liveness guard NOT APPLIED): after A and B dialed each other, a REGISTERED edge is already CLOSED (A's edge-to-B closed=%v, B's edge-to-A closed=%v). RegisterInbound (peer.go:542-550) evicted a LIVE outbound peerConn and cancelled its readLoop, closing pc.done. That closed done is exactly what the ReconnectLoop wakes on, and the success path has no backoff floor → unthrottled re-dial → the ~700 dials/sec/node ping-pong silicon the run measured (127,163 dials on one node). The fix: mirror Dial's liveness guard (peer.go:344-358) into RegisterInbound — if the existing peerConn is LIVE, do NOT evict and do NOT register; keep serving the conn unregistered.", order, closedA, closedB)
			}
			// Both sides must still have a live publishable edge (the data plane).
			if la, lb := a.ps.liveEdgeCountForTest(), b.ps.liveEdgeCountForTest(); la < 1 || lb < 1 {
				t.Fatalf("[%s] no live edge after mutual dial: A=%d B=%d — the liveness guard must PRESERVE a publishable edge, not suppress connectivity", order, la, lb)
			}
			t.Logf("[%s] GREEN — mutual dial produced NO eviction of a live edge: A's edge-to-B open, B's edge-to-A open, live edges A=%d B=%d. RegisterInbound honored the existing live conn (first-writer-wins-if-live), so no pc.done fired and no ReconnectLoop wake-up storm can start.",
				order, a.ps.liveEdgeCountForTest(), b.ps.liveEdgeCountForTest())
		})
	}
}

// TestMutualDialStaggeredBoot is the ANTI-TAUTOLOGY guard: must NOT be
// implementable by "never register". On a staggered boot A has NO outbound conn to
// B, so B's inbound MUST still be registered into A's ps.peers — that IS the fix
// the asymmetric-graph repair the 100-node cardinality cliff required.
//
// If it were written as an unconditional decline, this test goes RED.
func TestMutualDialStaggeredBoot(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP staggered-boot test (binds loopback ports)")
	}
	a, b, _, _ := newMutualPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	// A listens FIRST. B does not listen at all in this test — only B dials A, so
	// A's ps.peers can be populated ONLY by the accept-side RegisterInbound.
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
	// Poll for A's inbound registration (the inbound edge).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reg, closed := a.ps.doneClosedForTest(b.ident.NodeID); reg && !closed {
			t.Logf("GREEN — staggered boot: A had NO outbound conn to B, so RegisterInbound REGISTERED B's inbound (the accept-symmetry repair). A's edge-to-B is live. The liveness guard declines ONLY when an existing edge is LIVE; it must never suppress this direction.")
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	reg, closed := a.ps.doneClosedForTest(b.ident.NodeID)
	t.Fatalf("ACCEPT-SYMMETRY REGRESSION: after B dialed A (staggered boot — A has NO outbound to B), A's ps.peers[B] registered=%v closed=%v, want registered=true closed=false. The accept loop MUST register an inbound peer when no live edge exists, or the 100-node asymmetric-graph cliff reopens. The liveness guard must decline ONLY against a LIVE existing edge — an unconditional decline breaks the accept-symmetry fix.", reg, closed)
}

// TestMutualDialChurnRacesRegistration is the -race churn guard: N
// iterations racing Dial against RegisterInbound in both orders on the SAME pair.
// It hunts two things at once:
//   - the invariant under contention (no live edge evicted), and
//   - the wrong-kill: ReleaseInbound (peer.go:576-593) closes whatever sits in
//     ps.peers[nodeID] with NO identity check, so an accept goroutine that exits
//     AFTER its registration was superseded closes the NEWER live registrant's
//     done. Churn is what surfaces that.
//
// The assertion is the FINAL state after the churn settles: the pair must still
// hold a live edge in both directions. A wrong-kill leaves a closed done behind.
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
		t.Fatalf("CHURN LEFT A DEAD/MISSING EDGE after %d mutual-dial iterations: A-registers-B=%v closed=%v; B-registers-A=%v closed=%v (dials A=%d B=%d). Either the liveness guard failed under contention (a live edge was evicted) or the wrong-kill refinement fired: ReleaseInbound closes ps.peers[nodeID] with NO identity check, so a superseded accept goroutine's deferred release kills the NEWER live registrant's done. The fix: RegisterInbound returns the installed *peerConn; the accept loop's release binds to THAT pc and closes only if ps.peers[real] == thisPC.",
			iterations, regA, closedA, regB, closedB, dA, dB)
	}
	t.Logf("GREEN — %d churn iterations racing Dial vs RegisterInbound in both directions: both edges still LIVE at rest (A-registers-B open, B-registers-A open; dials A=%d B=%d). No live-edge eviction under contention and no identity-blind release wrong-kill.",
		iterations, dA, dB)
}
