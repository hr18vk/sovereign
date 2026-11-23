// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Tests for the mesh write deadline, close-on-error handling, and the
// address-keyed write-stall suspect breaker. All three operate in
// PeerSet.Publish, through which production mesh writes pass.
//
// Test-only disable switches exercise the failure modes at run time. Timing
// assertions reject both an early return, which means the harness did not block,
// and a late return, which means the mechanism did not bound the write.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// WedgeSndbufDialer dials through a real kernel socket with SO_SNDBUF shrunk
// (net.Dialer.Control), then runs the TLS client handshake — the same shape
// tls.Dial performs in production (transport.TLSConnections.Dial), minus the
// RecordHandshake disclosure. It satisfies the mesh dialer interface. The
// shrink makes the half-open fill deterministic: a frame larger than
// SNDBUF + the wedge's RCVBUF blocks inside netFD.Write instead of sitting
// in a megabyte-scale loopback buffer.
type WedgeSndbufDialer struct {
	tr  *transport.TLSConnections
	buf int
}

func (d *WedgeSndbufDialer) Dial(network, addr, serverName string) (*tls.Conn, error) {
	nd := net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, d.buf)
		})
	}}
	raw, err := nd.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, d.tr.ClientConfig(serverName))
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// wedgeNewCA creates a test CA and writes its PEM.
func wedgeNewCA(t *testing.T, dir string) (*crypto.MeshCA, string) {
	t.Helper()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("wedgeNewCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("wedgeNewCA: WriteCAPEM: %v", err)
	}
	return ca, caPath
}

// wedgeRetainMu and wedgeRetainedConns keep every wedge-parked connection
// reachable for the test binary's lifetime. Without retention, the wedge
// parks its goroutine with `select {}` after the last use of the conn value.
// Go's liveness analysis then marks the stack slot dead, so the *tls.Conn
// (and the net.TCPConn it wraps) becomes unreachable. The next GC runs the
// netFD finalizer, which calls close(fd), sending a FIN (empty receive queue
// — silent pre-sweep edge death) or an RST (publish data sitting unread).
// This flake was root-caused via strace at GOMAXPROCS=2/8 with near-100%
// reproduction and zero shutdown() syscalls in the process — the finalizer's
// close() was the only FIN sender. The GOMAXPROCS dependence is GC pacing,
// not application goroutine scheduling. Retention restores the intended
// contract: the wedge never reads, never closes, and leaks at process exit
// (test-only).
var wedgeRetainMu sync.Mutex

var wedgeRetainedConns = make([]net.Conn, 0, 64)

// wedgeRetain pins a wedge-parked conn for the test-binary lifetime (the
// GC-finalizer close fix above). Cold path; mutex-guarded for the
// multi-listener tests (the bounded test runs 3 wedges concurrently).
func wedgeRetain(c net.Conn) {
	wedgeRetainMu.Lock()
	wedgeRetainedConns = append(wedgeRetainedConns, c)
	wedgeRetainMu.Unlock()
}

// wedgeNewListener builds a real 127.0.0.1 TLS listener whose accepted
// connections complete the TLS handshake and then never read — the half-open
// peer (reachable at the TCP level with kernel ACKs, but the process is
// wedged). SO_RCVBUF is shrunk so the kernel buffers fill deterministically.
// The accept goroutine exits when the listener closes (the test's cleanup).
func wedgeNewListener(t *testing.T, tr *transport.TLSConnections, rcvbuf int, identW *NodeIdentity) (net.Listener, string, chan struct{}) {
	t.Helper()
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvbuf)
		})
	}}
	rawLn, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wedgeNewListener: listen: %v", err)
	}
	t.Cleanup(func() { _ = rawLn.Close() })
	ln := tls.NewListener(rawLn, tr.ServerConfig())
	// The client can observe handshake completion before the server's Handshake
	// returns. A publish in that window can reset or skip the edge without ever
	// blocking, so the tests wait for this server-side signal before sweeping.
	// The buffer covers every accepted connection in these tests.
	hsDone := make(chan struct{}, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				var tc *tls.Conn
				if t, ok := c.(*tls.Conn); ok {
					tc = t
					_ = tc.Handshake() // the dialer must succeed; only the read side is dead
				}
				wedgeRetain(c) // without retention the next GC finalizes the conn — see wedgeRetainedConns
				// hsDone means "the server handshake returned" — the answer
				// below must never delay it (the hardened test's race closure
				// depends on the signal's timing); the verify-await covers the
				// answer's landing.
				hsDone <- struct{}{}
				// Answer A's connect-time challenge once, then park. Reading
				// the 57-byte challenge does not drain the flood: the
				// data-plane batch (~1 MB) still wedges in the 8192 sndbuf.
				// The answer is the fixture emulating the responder side of
				// the protocol (a bare TransmitTLSFrame — foreign-code
				// posture, not an engine seam; the engine's own answers go
				// through writeToPC).
				if tc != nil && identW != nil {
					fr := receive.NewFrameReader(tc)
					if frame, err := fr.ReadFrame(); err == nil && IsChallengeFrame(frame) {
						if challengerID, nonce, ok := parseChallengeFrame(frame); ok {
							msg := buildChallengeMsg(nonce, identW.NodeID, challengerID)
							if sig, err := identity.SignCRDTFrame(identW.Seed, msg); err == nil {
								resp := buildChallengeResponseFrame(identW.NodeID, challengerID, nonce, sig)
								_, _ = transport.TransmitTLSFrame(tc, receive.LengthPrefixFrame(resp))
							}
						}
					}
				}
				select {} // the wedge — never read again (leaks at process exit; test-only)
			}(c)
		}
	}()
	return ln, rawLn.Addr().String(), hsDone
}

// k1SwitchAcceptLoop is the dialable-but-sick accept loop for a full node:
// while wedged, an accepted connection completes its handshake and is parked
// forever (never read); once unwedged, later accepts serve normally through
// the production serveTestConn path. Recovery is always a fresh connection —
// the parked connections stay parked (the sticky-fatal behavior forbids
// their reuse).
type WedgeSwitchAcceptLoop struct {
	wedged atomic.Bool
}

func (w *WedgeSwitchAcceptLoop) serve(ctx context.Context, ln net.Listener, recv any, digester DigestSink, ps *PeerSet) {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				if w.wedged.Load() {
					wedgeRetain(c) // same GC-finalizer-close fix as wedgeNewListener
					select {}      // parked: handshake done, never read (test-only)
				}
				serveTestConn(ctx, c, recv, digester, ps)
			}(conn)
		}
	}()
}

// WedgeNode is a full mesh node in the harness shape (engine, gate stack, TLS
// transport, listener, PeerSet, Gossiper). It does not dial anyone and does
// not cross-register pubkeys — each test composes its own topology so the
// negative-control test's shape is visible in the test body.
type WedgeNode struct {
	ident  *NodeIdentity
	engine *eng.DeltaCRDTEngine
	recv   *receive.Receiver
	dir    *identity.Directory
	tr     *transport.TLSConnections
	ln     net.Listener
	ps     *PeerSet
	g      *Gossiper
	addr   string
}

// wedgeNewNode builds a full node from the harness recipe. d selects the PeerSet's
// dialer: nil = the production transport itself; a *WedgeSndbufDialer gets its
// tr backfilled (the shrunk-SNDBUF test dialer). switchLoop, when non-nil,
// replaces the standard accept loop (the recovery test's wedgeable node).
func wedgeNewNode(t *testing.T, ca *crypto.MeshCA, caPath, baseDir, name string, d dialer, switchLoop *WedgeSwitchAcceptLoop) *WedgeNode {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("wedgeNewNode %s: rand seed: %v", name, err)
	}
	ident, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("wedgeNewNode %s: NewNodeIdentity: %v", name, err)
	}
	arenaDir := filepath.Join(baseDir, "eng_"+name)
	if err := os.MkdirAll(arenaDir, 0o755); err != nil {
		t.Fatalf("wedgeNewNode %s: mkdir: %v", name, err)
	}
	engine := newTestEngine(t, ident.NodeID, arenaDir)
	dir := identity.NewDirectory()
	hlcCap := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engine)
	recv := receive.NewReceiver(admission.NewPeerBucket(), hlcCap, clock.NewSystemClock(), dir, engine, 50_000_000)
	leaf, err := ca.IssueLeaf(identHex(ident.NodeID))
	if err != nil {
		t.Fatalf("wedgeNewNode %s: IssueLeaf: %v", name, err)
	}
	certPath, keyPath, err := leaf.WritePEM(filepath.Join(baseDir, "leaf_"+name))
	if err != nil {
		t.Fatalf("wedgeNewNode %s: WritePEM: %v", name, err)
	}
	tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("wedgeNewNode %s: NewTLSTransport: %v", name, err)
	}
	if d == nil {
		d = tr // the production dialer: this node's own TLS transport
	} else if sd, ok := d.(*WedgeSndbufDialer); ok {
		sd.tr = tr // backfill: the test dialer wraps this node's transport
	}
	ln, err := tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wedgeNewNode %s: listen: %v", name, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = ln.Close() })
	ps := NewPeerSet(d, recv, ident, engine)
	g := NewGossiper(ps, ident, engine, dir)
	var wg sync.WaitGroup
	if switchLoop != nil {
		switchLoop.serve(ctx, ln, recv, nil, ps)
	} else {
		wg.Add(1) // runAcceptLoopWithPeerSet's deferred Done must be pre-balanced — an unbalanced Done panics the whole test binary
		// The PeerSet-threaded accept loop — inbound connections register,
		// complete the challenge handshake, and earn egress (nil digester
		// stays; these negative-control tests drive the batch path).
		go runAcceptLoopWithPeerSet(ctx, ln, recv, nil, &wg, ps)
	}
	return &WedgeNode{ident: ident, engine: engine, recv: recv, dir: dir, tr: tr, ln: ln, ps: ps, g: g, addr: ln.Addr().String()}
}

// wedgeCrossRegister registers each node's CRDT-delta pubkey in the other's
// Directory (the pubkey-registration seam — without it the receiver drops frames).
func wedgeCrossRegister(t *testing.T, a, b *WedgeNode) {
	t.Helper()
	if err := a.dir.Register(b.ident.NodeID, b.ident.Pub); err != nil {
		t.Fatalf("wedgeCrossRegister: A<-B: %v", err)
	}
	if err := b.dir.Register(a.ident.NodeID, a.ident.Pub); err != nil {
		t.Fatalf("wedgeCrossRegister: B<-A: %v", err)
	}
}

// k1WedgeTopo is the standard topology for the write-deadline tests: A
// (full node whose PeerSet dials through the shrunk-SNDBUF test dialer),
// the bare half-open wedge W, and optionally a healthy full node C
// cross-registered with A. writeTimeout and suspectBackoff are pre-armed on
// A, and a write-timeout reporter counts into tp.timeouts for the deadline tests.
type WedgeTopo struct {
	A        *WedgeNode
	C        *WedgeNode
	addrW    string
	peerW    [16]byte
	ctx      context.Context
	timeouts int64
	// hsW: the wedge's server-handshake-done signal —
	// one buffered receive per A->W dial. The hardened sweep test waits for
	// it before sweeping, closing the client-early/server-late handshake race
	// the instrumented capture proved.
	hsW chan struct{}
	// identW: W's identity — provisioned for the test so the wedge can sign
	// the connect-time challenge once. A bare 0x77 id could never carry a key,
	// so without this the wedge would never verify and the write deadline
	// would never exercise. W now signs the connect-time challenge once with
	// this identity, then parks; the data-plane write still wedges.
	identW *NodeIdentity
}

func wedgeSetup(t *testing.T, withC bool, writeTimeout, suspectBackoff time.Duration) *WedgeTopo {
	t.Helper()
	dir := t.TempDir()
	ca, caPath := wedgeNewCA(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// W needs a real identity so A can verify its challenge response. The wedge
	// answers that challenge once, then stops reading data-plane writes.
	seedW := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seedW); err != nil {
		t.Fatalf("wedgeSetup: W seed: %v", err)
	}
	identW, err := NewNodeIdentity(seedW)
	if err != nil {
		t.Fatalf("wedgeSetup: W identity: %v", err)
	}
	tp := &WedgeTopo{ctx: ctx, peerW: identW.NodeID, identW: identW}
	tp.A = wedgeNewNode(t, ca, caPath, dir, "A", &WedgeSndbufDialer{buf: 8192}, nil)
	tp.A.ps.SetWriteTimeout(writeTimeout)
	tp.A.ps.SetSuspectBackoff(suspectBackoff)
	tp.A.ps.SetWriteTimeoutReporter(func() { atomic.AddInt64(&tp.timeouts, 1) })
	if err := tp.A.dir.Register(identW.NodeID, identW.Pub); err != nil {
		t.Fatalf("wedgeSetup: register W in A: %v", err)
	}
	leafW, err := ca.IssueLeaf(identHex(tp.peerW))
	if err != nil {
		t.Fatalf("wedgeSetup: IssueLeaf W: %v", err)
	}
	certW, keyW, err := leafW.WritePEM(filepath.Join(dir, "leafW"))
	if err != nil {
		t.Fatalf("wedgeSetup: WritePEM W: %v", err)
	}
	trW, err := transport.NewTLSTransport(certW, keyW, caPath)
	if err != nil {
		t.Fatalf("wedgeSetup: NewTLSTransport W: %v", err)
	}
	_, tp.addrW, tp.hsW = wedgeNewListener(t, trW, 8192, identW)
	if withC {
		tp.C = wedgeNewNode(t, ca, caPath, dir, "C", nil, nil)
		wedgeCrossRegister(t, tp.A, tp.C)
	}
	return tp
}

// TestWriteDeadlineSweepSurvivesHalfOpenPeer publishes to a half-open peer and
// a healthy peer in one serial sweep. The write to the half-open peer must reach
// the 250 ms deadline, and the healthy peer must still converge.
//
// Sixty-four 16 KiB events produce a batch larger than the shrunken socket
// buffers but still fit in one flush. The test waits for both the server-side TLS
// handshake and challenge verification before publishing; otherwise egress gating
// can skip the write without exercising the deadline. A bounded retry uses a fresh
// connection if an early reset prevents a blocking write. At least one attempt
// must invoke the timeout reporter.
func TestWriteDeadlineSweepSurvivesHalfOpenPeer(t *testing.T) {
	tp := wedgeSetup(t, true, 250*time.Millisecond, time.Second)
	payload := strings.Repeat("x", 16*1024)
	for i := 0; i < 64; i++ {
		tp.A.g.InsertLocalEvents(fmt.Sprintf("wedge-%d", i), payload, eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}
	tp.A.g.SetBatchSize(256)
	if bs := tp.A.g.BatchSize(); bs <= 64 {
		t.Fatalf("write-deadline: batch size %d does not exceed 64 events — single-flush shape is broken", bs)
	}
	if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil {
		t.Fatalf("dial A->W (must succeed — the wedge accepts and handshakes): %v", err)
	}
	if err := tp.A.ps.Dial(tp.ctx, tp.C.addr, "localhost", tp.C.ident.NodeID); err != nil {
		t.Fatalf("dial A->C: %v", err)
	}
	// Settle C's challenge handshake before the attempts as well. The sweep's
	// egress gate skips an unverified peer, so publishing before verification
	// could leave C without the batch even after W's deadline fires. C's edge
	// persists across attempts and its verification is monotone per connection.
	awaitVerified(t, tp.A.ps, tp.C.ident.NodeID)
	start := time.Now()
	var reporter int64
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			// A fresh wedge connection per attempt: the fast modes killed
			// the previous edge; Dial's liveness guard re-dials the dead
			// entry. An RST attempt armed the breaker (any write error
			// marks), so clear W's window first — exactly what production
			// expiry does after the backoff elapses (a skip attempt never
			// armed it: no publish error occurred).
			tp.A.ps.mu.Lock()
			if se := tp.A.ps.suspects[tp.addrW]; se != nil {
				se.skipUntil.Store(0)
			}
			tp.A.ps.mu.Unlock()
			if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil {
				t.Fatalf("write-deadline attempt %d re-dial A->W: %v", attempt, err)
			}
		}
		// Close the handshake race the capture proved: wait for this
		// connection's server-side handshake completion before the publish
		// can hit it.
		select {
		case <-tp.hsW:
		case <-time.After(5 * time.Second):
			t.Fatalf("write-deadline: attempt %d: the wedge server handshake never completed", attempt)
		}
		// The W-edge must be challenge-verified before the sweep — the
		// loop-top egress gate ships nothing toward an unverified connection,
		// and a gated attempt never wedges a write: the connection stays
		// live, the next Dial early-returns against the stale entry, and the
		// hsW wait starves (the observed "attempt 2" failure). The wedge
		// answers once (identW); A verifies within ~ms; then the sweep
		// writes.
		verifyDeadline := time.Now().Add(3 * time.Second)
		for !tp.A.ps.egressVerified(tp.peerW) && time.Now().Before(verifyDeadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if !tp.A.ps.egressVerified(tp.peerW) {
			t.Fatalf("write-deadline attempt %d: the W-edge did not verify within 3s — the wedge's one-shot challenge answer did not land; find out why before reporting", attempt)
		}
		attemptStart := time.Now()
		done := make(chan sweepState, 1)
		go func() { done <- tp.A.g.AntiEntropySweep(tp.ctx) }()
		var st sweepState
		select {
		case st = <-done:
		case <-time.After(4 * time.Second):
			t.Fatalf("write-deadline: attempt %d: the sweep is still running after 4s — the wedged peer is parking the serial sweep (the deadline did not bound the write)", attempt)
		}
		el := time.Since(attemptStart)
		if el > 3*time.Second {
			t.Fatalf("write-deadline: attempt %d sweep took %v — the wedged peer cost far more than deadline+slack (250ms)", attempt, el)
		}
		reporter = atomic.LoadInt64(&tp.timeouts)
		tp.A.ps.mu.RLock()
		np := len(tp.A.ps.peers)
		tp.A.ps.mu.RUnlock()
		t.Logf("write-deadline attempt %d/3: sweep bounded at %v (reporter=%d shippedEnvelopes=%d shippedEntries=%d len(ps.peers)=%d)", attempt, el, reporter, st.shippedEnvelopes, st.shippedEntries, np)
		if reporter >= 1 {
			break // the deadline fired — the mechanism was exercised
		}
	}
	if reporter < 1 {
		t.Fatalf("write-deadline: the write-timeout reporter fired 0 times across 3 attempts — the wedge write never blocked (harness-invalid) or the deadline is broken")
	}
	time.Sleep(150 * time.Millisecond) // let C's readLoop apply the batch
	ra, rc := tp.A.engine.State().MerkleRoot(), tp.C.engine.State().MerkleRoot()
	if ra != rc {
		t.Fatalf("write-deadline: the healthy peer did not converge past the wedged one — rootA=%x rootC=%x (head-of-line blocking survived)", ra, rc)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("write-deadline: total %v across attempts — the liveness bound is broken", el)
	}
	t.Logf("write-deadline: deadline exercised (reporter=%d), sweep bounded, healthy peer converged; wedged peer failed fast", reporter)
}

// TestWriteDeadlineNegativeControlNoDeadlineParksSweep disables the write
// deadline and verifies that a batch write to the half-open peer remains blocked
// beyond the test's 3-second watchdog. The opt-in fault test intentionally fails
// at that watchdog to document the behavior without the deadline.
func TestWriteDeadlineNegativeControlNoDeadlineParksSweep(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_WRITE_DEADLINE") == "" {
		t.Skip("write-deadline negative control: runs and fails (by design) only under SOVEREIGN_TEST_FAULT_WRITE_DEADLINE=1 — the capture is evidence, not suite state")
	}
	tp := wedgeSetup(t, true, 250*time.Millisecond, time.Second)
	tp.A.ps.disableWriteDeadline.Store(true) // the disable: base behavior
	payload := strings.Repeat("x", 1024)
	for i := 0; i < 40; i++ {
		tp.A.g.InsertLocalEvents(fmt.Sprintf("wedge-%d", i), payload, eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}
	tp.A.g.SetBatchSize(256)
	if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil {
		t.Fatalf("dial A->W: %v", err)
	}
	if err := tp.A.ps.Dial(tp.ctx, tp.C.addr, "localhost", tp.C.ident.NodeID); err != nil {
		t.Fatalf("dial A->C: %v", err)
	}
	start := time.Now()
	done := make(chan struct{}, 1)
	go func() { tp.A.g.AntiEntropySweep(tp.ctx); done <- struct{}{} }()
	select {
	case <-done:
		t.Fatalf("write-deadline negative control invalid: the sweep completed in %v despite the disabled deadline — the wedged write did not block (harness invalid) or the disable switch is not load-bearing", time.Since(start))
	case <-time.After(3 * time.Second):
		t.Fatalf("write-deadline negative control (expected with the fix disabled): the sweep is still parked after 3s on the wedged peer's deadline-less write — the base ~924.6s retransmit-abort block reproduced via the disable; the negative-control test catches the no-deadline design first-hand")
	}
}

// TestCloseOnErrorStickyFatalForcesFreshConn verifies that a write timeout
// closes the TLS connection, wakes readLoop, and removes the peer entry. Go's TLS
// timeout remains sticky, so recovery requires a fresh connection rather than a
// retry on the same connection. The next Publish fails immediately with "no live
// peer" until that connection is established.
func TestCloseOnErrorStickyFatalForcesFreshConn(t *testing.T) {
	tp := wedgeSetup(t, false, 200*time.Millisecond, time.Second)
	if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil {
		t.Fatalf("dial A->W: %v", err)
	}
	tp.A.ps.mu.RLock()
	pc := tp.A.ps.peers[tp.peerW]
	tp.A.ps.mu.RUnlock()
	if pc == nil {
		t.Fatalf("the wedged peer is not registered in ps.peers")
	}
	big := receive.LengthPrefixFrame(make([]byte, 256<<10))
	start := time.Now()
	err := tp.A.ps.Publish(tp.peerW, big)
	el := time.Since(start)
	if err == nil {
		t.Fatalf("close-on-error: the 256KiB write to the wedge succeeded in %v — the kernel buffers did not fill (harness invalid)", el)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("close-on-error: the write error is not a timeout: %v (deadline %v, elapsed %v)", err, 200*time.Millisecond, el)
	}
	if el > time.Second {
		t.Fatalf("close-on-error: the timeout took %v — nowhere near the 200ms deadline", el)
	}
	select {
	case <-pc.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("close-on-error: pc.done did not close within 2s — close-on-error (F2) did not fire; the readLoop is still parked on a dead conn")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tp.A.ps.mu.RLock()
		_, ok := tp.A.ps.peers[tp.peerW]
		tp.A.ps.mu.RUnlock()
		if !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	tp.A.ps.mu.RLock()
	_, still := tp.A.ps.peers[tp.peerW]
	tp.A.ps.mu.RUnlock()
	if still {
		t.Fatalf("close-on-error: the dead entry was not removed — removeDeadEntry never fired after the close")
	}
	perr := tp.A.ps.Publish(tp.peerW, big)
	if perr == nil || !strings.Contains(perr.Error(), "no live peer") {
		t.Fatalf("close-on-error: the post-drop Publish did not fast-fail 'no live peer': %v", perr)
	}
	if _, werr := pc.conn.Write([]byte("x")); werr == nil {
		t.Fatalf("close-on-error: a write on the closed conn succeeded — the close never happened")
	}
	t.Logf("close-on-error: timeout at %v (deadline 200ms) -> conn closed -> done closed -> entry dropped -> post-drop Publish fast-fails 'no live peer'; a direct write on the kept conn fails instantly (the sticky-fatal proof)", el)
}

// TestCloseOnErrorNegativeControlKeepConnStuck disables connection closure.
// The timed-out TLS connection then retains its permanent error: later writes
// fail immediately, readLoop remains parked, the peer entry remains registered,
// and Dial returns without replacing it. This opt-in fault test intentionally
// fails after demonstrating that the peer cannot recover.
func TestCloseOnErrorNegativeControlKeepConnStuck(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_WRITE_DEADLINE") == "" {
		t.Skip("close-on-error negative control: runs and fails (by design) only under SOVEREIGN_TEST_FAULT_WRITE_DEADLINE=1")
	}
	tp := wedgeSetup(t, false, 200*time.Millisecond, time.Second)
	tp.A.ps.disableCloseOnError.Store(true) // the disable: keep the connection
	if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil {
		t.Fatalf("dial A->W: %v", err)
	}
	tp.A.ps.mu.RLock()
	pc := tp.A.ps.peers[tp.peerW]
	tp.A.ps.mu.RUnlock()
	if pc == nil {
		t.Fatalf("the wedged peer is not registered")
	}
	big := receive.LengthPrefixFrame(make([]byte, 256<<10))
	err := tp.A.ps.Publish(tp.peerW, big)
	if err == nil {
		t.Fatalf("close-on-error negative control invalid: the 256KiB write succeeded — the buffers did not fill")
	}
	select {
	case <-pc.done:
		t.Fatalf("close-on-error negative control invalid: done closed even with close-on-error disabled — the disable switch is not load-bearing")
	case <-time.After(1200 * time.Millisecond):
	}
	st := time.Now()
	_, werr := pc.conn.Write([]byte("x"))
	if werr == nil || time.Since(st) > 500*time.Millisecond {
		t.Fatalf("close-on-error negative control invalid: the kept conn's next write is not an instant sticky failure: err=%v elapsed=%v", werr, time.Since(st))
	}
	if rerr := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); rerr != nil {
		t.Fatalf("close-on-error negative control invalid: the re-dial erred (%v) — expected nil 'already live' (the kept entry blocks it)", rerr)
	}
	perr := tp.A.ps.Publish(tp.peerW, receive.LengthPrefixFrame([]byte("probe")))
	if perr == nil {
		t.Fatalf("close-on-error negative control invalid: a publish on the poisoned conn succeeded")
	}
	t.Fatalf("close-on-error negative control (expected): the kept conn is sticky-fatal (every write returns %v instantly — the tls permanentError) + done never closes + the re-dial is refused 'already live' — the peer is stuck partitioned, the same-conn-retry design this negative-control test exists to catch", werr)
}

// TestRecoveryFreshConnReconverges wedges a peer's accept side, waits for the
// write timeout and connection removal, then re-dials after the peer recovers.
// A publish during the suspect window is skipped; one after the window succeeds,
// clears the suspect state, and allows the mesh to converge. The harness performs
// the re-dial because ReconnectLoop is wired by the command package.
func TestRecoveryFreshConnReconverges(t *testing.T) {
	ca, caPath := wedgeNewCA(t, t.TempDir())
	dir := t.TempDir()
	sw := &WedgeSwitchAcceptLoop{}
	sw.wedged.Store(true)
	A := wedgeNewNode(t, ca, caPath, dir, "A", &WedgeSndbufDialer{buf: 8192}, nil)
	B := wedgeNewNode(t, ca, caPath, dir, "B", nil, sw)
	wedgeCrossRegister(t, A, B)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	A.ps.SetWriteTimeout(150 * time.Millisecond)
	A.ps.SetSuspectBackoff(300 * time.Millisecond)
	if err := A.ps.Dial(ctx, B.addr, "localhost", B.ident.NodeID); err != nil {
		t.Fatalf("dial A->B (must succeed — the wedge accepts + handshakes): %v", err)
	}
	A.ps.mu.RLock()
	pc := A.ps.peers[B.ident.NodeID]
	A.ps.mu.RUnlock()
	if pc == nil {
		t.Fatalf("peer B not registered")
	}
	big := receive.LengthPrefixFrame(make([]byte, 256<<10))
	stPub := time.Now()
	pubErr := A.ps.Publish(B.ident.NodeID, big)
	t.Logf("recovery diag: first publish err=%v elapsed=%v", pubErr, time.Since(stPub))
	if pubErr == nil {
		t.Fatalf("recovery invalid: the wedged write succeeded — the buffers did not fill")
	}
	select {
	case <-pc.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("recovery: done did not close after the timeout — close-on-error did not fire")
	}
	sw.wedged.Store(false) // the peer heals: later accepts serve normally
	if err := A.ps.Dial(ctx, B.addr, "localhost", B.ident.NodeID); err != nil {
		t.Fatalf("the harness re-dial (the probe.Heal precedent) errored: %v", err)
	}
	perr := A.ps.Publish(B.ident.NodeID, receive.LengthPrefixFrame([]byte("probe")))
	if !errors.Is(perr, errPeerSuspected) {
		t.Fatalf("recovery invalid: the probe inside the suspect window did not fast-fail errPeerSuspected: %v", perr)
	}
	time.Sleep(350 * time.Millisecond) // the window expires — never a permanent skip
	if err := A.ps.Publish(B.ident.NodeID, receive.LengthPrefixFrame([]byte("probe"))); err != nil {
		t.Fatalf("recovery: the first write on the fresh conn failed after the window: %v — the peer is stuck partitioned", err)
	}
	se := A.ps.suspects[B.addr]
	if se == nil || se.skipUntil.Load() != 0 {
		t.Fatalf("recovery: the suspect state was not cleared by the successful fresh-conn probe (skipUntil=%v)", se)
	}
	for i := 0; i < 10; i++ {
		A.g.InsertLocalEvents(fmt.Sprintf("rec-%d", i), fmt.Sprintf("v-%d", i), eng.CRDTEntry{SystemTime: int64(1_800_000_000 + i), H3Index: uint64(i)})
	}
	for r := 0; r < 3; r++ {
		A.g.AntiEntropySweep(ctx)
		time.Sleep(50 * time.Millisecond)
	}
	ra, rb := A.engine.State().MerkleRoot(), B.engine.State().MerkleRoot()
	if ra != rb {
		t.Fatalf("recovery: the mesh did not re-converge on the fresh conn — rootA=%x rootB=%x", ra, rb)
	}
	t.Logf("recovery: timeout -> close -> drop -> re-dial -> window skip (bounded) -> fresh-conn probe OK -> suspect cleared -> re-converged")
}

// TestRecoveryNegativeControlKeepConnNeverReconverges disables close-on-error
// throughout a recovery attempt. The retained TLS connection keeps returning its
// sticky error, its done channel remains open, and Dial cannot replace the live
// registry entry. The opt-in fault test intentionally fails after confirming that
// the peer remains partitioned for the full recovery window.
func TestRecoveryNegativeControlKeepConnNeverReconverges(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_WRITE_DEADLINE") == "" {
		t.Skip("recovery negative control: runs and fails (by design) only under SOVEREIGN_TEST_FAULT_WRITE_DEADLINE=1")
	}
	ca, caPath := wedgeNewCA(t, t.TempDir())
	dir := t.TempDir()
	sw := &WedgeSwitchAcceptLoop{}
	sw.wedged.Store(true)
	A := wedgeNewNode(t, ca, caPath, dir, "A", &WedgeSndbufDialer{buf: 8192}, nil)
	B := wedgeNewNode(t, ca, caPath, dir, "B", nil, sw)
	wedgeCrossRegister(t, A, B)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	A.ps.SetWriteTimeout(150 * time.Millisecond)
	A.ps.SetSuspectBackoff(150 * time.Millisecond)
	A.ps.disableCloseOnError.Store(true) // the disable: the conn is kept
	if err := A.ps.Dial(ctx, B.addr, "localhost", B.ident.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	big := receive.LengthPrefixFrame(make([]byte, 256<<10))
	if err := A.ps.Publish(B.ident.NodeID, big); err == nil {
		t.Fatalf("recovery negative control invalid: the wedged write succeeded — the buffers did not fill")
	}
	sw.wedged.Store(false) // the peer heals — but the kept poisoned conn cannot
	deadline := time.Now().Add(1500 * time.Millisecond)
	var lastErr error
	for time.Now().Before(deadline) {
		_ = A.ps.Dial(ctx, B.addr, "localhost", B.ident.NodeID) // refused "already live" while the stale entry lives
		lastErr = A.ps.Publish(B.ident.NodeID, receive.LengthPrefixFrame([]byte("probe")))
		if lastErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr == nil {
		t.Fatalf("recovery negative control invalid: the peer recovered despite close-on-error being disabled — the disable switch is not load-bearing")
	}
	t.Fatalf("recovery negative control (expected): the peer is stuck partitioned for the whole 1.5s window — the timed-out conn is kept (sticky-fatal), done never closes so the re-dial is refused 'already live', and every publish fails with: %v — the no-silent-partition rule the close-on-error design enforces", lastErr)
}

// TestFailFastSkipSuspectSurvivesRedial verifies that the address-keyed suspect
// entry survives peerConn replacement. The first write waits for the deadline;
// the next publish after re-dial returns errPeerSuspected immediately. Once the
// backoff expires, a publish must make a real attempt rather than leaving the
// peer permanently skipped.
func TestFailFastSkipSuspectSurvivesRedial(t *testing.T) {
	tp := wedgeSetup(t, false, 150*time.Millisecond, 750*time.Millisecond)
	if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil {
		t.Fatalf("dial A->W: %v", err)
	}
	big := receive.LengthPrefixFrame(make([]byte, 256<<10))
	st1 := time.Now()
	err1 := tp.A.ps.Publish(tp.peerW, big)
	el1 := time.Since(st1)
	if err1 == nil || el1 < 100*time.Millisecond {
		t.Fatalf("fail-fast invalid: cycle 1 did not genuinely block+timeout (err=%v elapsed=%v)", err1, el1)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) { // wait for the close to drop the entry
		tp.A.ps.mu.RLock()
		_, ok := tp.A.ps.peers[tp.peerW]
		tp.A.ps.mu.RUnlock()
		if !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil { // the re-dial: a fresh peerConn at the same addr
		t.Fatalf("the re-dial errored (the wedge accepts): %v", err)
	}
	st2 := time.Now()
	err2 := tp.A.ps.Publish(tp.peerW, big)
	el2 := time.Since(st2)
	if !errors.Is(err2, errPeerSuspected) {
		t.Fatalf("fail-fast invalid: the cycle-2 publish did not fail-fast errPeerSuspected: %v — the addr-keyed state did not survive the re-dial (a conn-local breaker zeroed it)", err2)
	}
	if el2 >= 60*time.Millisecond {
		t.Fatalf("fail-fast: the cycle-2 skip took %v — not fail-fast (want <60ms; ~d per re-dial is the defect)", el2)
	}
	time.Sleep(800 * time.Millisecond) // the backoff expires — the peer is re-probed (never permanently skipped)
	st3 := time.Now()
	err3 := tp.A.ps.Publish(tp.peerW, big)
	el3 := time.Since(st3)
	if errors.Is(err3, errPeerSuspected) {
		t.Fatalf("fail-fast invalid: post-window publish was still skipped, leaving the peer permanently partitioned")
	}
	if err3 == nil || el3 < 100*time.Millisecond {
		t.Fatalf("fail-fast invalid: the post-window re-probe did not genuinely block+timeout (err=%v elapsed=%v)", err3, el3)
	}
	t.Logf("fail-fast: cycle1 paid d once (%v); cycle2 after re-dial fail-fasted in %v (addr-keyed state survived the peerConn recreation); post-window re-probe genuinely attempted (%v) — never permanent", el1, el2, el3)
}

// TestFailFastSkipNegativeControlNoBreakerPaysDeadlinePerRedial disables the
// suspect breaker and verifies that the publish after re-dial blocks for the full
// deadline again. The opt-in fault test intentionally fails after measuring the
// repeated stall that the address-keyed breaker prevents (ADR-0059).
func TestFailFastSkipNegativeControlNoBreakerPaysDeadlinePerRedial(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_WRITE_DEADLINE") == "" {
		t.Skip("fail-fast negative control: runs and fails (by design) only under SOVEREIGN_TEST_FAULT_WRITE_DEADLINE=1")
	}
	tp := wedgeSetup(t, false, 150*time.Millisecond, 750*time.Millisecond)
	tp.A.ps.disableSuspectBreaker.Store(true) // the disable: no breaker
	if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil {
		t.Fatalf("dial A->W: %v", err)
	}
	big := receive.LengthPrefixFrame(make([]byte, 256<<10))
	if err := tp.A.ps.Publish(tp.peerW, big); err == nil {
		t.Fatalf("fail-fast negative control invalid: cycle 1 did not block+timeout")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tp.A.ps.mu.RLock()
		_, ok := tp.A.ps.peers[tp.peerW]
		tp.A.ps.mu.RUnlock()
		if !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tp.A.ps.Dial(tp.ctx, tp.addrW, "localhost", tp.peerW); err != nil {
		t.Fatalf("the re-dial errored: %v", err)
	}
	st2 := time.Now()
	err2 := tp.A.ps.Publish(tp.peerW, big)
	el2 := time.Since(st2)
	if el2 < 100*time.Millisecond {
		t.Fatalf("fail-fast negative control invalid: the cycle-2 publish fail-fasted (%v, err=%v) despite the disabled breaker — the disable switch is not load-bearing", el2, err2)
	}
	t.Fatalf("fail-fast negative control (expected): the breaker-less cycle-2 publish blocked the deadline again (elapsed %v, err=%v) — without the addr-keyed breaker the sweep pays the deadline every re-dial cycle for a dialable-but-sick peer", el2, err2)
}

// TestHealthyPathDeadlineIsNoOp runs a healthy two-node mesh with a 500 ms
// deadline, well below the 10-second default. The mesh must converge without a
// timeout report or armed suspect. Existing convergence tests with the deadline
// disabled cover the default-off path.
func TestHealthyPathDeadlineIsNoOp(t *testing.T) {
	ca, caPath := wedgeNewCA(t, t.TempDir())
	dir := t.TempDir()
	A := wedgeNewNode(t, ca, caPath, dir, "A", nil, nil)
	B := wedgeNewNode(t, ca, caPath, dir, "B", nil, nil)
	wedgeCrossRegister(t, A, B)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	A.ps.SetWriteTimeout(500 * time.Millisecond) // tight: must still never fire on a healthy mesh
	A.ps.SetSuspectBackoff(time.Second)
	var to int64
	A.ps.SetWriteTimeoutReporter(func() { atomic.AddInt64(&to, 1) })
	if err := A.ps.Dial(ctx, B.addr, "localhost", B.ident.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	if err := B.ps.Dial(ctx, A.addr, "localhost", A.ident.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	for i := 0; i < 200; i++ {
		eid := fmt.Sprintf("healthy-%d", i)
		payload := fmt.Sprintf("value-%d", i)
		entry := eng.CRDTEntry{SystemTime: int64(1_900_000_000 + i), H3Index: uint64(i)}
		if i%2 == 0 {
			A.g.InsertLocalEvents(eid, payload, entry)
		} else {
			B.g.InsertLocalEvents(eid, payload, entry)
		}
	}
	converged := false
	var round int
	for round = 0; round < 10; round++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); A.g.AntiEntropySweep(ctx) }()
		go func() { defer wg.Done(); B.g.AntiEntropySweep(ctx) }()
		wg.Wait()
		// Poll root equality because asynchronous applies can still be in flight
		// when the sweep returns (ADR-0068).
		converged = false
		quit := time.Now().Add(2 * time.Second)
		for time.Now().Before(quit) {
			if A.engine.MerkleRootFromShards() == B.engine.MerkleRootFromShards() {
				converged = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if converged {
			break
		}
	}
	if !converged {
		t.Fatalf("healthy invalid: the healthy mesh did not converge in %d rounds with the deadline armed — the deadline is not a no-op on the healthy path", round)
	}
	if got := atomic.LoadInt64(&to); got != 0 {
		t.Fatalf("healthy: the write-timeout reporter fired %d times on a healthy mesh — the deadline false-fired (the byte-identical happy-path contract is broken)", got)
	}
	se := A.ps.suspects[B.addr]
	if se != nil && se.skipUntil.Load() != 0 {
		t.Fatalf("healthy: a suspect was armed on a healthy peer (skipUntil=%v)", se.skipUntil.Load())
	}
	t.Logf("healthy: converged in %d rounds with the 500ms deadline armed; reporter fired 0; no suspect armed — the happy path is byte-identical", round+1)
}

// TestHealthyNegativeControlFalseFireDeadline sets a 1-nanosecond deadline on
// a healthy connection. The resulting timeout report and publish error show that
// the healthy-path test's zero-report assertion can detect an overeager deadline.
// This opt-in fault test intentionally fails after observing both.
func TestHealthyNegativeControlFalseFireDeadline(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_WRITE_DEADLINE") == "" {
		t.Skip("healthy negative control: runs and fails (by design) only under SOVEREIGN_TEST_FAULT_WRITE_DEADLINE=1")
	}
	ca, caPath := wedgeNewCA(t, t.TempDir())
	dir := t.TempDir()
	A := wedgeNewNode(t, ca, caPath, dir, "A", nil, nil)
	B := wedgeNewNode(t, ca, caPath, dir, "B", nil, nil)
	wedgeCrossRegister(t, A, B)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	A.ps.SetWriteTimeout(time.Nanosecond) // the disable: an absurd deadline false-fires
	A.ps.SetSuspectBackoff(time.Second)
	var to int64
	A.ps.SetWriteTimeoutReporter(func() { atomic.AddInt64(&to, 1) })
	if err := A.ps.Dial(ctx, B.addr, "localhost", B.ident.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	big := receive.LengthPrefixFrame(make([]byte, 256<<10))
	perr := A.ps.Publish(B.ident.NodeID, big)
	got := atomic.LoadInt64(&to)
	if perr == nil || got < 1 {
		t.Fatalf("healthy negative control invalid: the absurd deadline did not false-fire (err=%v reporter=%d) — the control is not load-bearing", perr, got)
	}
	t.Fatalf("healthy negative control (expected): the 1ns deadline false-fired (reporter=%d, publish err=%v) — the healthy negative control's reporter==0 assertion catches exactly this class: a deadline so tight a healthy peer cannot meet it", got, perr)
}

// TestDeadlineMarginLoopbackMaxFrameWrite measures 50 writes of a 256 KiB
// frame on loopback. This frame exceeds the normal batch, digest, and root
// announcement sizes; the reader's 16 MiB limit is a reassembly bound, not a
// writer's normal frame size. The slowest write must remain below one second,
// providing a tenfold margin against the 10-second default. This is not a WAN
// timing measurement.
func TestDeadlineMarginLoopbackMaxFrameWrite(t *testing.T) {
	ca, caPath := wedgeNewCA(t, t.TempDir())
	dir := t.TempDir()
	A := wedgeNewNode(t, ca, caPath, dir, "A", nil, nil)
	B := wedgeNewNode(t, ca, caPath, dir, "B", nil, nil)
	wedgeCrossRegister(t, A, B)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	A.ps.SetWriteTimeout(10 * time.Second) // the production default
	if err := A.ps.Dial(ctx, B.addr, "localhost", B.ident.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	frame := receive.LengthPrefixFrame(make([]byte, 256<<10))
	const iters = 50
	var max, total time.Duration
	for i := 0; i < iters; i++ {
		st := time.Now()
		if err := A.ps.Publish(B.ident.NodeID, frame); err != nil {
			t.Fatalf("deadline margin: publish %d failed on a healthy peer: %v", i, err)
		}
		d := time.Since(st)
		if d > max {
			max = d
		}
		total += d
	}
	if max >= time.Second {
		t.Fatalf("deadline margin: the max 256KiB frame write took %v on loopback — under the 10x-margin floor vs the 10s default (a healthy peer would false-timeout on a degraded link)", max)
	}
	mean := total / iters
	t.Logf("deadline margin: 256KiB frame writes over %d iters: max=%v mean=%v vs the 10s deadline default = a %.0fx margin (layer: in-process loopback, not WAN; the frames are upper bounds over every mesh frame)", iters, max, mean, float64(10*time.Second)/float64(max))
}

// TestSSoT25MeshWriteTimeouts checks the telemetry registry entry for
// MeshWriteTimeouts. It must appear exactly once as a counter, not a gauge, and
// the registry must retain its three existing gauges. Duplicate registration
// would panic the Prometheus bridge during initialization (ADR-0026).
func TestSSoT25MeshWriteTimeouts(t *testing.T) {
	cs := telemetry.Counters()
	found := false
	gauges := 0
	names := make(map[string]int, len(cs))
	for _, c := range cs {
		names[c.Name()]++
		if c.Mode() == telemetry.ModeGauge {
			gauges++
		}
		if c.Name() == "supremum.mesh.write_timeouts" {
			found = true
			if c.Mode() != telemetry.ModeCounter {
				t.Fatalf("MeshWriteTimeouts has mode %v, want modeCounter", c.Mode())
			}
		}
	}
	if !found {
		t.Fatalf("supremum.mesh.write_timeouts is missing from telemetry.Counters() (len=%d)", len(cs))
	}
	if names["supremum.mesh.write_timeouts"] != 1 {
		t.Fatalf("MeshWriteTimeouts appears %d times, want exactly once to avoid duplicate Prometheus registration", names["supremum.mesh.write_timeouts"])
	}
	if gauges != 3 {
		t.Fatalf("telemetry registry has %d gauges, want 3", gauges)
	}
	t.Logf("MeshWriteTimeouts registered once as a counter; %d counters total; gauge count remains 3", len(cs))
}
