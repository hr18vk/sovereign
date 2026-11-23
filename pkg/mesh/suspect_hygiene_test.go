// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// suspect_hygiene_test.go — the suspect-breaker hygiene tests for the mesh
// write deadline (ADR-0059). The per-frame write deadline, close-on-error, and
// breaker skip are correct and stay intact — these tests pin the two hygiene
// issues caught in the new code:
//
//   Issue 1 (TestSuspectsMap_BoundedAndEvicted + TestSuspectInboundSurvivesRedial):
//     the suspects map had no eviction (an unbounded peer-keyed map) and keyed
//     the inbound edge by its ephemeral RemoteAddr, so every inbound reconnect
//     minted a fresh permanent entry and the breaker did not survive the inbound
//     re-dial it exists for. The fix (the (b) resolution, forced by the fact
//     that both sweep iteration sources publish to ps.peers keys, which
//     RegisterInbound installs): key the inbound edge by its cert-derived
//     nodeID, key the outbound edge by its stable configured addr, and evict
//     expired entries on the existing map mutations (markSuspect, Dial,
//     RegisterInbound — never on removeDeadEntry or ClosePeer, which would zero
//     the breaker on the very drop it must survive).
//
//   Issue 2 (the hardened sweep test — in the write deadline test file): the
//     ~40 KB wedge batch only probabilistically exceeded the shrunken kernel
//     buffers, causing a flake. This file carries no test for that issue; the
//     hardening (the oversize single-flush batch) is in
//     TestK1_WriteDeadline_SweepSurvivesHalfOpenPeer.
//
// Negative-control discipline: every negative control is negative-control-proven. The
// negative controls are captured on the pre-fix tree (they compile against the
// base — they name no post-fix symbol); the positive-side negative controls use the
// kill switches. Each negative-control capture is a runtime failure carrying
// its own FAIL line, never a compile break.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/receive"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// ── the synchronous inbound-edge harness ───────────────────────────────────
//
// The write-deadline harness wires a background accept loop per node; the suspect-breaker
// hygiene tests need per-cycle control of RegisterInbound and ReleaseInboundConn
// (the leak is minted per inbound reconnect, and the E1 liveness guard declines
// a registration while the previous edge is still live — the test must drive
// the release between cycles). danSyncInbound gives the test goroutine
// synchronous ownership of accept and server-side handshake, so every cycle is
// fully ordered by the test itself.

// danSyncInbound is a synchronous accept+handshake harness: the test owns the
// listener and the accept timing (no background accept loop). sndbuf, when
// > 0, is set on the LISTENER socket via ListenConfig.Control so every
// accepted (server-side) conn inherits it — A's Publish over an inbound edge
// then blocks deterministically against a parked client whose SO_RCVBUF was
// shrunk at dial (the write-deadline wedge behavior, mirrored on the inbound edge).
type danSyncInbound struct {
	ln  net.Listener
	raw net.Listener
}

func danNewInboundListener(t *testing.T, tr *transport.TLSConnections, sndbuf int) *danSyncInbound {
	t.Helper()
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		if sndbuf <= 0 {
			return nil
		}
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, sndbuf)
		})
	}}
	rawLn, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("danNewInboundListener: listen: %v", err)
	}
	t.Cleanup(func() { _ = rawLn.Close() })
	return &danSyncInbound{ln: tls.NewListener(rawLn, tr.ServerConfig()), raw: rawLn}
}

// acceptSync accepts one conn, drives the server half of the TLS handshake,
// and returns the established conn — RegisterInbound is the caller's move
// (the production accept loop's registration, made synchronous for the test).
func (d *danSyncInbound) acceptSync(t *testing.T) *tls.Conn {
	t.Helper()
	c, err := d.ln.Accept()
	if err != nil {
		t.Fatalf("danSyncInbound.acceptSync: accept: %v", err)
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		t.Fatalf("danSyncInbound.acceptSync: accepted conn is %T, want *tls.Conn", c)
	}
	if err := tc.Handshake(); err != nil {
		t.Fatalf("danSyncInbound.acceptSync: server handshake: %v", err)
	}
	return tc
}

// danDialInAsync dials the inbound listener as a client whose leaf CN carries
// nodeID (the identity RegisterInbound decodes — the production self-announce
// path), shrinking SO_RCVBUF to rcvbuf when > 0 (the wedge behavior: a client
// that never reads must not be able to drain a big publish). The raw dial is
// synchronous; the TLS handshake runs on a goroutine so the test goroutine can
// drive the server side (acceptSync) without deadlocking the client half.
// Returns the client conn and a channel carrying the client-side handshake error.
func danDialInAsync(t *testing.T, tr *transport.TLSConnections, addr string, rcvbuf int) (*tls.Conn, <-chan error) {
	t.Helper()
	ch := make(chan error, 1)
	nd := net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		if rcvbuf <= 0 {
			return nil
		}
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvbuf)
		})
	}}
	raw, err := nd.Dial("tcp", addr)
	if err != nil {
		ch <- err
		return nil, ch
	}
	tc := tls.Client(raw, tr.ClientConfig("localhost"))
	go func() { ch <- tc.Handshake() }()
	return tc, ch
}

// danMintClientTransport mints a leaf whose CN is nodeID (the write-deadline recipe:
// IssueLeaf(identHex(id)) — the hex-encoded CN nodeIDFromConn decodes) and
// returns the transport carrying it as the client cert. One per distinct
// inbound identity the test drives.
func danMintClientTransport(t *testing.T, ca *crypto.MeshCA, caPath, dir, name string, nodeID [16]byte) *transport.TLSConnections {
	t.Helper()
	leaf, err := ca.IssueLeaf(identHex(nodeID))
	if err != nil {
		t.Fatalf("danMintClientTransport %s: IssueLeaf: %v", name, err)
	}
	certPath, keyPath, err := leaf.WritePEM(filepath.Join(dir, "leaf_"+name))
	if err != nil {
		t.Fatalf("danMintClientTransport %s: WritePEM: %v", name, err)
	}
	tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("danMintClientTransport %s: NewTLSTransport: %v", name, err)
	}
	return tr
}

// danSuspectsLen reads len(ps.suspects) under the RLock (white-box, in-package;
// the map is written only under ps.mu, and -race demands the read be locked
// even on the test's single-threaded mutation timeline).
func danSuspectsLen(t *testing.T, ps *PeerSet) int {
	t.Helper()
	ps.mu.RLock()
	n := len(ps.suspects)
	ps.mu.RUnlock()
	return n
}

// danSuspectUntil reads one suspect entry's skipUntil under the RLock.
// Returns (value, present).
func danSuspectUntil(t *testing.T, ps *PeerSet, key string) (int64, bool) {
	t.Helper()
	ps.mu.RLock()
	se, ok := ps.suspects[key]
	var v int64
	if ok && se != nil {
		v = se.skipUntil.Load()
	}
	ps.mu.RUnlock()
	return v, ok
}

// TestSuspectsMap_BoundedAndEvicted — the bounded-and-evicted test for
// the suspects map. Drives the real creation sites — M distinct outbound
// dials + N inbound reconnect cycles of one identity (each cycle a fresh
// ephemeral source addr, with the release between cycles so the E1 liveness
// guard admits each new registration) plus the real markSuspect arm path —
// then asserts the map is bounded by the distinct-identity count (never the
// connection count) and that expired entries are evicted on the next map
// mutation (eviction on mutation).
//
// Expected behavior: under the (b) fix, N reconnects of the same nodeID
// collapse to one entry (the cert-derived nodeID key) alongside the M
// outbound configured-addr entries — the bound is distinct identities (here
// 3 + 1 = 4), not the 12 connection cycles. The eviction leg then arms one
// outbound entry with a tiny backoff, lets it expire, performs another
// mutation (markSuspect of a second outbound addr), and asserts the expired
// entry is gone while the live-armed one survives the sweep.
//
// Negative control (pre-fix, captured on base): the addr-keyed no-eviction
// code mints one permanent entry per inbound reconnect (N distinct ephemeral
// addrs) — the bound assertion fails with the connection count, the
// unbounded-map defect.
func TestSuspectsMap_BoundedAndEvicted(t *testing.T) {
	dir := t.TempDir()
	ca, caPath := wedgeNewCA(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Negative control (the fault-injection control): under SOVEREIGN_TEST_FAULT_SUSPECT_EVICT=1 the
	// test runs with the time-based eviction killed, so the eviction check
	// leg fails on demand — the inject proves the eviction assertion is
	// load-bearing, not a tautology.
	if os.Getenv("SOVEREIGN_TEST_FAULT_SUSPECT_EVICT") != "" {
		t.Logf("suspect-bounded negative control armed: disableSuspectEviction=true (expect eviction to fail)")
	}
	// A is a full node (the write-deadline harness): the outbound leg dials through
	// the production transport dialer, the inbound leg uses A's own
	// ServerConfig. A's background accept loop (runAcceptLoop, nil PeerSet)
	// never registers inbound edges, so every suspects mutation is the test's
	// own doing.
	A := wedgeNewNode(t, ca, caPath, dir, "A", nil, nil)
	if os.Getenv("SOVEREIGN_TEST_FAULT_SUSPECT_EVICT") != "" {
		A.ps.disableSuspectEviction.Store(true)
	}

	// M = 3 distinct outbound edges (the stable configured-addr keys).
	trW := danMintClientTransport(t, ca, caPath, dir, "wedge", [16]byte{0x99})
	var wedgeAddr [3]string
	for i := 0; i < 3; i++ {
		// Gateway anchor-pinning (ADR-0068): nil identity — this wedge never
		// answers the connect-time challenge (the test drives suspect-map
		// mutations directly, never data flow toward the wedges; an unverified
		// conn is exactly its shape).
		_, wedgeAddr[i], _ = wedgeNewListener(t, trW, 8192, nil)
		pid := [16]byte{byte(0x40 + i)}
		if err := A.ps.Dial(ctx, wedgeAddr[i], "localhost", pid); err != nil {
			t.Fatalf("suspect-bounded: outbound dial %d to %s: %v", i, wedgeAddr[i], err)
		}
	}

	// The inbound identity P1 + the synchronous listener on A's transport.
	p1 := [16]byte{0xd1, 0xa2, 0x8e, 0x11, 0x03, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	trP1 := danMintClientTransport(t, ca, caPath, dir, "p1", p1)
	inb := danNewInboundListener(t, A.tr, 0) // no shrink: this test never blocks a write

	// danCycle drives one inbound reconnect cycle: a fresh client (a fresh
	// ephemeral source addr) → server accept+handshake → RegisterInbound (the
	// production creation site) → ReleaseInboundConn (the accept loop's
	// deferred release) → close. This is the exact stampede shape the
	// 100-node run logged: "registered inbound peer ~10× at different
	// ephemeral ports".
	danCycle := func(nth int) {
		client, hsCh := danDialInAsync(t, trP1, inb.raw.Addr().String(), 0)
		sc := inb.acceptSync(t)
		select {
		case e := <-hsCh:
			if e != nil {
				t.Fatalf("suspect-bounded: cycle %d client handshake: %v", nth, e)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("suspect-bounded: cycle %d client handshake stalled", nth)
		}
		real, h := A.ps.RegisterInbound(sc)
		if real != p1 || h == nil {
			t.Fatalf("suspect-bounded: cycle %d RegisterInbound returned (%x, %v), want (%x, handle) — the leaf-CN decode or the install broke", nth, real, h, p1)
		}
		A.ps.ReleaseInboundConn(real, h)
		_ = sc.Close()
		_ = client.Close()
	}

	// The bound: distinct identities = 3 outbound addrs + P1 = 4. The connection
	// count is 12 by the end — the map must never track it.
	const distinct = 4
	for i := 0; i < 8; i++ {
		danCycle(i)
	}
	n8 := danSuspectsLen(t, A.ps)
	if n8 > distinct {
		t.Fatalf("suspect-bounded: after 8 inbound reconnect cycles of one identity + 3 outbound peers, len(suspects)=%d exceeds the distinct-identity bound %d — the map is keyed by connection address rather than peer identity", n8, distinct)
	}
	for i := 8; i < 12; i++ { // 4 more cycles: the map must not grow with N
		danCycle(i)
	}
	n12 := danSuspectsLen(t, A.ps)
	if n12 > distinct {
		t.Fatalf("suspect-bounded: after 12 reconnect cycles len(suspects)=%d still exceeds the distinct-identity bound %d — the map grows with connection count rather than identity count", n12, distinct)
	}

	// Eviction on mutation: arm wedgeAddr[0] with a tiny backoff,
	// let the window expire, then mutate the map via markSuspect(wedgeAddr[1])
	// — the expired entry must be gone and the live-armed one must survive.
	A.ps.SetSuspectBackoff(60 * time.Millisecond)
	A.ps.markSuspect(wedgeAddr[0])
	v0, ok0 := danSuspectUntil(t, A.ps, wedgeAddr[0])
	if !ok0 || v0 <= time.Now().UnixNano() {
		t.Fatalf("suspect-bounded: markSuspect(%s) did not arm a live entry (present=%v skipUntil=%d)", wedgeAddr[0], ok0, v0)
	}
	time.Sleep(90 * time.Millisecond) // the window expires (never a permanent skip)
	A.ps.markSuspect(wedgeAddr[1])    // the mutation that must sweep the expired entry
	v0b, ok0b := danSuspectUntil(t, A.ps, wedgeAddr[0])
	if ok0b {
		t.Fatalf("suspect-bounded: the expired entry %s (skipUntil=%d, now=%d) survived the markSuspect mutation — expired entries must be evicted", wedgeAddr[0], v0b, time.Now().UnixNano())
	}
	v1, ok1 := danSuspectUntil(t, A.ps, wedgeAddr[1])
	if !ok1 || v1 <= time.Now().UnixNano() {
		t.Fatalf("suspect-bounded: the live-armed entry %s did not survive the eviction sweep (present=%v skipUntil=%d) — the sweep evicted a live entry", wedgeAddr[1], ok1, v1)
	}
	t.Logf("suspect-bounded: len(suspects)=%d after 8 cycles, %d after 12 (the distinct-identity bound is %d, never the 12-conn count); eviction: the expired %s entry was evicted on the markSuspect mutation, the live-armed %s entry survived", n8, n12, distinct, wedgeAddr[0], wedgeAddr[1])
}

// TestSuspectInboundSurvivesRedial — the inbound suspect survival test
// (the breaker-survival test, the inbound direction the (b) keying exists for).
// A peer P dials into A (the inbound-resolved edge the sweep publishes to —
// both sweep iteration sources target ps.peers keys, which RegisterInbound
// installs). A's big publish to P times out on the wedged client (shrunk
// buffers on both sides — the write-deadline wedge behavior mirrored onto the
// inbound edge) → the breaker arms. P then re-dials (a fresh conn, a fresh
// ephemeral source addr) and the new inbound edge installs. The probe
// publish inside the suspect window must fail-fast with errPeerSuspected — the
// state keyed by the identity stable across the re-dial (the cert-derived
// nodeID) survived it. After the window the probe is a real attempt that
// succeeds on the fresh conn and clears the state (never a permanent skip).
//
// Negative control (pre-fix, captured on base): the pre-fix code keys the
// inbound edge by the ephemeral RemoteAddr, so the re-dial's fresh addr
// carries skipUntil=0 — the probe is not skipped, writes to the parked fresh
// conn, and succeeds: the breaker did not survive the inbound re-dial it
// exists for (the exact asymmetry the defect documents).
func TestSuspectInboundSurvivesRedial(t *testing.T) {
	dir := t.TempDir()
	ca, caPath := wedgeNewCA(t, dir)
	A := wedgeNewNode(t, ca, caPath, dir, "A", nil, nil)
	A.ps.SetWriteTimeout(200 * time.Millisecond)
	A.ps.SetSuspectBackoff(750 * time.Millisecond)
	// Negative control (the fault-injection control): under SOVEREIGN_TEST_FAULT_SUSPECT_EVICT=1
	// the breaker is killed, so the inside-window probe after the re-dial is
	// not skipped and the test fails at the errPeerSuspected assertion —
	// the inject proves the survival assertion is load-bearing, not a
	// tautology.
	if os.Getenv("SOVEREIGN_TEST_FAULT_SUSPECT_EVICT") != "" {
		A.ps.disableSuspectBreaker.Store(true)
		t.Logf("suspect-redial negative control armed: disableSuspectBreaker=true (expect inside-window probe to fail)")
	}
	var timeouts int64
	A.ps.SetWriteTimeoutReporter(func() { atomic.AddInt64(&timeouts, 1) })
	p1 := [16]byte{0xe1, 0xa2, 0x8e, 0x11, 0x03, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	trP1 := danMintClientTransport(t, ca, caPath, dir, "p1", p1)
	// SNDBUF 8192 on the LISTENER (accepted server-side conns inherit it) +
	// SO_RCVBUF 8192 on every client dial: ~32 KB total against the 256 KiB
	// arming publish → a deterministic block, never a borderline buffer-fit
	// (the write-deadline hardening lesson applied to this harness from the start).
	inb := danNewInboundListener(t, A.tr, 8192)

	// dialCycle: P re-dials in (the client PARKS — never reads: the wedge),
	// the server side handshakes + installs the inbound edge via the
	// production RegisterInbound path.
	dialCycle := func() (*tls.Conn, *tls.Conn, *PeerConnHandle) {
		client, hsCh := danDialInAsync(t, trP1, inb.raw.Addr().String(), 8192)
		sc := inb.acceptSync(t)
		select {
		case e := <-hsCh:
			if e != nil {
				t.Fatalf("suspect-redial: client handshake: %v", e)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("suspect-redial: client handshake stalled")
		}
		real, h := A.ps.RegisterInbound(sc)
		if real != p1 || h == nil {
			t.Fatalf("suspect-redial: RegisterInbound returned (%x, %v), want (%x, handle)", real, h, p1)
		}
		return client, sc, h
	}

	// Cycle 1: the arming write. The 256 KiB publish to the wedged inbound edge
	// blocks (the ~32 KB shrunken buffers) and the 200 ms deadline fires — the
	// breaker arms on a genuine write timeout: the real write-deadline path, never a
	// synthetic state poke.
	client1, sc1, h1 := dialCycle()
	big := receive.LengthPrefixFrame(make([]byte, 256<<10))
	stArm := time.Now()
	armErr := A.ps.Publish(p1, big)
	elArm := time.Since(stArm)
	if armErr == nil || elArm < 100*time.Millisecond {
		t.Fatalf("suspect-redial: the arming 256 KiB write to the wedged inbound edge did not genuinely block+timeout (err=%v elapsed=%v)", armErr, elArm)
	}
	if elArm > time.Second {
		t.Fatalf("suspect-redial: the arming timeout took %v — expected ~200 ms deadline", elArm)
	}
	var ne net.Error
	if !errors.As(armErr, &ne) || !ne.Timeout() {
		t.Fatalf("suspect-redial: the arming write error is not a timeout: %v (deadline 200 ms, elapsed %v)", armErr, elArm)
	}
	if got := atomic.LoadInt64(&timeouts); got < 1 {
		t.Fatalf("suspect-redial: the write-timeout reporter fired %d times, want >=1 — write-deadline event was not reported", got)
	}
	// The production accept loop's deferred release, driven by the test: the
	// conn is dead (close-on-error hard-aborted it), so the edge must drop
	// before the re-dial can install a fresh one.
	A.ps.ReleaseInboundConn(p1, h1)
	_ = sc1.Close()
	_ = client1.Close()

	// Cycle 2: the re-dial — a fresh conn from a fresh ephemeral source
	// addr. The parked client never reads (the wedge holds; test-only leak at
	// exit, the wedgeNewListener pattern). The trio is retained until the
	// test ends (the trailing uses keep them live): a discarded value is a
	// dead stack slot, and the next GC finalizes the conns — the
	// GC-finalizer-close class the wedgeNewListener retention fix
	// documents (strace-proven at GOMAXPROCS=2/8: the finalizer's close()
	// was the only FIN/RST sender in the process).
	client2, sc2, h2 := dialCycle()

	// The probe inside the suspect window: the identity-keyed state must have
	// survived the re-dial → the publish fail-fasts and ~d is never paid twice.
	stSkip := time.Now()
	skipErr := A.ps.Publish(p1, receive.LengthPrefixFrame([]byte("dan-redial-probe")))
	elSkip := time.Since(stSkip)
	if !errors.Is(skipErr, errPeerSuspected) {
		t.Fatalf("suspect-redial: the inside-window probe after the re-dial did not fail-fast errPeerSuspected (err=%v elapsed=%v) — suspect state must survive reconnects", skipErr, elSkip)
	}
	if elSkip >= 60*time.Millisecond {
		t.Fatalf("suspect-redial: the inside-window skip took %v — not fail-fast (want <60 ms)", elSkip)
	}
	// Post-window: the probe is a real re-probe attempt — it must succeed on
	// the fresh conn (a ~20 B probe fits the shrunk buffers) and clear the
	// state. Never a permanent skip.
	time.Sleep(850 * time.Millisecond)
	postErr := A.ps.Publish(p1, receive.LengthPrefixFrame([]byte("dan-redial-probe-2")))
	if postErr != nil {
		t.Fatalf("suspect-redial: the post-window re-probe on the fresh conn failed: %v — peer must recover after suspect window", postErr)
	}
	// The clear-on-success: no entry may remain armed for the future.
	A.ps.mu.RLock()
	for k, se := range A.ps.suspects {
		if se != nil && se.skipUntil.Load() > time.Now().UnixNano() {
			v := se.skipUntil.Load()
			A.ps.mu.RUnlock()
			t.Fatalf("suspect-redial: the suspect key %q remains armed (skipUntil=%d) after successful post-window probe", k, v)
		}
	}
	A.ps.mu.RUnlock()
	// The GC-finalizer retention uses (see the cycle-2 comment): these keep
	// the parked trio reachable for the whole test — removing them re-opens
	// the finalizer-close flake.
	_ = client2
	_ = sc2
	_ = h2
	t.Logf("suspect-redial: arming timeout at %v (reporter=%d) → re-dial from fresh ephemeral → inside-window probe fail-fasted in %v → post-window probe succeeded and cleared state", elArm, atomic.LoadInt64(&timeouts), elSkip)
}
