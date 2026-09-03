// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// review_guards_test.go — POST-REVIEW guards. Each test
// pins one adversarial-review finding's honest behavior; each is RED against
// the pre-fix tree and GREEN after its fix commit.
//
//	go test -run 'Test(Decline|ClosePeer|RetainBatch|CommitInFlight|CacheStatsNil|RetainOwnership|LiveReconnectEdge)' -count=1 -v ./pkg/mesh/

import (
	"bytes"
	"crypto/tls"
	"reflect"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/receive"
)

// ── Finding #3 (peer.go): an DECLINE must not wrong-kill the live edge ──
//
// RegisterInbound declines when a LIVE edge already exists and returns
// (nodeID, nil). The accept loop's deferred ReleaseInboundConn(nodeID, nil)
// then bypasses the identity guard (mine == nil) and closeDones the LIVE
// registration the declining goroutine never owned. The guard: two inbound
// conns from the same peer; the second is declined; releasing the SECOND
// must leave the FIRST registration's done OPEN.
func TestDeclineMustNotWrongKill(t *testing.T) {
	a, b, _, _ := newMutualPair(t)
	lnA, err := a.tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer lnA.Close()

	// Accept loop: surface each server-side *tls.Conn to the test so the test
	// drives RegisterInbound itself (deterministic ordering, no race with a
	// serving goroutine).
	acceptCh := make(chan *tls.Conn, 4)
	go func() {
		for {
			c, err := lnA.Accept()
			if err != nil {
				return
			}
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				continue
			}
			acceptCh <- tc
		}
	}()

	var clientConns []*tls.Conn // the dial-side ends must stay OPEN (closing one drops the server-side conn)
	defer func() {
		for _, c := range clientConns {
			_ = c.Close()
		}
	}()
	dialInbound := func() *tls.Conn {
		conn, err := b.tr.Dial("tcp", lnA.Addr().String(), "localhost")
		if err != nil {
			t.Fatalf("dial B->A: %v", err)
		}
		clientConns = append(clientConns, conn)
		select {
		case tc := <-acceptCh:
			return tc
		case <-time.After(5 * time.Second):
			t.Fatal("accept loop did not surface the inbound conn")
			return nil
		}
	}

	// First inbound conn: nothing registered yet → REGISTERED (the accept-symmetry repair).
	tc1 := dialInbound()
	idB, h1 := a.ps.RegisterInbound(tc1)
	if h1 == nil {
		t.Fatalf("first inbound registration was declined — the accept-symmetry repair is broken (idB=%x)", idB)
	}
	if reg, closed := a.ps.doneClosedForTest(idB); !reg || closed {
		t.Fatalf("after first RegisterInbound: registered=%v closed=%v, want true/false", reg, closed)
	}

	// Second inbound conn from the SAME peer: the first is LIVE → DECLINES.
	tc2 := dialInbound()
	idB2, h2 := a.ps.RegisterInbound(tc2)
	if h2 != nil {
		t.Fatalf("second inbound registration should have been declined by the liveness guard (h2 != nil)")
	}

	// The decline's deferred release — the exact call main.go:1620 /
	// gossip_test.go:360 make. It must NOT kill the first (live) registration.
	a.ps.ReleaseInboundConn(idB2, h2)
	if reg, closed := a.ps.doneClosedForTest(idB); !reg || closed {
		t.Fatalf("WRONG-KILL (finding #3): releasing the declined registration closed the LIVE edge (registered=%v closed=%v). The decline returns (nodeID, nil); ReleaseInboundConn's `mine != nil` guard is bypassed when mine==nil, so closeDone fired on an edge this goroutine never owned.", reg, closed)
	}
	_ = tc1.Close()
	_ = tc2.Close()
}

// ── Finding #2 (peer.go): ClosePeer must not deadlock on an INBOUND edge ────
//
// ClosePeer deletes ps.peers[peerID] then blocks on <-pc.done. An inbound
// peerConn has NO readLoop and cancelReader == nil; its only done-closer is
// the accept loop's deferred ReleaseInboundConn, which early-returns because
// the map entry is already deleted — so done never closes and ClosePeer hangs
// forever. The guard registers an inbound edge with no serving goroutine (the
// starkest form: nothing will EVER close done) and requires ClosePeer to
// return.
func TestClosePeerMustNotDeadlockOnInbound(t *testing.T) {
	a, b, _, _ := newMutualPair(t)
	lnA, err := a.tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer lnA.Close()
	acceptCh := make(chan *tls.Conn, 1)
	go func() {
		c, err := lnA.Accept()
		if err != nil {
			return
		}
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			return
		}
		acceptCh <- tc
	}()
	if _, err := b.tr.Dial("tcp", lnA.Addr().String(), "localhost"); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	var tc *tls.Conn
	select {
	case tc = <-acceptCh:
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop did not surface the inbound conn")
	}
	idB, h := a.ps.RegisterInbound(tc)
	if h == nil {
		t.Fatalf("inbound registration declined unexpectedly (idB=%x)", idB)
	}

	done := make(chan error, 1)
	go func() { done <- a.ps.ClosePeer(idB) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ClosePeer returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("DEADLOCK (finding #2): ClosePeer on an INBOUND-registered peerConn blocked >5s — it deletes the map entry, then waits on a done nobody closes (no readLoop; the accept loop's release early-returns on the deleted entry). Fix: ClosePeer must closeDone() itself after conn.Close() (the sync.Once makes it idempotent for outbound peerConns whose readLoop also closes done).")
	}
}

// ── Finding #6 (gossip.go): a 0-dot batch must not be retained ──────────────
//
// retainBatch stores the forward frame BEFORE the dot loop; with an empty
// dotCounters the loop never runs, so no refcount and no reverse entry exist —
// the frame is unreachable AND never freed (the GC frees only ref-counted
// frames). A 0-dot batch can never be resolved by lookupBatch (the lookup keys
// on dotCounters), so storing it is unambiguously dead weight.
func TestRetainBatchSkipsEmptyDots(t *testing.T) {
	rc := newRelayCache()
	origin := [16]byte{0xB}
	rc.retainBatch(origin, 7, nil, make([]byte, 512))
	fwd, rev := rc.batchLenForTest()
	if fwd != 0 || rev != 0 {
		t.Fatalf("0-dot batch retained: forward=%d reverse=%d, want 0/0 — the refcount can never free a frame no dot points at (finding #6)", fwd, rev)
	}
	g := &Gossiper{relay: rc, cache: newPayloadCache()}
	cs := g.CacheStats()
	if cs.RelayBatchForwardBytes != 0 {
		t.Fatalf("0-dot batch grew the byte counter: %d, want 0 (the E‴ arithmetic must not count dead weight)", cs.RelayBatchForwardBytes)
	}
}

// ── Finding #13 (gossip.go): commitInFlight's cache-line isolation ──────────
//
// The field comment claims a 128-byte stride with "no other field shares the
// line pair". The compiler's layout puts commitInFlight at offset 112 — inside
// the 64-byte line [64,128) shared with sweepRound/sweepEnvCache/batchSeq/
// bridge. The guard pins the honest invariant: the contended atomic must START
// a 64-byte line AND no other field may live within its 128-byte stride.
func TestCommitInFlightCacheLineIsolation(t *testing.T) {
	type fieldSpan struct{ off, size uintptr }
	spans := map[string]fieldSpan{}
	rt := reflect.TypeOf(Gossiper{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		spans[f.Name] = fieldSpan{f.Offset, f.Type.Size()}
	}
	cf, ok := spans["commitInFlight"]
	if !ok {
		t.Fatal("Gossiper.commitInFlight not found")
	}
	if cf.off%64 != 0 {
		t.Fatalf("commitInFlight at offset %d shares its 64-byte line [%d,%d) with its lower neighbors (finding #13) — the comment claims 128-byte isolation the layout does not deliver", cf.off, cf.off/64*64, cf.off/64*64+64)
	}
	// No other field may intersect [cf, cf+128) — the 128-byte stride the
	// comment promises (Graviton adjacent-line prefetcher). The blank `_`
	// padding fields ARE the isolation mechanism, not violators — skip them.
	for name, span := range spans {
		if name == "commitInFlight" || name == "_" {
			continue
		}
		if span.off < cf.off+128 && span.off+span.size > cf.off {
			t.Fatalf("field %s at [%d,%d) intersects commitInFlight's 128-byte stride [%d,%d)", name, span.off, span.off+span.size, cf.off, cf.off+128)
		}
	}
}

// ── Finding #15 (gossip.go): CacheStats must survive a struct-literal ───────
//
// convergence_metric_test.go builds &Gossiper{...} directly (bypassing
// NewGossiper), leaving the caches nil. The /debug/memstats handler calls
// CacheStats unconditionally — a nil cache deref there panics the SCRAPE of a
// running node.
func TestCacheStatsNilCaches(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CacheStats panicked on a struct-literal Gossiper (nil caches): %v (finding #15)", r)
		}
	}()
	cs := (&Gossiper{}).CacheStats()
	if cs != (CacheStats{}) {
		t.Fatalf("zero-caches Gossiper must report the zero CacheStats, got %+v", cs)
	}
}

// ── Finding #14 (gossip.go + receiver.go): the no-copy ownership premise ────
//
// retain/retainBatch now TAKE the slice (no copy). That is sound ONLY because
// FrameReader.ReadFrame returns a fresh per-frame buffer (receiver.go:486
// `out := make([]byte, frameLen)`). The guard pins the premise END-TO-END:
// frame 1 is retained, frame 2 is read through the SAME FrameReader, and the
// retained bytes must still equal frame 1's content. A buffer-reuse
// regression in ReadFrame fails this guard, which is exactly the failure the
// old copy was (mis)built to defend against.
func TestRetainOwnershipPremise(t *testing.T) {
	f1 := bytes.Repeat([]byte{0xA5}, 4096)
	f2 := bytes.Repeat([]byte{0x5A}, 4096)
	stream := append(receive.LengthPrefixFrame(f1), receive.LengthPrefixFrame(f2)...)
	fr := receive.NewFrameReader(bytes.NewReader(stream))

	r1, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 1: %v", err)
	}
	rc := newRelayCache()
	origin := [16]byte{0xC}
	rc.retain(origin, 1, r1) // no-copy store: the cache now holds r1's array

	r2, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 2: %v", err)
	}
	if !bytes.Equal(r2, f2) {
		t.Fatal("frame 2 content mismatch (the fixture itself is broken)")
	}
	got, ok := rc.lookup(origin, 1)
	if !ok {
		t.Fatal("the retained frame is missing")
	}
	if !bytes.Equal(got, f1) {
		t.Fatalf("OWNERSHIP BROKEN: the retained frame changed after a later ReadFrame — ReadFrame must return a fresh per-frame buffer (the no-copy retain relies on it)")
	}
}

// ── Finding #4 (peer.go): a DEAD byAddr entry must not shadow a LIVE inbound ──
//
// liveReconnectEdge consults byAddr[addr] and falls back to ps.peers[peerID]
// ONLY when the byAddr entry is ABSENT — never when it is present-but-DEAD.
// Natural drops never delete byAddr entries (only ClosePeer does), so a dead
// outbound entry shadows a live inbound edge and ReconnectLoop re-dials into
// an already-connected peer — the colocated churn the recheck was built to
// stop. The guard builds the exact state in-memory: dead byAddr entry + live
// inbound registration.
func TestLiveReconnectEdgeSeesPastDeadByAddr(t *testing.T) {
	pid := [16]byte{0xD}
	dead := &peerConn{addr: "configured-addr:7373", done: make(chan struct{})}
	dead.closeDone() // a natural drop: done closed, the byAddr entry lingers
	live := &peerConn{addr: "127.0.0.1:ephemeral", done: make(chan struct{})}
	ps := &PeerSet{
		byAddr: map[string]*peerConn{"configured-addr:7373": dead},
		peers:  map[[16]byte]*peerConn{pid: live},
	}
	got := ps.liveReconnectEdge("configured-addr:7373", pid)
	if got != live {
		t.Fatalf("finding #4: liveReconnectEdge returned %v with a DEAD byAddr entry shadowing a LIVE inbound edge — ReconnectLoop will re-dial into a live peer (the churn the storm guard was built to stop)", got == nil)
	}
}
