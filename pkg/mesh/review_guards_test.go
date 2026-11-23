// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover connection ownership and shutdown, relay retention,
// cache-line layout, and nil-safe statistics.
//
//	go test -run 'TestDeclineMustNotWrongKill|TestClosePeerMustNotDeadlockOnInbound|TestRetainBatchSkipsEmptyDots|TestCommitInFlightCacheLineIsolation|TestCacheStatsNilCaches|TestRetainOwnershipPremise|TestLiveReconnectEdgeSeesPastDeadByAddr' -count=1 -v ./pkg/mesh/

import (
	"bytes"
	"crypto/tls"
	"reflect"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/receive"
)

// TestDeclineMustNotWrongKill checks connection ownership when RegisterInbound
// declines a duplicate edge and returns (nodeID, nil). The accept loop releases
// that declined connection with the same nil handle. ReleaseInboundConn must not
// close the existing registration, which the declining goroutine does not own.
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

	var clientConns []*tls.Conn // closing a dial-side end also closes its server-side connection
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

	// The first inbound connection registers because no edge exists yet.
	tc1 := dialInbound()
	idB, h1 := a.ps.RegisterInbound(tc1)
	if h1 == nil {
		t.Fatalf("first inbound registration was unexpectedly declined (idB=%x)", idB)
	}
	if reg, closed := a.ps.doneClosedForTest(idB); !reg || closed {
		t.Fatalf("after first RegisterInbound: registered=%v closed=%v, want true/false", reg, closed)
	}

	// The second connection is declined while the first remains live.
	tc2 := dialInbound()
	idB2, h2 := a.ps.RegisterInbound(tc2)
	if h2 != nil {
		t.Fatalf("second inbound registration was not declined")
	}

	// Releasing the declined connection must leave the live registration open.
	a.ps.ReleaseInboundConn(idB2, h2)
	if reg, closed := a.ps.doneClosedForTest(idB); !reg || closed {
		t.Fatalf("releasing declined connection closed the live edge: registered=%v closed=%v", reg, closed)
	}
	_ = tc1.Close()
	_ = tc2.Close()
}

// TestClosePeerMustNotDeadlockOnInbound registers an inbound edge without a
// serving goroutine. ClosePeer deletes the map entry and waits for pc.done, so
// it must close that channel itself rather than rely on a read loop or a later
// ReleaseInboundConn call that can no longer find the registration.
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
		t.Fatalf("ClosePeer blocked for more than 5s on an inbound peer with no read loop; ClosePeer must close pc.done after closing the connection")
	}
}

// TestRetainBatchSkipsEmptyDots verifies that a batch without dots allocates no
// relay-cache entries. lookupBatch resolves frames by dot, so such a frame would
// be unreachable and could never be reclaimed by reference counting.
func TestRetainBatchSkipsEmptyDots(t *testing.T) {
	rc := newRelayCache()
	origin := [16]byte{0xB}
	rc.retainBatch(origin, 7, nil, make([]byte, 512))
	fwd, rev := rc.batchLenForTest()
	if fwd != 0 || rev != 0 {
		t.Fatalf("empty-dot batch retained %d forward and %d reverse entries, want zero", fwd, rev)
	}
	g := &Gossiper{relay: rc, cache: newPayloadCache()}
	cs := g.CacheStats()
	if cs.RelayBatchForwardBytes != 0 {
		t.Fatalf("empty-dot batch grew RelayBatchForwardBytes to %d, want 0", cs.RelayBatchForwardBytes)
	}
}

// TestCommitInFlightCacheLineIsolation checks that commitInFlight starts on a
// 64-byte boundary and that no other field intersects its 128-byte stride.
// Nearby fields must not share cache lines with this contended atomic.
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
		t.Fatalf("commitInFlight offset %d is not aligned to a 64-byte cache line; containing line is [%d,%d)", cf.off, cf.off/64*64, cf.off/64*64+64)
	}
	// Adjacent-line prefetching makes a 128-byte stride necessary. Blank
	// padding fields provide the isolation and are excluded from the check.
	for name, span := range spans {
		if name == "commitInFlight" || name == "_" {
			continue
		}
		if span.off < cf.off+128 && span.off+span.size > cf.off {
			t.Fatalf("field %s at [%d,%d) intersects commitInFlight's 128-byte stride [%d,%d)", name, span.off, span.off+span.size, cf.off, cf.off+128)
		}
	}
}

// TestCacheStatsNilCaches constructs a Gossiper directly, bypassing the
// constructor's cache initialization. CacheStats must return zero values rather
// than panic when the memstats handler encounters this shape.
func TestCacheStatsNilCaches(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CacheStats panicked on a Gossiper with nil caches: %v", r)
		}
	}()
	cs := (&Gossiper{}).CacheStats()
	if cs != (CacheStats{}) {
		t.Fatalf("zero-caches Gossiper must report the zero CacheStats, got %+v", cs)
	}
}

// TestRetainOwnershipPremise checks the ownership contract behind no-copy
// retention. FrameReader.ReadFrame allocates a fresh buffer for each frame, so
// reading a second frame through the same reader must not alter retained bytes
// from the first.
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
		t.Fatal("second frame did not match its fixture")
	}
	got, ok := rc.lookup(origin, 1)
	if !ok {
		t.Fatal("the retained frame is missing")
	}
	if !bytes.Equal(got, f1) {
		t.Fatalf("ownership broken: the retained frame changed after a later ReadFrame — ReadFrame must return a fresh per-frame buffer (the no-copy retain relies on it)")
	}
}

// TestLiveReconnectEdgeSeesPastDeadByAddr builds a closed byAddr entry beside
// a live inbound registration for the same peer. liveReconnectEdge must reject
// the dead entry and find the live peer by node ID, preventing ReconnectLoop
// from dialing an already-connected peer.
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
		t.Fatalf("liveReconnectEdge missed the live inbound registration behind a dead byAddr entry: nil=%v", got == nil)
	}
}
