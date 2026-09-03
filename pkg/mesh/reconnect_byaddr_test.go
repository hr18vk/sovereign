// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// reconnect_byaddr_test.go — the ADR-0045 guard: the
// byAddr cardinality bound. RegisterInbound keys byAddr under the peer's
// EPHEMERAL source port, so K reconnections minted K entries and — before the
// fix — nothing ever deleted on a natural close (ClosePeer has zero
// production callers; PeerSet.Close deleted nothing). The bound: byAddr
// tracks LIVE edges; removeDeadEntry (identity-checked) runs on both death
// paths (readLoop exit defer for outbound, ReleaseInboundConn for inbound).

import (
	"fmt"
	"testing"
)

// TestB1_ByAddrBoundedByLiveEdges plants K inbound edges exactly as
// RegisterInbound does (ps.peers by nodeID, ps.byAddr by EPHEMERAL addr — the
// reconnect_storm_test.go planting idiom), then drives the production
// death path (ReleaseInboundConn) for each. The invariant:
// len(ps.byAddr) == live edges — 0 after K releases, K/2 halfway through
// (per-death removal, not a deferred sweep).
//
// RED (fault-injection): delete the removeDeadEntry call from ReleaseInboundConn →
// the K entries leak → the O(K) assertion fires.
func TestB1_ByAddrBoundedByLiveEdges(t *testing.T) {
	const K = 64
	ps := NewPeerSet(nil, nopFrameSink{}, nil, nil)

	type planted struct {
		pc     *peerConn // pointer first (fieldalignment: 8 pointer bytes, not 24)
		nodeID [16]byte
	}
	edges := make([]planted, K)
	ps.mu.Lock()
	for i := range edges {
		var id [16]byte
		id[0] = 0xB1
		id[1] = byte(i + 1) // never the zero nodeID
		pc := &peerConn{
			addr:   fmt.Sprintf("10.9.0.%d:%d", i/256+1, 40000+i), // K DISTINCT ephemeral addrs
			peerID: id,
			done:   make(chan struct{}),
		}
		ps.peers[id] = pc
		ps.byAddr[pc.addr] = pc
		edges[i] = planted{pc, id}
	}
	ps.mu.Unlock()

	ps.mu.RLock()
	got := len(ps.byAddr)
	ps.mu.RUnlock()
	if got != K {
		t.Fatalf("PREMISE: planted %d edges but byAddr holds %d", K, got)
	}

	// Half die: per-death removal must track (not a bulk sweep at the end).
	for i := 0; i < K/2; i++ {
		ps.ReleaseInboundConn(edges[i].nodeID, &PeerConnHandle{pc: edges[i].pc})
	}
	ps.mu.RLock()
	half := len(ps.byAddr)
	ps.mu.RUnlock()
	if half != K/2 {
		t.Fatalf("after %d deaths: len(byAddr)=%d, want %d — removal must be per-death (B1: the map tracks LIVE edges)", K/2, half, K/2)
	}

	for i := K / 2; i < K; i++ {
		ps.ReleaseInboundConn(edges[i].nodeID, &PeerConnHandle{pc: edges[i].pc})
	}
	ps.mu.RLock()
	final := len(ps.byAddr)
	finalPeers := len(ps.peers)
	ps.mu.RUnlock()
	if final != 0 {
		t.Errorf("B1: len(byAddr)=%d after all %d edges died, want 0 — the unbounded-growth defect is live", final, K)
	}
	if finalPeers != 0 {
		t.Errorf("B1: len(peers)=%d after all %d edges died, want 0", finalPeers, K)
	}

	// THE TRAP (the identity check is load-bearing): re-register the SAME addr
	// with a NEWER peerConn, then release the OLD one — the new edge must
	// survive (deletion racing re-registration must never eat the live edge).
	var id [16]byte
	id[0] = 0xB1
	id[1] = 0xFF
	addr := "10.9.9.9:49999"
	oldPC := &peerConn{addr: addr, peerID: id, done: make(chan struct{})}
	ps.mu.Lock()
	ps.peers[id] = oldPC
	ps.byAddr[addr] = oldPC
	newPC := &peerConn{addr: addr, peerID: id, done: make(chan struct{})}
	ps.peers[id] = newPC // re-registered: both maps now point at the NEW edge
	ps.byAddr[addr] = newPC
	ps.mu.Unlock()
	// The old edge's death arrives LATE (a racing release):
	ps.ReleaseInboundConn(id, &PeerConnHandle{pc: oldPC})
	// And the removal primitive itself must be identity-safe when invoked
	// directly (the readLoop path calls it without ReleaseInboundConn's
	// guard in front):
	ps.removeDeadEntry(oldPC)
	ps.mu.RLock()
	_, survived := ps.byAddr[addr]
	_, survivedPeer := ps.peers[id]
	ps.mu.RUnlock()
	if !survived || !survivedPeer {
		t.Errorf("B1 TRAP: the late release of a superseded edge deleted the LIVE re-registration (byAddr hit=%v, peers hit=%v) — the identity check is broken", survived, survivedPeer)
	}
}
