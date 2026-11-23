// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// TestB1_ByAddrBoundedByLiveEdges verifies the byAddr cardinality bound
// (ADR-0045 Appendix B). RegisterInbound keys byAddr by the peer's ephemeral
// source address. Both connection teardown paths must remove the entry:
// readLoop exit for outbound connections and ReleaseInboundConn for inbound
// connections. Identity checks prevent a stale teardown from deleting a newer
// connection registered at the same address.

import (
	"fmt"
	"testing"
)

// TestB1_ByAddrBoundedByLiveEdges plants K inbound edges with separate peer
// and ephemeral-address keys, then releases them through ReleaseInboundConn.
// The byAddr count must fall on every release rather than waiting for a bulk
// sweep. Omitting removeDeadEntry from that path leaves K entries and fails the
// cardinality assertion.
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
			addr:   fmt.Sprintf("10.9.0.%d:%d", i/256+1, 40000+i), // K distinct ephemeral addrs
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
		t.Fatalf("planted %d edges but byAddr holds %d", K, got)
	}

	// Half die: per-death removal must track (not a bulk sweep at the end).
	for i := 0; i < K/2; i++ {
		ps.ReleaseInboundConn(edges[i].nodeID, &PeerConnHandle{pc: edges[i].pc})
	}
	ps.mu.RLock()
	half := len(ps.byAddr)
	ps.mu.RUnlock()
	if half != K/2 {
		t.Fatalf("after %d releases: len(byAddr)=%d, want %d; entries must be removed individually", K/2, half, K/2)
	}

	for i := K / 2; i < K; i++ {
		ps.ReleaseInboundConn(edges[i].nodeID, &PeerConnHandle{pc: edges[i].pc})
	}
	ps.mu.RLock()
	final := len(ps.byAddr)
	finalPeers := len(ps.peers)
	ps.mu.RUnlock()
	if final != 0 {
		t.Errorf("len(byAddr)=%d after all %d edges closed, want 0", final, K)
	}
	if finalPeers != 0 {
		t.Errorf("len(peers)=%d after all %d edges closed, want 0", finalPeers, K)
	}

	// Re-register the address with a newer peerConn. A late release of the old
	// connection must not remove either map's live entry.
	var id [16]byte
	id[0] = 0xB1
	id[1] = 0xFF
	addr := "10.9.9.9:49999"
	oldPC := &peerConn{addr: addr, peerID: id, done: make(chan struct{})}
	ps.mu.Lock()
	ps.peers[id] = oldPC
	ps.byAddr[addr] = oldPC
	newPC := &peerConn{addr: addr, peerID: id, done: make(chan struct{})}
	ps.peers[id] = newPC // re-registered: both maps now point at the new edge
	ps.byAddr[addr] = newPC
	ps.mu.Unlock()
	// Exercise both the public teardown path and the primitive used by readLoop.
	ps.ReleaseInboundConn(id, &PeerConnHandle{pc: oldPC})
	ps.removeDeadEntry(oldPC)
	ps.mu.RLock()
	_, survived := ps.byAddr[addr]
	_, survivedPeer := ps.peers[id]
	ps.mu.RUnlock()
	if !survived || !survivedPeer {
		t.Errorf("late release of a superseded edge removed the live registration (byAddr=%v, peers=%v)", survived, survivedPeer)
	}
}
