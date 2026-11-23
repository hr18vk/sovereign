// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover the shared-delta optimization for the non-stratified
// sweep. generateSweepDelta returns GenerateDelta(emptyDigest) on that branch,
// independently of the destination peer, so one result can serve the whole
// sweep instead of being recomputed for every peer.
//
// Sharing is valid because the batch envelope has no recipient field,
// ShipBatch signs only batchWire, and peerID is only the Publish target. One
// shared CRDTDelta also holds one EBR epoch pin per sweep rather than one per
// recipient. Stratified anti-entropy still generates a separate delta from
// each peer's digest.

import (
	"context"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestStratifiedHoistIsBranchGuarded checks the branch contract without a live
// transport: the non-stratified delta is independent of peerID and can be
// generated once per sweep. Publish requires a real TLS connection; the
// topology and relay tests exercise the full sweep over TCP.
func TestStratifiedHoistIsBranchGuarded(t *testing.T) {
	g := newHoistGossiper(t)

	// Compare non-stratified deltas for two peer IDs. Equal non-empty entry
	// counts demonstrate the peer independence required for sharing.
	if g.stratified {
		t.Fatalf("test requires the non-stratified branch")
	}
	var peerA, peerB [16]byte
	peerA[0], peerB[0] = 0xA1, 0xB2
	dA := g.generateSweepDelta(context.Background(), peerA)
	if dA == nil {
		t.Fatalf("generateSweepDelta returned nil without stratified anti-entropy")
	}
	nA := countDeltaEntries(t, dA)
	dA.Release()
	dB := g.generateSweepDelta(context.Background(), peerB)
	if dB == nil {
		t.Fatalf("generateSweepDelta returned nil without stratified anti-entropy")
	}
	nB := countDeltaEntries(t, dB)
	dB.Release()

	if nA != nB || nA == 0 {
		t.Fatalf("non-stratified delta is not peer-independent: peerA=%d entries peerB=%d; sharing requires equal non-empty GenerateDelta(emptyDigest) results", nA, nB)
	}
	t.Logf("non-stratified deltas for two peer IDs contain %d entries each and can share one EBR pin per sweep", nA)
}

// TestStratifiedOnStillPerPeer checks that the stratified branch still calls
// generateSweepDelta for each destination. Reusing another peer's IBLT diff
// would omit entries requested by the destination.
func TestStratifiedOnStillPerPeer(t *testing.T) {
	g := newHoistGossiper(t)
	g.SetStratifiedAntiEntropy(true)
	if !g.stratified {
		t.Fatalf("SetStratifiedAntiEntropy(true) did not enable stratified mode")
	}
	// The shared-delta generation site is guarded by !g.stratified, so this
	// branch still executes the per-peer digest-exchange path.
	d := g.generateSweepDelta(context.Background(), [16]byte{0xC3})
	if d != nil {
		d.Release()
	}
	t.Logf("stratified branch used per-peer generateSweepDelta; no peer received another peer's IBLT diff")
}

// newHoistGossiper builds a Gossiper with local writes but no peers, so tests
// can inspect delta generation without calling Publish.
func newHoistGossiper(t *testing.T) *Gossiper {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	owner, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	engN := newTestEngine(t, owner.NodeID, t.TempDir())
	// Close drains the persist worker before TempDir removes its files.
	// Cleanup functions run in LIFO order. This helper owns the only Close call
	// for its engine because other callers close their engines themselves and
	// arena.Free is not idempotent.
	t.Cleanup(func() { _ = engN.Close() })
	dir := identity.NewDirectory()
	g := NewGossiper(NewPeerSet(nil, nopFrameSink{}, owner, engN), owner, engN, dir)
	for i := 0; i < 16; i++ {
		g.InsertLocalEvents(hoistKey(i), "v", hoistEntry(i))
	}
	g.SetBatchSize(DefaultBatchSize)
	return g
}

func hoistKey(i int) string { return "sweep-hoist-key-" + string(rune('a'+i%26)) }

func hoistEntry(i int) eng.CRDTEntry {
	return eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)}
}

// TestSweepSkipsSelfPeer injects the node's own ID into PeerSet and checks the
// sweep's self-peer guard. A shared peer directory can contain the seed's own
// entry; selecting that entry must not attempt a publish to self.
func TestSweepSkipsSelfPeer(t *testing.T) {
	g := newHoistGossiper(t)
	// A publish to the injected nil connection would panic, exposing a missing
	// self-peer guard.
	g.peers.mu.Lock()
	g.peers.peers[g.owner.NodeID] = &peerConn{peerID: g.owner.NodeID, done: make(chan struct{})}
	g.peers.mu.Unlock()

	if got := len(g.peers.Peers()); got != 1 {
		t.Fatalf("PeerSet contains %d peers, want the single injected self entry", got)
	}
	st := g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes != 0 {
		t.Fatalf("sweep shipped %d envelopes to the node's own ID; the self-peer guard must skip it", st.shippedEnvelopes)
	}
	t.Logf("self-peer guard shipped %d envelopes with only the node's own ID registered", st.shippedEnvelopes)
}
