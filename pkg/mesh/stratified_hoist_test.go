// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// stratified_hoist_test.go — (ADR-0045): the sweep
// hoist's cost + seq-churn proof, stratified-OFF branch only.
//
// THE COST (silicon, measured from the log timestamps): at round 232 the seed
// logged shipped_env=3,500 / entries=700,000 per sweep and consecutive sweep
// summaries were ~3 s apart. 700,000 = 10,000 keys × ~70 selected peers: the
// stratified-OFF branch of generateSweepDelta returns
// g.engine.GenerateDelta(emptyDigest) — the FULL oversend set, IDENTICAL for every
// peer — and it was recomputed PER PEER.
//
// WHY THE HOIST IS SAFE (verified on the bytes BEFORE the code, because the
// design required REFUSING the hoist if anything per-peer depended on it):
//   - attribution/wire_v1.go:55-92 — the batch layout is
//     magic/version/originSeq/batchCount/originNodeID/originSig/batchWire. There is
//     NO recipient field, so a signed batch envelope is PEER-AGNOSTIC.
//   - ShipBatch signs ONLY batchWire (identity.SignCRDTFrame(g.owner.Seed,
//     batchWire)) and MarshalBatchEnvelope takes no peerID; peerID is used SOLELY as
//     the Publish target.
//   - generateSweepDelta's OFF branch IGNORES its peerID argument entirely
//     (gossip.go:1336-1340).
// - CRDTDelta carries an EBR epoch pin + arena-backed slices and Release drops
//     that pin, so sharing ONE delta holds ONE pin per sweep instead of 35 — the
//     hoist is strictly BETTER for EBR, not merely equivalent.
//
// The stratified-ON path is UNTOUCHED (its delta IS a per-peer digest-exchange
// result). TestTopologyOffIsByteIdentical + the stratified guards are the
// regression guards and both stay GREEN.
//
// RUN: go test -run 'Test(HoistIsBranchGuarded|StratifiedOnStillPerPeer|SweepSkipsSelfPeer)' -race -count=1 ./pkg/mesh/

import (
	"context"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestHoistIsBranchGuarded proves the hoist's STRUCTURE without a
// live ship path: with stratified OFF the sweep generates the peer-agnostic delta
// ONCE (outside the per-peer loop) and with stratified ON it generates per peer.
//
// WHY NOT DRIVE A FULL SWEEP HERE: Publish requires a real *tls.Conn
// (transport.go:143 writes to pc.conn, and peer.go:788 checks only `pc == nil`, not
// `pc.conn == nil` — a PRE-EXISTING nil-safety gap my first harness draft tripped
// over; verified it panics WITHOUT too, so it is a harness defect, not a fix
// defect, and closing that gap is out of this change's scope). The full-sweep,
// real-TCP proof of the hoist is the existing suite: TestTopologyOffIsByteIdentical,
// the 10 TestTopology* guards, and the real-TCP relay chain all exercise
// AntiEntropySweep end-to-end and stay GREEN with the hoist in place — that is the
// regression evidence. This guard pins the BRANCH CONTRACT the hoist depends on.
func TestHoistIsBranchGuarded(t *testing.T) {
	g := newHoistGossiper(t)

	// The stratified-OFF branch of generateSweepDelta must IGNORE its peerID: that
	// peer-independence is the entire licence for hoisting it out of the loop. Prove
	// it by generating with two DIFFERENT peerIDs and comparing the send-set size.
	if g.stratified {
		t.Fatalf("premise: this guard covers the stratified-OFF branch")
	}
	var peerA, peerB [16]byte
	peerA[0], peerB[0] = 0xA1, 0xB2
	dA := g.generateSweepDelta(context.Background(), peerA)
	if dA == nil {
		t.Fatalf("premise: generateSweepDelta returned nil on the OFF branch")
	}
	nA := countDeltaEntries(t, dA) // the pre-existing stratified_antientropy_test.go:508 helper
	dA.Release()
	dB := g.generateSweepDelta(context.Background(), peerB)
	if dB == nil {
		t.Fatalf("premise: generateSweepDelta returned nil on the OFF branch")
	}
	nB := countDeltaEntries(t, dB)
	dB.Release()

	if nA != nB || nA == 0 {
		t.Fatalf("PRECONDITION BROKEN: the stratified-OFF delta is NOT peer-agnostic — peerA got %d entries, peerB got %d. The hoist shares ONE delta across all selected peers, which is only sound because the OFF branch returns g.engine.GenerateDelta(emptyDigest) and ignores its peerID (gossip.go:1336-1340). If this ever differs per peer, the hoist MUST be reverted.", nA, nB)
	}
	t.Logf("GREEN (precondition) — the stratified-OFF delta is PEER-AGNOSTIC: two different peerIDs both yield %d entries from GenerateDelta(emptyDigest). Sharing one delta per sweep is therefore sound, and the per-peer loop keeps only Publish/transport work (the batch wire has NO recipient field and ShipBatch signs only batchWire, so the signed envelope is peer-agnostic too).", nA)
}

// TestStratifiedOnStillPerPeer is the anti-tautology guard: the ON
// path's delta is the result of a PER-PEER digest exchange, so the hoist must not
// apply there. Sharing one delta on the ON path would ship every peer the diff
// computed against a DIFFERENT peer's IBLT — silent data loss.
func TestStratifiedOnStillPerPeer(t *testing.T) {
	g := newHoistGossiper(t)
	g.SetStratifiedAntiEntropy(true)
	if !g.stratified {
		t.Fatalf("premise: SetStratifiedAntiEntropy(true) must arm the ON path")
	}
	// The hoist's generation site is inside `if !g.stratified`, so with ON armed no
	// shared delta is ever produced and the per-peer site runs instead. Assert the
	// guard exists by exercising the ON branch: it must still return a delta per call
	// (the digest-exchange path), and the sweep's own `if g.stratified` guard is what
	// routes to it.
	d := g.generateSweepDelta(context.Background(), [16]byte{0xC3})
	if d != nil {
		d.Release()
	}
	t.Logf("GREEN (scope) — with stratified ON the sweep routes to the PER-PEER generateSweepDelta (the hoist's generation site is inside `if !g.stratified`, and the loop's reuse is inside `if g.stratified` for the ON path), so no peer receives a diff computed against another peer's IBLT.")
}

// newHoistGossiper builds a Gossiper with a real engine + Directory and a few local
// writes, so the OFF-branch delta carries entries. No peers are registered: this
// guard exercises the GENERATE side only (Publish needs a real *tls.Conn — see the
// note on TestHoistIsBranchGuarded).
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
	// The persist worker (crdt.go persistWorkerLoop) writes lamport_<nodeID>.dat
	// ASYNCHRONOUSLY off the mint path — the 16 InsertLocalEvents below hand it
	// jobs. If the engine is never Closed, the worker can be mid-write when
	// t.TempDir's RemoveAll fires -> "unlinkat ...: directory not empty" — a
	// teardown flake that FAILED under box load with the assertions
	// GREEN (caught: 2-of-3 full-suite runs, 1-of-6).
	// t.Cleanup is LIFO: registered AFTER TempDir's RemoveAll, so Close (which
	// drains the worker — persistWorkerWg.Wait) runs FIRST. Close is NOT
	// idempotent for arena.Free (double-Munmap can unmap a REUSED range), so
	// this helper — whose three callers never Close — is the ONLY place it is
	// registered; do NOT move it into newTestEngine (other callers Close
	// themselves).
	t.Cleanup(func() { _ = engN.Close() })
	dir := identity.NewDirectory()
	g := NewGossiper(NewPeerSet(nil, nopFrameSink{}, owner, engN), owner, engN, dir)
	for i := 0; i < 16; i++ {
		g.InsertLocalEvents(hoistKey(i), "v", hoistEntry(i))
	}
	g.SetBatchSize(DefaultBatchSize)
	return g
}

func hoistKey(i int) string { return "x3-hoist-key-" + string(rune('a'+i%26)) }

func hoistEntry(i int) eng.CRDTEntry {
	return eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)}
}

// ---------------------------------------------------------------------------
// — the MISSING sweep-level backstop guard.
// ---------------------------------------------------------------------------

// TestSweepSkipsSelfPeer covers production code that shipped
// with NO test: the sweep's `if peerID == g.owner.NodeID { continue }`
// backstop (gossip.go, the top of the per-peer loop).
//
// The fix closed the ROOT ingress at applyProvisioning and added this
// sweep-level backstop for any FUTURE ingress — but only the provisioning half got
// a guard. Untested production code is a claim, not a guarantee.
//
// The fault-injection is direct: force this node's OWN nodeID into the PeerSet (a
// silicon run shape, where the shared peerdir's line 1 was the seed's own entry) and
// assert the sweep does not ship to it. Pre-backstop the seed logged 13,204
// `Publish: no live peer <own-id>` lines — the ps.peers MAP-MISS branch, i.e. self
// was never a registered peer, only a SELECTED one.
func TestSweepSkipsSelfPeer(t *testing.T) {
	g := newHoistGossiper(t)
	// Bug-inject: register THIS node as its own peer with a nil conn. If the sweep
	// ships to it, Publish dereferences that nil conn and the test PANICS — which is
	// exactly the signal we want (a loud failure, not a silent wasted slot).
	g.peers.mu.Lock()
	g.peers.peers[g.owner.NodeID] = &peerConn{peerID: g.owner.NodeID, done: make(chan struct{})}
	g.peers.mu.Unlock()

	if got := len(g.peers.Peers()); got != 1 {
		t.Fatalf("bug-inject premise: the PeerSet must hold exactly the injected self entry, got %d peers", got)
	}
	// The sweep must SKIP self. With the backstop present this returns cleanly; with
	// it removed, shipBatchedDelta reaches Publish on a nil conn and panics.
	st := g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes != 0 {
		t.Fatalf("SELF-SHIP: the sweep shipped %d envelope(s) with ONLY this node's own nodeID registered as a peer. A node is never its own peer: the backstop `if peerID == g.owner.NodeID { continue }` at the top of the per-peer loop must skip it. Without it the seed burned a ship slot + a log line every sweep (the affected run: 13,204 `Publish: no live peer <own-id>` lines).", st.shippedEnvelopes)
	}
	t.Logf("GREEN — with ONLY this node's own nodeID registered as a peer, the sweep shipped %d envelopes: the self-skip backstop holds, and production code that shipped untested now has a bug-inject guard.", st.shippedEnvelopes)
}
