// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover the sweep-envelope memo (ADR-0045 §2).
//
// With --stratified-anti-entropy enabled, every peer's delta comes from that
// peer's digest. A memo keyed only by sweepEnvIdx must therefore be bypassed:
// shipBatchedDelta rewinds the cursor for each peer, so reusing a position
// across peers would deliver the first peer's diff to the next one. The
// classical and hybrid batch paths both enforce this rule.
//
// Without stratified anti-entropy, the hybrid path consults the memo so two
// peers receiving the same content share one signed batch. The test checks
// batchSeq rather than envelope bytes because deterministic ML-DSA-65 signing
// can also produce identical bytes from independent mints.
//
// The tests drive ShipBatch and ShipBatchHybrid over real TLS connections.
// They reproduce the sweep's round reset and per-peer cursor rewind directly;
// running a digest exchange would let its oversend fallback mask memo reuse.

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// StratifiedMemoNode is one node of the 3-node harness.
type StratifiedMemoNode struct {
	ln     net.Listener
	ident  *NodeIdentity
	engine *eng.DeltaCRDTEngine
	recv   *receive.Receiver
	dir    *identity.Directory
	ps     *PeerSet
	g      *Gossiper
	addr   string
}

// StratifiedMemoHarness is a 3-node loopback TLS mesh (A, B, C) with manual
// peering: the test dials exactly A⇄B and A⇄C — never B⇄C — so no
// cross-seeding can mask which envelope each peer received.
type StratifiedMemoHarness struct {
	nodes  [3]*StratifiedMemoNode // 0=A (origin), 1=B, 2=C
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

func newStratifiedMemoHarness(t *testing.T) *StratifiedMemoHarness {
	t.Helper()
	return newCommitWindowHarness(t, false)
}

// newCommitWindowHarness builds the 3-node harness; hybrid=true mints hybrid
// identities (NewNodeIdentityHybrid — the PQ key from the same seed) and arms
// the receivers' SetHybridVerify, so the hybrid batch path (ShipBatchHybrid →
// HandleHybridFrame) runs end to end.
func newCommitWindowHarness(t *testing.T, hybrid bool) *StratifiedMemoHarness {
	t.Helper()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}

	h := &StratifiedMemoHarness{}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.wg = &sync.WaitGroup{}

	for i := 0; i < 3; i++ {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := cryptorand.Read(seed); err != nil {
			t.Fatalf("rand seed %d: %v", i, err)
		}
		var ident *NodeIdentity
		if hybrid {
			ident, err = NewNodeIdentityHybrid(seed)
		} else {
			ident, err = NewNodeIdentity(seed)
		}
		if err != nil {
			t.Fatalf("NewNodeIdentity(Hybrid=%v) %d: %v", hybrid, i, err)
		}
		engDir := filepath.Join(dir, fmt.Sprintf("eng%d", i))
		if err := os.MkdirAll(engDir, 0o755); err != nil {
			t.Fatalf("mkdir eng%d: %v", i, err)
		}
		engine := newTestEngine(t, ident.NodeID, engDir)
		nodeDir := identity.NewDirectory()
		recv := receive.NewReceiver(admission.NewPeerBucket(),
			clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engine),
			clock.NewSystemClock(), nodeDir, engine, 50_000_000)
		if hybrid {
			recv.SetHybridVerify(true) // the receiver-side opt-in
			// The hybrid verify path resolves the origin's ML-DSA-65 pubkey
			// through the Directory — register self now (peers at connect()).
			if err := nodeDir.RegisterPQ(ident.NodeID, ident.PQPub); err != nil {
				t.Fatalf("RegisterPQ self %d: %v", i, err)
			}
		}
		leaf, err := ca.IssueLeaf(identHex(ident.NodeID))
		if err != nil {
			t.Fatalf("IssueLeaf %d: %v", i, err)
		}
		certPath, keyPath, err := leaf.WritePEM(filepath.Join(dir, fmt.Sprintf("node%d", i)))
		if err != nil {
			t.Fatalf("WritePEM %d: %v", i, err)
		}
		tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
		if err != nil {
			t.Fatalf("NewTLSTransport %d: %v", i, err)
		}
		ln, err := tr.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %d: %v", i, err)
		}
		ps := NewPeerSet(tr, recv, ident, engine)
		g := NewGossiper(ps, ident, engine, nodeDir)
		h.nodes[i] = &StratifiedMemoNode{ln: ln, ident: ident, engine: engine, recv: recv, dir: nodeDir, ps: ps, g: g, addr: ln.Addr().String()}
		h.wg.Add(1)
		// nil digester: the test drives ShipBatch directly — no digest exchange
		// runs, so no digest sink is needed (the batchMesh precedent).
		// The PeerSet-threaded accept loop registers connections, completes the
		// challenge handshake, and edges earn egress.
		go runAcceptLoopWithPeerSet(h.ctx, ln, recv, nil, h.wg, ps)
	}
	return h
}

// connect dials both directions between nodes i and j and registers the
// directories both ways (the batch verify path resolves the origin through the
// Directory).
func (h *StratifiedMemoHarness) connect(t *testing.T, i, j int) {
	t.Helper()
	if err := h.nodes[i].ps.Dial(h.ctx, h.nodes[j].addr, "localhost", h.nodes[j].ident.NodeID); err != nil {
		t.Fatalf("dial %d->%d: %v", i, j, err)
	}
	if err := h.nodes[j].ps.Dial(h.ctx, h.nodes[i].addr, "localhost", h.nodes[i].ident.NodeID); err != nil {
		t.Fatalf("dial %d->%d: %v", j, i, err)
	}
	asyncWait(t, h.nodes[i].ps, h.nodes[j].ident.NodeID)
	asyncWait(t, h.nodes[j].ps, h.nodes[i].ident.NodeID)
	_ = h.nodes[i].g.RegisterPeer(h.nodes[j].ident.NodeID, h.nodes[j].ident.Pub)
	_ = h.nodes[j].g.RegisterPeer(h.nodes[i].ident.NodeID, h.nodes[i].ident.Pub)
	// Register each peer's ML-DSA public key for hybrid verification.
	if h.nodes[j].ident.PQPub != nil {
		if err := h.nodes[i].dir.RegisterPQ(h.nodes[j].ident.NodeID, h.nodes[j].ident.PQPub); err != nil {
			t.Fatalf("RegisterPQ %d<-%d: %v", i, j, err)
		}
	}
	if h.nodes[i].ident.PQPub != nil {
		if err := h.nodes[j].dir.RegisterPQ(h.nodes[i].ident.NodeID, h.nodes[i].ident.PQPub); err != nil {
			t.Fatalf("RegisterPQ %d<-%d: %v", j, i, err)
		}
	}
}

func (h *StratifiedMemoHarness) close() {
	h.cancel()
	for _, n := range h.nodes {
		_ = n.ln.Close() // unblock the accept loops
	}
	h.wg.Wait()
}

// holds reports whether node's engine state carries every key.
func (h *StratifiedMemoHarness) holds(node int, keys []string) bool {
	for _, k := range keys {
		if len(h.nodes[node].engine.PointGet(k)) == 0 {
			return false
		}
	}
	return true
}

// eventsOf builds the BuiltEvent slice consumed by the ship path. Each entry's
// stamped dot comes from the origin's current state, and the payload is looked
// up by that dot, matching the production walk.
func (h *StratifiedMemoHarness) eventsOf(t *testing.T, node int, keys []string) []BuiltEvent {
	t.Helper()
	evs := make([]BuiltEvent, 0, len(keys))
	for _, k := range keys {
		ents := h.nodes[node].engine.PointGet(k)
		if len(ents) == 0 {
			t.Fatalf("premise: node %d state lacks %s", node, k)
		}
		e := ents[0]
		dot := eng.CausalDot{NodeID: e.DotNodeID, Counter: e.DotCounter}
		payload, ok := h.nodes[node].g.cache.lookup(k, dot)
		if !ok {
			t.Fatalf("premise: node %d payloadCache lacks %s at its state-stamped dot %v", node, k, dot)
		}
		evs = append(evs, BuiltEvent{EntityID: k, Payload: payload, Entry: e})
	}
	return evs
}

// resetSweepRound puts the gossiper's memo at the top of a fresh round,
// exactly as AntiEntropySweep does (sweepEnvCache = nil, sweepEnvRound =
// sweepRound, sweepEnvIdx = 0 after sweepRound++).
func resetSweepRound(g *Gossiper) {
	g.sweepRound++
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0
}

// TestStratifiedMemoServesPerPeerContent is the position-keyed memo regression test.
func TestStratifiedMemoServesPerPeerContent(t *testing.T) {
	h := newStratifiedMemoHarness(t)
	defer h.close()
	const A, B, C = 0, 1, 2

	// A originates two disjoint sets; its payload cache holds both.
	var xs, ys []string
	for i := 0; i < 5; i++ {
		xk := fmt.Sprintf("stratmemo-x-%d", i)
		yk := fmt.Sprintf("stratmemo-y-%d", i)
		h.nodes[A].g.InsertLocalEvents(xk, fmt.Sprintf("xv-%d", i), eng.CRDTEntry{SystemTime: int64(1_700_400_000 + i), H3Index: uint64(i)})
		h.nodes[A].g.InsertLocalEvents(yk, fmt.Sprintf("yv-%d", i), eng.CRDTEntry{SystemTime: int64(1_700_410_000 + i), H3Index: uint64(1000 + i)})
		xs = append(xs, xk)
		ys = append(ys, yk)
	}

	eventsX := h.eventsOf(t, A, xs)
	eventsY := h.eventsOf(t, A, ys)

	h.connect(t, A, B)
	h.connect(t, A, C)

	g := h.nodes[A].g
	g.SetStratifiedAntiEntropy(true) // the condition the memo must respect

	// Reproduce AntiEntropySweep's round reset and shipBatchedDelta's per-peer
	// cursor rewind.
	g.sweepRound++
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0

	// B's diff is Y; the empty memo mints its envelope in slot 0.
	if _, _, err := g.ShipBatch(h.ctx, h.nodes[B].ident.NodeID, eventsY); err != nil {
		t.Fatalf("ShipBatch B: %v", err)
	}
	// Rewind the cursor before sending C's different diff, X.
	g.sweepEnvIdx = 0
	if _, _, err := g.ShipBatch(h.ctx, h.nodes[C].ident.NodeID, eventsX); err != nil {
		t.Fatalf("ShipBatch C: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.holds(B, ys) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !h.holds(B, ys) {
		t.Fatalf("B did not receive Y, so the first ShipBatch did not complete")
	}
	cDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(cDeadline) {
		if h.holds(C, xs) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.holds(C, ys) && !h.holds(C, xs) {
		t.Fatalf("memo reused B's envelope for C under stratified anti-entropy: C has Y=%v X=%v (ADR-0045 §2)",
			h.holds(C, ys), h.holds(C, xs))
	}
	if !h.holds(C, xs) {
		t.Fatalf("C received neither its own X nor B's Y; delivery failed before memo behavior could be checked")
	}
	t.Logf("stratified memo kept peer content separate: B has Y=%v and C has X=%v",
		h.holds(B, ys), h.holds(C, xs))
}

// TestHybridMemoByteIdenticalPerSweep checks both hybrid memo contracts. Two
// peers receiving one content in a round share one mint, observed through
// batchSeq. With stratified anti-entropy enabled and disjoint peer content,
// each peer gets a separately signed batch containing its own diff.
func TestHybridMemoByteIdenticalPerSweep(t *testing.T) {
	h := newCommitWindowHarness(t, true)
	defer h.close()
	const A, B, C = 0, 1, 2

	var xs, ys []string
	for i := 0; i < 5; i++ {
		xk := fmt.Sprintf("stratmemo-hyb-x-%d", i)
		yk := fmt.Sprintf("stratmemo-hyb-y-%d", i)
		h.nodes[A].g.InsertLocalEvents(xk, fmt.Sprintf("xv-%d", i), eng.CRDTEntry{SystemTime: int64(1_700_500_000 + i), H3Index: uint64(i)})
		h.nodes[A].g.InsertLocalEvents(yk, fmt.Sprintf("yv-%d", i), eng.CRDTEntry{SystemTime: int64(1_700_510_000 + i), H3Index: uint64(2000 + i)})
		xs = append(xs, xk)
		ys = append(ys, yk)
	}
	h.connect(t, A, B)
	h.connect(t, A, C)
	g := h.nodes[A].g

	// First phase: one round, one content, two peers → one mint (the memo).
	resetSweepRound(g)
	eventsX := h.eventsOf(t, A, xs)
	seq0 := g.batchSeq
	t0 := time.Now()
	if _, _, err := g.ShipBatchHybrid(h.ctx, h.nodes[B].ident.NodeID, eventsX); err != nil {
		t.Fatalf("ShipBatchHybrid B: %v", err)
	}
	mintWall := time.Since(t0)
	g.sweepEnvIdx = 0 // the per-peer cursor rewind (shipBatchedDelta)
	t0 = time.Now()
	if _, _, err := g.ShipBatchHybrid(h.ctx, h.nodes[C].ident.NodeID, eventsX); err != nil {
		t.Fatalf("ShipBatchHybrid C: %v", err)
	}
	memoWall := time.Since(t0)

	if g.batchSeq != seq0+1 {
		t.Fatalf("two peers receiving one content minted %d hybrid batches (batchSeq %d → %d), want one memoized mint (ADR-0045 §2)",
			g.batchSeq-seq0, seq0, g.batchSeq)
	}
	// Both peers must hold the content (the hybrid frames verified + applied —
	// the receivers are hybrid-armed in this harness).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.holds(B, xs) && h.holds(C, xs) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !h.holds(B, xs) || !h.holds(C, xs) {
		t.Fatalf("hybrid memo ship broke delivery: B holds X=%v, C holds X=%v (want both)", h.holds(B, xs), h.holds(C, xs))
	}
	t.Logf("hybrid memo: one mint for two peers (batchSeq %d → %d); mint+publish=%s vs memo-hit publish=%s", seq0, g.batchSeq, mintWall, memoWall)

	// With stratified anti-entropy enabled, B receives Y2 and C receives the
	// disjoint X2. The hybrid path must bypass the memo for both.
	g.SetStratifiedAntiEntropy(true)
	var x2s, y2s []string
	for i := 0; i < 3; i++ {
		xk := fmt.Sprintf("stratmemo-hyb2-x-%d", i)
		yk := fmt.Sprintf("stratmemo-hyb2-y-%d", i)
		h.nodes[A].g.InsertLocalEvents(xk, "x2v", eng.CRDTEntry{SystemTime: int64(1_700_520_000 + i), H3Index: uint64(3000 + i)})
		h.nodes[A].g.InsertLocalEvents(yk, "y2v", eng.CRDTEntry{SystemTime: int64(1_700_530_000 + i), H3Index: uint64(4000 + i)})
		x2s = append(x2s, xk)
		y2s = append(y2s, yk)
	}
	resetSweepRound(g)
	eventsY2 := h.eventsOf(t, A, y2s)
	eventsX2 := h.eventsOf(t, A, x2s)
	seq1 := g.batchSeq
	if _, _, err := g.ShipBatchHybrid(h.ctx, h.nodes[B].ident.NodeID, eventsY2); err != nil {
		t.Fatalf("ShipBatchHybrid B (stratified): %v", err)
	}
	g.sweepEnvIdx = 0 // the per-peer rewind
	if _, _, err := g.ShipBatchHybrid(h.ctx, h.nodes[C].ident.NodeID, eventsX2); err != nil {
		t.Fatalf("ShipBatchHybrid C (stratified): %v", err)
	}
	if g.batchSeq != seq1+2 {
		t.Fatalf("stratified peers minted %d hybrid batches (batchSeq %d → %d), want separate signatures for both peers", g.batchSeq-seq1, seq1, g.batchSeq)
	}
	deadline2 := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline2) {
		if h.holds(C, x2s) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !h.holds(C, x2s) || h.holds(C, y2s) {
		t.Fatalf("hybrid memo served the wrong content under stratified anti-entropy: C has X2=%v (want true), Y2=%v (want false)",
			h.holds(C, x2s), h.holds(C, y2s))
	}
	t.Logf("hybrid memo shared one mint for identical content and was bypassed for disjoint stratified content")
}
