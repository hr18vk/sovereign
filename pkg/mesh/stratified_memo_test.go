// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// stratified_memo_test.go — the stratified-memo guard.
//
// THE DEFECT (ADR-0045): the sweep-envelope memo is keyed by
// POSITION (sweepEnvIdx) and was never guarded against STRATIFIED mode. With
// --stratified-anti-entropy ON (ADR-0034), each peer's delta is a PER-PEER
// digest-exchange result: peer 1 fills memo slots 0..N with ITS envelopes, the
// per-peer rewind (batch.go:371) resets the cursor to 0 for peer 2, and peer 2
// HITS THE MEMO — receiving PEER 1's diff. The keys peer 2's digest asked for are
// never shipped: convergence stalls for exactly the entries the stratified path
// exists to send. Latent on the gate (stratified is OFF on silicon); live for any
// customer who turns the flag on.
//
// THE guard drives the exact production seam deterministically: ShipBatch (the
// function shipBatchedDelta's flush calls per batch) with the memo cursor
// managed exactly as the sweep manages it (round reset as AntiEntropySweep does;
// per-peer rewind verbatim from batch.go:371). A originates DISJOINT sets X and
// Y; peer B's digest-answer is Y, peer C's is X. Pre-fix, C's ShipBatch HITS the
// memo and C receives Y's envelope — C applies Y and never sees X. Post-fix the
// memo is bypassed under stratified and C receives X. Real TLS, real receiver,
// real apply — the only test-managed part is the two cursor lines, because the
// digest exchange itself (the timeout→oversend fallback) would MASK the memo
// defect by delivering the full state on any timeout.
//
// RED on pre-fix bytes (C never holds X); GREEN once the memo is gated on
// !g.stratified. Run:
//
//	go test -run 'Test(StratifiedMemo|HybridMemo)' -race -count=1 -v ./pkg/mesh/

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

// stratMemoNode is one node of the 3-node harness.
type stratMemoNode struct {
	ln     net.Listener
	ident  *NodeIdentity
	engine *eng.DeltaCRDTEngine
	recv   *receive.Receiver
	dir    *identity.Directory
	ps     *PeerSet
	g      *Gossiper
	addr   string
}

// stratMemoHarness is a 3-node loopback TLS mesh (A, B, C) with MANUAL peering:
// the test dials exactly A⇄B and A⇄C — never B⇄C — so no cross-seeding can mask
// which envelope each peer received.
type stratMemoHarness struct {
	nodes  [3]*stratMemoNode // 0=A (origin), 1=B, 2=C
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

func newStratMemoHarness(t *testing.T) *stratMemoHarness {
	t.Helper()
	return buildStratMemoHarness(t, false)
}

// buildStratMemoHarness builds the 3-node harness; hybrid=true mints HYBRID
// identities (NewNodeIdentityHybrid — the PQ key from the same seed) and arms
// the receivers' SetHybridVerify, so the hybrid batch path (ShipBatchHybrid →
// HandleHybridFrame) can run end to end.
func buildStratMemoHarness(t *testing.T, hybrid bool) *stratMemoHarness {
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

	h := &stratMemoHarness{}
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
			recv.SetHybridVerify(true) // the receiver-side opt-in (receiver.go:364)
			// The hybrid verify path resolves the origin's ML-DSA-65 pubkey
			// through the Directory — register SELF now (peers at connect),
			// the fixture's shape.
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
		h.nodes[i] = &stratMemoNode{ln: ln, ident: ident, engine: engine, recv: recv, dir: nodeDir, ps: ps, g: g, addr: ln.Addr().String()}
		h.wg.Add(1)
		// nil digester: the guard drives ShipBatch directly — no digest exchange
		// runs, so no digest sink is needed (the batchMesh precedent).
		go runAcceptLoop(h.ctx, ln, recv, nil, h.wg)
	}
	return h
}

// connect dials both directions between nodes i and j and registers the
// directories both ways (the batch verify path resolves the origin through the
// Directory).
func (h *stratMemoHarness) connect(t *testing.T, i, j int) {
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
	// The hybrid verify path resolves the origin's PQ pubkey through the
	// Directory (RegisterPQ,'s fixture shape) — register the peer's PQ
	// key on both nodes when present.
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

func (h *stratMemoHarness) close() {
	h.cancel()
	for _, n := range h.nodes {
		_ = n.ln.Close() // unblock the accept loops
	}
	h.wg.Wait()
}

// holds reports whether node's engine state carries every key.
func (h *stratMemoHarness) holds(node int, keys []string) bool {
	for _, k := range keys {
		if len(h.nodes[node].engine.State().Get(k)) == 0 {
			return false
		}
	}
	return true
}

// eventsOf builds the BuiltEvent slice the ship path consumes — each entry's
// stamped dot read from the origin node's STATE (no counter arithmetic
// assumed), the payload looked up by THAT dot: the exact pair the production
// walk uses.
func (h *stratMemoHarness) eventsOf(t *testing.T, node int, keys []string) []BuiltEvent {
	t.Helper()
	evs := make([]BuiltEvent, 0, len(keys))
	for _, k := range keys {
		ents := h.nodes[node].engine.State().Get(k)
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
// exactly as AntiEntropySweep does (gossip.go: sweepEnvCache = nil,
// sweepEnvRound = sweepRound, sweepEnvIdx = 0 after sweepRound++).
func resetSweepRound(g *Gossiper) {
	g.sweepRound++
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0
}

// TestStratifiedMemoServesPerPeerContent is the guard.
func TestStratifiedMemoServesPerPeerContent(t *testing.T) {
	h := newStratMemoHarness(t)
	defer h.close()
	const A, B, C = 0, 1, 2

	// A originates two DISJOINT sets X and Y (A's payloadCache holds all).
	var xs, ys []string
	for i := 0; i < 5; i++ {
		xk := fmt.Sprintf("strat-x-%d", i)
		yk := fmt.Sprintf("strat-y-%d", i)
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

	// Reproduce ONE stratified sweep round's per-peer ship sequence, with the
	// cursor managed exactly as production manages it:
	//   round reset — gossip.go (AntiEntropySweep): sweepEnvCache = nil,
	//     sweepEnvRound = sweepRound, sweepEnvIdx = 0;
	//   per-peer rewind — batch.go:371 (shipBatchedDelta): sweepEnvIdx = 0.
	g.sweepRound++
	g.sweepEnvCache = nil
	g.sweepEnvRound = g.sweepRound
	g.sweepEnvIdx = 0

	// Peer 1 (B): the digest exchange's answer for B is Y (B lacks Y). The memo
	// is empty, so this mints slot 0 — the Y envelope.
	if _, _, err := g.ShipBatch(h.ctx, h.nodes[B].ident.NodeID, eventsY); err != nil {
		t.Fatalf("ShipBatch B: %v", err)
	}
	// Peer 2 (C): the per-peer cursor rewind (batch.go:371), then C's ship — the
	// digest exchange's answer for C is X. PRE-FIX this HITS the memo and
	// publishes the Y envelope to C.
	g.sweepEnvIdx = 0
	if _, _, err := g.ShipBatch(h.ctx, h.nodes[C].ident.NodeID, eventsX); err != nil {
		t.Fatalf("ShipBatch C: %v", err)
	}

	// Wait for the receivers to apply, then assert on CONTENT, not on counters.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.holds(B, ys) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !h.holds(B, ys) {
		t.Fatalf("premise broken: peer 1's minted ship never landed (B lacks Y) — the guard proves nothing")
	}
	// Give C's (possibly wrong) envelope the same chance to apply.
	cDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(cDeadline) {
		if h.holds(C, xs) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.holds(C, ys) && !h.holds(C, xs) {
		t.Fatalf("(ADR-0045): peer C received PEER B's envelope — C holds Y=%v, X=%v. The position-keyed memo served peer 1's content to peer 2 under stratified mode; C's requested diff (X) was never shipped. Gate the memo on !g.stratified.",
			h.holds(C, ys), h.holds(C, xs))
	}
	if !h.holds(C, xs) {
		t.Fatalf("C holds neither X nor the wrong Y — the ship itself failed (check the receiver path); the memo verdict is indeterminate")
	}
	t.Logf("GREEN: under stratified mode, peer C received ITS OWN digest-answer (X) — B holds Y=%v, C holds X=%v, and neither got the other's envelope",
		h.holds(B, ys), h.holds(C, xs))
}

// TestHybridMemoByteIdenticalPerSweep is the guard,
// mirroring TestByteIdenticalEnvelopePerSweep for the
// HYBRID frame. The check is batchSeq, not byte-identity: ML-DSA-65 signing is
// deterministic, so two independent mints of the same content CAN be
// byte-identical — but a memo hit never advances batchSeq (no mint, no re-sign,
// no OriginSeq churn). Before this change, ShipBatchHybrid had NO memo consult: two peers
// in one round each paid the 60.19us Ed25519 + 585.8us ML-DSA-65 sign —
// 3,500 hybrid signs ≈ 2.26s per sweep round at the 35-peer × 100-batch gate
// shape. This test pins the stratified guard on the HYBRID path: stratified ON,
// disjoint per-peer sets, each peer must receive its OWN content.
func TestHybridMemoByteIdenticalPerSweep(t *testing.T) {
	h := buildStratMemoHarness(t, true)
	defer h.close()
	const A, B, C = 0, 1, 2

	var xs, ys []string
	for i := 0; i < 5; i++ {
		xk := fmt.Sprintf("hyb-x-%d", i)
		yk := fmt.Sprintf("hyb-y-%d", i)
		h.nodes[A].g.InsertLocalEvents(xk, fmt.Sprintf("xv-%d", i), eng.CRDTEntry{SystemTime: int64(1_700_500_000 + i), H3Index: uint64(i)})
		h.nodes[A].g.InsertLocalEvents(yk, fmt.Sprintf("yv-%d", i), eng.CRDTEntry{SystemTime: int64(1_700_510_000 + i), H3Index: uint64(2000 + i)})
		xs = append(xs, xk)
		ys = append(ys, yk)
	}
	h.connect(t, A, B)
	h.connect(t, A, C)
	g := h.nodes[A].g

	// ── ONE round, ONE content, TWO peers → ONE mint (the memo). ──────
	resetSweepRound(g)
	eventsX := h.eventsOf(t, A, xs)
	seq0 := g.batchSeq
	t0 := time.Now()
	if _, _, err := g.ShipBatchHybrid(h.ctx, h.nodes[B].ident.NodeID, eventsX); err != nil {
		t.Fatalf("ShipBatchHybrid B: %v", err)
	}
	mintWall := time.Since(t0)
	g.sweepEnvIdx = 0 // the per-peer cursor rewind (shipBatchedDelta, batch.go:371)
	t0 = time.Now()
	if _, _, err := g.ShipBatchHybrid(h.ctx, h.nodes[C].ident.NodeID, eventsX); err != nil {
		t.Fatalf("ShipBatchHybrid C: %v", err)
	}
	memoWall := time.Since(t0)

	if g.batchSeq != seq0+1 {
		t.Fatalf("(ADR-0045): two peers in ONE round minted %d hybrid batches (batchSeq %d → %d) — the hybrid path re-signs per peer: 3,500 × 646us ≈ 2.26s of signing per sweep round at the gate shape. The memo must serve peer 2 (one mint per round).",
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
	t.Logf("hybrid memo: ONE mint for two peers (batchSeq %d → %d); mint+publish=%s vs memo-hit publish=%s", seq0, g.batchSeq, mintWall, memoWall)

	// ── stratified ON: the memo must NOT serve across peers (the
	// guard holds on the HYBRID path too — do not fix one twin and leave the
	// other). B's diff is Y2, C's is a different per-peer diff — disjoint. ────
	g.SetStratifiedAntiEntropy(true)
	var x2s, y2s []string
	for i := 0; i < 3; i++ {
		xk := fmt.Sprintf("hyb2-x-%d", i)
		yk := fmt.Sprintf("hyb2-y-%d", i)
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
		t.Fatalf("Under stratified: two peers minted %d hybrid batches (batchSeq %d → %d) — under stratified EVERY peer must build+sign its own (the memo is bypassed); want 2", g.batchSeq-seq1, seq1, g.batchSeq)
	}
	deadline2 := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline2) {
		if h.holds(C, x2s) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !h.holds(C, x2s) || h.holds(C, y2s) {
		t.Fatalf("On the HYBRID path: under stratified, C must receive ITS OWN content — C holds X2=%v (want true), Y2=%v (want false: that is B's envelope)",
			h.holds(C, x2s), h.holds(C, y2s))
	}
	t.Logf("GREEN: hybrid memo serves ONE mint per round per content  and is bypassed under stratified (— both peers signed, each got its own content)")
}
