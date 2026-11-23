// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package mesh tests digest framing and steady-state exchange efficiency
// (ADR-0054).
//
// GenerateDelta consumes the remote IBLT but not the 51,789-byte
// StrataEstimator. Digest frames therefore omit the estimator: an seLen of
// zero marks an IBLT-only frame, reducing the example frame from 72,287 bytes
// to about 20,531 bytes. A legacy receiver treats that frame as malformed and
// falls back to oversend rather than computing a wrong difference.
//
// A full exchange runs only when the local Merkle root differs from the
// peer's last announced root. Converged nodes exchange only the roughly
// 65-byte root announcement. Gating on local root changes instead would stall
// a node that fell behind while its peers were stable, as the behind-node
// tests demonstrate.
package mesh

import (
	"context"
	"fmt"
	"hash/maphash"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// digestEfficiencyRealIBLT builds a valid 1024-bucket IBLT from n seeded
// entries. A malformed body would test error handling instead of the absent-SE
// path. Marshal copies the digest to the heap; the engine's TempDir cleanup
// handles its resources.
func digestEfficiencyRealIBLT(t *testing.T, nodeID [16]byte, n int) (marshaled []byte, seed maphash.Seed) {
	t.Helper()
	e := newTestEngine(t, nodeID, t.TempDir())
	for i := 0; i < n; i++ {
		e.InsertLocal(digestEfficiencyEntity(i), eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}
	seed = maphash.MakeSeed()
	ib := e.GenerateDigestWithSeed(seed) // GenerateDigestWithSeed produces a 1024-bucket IBLT
	m, err := eng.MarshalIBLT(ib)
	ib.Release()
	if err != nil {
		t.Fatalf("digestEfficiencyRealIBLT: MarshalIBLT: %v", err)
	}
	return m, seed
}

// digestEfficiencyEntity is the deterministic entity ID helper for the digest
// efficiency tests (reuses the package's existing itoa).
func digestEfficiencyEntity(i int) string {
	return "digest-entity-" + itoa(i)
}

// TestSEDROP_IBLTOnlyAccepted verifies that an IBLT-only digest frame
// (seLen==0) passes through digestFrameSplit and deliverPeerDigest with a
// non-nil IBLT, so the sweep does not fall back to oversend.
//
// digestFrameSplit returns a zero-length, non-nil SE subslice for this frame.
// The receiver must therefore test len(seBody) > 0 rather than seBody != nil:
// UnmarshalStrataEstimator rejects an empty body because it is shorter than
// the 13-byte strataWireHeaderLen. Treating that absence as malformed would
// deliver a peerDigest with a nil IBLT. Restoring the nil-only guard makes
// this test fail.
func TestSEDROP_IBLTOnlyAccepted(t *testing.T) {
	sender := [16]byte{0xF0, 0x21}
	mIBLT, seed := digestEfficiencyRealIBLT(t, sender, 64)

	// Build the IBLT-only frame: nil SE → seLen==0 on the wire.
	frame := buildDigestFrame(digestRoleResponse, sender, seed, nil /* SE dropped */, mIBLT)

	// Sanity check: the frame is IBLT-only (seLen==0 on the wire)
	// and is smaller than the SE+IBLT frame (the 72 KB -> ~20 KB drop). If
	// buildDigestFrame still emitted an SE, the size + the seLen==0 read would
	// not hold and the test would be exercising the wrong frame.
	if got := int(binaryBigEndianUint32(frame[digestFrameSELenOff:])); got != 0 {
		t.Fatalf("IBLT-only frame has seLen=%d, want 0 (the SE was not dropped)", got)
	}
	fullSE, fullSeed := digestEfficiencyRealSEFrame(t, sender, 64)
	_ = fullSeed
	if len(frame) >= len(fullSE) {
		t.Fatalf("IBLT-only frame (%d B) is not smaller than the SE+IBLT frame (%d B) — the SE-drop did not shrink the frame", len(frame), len(fullSE))
	}
	t.Logf("SE-DROP frame size: IBLT-only=%d B vs SE+IBLT=%d B (%.1f%% of the old frame)", len(frame), len(fullSE), 100*float64(len(frame))/float64(len(fullSE)))

	// The receiver path: split the frame, deliver it, read the peerDigest.
	seBody, ibltBody := digestFrameSplit(frame)
	g := &Gossiper{} // deliverPeerDigest touches only the channel + the eng unmarshalers
	ch := make(chan *peerDigest, 1)
	g.deliverPeerDigest(sender, ch, seBody, ibltBody, digestFrameStamp(frame)) // wire stamp rides the deposit (behavior-neutral for these unit calls)

	select {
	case pd := <-ch:
		if pd == nil {
			t.Fatalf("deliverPeerDigest sent a nil peerDigest (the sweep would block/panic)")
		}
		if pd.iblt == nil {
			t.Fatalf("IBLT-only frame delivered a nil IBLT; the receiver treated the absent SE as malformed")
		}
		if pd.se != nil {
			t.Logf("note: pd.se is non-nil on an IBLT-only frame; GenerateDelta does not consume it")
		}
		// The delivered IBLT must contain the remote 1024-bucket digest.
		if pd.iblt.NumBuckets() != 1024 {
			t.Fatalf("delivered IBLT has %d buckets, want 1024 (the real remote digest)", pd.iblt.NumBuckets())
		}
	default:
		t.Fatalf("deliverPeerDigest delivered no peerDigest; the sweep would time out and oversend")
	}
	t.Logf("IBLT-only frame accepted: absent SE skipped and 1024-bucket IBLT parsed without fallback")
}

// digestEfficiencyRealSEFrame builds a legacy SE+IBLT frame for the size
// comparison and mixed-mode receiver test.
func digestEfficiencyRealSEFrame(t *testing.T, sender [16]byte, n int) (frame []byte, seed maphash.Seed) {
	t.Helper()
	e := newTestEngine(t, sender, t.TempDir())
	for i := 0; i < n; i++ {
		e.InsertLocal(digestEfficiencyEntity(i), eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}
	seed = maphash.MakeSeed()
	se := e.GenerateStrataEstimator(seed) // GenerateStrataEstimator kept exported for mixed-mode test
	ib := e.GenerateDigestWithSeed(seed)
	mSE, err := eng.MarshalStrataEstimator(se)
	if err != nil {
		t.Fatalf("digestEfficiencyRealSEFrame: MarshalStrataEstimator: %v", err)
	}
	mIB, err := eng.MarshalIBLT(ib)
	ib.Release()
	if err != nil {
		t.Fatalf("digestEfficiencyRealSEFrame: MarshalIBLT: %v", err)
	}
	return buildDigestFrame(digestRoleRequest, sender, seed, mSE, mIB), seed
}

// The three-node TLS harness holds one node behind a partition while the
// other two converge and their roots stabilize. It uses stratified
// anti-entropy and a full mesh, with each pair sharing one verified
// bidirectional connection.

type DigestEfficiencyMeshNode struct {
	ident  *NodeIdentity
	engine *eng.DeltaCRDTEngine
	recv   *receive.Receiver
	ps     *PeerSet
	g      *Gossiper
	ln     net.Listener
	addr   string
}

type DigestEfficiencyMesh struct {
	nodes  []*DigestEfficiencyMeshNode
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// newDigestEfficiencyMesh builds an n-node full-mesh stratified-ON cluster over
// real loopback TLS. Each node dials every other (n*(n-1) dials), so every
// Publish direction has a live conn. The digester is each node's gossiper (so
// the digest exchange + the root-announce route correctly).
func newDigestEfficiencyMesh(t *testing.T, n int) *DigestEfficiencyMesh {
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

	m := &DigestEfficiencyMesh{}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.wg = &sync.WaitGroup{}

	nodes := make([]*DigestEfficiencyMeshNode, n)
	for i := 0; i < n; i++ {
		seed := bytesRepeat(byte(0x10+i), ed25519.SeedSize)
		ident, err := NewNodeIdentity(seed)
		if err != nil {
			t.Fatalf("NewNodeIdentity %d: %v", i, err)
		}
		arenaDir := filepath.Join(dir, fmt.Sprintf("eng%d", i))
		if err := os.MkdirAll(arenaDir, 0o755); err != nil {
			t.Fatalf("mkdir %d: %v", i, err)
		}
		engine := newTestEngine(t, ident.NodeID, arenaDir)
		idir := identity.NewDirectory()
		bucket := admission.NewPeerBucket()
		cap := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engine)
		recv := receive.NewReceiver(bucket, cap, clock.NewSystemClock(), idir, engine, 50_000_000)
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
		g := NewGossiper(ps, ident, engine, idir)
		g.SetStratifiedAntiEntropy(true)
		g.SetDigestWaitTimeout(300 * time.Millisecond)
		nodes[i] = &DigestEfficiencyMeshNode{ident: ident, engine: engine, recv: recv, ps: ps, g: g, ln: ln, addr: ln.Addr().String()}
	}
	m.nodes = nodes
	// Register every peer's public key so origin and connection verification
	// can resolve it on every node.
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			_ = nodes[i].g.RegisterPeer(nodes[j].ident.NodeID, nodes[j].ident.Pub)
		}
	}
	// The accept loops route digests through each node's gossiper. Passing the
	// PeerSet also registers inbound connections and runs their challenge
	// handshakes (ADR-0068).
	for i := 0; i < n; i++ {
		m.wg.Add(1)
		go runAcceptLoopWithPeerSet(m.ctx, nodes[i].ln, nodes[i].recv, nodes[i].g, m.wg, nodes[i].ps)
	}
	// Dial each unordered pair once. A second dial would be declined while the
	// original connection is live, so accept-side registration completes the
	// single bidirectional connection before any sweep starts.
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if err := nodes[i].ps.Dial(m.ctx, nodes[j].addr, "localhost", nodes[j].ident.NodeID); err != nil {
				t.Fatalf("dial %d->%d: %v", i, j, err)
			}
		}
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			asyncWait(t, nodes[i].ps, nodes[j].ident.NodeID)
			asyncWait(t, nodes[j].ps, nodes[i].ident.NodeID) // accept-side install
			awaitVerified(t, nodes[i].ps, nodes[j].ident.NodeID)
			awaitVerified(t, nodes[j].ps, nodes[i].ident.NodeID)
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			asyncWait(t, nodes[i].ps, nodes[j].ident.NodeID)
		}
	}
	return m
}

// close tears down the mesh (cancel ctx, close listeners, wait for accept loops).
func (m *DigestEfficiencyMesh) close() {
	m.cancel()
	for _, nd := range m.nodes {
		_ = nd.ln.Close()
	}
	m.wg.Wait()
}

// insertInto inserts k events into node idx (distinct entityIDs prefixed by tag).
func (m *DigestEfficiencyMesh) insertInto(idx int, tag string, k int) {
	for i := 0; i < k; i++ {
		m.nodes[idx].g.InsertLocalEvents(fmt.Sprintf("%s-%d", tag, i), fmt.Sprintf("val-%s-%d", tag, i), eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		})
	}
}

// sweepNode runs one node's AntiEntropySweep (the real sweep — where the
// change-gate lives). Manual per-node control lets the test hold a node behind.
func (m *DigestEfficiencyMesh) sweepNode(idx int) {
	m.nodes[idx].g.AntiEntropySweep(m.ctx)
}

// sweepSet runs one concurrent sweep round over the given node indices, then a
// tick so the async readers drain the frames + root-announces.
func (m *DigestEfficiencyMesh) sweepSet(idxs []int, tick time.Duration) {
	var wg sync.WaitGroup
	for _, idx := range idxs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); m.nodes[i].g.AntiEntropySweep(m.ctx) }(idx)
	}
	wg.Wait()
	time.Sleep(tick)
}

// root returns node idx's Merkle root (MerkleRootFromShards — the same root the
// change-gate computes; byte-identical to State().MerkleRoot()).
func (m *DigestEfficiencyMesh) root(idx int) [32]byte {
	return m.nodes[idx].engine.MerkleRootFromShards()
}

// partitionNode black-holes node idx: every other node closes its conn to idx
// (so idx is removed from their peer sets and they stop selecting/pushing to it)
// and idx closes its conns to them. A and B stay connected to each other.
func (m *DigestEfficiencyMesh) partitionNode(idx int) {
	for j := range m.nodes {
		if j == idx {
			continue
		}
		_ = m.nodes[j].ps.ClosePeer(m.nodes[idx].ident.NodeID) // j closes its conn to idx
		_ = m.nodes[idx].ps.ClosePeer(m.nodes[j].ident.NodeID) // idx closes its conn to j
	}
}

// healNode re-dials idx to every other node and waits for both sides to
// register each connection.
func (m *DigestEfficiencyMesh) healNode(t *testing.T, idx int) {
	t.Helper()
	// Dial from idx to each peer and let the accept side register the new
	// connection. A second dial in the reverse direction would be declined
	// while that connection is live.
	for j := range m.nodes {
		if j == idx {
			continue
		}
		if err := m.nodes[idx].ps.Dial(m.ctx, m.nodes[j].addr, "localhost", m.nodes[j].ident.NodeID); err != nil {
			t.Fatalf("heal dial %d->%d: %v", idx, j, err)
		}
	}
	for j := range m.nodes {
		if j == idx {
			continue
		}
		asyncWait(t, m.nodes[idx].ps, m.nodes[j].ident.NodeID)
		asyncWait(t, m.nodes[j].ps, m.nodes[idx].ident.NodeID)
	}
}

// allRootsEqual reports whether the given nodes all hold the same Merkle root.
func (m *DigestEfficiencyMesh) allRootsEqual(idxs []int) bool {
	if len(idxs) == 0 {
		return true
	}
	r0 := m.root(idxs[0])
	for _, i := range idxs[1:] {
		if m.root(i) != r0 {
			return false
		}
	}
	return true
}

// convergeWithin sweeps the given nodes until their roots all equal or the round
// cap is hit. Returns (converged, rounds). The convergence oracle reads
// MerkleRootFromShards (the same root the change-gate computes).
func (m *DigestEfficiencyMesh) convergeWithin(idxs []int, maxRounds int, tick time.Duration) (bool, int) {
	for round := 1; round <= maxRounds; round++ {
		m.sweepSet(idxs, tick)
		if m.allRootsEqual(idxs) {
			return true, round
		}
	}
	return m.allRootsEqual(idxs), maxRounds
}

// TestBehindNodeConvergesAfterHeal partitions C while A and B converge on new
// writes and their roots stabilize. After the partition heals, A's current
// root differs from its cached root for C, so the digest exchange must bring C
// to the same root. The setup also proves that C stayed at its baseline root
// throughout the partition.
func TestBehindNodeConvergesAfterHeal(t *testing.T) {
	m := newDigestEfficiencyMesh(t, 3)
	defer m.close()
	const A, B, C = 0, 1, 2
	tick := 25 * time.Millisecond

	// All three nodes converge on the baseline.
	m.insertInto(A, "base-a", 30)
	m.insertInto(B, "base-b", 30)
	m.insertInto(C, "base-c", 30)
	converged, rounds := m.convergeWithin([]int{A, B, C}, 60, tick)
	if !converged {
		t.Fatalf("setup: 3-node baseline did not converge in %d rounds (A=%x B=%x C=%x)", rounds, m.root(A), m.root(B), m.root(C))
	}
	baseRoot := m.root(A)
	t.Logf("baseline: three-node baseline converged in %d rounds (root=%x)", rounds, baseRoot[:8])

	// Sanity check #1: the root-announce flowed — A holds a cached root for C (the
	// gate's input). If not, the gate is untestable (it would always fire on
	// "unknown").
	if _, known := m.nodes[A].g.peerRootFor(m.nodes[C].ident.NodeID); !known {
		t.Fatalf("sanity check: A has no cached root for C after convergence — the always-on root-announce did not flow, so the change-gate was never exercised")
	}

	// Black-hole C; A and B stay connected.
	m.partitionNode(C)

	// A takes new writes; A and B converge on them (C is partitioned).
	m.insertInto(A, "diverge", 20)
	rA := m.root(A)
	if rA == baseRoot {
		t.Fatalf("setup: A's root did not change after the diverging writes")
	}
	// A and B converge on the new writes and stabilize (the ahead nodes' roots stop
	// changing — the condition under which a local-change gate would stop firing).
	if ok, _ := m.convergeWithin([]int{A, B}, 60, tick); !ok {
		t.Fatalf("setup: A and B did not converge on the diverging writes")
	}
	// Extra settle sweeps so A's + B's roots are provably stable at the new value
	// (this is what strands a behind node under a local-change gate).
	for i := 0; i < 4; i++ {
		m.sweepSet([]int{A, B}, tick)
	}
	stableRoot := m.root(A)
	if m.root(B) != stableRoot {
		t.Fatalf("setup: A and B did not stabilize on the same root (A=%x B=%x)", m.root(A), m.root(B))
	}

	// Sanity check #2: C is genuinely behind — its root neither advanced to the new
	// root nor changed at all during the partition (the partition held).
	if got := m.root(C); got != baseRoot {
		t.Fatalf("sanity check: C's root moved during the partition (got %x, want the baseline %x) — the partition leaked, C is not a clean behind node", got, baseRoot)
	}
	if m.root(C) == stableRoot {
		t.Fatalf("sanity check: C already holds the converged root before heal — no behind node was created")
	}
	cRoot := m.root(C)
	t.Logf("behind node: C is genuinely behind (C=%x, A/B=%x)", cRoot[:8], stableRoot[:8])

	// Heal C.
	m.healNode(t, C)

	// The mismatch gate must converge C. A (and B) see their (new) root
	// != C's (stale) cached root → fire the digest → push the diff → C converges.
	converged, rounds = m.convergeWithin([]int{A, B, C}, 60, tick)
	if !converged {
		t.Fatalf("behind node did not converge after heal under the mismatch gate — the change-gate stalled a behind node (A=%x B=%x C=%x)", m.root(A), m.root(B), m.root(C))
	}
	if m.root(C) != stableRoot {
		t.Fatalf("C converged to the wrong root (C=%x, want the converged %x) — a wrong-diff bug, not a convergence", m.root(C), stableRoot)
	}
	// Zero data loss: C holds A's partitioned divergence.
	for i := 0; i < 20; i++ {
		if got := m.nodes[C].engine.PointGet(fmt.Sprintf("diverge-%d", i)); len(got) == 0 { // PointGet migration (tier 1)
			t.Fatalf("C missing diverge-%d after heal — the behind node lost data", i)
		}
	}
	t.Logf("behind-node pass: the behind node C converged in %d rounds after heal (the mismatch gate fired on the root mismatch); zero data loss", rounds)
}

// TestBehindNodeLocalChangeGateStalls replaces peer-root mismatch gating with
// local-change gating as a negative control. Once A, B, and the partitioned C
// all have stable roots, no node starts an exchange for C after healing. C must
// remain behind; convergence would mean the control did not exercise the
// intended gate.
func TestBehindNodeLocalChangeGateStalls(t *testing.T) {
	m := newDigestEfficiencyMesh(t, 3)
	defer m.close()
	const A, B, C = 0, 1, 2
	tick := 25 * time.Millisecond
	// Negative control: the wrong local-change gate on all nodes.
	for _, nd := range m.nodes {
		nd.g.gateLocalChangeBugInject.Store(true)
	}

	// Converge all three nodes.
	m.insertInto(A, "base-a", 30)
	m.insertInto(B, "base-b", 30)
	m.insertInto(C, "base-c", 30)
	if ok, _ := m.convergeWithin([]int{A, B, C}, 60, tick); !ok {
		t.Fatalf("setup: baseline did not converge")
	}
	baseRoot := m.root(A)

	// Partition C; A writes; A and B converge and stabilize.
	m.partitionNode(C)
	m.insertInto(A, "diverge", 20)
	if ok, _ := m.convergeWithin([]int{A, B}, 60, tick); !ok {
		t.Fatalf("setup: A and B did not converge on the diverging writes under the local-change gate")
	}
	for i := 0; i < 5; i++ { // stabilize A's and B's roots (this is what kills the local-change gate)
		m.sweepSet([]int{A, B}, tick)
	}
	stableRoot := m.root(A)
	if m.root(C) != baseRoot {
		t.Fatalf("setup: C's root moved during the partition (the partition leaked)")
	}

	// Heal C; run many sweeps. Under the local-change gate, nobody fires
	// on C (A's and B's roots are stable; C's is stable) → C must not
	// converge. If C converges, the local-change bug is not load-bearing.
	m.healNode(t, C)
	converged, rounds := m.convergeWithin([]int{A, B, C}, 40, tick)
	if converged {
		t.Fatalf("local-change bug injection not load-bearing: the behind node C converged in %d rounds under the (wrong) local-change gate — so the mismatch gate is not what saves a behind node (the behind-node positive test passes)", rounds)
	}
	if m.root(C) == stableRoot {
		t.Fatalf("inconsistent result: C has the converged root but convergeWithin reported divergence")
	}
	cRoot := m.root(C)
	t.Logf("negative control pass: under the (wrong) local-change gate, the behind node C never converged in %d rounds (C=%x, A/B=%x) — proving the mismatch gate is load-bearing (the behind-node test passes)", rounds, cRoot[:8], stableRoot[:8])
}

// TestQuiesceSteadyStateStopsDigest verifies that a converged two-node mesh
// stops full digest exchanges within K sweeps. The exchange count must remain
// zero while digestGateSkips advances, demonstrating that the change gate
// actively selects the approximately 65-byte root announcement. Disabling the
// gate in the companion test restores an exchange on every sweep.
func TestQuiesceSteadyStateStopsDigest(t *testing.T) {
	h := newStratifiedHarness(t, true) // stratified anti-entropy enabled
	defer h.close()
	h.insertEvents(t, 100)
	_, converged, ra, rb := h.sweepUntilConverged(t, 30, 20*time.Millisecond)
	if !converged {
		t.Fatalf("setup: 2-node mesh did not converge (rootA=%x rootB=%x)", ra, rb)
	}
	// Settle: a few sweeps so the converged root-announces fully propagate and both
	// caches hold the peer's converged root (so the gate can engage cleanly).
	for i := 0; i < 4; i++ {
		h.gA.AntiEntropySweep(h.ctx)
		h.gB.AntiEntropySweep(h.ctx)
		time.Sleep(20 * time.Millisecond)
	}

	// Measure K steady-state sweeps (no new writes → converged → the gate must skip).
	gateBefore := h.gA.digestGateSkips.Load() + h.gB.digestGateSkips.Load()
	h.gA.stratDiagSnapshotReset()
	h.gB.stratDiagSnapshotReset()
	const K = 6
	for i := 0; i < K; i++ {
		h.gA.AntiEntropySweep(h.ctx)
		h.gB.AntiEntropySweep(h.ctx)
		time.Sleep(20 * time.Millisecond)
	}
	gateAfter := h.gA.digestGateSkips.Load() + h.gB.digestGateSkips.Load()
	exA, fbA, _ := h.gA.stratDiagSnapshotReset()
	exB, fbB, _ := h.gB.stratDiagSnapshotReset()
	exchanges := exA[RegionUnset] + exB[RegionUnset]
	fallbacks := fbA[RegionUnset] + fbB[RegionUnset]
	skips := gateAfter - gateBefore

	// The digest exchange must not have fired (the steady state quiesced).
	if exchanges != 0 {
		t.Fatalf("steady-state digest check failed: a converged mesh fired %d digest exchanges over %d steady-state sweeps (want 0) — the change-gate did not stop the digest flood", exchanges, K)
	}
	if fallbacks != 0 {
		t.Fatalf("steady-state digest check failed: %d oversend fallbacks in the converged steady state (want 0 — a fallback means the gate misread a converged peer as diverged)", fallbacks)
	}
	// The gate must engage, not merely leave the exchange count unchanged: at
	// least K skips.
	if skips < K {
		t.Fatalf("steady-state digest check failed: the change-gate skipped only %d times over %d sweeps (want >= %d — the gate is not engaging; 'no digest' could just be a dead sweep)", skips, K, K)
	}
	t.Logf("steady-state digest check passed: converged mesh fired 0 digest exchanges + 0 fallbacks over %d sweeps; the change-gate skipped %d times (the steady state collapsed to the root-announce)", K, skips)
}

// TestQuiesceGateDisabledFloodsDigest is the negative control for steady-state
// quiescence. With disableChangeGate set, a converged mesh must continue full
// digest exchanges on every sweep. A zero count would mean the control did not
// reach the exchange path.
func TestQuiesceGateDisabledFloodsDigest(t *testing.T) {
	h := newStratifiedHarness(t, true)
	defer h.close()
	h.insertEvents(t, 100)
	if _, converged, _, _ := h.sweepUntilConverged(t, 30, 20*time.Millisecond); !converged {
		t.Fatalf("setup: did not converge")
	}
	// Injection: disable the change-gate on both nodes (the digest fires every
	// sweep regardless of convergence).
	h.gA.disableChangeGate.Store(true)
	h.gB.disableChangeGate.Store(true)
	h.gA.stratDiagSnapshotReset()
	h.gB.stratDiagSnapshotReset()
	const K = 4
	for i := 0; i < K; i++ {
		h.gA.AntiEntropySweep(h.ctx)
		h.gB.AntiEntropySweep(h.ctx)
		time.Sleep(20 * time.Millisecond)
	}
	exA, _, _ := h.gA.stratDiagSnapshotReset()
	exB, _, _ := h.gB.stratDiagSnapshotReset()
	exchanges := exA[RegionUnset] + exB[RegionUnset]
	if exchanges == 0 {
		t.Fatalf("control broken: with the change-gate disabled, a converged mesh fired zero digest exchanges over %d sweeps — the injection is not load-bearing (the passing test would be empty)", K)
	}
	t.Logf("negative control: disabling the change gate caused %d digest exchanges over %d converged sweeps", exchanges, K)
}

// TestGossipExchangeConvergedPrunesToZero drives the complete exchange through
// generateSweepDelta, the peer read loop, respondToDigest, and GenerateDelta.
// A converged pair must produce an empty delta; a non-empty result isolates
// oversend to this wiring rather than the engine primitive or frame codec.
//
// Both engines share one process and maphash implementation, so this test does
// not check cross-process digest determinism. Its 100-key set also fits the
// harness's digest wait under the race detector; larger multi-IBLT exchanges
// need a longer timeout and belong to the cross-process tests.
func TestGossipExchangeConvergedPrunesToZero(t *testing.T) {
	h := newStratifiedHarness(t, true) // stratified anti-entropy enabled
	defer h.close()
	// A modest digest-wait bump over the harness's 200ms loopback default.
	// A 100-key exchange completes in ~10ms; 5s is a generous ceiling so the
	// test tolerates full-package -race load.
	// (The timeout is a ceiling, not a wait — the exchange completes in ~10ms and
	// the timer is stopped on receipt.)
	h.gA.SetDigestWaitTimeout(5 * time.Second)
	h.gB.SetDigestWaitTimeout(5 * time.Second)
	h.insertEvents(t, 100)
	if _, converged, ra, rb := h.sweepUntilConverged(t, 40, 20*time.Millisecond); !converged {
		t.Fatalf("setup: 2-node mesh did not converge (rootA=%x rootB=%x)", ra, rb)
	}
	// Settle so both readLoops are live + the converged state is fully plumbed.
	time.Sleep(150 * time.Millisecond)
	// Call generateSweepDelta directly (bypassing the change-gate, which would
	// skip a converged peer) to force the full request→response→GenerateDelta
	// exchange and measure the delta the wiring produces for a converged peer.
	for attempt := 0; attempt < 6; attempt++ {
		delta := h.gA.generateSweepDelta(h.ctx, h.identB.NodeID)
		n := 0
		if delta != nil {
			delta.Entries(func(string, eng.CRDTEntry) bool { n++; return true })
			delta.Release()
		}
		if n != 0 {
			t.Fatalf("gossip exchange oversend: node A's digest exchange with the converged node B produced a %d-entry delta (want 0) at attempt %d — the mesh wiring oversends a converged peer (an in-process wiring break; distinct from the cross-process maphash oversend this test cannot see)", n, attempt)
		}
	}
	t.Logf("gossip exchange pass: the full gossip digest exchange returns 0 for a converged peer across 6 forced exchanges (the wiring is correct)")
}

// TestMixedMode checks both wire-format directions. A current receiver must
// extract the IBLT from a legacy SE+IBLT frame and ignore its estimator. A
// current node and a node emitting legacy frames must converge over loopback
// TLS. Finally, parsing an IBLT-only frame with the legacy nil-only SE guard
// must produce a malformed-SE error, selecting oversend instead of a wrong
// difference.
func TestMixedMode(t *testing.T) {
	// A current receiver accepts a legacy sender's frame.
	t.Run("NewReceiverParsesOldFrame", func(t *testing.T) {
		sender := [16]byte{0x0A}
		oldFrame, _ := digestEfficiencyRealSEFrame(t, sender, 64) // SE+IBLT (the legacy wire shape)
		seBody, ibltBody := digestFrameSplit(oldFrame)
		if len(seBody) == 0 {
			t.Fatalf("invalid: the old frame has an empty SE body — it is not exercising the SE+IBLT path")
		}
		g := &Gossiper{}
		ch := make(chan *peerDigest, 1)
		g.deliverPeerDigest(sender, ch, seBody, ibltBody, digestFrameStamp(oldFrame)) // the wire stamp rides the deposit (behavior-neutral for these unit calls)
		select {
		case pd := <-ch:
			if pd.iblt == nil {
				t.Fatalf("new receiver failed to parse an old (SE+IBLT) frame's IBLT — a mixed cluster would not converge")
			}
			if pd.iblt.NumBuckets() != 1024 {
				t.Fatalf("legacy frame's IBLT has %d buckets, want 1024", pd.iblt.NumBuckets())
			}
		default:
			t.Fatalf("new receiver dropped an old (SE+IBLT) frame")
		}
	})

	// A current node and a legacy-SE node converge over loopback TLS.
	t.Run("NewAndLegacyConverge", func(t *testing.T) {
		h := newStratifiedHarness(t, true) // stratified anti-entropy enabled
		defer h.close()
		// B emulates a legacy node: it emits SE+IBLT (the legacy wire shape).
		h.gB.digestLegacySE.Store(true)
		h.insertEvents(t, 200)
		rounds, converged, ra, rb := h.sweepUntilConverged(t, 40, 20*time.Millisecond)
		if !converged {
			t.Fatalf("mixed-mode: new(A) + legacy(B) did not converge in %d rounds (rootA=%x rootB=%x) — the wire-version bump broke mixed-cluster convergence", rounds, ra, rb)
		}
		if ra != rb {
			t.Fatalf("mixed-mode: converged but roots differ (A=%x B=%x) — a wrong diff, not a convergence", ra, rb)
		}
		t.Logf("IBLT-only node and legacy SE+IBLT node converged to the same root in %d rounds", rounds)
	})

	// A legacy receiver falls back to oversend for a current sender's frame.
	t.Run("OldReceiverDegradesSafely", func(t *testing.T) {
		sender := [16]byte{0x0B}
		mIBLT, seed := digestEfficiencyRealIBLT(t, sender, 64)
		newFrame := buildDigestFrame(digestRoleRequest, sender, seed, nil /* IBLT-only */, mIBLT)
		seBody, _ := digestFrameSplit(newFrame)
		// The legacy nil-only guard parses the empty but non-nil SE body. Its
		// error must select oversend rather than a wrong difference.
		if seBody == nil {
			t.Fatalf("IBLT-only frame returned a nil seBody; the legacy nil-only guard simulation requires a non-nil empty slice")
		}
		if _, err := eng.UnmarshalStrataEstimator(seBody); err == nil {
			t.Fatalf("legacy guard parsed an absent SE without error; rollback would not select oversend")
		}
		t.Logf("legacy receiver parsing an IBLT-only frame gets a malformed-SE error and selects oversend")
	})
}

// TestOffIsByteIdentical verifies that the default disabled configuration
// allocates no peerRoots or diagnostic state, emits no root announcements,
// does not advance gate counters, and converges through the original oversend
// path. An incoming root announcement is ignored without a response.
func TestOffIsByteIdentical(t *testing.T) {
	// A disabled gossiper has no gate state and ignores a root announcement.
	g := &Gossiper{}
	g.SetStratifiedAntiEntropy(false)
	if g.peerRoots != nil {
		t.Fatalf("disabled node allocated the peerRoots map")
	}
	if g.stratDiag != nil {
		t.Fatalf("disabled node allocated stratDiag")
	}
	// A disabled node drops an incoming root announcement without recording it
	// or sending a response.
	root := [32]byte{0xDE, 0xAD}
	rootFrame := buildRootAnnounceFrame([16]byte{0x01}, root)
	g.DeliverDigest([16]byte{}, rootFrame)
	if g.peerRoots != nil && len(g.peerRoots) != 0 {
		t.Fatalf("disabled node recorded a root-announce — the disabled path is not byte-identical")
	}
	if got := g.digestRespondSent.Load(); got != 0 {
		t.Fatalf("disabled node responded to a root announcement (digestRespondSent=%d), want 0", got)
	}
	if got := g.digestGateSkips.Load(); got != 0 {
		t.Fatalf("disabled node advanced the gate-skip counter to %d, want 0", got)
	}

	// End to end, a disabled two-node mesh converges through oversend and
	// accumulates no gate state or skips.
	h := newStratifiedHarness(t, false) // stratified anti-entropy disabled
	defer h.close()
	h.insertEvents(t, 500)
	rounds, converged, ra, rb := h.sweepUntilConverged(t, 15, 20*time.Millisecond)
	if !converged {
		t.Fatalf("disabled mesh did not converge in %d rounds (the byte-identical oversend path regressed)", rounds)
	}
	if ra != rb {
		t.Fatalf("disabled mesh converged but roots differ (A=%x B=%x)", ra, rb)
	}
	if h.gA.digestGateSkips.Load() != 0 || h.gB.digestGateSkips.Load() != 0 {
		t.Fatalf("disabled mesh advanced the gate-skip counter (A=%d B=%d) — the gate is active on the disabled path", h.gA.digestGateSkips.Load(), h.gB.digestGateSkips.Load())
	}
	if h.gA.peerRoots != nil || h.gB.peerRoots != nil {
		t.Fatalf("disabled mesh allocated the peerRoots map")
	}
	t.Logf("disabled mesh converged %d events through oversend in %d rounds with no peerRoots or gate skips", 500, rounds)
}
