// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover shared-delta construction and relay-cache initialization.
// A batch sweep over two peers with the same delta must build and sort that
// delta once, and the resulting buffer must contain exactly the inserted set.
// shipBuildProbe captures the production buffer before the sweep sends it.
//
// Stratified anti-entropy computes a different delta for each peer, so those
// buffers must remain separate. An armed defer window also requires the
// per-peer walker even if the deferHandler field is false. A final comparison
// drives the same inserts through the shared and per-peer implementations and
// checks their contents and shipped-entry counts.
//
// Expectations come from engine state and payloadCache entries captured through
// the production probe, not from sweep timing or a fixed dot sequence.

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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

// RelaySharedNode holds the network, identity, engine, and gossip state for
// one node in the shared-delta harness.
type RelaySharedNode struct {
	ln     net.Listener
	ident  *NodeIdentity
	engine *eng.DeltaCRDTEngine
	recv   *receive.Receiver
	dir    *identity.Directory
	ps     *PeerSet
	g      *Gossiper
	addr   string
}

// RelaySharedHarness is an N-node loopback TLS mesh with manually selected
// edges. WireRelayHooks enables retention on every receiver so lazy relayCache
// layers are initialized by real incoming frames.
type RelaySharedHarness struct {
	nodes  []*RelaySharedNode
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
	// ca and caPath are the harness's mesh CA — all peers must mint from the
	// same CA the harness nodes' transports trust, or cross-dial fails with
	// x509 unknown-authority.
	ca     *crypto.MeshCA
	caPath string
}

// runMeshAcceptLoop mirrors runAcceptLoopWithPeerSet and also tracks every
// serveTestConn goroutine in wg. Closing the peer connections lets each handler
// finish its in-flight frame and return. wg.Wait then joins all accept-side
// handlers before the harness closes an engine, so no frame apply can race
// engine.Close.
func runMeshAcceptLoop(ctx context.Context, ln net.Listener, recv any, digester DigestSink, wg *sync.WaitGroup, peerSet *PeerSet) {
	defer wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveTestConn(ctx, conn, recv, digester, peerSet)
		}()
	}
}

func newRelaySharedHarness(t *testing.T, n int, arenaMB int) *RelaySharedHarness {
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
	h := &RelaySharedHarness{ca: ca, caPath: caPath}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.wg = &sync.WaitGroup{}
	for i := 0; i < n; i++ {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := cryptorand.Read(seed); err != nil {
			t.Fatalf("rand seed %d: %v", i, err)
		}
		ident, err := NewNodeIdentity(seed)
		if err != nil {
			t.Fatalf("NewNodeIdentity %d: %v", i, err)
		}
		engDir := filepath.Join(dir, fmt.Sprintf("eng%d", i))
		if err := os.MkdirAll(engDir, 0o755); err != nil {
			t.Fatalf("mkdir eng%d: %v", i, err)
		}
		eng.DataDir = engDir
		arena := arenaMB
		if arena <= 0 {
			arena = 64
		}
		engine, err := eng.NewDeltaCRDTEngine(ident.NodeID, 1, uintptr(arena)*1024*1024)
		if err != nil {
			t.Fatalf("NewDeltaCRDTEngine %d: %v", i, err)
		}
		nodeDir := identity.NewDirectory()
		recv := receive.NewReceiver(admission.NewPeerBucket(),
			clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engine),
			clock.NewSystemClock(), nodeDir, engine, 50_000_000)
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
		g.WireRelayHooks(recv) // retention enabled — the lazy relayCache initialization runs real retains
		h.nodes = append(h.nodes, &RelaySharedNode{ln: ln, ident: ident, engine: engine, recv: recv, dir: nodeDir, ps: ps, g: g, addr: ln.Addr().String()})
		h.wg.Add(1)
		// The gossiper answers digest requests on the accept side. A nil
		// digester would force fallback full-set sends instead of exercising
		// the per-peer deltas that the stratified test needs.
		go runMeshAcceptLoop(h.ctx, ln, recv, g, h.wg, ps)
	}
	return h
}

// connect registers each node's public key before dialing from i to j. The
// accept side installs the reverse peer, producing one bidirectional verified
// connection. Both ends must complete egress verification before a sweep;
// otherwise the sweep skips the peer and the probes observe no shipment.
func (h *RelaySharedHarness) connect(t *testing.T, i, j int) {
	t.Helper()
	// Register both public keys before dialing. The one-shot challenge response
	// is verified as soon as it arrives; without a directory entry it is dropped
	// as challengeNoEntry, leaving the edge without egress verification and
	// causing subsequent sweeps to skip it.
	_ = h.nodes[i].g.RegisterPeer(h.nodes[j].ident.NodeID, h.nodes[j].ident.Pub)
	_ = h.nodes[j].g.RegisterPeer(h.nodes[i].ident.NodeID, h.nodes[i].ident.Pub)
	// Dial once and let the accept side install the reverse peer. Independent
	// dials in both directions create declined duplicates without verified node
	// identities, which cannot carry digest exchanges or root announcements.
	if err := h.nodes[i].ps.Dial(h.ctx, h.nodes[j].addr, "localhost", h.nodes[j].ident.NodeID); err != nil {
		t.Fatalf("dial %d->%d: %v", i, j, err)
	}
	asyncWait(t, h.nodes[i].ps, h.nodes[j].ident.NodeID)
	asyncWait(t, h.nodes[j].ps, h.nodes[i].ident.NodeID) // j's accept-side install
	h.waitForEgress(t, i, j)
	h.waitForEgress(t, j, i) // both ends settle: the responder's ship gate reads j's own bit
}

// waitForEgress waits for challenge verification before probes are installed.
// The sweep skips unverified peers, which would otherwise leave the captures
// empty.
func (h *RelaySharedHarness) waitForEgress(t *testing.T, i int, peers ...int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ok := true
		for _, j := range peers {
			if !h.nodes[i].ps.egressVerified(h.nodes[j].ident.NodeID) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("node %d's egress edges to %v did not verify within 10s; sweeps would skip these peers", i, peers)
}

func (h *RelaySharedHarness) close() {
	h.cancel()
	for _, n := range h.nodes {
		_ = n.ln.Close()
	}
	// Close connections before joining accept-side handlers. A handler blocked
	// in ReadFrame returns on its closed connection; one in DispatchFrame first
	// finishes its apply. ps.Close closes pc.done itself, so its done wait does
	// not join these handler goroutines; the WaitGroup below provides that join.
	for _, n := range h.nodes {
		_ = n.ps.Close()
	}
	// Join every accept-side serveTestConn tracked by runMeshAcceptLoop.
	// Dial-side read loops and digest responders are not joined here. These
	// tests avoid depending on either during teardown: B and C send no data
	// frames to A, and digest responses complete before close. A test that
	// changes that traffic pattern must add the corresponding synchronization.
	h.wg.Wait()
	// Close each engine before t.TempDir removes its files so asynchronous WAL
	// and flush work cannot recreate a file during removal. The accept-side join
	// above prevents further frame applies from reaching Close.
	for _, n := range h.nodes {
		_ = n.engine.Close()
	}
}

// holds reports whether node's engine state carries every key.
func (h *RelaySharedHarness) holds(node int, keys []string) bool {
	for _, k := range keys {
		if len(h.nodes[node].engine.PointGet(k)) == 0 {
			return false
		}
	}
	return true
}

// holdsBounded waits for asynchronous receive-side application before the
// caller changes modes or inspects retained state.
func (h *RelaySharedHarness) holdsBounded(t *testing.T, node int, keys []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.holds(node, keys) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("node %d did not receive all %d pre-seeded keys before the deadline", node, len(keys))
}

// eventsOfSet builds the sorted BuiltEvent set the ship buffer must equal —
// each entry's state-stamped dot plus the payload recorded at that dot,
// sorted by DotCounter like the production buffer.
func (h *RelaySharedHarness) eventsOfSet(t *testing.T, node int, keys []string) []BuiltEvent {
	t.Helper()
	evs := make([]BuiltEvent, 0, len(keys))
	for _, k := range keys {
		ents := h.nodes[node].engine.PointGet(k)
		if len(ents) == 0 {
			t.Fatalf("node %d state does not contain key %s", node, k)
		}
		e := ents[0]
		dot := eng.CausalDot{NodeID: e.DotNodeID, Counter: e.DotCounter}
		payload, ok := h.nodes[node].g.cache.lookup(k, dot)
		if !ok {
			t.Fatalf("node %d payloadCache does not contain %s at state-stamped dot %v", node, k, dot)
		}
		evs = append(evs, BuiltEvent{EntityID: k, Payload: payload, Entry: e})
	}
	slicesSortByDot(evs)
	return evs
}

func slicesSortByDot(evs []BuiltEvent) {
	for i := 1; i < len(evs); i++ {
		for j := i; j > 0 && evs[j-1].Entry.DotCounter > evs[j].Entry.DotCounter; j-- {
			evs[j-1], evs[j] = evs[j], evs[j-1]
		}
	}
}

// armContentProbe installs the content capture before inserting or sweeping and
// clears it during cleanup.
func armContentProbe(t *testing.T, g *Gossiper) *[]shipBuildCapture {
	t.Helper()
	caps := &[]shipBuildCapture{}
	g.shipBuildProbe.Store(caps)
	t.Cleanup(func() { g.shipBuildProbe.Store(nil) })
	return caps
}

// TestRelaySharedDeltaByteEquality compares captured build buffers with the
// inserted set. A non-stratified batch sweep over two peers has one shared
// delta, so any per-peer buffers must be pairwise equal and contain exactly the
// inserted events. The production implementation builds that shared delta once.
func TestRelaySharedDeltaByteEquality(t *testing.T) {
	h := newRelaySharedHarness(t, 3, 64)
	defer h.close()
	const A, B, C = 0, 1, 2
	h.connect(t, A, B)
	h.connect(t, A, C)
	for i := range h.nodes {
		h.nodes[i].g.SetBatchSize(100)
	}
	h.waitForEgress(t, A, B, C)

	const nKeys = 60
	var keys []string
	for i := 0; i < nKeys; i++ {
		k := fmt.Sprintf("shared-delta-key-%d", i)
		h.nodes[A].g.InsertLocalEvents(k, fmt.Sprintf("payload-%03d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(1000 + i)})
		keys = append(keys, k)
	}
	caps := armContentProbe(t, h.nodes[A].g)
	st := h.nodes[A].g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes == 0 {
		t.Fatalf("sweep shipped no envelopes, so no shared-delta build was exercised")
	}
	if len(*caps) < 1 {
		t.Fatalf("captured %d builds, want at least 1", len(*caps))
	}
	for i := range *caps {
		c := &(*caps)[i]
		t.Logf("capture peer=%x n=%d walkSortNs=%d", c.peer, len(c.buf), c.walkSort.Nanoseconds())
	}
	for i := 1; i < len(*caps); i++ {
		a, b := (*caps)[0].buf, (*caps)[i].buf
		if len(a) != len(b) {
			t.Fatalf("capture %d holds %d events, capture 0 holds %d; shared-delta buffers must have equal length", i, len(b), len(a))
		}
		for k := range a {
			if a[k] != b[k] {
				t.Fatalf("capture %d differs from capture 0 at index %d: %s vs %s", i, k, b[k].EntityID, a[k].EntityID)
			}
		}
	}
	expected := h.eventsOfSet(t, A, keys)
	if len(expected) != len((*caps)[0].buf) {
		t.Fatalf("capture holds %d events, inserted set has %d", len((*caps)[0].buf), len(expected))
	}
	for k := range expected {
		if expected[k] != (*caps)[0].buf[k] {
			t.Fatalf("buffer index %d holds %s, inserted set has %s", k, (*caps)[0].buf[k].EntityID, expected[k].EntityID)
		}
	}
	t.Logf("%d captured build(s) matched the %d-key inserted set", len(*caps), nKeys)
}

// TestRelaySharedDeltaSingleSort requires one build and sort per non-stratified
// batch sweep, even with two recipients. Each capture corresponds to a walk and
// sort. SOVEREIGN_TEST_FAULT_BOUNDED_GOSSIP=sorts restores per-peer construction
// as a negative control.
func TestRelaySharedDeltaSingleSort(t *testing.T) {
	h := newRelaySharedHarness(t, 3, 64)
	defer h.close()
	const A, B, C = 0, 1, 2
	h.connect(t, A, B)
	h.connect(t, A, C)
	for i := range h.nodes {
		h.nodes[i].g.SetBatchSize(100)
	}
	h.waitForEgress(t, A, B, C)
	for i := 0; i < 60; i++ {
		h.nodes[A].g.InsertLocalEvents(fmt.Sprintf("single-sort-key-%d", i), fmt.Sprintf("v-%03d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_100_000 + i), H3Index: uint64(2000 + i)})
	}
	caps := armContentProbe(t, h.nodes[A].g)
	st := h.nodes[A].g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes == 0 {
		t.Fatalf("sweep shipped no envelopes, so no build was exercised")
	}
	for i := range *caps {
		c := &(*caps)[i]
		t.Logf("sort capture %d: peer=%x n=%d walkSortNs=%d", i, c.peer, len(c.buf), c.walkSort.Nanoseconds())
	}
	if got := len(*caps); got != 1 {
		t.Fatalf("shared delta was built and sorted %d times, want exactly once per sweep", got)
	}
	t.Logf("shared delta was built and sorted once")
}

// TestRelaySharedDeltaStratifiedFence pre-seeds B with Y and C with X, then
// enables stratified anti-entropy. A's next sweep must send X to B and Y to C.
// Sharing one build across these peers would send the wrong entries because
// stratified deltas come from per-peer digest exchanges.
func TestRelaySharedDeltaStratifiedFence(t *testing.T) {
	h := newRelaySharedHarness(t, 3, 64)
	defer h.close()
	const A, B, C = 0, 1, 2
	h.connect(t, A, B)
	h.connect(t, A, C)
	for i := range h.nodes {
		h.nodes[i].g.SetBatchSize(100)
	}
	h.waitForEgress(t, A, B, C)

	var xKeys, yKeys []string
	for i := 0; i < 30; i++ {
		xk := fmt.Sprintf("stratified-fence-x-%d", i)
		yk := fmt.Sprintf("stratified-fence-y-%d", i)
		h.nodes[A].g.InsertLocalEvents(xk, fmt.Sprintf("x-%03d", i), eng.CRDTEntry{SystemTime: int64(1_700_200_000 + i), H3Index: uint64(3000 + i)})
		h.nodes[A].g.InsertLocalEvents(yk, fmt.Sprintf("y-%03d", i), eng.CRDTEntry{SystemTime: int64(1_700_300_000 + i), H3Index: uint64(4000 + i)})
		xKeys = append(xKeys, xk)
		yKeys = append(yKeys, yk)
	}
	if _, _, err := h.nodes[A].g.ShipBatch(context.Background(), h.nodes[B].ident.NodeID, h.eventsOfSet(t, A, yKeys)); err != nil {
		t.Fatalf("pre-seed B: %v", err)
	}
	if _, _, err := h.nodes[A].g.ShipBatch(context.Background(), h.nodes[C].ident.NodeID, h.eventsOfSet(t, A, xKeys)); err != nil {
		t.Fatalf("pre-seed C: %v", err)
	}
	h.holdsBounded(t, B, yKeys)
	h.holdsBounded(t, C, xKeys)

	for i := range h.nodes {
		h.nodes[i].g.SetStratifiedAntiEntropy(true)
	}
	// A fallback round builds the full key set, which cannot distinguish correct
	// per-peer deltas from accidental sharing. Count callbacks from
	// SetStratifiedFallbackReporter and retry such rounds with fresh divergence
	// sets: the fallback may have converged the original sets, causing the next
	// sweep to skip shipment. Exhausting the retry bound without a clean
	// stratified exchange is a failure.
	var fb atomic.Uint64
	h.nodes[A].g.SetStratifiedFallbackReporter(func() { fb.Add(1) })
	const maxFenceRounds = 5
	var byPeer map[[16]byte][]BuiltEvent
	var xE, yE []string
	cleanRound := 0
	for round := 1; round <= maxFenceRounds; round++ {
		xE, yE = xKeys, yKeys // round 1: the original pre-seeded divergence
		if round > 1 {
			// Fallback may have converged the original sets. Insert fresh dots
			// and restore complementary divergence before retrying.
			xE, yE = nil, nil
			for i := 0; i < 30; i++ {
				xk := fmt.Sprintf("stratified-fence-x-r%d-%d", round, i)
				yk := fmt.Sprintf("stratified-fence-y-r%d-%d", round, i)
				h.nodes[A].g.InsertLocalEvents(xk, fmt.Sprintf("x%02d-%02d", round, i), eng.CRDTEntry{SystemTime: int64(1_701_000_000 + round*100 + i), H3Index: uint64(11000 + round*100 + i)})
				h.nodes[A].g.InsertLocalEvents(yk, fmt.Sprintf("y%02d-%02d", round, i), eng.CRDTEntry{SystemTime: int64(1_701_100_000 + round*100 + i), H3Index: uint64(12000 + round*100 + i)})
				xE = append(xE, xk)
				yE = append(yE, yk)
			}
			if _, _, err := h.nodes[A].g.ShipBatch(context.Background(), h.nodes[B].ident.NodeID, h.eventsOfSet(t, A, yE)); err != nil {
				t.Fatalf("re-seed B (round %d): %v", round, err)
			}
			if _, _, err := h.nodes[A].g.ShipBatch(context.Background(), h.nodes[C].ident.NodeID, h.eventsOfSet(t, A, xE)); err != nil {
				t.Fatalf("re-seed C (round %d): %v", round, err)
			}
			h.holdsBounded(t, B, yE)
			h.holdsBounded(t, C, xE)
		}
		before := fb.Load()
		caps := armContentProbe(t, h.nodes[A].g)
		st := h.nodes[A].g.AntiEntropySweep(context.Background())
		if st.shippedEnvelopes == 0 {
			t.Fatalf("round %d shipped no envelopes, so no per-peer build was captured", round)
		}
		if delta := fb.Load() - before; delta > 0 {
			t.Logf("round %d used full-keyset fallback %d time(s); retrying with fresh divergence", round, delta)
			continue
		}
		cleanRound = round
		byPeer = map[[16]byte][]BuiltEvent{}
		for i := range *caps {
			c := (*caps)[i]
			byPeer[c.peer] = c.buf
			t.Logf("fence capture (round %d) peer=%x n=%d walkSortNs=%d", round, c.peer, len(c.buf), c.walkSort.Nanoseconds())
		}
		break
	}
	if cleanRound == 0 {
		t.Fatalf("all %d rounds used full-keyset fallback; no clean stratified exchange was observed", maxFenceRounds)
	}
	// Report production digest and challenge counters to distinguish request
	// delivery, identity verification, response egress, and responder behavior.
	for _, n := range []int{A, B, C} {
		t.Logf("fence diag node %d: digestSeamDrops=%d respondSent=%d unverifiedDrops=%d identityDrops=%d respondEgressDrops=%d nilGuardDrops=%d challengeReplay=%d challengeMismatch=%d challengeNoEntry=%d challengeSigFail=%d challengeVerified=%d",
			n, h.nodes[n].ps.digestSeamDrops.Load(), h.nodes[n].g.digestRespondSent.Load(),
			h.nodes[n].g.digestUnverifiedDrops.Load(), h.nodes[n].g.digestIdentityDrops.Load(),
			h.nodes[n].g.digestRespondEgressDrops.Load(), h.nodes[n].g.deliverDigestNilGuardDrops.Load(),
			h.nodes[n].ps.challengeReplay.Load(), h.nodes[n].ps.challengeMismatch.Load(),
			h.nodes[n].ps.challengeNoEntry.Load(), h.nodes[n].ps.challengeSigFail.Load(),
			h.nodes[n].ps.challengeVerified.Load())
	}
	capB, okB := byPeer[h.nodes[B].ident.NodeID]
	capC, okC := byPeer[h.nodes[C].ident.NodeID]
	if !okB || !okC {
		t.Fatalf("missing per-peer build: B captured=%v, C captured=%v", okB, okC)
	}
	setB, setC := entityIDSet(capB), entityIDSet(capC)
	if !sameKeySet(setB, xE) {
		t.Fatalf("round %d sent B %d keys (%v...), want its X delta of %d keys", cleanRound, len(setB), sampleKeys(setB, 5), len(xE))
	}
	if !sameKeySet(setC, yE) {
		t.Fatalf("round %d sent C %d keys (%v...), want its Y delta of %d keys", cleanRound, len(setC), sampleKeys(setC, 5), len(yE))
	}
	t.Logf("round %d without fallback sent B its X delta (%d keys) and C its Y delta (%d keys)", cleanRound, len(setB), len(setC))
}

func entityIDSet(buf []BuiltEvent) map[string]bool {
	set := make(map[string]bool, len(buf))
	for i := range buf {
		set[buf[i].EntityID] = true
	}
	return set
}

func sameKeySet(got map[string]bool, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, k := range want {
		if !got[k] {
			return false
		}
	}
	return true
}

func sampleKeys(set map[string]bool, n int) []string {
	out := make([]string, 0, n)
	for k := range set {
		out = append(out, k)
		if len(out) == n {
			break
		}
	}
	return out
}

// TestRelaySharedDeltaDeferFence checks that an armed per-peer shipWindow
// forces per-peer construction even after SetDeferHandler(false). The dispatch
// predicate is deferState[peerID].shipWindow, not the deferHandler field, and
// disabling the field does not clear an existing window. Sharing one build in
// this state would apply the first peer's defer window to every recipient and
// charge every entry as cost one, undercounting foreign batches in the window's
// received-cost budget.
func TestRelaySharedDeltaDeferFence(t *testing.T) {
	h := newRelaySharedHarness(t, 3, 64)
	defer h.close()
	const A, B, C = 0, 1, 2
	h.connect(t, A, B)
	h.connect(t, A, C)
	for i := range h.nodes {
		h.nodes[i].g.SetBatchSize(100)
	}
	h.waitForEgress(t, A, B, C)
	// Arm B's window directly, then disable the handler field. The existing
	// shipWindow survives because the field-gated clear paths no longer run.
	h.nodes[A].g.SetDeferHandler(true)
	h.nodes[A].g.deferState[h.nodes[B].ident.NodeID] = peerDeferState{shipWindow: true, sEst: 100}
	h.nodes[A].g.SetDeferHandler(false)
	for i := 0; i < 60; i++ {
		h.nodes[A].g.InsertLocalEvents(fmt.Sprintf("defer-fence-key-%d", i), fmt.Sprintf("dv-%03d", i),
			eng.CRDTEntry{SystemTime: int64(1_700_800_000 + i), H3Index: uint64(9000 + i)})
	}
	caps := armContentProbe(t, h.nodes[A].g)
	st := h.nodes[A].g.AntiEntropySweep(context.Background())
	if st.shippedEnvelopes == 0 {
		t.Fatalf("sweep shipped no envelopes, so the defer-window path was not exercised")
	}
	if got := len(*caps); got != 2 {
		t.Fatalf("captured %d builds with B's shipWindow armed and deferHandler disabled, want 2 per-peer builds", got)
	}
	t.Logf("armed shipWindow retained per-peer construction with deferHandler disabled")
}

// TestRelayHoistMatchesPerPeerWalker drives the same inserts through the shared
// builder and the per-peer walker selected by fault injection. Their captured
// key unions and shipped-entry counts must agree, and both receivers must hold
// the full set. This comparison covers self-originated content, not foreign
// replay or ordering differences within a batch.
func TestRelayHoistMatchesPerPeerWalker(t *testing.T) {
	const nKeys = 50
	drive := func(perPeer bool) (union map[string]bool, shipped int) {
		h := newRelaySharedHarness(t, 3, 64)
		defer h.close()
		const A, B, C = 0, 1, 2
		h.connect(t, A, B)
		h.connect(t, A, C)
		for i := range h.nodes {
			h.nodes[i].g.SetBatchSize(100)
		}
		h.waitForEgress(t, A, B, C)
		if perPeer {
			h.nodes[A].g.redPerPeerSortBugInject.Store(true)
		}
		var keys []string
		for i := 0; i < nKeys; i++ {
			k := fmt.Sprintf("walker-compare-key-%d", i)
			h.nodes[A].g.InsertLocalEvents(k, fmt.Sprintf("tie-%03d", i),
				eng.CRDTEntry{SystemTime: int64(1_700_900_000 + i), H3Index: uint64(10000 + i)})
			keys = append(keys, k)
		}
		caps := armContentProbe(t, h.nodes[A].g)
		st := h.nodes[A].g.AntiEntropySweep(context.Background())
		if st.shippedEnvelopes == 0 {
			t.Fatalf("sweep shipped no envelopes with perPeer=%v", perPeer)
		}
		union = map[string]bool{}
		for i := range *caps {
			for k := range entityIDSet((*caps)[i].buf) {
				union[k] = true
			}
		}
		// The receive goroutine applies published batches asynchronously.
		for _, n := range []int{B, C} {
			h.holdsBounded(t, n, keys)
		}
		return union, st.shippedEntries
	}
	hoistUnion, hoistShipped := drive(false)
	perPeerUnion, perPeerShipped := drive(true)
	if len(hoistUnion) != nKeys {
		t.Fatalf("shared-builder capture union holds %d keys, want %d", len(hoistUnion), nKeys)
	}
	if len(perPeerUnion) != nKeys {
		t.Fatalf("per-peer capture union holds %d keys, want %d", len(perPeerUnion), nKeys)
	}
	for k := range hoistUnion {
		if !perPeerUnion[k] {
			t.Fatalf("shared builder shipped %s but the per-peer walker did not", k)
		}
	}
	if hoistShipped != perPeerShipped {
		t.Fatalf("shipped-entry counts differ: shared=%d per-peer=%d", hoistShipped, perPeerShipped)
	}
	t.Logf("shared and per-peer walkers agreed on %d keys and %d shipped entries", nKeys, hoistShipped)
}
