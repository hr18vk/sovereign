// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests guard the gateway connection checks in ADR-0068. An impostor
// presents a CA-signed leaf naming another node and takes that node's routing
// slot. Routing through PeerSet.Publish remains available, but an unverified
// connection must not receive sweep data or digest responses, and its root
// announcements must not enter peerRoots.
//
// The assertions use shippedEntries, framesReceived, peerRoots, gate counters,
// and the engine root. They also cover wrong-key and replayed challenge
// responses, missing directory entries, and a mutually verified pair.
package mesh

import (
	"context"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// gatewayConnFrames reads the dial-side peerConn's framesReceived counter for
// peerID. The counter advances before dispatch, so connect-time frames are
// included. A missing connection returns zero; callers check that condition
// separately because it invalidates the measurement.
func gatewayConnFrames(t *testing.T, ps *PeerSet, peerID [16]byte) uint64 {
	t.Helper()
	ps.mu.RLock()
	pc := ps.peers[peerID]
	var n uint64
	if pc != nil {
		n = atomic.LoadUint64(&pc.framesReceived)
	}
	ps.mu.RUnlock()
	return n
}

// gatewayWaitConnFramesQuiet polls framesReceived until three consecutive
// 150 ms samples agree or five seconds elapse. A frame arriving during the
// window resets the quiet count, so the caller's before-and-after delta still
// observes asynchronous deliveries.
func gatewayWaitConnFramesQuiet(t *testing.T, ps *PeerSet, peerID [16]byte) uint64 {
	t.Helper()
	last := gatewayConnFrames(t, ps, peerID)
	quiet := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		cur := gatewayConnFrames(t, ps, peerID)
		if cur == last {
			quiet++
			if quiet >= 3 {
				return cur
			}
		} else {
			quiet = 0
			last = cur
		}
	}
	return last
}

// TestGatewaySweepExfilBlocked converges V and X, closes both
// edges, and lets M take X's slot with an impostor leaf. A direct routing probe
// must still reach M, but V's sweep must ship no entries or delta-plane frames
// to the unverified connection.
func TestGatewaySweepExfilBlocked(t *testing.T) {
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	root := t.TempDir()
	caPath, err := ca.WriteCAPEM(root)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v := newEclipseNode(t, ca, caPath, root, "Vsweep", 0x51, false, false)
	x := newEclipseNode(t, ca, caPath, root, "Xsweep", 0x52, false, false)
	m := newEclipseNode(t, ca, caPath, root, "Msweep", 0x53, false, false)
	if err := v.dir.Register(x.ident.NodeID, x.ident.Pub); err != nil {
		t.Fatalf("register X in V: %v", err)
	}
	if err := x.dir.Register(v.ident.NodeID, v.ident.Pub); err != nil {
		t.Fatalf("register V in X: %v", err)
	}
	eclipseMint(v, "gatewayv", 120)
	eclipseMint(x, "gatewayx", 30)
	eclipseWire(t, ctx, v, x)
	eclipseConverge(t, ctx, v, x, 8)
	held := eclipseCount(v, "gatewayv", 120) + eclipseCount(v, "gatewayx", 30)
	if held != 150 {
		t.Fatalf("gateway sweep premise: V holds %d of 150 baseline entries — the baseline did not converge", held)
	}
	rootVPre := v.engine.MerkleRootFromShards()

	// Close both V-X edges before M dials with a leaf naming X.
	mPs := eclipseImpostor(t, ca, caPath, root, "gateway-sweep", x.ident.NodeID, m)
	if err := v.ps.ClosePeer(x.ident.NodeID); err != nil {
		t.Fatalf("kill V->X: %v", err)
	}
	if err := x.ps.ClosePeer(v.ident.NodeID); err != nil {
		t.Fatalf("kill X->V: %v", err)
	}
	eclipseAwaitAbsent(t, v.ps, x.ident.NodeID)
	eclipseAwaitAbsent(t, x.ps, v.ident.NodeID)
	if err := mPs.Dial(ctx, v.addr, "localhost", v.ident.NodeID); err != nil {
		t.Fatalf("M dials V (the landing): %v", err)
	}
	landed := false
	landDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(landDeadline) {
		v.ps.mu.RLock()
		_, ok := v.ps.peers[x.ident.NodeID]
		v.ps.mu.RUnlock()
		if ok {
			landed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !landed {
		t.Fatalf("gateway sweep setup: the impostor did not occupy the X-slot within 10s")
	}
	asyncWait(t, mPs, v.ident.NodeID)

	// Direct Publish routing must remain available even though sweep egress is
	// restricted to verified connections.
	probeBefore := m.sink.total.Load()
	if err := v.ps.Publish(x.ident.NodeID, receive.LengthPrefixFrame([]byte("gateway-routing-probe"))); err != nil {
		t.Fatalf("gateway sweep routing probe: Publish to the X-slot failed: %v", err)
	}
	probeDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(probeDeadline) {
		if m.sink.total.Load() > probeBefore {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m.sink.total.Load() == probeBefore {
		t.Fatalf("gateway sweep routing probe: the probe never reached M — the X-slot does not route (routing must stay preserved)")
	}

	// Settle asynchronous delivery, snapshot the frame count, drive V's sweep,
	// and settle again before measuring the delta.
	before := gatewayWaitConnFramesQuiet(t, mPs, v.ident.NodeID)
	st := v.g.AntiEntropySweep(ctx)
	after := gatewayWaitConnFramesQuiet(t, mPs, v.ident.NodeID)
	// A zero ship count is meaningful only if this sweep visited the
	// unverified peer and counted its dropped iteration.
	if st.egressUnverified < 1 {
		t.Fatalf("gateway sweep: the driven sweep counted %d egressUnverified drops (want >= 1) — the gate never fired; 0 shipped could mean 0 attempted", st.egressUnverified)
	}
	if drops := v.g.egressUnverifiedDrops.Load(); drops < 1 {
		t.Fatalf("gateway sweep: cumulative egressUnverifiedDrops %d (want >= 1) — the loop-top gate's counter is unwired", drops)
	}
	// The connection receives exactly two handshake frames and the routing
	// probe. Any delta-plane frame makes this census fail.
	if total := after; total != 3 {
		t.Fatalf("gateway sweep: M's conn received %d frames total (want exactly 3: the two handshake frames + the routing probe — any data-plane frame fails this census)", total)
	}
	if st.shippedEntries != 0 {
		t.Fatalf("V's sweep shipped %d of %d held entries to the unverified X-slot, want 0", st.shippedEntries, held)
	}
	if delta := after - before; delta != 0 {
		t.Fatalf("M received %d delta-plane frames from V's sweep (framesReceived %d -> %d), want 0", delta, before, after)
	}
	if got := v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed from %x to %x during the egress check", rootVPre, got)
	}
	t.Logf("V's sweep shipped no entries or frames to M (framesReceived %d -> %d); direct routing still delivered the probe", before, after)
}

// gatewayExfilHarness enables V's stratified digest surface and accept loop,
// then connects M with a leaf naming x. V's Directory has no key for M or x,
// so a frame stamped with x cannot be authenticated through this connection.
type gatewayExfilHarness struct {
	ctx    context.Context
	cancel context.CancelFunc
	v, m   *EclipseNode
	mPs    *PeerSet
	x      [16]byte
}

func gatewayNewExfilHarness(t *testing.T, name string, vSeed, mSeed, xByte byte) *gatewayExfilHarness {
	t.Helper()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	root := t.TempDir()
	caPath, err := ca.WriteCAPEM(root)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v := newEclipseNode(t, ca, caPath, root, "V"+name, vSeed, false, false)
	m := newEclipseNode(t, ca, caPath, root, "M"+name, mSeed, false, false)
	eclipseMint(v, "gateway"+name, 20) // V's state = the exfiltrated surface
	v.g.SetStratifiedAntiEntropy(true)
	v.ps.SetDigestSink(v.g)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, v.ln, v.sink, v.g, &wg, v.ps)
	var x [16]byte
	x[0] = xByte
	mPs := eclipseImpostor(t, ca, caPath, root, "gateway"+name, x, m)
	if err := mPs.Dial(ctx, v.addr, "localhost", v.ident.NodeID); err != nil {
		t.Fatalf("M dials V (the landing): %v", err)
	}
	landed := false
	landDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(landDeadline) {
		v.ps.mu.RLock()
		_, ok := v.ps.peers[x]
		v.ps.mu.RUnlock()
		if ok {
			landed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !landed {
		t.Fatalf("the impostor did not occupy the x-slot within 10s")
	}
	asyncWait(t, mPs, v.ident.NodeID) // M's dial-side V-slot
	return &gatewayExfilHarness{ctx: ctx, cancel: cancel, v: v, m: m, mPs: mPs, x: x}
}

// TestGatewayDigestExfilBlocked sends an empty-IBLT request stamped
// with x, although the connection belongs to M. V must neither return its
// state digest nor change its root, and the per-connection seam must count the
// dropped request.
func TestGatewayDigestExfilBlocked(t *testing.T) {
	h := gatewayNewExfilHarness(t, "digest", 0x55, 0x56, 0x54)
	rootVPre := h.v.engine.MerkleRootFromShards()
	before := gatewayWaitConnFramesQuiet(t, h.mPs, h.v.ident.NodeID)
	seed := maphash.MakeSeed()
	dig := h.m.engine.GenerateDigestSizedWithSeed(seed, eng.IBLTDigestDefaultBuckets)
	marshaledIBLT, err := eng.MarshalIBLT(dig)
	dig.Release()
	if err != nil {
		t.Fatalf("MarshalIBLT: %v", err)
	}
	req := buildDigestFrame(digestRoleRequest, h.x, seed, nil, marshaledIBLT)
	if err := h.mPs.Publish(h.v.ident.NodeID, receive.LengthPrefixFrame(req)); err != nil {
		t.Fatalf("gateway digest REQUEST Publish: %v", err)
	}
	var after uint64 = before
	respDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(respDeadline) {
		if cur := gatewayConnFrames(t, h.mPs, h.v.ident.NodeID); cur > before {
			after = cur
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if after > before {
		t.Fatalf("M received %d digest frames after the self-stamped request (framesReceived %d -> %d), want 0", after-before, before, after)
	}
	// The per-connection read seam drops the request before DeliverDigest.
	if drops := h.v.ps.digestSeamDrops.Load(); drops < 1 {
		t.Fatalf("self-stamped request produced digestSeamDrops=%d, want at least 1", drops)
	}
	if got := h.v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed from %x to %x while handling a digest frame", rootVPre, got)
	}
	t.Logf("self-stamped request extracted no digest (framesReceived %d -> %d)", before, after)
}

// TestGatewayRootAnnouncePoisonBlocked sends a root announcement stamped
// with x over M's unverified connection. The supplied root must not enter V's
// peerRoots map or change V's engine root, and the read seam must count the
// drop.
func TestGatewayRootAnnouncePoisonBlocked(t *testing.T) {
	h := gatewayNewExfilHarness(t, "root-announce", 0x57, 0x58, 0x5a)
	rootVPre := h.v.engine.MerkleRootFromShards()
	var poisonRoot [32]byte
	poisonRoot[0] = 0xDE
	announce := buildRootAnnounceFrame(h.x, poisonRoot)
	if err := h.mPs.Publish(h.v.ident.NodeID, receive.LengthPrefixFrame(announce)); err != nil {
		t.Fatalf("gateway root announcement announce Publish: %v", err)
	}
	poisoned := false
	poisonDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(poisonDeadline) {
		h.v.g.peerRootsMu.Lock()
		_, known := h.v.g.peerRoots[h.x]
		h.v.g.peerRootsMu.Unlock()
		if known {
			poisoned = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if poisoned {
		h.v.g.peerRootsMu.Lock()
		got := h.v.g.peerRoots[h.x]
		h.v.g.peerRootsMu.Unlock()
		t.Fatalf("unverified announcement populated peerRoots[%x]=%x, want no entry", h.x, got)
	}
	if drops := h.v.ps.digestSeamDrops.Load(); drops < 1 {
		t.Fatalf("forged announcement produced digestSeamDrops=%d, want at least 1", drops)
	}
	if got := h.v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed from %x to %x while handling a root announcement", rootVPre, got)
	}
	t.Logf("unverified announcement left peerRoots[%x] empty", h.x)
}
