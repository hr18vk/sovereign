// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// The eclipse tests use three loopback TLS nodes: victim V, baseline peer X,
// and impostor M. V's Directory contains X's origin key but not M's. M dials
// with a development-CA leaf whose CommonName contains X's node ID, taking
// X's routing slot without taking X's identity.
//
// The tests check that routing and data verification remain separate. M's
// per-frame, batch, and hybrid writes must not enter V's state; a frame
// claiming X's origin but signed by M must fail signature verification; and
// V must not send data or digest responses to the unverified connection.
// The shared EclipseNode harness lives in lamport_skew_convergence_test.go.
package mesh

import (
	"context"
	"crypto/sha256"
	"hash/maphash"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// eclipseConverge drives both nodes' sweeps until their roots match or
// maxRounds is exhausted. Polling without new sweeps would not exercise
// anti-entropy.
func eclipseConverge(t *testing.T, ctx context.Context, a, b *EclipseNode, maxRounds int) [32]byte {
	t.Helper()
	for round := 1; round <= maxRounds; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
		// Drain asynchronous receives before comparing roots.
		eclipseDrain(t, a)
		eclipseDrain(t, b)
		ra := a.engine.MerkleRootFromShards()
		rb := b.engine.MerkleRootFromShards()
		if ra == rb {
			return ra
		}
	}
	t.Fatalf("eclipseConverge: no convergence in %d driven rounds (rootA=%x rootB=%x)",
		maxRounds, a.engine.MerkleRootFromShards(), b.engine.MerkleRootFromShards())
	return [32]byte{}
}

// eclipseAwaitAbsent polls until peerID is gone from ps.peers (the kill's
// reaping is async: the readLoop's exit defer deletes the entry).
func eclipseAwaitAbsent(t *testing.T, ps *PeerSet, peerID [16]byte) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ps.mu.RLock()
		_, ok := ps.peers[peerID]
		ps.mu.RUnlock()
		if !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("eclipseAwaitAbsent: peer %x still in ps.peers after 3s (the kill did not reap the edge)", peerID)
}

// eclipseImpostor creates a transport whose CA-signed leaf names target
// instead of m. It rewires m's PeerSet and Gossiper to that transport while
// retaining m's sink, engine, Directory, and node identity. The returned
// PeerSet dials the victim; only the leaf CommonName is impersonated.
func eclipseImpostor(t *testing.T, ca *crypto.MeshCA, caPath, root, name string, target [16]byte, m *EclipseNode) *PeerSet {
	t.Helper()
	impostorLeaf, err := ca.IssueLeaf(identHex(target))
	if err != nil {
		t.Fatalf("IssueLeaf impostor (%s): %v", name, err)
	}
	iCert, iKey, err := impostorLeaf.WritePEM(filepath.Join(root, "leaf-"+name))
	if err != nil {
		t.Fatalf("WritePEM impostor (%s): %v", name, err)
	}
	impostorTr, err := transport.NewTLSTransport(iCert, iKey, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport impostor (%s): %v", name, err)
	}
	mPs := NewPeerSet(impostorTr, m.sink, m.ident, m.engine)
	mg := NewGossiper(mPs, m.ident, m.engine, m.dir)
	m.ps = mPs
	m.g = mg
	return mPs
}

// TestEclipseImpostorRoutingAndDataRejection runs with stratification
// disabled. After V and X converge, both V-X edges close and M takes X's
// routing slot. The test requires the slot to route a probe, rejects M's
// writes on each receive path, rejects a forged X origin, and blocks V's
// sweep from sending data to M. V's root and entry count must stay unchanged
// throughout.
func TestEclipseImpostorRoutingAndDataRejection(t *testing.T) {
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

	v := newEclipseNode(t, ca, caPath, root, "V", 0xC1, false, false)
	x := newEclipseNode(t, ca, caPath, root, "X", 0xC2, false, false)
	m := newEclipseNode(t, ca, caPath, root, "M", 0xC3, false, true)

	// V and X can verify each other's origins. V has no origin key for M.
	if err := v.dir.Register(x.ident.NodeID, x.ident.Pub); err != nil {
		t.Fatalf("register X in V: %v", err)
	}
	if err := x.dir.Register(v.ident.NodeID, v.ident.Pub); err != nil {
		t.Fatalf("register V in X: %v", err)
	}
	// M can verify V on its outbound connection, allowing its writes to reach
	// V's receive path. V still has no key for M, so origin verification there
	// must reject them and the X-slot must remain unverified.
	if err := m.dir.Register(v.ident.NodeID, v.ident.Pub); err != nil {
		t.Fatalf("register V in M: %v", err)
	}

	// Establish a 200-entry baseline: 150 from V and 50 from X.
	eclipseMint(v, "eclipse-v", 150)
	eclipseMint(x, "eclipse-x", 50)
	eclipseWire(t, ctx, v, x)
	rootV0 := eclipseConverge(t, ctx, v, x, 8)
	if got := eclipseCount(v, "eclipse-v", 150) + eclipseCount(v, "eclipse-x", 50); got != 200 {
		t.Fatalf("baseline: V holds %d of 200 entries", got)
	}
	t.Logf("eclipse baseline converged with rootV=%x and 200 entries at V", rootV0)
	// M's leaf names X, so V's accept path installs M's connection in X's
	// routing slot. M keeps its own origin identity and signing key.
	mPs := eclipseImpostor(t, ca, caPath, root, "impostor", x.ident.NodeID, m)

	// Close both sides of the baseline connection and wait for peer removal.
	if err := v.ps.ClosePeer(x.ident.NodeID); err != nil {
		t.Fatalf("kill V->X: %v", err)
	}
	if err := x.ps.ClosePeer(v.ident.NodeID); err != nil {
		t.Fatalf("kill X->V: %v", err)
	}
	eclipseAwaitAbsent(t, v.ps, x.ident.NodeID)
	eclipseAwaitAbsent(t, x.ps, v.ident.NodeID)

	// V's accept loop calls RegisterInbound, which derives X's node ID from
	// the leaf and installs M's inbound connection under that ID.
	if err := mPs.Dial(ctx, v.addr, "localhost", v.ident.NodeID); err != nil {
		t.Fatalf("M dials V: %v", err)
	}

	// Accept-side registration is asynchronous, so poll for the routing slot.
	v.ps.mu.RLock()
	xSlot, xOk := v.ps.peers[x.ident.NodeID]
	v.ps.mu.RUnlock()
	slotDeadline := time.Now().Add(10 * time.Second)
	for !xOk && time.Now().Before(slotDeadline) {
		time.Sleep(20 * time.Millisecond)
		v.ps.mu.RLock()
		xSlot, xOk = v.ps.peers[x.ident.NodeID]
		v.ps.mu.RUnlock()
	}
	if !xOk || xSlot == nil {
		t.Fatalf("impostor routing slot is absent after M's dial")
	}
	// A non-digest probe sent to X must reach M's read loop and increment its
	// malformed-frame sink counter, proving that the slot routes to M.
	mSinkBefore := m.sink.total.Load()
	probe := receive.LengthPrefixFrame([]byte("eclipse-impostor-routing-probe"))
	if err := v.ps.Publish(x.ident.NodeID, probe); err != nil {
		t.Fatalf("publish routing probe to the X-slot: %v", err)
	}
	probeDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(probeDeadline) {
		if m.sink.total.Load() > mSinkBefore {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m.sink.total.Load() == mSinkBefore {
		t.Fatalf("routing probe did not reach M through the X-slot")
	}
	t.Logf("impostor occupied the X-slot and received the routing probe (M sink total %d -> %d)", mSinkBefore, m.sink.total.Load())

	// M's per-frame writes must produce a Directory miss and leave V's root
	// unchanged. The same root anchors the remaining receive-path checks.
	rootVPre := v.engine.MerkleRootFromShards()
	eclipseMint(m, "eclipse-m", 30) // origin = M_id, the payload-retaining seam
	m.g.AntiEntropySweep(ctx)       // M's sweep iterates m.ps.Peers() = [V_id]
	eclipseDrain(t, v)
	missAfterPerFrame := v.sink.directoryMiss.Load()
	if missAfterPerFrame == 0 {
		t.Fatalf("V recorded no Directory miss for M's per-frame writes")
	}
	if got := v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed from %x to %x after M's per-frame writes", rootVPre, got)
	}

	// Exercise the same origin check through batch envelopes.
	m.g.SetBatchSize(DefaultBatchSize)
	m.g.AntiEntropySweep(ctx)
	eclipseDrain(t, v)
	if miss := v.sink.directoryMiss.Load(); miss == missAfterPerFrame {
		t.Fatalf("batch envelopes produced no additional Directory miss at V (count=%d)", miss)
	}
	if got := v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed after M's batch writes")
	}

	missAfterBatch := v.sink.directoryMiss.Load()

	// Enable hybrid verification only for this window. HandleHybridFrame
	// rejects immediately when verification is disabled; when enabled, its
	// LookupBoth call must reject M's unknown origin. Drain before changing the
	// setting so no frames race the plain boolean. The forgery check below uses
	// the classical receive path.
	vSinkRecv, ok := v.sink.recv.(*receive.Receiver)
	if !ok {
		t.Fatalf("sink's inner receiver is %T, want *receive.Receiver", v.sink.recv)
	}
	vSinkRecv.SetHybridVerify(true)
	m.g.SetHybridSign(true)
	m.g.AntiEntropySweep(ctx)
	eclipseDrain(t, v)
	vSinkRecv.SetHybridVerify(false)
	missAfterHybrid := v.sink.directoryMiss.Load()
	if missAfterHybrid == missAfterBatch {
		t.Fatalf("hybrid envelopes produced no additional Directory miss (count %d -> %d); either none arrived or verification rejected them before LookupBoth", missAfterBatch, missAfterHybrid)
	}
	t.Logf("hybrid verification rejected M's origin through LookupBoth (Directory misses %d -> %d)", missAfterBatch, missAfterHybrid)
	if got := v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed after M's hybrid writes")
	}

	// This zero-hop envelope claims X's origin, which V can resolve, but is
	// signed by M. Origin signature verification must reject it: the TLS leaf
	// CommonName does not determine the signing identity.
	sigFailBefore := v.sink.sigFail.Load()
	forgedEntry := eng.CRDTEntry{
		OriginNodeID: x.ident.NodeID, // claimed origin
		DotNodeID:    x.ident.NodeID, // attribution requires the same node ID
		DotCounter:   2,              // signature verification runs before the dot bound
		SystemTime:   int64(1_700_000_099),
		H3Index:      99,
	}
	fPayload := "eclipse-forged-payload"
	forgedEntry.PayloadDigest = sha256.Sum256([]byte(fPayload))
	innerWire, err := eng.BuildCRDTDeltaEvent("eclipse-forged", fPayload, forgedEntry)
	if err != nil {
		t.Fatalf("(k) BuildCRDTDeltaEvent: %v", err)
	}
	fSig, err := identity.SignCRDTFrame(m.ident.Seed, innerWire)
	if err != nil {
		t.Fatalf("(k) SignCRDTFrame: %v", err)
	}
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], fSig)
	fEnv := attribution.NewSignedRelayEnvelopeV3(innerWire, sigArr, forgedEntry.DotCounter, x.ident.NodeID, nil)
	// M publishes toward V so V's origin verification sees the forged frame.
	// Sending from V instead would exercise M's Directory, which has no X key.
	if err := mPs.Publish(v.ident.NodeID, receive.LengthPrefixFrame(fEnv.Marshal())); err != nil {
		t.Fatalf("publish forged frame M->V: %v", err)
	}
	eclipseAwaitSinkGrowth(t, "signature-fail", func() uint64 { return v.sink.sigFail.Load() }, sigFailBefore)
	if got := v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed after the forged-X frame")
	}
	t.Logf("frame claiming X's origin but signed by M failed verification (sigFail %d -> %d); V's state stayed unchanged", sigFailBefore, v.sink.sigFail.Load())
	// V's sweep must not send its signed data plane to the unverified X-slot.
	// M's framesReceived counter measures any delivery on that connection.
	var mFramesBefore uint64
	mPs.mu.RLock()
	if pc := mPs.peers[v.ident.NodeID]; pc != nil {
		mFramesBefore = atomic.LoadUint64(&pc.framesReceived)
	}
	mPs.mu.RUnlock()
	st := v.g.AntiEntropySweep(ctx)
	// shippedEntries must remain zero while egressUnverified proves that the
	// sweep visited and rejected M's slot.
	held := eclipseCount(v, "eclipse-v", 150) + eclipseCount(v, "eclipse-x", 50)
	if st.shippedEntries != 0 {
		t.Fatalf("V's sweep shipped %d of %d held entries to the unverified X-slot", st.shippedEntries, held)
	}
	if st.egressUnverified < 1 {
		t.Fatalf("sweep recorded egressUnverified=%d, want at least 1 to confirm the unverified peer was visited", st.egressUnverified)
	}
	// Start from the previous count so a removed connection cannot wrap the
	// unsigned delta. Losing that connection invalidates the measurement.
	mFramesAfter := mFramesBefore
	exfilDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(exfilDeadline) {
		mPs.mu.RLock()
		pc := mPs.peers[v.ident.NodeID]
		if pc != nil {
			mFramesAfter = atomic.LoadUint64(&pc.framesReceived)
		}
		mPs.mu.RUnlock()
		if pc == nil {
			t.Fatalf("M's connection disappeared during the egress measurement")
		}
		if mFramesAfter > mFramesBefore {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	exfilDelta := mFramesAfter - mFramesBefore
	if exfilDelta != 0 {
		t.Fatalf("M received %d frames from V's sweep (framesReceived %d -> %d), want 0", exfilDelta, mFramesBefore, mFramesAfter)
	}
	t.Logf("V's sweep shipped no entries to M (V holds %d, egressUnverified=%d, framesReceived unchanged); direct routing remained available", held, st.egressUnverified)

	// Recheck V's state after every receive path and V's own sweep.
	if got := v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed from %x to %x during the impostor checks", rootVPre, got)
	}
	if got := eclipseCount(v, "eclipse-v", 150) + eclipseCount(v, "eclipse-x", 50); got != 200 {
		t.Fatalf("V holds %d of 200 baseline entries after the impostor checks", got)
	}
	t.Logf("V retained its original root and all 200 baseline entries")
}

// eclipseAwaitSinkGrowth polls until the sink counter fn exceeds before (the
// verdict arrives asynchronously on the readLoop).
func eclipseAwaitSinkGrowth(t *testing.T, what string, fn func() uint64, before uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if fn() > before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("eclipse: no %s verdict observed before timeout (before=%d after=%d)", what, before, fn())
}

// TestEclipseDeliverDigestExfil enables V's stratified digest surface. M
// connects with a leaf naming X2, then stamps a digest request and a root
// announcement with X2's node ID. Neither frame may produce a response or
// alter V's peerRoots or engine state.
func TestEclipseDeliverDigestExfil(t *testing.T) {
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

	v := newEclipseNode(t, ca, caPath, root, "V2", 0xC5, false, false)
	m := newEclipseNode(t, ca, caPath, root, "M2", 0xC6, false, false)
	eclipseMint(v, "eclipse-exfil", 20)
	rootVPre := v.engine.MerkleRootFromShards()
	// Stratification allocates the responder and peer-root state. Installing
	// the digest sink routes digest frames to the gossiper.
	v.g.SetStratifiedAntiEntropy(true)
	v.ps.SetDigestSink(v.g)
	var wgExfil sync.WaitGroup
	wgExfil.Add(1)
	go runAcceptLoopWithPeerSet(ctx, v.ln, v.sink, v.g, &wgExfil, v.ps)
	// X2 is the identity M claims in its leaf and self-stamped frames.
	var x2 [16]byte
	x2[0] = 0xC4
	mPs := eclipseImpostor(t, ca, caPath, root, "exfil", x2, m)
	if err := mPs.Dial(ctx, v.addr, "localhost", v.ident.NodeID); err != nil {
		t.Fatalf("M dials V: %v", err)
	}
	// Poll for V's asynchronous accept-side registration of the X2-slot.
	landDeadline := time.Now().Add(10 * time.Second)
	landed := false
	for time.Now().Before(landDeadline) {
		v.ps.mu.RLock()
		_, ok := v.ps.peers[x2]
		v.ps.mu.RUnlock()
		if ok {
			landed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !landed {
		t.Fatalf("impostor did not occupy the X2-slot before timeout")
	}
	asyncWait(t, mPs, v.ident.NodeID)

	// The request carries X2 in senderID although M sent it. DeliverDigest
	// must bind that header identity to the verified connection identity before
	// respondToDigest can publish V's digest to ps.peers[X2].
	var mFramesBefore uint64
	mPs.mu.RLock()
	if pc := mPs.peers[v.ident.NodeID]; pc != nil {
		mFramesBefore = atomic.LoadUint64(&pc.framesReceived)
	}
	mPs.mu.RUnlock()
	seed := maphash.MakeSeed()
	dig := m.engine.GenerateDigestSizedWithSeed(seed, eng.IBLTDigestDefaultBuckets)
	marshaledIBLT, err := eng.MarshalIBLT(dig)
	dig.Release()
	if err != nil {
		t.Fatalf("(l-2) MarshalIBLT: %v", err)
	}
	req := buildDigestFrame(digestRoleRequest, x2, seed, nil, marshaledIBLT)
	if err := mPs.Publish(v.ident.NodeID, receive.LengthPrefixFrame(req)); err != nil {
		t.Fatalf("publish self-stamped digest request: %v", err)
	}
	mFramesAfter := mFramesBefore
	respDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(respDeadline) {
		mPs.mu.RLock()
		pc := mPs.peers[v.ident.NodeID]
		if pc != nil {
			mFramesAfter = atomic.LoadUint64(&pc.framesReceived)
		}
		mPs.mu.RUnlock()
		if pc == nil {
			t.Fatalf("M's connection disappeared during the digest-response measurement")
		}
		if mFramesAfter > mFramesBefore {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if mFramesAfter != mFramesBefore {
		t.Fatalf("M received a digest response from V (framesReceived %d -> %d), want no response", mFramesBefore, mFramesAfter)
	}
	if drops := v.ps.digestSeamDrops.Load(); drops < 1 {
		t.Fatalf("self-stamped request produced digestSeamDrops=%d, want at least 1", drops)
	}
	t.Logf("self-stamped request produced no digest response (framesReceived %d -> %d) and was counted at the read seam", mFramesBefore, mFramesAfter)
	// A root announcement stamped with X2 must not populate peerRoots[X2]
	// through recordPeerRoot. The in-package map read observes any acceptance.
	var poisonRoot [32]byte
	poisonRoot[0] = 0xDE
	announce := buildRootAnnounceFrame(x2, poisonRoot)
	if err := mPs.Publish(v.ident.NodeID, receive.LengthPrefixFrame(announce)); err != nil {
		t.Fatalf("publish self-stamped root announcement: %v", err)
	}
	poisonDeadline := time.Now().Add(10 * time.Second)
	poisoned := false
	for time.Now().Before(poisonDeadline) {
		v.g.peerRootsMu.Lock()
		gotRoot, gotOK := v.g.peerRoots[x2]
		v.g.peerRootsMu.Unlock()
		if gotOK && gotRoot == poisonRoot {
			poisoned = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if poisoned {
		v.g.peerRootsMu.Lock()
		gotRoot := v.g.peerRoots[x2]
		v.g.peerRootsMu.Unlock()
		t.Fatalf("unverified announcement populated peerRoots[%x]=%x, want no entry", x2, gotRoot)
	}
	t.Logf("unverified announcement left peerRoots[%x] empty", x2)
	if got := v.engine.MerkleRootFromShards(); got != rootVPre {
		t.Fatalf("V's root changed from %x to %x while handling digest-surface frames", rootVPre, got)
	}
	t.Logf("V's root stayed unchanged across the digest and announcement checks")
}

// TestEclipseNegativeControlDirectoryBypass registers M's origin at V,
// bypassing the check that rejects M in the main eclipse test. M's writes must
// then change V's root, after which the test intentionally fails to record the
// negative control. SOVEREIGN_TEST_FAULT_ECLIPSE_SKEW enables this run.
func TestEclipseNegativeControlDirectoryBypass(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_ECLIPSE_SKEW") == "" {
		t.Skip("SOVEREIGN_TEST_FAULT_ECLIPSE_SKEW not set; skipping the opt-in directory-bypass negative control")
	}
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

	v := newEclipseNode(t, ca, caPath, root, "V3", 0xC9, false, false)
	m := newEclipseNode(t, ca, caPath, root, "M3", 0xCA, false, false)
	eclipseMint(v, "eclipse-control", 3)
	rootVPre := v.engine.MerkleRootFromShards()
	// M takes X3's slot while V still lacks M's origin key.
	var x3 [16]byte
	x3[0] = 0xC8
	mPs := eclipseImpostor(t, ca, caPath, root, "negative-control", x3, m)
	var wgNegativeControl sync.WaitGroup
	wgNegativeControl.Add(1)
	go runAcceptLoopWithPeerSet(ctx, v.ln, v.sink, nil, &wgNegativeControl, v.ps)
	if err := mPs.Dial(ctx, v.addr, "localhost", v.ident.NodeID); err != nil {
		t.Fatalf("negative control: M dials V: %v", err)
	}
	asyncWait(t, v.ps, x3)
	asyncWait(t, mPs, v.ident.NodeID)
	// Registering M bypasses only origin resolution. Rate, signature, and skew
	// checks continue to run.
	if err := v.dir.Register(m.ident.NodeID, m.ident.Pub); err != nil {
		t.Fatalf("negative control: register M in V: %v", err)
	}
	eclipseMint(m, "eclipse-control-origin", 5)
	m.g.AntiEntropySweep(ctx)
	eclipseDrain(t, v)
	rootVPost := v.engine.MerkleRootFromShards()
	if rootVPost == rootVPre {
		t.Fatalf("negative control is invalid: V's root did not change after the Directory bypass")
	}
	t.Fatalf("negative control captured: V's root changed from %x to %x after M's origin was registered", rootVPre, rootVPost)
}
