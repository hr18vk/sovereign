// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests exercise gateway fault-injection controls and connect-time
// handshake verification (ADR-0068). Each negative control disables a specific
// check and requires the protected data flow to return, demonstrating that the
// corresponding assertion can fail. Handshake tests observe counters after
// driving real frames through loopback TLS connections.
//
// SOVEREIGN_TEST_FAULT_GATEWAY enables the negative controls. Without it they
// skip; the fault-injection test run sets it explicitly.
package mesh

import (
	"context"
	"crypto/rand"
	"hash/maphash"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// gatewayNegativeControlActive requires the gateway fault-injection variable
// before running a negative control.
func gatewayNegativeControlActive(t *testing.T) bool {
	t.Helper()
	if os.Getenv("SOVEREIGN_TEST_FAULT_GATEWAY") == "" {
		t.Skip("SOVEREIGN_TEST_FAULT_GATEWAY not set; skipping gateway negative controls")
		return false
	}
	return true
}

// TestGatewayNegativeControlEgressGateOff disables the sweep egress check.
// V's driven sweep must then ship into the impostor's x-slot. If it does not,
// another part of the path is masking the disabled check.
func TestGatewayNegativeControlEgressGateOff(t *testing.T) {
	if !gatewayNegativeControlActive(t) {
		return
	}
	h := gatewayNewExfilHarness(t, "egress-control", 0x5b, 0x5c, 0x5d)
	h.v.g.disableEgressGateBugInject.Store(true)
	before := gatewayWaitConnFramesQuiet(t, h.mPs, h.v.ident.NodeID)
	st := h.v.g.AntiEntropySweep(h.ctx)
	after := gatewayWaitConnFramesQuiet(t, h.mPs, h.v.ident.NodeID)
	if st.shippedEntries < 1 {
		t.Fatalf("egress-gate negative control shipped %d entries, want at least 1; another check is blocking the disabled path", st.shippedEntries)
	}
	if st.egressUnverified != 0 {
		t.Fatalf("egress-gate negative control counted %d unverified drops, want 0 when the check and its counter are disabled", st.egressUnverified)
	}
	if delta := after - before; delta < 1 {
		t.Fatalf("egress-gate negative control delivered %d sweep frames to M, want at least 1", delta)
	}
	t.Logf("egress-gate negative control shipped %d entries and delivered %d frames to M", st.shippedEntries, after-before)
}

// TestGatewayNegativeControlDigestChannelGateOff disables both the
// per-connection digest seam and the Gossiper channel check. Both are needed:
// leaving the seam enabled would drop the request first. The self-stamped
// request must then extract V's state digest.
func TestGatewayNegativeControlDigestChannelGateOff(t *testing.T) {
	if !gatewayNegativeControlActive(t) {
		return
	}
	h := gatewayNewExfilHarness(t, "digest-control", 0x61, 0x62, 0x63)
	h.v.ps.disableDigestSeamBugInject.Store(true)
	h.v.g.disableDigestChannelGateBugInject.Store(true)
	before := gatewayWaitConnFramesQuiet(t, h.mPs, h.v.ident.NodeID)
	seed := maphash.MakeSeed()
	dig := h.v.engine.GenerateDigestSizedWithSeed(seed, eng.IBLTDigestDefaultBuckets)
	marshaledIBLT, err := eng.MarshalIBLT(dig)
	dig.Release()
	if err != nil {
		t.Fatalf("MarshalIBLT: %v", err)
	}
	req := buildDigestFrame(digestRoleRequest, h.x, seed, nil, marshaledIBLT)
	if err := h.mPs.Publish(h.v.ident.NodeID, receive.LengthPrefixFrame(req)); err != nil {
		t.Fatalf("digest-channel negative control publish: %v", err)
	}
	var after uint64 = before
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cur := gatewayConnFrames(t, h.mPs, h.v.ident.NodeID); cur > before {
			after = cur
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if after == before {
		t.Fatalf("digest-channel negative control received no response (framesReceived %d -> %d); another check still blocks the path", before, after)
	}
	t.Logf("digest-channel negative control received a response after disabling both checks (framesReceived %d -> %d)", before, after)
}

// gatewayProvisionXEntry registers a fresh third identity under x in V's
// Directory. This lets the crafted response reach signature verification
// instead of stopping at challengeNoEntry; the third key cannot validate M's
// signature.
func gatewayProvisionXEntry(t *testing.T, h *gatewayExfilHarness) {
	t.Helper()
	seedT := make([]byte, 32)
	if _, err := rand.Read(seedT); err != nil {
		t.Fatalf("x-entry provision: seed: %v", err)
	}
	identT, err := NewNodeIdentity(seedT)
	if err != nil {
		t.Fatalf("x-entry provision: identity: %v", err)
	}
	if err := h.v.dir.Register(h.x, identT.Pub); err != nil {
		t.Fatalf("x-entry provision: register: %v", err)
	}
}

// gatewayCraftedWrongKeyResponse builds a response naming x and V with the
// x-slot's current nonce, but signs it with M's key. Only the signature is
// wrong. Reading the nonce under ps.mu is ordered with challenge arming and
// connection installation.
func gatewayCraftedWrongKeyResponse(t *testing.T, h *gatewayExfilHarness) []byte {
	t.Helper()
	h.v.ps.mu.RLock()
	pc := h.v.ps.peers[h.x]
	if pc == nil || !pc.challengeArmed {
		h.v.ps.mu.RUnlock()
		t.Fatalf("crafted response setup: the x-slot connection is absent or has no armed challenge")
	}
	nonce := pc.challengeNonce
	h.v.ps.mu.RUnlock()
	msg := buildChallengeMsg(nonce, h.x, h.v.ident.NodeID)
	sig, err := identity.SignCRDTFrame(h.m.ident.Seed, msg)
	if err != nil {
		t.Fatalf("crafted response: sign: %v", err)
	}
	return buildChallengeResponseFrame(h.x, h.v.ident.NodeID, nonce, sig)
}

// TestGatewayHandshakeWrongKey sends a well-formed response signed by the
// wrong key and requires challengeSigFail to count it. M's own response must
// fail the identity match instead. Neither response may make the x-slot
// eligible for sweep egress.
func TestGatewayHandshakeWrongKey(t *testing.T) {
	h := gatewayNewExfilHarness(t, "wk", 0x71, 0x72, 0x73)
	gatewayProvisionXEntry(t, h)
	crafted := gatewayCraftedWrongKeyResponse(t, h)
	if err := h.mPs.Publish(h.v.ident.NodeID, receive.LengthPrefixFrame(crafted)); err != nil {
		t.Fatalf("WrongKey: crafted response Publish: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.v.ps.challengeSigFail.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fails := h.v.ps.challengeSigFail.Load(); fails < 1 {
		t.Fatalf("wrong-key response produced challengeSigFail=%d, want at least 1; the response did not reach signature verification", fails)
	}
	if mism := h.v.ps.challengeMismatch.Load(); mism < 1 {
		t.Fatalf("M's own response produced challengeMismatch=%d, want at least 1", mism)
	}
	st := h.v.g.AntiEntropySweep(h.ctx)
	if st.shippedEntries != 0 || st.egressUnverified < 1 {
		t.Fatalf("wrong-key response permitted egress: shipped=%d egressUnverified=%d, want 0 and at least 1", st.shippedEntries, st.egressUnverified)
	}
	t.Logf("wrong-key response failed signature verification and M's response failed identity matching; sweep egress stayed blocked (drops=%d)", st.egressUnverified)
}

// TestGatewayNegativeControlChallengeVerifyOff disables challenge signature
// verification. The wrong-key response must then verify the x-slot and permit
// sweep egress, demonstrating that no other check supplies the possession
// proof.
func TestGatewayNegativeControlChallengeVerifyOff(t *testing.T) {
	if !gatewayNegativeControlActive(t) {
		return
	}
	h := gatewayNewExfilHarness(t, "challenge-control", 0x76, 0x77, 0x78)
	gatewayProvisionXEntry(t, h)
	h.v.ps.disableChallengeVerifyBugInject.Store(true)
	defer h.v.ps.disableChallengeVerifyBugInject.Store(false)
	crafted := gatewayCraftedWrongKeyResponse(t, h)
	if err := h.mPs.Publish(h.v.ident.NodeID, receive.LengthPrefixFrame(crafted)); err != nil {
		t.Fatalf("negative control:ChallengeVerifyOff: crafted response Publish: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.v.ps.egressVerified(h.x) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !h.v.ps.egressVerified(h.x) {
		t.Fatalf("challenge-verification negative control left the x-slot unverified; the wrong-key response did not reach the disabled check")
	}
	st := h.v.g.AntiEntropySweep(h.ctx)
	if st.shippedEntries < 1 || st.egressUnverified != 0 {
		t.Fatalf("challenge-verification negative control shipped=%d egressUnverified=%d, want at least 1 and 0", st.shippedEntries, st.egressUnverified)
	}
	t.Logf("challenge-verification negative control verified the wrong-key x-slot and shipped %d entries", st.shippedEntries)
}

// TestGatewayHandshakeNoEntry connects N with a valid identity and leaf but
// no entry in V's Directory. The challenge response must produce
// challengeNoEntry. N's routing slot remains installed, but V's sweep must
// not ship data to it.
func TestGatewayHandshakeNoEntry(t *testing.T) {
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
	v := newEclipseNode(t, ca, caPath, root, "Vne", 0x91, false, false)
	n := newEclipseNode(t, ca, caPath, root, "Nne", 0x92, false, false)
	// With no cross-registration, V cannot resolve N's challenge response.
	eclipseMint(v, "gatewayne", 20)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, v.ln, v.sink, v.g, &wg, v.ps)
	if err := n.ps.Dial(ctx, v.addr, "localhost", v.ident.NodeID); err != nil {
		t.Fatalf("NoEntry: N dials V: %v", err)
	}
	landDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(landDeadline) {
		v.ps.mu.RLock()
		_, present := v.ps.peers[n.ident.NodeID]
		v.ps.mu.RUnlock()
		if present {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	dropDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(dropDeadline) {
		if v.ps.challengeNoEntry.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if drops := v.ps.challengeNoEntry.Load(); drops < 1 {
		t.Fatalf("N's response produced challengeNoEntry=%d, want at least 1; it did not reach the directory lookup", drops)
	}
	v.ps.mu.RLock()
	_, present := v.ps.peers[n.ident.NodeID]
	v.ps.mu.RUnlock()
	if !present {
		t.Fatalf("N's routing slot was removed after the directory lookup failed")
	}
	if v.ps.egressVerified(n.ident.NodeID) {
		t.Fatalf("N's slot verified without a Directory entry")
	}
	st := v.g.AntiEntropySweep(ctx)
	if st.shippedEntries != 0 || st.egressUnverified < 1 {
		t.Fatalf("N's unverified slot received sweep data: shipped=%d egressUnverified=%d", st.shippedEntries, st.egressUnverified)
	}
	t.Logf("N's response failed the directory lookup (challengeNoEntry=%d); routing remained installed and sweep egress stayed blocked (drops=%d)", v.ps.challengeNoEntry.Load(), st.egressUnverified)
}

// TestGatewayHandshakeReplay completes a handshake on conn 1 and reconstructs
// its response from nonce1 and X's key. After conn 1 closes, a second
// connection using X's leaf must receive a different nonce. Replaying the
// captured response on conn 2 must fail the nonce check and earn no egress.
func TestGatewayHandshakeReplay(t *testing.T) {
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
	v := newEclipseNode(t, ca, caPath, root, "Vrp", 0x95, false, false)
	x := newEclipseNode(t, ca, caPath, root, "Xrp", 0x96, false, false)
	if err := v.dir.Register(x.ident.NodeID, x.ident.Pub); err != nil {
		t.Fatalf("Replay: register X in V: %v", err)
	}
	if err := x.dir.Register(v.ident.NodeID, v.ident.Pub); err != nil {
		t.Fatalf("Replay: register V in X: %v", err)
	}
	eclipseMint(v, "gatewayrp", 20)
	var wg sync.WaitGroup
	wg.Add(1)
	go runAcceptLoopWithPeerSet(ctx, v.ln, v.sink, v.g, &wg, v.ps)
	if err := x.ps.Dial(ctx, v.addr, "localhost", v.ident.NodeID); err != nil {
		t.Fatalf("Replay: X dials V (conn 1): %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if v.ps.egressVerified(x.ident.NodeID) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !v.ps.egressVerified(x.ident.NodeID) {
		t.Fatalf("replay setup: conn 1 did not complete the handshake")
	}
	v.ps.mu.RLock()
	pc1 := v.ps.peers[x.ident.NodeID]
	if pc1 == nil || !pc1.challengeArmed {
		v.ps.mu.RUnlock()
		t.Fatalf("Replay: conn 1 absent or un-armed at the capture")
	}
	nonce1 := pc1.challengeNonce
	v.ps.mu.RUnlock()
	msg := buildChallengeMsg(nonce1, x.ident.NodeID, v.ident.NodeID)
	sig1, err := identity.SignCRDTFrame(x.ident.Seed, msg)
	if err != nil {
		t.Fatalf("Replay: reconstruct sign: %v", err)
	}
	captured := buildChallengeResponseFrame(x.ident.NodeID, v.ident.NodeID, nonce1, sig1)
	if err := v.ps.ClosePeer(x.ident.NodeID); err != nil {
		t.Fatalf("Replay: kill conn 1: %v", err)
	}
	eclipseAwaitAbsent(t, v.ps, x.ident.NodeID)
	leafX, err := ca.IssueLeaf(identHex(x.ident.NodeID))
	if err != nil {
		t.Fatalf("Replay: IssueLeaf X: %v", err)
	}
	certX, keyX, err := leafX.WritePEM(filepath.Join(root, "leafXrp"))
	if err != nil {
		t.Fatalf("Replay: WritePEM X: %v", err)
	}
	trX, err := transport.NewTLSTransport(certX, keyX, caPath)
	if err != nil {
		t.Fatalf("Replay: transport X: %v", err)
	}
	conn2, err := trX.Dial("tcp", v.addr, "localhost")
	if err != nil {
		t.Fatalf("Replay: conn 2 dial: %v", err)
	}
	defer conn2.Close()
	landDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(landDeadline) {
		v.ps.mu.RLock()
		_, present := v.ps.peers[x.ident.NodeID]
		v.ps.mu.RUnlock()
		if present {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.ps.mu.RLock()
	pc2 := v.ps.peers[x.ident.NodeID]
	if pc2 == nil || !pc2.challengeArmed {
		v.ps.mu.RUnlock()
		t.Fatalf("Replay: conn 2 absent or un-armed — the fresh install broke")
	}
	nonce2 := pc2.challengeNonce
	v.ps.mu.RUnlock()
	if nonce2 == nonce1 {
		t.Fatalf("replay setup reused the same 256-bit nonce on both connections")
	}
	if _, err := transport.TransmitTLSFrame(conn2, receive.LengthPrefixFrame(captured)); err != nil {
		t.Fatalf("Replay: replay write: %v", err)
	}
	dropDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(dropDeadline) {
		if v.ps.challengeReplay.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if replays := v.ps.challengeReplay.Load(); replays < 1 {
		t.Fatalf("replayed response produced challengeReplay=%d, want at least 1; it did not reach the nonce check", replays)
	}
	if v.ps.egressVerified(x.ident.NodeID) {
		t.Fatalf("conn 2 verified under a replayed response")
	}
	st := v.g.AntiEntropySweep(ctx)
	if st.shippedEntries != 0 || st.egressUnverified < 1 {
		t.Fatalf("replayed response permitted sweep egress: shipped=%d egressUnverified=%d", st.shippedEntries, st.egressUnverified)
	}
	t.Logf("replayed response failed the nonce check (challengeReplay=%d); conn 2 remained unverified and sweep egress stayed blocked (drops=%d)", v.ps.challengeReplay.Load(), st.egressUnverified)
}

// TestGatewayMutualGreen checks a cross-registered pair over one
// connection. Both directions must complete the challenge handshake, converge,
// accept the verified peer's root announcement, and finish a digest exchange.
// The converged sweep must skip the digest without triggering egress drops.
func TestGatewayMutualGreen(t *testing.T) {
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
	v := newEclipseNode(t, ca, caPath, root, "Vmg", 0x99, false, false)
	x := newEclipseNode(t, ca, caPath, root, "Xmg", 0x9a, false, false)
	if err := v.dir.Register(x.ident.NodeID, x.ident.Pub); err != nil {
		t.Fatalf("mutual handshake: register X in V: %v", err)
	}
	if err := x.dir.Register(v.ident.NodeID, v.ident.Pub); err != nil {
		t.Fatalf("mutual handshake: register V in X: %v", err)
	}
	eclipseMint(v, "gatewaymg", 30)
	eclipseMint(x, "gatewaymg2", 10)
	v.g.SetStratifiedAntiEntropy(true)
	x.g.SetStratifiedAntiEntropy(true)
	v.ps.SetDigestSink(v.g)
	x.ps.SetDigestSink(x.g)
	var wg sync.WaitGroup
	wg.Add(2)
	go runAcceptLoopWithPeerSet(ctx, v.ln, v.sink, v.g, &wg, v.ps)
	go runAcceptLoopWithPeerSet(ctx, x.ln, x.sink, x.g, &wg, x.ps)
	// one-way dial (the digest exchange rides the single conn both
	// directions).
	if err := v.ps.Dial(ctx, x.addr, "localhost", x.ident.NodeID); err != nil {
		t.Fatalf("mutual handshake: V dials X: %v", err)
	}
	asyncWait(t, v.ps, x.ident.NodeID)
	awaitVerified(t, v.ps, x.ident.NodeID)
	landDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(landDeadline) {
		x.ps.mu.RLock()
		_, present := x.ps.peers[v.ident.NodeID]
		x.ps.mu.RUnlock()
		if present {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	awaitVerified(t, x.ps, v.ident.NodeID)
	if cv := v.ps.challengeVerified.Load() + x.ps.challengeVerified.Load(); cv < 2 {
		t.Fatalf("mutual handshake: challengeVerified across the pair = %d (want >= 2) — the mutual handshake did not complete", cv)
	}
	eclipseConverge(t, ctx, v, x, 12)
	// The harness drives sweeps explicitly and stops at the first equal-root
	// round. X's next sweep announces its final root to V; V can then compare
	// equal roots and skip its digest exchange.
	x.g.AntiEntropySweep(ctx)
	xRoot := x.engine.MerkleRootFromShards()
	// Poll the announced root rather than assuming delivery within a fixed
	// sleep. The three-second bound accommodates race-detector slowdown and
	// package-wide CPU contention; polling does not drive another exchange.
	announced := false
	annDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(annDeadline) {
		v.g.peerRootsMu.Lock()
		rk, ok := v.g.peerRoots[x.ident.NodeID]
		v.g.peerRootsMu.Unlock()
		if ok && rk == xRoot {
			announced = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.g.peerRootsMu.Lock()
	rootKnown, rootOK := v.g.peerRoots[x.ident.NodeID]
	v.g.peerRootsMu.Unlock()
	if !announced || !rootOK || rootKnown != xRoot {
		t.Fatalf("V's peerRoots[X]=(%x, %v), want X's final root %x from the verified connection", rootKnown, rootOK, xRoot)
	}
	if sent := x.g.digestRespondSent.Load(); sent < 1 {
		t.Fatalf("mutual handshake: digestRespondSent %d on X (want >= 1) — the digest exchange never completed", sent)
	}
	gated := v.g.digestGateSkips.Load()
	st := v.g.AntiEntropySweep(ctx)
	if st.egressUnverified != 0 {
		t.Fatalf("mutual handshake: the converged fleet hit the egress gate %d times — a verified pair must never gate", st.egressUnverified)
	}
	if now := v.g.digestGateSkips.Load(); now <= gated {
		t.Fatalf("mutual handshake: digestGateSkips did not rise on the converged sweep (%d -> %d) — the change-gate never quiesced", gated, now)
	}
	t.Logf("mutual handshake: the pair verified mutually (challengeVerified sum = %d), converged, the announce landed for the verified peer, digestRespondSent=%d, the converged sweep gated nothing and the change-gate quiesced (digestGateSkips %d -> %d)",
		v.ps.challengeVerified.Load()+x.ps.challengeVerified.Load(), x.g.digestRespondSent.Load(), gated, v.g.digestGateSkips.Load())
}
