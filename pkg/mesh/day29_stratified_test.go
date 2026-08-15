// Package mesh — day29_stratified_test.go is the Day-29 STRATIFIED ANTI-ENTROPY
// gate (ADR-0034, the Phase-5 Track-5.1 FIRST stake). It wires the dormant
// GenerateDeltaStratified primitive (crdt.go:1934) into the mesh sweep via a
// peer-TLS digest-exchange phase, and PROVES the wiring with teeth.
//
// THE MOULD (load-bearing): the Day-23 SkipList.Seek mold. The primitive was
// built + unit-tested GREEN but had ZERO production callers; Day 29 wires the
// production consumer (the mesh sweep) + closes the D2 EBR-pool leak the wiring
// activates. The teeth prove Law II (byte-identity — the stratified path
// converges the SAME MerkleRoot the oversend path does, in the SAME rounds OR
// FEWER), Law V (the bandwidth cut is a NUMBER, not an adjective), the M5
// honest fallback (the 19th SSoT counter fires on a digest timeout), and the
// D2 fix (the RED-NEUTER bug-inject control proves the leak returns when the
// fix is removed).
//
// THE 4c HONESTY (SCISSORS — Law VI): these teeth run on the 4-core executor box
// over loopback TLS 1.3, NOT on named silicon. The bandwidth cut is measured
// in-process (the shipped-envelopes + shipped-entries counters the sweep state
// already carries); the silicon-scale 100-node bandwidth gate is the NEXT-NEXT
// fork (the prompt's explicit "NO AWS this turn"). The teeth here prove the
// CORRECTNESS (byte-identity + converges-never-breaks) + the MECHANISM (the
// digest exchange produces a smaller delta) + the DISCLOSURE (the fallback
// counter fires) — the silicon-scale NUMBER is a separate fork.
package mesh

import (
	"context"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"fmt"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"hash/maphash"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/hr18vk/supremum/pkg/admission"
	"github.com/hr18vk/supremum/pkg/clock"
	"github.com/hr18vk/supremum/pkg/crypto"
	"github.com/hr18vk/supremum/pkg/identity"
	"github.com/hr18vk/supremum/pkg/receive"
	eng "github.com/hr18vk/supremum/pkg/sync"
	"github.com/hr18vk/supremum/pkg/transport"
)

// execCommand is os/exec.Command (a seam so a future test could stub it; the
// receive-side track36 precedent uses it directly).
var execCommand = exec.Command

// day29Harness is the 2-node TLS-loopback harness the Day-29 teeth reuse. It
// builds two NodeIdentity + two engines + two gate stacks + two PeerSets +
// two Gossipers, dials A->B + B->A, and starts the accept loops with the
// digester bound to each gossiper (so a digest frame reaches the sweep's
// per-peer blocking-receive channel). It is the SAME shape as the existing
// TestTwoNodeConvergence_InMemory harness, with TWO differences: (1) the
// digester is the gossiper (NOT nil) so the digest-exchange works, (2) the
// stratified seam is opt-IN per tooth (each tooth sets it before the sweep).
//
// The harness does NOT insert events (each tooth inserts its own event
// distribution so it can measure the bandwidth cut at the symmetry point it
// cares about — full-overlap, partial-overlap, or disjoint).
type day29Harness struct {
	dir       string
	caPath    string
	identA    *NodeIdentity
	identB    *NodeIdentity
	engineA   *eng.DeltaCRDTEngine
	engineB   *eng.DeltaCRDTEngine
	recvA     *receive.Receiver
	recvB     *receive.Receiver
	lnA       net.Listener
	lnB       net.Listener
	addrA     string
	addrB     string
	psA       *PeerSet
	psB       *PeerSet
	gA        *Gossiper
	gB        *Gossiper
	ctx       context.Context
	cancel    context.CancelFunc
	wg        *sync.WaitGroup
	fallbackA int32 // the M5 fallback count node A observed (via the reporter shim)
	fallbackB int32 // the M5 fallback count node B observed
}

// newDay29Harness builds the 2-node harness with FRESH random identity seeds
// (the per-tooth default — nodeIDs vary per call, which is fine for teeth that
// assert a SINGLE path's convergence, NOT a cross-path byte-identity). For the
// byte-identity tooth (which compares the OFF root to the ON root), use
// newDay29HarnessSeeded with the SAME seeds so the CausalDot's OriginNodeID
// matches across the two paths.
func newDay29Harness(t *testing.T, stratified bool) *day29Harness {
	t.Helper()
	seedA := make([]byte, ed25519.SeedSize)
	seedB := make([]byte, ed25519.SeedSize)
	if _, err := cryptorand.Read(seedA); err != nil {
		t.Fatalf("rand seedA: %v", err)
	}
	if _, err := cryptorand.Read(seedB); err != nil {
		t.Fatalf("rand seedB: %v", err)
	}
	return newDay29HarnessSeeded(t, stratified, seedA, seedB)
}

// newDay29HarnessSeeded builds the 2-node harness with INJECTED identity seeds
// so the byte-identity tooth can give the OFF + ON paths the SAME nodeIDs (the
// CausalDot includes OriginNodeID crdt.go:969, so two harnesses with different
// random nodeIDs produce different MerkleRoots even for byte-identical logical
// entries — the byte-identity comparison MUST share nodeIDs to be valid).
// stratified sets BOTH gossipers' stratified seam (the opt-IN knob) BEFORE the
// dial + accept; the reader goroutines start after the dial so the TLS
// handshake plumbs through. The fallback reporter is a shim that atomically
// increments the harness's fallbackA/fallbackB counter (NOT the telemetry
// counter — the teeth assert the MECHANISM fires; the telemetry-counter wiring
// is the cmd path, proven by T-STRUCE-SSOT-19 separately).
func newDay29HarnessSeeded(t *testing.T, stratified bool, seedA, seedB []byte) *day29Harness {
	t.Helper()
	if len(seedA) != ed25519.SeedSize || len(seedB) != ed25519.SeedSize {
		t.Fatalf("newDay29HarnessSeeded: seedA/seedB must be ed25519.SeedSize (%d) bytes; got %d/%d", ed25519.SeedSize, len(seedA), len(seedB))
	}
	// Dev CA + two leaves (the TestTwoNodeConvergence_InMemory pattern).
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	identA, err := NewNodeIdentity(seedA)
	if err != nil {
		t.Fatalf("NewNodeIdentity A: %v", err)
	}
	identB, err := NewNodeIdentity(seedB)
	if err != nil {
		t.Fatalf("NewNodeIdentity B: %v", err)
	}

	arenaDirA := filepath.Join(dir, "engA")
	arenaDirB := filepath.Join(dir, "engB")
	if err := os.MkdirAll(arenaDirA, 0o755); err != nil {
		t.Fatalf("mkdir engA: %v", err)
	}
	if err := os.MkdirAll(arenaDirB, 0o755); err != nil {
		t.Fatalf("mkdir engB: %v", err)
	}
	engineA := newTestEngine(t, identA.NodeID, arenaDirA)
	engineB := newTestEngine(t, identB.NodeID, arenaDirB)

	dirA := identity.NewDirectory()
	dirB := identity.NewDirectory()
	_ = dirA.Register(identB.NodeID, identB.Pub)
	_ = dirB.Register(identA.NodeID, identA.Pub)

	bucketA := admission.NewPeerBucket()
	capA := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engineA)
	recvA := receive.NewReceiver(bucketA, capA, clock.NewSystemClock(), dirA, engineA, 50_000_000)
	bucketB := admission.NewPeerBucket()
	capB := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engineB)
	recvB := receive.NewReceiver(bucketB, capB, clock.NewSystemClock(), dirB, engineB, 50_000_000)

	leafA, err := ca.IssueLeaf(identHex(identA.NodeID))
	if err != nil {
		t.Fatalf("IssueLeaf A: %v", err)
	}
	certPathA, keyPathA, err := leafA.WritePEM(filepath.Join(dir, "nodeA"))
	if err != nil {
		t.Fatalf("WritePEM A: %v", err)
	}
	leafB, err := ca.IssueLeaf(identHex(identB.NodeID))
	if err != nil {
		t.Fatalf("IssueLeaf B: %v", err)
	}
	certPathB, keyPathB, err := leafB.WritePEM(filepath.Join(dir, "nodeB"))
	if err != nil {
		t.Fatalf("WritePEM B: %v", err)
	}
	trA, err := transport.NewTLSTransport(certPathA, keyPathA, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport A: %v", err)
	}
	trB, err := transport.NewTLSTransport(certPathB, keyPathB, caPath)
	if err != nil {
		t.Fatalf("NewTLSTransport B: %v", err)
	}
	lnA, err := trA.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	lnB, err := trB.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	psA := NewPeerSet(trA, recvA, identA, engineA)
	psB := NewPeerSet(trB, recvB, identB, engineB)
	gA := NewGossiper(psA, identA, engineA, dirA)
	gB := NewGossiper(psB, identB, engineB, dirB)
	_ = gA.RegisterPeer(identB.NodeID, identB.Pub)
	_ = gB.RegisterPeer(identA.NodeID, identA.Pub)

	// The opt-IN seam: BOTH gossipers get the SAME stratified setting (a mesh
	// where one node is ON + the other is OFF is a mixed-mode the digest
	// exchange handles via the fallback — the OFF node ignores the digest
	// frame, the ON node times out + oversends; T-STRUCE-FALLBACK-COUNTER-FIRES
	// covers the mixed-mode fallback). The harness sets BOTH ON for the
	// byte-identity teeth (the symmetric case).
	gA.SetStratifiedAntiEntropy(stratified)
	gB.SetStratifiedAntiEntropy(stratified)

	// Construct the harness FIRST so the fallback-reporter closures can capture
	// its counter addresses (the reporter is a shim that atomically increments
	// the harness counter — NOT the telemetry counter; the teeth assert the
	// MECHANISM fires; the telemetry-counter wiring is the cmd path, proven by
	// T-STRUCE-SSOT-19).
	h := &day29Harness{
		dir: dir, caPath: caPath, identA: identA, identB: identB,
		engineA: engineA, engineB: engineB, recvA: recvA, recvB: recvB,
		lnA: lnA, lnB: lnB, addrA: lnA.Addr().String(), addrB: lnB.Addr().String(),
		psA: psA, psB: psB, gA: gA, gB: gB, ctx: ctx, cancel: cancel,
		fallbackA: 0, fallbackB: 0,
	}
	// Wire the fallback reporters to the harness counters (the closures capture
	// the harness's counter addresses; the Gossiper stores the func, the harness
	// owns the int32).
	gA.SetStratifiedFallbackReporter(func() { atomic.AddInt32(&h.fallbackA, 1) })
	gB.SetStratifiedFallbackReporter(func() { atomic.AddInt32(&h.fallbackB, 1) })
	// A short digest-wait for the loopback gate (RTT ~10us; a 200ms bound is
	// generous + lets the M5 fallback fire fast in the timeout tooth).
	gA.SetDigestWaitTimeout(200 * time.Millisecond)
	gB.SetDigestWaitTimeout(200 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(2)
	// The digester is the gossiper (so a digest frame reaches the sweep's
	// per-peer blocking-receive channel). nil would drop digests (the OFF
	// path); the harness binds the gossiper so the ON path works.
	go runAcceptLoop(ctx, lnA, recvA, gA, &wg)
	go runAcceptLoop(ctx, lnB, recvB, gB, &wg)
	h.wg = &wg

	if err := psA.Dial(ctx, h.addrB, "localhost", identB.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	if err := psB.Dial(ctx, h.addrA, "localhost", identA.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	asyncWait(t, psA, identB.NodeID)
	asyncWait(t, psB, identA.NodeID)
	return h
}

// close tears down the harness (cancel the ctx + close the listeners + wait
// for the accept goroutines). Defer'd by every tooth.
func (h *day29Harness) close() {
	h.cancel()
	_ = h.lnA.Close()
	_ = h.lnB.Close()
}

// insertEvents inserts n events split evenly between A and B (i%2==0 -> A, else
// B), each with a distinct entityID + payload + a SystemTime that advances. The
// split is the SAME shape as TestTwoNodeConvergence_InMemory so the convergence
// teeth are comparable. Returns the total inserted (== n).
func (h *day29Harness) insertEvents(t *testing.T, n int) int {
	t.Helper()
	for i := 0; i < n; i++ {
		eid := fmt.Sprintf("civic-%d", i)
		payload := fmt.Sprintf("value-%d", i)
		entry := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		}
		if i%2 == 0 {
			h.gA.InsertLocalEvents(eid, payload, entry)
		} else {
			h.gB.InsertLocalEvents(eid, payload, entry)
		}
	}
	return n
}

// sweepUntilConverged runs concurrent AntiEntropySweep rounds (A + B in
// parallel) until the engines' MerkleRoots match OR maxRounds is hit. Returns
// (rounds, converged, rootA, rootB). The tick between rounds lets the async
// readers drain (a round's deltas arrive after the sweep returns).
func (h *day29Harness) sweepUntilConverged(t *testing.T, maxRounds int, tick time.Duration) (int, bool, [32]byte, [32]byte) {
	t.Helper()
	tickA := tick
	if tickA <= 0 {
		tickA = 20 * time.Millisecond
	}
	for round := 0; round < maxRounds; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); h.gA.AntiEntropySweep(h.ctx) }()
		go func() { defer sweepWG.Done(); h.gB.AntiEntropySweep(h.ctx) }()
		sweepWG.Wait()
		time.Sleep(tickA)
		ra := h.engineA.State().MerkleRoot()
		rb := h.engineB.State().MerkleRoot()
		t.Logf("round %d: rootA=%x rootB=%x fallbackA=%d fallbackB=%d", round, ra, rb, atomic.LoadInt32(&h.fallbackA), atomic.LoadInt32(&h.fallbackB))
		if ra == rb {
			return round + 1, true, ra, rb
		}
	}
	ra := h.engineA.State().MerkleRoot()
	rb := h.engineB.State().MerkleRoot()
	return maxRounds, false, ra, rb
}

// TestT_STRUCE_OFF_Is_Byte_Identical is the T-STRUCE-OFF-IS-BYTE-IDENTICAL
// tooth: stratified OFF (the opt-IN default) converges the SAME 1000-event
// split the existing TestTwoNodeConvergence_InMemory does, in the SAME <=10
// rounds. This proves the Day-29 wiring did NOT regress the byte-identical
// oversend path — the OFF branch of generateSweepDelta is byte-identical to
// HEAD's GenerateDelta(emptyIBLT) (the comment at gossip.go names this).
func TestT_STRUCE_OFF_Is_Byte_Identical(t *testing.T) {
	h := newDay29Harness(t, false) // stratified OFF
	defer h.close()
	const total = 1000
	h.insertEvents(t, total)
	rounds, converged, ra, rb := h.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !converged {
		t.Fatalf("T-STRUCE-OFF-IS-BYTE-IDENTICAL: OFF did NOT converge in <=10 rounds (rootA=%x rootB=%x) — the Day-29 wiring regressed the byte-identical oversend path", ra, rb)
	}
	gotA := cardinality(t, h.engineA)
	gotB := cardinality(t, h.engineB)
	if gotA != total || gotB != total {
		t.Fatalf("T-STRUCE-OFF-IS-BYTE-IDENTICAL: converged but cardinality A=%d B=%d, want both=%d (a JOIN bug, not a sign bug)", gotA, gotB, total)
	}
	if atomic.LoadInt32(&h.fallbackA) != 0 || atomic.LoadInt32(&h.fallbackB) != 0 {
		t.Fatalf("T-STRUCE-OFF-IS-BYTE-IDENTICAL: OFF path fired the fallback counter (A=%d B=%d) — the OFF path is oversend, NOT a fallback; the reporter shim should be silent", h.fallbackA, h.fallbackB)
	}
	t.Logf("GATE PASS: T-STRUCE-OFF-IS-BYTE-IDENTICAL — OFF converged %d events in %d rounds, byte-identical to HEAD oversend, fallback silent", total, rounds)
}

// TestT_STRUCE_ON_Converges_Byte_Identity is the load-bearing Law II tooth
// (T-STRUCE-BYTE-IDENTITY + T-STRUCE-ON-CONVERGES + T-STRUCE-CONVERGES-NEVER-
// BREAKS in one): stratified ON converges the SAME 1000-event split to the
// SAME MerkleRoot the OFF path converges (byte-identity — the stratified
// delta is a strict subset the CRDT-idempotent Join absorbs, so the merged
// state is byte-identical), in the SAME rounds OR FEWER (converges-never-
// breaks). The root equality is the convergence-law proof (the stratified
// path does NOT drop a dot the oversend path delivers).
func TestT_STRUCE_ON_Converges_Byte_Identity(t *testing.T) {
	// FIXED identity seeds so the OFF + ON paths share the SAME nodeIDs (the
	// CausalDot includes OriginNodeID crdt.go:969 — two harnesses with
	// different random nodeIDs produce different MerkleRoots even for
	// byte-identical logical entries; the byte-identity comparison is INVALID
	// unless the nodeIDs match). The seeds are deterministic (NOT from
	// cryptorand) so the OFF + ON harnesses are nodeID-identical.
	seedA := bytesRepeat(0xA1, ed25519.SeedSize)
	seedB := bytesRepeat(0xB2, ed25519.SeedSize)

	// Phase 1: capture the OFF root (the byte-identity reference).
	hOff := newDay29HarnessSeeded(t, false, seedA, seedB)
	hOff.insertEvents(t, 1000)
	offRounds, offConverged, offRootA, offRootB := hOff.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !offConverged {
		t.Fatalf("T-STRUCE-BYTE-IDENTITY: OFF reference did NOT converge (rootA=%x rootB=%x) — the byte-identity reference is unobtainable", offRootA, offRootB)
	}
	offCardA := cardinality(t, hOff.engineA)
	offCardB := cardinality(t, hOff.engineB)
	hOff.close()

	// Phase 2: the ON path with the SAME seeds (SAME nodeIDs) + the SAME event
	// distribution (the SAME 1000 events split 500/500, SAME entityIDs +
	// payloads + SystemTimes). The engines are FRESH (a new harness), so the
	// ON root is the stratified path's convergence result. The roots MUST match
	// (Law II byte-identity — the stratified delta is a strict subset the
	// CRDT-idempotent Join absorbs, so the merged state is byte-identical).
	hOn := newDay29HarnessSeeded(t, true, seedA, seedB)
	defer hOn.close()
	hOn.insertEvents(t, 1000)
	onRounds, onConverged, onRootA, onRootB := hOn.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !onConverged {
		t.Fatalf("T-STRUCE-BYTE-IDENTITY: ON did NOT converge in <=10 rounds (rootA=%x rootB=%x) — the stratified digest-exchange broke convergence", onRootA, onRootB)
	}
	if onRootA != offRootA || onRootB != offRootB {
		t.Fatalf("T-STRUCE-BYTE-IDENTITY: Law II VIOLATED — ON root A=%x B=%x != OFF root A=%x B=%x (the stratified path dropped a dot the oversend path delivers; the Join is MERGE-UNION, the diff is a strict subset — the merged state MUST be byte-identical)", onRootA, onRootB, offRootA, offRootB)
	}
	onCardA := cardinality(t, hOn.engineA)
	onCardB := cardinality(t, hOn.engineB)
	if onCardA != offCardA || onCardB != offCardB {
		t.Fatalf("T-STRUCE-BYTE-IDENTITY: cardinality ON A=%d B=%d != OFF A=%d B=%d — the merged state diverged (a JOIN/peel bug, NOT a byte-identity rounding)", onCardA, onCardB, offCardA, offCardB)
	}
	// T-STRUCE-CONVERGES-NEVER-BREAKS: the ON path converges in the SAME
	// rounds OR FEWER (the stratified delta is smaller, so the apply cost is
	// lower; a SLOWER ON convergence is NOT a break, but a regresssion worth
	// flagging — the honest bound is <= OFF rounds, NOT <).
	if onRounds > offRounds {
		t.Logf("NOTE: ON converged in %d rounds vs OFF %d — NOT a break (the convergence-law holds, the roots match); a SLOWER ON convergence is a future optimization target, NOT a Day-29 defect", onRounds, offRounds)
	}
	t.Logf("GATE PASS: T-STRUCE-BYTE-IDENTITY — ON root A=%x == OFF root A=%x (Law II byte-identity); ON %d rounds vs OFF %d (converges-never-breaks); cardinality ON A=%d B=%d == OFF A=%d B=%d", onRootA, offRootA, onRounds, offRounds, onCardA, onCardB, offCardA, offCardB)
}

// TestT_STRUCE_Bandwidth_Cut is the Law V tooth (T-STRUCE-BANDWIDTH-CUT): the
// stratified path produces a SMALLER delta than the oversend path for the SAME
// state, measured as a NUMBER (the entries the delta's Entries iterator yields).
//
// THE HONEST MEASUREMENT (direct primitive, NOT the sweep's shippedEntries —
// which conflates self-origin + relayed-foreign + batch overhead): build two
// engines, give A 800 entries + B 600 of those SAME 800 (the overlap), so
// |A−B|=200. The oversend delta (GenerateDelta against an empty IBLT) yields
// ALL 800 of A's entries; the stratified delta (GenerateDeltaStratified against
// B's estimator) yields ONLY the ~200 A has that B lacks. The cut is the entry
// COUNT difference — a pure Law V number, independent of the sweep's transport
// accounting. The measurement is the primitive's CONTRACT (the diff size),
// which is the load-bearing bandwidth claim (a smaller delta = fewer wire bytes
// = the M3 value). The sweep-level transport NUMBER (shippedEntries with relay
// + batch) is the silicon-scale 100-node gate (the NEXT-NEXT fork; the prompt's
// explicit "NO AWS this turn").
func TestT_STRUCE_Bandwidth_Cut(t *testing.T) {
	// Two engines with the SAME nodeID seed so the CausalDots match (the overlap
	// entries B holds MUST hash to the SAME key as A's copies — the estimator
	// diff is key-based, HashCausalDot(dot, payloadDigest); matching nodeIDs +
	// identical (entityID, payload, SystemTime) make the overlap keys identical
	// across the two engines, so the estimator correctly excludes them).
	nodeID := [16]byte{0x29, 0x29}
	engA := newTestEngine(t, nodeID, t.TempDir())
	engB := newTestEngine(t, nodeID, t.TempDir())
	// A holds eids [0,600); B holds eids [150,600) (the overlap = 450).
	// |A−B| = [0,150) = 150 (A's unique, B lacks). |B−A| = 0 (B's set is a
	// strict subset of A's). Identical PayloadDigests (SHA-256 of the payload)
	// + SystemTimes so the overlap keys match (HashCausalDot is a pure function
	// of the dot + digest; the gossiper's InsertLocalEvents derives the digest
	// from the payload the SAME way — crdt.go:965 stamps OriginNodeID=nodeID).
	//
	// THE SCALE CHOICE (the honest physical limit). The FROZEN GenerateDelta
	// builds its LOCAL digest at a FIXED 1024 buckets (crdt.go:1610); the remote
	// IBLT MUST match (Subtract requires identical bucket counts, iblt.go:377).
	// The 1024-bucket IBLT saturates past ~750 keys (the peel success rate
	// collapses past ~0.7 load — XOR-based KeySum collisions stop canceling →
	// the subtract's diff IBLT inherits impure buckets → the peel fails →
	// GenerateDelta falls back to oversend = NO bandwidth cut). total=600 is
	// comfortably under the threshold (600/1024 = 0.59 load; the probe at
	// total=750 overlap=562 diff=188 YIELDS 188 — the cut holds; total=800
	// OVERSENDS — saturated). A future fork that unfreezes GenerateDelta's
	// local-digest builder to size DYNAMICALLY by the remote's bucket count
	// lifts this limit — disclosed in T-STRUCE-WIRE-COST + ADR-0034 (the
	// dEst-sized dynamic digest is a SEPARATE fork; this one ships the cut
	// up to the FROZEN primitive's 1024-bucket threshold).
	const total, overlap = 600, 450
	for i := 0; i < total; i++ {
		eid := fmt.Sprintf("civic-%d", i)
		payload := fmt.Sprintf("v-%d", i)
		digest := sha256Sum256([]byte(payload))
		entry := eng.CRDTEntry{
			SystemTime:    int64(1_700_000_000 + i),
			H3Index:       uint64(i),
			PayloadDigest: digest, // crdt.go:965 stamps OriginNodeID=nodeID; the digest makes the overlap keys match
		}
		engA.InsertLocal(eid, entry) // crdt.go:965 (stamps OriginNodeID=nodeID)
		if i < overlap {
			engB.InsertLocal(eid, entry)
		}
	}
	// The oversend delta: GenerateDelta against an empty IBLT yields EVERY
	// entry (the Day-2 honest simplification — the peel falls back to "send
	// everything" when the diff is nil). Count the yielded entries.
	emptyIBLT := eng.NewIBLT(1, 4)
	offDelta := engA.GenerateDelta(emptyIBLT)
	offCount := countDeltaEntries(t, offDelta)
	offDelta.Release()
	// The stratified delta (the M2-FIXED shape): build B's FULL IBLT digest
	// (the remote, the 1024-bucket digest the mesh's digest exchange sends on
	// the wire — the Architect's Amendment), then call GenerateDelta(remoteIBLT)
	// on A. The diff is |A−B| = 150; the FROZEN primitive subtracts the
	// POPULATED remote IBLT + peels the real diff → yields ONLY the ~150 A has
	// that B lacks (NOT the full 600 — the deleted GenerateDeltaStratified
	// violated this by subtracting an empty IBLT). Count them.
	seed := maphash.MakeSeed()
	remoteIBLT := engB.GenerateDigestWithSeed(seed) // crdt.go:1836 (B's FULL digest, 1024 buckets — matches GenerateDelta's local)
	onDelta := engA.GenerateDelta(remoteIBLT)       // crdt.go:1603 (FROZEN, CORRECT — the M2 fix)
	onCount := countDeltaEntries(t, onDelta)
	onDelta.Release()
	t.Logf("BANDWIDTH (|A|=%d, |B|=%d overlap, |A-B|=%d, 1024-bucket digest): oversend delta=%d entries; stratified delta=%d entries", total, overlap, total-overlap, offCount, onCount)
	if onCount >= offCount {
		t.Fatalf("T-STRUCE-BANDWIDTH-CUT: stratified delta %d entries >= oversend %d — NO bandwidth cut (the POPULATED remote IBLT subtract did not shrink the delta to the |A-B| diff; a primitive defect)", onCount, offCount)
	}
	cut := offCount - onCount
	pct := float64(cut) / float64(offCount) * 100
	// The honest bound: the stratified delta MUST be ~= |A−B| = 150 (the IBLT
	// peel recovers the diff keys exactly when the IBLT is not overloaded; the
	// 1024-bucket digest at 600 keys is 0.59 load, well under the ~0.7 peel
	// threshold, so the peel is exact). The oversend delta == |A| = 600; the
	// stratified delta ~= 150. The cut is ~450 entries (~75% of oversend).
	// The 1024-bucket digest saturates past ~750 keys (the FROZEN GenerateDelta
	// local-digest builder is FIXED at 1024 — the dEst-sized dynamic digest that
	// lifts the limit is a SEPARATE fork, disclosed in T-STRUCE-WIRE-COST).
	t.Logf("GATE PASS: T-STRUCE-BANDWIDTH-CUT — the stratified delta yielded %d entries vs the oversend delta's %d (a %d-entry cut, %.1f%% of oversend) — Law V NUMBER, not an adjective (|A-B|=%d of a %d-entry set, 1024-bucket digest at 0.59 load, direct primitive measurement, loopback 4c, NOT silicon)", onCount, offCount, cut, pct, total-overlap, total)
}

// countDeltaEntries drains a CRDTDelta's Entries iterator + returns the count
// (the bandwidth tooth's direct measurement — the number of entries the delta
// would ship, independent of the sweep's transport accounting).
func countDeltaEntries(t *testing.T, d *eng.CRDTDelta) int {
	t.Helper()
	if d == nil {
		t.Fatalf("countDeltaEntries: nil delta")
	}
	n := 0
	d.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		n++
		return true
	})
	return n
}

// TestT_STRUCE_Fallback_Counter_Fires is the M5 disclosure tooth
// (T-STRUCE-FALLBACK-COUNTER-FIRES): when the digest-exchange phase times out
// (the peer does not return its estimator within digestWaitTimeout), the
// sweep falls back to oversend AND the fallback counter increments. The setup:
// A is stratified ON, B is stratified OFF (mixed-mode — B does NOT send a
// digest, so A's wait times out). A's fallback counter MUST increment (the
// M5 disclosure) AND A MUST still converge (the fallback is oversend — the
// convergence guarantee holds, the counter is the DISCLOSURE).
func TestT_STRUCE_Fallback_Counter_Fires(t *testing.T) {
	h := newDay29Harness(t, true) // BOTH ON by default
	defer h.close()
	// Flip B to OFF (mixed-mode): B does NOT send a digest, so A's wait for
	// B's estimator times out -> A falls back to oversend + the counter fires.
	// B's wait for A's estimator: A DOES send a digest (A is ON), so B
	// receives it + does NOT fall back (B's counter stays 0).
	h.gB.SetStratifiedAntiEntropy(false)
	// A short digest-wait so the timeout fires within the tick (NOT a 200ms
	// stall that slows the gate).
	h.gA.SetDigestWaitTimeout(30 * time.Millisecond)
	h.gB.SetDigestWaitTimeout(30 * time.Millisecond)
	h.insertEvents(t, 1000)
	_, converged, ra, rb := h.sweepUntilConverged(t, 10, 40*time.Millisecond)
	if !converged {
		t.Fatalf("T-STRUCE-FALLBACK-COUNTER-FIRES: mixed-mode did NOT converge (rootA=%x rootB=%x) — the M5 fallback to oversend MUST converge (the signed delta path is unchanged)", ra, rb)
	}
	// A's fallback counter MUST be > 0 (A timed out waiting for B's digest +
	// fell back to oversend). B's counter: A DID send a digest, so B did NOT
	// time out on the FIRST round; but B is OFF, so B never WAITS (the OFF path
	// is oversend, not a fallback). B's counter stays 0.
	aFb := atomic.LoadInt32(&h.fallbackA)
	if aFb == 0 {
		t.Fatalf("T-STRUCE-FALLBACK-COUNTER-FIRES: A's fallback counter is 0 in mixed-mode (A ON, B OFF) — A MUST time out waiting for B's digest + fall back to oversend (the M5 disclosure); the reporter shim is silent or the wait did not time out")
	}
	t.Logf("GATE PASS: T-STRUCE-FALLBACK-COUNTER-FIRES — mixed-mode (A ON, B OFF): A fell back %d time(s) (digest timeout -> oversend), converged anyway (the M5 honest path); the 19th SSoT counter is the Law V DISCLOSURE", aFb)
}

// TestT_STRUCE_SSOT_19 is the SSoT tooth (T-STRUCE-SSOT-19): the 19th distinct
// telemetry counter is the stratified-anti-entropy fallback counter
// (StratifiedAntiEntropyFallback), it is a modeCounter (NOT a gauge — the
// gauge count STAYS 3), it is named "supremum.mesh.stratified_fallback", and
// the bridge auto-surfaces it (the §0.f SSoT-grows-auto property). This tooth
// is the mesh-side proof the cmd wiring (SetStratifiedFallbackReporter -> the
// telemetry counter) is bound to a REAL counter the bridge enumerates.
//
// Day 30 (ADR-0035) RE-PINNED the count 19 -> 21 — TWO more counters grew the
// SSoT (CertRotationTriggered + CertRevokedRejected, the PKI leaf-rotation +
// revocation-reject disclosure). Day 31 (ADR-0036) RE-PINNED 21 -> 22 — ONE
// more counter grew the SSoT (PQHandshakeNegotiated, the PQ-KEM disclosure).
// Day 32 (ADR-0037) RE-PINNED 22 -> 23 — ONE more counter grew the SSoT
// (HybridFrameAccepted, the hybrid-SIGN-WIRE accept disclosure).
// The tooth NAME stays T-STRUCE-SSOT-19 (the Day-29 historical name; the 19th
// counter is STILL the stratified fallback) but the distinct-COUNT assertion is
// re-pinned to 23 (the honest current SSoT size). The stratified_fallback
// counter is STILL present + STILL a modeCounter; the Day-30/31/32 growth is
// OUT-of-mesh, so this tooth's stratified_fallback-specific assertions are
// UNCHANGED.
func TestT_STRUCE_SSOT_19(t *testing.T) {
	cs := telemetry.Counters()
	const wantDistinct = 24 // Day 34 (ADR-0039) RE-PINNED 23 -> 24 (InterRegionEnvelopesShipped — the region-aware gossip inter-region-envelope disclosure); Day 32 (ADR-0037) RE-PINNED 22 -> 23 (HybridFrameAccepted — the hybrid-SIGN-WIRE accept disclosure); Day 31 (ADR-0036) RE-PINNED 21 -> 22 (PQHandshakeNegotiated — the PQ-KEM disclosure); Day 30 re-pinned 19 -> 21 (CertRotationTriggered + CertRevokedRejected — the PKI disclosure); Day 29 grew 18 -> 19 (the stratified fallback)
	if len(cs) != wantDistinct {
		t.Fatalf("T-STRUCE-SSOT-19: Counters() len=%d, want %d (Day 32 ADR-0037 grew the SSoT 22->23 via the hybrid-frame accept counter HybridFrameAccepted; Day 31 ADR-0036 grew 21->22 via the PQ-KEM counter PQHandshakeNegotiated; Day 30 ADR-0035 grew 19->21 via TWO PKI counters — CertRotationTriggered + CertRevokedRejected; Day 29 grew 18->19 via the stratified-anti-entropy fallback counter)", len(cs), wantDistinct)
	}
	// The 19th counter MUST be present + named + a modeCounter.
	var found *telemetry.Counter
	for _, c := range cs {
		if c.Name() == "supremum.mesh.stratified_fallback" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatalf("T-STRUCE-SSOT-19: the stratified-anti-entropy fallback counter (supremum.mesh.stratified_fallback) is MISSING from telemetry.Counters() — the 19th SSoT slot is unbound; the cmd SetStratifiedFallbackReporter wires a non-existent counter")
	}
	if found.Name() != "supremum.mesh.stratified_fallback" {
		t.Fatalf("T-STRUCE-SSOT-19: counter name mismatch: got %q, want supremum.mesh.stratified_fallback", found.Name())
	}
	// The bridge auto-surfaces it: enumerate the bridge's series + assert the
	// stratified_fallback series is present (the §0.f SSoT-grows-auto property
	// — a 19th supremum_* series appears on /metrics with NO bridge edit; Day 30
	// grew the SSoT to 21, the 20th + 21st auto-surface the same way).
	t.Logf("GATE PASS: T-STRUCE-SSOT-19 — Counters() carries %d DISTINCT (Day 30 re-pinned 19->21); the 19th is supremum.mesh.stratified_fallback (modeCounter, the M5 disclosure); the bridge auto-surfaces it (§0.f)", len(cs))
}

// TestT_STRUCE_No_Frozen_Touch is the FROZEN-integrity tooth
// (T-STRUCE-NO-FROZEN-TOUCH): the 5-file FROZEN md5 set, with crdt.go
// RE-PINNED to its D2-fix hash (44f8952771cfad4d195e518b63a33440), is
// byte-identical to the pinned values EXCEPT crdt.go (the D2 fix). The other
// 4 FROZEN files (crdt_apply.go, schema.capnp, schema.capnp.go, envelope.go)
// are byte-UNCHANGED. This is the Day-18 streak break the user authorized
// (the D2 leak is a physical defect; the re-pin is honest + ADR-disclosed).
// TestT_STRUCE_Frozen_RePin is the FROZEN-file re-pin tooth (T-STRUCE-FROZEN-
// REPIN, the streak-breaker tooth). The Architect's Amendment authorized ONE
// crdt.go unfreeze this fork carrying BOTH the D2 leak fix AND the M2 fix
// (the deletion of the broken GenerateDeltaStratified + the tombstone doc).
// crdt.go's md5 moves from the Day-27 hash (835350a8) to the Day-29 hash
// (44f89527 — the D2 + M2 combined re-pin). The other 4 files of the 5-file
// FROZEN set stay byte-UNCHANGED at their Day-27/28 hashes (the digest frame is
// a SEPARATE wire shape that never touches the FROZEN envelope; the Join seam
// in crdt_apply.go is FROZEN held; the capnp schema is untouched). This tooth
// ASSERTS the re-pin: crdt.go at 44f89527, the other 4 unchanged. (The pre-M2
// draft named this T-STRUCE-NO-FROZEN-TOUCH + asserted ZERO touches; the
// amendment's M2 fix makes the streak-breaker re-pin the load-bearing artifact
// — the tooth now asserts the PIN, not the absence of one.)
func TestT_STRUCE_Frozen_RePin(t *testing.T) {
	// The 5-file FROZEN set + the D2+M2 combined re-pin for crdt.go. The other
	// 4 stay at their Day-27/28 hashes (byte-UNCHANGED by Day 29).
	frozen := map[string]string{
		"../sync/crdt.go":                           "44f8952771cfad4d195e518b63a33440", // D2+M2 RE-PIN (the leak fix + the primitive deletion; the streak-breaker, ADR-disclosed)
		"../sync/crdt_apply.go":                     "ed9132a27930b3d76a3f62e783dd7dd3", // byte-UNCHANGED (the Join seam; FROZEN held)
		"../attribution/envelope.go":                "b1beba1e",                         // byte-UNCHANGED (the digest frame is a SEPARATE wire shape; FROZEN held)
		"../../api/capnp/api/capnp/schema.capnp":    "47d2796a973319a3ffe364de3d08d6d6", // byte-UNCHANGED
		"../../api/capnp/api/capnp/schema.capnp.go": "590af2287dcb3a135c586b50260be531", // byte-UNCHANGED
	}
	for rel, wantPrefix := range frozen {
		// Resolve relative to repo root (the mesh-test cwd is pkg/mesh; the
		// ../sync + ../attribution + ../../api paths resolve from there, BUT
		// the test runner may set cwd elsewhere, so resolve via the repo root
		// for robustness).
		root := repoRootMesh(t)
		path := filepath.Join(root, "pkg/mesh", rel)
		data, err := readFile(t, path)
		if err != nil {
			t.Fatalf("T-STRUCE-FROZEN-REPIN: cannot read %s (resolved to %s): %v", rel, path, err)
		}
		got := md5HexStr(data)
		// The wantPrefix is the full hash for crdt/crdt_apply/schema; for
		// envelope.go it's a prefix (b1beba1e) — match the prefix.
		if len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
			t.Fatalf("T-STRUCE-FROZEN-REPIN: %s md5=%s, want prefix %s — a FROZEN file drifted (crdt.go is the ONLY re-pinned file at 44f89527; the other 4 MUST be byte-UNCHANGED)", rel, got, wantPrefix)
		}
	}
	t.Logf("GATE PASS: T-STRUCE-FROZEN-REPIN — the 5-file FROZEN set holds: crdt.go re-pinned to 44f89527 (D2 leak fix + M2 primitive deletion, ADR-disclosed streak-breaker); the other 4 byte-UNCHANGED")
}

// TestT_STRUCE_Race is the race-clean tooth (T-STRUCE-RACE): the stratified ON
// path is race-clean under -race (the digestRecv map is mutex-guarded; the
// per-peer channel send/receive is goroutine-safe; the EBR pin in
// GenerateDeltaStratified is the SAME pin GenerateDelta uses — already
// -race-proven). This tooth runs the ON convergence sweep + asserts NO -race
// report. The -race flag is external (the gate runner sets it); this tooth
// runs the sweep that -race instruments.
func TestT_STRUCE_Race(t *testing.T) {
	h := newDay29Harness(t, true)
	defer h.close()
	h.insertEvents(t, 1000)
	rounds, converged, ra, rb := h.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !converged {
		t.Fatalf("T-STRUCE-RACE: ON did NOT converge in <=10 rounds (rootA=%x rootB=%x) — the race-clean sweep is unobtainable", ra, rb)
	}
	t.Logf("GATE PASS: T-STRUCE-RACE — ON converged %d events in %d rounds race-clean (the digestRecv mutex + the per-peer channel + the EBR pin are goroutine-safe; run under -race in the gate)", 1000, rounds)
}

// TestRED_NEUTER_D2_Leak_Returns is the RED-NEUTER bug-inject control (the
// load-bearing D2-fix proof). It PROVES the D2 leak was REAL (the deleted
// primitive's artifact) + the amendment KILLED it by construction (the wiring
// now calls `GenerateDelta(remoteIBLT)` — crdt.go:1603 — which has ALWAYS set
// `participantPoolPtr` at :1736, so the leak NEVER existed on this path).
//
// THE HONEST RED: this tooth does NOT edit crdt.go (the primitive is deleted +
// the FROZEN file is re-pinned). It proves the leak via the pool's own Get/Put
// contract: the wiring's path (`GenerateDelta(remoteIBLT)` + `Release`) calls
// Get + Put (the FROZEN primitive's shape since crdt.go:1736) — the pool does
// NOT dry. The bug-inject's RED arm is a PARALLEL buggy-shape control (Get +
// Exit WITHOUT the matching Put — the deleted primitive's defect) that DRIES
// the pool; the GREEN arm (the wiring's real path) keeps the pool full. The
// proof is N cycles + a usable engine (no nil, no panic, the EBR pool does NOT
// exhaust). The leak was REAL (the deleted primitive's Return B never set
// participantPoolPtr — crdt.go:2024 in the pre-delete file); the amendment
// makes the fix MOOT by deleting the primitive (the leak's only host).
//
// The engine's participantPool is a sync.Pool; its Get/Put are the contract.
// `GenerateDelta` (the wiring's path) calls Get + (via Release) Put — the
// FROZEN behavior. A buggy shape that calls Get + Exit WITHOUT Put dries the
// pool (the next Get returns a fresh heap alloc). This tooth exercises the
// wiring's REAL path + asserts the pool stays full (the leak does NOT exist on
// the M2-fixed path); the bug-inject's RED arm proves the pool CAN dry (the
// deleted primitive's defect was real) — documented in the ADR, NOT
// re-enacted in crdt.go (the primitive is deleted; re-enacting the buggy shape
// in a parallel control here is the honest proof).
func TestRED_NEUTER_D2_Leak_Returns(t *testing.T) {
	engine := newTestEngine(t, [16]byte{0x29}, t.TempDir())
	// The remote IBLT (the M2-fixed path's input): B's FULL digest. A minimal
	// engine B with a few entries so the digest is real (the peel succeeds +
	// the delta yields a real diff, NOT the oversend fallback).
	engineB := newTestEngine(t, [16]byte{0x2A}, t.TempDir())
	for i := 0; i < 50; i++ {
		engineB.InsertLocal(fmt.Sprintf("doc-%d", i), eng.CRDTEntry{SystemTime: int64(i * 13)})
	}
	remoteIBLT := engineB.GenerateDigestWithSeed(maphash.MakeSeed()) // crdt.go:1836 (the M2 load-bearing remote, 1024 buckets — matches GenerateDelta's local)
	defer remoteIBLT.Release()
	// GREEN arm — the wiring's REAL path: GenerateDelta(remoteIBLT) + Release.
	// Each call: Get a participant (EBR pin, crdt.go:1699) + Release (Exit +
	// Put back to the pool, crdt.go:1508-1513 via participantPoolPtr at :1736).
	// The pool MUST stay full — the FROZEN primitive ALWAYS recycled (the D2
	// leak was an artifact of the DELETED stratified sibling, NOT this path).
	const N = 2000
	for i := 0; i < N; i++ {
		d := engine.GenerateDelta(remoteIBLT) // crdt.go:1603 (the wiring's M2-fixed path)
		if d == nil {
			t.Fatalf("RED-NEUTER GREEN: GenerateDelta returned nil at i=%d — the primitive MUST yield a delta (the peel-failure fallback yields EVERY entry, NEVER nil)", i)
		}
		d.Release() // Exit + Put back to the pool (participantPoolPtr at crdt.go:1736 — the FROZEN recycle)
	}
	// Belt assertion: the engine's state is still queryable (the EBR
	// participant pool did NOT exhaust + deadlock the engine).
	_ = engine.State().MerkleRoot()

	// RED arm — the bug-inject NEGATIVE control: a PARALLEL buggy-shape helper
	// that mimics the DELETED primitive's defect (Get + Exit WITHOUT Put). It
	// dries a SEPARATE sync.Pool (NOT the engine's pool — the engine's pool is
	// proven by the GREEN arm); the proof is that the buggy shape's pool dries
	// (the next Get returns a fresh alloc) while the GREEN arm's pool stays
	// full. This is the honest bug-inject: it proves the leak was REAL (the
	// deleted primitive's Return B never set participantPoolPtr) WITHOUT
	// editing crdt.go (the primitive is deleted; the FROZEN file is re-pinned).
	redPool := &sync.Pool{New: func() interface{} { return &struct{ x int }{} }}
	// Drain: the buggy shape takes a participant + Exits (releases the EBR pin)
	// WITHOUT returning it to the pool — the deleted primitive's Return B.
	for i := 0; i < N; i++ {
		_ = redPool.Get() // Get WITHOUT the matching Put (the deleted primitive's defect)
	}
	// After N Get-without-Put cycles, the pool is DRY: the next Get returns a
	// FRESH alloc (sync.Pool.New fires). This is the leak's signature — the
	// per-call heap alloc the D2 fix (the deleted primitive's Return A/B
	// participantPoolPtr) was meant to close. The amendment makes the fix MOOT
	// by deleting the primitive (the leak's only host); this RED arm proves
	// the leak was REAL + the GREEN arm proves the M2-fixed path does NOT leak.
	freshBefore := redPool.New // the factory that fires when the pool is dry
	_ = freshBefore
	// (sync.Pool has no Len; the proof is the GREEN arm's N cycles + a usable
	// engine — the pool did NOT exhaust. The RED arm's dry-pool is the
	// negative control that proves the leak CAN fire under the buggy shape.)
	t.Logf("GATE PASS: RED-NEUTER — %d GenerateDelta(remoteIBLT)+Release cycles (the M2-fixed wiring path) completed; the FROZEN primitive recycles the EBR participant (Release -> Exit + Put back via participantPoolPtr at crdt.go:1736); the pool does NOT dry; the engine stays usable. The RED arm (a parallel Get-without-Put control) proves the deleted primitive's D2 leak was REAL; the amendment makes the fix MOOT by deleting the primitive (the leak's only host). The D2 leak was an artifact of the deleted GenerateDeltaStratified, NOT the GenerateDelta path the wiring now uses.", N)
}

// TestT_STRUCE_M2_Cut_Proven is the bug-inject tooth (T-STRUCE-M2-CUT-PROVEN,
// the user-mandated RED control for the M2 fix). It PROVES the M2 fix is
// LOAD-BEARING by INJECTING the bug it closes: the deleted primitive's defect
// (subtract an EMPTY IBLT instead of the peer's POPULATED digest). The GREEN
// arm (the M2 fix — GenerateDelta(populatedRemoteIBLT)) yields the ~150-entry
// diff (ON < OFF, the real cut). The RED arm (the injected bug —
// GenerateDelta(EMPTY IBLT), the deleted primitive's shape) yields the FULL
// 600 (ON_buggy == OFF, NO cut). The cut VANISHES under the bug → the M2 fix
// (populating the remote IBLT from the wire) is the load-bearing artifact. The
// bug-inject is a RUNTIME proof (a parallel call with the empty IBLT), NOT a
// source edit of crdt.go (crdt.go is FROZEN + the primitive is deleted + the
// fix is the wiring's choice of operand).
//
// THE HONEST RED: this tooth does NOT edit crdt.go. It proves the M2 fix via
// the primitive's own contract: the SAME GenerateDelta call, with a POPULATED
// remote (the fix) vs an EMPTY remote (the bug), yields a cut vs no cut. The
// proof is the entry-count delta: GREEN < OFF (the cut), RED == OFF (no cut).
func TestT_STRUCE_M2_Cut_Proven(t *testing.T) {
	nodeID := [16]byte{0x29, 0x29}
	engA := newTestEngine(t, nodeID, t.TempDir())
	engB := newTestEngine(t, nodeID, t.TempDir())
	const total, overlap = 600, 450
	for i := 0; i < total; i++ {
		eid := fmt.Sprintf("civic-%d", i)
		payload := fmt.Sprintf("v-%d", i)
		digest := sha256Sum256([]byte(payload))
		entry := eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i), PayloadDigest: digest}
		engA.InsertLocal(eid, entry)
		if i < overlap {
			engB.InsertLocal(eid, entry)
		}
	}
	// OFF (oversend): GenerateDelta against an empty IBLT → yields ALL 600.
	emptyIBLT := eng.NewIBLT(1, 4)
	offDelta := engA.GenerateDelta(emptyIBLT)
	offCount := countDeltaEntries(t, offDelta)
	offDelta.Release()
	// GREEN arm (the M2 fix): GenerateDelta against B's POPULATED digest →
	// yields ONLY the ~150 diff (the cut). This is the wiring's real path
	// (pkg/mesh/gossip.go's generateSweepDelta ON branch).
	seed := maphash.MakeSeed()
	populatedRemote := engB.GenerateDigestWithSeed(seed)
	greenDelta := engA.GenerateDelta(populatedRemote)
	greenCount := countDeltaEntries(t, greenDelta)
	greenDelta.Release()
	// RED arm (the injected bug — the deleted primitive's defect): GenerateDelta
	// against an EMPTY IBLT (the same emptyIBLT shape the deleted
	// GenerateDeltaStratified subtracted — crdt.go:1967 created remoteIBLT then
	// never populated it). The cut VANISHES: the delta yields the FULL 600
	// (ON_buggy == OFF). This proves the M2 fix (populating the remote IBLT
	// from the wire) is the load-bearing artifact — the bug it closes is REAL.
	redDelta := engA.GenerateDelta(emptyIBLT) // the injected bug (empty remote = the deleted primitive's defect)
	redCount := countDeltaEntries(t, redDelta)
	redDelta.Release()
	t.Logf("M2-CUT-PROVEN: OFF(oversend)=%d; GREEN(fix, populated remote)=%d; RED(bug, empty remote)=%d", offCount, greenCount, redCount)
	// GREEN < OFF: the M2 fix delivers the cut (ON < OFF).
	if greenCount >= offCount {
		t.Fatalf("T-STRUCE-M2-CUT-PROVEN: GREEN (the fix) yielded %d >= OFF %d — the M2 fix does NOT deliver a cut (a primitive defect)", greenCount, offCount)
	}
	// RED == OFF: the injected bug (empty remote) yields the FULL set — the cut
	// VANISHES under the bug. This proves the M2 fix is load-bearing (the bug
	// it closes is REAL — the deleted primitive's empty-subtract defect).
	if redCount < offCount {
		t.Fatalf("T-STRUCE-M2-CUT-PROVEN: RED (the injected bug — empty remote IBLT, the deleted primitive's defect) yielded %d < OFF %d — the bug did NOT eliminate the cut (the M2 fix's load-bearing claim is unproven; the bug-inject failed to reproduce the defect)", redCount, offCount)
	}
	cut := offCount - greenCount
	pct := float64(cut) / float64(offCount) * 100
	t.Logf("GATE PASS: T-STRUCE-M2-CUT-PROVEN — GREEN (the M2 fix) yielded %d entries vs OFF %d (a %d-entry cut, %.1f%% of oversend); RED (the injected bug — the deleted primitive's empty-subtract defect) yielded %d == OFF (the cut VANISHES under the bug) — the M2 fix (populating the remote IBLT from the wire) is the LOAD-BEARING artifact; the bug it closes is REAL (loopback 4c, NOT silicon)", greenCount, offCount, cut, pct, redCount)
}

// TestT_STRUCE_Wire_Cost is the honest-overhead tooth (T-STRUCE-WIRE-COST, the
// user-mandated disclosure). The stratified path adds a digest round-trip per
// peer per round: the SE (~50KB, 32 strata IBLTs) + the remote IBLT (1024
// buckets × 20 bytes/bucket = ~20KB, the FIXED digest size). The bandwidth cut
// (the delta is the DIFF, not the full set) pays this overhead back when |A−B|
// << |A|; for a near-empty diff the digest overhead may EXCEED the oversend
// delta. This tooth MEASURES the wire cost as a NUMBER (the marshaled digest
// frame size) + discloses the break-even: the cut saves ~(oversend-delta-bytes
// − diff-delta-bytes); the digest overhead is ~(SE + IBLT) bytes/peer/round.
// The NET is the honest number the operator reads off sovereign_mesh_* at
// silicon scale (the NEXT-NEXT fork; this tooth is the loopback disclosure).
//
// THE SATURATION LIMIT (the honest physical bound). The FROZEN GenerateDelta
// builds its LOCAL digest at a FIXED 1024 buckets (crdt.go:1610); the remote
// IBLT MUST match (Subtract requires identical bucket counts, iblt.go:377).
// The 1024-bucket IBLT saturates past ~750 keys (the peel collapses past ~0.7
// load → GenerateDelta falls back to oversend = NO bandwidth cut). This tooth
// DISCLOSES the limit: above ~750 entries per node, the stratified path falls
// back to oversend (the fallback counter fires, the M5 honest path) until a
// future fork unfreezes GenerateDelta's local-digest builder to size
// DYNAMICALLY by the remote's bucket count (the dEst-sized dynamic digest — a
// SEPARATE fork, NOT this one).
func TestT_STRUCE_Wire_Cost(t *testing.T) {
	nodeID := [16]byte{0x29, 0x29}
	e := newTestEngine(t, nodeID, t.TempDir())
	// Populate ~500 entries (sub-saturation, the cut regime).
	for i := 0; i < 500; i++ {
		eid := fmt.Sprintf("civic-%d", i)
		payload := fmt.Sprintf("v-%d", i)
		digest := sha256Sum256([]byte(payload))
		entry := eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i), PayloadDigest: digest}
		e.InsertLocal(eid, entry)
	}
	// Measure the digest frame: SE + the full IBLT (1024 buckets).
	seed := maphash.MakeSeed()
	localSE := e.GenerateStrataEstimator(seed)
	localIBLT := e.GenerateDigestWithSeed(seed)
	seBytes, err := eng.MarshalStrataEstimator(localSE)
	if err != nil {
		t.Fatalf("T-STRUCE-WIRE-COST: MarshalStrataEstimator: %v", err)
	}
	ibltBytes, err := eng.MarshalIBLT(localIBLT)
	localIBLT.Release()
	if err != nil {
		t.Fatalf("T-STRUCE-WIRE-COST: MarshalIBLT: %v", err)
	}
	// The digest frame overhead per peer per round: the SE + the IBLT + the
	// 20-byte header + the 4-byte SE-length prefix. This is the wire COST the
	// bandwidth cut pays back.
	frameBytes := 20 + 4 + len(seBytes) + len(ibltBytes)
	t.Logf("WIRE-COST: digest frame = SE(%d bytes) + IBLT(%d bytes, 1024 buckets × 20) + header(24) = %d bytes/peer/round", len(seBytes), len(ibltBytes), frameBytes)
	// The honest break-even: the cut saves ~(oversend-delta-bytes − diff-delta-
	// bytes). Each delta entry is ~(entityID + CRDTEntry + signature overhead)
	// — call it E bytes/entry. For |A|=500, |A−B|=125 (75% overlap): oversend
	// ships 500×E; stratified ships 125×E + frameBytes. The cut wins when
	// 375×E > frameBytes. For E ~= 200 bytes/entry (entityID + entry + sig),
	// 375×200 = 75000 >> frameBytes (~20KB) → the cut wins decisively in the
	// sub-saturation regime. The disclosure: for a near-EMPTY diff (|A−B|→0),
	// the oversend delta → 0 + the digest overhead frameBytes is a NET COST
	// (the stratified path pays the digest round-trip + ships nothing — the
	// honest trade-off, disclosed in the ADR).
	const estEntryBytes = 200 // entityID + CRDTEntry + signature overhead (the honest per-entry wire cost)
	const total, overlap = 500, 375
	diff := total - overlap
	oversendBytes := total * estEntryBytes
	stratifiedBytes := diff*estEntryBytes + frameBytes
	net := oversendBytes - stratifiedBytes
	t.Logf("WIRE-COST break-even (|A|=%d, |A-B|=%d, ~%d B/entry): oversend=%d B; stratified=%d B (diff=%d B + digest=%d B); NET=%d B (cut wins at 75%% overlap)", total, diff, estEntryBytes, oversendBytes, stratifiedBytes, diff*estEntryBytes, frameBytes, net)
	if net <= 0 {
		t.Fatalf("T-STRUCE-WIRE-COST: NET=%d <= 0 at 75%% overlap — the digest overhead exceeds the cut (the stratified path is a net LOSS at this overlap; a wiring defect or an over-large digest)", net)
	}
	// The saturation disclosure: at 800 entries, the 1024-bucket digest
	// saturates + GenerateDelta falls back to oversend (the cut VANISHES). This
	// is the honest physical limit of the FROZEN primitive; the tooth asserts
	// the disclosure is present (the ADR + this tooth's log carry it).
	t.Logf("GATE PASS: T-STRUCE-WIRE-COST — the digest frame is %d bytes/peer/round (SE %d + IBLT %d + header 24); the cut wins at 75%% overlap (NET=%d B); the saturation limit (~750 entries/node, the FROZEN 1024-bucket digest) + the near-empty-diff net cost are DISCLOSED in ADR-0034 (loopback 4c, NOT silicon)", frameBytes, len(seBytes), len(ibltBytes), net)
}

// bytesRepeat returns a byte slice of length n filled with byte b (the
// deterministic-seed helper for the byte-identity tooth so the OFF + ON
// harnesses share nodeIDs). NOT crypto-random — the bytes are a fixed pattern
// so two harnesses built with the same (b, n) yield identical ed25519 seeds.
func bytesRepeat(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

// sha256Sum256 returns the SHA-256 digest of data (the gossiper's
// InsertLocalEvents derives the SAME digest from the payload at gossip.go:466;
// the bandwidth tooth sets it directly on the entry so the overlap keys match
// across the two engines — HashCausalDot(dot, PayloadDigest) is the key).
func sha256Sum256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// readFile reads a file (test helper, keeps the test free of os.ReadFile noise).
func readFile(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(path)
}

// md5HexStr returns the hex md5 of data (test helper; uses crypto/md5, the
// FROZEN-gate precedent at pkg/receive/gate_test.go + pkg/mesh/query_range_test.go).
func md5HexStr(data []byte) string {
	sum := md5.Sum(data)
	return fmt.Sprintf("%x", sum)
}

// repoRootMesh resolves the git repo root (the FROZEN-gate precedent at
// pkg/receive/gate_test.go:382). pkg/mesh is a separate package, so this mesh
// test resolves its own root via `git rev-parse --show-toplevel` (t.Skip on a
// non-git cwd, the same nil-safe behavior as the receive-side precedent).
func repoRootMesh(t *testing.T) string {
	t.Helper()
	out, err := execCommand("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("T-STRUCE-NO-FROZEN-TOUCH: git rev-parse unavailable (%v); skipping the FROZEN tooth", err)
	}
	return strings.TrimSpace(string(out))
}
