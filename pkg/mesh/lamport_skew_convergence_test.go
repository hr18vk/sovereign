// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests exercise Lamport-skew admission and convergence on the default
// per-entry and batched send paths, with a reduced-slack negative control.
//
// HandleFrame and HandleBatchFrame return refusal errors that both dispatch
// sites discard, so a counting frameSink passed to NewPeerSet records them.
// These tests use the pkg/mesh loopback path because the internal/chaos
// VirtualNet mailbox bypasses PeerSet, Dial, Accept, Publish, and the receiver.
//
// Each partition scenario mints before connecting the nodes. A's unchanged
// Lamport clock, empty PointGet results, and zero sink verdicts demonstrate that
// no frames crossed before the connection was established.
package mesh

import (
	"context"
	"errors"
	"fmt"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// EclipseSink is a counting frameSink decorator. It wraps the real
// *receive.Receiver and classifies every verdict inside DispatchFrame before
// the caller discards it. No counter or log site exists on the loopback path
// for the refusal — it is a returned error that both dispatch sites discard.
// The skew class is typed (errors.As to *eng.WireIntegrityError with
// Kind == eng.WireIntegrityLamportSkewPoisoning); the Directory-miss and
// signature-fail classes are matched on stable reason strings.
type EclipseSink struct {
	recv          frameSink // the real *receive.Receiver
	skewRefusals  atomic.Uint64
	directoryMiss atomic.Uint64
	sigFail       atomic.Uint64
	dropVerify    atomic.Uint64
	accepts       atomic.Uint64
	total         atomic.Uint64

	// The arrival dot sequence is the ship-order witness, recorded in
	// HandleFrame before the receiver's verdict. Refused frames are recorded
	// too: the sequence is the sender's ship order, verdict-independent. The
	// skew-refusal count varies per run (delta-walk order and the
	// time-dependent rate-envelope term in MaxAcceptableDotCounter); the
	// sequence is deterministic on one connection and is what the
	// negative-control order test asserts on.
	arrivalMu   sync.Mutex
	arrivalDots []uint64
}

func newEclipseSink(r *receive.Receiver) *EclipseSink {
	return &EclipseSink{recv: r}
}

func (s *EclipseSink) classify(v receive.AcceptVerdict) receive.AcceptVerdict {
	s.total.Add(1)
	switch v.Verdict {
	case receive.Accept:
		s.accepts.Add(1)
	case receive.DropVerify:
		s.dropVerify.Add(1)
		var wie *eng.WireIntegrityError
		if errors.As(v.Reason, &wie) && wie.Kind == eng.WireIntegrityLamportSkewPoisoning {
			s.skewRefusals.Add(1)
		} else {
			msg := ""
			if v.Reason != nil {
				msg = v.Reason.Error()
			}
			switch {
			case strings.Contains(msg, "identity Directory miss"):
				s.directoryMiss.Add(1)
			case strings.Contains(msg, "signature verification failed"):
				s.sigFail.Add(1)
			}
		}
	}
	return v
}

func (s *EclipseSink) HandleFrame(b []byte) receive.AcceptVerdict {
	// Record the arrival dot (the ship-order witness) from the raw frame's
	// header mirror before the receiver classifies it. Batch frames are not
	// tapped (the per-frame path is the order axis; the batched path has
	// its own guards).
	if env, err := attribution.UnmarshalRelayEnvelope(b); err == nil {
		s.arrivalMu.Lock()
		s.arrivalDots = append(s.arrivalDots, env.DotCounter())
		s.arrivalMu.Unlock()
	}
	return s.classify(s.recv.HandleFrame(b))
}

func (s *EclipseSink) HandleBatchFrame(b []byte) receive.AcceptVerdict {
	return s.classify(s.recv.HandleBatchFrame(b))
}

func (s *EclipseSink) HandleHybridFrame(b []byte) receive.AcceptVerdict {
	return s.classify(s.recv.HandleHybridFrame(b))
}

// EclipseNode assembles an identity, engine, Directory, receiver wrapped in a
// counting sink, TLS transport, listener, PeerSet, and Gossiper. Construction
// does not dial any peer, so entries minted before eclipseWire cannot cross the
// partition. Stratified anti-entropy enables DeliverDigest; the skew tests leave
// it disabled and use the default oversend path.
type EclipseNode struct {
	ident  *NodeIdentity
	engine *eng.DeltaCRDTEngine
	dir    *identity.Directory
	sink   *EclipseSink
	recv   *receive.Receiver // the raw receiver — the hybrid-verify arm (SetHybridVerify) is a Receiver method the sink does not delegate
	tr     *transport.TLSConnections
	ln     net.Listener
	ps     *PeerSet
	g      *Gossiper
	addr   string
}

func newEclipseNode(t *testing.T, ca *crypto.MeshCA, caPath, root, name string, seed byte, stratified, hybrid bool) *EclipseNode {
	t.Helper()
	seedBuf := make([]byte, ed25519.SeedSize)
	for i := range seedBuf {
		seedBuf[i] = seed
	}
	var ident *NodeIdentity
	var err error
	if hybrid {
		// NewNodeIdentityHybrid derives the ML-DSA-65 keypair from the
		// same seed — the hybrid-sign capable owner (the SetHybridSign
		// guard requires PQPriv != nil).
		ident, err = NewNodeIdentityHybrid(seedBuf)
	} else {
		ident, err = NewNodeIdentity(seedBuf)
	}
	if err != nil {
		t.Fatalf("%s: NewNodeIdentity: %v", name, err)
	}
	dataDir := filepath.Join(root, "data-"+name)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("%s: mkdir: %v", name, err)
	}
	// eng.DataDir is a package-global captured at construction; set it immediately
	// before each sequential construction so per-node Lamport persist files never
	// collide.
	eng.DataDir = dataDir
	engine, err := eng.NewDeltaCRDTEngine(ident.NodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("%s: NewDeltaCRDTEngine: %v", name, err)
	}
	// No t.Cleanup(e.Close) — serve-conn goroutines outlive the test function by
	// microseconds; a cleanup Close would munmap the arena under in-flight
	// Joins. Deliberate, bounded leak.
	d := identity.NewDirectory()
	leaf, err := ca.IssueLeaf(identHex(ident.NodeID))
	if err != nil {
		t.Fatalf("%s: IssueLeaf: %v", name, err)
	}
	certPath, keyPath, err := leaf.WritePEM(filepath.Join(root, "leaf-"+name))
	if err != nil {
		t.Fatalf("%s: WritePEM: %v", name, err)
	}
	tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("%s: NewTLSTransport: %v", name, err)
	}
	ln, err := tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("%s: listen: %v", name, err)
	}
	bucket := admission.NewPeerBucket()
	capc := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engine)
	recv := receive.NewReceiver(bucket, capc, clock.NewSystemClock(), d, engine, 50_000_000)
	sink := newEclipseSink(recv)
	ps := NewPeerSet(tr, sink, ident, engine)
	g := NewGossiper(ps, ident, engine, d)
	// Install the production relay retainers so sweeps can republish inbound
	// foreign frames. recv implements relayHookSink. Per-frame and batch lookups
	// fall back to the other retention layer; the mixed-relay tests cover both
	// directions.
	g.WireRelayHooks(recv)
	if stratified {
		g.SetStratifiedAntiEntropy(true)
	}
	return &EclipseNode{ident: ident, engine: engine, dir: d, sink: sink, recv: recv, tr: tr, ln: ln, ps: ps, g: g, addr: ln.Addr().String()}
}

// eclipseMint inserts payload-retaining dots via Gossiper.InsertLocalEvents
// only (raw engine.InsertLocal orphans the payload — shipDelta's cache miss
// would confound the skew refusal with the retention class).
func eclipseMint(n *EclipseNode, prefix string, count int) {
	for i := 0; i < count; i++ {
		eid := fmt.Sprintf("%s-%05d", prefix, i)
		payload := fmt.Sprintf("%s-payload-%05d", prefix, i)
		n.g.InsertLocalEvents(eid, payload, eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		})
	}
}

// eclipseCount counts minted keys that PointGet can retrieve.
func eclipseCount(n *EclipseNode, prefix string, count int) int {
	present := 0
	for i := 0; i < count; i++ {
		if got := n.engine.PointGet(fmt.Sprintf("%s-%05d", prefix, i)); len(got) > 0 {
			present++
		}
	}
	return present
}

// eclipseDrain waits for the sink's counters to go quiet — driven sweeps ship
// async frames; a poll-until-stable (not a fixed sleep) drains them.
func eclipseDrain(t *testing.T, n *EclipseNode) (total, skew, miss, sig uint64) {
	t.Helper()
	last := n.sink.total.Load()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		cur := n.sink.total.Load()
		if cur == last {
			break
		}
		last = cur
	}
	return n.sink.total.Load(), n.sink.skewRefusals.Load(), n.sink.directoryMiss.Load(), n.sink.sigFail.Load()
}

// eclipseWire is the heal: start both accept loops (runAcceptLoopWithPeerSet
// so inbound peers register), dial both directions, wait for both read loops
// to be live. Until this runs the two nodes have never been connected — that
// is the partition.
func eclipseWire(t *testing.T, ctx context.Context, a, b *EclipseNode) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(2)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)
	go runAcceptLoopWithPeerSet(ctx, b.ln, b.sink, nil, &wg, b.ps)
	if err := a.ps.Dial(ctx, b.addr, "localhost", b.ident.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	if err := b.ps.Dial(ctx, a.addr, "localhost", a.ident.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	asyncWait(t, a.ps, b.ident.NodeID)
	asyncWait(t, b.ps, a.ident.NodeID)
	// Wait for the asynchronous challenge round-trip before driving convergence.
	// A sweep loop can otherwise reach the egress verification gate before the
	// challenge answer arrives.
	awaitVerified(t, a.ps, b.ident.NodeID)
	awaitVerified(t, b.ps, a.ident.NodeID)
}

// eclipseWireUnverified connects both directions and waits for liveness but not
// challenge verification. An edge without Directory entries cannot complete the
// possession proof, so awaiting verification would contradict the test setup.
func eclipseWireUnverified(t *testing.T, ctx context.Context, a, b *EclipseNode) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(2)
	go runAcceptLoopWithPeerSet(ctx, a.ln, a.sink, nil, &wg, a.ps)
	go runAcceptLoopWithPeerSet(ctx, b.ln, b.sink, nil, &wg, b.ps)
	if err := a.ps.Dial(ctx, b.addr, "localhost", b.ident.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	if err := b.ps.Dial(ctx, a.addr, "localhost", a.ident.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	asyncWait(t, a.ps, b.ident.NodeID)
	asyncWait(t, b.ps, a.ident.NodeID)
}

// awaitVerified waits for the peer's asynchronous challenge possession proof.
func awaitVerified(t *testing.T, ps *PeerSet, peerID [16]byte) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ps.egressVerified(peerID) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("peer %x was not challenge-verified within 10s; the handshake did not complete", peerID)
}

// TestSkewConvergenceDefaultPath uses the default per-entry send path because
// the harness never calls SetBatchSize. B mints three times the 1,000-dot
// admission window while disconnected. Ordered delivery must then converge the
// pair within eight driven sweeps without skew refusals and advance A's clock to
// the highest applied dot.
func TestSkewConvergenceDefaultPath(t *testing.T) {
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

	a := newEclipseNode(t, ca, caPath, root, "A", 0xA1, false, false)
	// NewDeltaCRDTEngine starts at counter 1. An unchanged construction value
	// shows that no delta crossed before the nodes connected.
	clockAtBuildA := a.engine.LamportCounter()
	b := newEclipseNode(t, ca, caPath, root, "B", 0xB2, false, false)
	// Register both origin keys so Directory misses cannot be mistaken for skew
	// refusals.
	if err := a.dir.Register(b.ident.NodeID, b.ident.Pub); err != nil {
		t.Fatalf("register B in A: %v", err)
	}
	if err := b.dir.Register(a.ident.NodeID, a.ident.Pub); err != nil {
		t.Fatalf("register A in B: %v", err)
	}

	// B mints before any connection exists; engine and sink observations verify
	// the partition rather than assuming it from the setup.
	const mint = 3000 // 3x the window (MaxAcceptableDotCounter{0,0,60,1000} = 1000)
	eclipseMint(b, "skew-default", mint)
	if got := a.engine.LamportCounter(); got != clockAtBuildA {
		t.Fatalf("partition observation failed: A.LamportCounter=%d moved from construction value %d; a delta crossed before connection", got, clockAtBuildA)
	}
	if got := eclipseCount(a, "skew-default", mint); got != 0 {
		t.Fatalf("partition observation failed: A holds %d of %d minted keys before connection", got, mint)
	}
	if total, _, _, _ := eclipseDrain(t, a); total != 0 {
		t.Fatalf("partition observation failed: A's sink observed %d verdicts before connection, want 0", total)
	}
	if got := b.engine.LamportCounter(); got < uint64(mint) {
		t.Fatalf("mint observation failed: B.LamportCounter=%d, want at least %d", got, mint)
	}

	// Connect the nodes to end the partition.
	eclipseWire(t, ctx, a, b)

	// Drive full anti-entropy sweeps until the roots match, bounded at eight
	// rounds. Merely polling would not make progress, and the larger bound avoids
	// treating delivery latency under -race load as a convergence failure.
	convergedRound := 0
	for round := 1; round <= 8; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
		// Quiesce the receiving sink before the compare so the recorded round
		// measures heal rounds, not delivery lag.
		eclipseDrain(t, a)
		if a.engine.MerkleRootFromShards() == b.engine.MerkleRootFromShards() {
			convergedRound = round
			break
		}
	}
	total, skew, _, _ := eclipseDrain(t, a)
	ra := a.engine.MerkleRootFromShards()
	rb := b.engine.MerkleRootFromShards()
	t.Logf("evidence: driven rounds used=%d (converged=%v): sinkTotal=%d skewRefusals=%d rootA=%x rootB=%x A.clock=%d A.held=%d",
		convergedRound, convergedRound > 0, total, skew, ra, rb, a.engine.LamportCounter(), eclipseCount(a, "skew-default", mint))

	// shipDelta publishes the self-diff in DotCounter order. Frame dot k+1 thus
	// arrives after Join advanced the receiver to k, and the bound
	// k + ceil(rate*horizon) + slack admits each next dot. Clock advancement now
	// occurs during Join rather than before verification, so zero refusals depends
	// on this ordering. The hash-order fault injection provides a negative control.
	if skew > 0 {
		t.Errorf("per-frame path: %d skew refusals; ordered delivery must keep dot k+1 within the window after Join advances to k", skew)
	}
	// Genesis 1 plus 3,000 mints produces dots 2..3001. Join's per-entry
	// AdvanceLamportTo is the only advance source, so A's clock must equal 3001.
	if clockA := a.engine.LamportCounter(); clockA != uint64(mint+1) {
		t.Errorf("A.LamportCounter=%d after the driven rounds, want exactly %d from genesis 1 plus %d mints; Join is the only advance source", clockA, mint+1, mint)
	}
	// Convergence: roots re-equal and both engines hold the full set.
	if ra != rb {
		t.Errorf("roots differ after eight driven rounds, convergedRound=%d (rootA=%x rootB=%x); the per-frame path did not converge", convergedRound, ra, rb)
	}
	if got := eclipseCount(a, "skew-default", mint); got != mint {
		t.Errorf("A holds %d of %d minted keys", got, mint)
	}
	if got := eclipseCount(b, "skew-default", mint); got != mint {
		t.Errorf("B holds %d of %d (its own mints)", got, mint)
	}
}

// TestSkewConvergenceBatchedPath sets DefaultBatchSize. Each batch takes one
// admission snapshot, and its first over-bound element rejects the whole chunk.
// Sending the digest diff in DotCounter order keeps each chunk's maximum within
// clock+envelope+slack as Join advances the receiver. A backlog six times the
// admission window must therefore heal without skew refusals and remain healed
// through three additional sweeps.
func TestSkewConvergenceBatchedPath(t *testing.T) {
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

	a := newEclipseNode(t, ca, caPath, root, "A", 0xA3, false, false)
	// Record the construction clock, initially 1, as the partition baseline.
	clockAtBuildA := a.engine.LamportCounter()
	b := newEclipseNode(t, ca, caPath, root, "B", 0xB4, false, false)
	if err := a.dir.Register(b.ident.NodeID, b.ident.Pub); err != nil {
		t.Fatalf("register B in A: %v", err)
	}
	if err := b.dir.Register(a.ident.NodeID, a.ident.Pub); err != nil {
		t.Fatalf("register A in B: %v", err)
	}
	// The batched ship path (batchSize > 1 routes to
	// shipBatchedDelta; chunks of DefaultBatchSize=100).
	b.g.SetBatchSize(DefaultBatchSize)

	// Mint six times the admission window before connecting. Each 100-element
	// chunk would contain an over-bound element if delivery were unordered.
	const mint = 6000
	eclipseMint(b, "skew-batch", mint)
	if got := a.engine.LamportCounter(); got != clockAtBuildA {
		t.Fatalf("partition observation failed: A.LamportCounter=%d, want construction value %d", got, clockAtBuildA)
	}
	if total, _, _, _ := eclipseDrain(t, a); total != 0 {
		t.Fatalf("partition observation failed: A's sink observed %d verdicts before connection", total)
	}

	eclipseWire(t, ctx, a, b)

	// Capture B's shipped-entry count and A's refusals for the first three
	// driven rounds.
	shippedPerSweep := make([]int, 0, 6)
	for round := 1; round <= 3; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(1)
		go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
		// st is B's sweep state, captured synchronously from this driven
		// round (shippedEntries counts the entries published this sweep);
		// A's sweep runs concurrently behind the WaitGroup. B's sweep is
		// the one under measurement.
		st := b.g.AntiEntropySweep(ctx)
		sweepWG.Wait()
		shippedPerSweep = append(shippedPerSweep, st.shippedEntries)
	}
	total, skew, _, _ := eclipseDrain(t, a)
	ra := a.engine.MerkleRootFromShards()
	rb := b.engine.MerkleRootFromShards()
	t.Logf("batched-path evidence rounds 1-3: sinkTotal=%d skewRefusals=%d shippedPerSweep=%v rootA=%x rootB=%x A.clock=%d",
		total, skew, shippedPerSweep, ra, rb, a.engine.LamportCounter())

	// Ordered chunks stay within the crawl window: each chunk's maximum is at
	// most the previous chunk's Join advance plus the rate envelope and slack.
	// Any refusal indicates incorrect ordering.
	if skew != 0 {
		t.Errorf("ordered batch crawl produced %d skew refusals at six times the admission window; chunk ordering is incorrect", skew)
	}
	// Roots must match within the first three rounds. A later converged round
	// legitimately ships nothing, so the shipped-entry assertions apply to the
	// rounds that still carry state.
	if ra != rb {
		t.Errorf("roots still differ after rounds 1-3 (rootA=%x rootB=%x); the ordered crawl did not heal the backlog", ra, rb)
	}
	// Round one must ship all 60 chunks in dot order. A zero-ship round while
	// state remains would expose a defer window or an orphaned payload cache.
	if len(shippedPerSweep) == 0 {
		t.Errorf("shippedPerSweep is empty; rounds 1-3 recorded no shipped-entry observations")
	} else if shippedPerSweep[0] != mint {
		t.Errorf("round 1 shipped %d of %d entries; the full backlog must ship in the first round", shippedPerSweep[0], mint)
	}
	for i, shipped := range shippedPerSweep {
		if shipped == 0 {
			t.Errorf("sweep %d shipped %d entries while state remained; a zero-ship round indicates stalled delivery", i+1, shipped)
		}
	}
	// Three additional sweeps verify that convergence persists without new
	// refusals or retransmission of stale out-of-window entries.
	skewBefore := a.sink.skewRefusals.Load()
	for round := 4; round <= 6; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
	}
	total6, skew6, _, _ := eclipseDrain(t, a)
	ra6 := a.engine.MerkleRootFromShards()
	rb6 := b.engine.MerkleRootFromShards()
	t.Logf("batched-path evidence rounds 4-6: sinkTotal=%d skewRefusals=%d (delta %d) rootA=%x rootB=%x A.clock=%d",
		total6, skew6, skew6-skewBefore, ra6, rb6, a.engine.LamportCounter())
	// The batch path has no cap.Admit call, so Join's per-entry advance is the
	// only clock source. Genesis 1 plus 6,000 mints must leave A at 6,001.
	if ra6 != rb6 {
		t.Errorf("roots differ after six total driven sweeps (rootA=%x rootB=%x); convergence did not persist", ra6, rb6)
	}
	if d := skew6 - skewBefore; d != 0 {
		t.Errorf("rounds 4-6 added %d skew refusals after convergence; stale entries were retransmitted or the earlier convergence was incomplete", d)
	}
	if clockA := a.engine.LamportCounter(); clockA != uint64(mint)+1 {
		t.Errorf("A.clock=%d after convergence, want %d from genesis 1 plus %d mints and Join's per-entry advance", clockA, uint64(mint)+1, mint)
	}
	if got := eclipseCount(a, "skew-batch", mint); got != mint {
		t.Errorf("A holds %d of %d minted keys after convergence", got, mint)
	}
}

// TestSkewConvergenceUnderBound checks the complementary admission case: a
// 50-entry batch backlog below the 1,000-dot window must converge without any
// skew refusals.
func TestSkewConvergenceUnderBound(t *testing.T) {
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

	a := newEclipseNode(t, ca, caPath, root, "A", 0xA5, false, false)
	// Record the construction clock, initially 1, as the partition baseline.
	clockAtBuildA := a.engine.LamportCounter()
	b := newEclipseNode(t, ca, caPath, root, "B", 0xB6, false, false)
	if err := a.dir.Register(b.ident.NodeID, b.ident.Pub); err != nil {
		t.Fatalf("register B in A: %v", err)
	}
	if err := b.dir.Register(a.ident.NodeID, a.ident.Pub); err != nil {
		t.Fatalf("register A in B: %v", err)
	}
	b.g.SetBatchSize(4) // small chunks: the 50-dot mint spans 13 frames

	const mint = 50 // below the 1,000-dot admission window
	eclipseMint(b, "skew-underbound", mint)
	if got := a.engine.LamportCounter(); got != clockAtBuildA {
		t.Fatalf("partition observation failed: A.LamportCounter=%d, want construction value %d", got, clockAtBuildA)
	}
	eclipseWire(t, ctx, a, b)

	revConverged := 0
	for round := 1; round <= 4; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
		// Same quiesce for the recorded round (the verdict roots are
		// already drain-computed below).
		eclipseDrain(t, a)
		if a.engine.MerkleRootFromShards() == b.engine.MerkleRootFromShards() {
			revConverged = round
			break
		}
	}
	_, skew, _, _ := eclipseDrain(t, a)
	ra := a.engine.MerkleRootFromShards()
	rb := b.engine.MerkleRootFromShards()
	t.Logf("under-bound control: skewRefusals=%d rootA=%x rootB=%x A.held=%d convergedRound=%d",
		skew, ra, rb, eclipseCount(a, "skew-underbound", mint), revConverged)
	if skew != 0 {
		t.Errorf("%d skew refusals for 50 dots with a 1,000-dot bound; the batch path rejected an under-window mint", skew)
	}
	if ra != rb {
		t.Errorf("roots differ after 4 driven rounds (converged=%d) at a sub-window mint (rootA=%x rootB=%x)", revConverged, ra, rb)
	}
	if got := eclipseCount(a, "skew-underbound", mint); got != mint {
		t.Errorf("A holds %d of %d", got, mint)
	}
}

// TestSkewConvergenceSlackLoweredControl sets A's AbsoluteSlack to 2 and sends
// 20 entries in chunks of four. With A's construction clock at 1 and a zero rate
// envelope, the bound is 3, so every chunk contains an over-bound element even
// though the default window would accept the entire mint.
//
// The control runs only when SOVEREIGN_TEST_FAULT_ECLIPSE_SKEW is set. It first
// requires a nonzero refusal count, then deliberately fails with that count so
// the negative-control run records the observed behavior.
func TestSkewConvergenceSlackLoweredControl(t *testing.T) {
	if os.Getenv("SOVEREIGN_TEST_FAULT_ECLIPSE_SKEW") == "" {
		t.Skip("slack-lowered negative control runs only when SOVEREIGN_TEST_FAULT_ECLIPSE_SKEW is set")
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

	a := newEclipseNode(t, ca, caPath, root, "A", 0xA7, false, false)
	// Record the construction clock, initially 1, as the partition baseline.
	clockAtBuildA := a.engine.LamportCounter()
	b := newEclipseNode(t, ca, caPath, root, "B", 0xB8, false, false)
	if err := a.dir.Register(b.ident.NodeID, b.ident.Pub); err != nil {
		t.Fatalf("register B in A: %v", err)
	}
	if err := b.dir.Register(a.ident.NodeID, a.ident.Pub); err != nil {
		t.Fatalf("register A in B: %v", err)
	}
	a.engine.SetLamportAbsoluteSlack(2) // the inject: bound collapses to 0+0+2
	b.g.SetBatchSize(4)

	const mint = 20
	eclipseMint(b, "skew-slack-control", mint)
	if got := a.engine.LamportCounter(); got != clockAtBuildA {
		t.Fatalf("partition observation failed: A.LamportCounter=%d, want construction value %d", got, clockAtBuildA)
	}
	eclipseWire(t, ctx, a, b)

	for round := 1; round <= 2; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
	}
	_, skew, _, _ := eclipseDrain(t, a)
	if skew == 0 {
		t.Fatalf("slack-lowered control observed zero refusals with slack=2 and 20 batched entries; the control did not exercise the refusal mechanism")
	}
	t.Fatalf("slack-lowered control (expected failure): %d refusals with slack=2 and 20 batched entries; bound is A.clock plus zero rate envelope plus slack 2 (rootA=%x rootB=%x A.clock=%d)",
		skew, a.engine.MerkleRootFromShards(), b.engine.MerkleRootFromShards(), a.engine.LamportCounter())
}
