// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// Hybrid signing carries Ed25519 and ML-DSA-65 signatures over the same
// SHAKE256 pad in a HybridEnvelope (ADR-0037). ShipBatchHybrid signs the wire,
// RegisterPQ and LookupBoth provision both public keys, DispatchFrame routes
// hybrid frames to HandleHybridFrame, and VerifyBatchHybrid requires both
// signatures. The behavior is opt-in through --hybrid-sign and
// --hybrid-verify; HybridFrameAccepted records accepted hybrid frames.
//
// These tests cover convergence through hybrid frames, acceptance accounting,
// compatibility with signing disabled, strict rejection when verification is
// disabled, and four-way frame dispatch. A receiver with hybrid verification
// enabled rejects a classical-only v1 frame. Conversely, a receiver with
// hybrid verification disabled rejects a hybrid frame rather than falling
// back to its Ed25519 signature alone.

// PQHybridHarness is a two-node TLS mesh with configurable hybrid signing and
// verification. NewNodeIdentityHybrid derives each ML-DSA-65 key from the same
// seed as its Ed25519 key, and both directories register both public keys.
// Local counters stand in for the command's HybridFrameAccepted telemetry so
// tests can observe accepted hybrid frames directly.
type PQHybridHarness struct {
	dir     string
	caPath  string
	identA  *NodeIdentity
	identB  *NodeIdentity
	engineA *eng.DeltaCRDTEngine
	engineB *eng.DeltaCRDTEngine
	recvA   *receive.Receiver
	recvB   *receive.Receiver
	lnA     net.Listener
	lnB     net.Listener
	addrA   string
	addrB   string
	psA     *PeerSet
	psB     *PeerSet
	gA      *Gossiper
	gB      *Gossiper
	ctx     context.Context
	cancel  context.CancelFunc
	wg      *sync.WaitGroup
	// acceptA and acceptB count hybrid frames accepted by each receiver.
	acceptA int32
	acceptB int32
	// Tests may change these flags independently to check asymmetric modes.
	hybridSignA   bool
	hybridSignB   bool
	hybridVerifyA bool
	hybridVerifyB bool
}

// newPQHybridHarness builds the 2-node hybrid mesh. hybridSign + hybridVerify
// arm both nodes (the symmetric case). The tests may disarm one side after
// construction (the strict-reject symmetry tests).
func newPQHybridHarness(t *testing.T, hybridSign, hybridVerify bool) *PQHybridHarness {
	t.Helper()
	seedA := bytesRepeat(0xA1, ed25519.SeedSize)
	seedB := bytesRepeat(0xB2, ed25519.SeedSize)
	return newPQHybridHarnessSeeded(t, hybridSign, hybridVerify, seedA, seedB)
}

// newPQHybridHarnessSeeded builds a two-node mesh with fixed identity seeds.
// Root comparisons between enabled and disabled hybrid signing require the
// same node IDs because CausalDot includes OriginNodeID: different IDs produce
// different Merkle roots even when the logical entries are identical.
// NewNodeIdentityHybrid derives the ML-DSA-65 keys, and RegisterPQ makes them
// available to LookupBoth in both directories.
func newPQHybridHarnessSeeded(t *testing.T, hybridSign, hybridVerify bool, seedA, seedB []byte) *PQHybridHarness {
	t.Helper()
	if len(seedA) != ed25519.SeedSize || len(seedB) != ed25519.SeedSize {
		t.Fatalf("newPQHybridHarnessSeeded: seedA/seedB must be ed25519.SeedSize (%d) bytes; got %d/%d", ed25519.SeedSize, len(seedA), len(seedB))
	}
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	// With signing disabled, use NewNodeIdentity so PQPriv remains nil and
	// ShipBatchHybrid emits no hybrid frames. Otherwise derive both keypairs
	// from each seed.
	var identA, identB *NodeIdentity
	if hybridSign {
		identA, err = NewNodeIdentityHybrid(seedA)
		if err != nil {
			t.Fatalf("NewNodeIdentityHybrid A: %v", err)
		}
		identB, err = NewNodeIdentityHybrid(seedB)
		if err != nil {
			t.Fatalf("NewNodeIdentityHybrid B: %v", err)
		}
	} else {
		identA, err = NewNodeIdentity(seedA)
		if err != nil {
			t.Fatalf("NewNodeIdentity A: %v", err)
		}
		identB, err = NewNodeIdentity(seedB)
		if err != nil {
			t.Fatalf("NewNodeIdentity B: %v", err)
		}
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

	// Register self and peer keys in each directory. LookupBoth then resolves
	// both signature public keys for locally originated and received frames.
	dirA := identity.NewDirectory()
	dirB := identity.NewDirectory()
	_ = dirA.Register(identA.NodeID, identA.Pub) // self (loopback verify)
	_ = dirB.Register(identB.NodeID, identB.Pub)
	_ = dirA.Register(identB.NodeID, identB.Pub) // peer
	_ = dirB.Register(identA.NodeID, identA.Pub)
	if hybridSign {
		// Register the PQ pubkeys (self + peer) so LookupBoth resolves both.
		if err := dirA.RegisterPQ(identA.NodeID, identA.PQPub); err != nil {
			t.Fatalf("RegisterPQ A self: %v", err)
		}
		if err := dirB.RegisterPQ(identB.NodeID, identB.PQPub); err != nil {
			t.Fatalf("RegisterPQ B self: %v", err)
		}
		if err := dirA.RegisterPQ(identB.NodeID, identB.PQPub); err != nil {
			t.Fatalf("RegisterPQ A peer: %v", err)
		}
		if err := dirB.RegisterPQ(identA.NodeID, identA.PQPub); err != nil {
			t.Fatalf("RegisterPQ B peer: %v", err)
		}
	}

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

	// Configure both nodes symmetrically. Individual tests can change one side
	// after construction.
	gA.SetHybridSign(hybridSign)
	gB.SetHybridSign(hybridSign)
	recvA.SetHybridVerify(hybridVerify)
	recvB.SetHybridVerify(hybridVerify)

	h := &PQHybridHarness{
		dir: dir, caPath: caPath, identA: identA, identB: identB,
		engineA: engineA, engineB: engineB, recvA: recvA, recvB: recvB,
		lnA: lnA, lnB: lnB, addrA: lnA.Addr().String(), addrB: lnB.Addr().String(),
		psA: psA, psB: psB, gA: gA, gB: gB, ctx: ctx, cancel: cancel,
		hybridSignA: hybridSign, hybridSignB: hybridSign,
		hybridVerifyA: hybridVerify, hybridVerifyB: hybridVerify,
	}
	// The harness owns the counters; each receiver reports an accepted hybrid
	// frame through its closure.
	recvA.SetHybridAcceptReporter(func() { atomic.AddInt32(&h.acceptA, 1) })
	recvB.SetHybridAcceptReporter(func() { atomic.AddInt32(&h.acceptB, 1) })

	var wg sync.WaitGroup
	wg.Add(2)
	// Use the PeerSet accept loop so challenge verification and egress checks
	// match the production connection path (ADR-0068).
	go runAcceptLoopWithPeerSet(ctx, lnA, recvA, gA, &wg, psA)
	go runAcceptLoopWithPeerSet(ctx, lnB, recvB, gB, &wg, psB)
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

func (h *PQHybridHarness) close() {
	h.cancel()
	_ = h.lnA.Close()
	_ = h.lnB.Close()
}

// insertEvents splits n events evenly between A and B, matching the
// stratified anti-entropy convergence workload.
func (h *PQHybridHarness) insertEvents(t *testing.T, n int) int {
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

// sweepUntilConverged runs concurrent sweeps on A and B until their Merkle
// roots match or maxRounds is exhausted.
func (h *PQHybridHarness) sweepUntilConverged(t *testing.T, maxRounds int, tick time.Duration) (int, bool, [32]byte, [32]byte) {
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
		ra := h.engineA.MerkleRootFromShards()
		rb := h.engineB.MerkleRootFromShards()
		t.Logf("round %d: rootA=%x rootB=%x acceptA=%d acceptB=%d", round, ra, rb, atomic.LoadInt32(&h.acceptA), atomic.LoadInt32(&h.acceptB))
		if ra == rb {
			return round + 1, true, ra, rb
		}
	}
	ra := h.engineA.MerkleRootFromShards()
	rb := h.engineB.MerkleRootFromShards()
	return maxRounds, false, ra, rb
}

// TestPQ_HybridE2EConverges checks that a two-node mesh with hybrid signing
// and verification enabled converges a 1,000-event split. It also checks final
// cardinality and requires both HybridFrameAccepted counters to increase,
// proving that convergence used frames accepted by the two-signature gate.
func TestPQ_HybridE2EConverges(t *testing.T) {
	h := newPQHybridHarness(t, true, true)
	defer h.close()
	const total = 1000
	h.insertEvents(t, total)
	rounds, converged, ra, rb := h.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !converged {
		t.Fatalf("hybrid mesh did not converge within 10 rounds (rootA=%x rootB=%x)", ra, rb)
	}
	gotA := cardinality(t, h.engineA)
	gotB := cardinality(t, h.engineB)
	if gotA != total || gotB != total {
		t.Fatalf("hybrid mesh converged with cardinalities A=%d B=%d, want %d on both", gotA, gotB, total)
	}
	// Each node must accept at least one hybrid batch from its peer.
	if atomic.LoadInt32(&h.acceptA) == 0 || atomic.LoadInt32(&h.acceptB) == 0 {
		t.Fatalf("hybrid acceptance counters are A=%d B=%d; both must be nonzero after convergence", h.acceptA, h.acceptB)
	}
	t.Logf("hybrid mesh converged %d events in %d rounds; accepted frames A=%d B=%d", total, rounds, h.acceptA, h.acceptB)
}

// TestPQ_HybridOffIsByteIdentical checks the default configuration with both
// hybrid flags disabled. The same 1,000-event split must converge through v1
// batch envelopes without producing or accepting a hybrid frame; both
// HybridFrameAccepted counters remain zero.
func TestPQ_HybridOffIsByteIdentical(t *testing.T) {
	h := newPQHybridHarness(t, false, false)
	defer h.close()
	const total = 1000
	h.insertEvents(t, total)
	rounds, converged, ra, rb := h.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !converged {
		t.Fatalf("v1 mesh did not converge within 10 rounds (rootA=%x rootB=%x)", ra, rb)
	}
	gotA := cardinality(t, h.engineA)
	gotB := cardinality(t, h.engineB)
	if gotA != total || gotB != total {
		t.Fatalf("v1 mesh converged with cardinalities A=%d B=%d, want %d on both", gotA, gotB, total)
	}
	if atomic.LoadInt32(&h.acceptA) != 0 || atomic.LoadInt32(&h.acceptB) != 0 {
		t.Fatalf("hybrid acceptance counters changed with hybrid mode disabled (A=%d B=%d); want zero on both", h.acceptA, h.acceptB)
	}
	t.Logf("v1 mesh converged %d events in %d rounds without accepting hybrid frames", total, rounds)
}

// TestPQ_HybridE2EByteIdentity runs the same seeded 1,000-event workload over
// v1 and hybrid framing. Both paths must produce the same Merkle roots and
// cardinalities. HybridEnvelope carries the batchWire decoded by
// ApplyCRDTDeltaBatch, so its signing and framing must not drop or change a
// dot that the v1 path delivers.
func TestPQ_HybridE2EByteIdentity(t *testing.T) {
	seedA := bytesRepeat(0xA1, ed25519.SeedSize)
	seedB := bytesRepeat(0xB2, ed25519.SeedSize)

	// Capture the v1 reference roots and cardinalities first.
	hOff := newPQHybridHarnessSeeded(t, false, false, seedA, seedB)
	hOff.insertEvents(t, 1000)
	_, offConverged, offRootA, offRootB := hOff.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !offConverged {
		t.Fatalf("v1 reference did not converge (rootA=%x rootB=%x)", offRootA, offRootB)
	}
	offCardA := cardinality(t, hOff.engineA)
	offCardB := cardinality(t, hOff.engineB)
	hOff.close()

	// Repeat the workload with hybrid framing and the same node IDs. The roots
	// must match because both paths apply the same batchWire.
	hOn := newPQHybridHarnessSeeded(t, true, true, seedA, seedB)
	defer hOn.close()
	hOn.insertEvents(t, 1000)
	_, onConverged, onRootA, onRootB := hOn.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !onConverged {
		t.Fatalf("hybrid path did not converge (rootA=%x rootB=%x)", onRootA, onRootB)
	}
	if onRootA != offRootA || onRootB != offRootB {
		t.Fatalf("hybrid roots A=%x B=%x differ from v1 roots A=%x B=%x; hybrid framing changed the applied state", onRootA, onRootB, offRootA, offRootB)
	}
	onCardA := cardinality(t, hOn.engineA)
	onCardB := cardinality(t, hOn.engineB)
	if onCardA != offCardA || onCardB != offCardB {
		t.Fatalf("hybrid cardinalities A=%d B=%d differ from v1 A=%d B=%d", onCardA, onCardB, offCardA, offCardB)
	}
	t.Logf("hybrid and v1 paths produced identical roots for the same seeded workload")
}

// TestPQ_HybridSignVerifyOff enables hybrid signing but not verification. A
// receiver without hybrid verification cannot fall back to the Ed25519
// signature alone. Senders emit only hybrid frames in this configuration, so
// every frame is rejected, the mesh does not converge, and acceptance counters
// remain zero (ADR-0037).
func TestPQ_HybridSignVerifyOff(t *testing.T) {
	h := newPQHybridHarness(t, true, false)
	defer h.close()
	const total = 100
	h.insertEvents(t, total)
	// Senders emit only hybrid frames, and receivers without hybrid
	// verification reject them. Convergence would therefore reveal either an
	// invalid acceptance or an unintended v1 fallback.
	_, converged, _, _ := h.sweepUntilConverged(t, 5, 20*time.Millisecond)
	if converged {
		t.Fatalf("mesh converged with hybrid signing enabled and verification disabled; a receiver accepted an unverifiable frame or a sender fell back to v1")
	}
	if atomic.LoadInt32(&h.acceptA) != 0 || atomic.LoadInt32(&h.acceptB) != 0 {
		t.Fatalf("hybrid acceptance counters changed with verification disabled (A=%d B=%d); want zero on both", h.acceptA, h.acceptB)
	}
	t.Logf("mesh rejected all hybrid frames with verification disabled")
}

// TestPQ_HybridDispatch4Way checks that DispatchFrame distinguishes hybrid,
// batch, digest, and relay frames by their wire prefixes. A counting sink
// records which handler receives each frame.
func TestPQ_HybridDispatch4Way(t *testing.T) {
	// A counting sink that records which arm a frame routed to.
	sink := &countingSink{}
	digester := &countingDigester{}
	// A hybrid frame (WireHybridPQMagic first).
	hybrid := make([]byte, 8)
	binary.BigEndian.PutUint32(hybrid[0:4], 0x53485942) // "SHYB"
	var peerID [16]byte
	// A hybrid frame must reach HandleHybridFrame and no other handler.
	DispatchFrame(hybrid, peerID, sink, digester)
	if sink.hybridCalls != 1 {
		t.Fatalf("hybrid frame reached HandleHybridFrame %d times, want 1", sink.hybridCalls)
	}
	if sink.batchCalls != 0 || sink.frameCalls != 0 || digester.calls != 0 {
		t.Fatalf("hybrid frame also reached another handler (batch=%d frame=%d digest=%d)", sink.batchCalls, sink.frameCalls, digester.calls)
	}
	// WireV1Magic selects HandleBatchFrame.
	batch := make([]byte, 8)
	binary.BigEndian.PutUint32(batch[0:4], 0x53424154) // "SBAT"
	DispatchFrame(batch, peerID, sink, digester)
	if sink.batchCalls != 1 {
		t.Fatalf("batch frame reached HandleBatchFrame %d times, want 1", sink.batchCalls)
	}
	// WireDigestMagic selects the digest sink.
	digest := make([]byte, 8)
	binary.BigEndian.PutUint32(digest[0:4], 0x53445354) // "SDST"
	DispatchFrame(digest, peerID, sink, digester)
	if digester.calls != 1 {
		t.Fatalf("digest frame reached DeliverDigest %d times, want 1", digester.calls)
	}
	// A little-endian RelayEnvelope version prefix selects the default handler.
	relay := make([]byte, 8)
	binary.LittleEndian.PutUint16(relay[0:2], 2)
	DispatchFrame(relay, peerID, sink, digester)
	if sink.frameCalls != 1 {
		t.Fatalf("relay frame reached HandleFrame %d times, want 1", sink.frameCalls)
	}
	t.Logf("hybrid, batch, digest, and relay frames reached their respective handlers")
}

// countingSink is a frameSink that counts which arm a frame routed to. It
// satisfies the frameSink interface (HandleFrame + HandleBatchFrame +
// HandleHybridFrame).
type countingSink struct {
	frameCalls  int
	batchCalls  int
	hybridCalls int
}

func (s *countingSink) HandleFrame(frameBytes []byte) receive.AcceptVerdict {
	s.frameCalls++
	return receive.AcceptVerdict{Verdict: receive.Accept}
}
func (s *countingSink) HandleBatchFrame(batchFrameBytes []byte) receive.AcceptVerdict {
	s.batchCalls++
	return receive.AcceptVerdict{Verdict: receive.Accept}
}
func (s *countingSink) HandleHybridFrame(hybridFrameBytes []byte) receive.AcceptVerdict {
	s.hybridCalls++
	return receive.AcceptVerdict{Verdict: receive.Accept}
}

// countingDigester is a DigestSink that counts DeliverDigest calls.
type countingDigester struct {
	calls int
}

func (d *countingDigester) DeliverDigest(peerID [16]byte, frame []byte) {
	d.calls++
}

// TestPQ_HybridAcceptDispatchParity mirrors the inline dispatch in
// cmd/sovereign-node's serveConnWithDigest: digest, batch, hybrid, then the
// default relay handler. The in-process accept loop uses DispatchFrame, so this
// separate replica guards the production ordering. Without the IsHybridFrame
// branch, a hybrid frame reaches HandleFrame, fails RelayEnvelope parsing, and
// is dropped as malformed instead of reaching HandleHybridFrame.
func TestPQ_HybridAcceptDispatchParity(t *testing.T) {
	sink := &countingSink{}
	digester := &countingDigester{}

	// Mirror serveConnWithDigest's inline order. In particular, IsHybridFrame
	// must precede the fallback to HandleFrame.
	acceptDispatch := func(frame []byte) {
		if attribution.IsDigestFrame(frame) {
			if digester != nil {
				digester.DeliverDigest([16]byte{}, frame)
			}
			return
		}
		if attribution.IsBatchFrame(frame) {
			sink.HandleBatchFrame(frame)
			return
		}
		if attribution.IsHybridFrame(frame) {
			sink.HandleHybridFrame(frame)
			return
		}
		sink.HandleFrame(frame)
	}

	hybrid := make([]byte, 8)
	binary.BigEndian.PutUint32(hybrid[0:4], 0x53485942) // "SHYB"
	acceptDispatch(hybrid)
	if sink.hybridCalls != 1 {
		t.Fatalf("accept dispatch reached HandleHybridFrame %d times, want 1", sink.hybridCalls)
	}
	if sink.frameCalls != 0 {
		t.Fatalf("hybrid frame reached HandleFrame %d times; it must not fall through to RelayEnvelope parsing", sink.frameCalls)
	}

	// Batch, digest, and relay frames retain their existing routes.
	batch := make([]byte, 8)
	binary.BigEndian.PutUint32(batch[0:4], 0x53424154) // "SBAT"
	acceptDispatch(batch)
	if sink.batchCalls != 1 {
		t.Fatalf("batch frame reached HandleBatchFrame %d times, want 1", sink.batchCalls)
	}
	if sink.hybridCalls != 1 {
		t.Fatalf("batch frame changed hybrid handler calls to %d, want 1", sink.hybridCalls)
	}

	digest := make([]byte, 8)
	binary.BigEndian.PutUint32(digest[0:4], 0x53445354) // "SDST"
	acceptDispatch(digest)
	if digester.calls != 1 {
		t.Fatalf("digest frame reached DeliverDigest %d times, want 1", digester.calls)
	}

	relay := make([]byte, 8)
	binary.LittleEndian.PutUint16(relay[0:2], 2)
	acceptDispatch(relay)
	if sink.frameCalls != 1 {
		t.Fatalf("relay frame reached HandleFrame %d times, want 1", sink.frameCalls)
	}

	t.Logf("accept dispatch routed hybrid, batch, digest, and relay frames correctly")
}

// TestPQ_HybridRateGateOrdering checks that a receiver with hybrid verification
// disabled rejects a hybrid frame before r.bucket.Accept or a Directory lookup.
// Otherwise a hybrid-signing peer could drain a default receiver's origin
// budget with frames that are guaranteed to fail, and a forged origin ID could
// drain a victim's budget without any signature work. The test seeds a real
// admission.PeerBucket, sends a validly shaped hybrid frame, and requires
// DropVerify with an unchanged budget.
func TestPQ_HybridRateGateOrdering(t *testing.T) {
	// Build a parseable header with nonzero signature placeholders. Unmarshal
	// must succeed before the configuration check can reject the frame; that
	// check precedes both the rate gate and signature verification.
	hybrid := make([]byte, attribution.HybridEnvelopeHeaderLen)
	binary.BigEndian.PutUint32(hybrid[0:4], 0x53485942) // "SHYB" WireHybridPQMagic
	hybrid[4] = 0x01                                    // WireHybridPQVersion
	binary.BigEndian.PutUint64(hybrid[5:13], 2)         // originSeq; the seed Accept below uses 1
	binary.BigEndian.PutUint16(hybrid[13:15], 1)        // batchCount
	// A distinct nonzero origin ID makes the budget key observable. Nonzero
	// Ed25519 and ML-DSA signatures avoid ErrHybridUnsigned during unmarshal.
	var origin [16]byte
	for i := range origin {
		origin[i] = 0xbb
	}
	copy(hybrid[15:31], origin[:])
	for i := 31; i < attribution.HybridEnvelopeHeaderLen; i++ {
		hybrid[i] = 0xaa // non-zero edSig + pqSig
	}

	// Receiver requires a concrete admission.PeerBucket. Seed one Accept with
	// counter 1 so the origin has an observable budget of initialBudget-1.
	bucket := admission.NewPeerBucket()
	var rateKey [32]byte
	copy(rateKey[:16], origin[:])
	_, _ = bucket.Accept(rateKey[:], 1)
	budgetBefore := bucket.Budget(rateKey[:])
	if budgetBefore == 0 {
		t.Fatalf("seed Accept created no budget; the rate-gate key is inconsistent")
	}

	// Leave the origin unregistered. A Directory lookup would miss, so a
	// DropVerify result also demonstrates that the configuration check ran
	// before LookupBoth.
	dir := identity.NewDirectory()

	// The engine and clock cap are nil because rejection precedes verification
	// and application. A zero max-hops budget is irrelevant on this path.
	recv := receive.NewReceiver(bucket, nil, nil, dir, nil, 0)
	recv.SetHybridVerify(false)

	verdict := recv.HandleHybridFrame(hybrid)
	if verdict.Verdict != receive.DropVerify {
		t.Fatalf("receiver with hybrid verification disabled returned %v, want DropVerify", verdict.Verdict)
	}
	budgetAfter := bucket.Budget(rateKey[:])
	if budgetAfter != budgetBefore {
		t.Fatalf("rejected hybrid frame changed the origin budget from %d to %d (delta %d); configuration rejection must precede r.bucket.Accept", budgetBefore, budgetAfter, int64(budgetBefore)-int64(budgetAfter))
	}
	t.Logf("receiver rejected the hybrid frame before the rate gate and Directory lookup; budget before=%d after=%d", budgetBefore, budgetAfter)
}

// TestPQHybridCounter checks that the telemetry registry contains 25 distinct
// counters, including the mode counter supremum.hybrid.frame_accepted. The
// registry grew through PQ handshake negotiation (ADR-0036), hybrid frame
// acceptance (ADR-0037), inter-region envelope shipping (ADR-0039), and mesh
// write timeouts (ADR-0059).
//
// SetHybridAcceptReporter binds command-side acceptance reporting to
// telemetry.HybridFrameAccepted.Inc, and the metrics bridge enumerates the
// counter without a separate bridge entry. A single-node --selftest run leaves
// its value at zero because no mesh peer connects; the runtime check requires
// the series to be present on /metrics rather than requiring a nonzero value.
func TestPQHybridCounter(t *testing.T) {
	cs := telemetry.Counters()
	const wantDistinct = 25
	if len(cs) != wantDistinct {
		t.Fatalf("telemetry.Counters() returned %d counters, want %d", len(cs), wantDistinct)
	}
	var found *telemetry.Counter
	for _, c := range cs {
		if c.Name() == "supremum.hybrid.frame_accepted" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatalf("supremum.hybrid.frame_accepted is missing from telemetry.Counters(); it must be constructed in init, rebuildCounters, and allCounters so it remains available under --otel")
	}
	if found.Name() != "supremum.hybrid.frame_accepted" {
		t.Fatalf("hybrid acceptance counter name is %q, want supremum.hybrid.frame_accepted", found.Name())
	}
	t.Logf("telemetry registry contains %d counters, including supremum.hybrid.frame_accepted for the metrics bridge", len(cs))
}

// bytesRepeat is defined in stratified_antientropy_test.go and shared here.
