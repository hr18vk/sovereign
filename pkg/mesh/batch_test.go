// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Batched-transport correctness tests.
//
// For the same 1,000 self-originated events, the batched and per-frame paths
// must converge to identical Merkle roots. BuildCRDTDeltaBatch stamps the same
// 12 contract fields as BuildCRDTDeltaEvent, and CRDT Join is idempotent, so
// batching changes transport and signature costs without changing engine state.
//
// The tests run in process over loopback TLS on 127.0.0.1. They check
// convergence and cross-path determinism, not multi-machine latency. The
// separate benchmark in pkg/receive/batch_bench_test.go measures ns/delta.
package mesh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// batchMesh is a fully wired two-node mesh parameterized by A's batch size.
// TestBatchedConverge_100PerBatch builds it once with batches of 100 and once
// with per-frame shipping, then compares the converged Merkle roots.
type batchMesh struct {
	engineA *eng.DeltaCRDTEngine
	engineB *eng.DeltaCRDTEngine
	gA      *Gossiper
	gB      *Gossiper
	psA     *PeerSet
	psB     *PeerSet
	recvA   *receive.Receiver
	recvB   *receive.Receiver
	lnA     interface{ Close() error }
	lnB     interface{ Close() error }
	cancel  context.CancelFunc
}

// newBatchMesh builds a two-node loopback TLS mesh. The fixture creates a
// development CA, identities, engines, cross-registered public keys, listeners,
// PeerSets, and Gossipers as in partition_test.go. A dials B, and both accept
// loops register their inbound peers. A uses batchSize; B's sender remains
// per-frame. The receiver dispatches on wire magic, so B accepts A's batches
// regardless of its own batch size.
func newBatchMesh(t *testing.T, batchSize int, identA, identB *NodeIdentity) *batchMesh {
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
	if err := dirB.Register(identA.NodeID, identA.Pub); err != nil {
		t.Fatalf("Register A in B: %v", err)
	}
	if err := dirA.Register(identB.NodeID, identB.Pub); err != nil {
		t.Fatalf("Register B in A: %v", err)
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
	addrB := lnB.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	psA := NewPeerSet(trA, recvA, identA, engineA)
	psB := NewPeerSet(trB, recvB, identB, engineB)
	// The PeerSet-threaded accept loops were moved below the PeerSet
	// construction (the construction-order reorder); nil digester stays (the
	// batch dispatch is the receive-side magic route; ADR-0068).
	go runAcceptLoopWithPeerSet(ctx, lnA, recvA, nil, &wg, psA)
	go runAcceptLoopWithPeerSet(ctx, lnB, recvB, nil, &wg, psB)
	gA := NewGossiper(psA, identA, engineA, dirA)
	gB := NewGossiper(psB, identB, engineB, dirB)
	_ = gA.RegisterPeer(identB.NodeID, identB.Pub)
	_ = gB.RegisterPeer(identA.NodeID, identA.Pub)
	// A is the batched sender; B stays per-frame (the receiver dispatches on the
	// wire magic, so B accepts A's batches regardless of B's own batch size).
	gA.SetBatchSize(batchSize)

	// One-way dial (the Fix-1 shape — see the stratified anti-entropy gate
	// (ADR-0034): the declined half's digest/announce death class) plus the
	// verify-settle before any negative-control test drives (the commit-window
	// receive premise raced the handshake).
	if err := psA.Dial(ctx, addrB, "localhost", identB.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	asyncWait(t, psA, identB.NodeID)
	asyncWait(t, psB, identA.NodeID) // B's ACCEPT-side install
	awaitVerified(t, psA, identB.NodeID)
	awaitVerified(t, psB, identA.NodeID)

	return &batchMesh{
		engineA: engineA, engineB: engineB,
		gA: gA, gB: gB, psA: psA, psB: psB,
		recvA: recvA, recvB: recvB,
		lnA: lnA, lnB: lnB, cancel: cancel,
	}
}

// close tears down the mesh (cancel the accept loops + close the listeners).
func (m *batchMesh) close() {
	m.cancel()
	_ = m.lnA.Close()
	_ = m.lnB.Close()
}

// injectSelfOriginated inserts N events on A only (self-originated — the
// workload batching serves) and returns. The events use deterministic
// (entityID, payload, entry) triples so two meshes injected with the same N
// converge to byte-identical state (the cross-path determinism test).
func (m *batchMesh) injectSelfOriginated(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		eid := fmt.Sprintf("civic-batch-%d", i)
		payload := fmt.Sprintf("value-batch-%d", i)
		entry := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		}
		m.gA.InsertLocalEvents(eid, payload, entry)
	}
}

// sweepUntilConverged runs concurrent AntiEntropySweep rounds on both
// gossipers until their Merkle roots match or maxRounds is exhausted. It
// returns the root, round count, and convergence result.
func (m *batchMesh) sweepUntilConverged(ctx context.Context, t *testing.T, maxRounds int) ([32]byte, int, bool) {
	t.Helper()
	tick := 20 * time.Millisecond
	for round := 0; round < maxRounds; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); m.gA.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); m.gB.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
		time.Sleep(tick)
		ra := m.engineA.MerkleRootFromShards()
		rb := m.engineB.MerkleRootFromShards()
		if ra == rb {
			return ra, round + 1, true
		}
	}
	ra := m.engineA.MerkleRootFromShards()
	rb := m.engineB.MerkleRootFromShards()
	t.Logf("did not converge: rootA=%x rootB=%x", ra, rb)
	return ra, maxRounds, false
}

// TestBatchedConverge_100PerBatch ships 1,000 self-originated events as ten
// batches of 100, then repeats the shipment one frame at a time using the same
// identities. Both paths must converge, B must hold all 1,000 entries, and the
// two Merkle roots must match. Batch application is atomic on integrity errors;
// the cardinality check catches partial application as well as lost events.
// This is an in-process correctness check, not a multi-machine performance
// measurement.
func TestBatchedConverge_100PerBatch(t *testing.T) {
	const total = 1000
	const maxRounds = 20

	// Shared node identities: the cross-path determinism test requires the batched
	// and per-frame meshes to use the same A/B identities, so the dots the two
	// engines mint are byte-identical and the converged MerkleRoots are comparable.
	// Fresh seeds per test run (the assertions are over root equality across paths,
	// not over specific key material).
	seedA := make([]byte, ed25519.SeedSize)
	seedB := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seedA); err != nil {
		t.Fatalf("rand seedA: %v", err)
	}
	if _, err := rand.Read(seedB); err != nil {
		t.Fatalf("rand seedB: %v", err)
	}
	identA, err := NewNodeIdentity(seedA)
	if err != nil {
		t.Fatalf("NewNodeIdentity A: %v", err)
	}
	identB, err := NewNodeIdentity(seedB)
	if err != nil {
		t.Fatalf("NewNodeIdentity B: %v", err)
	}

	// Batched path: A ships 1,000 events as ten batches of 100.
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	mBatch := newBatchMesh(t, 100, identA, identB)
	defer mBatch.close()
	mBatch.injectSelfOriginated(t, total)
	batchRoot, batchRounds, batchConverged := mBatch.sweepUntilConverged(ctxA, t, maxRounds)
	if !batchConverged {
		t.Fatalf("batched path did not converge in %d rounds (root=%x)", maxRounds, batchRoot)
	}
	batchEntriesB := batchCardinality(t, mBatch.engineB, total)
	if batchEntriesB != total {
		t.Fatalf("batched path: B holds %d entries, want %d; batch application was partial or events were lost", batchEntriesB, total)
	}
	t.Logf("batched path: converged in %d rounds, B holds %d/%d entries, root=%x", batchRounds, batchEntriesB, total, batchRoot)

	// Per-frame path: A ships the same events one frame at a time.
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	mFrame := newBatchMesh(t, 1, identA, identB) // batch=1 selects the per-frame shipDelta path
	defer mFrame.close()
	mFrame.injectSelfOriginated(t, total)
	frameRoot, frameRounds, frameConverged := mFrame.sweepUntilConverged(ctxB, t, maxRounds)
	if !frameConverged {
		t.Fatalf("per-frame path did not converge in %d rounds (root=%x)", maxRounds, frameRoot)
	}
	frameEntriesB := batchCardinality(t, mFrame.engineB, total)
	if frameEntriesB != total {
		t.Fatalf("per-frame path: B holds %d entries, want %d", frameEntriesB, total)
	}
	t.Logf("per-frame path: converged in %d rounds, B holds %d/%d entries, root=%x", frameRounds, frameEntriesB, total, frameRoot)

	// The batched and per-frame paths must converge to byte-identical state.
	if batchRoot != frameRoot {
		t.Fatalf("batched root %x != per-frame root %x; batching changed engine state", batchRoot, frameRoot)
	}
	t.Logf("batched and per-frame paths converged to root %x", batchRoot)
	t.Logf("in-process loopback correctness check; not a multi-machine performance measurement")
}

// batchCardinality counts the civic-batch-N keys with at least one entry,
// using PointGet without constructing a merged state view.
func batchCardinality(t *testing.T, e *eng.DeltaCRDTEngine, n int) int {
	t.Helper()
	count := 0
	for i := 0; i < n; i++ {
		if got := e.PointGet(fmt.Sprintf("civic-batch-%d", i)); len(got) > 0 {
			count++
		}
	}
	return count
}

// TestBatchRejectTamperedWire flips one byte in a signed batch wire and
// requires HandleBatchFrame to return DropVerify without changing engine
// state. Signature verification rejects the batch before
// ApplyCRDTDeltaBatch can join any event.
//
// A valid-batch case first applies the same events to a fresh sink and
// requires its root to change. The events are stamped on a separate source
// engine; applying them to that source would be an idempotent no-op and could
// not establish that the valid batch actually joined.
func TestBatchRejectTamperedWire(t *testing.T) {
	// Build five self-originated events directly to exercise receiver
	// verification and application without a mesh.
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand seed: %v", err)
	}
	ident, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}

	// The source engine mints the authoritative DotNodeID, DotCounter, and
	// OriginNodeID and stores the PayloadDigest carried by the wire. The batch
	// is applied to separate sink engines, not to this source.
	sourceEngine := newTestEngine(t, ident.NodeID, t.TempDir())
	events := make([]BuiltEvent, 5)
	for i := 0; i < 5; i++ {
		eid := fmt.Sprintf("civic-tamper-%d", i)
		payload := fmt.Sprintf("value-tamper-%d", i)
		entry := eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + i),
			H3Index:    uint64(i),
		}
		stamped := stampAndInsert(t, sourceEngine, eid, payload, entry)
		events[i] = BuiltEvent{EntityID: eid, Payload: payload, Entry: stamped}
	}
	batchWire, err := BuildCRDTDeltaBatch(events)
	if err != nil {
		t.Fatalf("BuildCRDTDeltaBatch: %v", err)
	}
	sig, err := identitySignForTest(t, ident.Seed, batchWire)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], sig)

	// Apply a valid batch to a fresh sink and require a real state change.
	validSink := newTestEngine(t, ident.NodeID, filepath.Join(t.TempDir(), "valid"))
	dirH := identity.NewDirectory()
	if err := dirH.Register(ident.NodeID, ident.Pub); err != nil {
		t.Fatalf("Register first: %v", err)
	}
	bucketH := admission.NewPeerBucket()
	capH := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), validSink)
	recvH := receive.NewReceiver(bucketH, capH, clock.NewSystemClock(), dirH, validSink, 50_000_000)
	validFrame := attribution.MarshalBatchEnvelope(ident.NodeID, sigArr, 1, uint16(len(events)), batchWire)

	rootBefore := validSink.State().MerkleRoot()
	verdict := recvH.HandleBatchFrame(validFrame)
	if verdict.Verdict != receive.Accept {
		t.Fatalf("first batch: got %s, want Accept (reason: %v)", verdict.Verdict, verdict.Reason)
	}
	rootAfterValid := validSink.State().MerkleRoot()
	if rootAfterValid == rootBefore {
		t.Fatalf("valid batch did not change the fresh sink root; five deltas should have joined")
	}
	t.Logf("valid batch accepted; five deltas joined on a fresh sink")

	// Flip one byte after the envelope header and apply the batch to another
	// fresh sink. Verification must reject it before any join.
	tamperedSink := newTestEngine(t, ident.NodeID, filepath.Join(t.TempDir(), "tamper"))
	dirT := identity.NewDirectory()
	if err := dirT.Register(ident.NodeID, ident.Pub); err != nil {
		t.Fatalf("Register tamper: %v", err)
	}
	bucketT := admission.NewPeerBucket()
	capT := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), tamperedSink)
	recvT := receive.NewReceiver(bucketT, capT, clock.NewSystemClock(), dirT, tamperedSink, 50_000_000)
	tamperedFrame := attribution.MarshalBatchEnvelope(ident.NodeID, sigArr, 2, uint16(len(events)), batchWire)
	tamperedFrame[attribution.BatchEnvelopeHeaderLen+10] ^= 0x01

	rootBefore2 := tamperedSink.State().MerkleRoot()
	verdict2 := recvT.HandleBatchFrame(tamperedFrame)
	if verdict2.Verdict != receive.DropVerify {
		t.Fatalf("tampered batch: got %s, want DropVerify", verdict2.Verdict)
	}
	rootAfter2 := tamperedSink.State().MerkleRoot()
	if rootAfter2 != rootBefore2 {
		t.Fatalf("tampered batch changed State() (before=%x after=%x); no deltas should join after verification fails", rootBefore2, rootAfter2)
	}
	t.Logf("tampered batch returned DropVerify and left State() unchanged")
}

// TestBatchRateGateCountsOnce submits batches with increasing originSeq until
// the per-origin budget returns DropRate. Each HandleBatchFrame call invokes
// bucket.Accept once and drains by the originSeq delta, not once per event.
func TestBatchRateGateCountsOnce(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand seed: %v", err)
	}
	ident, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	engine := newTestEngine(t, ident.NodeID, t.TempDir())
	dir := identity.NewDirectory()
	if err := dir.Register(ident.NodeID, ident.Pub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	bucket := admission.NewPeerBucket()
	capGate := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engine)
	recv := receive.NewReceiver(bucket, capGate, clock.NewSystemClock(), dir, engine, 50_000_000)

	// Build a batch of 50 self-originated events.
	const N = 50
	events := make([]BuiltEvent, N)
	for i := 0; i < N; i++ {
		eid := fmt.Sprintf("civic-rate-%d", i)
		payload := fmt.Sprintf("value-rate-%d", i)
		entry := eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)}
		stamped := stampAndInsert(t, engine, eid, payload, entry)
		events[i] = BuiltEvent{EntityID: eid, Payload: payload, Entry: stamped}
	}
	batchWire, err := BuildCRDTDeltaBatch(events)
	if err != nil {
		t.Fatalf("BuildCRDTDeltaBatch: %v", err)
	}
	sig, err := identitySignForTest(t, ident.Seed, batchWire)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var sigArr [attribution.OriginSigSize]byte
	copy(sigArr[:], sig)

	// Increasing originSeq by a large step drains the bucket on
	// originSeq-lastOriginSeq. The uint64 sequence avoids the uint16 wrap of
	// BatchCount. The first submission creates the bucket; later submissions
	// each drain by one step, regardless of the number of events in the batch.
	//
	// Budget returns zero before a peer's bucket exists, so the baseline is
	// captured after the first submission rather than before it. The expected
	// drain below covers accepted submissions after that baseline. An
	// over-budget drop does not zero the bucket, allowing later small sequence
	// advances after a partition.
	const step = uint64(1) << 18 // about 256K token units per submission
	var rateKey [32]byte
	copy(rateKey[:16], ident.NodeID[:])
	var budgetBefore uint64
	dropped := false
	dropAttempt := -1
	var seq uint64
	for attempt := 0; attempt < 100; attempt++ {
		seq += step // monotonically increasing originSeq without uint64 wrap
		risingFrame := attribution.MarshalBatchEnvelope(ident.NodeID, sigArr, seq, uint16(N), batchWire)
		v := recv.HandleBatchFrame(risingFrame)
		if attempt == 0 {
			// The first frame has created the bucket, so this is the baseline for
			// subsequent accepted submissions.
			budgetBefore = bucket.Budget(rateKey[:])
		}
		if v.Verdict == receive.DropRate {
			dropped = true
			dropAttempt = attempt
			t.Logf("rate gate dropped batch at attempt %d (originSeq=%d) — bucket decremented once per batch on the origin's monotonic sequence", attempt, seq)
			break
		}
	}
	if !dropped {
		t.Fatalf("rate gate never dropped after 100 submissions — the per-origin budget was not decremented (the rate gate is not wired, or originSeq is not the drain counter)")
	}
	// The measured drain covers accepted submissions after the baseline. It must
	// equal one originSeq step per accepted batch, not N steps. An over-budget
	// submission is not charged, so it is excluded from expectedDrain.
	budgetAfter := bucket.Budget(rateKey[:])
	expectedDrain := uint64(dropAttempt-1) * step
	t.Logf("budget: before=%d after=%d drain=%d (dropAttempt=%d, step=%d, N=%d); expected drain=(dropAttempt-1)*step",
		budgetBefore, budgetAfter, budgetBefore-budgetAfter, dropAttempt, step, N)
	if budgetBefore-budgetAfter != expectedDrain && budgetAfter != 0 {
		t.Fatalf("budget drain=%d, expected %d: one originSeq step per accepted batch, not one per event", budgetBefore-budgetAfter, expectedDrain)
	}
	t.Logf("rate gate admitted once per batch on originSeq, not per event; dropped at attempt %d", dropAttempt)
}

// identitySignForTest signs a batch directly without running a Gossiper sweep.
func identitySignForTest(t *testing.T, seed, msg []byte) ([]byte, error) {
	t.Helper()
	return identity.SignCRDTFrame(seed, msg)
}

// stampAndInsert sets PayloadDigest to SHA-256(payload) before InsertLocal so
// the engine stores it and ReconstructEntry can cross-validate it. It returns
// the entry with the engine's authoritative DotNodeID, DotCounter, and
// OriginNodeID for inclusion in the batch wire.
func stampAndInsert(t *testing.T, engine *eng.DeltaCRDTEngine, entityID, payload string, entry eng.CRDTEntry) eng.CRDTEntry {
	t.Helper()
	dgst := sha256.Sum256([]byte(payload))
	entry.PayloadDigest = dgst
	engine.InsertLocal(entityID, entry)
	stamped := engine.PointGet(entityID) // PointGet per key — the merged-view build retired
	if len(stamped) == 0 {
		t.Fatalf("InsertLocal did not produce an entry for %s", entityID)
	}
	return stamped[len(stamped)-1]
}
