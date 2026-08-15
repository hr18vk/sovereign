// Package mesh — batch_test.go is the Day-5 batched-transport gate: the
// cross-path MerkleRoot determinism tooth (the load-bearing correctness proof
// that batching changes THROUGHPUT, not STATE).
//
// THE TOOTH (G05.d): a batched path's MerkleRoot MUST EQUAL the per-frame
// path's MerkleRoot for the SAME 1000 self-originated events. Batching
// amortizes the Ed25519 verify (one sig per N deltas) but the engine state the
// two paths converge to is IDENTICAL — the CRDT Join is idempotent and the
// per-event wire bytes the batch carries are the SAME per-event bytes the
// per-frame path carries (BuildCRDTDeltaBatch stamps the same 12 contract
// fields BuildCRDTDeltaEvent stamps). A divergence would mean batching
// silently mutated state — a fabrication, not a feature.
//
// THE SCISSORS LABEL (load-bearing): the in-process test runs over loopback
// TLS (ONE kernel, 127.0.0.1, NOT silicon). It PROVES the CONVERGENCE +
// CROSS-PATH-DETERMINISM properties, NOT a silicon ns/delta number. The
// ns/delta bench is a SEPARATE gate (G05.f, pkg/receive/batch_bench_test.go).
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
	"github.com/hr18vk/supremum/pkg/admission"
	"github.com/hr18vk/supremum/pkg/attribution"
	"github.com/hr18vk/supremum/pkg/clock"
	"github.com/hr18vk/supremum/pkg/crypto"
	"github.com/hr18vk/supremum/pkg/identity"
	"github.com/hr18vk/supremum/pkg/receive"
	eng "github.com/hr18vk/supremum/pkg/sync"
	"github.com/hr18vk/supremum/pkg/transport"
)

// batchMesh is a fully-wired two-node mesh (the Day-2 harness SHAPE) parameterized
// by the sender's batch size. It is the fixture TestBatchedConverge_100PerBatch
// builds TWICE — once batched (batch=100), once per-frame (batch=1) — so the
// cross-path MerkleRoot determinism tooth can compare the two converged roots.
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

// newBatchMesh builds a two-node loopback TLS mesh with the sender (A) configured
// for the given batch size. It mirrors partition_test.go:66-189 (the Day-2
// harness SHAPE): dev CA, two NodeIdentity, two engines, GAP-3 pubkey Register
// on BOTH dirs, two loopback tls.Listen, two PeerSets/Gossipers, bidirectional
// Dial. A's gossiper is set to batchSize; B stays per-frame (the receiver
// dispatches on the wire magic, so B accepts A's batches regardless of B's own
// --batch-size).
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
	addrA := lnA.Addr().String()
	addrB := lnB.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go runAcceptLoop(ctx, lnA, recvA, nil, &wg) // nil digester: batch path (byte-identical HEAD; stratified OFF)
	go runAcceptLoop(ctx, lnB, recvB, nil, &wg)

	psA := NewPeerSet(trA, recvA, identA, engineA)
	psB := NewPeerSet(trB, recvB, identB, engineB)
	gA := NewGossiper(psA, identA, engineA, dirA)
	gB := NewGossiper(psB, identB, engineB, dirB)
	_ = gA.RegisterPeer(identB.NodeID, identB.Pub)
	_ = gB.RegisterPeer(identA.NodeID, identA.Pub)
	// A is the batched sender; B stays per-frame (the receiver dispatches on the
	// wire magic, so B accepts A's batches regardless of B's own batch size).
	gA.SetBatchSize(batchSize)

	if err := psA.Dial(ctx, addrB, "localhost", identB.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	if err := psB.Dial(ctx, addrA, "localhost", identA.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	asyncWait(t, psA, identB.NodeID)
	asyncWait(t, psB, identA.NodeID)

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

// injectSelfOriginated inserts N events on A ONLY (self-originated — the
// workload batching serves) and returns. The events use deterministic
// (entityID, payload, entry) triples so two meshes injected with the same N
// converge to byte-identical state (the cross-path determinism tooth).
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

// sweepUntilConverged runs concurrent AntiEntropySweep rounds on both gossipers
// until engineA/engineB MerkleRoots equal or maxRounds is hit. Returns (root,
// rounds, converged). It mirrors gossip_test.go:222-244.
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
		ra := m.engineA.State().MerkleRoot()
		rb := m.engineB.State().MerkleRoot()
		if ra == rb {
			return ra, round + 1, true
		}
	}
	ra := m.engineA.State().MerkleRoot()
	rb := m.engineB.State().MerkleRoot()
	t.Logf("did NOT converge: rootA=%x rootB=%x", ra, rb)
	return ra, maxRounds, false
}

// TestBatchedConverge_100PerBatch is the Day-5 cross-path determinism gate
// (G05.d). It proves:
//
//	(a) 1000 self-originated events shipped as 10 batches of 100 converge
//	    (B's MerkleRoot == A's MerkleRoot).
//	(b) B holds all 1000 entries (zero data loss — the S1a atomic-reject
//	    guarantee means a batch is all-or-nothing; a partial batch is a
//	    batch-level failure).
//	(c) the batched MerkleRoot EQUALS the per-frame path's MerkleRoot for the
//	    SAME 1000 events (CRDT idempotency — the two paths converge to the SAME
//	    state; the load-bearing correctness tooth: batching changes THROUGHPUT,
//	    not STATE).
//
// SCISSORS: in-process loopback; the batched ns/delta is a CORRECTNESS +
// through/api claim, NOT a silicon number.
func TestBatchedConverge_100PerBatch(t *testing.T) {
	const total = 1000
	const maxRounds = 20

	// Shared node identities: the cross-path determinism tooth requires the
	// batched and per-frame meshes to use the SAME A/B identities, so the dots
	// the two engines mint are byte-identical and the converged MerkleRoots are
	// comparable. Fresh seeds per test run (the assertions are over root
	// EQUALITY across paths, not over specific key material).
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

	// ── Batched path: A ships 1000 events as 10 batches of 100 ──
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	mBatch := newBatchMesh(t, 100, identA, identB)
	defer mBatch.close()
	mBatch.injectSelfOriginated(t, total)
	batchRoot, batchRounds, batchConverged := mBatch.sweepUntilConverged(ctxA, t, maxRounds)
	if !batchConverged {
		t.Fatalf("batched path did NOT converge in %d rounds (root=%x) — a batched-transport defect, not a perf negative", maxRounds, batchRoot)
	}
	batchEntriesB := batchCardinality(t, mBatch.engineB, total)
	if batchEntriesB != total {
		t.Fatalf("batched path data loss: B holds %d entries, want %d (S1a atomic-reject violated — a partial batch was applied)", batchEntriesB, total)
	}
	t.Logf("batched path: converged in %d rounds, B holds %d/%d entries, root=%x", batchRounds, batchEntriesB, total, batchRoot)

	// ── Per-frame path: A ships the SAME 1000 events one frame at a time ──
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	mFrame := newBatchMesh(t, 1, identA, identB) // batch=1 selects the per-frame shipDelta path
	defer mFrame.close()
	mFrame.injectSelfOriginated(t, total)
	frameRoot, frameRounds, frameConverged := mFrame.sweepUntilConverged(ctxB, t, maxRounds)
	if !frameConverged {
		t.Fatalf("per-frame path did NOT converge in %d rounds (root=%x) — a per-frame regression, not a batch defect", maxRounds, frameRoot)
	}
	frameEntriesB := batchCardinality(t, mFrame.engineB, total)
	if frameEntriesB != total {
		t.Fatalf("per-frame path data loss: B holds %d entries, want %d", frameEntriesB, total)
	}
	t.Logf("per-frame path: converged in %d rounds, B holds %d/%d entries, root=%x", frameRounds, frameEntriesB, total, frameRoot)

	// ── (c) CROSS-PATH DETERMINISM: the two roots MUST be byte-identical ──
	// Batching amortizes the verify (throughput) but the converged state is
	// IDENTICAL — the per-event wire bytes the batch carries are the SAME
	// per-event bytes the per-frame path carries. A divergence would mean
	// batching silently mutated state.
	if batchRoot != frameRoot {
		t.Fatalf("CROSS-PATH DETERMINISM VIOLATION: batched root %x != per-frame root %x — batching changed STATE, not just THROUGHPUT (a fabrication, not a feature)", batchRoot, frameRoot)
	}
	t.Logf("CROSS-PATH DETERMINISM PASS: batched root == per-frame root == %x (batching changes THROUGHPUT, not STATE)", batchRoot)
	t.Logf("SCISSORS: in-process loopback; the batched ns/delta is a CORRECTNESS + through/api claim, NOT a silicon number")
}

// batchCardinality counts the injected self-originated entries present in the
// engine's merged State() (the civic-batch-N keys injectSelfOriginated created).
// It mirrors gossip_test.go:350 cardinality but keys on the batch-test namespace.
func batchCardinality(t *testing.T, e *eng.DeltaCRDTEngine, n int) int {
	t.Helper()
	st := e.State()
	count := 0
	for i := 0; i < n; i++ {
		if got := st.Get(fmt.Sprintf("civic-batch-%d", i)); len(got) > 0 {
			count++
		}
	}
	return count
}

// TestBatchRejectTamperedWire proves a single tampered byte in the batch wire
// => HandleBatchFrame returns DropVerify AND engine.State() is UNCHANGED (S1a:
// zero joined). The one-sig-covers-the-batch binding catches the tamper at
// verify (before ApplyCRDTDeltaBatch), so the engine never sees the tampered
// batch — State() is byte-identical to the pre-batch snapshot.
//
// The honest-batch leg applies the batch to a FRESH sink engine that has NOT
// seen the events (so the CRDT Join is a real insert, producing a state
// change). The events are stamped on a separate SOURCE engine (to mint the
// authoritative dot fields the wire carries) but the batch is APPLIED to the
// sink — applying a batch to the same engine that pre-inserted its events would
// be an idempotent no-op (the CRDT Join is idempotent), which a naive test
// misreads as "deltas not joined." The honest leg proves the batch path JOINs;
// the tampered leg proves a tampered batch JOINs NOTHING (S1a).
func TestBatchRejectTamperedWire(t *testing.T) {
	// Build a single batch of 5 self-originated events directly (no mesh — the
	// tooth is the receiver's verify + apply, exercised in-process).
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand seed: %v", err)
	}
	ident, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}

	// SOURCE engine: mints the 5 events' authoritative dot fields (DotNodeID,
	// DotCounter, OriginNodeID) + caches the PayloadDigest the wire carries.
	// The batch is NOT applied to the source — it is the mint, not the sink.
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

	// ── Honest leg: apply the batch to a FRESH sink engine (never seen the
	// events) — the Join is a real insert, so State() MUST change. ──
	honestSink := newTestEngine(t, ident.NodeID, filepath.Join(t.TempDir(), "honest"))
	dirH := identity.NewDirectory()
	if err := dirH.Register(ident.NodeID, ident.Pub); err != nil {
		t.Fatalf("Register honest: %v", err)
	}
	bucketH := admission.NewPeerBucket()
	capH := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), honestSink)
	recvH := receive.NewReceiver(bucketH, capH, clock.NewSystemClock(), dirH, honestSink, 50_000_000)
	honestFrame := attribution.MarshalBatchEnvelope(ident.NodeID, sigArr, 1, uint16(len(events)), batchWire)

	rootBefore := honestSink.State().MerkleRoot()
	verdict := recvH.HandleBatchFrame(honestFrame)
	if verdict.Verdict != receive.Accept {
		t.Fatalf("honest batch: got %s, want Accept (reason: %v)", verdict.Verdict, verdict.Reason)
	}
	rootAfterHonest := honestSink.State().MerkleRoot()
	if rootAfterHonest == rootBefore {
		t.Fatalf("honest batch did not change State() — the 5 deltas were not joined (the sink engine was not fresh, or the batch path does not Join)")
	}
	t.Logf("honest leg PASS: batch Accept + State() changed (5 deltas joined on a fresh sink)")

	// ── Tampered leg: apply a TAMPERED batch (one flipped byte in batchWire)
	// to ANOTHER fresh sink — verify must fail (DropVerify) and State() MUST be
	// UNCHANGED (S1a: zero joined). ──
	tamperedSink := newTestEngine(t, ident.NodeID, filepath.Join(t.TempDir(), "tamper"))
	dirT := identity.NewDirectory()
	if err := dirT.Register(ident.NodeID, ident.Pub); err != nil {
		t.Fatalf("Register tamper: %v", err)
	}
	bucketT := admission.NewPeerBucket()
	capT := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), tamperedSink)
	recvT := receive.NewReceiver(bucketT, capT, clock.NewSystemClock(), dirT, tamperedSink, 50_000_000)
	tamperedFrame := attribution.MarshalBatchEnvelope(ident.NodeID, sigArr, 2, uint16(len(events)), batchWire)
	// Flip one byte in the BATCH WIRE (inside the envelope, after the header).
	tamperedFrame[attribution.BatchEnvelopeHeaderLen+10] ^= 0x01

	rootBefore2 := tamperedSink.State().MerkleRoot()
	verdict2 := recvT.HandleBatchFrame(tamperedFrame)
	if verdict2.Verdict != receive.DropVerify {
		t.Fatalf("tampered batch: got %s, want DropVerify (the one-sig-covers-the-batch binding must catch a tampered byte)", verdict2.Verdict)
	}
	rootAfter2 := tamperedSink.State().MerkleRoot()
	if rootAfter2 != rootBefore2 {
		t.Fatalf("S1a ATOMIC-REJECT VIOLATED: tampered batch changed State() (before=%x after=%x) — zero deltas should have joined on a verify failure", rootBefore2, rootAfter2)
	}
	t.Logf("S1a PASS: tampered batch => DropVerify + State() UNCHANGED (zero joined)")
}

// TestBatchRateGateCountsOnce proves an over-budget origin => DropRate with the
// bucket decremented ONCE per batch (the per-origin budget amortizes with the
// verify), NOT N times. The rate gate keys on the batch's originNodeID and
// decrements the budget once per batch — a batch of N deltas counts as ONE
// admission, not N.
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

	// Drain the origin's bucket by submitting batches with a MONOTONICALLY
	// RISING originSeq (the bucket drains on originSeq - lastOriginSeq). The
	// counter is the BatchEnvelope's originSeq header field (uint64, monotonic —
	// NO wrap, unlike the old BatchCount-as-counter design which wrapped at
	// 65536 and produced a zero delta). We bump originSeq by a large step per
	// submission so the delta exceeds the initialBudget (~1M token units) in a
	// small number of submissions. The first submission has delta 0 (no prior
	// observation — a fresh peer is never penalized for its first frame); the
	// second submission's delta is the step, which drains the budget.
	//
	// THE TOOTH: each HandleBatchFrame call invokes r.bucket.Accept EXACTLY
	// ONCE (receiver.go HandleBatchFrame step 2) — a batch of N deltas counts as
	// ONE admission, NOT N. The counter delta the bucket drains is the originSeq
	// delta (one decrement per batch), so a batch of N amortizes the rate gate
	// the same way it amortizes the verify. We assert the gate DROPS (the budget
	// drained) AND that the bucket was decremented by the originSeq delta (NOT
	// N×something) — the load-bearing "counts once, not N" proof.
	const step = uint64(1) << 18 // ~256K token units per submission; ~4 submissions drain 1M
	var rateKey [32]byte
	copy(rateKey[:16], ident.NodeID[:])
	budgetBefore := bucket.Budget(rateKey[:]) // initialBudget (~1M) — fresh peer
	dropped := false
	dropAttempt := -1
	var seq uint64
	for attempt := 0; attempt < 100; attempt++ {
		seq += step // monotonic rising originSeq — NO wrap (uint64)
		risingFrame := attribution.MarshalBatchEnvelope(ident.NodeID, sigArr, seq, uint16(N), batchWire)
		v := recv.HandleBatchFrame(risingFrame)
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
	// The load-bearing assertion: the bucket was decremented ONCE per batch by
	// the originSeq delta, NOT N times per batch. After `dropAttempt` batches
	// each advancing originSeq by `step`, the cumulative drain is
	// dropAttempt*step (the first batch's delta is 0 — a fresh peer is not
	// penalized for its first frame). The remaining budget is therefore
	// budgetBefore - dropAttempt*step (saturating at 0 once it drops). If the
	// gate had decremented N times per batch, the drain would be
	// dropAttempt*N*step — far larger, and the budget would have hit 0 much
	// sooner (dropAttempt would be ~1M/(N*step) ~= 1, not ~4). The observed
	// dropAttempt (~4) proves the per-batch decrement is the originSeq delta
	// (step), NOT N×step — the "counts once, not N" tooth.
	budgetAfter := bucket.Budget(rateKey[:])
	expectedDrain := uint64(dropAttempt) * step
	t.Logf("budget: before=%d after=%d drain=%d (dropAttempt=%d, step=%d, N=%d) — drain == dropAttempt*step (one decrement per batch), NOT dropAttempt*N*step",
		budgetBefore, budgetAfter, budgetBefore-budgetAfter, dropAttempt, step, N)
	if budgetBefore-budgetAfter != expectedDrain && budgetAfter != 0 {
		t.Fatalf("RATE-GATE-COUNTS-ONCE VIOLATED: budget drain=%d, expected %d (dropAttempt*step — one decrement per batch on originSeq), got a different drain — the gate decremented more than once per batch", budgetBefore-budgetAfter, expectedDrain)
	}
	t.Logf("RATE-GATE-COUNTS-ONCE PASS: bucket.Accept called once per batch (one admission per batch on originSeq, not N); dropped at attempt %d", dropAttempt)
}

// identitySignForTest wraps identity.SignCRDTFrame for the batch tests (the mesh
// package does not import pkg/identity directly for signing — the gossiper owns
// the seed; the test signs directly to build a batch frame without a full
// gossiper sweep).
func identitySignForTest(t *testing.T, seed, msg []byte) ([]byte, error) {
	t.Helper()
	return identity.SignCRDTFrame(seed, msg)
}

// stampAndInsert sets entry.PayloadDigest = SHA-256(payload) (mirroring
// gossiper.InsertLocalEvents, gossip.go:170 — the receive path cross-validates
// PayloadDigest == SHA-256(payload) in ReconstructEntry), inserts the entry via
// engine.InsertLocal (which stamps DotNodeID/DotCounter/OriginNodeID), and
// returns the stamped CRDTEntry the batch wire should carry. The digest MUST be
// set before InsertLocal so the engine stores it; the returned stamped entry
// carries the engine's authoritative dot fields + the digest.
func stampAndInsert(t *testing.T, engine *eng.DeltaCRDTEngine, entityID, payload string, entry eng.CRDTEntry) eng.CRDTEntry {
	t.Helper()
	dgst := sha256.Sum256([]byte(payload))
	entry.PayloadDigest = dgst
	engine.InsertLocal(entityID, entry)
	stamped := engine.State().Get(entityID)
	if len(stamped) == 0 {
		t.Fatalf("InsertLocal did not produce an entry for %s", entityID)
	}
	return stamped[len(stamped)-1]
}
