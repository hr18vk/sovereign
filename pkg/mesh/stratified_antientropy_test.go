// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package mesh tests the opt-in stratified anti-entropy path (ADR-0034).
// The digest exchange sends a peer's strata estimator and full IBLT, and
// generateSweepDelta passes the received IBLT to GenerateDelta. The previous
// GenerateDeltaStratified primitive subtracted an empty IBLT and therefore
// returned the full oversend set; it has been removed.
//
// These tests compare stratified and oversend Merkle roots, count delta
// entries and wire bytes, check the digest-timeout fallback counter, and run
// the exchange under the race detector. They use loopback TLS and in-process
// counters; they do not measure a distributed fleet.
package mesh

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"fmt"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"hash/maphash"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// StratifiedHarness builds two identities, engines, receive stacks, PeerSets,
// and Gossipers over loopback TLS. It follows TestTwoNodeConvergence_InMemory,
// but binds each gossiper as the digest sink and configures stratified
// anti-entropy per test. Digest frames consequently reach the sweep's per-peer
// receive channel.
//
// The harness does not insert events; each test inserts its own event
// distribution so it can measure the bandwidth cut at the symmetry point it
// cares about (full-overlap, partial-overlap, or disjoint).
type StratifiedHarness struct {
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
	fallbackA int32 // digest-timeout fallbacks observed by node A
	fallbackB int32 // digest-timeout fallbacks observed by node B
}

// newStratifiedHarness uses fresh random identities for tests that exercise a
// single path. Tests comparing roots across stratified and oversend paths use
// newStratifiedHarnessSeeded so CausalDot OriginNodeID values also match.
func newStratifiedHarness(t *testing.T, stratified bool) *StratifiedHarness {
	t.Helper()
	seedA := make([]byte, ed25519.SeedSize)
	seedB := make([]byte, ed25519.SeedSize)
	if _, err := cryptorand.Read(seedA); err != nil {
		t.Fatalf("rand seedA: %v", err)
	}
	if _, err := cryptorand.Read(seedB); err != nil {
		t.Fatalf("rand seedB: %v", err)
	}
	return newStratifiedHarnessSeeded(t, stratified, seedA, seedB)
}

// newStratifiedHarnessSeeded gives both paths the same node identities.
// CausalDot includes OriginNodeID, so different identities would produce
// different Merkle roots even for identical logical entries. The stratified
// setting is applied before connection setup. Fallback reporters increment
// local atomic counters; TestStratifiedFallbackCounter checks the telemetry
// registry.
func newStratifiedHarnessSeeded(t *testing.T, stratified bool, seedA, seedB []byte) *StratifiedHarness {
	t.Helper()
	if len(seedA) != ed25519.SeedSize || len(seedB) != ed25519.SeedSize {
		t.Fatalf("newStratifiedHarnessSeeded: seedA/seedB must be ed25519.SeedSize (%d) bytes; got %d/%d", ed25519.SeedSize, len(seedA), len(seedB))
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

	// Use the same stratified setting on both nodes for the symmetric tests.
	// TestStratifiedFallbackCounterFires covers a mixed configuration, where
	// the disabled node does not answer and its peer falls back to oversend.
	gA.SetStratifiedAntiEntropy(stratified)
	gB.SetStratifiedAntiEntropy(stratified)

	// Construct the harness before the reporter closures capture its counters.
	h := &StratifiedHarness{
		dir: dir, caPath: caPath, identA: identA, identB: identB,
		engineA: engineA, engineB: engineB, recvA: recvA, recvB: recvB,
		lnA: lnA, lnB: lnB, addrA: lnA.Addr().String(), addrB: lnB.Addr().String(),
		psA: psA, psB: psB, gA: gA, gB: gB, ctx: ctx, cancel: cancel,
		fallbackA: 0, fallbackB: 0,
	}
	// Gossiper stores the reporter; the harness owns each atomic counter.
	gA.SetStratifiedFallbackReporter(func() { atomic.AddInt32(&h.fallbackA, 1) })
	gB.SetStratifiedFallbackReporter(func() { atomic.AddInt32(&h.fallbackB, 1) })
	// Loopback RTT is about 10us; 200ms leaves room for delivery while keeping
	// the timeout test short.
	gA.SetDigestWaitTimeout(200 * time.Millisecond)
	gB.SetDigestWaitTimeout(200 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(2)
	// Binding the gossiper as digest sink delivers frames to the sweep's
	// per-peer receive channel. A nil sink drops them on the ordinary path.
	// The PeerSet-threaded accept loop — inbound connections
	// register, complete the challenge handshake, and earn egress.
	go runAcceptLoopWithPeerSet(ctx, lnA, recvA, gA, &wg, psA)
	go runAcceptLoopWithPeerSet(ctx, lnB, recvB, gB, &wg, psB)
	h.wg = &wg

	// Dial once and let accept-side registration complete one bidirectional
	// verified connection. Simultaneous dials would decline one connection at
	// each end, leaving the declined halves unavailable for digest exchange
	// and root announcements.
	if err := psA.Dial(ctx, h.addrB, "localhost", identB.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	asyncWait(t, psA, identB.NodeID)
	asyncWait(t, psB, identA.NodeID) // B installs A's inbound connection
	awaitVerified(t, psA, identB.NodeID)
	awaitVerified(t, psB, identA.NodeID)
	return h
}

// close cancels the harness context and closes both listeners.
func (h *StratifiedHarness) close() {
	h.cancel()
	_ = h.lnA.Close()
	_ = h.lnB.Close()
}

// insertEvents inserts n events split evenly between A and B (i%2==0 -> A,
// else B), each with a distinct entityID, payload, and SystemTime that
// advances. The split follows the same pattern as
// TestTwoNodeConvergence_InMemory so the convergence tests are comparable.
// Returns the total inserted (== n).
func (h *StratifiedHarness) insertEvents(t *testing.T, n int) int {
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

// sweepUntilConverged runs concurrent AntiEntropySweep rounds until the roots
// match or maxRounds is reached. The tick lets asynchronous readers deliver a
// round's deltas. It returns rounds, convergence, rootA, and rootB.
func (h *StratifiedHarness) sweepUntilConverged(t *testing.T, maxRounds int, tick time.Duration) (int, bool, [32]byte, [32]byte) {
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
		t.Logf("round %d: rootA=%x rootB=%x fallbackA=%d fallbackB=%d", round, ra, rb, atomic.LoadInt32(&h.fallbackA), atomic.LoadInt32(&h.fallbackB))
		if ra == rb {
			return round + 1, true, ra, rb
		}
	}
	ra := h.engineA.MerkleRootFromShards()
	rb := h.engineB.MerkleRootFromShards()
	return maxRounds, false, ra, rb
}

// TestStratifiedOffIsByteIdentical checks the default non-stratified path on
// the same 1,000-event split used by TestTwoNodeConvergence_InMemory. The
// generateSweepDelta branch remains GenerateDelta(emptyIBLT), must converge
// within 10 rounds, and must not report a digest fallback.
func TestStratifiedOffIsByteIdentical(t *testing.T) {
	h := newStratifiedHarness(t, false) // ordinary oversend
	defer h.close()
	const total = 1000
	h.insertEvents(t, total)
	rounds, converged, ra, rb := h.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !converged {
		t.Fatalf("non-stratified sweep did not converge in <=10 rounds (rootA=%x rootB=%x)", ra, rb)
	}
	gotA := cardinality(t, h.engineA)
	gotB := cardinality(t, h.engineB)
	if gotA != total || gotB != total {
		t.Fatalf("cardinality after convergence is A=%d B=%d, want %d on both", gotA, gotB, total)
	}
	if atomic.LoadInt32(&h.fallbackA) != 0 || atomic.LoadInt32(&h.fallbackB) != 0 {
		t.Fatalf("non-stratified oversend reported digest fallbacks A=%d B=%d, want zero", h.fallbackA, h.fallbackB)
	}
	t.Logf("non-stratified sweep converged %d events in %d rounds with no digest fallback", total, rounds)
}

// TestStratifiedOnConvergesByteIdentity compares stratified and oversend
// convergence over the same 1,000 events and node identities. The stratified
// delta is a subset absorbed by idempotent Join, so both paths must reach the
// same Merkle roots and cardinalities. Round counts are reported as well.
func TestStratifiedOnConvergesByteIdentity(t *testing.T) {
	// Fixed identities make the CausalDots, and therefore the roots, comparable.
	seedA := bytesRepeat(0xA1, ed25519.SeedSize)
	seedB := bytesRepeat(0xB2, ed25519.SeedSize)

	// Capture the non-stratified reference roots.
	hOff := newStratifiedHarnessSeeded(t, false, seedA, seedB)
	hOff.insertEvents(t, 1000)
	offRounds, offConverged, offRootA, offRootB := hOff.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !offConverged {
		t.Fatalf("non-stratified reference did not converge (rootA=%x rootB=%x)", offRootA, offRootB)
	}
	offCardA := cardinality(t, hOff.engineA)
	offCardB := cardinality(t, hOff.engineB)
	hOff.close()

	// Run stratified anti-entropy on fresh engines with the same events.
	hOn := newStratifiedHarnessSeeded(t, true, seedA, seedB)
	defer hOn.close()
	hOn.insertEvents(t, 1000)
	onRounds, onConverged, onRootA, onRootB := hOn.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !onConverged {
		t.Fatalf("stratified sweep did not converge in <=10 rounds (rootA=%x rootB=%x)", onRootA, onRootB)
	}
	if onRootA != offRootA || onRootB != offRootB {
		t.Fatalf("stratified roots A=%x B=%x differ from oversend roots A=%x B=%x", onRootA, onRootB, offRootA, offRootB)
	}
	onCardA := cardinality(t, hOn.engineA)
	onCardB := cardinality(t, hOn.engineB)
	if onCardA != offCardA || onCardB != offCardB {
		t.Fatalf("stratified cardinality A=%d B=%d differs from oversend A=%d B=%d", onCardA, onCardB, offCardA, offCardB)
	}
	if onRounds > offRounds {
		t.Logf("stratified convergence took %d rounds versus %d for oversend; roots still match", onRounds, offRounds)
	}
	t.Logf("stratified root A=%x matches oversend A=%x; rounds=%d/%d; stratified cardinality A=%d B=%d; oversend cardinality A=%d B=%d", onRootA, offRootA, onRounds, offRounds, onCardA, onCardB, offCardA, offCardB)
}

// TestStratifiedBandwidthCut compares GenerateDelta entry counts for the same
// state. A holds 300 entries and B holds the first 225, so the stratified
// digest should reduce A's delta from 300 entries to approximately 75. This
// direct primitive measurement avoids mixing delta size with relay and batch
// transport accounting.
func TestStratifiedBandwidthCut(t *testing.T) {
	// Shared node IDs, entity IDs, payloads, and timestamps make the overlapping
	// CausalDots hash identically across the engines.
	nodeID := [16]byte{0x29, 0x29}
	engA := newTestEngine(t, nodeID, t.TempDir())
	engB := newTestEngine(t, nodeID, t.TempDir())
	// A holds [0,300) and B holds [0,225), so |A-B|=75 and |B-A|=0.
	// GenerateDelta uses a fixed 1,024-bucket local digest, and Subtract
	// requires the remote digest to have the same bucket count. Peeling becomes
	// unreliable as collisions accumulate near a 0.7 load and eventually falls
	// back to oversend. The 225/1024 remote load used here is approximately
	// 0.22, avoiding a probabilistic peel failure in this deterministic check.
	// TestStratifiedWireCost and ADR-0034 describe the fixed-bucket limit.
	const total, overlap = 300, 225
	for i := 0; i < total; i++ {
		eid := fmt.Sprintf("civic-%d", i)
		payload := fmt.Sprintf("v-%d", i)
		digest := sha256Sum256([]byte(payload))
		entry := eng.CRDTEntry{
			SystemTime:    int64(1_700_000_000 + i),
			H3Index:       uint64(i),
			PayloadDigest: digest,
		}
		engA.InsertLocal(eid, entry) // InsertLocal stamps OriginNodeID=nodeID
		if i < overlap {
			engB.InsertLocal(eid, entry)
		}
	}
	// An empty remote IBLT produces the full oversend set.
	emptyIBLT := eng.NewIBLT(1, 4)
	offDelta := engA.GenerateDelta(emptyIBLT)
	offCount := countDeltaEntries(t, offDelta)
	offDelta.Release()
	// B's populated 1,024-bucket digest should isolate A's 75 unique entries.
	seed := maphash.MakeSeed()
	remoteIBLT := engB.GenerateDigestWithSeed(seed)
	onDelta := engA.GenerateDelta(remoteIBLT)
	onCount := countDeltaEntries(t, onDelta)
	onDelta.Release()
	t.Logf("bandwidth |A|=%d overlap=%d |A-B|=%d: oversend=%d entries, stratified=%d", total, overlap, total-overlap, offCount, onCount)
	if onCount >= offCount {
		t.Fatalf("stratified delta has %d entries, oversend has %d; populated digest did not reduce the delta", onCount, offCount)
	}
	cut := offCount - onCount
	pct := float64(cut) / float64(offCount) * 100
	t.Logf("stratified delta=%d entries versus oversend=%d (a %d-entry reduction, %.1f%%; |A-B|=%d of %d at 225/1024 digest load)", onCount, offCount, cut, pct, total-overlap, total)
}

// countDeltaEntries drains a CRDTDelta's Entries iterator and returns the count
// (the bandwidth measurement — the number of entries the delta would ship,
// independent of the sweep's transport accounting).
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

// TestStratifiedFallbackCounterFires enables stratified anti-entropy only on
// A. B does not answer its digest, so A's digestWaitTimeout expires and the
// fallback counter increments. Oversend must still converge both engines.
func TestStratifiedFallbackCounterFires(t *testing.T) {
	h := newStratifiedHarness(t, true)
	defer h.close()
	// B does not answer once stratified anti-entropy is disabled. B's own
	// non-stratified path oversends directly and records no digest fallback.
	h.gB.SetStratifiedAntiEntropy(false)
	// Keep the timeout short relative to the sweep tick.
	h.gA.SetDigestWaitTimeout(30 * time.Millisecond)
	h.gB.SetDigestWaitTimeout(30 * time.Millisecond)
	h.insertEvents(t, 1000)
	_, converged, ra, rb := h.sweepUntilConverged(t, 10, 40*time.Millisecond)
	if !converged {
		t.Fatalf("mixed configuration did not converge through oversend (rootA=%x rootB=%x)", ra, rb)
	}
	aFb := atomic.LoadInt32(&h.fallbackA)
	if aFb == 0 {
		t.Fatalf("A recorded no fallback after B stopped answering digests")
	}
	t.Logf("A recorded %d digest-timeout fallbacks and converged through oversend", aFb)
}

// TestStratifiedFallbackCounter checks the current telemetry registry size
// and the presence of supremum.mesh.stratified_fallback. The metric is the
// counter reached by SetStratifiedFallbackReporter and is enumerated by the
// telemetry bridge. Other counters are documented by ADR-0035, ADR-0036,
// ADR-0037, ADR-0039, and ADR-0059.
func TestStratifiedFallbackCounter(t *testing.T) {
	cs := telemetry.Counters()
	const wantDistinct = 25 // current telemetry registry size, including ADR-0059
	if len(cs) != wantDistinct {
		t.Fatalf("telemetry.Counters() returned %d counters, want %d", len(cs), wantDistinct)
	}
	// Find the stratified fallback metric in the registry.
	var found *telemetry.Counter
	for _, c := range cs {
		if c.Name() == "supremum.mesh.stratified_fallback" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatalf("telemetry registry lacks supremum.mesh.stratified_fallback")
	}
	if found.Name() != "supremum.mesh.stratified_fallback" {
		t.Fatalf("counter name is %q, want supremum.mesh.stratified_fallback", found.Name())
	}
	t.Logf("telemetry registry contains %d counters, including supremum.mesh.stratified_fallback", len(cs))
}

// TestStratifiedRace exercises concurrent stratified sweeps, the mutex-guarded
// digestRecv map, per-peer channels, and GenerateDelta's EBR pin. Run it with
// -race to instrument those accesses.
func TestStratifiedRace(t *testing.T) {
	h := newStratifiedHarness(t, true)
	defer h.close()
	h.insertEvents(t, 1000)
	rounds, converged, ra, rb := h.sweepUntilConverged(t, 10, 20*time.Millisecond)
	if !converged {
		t.Fatalf("stratified race workload did not converge in <=10 rounds (rootA=%x rootB=%x)", ra, rb)
	}
	t.Logf("stratified race workload converged %d events in %d rounds", 1000, rounds)
}

// TestStratifiedCutProven contrasts populated and empty remote IBLTs on the
// same GenerateDelta input. The populated digest must yield fewer entries than
// oversend; the empty digest recreates GenerateDeltaStratified's old behavior
// and must yield the full set. This isolates the operand that makes the
// stratified wiring effective without modifying the engine primitive.
func TestStratifiedCutProven(t *testing.T) {
	nodeID := [16]byte{0x29, 0x29}
	engA := newTestEngine(t, nodeID, t.TempDir())
	engB := newTestEngine(t, nodeID, t.TempDir())
	// The fixed 1,024-bucket digest becomes unreliable at high load (ADR-0034).
	// A 225/1024 load of approximately 0.22 keeps peeling reliable for arbitrary
	// maphash seeds, so this assertion tests the remote operand rather than a
	// probabilistic peel failure.
	const total, overlap = 300, 225
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
	// GenerateDelta against an empty IBLT yields the full oversend set.
	emptyIBLT := eng.NewIBLT(1, 4)
	offDelta := engA.GenerateDelta(emptyIBLT)
	offCount := countDeltaEntries(t, offDelta)
	offDelta.Release()
	// The populated digest is the operand used by generateSweepDelta.
	seed := maphash.MakeSeed()
	populatedRemote := engB.GenerateDigestWithSeed(seed)
	populatedDelta := engA.GenerateDelta(populatedRemote)
	populatedCount := countDeltaEntries(t, populatedDelta)
	populatedDelta.Release()
	// Repeating the call with an empty remote recreates the old defect.
	emptyRemoteDelta := engA.GenerateDelta(emptyIBLT)
	emptyRemoteCount := countDeltaEntries(t, emptyRemoteDelta)
	emptyRemoteDelta.Release()
	t.Logf("cut control: oversend=%d populated-remote=%d empty-remote=%d", offCount, populatedCount, emptyRemoteCount)
	if populatedCount >= offCount {
		t.Fatalf("populated remote yielded %d entries, want fewer than oversend %d", populatedCount, offCount)
	}
	if emptyRemoteCount < offCount {
		t.Fatalf("empty remote yielded %d entries, want full oversend set %d", emptyRemoteCount, offCount)
	}
	cut := offCount - populatedCount
	pct := float64(cut) / float64(offCount) * 100
	t.Logf("populated remote yielded %d entries versus oversend %d (%d-entry reduction, %.1f%%); empty remote yielded %d", populatedCount, offCount, cut, pct, emptyRemoteCount)
}

// TestStratifiedWireCost measures the marshaled digest frame: a 32-strata
// estimator, a fixed 1,024-bucket IBLT, and the frame header. It compares that
// per-peer overhead with an estimated 200-byte delta-entry cost. Stratified
// anti-entropy saves bytes when the avoided oversend entries exceed the digest
// frame; a near-empty diff can make the exchange a net cost.
//
// GenerateDelta's fixed 1,024-bucket digest must match the remote IBLT. Peel
// reliability falls near 0.7 load, around 750 entries, and failure falls back
// to oversend. ADR-0034 records that limit; sizing the digest dynamically is
// outside this test.
func TestStratifiedWireCost(t *testing.T) {
	nodeID := [16]byte{0x29, 0x29}
	e := newTestEngine(t, nodeID, t.TempDir())
	// Use 500 entries, below the fixed digest's saturation region.
	for i := 0; i < 500; i++ {
		eid := fmt.Sprintf("civic-%d", i)
		payload := fmt.Sprintf("v-%d", i)
		digest := sha256Sum256([]byte(payload))
		entry := eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i), PayloadDigest: digest}
		e.InsertLocal(eid, entry)
	}
	seed := maphash.MakeSeed()
	localSE := e.GenerateStrataEstimator(seed)
	localIBLT := e.GenerateDigestWithSeed(seed)
	seBytes, err := eng.MarshalStrataEstimator(localSE)
	if err != nil {
		t.Fatalf("MarshalStrataEstimator: %v", err)
	}
	ibltBytes, err := eng.MarshalIBLT(localIBLT)
	localIBLT.Release()
	if err != nil {
		t.Fatalf("MarshalIBLT: %v", err)
	}
	// digestFrameHeaderLen covers magic, sender, role, seed, and build stamp.
	// Add four bytes for the strata-estimator length prefix.
	frameBytes := digestFrameHeaderLen + 4 + len(seBytes) + len(ibltBytes)
	t.Logf("digest frame: strata=%d B IBLT=%d B header=%d B total=%d B/peer/round", len(seBytes), len(ibltBytes), digestFrameHeaderLen+4, frameBytes)
	// At 75% overlap, 500 estimated entries oversend and 125 remain in the
	// diff. Digest overhead is worthwhile when the avoided 375 entries cost
	// more than frameBytes. Near-empty diffs can reverse that relationship.
	const estEntryBytes = 200
	const total, overlap = 500, 375
	diff := total - overlap
	oversendBytes := total * estEntryBytes
	stratifiedBytes := diff*estEntryBytes + frameBytes
	net := oversendBytes - stratifiedBytes
	t.Logf("wire break-even |A|=%d |A-B|=%d entry=%d B: oversend=%d B stratified=%d B (diff=%d B digest=%d B) net=%d B", total, diff, estEntryBytes, oversendBytes, stratifiedBytes, diff*estEntryBytes, frameBytes, net)
	if net <= 0 {
		t.Fatalf("digest overhead exceeds estimated savings at 75%% overlap: net=%d B", net)
	}
	t.Logf("digest frame=%d B/peer/round (strata=%d IBLT=%d header=%d); estimated savings at 75%% overlap=%d B; ADR-0034 covers saturation and near-empty diffs", frameBytes, len(seBytes), len(ibltBytes), digestFrameHeaderLen+4, net)
}

// bytesRepeat returns n copies of b for deterministic, non-random identity
// seeds shared by the stratified and non-stratified harnesses.
func bytesRepeat(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

// sha256Sum256 returns the payload digest used by InsertLocalEvents. Setting
// it directly makes overlapping entries produce matching HashCausalDot keys.
func sha256Sum256(data []byte) [32]byte {
	return sha256.Sum256(data)
}
