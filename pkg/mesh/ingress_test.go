// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests exercise ingress admission and relay retention over loopback TLS:
// ordered hybrid batches healing a Lamport-skew backlog, unverified peers being
// unable to advance a receiver's clock, and relays resolving entries retained by
// either the per-frame or batch path. Counting sinks observe delivery and
// rejection verdicts directly.
package mesh

import (
	"context"
	"sync"
	"testing"

	"github.com/hr18vk/sovereign/pkg/crypto"
)

// TestI2HybridHeal runs the skew-backlog scenario with hybrid identities. Both
// signing modes share ApplyCRDTDeltaBatch, so ordered delivery must heal the
// backlog regardless of the signature scheme. Each Directory contains both
// public keys for its peer, A verifies both signatures, and B sends signed
// batches.
//
// B mints six times the 1,000-dot admission window while disconnected. Once the
// nodes connect, one or two driven sweeps must converge their roots without
// skew refusals. Applying the entries in order advances A's clock from its
// initial value of 1 to mint+1 and leaves A holding the complete set.
func TestI2HybridHeal(t *testing.T) {
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

	// Both identities derive their post-quantum keypair from the same seed as
	// their classical keypair. Record A's clock before any frame can arrive.
	a := newEclipseNode(t, ca, caPath, root, "A", 0xD1, false, true)
	clockAtBuildA := a.engine.LamportCounter()
	b := newEclipseNode(t, ca, caPath, root, "B", 0xD2, false, true)
	// LookupBoth must resolve both public keys in each direction.
	if err := a.dir.Register(b.ident.NodeID, b.ident.Pub); err != nil {
		t.Fatalf("register B in A: %v", err)
	}
	if err := a.dir.RegisterPQ(b.ident.NodeID, b.ident.PQPub); err != nil {
		t.Fatalf("register B's PQ key in A: %v", err)
	}
	if err := b.dir.Register(a.ident.NodeID, a.ident.Pub); err != nil {
		t.Fatalf("register A in B: %v", err)
	}
	if err := b.dir.RegisterPQ(a.ident.NodeID, a.ident.PQPub); err != nil {
		t.Fatalf("register A's PQ key in B: %v", err)
	}
	// A requires both signatures; B signs with both algorithms and sends batches.
	// Configure verification before eclipseWire starts the accept loops.
	a.recv.SetHybridVerify(true)
	b.g.SetHybridSign(true)
	b.g.SetBatchSize(DefaultBatchSize)

	const mint = 6000 // six times the 1,000-dot admission window
	eclipseMint(b, "hybrid-ingress", mint)
	if got := a.engine.LamportCounter(); got != clockAtBuildA {
		t.Fatalf("partition observation failed: A.LamportCounter=%d, want its construction value %d", got, clockAtBuildA)
	}
	if total, _, _, _ := eclipseDrain(t, a); total != 0 {
		t.Fatalf("partition observation failed: A's sink observed %d verdicts before connection", total)
	}
	eclipseWire(t, ctx, a, b)

	convergedRound := 0
	for round := 1; round <= 8; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2)
		go func() { defer sweepWG.Done(); a.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
		sweepWG.Wait()
		// Wait bounds publication, but A's readLoop applies B's envelopes
		// asynchronously. Poll A's sink until its verdict count is stable before
		// comparing roots so the round count measures healing, not delivery lag.
		eclipseDrain(t, a)
		if a.engine.MerkleRootFromShards() == b.engine.MerkleRootFromShards() {
			convergedRound = round
			break
		}
	}
	total, skew, dirMiss, sigFail := eclipseDrain(t, a)
	ra := a.engine.MerkleRootFromShards()
	rb := b.engine.MerkleRootFromShards()
	t.Logf("hybrid heal:convergedRound=%d sinkTotal=%d skewRefusals=%d directoryMiss=%d sigFail=%d rootA=%x rootB=%x A.clock=%d A.held=%d",
		convergedRound, total, skew, dirMiss, sigFail, ra, rb, a.engine.LamportCounter(), eclipseCount(a, "hybrid-ingress", mint))
	if convergedRound == 0 || convergedRound > 2 {
		t.Errorf("convergedRound=%d, want 1..2 (the ordered hybrid crawl heals the 6x-window backlog in <= 2 driven sweeps; 0 = no convergence in 8)", convergedRound)
	}
	if skew != 0 {
		t.Errorf("%d skew refusals on the hybrid path; ordered application did not keep the batches within the admission window", skew)
	}
	if ra != rb {
		t.Errorf("roots differ (rootA=%x rootB=%x)", ra, rb)
	}
	if clockA := a.engine.LamportCounter(); clockA != uint64(mint)+1 {
		t.Errorf("A.clock=%d, want %d (the mint high-water: genesis 1 + %d mints; the Join-crawl advance signature)", clockA, uint64(mint)+1, mint)
	}
	if got := eclipseCount(a, "hybrid-ingress", mint); got != mint {
		t.Errorf("A holds %d of %d hybrid-shipped keys", got, mint)
	}
}

// TestI3A1ClockBrick verifies that an unverified origin cannot advance V's
// Lamport clock. Advancing at the drift gate before identity verification would
// let a far-future dot make later peers reject V's own entries. Verification now
// earns the clock advance, and the gateway also refuses to send to a peer whose
// identity it cannot verify (ADR-0068).
//
// M mints 3,000 entries, but neither node has the other's Directory entry. M's
// sweeps must increment egressUnverifiedDrops while no frames reach V's sink.
// V's clock and keyset must remain unchanged. The drop counter distinguishes
// this result from a run that never offered frames to the gateway.
func TestI3A1ClockBrick(t *testing.T) {
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

	v := newEclipseNode(t, ca, caPath, root, "V", 0xE1, false, false)
	clockAtBuildV := v.engine.LamportCounter() // the genesis baseline (1)
	m := newEclipseNode(t, ca, caPath, root, "M", 0xE2, false, false)
	// Leave both Directory entries absent so neither side can verify the other.
	const mint = 3000
	eclipseMint(m, "unverified-origin", mint)
	if got := m.engine.LamportCounter(); got < uint64(mint) {
		t.Fatalf("mint observation failed: M.LamportCounter=%d, want at least %d", got, mint)
	}
	if got := v.engine.LamportCounter(); got != clockAtBuildV {
		t.Fatalf("partition observation failed: V.LamportCounter=%d, want its construction value %d", got, clockAtBuildV)
	}
	eclipseWireUnverified(t, ctx, v, m)

	// Drive M's self-originated per-frame envelopes, then poll V's sink until
	// quiet before checking whether any dropped frame advanced the clock.
	for round := 1; round <= 3; round++ {
		m.g.AntiEntropySweep(ctx)
	}
	total, _, dirMiss, sigFail := eclipseDrain(t, v)
	vClock := v.engine.LamportCounter()
	egressDrops := m.g.egressUnverifiedDrops.Load()
	t.Logf("unverified origin:sinkTotal=%d directoryMiss=%d sigFail=%d M.egressUnverifiedDrops=%d V.clock=%d (construction %d; M minted %d, M.clock=%d)",
		total, dirMiss, sigFail, egressDrops, vClock, clockAtBuildV, mint, m.engine.LamportCounter())
	// The gateway rejects V before transmission because M has no trusted key
	// for V. Thus directoryMiss and the sink total must stay zero; the gateway's
	// own drop counter proves that the sweeps attempted the send (ADR-0068).
	if egressDrops == 0 {
		t.Fatalf("zero egress-gate drops at M across three sweeps; no frames were offered to the gateway, so the clock check did not exercise admission")
	}
	if dirMiss != 0 {
		t.Fatalf("%d Directory-miss verdicts at V; unverified-origin frames crossed the gateway egress gate", dirMiss)
	}
	if total != 0 {
		t.Fatalf("V's sink received %d frame(s) from the unverified origin — data-plane bytes crossed the gate", total)
	}
	// No unverified frame may advance V's clock.
	if vClock != clockAtBuildV {
		t.Errorf("V.LamportCounter=%d after %d Directory-missed frames, want its construction value %d; an unverified origin advanced the clock by %d", vClock, dirMiss, clockAtBuildV, vClock-clockAtBuildV)
	}
	// The drop posture is unchanged: nothing Joined.
	if got := eclipseCount(v, "unverified-origin", mint); got != 0 {
		t.Errorf("V holds %d of M's %d keys — a Directory-missed frame Joined; the gate stack failed", got, mint)
	}
}

// TestI4MixedRelay connects a batch sender B to a per-frame relay A and then to
// C, with no direct B-C edge. A retains B's inbound batches in the batch relay
// layer. When A walks foreign entries for its per-frame output, a miss in the
// per-frame layer falls back to relayCache.lookupBatchCounted and republishes
// the retained batch envelopes. A seen set emits each batch at most once per
// peer per sweep.
//
// All three roots must converge within six driven rounds. C must hold all 100
// keys with no Directory misses, and A must report no relay misses. Without the
// batch-layer fallback, C receives nothing and the relay stalls after one hop.
func TestI4MixedRelay(t *testing.T) {
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

	b := newEclipseNode(t, ca, caPath, root, "B", 0xF3, false, false) // the batch shipper + minter
	a := newEclipseNode(t, ca, caPath, root, "A", 0xF4, false, false) // the per-frame relay middle
	c := newEclipseNode(t, ca, caPath, root, "C", 0xF5, false, false) // the per-frame far end
	// Register every origin in both directions. In particular, C needs B's key
	// because HandleBatchFrame verifies B's origin on A's republished batches.
	reg := func(x, y *EclipseNode) {
		if err := x.dir.Register(y.ident.NodeID, y.ident.Pub); err != nil {
			t.Fatalf("register %x in %x: %v", y.ident.NodeID, x.ident.NodeID, err)
		}
	}
	reg(a, b)
	reg(b, a)
	reg(a, c)
	reg(c, a)
	reg(c, b)
	reg(b, c)
	b.g.SetBatchSize(4) // small batches: the 100-dot mint spans 25 envelopes

	const mint = 100
	eclipseMint(b, "mixed-relay", mint)
	// C can receive B's entries only through A; there is no B-C edge.
	eclipseWire(t, ctx, b, a)
	eclipseWire(t, ctx, a, c)
	if total, _, _, _ := eclipseDrain(t, c); total != 0 {
		t.Fatalf("partition observation failed: C's sink observed %d verdicts before the driven rounds", total)
	}

	// Drive at most six rounds and accumulate A's relay-miss count.
	relayMissesTotal := 0
	convergedRound := 0
	for round := 1; round <= 6; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2) // B and C run asynchronously; A runs inline.
		go func() { defer sweepWG.Done(); b.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); c.g.AntiEntropySweep(ctx) }()
		stA := a.g.AntiEntropySweep(ctx)
		sweepWG.Wait()
		relayMissesTotal += stA.relayMisses
		// Drain both receiving sinks before comparing roots with asynchronous
		// applies still in flight.
		eclipseDrain(t, a)
		eclipseDrain(t, c)
		if b.engine.MerkleRootFromShards() == a.engine.MerkleRootFromShards() &&
			a.engine.MerkleRootFromShards() == c.engine.MerkleRootFromShards() {
			convergedRound = round
			break
		}
	}
	totalC, _, dirMissC, _ := eclipseDrain(t, c)
	t.Logf("mixed relay:convergedRound=%d A.relayMisses=%d C.sinkTotal=%d C.directoryMiss=%d rootB=%x rootA=%x rootC=%x C.held=%d A.held=%d",
		convergedRound, relayMissesTotal, totalC, dirMissC,
		b.engine.MerkleRootFromShards(), a.engine.MerkleRootFromShards(), c.engine.MerkleRootFromShards(),
		eclipseCount(c, "mixed-relay", mint), eclipseCount(a, "mixed-relay", mint))
	if convergedRound == 0 {
		t.Errorf("no convergence in 6 driven rounds — the mixed relay still stalls (C holds %d of %d)", eclipseCount(c, "mixed-relay", mint), mint)
	}
	if got := eclipseCount(c, "mixed-relay", mint); got != mint {
		t.Errorf("C holds %d of %d — the batch-received foreign dots stall at one hop on the per-frame relay", got, mint)
	}
	if relayMissesTotal != 0 {
		t.Errorf("%d relay misses on A's walks — the batch-layer fallback did not resolve the batch-retained foreign dots", relayMissesTotal)
	}
	if dirMissC != 0 {
		t.Errorf("C observed %d Directory misses — a re-published batch origin did not resolve at C", dirMissC)
	}
}

// TestI4Mirror reverses the mixed-relay arrangement. O sends per-frame
// envelopes, R retains them in relay.m but sends batches using the default
// batch size, and CM connects only to R. The batch path's resolveForeign must
// therefore fall back from its batch layer to the per-frame layer in batch.go.
// Consulting only the batch layer leaves every origin entry unresolved and
// stalls the delta at R.
//
// The roots must converge within six rounds, CM must receive all 100 keys, and
// R must report no relay misses. CM also checks origin resolution and signature
// verification on the republished frames.
func TestI4Mirror(t *testing.T) {
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

	o := newEclipseNode(t, ca, caPath, root, "O", 0xF6, false, false)   // the per-frame origin + minter
	r := newEclipseNode(t, ca, caPath, root, "R", 0xF7, false, false)   // the batch-path relay (the production default)
	cm := newEclipseNode(t, ca, caPath, root, "CM", 0xF8, false, false) // the per-frame far end
	// Register every origin in both directions. CM needs O's key to verify the
	// per-frame envelopes that R republishes.
	reg := func(x, y *EclipseNode) {
		if err := x.dir.Register(y.ident.NodeID, y.ident.Pub); err != nil {
			t.Fatalf("register %x in %x: %v", y.ident.NodeID, x.ident.NodeID, err)
		}
	}
	reg(r, o)
	reg(o, r)
	reg(r, cm)
	reg(cm, r)
	reg(cm, o)
	reg(o, cm)
	r.g.SetBatchSize(DefaultBatchSize) // the production default: R's sweeps dispatch to shipBatchedDelta

	const mint = 100
	eclipseMint(o, "mirror-relay", mint)
	// CM can receive O's entries only through R; there is no O-CM edge.
	eclipseWire(t, ctx, o, r)
	eclipseWire(t, ctx, r, cm)
	if total, _, _, _ := eclipseDrain(t, cm); total != 0 {
		t.Fatalf("partition observation failed: CM's sink observed %d verdicts before the driven rounds", total)
	}

	// Drive at most six rounds with R inline and accumulate its relay misses.
	relayMissesTotal := 0
	convergedRound := 0
	for round := 1; round <= 6; round++ {
		var sweepWG sync.WaitGroup
		sweepWG.Add(2) // only the o+cm goroutines carry Done (R runs inline)
		go func() { defer sweepWG.Done(); o.g.AntiEntropySweep(ctx) }()
		go func() { defer sweepWG.Done(); cm.g.AntiEntropySweep(ctx) }()
		stR := r.g.AntiEntropySweep(ctx)
		sweepWG.Wait()
		relayMissesTotal += stR.relayMisses
		// Drain R's application of O's frames and CM's application of R's
		// republished frames before comparing roots.
		eclipseDrain(t, r)
		eclipseDrain(t, cm)
		if o.engine.MerkleRootFromShards() == r.engine.MerkleRootFromShards() &&
			r.engine.MerkleRootFromShards() == cm.engine.MerkleRootFromShards() {
			convergedRound = round
			break
		}
	}
	totalCM, _, dirMissCM, sigFailCM := eclipseDrain(t, cm)
	t.Logf("mirror relay:convergedRound=%d R.relayMisses=%d CM.sinkTotal=%d CM.directoryMiss=%d CM.sigFail=%d rootO=%x rootR=%x rootCM=%x CM.held=%d",
		convergedRound, relayMissesTotal, totalCM, dirMissCM, sigFailCM,
		o.engine.MerkleRootFromShards(), r.engine.MerkleRootFromShards(), cm.engine.MerkleRootFromShards(),
		eclipseCount(cm, "mirror-relay", mint))
	if convergedRound == 0 {
		t.Errorf("no convergence in 6 driven rounds — the batch path's per-frame retention is still invisible to resolveForeign (CM holds %d of %d)", eclipseCount(cm, "mirror-relay", mint), mint)
	}
	if got := eclipseCount(cm, "mirror-relay", mint); got != mint {
		t.Errorf("CM holds %d of %d minted keys — the mirror mixed direction stalls", got, mint)
	}
	if relayMissesTotal != 0 {
		t.Errorf("%d relay misses on R's batch-path walks — the per-frame layer fallback did not resolve the origin's retained frames", relayMissesTotal)
	}
	if dirMissCM != 0 {
		t.Errorf("CM observed %d Directory misses — the origin registration is broken in this topology", dirMissCM)
	}
	if sigFailCM != 0 {
		t.Errorf("CM observed %d sig failures — the re-published per-frame envelopes do not verify", sigFailCM)
	}
}
