// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Adaptive digest wait tests (ADR-0072).
//
// The suite covers the per-pair floor, partitions, growth after late responses,
// the cap, observation decay, disabled operation, allocation behavior, and
// convergence in a six-node mesh. The timing cases use synthetic responder
// delays so they exercise the wait calculation deterministically rather than
// relying on loopback latency.
//
// The six-node cases insert 10,000 keys on one node and require every Merkle
// root to converge, with the crossover path exercised. The enabled case also
// requires a nonzero EWMA; the disabled case requires all adaptive state to
// stay zero. These are in-process convergence checks, not WAN latency
// measurements. Fast loopback responses normally complete below the wait floor
// and do not demonstrate adaptive growth (ADR-0062, ADR-0065).

import (
	"testing"
	"time"
)

// adaptiveWaitState returns the pair's EWMA and next-draw wait without the
// drain side effect of registerDigestRecv, leaving any pending deposit for the
// next round. The map read takes digestRecvMu; the field reads are race-free
// because these tests call the helper with no sweep in flight.
func adaptiveWaitState(g *Gossiper, peer [16]byte) (ewma time.Duration, wait time.Duration, ok bool) {
	g.digestRecvMu.Lock()
	w := g.digestRecv[peer]
	g.digestRecvMu.Unlock()
	if w == nil {
		return 0, 0, false
	}
	return w.ewma, g.digestWaitFor(w), true
}

// adaptiveInjectWaitState seeds the fields used by the production observation
// feeds for clamp and decay tests. It registers an absent pair through the
// normal path; no exchange has run, so there is no deposit to drain. Calls are
// isolated from sweep activity.
func adaptiveInjectWaitState(g *Gossiper, peer [16]byte, ewma time.Duration, age time.Duration) {
	g.digestRecvMu.Lock()
	w := g.digestRecv[peer]
	g.digestRecvMu.Unlock()
	if w == nil {
		w = g.registerDigestRecv(peer)
	}
	w.ewma = ewma
	w.lastObservedAt = time.Now().Add(-age)
}

// adaptiveAnyLiveEWMA reports whether any pair has a nonzero EWMA. The enabled
// six-node case requires one; the disabled case requires none because the
// observation feeds are guarded by the adaptive-wait flag.
func adaptiveAnyLiveEWMA(g *Gossiper) bool {
	g.digestRecvMu.Lock()
	defer g.digestRecvMu.Unlock()
	for _, w := range g.digestRecv {
		if w.ewma > 0 {
			return true
		}
	}
	return false
}

// TestAdaptiveDigestWait_FloorPinWithSilentPeer checks both the wait
// calculation and its effect on a draw. With no observations, digestWaitFor
// returns the configured floor. A silent peer leaves the wait at that floor,
// and the exchange waits for it before recording a timeout deferral.
func TestAdaptiveDigestWait_FloorPinWithSilentPeer(t *testing.T) {
	const floor = 50 * time.Millisecond
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: floor}, false})
	m.gA.SetDigestWaitAdaptive(true)
	m.gB.SetDigestWaitAdaptive(true)
	m.gB.disableDigestRespond.Store(true) // silent peer: no digest response arrives
	peer := m.identB.NodeID
	w := m.gA.registerDigestRecv(peer)
	if got := m.gA.digestWaitFor(w); got != floor {
		t.Fatalf("no-observation wait = %v, want configured floor %v", got, floor)
	}
	deferInsert(t, m.gA, "adaptive-floor-%04d", 0, 10)
	start := time.Now()
	deferSweepAOnly(t, m)
	elapsed := time.Since(start)
	if elapsed < floor {
		t.Fatalf("silent draw returned in %v, want at least floor %v", elapsed, floor)
	}
	if m.gA.digestDefers.Load() == 0 {
		t.Fatalf("silent draw did not record a timeout deferral")
	}
	if _, wait, ok := adaptiveWaitState(m.gA, peer); !ok || wait != floor {
		t.Fatalf("wait after silent draw = %v (ok=%v), want floor %v", wait, ok, floor)
	}
}

// TestAdaptiveDigestWait_PartitionedPeerStaysAtFloor drives three silent
// rounds. A partitioned peer produces no deposits or observations, so its wait
// must remain at the floor while each expiry still records a deferral.
func TestAdaptiveDigestWait_PartitionedPeerStaysAtFloor(t *testing.T) {
	const floor = 50 * time.Millisecond
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: floor}, false})
	m.gA.SetDigestWaitAdaptive(true)
	m.gB.SetDigestWaitAdaptive(true)
	m.gB.disableDigestRespond.Store(true) // partitioned peer: no digest response arrives
	peer := m.identB.NodeID
	deferInsert(t, m.gA, "adaptive-partition-%04d", 0, 10)
	for r := 0; r < 3; r++ {
		deferSweepAOnly(t, m)
		if _, wait, ok := adaptiveWaitState(m.gA, peer); !ok || wait != floor {
			t.Fatalf("round %d: partitioned peer wait = %v (ok=%v), want floor %v", r, wait, ok, floor)
		}
	}
	if m.gA.digestDefers.Load() == 0 {
		t.Fatalf("partition rounds did not record a timeout deferral")
	}
}

// TestAdaptiveDigestWait_DrainedObservationClimbsWait uses a synthetic
// three-second responder. The first exchange expires at the 50 ms floor. A
// later registration drains the late deposit and feeds its build-stamp span to
// the EWMA. The wait must then exceed three seconds so a subsequent exchange
// completes. Feeding only completed exchanges cannot handle this case because
// the first response always arrives after the initial floor.
func TestAdaptiveDigestWait_DrainedObservationClimbsWait(t *testing.T) {
	const floor = 50 * time.Millisecond
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: floor}, false})
	m.gA.SetDigestWaitAdaptive(true)
	m.gB.SetDigestWaitAdaptive(true)
	m.gB.digestResponderDelayMs.Store(3000)
	peer := m.identB.NodeID
	deferInsert(t, m.gA, "adaptive-climb-%04d", 0, 10)
	// The first response arrives after the 50 ms floor and cannot complete.
	deferSweepAOnly(t, m)
	if got := m.gA.digestExchCompleted.Load(); got != 0 {
		t.Fatalf("round 1 completed=%d, want 0 for a 3s response against a 50ms floor", got)
	}
	if m.gA.digestDefers.Load() == 0 {
		t.Fatalf("round 1 did not record its expected timeout deferral")
	}
	// The responder builds the deposit at request+3s. The next registration
	// drains it and feeds now-buildStamp to the EWMA. Allow 6.7s before that
	// round so the observation exceeds the responder delay.
	time.Sleep(6700 * time.Millisecond)
	deferSweepAOnly(t, m)
	time.Sleep(3400 * time.Millisecond)
	deferSweepAOnly(t, m)
	time.Sleep(3500 * time.Millisecond) // allow the next response to arrive inside the grown wait
	if got := m.gA.digestExchDrained.Load(); got < 1 {
		t.Fatalf("drained=%d, want at least 1 late deposit", got)
	}
	if got := m.gA.digestExchCompleted.Load(); got < 1 {
		t.Fatalf("completed=%d, want at least 1 after the drained observation grows the wait", got)
	}
	if _, wait, ok := adaptiveWaitState(m.gA, peer); !ok || wait <= 3*time.Second {
		t.Fatalf("observed wait = %v (ok=%v), want more than 3s", wait, ok)
	}
}

// TestAdaptiveDigestWait_ClampsAtMaxCap seeds a 40-second EWMA, whose raw wait
// is 2*40s+230ms = 80.23s. digestWaitFor must clamp it to 15 seconds, and the
// silent draw must wait for that capped interval before recording a deferral.
func TestAdaptiveDigestWait_ClampsAtMaxCap(t *testing.T) {
	const floor = 50 * time.Millisecond
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: floor}, false})
	m.gA.SetDigestWaitAdaptive(true)
	m.gB.SetDigestWaitAdaptive(true)
	m.gB.disableDigestRespond.Store(true) // silent draw exercises the capped wait before expiry
	peer := m.identB.NodeID
	adaptiveInjectWaitState(m.gA, peer, 40*time.Second, 0)
	if _, wait, ok := adaptiveWaitState(m.gA, peer); !ok || wait != digestWaitAdaptiveCap {
		t.Fatalf("wait = %v (ok=%v), want cap %v instead of raw 2*EWMA+margin", wait, ok, digestWaitAdaptiveCap)
	}
	deferInsert(t, m.gA, "adaptive-cap-%04d", 0, 10)
	start := time.Now()
	deferSweepAOnly(t, m)
	elapsed := time.Since(start)
	if elapsed < digestWaitAdaptiveCap {
		t.Fatalf("draw returned in %v, want at least cap %v", elapsed, digestWaitAdaptiveCap)
	}
	if elapsed > digestWaitAdaptiveCap+5*time.Second {
		t.Fatalf("draw took %v, exceeding cap+5s; raw 80.23s wait may not have been clamped", elapsed)
	}
	if m.gA.digestDefers.Load() == 0 {
		t.Fatalf("capped draw did not record a timeout deferral")
	}
}

// TestAdaptiveDigestWait_DecaysAndBlendsBackToFloor brackets the 60-second
// observation lifetime: a three-second EWMA still grows the wait at age 59
// seconds and is ignored at age 61 seconds. It then grows the wait with a slow
// responder, restores fast responses, and requires fresh completions to blend
// the EWMA back to the 1,500 ms floor. The 230 ms margin is below that floor.
func TestAdaptiveDigestWait_DecaysAndBlendsBackToFloor(t *testing.T) {
	const floor = 1500 * time.Millisecond
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: floor}, false})
	m.gA.SetDigestWaitAdaptive(true)
	m.gB.SetDigestWaitAdaptive(true)
	peer := m.identB.NodeID
	adaptiveInjectWaitState(m.gA, peer, 3*time.Second, 59*time.Second)
	if _, wait, ok := adaptiveWaitState(m.gA, peer); !ok || wait <= floor {
		t.Fatalf("at age 59s, wait = %v (ok=%v), want above the configured floor", wait, ok)
	}
	adaptiveInjectWaitState(m.gA, peer, 3*time.Second, 61*time.Second)
	if _, wait, ok := adaptiveWaitState(m.gA, peer); !ok || wait != floor {
		t.Fatalf("at age 61s, wait = %v (ok=%v), want floor %v after observation expiry", wait, ok, floor)
	}
	// Grow the wait with the slow responder before testing recovery.
	m.gB.digestResponderDelayMs.Store(3000)
	deferInsert(t, m.gA, "adaptive-decay-%05d", 0, 10)
	deferSweepAOnly(t, m)
	time.Sleep(6700 * time.Millisecond)
	deferSweepAOnly(t, m)
	time.Sleep(3400 * time.Millisecond)
	deferSweepAOnly(t, m)
	time.Sleep(3500 * time.Millisecond)
	if got := m.gA.digestExchCompleted.Load(); got < 1 {
		t.Fatalf("slow-responder setup did not complete an exchange before recovery (completed=%d)", got)
	}
	m.gB.digestResponderDelayMs.Store(0)
	floorReached := false
	for r := 0; r < 12 && !floorReached; r++ {
		// Insert fresh divergence so the change gate permits an exchange and
		// produces a completion sample to blend the EWMA downward.
		deferInsert(t, m.gA, "adaptive-recovery-%04d", r*10, 10)
		deferSweepRound(t, m)
		_, wait, _ := adaptiveWaitState(m.gA, peer)
		floorReached = wait == floor
	}
	if !floorReached {
		_, wait, _ := adaptiveWaitState(m.gA, peer)
		t.Fatalf("recovered responder wait = %v after 12 rounds, want floor %v", wait, floor)
	}
}

// TestAdaptiveDigestWait_DisabledKeepsFixedWaitAndCounts repeats the slow
// responder with adaptive waiting disabled, its default. Every exchange must
// expire at the fixed floor and record a deferral. Drained deposits are still
// counted, but the EWMA and calculated wait must not grow.
func TestAdaptiveDigestWait_DisabledKeepsFixedWaitAndCounts(t *testing.T) {
	const floor = 50 * time.Millisecond
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: floor}, false})
	// Leave SetDigestWaitAdaptive unset; adaptive waiting is disabled by default.
	m.gB.digestResponderDelayMs.Store(3000)
	peer := m.identB.NodeID
	deferInsert(t, m.gA, "adaptive-off-%04d", 0, 10)
	deferSweepAOnly(t, m)
	time.Sleep(6700 * time.Millisecond)
	deferSweepAOnly(t, m)
	time.Sleep(3400 * time.Millisecond)
	deferSweepAOnly(t, m)
	time.Sleep(3500 * time.Millisecond)
	if got := m.gA.digestExchCompleted.Load(); got != 0 {
		t.Fatalf("completed=%d, want 0 with adaptive waiting disabled and a 3s responder", got)
	}
	if got := m.gA.digestExchDrained.Load(); got < 1 {
		t.Fatalf("drained=%d, want at least 1; counters must work with adaptive waiting disabled", got)
	}
	if _, wait, ok := adaptiveWaitState(m.gA, peer); !ok || wait != floor {
		t.Fatalf("wait = %v (ok=%v), want fixed floor %v with adaptive waiting disabled", wait, ok, floor)
	}
	if m.gA.digestDefers.Load() == 0 {
		t.Fatalf("disabled adaptive waiting did not preserve timeout deferrals")
	}
}

// TestAdaptiveDigestWait_ZeroExtraHotPathAllocs compares per-draw allocations
// with adaptive waiting enabled and disabled. testing.AllocsPerRun counts
// process-wide allocations, including B's concurrent request parsing and
// response writes, so the comparison allows the measured common-mode residual
// rather than claiming an exact zero for the whole process.
func TestAdaptiveDigestWait_ZeroExtraHotPathAllocs(t *testing.T) {
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: 250 * time.Millisecond}, false})
	deferInsert(t, m.gA, "adaptive-alloc-%04d", 0, 10)
	deferSweepRound(t, m) // converge the pair so the measured draw follows its healthy path
	draw := func() {
		d := m.gA.generateSweepDelta(m.ctx, m.identB.NodeID)
		if d != nil {
			d.Release()
		}
	}
	// Warm both arms before measurement. testing.AllocsPerRun counts
	// process-wide allocations, including B's readLoop and responder, so a cold
	// arm can otherwise absorb unrelated initialization costs.
	const zeroAllocNoiseFloor = 2 // measured B-side residual: worst absolute delta across three characterization runs
	for i := 0; i < 300; i++ {
		draw()
	}
	allocsOff := testing.AllocsPerRun(300, draw)
	m.gA.SetDigestWaitAdaptive(true) // the test goroutine drives draws; no sweep loop runs
	for i := 0; i < 50; i++ {
		draw()
	}
	allocsOn := testing.AllocsPerRun(300, draw)
	t.Logf("per-draw allocations: disabled=%g enabled=%g", allocsOff, allocsOn)
	if d := allocsOn - allocsOff; d < -float64(zeroAllocNoiseFloor) || d > float64(zeroAllocNoiseFloor) {
		t.Fatalf("allocations enabled=%g disabled=%g (delta %g) exceed the measured +/-2 common-mode residual", allocsOn, allocsOff, d)
	}
}

// adaptiveSixNodeArc builds a six-node census mesh across three regions with
// defer, crossover, batches of 100, and a 1,500 ms wait floor. Adaptive waiting
// follows the argument. After inserting 10,000 keys on node 0, it runs
// synchronized sweeps until all sharded roots match, then settles asynchronous
// joins and checks root equality again. The caller closes the returned mesh.
func adaptiveSixNodeArc(t *testing.T, adaptive bool) (m *CensusMesh, converged bool, rounds int) {
	t.Helper()
	m = buildCensusMesh(t, 6)
	for _, nd := range m.nodes {
		nd.g.SetDeferHandler(true)
		nd.g.SetDeferCrossover(true)
		nd.g.SetBatchSize(100)
		nd.g.SetDigestWaitTimeout(1500 * time.Millisecond) // the floor
		if adaptive {
			nd.g.SetDigestWaitAdaptive(true)
		}
	}
	finishCensusMesh(t, m)
	deferInsert(t, m.nodes[0].g, "adaptive-six-%05d", 0, 10000)
	// Verify the last key before accepting root convergence; an empty source
	// would make the comparison pass without exercising replication.
	if got := m.nodes[0].engine.State().Get("adaptive-six-09999"); len(got) == 0 {
		t.Fatalf("source does not hold the last injected key")
	}
	srcRoot := m.nodes[0].engine.MerkleRootFromShards()
	for r := 1; r <= 30; r++ {
		rounds = r
		censusSweepRound(t, m, 100*time.Millisecond)
		allEq := true
		for _, nd := range m.nodes[1:] {
			if nd.engine.MerkleRootFromShards() != srcRoot {
				allEq = false
				break
			}
		}
		if allEq {
			time.Sleep(1 * time.Second) // settle the async join drain, then re-verify
			allEq = true
			for _, nd := range m.nodes[1:] {
				if nd.engine.MerkleRootFromShards() != srcRoot {
					allEq = false
					break
				}
			}
			if allEq {
				// Check a key on a non-source node as well as the roots.
				if got := m.nodes[5].engine.State().Get("adaptive-six-00042"); len(got) == 0 {
					t.Fatalf("node 5 has the source root but does not hold key 42")
				}
				return m, true, rounds
			}
		}
	}
	return m, false, rounds
}

// TestAdaptiveDigestWait_SixNodeConvergesEnabled requires all six roots to
// converge with adaptive waiting, defer, and crossover enabled. It also checks
// that node 0 used crossover shipping and recorded a nonzero EWMA on at least
// one pair, so convergence cannot hide an inactive adaptive path.
func TestAdaptiveDigestWait_SixNodeConvergesEnabled(t *testing.T) {
	m, converged, rounds := adaptiveSixNodeArc(t, true)
	defer m.close()
	if !converged {
		t.Fatalf("six nodes did not converge within %d rounds with adaptive waiting enabled", rounds)
	}
	if got := m.nodes[0].g.digestCrossoverShips.Load(); got < 1 {
		t.Fatalf("digestCrossoverShips=%d on node 0, want at least 1 to exercise crossover shipping", got)
	}
	if !adaptiveAnyLiveEWMA(m.nodes[0].g) {
		t.Fatalf("node 0 has no nonzero EWMA after enabled six-node convergence")
	}
	t.Logf("six nodes converged in %d rounds with adaptive waiting enabled", rounds)
}

// TestAdaptiveDigestWait_SixNodeConvergesDisabled runs the same six-node
// convergence path with adaptive waiting disabled. Crossover remains active,
// but every node's observation state must stay at its zero value.
func TestAdaptiveDigestWait_SixNodeConvergesDisabled(t *testing.T) {
	m, converged, rounds := adaptiveSixNodeArc(t, false)
	defer m.close()
	if !converged {
		t.Fatalf("six nodes did not converge within %d rounds with adaptive waiting disabled", rounds)
	}
	for i, nd := range m.nodes {
		if adaptiveAnyLiveEWMA(nd.g) {
			t.Fatalf("node %d has a nonzero EWMA with adaptive waiting disabled; observation feeds must remain inactive", i)
		}
	}
	t.Logf("six nodes converged in %d rounds with adaptive waiting disabled and zero EWMA state", rounds)
}
