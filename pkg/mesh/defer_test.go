// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests exercise the defer handler on a two-node loopback TLS mesh
// (ADR-0062/0063). A failure round may ship at most B_defer/s_entry, about 608
// entries, per peer. The disabled-handler control at the 10,000-key shape
// exceeds that bound and makes the assertion falsifiable.
//
// The suite covers timeout, peel-failure, and malformed-digest triggers at both
// ship paths; the empty trigger round; bounded escalation and convergence during
// keyset growth; clean-peel recovery; disabled-handler compatibility; and atomic
// publication of suspect-backoff state. The stratified fallback reporter stays
// silent on deferred triggers and retains its original disabled-mode behavior.
//
// All figures below are in-process two-node measurements, not larger-fleet
// wall-clock claims.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// DeferOpts configures the stratified anti-entropy harness from ADR-0034 with
// the defer handler, batch size, and digest wait used by these tests.
type DeferOpts struct {
	deferHandler bool
	stratified   bool
	batchSize    int
	digestWait   time.Duration
}

// DeferMesh is a two-node loopback TLS mesh with per-node stratified fallback
// reporter shims.
type DeferMesh struct {
	ctx              context.Context
	cancel           context.CancelFunc
	dir              string
	caPath           string
	identA, identB   *NodeIdentity
	engineA, engineB *eng.DeltaCRDTEngine
	recvA, recvB     *receive.Receiver
	lnA, lnB         net.Listener
	psA, psB         *PeerSet
	gA, gB           *Gossiper
	addrA, addrB     string
	wg               sync.WaitGroup
	fallbackA        atomic.Int32
	fallbackB        atomic.Int32
}

// buildDeferMesh creates a development CA, deterministic identities, separate
// engine arenas, and real TLS connections through runAcceptLoopWithPeerSet and
// Dial. Both gossipers receive the same options; mixed defer modes are outside
// this suite, and disabled-mode controls use a separate mesh.
func buildDeferMesh(t *testing.T, opts DeferOpts) *DeferMesh {
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
	m := &DeferMesh{dir: dir, caPath: caPath}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	seedA := sha256.Sum256([]byte("defer-node-A"))
	seedB := sha256.Sum256([]byte("defer-node-B"))
	if m.identA, err = NewNodeIdentity(seedA[:]); err != nil {
		t.Fatalf("NewNodeIdentity A: %v", err)
	}
	if m.identB, err = NewNodeIdentity(seedB[:]); err != nil {
		t.Fatalf("NewNodeIdentity B: %v", err)
	}
	arenaA := filepath.Join(dir, "engA")
	arenaB := filepath.Join(dir, "engB")
	if err := os.MkdirAll(arenaA, 0o755); err != nil {
		t.Fatalf("mkdir engA: %v", err)
	}
	if err := os.MkdirAll(arenaB, 0o755); err != nil {
		t.Fatalf("mkdir engB: %v", err)
	}
	// newTestEngine's 64MB test scale carries the 10K-key shapes (the
	// census ran non-hot nodes at 10K on 64MB; only ~250K needed 512MB).
	m.engineA = newTestEngine(t, m.identA.NodeID, arenaA)
	m.engineB = newTestEngine(t, m.identB.NodeID, arenaB)
	dirA := identity.NewDirectory()
	dirB := identity.NewDirectory()
	if err := dirA.Register(m.identB.NodeID, m.identB.Pub); err != nil {
		t.Fatalf("Register B in A: %v", err)
	}
	if err := dirB.Register(m.identA.NodeID, m.identA.Pub); err != nil {
		t.Fatalf("Register A in B: %v", err)
	}
	bucketA := admission.NewPeerBucket()
	capA := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), m.engineA)
	m.recvA = receive.NewReceiver(bucketA, capA, clock.NewSystemClock(), dirA, m.engineA, 50_000_000)
	bucketB := admission.NewPeerBucket()
	capB := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), m.engineB)
	m.recvB = receive.NewReceiver(bucketB, capB, clock.NewSystemClock(), dirB, m.engineB, 50_000_000)
	leafA, err := ca.IssueLeaf(identHex(m.identA.NodeID))
	if err != nil {
		t.Fatalf("IssueLeaf A: %v", err)
	}
	certPathA, keyPathA, err := leafA.WritePEM(filepath.Join(dir, "nodeA"))
	if err != nil {
		t.Fatalf("WritePEM A: %v", err)
	}
	leafB, err := ca.IssueLeaf(identHex(m.identB.NodeID))
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
	m.lnA, m.lnB = lnA, lnB
	m.addrA, m.addrB = lnA.Addr().String(), lnB.Addr().String()
	m.psA = NewPeerSet(trA, m.recvA, m.identA, m.engineA)
	m.psB = NewPeerSet(trB, m.recvB, m.identB, m.engineB)
	m.gA = NewGossiper(m.psA, m.identA, m.engineA, dirA)
	m.gB = NewGossiper(m.psB, m.identB, m.engineB, dirB)
	if err := m.gA.RegisterPeer(m.identB.NodeID, m.identB.Pub); err != nil {
		t.Fatalf("RegisterPeer A: %v", err)
	}
	if err := m.gB.RegisterPeer(m.identA.NodeID, m.identA.Pub); err != nil {
		t.Fatalf("RegisterPeer B: %v", err)
	}
	m.gA.SetStratifiedAntiEntropy(opts.stratified)
	m.gB.SetStratifiedAntiEntropy(opts.stratified)
	if opts.deferHandler {
		m.gA.SetDeferHandler(true)
		m.gB.SetDeferHandler(true)
	}
	// Count calls to the stratified fallback reporter. Deferred triggers must
	// leave it silent; disabled mode retains the original oversend report.
	m.gA.SetStratifiedFallbackReporter(func() { m.fallbackA.Add(1) })
	m.gB.SetStratifiedFallbackReporter(func() { m.fallbackB.Add(1) })
	if opts.digestWait > 0 {
		m.gA.SetDigestWaitTimeout(opts.digestWait)
		m.gB.SetDigestWaitTimeout(opts.digestWait)
	}
	if opts.batchSize > 1 {
		m.gA.SetBatchSize(opts.batchSize)
		m.gB.SetBatchSize(opts.batchSize)
	}
	m.wg.Add(2)
	// PeerSet-threaded accept loops run the challenge handshake and egress
	// verification required by ADR-0068.
	go runAcceptLoopWithPeerSet(m.ctx, m.lnA, m.recvA, m.gA, &m.wg, m.psA)
	go runAcceptLoopWithPeerSet(m.ctx, m.lnB, m.recvB, m.gB, &m.wg, m.psB)
	// Dial in one direction so the test also covers installation of the
	// accepted connection and its digest/announce routing (ADR-0068).
	if err := m.psA.Dial(m.ctx, m.addrB, "localhost", m.identB.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	asyncWait(t, m.psA, m.identB.NodeID)
	asyncWait(t, m.psB, m.identA.NodeID) // B's accept-side installation
	awaitVerified(t, m.psA, m.identB.NodeID)
	awaitVerified(t, m.psB, m.identA.NodeID)
	t.Cleanup(m.close)
	return m
}

// close cancels the mesh, closes both listeners, and waits for the accept
// loops. Engines stay open under newTestEngine's bounded test-lifetime policy.
func (m *DeferMesh) close() {
	m.cancel()
	_ = m.lnA.Close()
	_ = m.lnB.Close()
	m.wg.Wait()
}

// deferSweepRound starts both nodes' sweeps on one barrier and returns both
// states. B is A's only peer, so stA.shippedEntries is the per-peer count that
// the defer budget bounds.
func deferSweepRound(t *testing.T, m *DeferMesh) (stA, stB sweepState) {
	t.Helper()
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		stA = m.gA.AntiEntropySweep(m.ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		stB = m.gB.AntiEntropySweep(m.ctx)
	}()
	close(start)
	wg.Wait()
	time.Sleep(20 * time.Millisecond) // let async applies land (readLoop -> Join)
	return stA, stB
}

// deferSweepAOnly forces a digest timeout by sweeping A alone. When both nodes
// sweep, B's own request also satisfies A's wait channel, so disabling B's
// responses produces a peel failure rather than a timer expiry. With B's sweep
// stopped, no digest arrives and SetDigestWaitTimeout expires. The settle delay
// matches deferSweepRound so asynchronous Join calls finish before counts read.
func deferSweepAOnly(t *testing.T, m *DeferMesh) sweepState {
	t.Helper()
	stA := m.gA.AntiEntropySweep(m.ctx)
	time.Sleep(20 * time.Millisecond)
	return stA
}

// deferInsert uses InsertLocalEvents so payloadCache records every ship; a bare
// InsertLocal would leave payload misses. Constant SystemTime keeps pairwise
// skew at zero while dot counters carry causality.
//
// Raw int64(i) timestamps placed fixtures in 1970 and made batch100 reject all
// 10,000 entries during per-element reconstruction. Spreading stamps as 1.7e9+i
// also failed once B's snapshot maximum advanced past the earliest keys: 134
// low-i keys became unjoinable under the skew bound. The constant realistic
// stamp avoids both harness artifacts without weakening production admission.
func deferInsert(t *testing.T, g *Gossiper, fmtName string, first, n int) {
	t.Helper()
	for i := first; i < first+n; i++ {
		g.InsertLocalEvents(fmt.Sprintf(fmtName, i), "v", eng.CRDTEntry{SystemTime: 1_700_000_000})
	}
}

// deferCountPresent counts how many of names the engine currently holds
// (the exact, shape-independent presence check — State().Get per name; the
// cardinality helper is capped at 1000).
func deferCountPresent(t *testing.T, e *eng.DeltaCRDTEngine, fmtName string, first, n int) int {
	t.Helper()
	st := e.State()
	present := 0
	for i := first; i < first+n; i++ {
		if got := st.Get(fmt.Sprintf(fmtName, i)); len(got) > 0 {
			present++
		}
	}
	return present
}

// deferConverged compares sharded Merkle roots without materializing a merged
// view (ADR-0044).
func deferConverged(m *DeferMesh) bool {
	return m.engineA.MerkleRootFromShards() == m.engineB.MerkleRootFromShards()
}

// deferDrain polls sharded roots until the asynchronous join backlog drains or
// deadline expires. Publishing is synchronous on the sweep goroutine, but each
// frame's Ed25519 verification and Join runs on readLoop: about 60µs on 32 cores
// and several times longer on four. A 600-entry burst therefore exceeds the 20ms
// settle; one immediate count saw 437 published but unjoined keys. Polling avoids
// State(), whose merged arena copy can exhaust the test arena.
func deferDrain(t *testing.T, m *DeferMesh, deadline time.Duration) bool {
	t.Helper()
	quit := time.Now().Add(deadline)
	for time.Now().Before(quit) {
		if deferConverged(m) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return deferConverged(m)
}

// TestDeferNODUMP bounds each failure-triggered round at B_defer/s_entry,
// approximately 608 received entries per peer. The disabled control ships the
// full keyset and proves that bound can fail. Cases cover digest timeout,
// oversaturated peel failure, and injected nil digests at batch sizes 1 and 100;
// both shipDelta and shipBatchedDelta must use the same window.
func TestDeferNODUMP(t *testing.T) {
	const (
		deferBaseKeys       = 100
		deferDivergenceKeys = 10000 // the 10K shape: A's S = 10,100
		// deferRoundLimit covers two defers, the count round, and the exact
		// ceil(10,200/405)=26 slice rounds needed when each window advances by W,
		// plus closing slack. The nil-digest arm cannot finish with a clean peel,
		// so this budget must be sufficient through ring rotation alone.
		deferRoundLimit = 40
	)
	// armFn installs the trigger. A nil roundFn uses synchronized sweeps; the
	// timeout case supplies an A-only driver so no peer request satisfies the wait.
	runArm := func(t *testing.T, batchSize int, armFn func(m *DeferMesh), roundFn func(t *testing.T, m *DeferMesh, r int) (sweepState, sweepState)) {
		// Under -race, serialized Ed25519 verification measured 12–14 frames/s
		// on four cores and about 165/s on 64 under test load. A 10,100-frame
		// convergence would need 20–60 minutes. The batch100 arm amortizes one
		// signature across 100 entries and retains the 10,000-key race coverage;
		// per-frame 10,000-key arms run without the race detector.
		if deferRaceEnabled && batchSize == 1 {
			t.Skip("defer no-dump: skipping 10,000-key per-frame convergence under -race: serialized verification (~12-165 frames/s) requires 20-60+ minutes; the batched 10,000-key arm and small-shape tests still run, and non-race per-frame arms complete in 8.6s")
		}
		// Use a 250ms digest wait. A 50ms bound can expire while the peer is still
		// building and marshaling its O(state) IBLT under load or the race detector,
		// turning healthy exchanges into spurious timeout defers.
		m := buildDeferMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: batchSize, digestWait: 250 * time.Millisecond})
		// SetLamportAbsoluteSlack models a warm peer without widening production
		// admission (ADR-0045 §7). A's 10,000-key fixture reaches dot counters near
		// 10,100 while B starts near 100. Per-frame joins advance B's Lamport clock
		// after each verification (ADR-0067), but the batch cheap gate cannot feed
		// per-element counters to Admit. A cold batch receiver therefore stalled at
		// 1,630 of 10,000 entries when L+1000 rejected higher counters.
		m.engineA.SetLamportAbsoluteSlack(eng.LamportSkewAbsoluteSlackUnbounded)
		m.engineB.SetLamportAbsoluteSlack(eng.LamportSkewAbsoluteSlackUnbounded)
		deferInsert(t, m.gA, "defer-base-%d", 0, deferBaseKeys)
		deferInsert(t, m.gB, "defer-base-%d", 0, deferBaseKeys)
		deferInsert(t, m.gA, "defer-divergence-%d", 0, deferDivergenceKeys)
		armFn(m)
		var perRound []int
		converged := false
		for r := 1; r <= deferRoundLimit; r++ {
			defA, defB := m.gA.digestDefers.Load(), m.gB.digestDefers.Load()
			var stA, stB sweepState
			if roundFn == nil {
				stA, stB = deferSweepRound(t, m)
			} else {
				stA, stB = roundFn(t, m, r)
			}
			perRound = append(perRound, stA.shippedEntries, stB.shippedEntries)
			// Bound only failure-triggered rounds. A clean peel ships the true diff,
			// structurally below the approximately 750-entry IBLT saturation point,
			// and must not be capped. One clean round legitimately shipped a 649-entry
			// tail; applying the failure cap to it would reject correct behavior.
			if m.gA.digestDefers.Load() > defA && stA.shippedEntries > deferSliceMaxEntries {
				t.Fatalf("defer no-dump: round %d on A shipped %d entries above cap %d after a digest failure (batch=%d, per-round=%v)", r, stA.shippedEntries, deferSliceMaxEntries, batchSize, perRound)
			}
			if m.gB.digestDefers.Load() > defB && stB.shippedEntries > deferSliceMaxEntries {
				t.Fatalf("defer no-dump: round %d on B shipped %d entries above cap %d after a digest failure (batch=%d, per-round=%v)", r, stB.shippedEntries, deferSliceMaxEntries, batchSize, perRound)
			}
			if m.fallbackA.Load() != 0 || m.fallbackB.Load() != 0 {
				t.Fatalf("defer no-dump: stratified fallback reporter fired on a deferred round (A=%d B=%d), but no oversend shipped", m.fallbackA.Load(), m.fallbackB.Load())
			}
			if deferConverged(m) {
				converged = true
				break
			}
		}
		// The 20ms settle cannot cover a 600-frame verification backlog on four
		// cores. deferDrain allows that asynchronous work to finish before judging
		// convergence.
		if !converged {
			converged = deferDrain(t, m, 10*time.Second)
		}
		if m.gA.digestDefers.Load() == 0 {
			t.Fatalf("defer no-dump: digestDefers stayed zero (batch=%d), so the failure never entered the defer path", batchSize)
		}
		if m.gA.digestDeferEscalations.Load() == 0 {
			t.Fatalf("defer no-dump: digestDeferEscalations stayed zero (batch=%d), so no bounded slice shipped", batchSize)
		}
		if !converged {
			t.Fatalf("defer no-dump: not converged after %d rounds (batch=%d, per-round=%v, B holds %d/%d divergence keys); bounded escalation starved", deferRoundLimit, batchSize, perRound, deferCountPresent(t, m.engineB, "defer-divergence-%d", 0, deferDivergenceKeys), deferDivergenceKeys)
		}
		if got := deferCountPresent(t, m.engineB, "defer-divergence-%d", 0, deferDivergenceKeys); got != deferDivergenceKeys {
			t.Fatalf("defer no-dump: roots converged but B holds %d/%d divergence keys", got, deferDivergenceKeys)
		}
		t.Logf("defer no-dump: batch=%d per-round=%v defers=%d escalations=%d; B holds all %d divergence keys", batchSize, perRound, m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load(), deferDivergenceKeys)
	}
	// In synchronized rounds, B's request satisfies A's wait just like a response,
	// so the 10,000-key divergence produces peel failures instead of timeouts; peel
	// failure is nearly certain past D≈900. The timeout arm sweeps A alone until B
	// has every divergence key, then restores responses for synchronized closing
	// rounds. Cumulative shipped keys choose the transition because roots cannot
	// match while A still lacks B's base dots.
	t.Run("peel-failure-per-frame", func(t *testing.T) {
		runArm(t, 1, func(m *DeferMesh) {}, nil)
	})
	t.Run("peel-failure-batched", func(t *testing.T) {
		runArm(t, 100, func(m *DeferMesh) {}, nil)
	})
	t.Run("nil-digest-per-frame", func(t *testing.T) {
		runArm(t, 1, func(m *DeferMesh) { m.gA.nilDigestBugInject.Store(true) }, nil)
	})
	t.Run("timeout-single-sweep-per-frame", func(t *testing.T) {
		// Track cumulative A-shipped entries instead of calling State(): each call
		// materializes an arena-backed merged copy, and about 20 copies exhausted
		// the 64 MB test arena. During A-only sweeps no foreign entries join A, so
		// reaching the self-keyset count is the exact transition signal. Closing
		// clean diffs cover any asynchronous joins still behind.
		shippedSelf := 0
		sweep := func(t *testing.T, m *DeferMesh, r int) (sweepState, sweepState) {
			if shippedSelf < deferBaseKeys+deferDivergenceKeys {
				stA := deferSweepAOnly(t, m)
				shippedSelf += stA.shippedEntries
				return stA, sweepState{}
			}
			m.gB.disableDigestRespond.Store(false)
			return deferSweepRound(t, m)
		}
		runArm(t, 1, func(m *DeferMesh) { m.gB.disableDigestRespond.Store(true) }, sweep)
	})

	// The disabled control repeats the A-only timeout. Its first round ships the
	// full keyset, reports stratified fallback, and leaves defer counters at zero,
	// demonstrating both the bound and the original behavior. B never ships, so A
	// holds only self entries and the expected count is deterministic.
	t.Run("disabled-control-full-keyset", func(t *testing.T) {
		m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 50 * time.Millisecond})
		deferInsert(t, m.gA, "defer-base-%d", 0, deferBaseKeys)
		deferInsert(t, m.gB, "defer-base-%d", 0, deferBaseKeys)
		deferInsert(t, m.gA, "defer-divergence-%d", 0, deferDivergenceKeys)
		m.gB.disableDigestRespond.Store(true)
		stA := deferSweepAOnly(t, m)
		if stA.shippedEntries != deferBaseKeys+deferDivergenceKeys {
			t.Fatalf("defer disabled control: round 1 shipped %d entries, want the full self keyset %d above cap %d", stA.shippedEntries, deferBaseKeys+deferDivergenceKeys, deferSliceMaxEntries)
		}
		if m.fallbackA.Load() == 0 {
			t.Fatalf("defer disabled control: stratified fallback reporter stayed silent during the original full-keyset fallback")
		}
		if m.gA.digestDefers.Load() != 0 || m.gA.digestDeferEscalations.Load() != 0 {
			t.Fatalf("defer disabled control: defer counters changed (defers=%d escalations=%d), want no defer state activity", m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load())
		}
		t.Logf("defer disabled control: shipped %d entries above cap %d with %d stratified fallback reports", stA.shippedEntries, deferSliceMaxEntries, m.fallbackA.Load())
	})
}

// TestDeferWindow verifies that a trigger round sends only the approximately
// 65-byte root announce, not a delta. After responses resume, the mismatched
// root reopens the change gate and the next exchange delivers the diff.
func TestDeferWindow(t *testing.T) {
	const deferDivergenceKeys = 10
	// The post-trigger clean exchange needs B's request delivered within the
	// digest wait. A 50ms bound raced readLoop on a loaded four-core machine;
	// 250ms leaves room without affecting the unanswered trigger round.
	m := buildDeferMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	deferInsert(t, m.gA, "defer-base-%d", 0, 10)
	deferInsert(t, m.gB, "defer-base-%d", 0, 10)
	deferInsert(t, m.gA, "defer-window-divergence-%d", 0, deferDivergenceKeys)
	// Sweep A alone so its unanswered request expires. With both nodes sweeping,
	// B's request would satisfy A's wait and this 20-key diff would peel cleanly
	// instead of triggering a defer.
	m.gB.disableDigestRespond.Store(true)
	stA1 := deferSweepAOnly(t, m)
	// The trigger round sends no delta or entries frame; the root announce is
	// not a delta. B is A's only peer, so the sweep state is the per-peer count.
	if stA1.shippedEntries != 0 || stA1.shippedEnvelopes != 0 {
		t.Fatalf("defer window: trigger round shipped entries=%d envelopes=%d, want none; the root announce is not a delta", stA1.shippedEntries, stA1.shippedEnvelopes)
	}
	if got := deferCountPresent(t, m.engineB, "defer-window-divergence-%d", 0, deferDivergenceKeys); got != 0 {
		t.Fatalf("defer window: B received %d divergence keys on the trigger round — the window must be empty this round", got)
	}
	if m.gA.digestDefers.Load() != 1 {
		t.Fatalf("defer window: digestDefers=%d after the trigger round, want exactly 1 (one timeout defer; a gated/deferred accounting bug)", m.gA.digestDefers.Load())
	}
	if m.fallbackA.Load() != 0 {
		t.Fatalf("defer window: stratified fallback reporter fired on a deferred round (fallback=%d), want no oversend report", m.fallbackA.Load())
	}
	// Restoring responses lets the next mismatched-root exchange complete and
	// deliver the diff.
	m.gB.disableDigestRespond.Store(false)
	stA2, _ := deferSweepRound(t, m)
	if stA2.shippedEntries == 0 {
		t.Fatalf("defer window: the round after the trigger shipped nothing — the change-gate must re-fire on the still-mismatched root and the exchange must complete (the peer would starve)")
	}
	// Serialized verification measured about 165 frames/s under -race and test
	// load, so shipped frames can arrive after the 20ms settle; one immediate
	// count held 9 of 10 keys. A bounded drain still fails if Publish never sent
	// the entries, because TCP can deliver only what Publish accepted.
	if !deferDrain(t, m, 5*time.Second) {
		t.Fatalf("defer window: the roots did not converge within the bounded join drain — the re-fired exchange did not deliver the diff (B holds %d/%d)", deferCountPresent(t, m.engineB, "defer-window-divergence-%d", 0, deferDivergenceKeys), deferDivergenceKeys)
	}
	if got := deferCountPresent(t, m.engineB, "defer-window-divergence-%d", 0, deferDivergenceKeys); got != deferDivergenceKeys {
		t.Fatalf("defer window: B holds %d/%d divergence keys after the post-trigger exchange — the re-fired exchange did not deliver the diff", got, deferDivergenceKeys)
	}
	if m.gA.digestDefers.Load() != 1 {
		t.Fatalf("defer window: digestDefers=%d after the clean round, want still 1 — a clean exchange neither defers nor re-defers (the trigger-path accounting double-counted)", m.gA.digestDefers.Load())
	}
	t.Logf("defer window: trigger round shipped 0, next round shipped %d and B holds all %d — both halves hold", stA2.shippedEntries, deferDivergenceKeys)
}

// TestDeferEscalation checks bounded slices after three consecutive defers and
// convergence within bounded rounds, including 200 inserts during escalation.
// Fixed ring positions cover new keys; a static-prefix cap would starve them.
// The budget is two empty defers, one count round, ceil(S/608) ship rounds, and
// growth slack on the in-process two-node mesh (ADR-0062/0065).
func TestDeferEscalation(t *testing.T) {
	const (
		deferBaseKeys       = 100
		deferDivergenceKeys = 2000 // A's S = 2100 -> ceil(2100/608) = 4 ship rounds
		deferGrowthKeys     = 200  // the interleaved insert at round 6 (mid-escalation)
		deferRoundLimit     = 20   // 2 defers + count + 4 ships + a growth sweep + slack
	)
	m := buildDeferMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	// A 50ms digest wait can expire before an O(state) IBLT response under -race,
	// repeatedly deferring the small clean diff. Use 250ms as in the window and
	// recovery tests.
	//
	// Unbounded Lamport slack again models a warm receiver. A's dots reach about
	// 2,300 while B starts near 100, and hash-ring order is not counter order.
	// Without the knob, early high-counter frames exceed L+slack until B catches
	// up; race-detector runs left 32 keys missing after the clean-peel tail, with
	// 26 missing in a reproduction outside the race detector.
	m.engineA.SetLamportAbsoluteSlack(eng.LamportSkewAbsoluteSlackUnbounded)
	m.engineB.SetLamportAbsoluteSlack(eng.LamportSkewAbsoluteSlackUnbounded)
	deferInsert(t, m.gA, "defer-base-%d", 0, deferBaseKeys)
	deferInsert(t, m.gB, "defer-base-%d", 0, deferBaseKeys)
	deferInsert(t, m.gA, "defer-escalation-divergence-%d", 0, deferDivergenceKeys)
	// The 2,000-key divergence guarantees peel failure because D≈2,100 is far
	// above the approximately 750-entry saturation point. Slices shrink the diff
	// until a clean round finishes the tail. No responder fault is needed; B's
	// request would satisfy A's wait in synchronized rounds.
	var perRound []int
	converged := false
	rounds := 0
	for r := 1; r <= deferRoundLimit; r++ {
		if r == 6 {
			// The growth wave: 200 fresh keys inserted mid-escalation. The
			// walk's count adapts (sEst), each new key keeps its fixed ring
			// position, and the sweep covers them — or this guard fails.
			deferInsert(t, m.gA, "defer-escalation-divergence-%d", deferDivergenceKeys, deferGrowthKeys)
		}
		defA, defB := m.gA.digestDefers.Load(), m.gB.digestDefers.Load()
		stA, stB := deferSweepRound(t, m)
		rounds = r
		perRound = append(perRound, stA.shippedEntries)
		// Only trigger rounds use the 608-entry cap. A clean peel finishes with
		// the true diff, already below the approximately 750-entry saturation
		// point, and is not subject to that failure-path bound.
		if m.gA.digestDefers.Load() > defA && stA.shippedEntries > deferSliceMaxEntries {
			t.Fatalf("defer escalation: round %d triggered on A and shipped %d > cap %d — a failure path dumped (per-round=%v)", r, stA.shippedEntries, deferSliceMaxEntries, perRound)
		}
		if m.gB.digestDefers.Load() > defB && stB.shippedEntries > deferSliceMaxEntries {
			t.Fatalf("defer escalation: round %d triggered on B and shipped %d > cap %d — a failure path dumped (per-round=%v)", r, stB.shippedEntries, deferSliceMaxEntries, perRound)
		}
		if r < deferEscalationRounds && stA.shippedEntries != 0 {
			t.Fatalf("defer escalation: round %d (before N=%d) shipped %d — the defer rounds 1..N-1 must ship nothing", r, deferEscalationRounds, stA.shippedEntries)
		}
		if deferConverged(m) {
			converged = true
			break
		}
	}
	// Growth bursts create a verification backlog that the settles cannot cover.
	// At the measured 12–14 frames/s on four cores under -race, 2,300 frames need
	// about 190 seconds. S×150ms leaves room for that work while remaining bounded.
	// A rotation defect still fails: no amount of draining can deliver frames that
	// were never shipped.
	escDrainCap := time.Duration(deferDivergenceKeys+deferGrowthKeys) * 150 * time.Millisecond
	if !converged {
		converged = deferDrain(t, m, escDrainCap)
	}
	if !converged {
		t.Fatalf("defer escalation: not converged in %d rounds + drain (per-round=%v; B holds %d/%d keys) — the escalation starved the tail (ADR-0062/ADR-0065: in-process 2-node shape)", rounds, perRound, deferCountPresent(t, m.engineB, "defer-escalation-divergence-%d", 0, deferDivergenceKeys+deferGrowthKeys), deferDivergenceKeys+deferGrowthKeys)
	}
	// Check exact key presence, including the growth wave, rather than relying
	// on equal roots alone.
	if got := deferCountPresent(t, m.engineB, "defer-escalation-divergence-%d", 0, deferDivergenceKeys+deferGrowthKeys); got != deferDivergenceKeys+deferGrowthKeys {
		t.Fatalf("defer escalation: converged but B holds %d/%d divergence keys — the rotation did not cover the keyset", got, deferDivergenceKeys+deferGrowthKeys)
	}
	t.Logf("defer escalation: converged all %d keys in %d escalation-bounded rounds (per-round=%v) including the 200-key mid-escalation growth wave", deferDivergenceKeys+deferGrowthKeys, rounds, perRound)
}

// TestDeferRecovery checks that only a clean peel resets consecutive, while a
// change-gated round leaves it unchanged and imposes no lasting penalty. D=10
// makes a clean peel nearly certain; the analytic failure floor is about 0.02%.
func TestDeferRecovery(t *testing.T) {
	const deferDivergenceKeys = 10
	// Round 2 needs B's request delivered before the clean-peel reset. A 50ms
	// wait raced a loaded four-core readLoop and left consecutive=2 after another
	// timeout; 250ms avoids that harness timing failure. Round 1 is unanswered and
	// still expires regardless of the larger bound.
	m := buildDeferMesh(t, DeferOpts{deferHandler: true, stratified: true, batchSize: 1, digestWait: 250 * time.Millisecond})
	deferInsert(t, m.gA, "defer-base-%d", 0, 10)
	deferInsert(t, m.gB, "defer-base-%d", 0, 10)
	deferInsert(t, m.gA, "defer-recovery-divergence-%d", 0, deferDivergenceKeys)
	// Round 1 sweeps A alone so the wait expires into exactly one defer. A
	// synchronized round would clean-peel the 20-key diff instead.
	m.gB.disableDigestRespond.Store(true)
	deferSweepAOnly(t, m) // round 1: digest timeout defer
	if c := m.gA.deferState[m.identB.NodeID].consecutive; c != 1 {
		t.Fatalf("defer recovery: after one trigger round consecutive=%d, want 1 — the defer accounting is wrong (defers=%d)", c, m.gA.digestDefers.Load())
	}
	// Round 2 restores responses. The real diff clean-peels, resets the counter,
	// and ships normally without another defer or escalation.
	m.gB.disableDigestRespond.Store(false)
	stA2, _ := deferSweepRound(t, m)
	if c := m.gA.deferState[m.identB.NodeID].consecutive; c != 0 {
		t.Fatalf("defer recovery: clean peel left consecutive=%d, want 0", c)
	}
	if stA2.shippedEntries == 0 {
		t.Fatalf("defer recovery: the post-trigger clean round shipped nothing — the recovering peer must receive its diff normally (no defer, no escalation stall)")
	}
	defersAfter := m.gA.digestDefers.Load()
	// Equal roots enable change-gate skips only after A's readLoop processes B's
	// announce; a one-round lag is normal because peerRoots updates asynchronously.
	// Every round polled during that lag must still leave defer state unchanged.
	skipsBefore := m.gA.digestGateSkips.Load()
	var stA3 sweepState
	// Drive sweeps until the skip counter advances, with a 60-second deadline
	// (ADR-0070). A fixed five-round poll guessed when the asynchronous announce
	// would land and could fail under load. The deadline bounds waiting while each
	// polled round continues to assert unchanged consecutive and defer counters.
	pollDL := time.Now().Add(60 * time.Second)
	skipped := false
	for !skipped {
		if time.Now().After(pollDL) {
			t.Fatalf("defer recovery: change gate did not skip the converged pair within 60s (skips %d -> %d, rootA=%x rootB=%x)", skipsBefore, m.gA.digestGateSkips.Load(), m.engineA.MerkleRootFromShards(), m.engineB.MerkleRootFromShards())
		}
		stA3, _ = deferSweepRound(t, m)
		if c := m.gA.deferState[m.identB.NodeID].consecutive; c != 0 {
			t.Fatalf("defer recovery: a gated round moved the counter to %d — a gated round is a no-op (neither increments nor resets)", c)
		}
		if m.gA.digestDefers.Load() != defersAfter {
			t.Fatalf("defer recovery: a gated round advanced digestDefers (%d -> %d) — the gate-continue precedes the exchange entirely; a gated round must never touch the defer state", defersAfter, m.gA.digestDefers.Load())
		}
		if m.gA.digestGateSkips.Load() > skipsBefore {
			skipped = true
		}
	}
	t.Logf("defer recovery: one defer reset to 0 after clean peel and stayed 0 through gated rounds (skips %d->%d, last round shipped %d; 60s poll deadline)", skipsBefore, m.gA.digestGateSkips.Load(), stA3.shippedEntries)
}

// TestDeferOffByteIdentical verifies disabled-mode compatibility. The clean
// stratified path converges without touching defer state. A digest timeout then
// reports stratified fallback and ships the exact full keyset as before.
func TestDeferOffByteIdentical(t *testing.T) {
	const (
		deferBaseKeys       = 10
		deferDivergenceKeys = 10
	)
	// The clean path enables stratified anti-entropy and disables the defer handler.
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 200 * time.Millisecond})
	deferInsert(t, m.gA, "defer-base-%d", 0, deferBaseKeys)
	deferInsert(t, m.gB, "defer-base-%d", 0, deferBaseKeys)
	deferInsert(t, m.gA, "defer-disabled-divergence-%d", 0, deferDivergenceKeys)
	converged := false
	rounds := 0
	for r := 1; r <= 10; r++ {
		deferSweepRound(t, m)
		rounds = r
		if deferConverged(m) {
			converged = true
			break
		}
	}
	if !converged {
		t.Fatalf("defer disabled: no convergence in <=10 rounds (rounds=%d); the clean stratified path changed", rounds)
	}
	if got := deferCountPresent(t, m.engineB, "defer-disabled-divergence-%d", 0, deferDivergenceKeys); got != deferDivergenceKeys {
		t.Fatalf("defer disabled: converged but B holds %d/%d divergence keys (a join bug, not a wiring bug)", got, deferDivergenceKeys)
	}
	if m.gA.digestDefers.Load() != 0 || m.gA.digestDeferEscalations.Load() != 0 || m.fallbackA.Load() != 0 {
		t.Fatalf("defer disabled: the clean-path run touched the defer/fallback counters (defers=%d esc=%d fallback=%d) — with no trigger and the handler off they must all stay zero", m.gA.digestDefers.Load(), m.gA.digestDeferEscalations.Load(), m.fallbackA.Load())
	}
	if m.gA.deferState != nil {
		t.Fatalf("defer disabled: the defer map was allocated with the handler off — the off path must never allocate defer state")
	}
	// The trigger path uses the same disabled configuration with an A-only digest
	// timeout. It reports fallback and ships exactly 20 self entries: ten base keys
	// plus ten divergent keys over the live loopback connection.
	m2 := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 50 * time.Millisecond})
	deferInsert(t, m2.gA, "defer-base-%d", 0, deferBaseKeys)
	deferInsert(t, m2.gB, "defer-base-%d", 0, deferBaseKeys)
	deferInsert(t, m2.gA, "defer-disabled-divergence-%d", 0, deferDivergenceKeys)
	m2.gB.disableDigestRespond.Store(true)
	stA := deferSweepAOnly(t, m2)
	if stA.shippedEntries != deferBaseKeys+deferDivergenceKeys {
		t.Fatalf("defer disabled: the off trigger round shipped %d entries, want the exact full keyset %d — the off path must keep the base dump behavior", stA.shippedEntries, deferBaseKeys+deferDivergenceKeys)
	}
	if m2.fallbackA.Load() == 0 {
		t.Fatalf("defer disabled: fallback reporter stayed silent on the trigger path, want the original oversend report")
	}
	if m2.gA.digestDefers.Load() != 0 || m2.gA.deferState != nil {
		t.Fatalf("defer disabled: the off trigger path touched the defer state (defers=%d map=%v) — the off path must never defer", m2.gA.digestDefers.Load(), m2.gA.deferState != nil)
	}
	t.Logf("defer disabled: clean path converged in %d rounds; trigger path emitted %d fallback reports and shipped %d entries", rounds, m2.fallbackA.Load(), stA.shippedEntries)
}

// TestDAOSuspectStoreAtomic checks that markSuspect publishes skipUntil with
// the suspect entry under ps.mu. Storing after Unlock would let
// evictExpiredSuspectsLocked remove the new zero-valued entry before the store,
// losing the mark. Concurrent mutations exercise the race detector; dropping
// the store in a negative control makes the assertion fail even though the 2–5ns
// window is too small to schedule deterministically.
func TestDAOSuspectStoreAtomic(t *testing.T) {
	m := buildDeferMesh(t, DeferOpts{deferHandler: false, stratified: true, batchSize: 1, digestWait: 50 * time.Millisecond})
	defer m.close() // also registered via t.Cleanup; the double close is idempotent by ctx
	ps := m.psA
	ps.SetSuspectBackoff(time.Hour)
	// The invariant: a completed mark is immediately visible armed
	// (publication and arming are one atomic step under ps.mu).
	ps.markSuspect("defer-suspect-key")
	v, ok := danSuspectUntil(t, ps, "defer-suspect-key")
	if !ok || v <= 0 {
		t.Fatalf("suspect atomicity: after markSuspect returned, the entry is present=%v skipUntil=%d — a completed mark must be visible armed (the publish/arming gap, the suspect breaker)", ok, v)
	}
	// Concurrent marks on one key race another goroutine's eviction-driving marks;
	// every markSuspect calls evictExpiredSuspectsLocked first. If publication and
	// arming were separate, a sweep could observe skipUntil=0 and delete the fresh
	// entry. Each goroutine performs 20,000 iterations under the race detector.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20000; i++ {
			ps.markSuspect("defer-suspect-key")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20000; i++ {
			ps.markSuspect("defer-eviction-driver") // the evict driver: every mark sweeps the map
		}
	}()
	wg.Wait()
	v, ok = danSuspectUntil(t, ps, "defer-suspect-key")
	if !ok || v <= 0 {
		t.Fatalf("suspect atomicity: after 20k concurrent marks, the entry is present=%v skipUntil=%d — a mark was lost (publication without arming; the suspect breaker)", ok, v)
	}
	t.Logf("suspect atomicity: markSuspect publishes and arms atomically — the invariant held under 40k concurrent mutations")
}
