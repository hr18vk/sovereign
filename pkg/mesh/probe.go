// Package mesh — probe.go is the convergence-after-heal probe: a COMPOSER of
// the Day-2 PeerSet/Gossiper + Day-3 convergence-lag machinery that proves a
// 2-node mesh heals a network partition and re-converges to equal MerkleRoot()
// inside a wall-clock SLO an operator reads from /metrics.
//
// The probe does NOT reimplement the sweep (it STARTS the Day-2 SweepLoop at
// the tick arg) NOR convergence detection (it reads MerkleRoot directly via
// engine.State().MerkleRoot() — the SAME path the Day-3 gauge seeds from via
// stampConvergence). It does NOT touch the FROZEN receive gate stack: a frame
// that arrives after heal STILL flows HandleFrame -> VerifyCRDTFrame ->
// ApplyCRDTDeltaEvent. The partition is at the TRANSPORT layer
// (PeerSet.ClosePeer), NOT the receive gate.
//
// THE SLO CLOCK (the §0 three facts, recorded in ADR-0009):
//   - FACT 1: the <100ms SLO decomposes as sweep-wait + (RTT + IBLT-peel + apply).
//     The sweep-wait is a UNIFORM [0, tick) random variable with worst-case =
//     tick. At --gossip-tick=50ms the worst-case sweep-wait is 50ms; at the
//     100ms default the SLO is EXHAUSTED by the tick alone. WaitForConvergence
//     therefore takes the tick as an arg and the gate HARDCODES 50ms (the §0
//     FACT-1 fixture — a test precondition, NOT a hidden assumption).
//   - FACT 2: the SLO clock starts at RESTORE-OF-CONNECTIVITY (healAt — the
//     re-dial returning), NOT at the SG-CLI-return. The silicon harness excludes
//     AWS control-plane latency; the in-process probe has no SG layer, so
//     healAt IS the connectivity-restored timestamp. The wall-clock the probe
//     returns is time.Since(healAt).
//   - FACT 3 (SCISSORS): the in-process probe runs over loopback TLS (RTT
//     ~10us, NOT the ~0.3-1.0ms of intra-AZ). It proves the CONVERGENCE
//     PROPERTY (the mesh heals + roots equal + the 50ms tick fires the sweep +
//     the latency is bounded by the tick not the apply), NOT the silicon
//     <100ms number. The gate's t.Logf records this boundary honestly.
package mesh

import (
	"context"
	"errors"
	"time"

	eng "github.com/hr18vk/supremum/pkg/sync"
)

// ErrSLONotMet is returned by WaitForConvergence when the ctx deadline elapses
// before the two engines' MerkleRoots equal. It carries the measured wall-clock
// from healAt so the gate records the honest number (ACCEPTED-with-NEGATIVE-perf
// when roots converge but the SLO is exceeded — a real finding, NOT a defect).
var ErrSLONotMet = errors.New("mesh: convergence-after-heal SLO not met before ctx deadline")

// ConvergenceProbe composes two in-process Gossipers (gA, gB) over their
// PeerSets + engines and drives a partition/heal/converge sequence against a
// single peer. It is the in-process survival gate: a mesh that loses data on
// partition FAILS the engine's reason to exist; the probe PROVES it does not
// (CRDT idempotency: the divergence A injects while partitioned is REPLICATED
// to B after heal via the IBLT-delta Join — zero data loss by construction).
//
// The probe stores the two dial addresses so Heal can re-Dial both sides
// (PeerSet.Dial is the existing re-dial seam; the probe composes it, it does
// NOT add a Heal method to PeerSet). The peerID is the remote's CRDT-delta
// signing nodeID (the same [16]byte the PeerSet keys its peers map by).
type ConvergenceProbe struct {
	gA      *Gossiper
	gB      *Gossiper
	psA     *PeerSet
	psB     *PeerSet
	engine  *eng.DeltaCRDTEngine // A's engine (MerkleRoot source for the A side)
	engineB *eng.DeltaCRDTEngine // B's engine (MerkleRoot source for the B side)
	// addrA/addrB are the loopback TLS listener addresses; Heal re-Dials the
	// OTHER side from each (A dials addrB, B dials addrA) — the bidirectional
	// heal that mirrors the bidirectional Partition.
	addrA string
	addrB string
	// peerA/peerB are the two nodeIDs (A's and B's); Partition/Heal close +
	// re-dial the peer each side sees (A's peer is B's nodeID and vice versa).
	peerA [16]byte
	peerB [16]byte

	// partitionAt is when Partition closed the conns; healAt is when Heal's
	// re-dial returned (the SLO clock start — FACT 2). WaitForConvergence
	// returns time.Since(healAt).
	partitionAt time.Time
	healAt      time.Time
}

// NewConvergenceProbe binds the two Gossipers + PeerSets + engines + the two
// loopback addresses + the two nodeIDs. The caller (the gate) has ALREADY
// dialed both sides and registered the peer pubkeys (the Day-2 harness shape);
// the probe takes ownership of the partition/heal/converge sequence only.
func NewConvergenceProbe(gA, gB *Gossiper, psA, psB *PeerSet, engineA, engineB *eng.DeltaCRDTEngine, addrA, addrB string, peerA, peerB [16]byte) *ConvergenceProbe {
	return &ConvergenceProbe{
		gA:      gA,
		gB:      gB,
		psA:     psA,
		psB:     psB,
		engine:  engineA,
		engineB: engineB,
		addrA:   addrA,
		addrB:   addrB,
		peerA:   peerA,
		peerB:   peerB,
	}
}

// Partition closes ONE peer's conn on BOTH PeerSets (A closes its conn to B, B
// closes its conn to A — a bidirectional partition). It is the per-peer
// transport-layer partition primitive: a frame A ships to B after Partition
// fails to reach B (the conn is closed); B's sweep to A likewise stalls. The
// FROZEN receive gate stack is NEVER bypassed — a frame that arrives after
// heal STILL flows HandleFrame -> VerifyCRDTFrame -> ApplyCRDTDeltaEvent.
// Records partitionAt (the divergence-injection window starts here).
func (p *ConvergenceProbe) Partition(ctx context.Context, peerID [16]byte) error {
	// Bidirectional: A closes its conn to peerID, B closes its conn to peerID.
	// In the 2-node probe peerID is the OTHER node's ID on each side, so the
	// caller passes the remote's nodeID and we close it on both PeerSets.
	if err := p.psA.ClosePeer(peerID); err != nil {
		return err
	}
	// On B's PeerSet the peer to close is A's nodeID (the conn B holds to A).
	// peerID is B's nodeID (the remote A sees); A's nodeID is p.peerA.
	var otherID [16]byte
	if peerID == p.peerB {
		otherID = p.peerA // A was asked to close B; B must close A
	} else {
		otherID = p.peerB
	}
	if err := p.psB.ClosePeer(otherID); err != nil {
		return err
	}
	p.partitionAt = time.Now()
	return nil
}

// Heal re-Dials BOTH sides (A re-dials B at addrB, B re-dials A at addrA) via
// the existing PeerSet.Dial seam, then waits for both readLoops to plumb. It
// does NOT add a Heal method to PeerSet (re-dial IS PeerSet.Dial; the probe
// composes it). Records healAt — the SLO clock start (FACT 2: restore-of-
// connectivity, NOT SG-CLI-return; the in-process probe has no SG layer).
func (p *ConvergenceProbe) Heal(ctx context.Context, peerID [16]byte) error {
	// A re-dials B (addrB, SNI localhost, B's nodeID); B re-dials A (addrA).
	if err := p.psA.Dial(ctx, p.addrB, "localhost", p.peerB); err != nil {
		return err
	}
	if err := p.psB.Dial(ctx, p.addrA, "localhost", p.peerA); err != nil {
		return err
	}
	// Wait for both reader goroutines to plumb through the TLS handshake. The
	// readLoop installs the peerConn under the PeerSet's write lock before the
	// handshake completes, so we poll peers-map presence (the asyncWait shape).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		p.psA.mu.RLock()
		_, okA := p.psA.peers[p.peerB]
		p.psA.mu.RUnlock()
		p.psB.mu.RLock()
		_, okB := p.psB.peers[p.peerA]
		p.psB.mu.RUnlock()
		if okA && okB {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	p.healAt = time.Now()
	return nil
}

// StartSweepLoops starts BOTH SweepLoops at the tick (the §0 FACT-1 fixture;
// the gate HARDCODES 50ms) on a derived context the probe owns. The sweep runs
// CONTINUOUSLY — the production model: the sweep is already running when a
// partition stalls it (no live peers -> AntiEntropySweep returns early) and
// resumes within [0, tick) when Heal re-dials. This is the FACT-1 physics: the
// sweep-wait is a UNIFORM [0, tick) random variable ONLY when the sweep is
// already running at heal; starting the sweep AT healAt would bill a full tick
// that production excludes (the first ticker fire is tick elapsed, not 0).
// The gate calls StartSweepLoops ONCE at mesh setup, before Partition.
func (p *ConvergenceProbe) StartSweepLoops(ctx context.Context, tick time.Duration) context.CancelFunc {
	sweepCtx, cancel := context.WithCancel(ctx)
	go p.gA.SweepLoop(sweepCtx, tick)
	go p.gB.SweepLoop(sweepCtx, tick)
	return cancel
}

// WaitForConvergence polls MerkleRoot(A)==MerkleRoot(B) at <=tick cadence until
// equal OR ctx timeout. It returns the wall-clock from healAt (the SLO clock —
// FACT 2) and ErrSLONotMet if ctx elapses first. The probe does NOT reimplement
// the sweep (StartSweepLoops started the Day-2 SweepLoop at setup) NOR
// convergence detection (it reads MerkleRoot directly — the SAME path the Day-3
// gauge seeds from via stampConvergence).
//
// The returned healToConv is the OPERATOR-FACING TOTAL: wall-clock from
// restored-connectivity to roots-equal, INCLUDING the sweep-wait (games that
// exclude the tick from the SLO clock are rejected as hidden assumptions). The
// sweep-wait is genuinely [0, tick) because the sweep is already running.
func (p *ConvergenceProbe) WaitForConvergence(ctx context.Context, slo, tick time.Duration) (healToConv time.Duration, err error) {
	// Poll roots at <=tick cadence until equal OR ctx timeout. The poll interval
	// is tick/4 so a convergence that lands mid-tick is observed well within the
	// tick budget (the sweep-wait is the dominant term; the poll overhead is
	// sub-tick and does not gate the SLO).
	poll := tick / 4
	if poll <= 0 {
		poll = tick
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		ra := p.engine.State().MerkleRoot()  // crdt.go:1225 + hamt.go:265
		rb := p.engineB.State().MerkleRoot() // crdt.go:1225 + hamt.go:265
		if ra == rb {
			healToConv = time.Since(p.healAt)
			return healToConv, nil
		}
		select {
		case <-ctx.Done():
			healToConv = time.Since(p.healAt)
			return healToConv, ErrSLONotMet
		case <-ticker.C:
		}
	}
}

// PartitionAt returns when Partition closed the conns (the divergence-injection
// window start). Zero before Partition is called.
func (p *ConvergenceProbe) PartitionAt() time.Time { return p.partitionAt }

// HealAt returns when Heal's re-dial returned (the SLO clock start — FACT 2).
// Zero before Heal is called.
func (p *ConvergenceProbe) HealAt() time.Time { return p.healAt }
