// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// The convergence probe composes peer sets, gossipers, and engines to check
// that a two-node mesh heals a transport partition and returns to equal Merkle
// roots within a wall-clock deadline (ADR-0009).
//
// StartSweepLoops runs the ordinary sweep loop; WaitForConvergence reads roots
// through engine.MerkleRootFromShards, which does not grow the arena
// (ADR-0051). The probe closes connections with PeerSet.ClosePeer but leaves
// the receive path unchanged: frames still pass through HandleFrame,
// VerifyCRDTFrame, and ApplyCRDTDeltaEvent.
//
// The measured interval starts when connectivity returns, not when a cloud
// control-plane request returns. It includes the wait for the next sweep, then
// the network round trip, IBLT reconciliation, and delta application. With a
// running sweep, the first term is in [0, tick). A 100 ms tick can consume the
// entire 100 ms target, so the in-process test uses a 50 ms tick and passes it
// explicitly to the probe.
//
// Loopback TLS has a round trip of roughly 10 us, compared with approximately
// 0.3-1.0 ms within an availability zone. The probe checks partition recovery
// and the effect of the tick on convergence time; it does not reproduce the
// sub-100 ms result measured on cloud hardware.
package mesh

import (
	"context"
	"errors"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// ErrSLONotMet is returned by WaitForConvergence when the context deadline
// elapses before the engines' Merkle roots match. WaitForConvergence also
// returns the elapsed time since healAt, allowing a caller to distinguish a
// missed latency target from a failure to converge.
var ErrSLONotMet = errors.New("mesh: convergence-after-heal SLO not met before ctx deadline")

// ConvergenceProbe drives a partition, heal, and convergence sequence between
// two gossipers and their peer sets. It checks that updates injected while the
// nodes are partitioned replicate through the ordinary IBLT delta join after
// connectivity returns.
//
// Heal re-dials both sides through PeerSet.Dial; no separate heal operation is
// added to PeerSet. The stored peer IDs are the nodes' CRDT signing identities,
// which are also the keys in each peer set's peers map.
type ConvergenceProbe struct {
	gA      *Gossiper
	gB      *Gossiper
	psA     *PeerSet
	psB     *PeerSet
	engine  *eng.DeltaCRDTEngine // A's engine (MerkleRoot source for the A side)
	engineB *eng.DeltaCRDTEngine // B's engine (MerkleRoot source for the B side)
	// addrA and addrB are the loopback TLS listener addresses. Heal dials
	// addrB from A and addrA from B, mirroring the bidirectional partition.
	addrA string
	addrB string
	// peerA and peerB are the node IDs. Each side closes and re-dials the
	// other's ID.
	peerA [16]byte
	peerB [16]byte

	// partitionAt records when Partition closed the connections. healAt records
	// when Heal finished restoring them and starts the measured interval.
	partitionAt time.Time
	healAt      time.Time
}

// NewConvergenceProbe binds two connected gossipers, peer sets, engines,
// loopback addresses, and node IDs. The caller retains ownership of the
// components; the probe drives only the partition and heal sequence.
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

// Partition closes A's connection to B and B's connection to A. Writes on
// those connections then fail, and a sweep with no remaining peers returns
// early. Frames exchanged after Heal still pass through the ordinary receive
// verification and apply path. partitionAt marks the start of the divergence
// window.
func (p *ConvergenceProbe) Partition(ctx context.Context, peerID [16]byte) error {
	// Bidirectional: A closes its connection to peerID, B closes its connection
	// to peerID. In the 2-node probe peerID is the other node's ID on each
	// side, so the caller passes the remote's nodeID and we close it on both
	// peer sets.
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

// Heal re-dials A to B and B to A through PeerSet.Dial, then waits until both
// peers maps contain the restored edges. It records healAt after this wait so
// the convergence interval starts with connectivity restored.
func (p *ConvergenceProbe) Heal(ctx context.Context, peerID [16]byte) error {
	// A re-dials B (addrB, SNI localhost, B's nodeID); B re-dials A (addrA).
	if err := p.psA.Dial(ctx, p.addrB, "localhost", p.peerB); err != nil {
		return err
	}
	if err := p.psB.Dial(ctx, p.addrA, "localhost", p.peerA); err != nil {
		return err
	}
	// Dial installs each peer before starting its read loop. Poll both maps so
	// healAt does not include either installation wait.
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

// StartSweepLoops starts both sweep loops on a derived context. Call it before
// Partition so a sweep is already running at heal: the next sweep then arrives
// within [0, tick), matching the production loop. Starting at heal would always
// add a full tick before the first run. The test uses a 50 ms tick.
func (p *ConvergenceProbe) StartSweepLoops(ctx context.Context, tick time.Duration) context.CancelFunc {
	sweepCtx, cancel := context.WithCancel(ctx)
	go p.gA.SweepLoop(sweepCtx, tick)
	go p.gB.SweepLoop(sweepCtx, tick)
	return cancel
}

// WaitForConvergence polls both engines' Merkle roots until they match or ctx
// expires. It returns the wall-clock interval from restored connectivity to
// equal roots, including the wait for the next sweep, or ErrSLONotMet on
// timeout. StartSweepLoops must already be running for the sweep wait to lie
// in [0, tick). Roots are read with MerkleRootFromShards, as in the convergence
// gauge's stampConvergence path.
func (p *ConvergenceProbe) WaitForConvergence(ctx context.Context, slo, tick time.Duration) (healToConv time.Duration, err error) {
	// Poll four times per tick so polling adds little latency to the dominant
	// wait for the next sweep.
	poll := tick / 4
	if poll <= 0 {
		poll = tick
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		// Read shard roots directly; rebuilding a merged view with State would
		// allocate arena memory on every poll (ADR-0051).
		ra := p.engine.MerkleRootFromShards()
		rb := p.engineB.MerkleRootFromShards()
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

// HealAt returns when Heal finished restoring both connections, which is the
// start of the measured convergence interval. It is zero before Heal is called.
func (p *ConvergenceProbe) HealAt() time.Time { return p.healAt }
