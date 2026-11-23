// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests cover digestRecv eviction (ADR-0056) and rejection of truncated
// root announces (ADR-0055). registerDigestRecv creates a channel for each
// peer whose change gate fires. Sweep-time eviction removes departed peers so
// membership churn cannot grow the map without bound.
package mesh

import (
	"github.com/hr18vk/sovereign/pkg/receive"
	"testing"
	"time"
)

// TestDAIDigestRecvBoundedUnderChurn exercises eviction through
// AntiEntropySweep (ADR-0056). A sweep must remove the departed peer's channel
// and retain the live peer's channel; dropping a live channel would lose a
// digest and cause a full-keyset fallback. Once the peers converge, increasing
// digestGateSkips shows that subsequent sweeps skip them rather than register
// unnecessary channels.
func TestDAIDigestRecvBoundedUnderChurn(t *testing.T) {
	m := newDigestEfficiencyMesh(t, 3)
	defer m.close()
	const A, B, C = 0, 1, 2
	// Converge the base state. Unknown cached roots make the first gate fire,
	// so A registers digestRecv channels for B and C. Those entries must exist
	// before the eviction assertions are meaningful.
	m.insertInto(A, "base-a", 10)
	m.insertInto(B, "base-b", 10)
	m.insertInto(C, "base-c", 10)
	if ok, _ := m.convergeWithin([]int{A, B, C}, 60, 25*time.Millisecond); !ok {
		t.Fatalf("setup: 3-node mesh did not converge")
	}
	idB, idC := m.nodes[B].ident.NodeID, m.nodes[C].ident.NodeID
	if m.nodes[A].g.digestRecvFor(idB) == nil || m.nodes[A].g.digestRecvFor(idC) == nil {
		t.Fatalf("A holds no digestRecv channel for B/C after convergence — the test has nothing to evict (the entries the defect creates were not created)")
	}
	// Departure: every node closes its conns to C — ClosePeer removes C from
	// A's PeerSet, so isLive(C) is FALSE on A (the deterministic liveness
	// oracle; the map delete runs synchronously under ps.mu).
	m.partitionNode(C)
	// One sweep on A: the eviction at sweep start must drop C's (departed)
	// channel and keep B's (live).
	m.nodes[A].g.AntiEntropySweep(m.ctx)
	if m.nodes[A].g.digestRecvFor(idC) != nil {
		t.Fatalf("A's digestRecv still holds the departed peer C after a sweep — the map grows unboundedly under membership churn")
	}
	if m.nodes[A].g.digestRecvFor(idB) == nil {
		t.Fatalf("the eviction dropped live peer B's channel — the never-evict-a-live-peer guard is broken (a missed digest, the dangerous direction)")
	}

	// Rejoin: C heals and re-converges. The partition-sweep also evicted A's
	// cached peerRoots[C] (the peerRoots eviction from ADR-0055), so the first
	// post-heal gate for C fires on UNKNOWN and the rejoin exchange re-syncs it
	// — correct, the rejoin genuinely needs the exchange. Once converged and
	// cache-warm, further sweeps must skip every peer: the digestGateSkips
	// counter rises and no new registration occurs. That is the observable of
	// the rejoined-but-converged leg: an existing live peer's channel persists
	// by design (the map is bounded by the live peer set, not round-scoped),
	// and a converged peer that got a new entry would mean the gate fired
	// spuriously — this counter probe catches exactly that.
	m.healNode(t, C)
	if ok, _ := m.convergeWithin([]int{A, B, C}, 60, 25*time.Millisecond); !ok {
		t.Fatalf("heal: C did not re-converge after the re-dial")
	}
	g := m.nodes[A].g
	before := g.digestGateSkips.Load()
	g.AntiEntropySweep(m.ctx)
	skipped := g.digestGateSkips.Load() - before
	if skipped == 0 {
		t.Fatalf("a fully-converged sweep skipped zero peers — the change-gate fired spuriously (a converged peer must register nothing: the gate skips it, correct, not a leak)")
	}
	t.Logf("digestRecv eviction: departed peer's channel evicted after one sweep (the map is bounded to the live set); live peer's kept (the guard); converged peers gate-skipped (%d this sweep — no new entries)", skipped)
}

// TestRootAnnounceTruncatedDropped checks digestFrameRoot and its production
// delivery path (ADR-0055). Recording a truncated announce as a root could
// trigger needless digest exchanges or hide divergence. Stratified anti-entropy
// must be enabled for peerRoots to exist; the well-formed announce first proves
// that the observation path is active, so unchanged state cannot hide a skipped
// test premise.
func TestRootAnnounceTruncatedDropped(t *testing.T) {
	// Drive announces over the wire rather than calling DeliverDigest with a
	// zero identity, which the connection gate rejects (ADR-0068). This
	// one-way two-node harness settles both verified connections first. The
	// peer publishes each frame; readLoop supplies the verified connection and
	// the gate checks its identity against the frame's sender.
	m := newDigestEfficiencyMesh(t, 2)
	defer m.close()
	g := m.nodes[0].g
	peer := m.nodes[1]
	peerID := peer.ident.NodeID
	// (a) POSITIVE CONTROL: a well-formed 65-byte root-announce is recorded.
	var good, trunc [16]byte
	for i := range good {
		good[i], trunc[i] = byte(0xA0+i), byte(0x50+i)
	}
	var want [32]byte
	for i := range want {
		want[i] = byte(i)
	}
	// the announce is stamped with the peer's id (the gate binds it to the
	// connection's claimed identity) and rides the verified edge.
	announce := buildRootAnnounceFrame(peerID, want)
	if err := peer.ps.Publish(m.nodes[0].ident.NodeID, receive.LengthPrefixFrame(announce)); err != nil {
		t.Fatalf("POSITIVE CONTROL: the peer's announce Publish failed: %v", err)
	}
	goodDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(goodDeadline) {
		if _, known := g.peerRootFor(peerID); known {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got, known := g.peerRootFor(peerID); !known || got != want {
		t.Fatalf("positive control fail: a well-formed root-announce over the verified edge was not recorded (known=%v) — the observing path is not armed; every truncated-drop assert below would pass without exercising the defect", known)
	}
	// (b) Every length below the 65-byte minimum: digestFrameRoot reports
	// ok=false and the production path writes nothing.
	full := buildRootAnnounceFrame(peerID, want)
	for n := 0; n < digestFrameSELenOff+4+digestFrameRootLen; n++ {
		if _, ok := digestFrameRoot(full[:n]); ok {
			t.Fatalf("digestFrameRoot returned ok=true for a %d-byte frame (< the %d-byte minimum) — the guard is broken", n, digestFrameSELenOff+4+digestFrameRootLen)
		}
		// Check zero length at the parser level but do not send it on the
		// wire. FrameReader rejects a zero length prefix and closes the
		// receiving readLoop, preventing the remaining lengths from reaching
		// the digest-frame guard under test.
		if n == 0 {
			continue
		}
		// Send each truncation over the verified edge with the peer's real
		// identity. The ok=false guard must drop it before recordPeerRoot.
		if err := peer.ps.Publish(m.nodes[0].ident.NodeID, receive.LengthPrefixFrame(full[:n])); err != nil {
			t.Fatalf("truncated %d-byte Publish: %v", n, err)
		}
	}
	// The well-formed root must survive every truncated frame unchanged.
	// This rejects both an overwritten root and loss of the valid entry.
	stormDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(stormDeadline) {
		if got, known := g.peerRootFor(peerID); !known || got != want {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got, known := g.peerRootFor(peerID); !known || got != want {
		t.Fatalf("truncated root-announce drop fail: the truncated storm corrupted the peer's recorded entry (got=%x known=%v, want %x) — the drop is not surgical", got, known, want)
	}
	t.Logf("truncated root-announce drop: well-formed announce recorded (positive control armed); all %d truncated lengths dropped, unrecorded, surgical", digestFrameSELenOff+4+digestFrameRootLen)
}
