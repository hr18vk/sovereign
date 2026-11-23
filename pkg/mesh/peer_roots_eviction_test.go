// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// The change gate's peerRoots map is bounded by sweep-time eviction
// (ADR-0055 §6). This test checks that one sweep removes a departed peer,
// retains a live peer, and that a rejoined peer's root is recorded again by
// the root-announce path.
package mesh

import (
	"testing"
	"time"
)

// TestDAHPeerRootsBoundedUnderChurn verifies eviction, live-peer retention,
// and root recovery after a rejoin (ADR-0055 §6).
func TestDAHPeerRootsBoundedUnderChurn(t *testing.T) {
	m := newDigestEfficiencyMesh(t, 3)
	defer m.close()
	const A, B, C = 0, 1, 2
	m.insertInto(A, "base", 20)
	m.insertInto(B, "base", 20)
	m.insertInto(C, "base", 20)
	if ok, _ := m.convergeWithin([]int{A, B, C}, 60, 25*time.Millisecond); !ok {
		t.Fatalf("setup: 3-node mesh did not converge")
	}
	idB, idC := m.nodes[B].ident.NodeID, m.nodes[C].ident.NodeID
	if _, known := m.nodes[A].g.peerRootFor(idC); !known {
		t.Fatalf("A holds no cached root for C after convergence — the test has nothing to evict")
	}

	// Departure: every node (incl. A) closes its conns to C.
	m.partitionNode(C)
	// One sweep on A: the eviction must drop C's (departed) entry, keep B's.
	m.nodes[A].g.AntiEntropySweep(m.ctx)
	time.Sleep(50 * time.Millisecond)
	if _, known := m.nodes[A].g.peerRootFor(idC); known {
		t.Fatalf("A's peerRoots still holds the departed peer C after a sweep — the map grows unboundedly under membership churn")
	}
	if _, known := m.nodes[A].g.peerRootFor(idB); !known {
		t.Fatalf("the eviction dropped live peer B's root — the never-evict-a-live-peer guard is broken")
	}

	// Heal: C re-announces on the next sweep; the cache self-heals.
	m.healNode(t, C)
	if ok, _ := m.convergeWithin([]int{A, B, C}, 60, 25*time.Millisecond); !ok {
		t.Fatalf("heal: C did not re-converge after the re-dial")
	}
	if _, known := m.nodes[A].g.peerRootFor(idC); !known {
		t.Fatalf("after heal, A's cache did not re-record C's root — the self-healing property is broken (a rejoined peer would re-fire forever)")
	}
	t.Logf("peerRoots eviction: departed peer evicted after one sweep; live peer kept; healed peer re-recorded via the root-announce")
}
