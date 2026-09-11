// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package main

// self_peer_skip_test.go — the in-process
// falsification guard for the SELF-PEER ingress (ADR-0045).
//
// THE BUG, AT ITS REAL INGRESS (not where it was first suspected).
// An early report attributed the seed's 13,204 `Publish: no live peer <own-id>`
// lines to the ACCEPT side (`RegisterInbound` keying by TLS leaf CN at colocated
// density) and proposed guarding that path. A byte-audit refuted it, and the
// refutation was re-verified before this guard was written:
//
//	grep -c 'registered inbound peer 5e669e91' node-0-us-east-1.log -> 0
//
// The accept side NEVER registered self. `Publish: no live peer` is the ps.peers
// MAP-MISS branch (peer.go:781-787) — self was never a REGISTERED peer, only a
// SELECTED one. The real ingress is THIS file: the silicon gate ships ONE shared
// peerdir to all 100 nodes and its LINE 1 is the seed's own entry
// (`192.0.2.1:7373 5e669e91… … 1`), and applyProvisioning had ZERO
// self-checks. It registered the node's own nodeID and handed it to
// topo.SetRegion; TopologyManager cannot filter it because it never learns its own
// nodeID (it holds only selfRegion, topology.go:63). The self-ID then flowed out of
// topology.Select into the sweep.
//
// HONEST SEVERITY: the sweep CONTINUES past a failed ship (gossip.go:1128-1138), so
// this costs ~1 wasted slot + log noise per sweep out of ~37 peers. It is HYGIENE,
// NOT the 64-divergent stall root. This guard is scoped to what the
// fix actually does; it does not claim convergence impact.
//
// RUN: go test -run 'TestProvisioningSkipsSelf|TestSelfSkipIsScopedToSelf' -count=1./cmd/sovereign-node/

import (
	"context"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/mesh"
)

// selfPeerHarness builds the minimal provisioning-layer harness the existing
// guards use: a nil-peers/nil-engine/nil-owner Gossiper (NewGossiper is nil-safe —
// RegisterPeer only touches g.domains, and this guard never dials, signs, or
// sweeps), a fresh Directory, and a TopologyManager in self-region 1. selfRegion 1
// matches the peerdir shape (the seed's own line carries region 1).
func selfPeerHarness(t *testing.T, _ [16]byte) (*mesh.Gossiper, *identity.Directory, *mesh.TopologyManager) {
	t.Helper()
	dir := identity.NewDirectory()
	topo := mesh.NewTopologyManager(mesh.RegionTag(1))
	return mesh.NewGossiper(nil, nil, nil, dir), dir, topo
}

// selfFirstPeerdir builds the peerdir shape: this node's OWN entry FIRST
// (exactly as the shared silicon peerdir has it at line 1), then two real peers.
func selfFirstPeerdir(selfID [16]byte) (cfgs []peerDirConfig, peerA, peerB [16]byte) {
	peerA = [16]byte{0xB2, 0xE4, 0xAB, 0xF9}
	peerB = [16]byte{0xC3, 0xF5, 0xBC, 0x0A}
	mk := func(id [16]byte, addr string, region mesh.RegionTag) peerDirConfig {
		var pub [32]byte
		// A deterministic, non-zero Ed25519 pubkey blob. RegisterPeer only stores
		// the bytes (verification happens later at Directory.Lookup), so a
		// synthetic key is correct for a provisioning-layer guard.
		for i := range pub {
			pub[i] = id[0] ^ byte(i+1)
		}
		return peerDirConfig{addr: addr, nodeID: id, ed25519Pub: pub, region: region, hasRegion: true}
	}
	cfgs = []peerDirConfig{
		mk(selfID, "192.0.2.1:7373", 1), // LINE 1 = THIS NODE'S OWN ENTRY
		mk(peerA, "192.0.2.1:7374", 1),
		mk(peerB, "198.51.100.1:7373", 2),
	}
	return cfgs, peerA, peerB
}

// TestProvisioningSkipsSelf is the RED→GREEN guard for the actual ingress.
//
// RED on the pre-fix bytes: applyProvisioning registers every entry including self, so
// topology.Select's registry contains this node's own ID and the sweep ships to
// itself. After the fix: self is absent from the topology registry AND absent from the
// returned provisionedMap (so the dial loop never dials our own address), while
// both real peers are registered unchanged.
func TestProvisioningSkipsSelf(t *testing.T) {
	selfID := [16]byte{0x5E, 0x66, 0x9E, 0x91, 0xFA, 0xE7, 0x1B, 0xCD, 0x7D, 0x53, 0xE6, 0x81, 0xA2, 0x3E, 0x1A, 0x8C}
	cfgs, peerA, peerB := selfFirstPeerdir(selfID)

	gossiper, dir, topo := selfPeerHarness(t, selfID)
	provisioned, err := applyProvisioning(gossiper, dir, topo, cfgs, selfID)
	if err != nil {
		t.Fatalf("applyProvisioning: %v", err)
	}

	// (a) SELF must be absent from the returned addr→nodeID map (the dial loop's
	// source): a node must never dial its own listener.
	for addr, id := range provisioned {
		if id == selfID {
			t.Fatalf("self-skip FAIL: the provisionedMap contains this node's OWN nodeID at %s. The dial loop consumes this map, so the node would dial ITSELF. applyProvisioning must skip an entry whose nodeID == selfNodeID (the shared-peerdir deploy the silicon gate uses puts the node's own entry on LINE 1).", addr)
		}
	}

	// (b) SELF must be absent from the TOPOLOGY registry — the actual path the
	// self-ID took into the sweep on silicon (Select's output, NOT ps.peers).
	sel := topo.Select(context.Background())
	for _, id := range sel {
		if id == selfID {
			t.Fatalf("self-skip FAIL: topology.Select returned this node's OWN nodeID. That is EXACTLY the path: applyProvisioning → topo.SetRegion(selfID) → Select emits self → the sweep Publishes to self → 13,204 `Publish: no live peer <own-id>` lines (the ps.peers MAP-MISS branch). TopologyManager CANNOT filter this itself — it never learns its own nodeID (topology.go:63 holds only selfRegion), so the guard MUST live at the provisioning ingress.")
		}
	}

	// (c) THE REAL PEERS must still be provisioned — the anti-tautology guard. A
	// fix that skipped everything would pass (a)+(b) and break the mesh.
	if len(provisioned) != 2 {
		t.Fatalf("self-skip OVER-SKIP: provisionedMap has %d entries, want 2 (the two real peers). The skip must remove ONLY the self entry — skipping more would silently partition the node.", len(provisioned))
	}
	foundA, foundB := false, false
	for _, id := range provisioned {
		if id == peerA {
			foundA = true
		}
		if id == peerB {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("self-skip OVER-SKIP: peerA present=%v peerB present=%v — both real peers MUST be provisioned; only self is skipped", foundA, foundB)
	}
	selHasPeer := false
	for _, id := range sel {
		if id == peerA || id == peerB {
			selHasPeer = true
		}
	}
	if !selHasPeer {
		t.Fatalf("self-skip OVER-SKIP: topology.Select returned NO real peer (%d ids) — the region registration for the real peers must survive the self-skip", len(sel))
	}
	t.Logf("GREEN — the shared-peerdir self entry (LINE 1, the failing shape) is SKIPPED at the provisioning ingress: absent from the provisionedMap (so the dial loop never dials our own listener) AND absent from topology.Select's output (so the sweep never ships to itself), while BOTH real peers stay provisioned and selectable. The skip is LOUD (a `provisioning: skipped SELF entry` log line), never a silent drop.")
}

// TestSelfSkipIsScopedToSelf is the bug-inject control: a peerdir with NO
// self entry must be provisioned EXACTLY as before (byte-identical behavior), so
// the guard cannot be a blanket filter.
func TestSelfSkipIsScopedToSelf(t *testing.T) {
	selfID := [16]byte{0x5E, 0x66, 0x9E, 0x91}
	cfgs, _, _ := selfFirstPeerdir(selfID)
	// Provision with a DIFFERENT self identity: now NO entry matches, so all three
	// entries must be registered (the pre-fix behavior, unchanged).
	otherSelf := [16]byte{0xDE, 0xAD, 0xBE, 0xEF}
	gossiper, dir, topo := selfPeerHarness(t, otherSelf)
	provisioned, err := applyProvisioning(gossiper, dir, topo, cfgs, otherSelf)
	if err != nil {
		t.Fatalf("applyProvisioning: %v", err)
	}
	if len(provisioned) != 3 {
		t.Fatalf("self-skip SCOPE BROKEN: with NO matching self entry the provisionedMap has %d entries, want 3 — the skip must be a targeted self-skip, NOT a filter that drops entries for any other reason. A regression here means a legitimate peer is being dropped.", len(provisioned))
	}
	t.Logf("GREEN (scope) — a peerdir with NO self entry provisions all 3 entries unchanged: the skip fires ONLY on an exact nodeID match with this node, so pre-fix deploys are byte-identical.")
}
