// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// applyProvisioning must exclude the local node from a shared peer directory.
// Otherwise its nodeID enters topology selection, and the sweep tries to publish
// to itself and misses in ps.peers. The sweep continues after a failed publish;
// these tests check the avoided selection and dialing errors, not convergence
// time.

import (
	"context"
	"testing"

	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/mesh"
)

// selfPeerHarness builds a minimal provisioning-layer harness: a
// nil-peers/nil-engine/nil-owner Gossiper (NewGossiper is nil-safe;
// RegisterPeer only touches g.domains, and this test never dials, signs, or
// sweeps), a fresh Directory, and a TopologyManager in self-region 1.
func selfPeerHarness(t *testing.T, _ [16]byte) (*mesh.Gossiper, *identity.Directory, *mesh.TopologyManager) {
	t.Helper()
	dir := identity.NewDirectory()
	topo := mesh.NewTopologyManager(mesh.RegionTag(1))
	return mesh.NewGossiper(nil, nil, nil, dir), dir, topo
}

// selfFirstPeerdir builds a shared peer directory with this node's own entry
// first, followed by two other peers.
func selfFirstPeerdir(selfID [16]byte) (cfgs []peerDirConfig, peerA, peerB [16]byte) {
	peerA = [16]byte{0xB2, 0xE4, 0xAB, 0xF9}
	peerB = [16]byte{0xC3, 0xF5, 0xBC, 0x0A}
	mk := func(id [16]byte, addr string, region mesh.RegionTag) peerDirConfig {
		var pub [32]byte
		for i := range pub {
			pub[i] = id[0] ^ byte(i+1)
		}
		return peerDirConfig{addr: addr, nodeID: id, ed25519Pub: pub, region: region, hasRegion: true}
	}
	cfgs = []peerDirConfig{
		mk(selfID, "192.0.2.10:7373", 1),
		mk(peerA, "192.0.2.10:7374", 1),
		mk(peerB, "198.51.100.10:7373", 2),
	}
	return cfgs, peerA, peerB
}

func TestProvisioningSkipsSelf(t *testing.T) {
	selfID := [16]byte{0x5E, 0x66, 0x9E, 0x91, 0xFA, 0xE7, 0x1B, 0xCD, 0x7D, 0x53, 0xE6, 0x81, 0xA2, 0x3E, 0x1A, 0x8C}
	cfgs, peerA, peerB := selfFirstPeerdir(selfID)

	gossiper, dir, topo := selfPeerHarness(t, selfID)
	provisioned, err := applyProvisioning(gossiper, dir, topo, cfgs, selfID)
	if err != nil {
		t.Fatalf("applyProvisioning: %v", err)
	}

	for addr, id := range provisioned {
		if id == selfID {
			t.Fatalf("provisionedMap contains this node's own nodeID at %s — the dial loop would dial itself", addr)
		}
	}

	sel := topo.Select(context.Background())
	for _, id := range sel {
		if id == selfID {
			t.Fatalf("topology.Select returned this node's own nodeID — the self entry must be skipped at the provisioning ingress")
		}
	}

	if len(provisioned) != 2 {
		t.Fatalf("provisionedMap has %d entries, want 2 — only the self entry must be skipped", len(provisioned))
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
		t.Fatalf("peerA present=%v peerB present=%v — both real peers must be provisioned", foundA, foundB)
	}
	selHasPeer := false
	for _, id := range sel {
		if id == peerA || id == peerB {
			selHasPeer = true
		}
	}
	if !selHasPeer {
		t.Fatalf("topology.Select returned no real peer (%d ids) — region registration for real peers must survive the self-skip", len(sel))
	}
	t.Logf("self entry skipped at provisioning ingress: absent from provisionedMap and topology.Select output; both real peers provisioned and selectable")
}

func TestSelfSkipIsScopedToSelf(t *testing.T) {
	selfID := [16]byte{0x5E, 0x66, 0x9E, 0x91}
	cfgs, _, _ := selfFirstPeerdir(selfID)
	otherSelf := [16]byte{0xDE, 0xAD, 0xBE, 0xEF}
	gossiper, dir, topo := selfPeerHarness(t, otherSelf)
	provisioned, err := applyProvisioning(gossiper, dir, topo, cfgs, otherSelf)
	if err != nil {
		t.Fatalf("applyProvisioning: %v", err)
	}
	if len(provisioned) != 3 {
		t.Fatalf("with no matching self entry, provisionedMap has %d entries, want 3 — the skip must target only an exact nodeID match", len(provisioned))
	}
	t.Logf("peerdir with no self entry provisions all 3 entries unchanged — skip fires only on exact nodeID match")
}
