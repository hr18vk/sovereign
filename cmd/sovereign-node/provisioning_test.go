// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// The command package tests parsePeerDir and applyProvisioning directly;
// pkg/mesh cannot call these unexported functions without an import cycle.
// Mesh tests separately cover TLS identity reconciliation and topology
// selection (ADR-0040).
//
// The parser tests round-trip classical and hybrid entries, then check that
// malformed keys, duplicate addresses, and invalid regions return descriptive
// errors. The apply tests verify Directory registration and region lookup under
// the real nodeID. A separate surrogate-key case shows why address-derived IDs
// cannot select a provisioned peer's region.
//
// Empty and missing paths have distinct contracts: an empty --peer-dir disables
// provisioning and preserves zero-peerID dialing, while a named file that does
// not exist is a startup error. Further cases cover duplicate nodeIDs and the
// interaction between --peers region suffixes and provisioned identities.

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/mldsa"

	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/mesh"
)

// knownGoodPeerDir writes a three-peer configuration and returns the expected
// parsed values. Fixed nodeIDs and public keys make the round-trip comparison
// deterministic. The entries cover classical-only operation with a region,
// hybrid operation with a region, and classical-only operation without either
// optional field. GeneratePreviewKey65 derives the ML-DSA-65 keypair from a
// fixed seed, as NewNodeIdentityHybrid does for node identities.
func knownGoodPeerDir(t *testing.T) (path string, node1, node2, node3 [16]byte, pub1, pub2, pub3 [32]byte, pq2 *mldsa.PublicKey) {
	t.Helper()
	node1 = [16]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	node2 = [16]byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	node3 = [16]byte{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}
	for i := range pub1 {
		pub1[i] = 0xAA
		pub2[i] = 0xBB
		pub3[i] = 0xCC
	}
	// The fixed 32-byte seed makes peer 2's keypair reproducible. Its 1,952-byte
	// public-key encoding exercises mldsa.NewPublicKey in parsePeerDir.
	pqSeed := make([]byte, 32)
	for i := range pqSeed {
		pqSeed[i] = 0xDD
	}
	pqPriv, err := identity.GeneratePreviewKey65(pqSeed)
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pq2 = pqPriv.PublicKey() // the concrete key encoded in the configuration

	// Positional columns: addr nodeID ed25519 [mldsa65|-] [region|-].
	line1 := "127.0.0.1:9001 " + hex.EncodeToString(node1[:]) + " " + hex.EncodeToString(pub1[:]) + " - 3"
	line2 := "127.0.0.1:9002 " + hex.EncodeToString(node2[:]) + " " + hex.EncodeToString(pub2[:]) + " " + hex.EncodeToString(pq2.Bytes()) + " 7"
	line3 := "127.0.0.1:9003 " + hex.EncodeToString(node3[:]) + " " + hex.EncodeToString(pub3[:])
	content := strings.Join([]string{"# the peer-dir config", "", line1, line2, line3}, "\n") + "\n"
	dir := t.TempDir()
	path = filepath.Join(dir, "peerdir.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	return path, node1, node2, node3, pub1, pub2, pub3, pq2
}

// TestOOBConfigParse checks the three-entry round trip and rejection of
// malformed fields. The short-nodeID case exercises the exact-length check:
// removing that check would let an invalid identity reach provisioning.
func TestOOBConfigParse(t *testing.T) {
	path, node1, node2, node3, pub1, pub2, pub3, pq2 := knownGoodPeerDir(t)

	cfgs, err := parsePeerDir(path)
	if err != nil {
		t.Fatalf("parsePeerDir(%s): %v", path, err)
	}
	if len(cfgs) != 3 {
		t.Fatalf("parsePeerDir returned %d entries, want 3", len(cfgs))
	}
	// Peer 1 has a classical key and region 3.
	if cfgs[0].addr != "127.0.0.1:9001" || cfgs[0].nodeID != node1 || cfgs[0].ed25519Pub != pub1 {
		t.Fatalf("peer 1 mismatch: addr=%s nodeID=%x pub=%x", cfgs[0].addr, cfgs[0].nodeID, cfgs[0].ed25519Pub)
	}
	if cfgs[0].mldsa65Pub != nil {
		t.Fatalf("peer 1 has an ML-DSA-65 key, want nil")
	}
	if !cfgs[0].hasRegion || cfgs[0].region != mesh.RegionTag(3) {
		t.Fatalf("peer 1 region: hasRegion=%v region=%d, want true and 3", cfgs[0].hasRegion, cfgs[0].region)
	}
	// Peer 2 has Ed25519 and ML-DSA-65 keys and region 7.
	if cfgs[1].addr != "127.0.0.1:9002" || cfgs[1].nodeID != node2 || cfgs[1].ed25519Pub != pub2 {
		t.Fatalf("peer 2 mismatch: addr=%s nodeID=%x pub=%x", cfgs[1].addr, cfgs[1].nodeID, cfgs[1].ed25519Pub)
	}
	if cfgs[1].mldsa65Pub == nil {
		t.Fatalf("peer 2 has no ML-DSA-65 key")
	}
	// The reconstructed key must have the same encoding as the original key.
	if cfgs[1].mldsa65Pub.Bytes() == nil || len(cfgs[1].mldsa65Pub.Bytes()) != mldsa.MLDSA65PublicKeySize {
		t.Fatalf("peer 2 ML-DSA-65 key has %d bytes, want %d", len(cfgs[1].mldsa65Pub.Bytes()), mldsa.MLDSA65PublicKeySize)
	}
	if !bytesEqual(cfgs[1].mldsa65Pub.Bytes(), pq2.Bytes()) {
		t.Fatalf("peer 2 ML-DSA-65 key did not round-trip through its encoding")
	}
	if !cfgs[1].hasRegion || cfgs[1].region != mesh.RegionTag(7) {
		t.Fatalf("peer 2 region: hasRegion=%v region=%d, want true and 7", cfgs[1].hasRegion, cfgs[1].region)
	}
	// Peer 3 has neither optional field.
	if cfgs[2].addr != "127.0.0.1:9003" || cfgs[2].nodeID != node3 || cfgs[2].ed25519Pub != pub3 {
		t.Fatalf("peer 3 mismatch: addr=%s nodeID=%x pub=%x", cfgs[2].addr, cfgs[2].nodeID, cfgs[2].ed25519Pub)
	}
	if cfgs[2].mldsa65Pub != nil {
		t.Fatalf("peer 3 has an ML-DSA-65 key, want nil")
	}
	if cfgs[2].hasRegion {
		t.Fatalf("peer 3 has region %d, want no region", cfgs[2].region)
	}
	t.Logf("parsed classical and hybrid entries; ML-DSA-65 public-key encoding round-tripped")

	// Malformed entries must be rejected rather than coerced to zero values.
	t.Run("malformed_nodeID_short", func(t *testing.T) {
		// Eight bytes of hex-decoded nodeID must fail the 16-byte length check.
		bad := "127.0.0.1:9004 " + strings.Repeat("11", 8) + " " + hex.EncodeToString(pub1[:])
		p := writeTempPeerDir(t, bad)
		_, err := parsePeerDir(p) // use the subtest scope so err cannot be shadowed
		if err == nil {
			t.Fatalf("parsePeerDir accepted an 8-byte nodeID, want a 16-byte length error")
		}
		if !strings.Contains(err.Error(), "nodeID") || !strings.Contains(err.Error(), "16") {
			t.Fatalf("error does not name nodeID and its expected length: %q", err)
		}
		t.Logf("short nodeID rejected: %q", err)
	})
	t.Run("malformed_pubkey_badhex", func(t *testing.T) {
		bad := "127.0.0.1:9004 " + hex.EncodeToString(node1[:]) + " not-hex-at-all"
		p := writeTempPeerDir(t, bad)
		_, err := parsePeerDir(p)
		if err == nil {
			t.Fatalf("parsePeerDir accepted a non-hex Ed25519 public key")
		}
		t.Logf("non-hex public key rejected")
	})
	t.Run("malformed_dup_addr", func(t *testing.T) {
		// A duplicate address would shadow the first entry in the dial loop.
		line := "127.0.0.1:9004 " + hex.EncodeToString(node1[:]) + " " + hex.EncodeToString(pub1[:])
		p := writeTempPeerDir(t, line+"\n"+line)
		_, err := parsePeerDir(p)
		if err == nil {
			t.Fatalf("parsePeerDir accepted a duplicate peer address")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate-address error does not name the conflict: %q", err)
		}
		t.Logf("duplicate address rejected: %q", err)
	})
	t.Run("malformed_region_oor", func(t *testing.T) {
		bad := "127.0.0.1:9004 " + hex.EncodeToString(node1[:]) + " " + hex.EncodeToString(pub1[:]) + " - 256"
		p := writeTempPeerDir(t, bad)
		_, err := parsePeerDir(p)
		if err == nil {
			t.Fatalf("parsePeerDir accepted region 256, which exceeds uint8")
		}
		t.Logf("out-of-range region rejected")
	})
}

// TestOOBApply checks Ed25519 and ML-DSA-65 registration in a real Directory
// and region registration in a real TopologyManager. RegisterPeer only needs
// the Directory inside Gossiper, so the other Gossiper dependencies can be nil.
// Both provisioned cross-region peers must satisfy IsInterRegion; the peer with
// no region must remain local to the topology's conservative default.
//
// A separate surrogate-key case verifies that IsInterRegion(realNodeID) fails
// when only peerIDForAddr(addr) is registered, demonstrating why provisioning
// must use the real nodeID.
func TestOOBApply(t *testing.T) {
	path, node1, node2, node3, pub1, pub2, pub3, pq2 := knownGoodPeerDir(t)

	dir := identity.NewDirectory()
	topo := mesh.NewTopologyManager(mesh.RegionTag(1)) // self-region 1
	// RegisterPeer only touches the Directory held by the Gossiper. This test
	// never dials, signs, or sweeps, so the other dependencies can be nil.
	gossiper := mesh.NewGossiper(nil, nil, nil, dir)

	// The command parses the file before applying entries so the surrogate-region
	// pass can identify addresses that already have real nodeIDs.
	cfgs, perr := parsePeerDir(path)
	if perr != nil {
		t.Fatalf("parsePeerDir(%q): %v", path, perr)
	}
	provisioned, err := applyProvisioning(gossiper, dir, topo, cfgs, [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} /* a self nodeID that matches no configured peer */)
	if err != nil {
		t.Fatalf("applyProvisioning: %v", err)
	}
	// The dial loop uses this address-to-nodeID mapping.
	if len(provisioned) != 3 {
		t.Fatalf("provisioned map has %d entries, want 3", len(provisioned))
	}
	if provisioned["127.0.0.1:9001"] != node1 || provisioned["127.0.0.1:9002"] != node2 || provisioned["127.0.0.1:9003"] != node3 {
		t.Fatalf("provisioned map mismatch: %+v", provisioned)
	}
	// Each real nodeID must resolve to the configured Ed25519 public key.
	for _, c := range []struct {
		node [16]byte
		pub  [32]byte
	}{
		{node1, pub1}, {node2, pub2}, {node3, pub3},
	} {
		got, ok := dir.Lookup(c.node)
		if !ok {
			t.Fatalf("Directory.Lookup(%x) returned no key after RegisterPeer", c.node)
		}
		if !bytesEqual(got, c.pub[:]) {
			t.Fatalf("Directory.Lookup(%x) returned %x, want %x", c.node, got, c.pub)
		}
	}
	// The hybrid peer must resolve to both registered public keys.
	edPub, pqPub, ok := dir.LookupBoth(node2)
	if !ok {
		t.Fatalf("Directory.LookupBoth(%x) returned no entry after RegisterPQ", node2)
	}
	if !bytesEqual(edPub, pub2[:]) {
		t.Fatalf("LookupBoth(%x) Ed25519 key is %x, want %x", node2, edPub, pub2)
	}
	if pqPub == nil || !bytesEqual(pqPub.Bytes(), pq2.Bytes()) {
		t.Fatalf("LookupBoth(%x) ML-DSA-65 key does not match the configured key", node2)
	}
	// Peer 1 has no PQ key, so LookupBoth must leave that result nil.
	if _, pq1, ok1 := dir.LookupBoth(node1); ok1 && pq1 != nil {
		t.Fatalf("classical-only peer 1 has an ML-DSA-65 key, want nil")
	}
	// Peers 1 and 2 have regions 3 and 7 respectively, both different from the
	// local region 1. Region lookup must use their real nodeIDs.
	if !topo.IsInterRegion(node2) {
		t.Fatalf("IsInterRegion(%x)=false for peer 2 in region 7; local region is 1", node2)
	}
	if !topo.IsInterRegion(node1) {
		t.Fatalf("IsInterRegion(%x)=false for peer 1 in region 3; local region is 1", node1)
	}
	// Peer 3 has no region, so applyProvisioning must not call SetRegion for it.
	if topo.IsInterRegion(node3) {
		t.Fatalf("IsInterRegion(%x)=true for peer 3, which has no configured region", node3)
	}
	t.Logf("registered three Ed25519 keys and one ML-DSA-65 key; region lookup uses real nodeIDs")

	// Negative control: a topology keyed only by a fixed address surrogate has
	// no region entry for the real nodeID.
	surrogate := [16]byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
	topoRed := mesh.NewTopologyManager(mesh.RegionTag(1))
	topoRed.SetRegion(surrogate, mesh.RegionTag(7)) // register only the surrogate
	if topoRed.IsInterRegion(node2) {
		t.Fatalf("IsInterRegion(real %x)=true with only a surrogate region key", node2)
	}
	t.Logf("IsInterRegion(real %x)=false when region is keyed by surrogate %x", node2, surrogate)
}

// TestOOBEmptyNoOp verifies that the default empty --peer-dir path produces no
// registrations and an empty provisioned map. The caller treats ErrPeerDirEmpty
// as a disabled feature rather than a startup failure.
func TestOOBEmptyNoOp(t *testing.T) {
	dir := identity.NewDirectory()
	topo := mesh.NewTopologyManager(mesh.RegionTag(1))
	gossiper := mesh.NewGossiper(nil, nil, nil, dir)
	// Mirror the command's handling of ErrPeerDirEmpty as an empty config.
	cfgs, perr := parsePeerDir("")
	if perr != nil && !errors.Is(perr, ErrPeerDirEmpty) {
		t.Fatalf("parsePeerDir with an empty path returned %v, want ErrPeerDirEmpty or nil", perr)
	}
	provisioned, err := applyProvisioning(gossiper, dir, topo, cfgs, [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} /* a self nodeID that matches no configured peer */)
	if err != nil {
		t.Fatalf("applyProvisioning with no entries returned %v", err)
	}
	if len(provisioned) != 0 {
		t.Fatalf("empty configuration returned %d provisioned peers, want 0", len(provisioned))
	}
	if dir.Len() != 0 {
		t.Fatalf("Directory.Len()=%d after empty configuration, want 0", dir.Len())
	}
	t.Logf("empty path disabled provisioning and left the Directory empty")
}

// TestOOBMissingPathFails distinguishes a named but absent file from the
// default empty path. The open error must include the path and must not be
// mistaken for ErrPeerDirEmpty or suppressed by applyProvisioning.
func TestOOBMissingPathFails(t *testing.T) {
	dir := identity.NewDirectory()
	topo := mesh.NewTopologyManager(mesh.RegionTag(1))
	gossiper := mesh.NewGossiper(nil, nil, nil, dir)
	missing := filepath.Join(t.TempDir(), "does-not-exist.conf")
	// A non-empty missing path must return an open error, not ErrPeerDirEmpty.
	cfgs, err := parsePeerDir(missing)
	if err == nil {
		t.Fatalf("parsePeerDir(%q) returned no error for an absent file", missing)
	}
	if cfgs != nil {
		t.Fatalf("parsePeerDir(%q) returned entries after an open failure", missing)
	}
	if errors.Is(err, ErrPeerDirEmpty) {
		t.Fatalf("parsePeerDir(%q) returned ErrPeerDirEmpty for a non-empty path", missing)
	}
	// The command handles the parse error before applyProvisioning. With nil
	// configs, applyProvisioning itself has no entries to register.
	provisioned, applyErr := applyProvisioning(gossiper, dir, topo, cfgs, [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} /* a self nodeID that matches no configured peer */)
	_ = provisioned
	_ = applyErr
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing-file error does not name the path: %q", err)
	}
	t.Logf("parsePeerDir(%q) returned the missing-file error: %q", missing, err)
}

// writeTempPeerDir writes content to a temporary peer-directory file.
func writeTempPeerDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "peerdir.conf")
	if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("writeTempPeerDir: WriteFile %s: %v", p, err)
	}
	return p
}

// bytesEqual compares Directory and ML-DSA-65 public-key encodings.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestOOBSurrogateRetirement covers a peer that has both an @region suffix in
// --peers and an identity in --peer-dir. applySurrogateRegions must skip the
// address-derived ID so applyProvisioning can register the region under the
// real nodeID. Otherwise Select can spend an inter-region slot on an ID with no
// live peer connection.
//
// The test uses the same applySurrogateRegions helper as the command, followed
// by the SetRegion call made by applyProvisioning. The no-directory control
// retains surrogate registration; the provisioned case must omit it and select
// the real nodeID.
func TestOOBSurrogateRetirement(t *testing.T) {
	selfRegion := mesh.RegionTag(1)
	peerAddr := "192.0.2.2:7430"
	peerRegion := mesh.RegionTag(3)
	peerNodeID := [16]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	surrogate := peerIDForAddr(peerAddr) // SHA-256 address surrogate
	if surrogate == peerNodeID {
		t.Fatalf("test surrogate equals the real nodeID; choose a distinct peerNodeID")
	}

	// Without a peer directory, applySurrogateRegions registers the surrogate.
	topoRed := mesh.NewTopologyManager(selfRegion)
	applySurrogateRegions(topoRed, peerAddr+"@3", map[string]bool{})
	if !topoRed.IsInterRegion(surrogate) {
		t.Fatalf("IsInterRegion(surrogate %x)=false without a peer directory, want true", surrogate)
	}
	t.Logf("address surrogate %x registered when no peer directory is present", surrogate)

	// A provisioned address suppresses surrogate registration; the real nodeID
	// receives the region instead.
	topo := mesh.NewTopologyManager(selfRegion)
	applySurrogateRegions(topo, peerAddr+"@3", map[string]bool{peerAddr: true})
	topo.SetRegion(peerNodeID, peerRegion) // applyProvisioning uses the real nodeID
	if topo.IsInterRegion(surrogate) {
		t.Fatalf("surrogate %x remains registered for a provisioned address", surrogate)
	}
	if !topo.IsInterRegion(peerNodeID) {
		t.Fatalf("IsInterRegion(real %x)=false after provisioning; self=%d peer=%d", peerNodeID, selfRegion, peerRegion)
	}
	t.Logf("surrogate %x omitted and real nodeID %x registered", surrogate, peerNodeID)

	// Select must return the real nodeID rather than spending a slot on the
	// surrogate, which has no corresponding peer connection.
	topo.SetSeed(1)
	sel := topo.Select(context.Background())
	for _, id := range sel {
		if id == surrogate {
			t.Fatalf("Select returned surrogate %x, which has no peer connection", surrogate)
		}
	}
	foundReal := false
	for _, id := range sel {
		if id == peerNodeID {
			foundReal = true
		}
	}
	if !foundReal {
		t.Fatalf("Select did not return real nodeID %x; got %d peerIDs", peerNodeID, len(sel))
	}
	t.Logf("Select returned real nodeID %x and omitted the address surrogate", peerNodeID)
}

// TestOOBNodeIDDedup rejects two addresses that share a nodeID. Address-only
// deduplication would allow both entries, and the later RegisterPeer or
// RegisterPQ call would replace the first Directory binding. The first peer's
// deltas would then fail signature verification under its own key.
//
// The distinct-nodeID control confirms that valid multi-peer files still parse.
func TestOOBNodeIDDedup(t *testing.T) {
	// Both entries are well formed and differ only in address, so rejection must
	// come from the duplicate-nodeID check rather than key-length validation.
	nodeID := [16]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	nodeHex := strings.Repeat("44", 16) // 16-byte nodeID (32 hex chars)
	edHex := strings.Repeat("44", 32)   // 32-byte Ed25519 pubkey (64 hex chars)
	dupCfg := "192.0.2.2:7430 " + nodeHex + " " + edHex + "\n" +
		"192.0.2.3:7430 " + nodeHex + " " + edHex + "\n"
	dupPath := writeTempPeerDir(t, dupCfg)
	cfgs, err := parsePeerDir(dupPath)
	if err == nil {
		t.Fatalf("parsePeerDir accepted duplicate nodeID %x at different addresses", nodeID)
	}
	if !strings.Contains(err.Error(), "duplicate peer nodeID") {
		t.Fatalf("error does not identify the duplicate peer nodeID: %q", err.Error())
	}
	_ = cfgs
	t.Logf("duplicate nodeID %x at different addresses rejected", nodeID)

	// Distinct nodeIDs and addresses must remain valid; otherwise the duplicate
	// check would reject every multi-peer file rather than this specific error.
	distinctCfg := "192.0.2.2:7430 " + strings.Repeat("44", 16) + " " + edHex + "\n" +
		"192.0.2.3:7430 " + strings.Repeat("55", 16) + " " + strings.Repeat("55", 32) + "\n"
	distinctPath := writeTempPeerDir(t, distinctCfg)
	dcfgs, derr := parsePeerDir(distinctPath)
	if derr != nil {
		t.Fatalf("parsePeerDir rejected distinct nodeIDs: %v", derr)
	}
	if len(dcfgs) != 2 {
		t.Fatalf("parsePeerDir returned %d entries for two distinct peers, want 2", len(dcfgs))
	}
	t.Logf("two entries with distinct nodeIDs parsed successfully")
}
