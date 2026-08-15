package main

// provisioning_test.go is the Day-35 (ADR-0040) cmd-side §III gate — the
// T-OOB-CONFIG-PARSE + T-OOB-APPLY teeth that exercise parsePeerDir +
// applyProvisioning DIRECTLY (package main can reach them; pkg/mesh cannot —
// the import cycle: cmd imports mesh). The mesh-side teeth
// (pkg/mesh/day35_oob_test.go) cover the reconcile seam + the topology
// selector; these cover the config parser + the provisioning apply path.
//
// THE TEETH:
//
//   - T-OOB-CONFIG-PARSE: parsePeerDir round-trips a known 3-peer config (1
//     classical+region, 1 hybrid+region, 1 classical-only) → parsed == input.
//     The FAILSAFE discipline is the load-bearing gate: a malformed entry (bad
//     hex, wrong field length) is REJECTED with an error naming the line + the
//     field, NEVER silently coerced to zero. The RED bug-inject control proves
//     the length checks are load-bearing: a 16-byte-truncated nodeID is
//     ACCEPTED iff the length check is removed (the injected bug) — the tooth
//     FAILS under the bug.
//   - T-OOB-APPLY: applyProvisioning registers each peer's Ed25519 pubkey via
//     gossiper.RegisterPeer (+ dir.RegisterPQ for the PQ arm) + re-keys the
//     TopologyManager's region tag under the REAL nodeID (topo.SetRegion) →
//     the topology selector HITS → the 24th counter's gate is armed. The RED
//     control: applyProvisioning under a SURROGATE nodeID (the Day-34 path)
//     keys the topology under the surrogate → topo.IsInterRegion(realNodeID)
//     is false → the selector misses → the N=2 no-op reproduces.
//   - T-OOB-EMPTY-NO-OP: an empty --peer-dir (the OPT-IN default) returns an
//     empty provisioned map + nil → the dial loop's ELSE arm runs for every
//     peer (zero peerID = byte-identical Day-34). The honest no-op.
//   - T-OOB-MISSING-PATH-FAILS: a NON-EMPTY path that does not exist FAILS the
//     boot (a deploy misconfiguration MUST surface loudly, NOT silently fall
//     back to zero-peerID — the silent-partition class the honest-negative
//     posture forbids).

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/mldsa"

	"github.com/hr18vk/supremum/pkg/identity"
	"github.com/hr18vk/supremum/pkg/mesh"
)

// knownGoodPeerDir builds a known-good 3-peer --peer-dir config in a temp file
// + returns its path + the expected parsed values. The nodeIDs + pubkeys are
// FIXED (deterministic — the round-trip tooth needs byte-identical values; a
// random key would break the comparison). Peer-1 is classical + region 3;
// peer-2 is hybrid (Ed25519 + ML-DSA-65) + region 7; peer-3 is classical-only
// (no PQ, no region). The ML-DSA-65 pubkey is minted via
// identity.GeneratePreviewKey65(seed) (the SAME deterministic seed→*PrivateKey
// helper pkg/identity/pq_mldsa.go:70 exports — the anti-fab reuse; the test
// does NOT call mldsa.NewPrivateKey directly, mirroring the production path).
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
	// Peer-2's ML-DSA-65 keypair from a fixed 32-byte seed (the
	// identity.GeneratePreviewKey65 path — the deterministic seed form, byte-
	// identical across runs; the SAME path NewNodeIdentityHybrid uses at
	// peer.go:127). The pubkey's 1952-byte wire encoding round-trips through
	// parsePeerDir's mldsa.NewPublicKey (provisioning.go:267).
	pqSeed := make([]byte, 32)
	for i := range pqSeed {
		pqSeed[i] = 0xDD
	}
	pqPriv, err := identity.GeneratePreviewKey65(pqSeed)
	if err != nil {
		t.Fatalf("GeneratePreviewKey65: %v", err)
	}
	pq2 = pqPriv.PublicKey() // the concrete getter (peer.go:140 — NOT the Public() interface)

	// The config lines (positional columns: addr nodeID ed25519 [mldsa65|-] [region|-]).
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

// TestT_OOB_CONFIG_PARSE is the T-OOB-CONFIG-PARSE tooth: parsePeerDir round-
// trips a known 3-peer config → parsed == input. The FAILSAFE discipline (bad
// hex / wrong length REJECTED, NEVER coerced to zero) is asserted via the
// malformed-entry sub-tests. The RED bug-inject control proves the length
// checks are load-bearing: a 16-byte-truncated nodeID is ACCEPTED iff the
// length check is removed (the injected bug) — the tooth FAILS under the bug.
func TestT_OOB_CONFIG_PARSE(t *testing.T) {
	path, node1, node2, node3, pub1, pub2, pub3, pq2 := knownGoodPeerDir(t)

	cfgs, err := parsePeerDir(path)
	if err != nil {
		t.Fatalf("T-OOB-CONFIG-PARSE: parsePeerDir %s: %v", path, err)
	}
	if len(cfgs) != 3 {
		t.Fatalf("T-OOB-CONFIG-PARSE: parsePeerDir returned %d entries, want 3", len(cfgs))
	}
	// Peer-1: classical + region 3.
	if cfgs[0].addr != "127.0.0.1:9001" || cfgs[0].nodeID != node1 || cfgs[0].ed25519Pub != pub1 {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-1 mismatch (got addr=%s nodeID=%x pub=%x)", cfgs[0].addr, cfgs[0].nodeID, cfgs[0].ed25519Pub)
	}
	if cfgs[0].mldsa65Pub != nil {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-1 should be classical-only (mldsa65Pub=nil), got non-nil")
	}
	if !cfgs[0].hasRegion || cfgs[0].region != mesh.RegionTag(3) {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-1 should have region 3 (hasRegion=%v region=%d)", cfgs[0].hasRegion, cfgs[0].region)
	}
	// Peer-2: hybrid (Ed25519 + ML-DSA-65) + region 7.
	if cfgs[1].addr != "127.0.0.1:9002" || cfgs[1].nodeID != node2 || cfgs[1].ed25519Pub != pub2 {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-2 mismatch (got addr=%s nodeID=%x pub=%x)", cfgs[1].addr, cfgs[1].nodeID, cfgs[1].ed25519Pub)
	}
	if cfgs[1].mldsa65Pub == nil {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-2 should be hybrid (mldsa65Pub != nil), got nil")
	}
	// The reconstructed PQ pubkey round-trips: its Bytes() == the config's encoding.
	if cfgs[1].mldsa65Pub.Bytes() == nil || len(cfgs[1].mldsa65Pub.Bytes()) != mldsa.MLDSA65PublicKeySize {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-2 reconstructed PQ pubkey has %d bytes, want %d", len(cfgs[1].mldsa65Pub.Bytes()), mldsa.MLDSA65PublicKeySize)
	}
	if !bytesEqual(cfgs[1].mldsa65Pub.Bytes(), pq2.Bytes()) {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-2 reconstructed PQ pubkey != the minted pubkey (the Bytes()/NewPublicKey round-trip is broken)")
	}
	if !cfgs[1].hasRegion || cfgs[1].region != mesh.RegionTag(7) {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-2 should have region 7 (hasRegion=%v region=%d)", cfgs[1].hasRegion, cfgs[1].region)
	}
	// Peer-3: classical-only (no PQ, no region).
	if cfgs[2].addr != "127.0.0.1:9003" || cfgs[2].nodeID != node3 || cfgs[2].ed25519Pub != pub3 {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-3 mismatch (got addr=%s nodeID=%x pub=%x)", cfgs[2].addr, cfgs[2].nodeID, cfgs[2].ed25519Pub)
	}
	if cfgs[2].mldsa65Pub != nil {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-3 should be classical-only (mldsa65Pub=nil), got non-nil")
	}
	if cfgs[2].hasRegion {
		t.Fatalf("T-OOB-CONFIG-PARSE: peer-3 should have NO region (hasRegion=false), got hasRegion=true region=%d", cfgs[2].region)
	}
	t.Logf("GATE PASS: T-OOB-CONFIG-PARSE — parsePeerDir round-tripped the 3-peer config (1 classical+region, 1 hybrid+region, 1 classical-only); the ML-DSA-65 pubkey Bytes()/NewPublicKey round-trip is byte-identical")

	// The FAILSAFE discipline — malformed entries are REJECTED, NOT coerced to zero.
	t.Run("malformed_nodeID_short", func(t *testing.T) {
		// A 16-hex-char nodeID (8 bytes, NOT 16) — the length check MUST reject.
		bad := "127.0.0.1:9004 " + strings.Repeat("11", 8) + " " + hex.EncodeToString(pub1[:])
		p := writeTempPeerDir(t, bad)
		_, err := parsePeerDir(p) // declare err in the sub-test scope (NOT the if-init — that shadows + leaves the outer err nil → a nil-deref panic)
		if err == nil {
			t.Fatalf("T-OOB-CONFIG-PARSE: parsePeerDir ACCEPTED an 8-byte nodeID (want 16) — the length check is vestigial (a truncated nodeID would silently key the Directory + the topology under a WRONG nodeID)")
		}
		if !strings.Contains(err.Error(), "nodeID") || !strings.Contains(err.Error(), "16") {
			t.Fatalf("T-OOB-CONFIG-PARSE: the reject error does not name the field + the expected length (got %q)", err)
		}
		t.Logf("GATE PASS: T-OOB-CONFIG-PARSE/malformed_nodeID_short — an 8-byte nodeID was REJECTED with %q (the length check is load-bearing)", err)
	})
	t.Run("malformed_pubkey_badhex", func(t *testing.T) {
		// A non-hex pubkey — the hex decode MUST reject.
		bad := "127.0.0.1:9004 " + hex.EncodeToString(node1[:]) + " not-hex-at-all"
		p := writeTempPeerDir(t, bad)
		_, err := parsePeerDir(p)
		if err == nil {
			t.Fatalf("T-OOB-CONFIG-PARSE: parsePeerDir ACCEPTED a non-hex pubkey — the hex-decode guard is vestigial")
		}
		t.Logf("GATE PASS: T-OOB-CONFIG-PARSE/malformed_pubkey_badhex — a non-hex pubkey was REJECTED (the hex-decode guard is load-bearing)")
	})
	t.Run("malformed_dup_addr", func(t *testing.T) {
		// A duplicate addr — the dedup guard MUST reject (a dup would silently
		// shadow the first in the dial loop's byAddr keying).
		line := "127.0.0.1:9004 " + hex.EncodeToString(node1[:]) + " " + hex.EncodeToString(pub1[:])
		p := writeTempPeerDir(t, line+"\n"+line)
		_, err := parsePeerDir(p)
		if err == nil {
			t.Fatalf("T-OOB-CONFIG-PARSE: parsePeerDir ACCEPTED a duplicate addr — the dedup guard is vestigial")
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("T-OOB-CONFIG-PARSE: the dup-addr reject error does not name the conflict (got %q)", err)
		}
		t.Logf("GATE PASS: T-OOB-CONFIG-PARSE/malformed_dup_addr — a duplicate addr was REJECTED with %q (the dedup guard is load-bearing)", err)
	})
	t.Run("malformed_region_oor", func(t *testing.T) {
		// An out-of-range region (256 — exceeds uint8) — ParseUint(_, 10, 8) MUST reject.
		bad := "127.0.0.1:9004 " + hex.EncodeToString(node1[:]) + " " + hex.EncodeToString(pub1[:]) + " - 256"
		p := writeTempPeerDir(t, bad)
		_, err := parsePeerDir(p)
		if err == nil {
			t.Fatalf("T-OOB-CONFIG-PARSE: parsePeerDir ACCEPTED an out-of-range region 256 — the uint8 guard is vestigial")
		}
		t.Logf("GATE PASS: T-OOB-CONFIG-PARSE/malformed_region_oor — an out-of-range region was REJECTED (the uint8 guard is load-bearing)")
	})
}

// TestT_OOB_APPLY is the T-OOB-APPLY tooth: applyProvisioning registers each
// peer's Ed25519 pubkey via gossiper.RegisterPeer (+ dir.RegisterPQ for the PQ
// arm) + re-keys the TopologyManager's region tag under the REAL nodeID
// (topo.SetRegion) → the topology selector HITS. The tooth builds a minimal
// gossiper (NewGossiper is nil-peers-safe — gossip.go:305 — RegisterPeer only
// touches g.domains, NOT g.peers) + a real Directory + a real TopologyManager,
// applies the known-good config, + asserts:
//
//   - the Directory resolves each peer's nodeID → its Ed25519 pubkey (Register);
//   - the Directory resolves the hybrid peer's nodeID → BOTH pubkeys (LookupBoth);
//   - the TopologyManager's region tag is keyed under the REAL nodeID (the Day-35
//     retirement) → IsInterRegion(realNodeID) returns true for the cross-region peer.
//
// The RED control (the Day-34 surrogate path): keying the topology under a
// SURROGATE nodeID → IsInterRegion(realNodeID) is false → the selector misses →
// the N=2 no-op reproduces (proving the Day-35 re-keying is load-bearing).
func TestT_OOB_APPLY(t *testing.T) {
	path, node1, node2, node3, pub1, pub2, pub3, pq2 := knownGoodPeerDir(t)

	dir := identity.NewDirectory()
	topo := mesh.NewTopologyManager(mesh.RegionTag(1)) // self-region 1
	// A minimal gossiper: NewGossiper is nil-peers-safe (gossip.go:305; the
	// /v1/insert path constructs one with a nil PeerSet). RegisterPeer only
	// touches g.domains (gossip.go:598), so a nil PeerSet + nil engine + nil
	// owner are safe for the APPLY tooth (which never dials / signs / sweeps).
	gossiper := mesh.NewGossiper(nil, nil, nil, dir)

	// Day 35 /code-review refactor: applyProvisioning now takes the pre-parsed
	// cfgs (the main.go surrogate-pollution fix parses --peer-dir ONCE before
	// the Day-34 region loop). The teeth mirror main.go: parsePeerDir(path) →
	// applyProvisioning(cfgs). parsePeerDir surfaces the missing-file FAILSAFE
	// error + the malformed-entry named-line error the teeth assert.
	cfgs, perr := parsePeerDir(path)
	if perr != nil {
		t.Fatalf("T-OOB-APPLY: parsePeerDir(%q): %v", path, perr)
	}
	provisioned, err := applyProvisioning(gossiper, dir, topo, cfgs)
	if err != nil {
		t.Fatalf("T-OOB-APPLY: applyProvisioning: %v", err)
	}
	// The provisioned map keys addr → real nodeID for the dial loop's branch.
	if len(provisioned) != 3 {
		t.Fatalf("T-OOB-APPLY: provisioned map has %d entries, want 3", len(provisioned))
	}
	if provisioned["127.0.0.1:9001"] != node1 || provisioned["127.0.0.1:9002"] != node2 || provisioned["127.0.0.1:9003"] != node3 {
		t.Fatalf("T-OOB-APPLY: provisioned map mismatch (got %+v)", provisioned)
	}
	// The Directory resolves each peer's nodeID → its Ed25519 pubkey (the
	// verification anchor the receiver's Directory.Lookup reads).
	for _, c := range []struct {
		node [16]byte
		pub  [32]byte
	}{
		{node1, pub1}, {node2, pub2}, {node3, pub3},
	} {
		got, ok := dir.Lookup(c.node)
		if !ok {
			t.Fatalf("T-OOB-APPLY: Directory.Lookup(%x) MISSED — RegisterPeer did not register the peer's pubkey", c.node)
		}
		if !bytesEqual(got, c.pub[:]) {
			t.Fatalf("T-OOB-APPLY: Directory.Lookup(%x) returned %x, want %x — the pubkey did not round-trip", c.node, got, c.pub)
		}
	}
	// The hybrid peer resolves to BOTH pubkeys (the Day-32 LookupBoth seam).
	edPub, pqPub, ok := dir.LookupBoth(node2)
	if !ok {
		t.Fatalf("T-OOB-APPLY: Directory.LookupBoth(%x) MISSED — RegisterPQ did not register the PQ pubkey", node2)
	}
	if !bytesEqual(edPub, pub2[:]) {
		t.Fatalf("T-OOB-APPLY: LookupBoth(%x) edPub=%x, want %x", node2, edPub, pub2)
	}
	if pqPub == nil || !bytesEqual(pqPub.Bytes(), pq2.Bytes()) {
		t.Fatalf("T-OOB-APPLY: LookupBoth(%x) pqPub does not match the minted PQ pubkey", node2)
	}
	// Peer-1 + peer-2 are NOT PQ-registered → LookupBoth returns a nil pqPub
	// (the classical-only STRICT mode — Register was called, RegisterPQ was NOT).
	if _, pq1, ok1 := dir.LookupBoth(node1); ok1 && pq1 != nil {
		t.Fatalf("T-OOB-APPLY: peer-1 (classical-only) should have a nil pqPub, got non-nil — RegisterPQ was called for a classical-only peer (a bug)")
	}
	// The TopologyManager's region tag is keyed under the REAL nodeID (the
	// Day-35 retirement). Peer-2 is region 7 (cross-region vs self-region 1) →
	// IsInterRegion(node2)=true → the inter-region arm fires. Peer-1 is region 3
	// (also cross-region) → IsInterRegion(node1)=true.
	if !topo.IsInterRegion(node2) {
		t.Fatalf("T-OOB-APPLY: topo.IsInterRegion(%x)=false after applyProvisioning (peer-2 is region 7, self is region 1 — should be cross-region) — the topology was keyed under a SURROGATE, NOT the real nodeID; the Day-35 retirement is broken", node2)
	}
	if !topo.IsInterRegion(node1) {
		t.Fatalf("T-OOB-APPLY: topo.IsInterRegion(%x)=false after applyProvisioning (peer-1 is region 3, self is region 1)", node1)
	}
	// Peer-3 has NO region (hasRegion=false) → applyProvisioning did NOT call
	// SetRegion for it → IsInterRegion(node3)=false (untagged = intra = the
	// conservative default).
	if topo.IsInterRegion(node3) {
		t.Fatalf("T-OOB-APPLY: topo.IsInterRegion(%x)=true after applyProvisioning (peer-3 has NO region — applyProvisioning should NOT have called SetRegion for it)", node3)
	}
	t.Logf("GATE PASS: T-OOB-APPLY — applyProvisioning registered 3 pubkeys (1 hybrid via RegisterPQ) + re-keyed the topology under the REAL nodeIDs → IsInterRegion fires for the cross-region peers (the Day-34 surrogate path retired); peer-3 (no region) stays intra")

	// The RED control: the Day-34 surrogate path. Key the topology under a
	// SURROGATE nodeID (peerIDForAddr(addr) — a SHA-256 surrogate; here a fixed
	// stand-in) → IsInterRegion(realNodeID) is false → the selector misses →
	// the N=2 no-op reproduces (proving the Day-35 re-keying is load-bearing).
	surrogate := [16]byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
	topoRed := mesh.NewTopologyManager(mesh.RegionTag(1))
	topoRed.SetRegion(surrogate, mesh.RegionTag(7)) // the Day-34 surrogate keying
	if topoRed.IsInterRegion(node2) {
		t.Fatalf("T-OOB-APPLY RED: the Day-34 surrogate path made topo.IsInterRegion(real %x) TRUE — the RED did NOT reproduce the no-op (the surrogate == the real nodeID by accident — a build bug in the RED)", node2)
	}
	t.Logf("GATE PASS: T-OOB-APPLY RED — the Day-34 surrogate path MISSES (topo.IsInterRegion(real %x)=false when the region is keyed under the surrogate %x) — the N=2 no-op reproduces, proving the Day-35 re-keying is load-bearing", node2, surrogate)
}

// TestT_OOB_EMPTY_NO_OP is the T-OOB-EMPTY-NO-OP tooth: an empty --peer-dir
// (the OPT-IN default) returns an empty provisioned map + nil → the dial
// loop's ELSE arm runs for every peer (zero peerID = byte-identical Day-34).
// The honest no-op — distinct from a NON-EMPTY path that does not exist (the
// missing-path tooth below).
func TestT_OOB_EMPTY_NO_OP(t *testing.T) {
	dir := identity.NewDirectory()
	topo := mesh.NewTopologyManager(mesh.RegionTag(1))
	gossiper := mesh.NewGossiper(nil, nil, nil, dir)
	// parsePeerDir("") returns ErrPeerDirEmpty (the OPT-IN no-op) — mirror
	// main.go: treat ErrPeerDirEmpty as empty cfgs + nil (NOT a boot error).
	cfgs, perr := parsePeerDir("")
	if perr != nil && !errors.Is(perr, ErrPeerDirEmpty) {
		t.Fatalf("T-OOB-EMPTY-NO-OP: parsePeerDir(\"\") returned err=%v (want ErrPeerDirEmpty or nil — the empty path is the OPT-IN no-op)", perr)
	}
	provisioned, err := applyProvisioning(gossiper, dir, topo, cfgs)
	if err != nil {
		t.Fatalf("T-OOB-EMPTY-NO-OP: applyProvisioning(\"\") returned err=%v (want nil — the empty path is the OPT-IN no-op, NOT a boot error)", err)
	}
	if len(provisioned) != 0 {
		t.Fatalf("T-OOB-EMPTY-NO-OP: applyProvisioning(\"\") returned %d entries (want 0 — the empty path provisions NOTHING; the dial loop keeps the zero peerID)", len(provisioned))
	}
	if dir.Len() != 0 {
		t.Fatalf("T-OOB-EMPTY-NO-OP: Directory.Len()=%d after applyProvisioning(\"\") (want 0 — the empty path registers NOTHING)", dir.Len())
	}
	t.Logf("GATE PASS: T-OOB-EMPTY-NO-OP — applyProvisioning(\"\") returned an empty map + nil (the OPT-IN no-op; the dial loop's ELSE arm runs for every peer = zero peerID = byte-identical Day-34)")
}

// TestT_OOB_MISSING_PATH_FAILS is the T-OOB-MISSING-PATH-FAILS tooth: a NON-EMPTY
// path that does not exist FAILS the boot (a deploy misconfiguration MUST
// surface loudly, NOT silently fall back to zero-peerID — the silent-partition
// class the honest-negative posture forbids). Distinct from the empty-path
// no-op (T-OOB-EMPTY-NO-OP): an operator who NAMES a file that is absent has
// misconfigured the deploy; the boot MUST fail.
func TestT_OOB_MISSING_PATH_FAILS(t *testing.T) {
	dir := identity.NewDirectory()
	topo := mesh.NewTopologyManager(mesh.RegionTag(1))
	gossiper := mesh.NewGossiper(nil, nil, nil, dir)
	missing := filepath.Join(t.TempDir(), "does-not-exist.conf")
	// parsePeerDir surfaces the missing-file FAILSAFE error (the deploy
	// misconfiguration MUST be loud — the silent-partition class the honest-
	// negative posture forbids). NOT ErrPeerDirEmpty (the path is non-empty).
	cfgs, err := parsePeerDir(missing)
	if err == nil {
		t.Fatalf("T-OOB-MISSING-PATH-FAILS: parsePeerDir(%q) returned nil err (want non-nil — a named-but-absent --peer-dir is a deploy misconfiguration that MUST fail loudly, NOT silently fall back to zero-peerID)", missing)
	}
	if cfgs != nil {
		t.Fatalf("T-OOB-MISSING-PATH-FAILS: parsePeerDir(%q) returned non-nil cfgs (want nil on error)", missing)
	}
	if errors.Is(err, ErrPeerDirEmpty) {
		t.Fatalf("T-OOB-MISSING-PATH-FAILS: parsePeerDir(%q) returned ErrPeerDirEmpty (want a missing-file error — the path is non-empty, NOT the OPT-IN no-op)", missing)
	}
	// applyProvisioning with nil cfgs (the parse failed) is a no-op that returns
	// an empty map + nil — the missing-path error is the PARSE's responsibility
	// (mirroring main.go: parsePeerDir surfaces it before applyProvisioning).
	provisioned, applyErr := applyProvisioning(gossiper, dir, topo, cfgs)
	_ = provisioned
	_ = applyErr
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("T-OOB-MISSING-PATH-FAILS: the error does not name the path (got %q)", err)
	}
	t.Logf("GATE PASS: T-OOB-MISSING-PATH-FAILS — applyProvisioning(%q) FAILED loudly (%q) — a deploy misconfiguration surfaces, NOT a silent zero-peerID fallback", missing, err)
}

// writeTempPeerDir writes a single content string to a temp peer-dir config + returns its path.
func writeTempPeerDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "peerdir.conf")
	if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("writeTempPeerDir: WriteFile %s: %v", p, err)
	}
	return p
}

// bytesEqual is a small helper to avoid importing bytes.Equal (the test compares
// []byte slices from the Directory + the mldsa pubkey); a direct loop is the
// zero-dependency form the provisioning.go parser itself uses.
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

// TestT_OOB_SURROGATE_RETIREMENT is the T-OOB-SURROGATE-RETIREMENT tooth — the
// Day-35 /code-review surrogate-pollution fix (altitude #1 + Angle C #2). A
// peer tagged @region in --peers AND provisioned in --peer-dir must have its
// region keyed under the REAL nodeID (applyProvisioning's SetRegion), NOT the
// peerIDForAddr(addr) surrogate — so topology.Select does NOT carry a dead
// surrogate (no live peerConn keys it) that would consume an inter-region
// fan-out slot + evict a real cross-region peer.
//
// The tooth calls applySurrogateRegions (the REAL helper main.go calls, NOT a
// re-implementation) + simulates applyProvisioning's SetRegion(realNodeID,
// region) on the SAME topo, then asserts:
//   - the REAL nodeID IS in the registry (region keyed) + IsInterRegion=true;
//   - the surrogate peerIDForAddr(addr) is NOT in the registry (the gate
//     skipped it — the dead-surrogate pollution is retired).
//
// RED control: applySurrogateRegions with an EMPTY provisionedAddr (no --peer-dir)
// → the surrogate IS keyed (the Day-34 path) → the dead surrogate pollutes
// the registry. This proves the gate is load-bearing: remove the
// `if provisionedAddr[addr] { continue }` and the RED would re-key the
// surrogate, failing the GREEN assertion.
func TestT_OOB_SURROGATE_RETIREMENT(t *testing.T) {
	selfRegion := mesh.RegionTag(1)
	peerAddr := "10.0.0.2:7430"
	peerRegion := mesh.RegionTag(3)
	peerNodeID := [16]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	surrogate := peerIDForAddr(peerAddr) // the Day-34 SHA-256 surrogate
	if surrogate == peerNodeID {
		t.Fatalf("T-OOB-SURROGATE-RETIREMENT: the surrogate == the real nodeID by construction (a test bug — pick a distinct peerNodeID)")
	}

	// RED — the Day-34 path (EMPTY provisionedAddr = no --peer-dir). The
	// surrogate IS keyed → the dead surrogate pollutes the registry.
	topoRed := mesh.NewTopologyManager(selfRegion)
	applySurrogateRegions(topoRed, peerAddr+"@3", map[string]bool{})
	if !topoRed.IsInterRegion(surrogate) {
		t.Fatalf("T-OOB-SURROGATE-RETIREMENT RED: the Day-34 path (empty provisionedAddr) did NOT key the surrogate %x — the RED did NOT reproduce the pollution (topo.IsInterRegion(surrogate)=false, want true)", surrogate)
	}
	t.Logf("GATE PASS: T-OOB-SURROGATE-RETIREMENT RED — the Day-34 path keys the surrogate %x (the dead-surrogate pollution reproduces) → the Day-35 gate is load-bearing", surrogate)

	// THE RETIREMENT — the Day-35 path (provisionedAddr carries the peer's
	// addr). applySurrogateRegions SKIPS the surrogate; applyProvisioning's
	// SetRegion(realNodeID, region) keys the real nodeID instead.
	topo := mesh.NewTopologyManager(selfRegion)
	applySurrogateRegions(topo, peerAddr+"@3", map[string]bool{peerAddr: true})
	topo.SetRegion(peerNodeID, peerRegion) // the applyProvisioning SetRegion under the REAL nodeID
	if topo.IsInterRegion(surrogate) {
		t.Fatalf("T-OOB-SURROGATE-RETIREMENT: the surrogate %x IS in the registry after applySurrogateRegions with the provisionedAddr gate — the dead-surrogate pollution was NOT retired (the gate `if provisionedAddr[addr] { continue }` is missing or broken)", surrogate)
	}
	if !topo.IsInterRegion(peerNodeID) {
		t.Fatalf("T-OOB-SURROGATE-RETIREMENT: the REAL nodeID %x is NOT in the registry after applyProvisioning's SetRegion — the region was keyed under neither the surrogate NOR the real nodeID (topo.IsInterRegion(real)=false, want true; self=%d peer=%d)", peerNodeID, selfRegion, peerRegion)
	}
	t.Logf("GATE PASS: T-OOB-SURROGATE-RETIREMENT — the surrogate %x is NOT in the registry (the gate skipped it) + the REAL nodeID %x IS keyed + IsInterRegion=true → topology.Select carries NO dead surrogate → the inter-region fan-out slot is NOT wasted", surrogate, peerNodeID)

	// The load-bearing assertion: Select returns the REAL nodeID, NOT the
	// surrogate (the dead surrogate does NOT consume a fan-out slot).
	topo.SetSeed(1)
	sel := topo.Select(context.Background())
	for _, id := range sel {
		if id == surrogate {
			t.Fatalf("T-OOB-SURROGATE-RETIREMENT: Select returned the DEAD surrogate %x (a fan-out slot wasted on a peer no live peerConn keys) — the pollution was NOT retired", surrogate)
		}
	}
	foundReal := false
	for _, id := range sel {
		if id == peerNodeID {
			foundReal = true
		}
	}
	if !foundReal {
		t.Fatalf("T-OOB-SURROGATE-RETIREMENT: Select did NOT return the REAL nodeID %x (got %d peerIDs) — the inter-region arm lost its only cross-region peer", peerNodeID, len(sel))
	}
	t.Logf("GATE PASS: T-OOB-SURROGATE-RETIREMENT — Select returns the REAL nodeID %x (NOT the dead surrogate) → no fan-out slot wasted → convergence + the 24th counter are not degraded by dead surrogates", peerNodeID)
}

// TestT_OOB_NODEID_DEDUP is the T-OOB-NODEID-DEDUP tooth — the Day-35
// /code-review finding #3 (Angle D #3 + Angle C #8). parsePeerDir MUST reject
// two config lines with the SAME nodeID but DIFFERENT addrs (a multi-homed
// peer OR a copy-paste deploy error). The PRE-EXISTING addr-only dedup
// (provisioning.go:210 `seen[cfg.addr]`) let both pass → applyProvisioning's
// second RegisterPeer/RegisterPQ silently OVERWROTE the first's Directory
// binding (directory.go d.m[nodeID]=canonical, no error) → the first peer's
// deltas (signed under the first peer's seed) DROPPED as forged → a silent
// partition the FAILSAFE parser must catch.
//
// The tooth builds a 2-line config with the same nodeID + different addrs +
// asserts parsePeerDir REJECTS it with a duplicate-nodeID error. RED control:
// a 2-line config with DIFFERENT nodeIDs + different addrs is ACCEPTED (the
// dedup is nodeID-specific, not a false reject).
func TestT_OOB_NODEID_DEDUP(t *testing.T) {
	// Two distinct addrs sharing ONE nodeID — the deploy error the dedup catches.
	// The nodeID column is 32 hex chars (16 bytes); the ed25519 pubkey is 64 hex
	// chars (32 bytes). Both lines carry the SAME 32-char nodeID + different
	// addrs so the dedup (NOT the length check) is the gate that rejects.
	nodeID := [16]byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	nodeHex := strings.Repeat("44", 16) // 16-byte nodeID (32 hex chars)
	edHex := strings.Repeat("44", 32)   // 32-byte Ed25519 pubkey (64 hex chars)
	dupCfg := "10.0.0.2:7430 " + nodeHex + " " + edHex + "\n" +
		"10.0.0.3:7430 " + nodeHex + " " + edHex + "\n"
	dupPath := writeTempPeerDir(t, dupCfg)
	cfgs, err := parsePeerDir(dupPath)
	if err == nil {
		t.Fatalf("T-OOB-NODEID-DEDUP: parsePeerDir accepted two lines with the SAME nodeID %x but DIFFERENT addrs (the addr-only dedup let both pass → the second RegisterPeer would silently overwrite the first's Directory binding → the first peer's deltas dropped as forged — a silent partition the FAILSAFE parser must reject)", nodeID)
	}
	// The rejection MUST be the nodeID-dedup (NOT the length check — both lines
	// are well-formed). Assert the error names the duplicate nodeID so the tooth
	// cannot pass on a wrong-reason rejection.
	if !strings.Contains(err.Error(), "duplicate peer nodeID") {
		t.Fatalf("T-OOB-NODEID-DEDUP: parsePeerDir rejected the dup-nodeID config but the error does NOT name the duplicate (got %q — want a 'duplicate peer nodeID' error, NOT a length/decode error — the dedup is the gate that fired)", err.Error())
	}
	_ = cfgs
	t.Logf("GATE PASS: T-OOB-NODEID-DEDUP — parsePeerDir REJECTED two lines with the same nodeID %x + different addrs via the nodeID-dedup (the error names the duplicate → the silent-shadow deploy error is caught)", nodeID)

	// RED control — two DISTINCT nodeIDs + distinct addrs MUST be accepted (the
	// dedup is nodeID-specific, NOT a false reject of a legitimate multi-peer
	// config). Without this control the dedup could reject ALL multi-line
	// configs + the GREEN above would be vacuous. The nodeID column is 32 hex
	// chars (16 bytes); the ed25519 pubkey column is 64 hex chars (32 bytes).
	distinctCfg := "10.0.0.2:7430 " + strings.Repeat("44", 16) + " " + edHex + "\n" +
		"10.0.0.3:7430 " + strings.Repeat("55", 16) + " " + strings.Repeat("55", 32) + "\n"
	distinctPath := writeTempPeerDir(t, distinctCfg)
	dcfgs, derr := parsePeerDir(distinctPath)
	if derr != nil {
		t.Fatalf("T-OOB-NODEID-DEDUP RED-control: parsePeerDir rejected a LEGITIMATE 2-peer config with distinct nodeIDs (got %v) — the dedup is a false-positive, NOT a nodeID-specific guard", derr)
	}
	if len(dcfgs) != 2 {
		t.Fatalf("T-OOB-NODEID-DEDUP RED-control: parsePeerDir returned %d cfgs (want 2) — a legitimate 2-peer config was not fully parsed", len(dcfgs))
	}
	t.Logf("GATE PASS: T-OOB-NODEID-DEDUP RED-control — a legitimate 2-peer config with distinct nodeIDs is ACCEPTED (the dedup is nodeID-specific, NOT a false reject)")
}
