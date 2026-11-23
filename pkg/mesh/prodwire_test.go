// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests exercise production relay wiring and fan-out seed rotation
// (ADR-0045).
//
// The relay chain installs hooks through Gossiper.WireRelayHooks, the same entry
// point used by cmd/sovereign-node. A test that installed hooks directly could
// pass while the node left the batch retainer unwired. The negative control uses
// only the per-frame retainer: with batched gossip, B then has no batch envelope
// to relay to C. The production-wiring case must converge on the same topology.
//
// The seed tests separately check the sweep call site and the selector. The
// sweep must stamp round ^ LittleEndian.Uint64(nodeID[:8]); the selector must
// rotate remote peers while remaining deterministic for a given round and node.
//
// Run with: go test -run 'TestProdWire|TestSweepStampsSeed|TestFanoutRotation' -race -count=1 ./pkg/mesh/

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"

	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// wireRelayHooksLegacy installs only the per-frame retainer. Running the same
// A→B→C chain through this function and WireRelayHooks must produce different
// outcomes: without the batch retainer, the relay-only chain cannot converge.
func wireRelayHooksLegacy(g *Gossiper, r relayHookSink) {
	r.SetRelayRetainer(g.RetainForeign)
	// Do not install SetRelayRetainerBatch in this negative control.
}

// prodWireNode is one real-TCP node in the relay chain.
type prodWireNode struct {
	ident *NodeIdentity
	eng   *eng.DeltaCRDTEngine
	recv  *receive.Receiver
	ps    *PeerSet
	g     *Gossiper
	tr    *transport.TLSConnections
	ln    interface{ Close() error }
	addr  string
}

// seedForTest reads the seed stamped by AntiEntropySweep under the same lock
// Select uses. The test must observe the production call rather than setting the
// seed itself.
func (t *TopologyManager) seedForTest() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.seed
}

// TestSweepStampsSeed checks the production call site rather than calling
// SetSeed from the test. After each AntiEntropySweep, the topology seed must
// equal round ^ LittleEndian.Uint64(owner.NodeID[:8]). Without that call, a zero
// seed keeps selecting the same inter-region peers.
func TestSweepStampsSeed(t *testing.T) {
	dir := identity.NewDirectory()
	seedBytes := make([]byte, ed25519.SeedSize)
	for i := range seedBytes {
		seedBytes[i] = byte(i + 41)
	}
	owner, err := NewNodeIdentity(seedBytes)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	engN := newTestEngine(t, owner.NodeID, t.TempDir())
	ps := NewPeerSet(nil, nopFrameSink{}, owner, engN)
	g := NewGossiper(ps, owner, engN, dir)
	topo := NewTopologyManager(RegionTag(1))
	// Register one remote-region peer so Select has an inter-region candidate.
	var remote [16]byte
	remote[0] = 0x02
	remote[1] = 0x07
	topo.SetRegion(remote, RegionTag(2))
	g.SetTopology(topo)
	g.SetRegionAware(true)

	if got := topo.seedForTest(); got != 0 {
		t.Fatalf("topology seed is %d before any sweep, want 0", got)
	}
	ctx := context.Background()
	for round := uint64(1); round <= 3; round++ {
		g.AntiEntropySweep(ctx)
		want := round ^ w2SeedNodeTerm(owner.NodeID)
		got := topo.seedForTest()
		if got != want {
			t.Fatalf("after sweep %d topology seed is %d, want %d (round ^ nodeID term)", round, got, want)
		}
	}
	t.Logf("three sweeps stamped the expected per-round, per-node seeds")
}

// w2SeedNodeTerm is the node-specific half of the fan-out seed. Keeping the
// derivation here and in AntiEntropySweep aligned makes the rotation assertions
// check the intended value.
func w2SeedNodeTerm(nodeID [16]byte) uint64 {
	return binary.LittleEndian.Uint64(nodeID[:8])
}

// buildProdWireChain constructs three TCP+TLS nodes with no direct A↔C edge.
// DefaultBatchSize selects the batched relay path. The supplied function is the
// only difference between the negative control and production-wiring cases.
func buildProdWireChain(t *testing.T, wire func(*Gossiper, relayHookSink)) []*prodWireNode {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	const n = 3
	nodes := make([]*prodWireNode, n)
	for i := 0; i < n; i++ {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("rand seed %d: %v", i, err)
		}
		id, err := NewNodeIdentity(seed)
		if err != nil {
			t.Fatalf("NewNodeIdentity %d: %v", i, err)
		}
		leaf, err := ca.IssueLeaf(identHex(id.NodeID))
		if err != nil {
			t.Fatalf("IssueLeaf %d: %v", i, err)
		}
		certPath, keyPath, err := leaf.WritePEM(filepath.Join(dir, fmt.Sprintf("n%d", i)))
		if err != nil {
			t.Fatalf("WritePEM %d: %v", i, err)
		}
		tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
		if err != nil {
			t.Fatalf("NewTLSTransport %d: %v", i, err)
		}
		arenaDir := filepath.Join(dir, fmt.Sprintf("eng%d", i))
		if err := os.MkdirAll(arenaDir, 0o755); err != nil {
			t.Fatalf("mkdir eng%d: %v", i, err)
		}
		engN := newTestEngine(t, id.NodeID, arenaDir)
		d := identity.NewDirectory()
		recv := receive.NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engN), clock.NewSystemClock(), d, engN, 50_000_000)
		ps := NewPeerSet(tr, recv, id, engN)
		g := NewGossiper(ps, id, engN, d)
		// The only variable: which wiring function installs the hooks.
		wire(g, recv)
		g.SetBatchSize(DefaultBatchSize) // the production --batch-size=100 path
		nodes[i] = &prodWireNode{ident: id, eng: engN, recv: recv, ps: ps, g: g, tr: tr}
	}
	// Cross-register identities so every verify resolves (the Directory is the
	// verification anchor; a miss would DropVerify and confound the relay signal).
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if err := nodes[i].g.RegisterPeer(nodes[j].ident.NodeID, nodes[j].ident.Pub); err != nil {
				t.Fatalf("RegisterPeer %d->%d: %v", i, j, err)
			}
		}
	}
	return nodes
}

// runProdWireChain brings the chain up (A, then B dials A, then C dials B — no A↔C
// edge), injects `keys` events at A only, sweeps all three, and reports whether all
// three Merkle roots converged within the SLO.
func runProdWireChain(t *testing.T, nodes []*prodWireNode, keys int, slo time.Duration) (converged bool, rootA, rootC [32]byte, relayMisses int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := range nodes {
		ln, err := nodes[i].tr.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %d: %v", i, err)
		}
		nodes[i].ln = ln
		nodes[i].addr = ln.Addr().String()
		wg.Add(1)
		go runAcceptLoopWithPeerSet(ctx, ln, nodes[i].recv, nil, &wg, nodes[i].ps)
	}
	t.Cleanup(func() {
		cancel()
		for i := range nodes {
			if nodes[i].ln != nil {
				_ = nodes[i].ln.Close()
			}
		}
		wg.Wait()
	})
	// B dials A; C dials B. C never dials A — the relay-only topology.
	if err := nodes[1].ps.Dial(ctx, nodes[0].addr, "localhost", nodes[0].ident.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	if err := nodes[2].ps.Dial(ctx, nodes[1].addr, "localhost", nodes[1].ident.NodeID); err != nil {
		t.Fatalf("dial C->B: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // let the inbound registrations settle

	for i := 0; i < keys; i++ {
		nodes[0].g.InsertLocalEvents(fmt.Sprintf("prodwire-key-%d", i), fmt.Sprintf("v-%d", i), eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}
	for i := range nodes {
		go nodes[i].g.SweepLoop(ctx, 20*time.Millisecond)
	}
	deadline := time.Now().Add(slo)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		rootA = nodes[0].eng.MerkleRootFromShards()
		rb := nodes[1].eng.MerkleRootFromShards()
		rootC = nodes[2].eng.MerkleRootFromShards()
		if rootA == rb && rb == rootC && rootA != ([32]byte{}) {
			return true, rootA, rootC, relayMisses
		}
	}
	rootA = nodes[0].eng.MerkleRootFromShards()
	rootC = nodes[2].eng.MerkleRootFromShards()
	return false, rootA, rootC, relayMisses
}

// TestProdWireNegativeControl installs only the per-frame retainer. B can join
// A's batch but cannot retain the batch envelope needed by shipBatchedDelta's
// foreign branch, so the A→B→C chain must not converge. Convergence here would
// mean the topology no longer distinguishes wired from unwired batch retention.
func TestProdWireNegativeControl(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP relay-chain test (binds loopback ports)")
	}
	nodes := buildProdWireChain(t, wireRelayHooksLegacy)
	converged, ra, rc, _ := runProdWireChain(t, nodes, 25, 6*time.Second)
	if converged {
		t.Fatalf("chain converged with only the per-frame retainer; check that DefaultBatchSize uses shipBatchedDelta and that C has no direct path to A")
	}
	if rc != ([32]byte{}) {
		t.Logf("C received partial state without converging (rootC=%x rootA=%x)", rc, ra)
	}
	t.Logf("per-frame-only wiring did not converge (rootA=%x rootC=%x)", ra, rc)
}

// TestProdWireLoadBearing installs retainers through Gossiper.WireRelayHooks,
// the same method called by cmd/sovereign-node. The relay-only chain must
// converge, covering both RetainForeign and RetainForeignBatch registration.
func TestProdWireLoadBearing(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP relay-chain test (binds loopback ports)")
	}
	nodes := buildProdWireChain(t, func(g *Gossiper, r relayHookSink) {
		g.WireRelayHooks(r)
	})
	converged, ra, rc, _ := runProdWireChain(t, nodes, 25, 10*time.Second)
	if !converged {
		t.Fatalf("chain did not converge through Gossiper.WireRelayHooks (rootA=%x rootC=%x); check RetainForeign and RetainForeignBatch registration", ra, rc)
	}
	t.Logf("chain converged through production relay wiring with batch size %d (root=%x)", DefaultBatchSize, ra)
}

// TestFanoutRotation checks four properties of the fan-out seed: an unstamped
// seed repeats its selection; per-round seeds reach at least min(K, 6) peers in
// each remote region over R rounds; identical round and node IDs reproduce the
// selection; and different node IDs decorrelate colocated peers' selections.
func TestFanoutRotation(t *testing.T) {
	const (
		regions   = 3
		perRegion = 8
		rounds    = 20
	)
	selfRegion := RegionTag(1)
	mk := func() *TopologyManager {
		topo := NewTopologyManager(selfRegion)
		topo.SetFanout(3)
		for r := 1; r <= regions; r++ {
			for i := 0; i < perRegion; i++ {
				var id [16]byte
				id[0] = byte(r)
				id[1] = byte(i + 1)
				topo.SetRegion(id, RegionTag(r))
			}
		}
		return topo
	}
	ctx := context.Background()
	var selfNodeID [16]byte
	selfNodeID[0] = 0xA5
	selfNodeID[1] = 0x5A

	// Without SetSeed, consecutive selections provide the fixed baseline.
	frozen := mk()
	first := frozen.Select(ctx)
	second := frozen.Select(ctx)
	identical := len(first) == len(second)
	if identical {
		for i := range first {
			if first[i] != second[i] {
				identical = false
				break
			}
		}
	}
	if !identical {
		t.Fatalf("two Select calls without SetSeed returned different peer sets (first=%x second=%x), want identical results", first, second)
	}
	t.Logf("two Select calls without SetSeed returned the same peer set")

	// Stamp the same per-round seed as AntiEntropySweep and count coverage.
	rotated := mk()
	seen := map[RegionTag]map[[16]byte]bool{}
	for round := uint64(1); round <= rounds; round++ {
		rotated.SetSeed(round ^ w2SeedNodeTerm(selfNodeID))
		for _, p := range rotated.Select(ctx) {
			reg := RegionTag(p[0])
			if reg == selfRegion {
				continue // Intra-region full-mesh is not the fan-out under test.
			}
			if seen[reg] == nil {
				seen[reg] = map[[16]byte]bool{}
			}
			seen[reg][p] = true
		}
	}
	want := perRegion
	if want > 6 {
		want = 6
	}
	for r := RegionTag(1); r <= RegionTag(regions); r++ {
		if r == selfRegion {
			continue
		}
		got := len(seen[r])
		if got < want {
			t.Fatalf("over %d rounds fan-out reached %d distinct peers in region %d, want at least %d of %d", rounds, got, r, want, perRegion)
		}
		t.Logf("region %d reached %d distinct peers across %d rounds (minimum %d)", r, got, rounds, want)
	}

	// Equal round and node inputs must reproduce the selection exactly.
	d1 := mk()
	d2 := mk()
	d1.SetSeed(7 ^ w2SeedNodeTerm(selfNodeID))
	d2.SetSeed(7 ^ w2SeedNodeTerm(selfNodeID))
	o1, o2 := d1.Select(ctx), d2.Select(ctx)
	if len(o1) != len(o2) {
		t.Fatalf("equal round and node ID produced selection lengths %d and %d", len(o1), len(o2))
	}
	for i := range o1 {
		if o1[i] != o2[i] {
			t.Fatalf("equal round and node ID produced different peers at index %d (%x vs %x)", i, o1[i], o2[i])
		}
	}
	t.Logf("equal round and node ID reproduced the same selection")

	// The node ID term must decorrelate colocated nodes in the same round.
	var otherNode [16]byte
	otherNode[0] = 0x11
	otherNode[1] = 0x22
	nA, nB := mk(), mk()
	nA.SetSeed(3 ^ w2SeedNodeTerm(selfNodeID))
	nB.SetSeed(3 ^ w2SeedNodeTerm(otherNode))
	sa, sb := nA.Select(ctx), nB.Select(ctx)
	same := len(sa) == len(sb)
	if same {
		for i := range sa {
			if sa[i] != sb[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatalf("different node IDs selected the same peer set in round 3; check the nodeID XOR term")
	}
	t.Logf("different node IDs selected different peer sets in the same round")
}
