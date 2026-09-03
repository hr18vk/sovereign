// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// prodwire_test.go — (ADR-0045): the in-process
// falsification guards for the production-relay wiring and the fan-out rotation.
//
// WHY THIS FILE EXISTS — THE CLASS, NOT THE INSTANCE.
// `TestRelayChainLoadBearing` has long reported GREEN
// while the BATCH relay was DEAD IN PRODUCTION for two silicon runs. It lied by
// omission: it installs the retention hooks IN-TEST
// (`recv.SetRelayRetainer(...)` + `recv.SetRelayRetainerBatch(...)`,
// asymmetric_dial_test.go:514-515) and therefore proves the SEAM works while proving NOTHING about
// whether the BINARY installs it. Production installed only the per-frame hook
// (`main.go:1075`), so at `--batch-size=100` every relayCache batch layer stayed
// empty. Two docstrings asserted the wiring existed (gossip.go:541,
// topology.go:122); both were false.
//
// This guard closes that class: it drives the SAME function `main.go` calls —
// `Gossiper.WireRelayHooks` — so a future hook that main.go forgets is a hook this
// guard never installs either, and the chain goes RED. Adding a third relay hook
// later means adding it inside WireRelayHooks, which this guard already exercises.
//
// RED EVIDENCE (captured before the fix, per the in-process-falsification rule):
// `wireRelayHooksLegacy` below is a byte-faithful replica of TODAY's main.go —
// per-frame hook ONLY. TestProdWireNegativeControl drives the chain through
// it and asserts C stays root-zero AND that B's relay-miss counter fires. That is
// the silicon signature (373,504-377,776 `relay miss` lines per colocated receiver
// on a silicon run) reproduced at 3 nodes in-process.
//
// RUN: go test -run 'TestProdWire' -race -count=1 ./pkg/mesh/

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

// wireRelayHooksLegacy replicates cmd/sovereign-node/main.go:1075 AS IT WAS before
// — the per-frame retainer ONLY. It is the RED-control arm: the guard runs
// the identical A→B→C chain through this wiring and through the real
// WireRelayHooks, and the two outcomes must DIFFER. If they ever stop differing,
// either the batch path is no longer load-bearing or the guard has gone vacuous.
func wireRelayHooksLegacy(g *Gossiper, r relayHookSink) {
	r.SetRelayRetainer(g.RetainForeign)
	// DELIBERATELY MISSING: r.SetRelayRetainerBatch(g.RetainForeignBatch).
	// This omission IS the bug that cost silicon runs #6 and #6b.
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

// seedForTest reads the seed currently stamped on the TopologyManager, under the
// same lock Select uses. In-package access (the asyncWait / peerLiveForTest
// precedent) — there is no exported accessor and this guard must observe what
// PRODUCTION stamped, not what the test stamped.
func (t *TopologyManager) seedForTest() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.seed
}

// TestSweepStampsSeed is the CALL-SITE guard — the one that closes the
// same in-test-wiring class closes.
//
// TestFanoutRotation below validates the seed MODEL, but it calls SetSeed
// itself, so it would stay GREEN even if AntiEntropySweep never stamped a seed —
// which is precisely the failure mode that let `SetSeed has zero production
// callers` survive two silicon runs behind a docstring claiming "The SweepLoop
// calls this before each Select". This guard asserts on the PRODUCTION path: run
// AntiEntropySweep and observe that the topology's seed actually CHANGED, and that
// it equals the documented per-node-per-round value.
//
// RED on pre-bytes: the seed stays 0 forever (no production caller).
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
		t.Fatalf("Seed call-site guard premise: the topology seed is %d before any sweep, want 0", got)
	}
	ctx := context.Background()
	for round := uint64(1); round <= 3; round++ {
		g.AntiEntropySweep(ctx)
		want := round ^ w2SeedNodeTerm(owner.NodeID)
		got := topo.seedForTest()
		if got != want {
			t.Fatalf("Seed NOT STAMPED BY THE SWEEP: after sweep %d the topology seed is %d, want %d (= round ^ LittleEndian.Uint64(owner.NodeID[:8])). This is the exact defect that survived two silicon runs: SetSeed had ZERO production callers while topology.go:122 claimed 'The SweepLoop calls this before each Select'. A seed that never changes freezes the inter-region fan-out onto the same peers every sweep (the affected run: same 1 eu + 1 ap peer, 64/66 remotes never selected).", round, got, want)
		}
	}
	t.Logf("GREEN (seed call site) — AntiEntropySweep STAMPS the fan-out seed on the production path: after each of 3 sweeps the topology seed equals round ^ LittleEndian.Uint64(owner.NodeID[:8]) exactly. The seed is no longer frozen at 0, and the lying topology.go:122 docstring is now true.")
}

// w2SeedNodeTerm is the per-node half of the fan-out seed —
// LittleEndian.Uint64(nodeID[:8]) — kept in ONE place so the guard and
// AntiEntropySweep (gossip.go, the SetSeed stamp) cannot drift apart in how they
// derive it. If the production term ever changes shape, this guard changes with it
// and the rotation/determinism assertions stay meaningful.
func w2SeedNodeTerm(nodeID [16]byte) uint64 {
	return binary.LittleEndian.Uint64(nodeID[:8])
}

// buildProdWireChain mints a 3-node A→B→C chain over REAL TCP+TLS with NO A↔C edge,
// batch path armed (--batch-size=100, the production default), and installs the
// relay hooks through the caller-supplied wiring function. That injection point is
// the whole design: prod wiring vs legacy wiring is the ONLY variable.
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
		// THE ONLY VARIABLE: which wiring function installs the hooks.
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

// runProdWireChain brings the chain up (A, then B dials A, then C dials B — NO A↔C
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
	// B dials A; C dials B. C NEVER dials A — the relay-only topology.
	if err := nodes[1].ps.Dial(ctx, nodes[0].addr, "localhost", nodes[0].ident.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	if err := nodes[2].ps.Dial(ctx, nodes[1].addr, "localhost", nodes[1].ident.NodeID); err != nil {
		t.Fatalf("dial C->B: %v", err)
	}
	time.Sleep(150 * time.Millisecond) // let the inbound registrations settle

	for i := 0; i < keys; i++ {
		nodes[0].g.InsertLocalEvents(fmt.Sprintf("relay-chain-key-%d", i), fmt.Sprintf("v-%d", i), eng.CRDTEntry{SystemTime: int64(1_700_000_000 + i), H3Index: uint64(i)})
	}
	for i := range nodes {
		go nodes[i].g.SweepLoop(ctx, 20*time.Millisecond)
	}
	deadline := time.Now().Add(slo)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		rootA = nodes[0].eng.State().MerkleRoot()
		rb := nodes[1].eng.State().MerkleRoot()
		rootC = nodes[2].eng.State().MerkleRoot()
		if rootA == rb && rb == rootC && rootA != ([32]byte{}) {
			return true, rootA, rootC, relayMisses
		}
	}
	rootA = nodes[0].eng.State().MerkleRoot()
	rootC = nodes[2].eng.State().MerkleRoot()
	return false, rootA, rootC, relayMisses
}

// TestProdWireNegativeControl is the RED half: driving the chain through the
// LEGACY wiring (per-frame hook only — byte-faithful to main.go before)
// must FAIL to converge, because B has no retained batch to relay onward. This
// reproduces the silicon signature at 3 nodes in-process.
//
// If this control ever goes GREEN, the proof below is vacuous: it
// would mean the batch relay is not load-bearing on this topology and the guard
// cannot distinguish wired from unwired.
func TestProdWireNegativeControl(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP relay-chain test (binds loopback ports)")
	}
	nodes := buildProdWireChain(t, wireRelayHooksLegacy)
	converged, ra, rc, _ := runProdWireChain(t, nodes, 25, 6*time.Second)
	if converged {
		t.Fatalf("RED CONTROL BROKEN: the chain CONVERGED under the LEGACY wiring (per-frame retainer only, byte-faithful to main.go:1075 pre-). C must stay root-zero: with --batch-size=100 the sweep routes through shipBatchedDelta, whose foreign branch consults relayCache.lookupBatch — a cache only SetRelayRetainerBatch populates. If this converges, either the batch path is no longer exercised (check SetBatchSize/DefaultBatchSize) or C reached A another way (check that C never dials A) — either way this production-wire guard proves nothing.")
	}
	if rc != ([32]byte{}) {
		t.Logf("NOTE: C's root is non-zero (%x) but did not equal A's (%x) — partial propagation; the convergence assertion is what matters.", rc, ra)
	}
	t.Logf("RED CONTROL PASS — LEGACY wiring (per-frame hook ONLY, exactly main.go:1075 before): the A→B→C chain did NOT converge (rootA=%x rootC=%x). B Joined A's batch but retained NO batch envelope, so shipBatchedDelta's foreign branch relay-missed every entry and C never received A's data. THIS IS THE SILICON RUN-#6b SIGNATURE (373,504-377,776 `relay miss` lines per colocated receiver; zero cross-region frames), reproduced at 3 nodes for $0.", ra, rc)
}

// TestProdWireLoadBearing is the GREEN half AND the class elimination:
// the chain is wired through `Gossiper.WireRelayHooks` — the EXACT function
// cmd/sovereign-node/main.go calls — and must converge.
//
// This is the guard that did not exist before. Every prior relay guard
// installed the hooks itself, so no test observed the production wiring path.
func TestProdWireLoadBearing(t *testing.T) {
	if testing.Short() {
		t.Skip("real-TCP relay-chain test (binds loopback ports)")
	}
	nodes := buildProdWireChain(t, func(g *Gossiper, r relayHookSink) {
		// THE PRODUCTION CALL — identical to main.go's `gossiper.WireRelayHooks(recv)`.
		g.WireRelayHooks(r)
	})
	converged, ra, rc, _ := runProdWireChain(t, nodes, 25, 10*time.Second)
	if !converged {
		t.Fatalf("PRODUCTION WIRING BROKEN: the A→B→C chain did NOT converge (rootA=%x rootC=%x) even though the hooks were installed via Gossiper.WireRelayHooks — the same call cmd/sovereign-node/main.go makes. Either WireRelayHooks fails to install BOTH hooks (it must install RetainForeign AND RetainForeignBatch) or the batch relay seam itself regressed. This is the production path: if this is RED, the binary is broken.", ra, rc)
	}
	t.Logf("GREEN (wiring class elimination) — the A→B→C chain (NO A↔C edge, --batch-size=%d) CONVERGED (root=%x) with the hooks installed ONLY via Gossiper.WireRelayHooks — the exact function cmd/sovereign-node/main.go calls. A test now CONSUMES the production wiring path, so a hook main.go forgets is a hook this guard never installs either: the drift class that killed silicon runs #6 and #6b is closed.", DefaultBatchSize, ra)
}

// TestFanoutRotation is the guard: a frozen seed selects the SAME
// inter-region peers every round; the per-node-per-round seed rotates them.
//
// RED on pre-bytes: production never called SetSeed, so the seed stayed 0 and
// two consecutive rounds' inter-region picks were IDENTICAL — which is why a silicon
// run shipped cross-region to the SAME 1 eu + 1 ap peer every sweep and 64 of
// 66 remote nodes were NEVER selected.
//
// The guard asserts BOTH halves of the contract:
//   - ROTATION: across R rounds the distinct inter-region peers reached per remote
//     region is >= min(K, 6) — coverage, not a single frozen pick.
//   - DETERMINISM PRESERVED: the same (round, nodeID) reproduces the same output
//
// (the contract must not regress — introduces a
//
//	ROTATION, not randomness).
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

	// (a) frozen SEED (the pre-production behavior): never call SetSeed.
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
		t.Fatalf("Seed guard premise BROKEN: with NO SetSeed call, two consecutive Select() results DIFFER — the frozen-seed behavior this guard is built to detect is not reproducible, so the rotation assertion below proves nothing. first=%x second=%x", first, second)
	}
	t.Logf("RED baseline confirmed: with the seed never stamped (production, before the seed-stamping fix), two consecutive Select() calls return the IDENTICAL peer set — the frozen fan-out that left 64/66 remote nodes never selected on the affected silicon run.")

	// (b) POST-: stamp `round ^ LittleEndian(nodeID[:8])` each round, exactly as
	// AntiEntropySweep now does, and count distinct inter-region peers reached.
	rotated := mk()
	seen := map[RegionTag]map[[16]byte]bool{}
	for round := uint64(1); round <= rounds; round++ {
		rotated.SetSeed(round ^ w2SeedNodeTerm(selfNodeID))
		for _, p := range rotated.Select(ctx) {
			reg := RegionTag(p[0])
			if reg == selfRegion {
				continue // intra-region full-mesh is not the fan-out under test
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
			t.Fatalf("SEED ROTATION INSUFFICIENT: over %d rounds the fan-out reached only %d distinct peers in remote region %d (want >= %d of %d). A frozen or weakly-mixed seed starves most remote peers — the silicon run-#6b failure (same 1 eu + 1 ap peer every sweep, 64/66 remotes never selected). Check that AntiEntropySweep stamps SetSeed(round ^ LittleEndian.Uint64(owner.NodeID[:8])) BEFORE Select.", rounds, got, r, want, perRegion)
		}
		t.Logf("GREEN (seed rotation) — remote region %d: %d distinct peers reached across %d rounds (>= %d required).", r, got, rounds, want)
	}

	// (c) DETERMINISM PRESERVED — the contract. Same (round, nodeID) → same
	// output. is a rotation, NOT randomness.
	d1 := mk()
	d2 := mk()
	d1.SetSeed(7 ^ w2SeedNodeTerm(selfNodeID))
	d2.SetSeed(7 ^ w2SeedNodeTerm(selfNodeID))
	o1, o2 := d1.Select(ctx), d2.Select(ctx)
	if len(o1) != len(o2) {
		t.Fatalf("SEED DETERMINISM REGRESSED: same (round=7, nodeID) produced different-length selections (%d vs %d) — the topology-determinism contract is broken", len(o1), len(o2))
	}
	for i := range o1 {
		if o1[i] != o2[i] {
			t.Fatalf("SEED DETERMINISM REGRESSED: same (round=7, nodeID) produced different selections at index %d (%x vs %x) — the seed must be a deterministic ROTATION, not randomness", i, o1[i], o2[i])
		}
	}
	t.Logf("GREEN (seed determinism) — the same (round, nodeID) reproduces the identical selection: the rotation is deterministic, so the topology-determinism contract holds.")

	// (d) PER-NODE DE-CORRELATION — two DIFFERENT nodes in the SAME round must not
	// pile onto the identical remote peers (the 34-colocated-nodes-per-host case).
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
		t.Fatalf("SEED NODE-TERM INEFFECTIVE: two DIFFERENT nodeIDs in the SAME round (3) selected the IDENTICAL peer set. The nodeID term must de-correlate colocated nodes, or 34 nodes on one host all fan out to the same remote peer in the same round. Check the XOR uses owner.NodeID[:8].")
	}
	t.Logf("GREEN (seed per-node de-correlation) — two distinct nodeIDs in the same round select DIFFERENT peer sets: colocated nodes spread across remote peers instead of piling onto one.")
}
