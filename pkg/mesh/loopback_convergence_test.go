// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh_test

// These tests run real DeltaCRDTEngine instances over a chaos VirtualNet in
// three regions. They measure convergence in gossip rounds using the fan-out-3
// TopologyManager selector; they do not measure WAN wall time (ADR-0041).
//
// The external mesh_test package can import both pkg/mesh and internal/chaos
// without creating an import cycle. It owns the engine map and uses the chaos
// Orchestrator for receive wiring and Merkle roots. The small codec and network
// helpers match their internal/chaos counterparts byte for byte.
//
// RunGossipRound always selects the full mesh, so these tests call VirtualNet.Send
// for the peers returned by each node's TopologyManager.Select. BindNodes joins
// each delta when the virtual network delivers it.
//
// A root comparison alone can pass after a boot failure or when no writes arrive.
// The convergence checks therefore require every node, reject the empty-tree root,
// and read a source key from the final node. Negative controls drop all deltas at
// one node and remove a partition to show that both failures are observable.
//
// The 100-engine tests allocate substantial arena and race-detector shadow memory.
// State also builds transient merged HAMT views that are reclaimed as Join advances
// EBR epochs. The heaviest tests consequently require at least 32 logical CPUs;
// this resource requirement does not substitute loopback rounds for a WAN timing
// measurement.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/chaos"
	engmesh "github.com/hr18vk/sovereign/pkg/mesh"
	engsync "github.com/hr18vk/sovereign/pkg/sync"
)

const (
	loopbackNumNodes     = 100
	loopbackNumRegions   = 3
	loopbackKeys         = 10000
	loopbackConvKeys     = 1000
	loopbackFanout       = 3
	loopbackConvRoundCap = 10
	loopbackHealRoundCap = 5

	// loopbackCRDTEntryWireSize is the chaos codec's encoded CRDTEntry size:
	// seven 8-byte fields, two 16-byte node IDs, and a 32-byte digest.
	loopbackCRDTEntryWireSize = 120

	// loopbackConvArenaSize sizes each engine in the 100-node tests. State builds
	// transient merged HAMT views on every root comparison; Join advances the EBR
	// epochs that reclaim them between comparisons. The 1,000-key population keeps
	// this off-hot-path oracle within a practical per-engine arena budget.
	loopbackConvArenaSize = 64 * 1024 * 1024

	// loopbackJoin10KArenaSize leaves room for the larger live state and slower
	// epoch advance in the eight-node, 10,000-key test. Arenas use off-heap mmap
	// storage rather than the Go heap.
	loopbackJoin10KArenaSize = 256 * 1024 * 1024
)

// loopbackRegionFor assigns 100 nodes across regions 1, 2, and 3 in a 34/33/33
// split. RegionUnset is avoided because it routes as same-region and would hide
// the inter-region fan-out this harness measures.
func loopbackRegionFor(nodeIndex int) engmesh.RegionTag {
	switch {
	case nodeIndex < 34:
		return 1 // us-east-1 (34 nodes)
	case nodeIndex < 67:
		return 2 // eu-west-1 (33 nodes)
	default:
		return 3 // ap-southeast-1 (33 nodes)
	}
}

// loopbackBalancedRegionFor assigns regions round-robin so the eight-node test
// also has inter-region edges. At 100 nodes it produces the same 34/33/33 split
// as loopbackRegionFor.
func loopbackBalancedRegionFor(nodeIndex int) engmesh.RegionTag {
	return engmesh.RegionTag((nodeIndex % loopbackNumRegions) + 1)
}

// loopbackNodeID derives a stable 16-byte registry key by truncating SHA-256 of
// the node index. The in-process engines do not sign with this identifier.
func loopbackNodeID(nodeIndex int) [16]byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("loopback-node-%d", nodeIndex)))
	var id [16]byte
	copy(id[:], h[:16])
	return id
}

// loopbackBuildEngines constructs engines sequentially because engsync.DataDir is
// package-global and must be set separately for each one. It returns sorted node
// IDs for deterministic topology construction and rejects missing or nil engines
// before the root oracle can silently omit them.
func loopbackBuildEngines(t *testing.T, numNodes int, arenaSize uintptr) (engines map[[16]byte]*engsync.DeltaCRDTEngine, nodeIDs [][16]byte) {
	t.Helper()
	engines = make(map[[16]byte]*engsync.DeltaCRDTEngine, numNodes)
	nodeIDs = make([][16]byte, numNodes)
	for i := 0; i < numNodes; i++ {
		id := loopbackNodeID(i)
		// Set the package-global DataDir separately for each sequential construction.
		engsync.DataDir = t.TempDir()
		eng, err := engsync.NewDeltaCRDTEngine(id, 0, arenaSize)
		if err != nil {
			t.Fatalf("loopback: NewDeltaCRDTEngine %d: %v", i, err)
		}
		engines[id] = eng
		nodeIDs[i] = id
		t.Cleanup(func() { _ = eng.Close() })
	}
	if len(engines) != numNodes {
		t.Fatalf("loopback: built %d engines, want %d; the root oracle must not silently accept fewer than %d", len(engines), numNodes, numNodes)
	}
	for _, id := range nodeIDs {
		if engines[id] == nil || engines[id].State() == nil {
			t.Fatalf("loopback: engine %x is nil or has nil State", id)
		}
	}
	loopbackSortIDs(nodeIDs)
	return engines, nodeIDs
}

// loopbackBuildTopologies registers every peer's region with each node's
// TopologyManager and configures the fan-out. Select includes same-region peers
// plus a seeded inter-region selection. regionFn lets the eight-node test use a
// round-robin assignment instead of placing every node in region 1.
func loopbackBuildTopologies(t *testing.T, nodeIDs [][16]byte, regionFn func(int) engmesh.RegionTag) map[[16]byte]*engmesh.TopologyManager {
	t.Helper()
	topos := make(map[[16]byte]*engmesh.TopologyManager, len(nodeIDs))
	regionOf := make(map[[16]byte]engmesh.RegionTag, len(nodeIDs))
	for i, id := range nodeIDs {
		regionOf[id] = regionFn(i)
	}
	for i, id := range nodeIDs {
		selfRegion := regionFn(i)
		topo := engmesh.NewTopologyManager(selfRegion)
		topo.SetFanout(loopbackFanout)
		for _, peerID := range nodeIDs {
			if peerID == id {
				continue
			}
			topo.SetRegion(peerID, regionOf[peerID])
		}
		topos[id] = topo
	}
	return topos
}

// loopbackGossipRound sends each node's delta to the peers selected by its
// TopologyManager. It returns the number of entries sent, the inter-region subset,
// and the distinct peer edges that carried at least one entry. The entry and edge
// counts are separate: a peer edge can carry the whole delta.
//
// Each node receives a different seed for every round. Sharing one seed across
// nodes would correlate their inter-region choices and slow epidemic spreading.
func loopbackGossipRound(ctx context.Context, net *chaos.VirtualNet, engines map[[16]byte]*engsync.DeltaCRDTEngine, topos map[[16]byte]*engmesh.TopologyManager, nodeIDs [][16]byte, round int) (shipped int, interRegionShipped int, peerEdges int, err error) {
	for i, from := range nodeIDs {
		if err := ctx.Err(); err != nil {
			return shipped, interRegionShipped, peerEdges, err
		}
		topo := topos[from]
		topo.SetSeed(uint64(round*loopbackNumNodes + i)) // per-node-per-round seed (M3)
		peers := topo.Select(ctx)
		srcEng := engines[from]
		if srcEng == nil {
			return shipped, interRegionShipped, peerEdges, fmt.Errorf("loopback: missing engine for from=%x", from)
		}
		for _, to := range peers {
			if to == from {
				continue
			}
			dstEng := engines[to]
			if dstEng == nil {
				return shipped, interRegionShipped, peerEdges, fmt.Errorf("loopback: missing engine for to=%x", to)
			}
			// GenerateDelta may return a superset because Join is idempotent.
			dstDigest := dstEng.GenerateDigest()
			delta := srcEng.GenerateDelta(dstDigest)
			// The chaos receiver decodes one entry per message, so send each entry
			// separately rather than silently delivering only the first entry of a
			// multi-entry buffer.
			//
			// peerEdges counts distinct topology edges that shipped at least one
			// entry. shipped counts entries and is not comparable to the full-mesh
			// edge total asserted by TestLoopbackRoundCount.
			peerShipped := false
			var sendErr error
			delta.Entries(func(entityID string, entry engsync.CRDTEntry) bool {
				one := loopbackAppendDeltagram(make([]byte, 0, 4+len(entityID)+loopbackCRDTEntryWireSize), entityID, entry)
				if err := net.Send(from, to, one); err != nil {
					sendErr = err
					return false // stop iteration; propagate the send error out
				}
				shipped++
				if topo.IsInterRegion(to) {
					interRegionShipped++
				}
				peerShipped = true
				return true
			})
			delta.Release()
			dstDigest.Release()
			if sendErr != nil {
				return shipped, interRegionShipped, peerEdges, fmt.Errorf("loopback: vn.Send %x→%x: %w", from, to, sendErr)
			}
			if peerShipped {
				peerEdges++
			}
		}
	}
	return shipped, interRegionShipped, peerEdges, nil
}

// loopbackPumpUntilConverged runs gossip and waits for delivery after each round
// until every root matches or cap is exhausted. The expected root count comes
// from nodeIDs so the same helper works for the 100-node and eight-node tests.
func loopbackPumpUntilConverged(ctx context.Context, net *chaos.VirtualNet, orch *chaos.Orchestrator, engines map[[16]byte]*engsync.DeltaCRDTEngine, topos map[[16]byte]*engmesh.TopologyManager, nodeIDs [][16]byte, cap int) (converged bool, rounds int) {
	want := len(nodeIDs)
	for r := 1; r <= cap; r++ {
		if _, _, _, err := loopbackGossipRound(ctx, net, engines, topos, nodeIDs, r); err != nil {
			return false, r
		}
		loopbackQuiesce(net, loopbackQuiesceWindow)
		roots, ok := orch.MerkleRoots()
		if !ok {
			continue
		}
		if len(roots) != want { // M6 guard (node count derived from nodeIDs)
			continue
		}
		if loopbackAllEqualVals(roots, nodeIDs) {
			return true, r
		}
	}
	roots, _ := orch.MerkleRoots()
	return loopbackAllEqualVals(roots, nodeIDs) && len(roots) == want, cap
}

// loopbackEmptyRoot constructs an empty engine and returns its Merkle root.
// Convergence to this root would mean that no keys arrived. Construction stays
// inside the call because engsync.DataDir is package-global and must not be
// mutated during package initialization.
func loopbackEmptyRoot(t *testing.T) [32]byte {
	t.Helper()
	engsync.DataDir = t.TempDir()
	eng, err := engsync.NewDeltaCRDTEngine([16]byte{0xff}, 0, 32*1024*1024)
	if err != nil {
		t.Fatalf("loopbackEmptyRoot: NewDeltaCRDTEngine: %v", err)
	}
	defer func() { _ = eng.Close() }()
	return eng.State().MerkleRoot()
}

// ---------------------------------------------------------------------------
// Test-local counterparts of the internal/chaos codec and network helpers.
// ---------------------------------------------------------------------------

// loopbackAppendDeltagram encodes (entityID, CRDTEntry) into buf. Layout:
// entityIDLen(4) + entityID + CRDTEntry(120), matching internal/chaos's
// appendDeltagram.
func loopbackAppendDeltagram(buf []byte, entityID string, entry engsync.CRDTEntry) []byte {
	start := len(buf)
	buf = append(buf, make([]byte, 4+len(entityID)+loopbackCRDTEntryWireSize)...)
	binary.BigEndian.PutUint32(buf[start:start+4], uint32(len(entityID)))
	copy(buf[start+4:start+4+len(entityID)], entityID)
	loopbackEncodeCRDTEntry(buf[start+4+len(entityID):start+4+len(entityID)+loopbackCRDTEntryWireSize], entry)
	return buf
}

// loopbackDecodeDeltagram decodes one (entityID, entry) pair from p and reports
// ok=false for a short buffer, matching internal/chaos's decodeDeltagram.
func loopbackDecodeDeltagram(p []byte) (entry engsync.CRDTEntry, entityID string, ok bool) {
	if len(p) < 4 {
		return entry, "", false
	}
	ln := binary.BigEndian.Uint32(p[0:4])
	need := 4 + int(ln) + loopbackCRDTEntryWireSize
	if len(p) < need {
		return entry, "", false
	}
	entityID = string(p[4 : 4+int(ln)])
	entry = loopbackDecodeCRDTEntry(p[4+int(ln) : need])
	return entry, entityID, true
}

// loopbackEncodeCRDTEntry encodes a CRDTEntry into dst (120 bytes), matching
// internal/chaos's encodeCRDTEntry.
func loopbackEncodeCRDTEntry(dst []byte, e engsync.CRDTEntry) {
	off := 0
	copy(dst[off:off+32], e.PayloadDigest[:])
	off += 32
	copy(dst[off:off+16], e.OriginNodeID[:])
	off += 16
	copy(dst[off:off+16], e.DotNodeID[:])
	off += 16
	binary.BigEndian.PutUint64(dst[off:off+8], e.DotCounter)
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.SystemTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.ValidTimeStart))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.ValidTimeEnd))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.AssertionTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], uint64(e.DecisionTime))
	off += 8
	binary.BigEndian.PutUint64(dst[off:off+8], e.H3Index)
}

// loopbackDecodeCRDTEntry decodes a CRDTEntry from src (120 bytes), matching
// internal/chaos's decodeCRDTEntry.
func loopbackDecodeCRDTEntry(src []byte) engsync.CRDTEntry {
	var e engsync.CRDTEntry
	off := 0
	copy(e.PayloadDigest[:], src[off:off+32])
	off += 32
	copy(e.OriginNodeID[:], src[off:off+16])
	off += 16
	copy(e.DotNodeID[:], src[off:off+16])
	off += 16
	e.DotCounter = binary.BigEndian.Uint64(src[off : off+8])
	off += 8
	e.SystemTime = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.ValidTimeStart = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.ValidTimeEnd = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.AssertionTime = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.DecisionTime = int64(binary.BigEndian.Uint64(src[off : off+8]))
	off += 8
	e.H3Index = binary.BigEndian.Uint64(src[off : off+8])
	return e
}

// loopbackStagedEventEntry builds an event for index k and stamps it with the
// source node ID, matching internal/chaos's stagedEventEntry origin lineage.
func loopbackStagedEventEntry(k int, src [16]byte) engsync.CRDTEntry {
	h := sha256.Sum256([]byte(fmt.Sprintf("civic/%d/%x", k, src)))
	var payload [32]byte
	copy(payload[:], h[:])
	return engsync.CRDTEntry{
		PayloadDigest: payload,
		OriginNodeID:  src,
		H3Index:       uint64(k) << 8,
		SystemTime:    time.Now().UnixNano(),
	}
}

// TestLoopbackDeltagramCodecRoundTrip checks both directions of the test-local
// codec and compares its bytes with chaos.EncodeSubmit. Decoding the production
// result must return the original entry, so the harness cannot drift from the
// production deltagram layout while still passing a self-round-trip.
func TestLoopbackDeltagramCodecRoundTrip(t *testing.T) {
	src := [16]byte{0xde, 0xad, 0xbe, 0xef}
	for _, k := range []int{0, 1, 7, 42, 255, 4096} {
		entry := loopbackStagedEventEntry(k, src)
		entityID := fmt.Sprintf("civic-event-%d", k)

		// The local encode/decode pair must be the identity.
		var buf []byte
		buf = loopbackAppendDeltagram(buf, entityID, entry)
		gotEntry, gotID, ok := loopbackDecodeDeltagram(buf)
		if !ok {
			t.Fatalf("deltagram codec k=%d: decoder rejected freshly encoded buffer", k)
		}
		if gotID != entityID {
			t.Fatalf("deltagram codec k=%d: entityID round trip got %q, want %q", k, gotID, entityID)
		}
		if gotEntry != entry {
			t.Fatalf("deltagram codec k=%d: CRDTEntry round trip:\n got  =%+v\n want =%+v", k, gotEntry, entry)
		}

		// The local encoder must match the production codec byte for byte.
		prod := chaos.EncodeSubmit(entityID, entry)
		if !bytes.Equal(buf, prod) {
			t.Fatalf("deltagram codec k=%d: local and production encodings differ:\n test=%x\n prod=%x", k, buf, prod)
		}
		prodEntry, prodID, ok := chaos.DecodeSubmit(prod)
		if !ok || prodID != entityID || prodEntry != entry {
			t.Fatalf("deltagram codec k=%d: production decode did not recover the entry (ok=%v id=%q)", k, ok, prodID)
		}
	}
	t.Logf("deltagram codec matches chaos.EncodeSubmit and round-trips through both decoders")
}

// loopbackSortIDs sorts IDs in big-endian byte order with the allocation-free
// insertion sort used by internal/chaos.
func loopbackSortIDs(ids [][16]byte) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && loopbackLessID(ids[j-1], ids[j]); j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
}
func loopbackLessID(a, b [16]byte) bool {
	for k := 0; k < 16; k++ {
		if a[k] != b[k] {
			return a[k] < b[k]
		}
	}
	return false
}

// loopbackAllEqualVals reports whether every requested ID has the same root,
// matching the comparison used by the internal/chaos mesh tests.
func loopbackAllEqualVals(roots map[[16]byte][32]byte, ids [][16]byte) bool {
	if len(ids) == 0 {
		return true
	}
	first := roots[ids[0]]
	for _, id := range ids[1:] {
		if roots[id] != first {
			return false
		}
	}
	return true
}

// loopbackQuiesceWindow leaves time for the virtual network's time wheel to
// deliver a round before roots are compared. Race instrumentation quadruples the
// wall-clock allowance; it does not change the round limits under test.
const loopbackQuiesceWindowBase = 500 * time.Millisecond

var loopbackQuiesceWindow = func() time.Duration {
	if raceEnabled {
		return 4 * loopbackQuiesceWindowBase
	}
	return loopbackQuiesceWindowBase
}()

// loopbackQuiesce sleeps for the delivery window instead of busy-waiting. A
// shorter wait could report in-flight deliveries as divergent roots.
func loopbackQuiesce(net *chaos.VirtualNet, d time.Duration) {
	time.Sleep(d)
}

// loopbackRequires32Cores skips the resource-heavy 100-engine tests on smaller
// hosts. Their arena footprint and race-detector shadow memory require a larger
// machine; this skip does not turn loopback rounds into a WAN timing result.
func loopbackRequires32Cores(t *testing.T) {
	t.Helper()
	if n := runtime.NumCPU(); n < 32 {
		t.Skipf("100-engine loopback tests require at least 32 logical CPUs, found %d", n)
	}
}

// TestLoopbackConverges100 inserts 1,000 keys on one of 100 engines and requires
// equal non-empty roots within ten fan-out rounds. Reading the final source key
// on the final node also checks that equal roots represent replicated state.
func TestLoopbackConverges100(t *testing.T) {
	if testing.Short() {
		t.Skip("100-engine loopback convergence test skipped in short mode")
	}
	loopbackRequires32Cores(t)
	engines, nodeIDs := loopbackBuildEngines(t, loopbackNumNodes, loopbackConvArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		// Use a lossless, low-jitter fabric; partition behavior is tested separately.
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := loopbackBuildTopologies(t, nodeIDs, loopbackRegionFor)

	// Inject 10K keys into ONE node (region 0, node 0 — the source).
	ctx := context.Background()
	src := nodeIDs[0]
	srcEng := engines[src]
	for k := 0; k < loopbackConvKeys; k++ {
		srcEng.InsertLocal(fmt.Sprintf("loopback-key-%d", k), loopbackStagedEventEntry(k, src))
	}
	t.Logf("loopback: injected %d keys into source node %x (region %d)", loopbackConvKeys, src, loopbackRegionFor(0))

	conv, rounds := loopbackPumpUntilConverged(ctx, net, orch, engines, topos, nodeIDs, loopbackConvRoundCap)
	if !conv {
		roots, _ := orch.MerkleRoots()
		t.Fatalf("100-node loopback did not converge after %d rounds; %d distinct roots\n%s",
			rounds, loopbackCountDistinct(roots), loopbackShortRootDump(roots, nodeIDs))
	}
	roots, _ := orch.MerkleRoots()
	if len(roots) != loopbackNumNodes {
		t.Fatalf("100-node loopback: root oracle returned %d nodes, want %d", len(roots), loopbackNumNodes)
	}
	convergedRoot := roots[nodeIDs[0]]
	if convergedRoot == loopbackEmptyRoot(t) {
		t.Fatalf("100-node loopback converged to the empty root; %d keys did not arrive", loopbackConvKeys)
	}
	// Confirm state replication by reading the final source key on the final node.
	lastNode := nodeIDs[loopbackNumNodes-1]
	lastEntries := engines[lastNode].State().Get(fmt.Sprintf("loopback-key-%d", loopbackConvKeys-1))
	if len(lastEntries) == 0 {
		t.Fatalf("100-node loopback: source key loopback-key-%d is absent on final node %x", loopbackConvKeys-1, lastNode)
	}
	t.Logf("%d-node loopback converged to root %x after %d rounds; root is non-empty and final key is present", loopbackNumNodes, convergedRoot, rounds)
}

// TestLoopbackConverges100NegativeControl replaces the final node's receiver
// with one that drops every delta. Its empty root must prevent the root oracle
// from reporting convergence, demonstrating that the convergence test detects a
// node that never joins the replicated state.
func TestLoopbackConverges100NegativeControl(t *testing.T) {
	if testing.Short() {
		t.Skip("100-engine negative control skipped in short mode")
	}
	loopbackRequires32Cores(t)
	engines, nodeIDs := loopbackBuildEngines(t, loopbackNumNodes, loopbackConvArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := loopbackBuildTopologies(t, nodeIDs, loopbackRegionFor)

	// Dropping deltas gives a deterministic divergence. Changing a payload while
	// retaining its dot would instead race with Join's first-write-wins merge;
	// every node could accept the same changed payload and still reach equal roots.
	blackHoleID := nodeIDs[loopbackNumNodes-1]
	net.AddNode(blackHoleID, func(msg chaos.NetMessage) {
		_ = msg // BLACK HOLE: drop every delta, never Join.
	})

	src := nodeIDs[0]
	srcEng := engines[src]
	for k := 0; k < loopbackConvKeys; k++ {
		srcEng.InsertLocal(fmt.Sprintf("loopback-key-%d", k), loopbackStagedEventEntry(k, src))
	}
	ctx := context.Background()
	conv, rounds := loopbackPumpUntilConverged(ctx, net, orch, engines, topos, nodeIDs, loopbackConvRoundCap)
	if conv {
		t.Fatalf("100-node negative control converged after %d rounds despite the final node dropping every delta", rounds)
	}
	blackHoleRoot := engines[blackHoleID].State().MerkleRoot()
	if blackHoleRoot != loopbackEmptyRoot(t) {
		t.Fatalf("100-node negative control: drop-only node has root %x, want empty root %x; its receiver integrated deltas", blackHoleRoot, loopbackEmptyRoot(t))
	}
	t.Logf("100-node negative control remained divergent after %d rounds and the drop-only node stayed empty", rounds)
}

// TestLoopbackConverges10K inserts 10,000 keys on one of eight engines and checks
// convergence through the real fan-out topology. The smaller node count keeps the
// State-based root oracle's transient merged views within the test arena budget.
// This test covers the larger delta population; it does not measure the combined
// 100-node, 10,000-key WAN wall time.

func TestLoopbackConverges10K(t *testing.T) {
	if testing.Short() {
		t.Skip("eight-engine, 10000-key loopback test skipped in short mode")
	}
	const join10KNodes = 8
	engines, nodeIDs := loopbackBuildEngines(t, join10KNodes, loopbackJoin10KArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := loopbackBuildTopologies(t, nodeIDs, loopbackBalancedRegionFor)

	src := nodeIDs[0]
	srcEng := engines[src]
	for k := 0; k < loopbackKeys; k++ {
		srcEng.InsertLocal(fmt.Sprintf("loopback-10k-key-%d", k), loopbackStagedEventEntry(k, src))
	}
	t.Logf("10K loopback: injected %d keys into source node %x", loopbackKeys, src)

	ctx := context.Background()
	conv, rounds := loopbackPumpUntilConverged(ctx, net, orch, engines, topos, nodeIDs, 12)
	if !conv {
		roots, _ := orch.MerkleRoots()
		t.Fatalf("10K loopback did not converge after %d rounds; %d distinct roots\n%s",
			rounds, loopbackCountDistinct(roots), loopbackShortRootDump(roots, nodeIDs))
	}
	roots, _ := orch.MerkleRoots()
	if len(roots) != join10KNodes {
		t.Fatalf("10K loopback: root oracle returned %d nodes, want %d", len(roots), join10KNodes)
	}
	convergedRoot := roots[nodeIDs[0]]
	if convergedRoot == loopbackEmptyRoot(t) {
		t.Fatalf("10K loopback converged to the empty root; %d keys did not arrive", loopbackKeys)
	}
	lastNode := nodeIDs[join10KNodes-1]
	lastEntries := engines[lastNode].State().Get(fmt.Sprintf("loopback-10k-key-%d", loopbackKeys-1))
	if len(lastEntries) == 0 {
		t.Fatalf("10K loopback: source key loopback-10k-key-%d is absent on final node %x", loopbackKeys-1, lastNode)
	}
	t.Logf("%d-node loopback converged %d keys to root %x after %d rounds", join10KNodes, loopbackKeys, convergedRoot, rounds)
}

// TestLoopbackRoundCount requires convergence within six rounds and fewer peer
// edges than the 9,900 edges of a 100-node full mesh. It also requires at least
// one inter-region edge so an unset-region topology cannot satisfy the test.
func TestLoopbackRoundCount(t *testing.T) {
	if testing.Short() {
		t.Skip("100-engine round-count test skipped in short mode")
	}
	engines, nodeIDs := loopbackBuildEngines(t, loopbackNumNodes, loopbackConvArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := loopbackBuildTopologies(t, nodeIDs, loopbackRegionFor)

	src := nodeIDs[0]
	srcEng := engines[src]
	for k := 0; k < loopbackConvKeys; k++ {
		srcEng.InsertLocal(fmt.Sprintf("loopback-key-%d", k), loopbackStagedEventEntry(k, src))
	}
	ctx := context.Background()

	var fanoutEdges int
	var round1InterRegionEdges int
	conv, rounds := func() (bool, int) {
		for r := 1; r <= loopbackConvRoundCap; r++ {
			_, interRgn, peerEdges, err := loopbackGossipRound(ctx, net, engines, topos, nodeIDs, r)
			if err != nil {
				return false, r
			}
			if r == 1 {
				fanoutEdges = peerEdges
				round1InterRegionEdges = interRgn
			}
			loopbackQuiesce(net, loopbackQuiesceWindow)
			roots, ok := orch.MerkleRoots()
			if ok && len(roots) == loopbackNumNodes && loopbackAllEqualVals(roots, nodeIDs) {
				return true, r
			}
		}
		roots, _ := orch.MerkleRoots()
		return loopbackAllEqualVals(roots, nodeIDs) && len(roots) == loopbackNumNodes, loopbackConvRoundCap
	}()
	if !conv {
		t.Fatalf("fan-out loopback did not converge within %d rounds", loopbackConvRoundCap)
	}
	if rounds > 6 {
		t.Fatalf("fan-out loopback converged in %d rounds, want at most 6", rounds)
	}
	const fullMeshEdges = loopbackNumNodes * (loopbackNumNodes - 1) // 9900
	if fanoutEdges >= fullMeshEdges {
		t.Fatalf("fan-out loopback used %d peer edges in round one, want fewer than full-mesh %d", fanoutEdges, fullMeshEdges)
	}
	if round1InterRegionEdges == 0 {
		t.Fatalf("fan-out loopback sent no inter-region entries in round one; check region registration and same-region routing")
	}
	t.Logf("fan-out loopback converged in %d rounds with %d peer edges (full mesh %d) and %d inter-region entries in round one", rounds, fanoutEdges, fullMeshEdges, round1InterRegionEdges)
}

// TestLoopbackPartitionIsolates cuts region 1 from regions 2 and 3 and checks
// that a new region-1 key does not cross the cut. The control removes the
// partition and requires the key to propagate, proving that isolation comes from
// the configured cut rather than a failure to gossip.
func TestLoopbackPartitionIsolates(t *testing.T) {
	if testing.Short() {
		t.Skip("100-engine partition-isolation test skipped in short mode")
	}
	loopbackRequires32Cores(t)
	t.Run("real_partition", func(t *testing.T) { loopbackRunPartitionIsolates(t, true) })
	t.Run("no_partition_control", func(t *testing.T) { loopbackRunPartitionIsolates(t, false) })
}

func loopbackRunPartitionIsolates(t *testing.T, realPartition bool) {
	t.Helper()
	engines, nodeIDs := loopbackBuildEngines(t, loopbackNumNodes, loopbackConvArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := loopbackBuildTopologies(t, nodeIDs, loopbackRegionFor)
	ctx := context.Background()

	// Converge a baseline first (100 keys).
	src := nodeIDs[0]
	for k := 0; k < 100; k++ {
		engines[src].InsertLocal(fmt.Sprintf("loopback-baseline-%d", k), loopbackStagedEventEntry(k, src))
	}
	_, _ = loopbackPumpUntilConverged(ctx, net, orch, engines, topos, nodeIDs, loopbackConvRoundCap)

	// Cut both directions between region 1 and regions 2 and 3. Traffic between
	// regions 2 and 3 remains open.
	if realPartition {
		var parts []chaos.Partition
		for _, a := range nodeIDs {
			ra := loopbackRegionIndexOf(a, nodeIDs)
			for _, b := range nodeIDs {
				if a == b {
					continue
				}
				rb := loopbackRegionIndexOf(b, nodeIDs)
				if (ra == 1 && (rb == 2 || rb == 3)) || ((ra == 2 || ra == 3) && rb == 1) {
					parts = append(parts, chaos.Partition{From: a, To: b})
				}
			}
		}
		net.SetPartitions(parts)
		t.Logf("partition isolation (enabled=%v): cut %d directed edges between region 1 and regions 2 and 3", realPartition, len(parts))
	} else {
		net.SetPartitions(nil)
		t.Logf("partition isolation (enabled=%v): control leaves all regions connected", realPartition)
	}

	// Insert a new key on the region-1 source and run three gossip rounds.
	const divergenceKey = "loopback-isolates-divergence"
	engines[src].InsertLocal(divergenceKey, loopbackStagedEventEntry(9999, src))

	for r := 1; r <= 3; r++ {
		if _, _, _, err := loopbackGossipRound(ctx, net, engines, topos, nodeIDs, r); err != nil {
			t.Fatalf("partition-isolation gossip round %d: %v", r, err)
		}
		loopbackQuiesce(net, loopbackQuiesceWindow)
	}

	// PointGet checks key presence without constructing a merged State view for
	// every engine; an absent entity has the same zero-length result.
	reachedRegion2 := false
	reachedRegion3 := false
	for i, id := range nodeIDs {
		ri := loopbackRegionFor(i)
		if ri == 2 && len(engines[id].PointGet(divergenceKey)) > 0 {
			reachedRegion2 = true
		}
		if ri == 3 && len(engines[id].PointGet(divergenceKey)) > 0 {
			reachedRegion3 = true
		}
	}

	if realPartition {
		if reachedRegion2 || reachedRegion3 {
			t.Fatalf("partitioned region-1 key reached region2=%v region3=%v, want neither", reachedRegion2, reachedRegion3)
		}
		t.Logf("partition isolated the region-1 key from regions 2 and 3")
	} else {
		if !reachedRegion2 && !reachedRegion3 {
			t.Fatalf("no-partition control: region-1 key reached neither region 2 nor region 3; gossip did not establish the control premise")
		}
		t.Logf("no-partition control propagated the region-1 key to region2=%v region3=%v", reachedRegion2, reachedRegion3)
	}
}

// TestLoopbackPartitionHeals5Rounds converges a baseline, partitions region 1,
// adds new keys there, and then removes the partition. All 100 roots must
// converge again within five rounds.
func TestLoopbackPartitionHeals5Rounds(t *testing.T) {
	if testing.Short() {
		t.Skip("100-engine partition-healing test skipped in short mode")
	}
	loopbackRequires32Cores(t)
	engines, nodeIDs := loopbackBuildEngines(t, loopbackNumNodes, loopbackConvArenaSize)
	net := chaos.NewVirtualNet(chaos.ChaosProfile{
		Drop: 0.0, Duplicate: 0.0, ReorderMaxJitter: 2 * time.Millisecond, DeliveryBase: 1 * time.Millisecond,
	})
	t.Cleanup(net.Stop)
	orch, err := chaos.NewOrchestrator(chaos.OrchestratorConfig{Net: net, Engines: engines, Dedup: true})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	orch.BindNodes()
	topos := loopbackBuildTopologies(t, nodeIDs, loopbackRegionFor)
	ctx := context.Background()

	// Converge a baseline (100 keys).
	src := nodeIDs[0]
	for k := 0; k < 100; k++ {
		engines[src].InsertLocal(fmt.Sprintf("loopback-heal-baseline-%d", k), loopbackStagedEventEntry(k, src))
	}
	_, _ = loopbackPumpUntilConverged(ctx, net, orch, engines, topos, nodeIDs, loopbackConvRoundCap)

	// Partition region 1 from {2,3}.
	var parts []chaos.Partition
	for _, a := range nodeIDs {
		ra := loopbackRegionIndexOf(a, nodeIDs)
		for _, b := range nodeIDs {
			if a == b {
				continue
			}
			rb := loopbackRegionIndexOf(b, nodeIDs)
			if (ra == 1 && (rb == 2 || rb == 3)) || ((ra == 2 || ra == 3) && rb == 1) {
				parts = append(parts, chaos.Partition{From: a, To: b})
			}
		}
	}
	net.SetPartitions(parts)

	// Add divergence on region 1 and run rounds while the partition is active.
	for k := 0; k < 50; k++ {
		engines[src].InsertLocal(fmt.Sprintf("loopback-heal-divergence-%d", k), loopbackStagedEventEntry(k, src))
	}
	for r := 1; r <= 3; r++ {
		_, _, _, _ = loopbackGossipRound(ctx, net, engines, topos, nodeIDs, r)
		loopbackQuiesce(net, loopbackQuiesceWindow)
	}

	net.SetPartitions(nil)
	t.Logf("partition removed; counting rounds to re-convergence")

	healConv, healRounds := loopbackPumpUntilConverged(ctx, net, orch, engines, topos, nodeIDs, loopbackHealRoundCap)
	if !healConv {
		roots, _ := orch.MerkleRoots()
		t.Fatalf("loopback did not re-converge within %d rounds after healing; %d distinct roots\n%s",
			loopbackHealRoundCap, loopbackCountDistinct(roots), loopbackShortRootDump(roots, nodeIDs))
	}
	if healRounds > loopbackHealRoundCap {
		t.Fatalf("loopback re-converged in %d rounds after healing, want at most %d", healRounds, loopbackHealRoundCap)
	}
	t.Logf("loopback re-converged in %d rounds after healing (limit %d)", healRounds, loopbackHealRoundCap)
}

// TestLoopbackIBLTBound checks the decoder's bucket-count limit before a large
// allocation. Empty and 80-bucket inputs are valid; 838,859 and the maximum
// uint32 count must return ErrIBLTTooLarge. Header-only oversized inputs keep
// the test from allocating the buffers that the guard is meant to reject.
func TestLoopbackIBLTBound(t *testing.T) {
	buildWire := func(n uint32) []byte {
		header := make([]byte, 18)
		binary.LittleEndian.PutUint32(header[0:4], 0x49424C31) // ibltWireMagic
		binary.LittleEndian.PutUint32(header[4:8], n)
		binary.LittleEndian.PutUint16(header[8:10], 3) // k=3 (valid)
		binary.LittleEndian.PutUint64(header[10:18], 0)
		return append(header, make([]byte, int(n)*20)...)
	}
	buildHeader := func(n uint32) []byte {
		header := make([]byte, 18)
		binary.LittleEndian.PutUint32(header[0:4], 0x49424C31)
		binary.LittleEndian.PutUint32(header[4:8], n)
		binary.LittleEndian.PutUint16(header[8:10], 3)
		binary.LittleEndian.PutUint64(header[10:18], 0)
		return header
	}

	t.Run("n0_accepts", func(t *testing.T) {
		iblt, err := engsync.UnmarshalIBLT(buildWire(0))
		if err != nil {
			t.Fatalf("IBLT bound rejected empty input: %v", err)
		}
		if iblt == nil {
			t.Fatalf("IBLT bound returned nil IBLT with nil error for empty input")
		}
		t.Logf("IBLT bound accepted empty input")
	})

	t.Run("n80_accepts", func(t *testing.T) {
		iblt, err := engsync.UnmarshalIBLT(buildWire(80))
		if err != nil {
			t.Fatalf("IBLT bound rejected strataIBLTBuckets=80: %v", err)
		}
		if iblt == nil {
			t.Fatalf("IBLT bound returned nil IBLT with nil error for 80 buckets")
		}
		t.Logf("IBLT bound accepted the production 80-bucket shape")
	})

	t.Run("n838859_rejects", func(t *testing.T) {
		// A header-only input reaches the count guard without allocating the
		// declared bucket array.
		iblt, err := engsync.UnmarshalIBLT(buildHeader(838859))
		if err == nil {
			t.Fatalf("IBLT bound accepted 838859 buckets (returned %v), want rejection before allocation", iblt)
		}
		if !errors.Is(err, engsync.ErrIBLTTooLarge) {
			t.Fatalf("IBLT bound rejected 838859 buckets with %v, want ErrIBLTTooLarge", err)
		}
		t.Logf("IBLT bound rejected 838859 buckets with ErrIBLTTooLarge")
	})

	t.Run("nMaxU32_rejects", func(t *testing.T) {
		iblt, err := engsync.UnmarshalIBLT(buildHeader(0xFFFFFFFF))
		if err == nil {
			t.Fatalf("IBLT bound accepted uint32-max buckets (returned %v), want rejection before allocation", iblt)
		}
		if !errors.Is(err, engsync.ErrIBLTTooLarge) {
			t.Fatalf("IBLT bound rejected uint32-max buckets with %v, want ErrIBLTTooLarge", err)
		}
		t.Logf("IBLT bound rejected uint32-max buckets with ErrIBLTTooLarge")
	})
}

// TestLoopbackIBLTBoundLockstep distinguishes the 24-byte in-memory bucket size
// from the 20-byte wire size. A 16 MiB frame limit divided by 24 allows 699,050
// buckets; dividing by 20 would allow 838,860. Header-only counts of 699,051 and
// 838,860 must both return ErrIBLTTooLarge rather than reaching the short-array
// check. The test also compares the duplicated 16 MiB limit with pkg/receive's
// maxFrameSize declaration.
func TestLoopbackIBLTBoundLockstep(t *testing.T) {
	buildHeader := func(n uint32) []byte {
		header := make([]byte, 18)
		binary.LittleEndian.PutUint32(header[0:4], 0x49424C31) // ibltWireMagic 'IBL1'
		binary.LittleEndian.PutUint32(header[4:8], n)
		binary.LittleEndian.PutUint16(header[8:10], 3) // k=3 (valid)
		binary.LittleEndian.PutUint64(header[10:18], 0)
		return header
	}
	// The 24-byte bucket bound rejects 699051. A 20-byte bound would accept it
	// and reach the short-array check instead.
	if iblt, err := engsync.UnmarshalIBLT(buildHeader(699051)); err == nil {
		t.Fatalf("IBLT lockstep accepted 699051 buckets (returned %v), want rejection at the 24-byte limit", iblt)
	} else if !errors.Is(err, engsync.ErrIBLTTooLarge) {
		t.Fatalf("IBLT lockstep rejected 699051 buckets with %v, want ErrIBLTTooLarge rather than a short-array error", err)
	}
	// A 20-byte bound would also accept 838860; the 24-byte bound rejects it.
	if iblt, err := engsync.UnmarshalIBLT(buildHeader(838860)); err == nil {
		t.Fatalf("IBLT lockstep accepted 838860 buckets (returned %v), want rejection at the 24-byte limit", iblt)
	} else if !errors.Is(err, engsync.ErrIBLTTooLarge) {
		t.Fatalf("IBLT lockstep rejected 838860 buckets with %v, want ErrIBLTTooLarge rather than a short-array error", err)
	}
	root := repoRootMesh(t)
	receiverSrc, err := os.ReadFile(filepath.Join(root, "pkg", "receive", "receiver.go"))
	if err != nil {
		t.Fatalf("IBLT lockstep: cannot read pkg/receive/receiver.go: %v", err)
	}
	if !strings.Contains(string(receiverSrc), "const maxFrameSize = 16 << 20") {
		t.Fatalf("IBLT lockstep: pkg/receive maxFrameSize differs from the 16 << 20 limit used by the IBLT bucket bound")
	}
	t.Logf("IBLT bucket bound uses the 24-byte in-memory size and matches pkg/receive maxFrameSize")
}

// ---------------------------------------------------------------------------
// small helpers (region lookup, root dump, distinct count).
// ---------------------------------------------------------------------------

func loopbackRegionIndexOf(id [16]byte, nodeIDs [][16]byte) int {
	for i, nid := range nodeIDs {
		if nid == id {
			return int(loopbackRegionFor(i))
		}
	}
	return 0 // not found (RegionUnset) — should not happen
}

func loopbackCountDistinct(roots map[[16]byte][32]byte) int {
	seen := make(map[[32]byte]struct{})
	for _, r := range roots {
		seen[r] = struct{}{}
	}
	return len(seen)
}

func loopbackShortRootDump(roots map[[16]byte][32]byte, ids [][16]byte) string {
	var s string
	const hexd = "0123456789abcdef"
	for _, id := range ids {
		r := roots[id]
		var b [16]byte
		for i, c := range r[:8] {
			b[i*2] = hexd[c>>4]
			b[i*2+1] = hexd[c&0xf]
		}
		s += "  node " + fmt.Sprintf("%x", id[:4]) + ": " + string(b[:16]) + "...\n"
	}
	return s
}

// repoRootMesh resolves the repository root for the maxFrameSize source check.
// This external test package needs its own helper because the similarly named
// helper in package mesh is not accessible here.
func repoRootMesh(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("loopback: git rev-parse unavailable (%v); skipping maxFrameSize source check", err)
	}
	return strings.TrimSpace(string(out))
}
