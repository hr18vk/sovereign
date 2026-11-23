// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// The census drives the real gossip stack over loopback TLS in one process,
// normally on a four-core machine. It measures fallback causes and validates
// the responder concurrency cap.
//
// Full-keyset fallback after a timeout or failed peel changes reconciliation
// cost from the peeled difference to the entire keyset. Per node and sweep,
// the census separates the five noteStratFallback causes (IBLT marshal,
// test-only StrataEstimator marshal, Publish failure, timeout, and nil digest),
// completed exchanges with failed peels (digestPeelOversends), and responder
// drops (digestRespondDropped). SetStratifiedFallbackReporter counts all five
// noteStratFallback sites. The accounting identity is:
//
//	dumps = reporter fallback count + digestPeelOversends
//
// Each dump's S is the reporting node's full keyset size.
//
// Responder validation uses synchronized requests at one hot node, a
// synchronized sweep to observe fallback after dropped responses, and a
// between-bursts test-only respondSem increase to 4096. enqueueDigestResponse
// captures the semaphore per call, so replacing it after prior builds drain is
// race-free and affects only new requests. Drops at the production cap must
// disappear with the larger cap; otherwise the measurement is invalid. At
// in-degree 8, the old eight-slot cap had a 41% Poisson drop rate. The cap is
// now at least 2f (ADR-0063).
//
// RUN_CENSUS_N can reduce the mesh when 100 nodes do not complete. Such a run
// reports its actual bound rather than a 100-node result. Divergence sizes
// D=100, 400, and 1000 correspond to analytic peel-failure rates of 1.9%, 26%,
// and 61%. D=10000 runs at N=12 in this harness; the 100-by-10,000 shape is a
// separate hardware measurement.
//
// RUN_CENSUS=1 enables the full census, which takes minutes on four cores.
// TestCensusMicroSmoke always runs at N=6 so normal suite runs exercise the
// harness.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash/maphash"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// CensusNode holds one in-process node's engine, transport, Gossiper, region,
// and fallback reporter count. The reporter covers all five noteStratFallback
// call sites.
type CensusNode struct {
	ident    *NodeIdentity
	engine   *eng.DeltaCRDTEngine
	recv     *receive.Receiver
	ps       *PeerSet
	g        *Gossiper
	ln       net.Listener
	addr     string
	region   RegionTag
	fallback atomic.Int64 // the SetStratifiedFallbackReporter shim count
}

// CensusMesh is an n-node mesh across three regions. Full-mesh dialing avoids
// Publish failures caused by missing links, and both stratified anti-entropy
// and region-aware selection are enabled.
type CensusMesh struct {
	nodes  []*CensusNode
	ctx    context.Context
	cancel context.CancelFunc
	wg     *sync.WaitGroup
}

// censusRegionSizes splits n across three regions, assigning the remainder to
// the last region. For example, n=100 yields 33, 33, and 34.
func censusRegionSizes(n int) [3]int {
	s := n / 3
	return [3]int{s, s, n - 2*s}
}

// newCensusEngine creates an engine with a caller-selected arena size in MiB.
// Node 0 needs 512 MiB for the starvation arm's roughly 250,000-entry keyset;
// 64 MiB was exhausted during insertion. Other nodes retain 64 MiB because
// they hold only about 10,000 keys. Lazy mmap leaves the extra reservation
// untouched until pages are used.
//
// buildCensusMesh configures region-aware topology with NewTopologyManager,
// per-peer SetRegion, SetTopology, and SetRegionAware(true).
// SetStratifiedAntiEntropy allocates respondSem (16 slots with partial intra-
// region views, previously 8) and stratDiag. The fallback reporter increments
// the node's atomic counter. A five-second digest wait keeps four-core build
// latency and race-detector scheduling from being mistaken for timeout
// fallbacks; a separate phase measures the 500 ms production wait.
func newCensusEngine(t *testing.T, nodeID [16]byte, dataDir string, arenaMB int) *eng.DeltaCRDTEngine {
	t.Helper()
	eng.DataDir = dataDir
	e, err := eng.NewDeltaCRDTEngine(nodeID, 1, uintptr(arenaMB)*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine %x: %v", nodeID, err)
	}
	return e
}

func buildCensusMesh(t *testing.T, n int) *CensusMesh {
	t.Helper()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	dir := t.TempDir()
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	sizes := censusRegionSizes(n)
	m := &CensusMesh{}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.wg = &sync.WaitGroup{}
	m.nodes = make([]*CensusNode, n)
	// Assign contiguous blocks to regions 1–3; region 0 is RegionUnset and is
	// not used.
	regionOf := func(i int) RegionTag {
		if i < sizes[0] {
			return RegionTag(1)
		}
		if i < sizes[0]+sizes[1] {
			return RegionTag(2)
		}
		return RegionTag(3)
	}
	for i := 0; i < n; i++ {
		seed := sha256.Sum256([]byte(fmt.Sprintf("census-node-%d", i)))
		ident, err := NewNodeIdentity(seed[:])
		if err != nil {
			t.Fatalf("NewNodeIdentity %d: %v", i, err)
		}
		arenaDir := filepath.Join(dir, fmt.Sprintf("eng%d", i))
		if err := os.MkdirAll(arenaDir, 0o755); err != nil {
			t.Fatalf("mkdir %d: %v", i, err)
		}
		// Node 0 receives every batch and grows to roughly 250,000 entries in
		// the starvation arm. Its arena is 512 MiB; other nodes use 64 MiB.
		arenaMB := 64
		if i == 0 {
			arenaMB = 512
		}
		engine := newCensusEngine(t, ident.NodeID, arenaDir, arenaMB)
		idir := identity.NewDirectory()
		bucket := admission.NewPeerBucket()
		capc := clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engine)
		recv := receive.NewReceiver(bucket, capc, clock.NewSystemClock(), idir, engine, 50_000_000)
		leaf, err := ca.IssueLeaf(identHex(ident.NodeID))
		if err != nil {
			t.Fatalf("IssueLeaf %d: %v", i, err)
		}
		certPath, keyPath, err := leaf.WritePEM(filepath.Join(dir, fmt.Sprintf("node%d", i)))
		if err != nil {
			t.Fatalf("WritePEM %d: %v", i, err)
		}
		tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
		if err != nil {
			t.Fatalf("NewTLSTransport %d: %v", i, err)
		}
		ln, err := tr.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %d: %v", i, err)
		}
		ps := NewPeerSet(tr, recv, ident, engine)
		g := NewGossiper(ps, ident, engine, idir)
		node := &CensusNode{ident: ident, engine: engine, recv: recv, ps: ps, g: g, ln: ln, addr: ln.Addr().String(), region: regionOf(i)}
		// Relay hooks retain foreign frames at the receiver. Without them,
		// relayed propagation has no frame to ship and reports relay-cache
		// misses.
		g.WireRelayHooks(recv)
		g.SetStratifiedAntiEntropy(true) // allocates 16-slot respondSem and stratDiag
		g.SetStratifiedFallbackReporter(func() { node.fallback.Add(1) })
		g.SetDigestWaitTimeout(5 * time.Second)
		// Region-aware topology: the shipped seam chain.
		topo := NewTopologyManager(node.region)
		topo.SetFanout(DefaultRegionFanout)
		g.SetTopology(topo)
		g.SetRegionAware(true)
		m.nodes[i] = node
	}
	// Register peers in every node's directory + gossiper + topology registry.
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			if err := m.nodes[i].g.RegisterPeer(m.nodes[j].ident.NodeID, m.nodes[j].ident.Pub); err != nil {
				t.Fatalf("RegisterPeer %d->%d: %v", i, j, err)
			}
			m.nodes[i].g.topology.SetRegion(m.nodes[j].ident.NodeID, m.nodes[j].region)
		}
	}
	return m
}

// finishCensusMesh starts accept loops and connects every node pair. Complete
// connectivity keeps dial artifacts out of the Publish-failure fallback class.
func finishCensusMesh(t *testing.T, m *CensusMesh) {
	t.Helper()
	n := len(m.nodes)
	for i := 0; i < n; i++ {
		m.wg.Add(1)
		// Thread accept through PeerSet for gateway anchor pinning (ADR-0068).
		go runAcceptLoopWithPeerSet(m.ctx, m.nodes[i].ln, m.nodes[i].recv, m.nodes[i].g, m.wg, m.nodes[i].ps)
	}
	// Dial each unordered pair once (ADR-0068). Dialing both directions causes
	// one connection to be declined and keyed under the zero identity, which
	// blocks digest exchanges and root announces on that half. A single dial
	// plus accept-side registration provides one verified bidirectional
	// connection and avoids per-peer digestWait timeouts.
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if err := m.nodes[i].ps.Dial(m.ctx, m.nodes[j].addr, "localhost", m.nodes[j].ident.NodeID); err != nil {
				t.Fatalf("dial %d->%d: %v", i, j, err)
			}
			asyncWait(t, m.nodes[i].ps, m.nodes[j].ident.NodeID)
			// Settle the challenge proof at both ends before sweeping
			// (ADR-0068). Every selected visit must either fire or be gated;
			// a round racing the asynchronous handshake instead loses visits
			// to the egress skip. The dial side verifies when j's accept side
			// answers, and j's inbound entry verifies when i's dial readLoop
			// answers its challenge.
			awaitVerified(t, m.nodes[i].ps, m.nodes[j].ident.NodeID)
			awaitVerified(t, m.nodes[j].ps, m.nodes[i].ident.NodeID)
		}
	}
}

// close cancels the mesh, closes listeners, and waits for accept loops.
// Engines remain open because cleanup-time Close can unmap an arena while
// serve-conn readers still use it. Process exit reclaims the arenas.
func (m *CensusMesh) close() {
	m.cancel()
	for _, nd := range m.nodes {
		_ = nd.ln.Close()
	}
	m.wg.Wait()
}

// CensusNodeCounters snapshots one node's cumulative counters.
type CensusNodeCounters struct {
	gateSkips int64
	peel      int64 // completed exchanges with failed peels
	drops     int64 // responses dropped at the responder bound
	fallbacks int64 // all five noteStratFallback sites
	exchanges int64 // digest exchanges recorded in stratDiag.exchange
	digestNs  int64 // aggregate exchange time in stratDiag.digestNs
}

// readCensusCounters reads atomic counters directly and takes the stratDiag
// mutex before summing its maps.
func readCensusCounters(nd *CensusNode) CensusNodeCounters {
	c := CensusNodeCounters{
		gateSkips: nd.g.digestGateSkips.Load(),
		peel:      nd.g.digestPeelOversends.Load(),
		drops:     nd.g.digestRespondDropped.Load(),
		fallbacks: nd.fallback.Load(),
	}
	if d := nd.g.stratDiag; d != nil {
		d.mu.Lock()
		for _, v := range d.exchange {
			c.exchanges += v
		}
		c.digestNs = d.digestNs
		d.mu.Unlock()
	}
	return c
}

// censusSweepRound releases every node's AntiEntropySweep from one barrier,
// creating the synchronized load used by the responder-cap test (ADR-0063).
// The production ticker is also phase-aligned. It returns each node's
// sweepState, including shipped envelopes, entries, and duration.
func censusSweepRound(t *testing.T, m *CensusMesh, tick time.Duration) []sweepState {
	states := make([]sweepState, len(m.nodes))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range m.nodes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			states[i] = m.nodes[i].g.AntiEntropySweep(m.ctx)
		}(i)
	}
	close(start)
	wg.Wait()
	time.Sleep(tick)
	return states
}

// censusBatch inserts keys fresh entities on node 0, giving divergence D at
// round 1, then runs synchronized rounds with per-node counter snapshots.
// Each fired exchange resolves to one outcome:
//
//	fired = clean + five-site fallbacks + peelOversends
//
// clean is the derived residue. The test also requires fired + gated to equal
// the expected selected-peer total: the applicable intra-region term plus two
// inter-region peers per node. S is the full keyset at each dump; node 0's is
// firstKey+keys. Per-exchange logs report the peeled difference or a full-
// keyset fallback for the |delta| distribution.
func censusBatch(t *testing.T, m *CensusMesh, tag string, firstKey, keys, rounds int, tick time.Duration) {
	t.Helper()
	n := len(m.nodes)
	for i := 0; i < keys; i++ {
		eid := fmt.Sprintf("census-%s-%d", tag, firstKey+i)
		m.nodes[0].g.InsertLocalEvents(eid, fmt.Sprintf("v-%s-%d", tag, firstKey+i), eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + firstKey + i),
			H3Index:    uint64(firstKey + i),
		})
	}
	regionSize := make(map[RegionTag]int, 3)
	for _, nd := range m.nodes {
		regionSize[nd.region]++
	}
	var expectedSelected int64
	for _, nd := range m.nodes {
		// With partial intra-region views enabled, the intra term is
		// min(intraViewSize, n_r-1), using each node's own accessor
		// (ADR-0063). Otherwise it is n_r-1. The expected total remains an
		// independent assertion against observed fired + gated exchanges;
		// a wrong or omitted selection produces an exact-sum failure.
		intraTerm := regionSize[nd.region] - 1
		if nd.g.PartialIntraView() && intraTerm > intraViewSize {
			intraTerm = intraViewSize
		}
		expectedSelected += int64(intraTerm + 2) // min(f,n_r-1) intra + 2 inter (min(fanout=3, 2 remote regions))
	}
	t.Logf("census batch=%s: node0 inserted %d fresh keys (firstKey=%d) -> D@round1=%d, node0 keyset S_base=%d, expectedSelected/sweep=%d", tag, keys, firstKey, keys, firstKey+keys, expectedSelected)
	prev := make([]CensusNodeCounters, n)
	for i := range prev {
		prev[i] = readCensusCounters(m.nodes[i])
	}
	for round := 1; round <= rounds; round++ {
		states := censusSweepRound(t, m, tick)
		cur := make([]CensusNodeCounters, n)
		for i := range cur {
			cur[i] = readCensusCounters(m.nodes[i])
		}
		for i := 0; i < n; i++ {
			nd := m.nodes[i]
			wantDrawn, wantElig := 0, 0
			if nd.g.PartialIntraView() {
				wantDrawn = minInt(intraViewSize, regionSize[nd.region]-1)
				wantElig = regionSize[nd.region] - 1
			}
			if states[i].viewDrawn != wantDrawn || states[i].viewEligible != wantElig {
				t.Errorf("census view batch=%s round=%d node=%d: view=(%d/%d), want (%d/%d) for the node's partial-view state", tag, round, i, states[i].viewDrawn, states[i].viewEligible, wantDrawn, wantElig)
			}
		}
		var dExch, dGate, dFb, dPeel, dDrop, dEnv, dEntries, durSum int64
		worstNode, worstDur := -1, int64(-1)
		for i := 0; i < n; i++ {
			dExch += cur[i].exchanges - prev[i].exchanges
			dGate += cur[i].gateSkips - prev[i].gateSkips
			dFb += cur[i].fallbacks - prev[i].fallbacks
			dPeel += cur[i].peel - prev[i].peel
			dDrop += cur[i].drops - prev[i].drops
			dEnv += int64(states[i].shippedEnvelopes)
			dEntries += int64(states[i].shippedEntries)
			durSum += states[i].durMs
			if states[i].durMs > worstDur {
				worstDur = states[i].durMs
				worstNode = i
			}
		}
		clean := dExch - dFb - dPeel
		t.Logf("census batch=%s round=%d/%d: fired=%d gated=%d clean=%d | fallbacks(5-sites)=%d peelOversends=%d respondDropped=%d | dumps(S5+peel)=%d | shippedEnv=%d shippedEntries=%d durSumMs=%d worst=%d@%dms",
			tag, round, rounds, dExch, dGate, clean, dFb, dPeel, dDrop, dFb+dPeel, dEnv, dEntries, durSum, worstNode, worstDur)
		if dFb+dPeel > dExch {
			t.Errorf("census reconcile batch=%s round=%d: dumps (five-site=%d + peel=%d) exceed fired exchanges (%d); an event class is double-counted", tag, round, dFb, dPeel, dExch)
		}
		if dGate+dExch != expectedSelected {
			t.Errorf("census reconcile batch=%s round=%d: fired(%d) + gated(%d) != expected selected(%d); every selected peer must be visited exactly once", tag, round, dExch, dGate, expectedSelected)
		}
		copy(prev, cur)
	}
	root0 := m.nodes[0].engine.MerkleRootFromShards()
	equal := true
	for i := 1; i < n; i++ {
		if m.nodes[i].engine.MerkleRootFromShards() != root0 {
			equal = false
			break
		}
	}
	t.Logf("census batch=%s POST: rootsAllEqual=%v (node0 keyset %d entries)", tag, equal, firstKey+keys)
	if !equal {
		t.Errorf("census batch=%s: roots did not converge after %d rounds — the census mesh is not converging; batch reported [NON-CONVERGED]", tag, rounds)
	}
}

// censusBurstDirect pre-builds a real digest request on every non-hot node
// using GenerateDigestWithSeed and a fresh maphash seed. The IBLT-only frames
// have seLen == 0. A barrier releases all Publish calls together.
// GenerateDigestWithSeed, marshaling, and response publication at the hot node
// contend for digestRespondMaxConcurrent slots. The result is the hot node's
// digestRespondDropped delta for each repetition.
func censusBurstDirect(t *testing.T, m *CensusMesh, hot, reps int, drain time.Duration) []int64 {
	n := len(m.nodes)
	dropsPer := make([]int64, reps)
	for rep := 0; rep < reps; rep++ {
		before := m.nodes[hot].g.digestRespondDropped.Load()
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			if i == hot {
				continue
			}
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				seed := maphash.MakeSeed()
				localIBLT := m.nodes[i].g.engine.GenerateDigestWithSeed(seed)
				mIB, err := eng.MarshalIBLT(localIBLT)
				localIBLT.Release()
				if err != nil {
					return
				}
				frame := buildDigestFrame(digestRoleRequest, m.nodes[i].ident.NodeID, seed, nil, mIB)
				prefixed := receive.LengthPrefixFrame(frame)
				<-start
				_ = m.nodes[i].ps.Publish(m.nodes[hot].ident.NodeID, prefixed)
			}(i)
		}
		close(start)
		wg.Wait()
		time.Sleep(drain) // responder builds drain + responses land
		dropsPer[rep] = m.nodes[hot].g.digestRespondDropped.Load() - before
		t.Logf("census D1 direct-burst rep=%d/%d: requests=%d drops=%d (dropFrac=%.3f)", rep+1, reps, n-1, dropsPer[rep], float64(dropsPer[rep])/float64(n-1))
	}
	return dropsPer
}

// selectorPoissonTail returns P(X > k) for X ~ Poisson(lambda). At lambda=8
// and k=8, this is approximately 41%, the analytic reference for the old cap.
func selectorPoissonTail(lambda float64, k int) float64 {
	term := math.Exp(-lambda)
	cdf := term
	for i := 1; i <= k; i++ {
		term *= lambda / float64(i)
		cdf += term
	}
	if cdf > 1 {
		return 0
	}
	return 1 - cdf
}

// TestK3FallbackCensus sweeps D=100, 400, and 1000 at the analytic peel-
// failure calibration points of 1.9%, 26%, and 61%. A 500 ms production-wait
// phase covers timer fallback, the only five-site class reachable here:
// digestLegacySE is off, valid frames do not trigger IBLT marshal or nil-digest
// errors, and full-mesh dialing prevents Publish failure. D=10 trickle batches
// stay below the roughly 72-entry floor.
//
// Direct request bursts then measure responder drops, a synchronized sweep
// measures the resulting timeout fallback, and the cap-lifted control checks
// that drops vanish. RUN_CENSUS=1 enables this test; it takes minutes at N=100
// on four cores.
func TestK3FallbackCensus(t *testing.T) {
	if os.Getenv("RUN_CENSUS") != "1" {
		t.Skip("census: set RUN_CENSUS=1 to enable fallback and responder-cap validation (minutes at N=100 on four cores)")
	}
	n := 100
	if v := os.Getenv("RUN_CENSUS_N"); v != "" {
		nv, err := strconv.Atoi(v)
		if err != nil || nv < 6 {
			t.Fatalf("RUN_CENSUS_N must be an integer >= 6, got %q", v)
		}
		n = nv
	}
	if n < 100 {
		t.Logf("reduced census: N=%d < 100; no 100-node result is reported, and this run bounds behavior at N=%d", n, n)
	}
	t.Logf("census: building the %d-node in-process real-TLS mesh with region-aware stratified anti-entropy and full-mesh dialing; N=100 takes about 1–2 minutes", n)
	m := buildCensusMesh(t, n)
	defer m.close()
	finishCensusMesh(t, m)
	t.Logf("census mesh ready: %d nodes, %d connections", n, n*(n-1))
	// The D-axis at the calibration points.
	censusBatch(t, m, "D100", 0, 100, 3, 250*time.Millisecond)
	censusBatch(t, m, "D400", 100, 400, 3, 250*time.Millisecond)
	censusBatch(t, m, "D1000", 500, 1000, 3, 250*time.Millisecond)
	// Measure timer-timeout fallback with the 500 ms production wait under
	// four-core contention. Other phases use a longer wait so build latency
	// does not enter this category.
	for i := range m.nodes {
		m.nodes[i].g.SetDigestWaitTimeout(500 * time.Millisecond)
	}
	t.Logf("census timeout phase: digestWaitTimeout=500ms, the production default, on all nodes")
	censusBatch(t, m, "wait500-D200", 1500, 200, 3, 250*time.Millisecond)
	// Insert D=10 per batch with inter-write time below the sweep period.
	// Three rounds allow two to three hops at N=100; a single round would
	// leave later batches carrying the residual. Partial intra-region views
	// increase the hop count to roughly two to four at f=8 because a batch
	// reaches one view member and then that member's next-round view. The
	// round allowance reflects that measured hop count.
	for r := 0; r < 5; r++ {
		censusBatch(t, m, fmt.Sprintf("trickle%d", r), 1700+10*r, 10, 3, 250*time.Millisecond)
	}
	// Grow node 0 to 10,000 entries at N=100. Measured first-round shipped
	// envelope rates complete in seconds, so this shape is practical in-process.
	// It also lengthens responder builds. At roughly 1,900 keys, builds drained
	// before burst arrivals overlapped; even at 10,000 keys with all cores,
	// per-connection TLS decryption serializes arrivals below the drain rate.
	// Full-core drops are therefore report-only. The starvation phase below
	// exercises the cap deterministically.
	censusBatch(t, m, "D10000-at-N100", 1750, 8250, 3, 500*time.Millisecond)
	// The responder-cap validation on the same mesh (the hot node
	// now carries the 10K-keyset — the build wall is the overlap window).
	hot := 0
	t.Logf("census D1 (GOMAXPROCS=%d): direct synchronized REQUEST bursts at hot node %d (cap=%d, keyset ~10000 entries)", runtime.GOMAXPROCS(0), hot, digestRespondMaxConcurrent)
	d1 := censusBurstDirect(t, m, hot, 3, 750*time.Millisecond)
	var d1Total int64
	for _, d := range d1 {
		d1Total += d
	}
	t.Logf("census direct-burst summary (full cores): drops=%d over %d bursts x %d requests. At both ~1900-key and 10K-key builds, per-connection TLS decryption and frame handling serialize loopback arrivals below the old 8-slot saturation rate; the cap does not bind in-process at full cores. Responder-drop rates over WAN links are outside this measurement. The GOMAXPROCS=1 starvation phase checks the drop path, counter, and cap after the synchronized sweep.",
		d1Total, len(d1), n-1)
	// Measure the synchronized sweep with the production 500 ms wait. Compare
	// hot-node requests with the responder slots and record timeout fallbacks
	// and oversent entries from requesters whose responses were dropped.
	hotBefore := m.nodes[hot].g.digestRespondDropped.Load()
	var fbBefore int64
	for i := range m.nodes {
		fbBefore += m.nodes[i].fallback.Load()
	}
	for i := 0; i < 200; i++ {
		m.nodes[0].g.InsertLocalEvents(fmt.Sprintf("census-D2-%d", i), fmt.Sprintf("v-D2-%d", i), eng.CRDTEntry{
			SystemTime: int64(1_700_000_000 + 1900 + i),
			H3Index:    uint64(1900 + i),
		})
	}
	states := censusSweepRound(t, m, 400*time.Millisecond)
	hotDrops := m.nodes[hot].g.digestRespondDropped.Load() - hotBefore
	var fbAfter, ent int64
	for i := range m.nodes {
		fbAfter += m.nodes[i].fallback.Load()
	}
	for i := range states {
		ent += int64(states[i].shippedEntries)
	}
	rs := make(map[RegionTag]int, 3)
	for _, nd := range m.nodes {
		rs[nd.region]++
	}
	expIn := int64(rs[m.nodes[hot].region] - 1 + 2)
	t.Logf("D2: synchronized sweep, fresh +200 divergence: hotNode in-requests≈%d (n_r-1+2), hotDrops=%d, fleet fallbacks delta=%d (the timer-timeout class), fleet shippedEntries=%d (the consequential oversend)", expIn, hotDrops, fbAfter-fbBefore, ent)
	// Earlier cap-8 measurements recorded 273 drops, drop fraction 0.919, and
	// the ninth try-acquire failing. Partial intra-region views raised
	// digestRespondMaxConcurrent to 16 = 2f (ADR-0063), so the 17th arrival is
	// now the first to drop and the full-overlap bound at in-degree 99 is
	// (99-16)/99 = 0.838. The cap and counter behavior are unchanged.
	//
	// This starvation phase exercises the drop path; it is not a production-
	// rate measurement. A 1–2 ms 10,000-key build can finish inside one roughly
	// 10 ms scheduling quantum at GOMAXPROCS=1, with Go's runnext slot
	// serializing readLoop and builder execution, leaving slots unfilled.
	// Growing the hot keyset to about 250,000 entries increases builds to
	// roughly 25–50 ms, allowing preemption while slots are held. At cap 16,
	// the 17th of 99 arrivals must drop. Zero drops indicates a broken drop
	// path or digestRespondDropped counter (ADR-0055).
	for i := 0; i < 240000; i++ {
		m.nodes[hot].g.InsertLocalEvents(fmt.Sprintf("census-starve-%d", i), fmt.Sprintf("v-starve-%d", i), eng.CRDTEntry{
			SystemTime: int64(1_700_002_000 + i),
			H3Index:    uint64(2_000_000 + i),
		})
	}
	prevProcs := runtime.GOMAXPROCS(1)
	t.Logf("D1-starve (GOMAXPROCS=1): 250K-key builds exceed the ~10ms scheduling quantum, slots fill mid-hold; the cap must bind and drops must fire")
	d1s := censusBurstDirect(t, m, hot, 3, 12*time.Second)
	var d1sTotal int64
	for _, d := range d1s {
		d1sTotal += d
	}
	t.Logf("starvation summary: drops=%d over %d bursts x %d requests at GOMAXPROCS=1; full-window-overlap bound (n-1-%d)/(n-1)=%.3f; Poisson tail P(X>%d | lambda=%d)=%.3f. These values check the drop path and counter, not a production rate.",
		d1sTotal, len(d1s), n-1, digestRespondMaxConcurrent, float64(n-1-digestRespondMaxConcurrent)/float64(n-1), digestRespondMaxConcurrent, n-1, selectorPoissonTail(float64(n-1), digestRespondMaxConcurrent))
	if d1sTotal == 0 {
		t.Fatalf("starvation: zero drops under GOMAXPROCS=1 with 250K-key builds; the responder-drop path or digestRespondDropped counter is broken")
	}
	// Lift the cap between bursts. enqueueDigestResponse captures respondSem
	// per call, so after earlier builds drain, only new requests see the new
	// channel. Under the same starvation that produced drops at cap 16, every
	// lifted-cap repetition must report zero; otherwise the counter is not
	// measuring responder-cap drops.
	m.nodes[hot].g.respondSem = make(chan struct{}, 4096)
	t.Logf("lifted-cap control (GOMAXPROCS=1): hot node respondSem raised to 4096")
	ctl := censusBurstDirect(t, m, hot, 3, 12*time.Second)
	for rep, d := range ctl {
		if d != 0 {
			t.Fatalf("lifted-cap control rep=%d: drops=%d, want 0 under the starvation that produced drops at the current cap 16; the counter is not isolating responder-cap drops", rep+1, d)
		}
	}
	t.Logf("lifted-cap control: drops=0 on all %d starved repetitions at cap 4096, compared with %d drops at the production cap; the cap causes the measured drops", len(ctl), d1sTotal)
	// Restore the original core count and production cap after builds have
	// drained. Capturing the semaphore per call keeps the swap race-free.
	runtime.GOMAXPROCS(prevProcs)
	m.nodes[hot].g.respondSem = make(chan struct{}, digestRespondMaxConcurrent)
}

// TestK3FallbackCensusD10KSmallN measures D=10000 at N=12, split evenly
// across three regions. This is the largest such shape the four-core harness
// carries and exceeds the roughly 900-entry full-oversend bound. The separate
// N=100 by 10,000-key test reports that distinct shape.
func TestK3FallbackCensusD10KSmallN(t *testing.T) {
	if os.Getenv("RUN_CENSUS") != "1" {
		t.Skip("small-N D10K census: set RUN_CENSUS=1 (minutes on four cores)")
	}
	m := buildCensusMesh(t, 12)
	defer m.close()
	finishCensusMesh(t, m)
	censusBatch(t, m, "D10000", 0, 10000, 3, 750*time.Millisecond)
}

// TestCensusMicroSmoke always exercises the census harness at N=6. It builds
// and dials the mesh, performs real digest exchanges, and requires a 12-key
// batch to converge in milliseconds. Nonzero exchange counters ensure the
// normal suite exercises the digest path used by the gated census.
func TestCensusMicroSmoke(t *testing.T) {
	m := buildCensusMesh(t, 6)
	defer m.close()
	finishCensusMesh(t, m)
	censusBatch(t, m, "smoke", 0, 12, 3, 100*time.Millisecond)
	c0 := readCensusCounters(m.nodes[0])
	if c0.exchanges == 0 {
		t.Fatalf("census micro-smoke: zero fired exchanges after the rounds — the harness did not exercise the digest path")
	}
}
