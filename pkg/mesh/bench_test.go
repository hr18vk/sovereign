// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// Sender-side cost benchmark for 700,000 entries and 35 nop-sink peers, plus a
// nil-map-lookup microbenchmark. The cost benchmark runs only when
// SOVEREIGN_BENCH_BOUNDED_GOSSIP=700K, keeping it out of the regular test suite.
// Metrics-only probes record {peer, n, walkSort} without retaining buffers.
//
// Each sink uses the real TLS transport, challenge verification, and accept
// loop, but discards frames without a receiver, Join, or relay retention. This
// isolates the sender's walk, resolve, sort, and sign work on a four-core
// machine. Delivery to full receivers is covered by the convergence tests. The
// reported walk+sort interval runs from probeT0 to the post-sort capture and
// excludes publishing.

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// RelaySharedSink is a nop-frame TLS node with a real transport, PeerSet, and
// accept loop. Challenge verification makes the sender's edges eligible for
// egress; the sink discards every frame without receiving, joining, or
// retaining it.
type RelaySharedSink struct {
	ln     net.Listener
	ident  *NodeIdentity
	ps     *PeerSet
	dir    *identity.Directory
	addr   string
	engine *eng.DeltaCRDTEngine // retained so teardown can close it after the accept loops join
}

func benchNewSink(t *testing.T, ca *crypto.MeshCA, caPath, root, name string, seed byte, ctx context.Context, wg *sync.WaitGroup) *RelaySharedSink {
	t.Helper()
	seedBuf := make([]byte, ed25519.SeedSize)
	for i := range seedBuf {
		seedBuf[i] = seed + byte(i)
	}
	ident, err := NewNodeIdentity(seedBuf)
	if err != nil {
		t.Fatalf("sink %s: NewNodeIdentity: %v", name, err)
	}
	dataDir := filepath.Join(root, "data-"+name)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("sink %s: mkdir: %v", name, err)
	}
	eng.DataDir = dataDir
	// Untouched arenas reserve mmap address space without consuming RSS, so 35
	// sink engines have little memory cost despite their nominal 64 MiB size.
	engine, err := eng.NewDeltaCRDTEngine(ident.NodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("sink %s: engine: %v", name, err)
	}
	leaf, err := ca.IssueLeaf(identHex(ident.NodeID))
	if err != nil {
		t.Fatalf("sink %s: IssueLeaf: %v", name, err)
	}
	certPath, keyPath, err := leaf.WritePEM(filepath.Join(root, "leaf-"+name))
	if err != nil {
		t.Fatalf("sink %s: WritePEM: %v", name, err)
	}
	tr, err := transport.NewTLSTransport(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("sink %s: transport: %v", name, err)
	}
	ln, err := tr.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink %s: listen: %v", name, err)
	}
	ps := NewPeerSet(tr, nopFrameSink{}, ident, engine)
	// A sink has no Gossiper to install a challenge Directory. Install one
	// explicitly; the benchmark registers the sender's key before dialing so
	// challenge responses can be verified.
	dir := identity.NewDirectory()
	ps.SetChallengeDirectory(dir)
	wg.Add(1)
	go runMeshAcceptLoop(ctx, ln, nopFrameSink{}, nil, wg, ps)
	return &RelaySharedSink{ln: ln, ident: ident, ps: ps, dir: dir, addr: ln.Addr().String(), engine: engine}
}

// benchMemAvailableMB reads MemAvailable from /proc/meminfo so the benchmark
// can report available memory and reduce its entry count on smaller machines.
func benchMemAvailableMB(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Fatalf("read /proc/meminfo: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			kb, err := strconv.Atoi(fields[1])
			if err != nil {
				t.Fatalf("parse MemAvailable %q: %v", line, err)
			}
			return kb / 1024
		}
	}
	t.Fatalf("MemAvailable line not found")
	return 0
}

// TestRelaySharedDeltaCostBench runs the sender-side cost benchmark for
// 700,000 entries and 35 nop-sink peers when
// SOVEREIGN_BENCH_BOUNDED_GOSSIP=700K. One sender with a 1 GiB arena inserts
// the full self-diff through the batched insert path, pre-populating
// payloadCache so the walk measures shipping rather than payload misses. One
// sweep with metrics probes reports build count, walk+sort duration, entries
// per build, and unsafe.Sizeof(BuiltEvent).
func TestRelaySharedDeltaCostBench(t *testing.T) {
	if os.Getenv("SOVEREIGN_BENCH_BOUNDED_GOSSIP") != "700K" {
		t.Skip("the cost benchmark runs only under SOVEREIGN_BENCH_BOUNDED_GOSSIP=700K (the regular test suite never sets it; the benchmark artifact names its command)")
	}
	const nSinks = 35
	availMB := benchMemAvailableMB(t)
	entries := 700_000
	if availMB < 5000 {
		entries = 300_000
		t.Logf("benchmark: MemAvailable=%d MiB < 5000; using the reduced %d-entry shape with the same peer count", availMB, entries)
	}
	t.Logf("benchmark: MemAvailable=%d MiB at start; target shape %d entries x %d sinks", availMB, entries, nSinks)

	h := newRelaySharedHarness(t, 1, 1024) // the sender node, a 1 GiB arena
	defer h.close()
	const A = 0
	h.nodes[A].g.SetBatchSize(100)

	items := make([]BatchItem, 0, 100)
	inserted := 0
	flush := func() {
		if len(items) == 0 {
			return
		}
		if _, _, err := h.nodes[A].g.InsertLocalEventsBatch(items); err != nil {
			t.Fatalf("insert at %d: %v", inserted, err)
		}
		inserted += len(items)
		items = items[:0]
	}
	for i := 0; i < entries; i++ {
		items = append(items, BatchItem{
			EntityID: fmt.Sprintf("relay-bench-key-%d", i),
			Payload:  fmt.Sprintf("p-%08d", i),
			Entry:    eng.CRDTEntry{SystemTime: int64(1_700_600_000 + i/1000), H3Index: uint64(i % 20000)},
		})
		if len(items) == 100 {
			flush()
		}
	}
	flush()
	if inserted != entries {
		t.Fatalf("premise: inserted %d events, want %d", inserted, entries)
	}

	// The sinks use real TLS, challenge verification, and accept loops but
	// discard frames. Declare sinkWG and sinkCtx before their cleanup defer.
	sinkWG := &sync.WaitGroup{}
	sinkCtx, sinkCancel := context.WithCancel(context.Background())
	var sinks []*RelaySharedSink
	defer func() {
		sinkCancel()
		for _, s := range sinks {
			_ = s.ln.Close()
			_ = s.ps.Close() // close connections so blocked ReadFrames return and in-flight serves drain
		}
		sinkWG.Wait()
		for _, s := range sinks {
			_ = s.engine.Close() // join first so engine flushing cannot race TempDir cleanup
		}
	}()
	sinkRoot := t.TempDir()
	// All sinks use the harness CA trusted by the sender.
	for i := 0; i < nSinks; i++ {
		s := benchNewSink(t, h.ca, h.caPath, sinkRoot, fmt.Sprintf("sink%d", i), byte(0x40+i), sinkCtx, sinkWG)
		sinks = append(sinks, s)
		// Register both public keys before dialing. Challenge verification is
		// one-shot per connection, so a response that arrives before registration
		// would leave that edge permanently unverified.
		_ = h.nodes[A].g.RegisterPeer(s.ident.NodeID, s.ident.Pub)
		if err := s.dir.Register(h.nodes[A].ident.NodeID, h.nodes[A].ident.Pub); err != nil {
			t.Fatalf("sink %d dir register sender: %v", i, err)
		}
		if err := h.nodes[A].ps.Dial(h.ctx, s.addr, "localhost", s.ident.NodeID); err != nil {
			t.Fatalf("dial sink %d: %v", i, err)
		}
	}
	// Require every edge to verify before sweeping; otherwise the egress gate
	// would silently reduce the measured fan-out.
	deadline := time.Now().Add(60 * time.Second)
	for {
		missing := 0
		for i := range sinks {
			if !h.nodes[A].ps.egressVerified(sinks[i].ident.NodeID) {
				missing++
			}
		}
		if missing == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("premise: %d of %d sink edges did not verify egress within 60s — the sweep egress gate would skip them and the fan-out premise would break", missing, len(sinks))
		}
		time.Sleep(10 * time.Millisecond)
	}

	metrics := &[]shipBuildMetric{}
	h.nodes[A].g.shipBuildMetrics.Store(metrics)
	defer h.nodes[A].g.shipBuildMetrics.Store(nil)
	sweepStart := time.Now()
	st := h.nodes[A].g.AntiEntropySweep(context.Background())
	sweepWall := time.Since(sweepStart)
	if st.shippedEnvelopes == 0 {
		t.Fatalf("premise: the sweep shipped nothing — the bench would observe no ship path")
	}
	builds := len(*metrics)
	if builds == 0 {
		t.Fatalf("premise: the metrics probe captured no builds — the bench observed nothing")
	}
	sizeBytes := int(unsafe.Sizeof(BuiltEvent{}))
	var totalWalkSort time.Duration
	var totalBytes int64
	for i := range *metrics {
		m := (*metrics)[i]
		totalWalkSort += m.walkSort
		totalBytes += int64(m.n) * int64(sizeBytes)
		t.Logf("benchmark build %d: peer=%x n=%d walkSortNs=%d", i, m.peer, m.n, m.walkSort.Nanoseconds())
	}
	perBuild := (*metrics)[0]
	t.Logf("benchmark result: builds=%d sinks=%d entriesPerBuild=%d sizeofBuiltEvent=%d accumulatedBytes=%d totalWalkSortNs=%d sweepWallNs=%d shape=%dx%d MemAvailableAtStartMB=%d",
		builds, nSinks, perBuild.n, sizeBytes, totalBytes, totalWalkSort.Nanoseconds(), sweepWall.Nanoseconds(), entries, nSinks, availMB)
	if builds != nSinks {
		t.Logf("benchmark observation: builds=%d for %d sinks; the small-scale tests assert the shared-build count", builds, nSinks)
	}
}

// BenchmarkRelayLookupMiss measures the resolve-miss path. A nil relay map
// short-circuits before hashing, allowing comparison of lazy per-layer
// initialization with an eager empty-map read.
func BenchmarkRelayLookupMiss(b *testing.B) {
	c := newRelayCache()
	var origin [16]byte
	origin[0] = 0x7f
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, ok := c.lookupBatchCounted(origin, uint64(i)); ok {
			b.Fatalf("premise: the miss-path bench hit a retained entry")
		}
	}
}
