// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests check payload-cache dot alignment and foreign batch relay at one
// and two nodes (ADR-0045).
//
// The one-node tests insert through either the durable bridge or the bare
// engine, record the returned dots, and look up every entry in a generated
// delta. Matching record and lookup keys confirms that construction-time dot
// consumption does not desynchronize the payload cache. A numeric key index
// need not equal its dot counter; consecutive dots and identical cache keys are
// the relevant properties.
//
// The two-node test sends 300 entries from A to B with durable bridges and
// batch size 100. B must retain A's origin IDs, and its retained batch frames
// must let shipBatchedDelta relay A's entries instead of looking for them in
// B's self-originated payload cache. Foreign lookup failures are counted as
// relay misses; a sweep that drops every walked entry fails the test. A miss
// for one of A's own payload entries also fails. These small configurations do
// not establish behavior at larger fleet sizes.

import (
	"context"
	"crypto/rand"
	"fmt"
	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/admission"
	"github.com/hr18vk/sovereign/pkg/clock"
	"github.com/hr18vk/sovereign/pkg/crypto"
	"github.com/hr18vk/sovereign/pkg/durability"
	"github.com/hr18vk/sovereign/pkg/identity"
	"github.com/hr18vk/sovereign/pkg/receive"
	eng "github.com/hr18vk/sovereign/pkg/sync"
	"github.com/hr18vk/sovereign/pkg/transport"
)

// runSeedOwnMissRepro constructs either a durable-bridge gossiper or an
// in-memory gossiper with no WAL. Its engine, WAL, bridge, and gossiper setup
// matches newBatchControlServer, so the test uses the same dot-stamping path as
// batch inserts. Callers can generate a delta and inspect cache.lookup directly
// without HTTP or peer connections.
func runSeedOwnMissRepro(t *testing.T, durable bool) (*Gossiper, *eng.DeltaCRDTEngine, [16]byte) {
	t.Helper()
	nodeID := test503NodeID // reuse the test fixture's nodeID (a non-zero [16]byte)
	eng.DataDir = t.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(nodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	g := NewGossiper(nil, nil, engine, identity.NewDirectory())
	if durable {
		walPath := filepath.Join(t.TempDir(), "seedown.wal")
		wal, err := durability.OpenWAL(walPath)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		t.Cleanup(func() { _ = wal.Close() })
		bridge := durability.NewBridge(engine, wal, 0)
		g.SetBridge(bridge)
	}
	return g, engine, nodeID
}

// TestSeedOwnMissDurable inserts 200 entries through the WAL bridge, generates
// a delta from an empty digest, and resolves each entry through cache.lookup.
// Every lookup must hit using the dot carried by the generated entry.
func TestSeedOwnMissDurable(t *testing.T) {
	const n = 200
	g, engine, nodeID := runSeedOwnMissRepro(t, true)

	items := make([]BatchItem, n)
	for i := 0; i < n; i++ {
		items[i] = BatchItem{
			EntityID: fmt.Sprintf("seed-key-%d", i),
			Payload:  fmt.Sprintf("val-%d", i),
			Entry: eng.CRDTEntry{
				SystemTime:    int64(1_700_000_000 + i),
				AssertionTime: int64(1_700_000_000 + i),
			},
		}
	}
	dots, failedFrom, err := g.InsertLocalEventsBatch(items)
	if err != nil || failedFrom != -1 {
		t.Fatalf("InsertLocalEventsBatch: err=%v failedFrom=%d (want durable success)", err, failedFrom)
	}

	// Save the dots returned by insertion for comparison with lookup keys.
	recSeq := make([]uint64, n)
	for i, d := range dots {
		recSeq[i] = d.Counter
		if d.NodeID != nodeID {
			t.Fatalf("record-dot[%d] NodeID=%x, want seed nodeID=%x (InsertLocal should stamp the local node)", i, d.NodeID, nodeID)
		}
	}
	t.Logf("record-dot sequence (first 5): %v ... (last 3): %v", recSeq[:min(5, n)], recSeq[max(0, n-3):])

	// A numeric key index need not match its dot counter: construction consumes
	// counters before insertion. Gaps between consecutive returned dots are still
	// useful diagnostics, but only a record/lookup mismatch indicates desync.
	gaps := 0
	for i := 1; i < n; i++ {
		if recSeq[i] != recSeq[i-1]+1 {
			gaps++
			if gaps <= 5 {
				t.Logf("record-dot gap at key %d: dot %d -> %d (delta %d, not +1)", i, recSeq[i-1], recSeq[i], int64(recSeq[i])-int64(recSeq[i-1]))
			}
		}
	}

	// GenerateDelta against an empty IBLT follows the non-stratified oversend
	// path used by generateSweepDelta. shipDelta looks up each returned entry by
	// its entity ID and entry.Dot().
	emptyDigest := eng.NewIBLT(1, 4)
	delta := engine.GenerateDelta(emptyDigest)
	defer delta.Release()

	// Walk delta.Entries — the same iteration shipDelta runs — and for each,
	// cache.lookup(entityID, entry.Dot()). Count hits vs misses. A miss is the
	// seed-own-miss symptom reproduced at 1 node.
	hits, misses := 0, 0
	type missRec struct {
		idx          int
		entityID     string
		lookupDot    eng.CausalDot
		storedOrigin [16]byte
	}
	var firstMisses []missRec
	walkIdx := 0
	delta.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		// The self branch (shipDelta): cache.lookup(entityID, entry.Dot())
		_, ok := g.cache.lookup(entityID, entry.Dot())
		if ok {
			hits++
		} else {
			misses++
			if len(firstMisses) < 5 {
				firstMisses = append(firstMisses, missRec{walkIdx, entityID, entry.Dot(), entry.OriginNodeID})
			}
		}
		// The self branch requires the stored origin to remain the local node.
		if entry.OriginNodeID != nodeID {
			t.Errorf("walk[%d] %s: OriginNodeID=%x, want local node %x", walkIdx, entityID, entry.OriginNodeID, nodeID)
		}
		walkIdx++
		return true
	})

	t.Logf("GenerateDelta walked %d entries: cache.lookup hits=%d misses=%d (record-dot gaps=%d)", walkIdx, hits, misses, gaps)

	if misses == 0 {
		t.Logf("durable path: every cache.lookup hit; consecutive-dot gaps=%d", gaps)
		return
	}

	// Correlate each miss with the dot returned by insertion.
	t.Logf("durable path: %d/%d cache.lookups missed", misses, walkIdx)
	for _, m := range firstMisses {
		// Find the record-dot for this entityID (the dots[i] we recorded).
		var recDot eng.CausalDot
		recIdx := -1
		for i := 0; i < n; i++ {
			if items[i].EntityID == m.entityID {
				recDot = dots[i]
				recIdx = i
				break
			}
		}
		t.Logf("miss entity=%s (walk-idx=%d, batch-idx=%d): lookup-dot={%x %d} record-dot={%x %d} stored-origin=%x",
			m.entityID, m.idx, recIdx,
			m.lookupDot.NodeID, m.lookupDot.Counter,
			recDot.NodeID, recDot.Counter,
			m.storedOrigin)
	}
	t.Fatalf("durable path: %d/%d cache.lookups missed for self-originated dots; insertion and lookup dots must agree", misses, walkIdx)
}

// TestSeedOwnMissInMemory repeats the lookup check without a WAL bridge. It
// distinguishes bridge-specific dot handling from the bare engine insert path.
func TestSeedOwnMissInMemory(t *testing.T) {
	const n = 200
	g, engine, nodeID := runSeedOwnMissRepro(t, false)

	items := make([]BatchItem, n)
	for i := 0; i < n; i++ {
		items[i] = BatchItem{
			EntityID: fmt.Sprintf("seed-key-%d", i),
			Payload:  fmt.Sprintf("val-%d", i),
			Entry: eng.CRDTEntry{
				SystemTime:    int64(1_700_000_000 + i),
				AssertionTime: int64(1_700_000_000 + i),
			},
		}
	}
	dots, failedFrom, err := g.InsertLocalEventsBatch(items)
	if err != nil || failedFrom != -1 {
		t.Fatalf("InsertLocalEventsBatch (in-mem): err=%v failedFrom=%d", err, failedFrom)
	}
	recSeq := make([]uint64, n)
	for i, d := range dots {
		recSeq[i] = d.Counter
		if d.NodeID != nodeID {
			t.Fatalf("record-dot[%d] NodeID=%x, want %x", i, d.NodeID, nodeID)
		}
	}
	gaps := 0
	for i := 1; i < n; i++ {
		if recSeq[i] != recSeq[i-1]+1 {
			gaps++
			if gaps <= 5 {
				t.Logf("record-dot gap at key %d: dot %d -> %d (delta %d)", i, recSeq[i-1], recSeq[i], int64(recSeq[i])-int64(recSeq[i-1]))
			}
		}
	}

	emptyDigest := eng.NewIBLT(1, 4)
	delta := engine.GenerateDelta(emptyDigest)
	defer delta.Release()

	hits, misses := 0, 0
	var firstMisses []eng.CausalDot
	walkIdx := 0
	delta.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		_, ok := g.cache.lookup(entityID, entry.Dot())
		if ok {
			hits++
		} else {
			misses++
			if len(firstMisses) < 5 {
				firstMisses = append(firstMisses, entry.Dot())
			}
		}
		if entry.OriginNodeID != nodeID {
			t.Errorf("walk[%d] %s: entry.OriginNodeID=%x, want seed=%x", walkIdx, entityID, entry.OriginNodeID, nodeID)
		}
		walkIdx++
		return true
	})
	t.Logf("GenerateDelta walked %d entries (in-mem): hits=%d misses=%d gaps=%d", walkIdx, hits, misses, gaps)
	if misses == 0 {
		t.Logf("in-memory path: every cache.lookup hit")
		return
	}
	t.Fatalf("in-memory path: %d/%d cache.lookups missed; the mismatch is not bridge-specific", misses, walkIdx)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TestBatchShipForeignMiss uses two durable nodes and batch size 100 to cover
// foreign batch relay. A inserts 300 entries through InsertLocalEventsBatch and
// B originates none, so B's sweep must use retained frames rather than its own
// payload cache. The same test checks A's self-originated payload lookups.
//
// shipBatchedDelta handles self-originated and foreign entries separately.
// Foreign entries resolve through the batch relay cache populated by the
// receiver's retention hook; self-originated entries use payloadCache. This
// test exercises both paths through the production sweep implementation.
func TestBatchShipForeignMiss(t *testing.T) {
	if testing.Short() {
		t.Skip("2-node durable batch-ship reproduction (binds loopback TLS ports)")
	}
	dir := t.TempDir()
	ca, err := crypto.NewMeshCA()
	if err != nil {
		t.Fatalf("NewMeshCA: %v", err)
	}
	caPath, err := ca.WriteCAPEM(dir)
	if err != nil {
		t.Fatalf("WriteCAPEM: %v", err)
	}
	seedA := make([]byte, ed25519.SeedSize)
	seedB := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seedA); err != nil {
		t.Fatalf("rand seedA: %v", err)
	}
	if _, err := rand.Read(seedB); err != nil {
		t.Fatalf("rand seedB: %v", err)
	}
	identA, err := NewNodeIdentity(seedA)
	if err != nil {
		t.Fatalf("NewNodeIdentity A: %v", err)
	}
	identB, err := NewNodeIdentity(seedB)
	if err != nil {
		t.Fatalf("NewNodeIdentity B: %v", err)
	}

	// Per-node engines + durable bridges (--wal-path). Mirror the main engine setup.
	arenaDirA := filepath.Join(dir, "engA")
	arenaDirB := filepath.Join(dir, "engB")
	if err := os.MkdirAll(arenaDirA, 0o755); err != nil {
		t.Fatalf("mkdir engA: %v", err)
	}
	if err := os.MkdirAll(arenaDirB, 0o755); err != nil {
		t.Fatalf("mkdir engB: %v", err)
	}
	eng.DataDir = arenaDirA
	engineA, err := eng.NewDeltaCRDTEngine(identA.NodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("engine A: %v", err)
	}
	t.Cleanup(func() { _ = engineA.Close() })
	walA, err := durability.OpenWAL(filepath.Join(dir, "a.wal"))
	if err != nil {
		t.Fatalf("OpenWAL A: %v", err)
	}
	t.Cleanup(func() { _ = walA.Close() })
	bridgeA := durability.NewBridge(engineA, walA, 0)

	eng.DataDir = arenaDirB
	engineB, err := eng.NewDeltaCRDTEngine(identB.NodeID, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("engine B: %v", err)
	}
	t.Cleanup(func() { _ = engineB.Close() })
	walB, err := durability.OpenWAL(filepath.Join(dir, "b.wal"))
	if err != nil {
		t.Fatalf("OpenWAL B: %v", err)
	}
	t.Cleanup(func() { _ = walB.Close() })
	bridgeB := durability.NewBridge(engineB, walB, 0)

	dirA := identity.NewDirectory()
	dirB := identity.NewDirectory()
	if err := dirB.Register(identA.NodeID, identA.Pub); err != nil {
		t.Fatalf("Register A in B: %v", err)
	}
	if err := dirA.Register(identB.NodeID, identB.Pub); err != nil {
		t.Fatalf("Register B in A: %v", err)
	}
	recvA := receive.NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engineA), clock.NewSystemClock(), dirA, engineA, 50_000_000)
	recvB := receive.NewReceiver(admission.NewPeerBucket(), clock.NewIngressHLCScalarCap(clock.NewSystemClock(), engineB), clock.NewSystemClock(), dirB, engineB, 50_000_000)

	leafA, err := ca.IssueLeaf(identHex(identA.NodeID))
	if err != nil {
		t.Fatalf("IssueLeaf A: %v", err)
	}
	cpA, kpA, err := leafA.WritePEM(filepath.Join(dir, "nodeA"))
	if err != nil {
		t.Fatalf("WritePEM A: %v", err)
	}
	leafB, err := ca.IssueLeaf(identHex(identB.NodeID))
	if err != nil {
		t.Fatalf("IssueLeaf B: %v", err)
	}
	cpB, kpB, err := leafB.WritePEM(filepath.Join(dir, "nodeB"))
	if err != nil {
		t.Fatalf("WritePEM B: %v", err)
	}
	trA, err := transport.NewTLSTransport(cpA, kpA, caPath)
	if err != nil {
		t.Fatalf("transport A: %v", err)
	}
	trB, err := transport.NewTLSTransport(cpB, kpB, caPath)
	if err != nil {
		t.Fatalf("transport B: %v", err)
	}
	lnA, err := trA.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	lnB, err := trB.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)

	psA := NewPeerSet(trA, recvA, identA, engineA)
	psB := NewPeerSet(trB, recvB, identB, engineB)
	// PeerSet-threaded accept loops install verified peer identities. This test
	// uses oversend deltas, so no digest responder is needed.
	go runAcceptLoopWithPeerSet(ctx, lnA, recvA, nil, &wg, psA)
	go runAcceptLoopWithPeerSet(ctx, lnB, recvB, nil, &wg, psB)
	// Deferred calls run in reverse order: close listeners to release Accept,
	// cancel the context to release readers, then join the accept loops. These
	// defers are registered after the goroutines start so they run before the
	// engine and WAL cleanup registered above.
	defer wg.Wait()
	defer cancel()
	defer lnB.Close()
	defer lnA.Close()
	gA := NewGossiper(psA, identA, engineA, dirA)
	gB := NewGossiper(psB, identB, engineB, dirB)
	gA.SetBridge(bridgeA)
	gB.SetBridge(bridgeB)
	// Batch size 100 selects shipBatchedDelta, as in the default configuration.
	gA.SetBatchSize(100)
	gB.SetBatchSize(100)
	// Install both retention hooks used by production wiring. The per-frame hook
	// covers shipDelta; the batch hook populates the cache used below.
	recvA.SetRelayRetainer(gA.RetainForeign)
	recvB.SetRelayRetainer(gB.RetainForeign)
	// HandleBatchFrame calls InspectBatchDots and RetainForeignBatch, retaining
	// each received BatchEnvelope. shipBatchedDelta can then resolve foreign dots
	// with lookupBatch and republish the retained frame once per sweep.
	recvA.SetRelayRetainerBatch(gA.RetainForeignBatch)
	recvB.SetRelayRetainerBatch(gB.RetainForeignBatch)
	_ = gA.RegisterPeer(identB.NodeID, identB.Pub)
	_ = gB.RegisterPeer(identA.NodeID, identA.Pub)
	if err := psA.Dial(ctx, lnB.Addr().String(), "localhost", identB.NodeID); err != nil {
		t.Fatalf("dial A->B: %v", err)
	}
	if err := psB.Dial(ctx, lnA.Addr().String(), "localhost", identA.NodeID); err != nil {
		t.Fatalf("dial B->A: %v", err)
	}
	asyncWait(t, psA, identB.NodeID)
	asyncWait(t, psB, identA.NodeID)

	// A injects every key through the batch-insert path. B injects nothing, so
	// every entry later walked on B is foreign to B.
	const n = 300
	items := make([]BatchItem, n)
	for i := 0; i < n; i++ {
		items[i] = BatchItem{
			EntityID: fmt.Sprintf("seed-2node-key-%d", i),
			Payload:  fmt.Sprintf("val-%d", i),
			Entry: eng.CRDTEntry{
				SystemTime:    int64(1_700_000_000 + i),
				AssertionTime: int64(1_700_000_000 + i),
			},
		}
	}
	if _, ff, err := gA.InsertLocalEventsBatch(items); err != nil || ff != -1 {
		t.Fatalf("seed InsertLocalEventsBatch: err=%v ff=%d", err, ff)
	}

	// Run a few sweep rounds so A ships to B + B receives (Join's A's deltas).
	for round := 0; round < 3; round++ {
		gA.AntiEntropySweep(ctx)
		time.Sleep(50 * time.Millisecond)
		gB.AntiEntropySweep(ctx)
		time.Sleep(50 * time.Millisecond)
	}

	// Check that B retained A's origin IDs and count payload-cache misses by
	// origin before driving the production relay path.
	bEntries := 0
	bForeign := 0
	bSelf := 0
	bLookupMissForeign := 0
	bLookupMissSelf := 0
	emptyDigest := eng.NewIBLT(1, 4)
	deltaB := engineB.GenerateDelta(emptyDigest)
	defer deltaB.Release()
	deltaB.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		bEntries++
		isForeign := entry.OriginNodeID != identB.NodeID
		if isForeign {
			bForeign++
		} else {
			bSelf++
		}
		// The exact lookup shipBatchedDelta runs:
		_, ok := gB.cache.lookup(entityID, entry.Dot())
		if !ok {
			if isForeign {
				bLookupMissForeign++
			} else {
				bLookupMissSelf++
			}
		}
		return true
	})
	t.Logf("B GenerateDelta: entries=%d foreign=%d self=%d; payload-cache misses foreign=%d self=%d",
		bEntries, bForeign, bSelf, bLookupMissForeign, bLookupMissSelf)

	// Drive shipBatchedDelta against B's live peer A. Its counters distinguish a
	// working retained-frame relay from a sweep that drops every walked entry.
	deltaB2 := engineB.GenerateDelta(emptyDigest)
	defer deltaB2.Release()
	// entries counts published events only. Foreign lookup failures increment
	// relayMisses, while local payload failures increment misses. Count the walk
	// separately so the assertion can detect a round that ships nothing and
	// classifies every walked entry as a miss (ADR-0045 §5).
	b2Walked := 0
	deltaB2.Entries(func(entityID string, entry eng.CRDTEntry) bool { b2Walked++; return true })
	stB := gB.shipBatchedDelta(ctx, identA.NodeID, deltaB2, 100) // no self-originated commit is pending on this all-foreign delta
	t.Logf("B shipBatchedDelta(A): shipped=%d entries=%d foreign_env=%d foreign_recv=%d misses=%d relay_misses=%d walked=%d",
		stB.shipped, stB.entries, stB.foreignEnv, stB.foreignRecv, stB.misses, stB.relayMisses, b2Walked)

	// Repeat the payload lookup on A, separating self-originated entries from
	// any foreign entries received during the sweeps.
	aEntries := 0
	aSelfMiss := 0
	aForeignMiss := 0
	aSelfHit := 0
	deltaA := engineA.GenerateDelta(emptyDigest)
	defer deltaA.Release()
	deltaA.Entries(func(entityID string, entry eng.CRDTEntry) bool {
		aEntries++
		isSelf := entry.OriginNodeID == identA.NodeID
		_, ok := gA.cache.lookup(entityID, entry.Dot())
		if isSelf {
			if ok {
				aSelfHit++
			} else {
				aSelfMiss++
			}
		} else {
			if !ok {
				aForeignMiss++
			}
		}
		return true
	})
	t.Logf("A (seed) GenerateDelta: entries=%d | own-dots cache.lookup hit=%d miss=%d | foreign miss=%d",
		aEntries, aSelfHit, aSelfMiss, aForeignMiss)

	// A zero-ship result with every walked entry counted as a miss means the
	// foreign relay path dropped the entire delta.
	if b2Walked > 0 && stB.shipped == 0 && stB.misses+stB.relayMisses == b2Walked {
		t.Errorf("B dropped every foreign delta: shipped=0, misses=%d + relay_misses=%d = walked=%d", stB.misses, stB.relayMisses, b2Walked)
	}

	// Self-originated entries must resolve through A's own payload cache.
	if aSelfMiss > 0 {
		t.Errorf("A missed %d of its own payload-cache dots; hits=%d misses=%d", aSelfMiss, aSelfHit, aSelfMiss)
	} else {
		t.Logf("A resolved all %d self-originated payload-cache dots", aSelfHit)
	}

	if b2Walked > 0 && stB.shipped == 0 && stB.misses+stB.relayMisses == b2Walked {
		t.Fatalf("foreign batch relay failed: misses=%d + relay_misses=%d = walked=%d; B shipped zero entries", stB.misses, stB.relayMisses, b2Walked)
	}
	if bForeign == 0 {
		t.Logf("B received none of A's deltas in 3 rounds, so foreign relay was not exercised")
	}
}
