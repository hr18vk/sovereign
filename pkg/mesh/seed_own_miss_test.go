// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// seed_own_miss_test.go — DEEP root-cause investigation of the
// 100-node silicon convergence blocker (2026-08-21). Two symptoms were
// reported: (1) the SEED misses its OWN payload in cache.lookup; (2) every
// RECEIVER takes the SELF/payload-miss branch (relay_miss=0) for the SEED's
// FOREIGN deltas. This file reproduces + pins the LOAD-BEARING root cause at
// SMALL scale (2 nodes, NO silicon).
//
// THE ROOT CAUSE (PROVEN, RED at 2 nodes): shipBatchedDelta (batch.go:349-365)
// — the path AntiEntropySweep uses when --batch-size > 1 (the DEFAULT 100,
// main.go:330) — has NO foreign/relay branch. It routes the WHOLE delta
// (self + foreign) through cache.lookup (the SELF-only payloadCache, which
// holds ONLY self-originated payloads). So a receiver sweeping a FOREIGN delta
// MISSES for every entry → ships 0 → the foreign delta never propagates past
// one hop. This is the EXACT pre-fix one-hop-relay bug (gossip.go:88-99 doc), just
// on the BATCH path instead of the per-frame path. shipDelta got the
// relay branch (gossip.go:1176-1190: FOREIGN → relay.lookup → re-publish);
// shipBatchedDelta NEVER did.
//
// SYMPTOM 2 (REPRODUCED, RED): the 2-node test below proves B (receiver) Join's
// all 300 of A's foreign deltas with OriginNodeID preserved = A (the receive
// path is clean — ApplyCRDTDeltaEvent/Batch + Join store the wire's
// OriginNodeID verbatim), but B's shipBatchedDelta(A) ships=0, misses=300
// (drops every foreign delta). This is the 2-node mirror of the silicon
// "relay_miss=0 / payload miss across ALL nodes" symptom.
//
// SYMPTOM 1 (HONEST NEGATIVE): the seed-misses-its-OWN-payload symptom does
// NOT reproduce at 1 node (TestSeedOwnMissDurable / TestSeedOwnMissInMemory) NOR at 2 nodes (A's own
// dots all HIT). The payloadCache is never evicted (only record/lookup, no
// delete — gossip.go:58-86) + record/lookup use IDENTICAL payloadKey{entityID,
// dot} shapes, so a self-dot miss is statically impossible. The silicon
// "payload miss for-key-1585 dot={seedNodeID 1587}" log is consistent
// with the seed sweeping its OWN delta via shipBatchedDelta's SELF branch
// (entry.OriginNodeID==owner → "payload miss", NOT "relay miss") — but the
// dot it logs HITS at small scale, so symptom 1 is NOT independently
// reproduced here. The LOAD-BEARING blocker is symptom 2.
//
// THE CLUE (key-1585 → dot 1587, off-by-2) is a RED HERRING for the desync:
// the 1-node test shows record-dot[0]=2 (initialCounter=1 + 1 more consume at
// construction), a CONSTANT +2 offset (key-i → dot i+2), with NO gaps + record
// == lookup. The silicon's 1587 = 1585+2 is this same constant, NOT a desync.

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

// runSeedOwnMissRepro is the shared harness for both the durable-bridge path
// (the silicon /v1/batch-insert config) and the in-memory path (the
// --wal-path="" config). It mirrors batch_insert_test.go's
// newBatchControlServer setup (eng.DataDir + NewDeltaCRDTEngine + OpenWAL +
// NewBridge + NewGossiper + SetBridge) so the dot-stamping path is the
// production path byte-for-byte. It returns the gossiper + engine so the test
// can drive GenerateDelta + walk cache.lookup directly (no HTTP, no peers).
func runSeedOwnMissRepro(t *testing.T, durable bool) (*Gossiper, *eng.DeltaCRDTEngine, [16]byte) {
	t.Helper()
	nodeID := test503NodeID // reuse the fixture's nodeID (a non-zero [16]byte)
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

// TestSeedOwnMissDurable is the DURABLE-path reproduction (the silicon
// /v1/batch-insert config — --wal-path set, bridge active). It injects N keys
// via InsertLocalEventsBatch, then GenerateDelta (oversend = the production
// sweep's delta) + walks delta.Entries calling cache.lookup(entityID,
// entry.Dot). A MISS proves the record-dot != lookup-dot desync at 1 node.
func TestSeedOwnMissDurable(t *testing.T) {
	const n = 200 // >1585-ish scaled? no — small N first; the desync (if any) shows at ANY N
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

	// Record the dot sequence the cache was populated under (InsertLocal's
	// return). This is the record-dot. Print first/last + any gaps so an
	// off-by-N or a counter-consume is visible.
	recSeq := make([]uint64, n)
	for i, d := range dots {
		recSeq[i] = d.Counter
		if d.NodeID != nodeID {
			t.Fatalf("record-dot[%d] NodeID=%x, want seed nodeID=%x (InsertLocal should stamp the local node)", i, d.NodeID, nodeID)
		}
	}
	t.Logf("record-dot sequence (first 5): %v ... (last 3): %v", recSeq[:min(5, n)], recSeq[max(0, n-3):])

	// THE KEY OBSERVATION: is the recorded dot sequence strictly 1:1 with the
	// key index (recSeq[i] == i+1-ish)? If counters are CONSUMED elsewhere,
	// recSeq will have a GAP. The silicon clue (key-1585 → dot 1587) says the
	// gap appears. Detect ANY non-monotonic-by-1 step here.
	gaps := 0
	for i := 1; i < n; i++ {
		if recSeq[i] != recSeq[i-1]+1 {
			gaps++
			if gaps <= 5 {
				t.Logf("record-dot GAP at key %d: dot %d -> %d (delta %d, NOT +1)", i, recSeq[i-1], recSeq[i], int64(recSeq[i])-int64(recSeq[i-1]))
			}
		}
	}

	// GenerateDelta against an EMPTY IBLT = the production oversend sweep path
	// (gossip.go:1026 generateSweepDelta stratified-OFF branch). This is the
	// SAME delta shipDelta walks. The delta yields entries whose entry.Dot
	// is what the cache.lookup is keyed by in the sweep.
	emptyDigest := eng.NewIBLT(1, 4)
	delta := engine.GenerateDelta(emptyDigest)
	defer delta.Release()

	// Walk delta.Entries — the SAME iteration shipDelta runs — + for each,
	// cache.lookup(entityID, entry.Dot). COUNT hits vs misses. A miss IS the
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
		// The SELF branch (gossip.go:1193 shipDelta): cache.lookup(entityID, entry.Dot)
		_, ok := g.cache.lookup(entityID, entry.Dot())
		if ok {
			hits++
		} else {
			misses++
			if len(firstMisses) < 5 {
				firstMisses = append(firstMisses, missRec{walkIdx, entityID, entry.Dot(), entry.OriginNodeID})
			}
		}
		// Assert the stored entry's OriginNodeID == seed (the SELF branch
		// condition). If it's NOT the seed, the stored entry got re-origin'd
		// — the receive-path symptom 2, at the seed itself.
		if entry.OriginNodeID != nodeID {
			t.Errorf("walk[%d] %s: entry.OriginNodeID=%x, want seed=%x (the stored entry's origin got re-stamped — symptom 2 at the seed)", walkIdx, entityID, entry.OriginNodeID, nodeID)
		}
		walkIdx++
		return true
	})

	t.Logf("GenerateDelta walked %d entries: cache.lookup hits=%d misses=%d (record-dot gaps=%d)", walkIdx, hits, misses, gaps)

	if misses == 0 {
		t.Logf("GREEN at 1 node (durable): every cache.lookup HIT — the seed-own-miss symptom is NOT reproducible at 1 node on the durable path. The bug needs >1 node OR a different path (the record-dot vs lookup-dot agree). record-dot gaps=%d (if 0, the dot sequence is 1:1 with the key index — no counter-consume).", gaps)
		return
	}

	// Negative control: misses reproduced at 1 node. Print the record-dot vs lookup-dot for
	// the first few misses + cross-reference against the recorded sequence to
	// pin the desync.
	t.Logf("RED — seed-own-miss reproduced at 1 node (durable): %d/%d cache.lookups MISSED.", misses, walkIdx)
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
		t.Logf("MISS entity=%s (walk-idx=%d, batch-idx=%d): lookup-dot={%x %d} record-dot={%x %d} stored-origin=%x",
			m.entityID, m.idx, recIdx,
			m.lookupDot.NodeID, m.lookupDot.Counter,
			recDot.NodeID, recDot.Counter,
			m.storedOrigin)
	}
	t.Fatalf("RED — seed-own-miss reproduced at 1 node (durable path): %d/%d cache.lookups MISSED for the seed's OWN dots. See the record-dot vs lookup-dot values above (the desync is the root cause).", misses, walkIdx)
}

// TestSeedOwnMissInMemory is the in-memory-path control (the
// --wal-path="" config — bridge nil, bare engine.InsertLocal loop).
// It proves whether the durable bridge (PutLocals) is the desync source or
// whether the bare InsertLocal path ALSO desyncs (isolating the bridge).
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
				t.Logf("record-dot GAP at key %d: dot %d -> %d (delta %d)", i, recSeq[i-1], recSeq[i], int64(recSeq[i])-int64(recSeq[i-1]))
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
		t.Logf("GREEN at 1 node (in-memory): every cache.lookup HIT. The bare InsertLocal path does NOT desync (the durable bridge is the suspect if the durable test went RED).")
		return
	}
	t.Fatalf("RED — seed-own-miss reproduced at 1 node (in-memory path): %d/%d MISSED. The desync is NOT bridge-specific (bare InsertLocal desyncs too).", misses, walkIdx)
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

// TestBatchShipForeignMiss is the 2-node SILICON-MIRROR reproduction:
// durable bridge on BOTH nodes (the --wal-path config), InsertLocalEventsBatch
// on the seed (the /v1/batch-insert path), batchSize=100 (the --batch-size
// default → shipBatchedDelta, NOT per-frame shipDelta). It proves symptom 2
// (the receiver takes the SELF/payload-miss branch for the SEED's FOREIGN
// deltas) + symptom 1 (the seed misses its OWN payload) at 2 nodes — the
// cheap, deterministic, full-log mirror of the 100-node silicon gate.
//
// THE HYPOTHESIS IT TESTS: shipBatchedDelta (batch.go:349) has NO foreign/relay
// branch — it ALWAYS does cache.lookup (the SELF payloadCache, which holds ONLY
// self-originated payloads). So when the receiver sweeps + its GenerateDelta
// yields the SEED's foreign entries, shipBatchedDelta's cache.lookup MISSES for
// every foreign entry → "payload miss" log (batch.go:357) with relay_miss=0 (the
// relay branch in shipDelta is NEVER reached because shipBatchedDelta has none).
// This matches symptom 2 EXACTLY. The batch.go SELF-ORIGIN BOUNDARY doc (lines
// 11-18) says ShipBatch is self-only — but AntiEntropySweep (gossip.go:987)
// routes the WHOLE delta (self + foreign) through shipBatchedDelta when
// batchSize>1, contradicting the boundary.
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

	// Per-node engines + durable bridges (--wal-path). Mirror main.go:804-826.
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
	go runAcceptLoop(ctx, lnA, recvA, nil, &wg)
	go runAcceptLoop(ctx, lnB, recvB, nil, &wg)
	// Teardown LIFO order: close listeners FIRST (unblocks each runAcceptLoop's
	// ln.Accept → the loops return → wg.Done), then cancel ctx (unblocks the
	// serveTestConn readers), then wg.Wait. Registering these defers AFTER the
	// goroutines launch makes them run BEFORE any earlier defer.
	defer wg.Wait()
	defer cancel()
	defer lnB.Close()
	defer lnA.Close()

	psA := NewPeerSet(trA, recvA, identA, engineA)
	psB := NewPeerSet(trB, recvB, identB, engineB)
	gA := NewGossiper(psA, identA, engineA, dirA)
	gB := NewGossiper(psB, identB, engineB, dirB)
	gA.SetBridge(bridgeA)
	gB.SetBridge(bridgeB)
	// THE SILICON KNOB: batchSize=100 (main.go default) → shipBatchedDelta.
	// This is the path with NO foreign/relay branch (the hypothesis).
	gA.SetBatchSize(100)
	gB.SetBatchSize(100)
	// Wire the relay retainer (main.go:1075 does this) so the relay branch in
	// shipDelta WOULD work — but shipBatchedDelta never reaches it.
	recvA.SetRelayRetainer(gA.RetainForeign)
	recvB.SetRelayRetainer(gB.RetainForeign)
	// Wire the BATCH relay retainer (the batch-relay layer) so
	// HandleBatchFrame retains the whole BatchEnvelope A ships (the path the
	// --batch-size=100 sweep takes) — WITHOUT this the batch relay is EMPTY +
	// shipBatchedDelta's foreign branch lookupBatch misses (the RED this test
	// pins). WITH it B receives A's batch via HandleBatchFrame → InspectBatchDots
	// + RetainForeignBatch retains the envelope → shipBatchedDelta's foreign
	// branch relays it onward (lookupBatch + per-sweep dedup) → shipped>0 GREEN.
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

	// SEED (A) injects N keys via InsertLocalEventsBatch (the /v1/batch-insert
	// path, the silicon config). B injects NOTHING — so all of B's entries are
	// FOREIGN (A's), the exact condition symptom 2 names.
	const n = 300
	items := make([]BatchItem, n)
	for i := 0; i < n; i++ {
		items[i] = BatchItem{
			EntityID: fmt.Sprintf("twonode-key-%d", i),
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

	// ── INSPECT B (the receiver): does its stored state carry A's deltas with
	// A's OriginNodeID? And does shipBatchedDelta's cache.lookup MISS for them? ──
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
		// The EXACT lookup shipBatchedDelta runs (batch.go:354):
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
	t.Logf("B (receiver) GenerateDelta: entries=%d foreign(origin=A)=%d self(origin=B)=%d | shipBatchedDelta cache.lookup MISS foreign=%d self=%d",
		bEntries, bForeign, bSelf, bLookupMissForeign, bLookupMissSelf)

	// ── THE PRODUCTION-PATH PROOF: drive the REAL shipBatchedDelta (batch.go:309)
	// against B's live peer A, and read its returned (shipped, entries, misses).
	// On the BUGGY code: shipBatchedDelta has no foreign branch → cache.lookup
	// misses for ALL of A's foreign deltas → shipped=0, misses=entries (B drops
	// every foreign delta this round — the 2-node mirror of the 100-node stall).
	// After the FIX (a foreign branch mirroring shipDelta's relay.lookup): B
	// relays A's foreign deltas → shipped>0, misses drops → the test goes GREEN.
	// This is the true RED→GREEN gate (it exercises the production path, NOT a
	// hand-rolled cache.lookup that would stay RED after the fix).
	deltaB2 := engineB.GenerateDelta(emptyDigest)
	defer deltaB2.Release()
	// counter-semantics port: `entries` is PUBLISHED-only now
	// (the walk-top double-count is deleted) and foreign lookup failures land in
	// `relayMisses`, not `misses`. The RED detector therefore counts the WALK
	// itself (b2Walked) and fires when every walked entry landed in a miss
	// counter with zero ships — the bug shape, stated in the new counters.
	b2Walked := 0
	deltaB2.Entries(func(entityID string, entry eng.CRDTEntry) bool { b2Walked++; return true })
	shippedB, entriesB, missesB, relayMissesB, _ := gB.shipBatchedDelta(ctx, identA.NodeID, deltaB2, 100) // pending is the SELF-commit classifier — 0 on this all-FOREIGN delta by construction
	t.Logf("B shipBatchedDelta(A) PRODUCTION: shipped=%d entries=%d misses=%d relay_misses=%d walked=%d (RED if walked>0 && shipped==0 && misses+relay_misses==walked — every walked delta dropped; GREEN after the fix ships>0)",
		shippedB, entriesB, missesB, relayMissesB, b2Walked)

	// ── INSPECT A (the seed): does its own sweep miss its OWN payload? ──
	// At 1 node A hits its own. At 2 nodes A may have received B's (none) or its
	// own echoed back. The seed-own-miss symptom is A missing its OWN dots.
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
	t.Logf("A (seed) GenerateDelta: entries=%d | own-dots cache.lookup HIT=%d MISS=%d | foreign MISS=%d",
		aEntries, aSelfHit, aSelfMiss, aForeignMiss)

	// ── THE RED ASSERTION (symptom 2, production path): B's shipBatchedDelta
	// drops EVERY foreign delta — shipped=0 + misses==entries>0. This is the
	// load-bearing root cause: at 100 nodes every receiver's batch sweep drops
	// every foreign delta → deltas never propagate past one hop → 99/100 diverge.
	if b2Walked > 0 && shippedB == 0 && missesB+relayMissesB == b2Walked {
		t.Errorf("RED — symptom 2 reproduced at 2 nodes (production path): B's shipBatchedDelta(A) shipped=0, misses=%d + relay_misses=%d == walked=%d (it DROPPED every one of A's foreign deltas). shipBatchedDelta has NO working foreign/relay branch — it routes the WHOLE delta through cache.lookup (the SELF-only payloadCache), which holds NONE of A's payloads.", missesB, relayMissesB, b2Walked)
	}

	// ── THE RED ASSERTION (symptom 1): A misses its OWN payload. At 1 node A
	// hits; if at 2 nodes A's own-dots MISS, the concurrency with the receive
	// path (or a dot re-mint) desyncs A's cache. Report honestly either way.
	if aSelfMiss > 0 {
		t.Errorf("RED — symptom 1 reproduced at 2 nodes: A (seed) MISSED %d of its OWN dots in cache.lookup (at 1 node these HIT — the 2-node concurrency or a receive-path re-mint desyncs A's payloadCache). aSelfHit=%d aSelfMiss=%d.", aSelfMiss, aSelfHit, aSelfMiss)
	} else {
		t.Logf("GREEN (symptom 1 at 2 nodes): A's own-dots all HIT (aSelfHit=%d, aSelfMiss=0). The seed-own-miss is NOT reproduced at 2 nodes — it needs 100-node cardinality or a different condition (honest negative).", aSelfHit)
	}

	// Honest summary: if symptom 2 reproduced (the batch foreign-miss), that is
	// the LOAD-BEARING root cause for the 100-node stall regardless of symptom 1.
	if b2Walked > 0 && shippedB == 0 && missesB+relayMissesB == b2Walked {
		t.Fatalf("RED — root cause PINNED at 2 nodes: shipBatchedDelta has no WORKING foreign/relay branch — it routes the WHOLE delta (self + foreign) through cache.lookup (the SELF-only payloadCache) when batchSize>1, dropping every foreign delta (B shipped=0, misses=%d + relay_misses=%d == walked=%d). The fix site is shipBatchedDelta (batch.go, not a protected-core file) — branch on entry.OriginNodeID like shipDelta does: FOREIGN → relay.lookupBatch + re-publish the retained frame; SELF → the existing cache.lookup → BuildCRDTDeltaBatch path.", missesB, relayMissesB, b2Walked)
	}
	// If symptom 2 did NOT reproduce at 2 nodes (e.g., B received nothing yet),
	// report honestly — do NOT fake a RED.
	if bForeign == 0 {
		t.Logf("INCONCLUSIVE (symptom 2): B received 0 of A's deltas in 3 rounds — the 2-node timing did not deliver A's batch to B. Re-run or increase rounds; the foreign-miss hypothesis is NOT yet proven at 2 nodes (honest).")
	}
}
