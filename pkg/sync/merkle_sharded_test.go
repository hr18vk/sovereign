// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// These same-package tests compare MerkleRootFromShards with
// State().MerkleRoot and inspect the arena high-water mark directly.
//
// Foreign node IDs exercise both dimensions of the global dot ordering. A
// control that sorts by shard index must produce a different root, while the
// production method must match State for single- and multi-dot entities and
// for a 10,000-key set. Separate tests contrast the sharded method's constant
// arena high-water mark with growth from repeated State calls, including arena
// exhaustion in a small arena.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// shardKeyForIndex is a deterministic, distinct entityID that spreads across the
// 256 shards (routeShard = hash & 255). Distinct keys → distinct entityIDs →
// the keys land in many different shards (so byte-identity is exercised across
// shard boundaries, not within one shard).
func shardKeyForIndex(i int) string {
	b := []byte("shard-key-")
	b = append(b, byte('0'+(i/10000)%10))
	b = append(b, byte('0'+(i/1000)%10))
	b = append(b, byte('0'+(i/100)%10))
	b = append(b, byte('0'+(i/10)%10))
	b = append(b, byte('0'+i%10))
	return string(b)
}

// newShardedTestEngine builds a same-package engine on a private temp DataDir
// with the given arena size. The caller defers e.Close().
func newShardedTestEngine(t *testing.T, nodeID [16]byte, arenaSize uintptr) *DeltaCRDTEngine {
	t.Helper()
	DataDir = t.TempDir()
	e, err := NewDeltaCRDTEngine(nodeID, 1, arenaSize)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// insertForeignDots distributes nKeys entities among dots from foreignNodeIDs.
// Join preserves those node IDs, unlike InsertLocal, which always mints a local
// dot. Distinct node IDs and counters exercise both fields of the root
// comparator; using only local dots would leave node-ID ordering untested.
func insertForeignDots(t *testing.T, e *DeltaCRDTEngine, foreignNodeIDs [][16]byte, nKeys int) {
	t.Helper()
	entries := make([]seqEntry, 0, nKeys)
	for i := 0; i < nKeys; i++ {
		node := foreignNodeIDs[i%len(foreignNodeIDs)]
		var entry CRDTEntry
		binary.BigEndian.PutUint32(entry.PayloadDigest[:4], uint32(i))
		entry.DotNodeID = node
		entry.DotCounter = uint64(i + 1) // distinct counters per node (the counter-ASC tie-break)
		entry.OriginNodeID = node
		entry.SystemTime = int64(i)
		entries = append(entries, seqEntry{entityID: shardKeyForIndex(i), entry: entry})
	}
	e.Join(CRDTDelta{OriginNodeID: foreignNodeIDs[0], Entries: makeSeq(entries)})
}

// TestShardedRootByteIdentity compares roots across 100 entities whose dots
// come from seven foreign nodes. It then adds five dots from different nodes to
// one entity and repeats the comparison, covering multiple entries per entity.
func TestShardedRootByteIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("byte-identity guard inserts 100 keys across shards; skip in -short")
	}
	var localNode [16]byte
	for i := range localNode {
		localNode[i] = byte(i + 1)
	}
	e := newShardedTestEngine(t, localNode, 128*1024*1024)

	// Seven foreign node IDs ensure the comparator orders multiple node values;
	// 100 keys rotate across them.
	foreign := make([][16]byte, 7)
	for i := range foreign {
		foreign[i][0] = byte(0xA0 + i)
		foreign[i][15] = byte(0xB0 + i)
	}
	insertForeignDots(t, e, foreign, 100)
	// Advance epochs so retired roots from the Join are reclaim candidates —
	// exercising the "iterate the current root under the EBR pin" path the
	// production method relies on.
	for i := 0; i < 256; i++ {
		e.maybeAdvanceEpoch()
	}

	want := e.State().MerkleRoot()
	got := e.MerkleRootFromShards()
	if want != got {
		t.Fatalf("roots differ for 100 keys with distinct foreign dots:\n"+
			"  State().MerkleRoot()   = %x\n"+
			"  MerkleRootFromShards() = %x\n"+
			"Both paths must hash the same live dot set.",
			want, got)
	}
	// Count distinct node IDs to prove that node-ID ordering is exercised.
	distinct := make(map[[16]byte]struct{})
	for si := range e.shards {
		shardRoot := e.shards[si].ptr.Load()
		if shardRoot == nil {
			continue
		}
		shardRoot.ForEach(func(_ string, entries []CRDTEntry) bool {
			for i := range entries {
				distinct[entries[i].DotNodeID] = struct{}{}
			}
			return true
		})
	}
	if len(distinct) < 2 {
		t.Fatalf("found %d distinct DotNodeID values; at least 2 are required to exercise node-ID ordering", len(distinct))
	}
	t.Logf("byte-identity confirmed (distinct foreign dots, 100 keys, %d shards, %d distinct nodeIDs): %x", len(e.shards), len(distinct), want)

	// Multi-entry-per-entityID: add 5 more dots to one entityID from 5 different
	// foreign nodes so that key carries more than one entry with distinct nodeIDs (exercises
	// per-entry pair collection and the nodeID tie-break within an entityID).
	multiForeign := make([][16]byte, 5)
	for i := range multiForeign {
		multiForeign[i][0] = byte(0xC0 + i)
	}
	multiEntries := make([]seqEntry, 0, 5)
	for i := 0; i < 5; i++ {
		var entry CRDTEntry
		entry.PayloadDigest[0] = byte(200 + i)
		entry.DotNodeID = multiForeign[i]
		entry.DotCounter = uint64(500 + i)
		entry.OriginNodeID = multiForeign[i]
		entry.SystemTime = int64(200 + i)
		multiEntries = append(multiEntries, seqEntry{entityID: shardKeyForIndex(0), entry: entry})
	}
	e.Join(CRDTDelta{OriginNodeID: multiForeign[0], Entries: makeSeq(multiEntries)})
	want2 := e.State().MerkleRoot()
	got2 := e.MerkleRootFromShards()
	if want2 != got2 {
		t.Fatalf("byte-identity broken (multi-entry/entityID, distinct nodeIDs):\n  State=%x\n  sharded=%x", want2, got2)
	}
	t.Logf("byte-identity confirmed (multi-entry/entityID, 5 distinct nodeIDs on one key): %x", want2)
}

// TestShardedRootByteIdentityFuzz compares roots for 10,000 entities with dots
// from 32 foreign nodes. It also rejects a zero root and requires multiple node
// IDs so an empty or one-dimensional data set cannot satisfy the comparison.
func TestShardedRootByteIdentityFuzz(t *testing.T) {
	if testing.Short() {
		t.Skip("fuzz byte-identity guard inserts 10K keys; skip in -short")
	}
	var localNode [16]byte
	localNode[0] = 0xee
	e := newShardedTestEngine(t, localNode, 256*1024*1024)

	// 32 distinct foreign node IDs — the nodeID sort is exercised at 10K scale.
	const nForeign = 32
	foreign := make([][16]byte, nForeign)
	for i := range foreign {
		binary.BigEndian.PutUint16(foreign[i][:2], uint16(0xF000+i))
	}
	insertForeignDots(t, e, foreign, 10000)

	want := e.State().MerkleRoot()
	got := e.MerkleRootFromShards()
	if want != got {
		t.Fatalf("byte-identity broken (fuzz, %d keys, %d foreign nodes):\n  State=%x\n  sharded=%x", 10000, nForeign, want, got)
	}
	// Reject an empty data set, whose zero root would match trivially.
	var zero [32]byte
	if want == zero {
		t.Fatalf("the %d-key root is zero; the seeded entries are missing", 10000)
	}
	// Confirm that the data also exercises multiple node IDs.
	distinct := make(map[[16]byte]struct{})
	for si := range e.shards {
		shardRoot := e.shards[si].ptr.Load()
		if shardRoot == nil {
			continue
		}
		shardRoot.ForEach(func(_ string, entries []CRDTEntry) bool {
			for i := range entries {
				distinct[entries[i].DotNodeID] = struct{}{}
			}
			return true
		})
	}
	if len(distinct) < 2 {
		t.Fatalf("10,000-key set has %d distinct DotNodeID values; at least 2 are required to exercise ordering", len(distinct))
	}
	t.Logf("byte-identity confirmed (fuzz, %d keys, %d distinct nodeIDs): %x", 10000, len(distinct), want)
}

// TestShardedRootByteIdentityRedControl collects the same dot pairs but sorts
// them by shard index and counter. Distinct foreign node IDs make this ordering
// differ from the production comparator, so the resulting root must differ from
// State().MerkleRoot. Equality would show that the byte-identity test does not
// exercise global ordering.
func TestShardedRootByteIdentityRedControl(t *testing.T) {
	if testing.Short() {
		t.Skip("negative control guard inserts 100 keys across shards; skip in -short")
	}
	var localNode [16]byte
	for i := range localNode {
		localNode[i] = byte(i + 7)
	}
	e := newShardedTestEngine(t, localNode, 128*1024*1024)
	// Distinct foreign dots are required: with one node ID, shard-index and
	// node-ID ordering could produce the same sequence and weaken the control.
	foreign := make([][16]byte, 7)
	for i := range foreign {
		foreign[i][0] = byte(0xD0 + i)
		foreign[i][15] = byte(0xE0 + i)
	}
	insertForeignDots(t, e, foreign, 100)

	want := e.State().MerkleRoot()

	// Tag pairs with their shard index so the control can use a different global
	// ordering from the production (nodeID, counter) comparator.
	type brokenPair struct {
		shardIdx int
		nodeID   [16]byte
		counter  uint64
	}
	var pairs []brokenPair
	for si := range e.shards {
		shardRoot := e.shards[si].ptr.Load()
		if shardRoot == nil {
			continue
		}
		shardRoot.ForEach(func(_ string, entries []CRDTEntry) bool {
			for i := range entries {
				pairs = append(pairs, brokenPair{
					shardIdx: si,
					nodeID:   entries[i].DotNodeID,
					counter:  entries[i].DotCounter,
				})
			}
			return true
		})
	}
	// Sort by shard index and then counter. The production comparator uses node
	// ID bytes and then counter; hashed entity placement makes those orders
	// differ for this data set.
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].shardIdx != pairs[j].shardIdx {
			return pairs[i].shardIdx < pairs[j].shardIdx
		}
		return pairs[i].counter < pairs[j].counter
	})

	// Use the production 24-byte encoding so only the ordering differs.
	var buf [24]byte
	var broken [32]byte
	if len(pairs) == 0 {
		// An empty data set cannot distinguish the two orderings.
		t.Skip("negative control has no entries; cannot compare root orderings")
	}
	h256 := sha256.New()
	for _, p := range pairs {
		copy(buf[:16], p.nodeID[:])
		binary.BigEndian.PutUint64(buf[16:24], p.counter)
		h256.Write(buf[:])
	}
	copy(broken[:], h256.Sum(nil))

	if broken == want {
		t.Fatalf("shard-index sort produced the State() root %x\n"+
			"The control did not exercise global node-ID ordering.",
			want)
	}
	t.Logf("shard-index sort diverged from State().MerkleRoot()=%x\n"+
		"  control root = %x\n"+
		"  Global node-ID ordering affects the root as required.",
		want, broken)
}

// TestShardedRootNoArenaGrowth compares 200 root computations through each read
// path. MerkleRootFromShards must leave bumpOffset unchanged. State may either
// grow it or exhaust the arena, and either outcome demonstrates allocation by
// the merged-view path. A non-arena panic is rethrown.
//
// The 256 MiB arena provides room to measure growth at this scale.
// TestShardedRootStateOOMObserved separately checks exhaustion with a 16 MiB
// arena, and TestShardedRootNoArenaGrowthRedControl injects State into a
// sharded wrapper to confirm that the high-water comparison detects it.
func TestShardedRootNoArenaGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("no-arena-growth guard inserts 10K keys + runs a root-compute loop; skip in -short")
	}
	var nodeID [16]byte
	nodeID[0] = 0x42
	// 256 MiB so the State() loop's merged views fit for growth measurement
	// (not the OOM — that is TestShardedRootStateOOMObserved).
	e := newShardedTestEngine(t, nodeID, 256*1024*1024)

	const nKeys = 10000
	for i := 0; i < nKeys; i++ {
		var entry CRDTEntry
		binary.BigEndian.PutUint32(entry.PayloadDigest[:4], uint32(i))
		e.InsertLocal(shardKeyForIndex(i), entry)
	}

	// The arena high-water mark (bytes) — the same-package field the no-growth
	// claim is measured against. bumpOffset is monotonic-non-decreasing under
	// bump-allocate; the freelist can reuse freed offsets but does not lower the
	// high-water mark (the watermark only advances). So a path that bump-
	// allocates new arena nodes (State's merged view) advances bumpOffset; a path
	// that reads existing nodes (MerkleRootFromShards) does not.
	bumpBefore := e.arena.bumpOffset.Load()

	// The sharded method reads roots and allocates only its Go-heap pair slice.
	const shardedIters = 200
	for i := 0; i < shardedIters; i++ {
		_ = e.MerkleRootFromShards()
	}
	bumpAfterSharded := e.arena.bumpOffset.Load()
	if bumpAfterSharded != bumpBefore {
		t.Fatalf("MerkleRootFromShards moved bumpOffset across %d calls\n"+
			"  before=%d after=%d (delta=%d)\n"+
			"The method must not allocate arena nodes.",
			shardedIters, bumpBefore, bumpAfterSharded, bumpAfterSharded-bumpBefore)
	}
	t.Logf("MerkleRootFromShards left bumpOffset flat across %d calls (before=%d after=%d)",
		shardedIters, bumpBefore, bumpAfterSharded)

	// State builds merged views and retires earlier views through EBR. Its loop
	// must either advance bumpOffset or exhaust the arena; recover only the
	// expected arena-exhaustion panic so either outcome can be measured.
	const stateIters = 200
	var bumpAfterState uint64
	stateOOM := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				if strings.Contains(fmt.Sprintf("%v", r), "arena exhausted") {
					stateOOM = true
					bumpAfterState = e.arena.bumpOffset.Load()
					return
				}
				panic(r) // a non-arena panic is a real bug — re-panic.
			}
		}()
		for i := 0; i < stateIters; i++ {
			_ = e.State().MerkleRoot()
		}
		bumpAfterState = e.arena.bumpOffset.Load()
	}()
	if bumpAfterState <= bumpAfterSharded {
		t.Fatalf("State() did not increase arena use\n"+
			"  sharded-after=%d state-after=%d (oom=%v)\n"+
			"The merged-view path must advance bumpOffset or exhaust the arena;\n"+
			"  otherwise the allocation comparison is not exercised.",
			bumpAfterSharded, bumpAfterState, stateOOM)
	}
	if stateOOM {
		t.Logf("State() exhausted the arena after bumpOffset grew to %d (sharded=%d, delta=%d)",
			bumpAfterState, bumpAfterSharded, bumpAfterState-bumpAfterSharded)
	} else {
		t.Logf("State() grew bumpOffset across %d calls (sharded=%d state=%d, delta=%d)",
			stateIters, bumpAfterSharded, bumpAfterState, bumpAfterState-bumpAfterSharded)
	}
}

// TestShardedRootStateOOMObserved requires repeated State root computations to
// exhaust a 16 MiB arena holding 10,000 entities. The test recovers the expected
// arena-exhaustion panic; any other panic or a completed loop fails the test.
// TestShardedRootNoArenaGrowth covers the non-allocating sharded path.
func TestShardedRootStateOOMObserved(t *testing.T) {
	if testing.Short() {
		t.Skip("State-OOM-observed guard runs a tight-arena State() loop; skip in -short")
	}
	var nodeID [16]byte
	nodeID[0] = 0x77
	// A 16 MiB arena makes merged-view growth observable as exhaustion.
	e := newShardedTestEngine(t, nodeID, 16*1024*1024)
	const nKeys = 10000
	for i := 0; i < nKeys; i++ {
		var entry CRDTEntry
		binary.BigEndian.PutUint32(entry.PayloadDigest[:4], uint32(i))
		e.InsertLocal(shardKeyForIndex(i), entry)
	}

	// Recover the expected arena-exhaustion panic. Other panics and a completed
	// loop leave oomObserved false and fail below.
	oomObserved := false
	var oomMsg string
	func() {
		defer func() {
			if r := recover(); r != nil {
				oomMsg = fmt.Sprintf("%v", r)
				if strings.Contains(oomMsg, "arena exhausted") {
					oomObserved = true
				}
			}
		}()
		for i := 0; i < 1000; i++ {
			_ = e.State().MerkleRoot()
		}
	}()
	if !oomObserved {
		t.Fatalf("State() did not exhaust the 16 MiB arena\n"+
			"  within 1000 iterations (panic=%q).\n"+
			"The merged-view allocation premise no longer holds at this scale;\n"+
			"  check the arena size and State() behavior.",
			oomMsg)
	}
	t.Logf("State() exhausted the 16 MiB arena with %q\n"+
		"  MerkleRootFromShards allocation behavior is checked separately.", oomMsg)
}

// TestShardedRootNoArenaGrowthRedControl wraps State in a sharded-root
// function. The wrapper must increase bumpOffset or exhaust the arena, showing
// that the no-growth assertion detects merged-view allocation.
func TestShardedRootNoArenaGrowthRedControl(t *testing.T) {
	if testing.Short() {
		t.Skip("no-growth negative control; skip in -short")
	}
	var nodeID [16]byte
	nodeID[0] = 0x99
	e := newShardedTestEngine(t, nodeID, 16*1024*1024)
	for i := 0; i < 5000; i++ {
		var entry CRDTEntry
		binary.BigEndian.PutUint32(entry.PayloadDigest[:4], uint32(i))
		e.InsertLocal(shardKeyForIndex(i), entry)
	}

	// Inject merged-view allocation into a function with the same signature as
	// MerkleRootFromShards.
	brokenShardedThatCallsState := func() [32]byte {
		return e.State().MerkleRoot()
	}

	bumpBefore := e.arena.bumpOffset.Load()
	// Growth or arena exhaustion both demonstrate that the wrapper allocates.
	var bumpAfter uint64
	oomed := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				if strings.Contains(fmt.Sprintf("%v", r), "arena exhausted") {
					oomed = true
					bumpAfter = e.arena.bumpOffset.Load()
					return
				}
				panic(r)
			}
		}()
		for i := 0; i < 100; i++ {
			_ = brokenShardedThatCallsState()
		}
		bumpAfter = e.arena.bumpOffset.Load()
	}()
	if bumpAfter <= bumpBefore {
		t.Fatalf("State()-calling wrapper did not increase bumpOffset\n"+
			"  before=%d after=%d (oomed=%v)\n"+
			"The no-growth assertion did not detect merged-view allocation.",
			bumpBefore, bumpAfter, oomed)
	}
	if oomed {
		t.Logf("State()-calling wrapper exhausted the arena after bumpOffset grew to %d (before=%d, delta=%d)",
			bumpAfter, bumpBefore, bumpAfter-bumpBefore)
	} else {
		t.Logf("State()-calling wrapper grew bumpOffset from %d to %d (delta=%d)",
			bumpBefore, bumpAfter, bumpAfter-bumpBefore)
	}
}
