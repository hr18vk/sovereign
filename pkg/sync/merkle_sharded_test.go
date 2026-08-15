package sync

// Day 37 (ADR-0042) teeth for MerkleRootFromShards (pkg/sync/merkle_sharded.go).
// Same-package (package sync) so the tests reach the UNEXPORTED fields the
// production method + the no-arena-growth tooth rely on:
//   - e.shards []shardRoot (crdt.go:160) — the sharded root HAMTs the method iterates
//   - e.arena.bumpOffset (hamt_arena.go:235) — the arena high-water mark the
//     no-growth tooth reads to PROVE MerkleRootFromShards does not move it
// (the external package mesh_test CANNOT reach these — it imports pkg/sync as
// engsync, the exported surface only).
//
// These teeth are FALSIFIABLE + bug-inject-PROVEN (NOT tautologies):
//   T-SHARDED-ROOT-BYTE-IDENTITY  — the root equals State().MerkleRoot() byte-
//     for-byte; a RED control with a broken sort (by shard index) DIVERGES, so
//     the comparator is load-bearing. A fuzz variant runs 10K seeded keys.
//   T-SHARDED-ROOT-NO-ARENA-GROWTH — the OOM gate: State() grows bumpOffset as
//     merged views pile up; MerkleRootFromShards is FLAT. A RED control that
//     calls State() internally grows → FAILS.
//
// The probe (merkle_sharded_probe_test.go) was the verify-before-claim scaffold
// for approach (i); it is DELETED now that this file + the production method
// land (the byte-identity assertion here is the load-bearing empirical check,
// against the REAL MerkleRootFromShards, not an inline probe).

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

// insertForeignDots joins a CRDTDelta whose entries carry DISTINCT foreign
// DotNodeIDs (NOT the local node's) — simulating a converged mesh where many
// nodes contributed entries. This is the load-bearing setup the byte-identity
// teeth NEED: InsertLocal mints only the LOCAL node's dot, so an all-InsertLocal
// engine has ONE DotNodeID across all entries → the nodeID sort dimension is
// NEVER exercised (a broken nodeID sort would pass IDENTICALLY → a TAUTOLOGY,
// the defect a prior draft of these teeth shipped). foreignNodeIDs is the set
// of distinct node IDs the entries' dots come from; the entries are spread
// across `nKeys` distinct entityIDs, each dotted from a rotating foreign node.
// The Join path is the production apply path (crdt.go:1089) — it does NOT
// overwrite DotNodeID (unlike InsertLocal), so the foreign dots land verbatim.
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

// TestShardedRootByteIdentity is the load-bearing empirical check for approach
// (i): MerkleRootFromShards() == State().MerkleRoot() BYTE-FOR-BYTE on a seeded
// engine with keys across >1 shard whose dots come from DISTINCT foreign nodes
// (so the nodeID sort dimension is EXERCISED — a broken nodeID sort DIVERGES,
// NOT a tautology). It runs against the REAL production method (merkle_sharded.go),
// not an inline probe — so it catches any drift between the method and
// State().MerkleRoot(). Both 1-entry/entityID AND multi-entry/entityID.
func TestShardedRootByteIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("Day 37 byte-identity tooth inserts 100 keys across shards; skip in -short")
	}
	var localNode [16]byte
	for i := range localNode {
		localNode[i] = byte(i + 1)
	}
	e := newShardedTestEngine(t, localNode, 128*1024*1024)

	// 7 distinct foreign node IDs (the nodeID sort has >1 value to order — a
	// broken sort DIVERGES, NOT a tautology). 100 keys rotate across the 7 nodes.
	foreign := make([][16]byte, 7)
	for i := range foreign {
		foreign[i][0] = byte(0xA0 + i)
		foreign[i][15] = byte(0xB0 + i)
	}
	insertForeignDots(t, e, foreign, 100)
	// Advance epochs so retired roots from the Join are reclaim candidates —
	// exercising the "iterate the CURRENT root under the EBR pin" path the
	// production method relies on.
	for i := 0; i < 256; i++ {
		e.maybeAdvanceEpoch()
	}

	want := e.State().MerkleRoot()
	got := e.MerkleRootFromShards()
	if want != got {
		t.Fatalf("BYTE-IDENTITY BROKEN (distinct foreign dots, 100 keys):\n"+
			"  State().MerkleRoot()   = %x\n"+
			"  MerkleRootFromShards() = %x\n"+
			"approach (i) is NOT byte-identical — the sharded-direct path diverges from State().",
			want, got)
	}
	// NodeID-diversity guard: the multiset MUST have >1 distinct DotNodeID, else
	// the nodeID sort is unexercised (the prior-draft tautology). Count distinct
	// nodeIDs across the shards + assert >1.
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
		t.Fatalf("BYTE-IDENTITY VACUOUS (nodeID dimension): only %d distinct DotNodeID across the live set — the nodeID sort is UNEXERCISED (a broken nodeID sort would pass IDENTICALLY → a tautology). Need >=2 distinct nodeIDs.", len(distinct))
	}
	t.Logf("BYTE-IDENTITY CONFIRMED (distinct foreign dots, 100 keys, %d shards, %d distinct nodeIDs): %x", len(e.shards), len(distinct), want)

	// Multi-entry-per-entityID: add 5 more dots to ONE entityID from 5 DIFFERENT
	// foreign nodes so that key carries >1 entry with distinct nodeIDs (exercises
	// per-ENTRY pair collection + the nodeID tie-break WITHIN an entityID).
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
		t.Fatalf("BYTE-IDENTITY BROKEN (multi-entry/entityID, distinct nodeIDs):\n  State=%x\n  sharded=%x", want2, got2)
	}
	t.Logf("BYTE-IDENTITY CONFIRMED (multi-entry/entityID, 5 distinct nodeIDs on one key): %x", want2)
}

// TestShardedRootByteIdentityFuzz is the fuzz-stress variant: 10K seeded keys
// whose dots come from 32 DISTINCT foreign nodes (the nodeID sort has 32 values
// to order — a broken sort DIVERGES at scale, NOT a tautology). Asserts
// MerkleRootFromShards == State().MerkleRoot on the full 10K live set (the
// silicon gate's population). This is the population-scale byte-identity check.
func TestShardedRootByteIdentityFuzz(t *testing.T) {
	if testing.Short() {
		t.Skip("Day 37 fuzz byte-identity tooth inserts 10K keys; skip in -short")
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
		t.Fatalf("BYTE-IDENTITY BROKEN (fuzz, %d keys, %d foreign nodes):\n  State=%x\n  sharded=%x", 10000, nForeign, want, got)
	}
	// Non-empty guard: an all-empty multiset trivially matches; assert the root
	// is NOT the zero root (the 10K keys landed).
	var zero [32]byte
	if want == zero {
		t.Fatalf("BYTE-IDENTITY VACUOUS: the %d-key root is the zero root — the keys never landed", 10000)
	}
	// NodeID-diversity guard at scale: assert >=2 distinct DotNodeIDs (the 32
	// foreign nodes all landed).
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
		t.Fatalf("BYTE-IDENTITY VACUOUS (fuzz): only %d distinct DotNodeID — the nodeID sort is UNEXERCISED at scale (tautology).", len(distinct))
	}
	t.Logf("BYTE-IDENTITY CONFIRMED (fuzz, %d keys, %d distinct nodeIDs): %x", 10000, len(distinct), want)
}

// TestShardedRootByteIdentityRedControl is the bug-inject RED control: it
// replicates MerkleRootFromShards' collection BUT with a BROKEN sort (by shard
// index, NOT by DotNodeID bytes). The broken sort MUST produce a root that
// DIVERGES from State().MerkleRoot() (on a multiset where the global order
// differs from the per-shard order — which REQUIRES distinct DotNodeIDs across
// shards, else the nodeID sort is unexercised + the RED control is vacuous). If
// the RED control ever EQUALS State(), the tooth is a TAUTOLOGY (the sort is not
// load-bearing) — the failure proves the global comparator is the load-bearing
// part of approach (i).
func TestShardedRootByteIdentityRedControl(t *testing.T) {
	if testing.Short() {
		t.Skip("Day 37 RED control tooth inserts 100 keys across shards; skip in -short")
	}
	var localNode [16]byte
	for i := range localNode {
		localNode[i] = byte(i + 7)
	}
	e := newShardedTestEngine(t, localNode, 128*1024*1024)
	// DISTINCT foreign dots — REQUIRED so the nodeID/shard-index sort difference
	// is EXERCISED (without distinct nodeIDs the RED control is vacuous: a
	// shard-index sort + a nodeID sort produce the SAME hash when all nodeIDs are
	// identical, so the RED control would EQUAL State() → a tautology).
	foreign := make([][16]byte, 7)
	for i := range foreign {
		foreign[i][0] = byte(0xD0 + i)
		foreign[i][15] = byte(0xE0 + i)
	}
	insertForeignDots(t, e, foreign, 100)

	want := e.State().MerkleRoot()

	// BUG-INJECT: collect pairs tagged with their SHARD INDEX, then sort by
	// (shardIndex ASC, counter ASC) — NOT the (nodeID ASC, counter ASC) the
	// production method + HAMT.MerkleRoot use. This is the deliberate defect.
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
	// The BROKEN comparator: shard index first, then counter. The production
	// comparator is (nodeID bytes ASC, counter ASC). These differ whenever two
	// entries from different shards have nodeIDs out-of-shard-index-order —
	// which is the common case (routeShard hashes nodeID, so shard index is NOT
	// monotonic in nodeID bytes).
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].shardIdx != pairs[j].shardIdx {
			return pairs[i].shardIdx < pairs[j].shardIdx
		}
		return pairs[i].counter < pairs[j].counter
	})

	// Hash with the SAME 24-byte big-endian layout as the production method
	// (only the SORT differs — isolating the sort as the load-bearing part).
	var buf [24]byte
	var broken [32]byte
	if len(pairs) == 0 {
		// Degenerate — skip the vacuous-equality assertion below.
		t.Skip("RED control: empty multiset (no keys landed) — vacuous, skip")
	}
	h256 := sha256.New()
	for _, p := range pairs {
		copy(buf[:16], p.nodeID[:])
		binary.BigEndian.PutUint64(buf[16:24], p.counter)
		h256.Write(buf[:])
	}
	copy(broken[:], h256.Sum(nil))

	if broken == want {
		t.Fatalf("RED CONTROL FAILED: the broken (shard-index) sort produced the SAME root as State().MerkleRoot()=%x\n"+
			"the tooth is a TAUTOLOGY — the global (nodeID,counter) sort is NOT load-bearing. approach (i) is unproven.",
			want)
	}
	t.Logf("RED CONTROL PASS: the broken shard-index sort DIVERGES from State().MerkleRoot()=%x\n"+
		"  broken (shard-index sort) = %x\n"+
		"  → the global (nodeID,counter) sort IS load-bearing; the byte-identity tooth is NOT a tautology.",
		want, broken)
}

// TestShardedRootNoArenaGrowth is the OOM gate (Day-36 root cause A): State()
// builds a fresh merged *HAMT duplicating every live entry into arena nodes,
// which reclaim only on EBR epoch advance (every 64 ops via maybeAdvanceEpoch).
// Calling State() in a tight loop grows the arena high-water mark (bumpOffset)
// as merged views pile up faster than epoch advance reclaims them — at 100×10K
// that is the hamt_arena.go:638 OOM. MerkleRootFromShards reads the shard roots
// directly (NO merged view) so bumpOffset is FLAT across the same loop. This
// tooth PROVES it byte-level: bumpOffset after N MerkleRootFromShards() calls
// is FLAT; after N State() calls it GROWS. The contrast (sharded-flat vs
// State-grows) is the load-bearing signal — the OOM at silicon scale is its
// consequence (observed separately in TestShardedRootStateOOMObserved).
//
// The arena is 256 MiB (the same the 8-node 10K loopback tooth uses,
// day36Join10KArenaSize) so the State() loop's merged views FIT for measurement
// — the GROWTH is asserted, NOT the OOM (the OOM is a separate guarded tooth).
// RED control: TestShardedRootNoArenaGrowthRedControl — a wrapper that calls
// State() internally (the defect class the fix retires) grows bumpOffset → the
// flat assertion catches it (NOT a tautology).
func TestShardedRootNoArenaGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("Day 37 no-arena-growth tooth inserts 10K keys + runs a root-compute loop; skip in -short")
	}
	var nodeID [16]byte
	nodeID[0] = 0x42
	// 256 MiB so the State() loop's merged views FIT for growth measurement
	// (NOT the OOM — that is TestShardedRootStateOOMObserved).
	e := newShardedTestEngine(t, nodeID, 256*1024*1024)

	const nKeys = 10000
	for i := 0; i < nKeys; i++ {
		var entry CRDTEntry
		binary.BigEndian.PutUint32(entry.PayloadDigest[:4], uint32(i))
		e.InsertLocal(shardKeyForIndex(i), entry)
	}

	// The arena high-water mark (bytes) — the same-package field the no-growth
	// claim is measured against. bumpOffset is monotonic-non-decreasing under
	// bump-allocate; the freelist can REUSE freed offsets but does NOT lower the
	// high-water mark (the watermark only advances). So a path that bump-
	// allocates new arena nodes (State's merged view) ADVANCES bumpOffset; a path
	// that reads EXISTING nodes (MerkleRootFromShards) does NOT.
	bumpBefore := e.arena.bumpOffset.Load()

	// ── MerkleRootFromShards path: the fix. ──
	// Run the root compute in a loop. The high-water mark MUST stay flat (the
	// method reads shard roots, collects dot pairs into a Go-heap slice, sorts +
	// hashes — ZERO arena bump-allocate).
	const shardedIters = 200
	for i := 0; i < shardedIters; i++ {
		_ = e.MerkleRootFromShards()
	}
	bumpAfterSharded := e.arena.bumpOffset.Load()
	if bumpAfterSharded != bumpBefore {
		t.Fatalf("NO-ARENA-GROWTH BROKEN (sharded path): bumpOffset MOVED across %d MerkleRootFromShards() calls\n"+
			"  before=%d after=%d (delta=%d)\n"+
			"the sharded-direct path is bump-allocating arena nodes — the OOM root cause is NOT closed.",
			shardedIters, bumpBefore, bumpAfterSharded, bumpAfterSharded-bumpBefore)
	}
	t.Logf("NO-ARENA-GROWTH PASS (sharded): bumpOffset FLAT across %d MerkleRootFromShards() calls (before=%d after=%d)",
		shardedIters, bumpBefore, bumpAfterSharded)

	// ── State() path: the defect. ──
	// State() builds a merged view (arena bump-allocate) + retires the prior
	// view via EBR. A tight loop grows bumpOffset (merged views pile up inside
	// the grace window faster than maybeAdvanceEpoch reclaims). The OOM at
	// silicon 100×10K is the UNBOUNDED-growth consequence; at this in-vitro scale
	// the same loop OOMs a 256 MiB arena if run long enough (the pile-up is
	// unbounded within the grace window). So the loop is RECOVERED: if it OOMs,
	// the OOM IS the proof State() bumps (unbounded growth = the defect); if it
	// completes, the growth is the proof. Either outcome PASSes (State() is the
	// bump-allocating path); the load-bearing contrast is sharded-FLAT vs
	// State-GROWS-or-OOMs.
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
		t.Fatalf("RED SIGNAL MISSING (State path): bumpOffset did NOT grow across the State() loop\n"+
			"  sharded-after=%d state-after=%d (oom=%v)\n"+
			"expected State() (the defect) to ADVANCE bumpOffset — if it does not, the no-growth tooth's\n"+
			"  contrast (sharded flat vs State grows) is vacuous.",
			bumpAfterSharded, bumpAfterState, stateOOM)
	}
	if stateOOM {
		t.Logf("RED SIGNAL PASS (State, OOM): the State() loop OOM'd after bumpOffset grew to %d (sharded-flat=%d, delta=%d) — State() IS the bump-allocating path; the OOM is the unbounded-growth consequence (the silicon 100×10K root cause reproduced in-vitro).",
			bumpAfterState, bumpAfterSharded, bumpAfterState-bumpAfterSharded)
	} else {
		t.Logf("RED SIGNAL PASS (State, grew): bumpOffset GREW across %d State().MerkleRoot() calls (sharded-after=%d state-after=%d, delta=%d) — State() IS the bump-allocating path; the contrast is load-bearing.",
			stateIters, bumpAfterSharded, bumpAfterState, bumpAfterState-bumpAfterSharded)
	}
}

// TestShardedRootStateOOMObserved is the silicon-scale consequence tooth: under
// a TIGHT arena (16 MiB) the SAME State() loop that the no-growth tooth runs
// against a 256 MiB arena OOMs (hamt_arena.go:638 "arena exhausted (variable
// alloc)"). This is the Day-36 GATE 1 root cause (A) asserting itself in-vitro.
// The panic is RECOVERED (defer recover) so the tooth REPORTS the OOM as a PASS
// (the OOM IS the proof State() is the bump-allocating defect) instead of
// crashing the test binary. MerkleRootFromShards does NOT OOM on the same
// tight arena (the flat-path assertion in the no-growth tooth already proves it
// byte-level; this tooth adds the OOM-as-consequence observation).
func TestShardedRootStateOOMObserved(t *testing.T) {
	if testing.Short() {
		t.Skip("Day 37 State-OOM-observed tooth runs a tight-arena State() loop; skip in -short")
	}
	var nodeID [16]byte
	nodeID[0] = 0x77
	// 16 MiB — tight enough that a State() loop's merged-view pile-up exhausts
	// it (the silicon 100×10K consequence reproduced in-vitro at smaller scale).
	e := newShardedTestEngine(t, nodeID, 16*1024*1024)
	const nKeys = 10000
	for i := 0; i < nKeys; i++ {
		var entry CRDTEntry
		binary.BigEndian.PutUint32(entry.PayloadDigest[:4], uint32(i))
		e.InsertLocal(shardKeyForIndex(i), entry)
	}

	// The State() loop is EXPECTED to OOM. Recover the panic + assert it is the
	// arena-exhaust panic (the exact Day-36 root-cause string). A non-OOM panic
	// (or NO panic) is a FAIL — the tooth would otherwise be vacuous.
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
		t.Fatalf("State-OOM-OBSERVED FAIL: the tight-arena (16 MiB) State() loop did NOT OOM with the\n"+
			"  'arena exhausted' panic within 1000 iters (msg=%q).\n"+
			"expected the Day-36 root cause (A) to assert itself in-vitro — if it does not, the OOM\n"+
			"  is NOT reproduced at this scale + the tooth's premise is stale (re-check the arena size).",
			oomMsg)
	}
	t.Logf("State-OOM-OBSERVED PASS: the tight-arena State() loop OOM'd with %q — the Day-36 root cause (A)\n"+
		"  reproduced in-vitro; State() IS the bump-allocating defect (MerkleRootFromShards does NOT OOM —\n  see TestShardedRootNoArenaGrowth).", oomMsg)
}

// TestShardedRootNoArenaGrowthRedControl is the bug-inject RED control for the
// no-growth tooth: a root-compute path that calls State() internally (the exact
// defect class the fix retires) MUST grow bumpOffset → the tooth catches it. It
// proves the tooth is NOT a tautology (a path that secretly builds the merged
// view is detected).
func TestShardedRootNoArenaGrowthRedControl(t *testing.T) {
	if testing.Short() {
		t.Skip("Day 37 no-growth RED control; skip in -short")
	}
	var nodeID [16]byte
	nodeID[0] = 0x99
	e := newShardedTestEngine(t, nodeID, 16*1024*1024)
	for i := 0; i < 5000; i++ {
		var entry CRDTEntry
		binary.BigEndian.PutUint32(entry.PayloadDigest[:4], uint32(i))
		e.InsertLocal(shardKeyForIndex(i), entry)
	}

	// BUG-INJECT: a "sharded" wrapper that secretly calls State() internally —
	// the defect class. A correct MerkleRootFromShards is flat; this broken one
	// grows. The tooth asserts the broken one is CAUGHT (grows), proving the
	// flat assertion in the main tooth is load-bearing, not vacuous.
	brokenShardedThatCallsState := func() [32]byte {
		return e.State().MerkleRoot() // the defect: builds the merged view
	}

	bumpBefore := e.arena.bumpOffset.Load()
	// The defect wrapper OOMs a tight arena (the SAME root cause the main tooth
	// reproduces). Recover so the OOM is REPORTED as the proof the wrapper grows
	// (NOT a crash); if the loop completes, the growth is the proof.
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
		t.Fatalf("RED CONTROL FAILED: the State()-calling 'sharded' wrapper did NOT grow bumpOffset\n"+
			"  before=%d after=%d (oomed=%v)\n"+
			"the no-growth tooth's flat assertion is VACUOUS — it would not catch a State()-calling wrapper.",
			bumpBefore, bumpAfter, oomed)
	}
	if oomed {
		t.Logf("RED CONTROL PASS (OOM): the State()-calling 'sharded' wrapper OOM'd after bumpOffset grew to %d (before=%d, delta=%d) — the flat assertion catches the defect class (growth → OOM).",
			bumpAfter, bumpBefore, bumpAfter-bumpBefore)
	} else {
		t.Logf("RED CONTROL PASS: the State()-calling 'sharded' wrapper GREW bumpOffset (before=%d after=%d, delta=%d) — the flat assertion catches the defect class.",
			bumpBefore, bumpAfter, bumpAfter-bumpBefore)
	}
}
