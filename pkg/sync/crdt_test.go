package sync

import (
	"fmt"
	"hash/maphash"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type seqEntry struct {
	entityID string
	entry    CRDTEntry
}

// benchCRDTEngineArenaSize is the single shared bench-only arena size used by
// the CRDTE engine benchmarks in this file (BenchmarkCRDTEngine_GenerateDelta
// and BenchmarkCRDTEngine_Join). It is set to 2 GiB — the size Phase 2i Gate 2
// of PHASE_2I_REPORT.md proved holds the steady-state fill/reclaim equilibrium
// for BenchmarkCRDTEngine_Join's write-amplification path: at 64 MiB the Join
// loop panics with HamtArena OOM at ~1M ops (reclamation lag under
// write-amplification, NOT arena-size-alone — the sibling GenerateDelta bench
// passes at the same 64 MiB because it is read-only and does not grow the
// live-set); at 2 GiB the Join loop completes 3/3 runs at ~5.5M ops with a
// steady ~8174 ns/op and constant 472 B/op / 6 allocs/op. The whitepaper
// number we publish is the 2 GiB one. Do NOT bump the HAMT-unit / ABA-oneshot
// benches (hamt_test.go, aba_immune_test.go) to this size — they use small
// arenas on purpose to stress the EBR three-epoch ring at fixed cost. New
// CRDTE-Join-shaped benches should reference THIS constant (or a documented
// distinct parallel-headroom constant, e.g. benchParallelCRDTEngineArenaSize)
// rather than re-introducing a magic 64*1024*1024.
const benchCRDTEngineArenaSize uintptr = 2 * 1024 * 1024 * 1024 // 2 GiB — see PHASE_2I_REPORT.md §3 Gate 2.

// Helper to make a push-based Seq iterator from a slice of entries
func makeSeq(entries []seqEntry) Seq {
	return func(yield func(entityID string, entry CRDTEntry) bool) {
		for _, e := range entries {
			if !yield(e.entityID, e.entry) {
				return
			}
		}
	}
}

// Helper to collect entries from a push-based Seq iterator
func collectSeq(seq Seq) []CRDTEntry {
	var result []CRDTEntry
	seq(func(entityID string, entry CRDTEntry) bool {
		result = append(result, entry)
		return true
	})
	return result
}

// Helper to create a test engine with cleanup
func newTestEngine(t *testing.T, nodeID [16]byte, initialCounter uint64) *DeltaCRDTEngine {
	// Isolate DataDir for this test to avoid cross-test interference
	oldDir := DataDir
	DataDir = t.TempDir()
	t.Cleanup(func() {
		DataDir = oldDir
	})

	// 64MB arena for testing
	engine, err := NewDeltaCRDTEngine(nodeID, initialCounter, 64*1024*1024)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := engine.Close()
		require.NoError(t, err)
	})
	return engine
}

// --- IBLT Tests ---

func TestIBLT_InsertAndPeel(t *testing.T) {
	iblt := NewIBLT(100, 4)
	key1 := uint64(123456)
	key2 := uint64(789012)

	iblt.Insert(key1)
	iblt.Insert(key2)

	local, remote, err := iblt.Peel()
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint64{key1, key2}, local)
	assert.Empty(t, remote)
}

func TestIBLT_Subtract(t *testing.T) {
	ibltA := NewIBLT(100, 4)
	ibltB := NewIBLTWithSeed(100, 4, ibltA.Seed())

	keyShared := uint64(111)
	keyOnlyA := uint64(222)
	keyOnlyB := uint64(333)

	ibltA.Insert(keyShared)
	ibltA.Insert(keyOnlyA)

	ibltB.Insert(keyShared)
	ibltB.Insert(keyOnlyB)

	diff, err := ibltA.Subtract(ibltB)
	require.NoError(t, err)

	local, remote, err := diff.Peel()
	require.NoError(t, err)

	assert.ElementsMatch(t, []uint64{keyOnlyA}, local)
	assert.ElementsMatch(t, []uint64{keyOnlyB}, remote)
}

func TestIBLT_ZeroFalsePositives(t *testing.T) {
	ibltA := NewIBLT(1024, 4)
	ibltB := NewIBLTWithSeed(1024, 4, ibltA.Seed())

	// Insert 100,000 shared keys
	for i := 0; i < 100_000; i++ {
		key := uint64(i + 1000)
		ibltA.Insert(key)
		ibltB.Insert(key)
	}

	// Insert 100 differences
	for i := 0; i < 50; i++ {
		ibltA.Insert(uint64(i + 900000))
		ibltB.Insert(uint64(i + 900050))
	}

	diff, err := ibltA.Subtract(ibltB)
	require.NoError(t, err)

	local, remote, err := diff.Peel()
	require.NoError(t, err)

	assert.Len(t, local, 50)
	assert.Len(t, remote, 50)
}

func TestIBLT_IncompletePeel(t *testing.T) {
	ibltA := NewIBLT(10, 3)
	ibltB := NewIBLTWithSeed(10, 3, ibltA.Seed())

	// Insert more differences than the capacity (10 buckets can handle ~6 differences)
	for i := 0; i < 20; i++ {
		ibltA.Insert(uint64(i + 1))
	}

	diff, err := ibltA.Subtract(ibltB)
	require.NoError(t, err)

	_, _, err = diff.Peel()
	assert.ErrorIs(t, err, ErrIncompletePeel)
}

// --- Delta CRDT Engine Tests ---

func TestCRDTEngine_InsertLocal(t *testing.T) {
	nodeID := [16]byte{1}
	engine := newTestEngine(t, nodeID, 0)

	entry := CRDTEntry{
		SystemTime: 1000,
		H3Index:    0x8928308280fffff,
	}

	dot := engine.InsertLocal("doc-1", entry)
	assert.Equal(t, nodeID, dot.NodeID)
	assert.Equal(t, uint64(1), dot.Counter)

	// Verify state.
	state := engine.State()
	got := state.Get("doc-1")
	require.Len(t, got, 1)
	assert.Equal(t, int64(1000), got[0].SystemTime)
	assert.Equal(t, nodeID, got[0].OriginNodeID)
}

func TestCRDTEngine_GenerateDelta_FullSync(t *testing.T) {
	// Node A has 3 entries. Node B has nothing (empty digest).
	nodeA := [16]byte{1}
	engineA := newTestEngine(t, nodeA, 0)

	for i := 0; i < 3; i++ {
		engineA.InsertLocal(fmt.Sprintf("doc-%d", i), CRDTEntry{
			SystemTime: int64(i * 1000),
		})
	}

	// Node B sends an empty Bloom filter (knows nothing).
	emptyDigest := NewIBLT(1024, 4)
	delta := engineA.GenerateDelta(emptyDigest)
	defer delta.Release()

	// Delta should contain all 3 entries.
	entries := collectSeq(delta.Entries)
	assert.Len(t, entries, 3)
	assert.Equal(t, nodeA, delta.OriginNodeID)
}

func TestCRDTEngine_GenerateDelta_PartialSync(t *testing.T) {
	nodeA := [16]byte{1}
	engineA := newTestEngine(t, nodeA, 0)

	dots := make([]CausalDot, 5)
	for i := 0; i < 5; i++ {
		dots[i] = engineA.InsertLocal(fmt.Sprintf("doc-%d", i), CRDTEntry{
			SystemTime: int64(i),
		})
	}

	// Node B already has the first 3 entries.
	// We need consistent seeds — use the same construction.
	digestB := NewIBLT(1024, 4)
	digestB.Insert(HashCausalDot(dots[0], [32]byte{}))
	digestB.Insert(HashCausalDot(dots[1], [32]byte{}))
	digestB.Insert(HashCausalDot(dots[2], [32]byte{}))

	delta := engineA.GenerateDelta(digestB)
	defer delta.Release()

	// Delta should contain only entries 3 and 4.
	entries := collectSeq(delta.Entries)
	assert.Len(t, entries, 2)
}

func TestCRDTEngine_Join_Idempotent(t *testing.T) {
	nodeA := [16]byte{1}
	nodeB := [16]byte{2}
	engineB := newTestEngine(t, nodeB, 0)

	// Create a delta from node A.
	delta := CRDTDelta{
		OriginNodeID: nodeA,
		Entries: makeSeq([]seqEntry{{
			entityID: "doc-1",
			entry: CRDTEntry{
				SystemTime:   1000,
				DotNodeID:    nodeA,
				DotCounter:   1,
				OriginNodeID: nodeA,
			},
		}}),
	}

	// Apply twice — should be idempotent.
	engineB.Join(delta)
	engineB.Join(delta)

	state := engineB.State()
	got := state.Get("doc-1")
	require.Len(t, got, 1) // Only one entry, not duplicated.
}

func TestCRDTEngine_Join_BackPropagationPrevention(t *testing.T) {
	nodeA := [16]byte{1}
	engineA := newTestEngine(t, nodeA, 0)

	// Node A inserts an entry.
	engineA.InsertLocal("doc-1", CRDTEntry{
		SystemTime: 1000,
	})

	// A delta comes back to node A with its own OriginNodeID.
	// This simulates A→B→C→A back-propagation.
	bouncedDelta := CRDTDelta{
		OriginNodeID: [16]byte{3}, // From node C, but entry originated at A.
		Entries: makeSeq([]seqEntry{{
			entityID: "doc-1",
			entry: CRDTEntry{
				SystemTime:   1000,
				DotNodeID:    nodeA,
				DotCounter:   1,
				OriginNodeID: nodeA, // Originally from A.
			},
		}}),
	}

	engineA.Join(bouncedDelta)

	// Entry should NOT be duplicated.
	state := engineA.State()
	got := state.Get("doc-1")
	assert.Len(t, got, 1)

	stats := engineA.Stats()
	assert.Equal(t, uint64(1), stats["entries_skipped"])
}

func TestCRDTEngine_ThreeNodeConvergence(t *testing.T) {
	nodeA := [16]byte{1}
	nodeB := [16]byte{2}
	nodeC := [16]byte{3}

	engineA := newTestEngine(t, nodeA, 0)
	engineB := newTestEngine(t, nodeB, 0)
	engineC := newTestEngine(t, nodeC, 0)

	// Each node inserts a unique document.
	engineA.InsertLocal("doc-a", CRDTEntry{SystemTime: 100})
	engineB.InsertLocal("doc-b", CRDTEntry{SystemTime: 200})
	engineC.InsertLocal("doc-c", CRDTEntry{SystemTime: 300})

	// A → B sync.
	digestB := engineB.GenerateDigest()
	defer digestB.Release() // Phase 2.5b.1: arena-backed digest release
	deltaAtoB := engineA.GenerateDelta(digestB)
	engineB.Join(*deltaAtoB)
	deltaAtoB.Release()

	// B → C sync (B now has A's data too).
	digestC := engineC.GenerateDigest()
	defer digestC.Release() // Phase 2.5b.1: arena-backed digest release
	deltaBtoC := engineB.GenerateDelta(digestC)
	engineC.Join(*deltaBtoC)
	deltaBtoC.Release()

	// C → A sync (C now has everything).
	digestA := engineA.GenerateDigest()
	defer digestA.Release() // Phase 2.5b.1: arena-backed digest release
	deltaCtoA := engineC.GenerateDelta(digestA)
	engineA.Join(*deltaCtoA)
	deltaCtoA.Release()

	// A → B sync again so B gets the propagated C's data.
	digestB2 := engineB.GenerateDigest()
	defer digestB2.Release() // Phase 2.5b.1: arena-backed digest release
	deltaAtoB2 := engineA.GenerateDelta(digestB2)
	engineB.Join(*deltaAtoB2)
	deltaAtoB2.Release()

	// All three engines should have all three documents.
	for idx, engine := range []*DeltaCRDTEngine{engineA, engineB, engineC} {
		state := engine.State()
		keys := []string{}
		state.ForEach(func(key string, _ []CRDTEntry) bool {
			keys = append(keys, key)
			return true
		})
		fmt.Printf("Engine %d (node %v): len=%d, keys=%v\n", idx, engine.localNodeID, state.Len(), keys)
		assert.Equal(t, 3, state.Len(), "engine %d should have 3 entities", idx)
		assert.NotNil(t, state.Get("doc-a"))
		assert.NotNil(t, state.Get("doc-b"))
		assert.NotNil(t, state.Get("doc-c"))
	}
}

func TestCRDTEngine_FiveNodeConvergence(t *testing.T) {
	const N = 5
	engines := make([]*DeltaCRDTEngine, N)

	for i := 0; i < N; i++ {
		nodeID := [16]byte{byte(i + 1)}
		engines[i] = newTestEngine(t, nodeID, 0)
		engines[i].InsertLocal(fmt.Sprintf("doc-from-node-%d", i), CRDTEntry{
			SystemTime: int64(i * 1000),
		})
	}

	// Full mesh sync: every pair exchanges deltas.
	// Two rounds ensure full propagation in any topology.
	for round := 0; round < 2; round++ {
		for i := 0; i < N; i++ {
			for j := 0; j < N; j++ {
				if i == j {
					continue
				}
				digest := engines[j].GenerateDigest()
				delta := engines[i].GenerateDelta(digest)
				engines[j].Join(*delta)
				delta.Release()
				digest.Release() // Phase 2.5b.1: arena-backed digest release (loop: direct, not defer)
			}
		}
	}

	// All engines should converge to the same state.
	for i := 0; i < N; i++ {
		state := engines[i].State()
		assert.Equal(t, N, state.Len(), "engine %d should have %d entities", i, N)
		for j := 0; j < N; j++ {
			key := fmt.Sprintf("doc-from-node-%d", j)
			assert.NotNil(t, state.Get(key), "engine %d missing %s", i, key)
		}
	}
}

func TestCRDTEngine_ConcurrentInsertAndJoin(t *testing.T) {
	nodeA := [16]byte{1}
	engineA := newTestEngine(t, nodeA, 0)

	var wg sync.WaitGroup

	// Concurrent local inserts.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			engineA.InsertLocal(fmt.Sprintf("concurrent-doc-%d", idx), CRDTEntry{
				SystemTime: int64(idx),
			})
		}(i)
	}

	// Concurrent joins from a "remote" node.
	nodeB := [16]byte{2}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			delta := CRDTDelta{
				OriginNodeID: nodeB,
				Entries: makeSeq([]seqEntry{{
					entityID: fmt.Sprintf("remote-doc-%d", idx),
					entry: CRDTEntry{
						SystemTime:   int64(idx * 1000),
						DotNodeID:    nodeB,
						DotCounter:   uint64(idx + 1),
						OriginNodeID: nodeB,
					},
				}}),
			}
			engineA.Join(delta)
		}(i)
	}

	wg.Wait()

	state := engineA.State()
	assert.Equal(t, 150, state.Len())
}

func TestCRDTEngine_AdvanceLamportTo(t *testing.T) {
	engine := newTestEngine(t, [16]byte{1}, 10)
	assert.Equal(t, uint64(10), engine.LamportCounter())

	// Advance forward.
	engine.AdvanceLamportTo(100)
	assert.Equal(t, uint64(100), engine.LamportCounter())

	// Advance to a lower value — should be a no-op.
	engine.AdvanceLamportTo(50)
	assert.Equal(t, uint64(100), engine.LamportCounter())
}

func TestCRDTEngine_EmptyDeltaJoin(t *testing.T) {
	engine := newTestEngine(t, [16]byte{1}, 0)
	engine.InsertLocal("doc-1", CRDTEntry{SystemTime: 100})

	// Join with empty delta — should be a no-op.
	engine.Join(CRDTDelta{})
	assert.Equal(t, 1, engine.State().Len())
}

func TestCRDTEngine_MultipleEntriesPerEntity(t *testing.T) {
	nodeA := [16]byte{1}
	nodeB := [16]byte{2}
	engineA := newTestEngine(t, nodeA, 0)

	// Insert two versions of the same entity.
	engineA.InsertLocal("doc-1", CRDTEntry{SystemTime: 100})
	engineA.InsertLocal("doc-1", CRDTEntry{SystemTime: 200})

	// Receive a third version from a remote node.
	delta := CRDTDelta{
		OriginNodeID: nodeB,
		Entries: makeSeq([]seqEntry{{
			entityID: "doc-1",
			entry: CRDTEntry{
				SystemTime:   300,
				DotNodeID:    nodeB,
				DotCounter:   1,
				OriginNodeID: nodeB,
			},
		}}),
	}
	engineA.Join(delta)

	state := engineA.State()
	got := state.Get("doc-1")
	assert.Len(t, got, 3) // All three versions coexist (AWSet semantics).
}

func BenchmarkCRDTEngine_GenerateDelta(b *testing.B) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, benchCRDTEngineArenaSize)
	if err != nil {
		b.Fatal(err)
	}
	defer engine.Close()

	for i := 0; i < 10000; i++ {
		engine.InsertLocal(fmt.Sprintf("entity-%d", i), CRDTEntry{
			SystemTime: int64(i),
		})
	}
	emptyDigest := NewIBLT(1024, 4)

	// Phase 2.5b: warm the delta/EBR steady-state pools (the deltaPool,
	// participantPool, and EBR's three-epoch retired-ring need ~256
	// RetireBlock fills before the retiredPool recycles and `maybeAdvanceEpoch`
	// has advanced the epoch enough that the retired-lists reach steady state).
	// WITHOUT this warmup the cold fill amortizes across b.N and the bench
	// reads a spurious ~13 B/op that is NOT steady state — §6(iii) declares the
	// 0-alloc gate steady-state, not cold-start. Mirrors the Phase 2l
	// warmEBRPool precedent (hamt_test.go:269). R4: the INSERT setup above and
	// the emptyDigest line are byte-identical to 355581d; this warmup is BELOW
	// ResetTimer so it is not measured.
	for w := 0; w < 2048; w++ {
		wD := engine.GenerateDelta(emptyDigest)
		wD.Release()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := engine.GenerateDelta(emptyDigest)
		d.Release()
	}
}

func BenchmarkCRDTEngine_Join(b *testing.B) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, benchCRDTEngineArenaSize)
	if err != nil {
		b.Fatal(err)
	}
	defer engine.Close()
	nodeB := [16]byte{2}

	// Pre-build deltas.
	deltas := make([]CRDTDelta, b.N)
	for i := range deltas {
		deltas[i] = CRDTDelta{
			OriginNodeID: nodeB,
			Entries: makeSeq([]seqEntry{{
				entityID: fmt.Sprintf("remote-%d", i),
				entry: CRDTEntry{
					SystemTime:   int64(i),
					DotNodeID:    nodeB,
					DotCounter:   uint64(i + 1),
					OriginNodeID: nodeB,
				},
			}}),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Join(deltas[i])
	}
}

func TestCRDTEngine_LamportMonotonicPersistence(t *testing.T) {
	oldDir := DataDir
	DataDir = t.TempDir()
	t.Cleanup(func() {
		DataDir = oldDir
	})

	nodeID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// 1. Initial engine startup.
	engine1, err := NewDeltaCRDTEngine(nodeID, 10, 64*1024*1024)
	require.NoError(t, err)

	dot1 := engine1.NextDot()
	assert.Equal(t, uint64(11), dot1.Counter)
	_ = engine1.Close()

	// 2. Restart and verify crash recovery counter.
	engine2, err := NewDeltaCRDTEngine(nodeID, 10, 64*1024*1024)
	require.NoError(t, err)

	dot2 := engine2.NextDot()
	// Persisted limit was 11 + 1000 = 1011.
	// Recovered resumes from 1011. So dot2 counter should be 1012.
	assert.Equal(t, uint64(1012), dot2.Counter)
	_ = engine2.Close()
}

// --- ADR 5: Strata Estimator Tests ---

func TestStrataEstimator_IdenticalSets(t *testing.T) {
	seed := maphash.MakeSeed()
	seA := NewStrataEstimator(seed)
	seB := NewStrataEstimator(seed)

	// Insert identical keys into both
	for i := uint64(1); i <= 1000; i++ {
		seA.Insert(i)
		seB.Insert(i)
	}

	dEst := seA.Estimate(seB)
	assert.Equal(t, 0, dEst, "identical sets should have d_est=0")
}

func TestStrataEstimator_SmallDifference(t *testing.T) {
	seed := maphash.MakeSeed()
	seA := NewStrataEstimator(seed)
	seB := NewStrataEstimator(seed)

	// Shared: 1000 keys
	for i := uint64(1); i <= 1000; i++ {
		seA.Insert(i)
		seB.Insert(i)
	}

	// A has 10 extra keys
	for i := uint64(10001); i <= 10010; i++ {
		seA.Insert(i)
	}

	// B has 5 extra keys
	for i := uint64(20001); i <= 20005; i++ {
		seB.Insert(i)
	}

	dEst := seA.Estimate(seB)
	// True |d| = 15. Estimate should be in the right ballpark.
	// Strata estimators are approximate — accept within 4× factor.
	assert.Greater(t, dEst, 0, "should detect differences")
	assert.LessOrEqual(t, dEst, 60, "estimate should not be wildly off (true d=15)")
}

func TestStrataEstimator_LargeDifference(t *testing.T) {
	seed := maphash.MakeSeed()
	seA := NewStrataEstimator(seed)
	seB := NewStrataEstimator(seed)

	// No shared keys
	for i := uint64(1); i <= 500; i++ {
		seA.Insert(i)
	}
	for i := uint64(10001); i <= 10500; i++ {
		seB.Insert(i)
	}

	dEst := seA.Estimate(seB)
	// True |d| = 1000. Estimate should be reasonable.
	assert.Greater(t, dEst, 100, "should detect large difference (true d=1000)")
}

func TestDynamicIBLTSize_MinimumFloor(t *testing.T) {
	// Small estimate should hit the floor
	assert.Equal(t, minDynamicBuckets, DynamicIBLTSize(10))
	assert.Equal(t, minDynamicBuckets, DynamicIBLTSize(0))

	// Large estimate
	size := DynamicIBLTSize(1000)
	assert.Equal(t, 1500, size) // 1000 * 3 / 2 = 1500
}

func TestTrailingZeros64(t *testing.T) {
	tests := []struct {
		x    uint64
		want int
	}{
		{0, 64},
		{1, 0},
		{2, 1},
		{4, 2},
		{8, 3},
		{16, 4},
		{0x100, 8},
		{0x10000, 16},
		{0x80000000, 31},
		{3, 0},  // 0b11
		{6, 1},  // 0b110
		{12, 2}, // 0b1100
	}
	for _, tt := range tests {
		got := trailingZeros64(tt.x)
		assert.Equal(t, tt.want, got, "trailingZeros64(%d)", tt.x)
	}
}

// TestCRDTEngine_GenerateDeltaWithRemoteIBLT is the M2-FIX contract test
// (Day-29 ADR-0034, the Architect's Amendment). The deleted primitive
// `GenerateDeltaStratified(remoteEstimator)` subtracted an EMPTY remote IBLT
// every round (crdt.go created remoteIBLT then never populated it) → the delta
// was byte-identical to oversend for any non-empty remote overlap. The fix: the
// mesh sends the remote's FULL IBLT on the wire + the sweep calls
// `GenerateDelta(remoteIBLT)` — the FROZEN, CORRECT primitive that subtracts
// the POPULATED remote IBLT + peels the real diff. This test PROVES that
// contract: A holds 5 entries, B holds 3 of them (the overlap), and
// `GenerateDelta(B's digest)` yields ONLY the 2 A has that B lacks (NOT all
// 5) — the real bandwidth cut, the contract the deleted primitive violated.
//
// THE 3 CORE CONTRACTS (pre-and-post, re-proven):
//
//	(a) empty remote IBLT → delta == full set (oversend; the GenerateDelta
//	    "diff == local" path — the FROZEN behavior the OFF sweep relies on).
//	(b) populated remote IBLT (partial overlap) → delta == the |A−B| diff
//	    ONLY (the bandwidth cut — the M2 fix's load-bearing contract).
//	(c) identical remote IBLT (full overlap) → delta == empty (perfect sync;
//	    convergence terminates, no oversend).
func TestCRDTEngine_GenerateDeltaWithRemoteIBLT(t *testing.T) {
	// A holds 5 entries; B holds the SAME 3 (the overlap). Both engines share
	// nodeID seed 1 so the CausalDots match (the OriginNodeID is part of the
	// dot; identical nodeIDs + identical (entityID, SystemTime) make the
	// overlap keys identical across the two engines — HashCausalDot is a pure
	// function of the dot + PayloadDigest).
	nodeID := [16]byte{1}
	engineA := newTestEngine(t, nodeID, 0)
	engineB := newTestEngine(t, nodeID, 0)
	for i := 0; i < 5; i++ {
		eid := fmt.Sprintf("doc-%d", i)
		entry := CRDTEntry{SystemTime: int64(i * 1000)}
		engineA.InsertLocal(eid, entry)
		if i < 3 { // B holds [0,3) — the overlap
			engineB.InsertLocal(eid, entry)
		}
	}

	// Contract (a): empty remote IBLT → delta == full set (oversend). This is
	// the FROZEN behavior the OFF sweep relies on (GenerateDelta(emptyIBLT)).
	emptyRemote := NewIBLT(1, 4)
	emptyRemoteDelta := engineA.GenerateDelta(emptyRemote)
	emptyRemoteEntries := collectSeq(emptyRemoteDelta.Entries)
	emptyRemoteDelta.Release()
	assert.Len(t, emptyRemoteEntries, 5, "contract (a): empty remote IBLT must yield the full 5-entry set (oversend)")

	// Contract (b): populated remote IBLT (B's digest, the 3-entry overlap) →
	// delta == the |A−B| diff ONLY (2 entries — the M2 bandwidth cut). The
	// remote IBLT is B's FULL digest (GenerateDigestWithSeed, the SAME 1024-
	// bucket path the mesh's digest exchange uses — the bucket count matches
	// GenerateDelta's internal local at crdt.go:1610 so Subtract succeeds);
	// GenerateDelta subtracts it + peels the real diff. This is the contract
	// the deleted primitive VIOLATED (it subtracted an empty IBLT → yielded
	// all 5, not 2).
	seed := maphash.MakeSeed()
	remoteIBLT := engineB.GenerateDigestWithSeed(seed) // crdt.go:1836 (B's FULL digest, 1024 buckets — matches GenerateDelta's local)
	diffDelta := engineA.GenerateDelta(remoteIBLT)     // crdt.go:1603 (FROZEN, CORRECT)
	diffEntries := collectSeq(diffDelta.Entries)
	diffDelta.Release()
	assert.Len(t, diffEntries, 2, "contract (b): populated remote IBLT (3-of-5 overlap) must yield ONLY the 2 |A-B| diff entries (the M2 bandwidth cut) — NOT all 5 (the deleted primitive's empty-subtract defect)")

	// Contract (c): identical remote IBLT (A's own digest) → delta == empty
	// (perfect sync — convergence terminates, no oversend). A's digest minus
	// A's digest is the empty diff.
	ownDigest := engineA.GenerateDigestWithSeed(seed)
	syncDelta := engineA.GenerateDelta(ownDigest)
	syncEntries := collectSeq(syncDelta.Entries)
	syncDelta.Release()
	assert.Len(t, syncEntries, 0, "contract (c): identical remote IBLT (A's own digest) must yield the empty delta (perfect sync)")
}

func TestCRDTEngine_GenerateStrataEstimator(t *testing.T) {
	nodeA := [16]byte{1}
	engineA := newTestEngine(t, nodeA, 0)

	for i := 0; i < 100; i++ {
		engineA.InsertLocal(fmt.Sprintf("doc-%d", i), CRDTEntry{
			SystemTime: int64(i),
		})
	}

	seed := maphash.MakeSeed()
	se := engineA.GenerateStrataEstimator(seed)
	assert.NotNil(t, se)

	// Verify self-estimate is 0 (identical sets)
	se2 := engineA.GenerateStrataEstimator(seed)
	dEst := se.Estimate(se2)
	assert.Equal(t, 0, dEst, "self-estimate should be 0")
}

func BenchmarkStrataEstimator_Insert(b *testing.B) {
	seed := maphash.MakeSeed()
	se := NewStrataEstimator(seed)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		se.Insert(uint64(i + 1))
	}
}
