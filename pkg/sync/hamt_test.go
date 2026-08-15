package sync

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hash/maphash"
	"sync"
	"testing"
	"unsafe"
)

func newTestArena(t *testing.T) *HamtArena {
	// Allocate a 512MB virtual arena for tests.
	// Since it's MAP_ANON | MAP_PRIVATE, it doesn't use physical RAM until accessed.
	arena, err := NewHamtArena(512*1024*1024, NewEBRManager())
	require.NoError(t, err)
	t.Cleanup(func() {
		arena.Free()
	})
	return arena
}

func TestHAMT_EmptyGet(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)
	assert.Nil(t, h.Get("nonexistent"))
	assert.Equal(t, 0, h.Len())
}

func TestHAMT_SetAndGet(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)
	entries := []CRDTEntry{{
		SystemTime: 1000,
		DotNodeID:  [16]byte{1},
		DotCounter: 1,
	}}

	h2 := h.Set("entity-1", entries)

	// Original is unchanged.
	assert.Nil(t, h.Get("entity-1"))
	assert.Equal(t, 0, h.Len())

	// New HAMT has the entry.
	got := h2.Get("entity-1")
	require.Len(t, got, 1)
	assert.Equal(t, int64(1000), got[0].SystemTime)
	assert.Equal(t, 1, h2.Len())
}

func TestHAMT_StructuralSharing(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)

	// Insert 100 entities.
	for i := 0; i < 100; i++ {
		h = h.Set(fmt.Sprintf("entity-%d", i), []CRDTEntry{{
			SystemTime: int64(i),
			DotNodeID:  [16]byte{1},
			DotCounter: uint64(i),
		}})
	}
	assert.Equal(t, 100, h.Len())

	// Modify one entity — only the path to that leaf should change.
	h2 := h.Set("entity-50", []CRDTEntry{{
		SystemTime: 9999,
		DotNodeID:  [16]byte{1},
		DotCounter: 999,
	}})

	// Original entity-50 is unchanged.
	orig := h.Get("entity-50")
	require.Len(t, orig, 1)
	assert.Equal(t, int64(50), orig[0].SystemTime)

	// New HAMT has the updated entity-50.
	updated := h2.Get("entity-50")
	require.Len(t, updated, 1)
	assert.Equal(t, int64(9999), updated[0].SystemTime)

	// Other entities are shared (same data).
	for i := 0; i < 100; i++ {
		if i == 50 {
			continue
		}
		key := fmt.Sprintf("entity-%d", i)
		assert.Equal(t, h.Get(key), h2.Get(key), "entity %d should be shared", i)
	}
}

func TestHAMT_Delete(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)
	h = h.Set("a", []CRDTEntry{{DotCounter: 1}})
	h = h.Set("b", []CRDTEntry{{DotCounter: 2}})
	assert.Equal(t, 2, h.Len())

	h2 := h.Delete("a")
	assert.Equal(t, 1, h2.Len())
	assert.Nil(t, h2.Get("a"))
	assert.NotNil(t, h2.Get("b"))

	// Original unchanged.
	assert.NotNil(t, h.Get("a"))
	assert.Equal(t, 2, h.Len())

	// Delete non-existent key is no-op.
	h3 := h2.Delete("nonexistent")
	assert.Equal(t, 1, h3.Len())
}

func TestHAMT_ForEach(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)
	for i := 0; i < 50; i++ {
		h = h.Set(fmt.Sprintf("e-%d", i), []CRDTEntry{{
			DotCounter: uint64(i),
		}})
	}

	visited := make(map[string]bool)
	h.ForEach(func(entityID string, entries []CRDTEntry) bool {
		visited[entityID] = true
		return true
	})
	assert.Len(t, visited, 50)
}

func TestHAMT_ForEach_EarlyTermination(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)
	for i := 0; i < 100; i++ {
		h = h.Set(fmt.Sprintf("e-%d", i), []CRDTEntry{{}})
	}

	count := 0
	h.ForEach(func(_ string, _ []CRDTEntry) bool {
		count++
		return count < 10 // Stop after 10.
	})
	assert.Equal(t, 10, count)
}

func TestHAMT_AllEntries(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)
	h = h.Set("a", []CRDTEntry{
		{DotCounter: 1},
		{DotCounter: 2},
	})
	h = h.Set("b", []CRDTEntry{
		{DotCounter: 3},
	})

	all := h.AllEntries()
	assert.Len(t, all, 3)
}

func TestHAMT_ConcurrentReads(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)
	for i := 0; i < 1000; i++ {
		h = h.Set(fmt.Sprintf("entity-%d", i), []CRDTEntry{{
			DotCounter: uint64(i),
		}})
	}

	// Multiple concurrent readers on the same immutable HAMT.
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				got := h.Get(fmt.Sprintf("entity-%d", i))
				if len(got) != 1 {
					t.Errorf("expected 1 entry for entity-%d, got %d", i, len(got))
				}
			}
		}()
	}
	wg.Wait()
}

func TestHAMT_LargeScale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-scale HAMT test in short mode")
	}

	arena := newTestArena(t)
	h := NewHAMT(arena)
	const N = 100_000

	for i := 0; i < N; i++ {
		key := fmt.Sprintf("entity-%d", i)
		entries := []CRDTEntry{{
			DotCounter: uint64(i),
		}}
		h = h.Set(key, entries)
	}
	assert.Equal(t, N, h.Len())

	// Verify all entries are retrievable.
	for i := 0; i < N; i++ {
		key := fmt.Sprintf("entity-%d", i)
		got := h.Get(key)
		require.Len(t, got, 1, "missing entity %s", key)
	}
}

func TestHAMT_MerkleRoot_Deterministic(t *testing.T) {
	arena := newTestArena(t)
	seed := maphash.MakeSeed()
	h1 := newHAMTWithSeed(arena, seed)
	h2 := newHAMTWithSeed(arena, seed)

	for i := 0; i < 50; i++ {
		entityID := fmt.Sprintf("e-%d", i)
		entry := CRDTEntry{
			DotNodeID:  [16]byte{1},
			DotCounter: uint64(i),
		}
		h1 = h1.Set(entityID, []CRDTEntry{entry})
		h2 = h2.Set(entityID, []CRDTEntry{entry})
	}

	assert.Equal(t, h1.MerkleRoot(), h2.MerkleRoot())

	// Modify h2 — Merkle roots should diverge.
	h2 = h2.Set("e-0", []CRDTEntry{{
		DotNodeID:  [16]byte{2},
		DotCounter: 999,
	}})
	assert.NotEqual(t, h1.MerkleRoot(), h2.MerkleRoot())
}

func TestHAMT_MerkleRoot_Empty(t *testing.T) {
	arena := newTestArena(t)
	h := NewHAMT(arena)
	root := h.MerkleRoot()
	assert.Equal(t, [32]byte{}, root)
}

func BenchmarkHAMT_Set(b *testing.B) {
	// Steady-state HAMT.Set throughput under EBR reclamation.
	//
	// Phase 2l: this benchmark previously orphaned every prior *HAMT
	// wrapper without retiring it, leaking ~1300 B/op of path-copied
	// arena nodes unbounded. At b.N=500K (the framework's default
	// scaling toward 1s) the 512 MiB arena OOM'd at hamt_arena.go:329
	// (runN=0x7a985=501,125). The fix mirrors the production
	// InsertLocal reclamation contract (crdt.go:399-404) and the
	// sibling BenchmarkHAMTInsertZeroAlloc (physics_test.go:169-177):
	// retire the previous HAMT wrapper via EBR and advance the epoch
	// each iteration, so the three-epoch ring buffer physically
	// recycles slab offsets and the arena reaches steady state. This
	// is architecturally pure — Retire/AdvanceEpoch operate on the
	// sync.Pool-backed RetiredNode list, never on the Go heap.
	//
	// Arena size is calibrated to 2 GiB (mmap is MAP_ANON|MAP_PRIVATE,
	// so the virtual reservation does not consume physical RAM until
	// touched), matching BenchmarkHAMTInsertZeroAlloc's calibration
	// per PHASE_2I_REPORT.md §3 Gate 2 and PHASE_2J_REPORT.md R1.
	arena := allocTestArenaSized(b, 2*1024*1024*1024)
	h := NewHAMT(arena)
	warmEBRPool(arena)

	entries := make([]CRDTEntry, 1)
	entries[0] = CRDTEntry{DotCounter: 1}

	var keyBuf [8]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := makeBinaryKey(&keyBuf, uint64(i))
		prev := h
		h = h.Set(key, entries)
		// Retire the previous HAMT wrapper via EBR — zero heap
		// allocations. Mirrors DeltaCRDTEngine.InsertLocal's
		// reclamation contract (crdt.go:399-404): old state is
		// retired and epoch advanced, letting EBR's three-epoch ring
		// physically recycle slab offsets.
		arena.ebr.Retire(unsafe.Pointer(prev))
		arena.ebr.AdvanceEpoch()
	}
}

func BenchmarkHAMT_Get(b *testing.B) {
	arena, err := NewHamtArena(1024*1024*1024, NewEBRManager())
	if err != nil {
		b.Fatal(err)
	}
	defer arena.Free()
	h := NewHAMT(arena)
	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("entity-%d", i)
		h = h.Set(key, []CRDTEntry{{DotCounter: uint64(i)}})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Get(fmt.Sprintf("entity-%d", i%10000))
	}
}

func TestHamtNodeOffsets(t *testing.T) {
	var n HamtNode
	t.Logf("Sizeof(HamtNode): %d", unsafe.Sizeof(n))
	t.Logf("Offsetof(refCount): %d", unsafe.Offsetof(n.refCount))
	t.Logf("Offsetof(bitmap): %d", unsafe.Offsetof(n.bitmap))
	t.Logf("Offsetof(childrenPtr): %d", unsafe.Offsetof(n.childrenPtr))
	t.Logf("Offsetof(entriesPtr): %d", unsafe.Offsetof(n.entriesPtr))
	t.Logf("Offsetof(nextFree): %d", unsafe.Offsetof(n.nextFree))
}

// --- ADR 8 Phase 1: Mathematical Size and Alignment Verification ---

func TestCRDTEntry_SizeAndAlignment(t *testing.T) {
	var e CRDTEntry

	// Total struct size must be exactly 120 bytes (15 × 8-byte words)
	assert.Equal(t, uintptr(120), unsafe.Sizeof(e),
		"CRDTEntry must be exactly 120 bytes per ADR 8")

	// Alignment must be 8 bytes (largest field is uint64/[16]byte)
	assert.Equal(t, uintptr(8), unsafe.Alignof(e),
		"CRDTEntry alignment must be 8 bytes")

	// Verify field offsets match ADR 8 specification exactly — zero padding
	assert.Equal(t, uintptr(0), unsafe.Offsetof(e.PayloadDigest), "PayloadDigest at offset 0")
	assert.Equal(t, uintptr(32), unsafe.Offsetof(e.OriginNodeID), "OriginNodeID at offset 32")
	assert.Equal(t, uintptr(48), unsafe.Offsetof(e.DotNodeID), "DotNodeID at offset 48")
	assert.Equal(t, uintptr(64), unsafe.Offsetof(e.DotCounter), "DotCounter at offset 64")
	assert.Equal(t, uintptr(72), unsafe.Offsetof(e.SystemTime), "SystemTime at offset 72")
	assert.Equal(t, uintptr(80), unsafe.Offsetof(e.ValidTimeStart), "ValidTimeStart at offset 80")
	assert.Equal(t, uintptr(88), unsafe.Offsetof(e.ValidTimeEnd), "ValidTimeEnd at offset 88")
	assert.Equal(t, uintptr(96), unsafe.Offsetof(e.AssertionTime), "AssertionTime at offset 96")
	assert.Equal(t, uintptr(104), unsafe.Offsetof(e.DecisionTime), "DecisionTime at offset 104")
	assert.Equal(t, uintptr(112), unsafe.Offsetof(e.H3Index), "H3Index at offset 112")
}

func TestHamtLeaf_SizeAndAlignment(t *testing.T) {
	var l hamtLeaf

	// Total struct size must be exactly 32 bytes (4 × 8-byte words)
	// Two hamtLeaf structs fit perfectly within a single 64-byte CPU cache line
	assert.Equal(t, uintptr(32), unsafe.Sizeof(l),
		"hamtLeaf must be exactly 32 bytes per ADR 8")

	// Alignment must be 8 bytes (largest field is uint64/NodePtr)
	assert.Equal(t, uintptr(8), unsafe.Alignof(l),
		"hamtLeaf alignment must be 8 bytes")

	// Verify field offsets match ADR 8 specification exactly — zero padding
	assert.Equal(t, uintptr(0), unsafe.Offsetof(l.hash), "hash at offset 0")
	assert.Equal(t, uintptr(8), unsafe.Offsetof(l.entityPtr), "entityPtr at offset 8")
	assert.Equal(t, uintptr(16), unsafe.Offsetof(l.entriesPtr), "entriesPtr at offset 16")
	assert.Equal(t, uintptr(24), unsafe.Offsetof(l.entityLen), "entityLen at offset 24")
	assert.Equal(t, uintptr(28), unsafe.Offsetof(l.entriesLen), "entriesLen at offset 28")
}
