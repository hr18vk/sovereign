package sync

import (
	"testing"
)

func TestArenaUsagePerSet(t *testing.T) {
	arena := allocTestArena(t)
	h := NewHAMT(arena)
	warmEBRPool(arena)

	before := arena.bumpOffset.Load()

	entries := make([]CRDTEntry, 1)
	entries[0].DotCounter = 1
	var keyBuf [8]byte

	// Insert 1000 keys, measure total arena consumed
	const N = 1000
	for i := 0; i < N; i++ {
		key := makeBinaryKey(&keyBuf, uint64(i))
		h = h.Set(key, entries)
	}

	after := arena.bumpOffset.Load()
	used := after - before
	t.Logf("Arena used for %d Sets: %d bytes, per-op: %d bytes", N, used, used/N)

	// Insert another 1000 to see if per-op grows (deeper trie)
	before2 := arena.bumpOffset.Load()
	for i := 0; i < N; i++ {
		key := makeBinaryKey(&keyBuf, uint64(i+N))
		h = h.Set(key, entries)
	}
	after2 := arena.bumpOffset.Load()
	used2 := after2 - before2
	t.Logf("Arena used for next %d Sets: %d bytes, per-op: %d bytes", N, used2, used2/N)
}
