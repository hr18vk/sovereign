// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Unit and concurrency tests for SkipListArena.Seek (ADR-0028).
//
// Seek mirrors Put's top-down descent without splicing and falls back to a
// level-0 linear scan when a concurrent Put transiently shifts a level-0 link.
// Because randomHeight uses the auto-seeded math/rand/v2 global source, node
// heights vary across runs while TestSeekEquiv compares Seek against a linear
// scan on the same constructed list and splits 10,000 fuzz targets evenly
// between within-entity keys and random 128-bit hashes.

package database

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// entityHash returns the 128-bit hash prefix for an entity ID — the first 16
// bytes of sha256(entityID), the same prefix the production composite-key builder
// writes into key[0:16].
func entityHash(entityID string) [16]byte {
	full := sha256.Sum256([]byte(entityID))
	var h [16]byte
	copy(h[:], full[:16])
	return h
}

// buildKey builds a 40-byte composite key as a stack [keySize]byte array (the
// precedent in memtable.go — a fixed-size array stays on the stack; the slice
// header passed to Seek/Put is the only thing that escapes). Layout:
// [hash16 | sysTime8 | validTimeStart8 | assertion8] (big-endian within each
// 8-byte field → numeric order == byte order → bytes.Compare is the lower-bound
// order). Returns a value (no heap allocation).
func buildKey(hash [16]byte, sysTime, validStart, assertion int64) [keySize]byte {
	var k [keySize]byte
	copy(k[0:16], hash[:])
	binary.BigEndian.PutUint64(k[16:24], uint64(sysTime))
	binary.BigEndian.PutUint64(k[24:32], uint64(validStart))
	binary.BigEndian.PutUint64(k[32:40], uint64(assertion))
	return k
}

// putKey inserts a key with a zero-length value (valLen=0, empty valFn). The
// Seek tests care only about key ordering; the value content is irrelevant to
// the lower bound. valLen=0 keeps the arena footprint to one 64-byte node + 40
// key bytes per row (no packed-value bytes).
func putKey(t *testing.T, sl *SkipListArena, key [keySize]byte) {
	t.Helper()
	if err := sl.Put(key[:], 0, func([]byte) {}); err != nil {
		t.Fatalf("putKey Put: %v", err)
	}
}

// putKeyNoErr inserts a key without a *testing.T (for goroutines that cannot
// call t.Fatalf). Returns the Put error.
func putKeyNoErr(sl *SkipListArena, key [keySize]byte) error {
	return sl.Put(key[:], 0, func([]byte) {})
}

// linearLowerBound is the O(N) reference lower bound: a full level-0 scan from
// NewIterator returning the offset of the first node whose key >= target (or
// 0xFFFFFFFF if target > all keys). This is the oracle TestSeekEquiv checks Seek
// against — the descent must agree with the linear scan for every target.
func linearLowerBound(sl *SkipListArena, target []byte) uint32 {
	it := sl.NewIterator()
	for it.Valid() {
		if bytes.Compare(it.Key(), target) >= 0 {
			return it.current
		}
		it.Next()
	}
	return 0xFFFFFFFF
}

// TestSeekLowerBound verifies that for 4,096 distinct keys under one entity,
// Seek(K_i) and Seek(K_i - epsilon) both return K_i, matching NewSeekIterator.
func TestSeekLowerBound(t *testing.T) {
	const N = 4096
	hash := entityHash("lowerbound-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	keys := make([][keySize]byte, N)
	for i := 0; i < N; i++ {
		keys[i] = buildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0)
		putKey(t, sl, keys[i])
	}
	require.Equal(t, uint32(N), sl.Count())

	for i := 0; i < N; i++ {
		ki := keys[i]
		got := sl.Seek(ki[:]).Key()
		assert.Equalf(t, ki[:], got, "Seek(K_i) must return K_i as its own lower bound; i=%d", i)
		before := buildKey(hash, int64(i)*1000, 1000+int64(i)*100-1, 0)
		gotBefore := sl.Seek(before[:]).Key()
		assert.Equalf(t, ki[:], gotBefore, "Seek(K_i - epsilon) must return K_i (the just-before lower-bound); i=%d", i)
	}
	assert.Equal(t, sl.Seek(keys[0][:]).current, sl.NewSeekIterator(keys[0][:]).current,
		"NewSeekIterator(target) must == Seek(target) (the one-liner symmetry)")
	t.Logf("N=4096 exact and pre-key lower bounds matched")
}

// TestSeekBeforeFirst verifies that a target below all inserted keys returns
// the first node in the list, matching NewIterator.
func TestSeekBeforeFirst(t *testing.T) {
	const N = 4096
	hash := entityHash("beforefirst-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	for i := 0; i < N; i++ {
		putKey(t, sl, buildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0))
	}
	target := buildKey(hash, 0, 0, 0)
	it := sl.Seek(target[:])
	require.Truef(t, it.Valid(), "target < first key: Seek must return the first node, not nil/panic")
	firstIt := sl.NewIterator()
	require.True(t, firstIt.Valid(), "skiplist non-empty")
	assert.Equalf(t, firstIt.current, it.current, "Seek before first key must return the same node offset as NewIterator")
	assert.Truef(t, bytes.Compare(it.Key(), target[:]) >= 0, "the returned first key must be >= target")
	t.Logf("target below first key returned NewIterator head")
}

// TestSeekEquiv compares Seek against linearLowerBound across 10,000 fuzzed
// targets (seed 23), alternating within-entity and random 128-bit hashes.
func TestSeekEquiv(t *testing.T) {
	const N = 4096
	const fuzzN = 10000
	hash := entityHash("window-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	for i := 0; i < N; i++ {
		putKey(t, sl, buildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0))
	}
	require.Equal(t, uint32(N), sl.Count())

	rng := rand.New(rand.NewPCG(23, 0))
	var mismatches int
	for f := 0; f < fuzzN; f++ {
		var target [keySize]byte
		if f&1 == 0 {
			copy(target[0:16], hash[:])
		} else {
			binary.BigEndian.PutUint64(target[0:8], rng.Uint64())
			binary.BigEndian.PutUint64(target[8:16], rng.Uint64())
		}
		binary.BigEndian.PutUint64(target[16:24], rng.Uint64())
		binary.BigEndian.PutUint64(target[24:32], rng.Uint64())
		binary.BigEndian.PutUint64(target[32:40], rng.Uint64())

		seekCur := sl.Seek(target[:]).current
		linCur := linearLowerBound(sl, target[:])
		if seekCur != linCur {
			mismatches++
			if mismatches <= 5 {
				t.Errorf("seek equivalence mismatch at f=%d: seek=0x%x lin=0x%x target=%x", f, seekCur, linCur, target)
			}
		}
	}
	require.Zero(t, mismatches, "Seek must match linear-scan lower bound for all 10000 fuzzed targets")
	t.Logf("10000 fuzzed targets matched linear-scan lower bound (seed=23)")
}

// TestSeekEnd verifies that a target beyond the last key returns an exhausted
// iterator with current == 0xFFFFFFFF.
func TestSeekEnd(t *testing.T) {
	const N = 4096
	hash := entityHash("end-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	for i := 0; i < N; i++ {
		putKey(t, sl, buildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0))
	}
	lastSys := int64(N-1) * 1000
	lastValid := 1000 + int64(N-1)*100
	target := buildKey(hash, lastSys, lastValid+1_000_000, 0)
	it := sl.Seek(target[:])
	assert.Falsef(t, it.Valid(), "target past last key: Seek must be exhausted (0xFFFFFFFF) rather than returning the last node")
	assert.Equal(t, uint32(0xFFFFFFFF), it.current)
	lit := sl.NewIterator()
	var lastKey []byte
	for lit.Valid() {
		lastKey = lit.Key()
		lit.Next()
	}
	assert.Truef(t, bytes.Compare(lastKey, target[:]) < 0, "last key must be < target")
	t.Logf("target past last key returned exhausted iterator (0xFFFFFFFF)")
}

// TestSeekEmpty checks that Seek on an empty skiplist returns an exhausted
// iterator without dereferencing unallocated nodes.
func TestSeekEmpty(t *testing.T) {
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 1024*1024)
	defer sl.Free()
	require.Equal(t, uint32(0), sl.Count())
	target := buildKey(entityHash("any-entity"), 42, 99, 7)
	it := sl.Seek(target[:])
	assert.Falsef(t, it.Valid(), "empty skiplist: Seek must return an exhausted iterator (0xFFFFFFFF sentinel), not a node or panic")
	assert.Equal(t, uint32(0xFFFFFFFF), it.current)
	t.Logf("empty skiplist Seek returned 0xFFFFFFFF")
}

// TestSeekAlloc verifies Seek performs at most one heap allocation (the
// returned *SkipListIterator) with zero allocations during traversal.
func TestSeekAlloc(t *testing.T) {
	const N = 4096
	hash := entityHash("alloc-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	for i := 0; i < N; i++ {
		putKey(t, sl, buildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0))
	}
	allocs := testing.AllocsPerRun(100, func() {
		target := buildKey(hash, 1234, 50000, 0)
		_ = sl.Seek(target[:])
	})
	t.Logf("Seek allocs/run = %v", allocs)
	assert.LessOrEqualf(t, allocs, 1.0, "Seek must allocate <= 1 (the iterator struct); the descent + the target stay on the stack — got %v", allocs)
}

// TestSeekConcurrent runs 1 concurrent writer inserting 100,000 keys alongside
// 8 readers calling Seek under -race, verifying zero races, lower-bound
// validity at read time, and monotonic lower bounds after quiescence.
func TestSeekConcurrent(t *testing.T) {
	const N = 100_000
	const M = 8
	const seeksPerReader = 1000
	hash := entityHash("concurrent-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 64*1024*1024)
	defer sl.Free()

	writerDone := make(chan struct{})
	var putErr error
	go func() {
		defer close(writerDone)
		for i := 0; i < N; i++ {
			k := buildKey(hash, int64(i), 1000+int64(i), 0)
			if err := putKeyNoErr(sl, k); err != nil {
				putErr = err
				return
			}
		}
	}()

	type seekResult struct {
		target [keySize]byte
		cur    uint32
	}
	var mu sync.Mutex
	var results []seekResult
	var wg sync.WaitGroup
	for r := 0; r < M; r++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, 0))
			local := make([]seekResult, 0, seeksPerReader)
			for s := 0; s < seeksPerReader; s++ {
				var target [keySize]byte
				copy(target[0:16], hash[:])
				binary.BigEndian.PutUint64(target[16:24], rng.Uint64())
				binary.BigEndian.PutUint64(target[24:32], rng.Uint64())
				binary.BigEndian.PutUint64(target[32:40], rng.Uint64())
				cur := sl.Seek(target[:]).current
				local = append(local, seekResult{target, cur})
			}
			mu.Lock()
			results = append(results, local...)
			mu.Unlock()
		}(1000 + uint64(r))
	}
	wg.Wait()
	<-writerDone
	require.NoError(t, putErr, "writer Puts must all succeed (arena big enough for N=%d keys)", N)
	require.Equal(t, uint32(N), sl.Count(), "all N keys inserted")

	var violations int
	for _, res := range results {
		if res.cur == 0xFFFFFFFF {
			continue
		}
		key := sl.nodeKey(res.cur)
		if bytes.Compare(key, res.target[:]) < 0 {
			violations++
			if violations <= 5 {
				t.Errorf("concurrent Seek lower-bound violation: returned key < target (cur=0x%x)", res.cur)
			}
		}
	}
	require.Zero(t, violations, "every Seek result must be a valid lower-bound (returned key >= target) at the read moment")

	var quiescentViol int
	for _, res := range results {
		if res.cur == 0xFFFFFFFF {
			continue
		}
		finalCur := sl.Seek(res.target[:]).current
		if finalCur == 0xFFFFFFFF {
			quiescentViol++
			continue
		}
		if bytes.Compare(sl.nodeKey(finalCur), sl.nodeKey(res.cur)) > 0 {
			quiescentViol++
		}
	}
	require.Zero(t, quiescentViol, "quiescent re-check: final lower-bound <= moment lower-bound (monotone growth — keys only added)")
	t.Logf("concurrent Seek passed: %d readers x %d Seeks + %d Puts, 0 violations", M, seeksPerReader, N)
}

// BenchmarkSeekLogN and BenchmarkLinearScanLogN compare Seek against a linear
// scan over 131,072 keys using deterministic targets (seed 42). Seek traversal
// is capped by maxHeight = 11 levels. Run: go test -bench='Benchmark(Seek|Linear)LogN' ./internal/database/
func benchmarkBuild(b *testing.B, N int) (*SkipListArena, [][keySize]byte) {
	b.Helper()
	hash := entityHash("bench-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 64*1024*1024)
	for i := 0; i < N; i++ {
		k := buildKey(hash, int64(i), int64(i)*100, 0)
		if err := putKeyNoErr(sl, k); err != nil {
			b.Fatalf("bench Put: %v", err)
		}
	}
	rng := rand.New(rand.NewPCG(42, 0))
	targets := make([][keySize]byte, N)
	for i := range targets {
		targets[i] = buildKey(hash, rng.Int64N(int64(N)), rng.Int64N(int64(N)*100), rng.Int64N(1000))
	}
	return sl, targets
}

func BenchmarkSeekLogN(b *testing.B) {
	const N = 131072
	sl, targets := benchmarkBuild(b, N)
	defer sl.Free()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sl.Seek(targets[i%N][:])
	}
}

func BenchmarkLinearScanLogN(b *testing.B) {
	const N = 131072
	sl, targets := benchmarkBuild(b, N)
	defer sl.Free()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		target := targets[i%N][:]
		it := sl.NewIterator()
		for it.Valid() {
			if bytes.Compare(it.Key(), target) >= 0 {
				break
			}
			it.Next()
		}
		_ = it
	}
}
