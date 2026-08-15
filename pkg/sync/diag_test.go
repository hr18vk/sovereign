package sync

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiagCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent cycle-detection stress in short mode.")
	}
	const numGoroutines = 64
	stack := NewEliminationStack()
	pool := NewElimNodePool(elimTestPoolSize)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := make(chan struct{})

	for gid := 0; gid < numGoroutines; gid++ {
		gid := gid
		go func() {
			defer wg.Done()
			prng := &ElimPRNG{}
			_ = prng.next()
			base := uint64(gid) * 1000
			var val uint64 = base
			deadline := time.Now().Add(elimTestDuration)
			for time.Now().Before(deadline) {
				v := base + (val % 1000)
				stack.push(pool, prng, v)
				stack.pop(pool, prng)
				val++
			}
		}()
	}
	close(start)
	wg.Wait()

	// Walk the central stack WITHOUT popping to detect cycles.
	// head and next are packed (generation, index) — unpack with elimIndex.
	head := stack.head.Load()
	visited := make(map[uint64]bool)
	count := 0
	for head != NullOffset64 {
		headIdx := elimIndex(head)
		if visited[headIdx] {
			t.Fatalf("CYCLE detected at index %d after %d nodes", headIdx, count)
		}
		visited[headIdx] = true
		count++
		if count > elimTestPoolSize+100 {
			t.Fatalf("stack too deep (%d), pool size=%d — likely cycle or corruption", count, elimTestPoolSize)
		}
		head = atomic.LoadUint64(&pool.nodes[headIdx].next)
	}
	fmt.Printf("Stack depth after quiescence: %d nodes, no cycle detected\n", count)

	// Now try draining with a bounded limit
	prng := &ElimPRNG{}
	_ = prng.next()
	var drained int
	for i := 0; i < elimTestPoolSize+1000; i++ {
		_, ok := stack.pop(pool, prng)
		if !ok {
			break
		}
		drained++
	}
	fmt.Printf("Drained: %d nodes\n", drained)
}
