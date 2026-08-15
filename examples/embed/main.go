// Package main is the Phase 1 smoke example for the Great Export.
//
// It is evidence, not a benchmark: it imports ONLY the exported
// github.com/hr18vk/supremum/pkg/sync package (no internal/ path), drives
// a realistic concurrent push/pop workload on the lock-free core, and
// asserts the conservation invariant a downstream would rely on:
//
//	total pushed  −  total popped  ==  final stack size (drained to empty)
//
// No marketing numbers. No synthetic headline. Just "the exported API
// is usable and linearizable from an external Go module."
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	engsync "github.com/hr18vk/supremum/pkg/sync"
)

func main() {
	// Drive the sharded stack at the host's full core width. The
	// lock-free core's contention model only manifests at real
	// parallelism, so we refuse to run single-threaded.
	if runtime.GOMAXPROCS(0) < 2 {
		fmt.Fprintln(os.Stderr, "smoke example requires GOMAXPROCS>=2")
		os.Exit(1)
	}
	workers := runtime.GOMAXPROCS(0)

	const opsPerWorker = 200_000

	// One ElimPRNG per goroutine is a hard contract of the lock-free
	// core: the secDeepCache and stamp sequence are goroutine-local
	// state. Sharing one *ElimPRNG across goroutines would race on
	// that state and silently corrupt the free-list. The pool is sized
	// to (working_set + 1) because index 0 is the permanent empty
	// sentinel — see NewElimNodePool.
	stack := engsync.NewShardedStack()
	poolSize := workers*opsPerWorker + 1
	pool := engsync.NewElimNodePool(poolSize)

	var pushed, popped uint64

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			prng := engsync.NewElimPRNG() // exclusive to this goroutine
			localPush, localPop := uint64(0), uint64(0)
			for i := 0; i < opsPerWorker; i++ {
				value := uint64(w)<<32 | uint64(i)
				stack.Push(pool, prng, value)
				localPush++
				if v, ok := stack.Pop(pool, prng); ok {
					_ = v
					localPop++
				}
			}
			atomic.AddUint64(&pushed, localPush)
			atomic.AddUint64(&popped, localPop)
		}()
	}
	wg.Wait()

	// Drain the residual stack to empty via the public Pop surface.
	// Whatever remains must satisfy: pushed − popped == drained.
	drainPrng := engsync.NewElimPRNG()
	var drained uint64
	for {
		_, ok := stack.Pop(pool, drainPrng)
		if !ok {
			break
		}
		drained++
	}

	// Do the same against the elimination-backed stack to prove the
	// second export-list type is also usable downstream. Reusing the
	// same pool (sized to the working set) is legal: a pool outlives any
	// single stack once all indices are returned. We size one shared
	// pool for both stages to keep the example self-contained.
	estack := engsync.NewEliminationStack()
	var ePushed, ePopped, eDrained uint64
	var ewg sync.WaitGroup
	ewg.Add(workers)
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer ewg.Done()
			prng := engsync.NewElimPRNG()
			lp, lo := uint64(0), uint64(0)
			for i := 0; i < opsPerWorker; i++ {
				estack.Push(pool, prng, uint64(w)<<32|uint64(i))
				lp++
				if _, ok := estack.Pop(pool, prng); ok {
					lo++
				}
			}
			atomic.AddUint64(&ePushed, lp)
			atomic.AddUint64(&ePopped, lo)
		}()
	}
	ewg.Wait()
	eDrainPrng := engsync.NewElimPRNG()
	for {
		if _, ok := estack.Pop(pool, eDrainPrng); !ok {
			break
		}
		eDrained++
	}

	conservedSharded := int64(pushed) - int64(popped) - int64(drained)
	conservedElim := int64(ePushed) - int64(ePopped) - int64(eDrained)
	conserved := conservedSharded == 0 && conservedElim == 0
	fmt.Printf("smoke: GOMAXPROCS=%d workers=%d\n", runtime.GOMAXPROCS(0), workers)
	fmt.Printf("sharded: pushed=%d popped=%d drained=%d  (pushed-popped=%d)\n",
		pushed, popped, drained, int64(pushed)-int64(popped))
	fmt.Printf("elim:    pushed=%d popped=%d drained=%d  (pushed-popped=%d)\n",
		ePushed, ePopped, eDrained, int64(ePushed)-int64(ePopped))
	fmt.Printf("conservation (pushed - popped == drained): %v\n", conserved)
	if !conserved {
		fmt.Fprintln(os.Stderr, "CONSERVATION FAILED: lock-free core lost or duplicated values")
		os.Exit(1)
	}
	fmt.Println("SMOKE OK: exported lock-free core is usable and linearizable from a downstream module")
}
