// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// These tests and benchmarks measure heap allocations in HAMT.Set.
// TestHotPathZeroAllocations uses testing.AllocsPerRun and fails when the
// measured closure performs any heap allocation. BenchmarkHAMTInsertZeroAlloc
// supports profiling with Go's benchmark tooling.
//
// Keys are unique eight-byte values written into a reusable stack buffer and
// viewed through unsafe.String. Set copies the bytes into the arena before it
// returns, so the next iteration may overwrite the buffer. Reusing the buffer
// and entry slice keeps key construction out of the allocation measurement.
// Enough keys are inserted to exercise hash collisions as well as ordinary
// insertion.
//
// The benchmark retires each previous HAMT and advances the EBR epoch, matching
// InsertLocal's reclamation path and allowing arena storage to be recycled. It
// reserves a 2 GB arena for arbitrary benchmark iteration counts. The
// allocation test uses 1,000 iterations in a 512 MB arena and does not need
// retirement within that bound.

// makeBinaryKey returns a string backed by the caller's stack buffer. The
// caller must not retain it beyond the buffer's next overwrite. Set satisfies
// that constraint because makeLeaf copies the bytes through arena.allocString
// before returning.
func makeBinaryKey(buf *[8]byte, v uint64) string {
	binary.LittleEndian.PutUint64(buf[:], v)
	return unsafe.String(&buf[0], 8)
}

// allocTestArena constructs an EBR manager and a 512 MB anonymous private
// mapping. Virtual address space is reserved up front; physical pages are
// allocated only when touched.
func allocTestArena(b testing.TB) *HamtArena {
	return allocTestArenaSized(b, 512*1024*1024)
}

// allocTestArenaSized constructs an EBR manager and an anonymous private
// mapping of the requested size, releasing the mapping during test cleanup.
func allocTestArenaSized(b testing.TB, size uintptr) *HamtArena {
	arena, err := NewHamtArena(size, NewEBRManager())
	if err != nil {
		b.Fatalf("NewHamtArena: %v", err)
	}
	b.Cleanup(func() {
		if err := arena.Free(); err != nil {
			b.Errorf("arena.Free: %v", err)
		}
	})
	return arena
}

// warmEBRPool initializes participant and retired-node pool entries before the
// allocation measurement. Otherwise their first-use allocations would be
// attributed to the measured Set calls.
func warmEBRPool(arena *HamtArena) {
	eb := arena.ebr
	// Materialize & return one Participant slot.
	p := eb.Acquire()
	eb.Release(p)
	// Initialize retiredPool as well, so its lazy allocation does not occur in
	// the first measured Set. Do not retire a stack pointer: type 0 entries are
	// interpreted as HAMT wrappers and would pass a non-arena address to
	// freeHAMTWrapper. Pool warmup alone initializes the lazy paths.
	_ = eb.retiredPool.Get()
	eb.retiredPool.Put(&RetiredNode{})
}

// BenchmarkHAMTInsertZeroAlloc exercises HAMT.Set with unique stack-backed
// keys and one reused entries slice. Run it with
// `go test -bench=BenchmarkHAMTInsertZeroAlloc -benchmem`.
//
// Path copying consumes approximately 1,300 arena bytes per operation. Without
// retirement, 500,000 iterations would require about 650 MB. Retiring each old
// HAMT and advancing the epoch recycles those nodes through pooled RetiredNode
// values without adding heap allocations to the measured loop.
func BenchmarkHAMTInsertZeroAlloc(b *testing.B) {
	arena := allocTestArenaSized(b, 2*1024*1024*1024)
	h := NewHAMT(arena)
	warmEBRPool(arena)

	entries := make([]CRDTEntry, 1)
	entries[0].DotCounter = 1

	b.ReportAllocs()
	b.ResetTimer()

	var keyBuf [8]byte
	for i := 0; i < b.N; i++ {
		key := makeBinaryKey(&keyBuf, uint64(i))
		prev := h
		h = h.Set(key, entries)
		// Retire the previous HAMT wrapper via EBR — zero heap allocations.
		// This mirrors DeltaCRDTEngine.InsertLocal's reclamation contract:
		// old state is retired and epoch is advanced, allowing EBR's
		// three-epoch ring buffer to physically recycle slab offsets.
		arena.ebr.Retire(unsafe.Pointer(prev))
		arena.ebr.AdvanceEpoch()
	}
}

// TestHotPathZeroAllocations measures 1,000 Set calls with
// testing.AllocsPerRun. Unique keys exercise ordinary insertion and collisions
// in the 32-slot root. The reported average must be zero.
func TestHotPathZeroAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("race-detector instrumentation perturbs " +
			"testing.AllocsPerRun by adding shadow-memory " +
			"bookkeeping around pointer and length conversions, including " +
			"unsafe.String in makeBinaryKey. These allocations belong to " +
			"the race detector rather than HAMT.Set, so this test runs " +
			"only without -race. The ordinary build retains the " +
			"zero-allocation assertion. Race-enabled runs retain " +
			"the separate concurrency checks while skipping " +
			"only this instrument-sensitive measurement.")
	}
	arena := allocTestArena(t)
	h := NewHAMT(arena)
	warmEBRPool(arena)

	// entries must be reused, not re-allocated inside the closure.
	entries := make([]CRDTEntry, 1)
	entries[0].DotCounter = 1

	// Counter is captured by the closure — lives on the goroutine stack.
	i := uint64(0)
	var keyBuf [8]byte

	// Average over enough calls to smooth per-iteration scheduling variation.
	const iterations = 1000

	allocs := testing.AllocsPerRun(iterations, func() {
		key := makeBinaryKey(&keyBuf, i)
		h = h.Set(key, entries)
		i++
	})

	if allocs != 0 {
		t.Fatalf(
			"HAMT.Set allocated on the Go heap: "+
				"got %v allocations per operation, want 0 "+
				"(iterations=%d, measured average=%v)",
			allocs, iterations, allocs,
		)
	}
}

// The false-sharing benchmarks update two atomic counters from separate
// goroutines. In unpaddedCounters both fields share a 64-byte cache line, so
// writes contend for ownership of that line. CacheLinePad separates the fields
// in paddedCounters, allowing the counters to remain in different lines.
// Comparing their throughput measures the cost of that coherence traffic.
//
// Run with `go test -bench=BenchmarkFalseSharing -benchmem ./pkg/sync/`.

// unpaddedCounters has two atomic counters on the same cache line.
// sizeof = 16 bytes → both fit in a single 64-byte L1 cache line.
type unpaddedCounters struct {
	counter0 atomic.Uint64
	counter1 atomic.Uint64
}

// paddedCounters isolates each counter on its own cache line.
// sizeof = 144 bytes → counter0 on line 0, counter1 on line 2.
type paddedCounters struct {
	_        CacheLinePad
	counter0 atomic.Uint64
	_        CacheLinePad
	counter1 atomic.Uint64
	_        CacheLinePad
}

const falseSharingItersPerGoroutine = 1_000_000

// BenchmarkFalseSharingUnpadded updates two counters on one cache line from
// two goroutines. Writes by either goroutine can invalidate the other core's
// copy, adding coherence transfers to each update.
func BenchmarkFalseSharingUnpadded(b *testing.B) {
	c := &unpaddedCounters{}
	var wg sync.WaitGroup
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < falseSharingItersPerGoroutine; j++ {
				c.counter0.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < falseSharingItersPerGoroutine; j++ {
				c.counter1.Add(1)
			}
		}()
		wg.Wait()
	}
}

// BenchmarkFalseSharingPadded repeats the workload with counters separated by
// padding, so updates to one counter do not invalidate the other counter's
// cache line.
func BenchmarkFalseSharingPadded(b *testing.B) {
	c := &paddedCounters{}
	var wg sync.WaitGroup
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < falseSharingItersPerGoroutine; j++ {
				c.counter0.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < falseSharingItersPerGoroutine; j++ {
				c.counter1.Add(1)
			}
		}()
		wg.Wait()
	}
}

// TestFalseSharingProof compares the padded and unpadded counter workloads.
// It skips when fewer than two threads can run concurrently and fails when the
// padded variant takes more than 110% of the unpadded time. The tolerance
// accommodates scheduler noise; equal timings still pass.
func TestFalseSharingProof(t *testing.T) {
	if testing.Short() {
		t.Skip("skip the cache-coherence benchmark in short mode")
	}
	// Skip if GOMAXPROCS < 2 — false sharing requires multiple cores.
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("Skipping false sharing proof: GOMAXPROCS < 2, no multi-core contention possible")
	}

	unpaddedResult := testing.Benchmark(BenchmarkFalseSharingUnpadded)
	paddedResult := testing.Benchmark(BenchmarkFalseSharingPadded)

	unpaddedNs := float64(unpaddedResult.NsPerOp())
	paddedNs := float64(paddedResult.NsPerOp())

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  False sharing: cache-coherence benchmark                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Unpadded (false sharing):  %12.1f ns/op\n", unpaddedNs)
	fmt.Printf("  Padded   (no false share): %12.1f ns/op\n", paddedNs)
	fmt.Printf("  Speedup ratio:             %12.2fx\n", unpaddedNs/paddedNs)
	fmt.Printf("  GOMAXPROCS:                 %12d\n", runtime.GOMAXPROCS(0))
	fmt.Printf("  sizeof(unpaddedCounters):   %12d bytes\n", unsafe.Sizeof(unpaddedCounters{}))
	fmt.Printf("  sizeof(paddedCounters):     %12d bytes\n", unsafe.Sizeof(paddedCounters{}))
	fmt.Printf("  CacheLinePad size:          %12d bytes\n", unsafe.Sizeof(CacheLinePad{}))
	fmt.Println()

	// Allow 10% for scheduler noise, but reject a larger padded-time regression.
	if paddedNs > unpaddedNs*1.10 {
		t.Errorf(
			"padded counters took %.1f ns/op versus "+
				"%.1f ns/op unpadded, exceeding the 10%% tolerance. "+
				"Check the cache-line separation and measurement conditions.\n"+
				"  Speedup: %.2fx (expected > 1.0x)\n"+
				"  GOMAXPROCS: %d",
			paddedNs, unpaddedNs, unpaddedNs/paddedNs, runtime.GOMAXPROCS(0),
		)
	}

	if unpaddedNs > paddedNs {
		t.Logf(
			"cache-line padding improved counter throughput "+
				"by %.2fx (%.1f → %.1f ns/op)",
			unpaddedNs/paddedNs, unpaddedNs, paddedNs,
		)
	}
}

// Engine-proxy benchmarks apply the same comparison to groups of atomic fields
// arranged like the engine's hot counters. Run them with
// `go test -bench=BenchmarkEngineProxy -benchmem ./pkg/sync/`.

// unpaddedEngineProxy groups engine-like state, Lamport, persistence, epoch,
// and metric counters without cache-line padding. It provides a comparison
// workload; it does not execute DeltaCRDTEngine.InsertLocal.
type unpaddedEngineProxy struct {
	state            atomic.Uint64
	lamportCounter   atomic.Uint64
	lastSavedCounter atomic.Uint64
	epochCounter     atomic.Uint64
	deltasGenerated  atomic.Uint64
	deltasApplied    atomic.Uint64
	entriesInserted  atomic.Uint64
	entriesSkipped   atomic.Uint64
}

// paddedEngineProxy separates the engine-like atomic fields with CacheLinePad
// so independent updates do not share cache lines unnecessarily.
type paddedEngineProxy struct {
	_                CacheLinePad
	state            atomic.Uint64
	_                CacheLinePad
	lamportCounter   atomic.Uint64
	lastSavedCounter atomic.Uint64
	_                CacheLinePad
	epochCounter     atomic.Uint64
	_                CacheLinePad
	deltasGenerated  atomic.Uint64
	deltasApplied    atomic.Uint64
	entriesInserted  atomic.Uint64
	entriesSkipped   atomic.Uint64
	_                CacheLinePad
}

const engineProxyIters = 500_000

// BenchmarkEngineProxyUnpadded updates the unpadded proxy from two goroutines,
// concentrating their writes on shared cache lines.
func BenchmarkEngineProxyUnpadded(b *testing.B) {
	e := &unpaddedEngineProxy{}
	var wg sync.WaitGroup
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < engineProxyIters; j++ {
				e.state.Add(1)
				e.deltasGenerated.Add(1)
				e.entriesInserted.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < engineProxyIters; j++ {
				e.lamportCounter.Add(1)
				e.epochCounter.Add(1)
				e.deltasApplied.Add(1)
			}
		}()
		wg.Wait()
	}
}

// BenchmarkEngineProxyPadded repeats the proxy updates with cache-line padding
// between the hot fields.
func BenchmarkEngineProxyPadded(b *testing.B) {
	e := &paddedEngineProxy{}
	var wg sync.WaitGroup
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < engineProxyIters; j++ {
				e.state.Add(1)
				e.deltasGenerated.Add(1)
				e.entriesInserted.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < engineProxyIters; j++ {
				e.lamportCounter.Add(1)
				e.epochCounter.Add(1)
				e.deltasApplied.Add(1)
			}
		}()
		wg.Wait()
	}
}

// TestEngineProxyFalseSharingProof applies the same 110% tolerance to the
// engine-proxy workloads. It reports their timings and struct sizes and skips
// when concurrent execution is unavailable.
func TestEngineProxyFalseSharingProof(t *testing.T) {
	if testing.Short() {
		t.Skip("skip the cache-coherence benchmark in short mode")
	}
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("Skipping engine proxy proof: GOMAXPROCS < 2")
	}

	unpaddedResult := testing.Benchmark(BenchmarkEngineProxyUnpadded)
	paddedResult := testing.Benchmark(BenchmarkEngineProxyPadded)

	unpaddedNs := float64(unpaddedResult.NsPerOp())
	paddedNs := float64(paddedResult.NsPerOp())

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Engine proxy: cache-coherence benchmark                        ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Unpadded engine proxy:  %12.1f ns/op\n", unpaddedNs)
	fmt.Printf("  Padded engine proxy:    %12.1f ns/op\n", paddedNs)
	fmt.Printf("  Speedup ratio:          %12.2fx\n", unpaddedNs/paddedNs)
	fmt.Printf("  sizeof(unpaddedEngineProxy): %8d bytes\n", unsafe.Sizeof(unpaddedEngineProxy{}))
	fmt.Printf("  sizeof(paddedEngineProxy):  %8d bytes\n", unsafe.Sizeof(paddedEngineProxy{}))
	fmt.Println()

	// The proxy comparison uses the same 10% tolerance as the counter workload.
	if paddedNs > unpaddedNs*1.10 {
		t.Errorf(
			"padded engine proxy took %.1f ns/op versus "+
				"%.1f ns/op unpadded, exceeding the 10%% tolerance (speedup %.2fx)",
			paddedNs, unpaddedNs, unpaddedNs/paddedNs,
		)
	}

	if unpaddedNs > paddedNs {
		t.Logf(
			"cache-line padding improved engine-proxy throughput by %.2fx "+
				"(%.1f → %.1f ns/op)",
			unpaddedNs/paddedNs, unpaddedNs, paddedNs,
		)
	}
}
