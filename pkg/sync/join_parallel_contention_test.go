// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"fmt"
	"math"
	"runtime"
	"sync/atomic"
	"testing"
)

// benchParallelCRDTEngineArenaSize is calibrated separately from the serial
// Join benchmark so either workload can change its arena size independently.
// The serial benchmark reaches approximately 5.5M operations in 30 seconds:
// a 1 GiB arena panics near that point, while 2 GiB holds the fill/reclaim
// equilibrium. Parallel workers have comparable total operation volume, but
// the three-epoch EBR ring can hold retired roots from every worker at once.
// Distinct entity IDs partition their HAMT writes. A change to 2 GiB therefore
// needs a new measurement of the parallel workload, not just the serial result.
const benchParallelCRDTEngineArenaSize uintptr = 2 * 1024 * 1024 * 1024 // 2 GiB

// joinWorkerID assigns each benchmark worker a distinct entity-ID range.
// testing.PB has no worker index, so an atomic counter provides one when the
// worker starts. Disjoint IDs exercise HAMT growth rather than repeatedly
// contending on one shared leaf.
var joinWorkerID atomic.Uint64

// BenchmarkCRDTEngine_JoinParallel runs Join with distinct entity IDs and
// monotonically increasing dots per worker. The shared root CAS loop contends
// across workers, and every thousandth operation reaches the Lamport
// persistence path guarded by persistMu.
//
// DataDir points to b.TempDir() so persistLamport performs the same open,
// write, fsync, and rename sequence as production. A failed write to the
// default directory would release the mutex too quickly to measure its
// contention.
func BenchmarkCRDTEngine_JoinParallel(b *testing.B) {
	// Isolate DataDir so persistLamport performs real disk I/O (see comment).
	oldDir := DataDir
	DataDir = b.TempDir()
	b.Cleanup(func() { DataDir = oldDir })

	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, benchParallelCRDTEngineArenaSize)
	if err != nil {
		b.Fatal(err)
	}
	defer engine.Close()

	// Reset the per-bench worker ID mint so two benchmarking runs in one
	// process don't drift the divisor past modulo-256.
	joinWorkerID.Store(0)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Goroutine-local discriminators (race-clean; each goroutine writes
		// only its own locals — no shared atomics on the hot path).
		worker := uint8(joinWorkerID.Add(1))
		// Per-worker node ID so dots don't collide across workers and
		// AdvanceLamportTo's CAS actually advances (local-max monotone per
		// worker).
		var nodeID [16]byte
		nodeID[0] = worker + 2 // distinct from the engine's own [16]byte{1}

		var local uint64
		for pb.Next() {
			local++
			entityID := fmt.Sprintf("parallel-%d-%d", worker, local)
			entry := CRDTEntry{
				SystemTime:   int64(local),
				DotNodeID:    nodeID,
				DotCounter:   local,
				OriginNodeID: nodeID,
			}
			delta := CRDTDelta{
				OriginNodeID: nodeID,
				Entries:      makeSeq([]seqEntry{{entityID: entityID, entry: entry}}),
			}
			engine.Join(delta)
		}
	})
}

// joinMaxParallelGOMAXPROCS caps the contention curve at 32 workers or the
// number of available CPUs, whichever is smaller. The test reports both the
// requested and actual GOMAXPROCS values.
func joinMaxParallelGOMAXPROCS() int {
	n := runtime.NumCPU()
	if n > 32 {
		n = 32
	}
	return n
}

// joinContentionRatioThreshold separates a material slowdown from a workload
// that merely fails to accelerate. At or above 1.5, ns/op at maximum parallelism
// is at least 1.5 times the single-worker result. Shared-root CAS retries and
// Lamport persistence are possible contributors; the ratio alone does not
// identify a cause. The test reports the result without failing on either side.
const joinContentionRatioThreshold float64 = 1.5

// TestBenchArenaGreen runs BenchmarkCRDTEngine_Join with its calibrated 2 GiB
// arena and requires a finite, positive ns/op from at least one iteration. It
// catches an exhausted arena or aborted benchmark without imposing a throughput
// target. testing.Benchmark uses its default measurement window because the
// in-process harness cannot read the -benchtime command-line value.
func TestBenchArenaGreen(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the full Join bench; skip in -short")
	}
	res := testing.Benchmark(BenchmarkCRDTEngine_Join)
	if res.N <= 0 {
		t.Fatalf("BenchmarkCRDTEngine_Join did not run any iterations: N=%d (bench panicked or aborted)", res.N)
	}
	nsPerOp := float64(res.NsPerOp())
	if math.IsNaN(nsPerOp) || math.IsInf(nsPerOp, 0) || nsPerOp <= 0 {
		t.Fatalf("BenchmarkCRDTEngine_Join produced a non-finite ns/op: got %v (N=%d, T=%v) — the bench likely panicked before reporting a measured iteration count", nsPerOp, res.N, res.T)
	}
	t.Logf("BenchmarkCRDTEngine_Join: N=%d ns/op=%d B/op=%d allocs/op=%d arena=%d MiB",
		res.N, res.NsPerOp(), res.AllocedBytesPerOp(), res.AllocsPerOp(), int64(benchCRDTEngineArenaSize)/(1024*1024))
}

// joinRunParallelAt measures BenchmarkCRDTEngine_JoinParallel at p workers,
// restores the previous GOMAXPROCS value, and returns ns/op, the iteration
// count, and the actual worker setting.
func joinRunParallelAt(t *testing.T, p int) (nsPerOp float64, n int, gomaxprocs int) {
	t.Helper()
	prior := runtime.GOMAXPROCS(p)
	defer runtime.GOMAXPROCS(prior)
	res := testing.Benchmark(BenchmarkCRDTEngine_JoinParallel)
	if res.N <= 0 {
		t.Fatalf("BenchmarkCRDTEngine_JoinParallel @ GOMAXPROCS=%d did not run any iterations: N=%d (bench panicked or aborted)", p, res.N)
	}
	ns := float64(res.NsPerOp())
	if math.IsNaN(ns) || math.IsInf(ns, 0) || ns <= 0 {
		t.Fatalf("BenchmarkCRDTEngine_JoinParallel @ GOMAXPROCS=%d produced non-finite ns/op=%v (N=%d, T=%v)", p, ns, res.N, res.T)
	}
	return ns, res.N, runtime.GOMAXPROCS(0)
}

// TestJoinParallelContentionCurve measures the parallel Join benchmark at one
// worker and at joinMaxParallelGOMAXPROCS. It logs ns/op at both points and
// their ratio against joinContentionRatioThreshold. Either ratio is valid; the
// test fails only for an invalid measurement or a GOMAXPROCS mismatch.
func TestJoinParallelContentionCurve(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the parallel Join bench twice; skip in -short")
	}
	maxP := joinMaxParallelGOMAXPROCS()
	numCPU := runtime.NumCPU()
	t.Logf("runtime.NumCPU()=%d; maximum GOMAXPROCS=%d; threshold=%.2fx",
		numCPU, maxP, joinContentionRatioThreshold)
	if maxP > numCPU {
		t.Fatalf("joinMaxParallelGOMAXPROCS=%d exceeds runtime.NumCPU()=%d", maxP, numCPU)
	}
	if maxP < 1 {
		t.Fatalf("joinMaxParallelGOMAXPROCS=%d must be >= 1", maxP)
	}

	ns1, n1, gmp1 := joinRunParallelAt(t, 1)
	nsMax, nMax, gmpMax := joinRunParallelAt(t, maxP)

	ratio := nsMax / ns1 // >1 means parallelism regressed ns/op (contention signature)
	corroborated := ratio >= joinContentionRatioThreshold

	t.Logf("row: GOMAXPROCS=1    ns/op=%.2f N=%d (actual GOMAXPROCS=%d)", ns1, n1, gmp1)
	t.Logf("row: GOMAXPROCS=%-4d ns/op=%.2f N=%d (actual GOMAXPROCS=%d)", maxP, nsMax, nMax, gmpMax)
	t.Logf("ratio = ns/op@%d / ns/op@1 = %.4f / %.4f = %.2f", maxP, nsMax, ns1, ratio)
	t.Logf("threshold = %.2fx (named const joinContentionRatioThreshold)", joinContentionRatioThreshold)

	if corroborated {
		t.Logf("ratio at or above threshold: ns/op@%d=%.2f is at least %.2fx ns/op@1=%.2f. "+
			"Parallelism increased per-operation cost at this scale. "+
			"Shared-root CAS retries and Lamport persistence are possible contributors. "+
			"The measurement alone does not identify a cause; "+
			"profile those paths before changing them.",
			maxP, nsMax, joinContentionRatioThreshold, ns1)
	} else {
		t.Logf("ratio below threshold: ns/op@%d=%.2f is less than %.2fx ns/op@1=%.2f. "+
			"This measurement does not show a material parallel slowdown. "+
			"The ratio does not establish the reason; "+
			"%d workers remained below the selected threshold.",
			maxP, nsMax, joinContentionRatioThreshold, ns1, maxP)
	}

	// The ratio is informational. Only invalid measurements or a mismatch
	// between requested and actual parallelism fail the test.
	if gmp1 != 1 {
		t.Fatalf("GOMAXPROCS=1 row actually ran at GOMAXPROCS=%d", gmp1)
	}
	if gmpMax != maxP {
		t.Fatalf("GOMAXPROCS=%d row actually ran at GOMAXPROCS=%d", maxP, gmpMax)
	}
	t.Logf("ratio=%.2f threshold=%.2fx atOrAboveThreshold=%v",
		ratio, joinContentionRatioThreshold, corroborated)
}
