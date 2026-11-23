// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability120

// BenchmarkFsyncWAL_120B measures the engine's write+fsync durability path
// on a long-lived WAL with a 120-byte CRDT frame per operation.
//
// The engine runs a single long-lived WAL per worker; the benchmark matches
// that model. OpenWAL writes and verifies an 8-byte header and scans existing
// records on reopen, so it is constructed once outside b.N (b.ResetTimer is
// called after) and AppendMutation is called inside b.N — exactly the
// write+fsync-per-op durability path. Constructing a fresh WAL per iteration
// would measure OpenWAL overhead, not the fsync seam.
//
// The benchmark uses a fixed scratch subpath under os.TempDir() rather than
// t.TempDir(). TempDir directories vary per run (a fresh mktemp directory each
// invocation), and on some filesystems the directory's inode and allocation
// state varies enough to add jitter to the fsync CDF. For a stable latency CDF
// we use a fixed path with a BENCH_WAL_DIR environment override for operators
// who want a specific NVMe mount. The WAL file is removed between runs so the
// benchmark always starts from a fresh header — the long-lived-WAL model is
// preserved within a run, not across runs.
//
// PAYLOAD: MakeFrame120(uint64(i % 1024)) — the 120-byte CRDT frame from
// frame_factory_test.go. It is encoded into a WALMutation via the production
// constructor (chaos.NewWALMutation with a CRDTEntry built by frameToEntry).
// AppendMutation calls encodeMutationRecord internally, so the benchmark
// measures the real encode + write + fsync path, not a synthetic one.
//
// REPORTING: the native testing.B mean (ns/op, allocs/op, B/op) is reported,
// and a per-op fsync-latency CDF (p50/p99/p99.9/pMax) is computed by recording
// time.Since(start) per iteration into a []time.Duration slice. The mean alone
// is not enough — the sub-millisecond threshold is a p99 bar. The CDF is
// emitted as a machine-parsable NVME_CDF token that the harness extracts from
// the log; the verdict matrix parses it.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/chaos"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// benchWalDir resolves the scratch directory for the WAL bench. See the file
// header for the choice rationale (fixed /tmp subpath, BENCH_WAL_DIR override).
func benchWalDir(t testing.TB) string {
	if d := os.Getenv("BENCH_WAL_DIR"); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), "sovereign-durability120-wal")
}

// BenchmarkFsyncWAL_120B measures the engine's write+fsync durability path
// on a long-lived WAL with a 120-byte CRDT frame per operation. The function
// name carries no core-count suffix; the 32-core configuration lives in the
// log header and the GOMAXPROCS=32 / -cpu=32 flags, not the name.
func BenchmarkFsyncWAL_120B(b *testing.B) {
	dir := benchWalDir(b)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatalf("mkdir %s: %v", dir, err)
	}
	walPath := filepath.Join(dir, "fsync_120b.wal")
	// Start from a fresh header each run (the long-lived-WAL model is preserved
	// within a run, not across runs — see the file header).
	_ = os.Remove(walPath)

	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		b.Fatalf("OpenWAL: %v", err)
	}
	b.Cleanup(func() {
		_ = wal.Close()
		_ = os.RemoveAll(dir)
	})

	// A stable node identity for the WALMutation.NodeID (the bench measures
	// fsync latency, not node-id entropy; a fixed 16-byte id is the production
	// shape — one worker = one node id).
	var nodeID [16]byte
	nodeID[0] = 0x5A // "Z" — a representative fixed node id

	// Pre-build the 1024 distinct frames ONCE (i % 1024 inside b.N reuses them).
	// Building per-op would measure the PRNG, not the fsync.
	frames := make([][frameSize]byte, 1024)
	for i := range frames {
		frames[i] = MakeFrame120(uint64(i))
	}

	// Per-op latency samples for the CDF. Allocated once (not per-op) so it does
	// not perturb the allocs/op metric.
	latencies := make([]time.Duration, b.N)

	// Reset the timer after the setup (OpenWAL + frame build) so the
	// reported ns/op is the write+fsync-per-op cost, not setup.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := frames[i%len(frames)]
		m := chaos.NewWALMutation("durability-bench-entity",
			eng.CausalDot{NodeID: nodeID, Counter: uint64(i + 1)},
			frameToEntry(f))
		start := time.Now()
		if err := wal.AppendMutation(m); err != nil {
			b.Fatalf("AppendMutation %d: %v", i, err)
		}
		latencies[i] = time.Since(start)
	}
	b.StopTimer()

	// Report the native mean (ns/op, allocs/op, B/op are automatic) and the CDF.
	cdf := computeCDF(latencies)
	b.ReportMetric(float64(cdf.p50.Nanoseconds()), "p50_ns/op")
	b.ReportMetric(float64(cdf.p99.Nanoseconds()), "p99_ns/op")
	b.ReportMetric(float64(cdf.p999.Nanoseconds()), "p99.9_ns/op")
	b.ReportMetric(float64(cdf.pMax.Nanoseconds()), "pMax_ns/op")
	// Machine-parsable token the harness greps into the .log (the verdict matrix
	// parses it). Single line, fixed key order.
	b.Logf("NVME_CDF p50=%dns p99=%dns p99.9=%dns pMax=%dns n=%d",
		cdf.p50.Nanoseconds(), cdf.p99.Nanoseconds(),
		cdf.p999.Nanoseconds(), cdf.pMax.Nanoseconds(), len(latencies))
}

// TestFsyncWAL_CDF is the non-Benchmark entry point for the NVMe CDF: a fixed
// 1000-sample run so the CDF is comparable in shape to the S3 Express test
// (which is also a fixed-1000 test, not a benchmark). It runs on the 4-core
// box as a pre-flight check (the NVMe here is a 4-core proxy; a 4-core number
// does not stand in for a 32-core number; the 4-core run is a smoke check that
// the fsync path works, not a published number) and on the 32-core box in the
// harness (the published number).
func TestFsyncWAL_CDF(t *testing.T) {
	const n = 1000
	dir := benchWalDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	walPath := filepath.Join(dir, "fsync_cdf.wal")
	_ = os.Remove(walPath)

	wal, err := chaos.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	t.Cleanup(func() {
		_ = wal.Close()
		_ = os.RemoveAll(dir)
	})

	var nodeID [16]byte
	nodeID[0] = 0x5A
	frames := make([][frameSize]byte, 1024)
	for i := range frames {
		frames[i] = MakeFrame120(uint64(i))
	}

	latencies := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		f := frames[i%len(frames)]
		m := chaos.NewWALMutation("durability-bench-entity",
			eng.CausalDot{NodeID: nodeID, Counter: uint64(i + 1)},
			frameToEntry(f))
		start := time.Now()
		if err := wal.AppendMutation(m); err != nil {
			t.Fatalf("AppendMutation %d: %v", i, err)
		}
		latencies[i] = time.Since(start)
	}

	cdf := computeCDF(latencies)
	t.Logf("NVME_CDF p50=%dns p99=%dns p99.9=%dns pMax=%dns n=%d",
		cdf.p50.Nanoseconds(), cdf.p99.Nanoseconds(),
		cdf.p999.Nanoseconds(), cdf.pMax.Nanoseconds(), n)
}
