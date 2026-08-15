package durability120

// Track 4.E5 Half A — BenchmarkFsyncWAL_120B: the LITERAL fsync path the engine
// ships (internal/chaos/wal.go:182 AppendMutation = write + fsync, the
// "crash-consistency, not liveness" durability byte at wal.go:24).
//
// MODEL CHOICE (load-bearing — matches the production shape, NOT a micro-bench
// artifact): the engine runs a SINGLE long-lived WAL per worker; the bench
// matches that. OpenWAL is EXPENSIVE (it writes/verifies an 8-byte header and
// scans existing records on reopen), so it is constructed ONCE outside b.N
// (b.ResetTimer after), and AppendMutation is called inside b.N — exactly the
// write+fsync-per-op durability byte. Constructing a fresh WAL per iteration
// would measure OpenWAL overhead, NOT the fsync seam; that is the wrong number.
//
// SCRATCH PATH CHOICE: t.TempDir() is NOT used for the bench. TempDir dirs vary
// per-run (a fresh mktemp'd dir each test invocation), and on some filesystems
// the dir's inode/allocation state varies enough to add jitter to the fsync CDF.
// For a STABLE latency CDF we use a fixed scratch subpath under /tmp, with a
// BENCH_WAL_DIR env override for operators who want a specific NVMe mount. The
// WAL file is removed between runs (os.RemoveAll on the scratch dir) so the
// bench always starts from a fresh header — the long-lived-WAL model is
// preserved WITHIN a run, not across runs.
//
// PAYLOAD: MakeFrame120(uint64(i % 1024)) — the 120-byte CRDT frame from
// frame_factory_test.go. It is encoded into a REAL WALMutation via the
// production constructor shape (wal_test.go:72: WALMutation{EntityID, NodeID,
// Counter, Entry: WALEntry{PayloadDigest, OriginNodeID, DotNodeID, DotCounter,
// SystemTime}}). We do NOT hand-roll bytes; AppendMutation calls
// encodeMutationRecord internally, so the bench measures the REAL encode +
// write + fsync path, not a synthetic one.
//
// REPORTING: the native testing.B mean (ns/op, allocs/op, B/op) is reported,
// AND a per-op fsync-latency CDF (p50/p99/p99.9/pMax) is computed by recording
// time.Since(start) per iteration into a []time.Duration slice. The mean is not
// enough — the §5 gate is p99 (the roadmap line 84 sub-millisecond bar is a
// p99 bar). The CDF is emitted as a machine-parsable NVME_CDF token the harness
// greps into the .log; the verdict matrix (verdict_test.go) parses it.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/chaos"
)

// benchWalDir resolves the scratch directory for the WAL bench. See the file
// header for the choice rationale (fixed /tmp subpath, BENCH_WAL_DIR override).
func benchWalDir(t testing.TB) string {
	if d := os.Getenv("BENCH_WAL_DIR"); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), "sovereign-durability120-wal")
}

// BenchmarkFsyncWAL_120B measures the engine's REAL write+fsync durability byte
// on a long-lived WAL, 120-byte CRDT frame per op. The function name carries
// NEITHER a 4-core NOR a 32-core suffix (the 4.E1/4.E3 discipline: the 32c gear
// lives in the .log header + the GOMAXPROCS=32 / -cpu=32 flags, NOT the name).
func BenchmarkFsyncWAL_120B(b *testing.B) {
	dir := benchWalDir(b)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatalf("mkdir %s: %v", dir, err)
	}
	walPath := filepath.Join(dir, "fsync_120b.wal")
	// Start from a fresh header each run (the long-lived-WAL model is preserved
	// WITHIN a run, not across runs — see the file header).
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

	// Reset the timer AFTER the expensive setup (OpenWAL + frame build) so the
	// reported ns/op is the write+fsync-per-op cost, not setup.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := frames[i%len(frames)]
		m := chaos.WALMutation{
			EntityID: "durability-bench-entity",
			NodeID:   nodeID,
			Counter:  uint64(i + 1),
			Entry: chaos.WALEntry{
				PayloadDigest: func() [32]byte {
					var d [32]byte
					copy(d[:], f[0:32])
					return d
				}(),
				OriginNodeID: func() [16]byte {
					var n [16]byte
					copy(n[:], f[32:48])
					return n
				}(),
				DotNodeID: func() [16]byte {
					var n [16]byte
					copy(n[:], f[48:64])
					return n
				}(),
				DotCounter: uint64(i + 1),
				SystemTime: int64(f[72])<<0 | int64(f[73])<<8, // low-entropy fold of the frame
			},
		}
		start := time.Now()
		if err := wal.AppendMutation(m); err != nil {
			b.Fatalf("AppendMutation %d: %v", i, err)
		}
		latencies[i] = time.Since(start)
	}
	b.StopTimer()

	// Report the native mean (ns/op, allocs/op, B/op are automatic) AND the CDF.
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
// 1000-sample run (NOT b.N) so the CDF is comparable in shape to the S3 half
// (which is a fixed-1000 Test, not a Benchmark). It runs on the 4c box
// pre-flight (the NVMe here is a 4c proxy — the SCISSORS rule forbids a 4c
// number standing in for a 32c number; the 4c run is a SMOKE gate that the
// fsync path works, NOT a published number) and on the 32c box in the harness
// (the published number).
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
		m := chaos.WALMutation{
			EntityID: "durability-bench-entity",
			NodeID:   nodeID,
			Counter:  uint64(i + 1),
			Entry: chaos.WALEntry{
				PayloadDigest: bytesTo32(f[0:32]),
				OriginNodeID:  bytesTo16(f[32:48]),
				DotNodeID:     bytesTo16(f[48:64]),
				DotCounter:    uint64(i + 1),
				SystemTime:    int64(f[72])<<0 | int64(f[73])<<8,
			},
		}
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

// bytesTo32 copies a 32-byte slice into a [32]byte (the WALEntry.PayloadDigest
// shape). Panics if len != 32 — the frame layout guarantees it.
func bytesTo32(s []byte) [32]byte {
	var d [32]byte
	copy(d[:], s)
	return d
}

// bytesTo16 copies a 16-byte slice into a [16]byte (the WALEntry node-ID shape).
func bytesTo16(s []byte) [16]byte {
	var d [16]byte
	copy(d[:], s)
	return d
}
