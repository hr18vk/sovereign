// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// These benchmarks compare PutLocal, including its AppendMutation fsync, with
// bare engine.InsertLocal. Their difference measures the write-path latency of
// fsync-per-mutation durability on the host running the benchmark; it is not a
// 32-core fleet result.
//
// Run: go test -bench=BenchmarkBridgePutLocal -benchmem -count=5 ./pkg/durability/
// The WAL is a temporary file, so the benchmark performs real fsyncs rather
// than writing to a null sink.

// benchArenaSize accommodates high b.N values because the mmap arena is a bump
// allocator that does not reclaim EBR-retired nodes until Close. At roughly
// 256 bytes path-copied per InsertLocal, 64 MiB fills after about 256,000
// operations and 1 GiB after about 4 million. The larger arena avoids an
// exhaustion panic during a long benchmark. Production uses --arena-mib.
const benchArenaSize uintptr = 1024 * 1024 * 1024

func benchNodeID() [16]byte {
	var n [16]byte
	binary.BigEndian.PutUint64(n[:8], 0xdeadbeef)
	return n
}

func benchEntityID(i int) string {
	return fmt.Sprintf("bench-entity-%d", i)
}

func benchPayload(i int) string {
	// 64-byte payload (a realistic small event).
	b := make([]byte, 64)
	binary.BigEndian.PutUint64(b[:8], uint64(i))
	return string(b)
}

func benchEntry(i int) eng.CRDTEntry {
	var origin [16]byte
	binary.BigEndian.PutUint64(origin[:8], uint64(i))
	return eng.CRDTEntry{
		OriginNodeID: origin,
		SystemTime:   int64(i),
	}
}

// BenchmarkBridgePutLocal measures InsertLocal followed by an AppendMutation
// fsync. BenchmarkBareInsertLocal supplies the in-memory baseline.
//
// The benchmark reuses a bounded working set, as an origin overwriting an
// existing key space does. Each iteration writes entity i%workingSet with a
// fresh, strictly greater dot. The 1 GiB benchArenaSize leaves room for the
// path copies retained by this workload.
func BenchmarkBridgePutLocal(b *testing.B) {
	const workingSet = 4096
	walPath := filepath.Join(b.TempDir(), "bench.wal")
	eng.DataDir = b.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(benchNodeID(), 1, benchArenaSize)
	if err != nil {
		b.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()
	wal, err := OpenWAL(walPath)
	if err != nil {
		b.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()
	bridge := NewBridge(engine, wal, 0) // no periodic checkpoint — measure the per-mutation floor
	ids := make([]string, workingSet)
	for i := range ids {
		ids[i] = benchEntityID(i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := bridge.PutLocal(ids[i%workingSet], benchPayload(i), benchEntry(i)); err != nil {
			b.Fatalf("PutLocal %d: %v", i, err)
		}
	}
}

// BenchmarkBareInsertLocal measures InsertLocal with a payload digest but no
// WAL or fsync. Its difference from BenchmarkBridgePutLocal is the measured
// latency added by durable append.
func BenchmarkBareInsertLocal(b *testing.B) {
	const workingSet = 4096
	eng.DataDir = b.TempDir()
	engine, err := eng.NewDeltaCRDTEngine(benchNodeID(), 1, benchArenaSize)
	if err != nil {
		b.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	defer engine.Close()
	ids := make([]string, workingSet)
	for i := range ids {
		ids[i] = benchEntityID(i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		entry := benchEntry(i)
		entry.PayloadDigest = sha256.Sum256([]byte(benchPayload(i)))
		engine.InsertLocal(ids[i%workingSet], entry)
	}
}

// TestMain uses the default test runner. The benchmarks manage their own
// temporary directories through testing.B.
func TestMain(m *testing.M) { os.Exit(m.Run()) }
