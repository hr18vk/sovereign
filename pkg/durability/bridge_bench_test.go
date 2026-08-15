package durability

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	eng "github.com/hr18vk/supremum/pkg/sync"
)

// G08.g — LATENCY HONESTY. The bridge adds an AppendMutation fsync to the
// origin write path. The fsync cost is REAL; hiding it would fabricate
// durability. This bench measures PutLocal ns/op (InsertLocal + AppendMutation
// fsync) vs bare engine.InsertLocal ns/op, on the executor box (SCISSORS —
// NOT a 32c number). The honest delta = the production write-path latency
// price of fsync-per-mutation durability.
//
// Run: go test -bench=BenchmarkBridgePutLocal -benchmem -count=5 ./pkg/durability/
// The bench writes to a temp-file WAL (real fsync) so the number reflects the
// production cost, not a /dev/null sink.

// benchArenaSize is larger than the test arena (64MiB) because the bench runs
// to high b.N and the mmap arena is a bump allocator that does not reclaim
// EBR-retired nodes until Close. Each InsertLocal path-copies ~256B; a 64MiB
// arena fills at ~256k ops (the bench's typical max N). 1GiB handles ~4M ops,
// comfortably above the bench ceiling, so the per-op ns/op is measured without
// an arena-exhaustion panic. This is a bench-only knob; production sets the
// arena via --arena-mib.
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

// BenchmarkBridgePutLocal measures the durable write path: InsertLocal +
// AppendMutation (fsync). Compare against BenchmarkBareInsertLocal to read
// the fsync latency price.
//
// The bench reuses a bounded working set of entity IDs (the realistic
// steady-state pattern — a production node overwrites a bounded set of
// entities, it does not mint unbounded new ones) so the fixed 64MiB arena is
// not exhausted at high b.N. Each iteration overwrites entity (i % workingSet)
// with a fresh, strictly-higher dot, exactly as a live origin does.
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

// BenchmarkBareInsertLocal measures the in-memory write path (no WAL, no
// fsync) — the Day-7 baseline. The delta vs BenchmarkBridgePutLocal is the
// fsync latency price of durability.
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

// TestMain keeps the bench file from polluting the package's test binary with
// stray temp dirs when run as a plain test (no-op here; the bench funcs own
// their setup).
func TestMain(m *testing.M) { os.Exit(m.Run()) }
