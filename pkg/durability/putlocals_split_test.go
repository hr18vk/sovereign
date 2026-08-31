// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//putlocals_split_test.go — V2(a): DECOMPOSE THE
// COMMIT WINDOW. PutLocals (gossip.go:1101's batch path) = N × (sha256 +
// InsertLocal) + ONE AppendMutations (N writes + ONE fsync). This test measures
// each term at the gate's shape (10 workers × 100-key batches, 10,000 keys):
//
//	A = PutLocals total per-call wall (the production seam, measured directly)
//	B = AppendMutations-only per-call wall (prebuilt mutations, same concurrency)
//	C = the engine+encode term = A − B (DERIVED — stated as derived, not measured)
//	D = the raw fsync floor on the same filesystem (write 20 KB + Sync)
//
// The WAL/engine dir is_SPLIT_DIR (default t.TempDir()): on this box /tmp
// is tmpfs (fsync is a no-op), so the test is run twice — tmpfs and the ext4
// repo filesystem — and BOTH are reported; the fsync term is only real on ext4.
// A claim about "fsync-dominated" without naming the filesystem is not a number.
//
// Run: go test -run TestPutLocalsSplit -v -count=1./pkg/durability/
//_SPLIT_DIR=/path/to/an/ext4/dir \
// go test -run TestPutLocalsSplit -v -count=1./pkg/durability/

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

func splitTestDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("PUTLOCALS_SPLIT_DIR"); d != "" {
		p := filepath.Join(d, fmt.Sprintf("split-%d", time.Now().UnixNano()))
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", p, err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(p) })
		return p
	}
	return t.TempDir()
}

func TestPutLocalsSplit(t *testing.T) {
	dir := splitTestDir(t)
	const workers, callsPerWorker, batchSize = 10, 10, 100 // the gate's shape: 10,000 keys

	engDir := filepath.Join(dir, "eng")
	if err := os.MkdirAll(engDir, 0o755); err != nil {
		t.Fatalf("MkdirAll eng: %v", err)
	}
	eng.DataDir = engDir
	engine, err := eng.NewDeltaCRDTEngine([16]byte{0xF0, 0x9}, 1, 64*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	wal, err := OpenWAL(filepath.Join(dir, "split.wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer func() { _ = wal.Close() }()
	bridge := NewBridge(engine, wal, 0)

	mkItems := func(tag string, n int) []LocalItem {
		items := make([]LocalItem, n)
		for i := range items {
			items[i] = LocalItem{
				EntityID: fmt.Sprintf("split-%s-%d", tag, i),
				Payload:  fmt.Sprintf("payload-%010d", i),
				Entry:    eng.CRDTEntry{SystemTime: int64(1_700_200_000 + i), H3Index: uint64(i)},
			}
		}
		return items
	}

	// runPar drives workers×callsPerWorker concurrent calls of fn, returning all
	// per-call wall times.
	runPar := func(fn func(call int)) []time.Duration {
		var mu sync.Mutex
		var walls []time.Duration
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for c := 0; c < callsPerWorker; c++ {
					call := w*callsPerWorker + c
					t0 := time.Now()
					fn(call)
					mu.Lock()
					walls = append(walls, time.Since(t0))
					mu.Unlock()
				}
			}(w)
		}
		wg.Wait()
		return walls
	}

	// ── A: the full PutLocals seam ───────────────────────────────────────────
	wallA := runPar(func(call int) {
		if _, _, err := bridge.PutLocals(mkItems(fmt.Sprintf("a-%d", call), batchSize)); err != nil {
			t.Errorf("PutLocals call %d: %v", call, err)
		}
	})

	// ── B: AppendMutations only (prebuilt mutations; no engine work) ────────
	prebuilt := make([][]WALMutation, workers*callsPerWorker)
	for c := range prebuilt {
		ms := make([]WALMutation, batchSize)
		for i := range ms {
			ms[i] = NewWALMutation(
				fmt.Sprintf("split-b-%d-%d", c, i),
				eng.CausalDot{NodeID: [16]byte{0xF0, 0x9}, Counter: uint64(c*batchSize + i + 1)},
				eng.CRDTEntry{SystemTime: int64(1_700_200_000 + i)})
		}
		prebuilt[c] = ms
	}
	wallB := runPar(func(call int) {
		if _, err := wal.AppendMutations(prebuilt[call]); err != nil {
			t.Errorf("AppendMutations call %d: %v", call, err)
		}
	})

	// ── D: the raw fsync floor on THIS filesystem ───────────────────────────
	var fsyncWalls []time.Duration
	floorPath := filepath.Join(dir, "fsync-floor.bin")
	for i := 0; i < 100; i++ {
		f, err := os.OpenFile(floorPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			t.Fatalf("open floor: %v", err)
		}
		buf := make([]byte, 20*1024) // ~ a 100-entry batch's wire size
		if _, err := f.Write(buf); err != nil {
			t.Fatalf("write floor: %v", err)
		}
		t0 := time.Now()
		if err := f.Sync(); err != nil {
			t.Fatalf("sync floor: %v", err)
		}
		fsyncWalls = append(fsyncWalls, time.Since(t0))
		_ = f.Close()
	}

	pA := durStatsOf(wallA)
	pB := durStatsOf(wallB)
	pD := durStatsOf(fsyncWalls)
	t.Logf("V2(a) COMMIT-WINDOW SPLIT — dir=%s (filesystem per `df`), shape=%d workers × %d calls × %d keys:", dir, workers, callsPerWorker, batchSize)
	t.Logf(" A PutLocals total: p50=%s p99=%s max=%s (n=%d)", pA.p50, pA.p99, pA.max, len(wallA))
	t.Logf(" B AppendMutations only: p50=%s p99=%s max=%s (n=%d)", pB.p50, pB.p99, pB.max, len(wallB))
	t.Logf(" C engine+encode (A−B, DERIVED): p50=%s p99=%s", pA.p50-pB.p50, pA.p99-pB.p99)
	t.Logf(" D raw fsync floor (20KB write+Sync): p50=%s p99=%s max=%s", pD.p50, pD.p99, pD.max)
	t.Logf(" VERDICT HINT: if B≈A the window is WAL/fsync-dominated; if C≈A it is engine/CPU-dominated. State the filesystem next to the number.")
}

type durStats struct{ p50, p99, max time.Duration }

func durStatsOf(d []time.Duration) durStats {
	if len(d) == 0 {
		return durStats{}
	}
	s := make([]time.Duration, len(d))
	copy(s, d)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return durStats{p50: s[len(s)/2], p99: s[(len(s)*99)/100], max: s[len(s)-1]}
}
