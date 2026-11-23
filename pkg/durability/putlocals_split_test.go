// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// TestPutLocalsSplit separates the batch commit path into engine work, WAL
// append work, and the filesystem sync cost. With 10 workers and 100-key
// batches, it measures:
//
//	A: total PutLocals latency.
//	B: AppendMutations latency for prebuilt mutations at the same concurrency.
//	C: engine and encoding time, derived as A minus B rather than measured.
//	D: sync latency after writing a 20 KB file on the same filesystem.
//
// SOVEREIGN_TEST_SPLIT_DIR selects the WAL and engine directory; the default
// is t.TempDir(). Sync behavior depends on the filesystem, so measurements from
// different filesystems must be reported separately. On tmpfs, for example,
// fsync does not represent persistent-disk latency.
//
// Run: go test -run TestPutLocalsSplit -v -count=1 ./pkg/durability/
//      SOVEREIGN_TEST_SPLIT_DIR=/path/to/filesystem/tmp \
//        go test -run TestPutLocalsSplit -v -count=1 ./pkg/durability/

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

func splitDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("SOVEREIGN_TEST_SPLIT_DIR"); d != "" {
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
	dir := splitDir(t)
	const workers, callsPerWorker, batchSize = 10, 10, 100 // 10,000 keys total

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

	// A: full PutLocals calls.
	wallA := runPar(func(call int) {
		if _, _, err := bridge.PutLocals(mkItems(fmt.Sprintf("a-%d", call), batchSize)); err != nil {
			t.Errorf("PutLocals call %d: %v", call, err)
		}
	})

	// B: AppendMutations alone, excluding engine work.
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

	// D: raw sync latency on this filesystem.
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

	pA := collectSplitStats(wallA)
	pB := collectSplitStats(wallB)
	pD := collectSplitStats(fsyncWalls)
	t.Logf("commit-window split — dir=%s (filesystem per `df`), shape=%d workers × %d calls × %d keys:", dir, workers, callsPerWorker, batchSize)
	t.Logf("  A PutLocals total:        p50=%s p99=%s max=%s (n=%d)", pA.p50, pA.p99, pA.max, len(wallA))
	t.Logf("  B AppendMutations only:   p50=%s p99=%s max=%s (n=%d)", pB.p50, pB.p99, pB.max, len(wallB))
	t.Logf("  C engine+encode (A−B, derived): p50=%s p99=%s", pA.p50-pB.p50, pA.p99-pB.p99)
	t.Logf("  D raw fsync floor (20KB write+Sync): p50=%s p99=%s max=%s", pD.p50, pD.p99, pD.max)
	t.Logf("  interpretation: B near A indicates WAL/sync dominance; C near A indicates engine/CPU dominance. Report the filesystem with these timings.")
}

type splitStat struct{ p50, p99, max time.Duration }

func collectSplitStats(d []time.Duration) splitStat {
	if len(d) == 0 {
		return splitStat{}
	}
	s := make([]time.Duration, len(d))
	copy(s, d)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return splitStat{p50: s[len(s)/2], p99: s[(len(s)*99)/100], max: s[len(s)-1]}
}
