// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//checkpoint_concurrency_test.go — the guards (ADR-0045): T7, T8,
// T17 — the checkpoint race, the anchor-mismatch loud fallback, and the
// exact-count contract. T16 (the 503-on-durable-write guard) lives in
//checkpoint_failure_ack_test.go: it references-only bridge API and must be
// movable aside for the T7/T17 HEAD-revert RED.
//
// T7/T17 REDs are HEAD-reverts of bridge.go (+ the wal.go, commit
// e274a90, for API compatibility): HEAD's non-atomic mutationsSinceCkpt with
// the post-body reset stampedes (13 checkpoints for 10 crossings measured) and
// loses updates; the -race detector convicts it directly for T7. T8's RED is a
// bug-inject on the new mechanism, named in its doc comment.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// countCheckpoints walks the RAW WAL bytes (the code under test is never its
// own check) and returns the number of WALRecCheckpoint (0x02) + WALRecCheckpointV2 (0x05) records — the
// exact checkpoint count, which Replayed structurally cannot report (it keeps
// only FinalCheckpt).
func countCheckpoints(t *testing.T, walPath string) int {
	t.Helper()
	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("read WAL %s: %v", walPath, err)
	}
	if len(data) < 8 {
		t.Fatalf("WAL %s too short for the file header", walPath)
	}
	count := 0
	for off := 8; off < len(data); {
		// (C1): records are now 0x06 CRC-framed; walRecordAtForTest
		// verifies the CRC and unwraps to the inner checkpoint type so this scanner
		// matches 0x02/0x05 exactly as before — WITHOUT weakening it (a wrapped
		// record with a bad CRC Fatalf's inside the helper).
		innerType, _, recLen, complete := walRecordAtForTest(t, data, off)
		if !complete {
			break // torn tail — end of clean records (a crash boundary, not a record)
		}
		if innerType == byte(WALRecCheckpoint) || innerType == byte(WALRecCheckpointV2) {
			count++
		}
		off += recLen
	}
	return count
}

// ---------------------------------------------------------------------------
// T17 — exactly-once checkpoint under concurrency
// ---------------------------------------------------------------------------

// TestExactlyOnceCheckpointUnderConcurrency is the exactly-once-checkpoint-under-concurrency guard (T17).
// K=100, 1000 mutations, therefore EXACTLY 10 K-crossings — and the WAL must
// hold EXACTLY 10 checkpoint records, from a SINGLE goroutine (the control)
// AND from 8 concurrent ones (the guard). The control is load-bearing: without
// it "10 == 10" says nothing about concurrency.
//
// RED on the pre-fix tree (revert bridge.go + wal.go): the
// non-atomic mutationsSinceCkpt loses updates AND the post-body reset lets
// every goroutine in flight see >= K for the whole slow body — the measured
// HEAD shape is 13 checkpoints for 10 crossings. The concurrent count fires.
func TestExactlyOnceCheckpointUnderConcurrency(t *testing.T) {
	const K = 100
	const total = 1000

	// CONTROL: single goroutine. If this ever fails, the concurrent assertion
	// is meaningless.
	t.Run("SingleGoroutineControl", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "t17ctl.wal")
		live := newLiveBridge(t, walPath, K)
		for i := 0; i < total; i++ {
			if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
				t.Fatalf("PutLocal %d: %v", i, err)
			}
		}
		// T-A3: the decouple makes checkpoint completion ASYNC — the WAL
		// anchor now lands on a background goroutine. Drain BEFORE counting, or a
		// short count is an artifact of asynchrony, not an exact-count break.
		live.waitCheckpointsIdle()
		if got := countCheckpoints(t, walPath); got != total/K {
			t.Fatalf("CONTROL: %d checkpoints, want exactly %d (single-goroutine, no race)", got, total/K)
		}
	})

	// THE GUARD: 8 goroutines x 125 sequential puts. The interval-ownership
	// predicate designates exactly one owner per K-multiple and the packed-word
	// scheduler runs one checkpoint per designation, under ANY interleaving.
	t.Run("Concurrent", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "t17.wal")
		live := newLiveBridge(t, walPath, K)
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 125; i++ {
					// Distinct entity per (g, i); content is irrelevant to the count.
					if _, err := live.PutLocal(utf8EntityID(g*1000+i+7000), stagedPayload(i), stagedEntry(i)); err != nil {
						t.Errorf("PutLocal g%d i%d: %v", g, i, err)
						return
					}
				}
			}(g)
		}
		wg.Wait()
		// T-A3: drain the async checkpoint runner before counting (see
		// the SingleGoroutineControl note). All designations are already CAS'd
		// into ckptState (each PutLocal designates synchronously before it
		// returns), so the pending count is final; the drain waits for the runner.
		live.waitCheckpointsIdle()
		if got := countCheckpoints(t, walPath); got != total/K {
			t.Errorf("CONCURRENT: %d checkpoints, want exactly %d — a stampede (reset window) or a lost update (non-atomic counter)", got, total/K)
		}
	})
}

// ---------------------------------------------------------------------------
// T7 — the -race workhorse: concurrent PutLocal + PutLocals at K > 0
// ---------------------------------------------------------------------------

// TestConcurrentCheckpointRace is the concurrent-checkpoint race guard (T7). It mixes the
// SINGLE path (PutLocal) and the BATCH path (PutLocals — which advances the
// counter by len(items), so a batch's interval can CONTAIN the crossing) under
// 8-way concurrency, and asserts BOTH the race detector's verdict (this test
// runs under -race in the battery) AND the exact checkpoint count. The batch
// leg is the one that exercises the interval predicate's n>1 case.
//
// RED on HEAD: `go test -race` convicts the non-atomic mutationsSinceCkpt
// (W/W at the increment and the reset), and the count diverges from the
// crossing count.
func TestConcurrentCheckpointRace(t *testing.T) {
	const K = 100
	walPath := filepath.Join(t.TempDir(), "t7.wal")
	live := newLiveBridge(t, walPath, K)

	var wg sync.WaitGroup
	// 4 goroutines x 125 single puts = 500 mutations.
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 125; i++ {
				if _, err := live.PutLocal(utf8EntityID(g*10000+i+20000), stagedPayload(i), stagedEntry(i)); err != nil {
					t.Errorf("PutLocal g%d i%d: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	// 4 goroutines x 25 batches x 5 items = 500 mutations (multi-count intervals).
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for b := 0; b < 25; b++ {
				items := make([]LocalItem, 5)
				for i := range items {
					id := g*10000 + b*5 + i + 60000
					items[i] = LocalItem{EntityID: utf8EntityID(id), Payload: stagedPayload(i), Entry: stagedEntry(i)}
				}
				if _, _, err := live.PutLocals(items); err != nil {
					t.Errorf("PutLocals g%d b%d: %v", g, b, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	// T-A3: drain the async checkpoint runner before counting (see T17).
	live.waitCheckpointsIdle()
	if got := countCheckpoints(t, walPath); got != 10 {
		t.Errorf("%d checkpoints for 1000 mutations at K=100, want exactly 10", got)
	}
}

// ---------------------------------------------------------------------------
// T8 — snapshot anchor mismatch => LOUD fallback
// ---------------------------------------------------------------------------

// TestSnapshotAnchorMismatchLoudFallback is the snapshot-anchor-mismatch loud-fallback guard (T8). An image
// whose embedded LamportHigh disagrees with the ckpt/<N> key it is stored
// under is a torn or rewritten artifact — recovery must REFUSE it, mark the
// fallback, and rebuild from the WAL alone.
//
// LAYERED-DEFENSE DISCLOSURE: the anchor is guarded TWICE on the LocalFS path.
// The PRIMARY guard is the loader check (snapshot.go:281, commit
// 1c7ed86 — LoadSnapshotImage itself refuses a header/key mismatch), which
// surfaces here as the load-failed fallback; the recovery-side check
// (recovery.go `if snapshotLamportHigh != lh`) is the store-INDEPENDENT guard
// for SnapshotStore implementations that do not re-validate. A single-site
// inject therefore CANNOT flip this guard — its RED neutralizes BOTH guards
// (snapshot.go:281 + recovery.go:204), proving the guard detects total absence
// of the anchor defense. T8b isolates the recovery-side guard as live code.
//
// RED (bug-inject, both guards off): the forged image is USED, the marker
// stays clear, and the witness claims a bounded recovery that never happened.
func TestSnapshotAnchorMismatchLoudFallback(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t8.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	for i := 0; i < 3; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	ckptLamport := live.Engine().LamportCounter()
	if _, err := live.PutLocal(utf8EntityID(3), stagedPayload(3), stagedEntry(3)); err != nil {
		t.Fatalf("PutLocal tail: %v", err)
	}
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	// Rewrite the image with a FORGED header watermark (the file stays at the
	// honest key ckpt/<ckptLamport>).
	img, err := lfs.LoadSnapshotImage(context.Background(), ckptLamport)
	if err != nil {
		t.Fatalf("LoadSnapshotImage: %v", err)
	}
	img.LamportHigh = ckptLamport + 999
	forged, err := encodeSnapshotImage(img)
	if err != nil {
		t.Fatalf("encodeSnapshotImage: %v", err)
	}
	key := "ckpt/" + strconv.FormatUint(ckptLamport, 10)
	if err := lfs.Upload(context.Background(), key, strings.NewReader(string(forged)), int64(len(forged))); err != nil {
		t.Fatalf("Upload forged image: %v", err)
	}

	rec, witness := recoverBounded(t, walPath, lfs)
	if !witness.ExactWALFallback {
		t.Errorf("MARKER: ExactWALFallback=false — a forged-anchor image was used SILENTLY")
	}
	if !strings.Contains(witness.FallbackReason, "watermark mismatch") {
		t.Errorf("MARKER: FallbackReason=%q, want it to name the watermark mismatch", witness.FallbackReason)
	}
	if got := countDots(t, rec); got != 4 {
		t.Errorf("DOT COUNT: recovered %d != 4", got)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("ROOT: recovered %x != live %x (the WAL alone must rebuild the live state)", got, liveRoot)
	}
}

// ---------------------------------------------------------------------------
// T8b — the recovery-side anchor guard, isolated (non-validating store)
// ---------------------------------------------------------------------------

// rawImageStore is a SnapshotStore that returns a caller-supplied image with
// NO loader-side watermark validation (LocalFS validates at snapshot.go:281; a
// remote store that streams bytes and decodes without checking would not). It
// exists to isolate recovery.go's own anchor guard from the loader's — so the
// recovery-side check is proven LIVE CODE, not unreachable defense-in-depth.
type rawImageStore struct{ img *SnapshotImage }

func (s *rawImageStore) SnapshotExists(_ context.Context, _ uint64) (bool, error) {
	return true, nil
}
func (s *rawImageStore) LoadSnapshotImage(_ context.Context, _ uint64) (*SnapshotImage, error) {
	return s.img, nil
}

// TestRecoveryAnchorGuardNonValidatingStore is T8's isolation leg: the
// genuine image content with a FORGED header watermark, served by a store that
// does not validate. recovery.go's `snapshotLamportHigh != lh` check is then
// the ONLY guard. The fallback must fire, loudly, and the rebuild must be
// correct from the WAL alone.
//
// RED (bug-inject): neutralize recovery.go's check alone (`if false &&...`)
// → the forged image is used → the MARKER assertion fires.
func TestRecoveryAnchorGuardNonValidatingStore(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "t8b.wal")
	live := newLiveBridge(t, walPath, 0)
	live.SetSnapshotter(lfs, false)

	for i := 0; i < 3; i++ {
		if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
			t.Fatalf("PutLocal %d: %v", i, err)
		}
	}
	if err := live.AppendCheckpoint(); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	ckptLamport := live.Engine().LamportCounter()
	if _, err := live.PutLocal(utf8EntityID(3), stagedPayload(3), stagedEntry(3)); err != nil {
		t.Fatalf("PutLocal tail: %v", err)
	}
	liveRoot := live.Engine().State().MerkleRoot()
	if err := live.WAL().Close(); err != nil {
		t.Fatalf("live WAL close: %v", err)
	}
	if err := live.Engine().Close(); err != nil {
		t.Fatalf("live engine close: %v", err)
	}

	img, err := lfs.LoadSnapshotImage(context.Background(), ckptLamport)
	if err != nil {
		t.Fatalf("LoadSnapshotImage (genuine): %v", err)
	}
	img.LamportHigh = ckptLamport + 999 // forged header; raw store does NOT re-validate

	rec, witness := recoverBounded(t, walPath, &rawImageStore{img: img})
	if !witness.ExactWALFallback {
		t.Errorf("MARKER: ExactWALFallback=false — a forged-anchor image from a non-validating store was used SILENTLY")
	}
	if !strings.Contains(witness.FallbackReason, "watermark mismatch") {
		t.Errorf("MARKER: FallbackReason=%q, want it to name the watermark mismatch", witness.FallbackReason)
	}
	if got := countDots(t, rec); got != 4 {
		t.Errorf("DOT COUNT: recovered %d != 4", got)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("ROOT: recovered %x != live %x (the WAL alone must rebuild the live state)", got, liveRoot)
	}
}
