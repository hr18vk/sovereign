// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// These tests cover concurrent checkpoint scheduling and snapshot anchor
// validation (ADR-0045 §5). The scheduler must write one checkpoint per
// interval crossing even when single and batched writes overlap. A non-atomic
// counter with a post-checkpoint reset previously lost crossings and produced
// 13 checkpoints for 10 crossings in one measured run.
//
// The anchor tests require a mismatched image to be rejected with a reported
// fallback to exact WAL replay. Checkpoint failure acknowledgement is covered
// separately in checkpoint_failure_ack_test.go.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// countCheckpoints parses the raw WAL and counts both legacy 0x02 and V2 0x05
// checkpoint records. Replayed cannot supply this count because it retains only
// FinalCheckpt.
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
		// Records use 0x06 CRC framing. walRecordAtForTest verifies the CRC and
		// unwraps the inner checkpoint type; an invalid checksum fails the test.
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
// Exact checkpoint count under concurrency
// ---------------------------------------------------------------------------

// TestExactlyOnceCheckpointUnderConcurrency writes 1,000 mutations at K=100,
// first from one goroutine and then from eight. Both runs must leave exactly 10
// checkpoint records. The single-goroutine control distinguishes a scheduling
// defect from a concurrent counter defect. A non-atomic counter and reset could
// instead lose crossings or produce 13 checkpoints for the same 10 crossings.
func TestExactlyOnceCheckpointUnderConcurrency(t *testing.T) {
	const K = 100
	const total = 1000

	// Establish the expected count without concurrency first.
	t.Run("SingleGoroutineControl", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "checkpoint-control.wal")
		live := newLiveBridge(t, walPath, K)
		for i := 0; i < total; i++ {
			if _, err := live.PutLocal(utf8EntityID(i), stagedPayload(i), stagedEntry(i)); err != nil {
				t.Fatalf("PutLocal %d: %v", i, err)
			}
		}
		// Checkpoint anchors are appended asynchronously. Drain the runner before
		// counting so an incomplete run is not mistaken for a scheduling error.
		live.waitCheckpointsIdle()
		if got := countCheckpoints(t, walPath); got != total/K {
			t.Fatalf("single writer produced %d checkpoints, want %d", got, total/K)
		}
	})

	// Eight goroutines each perform 125 sequential puts. Interval ownership and
	// the packed scheduler must preserve one checkpoint per crossing.
	t.Run("Concurrent", func(t *testing.T) {
		walPath := filepath.Join(t.TempDir(), "checkpoint-concurrent.wal")
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
		// Every PutLocal records its designation before returning, so the pending
		// count is final and only runner completion remains to be observed.
		live.waitCheckpointsIdle()
		if got := countCheckpoints(t, walPath); got != total/K {
			t.Errorf("concurrent writers produced %d checkpoints, want %d; check for duplicate or lost crossings", got, total/K)
		}
	})
}

// ---------------------------------------------------------------------------
// Concurrent single and batched writes
// ---------------------------------------------------------------------------

// TestConcurrentCheckpointRace mixes PutLocal and PutLocals across eight
// goroutines at K=100. Batch calls advance the counter by len(items), exercising
// crossings inside multi-mutation intervals. The race-enabled test suite checks
// synchronization, and the WAL must contain exactly 10 checkpoints.
func TestConcurrentCheckpointRace(t *testing.T) {
	const K = 100
	walPath := filepath.Join(t.TempDir(), "checkpoint-race.wal")
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
	// Wait for all asynchronously designated checkpoints before counting anchors.
	live.waitCheckpointsIdle()
	if got := countCheckpoints(t, walPath); got != 10 {
		t.Errorf("%d checkpoints for 1000 mutations at K=100, want exactly 10", got)
	}
}

// ---------------------------------------------------------------------------
// Snapshot anchor mismatch
// ---------------------------------------------------------------------------

// TestSnapshotAnchorMismatchLoudFallback stores an image whose LamportHigh
// disagrees with its ckpt/<N> key. Recovery must reject the rewritten or torn
// artifact, report ExactWALFallback, and rebuild the live root from the WAL.
//
// LocalFS.LoadSnapshotImage checks the header against the key, and recovery
// independently compares snapshotLamportHigh with the anchor for stores that do
// not validate. TestRecoveryAnchorGuardNonValidatingStore isolates the second
// check; disabling both provides the negative control for this test.
func TestSnapshotAnchorMismatchLoudFallback(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "anchor-mismatch.wal")
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

	// Rewrite the image header's watermark while retaining its legitimate
	// ckpt/<ckptLamport> key.
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
		t.Errorf("ExactWALFallback=false after anchor mismatch; the forged image must not be used")
	}
	if !strings.Contains(witness.FallbackReason, "watermark mismatch") {
		t.Errorf("FallbackReason=%q, want a watermark mismatch explanation", witness.FallbackReason)
	}
	if got := countDots(t, rec); got != 4 {
		t.Errorf("recovered dot count=%d, want 4", got)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x != live %x; exact WAL replay must rebuild live state", got, liveRoot)
	}
}

// ---------------------------------------------------------------------------
// Recovery-side anchor validation
// ---------------------------------------------------------------------------

// rawImageStore returns a caller-supplied image without loader-side watermark
// validation. It isolates recovery's anchor check from the equivalent LocalFS
// loader check.
type rawImageStore struct{ img *SnapshotImage }

func (s *rawImageStore) SnapshotExists(_ context.Context, _ uint64) (bool, error) {
	return true, nil
}
func (s *rawImageStore) LoadSnapshotImage(_ context.Context, _ uint64) (*SnapshotImage, error) {
	return s.img, nil
}

// TestRecoveryAnchorGuardNonValidatingStore serves a valid image with a forged
// header watermark through rawImageStore. Recovery's snapshotLamportHigh != lh
// check is then the only anchor guard; it must trigger ExactWALFallback and
// rebuild the live root from the WAL.
func TestRecoveryAnchorGuardNonValidatingStore(t *testing.T) {
	lfs := newSnapshotStore(t)
	walPath := filepath.Join(t.TempDir(), "anchor-guard.wal")
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
	img.LamportHigh = ckptLamport + 999 // forged header; raw store does not re-validate

	rec, witness := recoverBounded(t, walPath, &rawImageStore{img: img})
	if !witness.ExactWALFallback {
		t.Errorf("ExactWALFallback=false for a forged image from a non-validating store")
	}
	if !strings.Contains(witness.FallbackReason, "watermark mismatch") {
		t.Errorf("FallbackReason=%q, want a watermark mismatch explanation", witness.FallbackReason)
	}
	if got := countDots(t, rec); got != 4 {
		t.Errorf("recovered dot count=%d, want 4", got)
	}
	if got := rec.State().MerkleRoot(); got != liveRoot {
		t.Errorf("recovered root %x != live %x; exact WAL replay must rebuild live state", got, liveRoot)
	}
}
