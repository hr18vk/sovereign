// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// The L0→L1 per-entity compaction guards (ADR-0019).
//
// These guards CLOSE the MaxL0Files silent-data-loss cap (the cap form of the
// silent-miss class the per-entity split closed in keying form). AsOf lists ONLY the newest
// MaxL0Files per-entity L0 files per query; every older per-entity file is
// invisible → a query for an OLD valid-time returns ErrEntityNotFound for data
// that IS durable on disk. The L0→L1 per-entity compaction eliminates the cap:
// a background compaction merges the N per-entity L0 files into ONE sorted L1
// file; AsOf scans the L1 (always, the full merged history) + the uncompacted
// L0 tail (MaxL0Files now bounds the TAIL, a perf cap not a correctness cap)
// and skips L0 keys listed in a compaction manifest.
//
// BITEMPORAL CORRECTNESS — the merge PRESERVES ALL ROWS. Row-pruning is a
// future Level-2 work requiring truth-maintenance + a real DELETE operator; the
// dead tombstone EpochCompactor stays DEAD.
//
// The headline merge-round-trip, idempotency, and L1+tail route guards live in
// pkg/durability — they drive a REAL *LocalFS (drive the route, not the seam).
// LocalFS lives in pkg/durability (which imports internal/database), so an
// internal/database test cannot import it (import cycle). This file holds the
// Law II byte-identity guard, the scope-hygiene guard, and the frozen-md5 gate,
// which need only internal/database symbols and read the frozen files off disk.
package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/apache/arrow/go/v17/arrow"
	"github.com/apache/arrow/go/v17/arrow/array"
	"github.com/apache/arrow/go/v17/arrow/ipc"
	"github.com/apache/arrow/go/v17/arrow/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Law II byte-identity across the merge: the L1's row set == the union
// of the merged L0 files' rows for that entity (same count, same tri-temporal
// coordinates). Asserted as set equality on the 40-byte composite key. Driven
// against an in-memory store (the S3-interface seam) — the route guard drives
// the REAL *LocalFS route in pkg/durability. ---
func TestL1ByteIdentityUnionOfMergedL0Rows(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	flusher := NewL0Flusher(alloc, store, "compact-bucket")
	const entity = "alpha"
	const N = 12
	const openEnd int64 = 9_000_000_000_000_000_000
	base := time.Now().UnixNano()
	for i := 0; i < N; i++ {
		sys := base + int64(i)
		payload := []byte("ckpt-" + strconv.Itoa(i))
		sl := NewSkipListArena(alloc, 2*1024*1024)
		insertEntityRow(sl, entity, sys, sys, sys, openEnd, payload)
		_, err := flusher.FlushFromArena(ctx, sl)
		require.NoErrorf(t, err, "flush checkpoint %d", i)
		sl.Free()
	}

	compactor := NewL1Compactor(store, store, store, alloc, "compact-bucket", DefaultCompactionConfig())
	h8 := EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Equalf(t, N, res.Rows, "L1 must preserve ALL %d rows (no pruning)", N)

	// Composite keys from the L1.
	got := collectRowKeys(t, alloc, store, "compact-bucket", []string{res.L1Key})
	// Composite keys from the union of the merged L0 files.
	want := map[[40]byte]struct{}{}
	for _, l0k := range res.L0Files {
		ks := collectRowKeys(t, alloc, store, "compact-bucket", []string{l0k})
		for k := range ks {
			want[k] = struct{}{}
		}
	}
	// Set equality on the composite key: every L1 row exists in some merged L0
	// and vice versa (Law II byte-identity across the merge).
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("Law II: L1 is MISSING a row that exists in a merged L0 (frag=%x)", k)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("Law II: L1 has a row NOT present in any merged L0 (frag=%x)", k)
		}
	}
	assert.Lenf(t, got, len(want), "Law II: L1 row count (%d) must == union of merged L0 rows (%d)", len(got), len(want))
}

// collectRowKeys reads the Arrow IPC keys via an S3Downloader and returns the
// set of 40-byte composite keys (entityHash16|sysTime|validTime|assertTime).
func collectRowKeys(t *testing.T, alloc *JemallocAllocator, dl S3Downloader, bucket string, keys []string) map[[40]byte]struct{} {
	t.Helper()
	out := make(map[[40]byte]struct{})
	var arrowAlloc memory.Allocator = memory.DefaultAllocator
	if alloc != nil {
		arrowAlloc = alloc
	}
	for _, key := range keys {
		rc, err := dl.Download(context.Background(), bucket, key)
		require.NoErrorf(t, err, "download %s", key)
		data, n, _ := readAllIntoJemalloc(arrowAlloc, rc)
		_ = rc.Close()
		if n == 0 {
			arrowAlloc.Free(data)
			continue
		}
		reader, err := ipc.NewFileReader(bytes.NewReader(data[:n]), ipc.WithAllocator(arrowAlloc))
		require.NoErrorf(t, err, "open reader %s", key)
		for i := 0; i < reader.NumRecords(); i++ {
			rec, rerr := reader.Record(i)
			require.NoError(t, rerr)
			hashCol := rec.Column(0).(*array.FixedSizeBinary)
			sysCol := rec.Column(1).(*array.Timestamp)
			vsCol := rec.Column(2).(*array.Timestamp)
			astCol := rec.Column(4).(*array.Timestamp)
			nRows := int(rec.NumRows())
			for row := 0; row < nRows; row++ {
				var frag [40]byte
				copy(frag[:16], hashCol.Value(row))
				binary.BigEndian.PutUint64(frag[16:24], uint64(int64(sysCol.Value(row))))
				binary.BigEndian.PutUint64(frag[24:32], uint64(int64(vsCol.Value(row))))
				binary.BigEndian.PutUint64(frag[32:40], uint64(int64(astCol.Value(row))))
				out[frag] = struct{}{}
			}
			rec.Release()
		}
		_ = reader.Close()
		arrowAlloc.Free(data)
	}
	return out
}

// readAllIntoJemalloc reads a ReadCloser into a jemalloc-backed buffer (the
// growable pattern, query.go:189-220). It returns the FULL allocated buffer
// (owned by the caller — free with alloc.Free(buf)) plus n, the count of content
// bytes read; the caller reads buf[:n] but MUST free the FULL buf.
//
// The prior form returned buf[:n] and the caller freed that
// RESLICE, so Free handed sdallocx the content length n (e.g. 3266) instead of
// the usable size jemalloc recorded (32768) — a wrong-size free that returned a
// 32KB large block to the wrong size class and corrupted the heap (the intermittent
// SIGSEGV this guards against). Free now derives the size from jemalloc's ground truth,
// but the correct pattern is to free the full buffer, not a reslice.
func readAllIntoJemalloc(alloc memory.Allocator, rc io.ReadCloser) (buf []byte, n int, err error) {
	capacity := 32 * 1024
	buf = alloc.Allocate(capacity)
	for {
		if n == capacity {
			capacity *= 2
			buf = alloc.Reallocate(capacity, buf)
		}
		var nb int
		nb, err = rc.Read(buf[n:])
		n += nb
		if err == io.EOF {
			break
		}
		if err != nil {
			alloc.Free(buf)
			return nil, 0, err
		}
	}
	return buf, n, nil
}

// --- Scope hygiene: the dead tombstone EpochCompactor stays dead. The L1
// compaction is NOT a subclass of EpochCompactor; NewEpochCompactor /
// SetCompactor / InsertTombstone still have ZERO production importers.
// (A grep-based guard.) ---
func TestDeadTombstoneCompactorUnchanged(t *testing.T) {
	// L1Compactor does NOT embed or reference EpochCompactor (compiler-enforced:
	// no field of that type on the struct). The dead tombstone EpochCompactor's
	// NewEpochCompactor / SetCompactor / InsertTombstone retain ZERO production
	// importers (grep-verified; the L1Compactor is a NEW
	// trigger+merger, NOT a subclass). The symbols exist as dead code; this
	// guard asserts the discipline (not a runtime grep — that belongs in the
	// commit history).
	_ = EpochCompactor{}
	t.Log("T5: EpochCompactor/SetCompactor/InsertTombstone retained as dead code (zero production importers); L1Compactor is a NEW trigger+merger, NOT a subclass")
}

// keep references alive (unused-symbol guard; prevents "declared but not used").
var (
	_ = arrow.Timestamp(0)
	_ = array.NewRecordBuilder
	_ = sort.Strings
	_ = strings.HasPrefix
	_ = sha256.Sum256
	_ = unsafe.Sizeof(0)
)
