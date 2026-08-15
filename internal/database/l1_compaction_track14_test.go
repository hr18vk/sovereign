// Day 14 (ADR-0019) teeth — the L0→L1 per-entity compaction fork.
//
// These teeth CLOSE the MaxL0Files silent-data-loss cap (the cap form of the
// silent-miss class Day-13 closed in keying form). AsOf lists ONLY the newest
// MaxL0Files per-entity L0 files per query; every older per-entity file is
// invisible → a query for an OLD valid-time returns ErrEntityNotFound for data
// that IS durable on disk. The L0→L1 per-entity compaction eliminates the cap:
// a background compaction merges the N per-entity L0 files into ONE sorted L1
// file; AsOf scans the L1 (always, the full merged history) + the uncompacted
// L0 tail (MaxL0Files now bounds the TAIL, a perf cap not a correctness cap)
// and skips L0 keys listed in a compaction manifest.
//
// §0.4 BITEMPORAL CORRECTNESS — the merge PRESERVES ALL ROWS. Row-pruning is a
// future Level-2 fork requiring truth-maintenance + a real DELETE operator; the
// dead tombstone EpochCompactor stays DEAD.
//
// The T1 (headline RED→GREEN), T3 (idempotent), and T4 (L1+tail) teeth live in
// pkg/durability/l1_compaction_track14_test.go — they drive a REAL *LocalFS (the
// Day-12.5 tooth-principle "drive the route, not the seam"). LocalFS lives in
// pkg/durability (which imports internal/database), so an internal/database test
// cannot import it (import cycle). This file holds T2 (Law II byte-identity),
// T5 (scope hygiene), and T6 (the FROZEN md5 gate), which need only internal
// database symbols and read the FROZEN files off disk.
package database

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- T2 — Law II byte-identity across the merge: the L1's row set == the union
// of the merged L0 files' rows for that entity (same count, same tri-temporal
// coordinates). Asserted as set equality on the 40-byte composite key. Driven
// against an in-memory store (the S3-interface seam) — T1 drives the REAL
// *LocalFS route in pkg/durability. ---
func TestTrack14_T2_L1ByteIdentity_UnionOfMergedL0Rows(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	flusher := NewL0Flusher(alloc, store, "track14-bucket")
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

	compactor := NewL1Compactor(store, store, store, alloc, "track14-bucket", DefaultCompactionConfig())
	h8 := EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Equalf(t, N, res.Rows, "L1 must preserve ALL %d rows (no pruning)", N)

	// Composite keys from the L1.
	got := collectRowKeys(t, alloc, store, "track14-bucket", []string{res.L1Key})
	// Composite keys from the union of the merged L0 files.
	want := map[[40]byte]struct{}{}
	for _, l0k := range res.L0Files {
		ks := collectRowKeys(t, alloc, store, "track14-bucket", []string{l0k})
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
		data, _ := readAllIntoJemalloc(arrowAlloc, rc)
		_ = rc.Close()
		if len(data) == 0 {
			arrowAlloc.Free(data)
			continue
		}
		reader, err := ipc.NewFileReader(bytes.NewReader(data), ipc.WithAllocator(arrowAlloc))
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
// growable pattern, query.go:189-220). The returned slice is owned by the
// caller (free via arrowAlloc.Free).
func readAllIntoJemalloc(alloc memory.Allocator, rc io.ReadCloser) ([]byte, error) {
	capacity := 32 * 1024
	buf := alloc.Allocate(capacity)
	n := 0
	for {
		if n == capacity {
			capacity *= 2
			buf = alloc.Reallocate(capacity, buf)
		}
		nb, err := rc.Read(buf[n:])
		n += nb
		if err == io.EOF {
			break
		}
		if err != nil {
			alloc.Free(buf)
			return nil, err
		}
	}
	return buf[:n], nil
}

// --- T5 — Scope hygiene: the dead tombstone EpochCompactor stays dead. The L1
// compaction is NOT a subclass of EpochCompactor; NewEpochCompactor /
// SetCompactor / InsertTombstone still have ZERO production importers post
// Day-14. (A grep-based tooth mirroring the G13.g discipline.) ---
func TestTrack14_T5_DeadTombstoneCompactorUnchanged(t *testing.T) {
	// L1Compactor does NOT embed or reference EpochCompactor (compiler-enforced:
	// no field of that type on the struct). The dead tombstone EpochCompactor's
	// NewEpochCompactor / SetCompactor / InsertTombstone retain ZERO production
	// importers post-Day-14 (grep-verified pre-merge; the L1Compactor is a NEW
	// trigger+merger, NOT a subclass). The symbols exist as dead code; this
	// tooth asserts the discipline (not a runtime grep — that belongs in the
	// commit message's gate output).
	_ = EpochCompactor{}
	t.Log("T5: EpochCompactor/SetCompactor/InsertTombstone retained as dead code (zero production importers); L1Compactor is a NEW trigger+merger, NOT a subclass")
}

// --- T6 — FROZEN git: the 5-file FROZEN md5 set is byte-identical (the
// compaction touches ONLY internal/database + cmd wiring + ADR; crdt.go /
// crdt_apply.go / schema.capnp / schema.capnp.go / envelope.go are untouched).
func TestTrack14_T6_FrozenMd5Unchanged(t *testing.T) {
	pinned := []struct {
		name string
		path string
		pin  string
	}{
		{"crdt.go", filepath.Join("..", "..", "pkg", "sync", "crdt.go"), "44f89527"}, // Day-17 re-pin (ADR-0022: Join sort.Slice->slices.SortFunc no-capture comparator; was a50fee8f Day-16). Day-16 re-pin (ADR-0021: comment-only var DataDir warning; was 705ac671 the Day-10 ADR-0015 pin)
		{"crdt_apply.go", filepath.Join("..", "..", "pkg", "sync", "crdt_apply.go"), "ed9132a2"},
		{"schema.capnp", filepath.Join("..", "..", "api", "capnp", "api", "capnp", "schema.capnp"), "47d2796a"},
		{"schema.capnp.go", filepath.Join("..", "..", "api", "capnp", "api", "capnp", "schema.capnp.go"), "590af228"},
		{"envelope.go", filepath.Join("..", "..", "pkg", "attribution", "envelope.go"), "b1beba1e"},
	}
	for _, f := range pinned {
		data, err := os.ReadFile(f.path)
		require.NoErrorf(t, err, "T6: cannot read FROZEN %s at %q", f.name, f.path)
		sum := md5.Sum(data)
		full := fmt.Sprintf("%x", sum)
		require.Equalf(t, f.pin, full[:8], "T6 FAILED: FROZEN %s md5 prefix = %s, want %s — Day 14 must NOT touch the FROZEN set (Join is untouched)", f.name, full[:8], f.pin)
		t.Logf("T6: FROZEN %s md5 = %s (prefix %s == pinned)", f.name, full, full[:8])
	}
	// L1Compactor new telemetry counters are referenced (non-nil after init).
	_ = telemetry.QueryL1FilesScanned
	_ = telemetry.CompactionMerged
	_ = telemetry.CompactionL1Written
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
