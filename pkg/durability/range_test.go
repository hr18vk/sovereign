// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests exercise Resolver.Range against Arrow files in LocalFS. They
// cover interval intersection, the MaxRangeRows cap, and reading both a
// compacted L1 and newer uncompacted L0 files. The last case lives here because
// it needs both internal/database's compactor and durability.LocalFS.
//
// Rows are written through SkipListArena and L0Flusher, then read with a
// Resolver over the same filesystem. Reading only L1 or only the tail would
// omit durable rows from the requested window.
package durability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rangeOpenEnd is the int64-safe open-ended ValidTimeEnd sentinel, mirroring
// the convention used in related tests. MaxValidTime.UnixNano overflows int64
// and cannot be used in a query.
const rangeOpenEnd int64 = 9_000_000_000_000_000_000

// range19BaseDur is a fixed nanosecond epoch for the durability tests, using
// the same convention as the internal/database seam tests. Distinct decimal
// lengths for file txTime suffixes make lexicographic order match numeric order.
const range19BaseDur int64 = 1_700_000_000_000_000_000

// insertWindowRow flushes one row with valid-time interval [validStart,
// validEnd) through a fresh SkipListArena and L0Flusher. AssertionTime equals
// SystemTime; these tests vary only system and valid time.
func insertWindowRow(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, flusher *database.L0Flusher, entityID string, sysNs, validStart, validEnd int64, payload []byte) {
	t.Helper()
	if validEnd <= validStart {
		t.Fatalf("insertWindowRow: degenerate window for %q: [%d,%d)", entityID, validStart, validEnd)
	}
	flushed, err := buildAndFlush(t, alloc, lfs, flusher, entityID, sysNs, validStart, validEnd, payload)
	require.Truef(t, flushed, "insertWindowRow: FlushFromArena uploaded 0 partitions (the single-entity row did not flush)")
	_ = err
}

// buildAndFlush builds a single-row SkipList and flushes it, returning whether
// any partition was uploaded and any flush error. It is the shared build-and-flush
// helper the window tests use.
func buildAndFlush(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, flusher *database.L0Flusher, entityID string, sysNs, validStart, validEnd int64, payload []byte) (bool, error) {
	t.Helper()
	sl := database.NewSkipListArena(alloc, 2*1024*1024)
	// Composite key: col0 = sha256(entityID)[:16], sysNs, validStart, assertNs.
	fullHash := sha256.Sum256([]byte(entityID))
	key := make([]byte, 40)
	copy(key[0:16], fullHash[:16])
	putBE64(key[16:24], uint64(sysNs))
	putBE64(key[24:32], uint64(validStart))
	putBE64(key[32:40], uint64(sysNs)) // AssertTime == SystemTime
	pd := sha256.Sum256(payload)
	val := makePackedValue(entityID, 0x89283082803ffff, validEnd, pd, payload)
	if err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) }); err != nil {
		sl.Free()
		return false, fmt.Errorf("Put: %w", err)
	}
	uploaded, err := flusher.FlushFromArena(context.Background(), sl)
	sl.Free()
	return uploaded > 0, err
}

// TestRangeHeadlineIntervalIntersectionRealLocalFS writes four disjoint
// valid-time intervals and queries [25,65). Only [30,40) and [50,60) intersect
// that window. This checks the interval filters against on-disk Arrow files,
// complementing the in-memory tests in internal/database.
func TestRangeHeadlineIntervalIntersectionRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "range-bucket")
	const entity = "alpha"
	wins := [][2]int64{
		{range19BaseDur + 10, range19BaseDur + 20},
		{range19BaseDur + 30, range19BaseDur + 40},
		{range19BaseDur + 50, range19BaseDur + 60},
		{range19BaseDur + 70, range19BaseDur + 80},
	}
	for i, w := range wins {
		insertWindowRow(t, alloc, lfs, flusher, entity, range19BaseDur+int64(i), w[0], w[1], []byte("r1-"+strconv.Itoa(i)))
	}

	r := database.NewResolver(lfs, lfs, alloc, "range-bucket", database.ResolverConfig{MaxRangeRows: 4096})
	vLo := time.Unix(0, range19BaseDur+25)
	vHi := time.Unix(0, range19BaseDur+65)
	tx := time.Unix(0, range19BaseDur+99999)
	rows, truncated, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range over LocalFS failed")
	assert.Falsef(t, truncated, "two rows unexpectedly exceeded the cap")
	require.Lenf(t, rows, 2, "Range returned %d rows, want [30,40) and [50,60)", len(rows))
	wantStarts := []int64{range19BaseDur + 30, range19BaseDur + 50}
	gotStarts := []int64{rows[0].ValidTimeStart, rows[1].ValidTimeStart}
	assert.Equalf(t, wantStarts, gotStarts, "validTimeStart-sorted [30 then 50] over the on-disk index")
	t.Logf("Range [25,65) returned %d rows from four on-disk intervals", len(rows))
}

// ---------------------------------------------------------------------------
// L1 and uncompacted tail reads.
// ---------------------------------------------------------------------------

// TestRangeScansL1PlusUncompactedTail compacts four older rows, writes two
// newer L0 rows, and queries [25,65). Two intervals from each tier intersect
// the window. Checking their valid-time starts verifies that Range merges both
// sources and preserves valid-time ordering rather than reading only one tier.
func TestRangeScansL1PlusUncompactedTail(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "range-bucket")
	const entity = "alpha"

	// Four checkpoints become four L0 files. Compaction preserves all rows;
	// [30,40) and [38,45) intersect the query window.
	bulk := [][2]int64{
		{range19BaseDur + 5, range19BaseDur + 12},
		{range19BaseDur + 10, range19BaseDur + 20},
		{range19BaseDur + 30, range19BaseDur + 40},
		{range19BaseDur + 38, range19BaseDur + 45},
	}
	for i, w := range bulk {
		insertWindowRow(t, alloc, lfs, flusher, entity, range19BaseDur+int64(i), w[0], w[1], []byte("bulk-"+strconv.Itoa(i)))
	}

	// Merge the four L0 files into one preserve-all L1.
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "range-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (4 L0 files exist)")
	require.NotEmptyf(t, res.L1Key, "an L1 must be written (the merged bulk)")
	require.Lenf(t, res.L0Files, len(bulk), "all bulk L0 keys must be superseded into the L1's manifest")

	// Two later checkpoints remain as uncompacted L0 files. Both intervals
	// intersect the query window and have newer system times than the L1 rows.
	tail := [][2]int64{
		{range19BaseDur + 50, range19BaseDur + 60},
		{range19BaseDur + 58, range19BaseDur + 63},
	}
	for i, w := range tail {
		insertWindowRow(t, alloc, lfs, flusher, entity, range19BaseDur+1000+int64(i), w[0], w[1], []byte("tail-"+strconv.Itoa(i)))
	}

	// The query intersects [30,40) and [38,45) in L1, plus [50,60) and
	// [58,63) in the tail. Intervals ending at or before 25 are excluded.
	r := database.NewResolver(lfs, lfs, alloc, "range-bucket", database.ResolverConfig{MaxRangeRows: 4096})
	vLo := time.Unix(0, range19BaseDur+25)
	vHi := time.Unix(0, range19BaseDur+65)
	tx := time.Unix(0, range19BaseDur+99999)
	rows, _, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range over the L1 + tail must resolve")
	// Four rows are expected: two from L1 and two from the tail. Reading only
	// one tier would return two.
	require.Lenf(t, rows, 4, "Range returned %d rows, want 2 from L1 and 2 from the tail", len(rows))

	// Identify tier contributions by valid-time start: base+30 and base+38 in
	// L1, and base+50 and base+58 in the tail.
	l1Starts := map[int64]bool{range19BaseDur + 30: true, range19BaseDur + 38: true}
	tailStarts := map[int64]bool{range19BaseDur + 50: true, range19BaseDur + 58: true}
	var l1Count, tailCount int
	for _, row := range rows {
		if l1Starts[row.ValidTimeStart] {
			l1Count++
		}
		if tailStarts[row.ValidTimeStart] {
			tailCount++
		}
	}
	assert.Equalf(t, 2, l1Count, "Range returned %d L1 rows, want 2", l1Count)
	assert.Equalf(t, 2, tailCount, "Range returned %d tail rows, want 2", tailCount)

	// The merged result must remain sorted by valid-time start.
	for i := 1; i < len(rows); i++ {
		assert.Lessf(t, rows[i-1].ValidTimeStart, rows[i].ValidTimeStart, "rows must be validTimeStart-sorted across L1+tail")
	}
	t.Logf("Range [25,65) returned %d rows: %d from L1 and %d from the tail", len(rows), l1Count, tailCount)
}

// TestRangeMaxRowsCapTruncatedRealLocalFS queries ten on-disk rows with
// MaxRangeRows=4. Range must return four rows and set truncated, bounding the
// slice passed to the JSON encoder.
func TestRangeMaxRowsCapTruncatedRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "range-bucket")
	const entity = "alpha"
	const N = 10
	const cap = 4
	for i := 0; i < N; i++ {
		vs := range19BaseDur + int64(100*i)
		ve := vs + 50
		insertWindowRow(t, alloc, lfs, flusher, entity, range19BaseDur+int64(i), vs, ve, []byte("c-"+strconv.Itoa(i)))
	}

	r := database.NewResolver(lfs, lfs, alloc, "range-bucket", database.ResolverConfig{MaxRangeRows: cap})
	vLo := time.Unix(0, range19BaseDur)
	vHi := time.Unix(0, range19BaseDur+1000)
	tx := time.Unix(0, range19BaseDur+99999)
	rows, truncated, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err)
	assert.Truef(t, truncated, "%d-row history did not set truncated with MaxRangeRows=%d", N, cap)
	require.Lenf(t, rows, cap, "Range must return exactly %d rows with MaxRangeRows=%d", cap, cap)
	t.Logf("%d-row history with MaxRangeRows=%d returned exactly %d rows with truncation", N, cap, len(rows))
}
