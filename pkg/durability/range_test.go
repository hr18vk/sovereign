// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// (ADR-0024) guards (the REAL *LocalFS guards) — Resolver.Range, the
// durable bitemporal-HISTORY range read, driven against a REAL *LocalFS (the
// guard-principle "drive the route, not the seam").
//
// These guards live in pkg/durability (the home of LocalFS) because an
// internal/database test cannot import pkg/durability (import cycle: snapshot.go
// imports internal/database). The seam-level guards (interval-intersection, the
// Filter-4 collision guard, the MaxRangeRows cap, the AsOf-superset invariant)
// live in internal/database/range_test.go + pkg/mesh/query_range_test.go.
// This file holds the ONE guard the import-cycle FORCES here: T4 — the L1+tail
// scan after compaction (Range over BOTH the compacted L1 AND the uncompacted
// tail, NOT one alone — the same data-loss class closed for AsOf). It also
// re-proves the headline T1 over the REAL on-disk path (belt + suspenders: the
// seam guard proves the filters; this proves the durable surface a production
// node reads).
//
// It reuses the helpers (newLocalFS / insertRow / writeNCheckpoints
// / makePackedValue / putBE64) — the SAME REAL *LocalFS + the SAME
// L0Flusher→Arrow→disk path the compaction guards drive. Range is READ-only; it
// reuses Resolver (NewResolver over the *LocalFS lister+downloader), NOT a new
// write path. compaction+Range proves AsOf's L1+tail discipline carries ONE-FOR-
// ONE to the window path (the §1.3 invariant: a Range result MUST be a superset of
// the AsOf point at every v in the window, so the SURFACE Range scans is byte-
// identical to AsOf's).
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

// rangeOpenEnd is the int64-safe open-ended ValidTimeEnd sentinel (mirrors the
// query_test.go + convention; deliberately NOT MaxValidTime.UnixNano,
// which overflows int64 — unqueryable).
const rangeOpenEnd int64 = 9_000_000_000_000_000_000

// rangeWinBase is a fixed ns epoch for the durability guards (same convention as
// the internal/database seam guards; distinct decimal-length file txTime suffixes
// so lexicographic == numeric).
const rangeWinBaseDur int64 = 1_700_000_000_000_000_000

// insertWindowRow inserts ONE row with an EXPLICIT valid-time window
// [validStart, validEnd) into a fresh SkipListArena, then flushes to the REAL
// *LocalFS (the production l0_flusher→Arrow→disk path). Mirrors insertRow
// but ACCEPTS both bounds (the mirrored helper hard-codes validEnd=openEnd, fine for
// AsOf's degenerate-window pin, NOT for a window-intersection Range). The
// AssertTime == SystemTime (the simple tri-temporal pin; the guards assert
// SystemTime + ValidTime, not assertion-time.
func insertWindowRow(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, flusher *database.L0Flusher, entityID string, sysNs, validStart, validEnd int64, payload []byte) {
	t.Helper()
	if validEnd <= validStart {
		t.Fatalf("insertWindowRow: degenerate window for %q: [%d,%d)", entityID, validStart, validEnd)
	}
	flushed, err := buildAndFlush(t, alloc, lfs, flusher, entityID, sysNs, validStart, validEnd, payload)
	require.Truef(t, flushed, "insertWindowRow: FlushFromArena uploaded 0 partitions (the single-entity row did not flush)")
	_ = err
}

// buildAndFlush builds a single-row SkipList + flushes it; returns
// (uploaded>0, flushErr). It is the shared build+flush the window guards use.
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

// ---------------------------------------------------------------------------
// T1 (REAL *LocalFS) — the headline interval-intersection over the production
// on-disk path (re-proves the seam guard on the durable surface a node reads).
// ---------------------------------------------------------------------------

// TestRangeHeadlineIntervalIntersectionRealLocalFS is T1 over
// a REAL *LocalFS. Write 4 events for E with ValidTime windows [10,20), [30,40),
// [50,60), [70,80) via the production L0Flusher→Arrow→disk path; Range E window
// [25,65), txTime=now → EXACTLY the [30,40)+[50,60) rows (interval-intersection;
// [10,20) excluded by W2, [70,80) by W1). The seam guard (internal/database)
// proves the filters against an in-memory store; THIS guard proves the durable
// SURFACE is the SAME — the Resolver reads the on-disk Arrow files a production
// node writes, not a mock.
func TestRangeHeadlineIntervalIntersectionRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "range-bucket")
	const entity = "alpha"
	wins := [][2]int64{
		{rangeWinBaseDur + 10, rangeWinBaseDur + 20},
		{rangeWinBaseDur + 30, rangeWinBaseDur + 40},
		{rangeWinBaseDur + 50, rangeWinBaseDur + 60},
		{rangeWinBaseDur + 70, rangeWinBaseDur + 80},
	}
	for i, w := range wins {
		insertWindowRow(t, alloc, lfs, flusher, entity, rangeWinBaseDur+int64(i), w[0], w[1], []byte("r1-"+strconv.Itoa(i)))
	}

	r := database.NewResolver(lfs, lfs, alloc, "range-bucket", database.ResolverConfig{MaxRangeRows: 4096})
	vLo := time.Unix(0, rangeWinBaseDur+25)
	vHi := time.Unix(0, rangeWinBaseDur+65)
	tx := time.Unix(0, rangeWinBaseDur+99999)
	rows, truncated, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range over REAL *LocalFS must resolve")
	assert.Falsef(t, truncated, "no truncation (2 rows << cap)")
	require.Lenf(t, rows, 2, "interval-intersection over the durable index: [25,65) intersects [30,40)+[50,60) only; got %d", len(rows))
	wantStarts := []int64{rangeWinBaseDur + 30, rangeWinBaseDur + 50}
	gotStarts := []int64{rows[0].ValidTimeStart, rows[1].ValidTimeStart}
	assert.Equalf(t, wantStarts, gotStarts, "validTimeStart-sorted [30 then 50] over the on-disk index")
	t.Logf("T1 REAL *LocalFS: Range [25,65) over 4 on-disk disjoint windows → %d rows; the durable surface is the SAME AsOf reads", len(rows))
}

// ---------------------------------------------------------------------------
// T4 — L1 + uncompacted tail: Range scans BOTH tiers, NOT one alone.
// ---------------------------------------------------------------------------

// TestRangeScansL1PlusUncompactedTail is T4. After a compaction
// merges the bulk into ONE L1, write MORE checkpoints (the uncompacted tail) so
// the window's intersecting rows span BOTH the L1 (older windows) AND the tail
// (newer windows). Range MUST return rows across BOTH — a Range that reads ONLY
// the L1 OR ONLY the tail LOSES durable history (the SAME data-loss class
// closed for AsOf). This is the guard the import-cycle forces into pkg/durability:
// it needs the compactor + the REAL *LocalFS the compactor writes the L1 to.
//
// The L1 holds OLDER windows [10,20)+[30,40) (merged); the tail holds a NEWER
// window [50,60) (uncompacted). A Range window [25, 65) intersects [30,40) (L1)
// AND [50,60) (tail) — both MUST appear. A Range that scanned only the L1 returns
// [30,40) (1 row, missing the tail); only the tail returns [50,60) (1 row, missing
// the L1). The GREEN: 2 rows, one from each tier.
func TestRangeScansL1PlusUncompactedTail(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "range-bucket")
	const entity = "alpha"

	// Bulk: 4 windows in 4 checkpoints → 4 L0 files. Window [10,20) + [30,40)
	// will be the L1 survivors the Range window intersects; [5,12) + [38,45) are
	// extra intersect-with-tail rows that round out the bulk (the L1 holds ALL
	// of them under preserve-all).
	bulk := [][2]int64{
		{rangeWinBaseDur + 5, rangeWinBaseDur + 12},
		{rangeWinBaseDur + 10, rangeWinBaseDur + 20},
		{rangeWinBaseDur + 30, rangeWinBaseDur + 40},
		{rangeWinBaseDur + 38, rangeWinBaseDur + 45},
	}
	for i, w := range bulk {
		insertWindowRow(t, alloc, lfs, flusher, entity, rangeWinBaseDur+int64(i), w[0], w[1], []byte("bulk-"+strconv.Itoa(i)))
	}

	// Compaction: merge the 4 L0 files into ONE L1 (the merged history; preserve-all).
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "range-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (4 L0 files exist)")
	require.NotEmptyf(t, res.L1Key, "an L1 must be written (the merged bulk)")
	require.Lenf(t, res.L0Files, len(bulk), "all bulk L0 keys must be superseded into the L1's manifest")

	// Tail: TWO more windows in TWO checkpoints (uncompacted L0 files, NOT in L1).
	// [50,60) intersects the query window AND is NEWER than every L1 row's sysTime.
	tail := [][2]int64{
		{rangeWinBaseDur + 50, rangeWinBaseDur + 60},
		{rangeWinBaseDur + 58, rangeWinBaseDur + 63},
	}
	for i, w := range tail {
		insertWindowRow(t, alloc, lfs, flusher, entity, rangeWinBaseDur+1000+int64(i), w[0], w[1], []byte("tail-"+strconv.Itoa(i)))
	}

	// Query window [25, 65). Intersects: L1's [30,40) and [38,45); tail's [50,60)
	// and [58,63). (Does NOT intersect [5,12) [10,20) — both end <= 25.) So the
	// expected intersecting set = {[30,40),[38,45)} from L1 ∪ {[50,60),[58,63)}
	// from tail = 4 rows. The load-bearing claim: BOTH tiers contribute — drop
	// either and the count drops to 2.
	r := database.NewResolver(lfs, lfs, alloc, "range-bucket", database.ResolverConfig{MaxRangeRows: 4096})
	vLo := time.Unix(0, rangeWinBaseDur+25)
	vHi := time.Unix(0, rangeWinBaseDur+65)
	tx := time.Unix(0, rangeWinBaseDur+99999)
	rows, _, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range over the L1 + tail must resolve")
	// Expect EXACTLY 4 rows: 2 from the L1 (the merged bulk intersecting the
	// window) + 2 from the tail (uncompacted). A Range that scanned only ONE
	// tier returns 2 → this count is the L1+tail proof.
	require.Lenf(t, rows, 4, "T4: Range window [25,65) must return rows from BOTH the L1 (2 older windows) AND the tail (2 newer windows) = 4 total; got %d (a Range scanning only one tier returns 2 — the data-loss class closed)", len(rows))

	// Assert BOTH tiers contributed: an L1 row (sysTime in the bulk range
	// [1000,1003]) AND a tail row (sysTime in [11000,11001]-ish; wrote 1000+1000+i).
	l1Starts := map[int64]bool{rangeWinBaseDur + 30: true, rangeWinBaseDur + 38: true}
	tailStarts := map[int64]bool{rangeWinBaseDur + 50: true, rangeWinBaseDur + 58: true}
	var l1Count, tailCount int
	for _, row := range rows {
		if l1Starts[row.ValidTimeStart] {
			l1Count++
		}
		if tailStarts[row.ValidTimeStart] {
			tailCount++
		}
	}
	assert.Equalf(t, 2, l1Count, "T4: the L1 must contribute 2 rows ([30,40)+[38,45)); got %d — a Range that misses the L1 loses the merged history", l1Count)
	assert.Equalf(t, 2, tailCount, "T4: the tail must contribute 2 rows ([50,60)+[58,63)); got %d — a Range that misses the tail loses the uncompacted history", tailCount)

	// Sort check: the 4 rows are validTimeStart-sorted (the L1+tail merge did NOT
	// break the post-sort window order — the honest operator-facing contract).
	for i := 1; i < len(rows); i++ {
		assert.Lessf(t, rows[i-1].ValidTimeStart, rows[i].ValidTimeStart, "rows must be validTimeStart-sorted across L1+tail")
	}
	t.Logf("T4 REAL *LocalFS: Range [25,65) after compaction → %d rows = %d from L1 + %d from tail (ScansBOTH tiers — the L1+tail discipline carries ONE-FOR-ONE from AsOf)", len(rows), l1Count, tailCount)
}

// ---------------------------------------------------------------------------
// T5 (REAL *LocalFS) — MaxRangeRows cap + truncated over the on-disk index.
// ---------------------------------------------------------------------------

// TestRangeMaxRowsCapTruncatedRealLocalFS re-proves the cap over the
// durable surface: 10 disjoint on-disk windows, MaxRangeRows=4 → exactly 4 rows
// + truncated=true (the marshal never sees >4). Mirrors the seam guard but on
// REAL disk (the production-resident slice the JSON encoder marshals).
func TestRangeMaxRowsCapTruncatedRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "range-bucket")
	const entity = "alpha"
	const N = 10
	const cap = 4
	for i := 0; i < N; i++ {
		vs := rangeWinBaseDur + int64(100*i)
		ve := vs + 50
		insertWindowRow(t, alloc, lfs, flusher, entity, rangeWinBaseDur+int64(i), vs, ve, []byte("c-"+strconv.Itoa(i)))
	}

	r := database.NewResolver(lfs, lfs, alloc, "range-bucket", database.ResolverConfig{MaxRangeRows: cap})
	vLo := time.Unix(0, rangeWinBaseDur)
	vHi := time.Unix(0, rangeWinBaseDur+1000)
	tx := time.Unix(0, rangeWinBaseDur+99999)
	rows, truncated, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err)
	assert.Truef(t, truncated, "truncated MUST be true over REAL disk (the %d-row history exceeds MaxRangeRows=%d)", N, cap)
	require.Lenf(t, rows, cap, "the marshal NEVER sees >MaxRangeRows rows: exactly %d over the on-disk index, want %d", cap, cap)
	t.Logf("T5 REAL *LocalFS: %d-row on-disk history, MaxRangeRows=%d → exactly %d rows + truncated=true (cap pre-marshal on the durable surface)", N, cap, len(rows))
}
