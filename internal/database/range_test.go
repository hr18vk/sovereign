// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Unit tests for Resolver.Range over the Arrow index (ADR-0024).
//
// These tests drive flush-to-Range round-trips against an in-memory S3
// simulator using L0Flusher and SkipListArena, verifying interval intersection,
// AsOf consistency, Filter 4 full entity-ID verification, and MaxRangeRows
// truncation. End-to-end *LocalFS tests live in pkg/durability and pkg/mesh.

package database

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isRangeNotFound reports whether err wraps the bare database.ErrEntityNotFound
// sentinel (the "no matching event" signal query.go returns).
// AsOf and Range return it unwrapped from the list-empty and no-match paths
// (so a direct == suffices); errors.Is and the substring guard catch any future
// wrap. Mirrors the pkg/mesh isErrEntityNotFound helper (different package —
// this is the in-package copy the internal/database tests need).
func isRangeNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrEntityNotFound) || strings.Contains(err.Error(), ErrEntityNotFound.Error())
}

// openEndNs is the int64-safe open-ended ValidTimeEnd sentinel the Range tests
// use for rows whose validity extends past the window's high end (mirrors the
// query_test.go queryValidEndNs convention; deliberately not MaxValidTime.UnixNano
// — overflows int64, unqueryable; see query_test.go).
const openEndNs int64 = 9_000_000_000_000_000_000

// rangeWinBase is a fixed ns epoch (so the tests' file txTime suffixes are
// deterministic decimal lengths — lexicographic == numeric; AsOf/Range dominance
// is order-independent regardless but the determinism shrinks the surface).
// 1.7e18 is comfortably below openEndNs (9e18) and int64-max (9.2e18).
const rangeWinBase int64 = 1_700_000_000_000_000_000

// rangeWinInsertRow inserts one tri-temporal row with an explicit valid-time window
// [validStart, validEnd) — the Range tests need distinct windows to assert
// interval-intersection (the open-ended helper insertEntityRow reused across
// tests sets validEnd = openEnd, which is a degenerate-window pin for AsOf,
// not a Range window-intersection test). It mirrors insertEntityRow but lets the
// caller set both bounds.
func rangeWinInsertRow(t *testing.T, sl *SkipListArena, entityID string, sysNs, validStart, validEnd int64, payload []byte) {
	t.Helper()
	if validEnd <= validStart {
		t.Fatalf("rangeWinInsertRow: degenerate window for %q: [%d,%d)", entityID, validStart, validEnd)
	}
	key := make([]byte, keySize)
	full := sha256.Sum256([]byte(entityID))
	copy(key[0:16], full[:16])
	binary.BigEndian.PutUint64(key[16:24], uint64(sysNs))      // systemTime
	binary.BigEndian.PutUint64(key[24:32], uint64(validStart)) // validTimeStart
	binary.BigEndian.PutUint64(key[32:40], uint64(sysNs))      // assertionTime (== sys for these tests)
	pd := sha256.Sum256(payload)
	val := makePackedValue(entityID, 0x89283082803ffff, validEnd, pd, payload)
	if err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) }); err != nil {
		t.Fatalf("rangeWinInsertRow Put %q: %v", entityID, err)
	}
}

// rangeWinInsertRowDecoupled inserts a row whose 16-byte key prefix hashes
// impostorHashEntity while storing lyingEntityID in the payload header so
// Filter 4 must reject it even after Filter 1 matches.
func rangeWinInsertRowDecoupled(t *testing.T, sl *SkipListArena, impostorHashEntity, lyingEntityID string, sysNs, validStart, validEnd int64, payload []byte) {
	t.Helper()
	key := make([]byte, keySize)
	full := sha256.Sum256([]byte(impostorHashEntity))
	copy(key[0:16], full[:16])
	binary.BigEndian.PutUint64(key[16:24], uint64(sysNs))
	binary.BigEndian.PutUint64(key[24:32], uint64(validStart))
	binary.BigEndian.PutUint64(key[32:40], uint64(sysNs))
	pd := sha256.Sum256(payload)
	val := makePackedValue(lyingEntityID, 0x89283082803ffff, validEnd, pd, payload)
	if err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) }); err != nil {
		t.Fatalf("rangeWinInsertRowDecoupled Put: %v", err)
	}
}

// rangeWinFlush flushes sl to store and frees the arena, returning upload count.
func rangeWinFlush(t *testing.T, ctx context.Context, alloc *JemallocAllocator, store *memStore, sl *SkipListArena) int {
	t.Helper()
	flusher := NewL0Flusher(alloc, store, "range-bucket")
	uploaded, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err, "FlushFromArena")
	sl.Free()
	return uploaded
}

// rangeWinResolver builds a Resolver backed by store with MaxRangeRows set.
func rangeWinResolver(alloc *JemallocAllocator, store *memStore, maxRangeRows int) *Resolver {
	return NewResolver(store, store, alloc, "range-bucket", ResolverConfig{MaxRangeRows: maxRangeRows})
}

// TestRangeHeadlineIntervalIntersectionNotPointInWindow verifies Range uses
// half-open interval intersection [validStart, validEnd) vs [vLo, vHi).
func TestRangeHeadlineIntervalIntersectionNotPointInWindow(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	wins := [][2]int64{
		{rangeWinBase + 10, rangeWinBase + 20},
		{rangeWinBase + 30, rangeWinBase + 40},
		{rangeWinBase + 50, rangeWinBase + 60},
		{rangeWinBase + 70, rangeWinBase + 80},
	}
	sys := rangeWinBase
	sl := NewSkipListArena(alloc, 8*1024*1024)
	for i, w := range wins {
		rangeWinInsertRow(t, sl, entity, sys+int64(i), w[0], w[1], []byte(fmt.Sprintf("p%d", i)))
	}
	uploaded := rangeWinFlush(t, ctx, alloc, store, sl)
	require.Equal(t, 1, uploaded, "one per-entity partition (single entity)")

	vLo := time.Unix(0, rangeWinBase+25)
	vHi := time.Unix(0, rangeWinBase+65)
	tx := time.Unix(0, sys+9999)
	r := rangeWinResolver(alloc, store, 4096)
	rows, truncated, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range must resolve (2 intersecting rows)")
	assert.Falsef(t, truncated, "truncated must be false (2 rows << MaxRangeRows)")

	require.Lenf(t, rows, 2, "interval-intersection: window [25,65) intersects [30,40)+[50,60) only; got %d rows", len(rows))
	wantStarts := []int64{rangeWinBase + 30, rangeWinBase + 50}
	gotStarts := []int64{rows[0].ValidTimeStart, rows[1].ValidTimeStart}
	assert.Equalf(t, wantStarts, gotStarts, "rows must be validTimeStart-sorted [30 then 50]")
	for _, row := range rows {
		assert.Falsef(t, row.ValidTimeStart == rangeWinBase+10, "[10,20) must be excluded (validEnd 20 <= vLo 25 — W2)")
		assert.Falsef(t, row.ValidTimeStart == rangeWinBase+70, "[70,80) must be excluded (validStart 70 >= vHi 65 — W1)")
	}
	t.Logf("Range [25,65) over 4 disjoint windows returned %d intersecting rows", len(rows))
}

// TestAsOfConsistencyRangeSupersetOfEveryPoint verifies that for any point v
// inside [vLo, vHi), AsOf returns a row contained in Range(E, [vLo, vHi), tx).
func TestAsOfConsistencyRangeSupersetOfEveryPoint(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	wins := [][2]int64{
		{rangeWinBase + 10, rangeWinBase + 50},
		{rangeWinBase + 30, rangeWinBase + 70},
		{rangeWinBase + 55, rangeWinBase + 90},
	}
	sys := []int64{rangeWinBase + 1000, rangeWinBase + 2000, rangeWinBase + 3000}
	sl := NewSkipListArena(alloc, 8*1024*1024)
	for i, w := range wins {
		rangeWinInsertRow(t, sl, entity, sys[i], w[0], w[1], []byte(fmt.Sprintf("ov%d", i)))
	}
	rangeWinFlush(t, ctx, alloc, store, sl)

	vLo := time.Unix(0, rangeWinBase+10)
	vHi := time.Unix(0, rangeWinBase+90)
	tx := time.Unix(0, rangeWinBase+99999)
	r := rangeWinResolver(alloc, store, 4096)
	rows, _, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range over the union window")
	type key struct{ vs, sys int64 }
	rangeSet := make(map[key]*TriTemporalEvent, len(rows))
	for _, row := range rows {
		rangeSet[key{row.ValidTimeStart, row.SystemTime}] = row
	}
	for _, probe := range []int64{rangeWinBase + 10, rangeWinBase + 45, rangeWinBase + 60, rangeWinBase + 89} {
		vT := time.Unix(0, probe)
		got, asErr := r.AsOf(ctx, entity, vT, tx)
		require.NoErrorf(t, asErr, "AsOf at v=%d must resolve (an intersecting row covers it)", probe-rangeWinBase)
		require.NotNil(t, got)
		k := key{got.ValidTimeStart, got.SystemTime}
		_, present := rangeSet[k]
		assert.Truef(t, present,
			"AsOf(E, v=%d) row {vs=%d,sys=%d} must appear in Range(E, [10,90)) result set",
			probe-rangeWinBase, got.ValidTimeStart, got.SystemTime)
	}
	t.Logf("4-point AsOf sweep matched rows present in Range result set")
}

// TestFilter4IntegrityDecoupledCol0NotEntityID verifies Filter 4 rejects rows
// whose 16-byte col0 hash matches E1 but whose stored entityID names E2.
func TestFilter4IntegrityDecoupledCol0NotEntityID(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const e1 = "alpha"
	const e2 = "imposter-zzz"
	const wLo = rangeWinBase + 10
	const wHi = rangeWinBase + 90

	sl := NewSkipListArena(alloc, 8*1024*1024)
	rangeWinInsertRow(t, sl, e1, rangeWinBase+1000, wLo, wHi, []byte("e1-real"))
	rangeWinInsertRowDecoupled(t, sl, e1, e2, rangeWinBase+2000, wLo, wHi, []byte("e2-imposter"))
	uploaded := rangeWinFlush(t, ctx, alloc, store, sl)
	require.Equal(t, 1, uploaded, "both rows share e1's hex8 prefix and flush into one file")

	r := rangeWinResolver(alloc, store, 4096)
	rows, _, err := r.Range(ctx, e1, time.Unix(0, wLo), time.Unix(0, wHi), time.Unix(0, rangeWinBase+99999))
	require.NoError(t, err, "Range(e1) must resolve (the E1 row)")
	var sawE1, sawE2 bool
	for _, row := range rows {
		switch row.EntityID {
		case e1:
			sawE1 = true
		case e2:
			sawE2 = true
		}
	}
	assert.Truef(t, sawE1, "the E1 row must be present in Range(e1)")
	assert.Falsef(t, sawE2, "imposter row with col0=sha256(e1) and entityID=e2 must be rejected by Filter 4")
	if sawE2 {
		t.Logf("E2 imposter row leaked into Range(e1)")
	} else {
		t.Logf("decoupled row rejected by Filter 4 as expected")
	}
}

// TestMaxRangeRowsCapTruncatedPreMarshal verifies MaxRangeRows stops collection
// at the configured ceiling and returns truncated=true.
func TestMaxRangeRowsCapTruncatedPreMarshal(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	const N = 10
	const cap = 4
	sl := NewSkipListArena(alloc, 8*1024*1024)
	for i := 0; i < N; i++ {
		vs := rangeWinBase + int64(100*i)
		ve := vs + 50
		rangeWinInsertRow(t, sl, entity, rangeWinBase+int64(i), vs, ve, []byte(fmt.Sprintf("cap-%d", i)))
	}
	uploaded := rangeWinFlush(t, ctx, alloc, store, sl)
	require.Equal(t, 1, uploaded)

	vLo := time.Unix(0, rangeWinBase)
	vHi := time.Unix(0, rangeWinBase+1000)
	tx := time.Unix(0, rangeWinBase+99999)
	r := rangeWinResolver(alloc, store, cap)
	rows, truncated, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range must resolve (capped at %d of %d rows)", cap, N)
	assert.Truef(t, truncated, "truncated must be true (the %d-row history exceeds MaxRangeRows=%d)", N, cap)
	require.Lenf(t, rows, cap, "returned rows must be %d, matching MaxRangeRows=%d", cap, cap)
	sorted := sort.SliceIsSorted(rows, func(i, j int) bool { return rows[i].ValidTimeStart < rows[j].ValidTimeStart })
	assert.Truef(t, sorted, "the %d capped rows must be validTimeStart-sorted", cap)
	t.Logf("10-row history with MaxRangeRows=%d returned %d rows with truncated=true (cap %d)", cap, len(rows), cap)

	rUnbounded := rangeWinResolver(alloc, store, 0)
	all, trUnc, err := rUnbounded.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err)
	assert.Falsef(t, trUnc, "MaxRangeRows=0 (unlimited) must not truncate (the disclosed unbounded sentinel)")
	assert.Lenf(t, all, N, "unlimited returns all %d intersecting rows (the cap-0 contrast)", N)
	t.Logf("MaxRangeRows=0 over the same 10-row history returned %d rows with truncated=false", len(all))
}

// TestEmptyWindowRangeReturnsErrEntityNotFound checks that a disjoint query
// window returns ErrEntityNotFound rather than a nil error and empty slice.
func TestEmptyWindowRangeReturnsErrEntityNotFound(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	sl := NewSkipListArena(alloc, 8*1024*1024)
	rangeWinInsertRow(t, sl, entity, rangeWinBase+1000, rangeWinBase+100, rangeWinBase+200, []byte("only-row"))
	rangeWinFlush(t, ctx, alloc, store, sl)

	r := rangeWinResolver(alloc, store, 4096)
	rows, truncated, err := r.Range(ctx, entity, time.Unix(0, rangeWinBase+300), time.Unix(0, rangeWinBase+400), time.Unix(0, rangeWinBase+99999))
	assert.ErrorIsf(t, err, ErrEntityNotFound, "a disjoint window must return ErrEntityNotFound (the not-found sentinel), not an empty 200")
	assert.Nilf(t, rows, "no rows on a not-found window")
	assert.Falsef(t, truncated, "truncated false on a not-found window (no cap interaction)")
	t.Logf("disjoint window returned ErrEntityNotFound")
}

// TestHalfOpenBoundsRangeCarriesFilter3Discipline verifies the half-open window
// boundary rules [vLo, vHi) match Filter 3 semantics.
func TestHalfOpenBoundsRangeCarriesFilter3Discipline(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	const rowLo = rangeWinBase + 100
	const rowHi = rangeWinBase + 200
	sl := NewSkipListArena(alloc, 8*1024*1024)
	rangeWinInsertRow(t, sl, entity, rangeWinBase+1000, rowLo, rowHi, []byte("boundary-row"))
	rangeWinFlush(t, ctx, alloc, store, sl)
	r := rangeWinResolver(alloc, store, 4096)
	tx := time.Unix(0, rangeWinBase+99999)

	cases := []struct {
		name   string
		expect bool
		vLo    int64
		vHi    int64
		why    string
	}{
		{"window_starts_at_row_start_full_overlap", true, rowLo, rowHi + 50, "vLo==rowLo, vHi>rowHi overlaps"},
		{"window_inside_row", true, rowLo + 10, rowLo + 20, "window strictly inside row interval"},
		{"window_ends_at_row_start_excluded", false, rowLo - 50, rowLo, "vHi==rowLo excluded at high end"},
		{"window_starts_at_row_end_excluded", false, rowHi, rowHi + 50, "vLo==rowHi excluded at low end"},
		{"window_disjoint_before", false, rowLo - 50, rowLo - 10, "entirely before row"},
		{"window_disjoint_after", false, rowHi + 10, rowHi + 50, "entirely after row"},
		{"window_exact_match", true, rowLo, rowHi, "exact interval equality [rowLo, rowHi)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows, _, err := r.Range(ctx, entity, time.Unix(0, c.vLo), time.Unix(0, c.vHi), tx)
			if c.expect {
				if err != nil || len(rows) != 1 {
					t.Fatalf("window [%d,%d): expected the row to intersect (why: %s); got err=%v rows=%d", c.vLo-rangeWinBase, c.vHi-rangeWinBase, c.why, err, len(rows))
				}
			} else {
				if !isRangeNotFound(err) {
					t.Fatalf("window [%d,%d): expected ErrEntityNotFound (why: %s); got err=%v rows=%d — the half-open bound discipline diverged from Filter3", c.vLo-rangeWinBase, c.vHi-rangeWinBase, c.why, err, len(rows))
				}
			}
		})
	}
}
