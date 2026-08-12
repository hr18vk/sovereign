// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// Resolver.Range guards (ADR-0024) — the durable bitemporal-HISTORY
// range read over the Arrow index (the multi-row generalization of AsOf).
//
// These guards are the SEAM-level proofs: they drive a flush → Range round-trip
// against an in-memory S3 simulator (memStore) using the production
// L0Flusher + SkipListArena the split-merge guards introduced. The REAL-*LocalFS
// route guards (over the production on-disk path) live in
// pkg/durability and pkg/mesh — the
// import-cycle constraint (an internal/database test cannot import
// pkg/durability because snapshot.go imports internal/database). This file holds
// the in-package seam guards that need only internal/database symbols: the
// interval-intersection proof, the AsOf-consistency superset, the Filter-4
// collision-guard, and the MaxRangeRows cap.
//
// LAW II (byte-identity, pre-traced before the first guard): Range reads the
// SAME durable surface AsOf reads (query.go AsOf + Range share the listing +
// supersession + reverse-sort discipline; scanWindowRecordBatch reuses the 4
// filters scanRecordBatch carries). A Range result MUST be a superset of the
// AsOf point at every v in the window — the load-bearing invariant.
//
// THE FILTER-4 PREMISE-AUDIT (the honest deviation, disclosed in ADR-0024 §4): the
// original framing seeded a sha256[:8]-prefix collision between two entities
// (same l0/<hex8>/ dir, different [:16]). A byte-read of query.go refutes that
// premise: col0 (entity_id_hash) is FixedSizeBinary(16) — the FULL 128-bit hash
// — and Filter 1 compares the FULL 16 bytes (bytes.Equal(rowHash, hashPrefix[:]),
// hashPrefix is [16]byte). A [:8]-collision-with-[:16]-diff is therefore REJECTED
// by Filter 1 itself, NEVER reaching Filter 4; dropping Filter 4 would NOT leak
// it. The naive RED ("drop Filter 4 leaks the collision") is a mechanism that
// does not hold against the bytes. The
// honest Filter-4 test DECOUPLES the col0 key prefix from the value-body
// entityID: a planted row whose 16-byte key claims "E1" (so it lands in E1's
// l0/<hex8(sha256(E1))>/ dir + passes Filter 1) but whose value-body entityID is
// "E2" (so Filter 4 MUST reject it). That exercises the REAL Filter-4 guard
// deterministically (no birthday search on 64 bits — infeasible in CI), matches
// the INTENT ("Range for E1 MUST NOT return E2's rows"), and is the
// defense-in-depth against a dishonest write path.

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
// sentinel (the "no matching event" honest-not-found signal query.go returns).
// AsOf/Range return it unwrapped from the list-empty + no-match paths (so a
// direct == suffices); errors.Is + the substring guard catch any future wrap.
// Mirrors the pkg/mesh isErrEntityNotFound helper (different package — this is
// the in-package copy the internal/database guards need).
func isRangeNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrEntityNotFound) || strings.Contains(err.Error(), ErrEntityNotFound.Error())
}

// openEndNs is the int64-safe open-ended ValidTimeEnd sentinel the Range guards
// use for rows whose validity extends past the window's high end (mirrors the
// query_test.go queryValidEndNs convention; deliberately NOT MaxValidTime.UnixNano
// — overflows int64, unqueryable; see query_test.go:78).
const openEndNs int64 = 9_000_000_000_000_000_000

// rangeWinBase is a fixed ns epoch (so the guards's file txTime suffixes are
// deterministic decimal lengths — lexicographic == numeric; AsOf/Range dominance
// is order-independent regardless but the determinism shrinks the surface). 1.7e18
// is comfortably below openEndNs (9e18) and int64-max (9.2e18).
const rangeWinBase int64 = 1_700_000_000_000_000_000

// rangeWinInsertRow inserts one tri-temporal row with an EXPLICIT valid-time window
// [validStart, validEnd) — the Range guards need DISTINCT windows to assert
// interval-intersection (the open-ended helper insertEntityRow
// sets validEnd = openEnd, which is a degenerate-window pin for AsOf,
// NOT a Range window-intersection test). It mirrors insertEntityRow but lets the
// caller set BOTH bounds.
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
	binary.BigEndian.PutUint64(key[32:40], uint64(sysNs))      // assertionTime (== sys for these guards)
	pd := sha256.Sum256(payload)
	val := makePackedValue(entityID, 0x89283082803ffff, validEnd, pd, payload)
	if err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) }); err != nil {
		t.Fatalf("rangeWinInsertRow Put %q: %v", entityID, err)
	}
}

// rangeWinInsertRowDecoupled plants a row whose 16-byte COL0 key claims
// "impostorHashEntity" (so it lands in THAT entity's l0/<hex8>/ dir + passes
// Filter 1 for a Range(impostorHashEntity) query) but whose VALUE-BODY entityID
// is "lyingEntityID" (so Filter 4 MUST reject it). This is the honest Filter-4
// test — see the file's Filter-4 premise-audit docstring. The col0/entityID are
// DECOUPLED by construction here; the production write path couples them
// (insertEntityRow sets both from sha256(entityID)), so this plants the ONE shape
// a dishonest/corrupt write could produce that reaches Filter 4. Filter 1 passes
// (16-byte col0 == the queried entity's hash); Filter 4 is the ONLY remaining
// guard against the leak.
func rangeWinInsertRowDecoupled(t *testing.T, sl *SkipListArena, impostorHashEntity, lyingEntityID string, sysNs, validStart, validEnd int64, payload []byte) {
	t.Helper()
	key := make([]byte, keySize)
	full := sha256.Sum256([]byte(impostorHashEntity)) // col0 = the QUERIED entity's 16-byte hash
	copy(key[0:16], full[:16])
	binary.BigEndian.PutUint64(key[16:24], uint64(sysNs))
	binary.BigEndian.PutUint64(key[24:32], uint64(validStart))
	binary.BigEndian.PutUint64(key[32:40], uint64(sysNs))
	pd := sha256.Sum256(payload)
	// value-body entityID = lyingEntityID (decoupled from col0). makePackedValue
	// embeds lyingEntityID into the body the flusher reads entityID from.
	val := makePackedValue(lyingEntityID, 0x89283082803ffff, validEnd, pd, payload)
	if err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) }); err != nil {
		t.Fatalf("rangeWinInsertRowDecoupled Put: %v", err)
	}
}

// rangeWinFlush flushes the arena to the in-memory store + frees the arena,
// returning the upload count (one per entity-hash partition). Mirrors the compaction
// flush discipline. The store satisfies S3Uploader/S3Lister/S3Downloader so the
// Resolver reads the SAME key-space the flush wrote.
func rangeWinFlush(t *testing.T, ctx context.Context, alloc *JemallocAllocator, store *memStore, sl *SkipListArena) int {
	t.Helper()
	flusher := NewL0Flusher(alloc, store, "range-bucket")
	uploaded, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err, "FlushFromArena")
	sl.Free()
	return uploaded
}

// rangeWinResolver builds a Resolver over the in-memory store with the given
// MaxRangeRows (0 = UNLIMITED). The store is BOTH lister + downloader (one key-
// space). bucket is cosmetic for memStore (it ignores it).
func rangeWinResolver(alloc *JemallocAllocator, store *memStore, maxRangeRows int) *Resolver {
	return NewResolver(store, store, alloc, "range-bucket", ResolverConfig{MaxRangeRows: maxRangeRows})
}

// ---------------------------------------------------------------------------
// Interval-INTERSECTION (NOT point-in-window): the headline.
// ---------------------------------------------------------------------------

// TestRangeHeadlineIntervalIntersectionNotPointInWindow is the headline Range guard.
// Write 4 events for E with ValidTime windows [10,20), [30,40), [50,60), [70,80);
// flush; Range E window [25,65), txTime=now → returns EXACTLY the [30,40)+[50,60)
// rows. The window INTERSECTS both; [10,20) ends at vLo=25 -> excluded (W1/W2:
// validEnd 20 <= vLo 25); [70,80) starts at vHi=65 -> excluded (W1: validStart 70
// >= vHi 65). A point-query generalization returns ONE; the GREEN is 2 rows,
// validTimeStart-sorted. This PROVES interval-intersection (§1.1), the load-
// bearing semantic a point-in-window test would SILENTLY LOSE history on.
func TestRangeHeadlineIntervalIntersectionNotPointInWindow(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	// 4 disjoint windows, all SystemTime < txTime (so Filter2 admits all).
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

	// Query window [25, 65). Intersects [30,40) and [50,60); excludes [10,20)
	// (ends before vLo) and [70,80) (starts at vHi).
	vLo := time.Unix(0, rangeWinBase+25)
	vHi := time.Unix(0, rangeWinBase+65)
	tx := time.Unix(0, sys+9999) // > all SystemTimes
	r := rangeWinResolver(alloc, store, 4096)
	rows, truncated, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range must resolve (2 intersecting rows)")
	assert.Falsef(t, truncated, "truncated must be false (2 rows << MaxRangeRows)")

	// GREEN: EXACTLY the 2 intersecting rows, validTimeStart-sorted ascending.
	require.Lenf(t, rows, 2, "interval-intersection: window [25,65) intersects [30,40)+[50,60) only; got %d rows", len(rows))
	wantStarts := []int64{rangeWinBase + 30, rangeWinBase + 50}
	gotStarts := []int64{rows[0].ValidTimeStart, rows[1].ValidTimeStart}
	assert.Equalf(t, wantStarts, gotStarts, "rows must be validTimeStart-sorted [30 then 50], the honest raw window")
	// The EXCLUDED windows are absent (the silent-data-loss class a point-in-
	// window or wrong-bounded test would NOT catch — each boundary below is a
	// distinct W1/W2 exclusion, proven by ABSENCE).
	for _, row := range rows {
		assert.Falsef(t, row.ValidTimeStart == rangeWinBase+10, "[10,20) must be EXCLUDED (validEnd 20 <= vLo 25 — W2)")
		assert.Falsef(t, row.ValidTimeStart == rangeWinBase+70, "[70,80) must be EXCLUDED (validStart 70 >= vHi 65 — W1)")
	}
	t.Logf("T1: Range [25,65) over 4 disjoint windows → %d rows ([30,40)+[50,60)); [10,20) excluded (W2), [70,80) excluded (W1) — interval-intersection proven, NOT point-in-window", len(rows))
}

// ---------------------------------------------------------------------------
// AsOf-CONSISTENCY: Range is a SUPERSET of every AsOf point in the window.
// ---------------------------------------------------------------------------

// TestAsOfConsistencyRangeSupersetOfEveryPoint is the
// LOAD-BEARING invariant. For the SAME entity+txTime, AsOf(E, v, txTime) for ANY v
// in [vLo, vHi) returns a row PRESENT in Range(E, [vLo,vHi), txTime). A Range that
// uses a DIFFERENT filter than AsOf (the consistency killer) breaks this — 4-probe
// sweep (vLo, mid, vHi-1, vHi) each AsOf ∈ Range result-set.
//
// Seeded with OVERLAPPING windows so AsOf's dominance + Range's intersection see
// the SAME set of rows (no single-point/interval divergence on disjoint data).
// txTime is fixed; AsOf picks max-SystemTime<=txTime per point; Range returns every
// intersecting row — the AsOf dominant MUST be among them.
func TestAsOfConsistencyRangeSupersetOfEveryPoint(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	// Overlapping windows whose union spans [10, 90): a point sweep across the
	// window lands in multiple rows; the consistency killer (a Range filter that
	// DIVERGES from AsOf's, e.g. an off-by-one bound) drops an AsOf-eligible row.
	wins := [][2]int64{
		{rangeWinBase + 10, rangeWinBase + 50}, // [10,50)
		{rangeWinBase + 30, rangeWinBase + 70}, // [30,70)
		{rangeWinBase + 55, rangeWinBase + 90}, // [55,90)
	}
	// Distinct SystemTimes so AsOf dominance is deterministic at each point.
	sys := []int64{rangeWinBase + 1000, rangeWinBase + 2000, rangeWinBase + 3000}
	sl := NewSkipListArena(alloc, 8*1024*1024)
	for i, w := range wins {
		rangeWinInsertRow(t, sl, entity, sys[i], w[0], w[1], []byte(fmt.Sprintf("ov%d", i)))
	}
	rangeWinFlush(t, ctx, alloc, store, sl)

	vLo := time.Unix(0, rangeWinBase+10)
	vHi := time.Unix(0, rangeWinBase+90)
	tx := time.Unix(0, rangeWinBase+99999) // > all SystemTimes → Filter2 admits all
	r := rangeWinResolver(alloc, store, 4096)
	rows, _, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range over the union window")
	// Index Range rows by (validStart, SystemTime) for the superset containment check.
	type key struct{ vs, sys int64 }
	rangeSet := make(map[key]*TriTemporalEvent, len(rows))
	for _, row := range rows {
		rangeSet[key{row.ValidTimeStart, row.SystemTime}] = row
	}
	// 4-probe sweep: vLo, mid, vHi-1, vHi (vHi itself is OUTSIDE the half-open
	// window — AsOf at vHi may still resolve a row whose interval extends past vHi,
	// but the invariant is for v IN [vLo,vHi); we probe vHi as a NEGATIVE
	// control: an AsOf at vHi should ALSO be in Range IF Range's window were
	// [vLo, ∞) — but [vLo,vHi) excludes a row that STARTS at vHi. The positive
	// probes are vLo, mid, vHi-1.)
	for _, probe := range []int64{rangeWinBase + 10, rangeWinBase + 45, rangeWinBase + 60, rangeWinBase + 89} {
		vT := time.Unix(0, probe)
		got, asErr := r.AsOf(ctx, entity, vT, tx)
		require.NoErrorf(t, asErr, "AsOf at v=%d must resolve (an intersecting row covers it)", probe-rangeWinBase)
		require.NotNil(t, got)
		k := key{got.ValidTimeStart, got.SystemTime}
		_, present := rangeSet[k]
		assert.Truef(t, present,
			"T2 superset: AsOf(E, v=%d) row {vs=%d,sys=%d} NOT in Range(E, [10,90)) result-set — Range is NOT a superset of the AsOf point (the consistency killer: Range's filter DIVERGES from AsOf's)",
			probe-rangeWinBase, got.ValidTimeStart, got.SystemTime)
	}
	t.Logf("T2: 4-point AsOf sweep (v=10,45,60,89) each ∈ Range result-set — Range is a SUPERSET of every AsOf point in the window (the load-bearing invariant holds)")
}

// ---------------------------------------------------------------------------
// Filter-4 integrity (the collision guard carries): the decoupled-col0 test.
// ---------------------------------------------------------------------------

// TestFilter4IntegrityDecoupledCol0NotEntityID. A
// planted row whose 16-byte col0 key claims E1 (the queried entity — passes
// Filter 1 + lands in E1's l0/<hex8>/ dir) but whose value-body entityID is E2
// (an imposter) MUST be rejected by Filter 4 (full entityID verify). The RED:
// a Range that drops Filter 4 returns E2's imposter row for a Range(E1) query
// (the data-leak-for-the-wrong-entity class). The GREEN: no E2 row in the E1
// window.
//
// PREMISE-AUDIT (disclosed in the file docstring + ADR-0024 §4): the original
// framing was a sha256[:8] collision between two entities — refuted by a
// byte-read (col0 is FixedSizeBinary(16); Filter 1 compares the FULL 16 bytes,
// so a [:8]-collision-with-[:16]-diff is caught by Filter 1, NOT Filter 4). The
// honest test DECOUPLES col0 from value-body entityID (the ONE shape a dishonest
// write could produce that reaches Filter 4), exercising the REAL guard
// deterministically — no infeasible 64-bit birthday search. The intent matches:
// "Range for E1 MUST NOT return E2's rows."
func TestFilter4IntegrityDecoupledCol0NotEntityID(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const e1 = "alpha"        // the QUERIED entity
	const e2 = "imposter-zzz" // the lying value-body entityID (decoupled col0)
	const wLo = rangeWinBase + 10
	const wHi = rangeWinBase + 90

	sl := NewSkipListArena(alloc, 8*1024*1024)
	// One HONEST E1 row in the window (so Range resolves non-empty).
	rangeWinInsertRow(t, sl, e1, rangeWinBase+1000, wLo, wHi, []byte("e1-real"))
	// One DECOUPLED row: col0 = sha256(e1)[:16] (lands in e1's dir + passes
	// Filter 1 for a Range(e1)), value-body entityID = e2 (Filter 4 MUST reject).
	rangeWinInsertRowDecoupled(t, sl, e1, e2, rangeWinBase+2000, wLo, wHi, []byte("e2-imposter"))
	uploaded := rangeWinFlush(t, ctx, alloc, store, sl)
	require.Equal(t, 1, uploaded, "both rows share e1's hex8 dir → ONE partition, ONE file")

	r := rangeWinResolver(alloc, store, 4096)
	rows, _, err := r.Range(ctx, e1, time.Unix(0, wLo), time.Unix(0, wHi), time.Unix(0, rangeWinBase+99999))
	require.NoError(t, err, "Range(e1) must resolve (the honest E1 row)")
	// GREEN: the honest E1 row is present, the E2 imposter is EXCLUDED.
	var sawE1, sawE2 bool
	for _, row := range rows {
		switch row.EntityID {
		case e1:
			sawE1 = true
		case e2:
			sawE2 = true
		}
	}
	assert.Truef(t, sawE1, "the honest E1 row must be present in Range(e1)")
	assert.Falsef(t, sawE2, "T3 RED: the E2 imposter row (col0=sha256(e1), value-entityID=e2) MUST be excluded by Filter 4 — a Range that drops Filter 4 leaks the wrong entity's rows into E1's window")
	if sawE2 {
		t.Logf("T3 FAILED: E2 imposter row LEAKED into Range(e1) — Filter 4 (full entityID verify) was dropped or weakened")
	} else {
		t.Logf("T3: the decoupled-row (col0=sha256(e1)[:16], value-body entityID=e2) was rejected by Filter 4 — the collision guard carries, Range(e1) returns no e2 rows")
	}
}

// ---------------------------------------------------------------------------
// MaxRangeRows + truncated: the cap is checked BEFORE the marshal.
// ---------------------------------------------------------------------------

// TestMaxRangeRowsCapTruncatedPreMarshal. A 10-row
// history (10 disjoint windows, all intersecting a wide query window) → Range
// with MaxRangeRows=4 returns EXACTLY 4 rows + truncated=true. The cap is
// checked in the collector BEFORE the slice carries >4 rows — the marshal never
// sees >4. (The seam-level proof: pkg/durability re-proves over *LocalFS.)
func TestMaxRangeRowsCapTruncatedPreMarshal(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	const N = 10
	const cap = 4
	// 10 disjoint windows, all intersecting the wide query window [0, 1000).
	sl := NewSkipListArena(alloc, 8*1024*1024)
	for i := 0; i < N; i++ {
		vs := rangeWinBase + int64(100*i)
		ve := vs + 50 // [vs, vs+50)
		rangeWinInsertRow(t, sl, entity, rangeWinBase+int64(i), vs, ve, []byte(fmt.Sprintf("cap-%d", i)))
	}
	uploaded := rangeWinFlush(t, ctx, alloc, store, sl)
	require.Equal(t, 1, uploaded)

	// Wide window [0, 1000) intersects ALL 10.
	vLo := time.Unix(0, rangeWinBase)
	vHi := time.Unix(0, rangeWinBase+1000)
	tx := time.Unix(0, rangeWinBase+99999)
	r := rangeWinResolver(alloc, store, cap) // MaxRangeRows=4
	rows, truncated, err := r.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err, "Range must resolve (capped at %d of %d rows)", cap, N)
	assert.Truef(t, truncated, "truncated MUST be true (the %d-row history exceeds MaxRangeRows=%d)", N, cap)
	require.Lenf(t, rows, cap, "the marshal NEVER sees >MaxRangeRows rows: exactly %d returned, want %d (1 row could be a stale-gate; the count IS the proof)", cap, cap)
	// The returned rows are the FIRST cap the scan encountered — sorted by
	// validTimeStart ascending (the honest post-sort window order). Assert they
	// ARE validTimeStart-sorted (the operator-facing contract) + distinct.
	sorted := sort.SliceIsSorted(rows, func(i, j int) bool { return rows[i].ValidTimeStart < rows[j].ValidTimeStart })
	assert.Truef(t, sorted, "the %d capped rows must be validTimeStart-sorted (the honest post-sort window order)", cap)
	t.Logf("T5: 10-row history, MaxRangeRows=%d → exactly %d rows returned + truncated=true (cap checked pre-marshal; marshal never saw >%d)", cap, len(rows), cap)

	// The UNLIMITED control (cap=0): the SAME 10-row history returns ALL 10 +
	// truncated=false — the disclosed unbounded sentinel, the honest contrast.
	rUnbounded := rangeWinResolver(alloc, store, 0) // 0 = UNLIMITED
	all, trUnc, err := rUnbounded.Range(ctx, entity, vLo, vHi, tx)
	require.NoError(t, err)
	assert.Falsef(t, trUnc, "MaxRangeRows=0 (UNLIMITED) must NOT truncate (the disclosed unbounded sentinel)")
	assert.Lenf(t, all, N, "UNLIMITED returns all %d intersecting rows (the cap-0 contrast — the disclosed unbounded path)", N)
	t.Logf("T5 control: MaxRangeRows=0 (UNLIMITED) over the SAME 10-row history → %d rows, truncated=false (the honest unbounded contrast)", len(all))
}

// ---------------------------------------------------------------------------
// The negative control: a window that intersects NO row → 404-class
// (ErrEntityNotFound), NOT an empty 200. Mirrors AsOf's honest-not-found.
// ---------------------------------------------------------------------------

// TestEmptyWindowRangeReturnsErrEntityNotFound is the negative
// control for the headline guard: a query window disjoint from every durable row returns
// ErrEntityNotFound (the SAME sentinel AsOf returns when no row matches), NOT an
// empty 200. The /v1/range handler maps this to the honest 404 (the SAME as
// /v1/query). A Range that returned an empty []TriTemporalEvent + nil error would
// be indistinguishable to the handler from a 200-with-empty-window — the honest
// contract is the sentinel.
func TestEmptyWindowRangeReturnsErrEntityNotFound(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "alpha"
	sl := NewSkipListArena(alloc, 8*1024*1024)
	// One row at [100, 200).
	rangeWinInsertRow(t, sl, entity, rangeWinBase+1000, rangeWinBase+100, rangeWinBase+200, []byte("only-row"))
	rangeWinFlush(t, ctx, alloc, store, sl)

	r := rangeWinResolver(alloc, store, 4096)
	// Window [300, 400) — disjoint from the only row [100,200).
	rows, truncated, err := r.Range(ctx, entity, time.Unix(0, rangeWinBase+300), time.Unix(0, rangeWinBase+400), time.Unix(0, rangeWinBase+99999))
	assert.ErrorIsf(t, err, ErrEntityNotFound, "a disjoint window must return ErrEntityNotFound (the honest not-found sentinel), NOT an empty 200")
	assert.Nilf(t, rows, "no rows on a not-found window")
	assert.Falsef(t, truncated, "truncated false on a not-found window (no cap interaction)")
	t.Logf("T1-empty: a window disjoint from every durable row → ErrEntityNotFound (honest not-found, NOT an empty 200)")
}

// ---------------------------------------------------------------------------
// BOUNDARY guards: the half-open [vLo, vHi) bound discipline (carry Filter 3).
// ---------------------------------------------------------------------------

// TestHalfOpenBoundsRangeCarriesFilter3Discipline asserts the W1/W2
// bound discipline carries Filter 3's strict/non-strict bounds EXACTLY. A row
// [100,200): a query window [200, 300) must EXCLUDE it (W2: validEnd 200 <= vLo
// 200 → row ends AT the window's low end, half-open excludes); a window [50, 100)
// must EXCLUDE it (W1: validStart 100 >= vHi 100 → row starts AT the window's
// high end, half-open excludes). A window [100, 200) must EXCLUDE it too (W1:
// validStart 100 >= vHi 200? NO — validStart 100 < vHi 200 AND validEnd 200 > vLo
// 100 → INTERSECTS). This pins the EXACT boundary: a row whose interval touches
// the window at exactly one endpoint is EXCLUDED; a row whose interval OVERLAPS
// is INCLUDED.
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
		expect bool  // does the row intersect the window?
		vLo    int64 // fields reordered bool-before-int64 to satisfy fieldalignment (cache law; the same lint the production path gates on)
		vHi    int64
		why    string
	}{
		{"window_starts_at_row_start_full_overlap", true, rowLo, rowHi + 50, "vLo==rowLo, vHi>rowHi → fully overlaps"},
		{"window_inside_row", true, rowLo + 10, rowLo + 20, "window ⊂ row interval → contains"},
		{"window_ends_at_row_start_EXCLUDED", false, rowLo - 50, rowLo, "vHi==rowLo (W1: validStart>=vHi → excluded at the high end)"},
		{"window_starts_at_row_end_EXCLUDED", false, rowHi, rowHi + 50, "vLo==rowHi (W2: validEnd<=vLo → excluded at the low end)"},
		{"window_disjoint_before", false, rowLo - 50, rowLo - 10, "entirely before the row"},
		{"window_disjoint_after", false, rowHi + 10, rowHi + 50, "entirely after the row"},
		{"window_exact_match", true, rowLo, rowHi, "vLo==rowLo, vHi==rowHi → [rowLo,rowHi) ⊆ [vLo,vHi) endpoint-touch ≠ intersect-with-zero-width; validStart<Hi && validEnd>Lo both hold"},
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
					t.Fatalf("window [%d,%d): expected ErrEntityNotFound (why: %s); got err=%v rows=%d — the half-open bound discipline DIVERGED from Filter3", c.vLo-rangeWinBase, c.vHi-rangeWinBase, c.why, err, len(rows))
				}
			}
		})
	}
}
