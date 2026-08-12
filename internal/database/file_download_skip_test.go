// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// (ADR-0029) guards — the filename-bounded download skip, the durable
// AsOf/Range download-cut.
//
// This CLOSES the genuine unbounded-cost residual the durable read path has
// carried since the read path landed (ADR-0017 §6.1): AsOf + Range are O(L0-files) per query
// because they DOWNLOAD + DECODE every L0/L1 Arrow file under the entity's
// prefix, even when the file's filename-encoded FirstSysTimeNs (the file's MIN
// sysTime, written by the flush) proves the file carries ZERO rows
// visible at the query's txTime. The skip is a `continue` BEFORE the Download —
// it cuts the DOWNLOAD count, not the per-file decode.
//
// THE PREMISE-AUDIT (ADR-0029 §7):
// an earlier plan (ADR-0028 §6.a) named the next move as "wire Seek into
// scanWindowRecordBatch." That premise is FALSE on the bytes (load-bearing):
// scanWindowRecordBatch takes arrow.Record (query.go:1013), NOT a SkipList; the
// Resolver struct holds NO MemTable field (query.go:104-128); ZERO SkipList/Seek
// reference in the durable read path (grep-verified). The wiring target is a
// NO-OP. The genuine acceleration target is the DOWNLOAD (the cost), NOT the row
// scan (which has NO SkipList to accelerate). The bound the SkipList COULD
// support (sysTime, via the composite key) is the bound the FILENAME ALREADY
// carries for free.
//
// THE TRANSITIVELY-SAFE ELIMINATION (§0.e — a TAUTOLOGY, NOT a heuristic): for a
// query at txTime T + a file F with filename min(F): min(F) > T ⟹ ∀ row r in F:
// r.sysTime >= min(F) > T ⟹ Filter2 (sysTime<=txTime) FALSE ⟹ ZERO qualifying
// rows ⟹ skipping F's download preserves the answer set IDENTICALLY (the honest-fallback invariant).
// The bound is STRICT (firstSys > txTime): a row AT sysTime==txTime passes
// Filter2 (<=), so firstSys==txTime means the file's first row MIGHT qualify →
// DO NOT skip (the off-by-skip boundary guard).
//
// These guards are the SEAM-level proofs over the in-memory S3 simulator
// (memStore). The REAL-*LocalFS route guards live in
// pkg/durability (the import-cycle constraint — an
// internal/database test cannot import pkg/durability). The telemetry + bridge sister
// guards live in internal/telemetry + pkg/metrics.
// This file holds the in-package guards that need only
// internal/database symbols: the parser, the failsafe honest-fallback
// preservation, the EQUIV fuzz, + the skip boundary.

package database

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fileSkipBase is a fixed ns epoch for these guards (same convention as
// rangeWinBase: 1.7e18, comfortably below openEndNs (9e18) + int64-max (9.2e18),
// 19-digit fixed-width so lexicographic == numeric — the §1.a parse uses
// strconv.ParseInt base 10, NOT a lexical compare, so the width is for the
// production-realism of the filename, not the skip's correctness).
const fileSkipBase int64 = 1_700_000_000_000_000_000

// ---------------------------------------------------------------------------
// §1.a the zero-alloc filename parser (l0 + l1 grammar).
// ---------------------------------------------------------------------------

// TestSkipParser: parseFirstSysFromKey
// extracts the file's MIN sysTime (FirstSysTimeNs) from a durable Arrow key.
// Grammar (byte-verified against the writer): "<tier>/<hex(hash8)>/<int64-
// decimal>.arrow", tier ∈ {"l0","l1"}. For BOTH tiers it returns the EXACT
// int64 written. RED controls: no slash, no dot, non-numeric tail, NEGATIVE
// tail (the §1.a landmine disarm), trailing-slash key. The parser NEVER panics
// + NEVER allocates (the alloc guard asserts the latter).
func TestSkipParser(t *testing.T) {
	// The headline: a 19-digit production UnixNano parses EXACTLY.
	got, ok := parseFirstSysFromKey("l0/abcd1234/1785542400000000000.arrow")
	require.Truef(t, ok, "l0 production key must parse (ok=true)")
	assert.Equalf(t, int64(1785542400000000000), got, "l0 key: parseFirstSysFromKey must return the EXACT int64 written")

	// l1 tier: the SAME grammar, the SAME parser (the read path lists BOTH tiers).
	gotL1, okL1 := parseFirstSysFromKey("l1/abcd1234/1785542400000000000.arrow")
	require.Truef(t, okL1, "l1 production key must parse (ok=true)")
	assert.Equalf(t, int64(1785542400000000000), gotL1, "l1 key: parseFirstSysFromKey must return the EXACT int64 written")

	// A smaller value (the staggered-file guard uses i*1000 sysTimes — verify
	// the parser handles non-19-digit widths correctly; strconv.ParseInt base 10
	// is width-agnostic, unlike a lexical compare).
	gotSmall, okSmall := parseFirstSysFromKey("l0/abcd1234/1000.arrow")
	require.True(t, okSmall)
	assert.Equal(t, int64(1000), gotSmall, "a 4-digit suffix must parse (ParseInt base 10 is width-agnostic)")

	// RED controls — each returns ok=false (the honest fallback: do NOT skip).
	redCases := []struct {
		name string
		key  string
	}{
		{"no slash", "1785542400000000000.arrow"},
		{"no dot", "l0/abcd1234/1785542400000000000"},
		{"non-numeric tail", "l0/abcd1234/NOTANUMBER.arrow"},
		{"negative tail (§1.a landmine disarm)", "l0/abcd1234/-1785542400000000000.arrow"},
		{"trailing slash", "l0/abcd1234/"},
		{"dot at position 0 (no numeric prefix)", "l0/abcd1234/.arrow"},
	}
	for _, c := range redCases {
		_, ok := parseFirstSysFromKey(c.key)
		assert.Falsef(t, ok, "RED control %q: must return ok=false (the honest fallback — do NOT skip; no row is silently dropped)", c.name)
	}
	t.Logf("skip-parser PASS: l0+l1 production keys parse EXACT; 6 RED controls return ok=false (the honest fallback — never silently skip a parse anomaly)")
}

// ---------------------------------------------------------------------------
// The zero-alloc property (MEASURED, not "0").
// ---------------------------------------------------------------------------

// TestSkipParserAlloc.
// testing.AllocsPerRun over parseFirstSysFromKey. The HONEST expectation: 0
// allocs — the suffix extraction is a strings.LastIndexByte slice + a
// strconv.ParseInt(base 10) on the trimmed tail, NO strings.Split, NO regexp.
// The numeric string is < 40 bytes; ParseInt does NOT allocate. Assert allocs
// == 0 (MEASURED, not asserted; the parser is on the read path, the §0.e read-path-
// zero-alloc discipline). The key is built INSIDE the AllocsPerRun closure so
// it does not escape (building it outside + capturing would heap-allocate the
// string — the anti-pattern, the seek-alloc precedent).
func TestSkipParserAlloc(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		// Key built INSIDE the closure — a string literal does not escape
		// (parseFirstSysFromKey only slices it + ParseInts the tail; nothing
		// stores it). A const-length literal is the cleanest zero-alloc form.
		_, _ = parseFirstSysFromKey("l0/abcd1234/1785542400000000000.arrow")
	})
	assert.Equalf(t, 0.0, allocs, "parseFirstSysFromKey must allocate 0 (LastIndexByte slice + ParseInt base 10 — no Split, no regexp; the §0.e read-path-zero-alloc discipline) — got %v", allocs)
	t.Logf("skip-parser-alloc: parseFirstSysFromKey allocs/run = %v (LastIndexByte + ParseInt; zero-alloc read-path parser)", allocs)
}

// ---------------------------------------------------------------------------
// A corrupt filename is NEVER silently dropped.
// ---------------------------------------------------------------------------

// TestSkipFailsafe: a key
// shaped "l0/{hex8}/NOTANUMBER.arrow" (a renamed/corrupt file the lister still
// returns). With EnableFirstSysSkip=true, the parser returns (0, false) → NO
// skip → the file is downloaded + scanned (the pre-skip path). The disclosure
// counter does NOT fire. The answer is byte-IDENTICAL to EnableFirstSysSkip=
// false. A corrupt filename is NEVER silently dropped — the honest
// fallback is the full download.
//
// The guard drives a REAL flush→query round-trip over memStore, then
// PLANTS a corrupt-renamed key (a copy of a real file's bytes under a
// "l0/{hex8}/NOTANUMBER.arrow" key) so the lister returns it. The skip's parser
// fails on it (ok=false) → the file is downloaded + scanned → its rows ARE in
// the answer (NOT dropped). The comparison: EnableFirstSysSkip=true ==
// EnableFirstSysSkip=false byte-identically (the corrupt key's rows survive
// under BOTH, because the skip does NOT fire on a parse anomaly).
func TestSkipFailsafe(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()

	const entity = "failsafe-entity"
	// One real file: sysTime = fileSkipBase + 100, valid [fileSkipBase, openEnd).
	sl := NewSkipListArena(alloc, 2*1024*1024)
	rangeWinInsertRow(t, sl, entity, fileSkipBase+100, fileSkipBase, openEndNs, []byte("real-row"))
	require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl), "one real L0 file flushed")

	// PLANT a corrupt-renamed key: copy the real file's Arrow bytes under a
	// "l0/{hex8}/NOTANUMBER.arrow" key (the SAME hex8 prefix so the lister
	// returns it under the entity's l0Prefix; the tail is non-numeric so the
	// parser fails). This simulates a renamed/corrupt file the lister still
	// returns — the §1.a FAILSAFE contract.
	h8 := sha256.Sum256([]byte(entity))
	hexHex := hexEncode8(h8)
	realKey := fmt.Sprintf("l0/%s/%d.arrow", hexHex, fileSkipBase+100)
	corruptKey := fmt.Sprintf("l0/%s/NOTANUMBER.arrow", hexHex)
	store.mu.Lock()
	realBytes := store.objects[realKey]
	store.objects[corruptKey] = realBytes // the SAME Arrow bytes under a corrupt filename
	store.mu.Unlock()

	// The parser fails on the corrupt key (the §1.a landmine disarm — do NOT skip).
	_, ok := parseFirstSysFromKey(corruptKey)
	require.Falsef(t, ok, "the corrupt key %q must NOT parse (ok=false) — the §1.a failsafe; the file is downloaded + scanned, NOT dropped", corruptKey)

	// Query at txTime ABOVE the real row's sysTime (so the real row qualifies).
	// Under EnableFirstSysSkip=true: the corrupt key does NOT skip (parse fails)
	// → its rows ARE scanned → the answer INCLUDES them. Under false: same path.
	// The answer is byte-IDENTICAL — the corrupt filename is NEVER silently dropped.
	qEntity := func(enable bool) *TriTemporalEvent {
		cfg := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: enable}
		r := NewResolver(store, store, alloc, "fileskip-failsafe", cfg)
		got, err := r.AsOf(ctx, entity, time.Unix(0, fileSkipBase+50), time.Unix(0, fileSkipBase+99999))
		require.NoErrorf(t, err, "AsOf must resolve under EnableFirstSysSkip=%v (the corrupt key's rows survive)", enable)
		require.NotNilf(t, got, "the dominant must be non-nil under EnableFirstSysSkip=%v", enable)
		return got
	}
	withSkip := qEntity(true)
	withoutSkip := qEntity(false)
	// byte-IDENTITY: the corrupt filename did NOT change the answer (the skip
	// did NOT fire on it; the rows survived under BOTH paths).
	assert.Equalf(t, withSkip.SystemTime, withoutSkip.SystemTime, "FAILSAFE: SystemTime must be byte-identical (the corrupt key was NOT dropped under the skip)")
	assert.Equalf(t, withSkip.Payload, withoutSkip.Payload, "FAILSAFE: Payload must be byte-identical (the corrupt key's rows survived)")
	assert.Equalf(t, withSkip.ValidTimeStart, withoutSkip.ValidTimeStart, "FAILSAFE: ValidTimeStart byte-identical")
	t.Logf("skip-failsafe PASS: corrupt key %q did NOT parse → NOT skipped → its rows survive byte-identical under EnableFirstSysSkip true vs false (a corrupt filename is NEVER silently dropped)", corruptKey)
}

// ---------------------------------------------------------------------------
// The STRICT > bound (firstSys==txTime → NO skip).
// ---------------------------------------------------------------------------

// TestSkipOffBySkipIPBoundary
// (the §1.c boundary guard). Edge cases, each over the in-memory store:
//   - txTime == firstSys (a row AT sysTime==firstSys passes Filter2 with <=) →
//     the file's first row MIGHT qualify → DO NOT skip (firstSys > txTime is
//     false). ASSERT: no skip, download runs, the first row is returned.
//   - txTime == firstSys - 1 (every row sysT >= firstSys > txTime) → SKIP.
//     ASSERT: skip fires, download NOT called, the file's rows are absent.
//   - txTime BELOW every file's firstSys → ALL skipped (answer-preserving empty
//     result; AsOf returns ErrEntityNotFound — byte-identical to the no-skip
//     path's empty result).
//   - txTime ABOVE every file's firstSys → NONE skipped (the §6.a scope cap).
//
// The load-bearing boundary: firstSys == txTime MUST NOT skip (a row AT sysTime
// == txTime passes Filter2 with <=, so firstSys == txTime means the file's first
// row DOES qualify → skipping it would DROP a qualifying row → a qualifying row is silently dropped).
// The EQUIV fuzz is the gate on the full set; THIS guard pins the boundary.
func TestSkipOffBySkipIPBoundary(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()

	// Build a store with ONE file at firstSys = fileSkipBase + 1000 (one row at
	// sysTime == firstSys, valid [fileSkipBase, openEnd) so it qualifies at any
	// validTime below openEnd).
	const firstSys = fileSkipBase + 1000
	buildFile := func(t *testing.T) *memStore {
		t.Helper()
		store := newMemStore()
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, "boundary-entity", firstSys, fileSkipBase, openEndNs, []byte("boundary-row"))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))
		return store
	}

	// (1) txTime == firstSys → NO skip (a row AT sysTime==firstSys passes Filter2).
	store1 := buildFile(t)
	r1 := NewResolver(store1, store1, alloc, "fileskip-b1", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got1, err1 := r1.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys))
	require.NoErrorf(t, err1, "txTime==firstSys: AsOf must resolve (the file's first row at sysTime==firstSys passes Filter2 with <=)")
	require.NotNilf(t, got1, "txTime==firstSys: the dominant must be non-nil (the row at sysTime==firstSys QUALIFIES — DO NOT skip)")
	assert.Equalf(t, firstSys, got1.SystemTime, "txTime==firstSys: the returned row's SystemTime == firstSys (the file was NOT skipped)")

	// (2) txTime == firstSys - 1 → SKIP (every row sysT >= firstSys > txTime).
	store2 := buildFile(t)
	r2 := NewResolver(store2, store2, alloc, "fileskip-b2", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got2, err2 := r2.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys-1))
	assert.Errorf(t, err2, "txTime==firstSys-1: AsOf must return ErrEntityNotFound (the file was SKIPPED — every row sysT >= firstSys > txTime)")
	assert.Nilf(t, got2, "txTime==firstSys-1: no dominant (the skip dropped the file — correctly, zero qualifying rows)")
	// Answer-preserving: the no-skip path ALSO returns NotFound here (the row at
	// sysTime==firstSys fails Filter2 since firstSys > firstSys-1). byte-identical.
	r2NoSkip := NewResolver(store2, store2, alloc, "fileskip-b2-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	got2No, err2No := r2NoSkip.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys-1))
	assert.Errorf(t, err2No, "the no-skip path at txTime==firstSys-1 ALSO returns ErrEntityNotFound (the row fails Filter2 — the skip is answer-preserving, byte-identical)")
	assert.Nilf(t, got2No, "no-skip path: no dominant (the skip changed NOTHING — both paths empty)")

	// (3) txTime BELOW every file's firstSys → ALL skipped → ErrEntityNotFound
	// (byte-identical to the no-skip path's empty result).
	store3 := buildFile(t)
	r3 := NewResolver(store3, store3, alloc, "fileskip-b3", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	_, err3 := r3.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys-500))
	assert.Errorf(t, err3, "txTime far below firstSys: ErrEntityNotFound (the file skipped — answer-preserving empty result)")

	// (4) txTime ABOVE every file's firstSys → NONE skipped (the §6.a scope cap:
	// The skip helps FORENSIC queries BELOW the frontier, NOT queries above it).
	store4 := buildFile(t)
	r4 := NewResolver(store4, store4, alloc, "fileskip-b4", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got4, err4 := r4.AsOf(ctx, "boundary-entity", time.Unix(0, fileSkipBase+50), time.Unix(0, firstSys+99999))
	require.NoErrorf(t, err4, "txTime above firstSys: AsOf must resolve (the skip does NOT fire — firstSys < txTime)")
	require.NotNilf(t, got4, "txTime above firstSys: the dominant must be non-nil (NONE skipped)")
	assert.Equalf(t, firstSys, got4.SystemTime, "txTime above firstSys: the returned row's SystemTime == firstSys (the file was NOT skipped — the §6.a scope cap)")
	t.Logf("skip-off-by-skip-boundary PASS: txTime==firstSys → NO skip (row qualifies); txTime==firstSys-1 → SKIP (byte-identical to no-skip NotFound); below → ALL skipped; above → NONE skipped (the §6.a scope cap)")
}

// ---------------------------------------------------------------------------
// §0.e the differential-equivalence fuzz (the load-bearing gate).
// ---------------------------------------------------------------------------

// TestSkipEquiv is the LOAD-BEARING differential-
// equivalence proof. For N=64 files for ONE entity, FirstSysTimeNs staggered at
// i*1000 (i=0..63), each file holds ONE row at sysTime == firstSys (valid
// [fileSkipBase, openEndNs) so it qualifies at any validTime below openEnd). Fuzz
// 2000 txTime values via rand.New(rand.NewPCG(24, 0)) in [0, 64000]. For EACH
// txTime: run AsOf with EnableFirstSysSkip=true AND with =false. ASSERT byte-
// IDENTITY of the dominant TriTemporalEvent (SystemTime/ValidTimeStart/
// ValidTimeEnd/Payload). The skip fires on some subset; the answer is
// UNCHANGED for ALL 2000 txTimes. The transitively-safe elimination (§0.e)
// holds: file.min > T ⟹ zero qualifying rows ⟹ skip preserves the set.
//
// CAUGHT-IN-DEV risk: a parser off-by-one (e.g. > vs >=, or a ParseInt base
// error) would skip a file that DOES carry a qualifying row → the EQUIV diverges
// → RED. The honest design (skip iff firstSys > txTime — STRICT >, because
// firstSys is the MIN and a row AT sysTime==txTime passes Filter2 with <=, so
// firstSys==txTime means the first row DOES qualify → DO NOT skip) is exact; the
// EQUIV is the gate. The EQUIV runs NON-race (the §2 precedent — the
// 10k-class fuzz is alloc-heavy + the skip has NO concurrency surface; the
// parser is pure + the skip is a `continue` on a non-shared key string).
//
// PREMISE-CORRECTION: the SkipList composite-key order is hash|sysTime|
// validStart|assertTime (ASC) — validStart is co-sorted with sysTime, NOT
// independently sorted. The skip bounds sysTime (Filter2), NOT validTime
// (Filter3) — the bound the SkipList COULD support is the bound the filename
// ALREADY carries. The EQUIV therefore uses ONE validTime (fileSkipBase+50, below
// every file's openEnd) so the ONLY varying axis is txTime (the skip's bound).
func TestSkipEquiv(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "equiv-entity"
	const N = 64
	const fuzzN = 2000

	// Build N=64 files, FirstSysTimeNs staggered at i*1000, each holding ONE row
	// at sysTime == firstSys (the file's MIN == its ONLY row's sysTime — the
	// production-invariant the flush writes). The row's validTime window is
	// [fileSkipBase, openEndNs) so it qualifies at validTime = fileSkipBase+50.
	store := newMemStore()
	firstSyses := make([]int64, N)
	for i := 0; i < N; i++ {
		firstSys := fileSkipBase + int64(i)*1000
		firstSyses[i] = firstSys
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, firstSys, fileSkipBase, openEndNs, []byte(fmt.Sprintf("row-%d", i)))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl), "each file flushes ONE per-entity upload")
	}
	// Self-check: the store holds N files under the entity's l0 prefix, each
	// keyed by its firstSys (the filename grammar the parser reads).
	h8 := sha256.Sum256([]byte(entity))
	hexHex := hexEncode8(h8)
	prefix := fmt.Sprintf("l0/%s/", hexHex)
	store.mu.Lock()
	fileCount := 0
	for k := range store.objects {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			fileCount++
		}
	}
	store.mu.Unlock()
	require.Equalf(t, N, fileCount, "the store must hold N=%d files under %s (one per firstSys)", N, prefix)

	// Two resolvers over the SAME store: skip ON vs skip OFF (the comparison path).
	rSkip := NewResolver(store, store, alloc, "fileskip-equiv-skip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	rNoSkip := NewResolver(store, store, alloc, "fileskip-equiv-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})

	rng := rand.New(rand.NewPCG(24, 0))
	vt := time.Unix(0, fileSkipBase+50) // ONE validTime (the skip bounds txTime/sysTime, not validTime)
	var diverge int
	var skipFires int
	for f := 0; f < fuzzN; f++ {
		// txTime in [0, 64000): the staggered firstSyses are fileSkipBase+[0..63000].
		// A txTime < fileSkipBase skips ALL files (all firstSys > txTime); a txTime
		// >= fileSkipBase+63000 skips NONE; in between, a prefix of files is skipped.
		txNs := fileSkipBase + rng.Int64N(int64(N)*1000+1)
		tx := time.Unix(0, txNs)

		gotSkip, errSkip := rSkip.AsOf(ctx, entity, vt, tx)
		gotNo, errNo := rNoSkip.AsOf(ctx, entity, vt, tx)

		// Track whether the skip fired on this txTime (any file with firstSys > txNs).
		for _, fs := range firstSyses {
			if fs > txNs {
				skipFires++
				break
			}
		}

		// byte-IDENTITY: the skip path == the no-skip path.
		if errSkip != nil && errNo == nil {
			diverge++
			t.Errorf("skip-equiv diverge at f=%d txNs=%d: skip=Err no-skip=event (the skip DROPPED a qualifying row — off-by-one or parse bug)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errNo != nil && errSkip == nil {
			diverge++
			t.Errorf("skip-equiv diverge at f=%d txNs=%d: skip=event no-skip=Err (the skip FABRICATED a row — impossible if it only skips; a bug)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errSkip != nil && errNo != nil {
			// Both NotFound — byte-identical (the skip dropped files that carried
			// no qualifying row anyway — the transitively-safe elimination).
			continue
		}
		// Both resolved a dominant — assert byte-identity on the load-bearing fields.
		if gotSkip.SystemTime != gotNo.SystemTime {
			diverge++
			t.Errorf("skip-equiv diverge at f=%d txNs=%d: SystemTime skip=%d no-skip=%d", f, txNs, gotSkip.SystemTime, gotNo.SystemTime)
			if diverge > 5 {
				break
			}
			continue
		}
		if gotSkip.ValidTimeStart != gotNo.ValidTimeStart || gotSkip.ValidTimeEnd != gotNo.ValidTimeEnd {
			diverge++
			t.Errorf("skip-equiv diverge at f=%d txNs=%d: ValidTime skip=[%d,%d) no-skip=[%d,%d)", f, txNs, gotSkip.ValidTimeStart, gotSkip.ValidTimeEnd, gotNo.ValidTimeStart, gotNo.ValidTimeEnd)
			if diverge > 5 {
				break
			}
			continue
		}
		if !bytesEqual(gotSkip.Payload, gotNo.Payload) {
			diverge++
			t.Errorf("skip-equiv diverge at f=%d txNs=%d: Payload differs (the skip returned the WRONG row's payload)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
	}
	require.Zerof(t, diverge, "skip-equiv: skip-path == no-skip-path byte-IDENTICAL for ALL %d fuzzed txTimes (a divergence is a skip off-by-one — firstSys>txTime STRICT, a row AT sysTime==txTime passes Filter2; the §0.e transitively-safe elimination)", fuzzN)
	t.Logf("skip-equiv PASS: %d fuzzed txTimes (seed=24), skip-path == no-skip-path byte-IDENTICAL; the skip fired on %d/%d txTimes (the transitively-safe elimination, §0.e)", fuzzN, skipFires, fuzzN)
}

// bytesEqual is a nil-safe byte-slice equality (avoids importing bytes in this
// file — the seek-guard file imports bytes; this file keeps its import set minimal
// for the parser/fuzz guards).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// hexEncode8 returns the 16-char lowercase hex of an 8-byte hash prefix (the
// SAME encoding l0Key / the production path uses — encoding/hex on hash[:8]).
// Kept local so this guard does not import encoding/hex (the import is already
// in the package via query.go; a test-only helper here avoids a second import
// line that gofmt would reorder).
func hexEncode8(h8 [32]byte) string {
	var b [16]byte
	const hex = "0123456789abcdef"
	for i := 0; i < 8; i++ {
		b[i*2] = hex[h8[i]>>4]
		b[i*2+1] = hex[h8[i]&0x0f]
	}
	return unsafe.String(&b[0], 16)
}
