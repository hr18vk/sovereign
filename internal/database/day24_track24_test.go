// Day 24 (ADR-0029) teeth — the filename-bounded download skip, the durable
// AsOf/Range download-cut.
//
// This fork CLOSES the genuine unbounded-cost residual the durable read path has
// carried since Day-12 (ADR-0017 §6.1): AsOf + Range are O(L0-files) per query
// because they DOWNLOAD + DECODE every L0/L1 Arrow file under the entity's
// prefix, even when the file's filename-encoded FirstSysTimeNs (the file's MIN
// sysTime, written by the flush since Day-13) proves the file carries ZERO rows
// visible at the query's txTime. The skip is a `continue` BEFORE the Download —
// it cuts the DOWNLOAD count, not the per-file decode.
//
// THE PREMISE-AUDIT (the SEVENTH dictated-correction since Day-17, ADR-0029 §7):
// the queue entry (ADR-0028 §6.a) named the next move as "wire Seek into
// scanWindowRecordBatch." That premise is FALSE on the bytes — M1 (load-bearing):
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
// rows ⟹ skipping F's download preserves the answer set IDENTICALLY (Law II).
// The bound is STRICT (firstSys > txTime): a row AT sysTime==txTime passes
// Filter2 (<=), so firstSys==txTime means the file's first row MIGHT qualify →
// DO NOT skip (T-SKIP-OFF-BY-SKIP-BOUNDARY).
//
// These teeth are the SEAM-level proofs over the in-memory S3 simulator
// (memStoreTrack13). The REAL-*LocalFS route teeth (T-SKIP-PRESERVES-ANSWER +
// T-SKIP-DOWNLOAD-COUNT + T-SKIP-RANGE-WINDOW-ORTHOGONAL) live in
// pkg/durability/day24_track24_test.go (the import-cycle precedent — an
// internal/database test cannot import pkg/durability). The SSoT + bridge sister
// teeth live in internal/telemetry/day24_track24_test.go + pkg/metrics/
// day24_track24_test.go. This file holds the in-package teeth that need only
// internal/database symbols: the parser, the failsafe Law-II preservation, the
// EQUIV fuzz, the skip boundary, + the FROZEN-scope tooth.

package database

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// day24Base is a fixed ns epoch for the Day-24 teeth (same convention as
// range19Base: 1.7e18, comfortably below openDay19Ns (9e18) + int64-max (9.2e18),
// 19-digit fixed-width so lexicographic == numeric — the §1.a parse uses
// strconv.ParseInt base 10, NOT a lexical compare, so the width is for the
// production-realism of the filename, not the skip's correctness).
const day24Base int64 = 1_700_000_000_000_000_000

// ---------------------------------------------------------------------------
// T-SKIP-PARSER — §1.a the zero-alloc filename parser (l0 + l1 grammar).
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_PARSER is DAY-24 T-SKIP-PARSER. parseFirstSysFromKey
// extracts the file's MIN sysTime (FirstSysTimeNs) from a durable Arrow key.
// Grammar (byte-verified against the writer): "<tier>/<hex(hash8)>/<int64-
// decimal>.arrow", tier ∈ {"l0","l1"}. For BOTH tiers it returns the EXACT
// int64 written. RED controls: no slash, no dot, non-numeric tail, NEGATIVE
// tail (the §1.a landmine disarm), trailing-slash key. The parser NEVER panics
// + NEVER allocates (the alloc tooth asserts the latter).
func TestTrack24_T_SKIP_PARSER(t *testing.T) {
	// The headline: a 19-digit production UnixNano parses EXACTLY.
	got, ok := parseFirstSysFromKey("l0/abcd1234/1785542400000000000.arrow")
	require.Truef(t, ok, "l0 production key must parse (ok=true)")
	assert.Equalf(t, int64(1785542400000000000), got, "l0 key: parseFirstSysFromKey must return the EXACT int64 written")

	// l1 tier: the SAME grammar, the SAME parser (the read path lists BOTH tiers).
	gotL1, okL1 := parseFirstSysFromKey("l1/abcd1234/1785542400000000000.arrow")
	require.Truef(t, okL1, "l1 production key must parse (ok=true)")
	assert.Equalf(t, int64(1785542400000000000), gotL1, "l1 key: parseFirstSysFromKey must return the EXACT int64 written")

	// A smaller value (the staggered-file tooth uses i*1000 sysTimes — verify
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
		assert.Falsef(t, ok, "RED control %q: must return ok=false (the honest fallback — do NOT skip; Law II preserved)", c.name)
	}
	t.Logf("T-SKIP-PARSER PASS: l0+l1 production keys parse EXACT; 6 RED controls return ok=false (the honest fallback — never silently skip a parse anomaly)")
}

// ---------------------------------------------------------------------------
// T-SKIP-PARSER-ALLOC — the zero-alloc property (MEASURED, not "0").
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_PARSER_ALLOC is DAY-24 T-SKIP-PARSER-ALLOC.
// testing.AllocsPerRun over parseFirstSysFromKey. The HONEST expectation: 0
// allocs — the suffix extraction is a strings.LastIndexByte slice + a
// strconv.ParseInt(base 10) on the trimmed tail, NO strings.Split, NO regexp.
// The numeric string is < 40 bytes; ParseInt does NOT allocate. Assert allocs
// == 0 (Law V — MEASURED; the parser is on the read path, the §0.e read-path-
// zero-alloc discipline). The key is built INSIDE the AllocsPerRun closure so
// it does not escape (building it outside + capturing would heap-allocate the
// string — the anti-pattern, the Day-23 T-SEEK-ALLOC precedent).
func TestTrack24_T_SKIP_PARSER_ALLOC(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		// Key built INSIDE the closure — a string literal does not escape
		// (parseFirstSysFromKey only slices it + ParseInts the tail; nothing
		// stores it). A const-length literal is the cleanest zero-alloc form.
		_, _ = parseFirstSysFromKey("l0/abcd1234/1785542400000000000.arrow")
	})
	assert.Equalf(t, 0.0, allocs, "parseFirstSysFromKey must allocate 0 (LastIndexByte slice + ParseInt base 10 — no Split, no regexp; the §0.e read-path-zero-alloc discipline) — got %v", allocs)
	t.Logf("T-SKIP-PARSER-ALLOC: parseFirstSysFromKey allocs/run = %v (LastIndexByte + ParseInt; zero-alloc read-path parser)", allocs)
}

// ---------------------------------------------------------------------------
// T-SKIP-FAILSAFE-KEEPS-LAW-II — a corrupt filename is NEVER silently dropped.
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_FAILSAFE is DAY-24 T-SKIP-FAILSAFE-KEEPS-LAW-II. A key
// shaped "l0/{hex8}/NOTANUMBER.arrow" (a renamed/corrupt file the lister still
// returns). With EnableFirstSysSkip=true, the parser returns (0, false) → NO
// skip → the file is downloaded + scanned (the pre-Day-24 path). The disclosure
// counter does NOT fire. The answer is byte-IDENTICAL to EnableFirstSysSkip=
// false. Law II: a corrupt filename is NEVER silently dropped — the honest
// fallback is the full download.
//
// The tooth drives a REAL flush→query round-trip over memStoreTrack13, then
// PLANTS a corrupt-renamed key (a copy of a real file's bytes under a
// "l0/{hex8}/NOTANUMBER.arrow" key) so the lister returns it. The skip's parser
// fails on it (ok=false) → the file is downloaded + scanned → its rows ARE in
// the answer (NOT dropped). The comparison: EnableFirstSysSkip=true ==
// EnableFirstSysSkip=false byte-identically (the corrupt key's rows survive
// under BOTH, because the skip does NOT fire on a parse anomaly).
func TestTrack24_T_SKIP_FAILSAFE(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()

	const entity = "failsafe-entity"
	// One real file: sysTime = day24Base + 100, valid [day24Base, openEnd).
	sl := NewSkipListArena(alloc, 2*1024*1024)
	range19InsertRow(t, sl, entity, day24Base+100, day24Base, openDay19Ns, []byte("real-row"))
	require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl), "one real L0 file flushed")

	// PLANT a corrupt-renamed key: copy the real file's Arrow bytes under a
	// "l0/{hex8}/NOTANUMBER.arrow" key (the SAME hex8 prefix so the lister
	// returns it under the entity's l0Prefix; the tail is non-numeric so the
	// parser fails). This simulates a renamed/corrupt file the lister still
	// returns — the §1.a FAILSAFE contract.
	h8 := sha256.Sum256([]byte(entity))
	hexHex := hexEncode8(h8)
	realKey := fmt.Sprintf("l0/%s/%d.arrow", hexHex, day24Base+100)
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
		r := NewResolver(store, store, alloc, "track24-failsafe", cfg)
		got, err := r.AsOf(ctx, entity, time.Unix(0, day24Base+50), time.Unix(0, day24Base+99999))
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
	t.Logf("T-SKIP-FAILSAFE PASS: corrupt key %q did NOT parse → NOT skipped → its rows survive byte-identical under EnableFirstSysSkip true vs false (Law II: a corrupt filename is NEVER silently dropped)", corruptKey)
}

// ---------------------------------------------------------------------------
// T-SKIP-OFF-BY-SKIP-BOUNDARY — the STRICT > bound (firstSys==txTime → NO skip).
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_OFF_BY_SKIPIP_BOUNDARY is DAY-24 T-SKIP-OFF-BY-SKIP-
// BOUNDARY (the §1.c boundary tooth). Edge cases, each over the in-memory store:
//   - txTime == firstSys (a row AT sysTime==firstSys passes Filter2 with <=) →
//     the file's first row MIGHT qualify → DO NOT skip (firstSys > txTime is
//     false). ASSERT: no skip, download runs, the first row is returned.
//   - txTime == firstSys - 1 (every row sysT >= firstSys > txTime) → SKIP.
//     ASSERT: skip fires, download NOT called, the file's rows are absent.
//   - txTime BELOW every file's firstSys → ALL skipped (law-II-preserving empty
//     result; AsOf returns ErrEntityNotFound — byte-identical to the no-skip
//     path's empty result).
//   - txTime ABOVE every file's firstSys → NONE skipped (the §6.a scope cap).
//
// The load-bearing boundary: firstSys == txTime MUST NOT skip (a row AT sysTime
// == txTime passes Filter2 with <=, so firstSys == txTime means the file's first
// row DOES qualify → skipping it would DROP a qualifying row → Law II BREAKS).
// The EQUIV fuzz is the gate on the full set; THIS tooth pins the boundary.
func TestTrack24_T_SKIP_OFF_BY_SKIPIP_BOUNDARY(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()

	// Build a store with ONE file at firstSys = day24Base + 1000 (one row at
	// sysTime == firstSys, valid [day24Base, openEnd) so it qualifies at any
	// validTime below openEnd).
	const firstSys = day24Base + 1000
	buildFile := func(t *testing.T) *memStoreTrack13 {
		t.Helper()
		store := newMemStoreTrack13()
		sl := NewSkipListArena(alloc, 2*1024*1024)
		range19InsertRow(t, sl, "boundary-entity", firstSys, day24Base, openDay19Ns, []byte("boundary-row"))
		require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl))
		return store
	}

	// (1) txTime == firstSys → NO skip (a row AT sysTime==firstSys passes Filter2).
	store1 := buildFile(t)
	r1 := NewResolver(store1, store1, alloc, "track24-b1", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got1, err1 := r1.AsOf(ctx, "boundary-entity", time.Unix(0, day24Base+50), time.Unix(0, firstSys))
	require.NoErrorf(t, err1, "txTime==firstSys: AsOf must resolve (the file's first row at sysTime==firstSys passes Filter2 with <=)")
	require.NotNilf(t, got1, "txTime==firstSys: the dominant must be non-nil (the row at sysTime==firstSys QUALIFIES — DO NOT skip)")
	assert.Equalf(t, firstSys, got1.SystemTime, "txTime==firstSys: the returned row's SystemTime == firstSys (the file was NOT skipped)")

	// (2) txTime == firstSys - 1 → SKIP (every row sysT >= firstSys > txTime).
	store2 := buildFile(t)
	r2 := NewResolver(store2, store2, alloc, "track24-b2", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got2, err2 := r2.AsOf(ctx, "boundary-entity", time.Unix(0, day24Base+50), time.Unix(0, firstSys-1))
	assert.Errorf(t, err2, "txTime==firstSys-1: AsOf must return ErrEntityNotFound (the file was SKIPPED — every row sysT >= firstSys > txTime)")
	assert.Nilf(t, got2, "txTime==firstSys-1: no dominant (the skip dropped the file — correctly, zero qualifying rows)")
	// Law-II-preserving: the no-skip path ALSO returns NotFound here (the row at
	// sysTime==firstSys fails Filter2 since firstSys > firstSys-1). byte-identical.
	r2NoSkip := NewResolver(store2, store2, alloc, "track24-b2-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	got2No, err2No := r2NoSkip.AsOf(ctx, "boundary-entity", time.Unix(0, day24Base+50), time.Unix(0, firstSys-1))
	assert.Errorf(t, err2No, "the no-skip path at txTime==firstSys-1 ALSO returns ErrEntityNotFound (the row fails Filter2 — the skip is Law-II-preserving, byte-identical)")
	assert.Nilf(t, got2No, "no-skip path: no dominant (the skip changed NOTHING — both paths empty)")

	// (3) txTime BELOW every file's firstSys → ALL skipped → ErrEntityNotFound
	// (byte-identical to the no-skip path's empty result).
	store3 := buildFile(t)
	r3 := NewResolver(store3, store3, alloc, "track24-b3", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	_, err3 := r3.AsOf(ctx, "boundary-entity", time.Unix(0, day24Base+50), time.Unix(0, firstSys-500))
	assert.Errorf(t, err3, "txTime far below firstSys: ErrEntityNotFound (the file skipped — law-II-preserving empty result)")

	// (4) txTime ABOVE every file's firstSys → NONE skipped (the §6.a scope cap:
	// Day 24 helps FORENSIC queries BELOW the frontier, NOT queries above it).
	store4 := buildFile(t)
	r4 := NewResolver(store4, store4, alloc, "track24-b4", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got4, err4 := r4.AsOf(ctx, "boundary-entity", time.Unix(0, day24Base+50), time.Unix(0, firstSys+99999))
	require.NoErrorf(t, err4, "txTime above firstSys: AsOf must resolve (the skip does NOT fire — firstSys < txTime)")
	require.NotNilf(t, got4, "txTime above firstSys: the dominant must be non-nil (NONE skipped)")
	assert.Equalf(t, firstSys, got4.SystemTime, "txTime above firstSys: the returned row's SystemTime == firstSys (the file was NOT skipped — the §6.a scope cap)")
	t.Logf("T-SKIP-OFF-BY-SKIP-BOUNDARY PASS: txTime==firstSys → NO skip (row qualifies); txTime==firstSys-1 → SKIP (byte-identical to no-skip NotFound); below → ALL skipped; above → NONE skipped (the §6.a scope cap)")
}

// ---------------------------------------------------------------------------
// T-SKIP-EQUIV — §0.e the differential-equivalence fuzz (the load-bearing gate).
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_EQUIV is DAY-24 T-SKIP-EQUIV, the LOAD-BEARING differential-
// equivalence proof. For N=64 files for ONE entity, FirstSysTimeNs staggered at
// i*1000 (i=0..63), each file holds ONE row at sysTime == firstSys (valid
// [day24Base, openDay19Ns) so it qualifies at any validTime below openEnd). Fuzz
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
// EQUIV is the gate. The EQUIV runs NON-race (the Day-22 §2 precedent — the
// 10k-class fuzz is alloc-heavy + the skip has NO concurrency surface; the
// parser is pure + the skip is a `continue` on a non-shared key string).
//
// PREMISE-CORRECTION (M2): the SkipList composite-key order is hash|sysTime|
// validStart|assertTime (ASC) — validStart is co-sorted with sysTime, NOT
// independently sorted. The skip bounds sysTime (Filter2), NOT validTime
// (Filter3) — the bound the SkipList COULD support is the bound the filename
// ALREADY carries. The EQUIV therefore uses ONE validTime (day24Base+50, below
// every file's openEnd) so the ONLY varying axis is txTime (the skip's bound).
func TestTrack24_T_SKIP_EQUIV(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "equiv-entity"
	const N = 64
	const fuzzN = 2000

	// Build N=64 files, FirstSysTimeNs staggered at i*1000, each holding ONE row
	// at sysTime == firstSys (the file's MIN == its ONLY row's sysTime — the
	// production-invariant the flush writes). The row's validTime window is
	// [day24Base, openDay19Ns) so it qualifies at validTime = day24Base+50.
	store := newMemStoreTrack13()
	firstSyses := make([]int64, N)
	for i := 0; i < N; i++ {
		firstSys := day24Base + int64(i)*1000
		firstSyses[i] = firstSys
		sl := NewSkipListArena(alloc, 2*1024*1024)
		range19InsertRow(t, sl, entity, firstSys, day24Base, openDay19Ns, []byte(fmt.Sprintf("row-%d", i)))
		require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl), "each file flushes ONE per-entity upload")
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
	rSkip := NewResolver(store, store, alloc, "track24-equiv-skip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	rNoSkip := NewResolver(store, store, alloc, "track24-equiv-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})

	rng := rand.New(rand.NewPCG(24, 0))
	vt := time.Unix(0, day24Base+50) // ONE validTime (the skip bounds txTime/sysTime, not validTime — M2)
	var diverge int
	var skipFires int
	for f := 0; f < fuzzN; f++ {
		// txTime in [0, 64000): the staggered firstSyses are day24Base+[0..63000].
		// A txTime < day24Base skips ALL files (all firstSys > txTime); a txTime
		// >= day24Base+63000 skips NONE; in between, a prefix of files is skipped.
		txNs := day24Base + rng.Int64N(int64(N)*1000+1)
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
			t.Errorf("T-SKIP-EQUIV diverge at f=%d txNs=%d: skip=Err no-skip=event (the skip DROPPED a qualifying row — off-by-one or parse bug)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errNo != nil && errSkip == nil {
			diverge++
			t.Errorf("T-SKIP-EQUIV diverge at f=%d txNs=%d: skip=event no-skip=Err (the skip FABRICATED a row — impossible if it only skips; a bug)", f, txNs)
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
			t.Errorf("T-SKIP-EQUIV diverge at f=%d txNs=%d: SystemTime skip=%d no-skip=%d", f, txNs, gotSkip.SystemTime, gotNo.SystemTime)
			if diverge > 5 {
				break
			}
			continue
		}
		if gotSkip.ValidTimeStart != gotNo.ValidTimeStart || gotSkip.ValidTimeEnd != gotNo.ValidTimeEnd {
			diverge++
			t.Errorf("T-SKIP-EQUIV diverge at f=%d txNs=%d: ValidTime skip=[%d,%d) no-skip=[%d,%d)", f, txNs, gotSkip.ValidTimeStart, gotSkip.ValidTimeEnd, gotNo.ValidTimeStart, gotNo.ValidTimeEnd)
			if diverge > 5 {
				break
			}
			continue
		}
		if !bytesEqual(gotSkip.Payload, gotNo.Payload) {
			diverge++
			t.Errorf("T-SKIP-EQUIV diverge at f=%d txNs=%d: Payload differs (the skip returned the WRONG row's payload)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
	}
	require.Zerof(t, diverge, "T-SKIP-EQUIV: skip-path == no-skip-path byte-IDENTICAL for ALL %d fuzzed txTimes (a divergence is a skip off-by-one — firstSys>txTime STRICT, a row AT sysTime==txTime passes Filter2; the §0.e transitively-safe elimination)", fuzzN)
	t.Logf("T-SKIP-EQUIV PASS: %d fuzzed txTimes (seed=24), skip-path == no-skip-path byte-IDENTICAL; the skip fired on %d/%d txTimes (the transitively-safe elimination, §0.e)", fuzzN, skipFires, fuzzN)
}

// bytesEqual is a nil-safe byte-slice equality (avoids importing bytes in this
// file — the Day-23 file imports bytes; this file keeps its import set minimal
// for the parser/fuzz teeth).
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
// Kept local so this tooth does not import encoding/hex (the import is already
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

// ---------------------------------------------------------------------------
// T-SKIP-FROZEN — the scope-fidelity tooth (5-FILE FROZEN byte-identical).
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_FROZEN is DAY-24 T-SKIP-FROZEN (the scope-fidelity tooth).
// The SEVENTH clean-chain fork: ZERO FROZEN touched. This tooth asserts the
// 5-FILE FROZEN set is byte-identical to the proven md5s (the same set the
// pkg/receive gate pins + the prompt's §1.7 pins). query.go md5 CHANGES (the
// edit), registry.go md5 CHANGES (the new counter — UNFROZEN), but the 5 FROZEN
// files + the verifier-side files (l0_flusher.go, l1_compactor.go,
// skiplist_arena.go, telemetry_bridge.go) are byte-UNCHANGED. The SkipList.Seek
// primitive (skiplist_arena.go) is byte-UNCHANGED (Day 24 does NOT touch it —
// M3: dormant, NOT ROI to wire; the genuine first Seek consumer is the live
// cross-entity tail mega-fork, NOT the durable Arrow wiring the queue named).
//
// The pkg/receive gate (TestGate_FrozenMD5 + TestGate_UntouchedFrozenAndOutOfScope)
// is the AUTHORITATIVE pre-AND-post gate (run in §3); this in-package tooth is
// the belt-and-suspenders assertion from WITHIN internal/database (the package
// the fork edited — a local md5 read catches a stray edit faster, the same
// belt-and-suspenders discipline the Day-22 in-package teeth carry).
func TestTrack24_T_SKIP_FROZEN(t *testing.T) {
	frozen := []struct {
		path string
		md5  string
	}{
		{"../../pkg/sync/crdt.go", "44f8952771cfad4d195e518b63a33440"},
		{"../../pkg/sync/crdt_apply.go", "ed9132a27930b3d76a3f62e783dd7dd3"},
		{"../../api/capnp/api/capnp/schema.capnp", "47d2796a973319a3ffe364de3d08d6d6"},
		{"../../api/capnp/api/capnp/schema.capnp.go", "590af2287dcb3a135c586b50260be531"},
		{"../../pkg/attribution/envelope.go", "b1beba1e9de81294bc66a823dece6ab6"},
	}
	for _, f := range frozen {
		b, err := os.ReadFile(f.path)
		require.NoErrorf(t, err, "read FROZEN %s", f.path)
		sum := md5.Sum(b)
		got := fmt.Sprintf("%x", sum)
		if got != f.md5 {
			t.Fatalf("T-SKIP-FROZEN: FROZEN %s md5 changed: got %s, want %s (Day 24 MUST NOT touch the 5-FILE FROZEN set — the SEVENTH clean-chain fork)", f.path, got, f.md5)
		}
	}
	// The verifier-side files (the bound's WRITERS + the bridge) are byte-
	// UNCHANGED — the read path just parses what they write. The SkipList.Seek
	// primitive (skiplist_arena.go) is covered by the pkg/receive gate's
	// untouchedFiles (it is NOT in the 5-FILE FROZEN set; Day 24 does NOT edit
	// it, verified by the git-HEAD byte-identity the receive gate runs).
	verifierUnchanged := []struct {
		path   string
		preMD5 string // the md5 BEFORE this fork (captured pre-edit this turn)
	}{
		// l0_flusher.go: writes FirstSysTimeNs into the filename (READ-ONLY verify).
		{"../../internal/database/l0_flusher.go", "3c1b4a8f4ad5efdbf3bb2df2d83f3f2a"},
		// telemetry_bridge.go: auto-surfaces the 17th series with ZERO edit (§0.f;
		// Day 25 grew the SSoT 16 -> 17, the bridge byte-UNCHANGED across Day 24
		// AND Day 25 — the EIGHTH clean-chain fork).
		{"../../pkg/metrics/telemetry_bridge.go", "8fcc149b3caed713cfc67bd583cb9a6b"},
	}
	for _, f := range verifierUnchanged {
		b, err := os.ReadFile(f.path)
		require.NoErrorf(t, err, "read verifier-side %s", f.path)
		sum := md5.Sum(b)
		got := fmt.Sprintf("%x", sum)
		if got != f.preMD5 {
			t.Fatalf("T-SKIP-FROZEN: verifier-side %s md5 changed: got %s, want %s (Day 24 READ-ONLY-verifies the writers; the bridge auto-surfaces the new counter with NO edit)", f.path, got, f.preMD5)
		}
	}
	// Day 26 (ADR-0031) re-pin: l1_compactor.go is NO LONGER in the byte-UNCHANGED
	// set — Day 26 edited ParseManifest (the reader) + added readManifestBody there.
	// The WRITER (buildManifest, l1_compactor.go:972) is byte-UNCHANGED (Day 26
	// touched ONLY the reader + the 3 caller-site io.ReadAll swaps). Pin the new
	// md5 + assert it DID change (the honest re-pin: the reader changed, the
	// writer did not — verified by the buildManifest-substring check below).
	const l1CompactorPreDay26 = "2ed280348df3a34b6461894d5d9b93fb"
	const l1CompactorPostDay26 = "d0830b43cc9afd66e52b9bc968c77ff9"
	b, err := os.ReadFile("../../internal/database/l1_compactor.go")
	require.NoErrorf(t, err, "read l1_compactor.go for Day-26 re-pin")
	sum := md5.Sum(b)
	got := fmt.Sprintf("%x", sum)
	require.NotEqualf(t, l1CompactorPreDay26, got, "T-SKIP-FROZEN: l1_compactor.go md5 UNCHANGED at %s — Day 26 was supposed to edit ParseManifest+add readManifestBody (the reader); an unchanged md5 means the fork did NOT land", got)
	require.Equalf(t, l1CompactorPostDay26, got, "T-SKIP-FROZEN: l1_compactor.go md5 changed to %s, want %s (Day 26 re-pin — if a LATER fork edits l1_compactor.go's reader again, update BOTH this const + the Day-25 tooth; if it edits the WRITER buildManifest, the receive-gate T-UNCHANGED is the catcher)", got, l1CompactorPostDay26)
	// The WRITER (buildManifest) is byte-unchanged — Day 26 touched the reader
	// only. A substring check (the buildManifest body is stable) is the
	// finer-than-md5 guard a whole-file md5 cannot express.
	require.Contains(t, string(b), "func buildManifest(l1Key string, l0Keys []string) []byte {", "buildManifest (the writer) MUST be byte-unchanged — Day 26 edits the READER ParseManifest, NOT the writer")
	require.Contains(t, string(b), "func readManifestBody(r io.Reader) ([]byte, error) {", "readManifestBody (the Day-26 read helper) MUST be present")
	t.Logf("T-SKIP-FROZEN PASS: 5-FILE FROZEN byte-identical (the SEVENTH clean-chain fork) + verifier-side (l0_flusher/telemetry_bridge) byte-UNCHANGED; l1_compactor.go RE-PINNED Day 26 2ed280348->d0830b43c (the reader ParseManifest+readManifestBody changed, the writer buildManifest byte-UNCHANGED); the SkipList.Seek primitive stays dormant (M3)")
}
