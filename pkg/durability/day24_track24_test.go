// Day 24 (ADR-0029) teeth (the REAL *LocalFS route teeth) — the filename-
// bounded download skip, driven against a REAL *LocalFS (the Day-12.5 tooth-
// principle "drive the route, not the seam").
//
// These teeth live in pkg/durability (the home of LocalFS) because an
// internal/database test cannot import pkg/durability (import cycle: snapshot.go
// imports internal/database). The seam-level teeth (the parser, the failsafe,
// the EQUIV fuzz, the boundary, the FROZEN scope) live in
// internal/database/day24_track24_test.go. This file holds the teeth the import-
// cycle FORCES here: the production-on-disk proofs that the skip PRESERVES the
// answer (Law II) AND CUTS the download count (the disclosure counter fires on
// the skipped files), over the REAL *LocalFS + the REAL L0Flusher→Arrow→disk
// path a production node reads.
//
// It reuses the track14 helpers (track14LocalFS / track14InsertRow / track14WriteN
// / track14MakePackedValue / putBE64) + the track19 helpers (track19InsertWindowRow
// / range19BaseDur) — the SAME REAL *LocalFS + the SAME L0Flusher→Arrow→disk
// path the compaction/range teeth drive. The skip is READ-only; it reuses the
// Resolver (NewResolver over the *LocalFS lister+downloader), NOT a new write
// path. Each track19InsertWindowRow flushes ONE row → ONE L0 file keyed by that
// row's sysT = the file's FirstSysTimeNs (the production-invariant the flush
// writes). The N=4 staggered-files setup is the load-bearing precondition: it
// gives the skip a file-predicate to evaluate.
//
// DAY-24 §5 CONTRACT: the skip is a transitively-safe elimination (§0.e). For a
// query at txTime T + a file F with filename min(F): min(F) > T ⟹ ZERO rows in
// F pass Filter2 (sysTime<=txTime) ⟹ skipping F's download preserves the answer
// IDENTICALLY (Law II) AND cuts the download count (the disclosure counter fires
// on F). The bound is STRICT (min(F) > T): a row AT sysTime==T passes Filter2
// (<=), so min(F)==T means the file's first row MIGHT qualify → DO NOT skip.

package durability

import (
	"context"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/database"
	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// T-SKIP-PRESERVES-ANSWER (REAL *LocalFS) — the headline Law-II preservation.
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_PRESERVES_ANSWER_REALLocalFS is DAY-24 T-SKIP-PRESERVES-
// ANSWER over a REAL *LocalFS. Write N=4 staggered files for E at sysTime
// base+0, base+1000, base+2000, base+3000 (each file's FirstSysTimeNs = its
// row's sysTime = i*1000). Query at txTime = base+1500: the files at base+2000
// + base+3000 have firstSys > txTime → SKIPPED (their rows fail Filter2); the
// files at base+0 + base+1000 have firstSys <= txTime → DOWNLOADED. The dominant
// is the row at base+1000 (the highest sysTime <= txTime that covers the
// validTime). ASSERT: the answer is byte-IDENTICAL to the no-skip path
// (EnableFirstSysSkip=false) — Law II preserved. The skip did NOT change the
// answer; it CUT the downloads from 4 to 2.
//
// This is the §0.e headline over the production on-disk path: a skip the
// seam-tooth (internal/database T-SKIP-EQUIV) proved over the in-memory store,
// re-proved over the REAL Arrow files a production node writes. The two files
// skipped are the ones the filename ALREADY proved carry ZERO qualifying rows —
// the skip is the transitively-safe elimination, NOT a heuristic.
func TestTrack24_T_SKIP_PRESERVES_ANSWER_REALLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "track24-bucket")
	const entity = "alpha"

	// N=4 staggered files: sysTime = base + i*1000 (i=0..3). Each file's
	// FirstSysTimeNs = its row's sysTime (the production-invariant). The row's
	// validTime window = [base, openEnd) so it qualifies at validTime = base+50.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		track19InsertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("row-"+strconv.Itoa(i)))
	}

	// Query at txTime = base+1500: files at base+0 + base+1000 are <= txTime
	// (downloaded); files at base+2000 + base+3000 are > txTime (skipped).
	const txNs = range19BaseDur + 1500
	q := func(enable bool) (*database.TriTemporalEvent, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "track24-bucket", cfg)
		return r.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txNs))
	}

	withSkip, errSkip := q(true)
	require.NoErrorf(t, errSkip, "AsOf with skip must resolve over REAL *LocalFS")
	require.NotNilf(t, withSkip, "the dominant must be non-nil with the skip")
	withoutSkip, errNoSkip := q(false)
	require.NoErrorf(t, errNoSkip, "AsOf without skip must resolve over REAL *LocalFS")
	require.NotNilf(t, withoutSkip, "the dominant must be non-nil without the skip")

	// byte-IDENTITY: the skip did NOT change the answer (Law II).
	assert.Equalf(t, withSkip.SystemTime, withoutSkip.SystemTime,
		"PRESERVES-ANSWER: SystemTime byte-identical (the skip dropped files carrying ZERO qualifying rows — Law II)")
	assert.Equalf(t, withSkip.Payload, withoutSkip.Payload,
		"PRESERVES-ANSWER: Payload byte-identical (the skip returned the SAME dominant)")
	assert.Equalf(t, withSkip.ValidTimeStart, withoutSkip.ValidTimeStart,
		"PRESERVES-ANSWER: ValidTimeStart byte-identical")
	// The dominant is the row at base+1000 (the highest sysTime <= txNs=base+1500
	// that covers validTime=base+50). The files at base+2000/base+3000 were
	// skipped (firstSys > txNs) — their rows fail Filter2 anyway.
	assert.Equalf(t, range19BaseDur+1000, withSkip.SystemTime,
		"the dominant sysTime == base+1000 (the highest sysTime <= txNs=base+1500; the base+2000/base+3000 rows are invisible at txNs)")
	t.Logf("T-SKIP-PRESERVES-ANSWER REAL *LocalFS: 4 staggered files, txTime=base+1500 → skip-path == no-skip-path byte-IDENTICAL (dominant sysTime=%d); the base+2000/base+3000 files skipped (Law II preserved)", withSkip.SystemTime)
}

// ---------------------------------------------------------------------------
// T-SKIP-DOWNLOAD-COUNT (REAL *LocalFS) — the disclosure counter + the cut.
// ---------------------------------------------------------------------------

// countingLocalFS wraps a *LocalFS in a Download counter (the SAME S3Downloader
// interface the Resolver reads, with a per-Download atomic increment). It is the
// instrument the T-SKIP-DOWNLOAD-COUNT tooth reads to ASSERT the skip CUT the
// downloads from 4 to 2 (the disclosure counter QueryDownloadSkippedFirstSys
// fires on the 2 skipped files; the Download counter fires on the 2 downloaded).
// The wrapper delegates ListObjects/Upload/Delete to the embedded *LocalFS so
// the Resolver reads the SAME production on-disk path (only the Download is
// counted — the read path's cost center).
type countingLocalFS struct {
	*LocalFS
	downloads int // non-atomic: the tooth is single-threaded (one AsOf at a time)
}

// Download delegates to *LocalFS.Download + counts (the S3Downloader seam the
// Resolver's scanFile/scanWindowFile calls). The count is the load-bearing
// signal: the skip CUT the downloads (4 files → 2 downloads under the skip).
func (c *countingLocalFS) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	c.downloads++
	return c.LocalFS.Download(ctx, bucket, key)
}

// TestTrack24_T_SKIP_DOWNLOAD_COUNT_REALLocalFS is DAY-24 T-SKIP-DOWNLOAD-COUNT
// over a REAL *LocalFS. Same N=4 staggered-files setup as T-SKIP-PRESERVES-
// ANSWER. Query at txTime = base+1500 with EnableFirstSysSkip=true: the Download
// counter reads EXACTLY 2 (the base+0 + base+1000 files; the base+2000 +
// base+3000 files skipped), AND the disclosure counter QueryDownloadSkippedFirstSys
// fires EXACTLY 2 (the 2 skipped files). Query with EnableFirstSysSkip=false:
// the Download counter reads 4 (no skip), the disclosure counter fires 0. The
// differential (4 → 2 downloads, 0 → 2 skips) is the load-bearing cut.
//
// CAUGHT-IN-DEV risk: a skip that fires but does NOT cut the download (e.g. the
// `continue` placed AFTER the scanFile call) would show downloads=4 AND skips=2
// → the tooth's downloads<=2 assertion catches it. A skip that cuts the download
// but does NOT fire the counter would show downloads=2 + skips=0 → the tooth's
// skips>=2 assertion catches it. BOTH the cut AND the disclosure are asserted.
func TestTrack24_T_SKIP_DOWNLOAD_COUNT_REALLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "track24-dc-bucket")
	const entity = "alpha"

	// N=4 staggered files (same setup as PRESERVES-ANSWER).
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		track19InsertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("dc-"+strconv.Itoa(i)))
	}

	const txNs = range19BaseDur + 1500

	// (1) SKIP ON: downloads == 2, disclosure counter fires == 2.
	skipLFS := &countingLocalFS{LocalFS: lfs}
	skipR := database.NewResolver(skipLFS, skipLFS, alloc, "track24-dc-bucket", database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	skipsBefore := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		skipsBefore = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	got, err := skipR.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txNs))
	require.NoErrorf(t, err, "AsOf with skip must resolve")
	require.NotNil(t, got)
	assert.Equalf(t, 2, skipLFS.downloads, "SKIP ON: exactly 2 downloads (the base+0 + base+1000 files; the base+2000/base+3000 SKIPPED — firstSys > txNs=base+1500)")
	skipsAfter := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		skipsAfter = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	assert.Equalf(t, int64(2), skipsAfter-skipsBefore, "SKIP ON: the disclosure counter fired EXACTLY 2 (the 2 skipped files; QueryDownloadSkippedFirstSys)")

	// (2) SKIP OFF: downloads == 4, disclosure counter fires == 0.
	noSkipLFS := &countingLocalFS{LocalFS: lfs}
	noSkipR := database.NewResolver(noSkipLFS, noSkipLFS, alloc, "track24-dc-bucket", database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	skipsBefore2 := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		skipsBefore2 = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	got2, err2 := noSkipR.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txNs))
	require.NoErrorf(t, err2, "AsOf without skip must resolve")
	require.NotNil(t, got2)
	assert.Equalf(t, 4, noSkipLFS.downloads, "SKIP OFF: exactly 4 downloads (no skip — every file downloaded)")
	skipsAfter2 := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		skipsAfter2 = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	assert.Equalf(t, int64(0), skipsAfter2-skipsBefore2, "SKIP OFF: the disclosure counter fired 0 (no skip — the pre-Day-24 behavior)")

	// byte-IDENTITY of the answer across the two paths (belt-and-suspenders with
	// T-SKIP-PRESERVES-ANSWER — the cut did NOT change the answer).
	assert.Equalf(t, got.SystemTime, got2.SystemTime, "the cut did NOT change the answer (downloads 4→2, dominant byte-identical)")
	t.Logf("T-SKIP-DOWNLOAD-COUNT REAL *LocalFS: SKIP ON → %d downloads + %d skips; SKIP OFF → %d downloads + %d skips (the cut 4→2 + the disclosure 0→2; Law II preserved: dominant sysTime=%d both paths)", skipLFS.downloads, skipsAfter-skipsBefore, noSkipLFS.downloads, skipsAfter2-skipsBefore2, got.SystemTime)
}

// ---------------------------------------------------------------------------
// T-SKIP-RANGE-WINDOW-ORTHOGONAL (REAL *LocalFS) — the skip is window-agnostic.
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_RANGE_WINDOW_ORTHOGONAL_REALLocalFS is DAY-24 T-SKIP-RANGE-
// WINDOW-ORTHOGONAL over a REAL *LocalFS. The skip bounds sysTime (Filter2);
// Range bounds validTime (Filter3). The two are ORTHOGONAL: the window [vLo,vHi)
// is IRRELEVANT to the skip. This tooth proves it: N=4 staggered files (same
// setup), a Range window [base+50, base+99999) at txTime = base+1500. The files
// at base+2000/base+3000 are STILL skipped (firstSys > txTime — the window does
// NOT rescue them), AND the Range result is byte-IDENTICAL to the no-skip path
// (the rows skipped fail Filter2 anyway; the window-passing rows are a SUBSET of
// the Filter2-passing rows). The §0.e step 7: the window slice is UNCHANGED
// byte-for-byte.
//
// The load-bearing claim: a Range window WIDE enough to intersect a skipped
// file's validTime window does NOT cause the skip to misfire. The skip is on
// sysTime (the file's MIN sysTime), NOT validTime — so a file skipped for AsOf
// is skipped for Range too (the SAME block, query.go Range loop). The window
// is the SECOND filter (Filter3), applied AFTER the skip; the skip's bound
// (firstSys > txTime) is the FIRST filter (Filter2's precondition), applied
// BEFORE the window. The order is load-bearing: skip-then-window, NOT window-
// then-skip (a window-then-skip would need the file's validTime range, which the
// filename does NOT carry — the §6.a upper-bound-fork disclosure).
func TestTrack24_T_SKIP_RANGE_WINDOW_ORTHOGONAL_REALLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "track24-rw-bucket")
	const entity = "alpha"

	// N=4 staggered files. Each row's sysTime = base+i*1000 (the file's
	// FirstSysTimeNs) AND its validTimeStart = base+i*1000 (DISTINCT, ascending
	// == sysTime-ascending, so the Range validTimeStart-sort is deterministic +
	// matches sysTime order — the Day-19 contract sorts by validTimeStart, NOT
	// sysTime; making them equal removes the tie-order ambiguity). The validTime
	// window = [base+i*1000, openEnd) — WIDE, so a Range window
	// [base+50, base+99999) intersects ALL 4 rows' validTime intervals (the
	// window is wide on purpose — to prove the skip is on sysTime, NOT validTime;
	// a window-then-skip would NOT skip the base+2000/base+3000 files because
	// their validTime intervals intersect the window).
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		track19InsertWindowRow(t, alloc, lfs, flusher, entity, sysNs, sysNs, rangeOpenEnd, []byte("rw-"+strconv.Itoa(i)))
	}

	const txNs = range19BaseDur + 1500
	vLo := time.Unix(0, range19BaseDur+50)
	vHi := time.Unix(0, range19BaseDur+99999)
	tx := time.Unix(0, txNs)

	q := func(enable bool) ([]*database.TriTemporalEvent, bool, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "track24-rw-bucket", cfg)
		return r.Range(ctx, entity, vLo, vHi, tx)
	}

	withSkip, truncSkip, errSkip := q(true)
	require.NoErrorf(t, errSkip, "Range with skip must resolve over REAL *LocalFS")
	assert.Falsef(t, truncSkip, "no truncation (4-window-rows << cap)")
	withoutSkip, truncNo, errNoSkip := q(false)
	require.NoErrorf(t, errNoSkip, "Range without skip must resolve")
	assert.Falsef(t, truncNo, "no truncation without skip")

	// byte-IDENTITY: the skip did NOT change the Range window. The files at
	// base+2000/base+3000 were skipped (firstSys > txNs) — their rows fail
	// Filter2 (sysTime > txNs) so they were NEVER in the window anyway. The
	// window-passing rows are a SUBSET of the Filter2-passing rows; the skip
	// removed ZERO window-passers.
	require.Equalf(t, len(withoutSkip), len(withSkip),
		"RANGE-WINDOW-ORTHOGONAL: the row count is byte-identical (the skip removed ZERO window-passers; the window is ORTHOGONAL to the sysTime skip)")
	// The 2 surviving rows: base+0 + base+1000 (the files NOT skipped; their rows
	// pass Filter2 sysTime<=txNs AND the wide window intersects [base,openEnd)).
	require.Lenf(t, withSkip, 2, "exactly 2 rows (the base+0 + base+1000 files; the base+2000/base+3000 skipped — their rows fail Filter2)")
	// Assert byte-identity on each row (sorted by validTimeStart — both paths).
	for i := range withSkip {
		assert.Equalf(t, withoutSkip[i].SystemTime, withSkip[i].SystemTime,
			"RANGE-WINDOW-ORTHOGONAL: row %d SystemTime byte-identical", i)
		assert.Equalf(t, withoutSkip[i].Payload, withSkip[i].Payload,
			"RANGE-WINDOW-ORTHOGONAL: row %d Payload byte-identical", i)
	}
	// The 2 rows are the base+0 + base+1000 sysTimes (sorted by validTimeStart
	// asc == sysTime asc here since each row's validStart == base).
	assert.Equalf(t, range19BaseDur, withSkip[0].SystemTime, "the first row is the base+0 file (NOT skipped)")
	assert.Equalf(t, range19BaseDur+1000, withSkip[1].SystemTime, "the second row is the base+1000 file (NOT skipped)")
	t.Logf("T-SKIP-RANGE-WINDOW-ORTHOGONAL REAL *LocalFS: wide window [base+50,base+99999), txTime=base+1500 → %d rows both paths (the base+2000/base+3000 files skipped — their rows fail Filter2; the window is ORTHOGONAL to the sysTime skip)", len(withSkip))
}

// ---------------------------------------------------------------------------
// T-SKIP-DEFAULT-IS-ON — the opt-OUT contract (Day 19 §0.c.1 inverted).
// ---------------------------------------------------------------------------

// TestTrack24_T_SKIP_DEFAULT_IS_ON is DAY-24 T-SKIP-DEFAULT-IS-ON (the opt-OUT
// contract). Day 19 §0.c.1 was an opt-IN (MaxRangeRows=0 = UNLIMITED, the
// disclosed unbounded sentinel). Day 24 INVERTS the default: the skip is ON by
// default (DefaultResolverConfig returns EnableFirstSysSkip=true). The honest
// rationale (§1.b): the bound is on disk for free (the filename has carried
// FirstSysTimeNs since Day-13), the parse is zero-alloc + failsafe, + the
// transitively-safe elimination (§0.e) is a TAUTOLOGY (proven, not heuristic).
// An opt-IN would leave the cost-center residual un-cut for every caller that
// uses DefaultResolverConfig (the production path, cmd/sovereign-node/main.go +
// pkg/mesh). The opt-OUT (false) is the comparison path the EQUIV uses.
//
// This tooth asserts DefaultResolverConfig().EnableFirstSysSkip == true (the
// production-safe default is ON), AND a literal ResolverConfig{} has
// EnableFirstSysSkip == false (the zero value — the existing Day-14..22 teeth
// that build `ResolverConfig{MaxL0Files: maxL0}` run with the skip OFF, byte-
// identical to pre-Day-24; the existing teeth stay GREEN by construction).
func TestTrack24_T_SKIP_DEFAULT_IS_ON(t *testing.T) {
	def := database.DefaultResolverConfig()
	assert.Truef(t, def.EnableFirstSysSkip,
		"DefaultResolverConfig().EnableFirstSysSkip MUST be true (the opt-OUT contract — Day 24 inverts Day-19's opt-IN; the bound is on disk for free, the parse is zero-alloc + failsafe, the §0.e elimination is a tautology)")
	assert.Equalf(t, 1000, def.MaxL0Files, "the other defaults are byte-identical to pre-Day-24")
	assert.Equalf(t, 4096, def.MaxRangeRows, "MaxRangeRows default unchanged")

	// A literal ResolverConfig{} has EnableFirstSysSkip == false (the zero value).
	// The existing Day-14..22 teeth that build `ResolverConfig{MaxL0Files: maxL0}`
	// run with the skip OFF → byte-identical to pre-Day-24 (GREEN by construction).
	literal := database.ResolverConfig{MaxL0Files: 1000}
	assert.Falsef(t, literal.EnableFirstSysSkip,
		"a literal ResolverConfig{...} has EnableFirstSysSkip == false (the zero value) — the existing Day-14..22 teeth run with the skip OFF, byte-identical to pre-Day-24")
	t.Logf("T-SKIP-DEFAULT-IS-ON PASS: DefaultResolverConfig().EnableFirstSysSkip=true (opt-OUT); literal ResolverConfig{} = false (the existing teeth stay GREEN by construction)")
}
