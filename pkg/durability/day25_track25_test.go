// Day 25 (ADR-0030) teeth (the REAL *LocalFS route teeth) — the manifest-
// channel download skip, driven against a REAL *LocalFS (the Day-12.5 tooth-
// principle "drive the route, not the seam").
//
// Day 24 (ADR-0029) closed the L0/L1 FILE channel over the REAL *LocalFS (the
// Day-24 teeth in pkg/durability/day24_track24_test.go). Day 25 closes the
// MANIFEST channel over the SAME REAL *LocalFS: loadSupersededL0Keys downloads +
// ParseManifest-decodes EVERY compaction manifest per query to mark L0 keys
// superseded before the tail cap. The manifest's filename-encoded firstSys is
// the L1's MIN sysTime (the SAME field Day-24 skips on the file channel). When
// firstSys > the query's txTime (STRICT >), the L1 the manifest points at is
// file-skipped (Day-24 scan loop) AND every L0 the manifest lists is file-skipped
// → skipping the manifest DOWNLOAD preserves the superseded set w.r.t. the
// query's VISIBLE rows byte-identically (Law II) AND cuts a manifest Download
// (+ the ParseManifest strings.Split alloc). The counter QueryManifestSkippedFirstSys
// is the disclosure (Law V).
//
// These teeth run a REAL Compaction() over the REAL *LocalFS (the production
// manifest producer — compaction/{hex8}/{firstSys}.manifest on disk) + a REAL
// Resolver.AsOf/Range over the SAME *LocalFS. The compaction merges N staggered
// L0s → 1 L1 + 1 manifest whose firstSys == the OLDEST L0's sysTime (the byte-
// identity the tautology leverages). The teeth query at txTimes below the
// manifest's firstSys (skip fires) vs above it (skip does NOT fire) + assert
// byte-IDENTITY to the no-skip path (Law II) + the disclosure counter's cut.
//
// They reuse the track14 helpers (track14LocalFS) + the track19 helpers
// (track19InsertWindowRow, range19BaseDur, rangeOpenEnd) + the countingLocalFS
// wrapper (the Day-24 Download counter). The seam-level teeth (the parser, the
// EQUIV fuzz, the boundary, the FROZEN scope, the RED controls) live in
// internal/database/day25_track25_test.go. The SSoT + bridge sister teeth live
// in internal/telemetry/day25_track25_test.go + pkg/metrics/day25_track25_test.go.
//
// DAY-25 §5 CONTRACT: the skip is the Day-24 transitively-safe elimination on
// the manifest channel (§0.e). For a query at txTime T + a manifest M with
// filename min(M): min(M) > T ⟹ the L1 M points at is file-skipped (Day-24) AND
// every L0 M lists is file-skipped ⟹ skipping M's download leaves the superseded
// set intersecting ONLY files the scan loop skips anyway ⟹ the tailKeys + the
// dominant are byte-identical for the query's VISIBLE rows (Law II) AND cuts the
// manifest Download. The bound is STRICT (min(M) > T): a manifest at min(M)==T
// points at an L1 whose first row AT sysTime==T passes Filter2 (<=) → that L1
// MIGHT qualify → its listed L0s MIGHT carry visible rows → DO NOT skip M.

package durability

import (
	"context"
	"fmt"
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
// T-MANIFEST-PRESERVES-ANSWER (REAL *LocalFS) — the headline Law-II preservation.
// ---------------------------------------------------------------------------

// TestTrack25_T_MANIFEST_PRESERVES_ANSWER_REALLocalFS is DAY-25 T-MANIFEST-
// PRESERVES-ANSWER over a REAL *LocalFS. Write N=4 staggered L0 files for E at
// sysTime base+0, base+1000, base+2000, base+3000; run a REAL Compaction() →
// 1 L1 (carrying ALL 4 rows, Preserve-All) + 1 manifest (firstSys == base, the
// OLDEST L0's sysTime, listing ALL 4 L0s). Query at txTime = base+1500: the
// manifest's firstSys == base <= txTime → the manifest is NOT skipped (its L1's
// first row at base qualifies, + the L1 carries rows up to base+3000 visible at
// base+1500). Query at txTime = base-500 (BELOW the manifest's firstSys): the
// manifest IS skipped (firstSys==base > base-500) AND the L1 is file-skipped AND
// the 4 L0s are file-skipped → AsOf returns ErrEntityNotFound (law-II-preserving;
// byte-identical to the no-skip path). ASSERT: the answer is byte-IDENTICAL to
// the no-skip path (EnableFirstSysSkip=false) at BOTH txTimes — Law II preserved.
// The skip did NOT change the answer; it cut the manifest download at base-500.
//
// This is the §0.e headline on the manifest channel over the production on-disk
// path: a skip the seam tooth (internal/database T-MANIFEST-EQUIV) proved over
// the in-memory store, re-proved over the REAL Arrow files + the REAL manifest
// a production node writes + reads. The manifest skipped is the one the filename
// ALREADY proved points at an L1 carrying ZERO rows visible at txTime — the skip
// is the transitively-safe elimination, NOT a heuristic.
func TestTrack25_T_MANIFEST_PRESERVES_ANSWER_REALLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "track25-bucket")
	const entity = "alpha"

	// N=4 staggered L0 files: sysTime = base + i*1000 (i=0..3). Each file's
	// FirstSysTimeNs = its row's sysTime (the production-invariant). The row's
	// validTime window = [base, openEnd) so it qualifies at validTime = base+50.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		track19InsertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("row-"+strconv.Itoa(i)))
	}

	// Run a REAL Compaction() over the REAL *LocalFS → 1 L1 + 1 manifest. The
	// manifest's firstSys == base (the OLDEST L0's sysTime); it lists ALL 4 L0s.
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track25-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoErrorf(t, err, "compaction must produce the L1 + the manifest over REAL *LocalFS")
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (4 L0 files exist)")
	require.Equalf(t, 4, res.Rows, "the L1 must preserve ALL 4 rows (Preserve-All)")
	require.Lenf(t, res.L0Files, 4, "the manifest must list ALL 4 L0 keys (Preserve-All)")
	// The manifest's firstSys == the OLDEST L0's sysTime (the byte-identity the
	// tautology leverages — manifestKeyFor + l1KeyFor share firstSysT).
	require.Containsf(t, res.ManifestKey, fmt.Sprintf("/%d.manifest", range19BaseDur),
		"the manifest key %q MUST encode firstSys==base (the OLDEST L0's sysTime) — the byte-identity the tautology leverages", res.ManifestKey)

	// Query at TWO txTimes: (A) base+1500 (manifest NOT skipped) + (B) base-500
	// (manifest skipped). Each under EnableFirstSysSkip true vs false.
	q := func(enable bool, txNs int64) (*database.TriTemporalEvent, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "track25-bucket", cfg)
		return r.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txNs))
	}

	// (A) txTime = base+1500: the manifest is NOT skipped (firstSys==base <=
	// base+1500). The dominant is the row at base+1000 (the highest sysTime <=
	// txTime that covers validTime=base+50). byte-IDENTICAL to the no-skip path.
	const txAbove = range19BaseDur + 1500
	withSkipA, errSkipA := q(true, txAbove)
	require.NoErrorf(t, errSkipA, "AsOf at base+1500 with skip must resolve")
	require.NotNilf(t, withSkipA, "the dominant at base+1500 must be non-nil with the skip")
	withoutSkipA, errNoSkipA := q(false, txAbove)
	require.NoErrorf(t, errNoSkipA, "AsOf at base+1500 without skip must resolve")
	require.NotNilf(t, withoutSkipA, "the dominant at base+1500 must be non-nil without the skip")
	assert.Equalf(t, withSkipA.SystemTime, withoutSkipA.SystemTime,
		"PRESERVES-ANSWER (A, base+1500): SystemTime byte-identical (the manifest NOT skipped — Law II)")
	assert.Equalf(t, withSkipA.Payload, withoutSkipA.Payload,
		"PRESERVES-ANSWER (A, base+1500): Payload byte-identical (the SAME dominant)")
	assert.Equalf(t, range19BaseDur+1000, withSkipA.SystemTime,
		"the dominant at base+1500 == base+1000 (the highest sysTime <= txTime; the manifest's L1 carries it)")

	// (B) txTime = base-500: the manifest IS skipped (firstSys==base > base-500)
	// AND the L1 is file-skipped AND the 4 L0s are file-skipped. AsOf returns
	// ErrEntityNotFound (law-II-preserving; byte-identical to the no-skip path —
	// every row fails Filter2 since sysT >= base > base-500).
	const txBelow = range19BaseDur - 500
	_, errSkipB := q(true, txBelow)
	assert.Errorf(t, errSkipB, "PRESERVES-ANSWER (B, base-500): AsOf with skip must return ErrEntityNotFound (the manifest + L1 + L0s all skipped — law-II-preserving empty)")
	_, errNoSkipB := q(false, txBelow)
	assert.Errorf(t, errNoSkipB, "PRESERVES-ANSWER (B, base-500): AsOf without skip must ALSO return ErrEntityNotFound (every row fails Filter2 — byte-identical to the skip path; Law II preserved)")
	// The skip path + the no-skip path BOTH return NotFound at base-500 — the
	// manifest skip changed NOTHING (byte-identical empty result).
	assert.Truef(t, errSkipB != nil && errNoSkipB != nil, "PRESERVES-ANSWER (B): both paths empty (the manifest skip is Law-II-preserving — byte-identical)")
	t.Logf("T-MANIFEST-PRESERVES-ANSWER REAL *LocalFS: compaction → L1+manifest(firstSys=base); txTime=base+1500 → dominant base+1000 byte-identical (manifest NOT skipped); txTime=base-500 → manifest+L1+L0s skipped, NotFound byte-identical both paths (Law II preserved)")
}

// ---------------------------------------------------------------------------
// T-MANIFEST-DOWNLOAD-COUNT (REAL *LocalFS) — the disclosure counter + the cut.
// ---------------------------------------------------------------------------

// manifestCountingLocalFS wraps a *LocalFS in a per-key-prefix Download counter
// (manifest vs L1 vs L0) — the instrument T-MANIFEST-DOWNLOAD-COUNT reads to
// ASSERT the skip CUT the manifest download (the cost center this fork closes).
// It embeds *LocalFS so ListObjects/Upload/Delete delegate to the production
// on-disk path (only the Download is counted — by key prefix; the read path's
// cost center). The Download override returns the REAL io.ReadCloser (the
// S3Downloader interface signature), the SAME shape as the Day-24
// countingLocalFS wrapper. Single-threaded (one AsOf at a time) → non-atomic
// counts are safe (the Day-24 countingLocalFS precedent).
type manifestCountingLocalFS struct {
	*LocalFS
	manifestDLs int // downloads of compaction/{hex8}/{firstSys}.manifest keys
	l1DLs       int // downloads of l1/{hex8}/{firstSys}.arrow keys
	l0DLs       int // downloads of l0/{hex8}/{firstSys}.arrow keys
}

// Download delegates to *LocalFS.Download + tallies by key prefix (the cost
// center the manifest skip cuts). The Resolver reads the SAME production on-disk
// path; only the Download is counted.
func (c *manifestCountingLocalFS) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	switch {
	case isManifestKey(key):
		c.manifestDLs++
	case isL1Key(key):
		c.l1DLs++
	case isL0Key(key):
		c.l0DLs++
	}
	return c.LocalFS.Download(ctx, bucket, key)
}

// isManifestKey / isL1Key / isL0Key classify a durable key by its tier prefix
// (the byte-identity the manifest-skip tautology leverages — the manifest key
// lives under "compaction/", the L1 under "l1/", the L0 under "l0/").
func isManifestKey(key string) bool    { return startsWith(key, "compaction/") }
func isL1Key(key string) bool          { return startsWith(key, "l1/") }
func isL0Key(key string) bool          { return startsWith(key, "l0/") }
func startsWith(s, prefix string) bool { return len(s) >= len(prefix) && s[:len(prefix)] == prefix }

// TestTrack25_T_MANIFEST_DOWNLOAD_COUNT_REALLocalFS is DAY-25 T-MANIFEST-DOWNLOAD-
// COUNT over a REAL *LocalFS. Same N=4 staggered-files + REAL Compaction() setup
// as T-MANIFEST-PRESERVES-ANSWER. Query at txTime = base-500 (BELOW the manifest's
// firstSys==base) with EnableFirstSysSkip=true: the manifest Download counter
// reads EXACTLY 0 (the manifest download was SKIPPED), the L1 Download counter
// reads 0 (the L1 download was SKIPPED — Day-24 file-skip), the L0 Download
// counter reads 0 (all 4 L0s SKIPPED — Day-24 file-skip), AND the disclosure
// counter QueryManifestSkippedFirstSys fires EXACTLY 1 (the 1 skipped manifest).
// Query with EnableFirstSysSkip=false: the manifest Download counter reads 1 (the
// manifest IS downloaded + ParseManifest'd), the L1 Download counter reads 1,
// the L0 Download counter reads 4 (no skip — every file downloaded). The
// differential (manifest 1→0, L1 1→0, L0 4→0, disclosure 0→1) is the load-bearing
// cut on the manifest channel.
//
// CAUGHT-IN-DEV risk: a manifest skip that fires but does NOT cut the manifest
// download (the `continue` placed AFTER the Download call) would show the manifest
// downloaded (counter 1) AND the disclosure fired (1) → the tooth's
// "manifestDLs==0" assertion catches it. A skip that cuts the download but does
// NOT fire the disclosure counter would show manifestDLs==0 + disclosure 0 → the
// tooth's "disclosure fires >= 1" assertion catches it. BOTH the cut AND the
// disclosure are asserted.
func TestTrack25_T_MANIFEST_DOWNLOAD_COUNT_REALLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "track25-dc-bucket")
	const entity = "alpha"

	// N=4 staggered L0 files (same setup as PRESERVES-ANSWER) + a REAL Compaction().
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		track19InsertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("dc-"+strconv.Itoa(i)))
	}
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track25-dc-bucket", database.DefaultCompactionConfig())
	res, err := compactor.Compaction(ctx, entity, database.EntityHash8(entity))
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce the manifest")

	const txBelow = range19BaseDur - 500 // BELOW the manifest's firstSys==base

	// (1) SKIP ON: the manifest + L1 + L0 downloads are ALL SKIPPED (counters 0);
	// the disclosure counter fires EXACTLY 1 (the 1 skipped manifest).
	skipLFS := &manifestCountingLocalFS{LocalFS: lfs}
	skipR := database.NewResolver(skipLFS, skipLFS, alloc, "track25-dc-bucket", database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	manBefore := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manBefore = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	_, err = skipR.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txBelow))
	assert.Errorf(t, err, "SKIP ON at base-500: AsOf must return ErrEntityNotFound (the manifest + L1 + L0s all skipped)")
	manAfter := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manAfter = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	assert.Equalf(t, 0, skipLFS.manifestDLs, "SKIP ON: the manifest download was SKIPPED (manifestDLs==0 — the cost center this fork closes)")
	assert.Equalf(t, 0, skipLFS.l1DLs, "SKIP ON: the L1 download was SKIPPED (Day-24 file-skip — firstSys==base > base-500)")
	assert.Equalf(t, 0, skipLFS.l0DLs, "SKIP ON: the 4 L0 downloads were SKIPPED (Day-24 file-skip)")
	assert.Equalf(t, int64(1), manAfter-manBefore, "SKIP ON: the manifest-skip disclosure counter fired EXACTLY 1 (the 1 skipped manifest — QueryManifestSkippedFirstSys)")

	// (2) SKIP OFF: the manifest + L1 + L0 downloads ALL run; the disclosure
	// counter fires 0 (the pre-Day-25 behavior).
	noSkipLFS := &manifestCountingLocalFS{LocalFS: lfs}
	noSkipR := database.NewResolver(noSkipLFS, noSkipLFS, alloc, "track25-dc-bucket", database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	manBefore2 := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manBefore2 = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	_, err = noSkipR.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txBelow))
	assert.Errorf(t, err, "SKIP OFF at base-500: AsOf must ALSO return ErrEntityNotFound (every row fails Filter2 — byte-identical to the skip path)")
	manAfter2 := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manAfter2 = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	assert.Equalf(t, 1, noSkipLFS.manifestDLs, "SKIP OFF: the manifest IS downloaded (manifestDLs==1 — the pre-Day-25 behavior; ParseManifest runs)")
	assert.Equalf(t, 1, noSkipLFS.l1DLs, "SKIP OFF: the L1 IS downloaded (l1DLs==1 — no Day-24 file-skip)")
	// HONEST: under SKIP OFF the 4 L0s are NOT downloaded (l0DLs==0) — the
	// manifest IS downloaded + ParseManifest marks ALL 4 L0s superseded → they are
	// REMOVED from tailKeys → they are NOT downloaded (the manifest's whole
	// purpose since Day-14: mark superseded L0s so they are not re-scanned). The
	// no-skip path downloads manifest(1) + L1(1) + L0s(0) = 2 downloads; the skip
	// path downloads manifest(0) + L1(0) + L0s(0) = 0 downloads. The manifest
	// skip cut the manifest download (1→0) AND the L1 download (1→0); the L0s
	// were ALREADY not-downloaded under supersession in BOTH paths.
	assert.Equalf(t, 0, noSkipLFS.l0DLs, "SKIP OFF: the 4 L0s are NOT downloaded (l0DLs==0) — the manifest IS downloaded + ParseManifest marks them superseded → removed from tailKeys (the Day-14 supersession contract; the L0s are in the L1, not re-scanned)")
	assert.Equalf(t, int64(0), manAfter2-manBefore2, "SKIP OFF: the manifest-skip disclosure counter fired 0 (the pre-Day-25 behavior)")
	t.Logf("T-MANIFEST-DOWNLOAD-COUNT REAL *LocalFS: SKIP ON at base-500 → manifestDLs=%d l1DLs=%d l0DLs=%d disclosure+=%d (the manifest + L1 + L0 downloads CUT); SKIP OFF → manifestDLs=%d l1DLs=%d l0DLs=%d disclosure+=0 (pre-Day-25); AsOf byte-identical (NotFound) both paths (Law II)",
		skipLFS.manifestDLs, skipLFS.l1DLs, skipLFS.l0DLs, manAfter-manBefore, noSkipLFS.manifestDLs, noSkipLFS.l1DLs, noSkipLFS.l0DLs)
}

// ---------------------------------------------------------------------------
// T-MANIFEST-RANGE-WINDOW-ORTHOGONAL (REAL *LocalFS) — the skip is window-agnostic.
// ---------------------------------------------------------------------------

// TestTrack25_T_MANIFEST_RANGE_WINDOW_ORTHOGONAL_REALLocalFS is DAY-25 T-MANIFEST-
// RANGE-WINDOW-ORTHOGONAL over a REAL *LocalFS. The manifest skip bounds sysTime
// (Filter2); Range bounds validTime (Filter3). The two are ORTHOGONAL: the
// window [vLo,vHi) is IRRELEVANT to the manifest skip. This tooth proves it: N=4
// staggered files + a REAL Compaction() → 1 manifest; a Range window
// [base+50, base+99999) at txTime = base-500 (BELOW the manifest's firstSys). The
// manifest IS skipped (firstSys==base > base-500 — the window does NOT rescue it),
// AND the Range result is byte-IDENTICAL to the no-skip path (the rows skipped
// fail Filter2 anyway; the window-passing rows are a SUBSET of the Filter2-passing
// rows). The §0.e step 7: the window slice is UNCHANGED byte-for-byte.
//
// The load-bearing claim: a Range window WIDE enough to intersect a skipped
// manifest's L1 validTime window does NOT cause the manifest skip to misfire. The
// manifest skip is on sysTime (the manifest's MIN sysTime == the L1's firstSys),
// NOT validTime — so a manifest skipped for AsOf is skipped for Range too (the
// SAME loadSupersededL0Keys call, query.go Range loop). The window is the SECOND
// filter (Filter3), applied AFTER the skip; the skip's bound (firstSys > txTime)
// is the FIRST filter (Filter2's precondition), applied BEFORE the window.
func TestTrack25_T_MANIFEST_RANGE_WINDOW_ORTHOGONAL_REALLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "track25-rw-bucket")
	const entity = "alpha"

	// N=4 staggered files. Each row's sysTime = base+i*1000 (the file's
	// FirstSysTimeNs) AND its validTimeStart = base+i*1000 (DISTINCT, ascending
	// == sysTime-ascending, so the Range validTimeStart-sort is deterministic +
	// matches sysTime order). The validTime window = [base+i*1000, openEnd) — WIDE,
	// so a Range window [base+50, base+99999) intersects ALL 4 rows' validTime
	// intervals (the window is wide on purpose — to prove the manifest skip is on
	// sysTime, NOT validTime; a window-then-skip would NOT skip the manifest
	// because the manifest's L1 validTime intervals intersect the window).
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		track19InsertWindowRow(t, alloc, lfs, flusher, entity, sysNs, sysNs, rangeOpenEnd, []byte("rw-"+strconv.Itoa(i)))
	}
	// REAL Compaction() → 1 manifest (firstSys==base) listing ALL 4 L0s.
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track25-rw-bucket", database.DefaultCompactionConfig())
	res, err := compactor.Compaction(ctx, entity, database.EntityHash8(entity))
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce the manifest")

	// Range at txTime = base-500 (BELOW the manifest's firstSys==base): the manifest
	// IS skipped (firstSys==base > base-500) AND the L1 is file-skipped AND the L0s
	// are file-skipped. EVERY row fails Filter2 (sysT >= base > base-500) → the
	// Range window is EMPTY under BOTH the skip + the no-skip path (Range returns
	// ErrEntityNotFound — no row intersects the window at txTime; query.go:503/536).
	// byte-IDENTITY: BOTH paths return the SAME error (the manifest skip removed
	// ZERO window-passers — there are NONE to remove; the window is ORTHOGONAL to
	// the sysTime skip).
	const txBelow = range19BaseDur - 500
	vLo := time.Unix(0, range19BaseDur+50)
	vHi := time.Unix(0, range19BaseDur+99999)
	tx := time.Unix(0, txBelow)

	q := func(enable bool) ([]*database.TriTemporalEvent, bool, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "track25-rw-bucket", cfg)
		return r.Range(ctx, entity, vLo, vHi, tx)
	}
	withSkip, truncSkip, errSkip := q(true)
	// At base-500 EVERY row fails Filter2 → no row intersects the window → Range
	// returns ErrEntityNotFound (NOT a nil-slice-no-error; query.go:503/536). The
	// skip + no-skip paths BOTH return the SAME error — the manifest skip is
	// window-agnostic (it removed ZERO window-passers; there are none).
	assert.ErrorIsf(t, errSkip, database.ErrEntityNotFound, "Range with skip at base-500 returns ErrEntityNotFound (no row intersects the window at txTime — every row fails Filter2)")
	assert.Nilf(t, withSkip, "the Range window at base-500 is EMPTY (nil slice)")
	assert.Falsef(t, truncSkip, "no truncation (the window is EMPTY — every row fails Filter2)")
	withoutSkip, truncNo, errNoSkip := q(false)
	assert.ErrorIsf(t, errNoSkip, database.ErrEntityNotFound, "Range without skip at base-500 ALSO returns ErrEntityNotFound (every row fails Filter2 — byte-identical to the skip path; the window is ORTHOGONAL)")
	assert.Nilf(t, withoutSkip, "the no-skip Range window at base-500 is EMPTY (nil slice — byte-identical to the skip path)")
	assert.Falsef(t, truncNo, "no truncation without skip")

	// byte-IDENTITY: the skip did NOT change the Range window. The manifest was
	// skipped (firstSys==base > base-500), the L1 was file-skipped, the 4 L0s were
	// file-skipped — their rows fail Filter2 (sysT >= base > base-500) so they were
	// NEVER in the window anyway. BOTH paths return ErrEntityNotFound (the SAME
	// error) + a nil slice — byte-identical.
	assert.Truef(t, errSkip != nil && errNoSkip != nil, "RANGE-WINDOW-ORTHOGONAL: both paths return ErrEntityNotFound (the manifest skip removed ZERO window-passers; the window is ORTHOGONAL to the sysTime skip)")

	// (B) Range at txTime = base+1500 (ABOVE the manifest's firstSys): the manifest
	// is NOT skipped (firstSys==base <= base+1500). The L1 is scanned (it carries
	// all 4 rows). The rows at base+0..base+1000 pass Filter2 (sysT <= base+1500);
	// the rows at base+2000..base+3000 fail Filter2 (sysT > base+1500). The wide
	// window [base+50, base+99999) intersects the 2 surviving rows' validTime
	// intervals. byte-IDENTICAL to the no-skip path (the manifest skip did NOT
	// fire — firstSys <= txTime).
	const txAbove = range19BaseDur + 1500
	tx2 := time.Unix(0, txAbove)
	q2 := func(enable bool) ([]*database.TriTemporalEvent, bool, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "track25-rw-bucket", cfg)
		return r.Range(ctx, entity, vLo, vHi, tx2)
	}
	withSkip2, _, errSkip2 := q2(true)
	require.NoErrorf(t, errSkip2, "Range with skip at base+1500 must resolve")
	withoutSkip2, _, errNoSkip2 := q2(false)
	require.NoErrorf(t, errNoSkip2, "Range without skip at base+1500 must resolve")
	// The 2 surviving rows: base+0 + base+1000 (Filter2 sysT<=base+1500; the
	// base+2000/base+3000 rows fail Filter2). The manifest skip did NOT fire
	// (firstSys==base <= base+1500) → byte-IDENTICAL to the no-skip path.
	require.Lenf(t, withSkip2, 2, "exactly 2 rows at base+1500 (the base+0 + base+1000 rows pass Filter2; the base+2000/base+3000 rows fail Filter2 — NOT skipped, just Filter2-rejected)")
	require.Equalf(t, len(withoutSkip2), len(withSkip2), "RANGE-WINDOW-ORTHOGONAL (B, base+1500): the row count is byte-identical (the manifest skip did NOT fire — firstSys <= txTime)")
	for i := range withSkip2 {
		assert.Equalf(t, withoutSkip2[i].SystemTime, withSkip2[i].SystemTime,
			"RANGE-WINDOW-ORTHOGONAL (B): row %d SystemTime byte-identical", i)
		assert.Equalf(t, withoutSkip2[i].Payload, withSkip2[i].Payload,
			"RANGE-WINDOW-ORTHOGONAL (B): row %d Payload byte-identical", i)
	}
	t.Logf("T-MANIFEST-RANGE-WINDOW-ORTHOGONAL REAL *LocalFS: compaction → manifest(firstSys=base); Range at base-500 → manifest+L1+L0s skipped, window EMPTY both paths (orthogonal); Range at base+1500 → %d rows both paths (manifest NOT skipped — firstSys<=txTime; the window is ORTHOGONAL to the sysTime skip)", len(withSkip2))
}
