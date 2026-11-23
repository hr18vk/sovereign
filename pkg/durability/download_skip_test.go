// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Download-skip tests over real LocalFS files (ADR-0029). They live here rather
// than internal/database because that package cannot import pkg/durability
// without creating an import cycle through snapshot.go. Parser and boundary
// tests remain in internal/database; these tests exercise the LocalFS,
// L0Flusher, Arrow, and Resolver read path.
//
// Each fixture writes four single-row L0 files whose FirstSysTimeNs values
// increase in steps of 1,000. At a query time between the second and third
// values, the two later files cannot contain a row with sysTime <= txTime and
// need not be downloaded. The tests compare results with the skip enabled and
// disabled and count both downloads and QueryDownloadSkippedFirstSys events.
//
// The comparison is strict: FirstSysTimeNs == txTime does not permit a skip
// because the file's first row passes the sysTime <= txTime filter.

package durability

import (
	"context"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Answer preservation over real LocalFS files.
// ---------------------------------------------------------------------------

// TestDownloadSkipPreservesAnswerRealLocalFS queries four staggered Arrow files
// at base+1500. The files at base+2000 and base+3000 are skipped by their
// filenames, while the two earlier files are read. The dominant row is at
// base+1000, and every returned field must match the no-skip result.
func TestDownloadSkipPreservesAnswerRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "dl-bucket")
	const entity = "alpha"

	// Each row occupies its own file, with FirstSysTimeNs increasing by 1,000.
	// Every row's valid interval includes the query's valid time at base+50.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		insertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("row-"+strconv.Itoa(i)))
	}

	// Query at txTime = base+1500: files at base+0 and base+1000 are <= txTime
	// (downloaded); files at base+2000 and base+3000 are > txTime (skipped).
	const txNs = range19BaseDur + 1500
	q := func(enable bool) (*database.TriTemporalEvent, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "dl-bucket", cfg)
		return r.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txNs))
	}

	withSkip, errSkip := q(true)
	require.NoErrorf(t, errSkip, "AsOf with skip failed over real LocalFS")
	require.NotNilf(t, withSkip, "the dominant must be non-nil with the skip")
	withoutSkip, errNoSkip := q(false)
	require.NoErrorf(t, errNoSkip, "AsOf without skip failed over real LocalFS")
	require.NotNilf(t, withoutSkip, "the dominant must be non-nil without the skip")

	// The skip must not change any field of the selected row.
	assert.Equalf(t, withSkip.SystemTime, withoutSkip.SystemTime,
		"SystemTime changed after skipping files that contain no qualifying rows")
	assert.Equalf(t, withSkip.Payload, withoutSkip.Payload,
		"Payload changed after skipping files that contain no qualifying rows")
	assert.Equalf(t, withSkip.ValidTimeStart, withoutSkip.ValidTimeStart,
		"ValidTimeStart byte-identical")
	// The dominant is the highest system time not after txNs. The skipped files
	// contain only later system times and cannot supply a qualifying row.
	assert.Equalf(t, range19BaseDur+1000, withSkip.SystemTime,
		"the dominant sysTime == base+1000 (the highest sysTime <= txNs=base+1500; the base+2000/base+3000 rows are invisible at txNs)")
	t.Logf("real LocalFS: four staggered files at txTime=base+1500; skip and no-skip paths returned the same dominant sysTime=%d", withSkip.SystemTime)
}

// ---------------------------------------------------------------------------
// Download and skip counters over real LocalFS files.
// ---------------------------------------------------------------------------

// countingLocalFS counts calls through the S3Downloader interface used by the
// Resolver. The embedded LocalFS supplies the other storage operations, so only
// download instrumentation differs from the unwrapped read path.
type countingLocalFS struct {
	*LocalFS
	downloads int // non-atomic: the test is single-threaded (one AsOf at a time)
}

// Download counts each Resolver download before delegating to LocalFS.
func (c *countingLocalFS) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	c.downloads++
	return c.LocalFS.Download(ctx, bucket, key)
}

// TestDownloadSkipDownloadCountRealLocalFS compares the same query with the skip
// enabled and disabled. The enabled path must perform two downloads and record
// two skips; the disabled path must perform four downloads and record none.
// Checking both counters distinguishes a real avoided download from a misplaced
// skip counter increment.
func TestDownloadSkipDownloadCountRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "dl-dc-bucket")
	const entity = "alpha"

	// N=4 staggered files (same setup as preserves-answer).
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		insertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("dc-"+strconv.Itoa(i)))
	}

	const txNs = range19BaseDur + 1500

	// With the skip enabled, two files are downloaded and two are reported as
	// skipped.
	skipLFS := &countingLocalFS{LocalFS: lfs}
	skipR := database.NewResolver(skipLFS, skipLFS, alloc, "dl-dc-bucket", database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	skipsBefore := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		skipsBefore = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	got, err := skipR.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txNs))
	require.NoErrorf(t, err, "AsOf with skip must resolve")
	require.NotNil(t, got)
	assert.Equalf(t, 2, skipLFS.downloads, "skip on: exactly 2 downloads (the base+0 + base+1000 files; the base+2000/base+3000 skipped — firstSys > txNs=base+1500)")
	skipsAfter := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		skipsAfter = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	assert.Equalf(t, int64(2), skipsAfter-skipsBefore, "skip on: the disclosure counter fired exactly 2 (the 2 skipped files; QueryDownloadSkippedFirstSys)")

	// With the skip disabled, every file is downloaded and no skip is reported.
	noSkipLFS := &countingLocalFS{LocalFS: lfs}
	noSkipR := database.NewResolver(noSkipLFS, noSkipLFS, alloc, "dl-dc-bucket", database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	skipsBefore2 := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		skipsBefore2 = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	got2, err2 := noSkipR.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txNs))
	require.NoErrorf(t, err2, "AsOf without skip must resolve")
	require.NotNil(t, got2)
	assert.Equalf(t, 4, noSkipLFS.downloads, "skip off: exactly 4 downloads (no skip — every file downloaded)")
	skipsAfter2 := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		skipsAfter2 = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	assert.Equalf(t, int64(0), skipsAfter2-skipsBefore2, "skip disabled: the disclosure counter fired although no files were skipped")

	// The download-count comparison must also preserve the selected row.
	assert.Equalf(t, got.SystemTime, got2.SystemTime, "the cut did not change the answer (downloads 4→2, dominant byte-identical)")
	t.Logf("real LocalFS: skip enabled made %d downloads with %d skips; disabled made %d downloads with %d skips; dominant sysTime=%d on both paths", skipLFS.downloads, skipsAfter-skipsBefore, noSkipLFS.downloads, skipsAfter2-skipsBefore2, got.SystemTime)
}

// ---------------------------------------------------------------------------
// Range behavior with a wide valid-time window.
// ---------------------------------------------------------------------------

// TestDownloadSkipRangeWindowOrthogonalRealLocalFS verifies that Range applies
// the same sysTime skip as AsOf before evaluating its valid-time window. The
// window intersects every row's valid interval, but the two files after txTime
// are still skipped. The returned rows must match the no-skip path.
//
// This ordering matters because a filename carries FirstSysTimeNs, not a valid-
// time range. A skipped file cannot contain a row that passes sysTime <= txTime,
// regardless of the valid-time window.
func TestDownloadSkipRangeWindowOrthogonalRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "dl-rw-bucket")
	const entity = "alpha"

	// ValidTimeStart equals sysTime in each row, making the Range result order
	// deterministic. The open-ended valid intervals all intersect the query
	// window, so only the sysTime filter can remove the later files.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		insertWindowRow(t, alloc, lfs, flusher, entity, sysNs, sysNs, rangeOpenEnd, []byte("rw-"+strconv.Itoa(i)))
	}

	const txNs = range19BaseDur + 1500
	vLo := time.Unix(0, range19BaseDur+50)
	vHi := time.Unix(0, range19BaseDur+99999)
	tx := time.Unix(0, txNs)

	q := func(enable bool) ([]*database.TriTemporalEvent, bool, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "dl-rw-bucket", cfg)
		return r.Range(ctx, entity, vLo, vHi, tx)
	}

	withSkip, truncSkip, errSkip := q(true)
	require.NoErrorf(t, errSkip, "Range with skip failed over real LocalFS")
	assert.Falsef(t, truncSkip, "no truncation (4-window-rows << cap)")
	withoutSkip, truncNo, errNoSkip := q(false)
	require.NoErrorf(t, errNoSkip, "Range without skip must resolve")
	assert.Falsef(t, truncNo, "no truncation without skip")

	// The later files contain no row with sysTime <= txNs, so skipping them
	// cannot change the Range result.
	require.Equalf(t, len(withoutSkip), len(withSkip),
		"range-window-orthogonal: the row count is byte-identical (the skip removed zero window-passers; the window is orthogonal to the sysTime skip)")
	// Only the rows at base and base+1000 pass both the transaction-time bound
	// and the valid-time window.
	require.Lenf(t, withSkip, 2, "Range did not return the two eligible files")
	// Assert byte-identity on each row (sorted by validTimeStart — both paths).
	for i := range withSkip {
		assert.Equalf(t, withoutSkip[i].SystemTime, withSkip[i].SystemTime,
			"range-window-orthogonal: row %d SystemTime byte-identical", i)
		assert.Equalf(t, withoutSkip[i].Payload, withSkip[i].Payload,
			"range-window-orthogonal: row %d Payload byte-identical", i)
	}
	// The 2 rows are the base+0 + base+1000 sysTimes (sorted by validTimeStart
	// asc == sysTime asc here since each row's validStart == base).
	assert.Equalf(t, range19BaseDur, withSkip[0].SystemTime, "the first row is the base+0 file (not skipped)")
	assert.Equalf(t, range19BaseDur+1000, withSkip[1].SystemTime, "the second row is the base+1000 file (not skipped)")
	t.Logf("real LocalFS Range: wide valid window at txTime=base+1500 returned %d rows on both paths after skipping later sysTime files", len(withSkip))
}

// ---------------------------------------------------------------------------
// Default configuration.
// ---------------------------------------------------------------------------

// TestDownloadSkipDefaultIsOn checks the production opt-out default. The file
// name already carries FirstSysTimeNs, and parsing it is zero-allocation and
// fails closed, so DefaultResolverConfig enables the skip. Callers can disable
// it for comparison or for a literal zero-value ResolverConfig.
func TestDownloadSkipDefaultIsOn(t *testing.T) {
	def := database.DefaultResolverConfig()
	assert.Truef(t, def.EnableFirstSysSkip,
		"DefaultResolverConfig must enable the filename-bounded download skip")
	assert.Equalf(t, 1000, def.MaxL0Files, "DefaultResolverConfig changed MaxL0Files")
	assert.Equalf(t, 4096, def.MaxRangeRows, "MaxRangeRows default unchanged")

	// A literal ResolverConfig retains the boolean's zero value, allowing tests
	// and callers to select the comparison path explicitly.
	literal := database.ResolverConfig{MaxL0Files: 1000}
	assert.Falsef(t, literal.EnableFirstSysSkip,
		"literal ResolverConfig unexpectedly enables the download skip")
	t.Logf("DefaultResolverConfig enables download skip; a literal ResolverConfig leaves it disabled")
}
