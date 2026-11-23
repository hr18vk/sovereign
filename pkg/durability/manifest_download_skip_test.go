// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These tests exercise the manifest download skip through compaction and
// Resolver reads over LocalFS (ADR-0030). A manifest filename carries firstSys,
// the minimum system time in its L1. When firstSys is greater than txTime, the
// system-time filter excludes every row in that L1 and all L0 files it
// supersedes. The resolver can skip the manifest download without changing the
// query result, and QueryManifestSkippedFirstSys records the skip.
//
// The comparison is strict. At firstSys == txTime, the first row is visible, so
// the manifest must still be loaded. Tests cover AsOf and Range, compare skip
// and no-skip results, and count downloads by object tier. Parsing, boundary,
// and telemetry units are covered in internal/database and internal/telemetry.

package durability

import (
	"context"
	"fmt"
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
// Answer preservation over LocalFS.
// ---------------------------------------------------------------------------

// TestManifestPreservesAnswerRealLocalFS compacts four rows into an L1 and a
// manifest with firstSys=base. At txTime=base+1500 the manifest is loaded and
// the row at base+1000 wins. At base-500 the manifest, L1, and superseded L0
// files are all ineligible, so both skip configurations return not-found.
// Comparing enabled and disabled skips checks that the optimization does not
// change either answer.
func TestManifestPreservesAnswerRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "manifest-bucket")
	const entity = "alpha"

	// Each L0 contains one row at base+i*1000. All valid-time intervals include
	// base+50, and each file's FirstSysTimeNs equals its row's system time.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		insertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("row-"+strconv.Itoa(i)))
	}

	// Compaction produces one L1 and one manifest with firstSys=base, listing
	// all four input L0 files.
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "manifest-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoErrorf(t, err, "compaction failed over LocalFS")
	require.Falsef(t, res.AlreadyMoved, "compaction did not produce an L1")
	require.Equalf(t, 4, res.Rows, "L1 does not preserve all 4 rows")
	require.Lenf(t, res.L0Files, 4, "manifest does not list all 4 L0 keys")
	// The manifest and L1 keys share firstSys, taken from the oldest L0 row.
	require.Containsf(t, res.ManifestKey, fmt.Sprintf("/%d.manifest", range19BaseDur),
		"manifest key %q does not encode the oldest L0 system time", res.ManifestKey)

	// Compare both skip configurations above and below firstSys.
	q := func(enable bool, txNs int64) (*database.TriTemporalEvent, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "manifest-bucket", cfg)
		return r.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txNs))
	}

	// At base+1500 the manifest is loaded and the visible row at base+1000 wins.
	const txAbove = range19BaseDur + 1500
	withSkipA, errSkipA := q(true, txAbove)
	require.NoErrorf(t, errSkipA, "AsOf at base+1500 with skip must resolve")
	require.NotNilf(t, withSkipA, "the dominant at base+1500 must be non-nil with the skip")
	withoutSkipA, errNoSkipA := q(false, txAbove)
	require.NoErrorf(t, errNoSkipA, "AsOf at base+1500 without skip must resolve")
	require.NotNilf(t, withoutSkipA, "the dominant at base+1500 must be non-nil without the skip")
	assert.Equalf(t, withSkipA.SystemTime, withoutSkipA.SystemTime,
		"SystemTime differs between skip configurations at base+1500")
	assert.Equalf(t, withSkipA.Payload, withoutSkipA.Payload,
		"payload differs between skip configurations at base+1500")
	assert.Equalf(t, range19BaseDur+1000, withSkipA.SystemTime,
		"dominant at base+1500 must have SystemTime base+1000")

	// At base-500, every row is newer than txTime. Skipping the manifest and
	// its files must produce the same not-found result as loading them.
	const txBelow = range19BaseDur - 500
	_, errSkipB := q(true, txBelow)
	assert.Errorf(t, errSkipB, "AsOf with skip unexpectedly resolved at base-500")
	_, errNoSkipB := q(false, txBelow)
	assert.Errorf(t, errNoSkipB, "AsOf without skip unexpectedly resolved at base-500")
	// Both configurations must return an error for the empty result.
	assert.Truef(t, errSkipB != nil && errNoSkipB != nil, "one skip configuration returned a result at base-500")
	t.Logf("at base+1500 the dominant is base+1000; at base-500 both configurations return not-found")
}

// ---------------------------------------------------------------------------
// The manifest skip disclosure counter and the download cut.
// ---------------------------------------------------------------------------

// manifestCountingLocalFS counts downloads by object prefix while delegating
// storage operations to LocalFS. Its counters are plain integers because these
// tests issue one query at a time.
type manifestCountingLocalFS struct {
	*LocalFS
	manifestDLs int // downloads of compaction/{hex8}/{firstSys}.manifest keys
	l1DLs       int // downloads of l1/{hex8}/{firstSys}.arrow keys
	l0DLs       int // downloads of l0/{hex8}/{firstSys}.arrow keys
}

// Download delegates to LocalFS and records the object tier.
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

// The classifiers identify manifests, L1 objects, and L0 objects by prefix.
func isManifestKey(key string) bool    { return startsWith(key, "compaction/") }
func isL1Key(key string) bool          { return startsWith(key, "l1/") }
func isL0Key(key string) bool          { return startsWith(key, "l0/") }
func startsWith(s, prefix string) bool { return len(s) >= len(prefix) && s[:len(prefix)] == prefix }

// TestManifestDownloadCountRealLocalFS compares downloads at base-500 with the
// skip enabled and disabled. Skipping must avoid the manifest and L1 downloads
// and increment QueryManifestSkippedFirstSys once. Without the skip, the
// manifest is parsed and marks all four L0 files superseded, so only the
// manifest and L1 are downloaded. Independent counters distinguish an avoided
// download from a missing telemetry increment.
func TestManifestDownloadCountRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "manifest-dc-bucket")
	const entity = "alpha"

	// Use the same four staggered L0 files and compaction as the answer test.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		insertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("dc-"+strconv.Itoa(i)))
	}
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "manifest-dc-bucket", database.DefaultCompactionConfig())
	res, err := compactor.Compaction(ctx, entity, database.EntityHash8(entity))
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce the manifest")

	const txBelow = range19BaseDur - 500 // below the manifest's firstSys==base

	// With skipping enabled, no object tier should be downloaded and the skip
	// counter should increase once.
	skipLFS := &manifestCountingLocalFS{LocalFS: lfs}
	skipR := database.NewResolver(skipLFS, skipLFS, alloc, "manifest-dc-bucket", database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	manBefore := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manBefore = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	_, err = skipR.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txBelow))
	assert.Errorf(t, err, "AsOf with skip unexpectedly resolved at base-500")
	manAfter := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manAfter = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	assert.Equalf(t, 0, skipLFS.manifestDLs, "skip enabled: manifest was downloaded")
	assert.Equalf(t, 0, skipLFS.l1DLs, "skip enabled: L1 was downloaded")
	assert.Equalf(t, 0, skipLFS.l0DLs, "skip enabled: an L0 was downloaded")
	assert.Equalf(t, int64(1), manAfter-manBefore, "manifest skip counter did not increase exactly once")

	// With skipping disabled, the manifest and L1 are downloaded and the skip
	// counter remains unchanged.
	noSkipLFS := &manifestCountingLocalFS{LocalFS: lfs}
	noSkipR := database.NewResolver(noSkipLFS, noSkipLFS, alloc, "manifest-dc-bucket", database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	manBefore2 := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manBefore2 = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	_, err = noSkipR.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txBelow))
	assert.Errorf(t, err, "AsOf without skip unexpectedly resolved at base-500")
	manAfter2 := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manAfter2 = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	assert.Equalf(t, 1, noSkipLFS.manifestDLs, "skip disabled: manifest was not downloaded")
	assert.Equalf(t, 1, noSkipLFS.l1DLs, "skip disabled: L1 was not downloaded")
	// Parsing the manifest removes all four superseded L0 files from the read
	// set even when the skip is disabled. Thus the two paths differ by the
	// manifest and L1 downloads, while both avoid L0 downloads.
	assert.Equalf(t, 0, noSkipLFS.l0DLs, "skip disabled: an L0 was downloaded despite supersession")
	assert.Equalf(t, int64(0), manAfter2-manBefore2, "manifest skip counter increased with skipping disabled")
	t.Logf("skip enabled: manifest/L1/L0 downloads=%d/%d/%d, counter delta=%d; disabled: %d/%d/%d, counter unchanged",
		skipLFS.manifestDLs, skipLFS.l1DLs, skipLFS.l0DLs, manAfter-manBefore,
		noSkipLFS.manifestDLs, noSkipLFS.l1DLs, noSkipLFS.l0DLs)
}

// ---------------------------------------------------------------------------
// The manifest skip is window-agnostic (real *LocalFS) — sysTime vs validTime orthogonality.
// ---------------------------------------------------------------------------

// TestManifestRangeWindowOrthogonalRealLocalFS verifies that firstSys skipping
// depends on transaction time, not the Range valid-time window. A wide window
// intersects every stored interval, but at base-500 all rows fail the
// system-time visibility check and both configurations return not-found. At
// base+1500 the manifest is loaded and both return the same two rows.
func TestManifestRangeWindowOrthogonalRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "manifest-rw-bucket")
	const entity = "alpha"

	// System time and valid-time start both increase with i, making result order
	// deterministic. Open-ended valid intervals all intersect the query window,
	// ensuring that only the system-time bound can exclude the manifest.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		insertWindowRow(t, alloc, lfs, flusher, entity, sysNs, sysNs, rangeOpenEnd, []byte("rw-"+strconv.Itoa(i)))
	}
	// Compaction writes one manifest with firstSys=base, listing all four L0s.
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "manifest-rw-bucket", database.DefaultCompactionConfig())
	res, err := compactor.Compaction(ctx, entity, database.EntityHash8(entity))
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce the manifest")

	// At base-500, every row is above txTime. Both configurations therefore
	// return ErrEntityNotFound and no rows despite the wide valid-time window.
	const txBelow = range19BaseDur - 500
	vLo := time.Unix(0, range19BaseDur+50)
	vHi := time.Unix(0, range19BaseDur+99999)
	tx := time.Unix(0, txBelow)

	q := func(enable bool) ([]*database.TriTemporalEvent, bool, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "manifest-rw-bucket", cfg)
		return r.Range(ctx, entity, vLo, vHi, tx)
	}
	withSkip, truncSkip, errSkip := q(true)
	// Range returns ErrEntityNotFound, not an empty successful slice, when no
	// row is visible at txTime.
	assert.ErrorIsf(t, errSkip, database.ErrEntityNotFound, "Range with skip must return not-found at base-500")
	assert.Nilf(t, withSkip, "Range with skip returned rows at base-500")
	assert.Falsef(t, truncSkip, "Range with skip reported truncation for an empty result")
	withoutSkip, truncNo, errNoSkip := q(false)
	assert.ErrorIsf(t, errNoSkip, database.ErrEntityNotFound, "Range without skip must return not-found at base-500")
	assert.Nilf(t, withoutSkip, "Range without skip returned rows at base-500")
	assert.Falsef(t, truncNo, "Range without skip reported truncation for an empty result")

	// Both paths returned an error and a nil slice for the invisible history.
	assert.Truef(t, errSkip != nil && errNoSkip != nil, "one Range configuration succeeded at base-500")

	// At base+1500 the manifest is loaded. Rows at base and base+1000 are
	// visible; the two newer rows are excluded by their system times.
	const txAbove = range19BaseDur + 1500
	tx2 := time.Unix(0, txAbove)
	q2 := func(enable bool) ([]*database.TriTemporalEvent, bool, error) {
		cfg := database.ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: enable}
		r := database.NewResolver(lfs, lfs, alloc, "manifest-rw-bucket", cfg)
		return r.Range(ctx, entity, vLo, vHi, tx2)
	}
	withSkip2, _, errSkip2 := q2(true)
	require.NoErrorf(t, errSkip2, "Range with skip at base+1500 must resolve")
	withoutSkip2, _, errNoSkip2 := q2(false)
	require.NoErrorf(t, errNoSkip2, "Range without skip at base+1500 must resolve")
	// The manifest is not skipped at base+1500, so both configurations must
	// return the two visible rows at base and base+1000.
	require.Lenf(t, withSkip2, 2, "Range at base+1500 must return the two visible rows")
	require.Equalf(t, len(withoutSkip2), len(withSkip2), "Range row counts differ between skip configurations")
	for i := range withSkip2 {
		assert.Equalf(t, withoutSkip2[i].SystemTime, withSkip2[i].SystemTime,
			"row %d SystemTime differs between skip configurations", i)
		assert.Equalf(t, withoutSkip2[i].Payload, withSkip2[i].Payload,
			"row %d payload differs between skip configurations", i)
	}
	t.Logf("Range returned no rows at base-500 and %d matching rows at base+1500", len(withSkip2))
}
