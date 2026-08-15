// Day 26 (ADR-0031) teeth (the REAL *LocalFS route teeth) — the zero-alloc-line
// streaming ParseManifest + readManifestBody, driven against a REAL *LocalFS
// (the Day-12.5 tooth-principle "drive the route, not the seam").
//
// Day 26 swapped the 3 ParseManifest caller sites' io.ReadAll → readManifestBody
// (the single-grow read) + replaced ParseManifest's strings.Split body with a
// strings.IndexByte scan (the stringScan). BOTH are byte-identical (the
// internal/database T-STREAM-BYTE-IDENTITY fuzz + the T-STREAM-READ-BODY guard
// prove it at the unit level). This file drives the COMPOSITION over a REAL
// *LocalFS: a REAL Compaction() → a manifest on disk → an AsOf whose
// loadSupersededL0Keys caller DOWNLOADS the manifest (the NEW readManifestBody
// reads it off the on-disk io.ReadCloser) + PARSES it (the NEW ParseManifest) →
// the superseded set + the dominant MUST be byte-identical to the Day-25
// baseline. The manifest IS downloaded (the manifestDLs counter reads 1) so the
// NEW parse path is the one that ran (NOT the skip path — the skip is Day-25's
// already-shipped tooth; Day 26 is the NON-skipped manifest's parse). This is
// the load-bearing composition tooth: the unit teeth prove ParseManifest +
// readManifestBody in isolation; this tooth proves they compose correctly over
// the production on-disk route the query actually takes.
package durability

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTrack26_T_STREAM_LOADSUPERSEDED_REALLocalFS is DAY-26
// T-STREAM-LOADSUPERSEDED-REALLocalFS. A REAL Compaction() over a REAL *LocalFS
// produces 1 L1 + 1 manifest (firstSys==base, listing ALL 4 L0s). An AsOf at
// txTime=base+1500 (the manifest is NOT skipped — firstSys==base <= base+1500)
// drives loadSupersededL0Keys: the manifest is DOWNLOADED (the NEW
// readManifestBody reads it off the on-disk io.ReadCloser) + PARSED (the NEW
// ParseManifest) → the 4 L0s are marked superseded → the dominant is the row at
// base+1000 (the highest sysTime <= txTime covering validTime=base+50), byte-
// identical to the Day-25 baseline.
//
// The manifestDLs counter reads EXACTLY 1 (the manifest WAS downloaded — the NEW
// parse path ran, NOT the Day-25 skip path). The l0DLs counter reads EXACTLY 0
// (the 4 L0s are superseded → removed from tailKeys → NOT re-scanned; the Day-14
// supersession contract, now driven through the NEW parse). The l1DLs counter
// reads 1 (the L1 IS scanned — it carries the dominant). The dominant's
// SystemTime == base+1000 + Payload == "row-1" (byte-identical to Day-25).
//
// This is the COMPOSITION tooth: the unit teeth (T-STREAM-BYTE-IDENTITY +
// T-STREAM-READ-BODY) prove byte-identity in isolation; this tooth proves the
// composition over the production route. If readManifestBody or ParseManifest
// returned a wrong body/l1Key/l0Keys, the superseded set would differ → the L0s
// would NOT be marked superseded → l0DLs would be 4 (re-scanned) OR the dominant
// would be wrong → the tooth catches it.
func TestTrack26_T_STREAM_LOADSUPERSEDED_REALLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "track26-bucket")
	const entity = "alpha"

	// N=4 staggered L0 files: sysTime = base + i*1000 (i=0..3). Each file's
	// FirstSysTimeNs = its row's sysTime (the production-invariant). The row's
	// validTime window = [base, openEnd) so it qualifies at validTime = base+50.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		track19InsertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("row-"+itoa26(i)))
	}

	// REAL Compaction() over the REAL *LocalFS → 1 L1 + 1 manifest (firstSys==base,
	// listing ALL 4 L0s).
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track26-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoErrorf(t, err, "compaction must produce the L1 + the manifest over REAL *LocalFS")
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (4 L0 files exist)")
	require.Equalf(t, 4, res.Rows, "the L1 must preserve ALL 4 rows (Preserve-All)")
	require.Lenf(t, res.L0Files, 4, "the manifest must list ALL 4 L0 keys (Preserve-All)")
	require.Containsf(t, res.ManifestKey, fmt.Sprintf("/%d.manifest", range19BaseDur),
		"the manifest key %q MUST encode firstSys==base (the OLDEST L0's sysTime)", res.ManifestKey)

	// Wrap the *LocalFS in the per-key-prefix Download counter (the Day-25
	// manifestCountingLocalFS instrument) so we can ASSERT the manifest WAS
	// downloaded (the NEW parse path ran, NOT the skip path).
	counting := &manifestCountingLocalFS{LocalFS: lfs}

	// AsOf at txTime = base+1500 (manifest NOT skipped — firstSys==base <= base+1500).
	// EnableFirstSysSkip=true but the skip does NOT fire on this manifest (firstSys
	// <= txTime) → the manifest IS downloaded + parsed via the NEW path.
	cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true}
	r := database.NewResolver(counting, counting, alloc, "track26-bucket", cfg)
	const txAbove = range19BaseDur + 1500
	got, qerr := r.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txAbove))
	require.NoErrorf(t, qerr, "AsOf at base+1500 must resolve (the manifest NOT skipped — the NEW parse path ran)")
	require.NotNilf(t, got, "the dominant at base+1500 must be non-nil")

	// The manifest WAS downloaded (manifestDLs==1) — the NEW readManifestBody +
	// ParseManifest ran over the on-disk manifest body. This is the load-bearing
	// assertion that the NEW parse path (NOT the Day-25 skip) is what produced the
	// superseded set.
	assert.Equalf(t, 1, counting.manifestDLs,
		"T-STREAM-LOADSUPERSEDED: manifestDLs=%d, want 1 (the manifest WAS downloaded — the NEW readManifestBody+ParseManifest ran; the Day-25 skip did NOT fire at txTime=base+1500 since firstSys==base <= base+1500)", counting.manifestDLs)
	// The 4 L0s are superseded → removed from tailKeys → NOT re-scanned (l0DLs==0).
	// This is the Day-14 supersession contract, now driven through the NEW parse:
	// if ParseManifest returned a wrong l0Keys set, the L0s would NOT be marked
	// superseded → l0DLs would be 4 (re-scanned) → the tooth catches it.
	assert.Equalf(t, 0, counting.l0DLs,
		"T-STREAM-LOADSUPERSEDED: l0DLs=%d, want 0 (the 4 L0s are superseded by the NEW ParseManifest → removed from tailKeys → NOT re-scanned; the Day-14 supersession contract through the NEW parse)", counting.l0DLs)
	// The L1 IS scanned (l1DLs==1) — it carries the dominant.
	assert.Equalf(t, 1, counting.l1DLs,
		"T-STREAM-LOADSUPERSEDED: l1DLs=%d, want 1 (the L1 IS scanned — it carries the dominant)", counting.l1DLs)

	// The dominant is byte-identical to the Day-25 baseline: SystemTime==base+1000
	// (the highest sysTime <= txTime covering validTime=base+50), Payload=="row-1".
	assert.Equalf(t, range19BaseDur+1000, got.SystemTime,
		"T-STREAM-LOADSUPERSEDED: dominant SystemTime=%d, want base+1000 (byte-identical to Day-25; the NEW parse marked the 4 L0s superseded so the L1's base+1000 row is the dominant)", got.SystemTime)
	assert.Equalf(t, []byte("row-1"), got.Payload,
		"T-STREAM-LOADSUPERSEDED: dominant Payload=%q, want \"row-1\" (byte-identical to Day-25)", got.Payload)

	t.Logf("T-STREAM-LOADSUPERSEDED REAL *LocalFS PASS: compaction → L1+manifest(firstSys=base); AsOf at base+1500 (manifest NOT skipped) → manifestDLs=1 (NEW readManifestBody+ParseManifest ran), l0DLs=0 (4 L0s superseded through the NEW parse), l1DLs=1; dominant base+1000 \"row-1\" byte-identical to Day-25 (the composition over the production route holds)")
}

// itoa26 is a tiny strconv.Itoa-free helper (keeps the test file dependency-free;
// the internal/database day26 tooth has its own copy — these are test-package-
// local helpers, intentionally NOT shared to avoid cross-package test coupling).
func itoa26(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
