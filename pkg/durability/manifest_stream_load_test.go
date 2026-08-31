// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// (ADR-0031) guards (the REAL *LocalFS route guards) — the zero-alloc-line
// streaming ParseManifest + readManifestBody, driven against a REAL *LocalFS
// (the guard-principle "drive the route, not the seam").
//
// swapped the 3 ParseManifest caller sites' io.ReadAll → readManifestBody
// (the single-grow read) + replaced ParseManifest's strings.Split body with a
// strings.IndexByte scan (the stringScan). BOTH are byte-identical (the
// internal/database byte-identity fuzz + the read-body guard
// prove it at the unit level). This file drives the COMPOSITION over a REAL
// *LocalFS: a REAL Compaction() → a manifest on disk → an AsOf whose
// loadSupersededL0Keys caller DOWNLOADS the manifest (the NEW readManifestBody
// reads it off the on-disk io.ReadCloser) + PARSES it (the NEW ParseManifest) →
// the superseded set + the dominant MUST be byte-identical to the
// baseline. The manifest IS downloaded (the manifestDLs counter reads 1) so the
// NEW parse path is the one that ran (NOT the skip path — the skip is's
// already-shipped guard; is the NON-skipped manifest's parse). This is
// the load-bearing composition guard: the unit guards prove ParseManifest +
// readManifestBody in isolation; this guard proves they compose correctly over
// the production on-disk route the query actually takes.
package durability

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStreamLoadSupersededRealLocalFS is the
// stream-load-superseded-over-real-LocalFS guard. A REAL Compaction() over a REAL *LocalFS
// produces 1 L1 + 1 manifest (firstSys==base, listing ALL 4 L0s). An AsOf at
// txTime=base+1500 (the manifest is NOT skipped — firstSys==base <= base+1500)
// drives loadSupersededL0Keys: the manifest is DOWNLOADED (the NEW
// readManifestBody reads it off the on-disk io.ReadCloser) + PARSED (the NEW
// ParseManifest) → the 4 L0s are marked superseded → the dominant is the row at
// base+1000 (the highest sysTime <= txTime covering validTime=base+50), byte-
// identical to the baseline.
//
// The manifestDLs counter reads EXACTLY 1 (the manifest WAS downloaded — the NEW
// parse path ran, NOT the skip path). The l0DLs counter reads EXACTLY 0
// (the 4 L0s are superseded → removed from tailKeys → NOT re-scanned; the
// supersession contract, now driven through the NEW parse). The l1DLs counter
// reads 1 (the L1 IS scanned — it carries the dominant). The dominant's
// SystemTime == base+1000 + Payload == "row-1" (byte-identical to).
//
// This is the COMPOSITION guard: the unit guards (the byte-identity fuzz +
// the read-body guard) prove byte-identity in isolation; this guard proves the
// composition over the production route. If readManifestBody or ParseManifest
// returned a wrong body/l1Key/l0Keys, the superseded set would differ → the L0s
// would NOT be marked superseded → l0DLs would be 4 (re-scanned) OR the dominant
// would be wrong → the guard catches it.
func TestStreamLoadSupersededRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "stream-bucket")
	const entity = "alpha"

	// N=4 staggered L0 files: sysTime = base + i*1000 (i=0..3). Each file's
	// FirstSysTimeNs = its row's sysTime (the production-invariant). The row's
	// validTime window = [base, openEnd) so it qualifies at validTime = base+50.
	for i := 0; i < 4; i++ {
		sysNs := rangeWinBaseDur + int64(i)*1000
		insertWindowRow(t, alloc, lfs, flusher, entity, sysNs, rangeWinBaseDur, rangeOpenEnd, []byte("row-"+itoa26(i)))
	}

	// REAL Compaction() over the REAL *LocalFS → 1 L1 + 1 manifest (firstSys==base,
	// listing ALL 4 L0s).
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "stream-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoErrorf(t, err, "compaction must produce the L1 + the manifest over REAL *LocalFS")
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (4 L0 files exist)")
	require.Equalf(t, 4, res.Rows, "the L1 must preserve ALL 4 rows (Preserve-All)")
	require.Lenf(t, res.L0Files, 4, "the manifest must list ALL 4 L0 keys (Preserve-All)")
	require.Containsf(t, res.ManifestKey, fmt.Sprintf("/%d.manifest", rangeWinBaseDur),
		"the manifest key %q MUST encode firstSys==base (the OLDEST L0's sysTime)", res.ManifestKey)

	// Wrap the *LocalFS in the per-key-prefix Download counter (the
	// manifestCountingLocalFS instrument) so we can ASSERT the manifest WAS
	// downloaded (the NEW parse path ran, NOT the skip path).
	counting := &manifestCountingLocalFS{LocalFS: lfs}

	// AsOf at txTime = base+1500 (manifest NOT skipped — firstSys==base <= base+1500).
	// EnableFirstSysSkip=true but the skip does NOT fire on this manifest (firstSys
	// <= txTime) → the manifest IS downloaded + parsed via the NEW path.
	cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true}
	r := database.NewResolver(counting, counting, alloc, "stream-bucket", cfg)
	const txAbove = rangeWinBaseDur + 1500
	got, qerr := r.AsOf(ctx, entity, time.Unix(0, rangeWinBaseDur+50), time.Unix(0, txAbove))
	require.NoErrorf(t, qerr, "AsOf at base+1500 must resolve (the manifest NOT skipped — the NEW parse path ran)")
	require.NotNilf(t, got, "the dominant at base+1500 must be non-nil")

	// The manifest WAS downloaded (manifestDLs==1) — the NEW readManifestBody +
	// ParseManifest ran over the on-disk manifest body. This is the load-bearing
	// assertion that the NEW parse path (NOT the skip) is what produced the
	// superseded set.
	assert.Equalf(t, 1, counting.manifestDLs,
		"manifestDLs=%d, want 1 (the manifest WAS downloaded — the NEW readManifestBody+ParseManifest ran; the skip did NOT fire at txTime=base+1500 since firstSys==base <= base+1500)", counting.manifestDLs)
	// The 4 L0s are superseded → removed from tailKeys → NOT re-scanned (l0DLs==0).
	// This is the supersession contract, now driven through the NEW parse:
	// if ParseManifest returned a wrong l0Keys set, the L0s would NOT be marked
	// superseded → l0DLs would be 4 (re-scanned) → the guard catches it.
	assert.Equalf(t, 0, counting.l0DLs,
		"l0DLs=%d, want 0 (the 4 L0s are superseded by the NEW ParseManifest → removed from tailKeys → NOT re-scanned; the supersession contract through the NEW parse)", counting.l0DLs)
	// The L1 IS scanned (l1DLs==1) — it carries the dominant.
	assert.Equalf(t, 1, counting.l1DLs,
		"l1DLs=%d, want 1 (the L1 IS scanned — it carries the dominant)", counting.l1DLs)

	// The dominant is byte-identical to the baseline: SystemTime==base+1000
	// (the highest sysTime <= txTime covering validTime=base+50), Payload=="row-1".
	assert.Equalf(t, rangeWinBaseDur+1000, got.SystemTime,
		"dominant SystemTime=%d, want base+1000 (byte-identical to; the NEW parse marked the 4 L0s superseded so the L1's base+1000 row is the dominant)", got.SystemTime)
	assert.Equalf(t, []byte("row-1"), got.Payload,
		"dominant Payload=%q, want \"row-1\" (byte-identical to)", got.Payload)

	t.Logf("stream-load-superseded REAL *LocalFS PASS: compaction → L1+manifest(firstSys=base); AsOf at base+1500 (manifest NOT skipped) → manifestDLs=1 (NEW readManifestBody+ParseManifest ran), l0DLs=0 (4 L0s superseded through the NEW parse), l1DLs=1; dominant base+1000 \"row-1\" byte-identical to (the composition over the production route holds)")
}

// itoa26 is a tiny strconv.Itoa-free helper (keeps the test file dependency-free;
// the internal/database guard has its own copy — these are test-package-
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
