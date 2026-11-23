// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// This integration test exercises streaming manifest loading through the
// production storage path (ADR-0031). Compaction writes an L1 and manifest to
// LocalFS; Resolver.AsOf downloads and parses that manifest, marks its L0 files
// superseded, and resolves the dominant row from the L1.
//
// The download counters distinguish this path from the firstSys skip. Unit
// tests cover readManifestBody and ParseManifest byte equivalence; this test
// checks their composition with real Arrow files and a real on-disk manifest.
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

// TestStreamLoadSupersededRealLocalFS writes four L0 files and compacts them
// into one L1 and one manifest. An AsOf at base+1500 cannot skip the manifest,
// whose firstSys is base, so it must download and parse the manifest once.
//
// The parsed superseded set prevents all four L0 downloads, while the L1 is
// downloaded once and supplies the row at base+1000. An incorrect manifest body
// or L0 list therefore changes either the counters or the query result.
func TestStreamLoadSupersededRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "stream-bucket")
	const entity = "alpha"

	// Write four staggered L0 files. Each contains one row whose system time is
	// base+i*1000 and whose valid-time interval includes base+50.
	for i := 0; i < 4; i++ {
		sysNs := range19BaseDur + int64(i)*1000
		insertWindowRow(t, alloc, lfs, flusher, entity, sysNs, range19BaseDur, rangeOpenEnd, []byte("row-"+itoa26(i)))
	}

	// Compact into one L1 and one manifest with firstSys=base.
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "stream-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoErrorf(t, err, "compaction failed over LocalFS")
	require.Falsef(t, res.AlreadyMoved, "compaction did not produce an L1")
	require.Equalf(t, 4, res.Rows, "L1 does not preserve all 4 rows")
	require.Lenf(t, res.L0Files, 4, "manifest does not list all 4 L0 keys")
	require.Containsf(t, res.ManifestKey, fmt.Sprintf("/%d.manifest", range19BaseDur),
		"manifest key %q does not encode the oldest L0 system time", res.ManifestKey)

	// Count downloads to prove that the manifest was loaded rather than skipped.
	counting := &manifestCountingLocalFS{LocalFS: lfs}

	// firstSys=base is visible at base+1500, so enabling the skip does not avoid
	// this manifest download.
	cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true}
	r := database.NewResolver(counting, counting, alloc, "stream-bucket", cfg)
	const txAbove = range19BaseDur + 1500
	got, qerr := r.AsOf(ctx, entity, time.Unix(0, range19BaseDur+50), time.Unix(0, txAbove))
	require.NoErrorf(t, qerr, "AsOf at base+1500 failed after loading the manifest")
	require.NotNilf(t, got, "AsOf at base+1500 returned no dominant")

	// One manifest download proves that readManifestBody and ParseManifest,
	// rather than the skip path, produced the superseded set.
	assert.Equalf(t, 1, counting.manifestDLs,
		"manifest download count = %d, want 1 at base+1500", counting.manifestDLs)
	// Correct parsing removes all four superseded L0 files from the read set.
	// An incorrect L0 list would instead cause those files to be downloaded.
	assert.Equalf(t, 0, counting.l0DLs,
		"manifest parsing left %d L0 downloads, want 0", counting.l0DLs)
	// The L1 carries the dominant row and must be downloaded once.
	assert.Equalf(t, 1, counting.l1DLs,
		"L1 download count = %d, want 1", counting.l1DLs)

	// The newest visible row at base+1000 must carry the expected payload.
	assert.Equalf(t, range19BaseDur+1000, got.SystemTime,
		"dominant SystemTime = %d, want base+1000", got.SystemTime)
	assert.Equalf(t, []byte("row-1"), got.Payload,
		"dominant payload = %q, want row-1", got.Payload)

	t.Logf("streaming manifest load returned the expected row and download counts")
}

// itoa26 formats small fixture indexes without adding a strconv import. A
// package-local copy avoids coupling tests across packages.
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
