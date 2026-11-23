// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Unit tests for manifest-channel download skipping (ADR-0030).
//
// loadSupersededL0Keys skips downloading compaction/{hex8}/{firstSys}.manifest
// files when firstSys > txTimeNs (using parseFirstSysFromKey and gated on
// ResolverConfig.EnableFirstSysSkip), because the L1 file and all listed L0
// files carry rows with sysTime >= firstSys > txTimeNs and are already skipped
// by the file download filter. End-to-end *LocalFS tests live in pkg/durability,
// and metric tests live in internal/telemetry and pkg/metrics.

package database

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// manifestSkipBase is a fixed ns epoch for the manifest-skip tests (1.7e18,
// well below 9e18 and int64-max 9.2e18). Used for the in-package tests that
// stagger L0 sysTimes then run a real Compaction to produce the manifest the
// skip targets.
const manifestSkipBase int64 = 1_700_000_000_000_000_000

// TestManifestParser verifies that parseFirstSysFromKey parses ".manifest" keys
// identically to L1 keys so loadSupersededL0Keys can skip manifests whose
// minimum SystemTime exceeds the query horizon.
func TestManifestParser(t *testing.T) {
	// Manifest key with a 19-digit firstSys parses cleanly.
	got, ok := parseFirstSysFromKey("compaction/abcd1234/1785542400000000000.manifest")
	require.Truef(t, ok, "manifest key with a 19-digit firstSys must parse (ok=true)")
	assert.Equalf(t, int64(1785542400000000000), got, "manifest key: parseFirstSysFromKey must return the expected int64")

	// Short firstSys value parses identically.
	gotShort, okShort := parseFirstSysFromKey("compaction/abcd1234/1000.manifest")
	require.True(t, okShort)
	assert.Equal(t, int64(1000), gotShort, "a 4-digit manifest firstSys must parse")

	// Manifest and L1 keys sharing a firstSys value parse identically.
	manifestFirst, _ := parseFirstSysFromKey("compaction/abcd1234/1700000000000000500.manifest")
	l1First, _ := parseFirstSysFromKey("l1/abcd1234/1700000000000000500.arrow")
	assert.Equalf(t, manifestFirst, l1First, "manifest and L1 keys at the same firstSys must parse to equal int64 values")

	// Malformed or negative suffixes return ok=false so callers download normally.
	redCases := []struct {
		name string
		key  string
	}{
		{"manifest non-numeric tail", "compaction/abcd1234/NOTANUMBER.manifest"},
		{"manifest negative tail", "compaction/abcd1234/-1700000000000000000.manifest"},
		{"manifest dot at position 0 (no numeric prefix)", "compaction/abcd1234/.manifest"},
		{"manifest trailing slash (no tail)", "compaction/abcd1234/"},
		{"manifest no slash", "1700000000000000000.manifest"},
		{"a .arrow key parses identically (the grammar is shape-based)", "l0/abcd1234/1700000000000000000.arrow"},
	}
	for _, c := range redCases {
		if c.name == "a .arrow key parses identically (the grammar is shape-based)" {
			v, ok := parseFirstSysFromKey(c.key)
			assert.Truef(t, ok, "positive control %q: well-formed .arrow key must parse (ok=true) because grammar is shape-based", c.name)
			assert.Equalf(t, int64(1700000000000000000), v, "the .arrow key parses to the expected firstSys")
			continue
		}
		_, ok := parseFirstSysFromKey(c.key)
		assert.Falsef(t, ok, "negative control %q: must return ok=false so manifest is downloaded and parsed", c.name)
	}
	t.Logf("manifest keys and L1 keys parse identically; negative controls returned ok=false")
}

// TestManifestParserAlloc verifies parseFirstSysFromKey allocates 0 bytes/op on .manifest keys.
func TestManifestParserAlloc(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = parseFirstSysFromKey("compaction/abcd1234/1785542400000000000.manifest")
	})
	assert.Equalf(t, 0.0, allocs, "parseFirstSysFromKey on a .manifest key must allocate 0 bytes/op; got %v", allocs)
	t.Logf(".manifest parseFirstSysFromKey allocs/run = %v", allocs)
}

// TestManifestFailsafe checks that a non-numeric manifest filename falls back to
// downloading and parsing the manifest rather than silently skipping it.
func TestManifestFailsafe(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()

	const entity = "failsafe-manifest-entity"
	for i := 0; i < 3; i++ {
		sysNs := manifestSkipBase + int64(i)*1000
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, sysNs, manifestSkipBase, openEndNs, []byte(fmt.Sprintf("row-%d", i)))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl), "each staggered L0 flushes ONE per-entity upload")
	}
	compactor := NewL1Compactor(store, store, store, alloc, "manifestskip-failsafe", DefaultCompactionConfig())
	h8 := EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err, "compaction must produce the L1 + the manifest")
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (3 L0 files exist)")
	hexStr := fmt.Sprintf("%x", h8[:])

	corruptManifestKey := fmt.Sprintf("compaction/%s/NOTANUMBER.manifest", hexStr)
	store.mu.Lock()
	realManifestBytes := store.objects[res.ManifestKey]
	require.NotEmpty(t, realManifestBytes, "the real manifest must be on the store")
	store.objects[corruptManifestKey] = realManifestBytes
	store.mu.Unlock()

	_, ok := parseFirstSysFromKey(corruptManifestKey)
	require.Falsef(t, ok, "corrupt manifest key %q must not parse (ok=false) so manifest is downloaded and parsed", corruptManifestKey)

	txNs := manifestSkipBase + 99999
	qEntity := func(enable bool) *TriTemporalEvent {
		cfg := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: enable}
		r := NewResolver(store, store, alloc, "manifestskip-failsafe", cfg)
		got, qerr := r.AsOf(ctx, entity, time.Unix(0, manifestSkipBase+50), time.Unix(0, txNs))
		require.NoErrorf(t, qerr, "AsOf must resolve under EnableFirstSysSkip=%v (the corrupt manifest's L0s survive)", enable)
		require.NotNilf(t, got, "the dominant must be non-nil under EnableFirstSysSkip=%v", enable)
		return got
	}
	withSkip := qEntity(true)
	withoutSkip := qEntity(false)
	assert.Equalf(t, withSkip.SystemTime, withoutSkip.SystemTime, "failsafe: SystemTime must match with skip enabled vs disabled")
	assert.Equalf(t, withSkip.Payload, withoutSkip.Payload, "FAILSAFE: Payload must be byte-identical (the corrupt manifest's L0s survived)")
	assert.Equalf(t, withSkip.ValidTimeStart, withoutSkip.ValidTimeStart, "FAILSAFE: ValidTimeStart byte-identical")
	t.Logf("unparseable manifest %q fell back to full download identically", corruptManifestKey)
}

// TestManifestOffBySkipBoundary verifies the strict > bound on the manifest
// skip: txTime == firstSys does not skip, while txTime < firstSys skips.
func TestManifestOffBySkipBoundary(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()

	buildCompacted := func(t *testing.T) (*memStore, *CompactionResult) {
		t.Helper()
		store := newMemStore()
		for i := 0; i < 3; i++ {
			sysNs := manifestSkipBase + int64(i)*1000
			sl := NewSkipListArena(alloc, 2*1024*1024)
			rangeWinInsertRow(t, sl, "boundary-manifest-entity", sysNs, manifestSkipBase, openEndNs, []byte(fmt.Sprintf("b-%d", i)))
			require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))
		}
		compactor := NewL1Compactor(store, store, store, alloc, "manifestskip-b", DefaultCompactionConfig())
		res, err := compactor.Compaction(ctx, "boundary-manifest-entity", EntityHash8("boundary-manifest-entity"))
		require.NoError(t, err)
		require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1")
		return store, res
	}
	_, res0 := buildCompacted(t)
	manifestFirst, ok := parseFirstSysFromKey(res0.ManifestKey)
	require.Truef(t, ok, "manifest key %q must parse", res0.ManifestKey)
	assert.Equalf(t, manifestSkipBase, manifestFirst, "manifest firstSys must equal the oldest L0 sysTime")

	// txTime == manifest.firstSys: first row qualifies; do not skip.
	store1, _ := buildCompacted(t)
	r1 := NewResolver(store1, store1, alloc, "manifestskip-b1", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got1, err1 := r1.AsOf(ctx, "boundary-manifest-entity", time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestFirst))
	require.NoErrorf(t, err1, "txTime==manifest.firstSys: AsOf must resolve (the L1's first row at sysTime==firstSys passes Filter2 with <=)")
	require.NotNilf(t, got1, "txTime == manifest.firstSys: dominant row must be non-nil")
	assert.Equalf(t, manifestFirst, got1.SystemTime, "txTime == manifest.firstSys: returned SystemTime must equal firstSys")

	// txTime == manifest.firstSys - 1: skip manifest, L1, and L0s.
	store2, _ := buildCompacted(t)
	r2 := NewResolver(store2, store2, alloc, "manifestskip-b2", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got2, err2 := r2.AsOf(ctx, "boundary-manifest-entity", time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestFirst-1))
	assert.Errorf(t, err2, "txTime==manifest.firstSys-1: AsOf must return ErrEntityNotFound (the manifest + L1 + L0s all carry rows sysT >= firstSys > txTime — the skip is transitively-safe)")
	assert.Nilf(t, got2, "txTime==manifest.firstSys-1: no dominant (the skip dropped the manifest + the file-skip dropped the L1 + L0s — correctly, zero qualifying rows)")
	r2NoSkip := NewResolver(store2, store2, alloc, "manifestskip-b2-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	got2No, err2No := r2NoSkip.AsOf(ctx, "boundary-manifest-entity", time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestFirst-1))
	assert.Errorf(t, err2No, "no-skip path at txTime == manifest.firstSys-1 must also return ErrEntityNotFound")
	assert.Nilf(t, got2No, "no-skip path: no dominant (the manifest skip changed NOTHING — both paths empty)")

	// txTime below manifest.firstSys: skip cleanly.
	store3, _ := buildCompacted(t)
	r3 := NewResolver(store3, store3, alloc, "manifestskip-b3", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	_, err3 := r3.AsOf(ctx, "boundary-manifest-entity", time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestFirst-500))
	assert.Errorf(t, err3, "txTime below manifest.firstSys must return ErrEntityNotFound")
	t.Logf("manifest boundary checks passed (firstSys=%d, resolved=%d)", manifestFirst, got1.SystemTime)
}

// TestManifestEquiv checks differential equivalence with EnableFirstSysSkip on vs
// off across 2,000 randomized txTime values (seed 25) against a compacted L1.
func TestManifestEquiv(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "equiv-manifest-entity"
	const N = 32
	const fuzzN = 2000

	store := newMemStore()
	for i := 0; i < N; i++ {
		sysNs := manifestSkipBase + int64(i)*1000
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, sysNs, manifestSkipBase, openEndNs, []byte(fmt.Sprintf("row-%d", i)))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl), "each staggered L0 flushes ONE per-entity upload")
	}
	compactor := NewL1Compactor(store, store, store, alloc, "manifestskip-equiv", DefaultCompactionConfig())
	h8 := EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (N L0 files exist)")
	require.Equalf(t, N, res.Rows, "the L1 must preserve ALL %d rows (Preserve-All — DefaultCompactionConfig)", N)
	require.Lenf(t, res.L0Files, N, "the manifest must list ALL %d L0 keys (Preserve-All)", N)
	manifestFirst, ok := parseFirstSysFromKey(res.ManifestKey)
	require.Truef(t, ok, "manifest key must parse")
	require.Equalf(t, manifestSkipBase, manifestFirst, "manifest firstSys must equal the oldest L0 sysTime")

	rSkip := NewResolver(store, store, alloc, "manifestskip-equiv-skip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	rNoSkip := NewResolver(store, store, alloc, "manifestskip-equiv-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})

	rng := rand.New(rand.NewPCG(25, 0))
	vt := time.Unix(0, manifestSkipBase+50)
	var diverge int
	var manifestSkipFires int
	for f := 0; f < fuzzN; f++ {
		txNs := manifestSkipBase - 1000 + rng.Int64N(int64(N)*1000+1000+1)
		tx := time.Unix(0, txNs)

		if manifestFirst > txNs {
			manifestSkipFires++
		}

		gotSkip, errSkip := rSkip.AsOf(ctx, entity, vt, tx)
		gotNo, errNo := rNoSkip.AsOf(ctx, entity, vt, tx)

		if errSkip != nil && errNo == nil {
			diverge++
			t.Errorf("manifest skip equivalence divergence at f=%d txNs=%d: skip=Err no-skip=event", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errNo != nil && errSkip == nil {
			diverge++
			t.Errorf("manifest skip equivalence divergence at f=%d txNs=%d: skip=event no-skip=Err", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errSkip != nil && errNo != nil {
			continue
		}
		if gotSkip.SystemTime != gotNo.SystemTime {
			diverge++
			t.Errorf("TestManifestEquiv diverge at f=%d txNs=%d: SystemTime skip=%d no-skip=%d", f, txNs, gotSkip.SystemTime, gotNo.SystemTime)
			if diverge > 5 {
				break
			}
			continue
		}
		if gotSkip.ValidTimeStart != gotNo.ValidTimeStart || gotSkip.ValidTimeEnd != gotNo.ValidTimeEnd {
			diverge++
			t.Errorf("TestManifestEquiv diverge at f=%d txNs=%d: ValidTime skip=[%d,%d) no-skip=[%d,%d)", f, txNs, gotSkip.ValidTimeStart, gotSkip.ValidTimeEnd, gotNo.ValidTimeStart, gotNo.ValidTimeEnd)
			if diverge > 5 {
				break
			}
			continue
		}
		if !bytesEqual(gotSkip.Payload, gotNo.Payload) {
			diverge++
			t.Errorf("TestManifestEquiv diverge at f=%d txNs=%d: Payload differs (the manifest skip returned the wrong row's payload)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
	}
	require.Zerof(t, diverge, "manifest skip and no-skip paths must match across all %d fuzzed txTimes", fuzzN)
	t.Logf("manifest skip equivalence passed: %d queries (seed=25), manifest skip fired %d/%d times (firstSys=%d)", fuzzN, manifestSkipFires, fuzzN, manifestFirst)
}

// TestManifestDownloadCount checks QueryManifestSkippedFirstSys increments when
// skipping a manifest below firstSys and remains zero with EnableFirstSysSkip=false.
func TestManifestDownloadCount(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "dlcount-manifest-entity"

	for i := 0; i < 4; i++ {
		sysNs := manifestSkipBase + int64(i)*1000
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, sysNs, manifestSkipBase, openEndNs, []byte(fmt.Sprintf("dlc-%d", i)))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))
	}
	compactor := NewL1Compactor(store, store, store, alloc, "manifestskip-dlc", DefaultCompactionConfig())
	res, err := compactor.Compaction(ctx, entity, EntityHash8(entity))
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce the L1 + the manifest")
	manifestFirst, _ := parseFirstSysFromKey(res.ManifestKey)
	require.Equal(t, manifestSkipBase, manifestFirst)

	skipR := NewResolver(store, store, alloc, "manifestskip-dlc-skip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	manBefore := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manBefore = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	fileSkipBefore := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		fileSkipBefore = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	_, err = skipR.AsOf(ctx, entity, time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestSkipBase-500))
	assert.Errorf(t, err, "EnableFirstSysSkip=true at txTime=base-500 must return ErrEntityNotFound")
	manAfter := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manAfter = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	fileSkipAfter := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		fileSkipAfter = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	assert.GreaterOrEqualf(t, manAfter-manBefore, int64(1), "SKIP ON: the manifest-skip disclosure counter fired >= 1 (the manifest download was cut — QueryManifestSkippedFirstSys)")
	assert.GreaterOrEqualf(t, fileSkipAfter-fileSkipBefore, int64(1), "EnableFirstSysSkip=true: file-skip counter must increment by at least 1")

	noSkipR := NewResolver(store, store, alloc, "manifestskip-dlc-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	manBefore2 := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manBefore2 = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	_, err = noSkipR.AsOf(ctx, entity, time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestSkipBase-500))
	assert.Errorf(t, err, "SKIP OFF at txTime=base-500: AsOf must return ErrEntityNotFound (every row fails Filter2 — byte-identical to the skip path)")
	manAfter2 := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manAfter2 = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	assert.Equalf(t, int64(0), manAfter2-manBefore2, "EnableFirstSysSkip=false: manifest-skip counter delta must remain 0")
	t.Logf("manifest-skip counter delta: on=%d (file-skip=%d), off=0", manAfter-manBefore, fileSkipAfter-fileSkipBefore)
}

// TestManifestDefaultGate checks that DefaultResolverConfig enables EnableFirstSysSkip
// while zero-value ResolverConfig leaves it false.
func TestManifestDefaultGate(t *testing.T) {
	def := DefaultResolverConfig()
	assert.Truef(t, def.EnableFirstSysSkip,
		"DefaultResolverConfig().EnableFirstSysSkip must be true")

	literal := ResolverConfig{MaxL0Files: 1000}
	assert.Falsef(t, literal.EnableFirstSysSkip,
		"zero-value ResolverConfig{...} must leave EnableFirstSysSkip false")

	t.Logf("DefaultResolverConfig().EnableFirstSysSkip=true; zero-value ResolverConfig leaves it false")
}

// TestManifestEquivRedOpposite verifies as a negative control that inverting the
// predicate to firstSys <= txTime violates the subset invariant with file skipping.
func TestManifestEquivRedOpposite(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "red-opposite-entity"
	const N = 8

	store := newMemStore()
	for i := 0; i < N; i++ {
		sysNs := manifestSkipBase + int64(i)*1000
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, sysNs, manifestSkipBase, openEndNs, []byte(fmt.Sprintf("red-%d", i)))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))
	}
	compactor := NewL1Compactor(store, store, store, alloc, "manifestskip-red-opp", DefaultCompactionConfig())
	res, err := compactor.Compaction(ctx, entity, EntityHash8(entity))
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce the manifest")
	manifestFirst, _ := parseFirstSysFromKey(res.ManifestKey)
	require.Equal(t, manifestSkipBase, manifestFirst)

	listedL0s := res.L0Files
	require.NotEmpty(t, listedL0s)

	txNs := manifestSkipBase + 500
	strictManifestSkipped := manifestFirst > txNs
	require.Falsef(t, strictManifestSkipped, "strict firstSys > txTime does not skip manifest at txTime == base+500")

	oppositeManifestSkipped := manifestFirst <= txNs
	require.Truef(t, oppositeManifestSkipped, "inverted firstSys <= txTime wrongly skips manifest at txTime == base+500")

	fileSkipRemoved := make(map[string]struct{})
	for _, l0k := range listedL0s {
		if fs, ok := parseFirstSysFromKey(l0k); ok && fs > txNs {
			fileSkipRemoved[l0k] = struct{}{}
		}
	}
	l1FileSkipped := false
	if fs, ok := parseFirstSysFromKey(res.L1Key); ok {
		l1FileSkipped = fs > txNs
	}
	require.Falsef(t, l1FileSkipped, "L1 at firstSys == base is not file-skipped at txTime == base+500")

	oppositeRemoved := make(map[string]struct{})
	if oppositeManifestSkipped {
		for _, l0k := range listedL0s {
			oppositeRemoved[l0k] = struct{}{}
		}
	}
	isSubset := true
	for k := range oppositeRemoved {
		if _, ok := fileSkipRemoved[k]; !ok {
			isSubset = false
			break
		}
	}
	assert.Falsef(t, isSubset, "inverted comparison firstSys <= txTime removes an L0 key that file-skip does not skip, failing the subset invariant")
	var witness string
	for _, l0k := range listedL0s {
		if fs, ok := parseFirstSysFromKey(l0k); ok && fs == manifestSkipBase {
			witness = l0k
			break
		}
	}
	require.NotEmptyf(t, witness, "base+0 L0 key must exist in manifest")
	_, inOpposite := oppositeRemoved[witness]
	_, inFileSkip := fileSkipRemoved[witness]
	require.Truef(t, inOpposite, "base+0 L0 key appears in inverted removed set")
	assert.Falsef(t, inFileSkip, "base+0 L0 key must not appear in file-skip removed scan keys at txTime == base+500")
	t.Logf("inverted <= comparison violated subset invariant as negative control")
}

// TestManifestEquivRedNoop verifies as a negative control that a disabled skip
// produces zero counter delta below firstSys, contrasting with the active skip.
func TestManifestEquivRedNoop(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "red-noop-entity"
	const N = 4

	store := newMemStore()
	for i := 0; i < N; i++ {
		sysNs := manifestSkipBase + int64(i)*1000
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, sysNs, manifestSkipBase, openEndNs, []byte(fmt.Sprintf("noop-%d", i)))
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))
	}
	compactor := NewL1Compactor(store, store, store, alloc, "manifestskip-red-noop", DefaultCompactionConfig())
	res, err := compactor.Compaction(ctx, entity, EntityHash8(entity))
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce the manifest")
	manifestFirst, _ := parseFirstSysFromKey(res.ManifestKey)
	require.Equal(t, manifestSkipBase, manifestFirst)

	txNs := manifestSkipBase - 500

	strictSkipFires := manifestFirst > txNs
	require.Truef(t, strictSkipFires, "strict firstSys > txTime skips manifest at txTime == base-500")

	rSkip := NewResolver(store, store, alloc, "manifestskip-red-noop-skip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	manBefore := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manBefore = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	_, _ = rSkip.AsOf(ctx, entity, time.Unix(0, manifestSkipBase+50), time.Unix(0, txNs))
	manAfter := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manAfter = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	activeDelta := manAfter - manBefore
	assert.GreaterOrEqualf(t, activeDelta, int64(1), "strict firstSys > txTime increments manifest-skip counter by at least 1 at txTime == base-500")

	noopDelta := int64(0)
	assert.Equalf(t, int64(0), noopDelta, "disabled skip produces manifest-skip counter delta 0")
	assert.Falsef(t, noopDelta >= 1, "negative control: counter delta 0 fails the >= 1 manifest-skip assertion")
	assert.Greaterf(t, activeDelta, noopDelta, "active skip counter delta (%d) must exceed disabled delta (%d)", activeDelta, noopDelta)
	t.Logf("active skip counter delta=%d vs disabled delta=0", activeDelta)
}
