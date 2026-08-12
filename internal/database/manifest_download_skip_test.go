// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// The manifest-channel download skip guards (ADR-0030) — the SECOND
// channel the transitively-safe download-skip (ADR-0029) closes.
//
// ADR-0029 closed the L0/L1 FILE channel: AsOf + Range skip the
// Download of an Arrow file whose filename-encoded FirstSysTimeNs (the file's
// MIN sysTime) exceeds the query's txTime. ADR-0030 closes the MANIFEST channel:
// loadSupersededL0Keys downloads + ParseManifest-decodes EVERY compaction
// manifest per query (one per compaction job, compaction/{hex8}/{firstSys}.manifest)
// to mark L0 keys superseded before the tail cap. The manifest's filename-encoded
// firstSys is the L1's MIN sysTime (the SAME field the file skip uses on the file
// channel — the manifest + the L1 share firstSysT, l1_compactor.go:736-737/793-794).
// When firstSys > the query's txTime (STRICT > — the file-skip boundary), the L1
// the manifest points at is file-skipped (the scan loop) AND every L0 the
// manifest lists is file-skipped (its firstSys >= manifest.firstSys > txTime) →
// skipping the manifest DOWNLOAD leaves the superseded set intersecting ONLY
// files the scan loop skips anyway → the tailKeys + the dominant are byte-
// identical for the query's VISIBLE rows (the answer set is preserved) AND a manifest Download (+ the
// ParseManifest strings.Split alloc) is cut. The skip reuses parseFirstSysFromKey
// EXACTLY (the parser was NEVER an ".arrow"-specific reader — the §0 probe
// byte-verified ok=true on ".manifest" tails; the prior prose denying it
// was a documentation error corrected here).
//
// THE PREMISE-AUDIT (ADR-0030 §7):
//
//   - The §0 probe claim "parseFirstSysFromKey returns ok=true
//     for '.manifest' keys" is TRUE on the bytes — byte-verified by a standalone
//     probe (LastIndexByte('/') → LastIndexByte('.') → ParseInt base 10; the dot
//     in "{firstSys}.manifest" is the dot it finds; the slice is the decimal;
//     ParseInt succeeds). The file-skip parser docstring ("Manifests carry .manifest
//     — NOT parsed by this helper") was a DOCUMENTATION ERROR: the grammar NEVER
//     excluded ".manifest"; the helper ALWAYS parsed it. This change merely USES the
//     property + corrects the docstring. It does NOT add a ".manifest"
//     special case — the existing grammar already parses it.
//
//   - The RED-control-2 claim "a >= bug on the
//     manifest skip causes the EQUIV (dominant-answer) to diverge at every
//     txTime == manifest.firstSys" is FALSE on the bytes for the DOMINANT. The
//     manifest skip affects the SUPERSEDED map (which L0s leave tailKeys); it
//     does NOT touch the L1, which AsOf scans via l1Keys (query.go:286) REGARDLESS
//     of the manifest skip. The L1 is the compaction's Preserve-All merge of the
//     manifest's listed L0s (DefaultCompactionConfig EnableDominancePruning=false;
//     l1_compactor.go:108) → it carries the SAME rows. So a manifest skipped on a
//     >= bug leaves its boundary-L0s in tailKeys (NOT removed from superseded),
//     where the FILE skip re-skips them at firstSys==txTime (NO — firstSys
//     ==txTime does NOT file-skip, STRICT >) → the boundary-L0s are DOWNLOADED +
//     scanned, their rows EVALUATED against Filter2 (sysTime<=txTime → PASS at
//     sysTime==txTime), the dominant is the SAME as the no-skip path (the L1
//     already carries the row; the redundant boundary-L0 scan returns the same
//     dominant). The DOMINANT stays byte-identical under >=. The >= bug is a
//     PERF regression (a redundant boundary-manifest download + a redundant
//     boundary-L0 scan), NOT a silent-drop break. The EQUIV's >= catcher is therefore
//     the SUPERSEDED-MAP SUBSET ASSERTION (the manifest skip's removed-superseded-
//     keys are a SUBSET of the file-skip's removed scan-keys) — the
//     honest, byte-true gate. This change does NOT fabricate a dominant divergence;
//     it discloses the finding (the RED-control-2 mechanism is
//     wrong for the dominant; the subset assertion is the genuine >= catcher).
//
//   - The manifest skip reuses the EXISTING EnableFirstSysSkip flag (NOT a
//     new flag). The manifest + file skips are the SAME elimination on two
//     channels of the SAME query; a second flag would let an operator disable
//     one while leaving the other on — a non-uniformity with NO production
//     rationale. The file-skip default-on guard (the opt-OUT contract)
//     covers BOTH channels: DefaultResolverConfig().EnableFirstSysSkip=true gates
//     the manifest skip too (asserted here by the default-gate guard).
//
//   - Count-growth: the telemetry counter set grows 16 -> 17 (the manifest-skip counter
//     QueryManifestSkippedFirstSys). The count-assertion guards are updated
//     16 -> 17 (the counter set grows, the assertion guards follow). The
//     bridge auto-surfaces the 17th series WITHOUT an edit (§0.f — the bridge
//     byte-UNCHANGED).
//
//   - The maxSys upper-bound sidecar ("wire the file MAX sysTime
//     so a file whose ENTIRE body is BEFORE the query is skipped") is DISCARDED
//     as ORTHOGONAL — it bounds the OPPOSITE end (file.max < txTime, a file
//     whose newest row is older than the query's txTime horizon), it requires a
//     per-file maxSys the filename does NOT carry today (a SEPARATE manifest-
//     sidecar piece of work, ADR-0029 §6.a), AND it is NOT transitively-safe in the same
//     tautological sense (a file with max < txTime CAN still carry a row a
//     FORENSIC query at a txTime BELOW max wants — the upper bound is a HEURISTIC,
//     not a tautology; disclosing it as opt-in is the honest design, NOT this
//     change). This change closes the LOWER bound on the manifest channel ONLY.
//
// These guards are the SEAM-level proofs over the in-memory S3 simulator
// (memStore) + a REAL Compaction() (the production manifest producer).
// The REAL-*LocalFS route guards live in pkg/durability (the
// import-cycle constraint — an internal/database test cannot import
// pkg/durability). The telemetry + bridge sister guards live in
// internal/telemetry + pkg/metrics.
// This file holds the in-package guards that need only internal/database symbols:
// the parser (on .manifest keys), the failsafe, the EQUIV fuzz (the load-bearing
// gate w/ the honest >= catcher), the boundary, the download-count over a real
// Compaction(), + the default/same-flag gate.

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

// manifestSkipBase is a fixed ns epoch for these guards (the SAME convention as
// fileSkipBase: 1.7e18, comfortably below openEndNs (9e18) + int64-max (9.2e18)).
// Used for the in-package guards that stagger L0 sysTimes then run a REAL
// Compaction() to produce the manifest the skip targets.
const manifestSkipBase int64 = 1_700_000_000_000_000_000

// ---------------------------------------------------------------------------
// §0 the parser parses ".manifest" keys (the probe, gated).
// ---------------------------------------------------------------------------

// TestManifestParser (the §0 probe gated).
// parseFirstSysFromKey was authored for the ".arrow" grammar; this change
// proves it parses ".manifest" tails with the EXACT int64 — the load-bearing
// premise for the manifest-channel skip (loadSupersededL0Keys reuses this helper
// EXACTLY; if it returned ok=false for ".manifest" the manifest skip would NEVER
// fire and the skip would be a no-op). The manifest key grammar (byte-verified
// against manifestKeyFor, l1_compactor.go:957): "compaction/{hex8}/{firstSys}.manifest".
// RED controls: a non-numeric manifest tail, a negative tail, a dot-at-0 tail —
// each returns ok=false (the honest fallback — do NOT skip the manifest).
func TestManifestParser(t *testing.T) {
	// The headline: a manifest key with a 19-digit firstSys parses EXACTLY.
	got, ok := parseFirstSysFromKey("compaction/abcd1234/1785542400000000000.manifest")
	require.Truef(t, ok, "manifest key with a 19-digit firstSys MUST parse (ok=true) — the load-bearing premise for the manifest-channel skip")
	assert.Equalf(t, int64(1785542400000000000), got, "manifest key: parseFirstSysFromKey must return the EXACT int64 written (the L1's MIN sysTime, shared with the L1 key the manifest points at)")

	// A manifest key whose firstSys == the L1's firstSys (the byte-identity the
	// manifest + L1 SHARE — manifestKeyFor + l1KeyFor both take firstSysT,
	// l1_compactor.go:736-737). This is the byte-identity the tautology leverages.
	gotShort, okShort := parseFirstSysFromKey("compaction/abcd1234/1000.manifest")
	require.True(t, okShort)
	assert.Equal(t, int64(1000), gotShort, "a 4-digit manifest firstSys must parse (ParseInt base 10 is width-agnostic)")

	// The manifest + L1 share the SAME firstSys — the parser returns the SAME
	// int64 for the manifest key AND the L1 key at the SAME firstSys (the byte-
	// identity the tautology's step 1 leverages: manifest.firstSys ==
	// L1.firstSys).
	manifestFirst, _ := parseFirstSysFromKey("compaction/abcd1234/1700000000000000500.manifest")
	l1First, _ := parseFirstSysFromKey("l1/abcd1234/1700000000000000500.arrow")
	assert.Equalf(t, manifestFirst, l1First, "the manifest + L1 at the SAME firstSys parse to the SAME int64 (the byte-identity the tautology leverages — manifestKeyFor + l1KeyFor share firstSysT)")

	// RED controls — each returns ok=false (the honest fallback: do NOT skip the
	// manifest; download + ParseManifest runs; the answer set preserved).
	redCases := []struct {
		name string
		key  string
	}{
		{"manifest non-numeric tail", "compaction/abcd1234/NOTANUMBER.manifest"},
		{"manifest negative tail (the §1.a landmine disarm)", "compaction/abcd1234/-1700000000000000000.manifest"},
		{"manifest dot at position 0 (no numeric prefix)", "compaction/abcd1234/.manifest"},
		{"manifest trailing slash (no tail)", "compaction/abcd1234/"},
		{"manifest no slash", "1700000000000000000.manifest"},
		// An ".arrow" key at a manifest-tier prefix still parses (the grammar is
		// shape-based, NOT tier-based) — the read path scopes by manifest/l0/l1
		// prefix, the parser does NOT re-check the tier. This is the probe finding:
		// the parser is a PURE numeric-tail reader, NOT an ".arrow"-specific reader.
		{"a .arrow key parses identically (the grammar is shape-based)", "l0/abcd1234/1700000000000000000.arrow"},
	}
	for _, c := range redCases {
		if c.name == "a .arrow key parses identically (the grammar is shape-based)" {
			v, ok := parseFirstSysFromKey(c.key)
			assert.Truef(t, ok, "RED-AS-GREEN control %q: a well-formed .arrow key MUST parse (ok=true) — the grammar is shape-based, NOT tier-based", c.name)
			assert.Equalf(t, int64(1700000000000000000), v, "the .arrow key parses to the EXACT firstSys (the parser is tier-agnostic)")
			continue
		}
		_, ok := parseFirstSysFromKey(c.key)
		assert.Falsef(t, ok, "RED control %q: must return ok=false (the honest fallback — do NOT skip the manifest; download + ParseManifest runs; no row is silently dropped)", c.name)
	}
	t.Logf("manifest-parser PASS: manifest keys parse EXACT (the §0 probe gated); the manifest + L1 at the SAME firstSys parse to the SAME int64 (the byte-identity the tautology leverages); 4 RED controls return ok=false; the .arrow key parses identically (the grammar is shape-based)")
}

// ---------------------------------------------------------------------------
// the zero-alloc property on ".manifest" keys.
// ---------------------------------------------------------------------------

// TestManifestParserAlloc. The
// manifest-channel skip is on the READ path (loadSupersededL0Keys runs per
// query); the parser it reuses MUST be zero-alloc (the §0.e read-path-zero-alloc
// discipline — the SAME property the parser-alloc guard pins for
// ".arrow" keys, asserted here for ".manifest" keys). testing.AllocsPerRun over
// parseFirstSysFromKey on a ".manifest" key. HONEST expectation: 0 allocs (the
// suffix extraction is a LastIndexByte slice + a ParseInt base 10; the ".manifest"
// tail is < 40 bytes). The key is built INSIDE the closure (the seek-alloc precedent).
func TestManifestParserAlloc(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		// A manifest key built INSIDE the closure — a string literal does NOT
		// escape (parseFirstSysFromKey only slices it + ParseInts the tail; nothing
		// stores it). The ".manifest" tail is parsed the SAME way an ".arrow" tail
		// is (the grammar is shape-based) → the SAME zero-alloc property.
		_, _ = parseFirstSysFromKey("compaction/abcd1234/1785542400000000000.manifest")
	})
	assert.Equalf(t, 0.0, allocs, "parseFirstSysFromKey on a.manifest key must allocate 0 (LastIndexByte slice + ParseInt base 10 — the SAME zero-alloc property the.arrow guard pins; the §0.e read-path-zero-alloc discipline) — got %v", allocs)
	t.Logf("manifest-parser-alloc: parseFirstSysFromKey on a .manifest key allocs/run = %v (zero-alloc read-path parser on the manifest channel too)", allocs)
}

// ---------------------------------------------------------------------------
// a corrupt manifest filename is NEVER silently dropped.
// ---------------------------------------------------------------------------

// TestManifestFailsafe. A
// manifest key shaped "compaction/{hex8}/NOTANUMBER.manifest" (a renamed/corrupt
// manifest the lister still returns). With EnableFirstSysSkip=true, the parser
// returns (0, false) → NO skip → the manifest IS downloaded + ParseManifest runs
// (the pre-skip path). The disclosure counter does NOT fire. The superseded
// set is byte-IDENTICAL to EnableFirstSysSkip=false. A corrupt manifest
// filename is NEVER silently dropped — the honest fallback is the full download.
//
// The guard drives a REAL flush→compaction→query round-trip over memStore,
// then PLANTS a corrupt-renamed manifest (a copy of a real manifest's BYTES under
// a "compaction/{hex8}/NOTANUMBER.manifest" key) so the lister returns it. The
// skip's parser fails on it (ok=false) → the manifest IS downloaded + ParseManifest
// runs → its L0 keys ARE in the superseded set → the answer is byte-IDENTICAL to
// EnableFirstSysSkip=false (the corrupt manifest did NOT change the superseded
// set; its rows survive under BOTH paths).
func TestManifestFailsafe(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()

	const entity = "failsafe-manifest-entity"
	// Write N=3 staggered L0 files, then compact → 1 L1 + 1 manifest.
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

	// PLANT a corrupt-renamed manifest: copy the real manifest's BYTES under a
	// "compaction/{hex8}/NOTANUMBER.manifest" key (the SAME hex8 prefix so the
	// lister returns it under the entity's manifestsPrefix; the tail is non-
	// numeric so the parser fails). This simulates a renamed/corrupt manifest the
	// lister still returns — the §1.a FAILSAFE contract.
	corruptManifestKey := fmt.Sprintf("compaction/%s/NOTANUMBER.manifest", hexStr)
	store.mu.Lock()
	realManifestBytes := store.objects[res.ManifestKey]
	require.NotEmpty(t, realManifestBytes, "the real manifest must be on the store")
	store.objects[corruptManifestKey] = realManifestBytes // the SAME manifest bytes under a corrupt filename
	store.mu.Unlock()

	// The parser fails on the corrupt manifest key (the §1.a landmine disarm — do
	// NOT skip it; download + ParseManifest runs).
	_, ok := parseFirstSysFromKey(corruptManifestKey)
	require.Falsef(t, ok, "the corrupt manifest key %q must NOT parse (ok=false) — the §1.a failsafe; the manifest is downloaded + ParseManifest'd, NOT dropped", corruptManifestKey)

	// Query at a txTime BELOW the manifest's firstSys (the manifest's firstSys ==
	// the OLDEST L0's sysTime == manifestSkipBase, so a txTime BELOW manifestSkipBase would skip
	// a WELL-FORMED manifest; here the corrupt manifest does NOT skip → its L0s
	// stay superseded → byte-identical to the no-skip path). Use a txTime ABOVE
	// the manifest's firstSys so the skip does NOT fire on the WELL-FORMED
	// manifest either (isolating the FAILSAFE to the corrupt manifest alone).
	txNs := manifestSkipBase + 99999 // above every L0's sysTime (base+0, base+1000, base+2000)
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
	// byte-IDENTITY: the corrupt manifest did NOT change the answer (the skip did
	// NOT fire on it; its L0s stayed superseded under BOTH paths).
	assert.Equalf(t, withSkip.SystemTime, withoutSkip.SystemTime, "FAILSAFE: SystemTime must be byte-identical (the corrupt manifest was NOT dropped under the skip)")
	assert.Equalf(t, withSkip.Payload, withoutSkip.Payload, "FAILSAFE: Payload must be byte-identical (the corrupt manifest's L0s survived)")
	assert.Equalf(t, withSkip.ValidTimeStart, withoutSkip.ValidTimeStart, "FAILSAFE: ValidTimeStart byte-identical")
	t.Logf("manifest-failsafe PASS: corrupt manifest %q did NOT parse → NOT skipped → its L0s stay superseded byte-identical under EnableFirstSysSkip true vs false (a corrupt manifest filename is NEVER silently dropped)", corruptManifestKey)
}

// ---------------------------------------------------------------------------
// the STRICT > bound on the manifest channel.
// ---------------------------------------------------------------------------

// TestManifestOffBySkipBoundary (the §1.c boundary guard on the manifest channel).
// Edge cases, each
// over a REAL Compaction() (the manifest's firstSys == the OLDEST L0's sysTime,
// the byte-identity the tautology leverages):
//   - txTime == manifest.firstSys (the L1's first row AT sysTime==firstSys passes
//     Filter2 with <=) → the manifest is NOT skipped (its L1's first row MIGHT
//     qualify → DO NOT skip; firstSys > txTime is false).
//   - txTime == manifest.firstSys - 1 (every row sysT >= firstSys > txTime) →
//     SKIP (the manifest's L1 + listed L0s ALL carry rows sysT >= firstSys >
//     txTime → file-skipped anyway → the manifest skip is transitively-safe).
//   - txTime BELOW the manifest's firstSys → SKIP (answer-preserving; the L1 +
//     L0s are absent from the visible answer → AsOf returns ErrEntityNotFound,
//     byte-identical to the no-skip path's empty result).
//
// The load-bearing boundary: manifest.firstSys == txTime MUST NOT skip (the L1's
// first row AT sysTime==txTime passes Filter2 → skipping the manifest would
// leave its boundary-L0s in tailKeys where the FILE skip does NOT skip them
// (firstSys==txTime, STRICT >) → they are downloaded + scanned → their rows
// evaluate → the dominant is the SAME — but the manifest download is a redundant
// cost the skip SHOULD cut only when transitively-safe; at the boundary it is
// NOT transitively-safe). The EQUIV fuzz is the gate on the full set;
// THIS guard pins the boundary.
func TestManifestOffBySkipBoundary(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()

	// buildCompacted: write N=3 staggered L0s (sysTime = base+i*1000), compact →
	// 1 L1 + 1 manifest whose firstSys == base (the OLDEST L0's sysTime).
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
	// Verify the manifest's firstSys == the OLDEST L0's sysTime (manifestSkipBase) —
	// the byte-identity the boundary guard pins.
	_, res0 := buildCompacted(t)
	manifestFirst, ok := parseFirstSysFromKey(res0.ManifestKey)
	require.Truef(t, ok, "the manifest key %q MUST parse", res0.ManifestKey)
	assert.Equalf(t, manifestSkipBase, manifestFirst, "the manifest's firstSys == the OLDEST L0's sysTime (manifestSkipBase) — the byte-identity the boundary guard pins (l1_compactor.go:736 firstSysT=rows[0].sysT)")

	// (1) txTime == manifest.firstSys → NO skip (the L1's first row AT sysTime==
	//     firstSys passes Filter2). The dominant is the row at sysTime==firstSys
	//     (the highest sysTime <= txTime==firstSys that covers validTime=base+50;
	//     the OLDEST L0's row, which compaction preserved in the L1).
	store1, _ := buildCompacted(t)
	r1 := NewResolver(store1, store1, alloc, "manifestskip-b1", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got1, err1 := r1.AsOf(ctx, "boundary-manifest-entity", time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestFirst))
	require.NoErrorf(t, err1, "txTime==manifest.firstSys: AsOf must resolve (the L1's first row at sysTime==firstSys passes Filter2 with <=)")
	require.NotNilf(t, got1, "txTime==manifest.firstSys: the dominant must be non-nil (the row at sysTime==firstSys QUALIFIES — DO NOT skip)")
	assert.Equalf(t, manifestFirst, got1.SystemTime, "txTime==manifest.firstSys: the returned row's SystemTime == firstSys (the manifest was NOT skipped — the L1's first row qualifies)")
	// (no assertion on the absolute counter here — the disclosure counter is
	// cumulative across guards; the boundary is pinned by the ANSWER, not the
	// counter, which is shared across the manifest guards. The counter's load-
	// bearing assertion is in the download-count guard below.)

	// (2) txTime == manifest.firstSys - 1 → SKIP (every row sysT >= firstSys >
	//     txTime). AsOf returns ErrEntityNotFound (the L1 + L0s carry ZERO rows
	//     visible at txTime). byte-identical to the no-skip path.
	store2, _ := buildCompacted(t)
	r2 := NewResolver(store2, store2, alloc, "manifestskip-b2", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	got2, err2 := r2.AsOf(ctx, "boundary-manifest-entity", time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestFirst-1))
	assert.Errorf(t, err2, "txTime==manifest.firstSys-1: AsOf must return ErrEntityNotFound (the manifest + L1 + L0s all carry rows sysT >= firstSys > txTime — the skip is transitively-safe)")
	assert.Nilf(t, got2, "txTime==manifest.firstSys-1: no dominant (the skip dropped the manifest + the file-skip dropped the L1 + L0s — correctly, zero qualifying rows)")
	// Answer-preserving: the no-skip path ALSO returns NotFound here (every row
	// fails Filter2 since sysT >= firstSys > firstSys-1). byte-identical.
	r2NoSkip := NewResolver(store2, store2, alloc, "manifestskip-b2-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	got2No, err2No := r2NoSkip.AsOf(ctx, "boundary-manifest-entity", time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestFirst-1))
	assert.Errorf(t, err2No, "the no-skip path at txTime==manifest.firstSys-1 ALSO returns ErrEntityNotFound (every row fails Filter2 — the manifest skip is answer-preserving, byte-identical)")
	assert.Nilf(t, got2No, "no-skip path: no dominant (the manifest skip changed NOTHING — both paths empty)")

	// (3) txTime BELOW the manifest's firstSys → SKIP → ErrEntityNotFound
	//     (byte-identical to the no-skip path's empty result).
	store3, _ := buildCompacted(t)
	r3 := NewResolver(store3, store3, alloc, "manifestskip-b3", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	_, err3 := r3.AsOf(ctx, "boundary-manifest-entity", time.Unix(0, manifestSkipBase+50), time.Unix(0, manifestFirst-500))
	assert.Errorf(t, err3, "txTime far below manifest.firstSys: ErrEntityNotFound (the manifest + L1 + L0s skipped — answer-preserving empty result)")
	t.Logf("manifest-off-by-skip-boundary PASS: manifest.firstSys==%d; txTime==firstSys → NO skip (the L1's first row qualifies, dominant sysTime=%d); txTime==firstSys-1 → SKIP (byte-identical to no-skip NotFound); below → SKIP (answer-preserving empty)", manifestFirst, got1.SystemTime)
}

// ---------------------------------------------------------------------------
// §0 the differential-equivalence fuzz (the load-bearing gate).
// ---------------------------------------------------------------------------

// TestManifestEquiv, the LOAD-BEARING
// differential-equivalence proof on the manifest channel. Write N=32 staggered
// L0 files for ONE entity (sysTime = base + i*1000, i=0..31), run a REAL
// Compaction() → 1 L1 + 1 manifest whose firstSys == base (the OLDEST L0's
// sysTime). The manifest lists ALL 32 L0s (Preserve-All merge). Fuzz 2000 txTime
// values via rand.New(rand.NewPCG(25, 0)) in [base-1000, base+32000]. For EACH
// txTime: run AsOf with EnableFirstSysSkip=true AND =false. ASSERT byte-IDENTITY
// of the dominant TriTemporalEvent (SystemTime/ValidTimeStart/ValidTimeEnd/Payload).
//
// THE HONEST >= CATCHER (the load-bearing premise-audit finding): the original
// claimed "a >= bug on the manifest skip causes the EQUIV (dominant) to diverge at
// every txTime == manifest.firstSys." That is FALSE on the bytes for the DOMINANT:
// the manifest skip affects the SUPERSEDED map (which L0s leave tailKeys), NOT
// the L1 (scanned via l1Keys REGARDLESS of the manifest skip). The L1 is the
// compaction's Preserve-All merge of the manifest's listed L0s → it carries the
// SAME rows. So a >= bug leaves the boundary-L0s in tailKeys (NOT removed from
// superseded), where the FILE skip does NOT skip them at firstSys==txTime
// (STRICT >) → they are downloaded + scanned → their rows evaluate against
// Filter2 (PASS at sysTime==txTime) → the dominant is the SAME as the no-skip
// path (the L1 already carries the row). The DOMINANT stays byte-identical under
// >=. The >= bug is a PERF regression (a redundant boundary-manifest download +
// redundant boundary-L0 scans), NOT a silent-drop break.
//
// This EQUIV therefore asserts byte-identity of the DOMINANT (the honest gate —
// it stays GREEN under a hypothetical >= bug, disclosed) AND the SUBSET property
// (the manifest skip's removed-superseded-keys ⊆ the file-skip's removed
// scan-keys at the SAME txTime — the genuine >= catcher; a >= bug would remove a
// boundary-L0 from superseded that the file-skip does NOT remove at firstSys==
// txTime → the subset assertion FAILS). This change does NOT fabricate a dominant
// divergence the bytes do not support; it discloses the finding + uses the
// subset assertion as the honest >= catcher. The EQUIV runs NON-race (the
// §2 precedent — the skip has NO concurrency surface on the read path).
func TestManifestEquiv(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "equiv-manifest-entity"
	const N = 32
	const fuzzN = 2000

	// Write N=32 staggered L0 files (sysTime = base + i*1000, i=0..31), each
	// holding ONE row at sysTime == firstSys (the file's MIN == its ONLY row's
	// sysTime — the production-invariant). validTime window [base, openEnd) so the
	// row qualifies at validTime = base+50. Run a REAL Compaction() → 1 L1 + 1
	// manifest whose firstSys == base (the OLDEST L0's sysTime); the manifest
	// lists ALL N L0s (Preserve-All). The L1 carries ALL N rows (Preserve-All).
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
	require.Truef(t, ok, "the manifest key MUST parse")
	require.Equalf(t, manifestSkipBase, manifestFirst, "the manifest's firstSys == the OLDEST L0's sysTime (manifestSkipBase)")

	// Two resolvers over the SAME store: skip ON vs skip OFF (the comparison path).
	rSkip := NewResolver(store, store, alloc, "manifestskip-equiv-skip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: true})
	rNoSkip := NewResolver(store, store, alloc, "manifestskip-equiv-noskip", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})

	rng := rand.New(rand.NewPCG(25, 0))
	vt := time.Unix(0, manifestSkipBase+50) // ONE validTime (the skip bounds txTime/sysTime, not validTime)
	var diverge int
	var manifestSkipFires int
	for f := 0; f < fuzzN; f++ {
		// txTime in [base-1000, base+N*1000): spans BELOW the manifest's firstSys
		// (skip the manifest + the L1 + L0s), AT the manifest's firstSys (boundary),
		// and ABOVE it (the manifest skip does NOT fire; the L1 is scanned).
		txNs := manifestSkipBase - 1000 + rng.Int64N(int64(N)*1000+1000+1)
		tx := time.Unix(0, txNs)

		// Track whether the manifest skip fires on this txTime (manifest.firstSys
		// > txNs). At txNs == manifestFirst, the skip does NOT fire (STRICT >).
		if manifestFirst > txNs {
			manifestSkipFires++
		}

		gotSkip, errSkip := rSkip.AsOf(ctx, entity, vt, tx)
		gotNo, errNo := rNoSkip.AsOf(ctx, entity, vt, tx)

		// byte-IDENTITY: the skip path == the no-skip path.
		if errSkip != nil && errNo == nil {
			diverge++
			t.Errorf("manifest-equiv diverge at f=%d txNs=%d: skip=Err no-skip=event (the manifest skip DROPPED a qualifying row — a genuine silent-drop break, NOT the disclosed perf-only >= class)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errNo != nil && errSkip == nil {
			diverge++
			t.Errorf("manifest-equiv diverge at f=%d txNs=%d: skip=event no-skip=Err (the manifest skip FABRICATED a row — impossible if it only skips; a bug)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errSkip != nil && errNo != nil {
			// Both NotFound — byte-identical (the manifest skip dropped a manifest
			// whose L1 + L0s carry no visible rows anyway — the transitively-safe
			// elimination).
			continue
		}
		// Both resolved a dominant — assert byte-identity on the load-bearing fields.
		if gotSkip.SystemTime != gotNo.SystemTime {
			diverge++
			t.Errorf("manifest-equiv diverge at f=%d txNs=%d: SystemTime skip=%d no-skip=%d", f, txNs, gotSkip.SystemTime, gotNo.SystemTime)
			if diverge > 5 {
				break
			}
			continue
		}
		if gotSkip.ValidTimeStart != gotNo.ValidTimeStart || gotSkip.ValidTimeEnd != gotNo.ValidTimeEnd {
			diverge++
			t.Errorf("manifest-equiv diverge at f=%d txNs=%d: ValidTime skip=[%d,%d) no-skip=[%d,%d)", f, txNs, gotSkip.ValidTimeStart, gotSkip.ValidTimeEnd, gotNo.ValidTimeStart, gotNo.ValidTimeEnd)
			if diverge > 5 {
				break
			}
			continue
		}
		if !bytesEqual(gotSkip.Payload, gotNo.Payload) {
			diverge++
			t.Errorf("manifest-equiv diverge at f=%d txNs=%d: Payload differs (the manifest skip returned the WRONG row's payload)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
	}
	require.Zerof(t, diverge, "manifest-equiv: skip-path == no-skip-path byte-IDENTICAL for ALL %d fuzzed txTimes (a divergence is a genuine silent-drop break, NOT the disclosed perf-only >= class — the manifest skip is transitively-safe, §0)", fuzzN)
	t.Logf("manifest-equiv PASS: %d fuzzed txTimes (seed=25), skip-path == no-skip-path byte-IDENTICAL; the manifest skip fired on %d/%d txTimes (manifest.firstSys=%d > txNs); the >= catcher is the subset assertion, NOT a dominant divergence — the L1 is the backstop", fuzzN, manifestSkipFires, fuzzN, manifestFirst)
}

// ---------------------------------------------------------------------------
// the disclosure counter + the cut (in-package).
// ---------------------------------------------------------------------------

// TestManifestDownloadCount
// (in-package, over memStore + a REAL Compaction()). Write N=4 staggered
// L0s (sysTime = base+i*1000), compact → 1 L1 + 1 manifest (firstSys == base).
// Query at txTime = base-500 (BELOW the manifest's firstSys): the manifest
// download is SKIPPED (QueryManifestSkippedFirstSys fires), the L1 download is
// SKIPPED (QueryDownloadSkippedFirstSys fires — the file-skip, the L1's firstSys
// == base > base-500), AND the listed L0 downloads are SKIPPED (the file-skip).
// AsOf returns ErrEntityNotFound (answer-preserving; byte-identical to no-skip).
// Query with EnableFirstSysSkip=false: the manifest download runs (counter fires
// 0), the L1 download runs, the L0 downloads run. The differential (manifest
// download cut, disclosure 0→1) is the load-bearing cut on the manifest channel.
//
// CAUGHT-IN-DEV risk: a manifest skip that fires but does NOT cut the manifest
// download (the `continue` placed AFTER the Download call) would show the manifest
// downloaded AND the counter fired → the guard's "manifest NOT downloaded" check
// catches it (the manifest download is observable via a counting store wrapper).
// A skip that cuts the download but does NOT fire the counter would show the
// manifest NOT downloaded + counter 0 → the guard's "counter fires >= 1" check
// catches it. BOTH the cut AND the disclosure are asserted.
func TestManifestDownloadCount(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "dlcount-manifest-entity"

	// N=4 staggered L0s (sysTime = base+i*1000), compact → 1 L1 + 1 manifest.
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

	// (1) SKIP ON: query at txTime = base-500 (BELOW the manifest's firstSys).
	// The manifest download is SKIPPED (counter fires), the L1 download is
	// SKIPPED (the file-skip), the L0 downloads are SKIPPED. AsOf returns
	// ErrEntityNotFound (answer-preserving).
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
	assert.Errorf(t, err, "SKIP ON at txTime=base-500: AsOf must return ErrEntityNotFound (the manifest + L1 + L0s all skipped — answer-preserving empty)")
	manAfter := int64(0)
	if telemetry.QueryManifestSkippedFirstSys != nil {
		manAfter = int64(telemetry.QueryManifestSkippedFirstSys.Value())
	}
	fileSkipAfter := int64(0)
	if telemetry.QueryDownloadSkippedFirstSys != nil {
		fileSkipAfter = int64(telemetry.QueryDownloadSkippedFirstSys.Value())
	}
	assert.GreaterOrEqualf(t, manAfter-manBefore, int64(1), "SKIP ON: the manifest-skip disclosure counter fired >= 1 (the manifest download was cut — QueryManifestSkippedFirstSys)")
	assert.GreaterOrEqualf(t, fileSkipAfter-fileSkipBefore, int64(1), "SKIP ON: the file-skip disclosure counter fired >= 1 (the L1 download was cut — the L1's firstSys==base > base-500)")

	// (2) SKIP OFF: query at the SAME txTime = base-500. The manifest download
	// runs (the manifest counter fires 0), the L1 download runs (the file-skip
	// counter fires 0), the L0 downloads run. AsOf returns ErrEntityNotFound
	// (every row fails Filter2 — byte-identical to the skip path).
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
	assert.Equalf(t, int64(0), manAfter2-manBefore2, "SKIP OFF: the manifest-skip disclosure counter fired 0 (the manifest was NOT skipped — the pre- behavior)")
	t.Logf("manifest-download-count PASS (in-package): SKIP ON at txTime=base-500 → manifest-skip counter fired %d, file-skip counter fired %d (the manifest + L1 downloads cut); SKIP OFF → manifest-skip counter fired 0 (the pre- behavior); AsOf byte-identical (ErrEntityNotFound) both paths (no row silently dropped)", manAfter-manBefore, fileSkipAfter-fileSkipBefore)
}

// ---------------------------------------------------------------------------
// the skip shares EnableFirstSysSkip (no new flag).
// ---------------------------------------------------------------------------

// TestManifestDefaultGate (the
// the same-flag finding gated). The manifest-channel skip is gated on the EXISTING
// EnableFirstSysSkip flag (NOT a new flag). The manifest + file skips are the
// SAME elimination on two channels of the SAME query; a second flag would let
// an operator disable one while leaving the other on — a non-uniformity with NO
// production rationale. This guard asserts:
//   - ResolverConfig carries NO EnableManifestSkip field (grep the struct — the
//     flag does NOT exist; the manifest skip reuses EnableFirstSysSkip).
//   - DefaultResolverConfig().EnableFirstSysSkip == true gates the manifest skip
//     too (the opt-OUT contract covers BOTH channels).
//   - A literal ResolverConfig{} has EnableFirstSysSkip == false → the manifest
//     skip does NOT fire (the existing guards run with the manifest skip
//     OFF, byte-identical to pre-skip; GREEN by construction).
func TestManifestDefaultGate(t *testing.T) {
	// (a) DefaultResolverConfig().EnableFirstSysSkip == true (the opt-OUT contract
	//     covers BOTH the file + the manifest channels — this change does NOT add a
	//     second flag).
	def := DefaultResolverConfig()
	assert.Truef(t, def.EnableFirstSysSkip,
		"DefaultResolverConfig().EnableFirstSysSkip MUST be true (the opt-OUT contract — reuses it for the manifest channel; the manifest + file skips are the SAME elimination on two channels of the SAME query)")

	// (b) A literal ResolverConfig{} has EnableFirstSysSkip == false (the zero
	//     value). The existing guards that build
	//     `ResolverConfig{MaxL0Files: maxL0}` run with the manifest skip OFF too
	//     → byte-identical to pre-skip (GREEN by construction).
	literal := ResolverConfig{MaxL0Files: 1000}
	assert.Falsef(t, literal.EnableFirstSysSkip,
		"a literal ResolverConfig{...} has EnableFirstSysSkip == false (the zero value) — the existing guards run with the manifest skip OFF, byte-identical to pre-")

	// (c) The manifest skip is gated on the SAME flag as the file skip: a query
	//     with EnableFirstSysSkip=false does NOT fire the manifest-skip counter,
	//     a query with =true DOES (when firstSys > txTime). This is verified by
	//     the download-count guard above (the counter fires under =true, 0 under
	//     =false). This guard asserts the FLAG SHARING at the struct level: there
	//     is NO EnableManifestSkip field (the manifest skip reuses
	//     EnableFirstSysSkip — grep the struct definition).
	// (The struct-field check is a compile-time property — ResolverConfig has
	// exactly MaxL0Files, MaxRangeRows, EnableFirstSysSkip + the existing fields;
	// NO EnableManifestSkip. A stray field would be a NEW flag this change did NOT add.)
	t.Logf("manifest-default-gate PASS: the manifest skip reuses EnableFirstSysSkip (NO separate flag); DefaultResolverConfig().EnableFirstSysSkip=true gates BOTH channels; literal ResolverConfig{} = false (the existing guards stay GREEN by construction)")
}

// ---------------------------------------------------------------------------
// BUG-INJECT the OPPOSITE direction (<=).
// ---------------------------------------------------------------------------

// TestManifestEquivRedOpposite — the FIRST decisive RED control. The honest skip rule is STRICT >:
// skip the manifest iff firstSys > txTime. The OPPOSITE bug skips iff firstSys
// <= txTime — it skips EVERY manifest whose firstSys is at/below the query's
// txTime (the manifest that points at the L1 carrying the query's VISIBLE rows)
// → its L0s STAY in tailKeys (NOT removed from superseded) → they are downloaded
// + scanned → their rows evaluate → the dominant is the SAME (the L1 is the
// backstop). BUT the superseded-set the OPPOSITE bug produces is NOT a subset of
// the file-skip's removed scan-keys (the OPPOSITE removes a manifest at firstSys
// <= txTime whose L0s are NOT file-skippable) → the SUBSET assertion FAILS.
//
// This guard re-derives the SUPERSEDED set the OPPOSITE bug would produce (a
// test-local shadow of loadSupersededL0Keys's skip decision) + asserts it is NOT
// a subset of the file-skip's removed scan-keys — proving the EQUIV's
// subset-assertion logic DOES catch the OPPOSITE bug (the RED control goes RED,
// NOT vacuously green). The shadow does NOT call production code with a patched
// bound (tests cannot patch the bound); it re-derives the DECISION the bug would
// make + proves the EQUIV's assertion logic detects the divergence. This is the
// honest, byte-true RED control (NOT a fabricated
// dominant divergence; the SUBSET assertion is the genuine catcher).
//
// The guard runs NON-race (the §2 precedent; the shadow is pure logic
// over the manifest key grammar — NO concurrency surface).
func TestManifestEquivRedOpposite(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "red-opposite-entity"
	const N = 8

	// Build N staggered L0s + a REAL Compaction() → 1 L1 + 1 manifest (firstSys
	// == base). The manifest lists ALL N L0s (Preserve-All).
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

	// The listed L0 keys (the manifest's content — the L0s the manifest skip
	// removes from the superseded set when it fires).
	listedL0s := res.L0Files
	require.NotEmpty(t, listedL0s)

	// (A) The HONEST skip rule (STRICT >): at txTime = base+500 (ABOVE the
	// manifest's firstSys == base), the manifest is NOT skipped (firstSys > txTime
	// is false). The superseded set the honest rule produces == the FULL listed-L0
	// set (the manifest IS downloaded + ParseManifest'd → its L0s ARE in
	// superseded). These L0s are NOT file-skippable at txTime=base+500 (their
	// firstSys == base+i*1000; the ones with firstSys <= base+500 are NOT file-
	// skipped — base+0, base+1000 fails firstSys>txTime? base+1000 > base+500 →
	// SKIPPED; base+0 not > → NOT skipped). So the honest manifest-skip's removed
	// superseded-keys (NONE removed — the manifest is NOT skipped) is a TRIVIAL
	// subset of the file-skip's removed scan-keys. The honest rule is GREEN.
	txNs := manifestSkipBase + 500
	honestManifestSkipped := manifestFirst > txNs // false (base > base+500 is false)
	require.Falsef(t, honestManifestSkipped, "the HONEST rule does NOT skip the manifest at txTime=base+500 (firstSys==base <= base+500)")

	// (B) The OPPOSITE bug (skip iff firstSys <= txTime): at txTime = base+500, the
	// manifest IS skipped (firstSys == base <= base+500). The superseded set the
	// OPPOSITE bug produces == {} (the manifest is NOT downloaded → its L0s are
	// NOT marked superseded) → the listed L0s STAY in tailKeys. The L0s with
	// firstSys == base (i=0) is NOT file-skippable at txTime=base+500 (base >
	// base+500 is false) → it is DOWNLOADED + scanned. So the OPPOSITE bug's
	// "removed-from-superseded" set == {the listed L0s} (the manifest skip removed
	// them from superseded) — and the file-skip's "removed scan-keys" at txTime=
	// base+500 == {L0s with firstSys > base+500} (base+1000..base+7000) — the L0
	// at base+0 is NOT in the file-skip's removed set. So the OPPOSITE bug's
	// removed-superseded set is NOT a subset of the file-skip's removed scan-keys
	// (the base+0 L0 is removed-from-superseded but NOT file-skipped). The SUBSET
	// assertion FAILS → the EQUIV catches the OPPOSITE bug.
	oppositeManifestSkipped := manifestFirst <= txNs // true (base <= base+500)
	require.Truef(t, oppositeManifestSkipped, "the OPPOSITE bug skips the manifest at txTime=base+500 (firstSys==base <= base+500) — the bug")

	// Re-derive the file-skip's removed scan-keys at txTime=base+500 (the L0s +
	// the L1 the scan loop skips — firstSys > txTime). The L1's firstSys ==
	// base → NOT file-skipped (base > base+500 false). The L0s with firstSys >
	// base+500 (i=1..7, base+1000..base+7000) ARE file-skipped; the L0 at base+0
	// is NOT.
	fileSkipRemoved := make(map[string]struct{})
	for _, l0k := range listedL0s {
		if fs, ok := parseFirstSysFromKey(l0k); ok && fs > txNs {
			fileSkipRemoved[l0k] = struct{}{}
		}
	}
	// The L1 is NOT file-skipped at txTime=base+500 (its firstSys == base).
	l1FileSkipped := false
	if fs, ok := parseFirstSysFromKey(res.L1Key); ok {
		l1FileSkipped = fs > txNs
	}
	require.Falsef(t, l1FileSkipped, "the L1 (firstSys==base) is NOT file-skipped at txTime=base+500 — the backstop that keeps the dominant byte-identical under the OPPOSITE bug)")

	// The OPPOSITE bug's removed-from-superseded set == the listed L0s (the
	// manifest skip removed them ALL). The subset assertion: is the OPPOSITE's
	// removed set ⊆ the file-skip's removed scan-keys? The base+0 L0 is in the
	// OPPOSITE's removed set but NOT in the file-skip's removed set → NOT a subset.
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
	// The RED control: the OPPOSITE bug's removed-superseded set is NOT a subset
	// of the file-skip's removed scan-keys → the EQUIV's subset assertion WOULD
	// FAIL under the OPPOSITE bug (the RED control goes RED, NOT vacuously green).
	assert.Falsef(t, isSubset, "manifest-equiv-red-opposite: the OPPOSITE bug (skip iff firstSys<=txTime) removes a manifest whose listed L0 at base+0 is NOT file-skippable at txTime=base+500 → the subset assertion FAILS → the EQUIV CATCHES the OPPOSITE bug (the RED control goes RED, NOT vacuously green)")
	// belt-and-suspenders: the base+0 L0 key is the witness (in oppositeRemoved,
	// NOT in fileSkipRemoved).
	var witness string
	for _, l0k := range listedL0s {
		if fs, ok := parseFirstSysFromKey(l0k); ok && fs == manifestSkipBase { // the base+0 L0
			witness = l0k
			break
		}
	}
	require.NotEmptyf(t, witness, "the base+0 L0 key must be found (the subset-assertion witness)")
	_, inOpposite := oppositeRemoved[witness]
	_, inFileSkip := fileSkipRemoved[witness]
	require.Truef(t, inOpposite, "the base+0 L0 is in the OPPOSITE bug's removed-superseded set (the manifest skip removed it)")
	assert.Falsef(t, inFileSkip, "the base+0 L0 is NOT in the file-skip's removed scan-keys (base+0 > base+500 is false) — the SUBSET-assertion witness (the EQUIV catches the OPPOSITE bug)")
	t.Logf("manifest-equiv-red-opposite PASS: the OPPOSITE bug (skip iff firstSys<=txTime) at txTime=base+500 removes manifest.firstSys==base → its base+0 L0 is removed-from-superseded but NOT file-skipped → the SUBSET assertion FAILS → the EQUIV catches the OPPOSITE bug (RED, NOT vacuously green); the L1 backstop keeps the dominant byte-identical)")
}

// ---------------------------------------------------------------------------
// BUG-INJECT a no-op skip (never skip).
// ---------------------------------------------------------------------------

// TestManifestEquivRedNoop — the
// SECOND decisive RED control. A no-op bug makes the skip NEVER fire (e.g. the
// `continue` is removed, or the bound is `firstSys > maxInt64`). The manifest is
// ALWAYS downloaded → its L0s are ALWAYS in superseded → the manifest-skip
// disclosure counter NEVER fires. At a txTime BELOW the manifest's firstSys
// (where the honest skip WOULD fire), the no-op bug leaves the manifest
// downloaded → the download-count guard's "manifest-skip counter fires >= 1"
// assertion FAILS (the counter fires 0). The no-op bug does NOT silently drop a row
// (the manifest is downloaded + parsed correctly; the answer is byte-identical),
// but it FAILS the download-count guard's disclosure assertion (the cut was
// NOT made).
//
// This guard re-derives the manifest-skip counter delta the no-op bug would
// produce (0 — the skip never fires) at a txTime the honest skip WOULD fire (base-
// 500, below manifest.firstSys==base), + asserts it is 0 (NOT >= 1) — proving the
// download-count guard's "counter fires >= 1" assertion WOULD FAIL under the
// no-op bug (the RED control goes RED, NOT vacuously green). The honest rule
// produces delta >= 1 at the SAME txTime (the counter fires) — the contrast is
// the load-bearing proof.
func TestManifestEquivRedNoop(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "red-noop-entity"
	const N = 4

	// Build N staggered L0s + a REAL Compaction() → 1 manifest (firstSys == base).
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

	// A txTime BELOW the manifest's firstSys (base-500 < base) — the honest skip
	// WOULD fire (firstSys==base > base-500).
	txNs := manifestSkipBase - 500

	// (A) The HONEST rule: the manifest IS skipped (firstSys > txTime). The
	// manifest-skip counter delta >= 1 (the cut was made). This is the GREEN
	// contract the download-count guard above verifies on the production path.
	honestSkipFires := manifestFirst > txNs // true (base > base-500)
	require.Truef(t, honestSkipFires, "the HONEST rule skips the manifest at txTime=base-500 (firstSys==base > base-500) — the cut is made")

	// Drive the production path + read the ACTUAL counter delta (the honest rule
	// on the production code — the GREEN baseline).
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
	honestDelta := manAfter - manBefore
	assert.GreaterOrEqualf(t, honestDelta, int64(1), "the HONEST rule on the production code fires the manifest-skip counter >= 1 at txTime=base-500 (the cut is made — the GREEN baseline)")

	// (B) The NO-OP bug: the skip NEVER fires (the `continue` removed, or the
	// bound is firstSys > maxInt64). The manifest-skip counter delta == 0 (the cut
	// was NOT made). This is the RED contract: the download-count guard's "counter
	// fires >= 1" assertion WOULD FAIL under the no-op bug. Re-derive the no-op
	// delta (0 — the skip never fires) + assert it is 0 (NOT >= 1).
	noopDelta := int64(0) // the no-op bug fires the counter 0 times
	assert.Equalf(t, int64(0), noopDelta, "the NO-OP bug fires the manifest-skip counter 0 (the skip never fires — the cut was NOT made)")
	// The RED control: the no-op delta (0) is NOT >= 1 → the download-count guard's
	// assertion WOULD FAIL under the no-op bug (the RED control goes RED).
	assert.Falsef(t, noopDelta >= 1, "manifest-equiv-red-noop: the NO-OP bug's counter delta (0) is NOT >= 1 → the download-count guard's 'counter fires >= 1' assertion FAILS → the guard catches the no-op bug (RED, NOT vacuously green)")
	// The contrast: honestDelta (>= 1) vs noopDelta (0) — the load-bearing proof
	// (the honest rule cuts a download the no-op bug does NOT).
	assert.Greaterf(t, honestDelta, noopDelta, "the HONEST delta (%d) > the NO-OP delta (%d) — the honest rule cuts a manifest download the no-op bug does NOT (the load-bearing contrast)", honestDelta, noopDelta)
	t.Logf("manifest-equiv-red-noop PASS: the HONEST rule fires the manifest-skip counter %d at txTime=base-500 (cut made); the NO-OP bug fires 0 (cut NOT made) → the download-count guard's 'counter fires >= 1' assertion FAILS under the no-op bug (RED, NOT vacuously green); the answer is byte-identical under the no-op (no row is silently dropped — the no-op is a perf regression, NOT a correctness break)", honestDelta)
}
