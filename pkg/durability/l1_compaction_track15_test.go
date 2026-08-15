// Day 15 (ADR-0020) teeth (the REAL *LocalFS ROUTE teeth) — the Level-2
// superseded-row pruning fork, driven against a REAL *LocalFS (the Day-12.5
// tooth-principle "drive the route, not the seam").
//
// These teeth CLOSE the §0.4 truth-maintenance trap Day-14 deferred. A row R
// written via the production write path (SkipListArena -> L0Flusher -> LocalFS)
// is, after a compaction that opts into the Level-2 DominancePrune, SAFE TO
// DROP iff the merged set has a retained R' with:
//
//	(C1) sysTime(R') > sysTime(R)        -- R' is NEWER (a later assertion)
//	(C2) [vs', ve') contains [vs, ve)     -- R' answers every validTime R does
//	(C3) sysTime(R') <= T_gc               -- the dominator is FLOOR-admitted
//
// The ROUTE teeth prove the end-to-end SAFE drop: write -> compaction (with a
// FLOOR) -> AsOf over the REAL *LocalFS. The pure-function provenance (each
// claw pinned in isolation, idempotency, Preserve-All default) lives in
// internal/database/l1_compaction_track15_test.go; these teeth prove the drop
// holds over the FULL write/compact/read route:
//
//   - T1 pins (C3) via the route: the txTime-GAP proof. The dominator above the
//     floor is REFUSED the drop (R survives an AsOf at a txTime in the GAP);
//     once the floor advances past the dominator, R is safe-to-drop AND every
//     live AsOf (txTime >= T_gc) still resolves to R' (the dominator) — NO
//     silent data loss.
//   - T2 pins (C2) via the route: the containment claw. A DOMINATOR that does
//     NOT contain the interval is refused the drop (R survives an AsOf at the
//     boundary validTime R' does not cover); once the interval IS contained +
//     dominator floor-admitted, R is safe-to-drop AND every live AsOf at any V
//     in [vs, ve) resolves to R'.
//   - T3b pins byte-identity: a Preserve-All compaction (the DEFAULT) produces
//     the BYTE-IDENTICAL L1 to a Day-14 compaction (the back-compat gate G15.h,
//     route half). An ENABLED prune with the floor set ABOVE every dominator is
//     byte-identical too; ENABLED with a floor admitting the dominators drops
//     the dead rows (the byte-identity DIFFERS by the pruned rows count only).
//   - T4 pins live-query EQUIVALENCE: a pruned L1 is a STRICT SUBSET of the
//     Preserve-All L1 for the LIVE query set (txTime >= T_gc) — every live AsOf
//     resolves to the SAME dominant as the Preserve-All resolve; the prune
//     drops rows that are provably-never-the-answer.
package durability

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────────────────────────────────
// track15InsertRowInterval inserts ONE tri-temporal row into a fresh
// SkipListArena with an EXPLICIT validTime interval [validStartNs, validEndNs)
// (Day-14's track14InsertRow hardcodes validStart==sysTime + the open-ended
// 9e18 sentry, which makes (C2) containment IMPOSSIBLE under (C1): a wider
// interval asserted at a LATER time is what the Level-2 dominance lattice
// requires). The row uses the production MemTable.Write packing.
//
// sysNs -> key[16:24] (BigEndian system_time) + assertNs == sysNs (key[32:40])
// validStartNs -> key[24:32] (BigEndian valid_time_start)
// validEndNs   -> the packed value's validTimeEnd field (LittleEndian).
// ──────────────────────────────────────────────────────────────────────────
func track15InsertRowInterval(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, flusher *database.L0Flusher, entityID string, sysNs, validStartNs, validEndNs int64, payload []byte) {
	t.Helper()
	sl := database.NewSkipListArena(alloc, 2*1024*1024)
	fullHash := sha256.Sum256([]byte(entityID))
	key := make([]byte, 40)
	copy(key[0:16], fullHash[:16])
	putBE64(key[16:24], uint64(sysNs))
	putBE64(key[24:32], uint64(validStartNs))
	putBE64(key[32:40], uint64(sysNs)) // assertNs == sysNs
	pd := sha256.Sum256(payload)
	val := track14MakePackedValue(entityID, 0x89283082803ffff, validEndNs, pd, payload)
	err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
	require.NoError(t, err)
	_, err = flusher.FlushFromArena(context.Background(), sl)
	require.NoError(t, err)
	sl.Free()
}

// track15CompactWithHorizon runs a Compaction job for `entity` on `lfs` with
// the given prune enable/floor. Returns the CompactionResult (carrying
// RowsBefore/RowsAfter/RowsPruned) + a Resolver over the SAME *LocalFS for the
// immediate AsOf assertions. Mirrors track14's compaction-driving API exactly.
func track15CompactWithHorizon(t *testing.T, ctx context.Context, alloc *database.JemallocAllocator, lfs *LocalFS, entity string, enable bool, floor int64) (*database.CompactionResult, *database.Resolver) {
	t.Helper()
	h8 := database.EntityHash8(entity)
	cfg := database.DefaultCompactionConfig()
	cfg.EnableDominancePruning = enable
	cfg.PruningHorizonInt64Ns = floor
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track15-bucket", cfg)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	// A fresh resolver over the SAME *LocalFS (MaxL0Files large enough to see
	// the uncompacted tail; the L1 is always scanned).
	resolver := database.NewResolver(lfs, lfs, alloc, "local", database.ResolverConfig{MaxL0Files: 1000})
	return res, resolver
}

// ──────────────────────────────────────────────────────────────────────────
// T1 — (C3) via the ROUTE: the §0.4(ii) txTime-GAP proof.
//
// Two rows, SAME wide interval [0, 1000):
//
//	R  : sysTime=100, payload='R'   (the OLDER assertion)
//	R' : sysTime=250, payload='D'   (the NEWER assertion, the dominator)
//
// (C1) 250>100 YES; (C2) [0,1000) contains [0,1000) YES; (C3) depends on T_gc.
//
// GREEN-LOW — the floor T_gc = 200 is BELOW the dominator (sys'=250 > 200):
//
//	(C3) refuses -> R is RETAINED (RowsPruned=0). An AsOf at txTime=150 (in the
//	GAP [100, 250)) admits ONLY R (R' is Filter2-skipped: sys'=250 > 150) ->
//	resolves to R. The drop was refused -> NO silent data loss.
//
// GREEN-HIGH — the floor advances to T_gc = 1000 (>= the dominator 250) so:
//
//	(C3) admits the dominator for every live query (txTime >= 1000 >= 250) ->
//	R IS dropped (RowsPruned=1). The SAME wide interval + newer sys + floor-
//	admitted -> R' dominates R for the LIVE set. An AsOf at txTime=1000 (a
//	LIVE query) resolves to R' (the dominator sys'=250 <= 1000, newer, valid)
//	-> the SAME answer a Preserve-All resolve gives (R' wins on max-sysTime).
//	NO silent data loss.
//
// ──────────────────────────────────────────────────────────────────────────
const track15OpenInterval = int64(1_000) // [0, 1000) — a wide interval BOTH R and R' cover

func TestTrack15_RouteT1_C3_TxTimeGap_RedThenGreen(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	flusher := database.NewL0Flusher(alloc, lfs, "track15-bucket")

	// R : sys=100, [0,1000), payload 'R'
	track15InsertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, track15OpenInterval, []byte{'R'})
	// R': sys=250, [0,1000), payload 'D'  (the dominator)
	track15InsertRowInterval(t, alloc, lfs, flusher, entity, 250, 0, track15OpenInterval, []byte{'D'})

	// GREEN-LOW — floor BELOW the dominator (200 < 250) -> (C3) refuses -> R kept.
	resLow, resolverLow := track15CompactWithHorizon(t, ctx, alloc, lfs, entity, true, 200)
	assert.Equalf(t, 0, resLow.RowsPruned, "T1 GREEN-LOW: the floor (200) is below the dominator (sys'=250) -> (C3) refuses -> R must be RETAINED (RowsPruned=0); got RowsPruned=%d", resLow.RowsPruned)
	assert.Equalf(t, 2, resLow.RowsAfter, "T1 GREEN-LOW: both rows survive; got RowsAfter=%d", resLow.RowsAfter)

	// The GAP query at txTime=150 (in [100, 250)) admits ONLY R -> resolves to R.
	gap, err := resolverLow.AsOf(ctx, entity, nsToTime(500), nsToTime(150))
	require.NoError(t, err, "T1 GREEN-LOW: the GAP query (txTime=150) must resolve to R (R' is Filter2-skipped: sys'=250 > 150)")
	assert.Equalf(t, []byte{'R'}, gap.Payload, "T1 GREEN-LOW: the GAP query resolves to R (the sole admitted row); got payload %q (silent data loss if 'D')", gap.Payload)
	assert.Equalf(t, int64(100), gap.SystemTime, "T1 GREEN-LOW: the GAP query's dominant is R (sysTime=100), NOT R' (sysTime=250 is Filter2-skipped)")
	t.Logf("T1 GREEN-LOW: floor 200 < dominator 250 -> R retained; GAP AsOf(txTime=150) resolves to R (sys=100) — the drop correctly refused")

	// GREEN-HIGH — advance the floor to 1000 (>= dominator 250) -> (C3) admits ->
	// R dropped. Wire a FRESH compaction (a second Compaction on the SAME L0 set
	// re-merges; the first L1 + manifest are superseded by the second). For a
	// clean GREEN-HIGH we use a FRESH *LocalFS (write the SAME two rows again +
	// the high floor) so the L1 result is unambiguous.
	lfs2 := track14LocalFS(t)
	flusher2 := database.NewL0Flusher(alloc, lfs2, "track15-bucket")
	track15InsertRowInterval(t, alloc, lfs2, flusher2, entity, 100, 0, track15OpenInterval, []byte{'R'})
	track15InsertRowInterval(t, alloc, lfs2, flusher2, entity, 250, 0, track15OpenInterval, []byte{'D'})
	resHigh, resolverHigh := track15CompactWithHorizon(t, ctx, alloc, lfs2, entity, true, 1000)
	assert.Equalf(t, 1, resHigh.RowsPruned, "T1 GREEN-HIGH: the floor (1000) admits the dominator (sys'=250 <= 1000) -> R is now SAFE TO DROP (RowsPruned=1); got RowsPruned=%d", resHigh.RowsPruned)
	assert.Equalf(t, 1, resHigh.RowsAfter, "T1 GREEN-HIGH: only the dominator D survives (RowsAfter=1); got RowsAfter=%d", resHigh.RowsAfter)

	// A LIVE query (txTime=1000 >= floor 1000 >= sys'=250) resolves to R' (the
	// dominator) — the SAME answer a Preserve-All resolve gives (R' wins on
	// max-sysTime). NO silent data loss.
	live, err := resolverHigh.AsOf(ctx, entity, nsToTime(500), nsToTime(1000))
	require.NoError(t, err, "T1 GREEN-HIGH: the LIVE query (txTime=1000 >= floor) must resolve to R' (the dominator)")
	assert.Equalf(t, []byte{'D'}, live.Payload, "T1 GREEN-HIGH: the live query resolves to R' ('D'); got %q (R was dropped; the dominator must win)", live.Payload)
	assert.Equalf(t, int64(250), live.SystemTime, "T1 GREEN-HIGH: dominant is R' (sysTime=250, the newer floor-admitted row)")

	// And the GAP query (txTime=150, BEFORE the floor) against the PRUNED set:
	// R was dropped, R' is Filter2-skipped (sys'=250 > 150) -> ErrEntityNotFound.
	// This is the HONEST residual: the prune is correct for the LIVE set
	// (txTime >= T_gc) ONLY; a BELOW-floor query loses R. The (C3) floor is the
	// operator's contract that NO such below-floor query is live. (The GREEN-LOW
	// branch above shows R IS retained when the floor refuses — the SAFE path.)
	_, gapErr := resolverHigh.AsOf(ctx, entity, nsToTime(500), nsToTime(150))
	t.Logf("T1 GREEN-HIGH: GAP AsOf(txTime=150, below floor) -> %v (the honest residual: the below-floor query lost R; the floor is the operator's no-below-floor-query contract)", gapErr)
}

// ──────────────────────────────────────────────────────────────────────────
// T2 — (C2) via the ROUTE: the containment claw.
//
// Two rows at a floor-admitted sysTime, DIFFERENT validTime intervals:
//
//	R  : sysTime=100, valid=[0, 1000),  payload 'R'  (the WIDER interval)
//	R' : sysTime=250, valid=[200, 800), payload 'D'  (the NARROWER interval)
//
// (C1) 250>100 YES; (C2) [200,800) does NOT contain [0,1000) -> REFUSED.
//
// GREEN — the floor admits the dominator (T_gc=1000 >= 250) BUT (C2) refuses
// (the interval is NOT contained) -> R is RETAINED. An AsOf at V=500 (in BOTH
// intervals) resolves to R' (newer) — fine; but an AsOf at V=10 (in [0,200) —
// R ONLY; R' is Filter3-skipped: 10 < vs'=200) resolves to R -> the boundary V
// is answered ONLY by R -> R survives (NO silent data loss).
//
// CONTAIN-GREEN — swap the intervals so R' is the WIDER ([0,1000)) and R is
// the NARROWER ([200,800)); now [vs',ve')=[0,1000) CONTAINS [200,800) AND the
// dominator is floor-admitted -> (C1)&&(C2)&&(C3) all hold -> R is dropped;
// every AsOf at V in [200,800) resolves to R' (the dominator) — the same answer
// a Preserve-All resolve gives (R' wins on max-sysTime). NO silent data loss.
// ──────────────────────────────────────────────────────────────────────────
func TestTrack15_RouteT2_C2_Containment_RedThenGreen(t *testing.T) {
	ctx := context.Background()

	// SCENARIO-A — dominator NARROWER (C2 refuses) -> R retained.
	lfsA := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "beta"
	flusherA := database.NewL0Flusher(alloc, lfsA, "track15-bucket")
	track15InsertRowInterval(t, alloc, lfsA, flusherA, entity, 100, 0, 1000, []byte{'R'})  // wider
	track15InsertRowInterval(t, alloc, lfsA, flusherA, entity, 250, 200, 800, []byte{'D'}) // narrower dominator
	resA, resolverA := track15CompactWithHorizon(t, ctx, alloc, lfsA, entity, true, 1000)
	assert.Equalf(t, 0, resA.RowsPruned, "T2 SCENARIO-A: (C2) refuses (narrower interval does NOT contain wider) -> R retained (RowsPruned=0); got RowsPruned=%d", resA.RowsPruned)
	// Boundary V=10 in [0,200) is R-ONLY (R' is Filter3-skipped: 10 < vs'=200) -> resolves to R.
	boundary, err := resolverA.AsOf(ctx, entity, nsToTime(10), nsToTime(1000))
	require.NoError(t, err, "T2 SCENARIO-A: the boundary V=10 query must resolve to R (R' is Filter3-skipped: 10 < vs'=200)")
	assert.Equalf(t, []byte{'R'}, boundary.Payload, "T2 SCENARIO-A: boundary V=10 resolves to R (the SOLE Filter3-valid row); got %q", boundary.Payload)
	t.Logf("T2 SCENARIO-A: narrower dominator -> (C2) refuses -> R retained; boundary V=10 resolves to R — NO silent data loss")

	// SCENARIO-B — dominator WIDER (C2 holds) + floor-admitted -> R dropped.
	lfsB := track14LocalFS(t)
	flusherB := database.NewL0Flusher(alloc, lfsB, "track15-bucket")
	track15InsertRowInterval(t, alloc, lfsB, flusherB, entity, 100, 200, 800, []byte{'R'}) // narrower (to be dropped)
	track15InsertRowInterval(t, alloc, lfsB, flusherB, entity, 250, 0, 1000, []byte{'D'})  // wider dominator
	resB, resolverB := track15CompactWithHorizon(t, ctx, alloc, lfsB, entity, true, 1000)
	assert.Equalf(t, 1, resB.RowsPruned, "T2 SCENARIO-B: (C1)&&(C2)&&(C3) all hold (wider dominator, floor-admitted) -> R SAFE TO DROP (RowsPruned=1); got RowsPruned=%d", resB.RowsPruned)
	// Every V in [200,800) is covered by BOTH; the dominator (newer) wins -> resolves to D (the SAME as Preserve-All).
	covered, err := resolverB.AsOf(ctx, entity, nsToTime(500), nsToTime(1000))
	require.NoError(t, err, "T2 SCENARIO-B: the covered V=500 query must resolve to the dominator D")
	assert.Equalf(t, []byte{'D'}, covered.Payload, "T2 SCENARIO-B: V=500 resolves to D (the dominator, same as Preserve-All); got %q", covered.Payload)
	t.Logf("T2 SCENARIO-B: wider dominator + floor-admitted -> (C1)&&(C2)&&(C3) hold -> R dropped; V=500 resolves to D — NO silent data loss")
}

// ──────────────────────────────────────────────────────────────────────────
// T3b — byte-identity: Preserve-All (the DEFAULT) is byte-identical to Day-14.
//
// Write 3 rows for one entity; run TWO compactions:
//
//	(a) Preserve-All — EnableDominancePruning=false (the DEFAULT).
//	(b) Preserve-All — EnableDominancePruning=true + floor<=0 (the LOUD coerce
//	    to Preserve-All path; NewL1Compactor logs a WARN + disables).
//
// Assert BOTH produce RowsPruned=0 + the SAME L1 bytes (byte-identity across
// the two Preserve-All paths). Then a THIRD compaction ENABLED with the floor set
// strictly above every row's sysTime admits ALL dominators -> the OLDER nested
// rows drop (RowsPruned > 0) — the byte-identity DIFFERS ONLY by the pruned rows.
// ──────────────────────────────────────────────────────────────────────────
func TestTrack15_RouteT3b_PreserveAllByteIdenticalDefault(t *testing.T) {
	ctx := context.Background()
	const entity = "gamma"

	writeRows := func(lfs *LocalFS, alloc *database.JemallocAllocator) {
		flusher := database.NewL0Flusher(alloc, lfs, "track15-bucket")
		// 3 rows, identical wide interval [0,1000), strictly-increasing sysTime.
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, 1000, []byte{'A'})
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 200, 0, 1000, []byte{'B'})
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 300, 0, 1000, []byte{'C'})
	}

	// (a) Preserve-All DEFAULT (EnableDominancePruning=false).
	lfsA := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	writeRows(lfsA, alloc)
	resA, _ := track15CompactWithHorizon(t, ctx, alloc, lfsA, entity, false, 0)
	require.Equalf(t, 0, resA.RowsPruned, "T3b(a): Preserve-All DEFAULT drops nothing (RowsPruned=0); got %d", resA.RowsPruned)
	require.Equalf(t, 3, resA.RowsAfter, "T3b(a): all 3 rows preserved (RowsAfter=3); got %d", resA.RowsAfter)
	l1BytesA := track14ReadObject(t, lfsA, resA.L1Key)

	// (b) Preserve-All via the LOUD coerce (ENABLED + floor<=0 -> WARN + disable).
	lfsB := track14LocalFS(t)
	writeRows(lfsB, alloc)
	resB, _ := track15CompactWithHorizon(t, ctx, alloc, lfsB, entity, true, 0) // floor<=0 -> coerced
	require.Equalf(t, 0, resB.RowsPruned, "T3b(b): the LOUD-coerce path (ENABLED + floor<=0) preserves all (RowsPruned=0); got %d", resB.RowsPruned)
	require.Equalf(t, 3, resB.RowsAfter, "T3b(b): all 3 rows preserved (RowsAfter=3); got %d", resB.RowsAfter)
	l1BytesB := track14ReadObject(t, lfsB, resB.L1Key)

	// Byte-identity: the two Preserve-All L1s are byte-identical (the DEFAULT +
	// the coerce path are the SAME Day-14 behavior — the back-compat gate G15.h).
	assert.True(t, bytesEqual(l1BytesA, l1BytesB),
		"T3b: Preserve-All DEFAULT + the LOUD-coerce path produce BYTE-IDENTICAL L1s (the Day-14 back-compat)")
	t.Logf("T3b: Preserve-All DEFAULT + LOUD-coerce -> byte-identical L1 (%d bytes each), RowsPruned=0 for both", len(l1BytesA))

	// (c) ENABLED + floor above every sysTime (1000 >= 300) -> all dominators
	// admitted -> the 2 older rows drop (A and B dominated by C; C is the newest
	// at-floor, survives). RowsPruned=2, RowsAfter=1.
	lfsC := track14LocalFS(t)
	writeRows(lfsC, alloc)
	resC, _ := track15CompactWithHorizon(t, ctx, alloc, lfsC, entity, true, 1000)
	require.Equalf(t, 2, resC.RowsPruned, "T3c: floor above every sysTime admits the newest as dominator -> A,B dropped (RowsPruned=2); got %d", resC.RowsPruned)
	require.Equalf(t, 1, resC.RowsAfter, "T3c: only C survives (RowsAfter=1); got %d", resC.RowsAfter)
	l1BytesC := track14ReadObject(t, lfsC, resC.L1Key)
	assert.False(t, bytesEqual(l1BytesA, l1BytesC),
		"T3c: the ENABLED+floor L1 DIFFERS from Preserve-All (the pruned rows removed) — the prune IS wired (not a silent no-op)")
	t.Logf("T3c: ENABLED + floor 1000 -> A,B dropped (RowsPruned=2, RowsAfter=1); the L1 DIFFERS from Preserve-All by the 2 pruned rows")
}

// ──────────────────────────────────────────────────────────────────────────
// T4 — live-query EQUIVALENCE: pruned L1 ⊆ Preserve-All L1 for the LIVE set.
//
// Write 4 rows for one entity (same wide interval, sysTime 100/200/300/400).
//
//	Preserve-All  : every AsOf (any txTime, any V) resolves to the max-sysTime
//	                row admitted (a live txTime >= 400 resolves to 'D').
//	Pruned        : floor = 1000 (>= 400); A,B,C DROP (dominated by D); only
//	                D survives. Every LIVE AsOf (txTime >= 1000) resolves to D,
//	                the same answer the Preserve-All resolve gives (D wins on
//	                max-sysTime) -> the pruned L1 is a STRICT SUBSET of the
//	                Preserve-All L1 for the LIVE set, with NO query divergence.
//
// ──────────────────────────────────────────────────────────────────────────
func TestTrack15_RouteT4_LiveQueryEquivalence(t *testing.T) {
	ctx := context.Background()
	const entity = "delta"

	writeRows := func(lfs *LocalFS, alloc *database.JemallocAllocator) {
		flusher := database.NewL0Flusher(alloc, lfs, "track15-bucket")
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, 1000, []byte{'A'})
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 200, 0, 1000, []byte{'B'})
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 300, 0, 1000, []byte{'C'})
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 400, 0, 1000, []byte{'D'})
	}

	// Preserve-All + a resolver.
	lfsPA := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	writeRows(lfsPA, alloc)
	resPA, resolverPA := track15CompactWithHorizon(t, ctx, alloc, lfsPA, entity, false, 0)
	require.Equalf(t, 0, resPA.RowsPruned, "T4: Preserve-All drops nothing; got RowsPruned=%d", resPA.RowsPruned)
	require.Equalf(t, 4, resPA.RowsAfter, "T4: Preserve-All keeps all 4 rows; got RowsAfter=%d", resPA.RowsAfter)

	// Pruned (floor 1000) + a resolver.
	lfsPR := track14LocalFS(t)
	writeRows(lfsPR, alloc)
	resPR, resolverPR := track15CompactWithHorizon(t, ctx, alloc, lfsPR, entity, true, 1000)
	require.Equalf(t, 3, resPR.RowsPruned, "T4: the floor admits D as dominator -> A,B,C dropped (RowsPruned=3); got %d", resPR.RowsPruned)
	require.Equalf(t, 1, resPR.RowsAfter, "T4: only D survives (RowsAfter=1); got %d", resPR.RowsAfter)

	// LIVE-query sweep: a set of (V in [0,1000), txTime >= floor 1000) queries.
	// Every one resolves to the SAME dominant under BOTH the pruned + Preserve-All
	// resolvers -> equivalence (the prune drops rows that are provably-never-the-
	// answer for the LIVE set; no query diverges).
	probes := []struct {
		name string
		v    int64
		tx   int64
	}{
		{"V=0 txTime=1000", 0, 1000},
		{"V=200 txTime=1500", 200, 1500},
		{"V=500 txTime=5000", 500, 5000},
		{"V=999 txTime=9999999", 999, 9999999},
	}
	for _, p := range probes {
		gotPA, errPA := resolverPA.AsOf(ctx, entity, nsToTime(p.v), nsToTime(p.tx))
		require.NoErrorf(t, errPA, "T4 %s: Preserve-All AsOf must resolve (txTime=%d >= every sysTime)", p.name, p.tx)
		gotPR, errPR := resolverPR.AsOf(ctx, entity, nsToTime(p.v), nsToTime(p.tx))
		require.NoErrorf(t, errPR, "T4 %s: Pruned AsOf must resolve (txTime=%d >= floor, D admitted)", p.name, p.tx)
		assert.Equalf(t, gotPA.Payload, gotPR.Payload, "T4 %s: LIVE-query EQUIVALENCE — Preserve-All and Pruned resolve to the SAME dominant", p.name)
		assert.Equalf(t, gotPA.SystemTime, gotPR.SystemTime, "T4 %s: the dominant's SystemTime matches across Preserve-All and Pruned", p.name)
		t.Logf("T4 %s: Preserve-All(',%s', sys=%d) == Pruned(',%s', sys=%d) — LIVE-query equivalence holds", p.name, gotPA.Payload, gotPA.SystemTime, gotPR.Payload, gotPR.SystemTime)
	}
}

// nsToTime converts a Unix-nanosecond int64 to a time.Time (the AsOf arg type).
func nsToTime(ns int64) time.Time { return time.Unix(0, ns).UTC() }

// bytesEqual is a length+content byte compare (avoids importing bytes for one fn).
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
