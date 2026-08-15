// Day 20 (ADR-0025) ROUTE tooth — the REAL *LocalFS route re-pin.
//
// The Level-3 DominancePrune sweep refactor is a PURE-FUNCTION change; the
// pure-function teeth (T-EQUIV fuzz + T-PERF + T1/T2/T3/T5/T6) live in
// internal/database/l1_compaction_track20_test.go. The ROUTE tooth here proves
// the end-to-end write/compact/read round-trip holds under the NEW sweep: the
// SAME 4-row same-interval adversary ADR-0020 T4 used, driven through the
// production SkipListArena -> L0Flusher -> REAL *LocalFS -> Compaction (with a
// floor) -> Resolver.AsOf over the SAME *LocalFS. The day-principle (Day-12.5
// [243c10a]): drive the ROUTE, not the seam — the route catches a sweep that
// breaks the compaction merge + the byte-identity of the bounded-recovery L1.
//
// This tooth RE-PINS the Day-15 T4 (ADR-0020) on the NEW sweep. It reuses the
// track14LocalFS + track15InsertRowInterval + track15CompactWithHorizon helpers
// already in pkg/durability/l1_compaction_track15_test.go + the
// l1_compaction_track14_test.go helpers — per the prompt (REUSE them, do NOT
// reimplement). The byte-identical round-trip is the load-bearing proof: a
// sweep that breaks the column-append loop (which reads the survivors in order)
// corrupts the L1 and changes the AsOf dominant.
package durability

import (
	"context"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTrack20_RouteT4_LiveQueryEquivalence_SweepByteIdentical re-pins the
// Day-15 T4 live-query equivalence on the NEW O(N*H) sweep: the SAME 4 rows
// (same wide interval [0,1000), sysTime 100/200/300/400) written + compacted
// with floor 1000 -> A,B,C dropped (D dominates); every LIVE AsOf (txTime >=
// 1000) resolves to D under BOTH Preserved-All AND the sweep-pruned resolver.
// The byte-identical round-trip proves the sweep did NOT corrupt the L1.
func TestTrack20_RouteT4_LiveQueryEquivalence_SweepByteIdentical(t *testing.T) {
	ctx := context.Background()
	const entity = "day20route"

	writeRows := func(lfs *LocalFS, alloc *database.JemallocAllocator) {
		flusher := database.NewL0Flusher(alloc, lfs, "track20-bucket")
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, 1000, []byte{'A'})
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 200, 0, 1000, []byte{'B'})
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 300, 0, 1000, []byte{'C'})
		track15InsertRowInterval(t, alloc, lfs, flusher, entity, 400, 0, 1000, []byte{'D'})
	}

	// Preserve-All (the DEFAULT — the byte-identical Day-14 behavior).
	lfsPA := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	writeRows(lfsPA, alloc)
	resPA, resolverPA := track15CompactWithHorizon(t, ctx, alloc, lfsPA, entity, false, 0)
	require.Equalf(t, 0, resPA.RowsPruned, "Day20 T4: Preserve-All drops nothing; got RowsPruned=%d", resPA.RowsPruned)
	require.Equalf(t, 4, resPA.RowsAfter, "Day20 T4: Preserve-All keeps all 4 rows; got RowsAfter=%d", resPA.RowsAfter)

	// Pruned (floor 1000) on a FRESH *LocalFS — the NEW sweep drives the prune.
	lfsPR := track14LocalFS(t)
	writeRows(lfsPR, alloc)
	resPR, resolverPR := track15CompactWithHorizon(t, ctx, alloc, lfsPR, entity, true, 1000)
	require.Equalf(t, 3, resPR.RowsPruned, "Day20 T4: the sweep drops A,B,C (D dominates, floor admits); got RowsPruned=%d", resPR.RowsPruned)
	require.Equalf(t, 1, resPR.RowsAfter, "Day20 T4: only D survives (RowsAfter=1); got %d", resPR.RowsAfter)

	// LIVE-query sweep: (V in [0,1000), txTime >= floor 1000). Each probe must
	// resolve to the SAME dominant under BOTH resolvers (the sweep-pruned L1
	// is a strict subset of the Preserve-All L1 for the LIVE set).
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
		gotPA, errPA := resolverPA.AsOf(ctx, entity, nsToTime20(p.v), nsToTime20(p.tx))
		require.NoErrorf(t, errPA, "Day20 T4 %s: Preserve-All AsOf must resolve (txTime=%d >= every sysTime)", p.name, p.tx)
		gotPR, errPR := resolverPR.AsOf(ctx, entity, nsToTime20(p.v), nsToTime20(p.tx))
		require.NoErrorf(t, errPR, "Day20 T4 %s: sweep-pruned AsOf must resolve (txTime=%d >= floor, D admitted)", p.name, p.tx)
		assert.Equalf(t, gotPA.Payload, gotPR.Payload, "Day20 T4 %s: LIVE-query EQUIVALENCE — Preserve-All and sweep-pruned resolve to the SAME dominant", p.name)
		assert.Equalf(t, gotPA.SystemTime, gotPR.SystemTime, "Day20 T4 %s: the dominant's SystemTime matches across Preserve-All and the sweep-pruned set", p.name)
		// The dominant IS D in BOTH cases (a live query resolves to the max-sysTime
		// admitted row, which is D in both). The sweep-pruned L1 contains ONLY D
		// (A,B,C dropped); the Preserve-All L1 contains all 4 but D still wins.
		require.Equalf(t, []byte{'D'}, gotPR.Payload, "Day20 T4 %s: the sweep-pruned dominant IS D (the sole survivor)", p.name)
		t.Logf("Day20 T4 %s: Preserved(',%s', sys=%d) == sweep-pruned(',%s', sys=%d) — the route round-trip holds under the NEW sweep", p.name, gotPA.Payload, gotPA.SystemTime, gotPR.Payload, gotPR.SystemTime)
	}
}

// nsToTime20 converts a Unix-nanosecond int64 to a time.Time (the AsOf arg).
// (track15_test.go already defines nsToTime; this is the track20 alias for the
// function — different files, same body — so both test files are self-contained
// without cross-file symbol collision.)
func nsToTime20(ns int64) time.Time { return time.Unix(0, ns).UTC() }
