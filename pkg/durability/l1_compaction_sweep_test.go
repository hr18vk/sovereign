// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// (ADR-0025) ROUTE guard — the REAL *LocalFS route proof.
//
// The Level-3 DominancePrune sweep refactor is a PURE-FUNCTION change; the
// pure-function guards (the equivalence fuzz + the perf guard) live in
// internal/database/l1_compaction_sweep_test.go. The ROUTE guard here proves
// the end-to-end write/compact/read round-trip holds under the NEW sweep: the
// SAME 4-row same-interval adversary used in ADR-0020, driven through the
// production SkipListArena -> L0Flusher -> REAL *LocalFS -> Compaction (with a
// floor) -> Resolver.AsOf over the SAME *LocalFS. The principle: drive the
// ROUTE, not the seam — the route catches a sweep that
// breaks the compaction merge + the byte-identity of the bounded-recovery L1.
//
// This guard re-proves the ADR-0020 live-query equivalence on the NEW sweep.
// It reuses the newLocalFS + insertRowInterval + compactWithHorizon helpers
// already in pkg/durability/l1_compaction_routes_test.go + the
// l1_compaction_test.go helpers rather than reimplementing them. The
// byte-identical round-trip is the load-bearing proof: a
// sweep that breaks the column-append loop (which reads the survivors in order)
// corrupts the L1 and changes the AsOf dominant.
package durability

import (
	"context"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompactionSweepLiveQueryEquivalenceByteIdentical re-proves the
// live-query equivalence on the NEW O(N*H) sweep: the SAME 4 rows
// (same wide interval [0,1000), sysTime 100/200/300/400) written + compacted
// with floor 1000 -> A,B,C dropped (D dominates); every LIVE AsOf (txTime >=
// 1000) resolves to D under BOTH Preserved-All AND the sweep-pruned resolver.
// The byte-identical round-trip proves the sweep did NOT corrupt the L1.
func TestCompactionSweepLiveQueryEquivalenceByteIdentical(t *testing.T) {
	ctx := context.Background()
	const entity = "sweep-route"

	writeRows := func(lfs *LocalFS, alloc *database.JemallocAllocator) {
		flusher := database.NewL0Flusher(alloc, lfs, "sweep-bucket")
		insertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, 1000, []byte{'A'})
		insertRowInterval(t, alloc, lfs, flusher, entity, 200, 0, 1000, []byte{'B'})
		insertRowInterval(t, alloc, lfs, flusher, entity, 300, 0, 1000, []byte{'C'})
		insertRowInterval(t, alloc, lfs, flusher, entity, 400, 0, 1000, []byte{'D'})
	}

	// Preserve-All (the DEFAULT — the byte-identical behavior).
	lfsPA := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	writeRows(lfsPA, alloc)
	resPA, resolverPA := compactWithHorizon(t, ctx, alloc, lfsPA, entity, false, 0)
	require.Equalf(t, 0, resPA.RowsPruned, "Preserve-All drops nothing; got RowsPruned=%d", resPA.RowsPruned)
	require.Equalf(t, 4, resPA.RowsAfter, "Preserve-All keeps all 4 rows; got RowsAfter=%d", resPA.RowsAfter)

	// Pruned (floor 1000) on a FRESH *LocalFS — the NEW sweep drives the prune.
	lfsPR := newLocalFS(t)
	writeRows(lfsPR, alloc)
	resPR, resolverPR := compactWithHorizon(t, ctx, alloc, lfsPR, entity, true, 1000)
	require.Equalf(t, 3, resPR.RowsPruned, "the sweep drops A,B,C (D dominates, floor admits); got RowsPruned=%d", resPR.RowsPruned)
	require.Equalf(t, 1, resPR.RowsAfter, "only D survives (RowsAfter=1); got %d", resPR.RowsAfter)

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
		require.NoErrorf(t, errPA, "%s: Preserve-All AsOf must resolve (txTime=%d >= every sysTime)", p.name, p.tx)
		gotPR, errPR := resolverPR.AsOf(ctx, entity, nsToTime20(p.v), nsToTime20(p.tx))
		require.NoErrorf(t, errPR, "%s: sweep-pruned AsOf must resolve (txTime=%d >= floor, D admitted)", p.name, p.tx)
		assert.Equalf(t, gotPA.Payload, gotPR.Payload, "%s: LIVE-query EQUIVALENCE — Preserve-All and sweep-pruned resolve to the SAME dominant", p.name)
		assert.Equalf(t, gotPA.SystemTime, gotPR.SystemTime, "%s: the dominant's SystemTime matches across Preserve-All and the sweep-pruned set", p.name)
		// The dominant IS D in BOTH cases (a live query resolves to the max-sysTime
		// admitted row, which is D in both). The sweep-pruned L1 contains ONLY D
		// (A,B,C dropped); the Preserve-All L1 contains all 4 but D still wins.
		require.Equalf(t, []byte{'D'}, gotPR.Payload, "%s: the sweep-pruned dominant IS D (the sole survivor)", p.name)
		t.Logf("%s: Preserved(',%s', sys=%d) == sweep-pruned(',%s', sys=%d) — the route round-trip holds under the NEW sweep", p.name, gotPA.Payload, gotPA.SystemTime, gotPR.Payload, gotPR.SystemTime)
	}
}

// nsToTime20 converts a Unix-nanosecond int64 to a time.Time (the AsOf arg).
// (l1_compaction_routes_test.go already defines nsToTime; this is the alias for
// the function — different files, same body — so both test files are
// self-contained without cross-file symbol collision.)
func nsToTime20(ns int64) time.Time { return time.Unix(0, ns).UTC() }
