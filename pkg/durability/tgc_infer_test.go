// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//tgc_infer_test.go (ADR-0027) — the REAL *LocalFS inferrer guard.
//
// §2.h — the real-LocalFS inferrer guard: the end-to-end T_gc auto-inference over a REAL
// *LocalFS — the route half of the inferrer (the in-package guards proved the
// arithmetic + the clamp; this guard proves the inferrer drives the prune over
// the production write/compact/read route). The inferrer FLOORS the operator
// knob: the operator's static floor alone would REFUSE the drop, but the
// inferrer advances the horizon ABOVE the operator floor (from the observed
// live-query txTime frontier - backoff), and the prune ADMITS the dominator the
// operator floor alone would have refused — the load-bearing proof that the
// inferrer is NOT a no-op (a no-op inferrer leaves the horizon at the operator
// floor; the drop is refused; the LIVE query still resolves to R' only because
// R' wins on max-sysTime, NOT because R was pruned — the guard distinguishes
// these by reading RowsPruned).
//
// The flow (mirrors the green high-water route, + the inferrer step):
//
// 1. Write R (sys=100, [0,1000)) + R' (sys=250, [0,1000)) to a real *LocalFS.
// 2. Drive AsOf at txTime=2000 (a LIVE query) — the §1.a seam advances the
// Resolver's observed frontier to 2000.
// 3. Build a compactor with operatorFloor=100 + backoff=400. The inferrer
// computes effective = max(100, 2000 - 400) = 1600 (admits R' sys'=250).
// The operator floor ALONE (100) would REFUSE the drop (250 > 100); the
// inferrer's advance to 1600 is what ADMITS it.
// 4. Run the inferrer (InferHorizon) + compact -> R DROPPED (RowsPruned=1).
// 5. Assert a LIVE AsOf (txTime=2000) resolves to R' (the dominator) — NO
// silent data loss.
// 6. The load-bearing assertion: an inferrer that did NOT advance the horizon
// (a no-op) leaves the horizon at the operator floor 100 -> 250 > 100 -> the
// drop is REFUSED -> RowsPruned=0. The guard asserts RowsPruned=1, proving
// the inferrer advanced the horizon (the §0.a "engine tracks the frontier"
// load-bearing claim).
//
// The guard REUSES the REAL-LocalFS helpers (newLocalFS,
// insertRowInterval) + the compactWithHorizon-API SHAPE, but
// builds its OWN compactor (the inferrer needs the backoff + the InferHorizon
// step, which compactWithHorizon does NOT expose — it sets a static
// horizon). The Resolver is the SAME shape compactWithHorizon returns.

import (
	"context"
	"testing"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCFloorInferRealLocalFS(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	flusher := database.NewL0Flusher(alloc, lfs, "compact-bucket")

	// (1) Write R (sys=100, [0,1000)) + R' (sys=250, [0,1000)) — the SAME wide
	// interval, R' the NEWER (the dominator).
	insertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, openInterval, []byte{'R'})
	insertRowInterval(t, alloc, lfs, flusher, entity, 250, 0, openInterval, []byte{'D'})

	// (2) A Resolver over the SAME *LocalFS. Drive AsOf at txTime=2000 (a LIVE
	// query) — the §1.a seam advances the observed frontier to 2000. The AsOf
	// resolves to R' (the dominator, sys'=250 <= 2000, newer, valid) — the same
	// answer a Preserve-All resolve gives. The seam fires BEFORE the storage
	// list, so the frontier is 2000 after this call regardless of the resolve.
	resolver := database.NewResolver(lfs, lfs, alloc, "local", database.ResolverConfig{MaxL0Files: 1000})
	live, err := resolver.AsOf(ctx, entity, nsToTime(500), nsToTime(2000))
	require.NoError(t, err, "real-LocalFS inferrer: the LIVE AsOf(txTime=2000) must resolve (R' sys'=250 <= 2000, newer, valid)")
	assert.Equalf(t, []byte{'D'}, live.Payload, "real-LocalFS inferrer: the LIVE AsOf resolves to R' ('D', the dominator); got %q", live.Payload)
	// The observed frontier MUST be 2000 (the seam advanced it — the §1.a claim).
	if got := resolver.QueryTxTimeFrontier(); got != 2000 {
		t.Fatalf("real-LocalFS inferrer: after AsOf(txTime=2000) the observed frontier=%d, want 2000 (the §1.a seam advanced it; the inferrer reads this)", got)
	}

	// (3) Build a compactor with operatorFloor=100 + backoff=400. The inferrer
	// computes effective = max(100, 2000 - 400) = 1600. The operator floor ALONE
	// (100) would REFUSE the drop (the dominator sys'=250 > 100); the inferrer's
	// advance to 1600 is what ADMITS it — the load-bearing §0.a claim.
	cfg := database.DefaultCompactionConfig()
	cfg.EnableDominancePruning = true
	cfg.PruningHorizonInt64Ns = 100 // the operator HARD floor (BELOW the dominator 250)
	cfg.PruneBackoffInt64Ns = 400   // the backoff
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "compact-bucket", cfg)

	// SANITY: the inferrer's EffectiveHorizon(2000) == 1600 (the arithmetic the
	// in-package floor-arithmetic guard pinned; re-assert here over the route).
	assert.Equalf(t, int64(1600), compactor.EffectiveHorizon(2000),
		"real-LocalFS inferrer: EffectiveHorizon(2000) with floor=100 backoff=400 = %d, want 1600 (max(100, 2000-400); the inferrer's arithmetic over the route)", compactor.EffectiveHorizon(2000))

	// (4) Run the inferrer (InferHorizon reads the observed frontier, advances
	// the compactor's horizon monotonically) THEN compact. The inferrer advances
	// cfg.PruningHorizonInt64Ns from 100 -> 1600; the prune at 1600 admits R'.
	compactor.InferHorizon(resolver)
	// The compactor's horizon MUST now be 1600 (the inferrer advanced it ABOVE
	// the operator floor 100 — the §0.a load-bearing advance).
	if got := compactor.Config().PruningHorizonInt64Ns; got != 1600 {
		t.Fatalf("real-LocalFS inferrer: after InferHorizon the compactor horizon=%d, want 1600 (the inferrer advanced it from the operator floor 100 to the inferred 1600 — the §0.a load-bearing advance)", got)
	}
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err, "real-LocalFS inferrer: the compaction must succeed")

	// (5) R is DROPPED (RowsPruned=1) — the inferrer advanced the horizon to 1600
	// (>= the dominator 250), so (C3) admits R'. The operator floor ALONE (100)
	// would have REFUSED (250 > 100) -> RowsPruned=0. The guard asserts
	// RowsPruned=1, proving the inferrer advanced the horizon (the load-bearing
	// claim; a no-op inferrer leaves RowsPruned=0).
	assert.Equalf(t, 1, res.RowsPruned, "real-LocalFS inferrer: RowsPruned=%d, want 1 (the inferrer advanced the horizon to 1600 -> the dominator R' (sys'=250) is floor-admitted -> R is safe-to-drop; the operator floor ALONE (100) would have REFUSED -> RowsPruned=0 — the inferrer is NOT a no-op)", res.RowsPruned)
	assert.Equalf(t, 1, res.RowsAfter, "real-LocalFS inferrer: RowsAfter=%d, want 1 (only the dominator R' survives)", res.RowsAfter)

	// (6) A LIVE AsOf (txTime=2000 >= the inferred horizon 1600) over the PRUNED
	// set resolves to R' (the dominator) — the SAME answer a Preserve-All resolve
	// gives (R' wins on max-sysTime). NO silent data loss (the class
	// stays closed — the inferrer NEVER admits a horizon BELOW the operator
	// floor, and the LIVE query is at/above the inferred horizon).
	resolverPost := database.NewResolver(lfs, lfs, alloc, "local", database.ResolverConfig{MaxL0Files: 1000})
	livePost, err := resolverPost.AsOf(ctx, entity, nsToTime(500), nsToTime(2000))
	require.NoError(t, err, "real-LocalFS inferrer: the LIVE AsOf(txTime=2000 >= inferred horizon 1600) over the PRUNED set must resolve to R'")
	assert.Equalf(t, []byte{'D'}, livePost.Payload, "real-LocalFS inferrer: the LIVE AsOf over the pruned set resolves to R' ('D'); got %q (R was dropped; the dominator must win — NO silent data loss)", livePost.Payload)
	assert.Equalf(t, int64(250), livePost.SystemTime, "real-LocalFS inferrer: the dominant is R' (sysTime=250, the newer floor-admitted row)")

	t.Logf("real-LocalFS inferrer PASS: the inferrer advanced the horizon 100 -> 1600 (max(100, observed=2000 - backoff=400)) over the REAL route; R was DROPPED (RowsPruned=1 — the operator floor ALONE would have refused); a LIVE AsOf(txTime=2000) resolves to R' (the dominator) — NO silent data loss (the class stays closed; the §0.a load-bearing advance byte-verified)")
}

// TestGCFloorInferRealLocalFSNoOpControl is the RED CONTROL: a compactor
// whose inferrer does NOT advance (the operator floor alone, no observed
// frontier driven) compacts at the operator floor 100 -> the dominator R'
// (sys'=250 > 100) is NOT floor-admitted -> R is RETAINED (RowsPruned=0). The
// guard asserts RowsPruned=0, proving the inferrer's advance is load-bearing
// (without the advance, the drop is refused — the divergence the
// real-LocalFS inferrer guard catches). This is the no-op-inferrer φ-break.
func TestGCFloorInferRealLocalFSNoOpControl(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	flusher := database.NewL0Flusher(alloc, lfs, "compact-bucket")
	insertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, openInterval, []byte{'R'})
	insertRowInterval(t, alloc, lfs, flusher, entity, 250, 0, openInterval, []byte{'D'})

	// A Resolver whose observed frontier is NEVER driven (no AsOf) -> the frontier
	// stays 0. The inferrer computes effective = max(100, 0 - 400) = max(100,
	// -400) = 100 (the operator floor — the backoff takes 0-400 negative, the
	// floor clamps it). The horizon stays at the operator floor 100.
	resolver := database.NewResolver(lfs, lfs, alloc, "local", database.ResolverConfig{MaxL0Files: 1000})
	if got := resolver.QueryTxTimeFrontier(); got != 0 {
		t.Fatalf("no-op inferrer control: fresh Resolver frontier=%d, want 0 (no AsOf driven — the no-op-inferrer control)", got)
	}

	cfg := database.DefaultCompactionConfig()
	cfg.EnableDominancePruning = true
	cfg.PruningHorizonInt64Ns = 100 // the operator floor (BELOW the dominator 250)
	cfg.PruneBackoffInt64Ns = 400
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "compact-bucket", cfg)

	// The no-op inferrer: observed frontier 0 -> effective = max(100, 0-400) = 100.
	assert.Equalf(t, int64(100), compactor.EffectiveHorizon(0),
		"no-op inferrer control: EffectiveHorizon(0) with floor=100 backoff=400 = %d, want 100 (max(100, -400); the no-op-inferrer control — the horizon stays at the operator floor)", compactor.EffectiveHorizon(0))

	compactor.InferHorizon(resolver)
	// The horizon stays at 100 (the no-op inferrer did NOT advance it).
	if got := compactor.Config().PruningHorizonInt64Ns; got != 100 {
		t.Fatalf("no-op inferrer control: after InferHorizon (no observed frontier) the compactor horizon=%d, want 100 (the no-op inferrer did NOT advance — the operator floor holds)", got)
	}
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)

	// R is RETAINED (RowsPruned=0) — the operator floor 100 is BELOW the dominator
	// 250, so (C3) refuses. This is the divergence the real-LocalFS inferrer guard catches:
	// a no-op inferrer leaves RowsPruned=0; the advancing inferrer (the
	// production path) leaves RowsPruned=1.
	assert.Equalf(t, 0, res.RowsPruned, "no-op inferrer control: RowsPruned=%d, want 0 (the no-op inferrer left the horizon at the operator floor 100 -> the dominator R' (sys'=250 > 100) is NOT floor-admitted -> R is RETAINED — the divergence the advancing inferrer in the real-LocalFS inferrer guard catches)", res.RowsPruned)
	assert.Equalf(t, 2, res.RowsAfter, "no-op inferrer control: RowsAfter=%d, want 2 (both rows survive — the prune refused)", res.RowsAfter)

	t.Logf("no-op inferrer control PASS: the no-op inferrer (no observed frontier) left the horizon at the operator floor 100 -> R RETAINED (RowsPruned=0) — the divergence the advancing inferrer in the real-LocalFS inferrer guard catches (RowsPruned=1); the inferrer's advance is load-bearing")
}
