// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// End-to-end tests for transaction-time GC horizon inference (ADR-0027).
//
// Two rows have the same valid-time interval. The newer row has SystemTime 250,
// while the configured operator floor is 100, so that floor alone prevents
// pruning. An AsOf query at txTime 2000 advances the resolver's observed
// frontier; with backoff 400, InferHorizon raises the effective horizon to 1600
// and permits the older row to be pruned. A second AsOf must still return the
// newer row.
//
// The no-query control keeps the frontier at zero. Its horizon remains at the
// operator floor and both rows survive. Checking RowsPruned distinguishes the
// inferred horizon from a query that merely happens to select the newer row.

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

	// Write two versions with the same valid-time interval. SystemTime 250
	// dominates SystemTime 100.
	insertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, openInterval, []byte{'R'})
	insertRowInterval(t, alloc, lfs, flusher, entity, 250, 0, openInterval, []byte{'D'})

	// AsOf advances the observed transaction-time frontier before reading
	// storage. The query returns the newer row and leaves the frontier at 2000.
	resolver := database.NewResolver(lfs, lfs, alloc, "local", database.ResolverConfig{MaxL0Files: 1000})
	live, err := resolver.AsOf(ctx, entity, nsToTime(500), nsToTime(2000))
	require.NoError(t, err, "AsOf at txTime 2000 failed")
	assert.Equalf(t, []byte{'D'}, live.Payload, "AsOf returned %q, want the newer row D", live.Payload)
	// The resolver records this query's transaction time for horizon inference.
	if got := resolver.QueryTxTimeFrontier(); got != 2000 {
		t.Fatalf("observed frontier after AsOf = %d, want 2000", got)
	}

	// The observed frontier and backoff produce max(100, 2000-400) = 1600.
	// That horizon admits the newer row at SystemTime 250; the operator floor
	// alone would not.
	cfg := database.DefaultCompactionConfig()
	cfg.EnableDominancePruning = true
	cfg.PruningHorizonInt64Ns = 100 // the operator floor (below the dominator 250)
	cfg.PruneBackoffInt64Ns = 400   // the backoff
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "compact-bucket", cfg)

	// Check the inferred horizon directly before running compaction.
	assert.Equalf(t, int64(1600), compactor.EffectiveHorizon(2000),
		"EffectiveHorizon(2000) = %d, want max(100, 2000-400) = 1600", compactor.EffectiveHorizon(2000))

	// InferHorizon advances the compactor's horizon monotonically from the
	// resolver's observed frontier. Compaction then uses the inferred horizon.
	compactor.InferHorizon(resolver)
	// The configured horizon must now be 1600 rather than the operator floor.
	if got := compactor.Config().PruningHorizonInt64Ns; got != 1600 {
		t.Fatalf("horizon after InferHorizon = %d, want 1600 instead of operator floor 100", got)
	}
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err, "compaction failed")

	// A horizon of 1600 admits the newer row at SystemTime 250, allowing the
	// older row to be pruned. The operator floor alone would retain both rows.
	assert.Equalf(t, 1, res.RowsPruned, "RowsPruned = %d, want 1 with inferred horizon 1600", res.RowsPruned)
	assert.Equalf(t, 1, res.RowsAfter, "RowsAfter = %d, want only the newer row", res.RowsAfter)

	// The same live query must still return the newer row after pruning.
	resolverPost := database.NewResolver(lfs, lfs, alloc, "local", database.ResolverConfig{MaxL0Files: 1000})
	livePost, err := resolverPost.AsOf(ctx, entity, nsToTime(500), nsToTime(2000))
	require.NoError(t, err, "AsOf at txTime 2000 failed after pruning")
	assert.Equalf(t, []byte{'D'}, livePost.Payload, "AsOf after pruning returned %q, want D", livePost.Payload)
	assert.Equalf(t, int64(250), livePost.SystemTime, "pruned query did not return the newer row at SystemTime 250")

	t.Logf("observed frontier 2000 and backoff 400 advanced the horizon from 100 to 1600; compaction pruned the older row and preserved the query result")
}

// TestGCFloorInferRealLocalFSNoOpControl leaves the observed frontier at zero.
// The effective horizon therefore stays at the operator floor 100, below the
// newer row's SystemTime 250, so compaction must retain both rows.
func TestGCFloorInferRealLocalFSNoOpControl(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	flusher := database.NewL0Flusher(alloc, lfs, "compact-bucket")
	insertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, openInterval, []byte{'R'})
	insertRowInterval(t, alloc, lfs, flusher, entity, 250, 0, openInterval, []byte{'D'})

	// Without AsOf, the observed frontier remains zero. The backoff computes
	// max(100, 0-400), so the operator floor keeps the horizon at 100.
	resolver := database.NewResolver(lfs, lfs, alloc, "local", database.ResolverConfig{MaxL0Files: 1000})
	if got := resolver.QueryTxTimeFrontier(); got != 0 {
		t.Fatalf("fresh resolver frontier = %d, want 0 before any AsOf query", got)
	}

	cfg := database.DefaultCompactionConfig()
	cfg.EnableDominancePruning = true
	cfg.PruningHorizonInt64Ns = 100 // the operator floor (below the dominator 250)
	cfg.PruneBackoffInt64Ns = 400
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "compact-bucket", cfg)

	// The zero frontier produces the operator floor rather than an advance.
	assert.Equalf(t, int64(100), compactor.EffectiveHorizon(0),
		"EffectiveHorizon(0) = %d, want operator floor 100", compactor.EffectiveHorizon(0))

	compactor.InferHorizon(resolver)
	// InferHorizon must leave the configured horizon unchanged.
	if got := compactor.Config().PruningHorizonInt64Ns; got != 100 {
		t.Fatalf("horizon after InferHorizon without queries = %d, want operator floor 100", got)
	}
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)

	// SystemTime 250 is above horizon 100, so dominance pruning retains both
	// rows. The advancing-frontier test instead prunes the older row.
	assert.Equalf(t, 0, res.RowsPruned, "RowsPruned = %d, want 0 with horizon 100 below SystemTime 250", res.RowsPruned)
	assert.Equalf(t, 2, res.RowsAfter, "RowsAfter = %d, want both rows", res.RowsAfter)

	t.Logf("without an observed query frontier, the horizon remained at 100 and both rows survived")
}
