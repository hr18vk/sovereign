// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// This integration test exercises the DominancePrune interval sweep through
// SkipListArena, L0Flusher, LocalFS, compaction, and Resolver.AsOf (ADR-0025).
// Pure sweep behavior and performance are covered in internal/database.
//
// Four rows share a valid-time interval and have increasing system times. A
// pruning horizon above the newest row lets the sweep discard the three older
// rows. Queries at or above the horizon must still match a preserve-all
// compaction. Comparing both results also catches corruption in the ordered
// column-append loop that builds the pruned L1.
package durability

import (
	"context"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompactionSweepLiveQueryEquivalenceByteIdentical compares preserve-all
// and sweep-pruned compactions of four rows with system times 100 through 400
// and valid-time interval [0,1000). With horizon 1000, only D survives pruning;
// every query at or above the horizon must return the same result from both L1s.
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

	// Preserve every row with the default compaction policy.
	lfsPA := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	writeRows(lfsPA, alloc)
	resPA, resolverPA := compactWithHorizon(t, ctx, alloc, lfsPA, entity, false, 0)
	require.Equalf(t, 0, resPA.RowsPruned, "preserve-all compaction pruned %d rows", resPA.RowsPruned)
	require.Equalf(t, 4, resPA.RowsAfter, "preserve-all compaction returned %d rows, want 4", resPA.RowsAfter)

	// Compact a fresh store with horizon 1000 to enable the interval sweep.
	lfsPR := newLocalFS(t)
	writeRows(lfsPR, alloc)
	resPR, resolverPR := compactWithHorizon(t, ctx, alloc, lfsPR, entity, true, 1000)
	require.Equalf(t, 3, resPR.RowsPruned, "sweep pruned %d rows, want 3", resPR.RowsPruned)
	require.Equalf(t, 1, resPR.RowsAfter, "sweep returned %d rows, want only D", resPR.RowsAfter)

	// Probe valid times within [0,1000) at transaction times at or above the
	// pruning horizon. Both resolvers must return the same dominant row.
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
		require.NoErrorf(t, errPA, "%s: preserve-all AsOf failed at txTime=%d", p.name, p.tx)
		gotPR, errPR := resolverPR.AsOf(ctx, entity, nsToTime20(p.v), nsToTime20(p.tx))
		require.NoErrorf(t, errPR, "%s: sweep-pruned AsOf failed at txTime=%d", p.name, p.tx)
		assert.Equalf(t, gotPA.Payload, gotPR.Payload, "%s: payload differs between preserve-all and pruned results", p.name)
		assert.Equalf(t, gotPA.SystemTime, gotPR.SystemTime, "%s: SystemTime differs between preserve-all and pruned results", p.name)
		// D is the newest visible row in both sets and the only pruned survivor.
		require.Equalf(t, []byte{'D'}, gotPR.Payload, "%s: pruned result is not D", p.name)
		t.Logf("%s: preserve-all=(%q, sys=%d), pruned=(%q, sys=%d)", p.name, gotPA.Payload, gotPA.SystemTime, gotPR.Payload, gotPR.SystemTime)
	}
}

// nsToTime20 converts Unix nanoseconds to the time.Time expected by AsOf. Its
// distinct name avoids colliding with nsToTime in the compaction route tests.
func nsToTime20(ns int64) time.Time { return time.Unix(0, ns).UTC() }
