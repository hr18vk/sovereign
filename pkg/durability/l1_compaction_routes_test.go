// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These integration tests exercise dominance pruning through SkipListArena,
// L0Flusher, LocalFS, compaction, and Resolver.AsOf (ADR-0020). A row R can be
// pruned only when a retained row R' has a later system time, covers R's entire
// valid-time interval, and is visible at the pruning horizon T_gc.
//
// The tests cover each condition and the resulting reads. A dominator above the
// horizon or one with a narrower valid-time interval cannot replace R. Once
// all three conditions hold, pruning must preserve every query at or above T_gc;
// queries below that horizon are outside the pruning contract. Other tests
// compare preserve-all L1 bytes with the coerced default and verify that an
// enabled prune changes only the dominated rows. Pure pruning logic and fuzz
// coverage live in internal/database.
package durability

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertRowInterval writes one row with an explicit valid-time interval. Its
// key packs system time, valid-time start, and assertion time; the packed value
// carries valid-time end. Assertion time equals system time. Unlike insertRow,
// this helper allows a later assertion to cover a wider interval, which the
// dominance tests require.
func insertRowInterval(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, flusher *database.L0Flusher, entityID string, sysNs, validStartNs, validEndNs int64, payload []byte) {
	t.Helper()
	sl := database.NewSkipListArena(alloc, 2*1024*1024)
	fullHash := sha256.Sum256([]byte(entityID))
	key := make([]byte, 40)
	copy(key[0:16], fullHash[:16])
	putBE64(key[16:24], uint64(sysNs))
	putBE64(key[24:32], uint64(validStartNs))
	putBE64(key[32:40], uint64(sysNs)) // assertNs == sysNs
	pd := sha256.Sum256(payload)
	val := makePackedValue(entityID, 0x89283082803ffff, validEndNs, pd, payload)
	err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
	require.NoError(t, err)
	_, err = flusher.FlushFromArena(context.Background(), sl)
	require.NoError(t, err)
	sl.Free()
}

// compactWithHorizon compacts entity with the requested pruning policy and
// returns both the compaction result and a resolver over the same LocalFS.
// MaxL0Files is large enough to retain any uncompacted tail in subsequent reads.
func compactWithHorizon(t *testing.T, ctx context.Context, alloc *database.JemallocAllocator, lfs *LocalFS, entity string, enable bool, floor int64) (*database.CompactionResult, *database.Resolver) {
	t.Helper()
	h8 := database.EntityHash8(entity)
	cfg := database.DefaultCompactionConfig()
	cfg.EnableDominancePruning = enable
	cfg.PruningHorizonInt64Ns = floor
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "compact-bucket", cfg)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	// Use a resolver that can read the L1 and any uncompacted tail.
	resolver := database.NewResolver(lfs, lfs, alloc, "local", database.ResolverConfig{MaxL0Files: 1000})
	return res, resolver
}

// TestCompactionRouteTxTimeGapRedThenGreen uses R at system time 100 and D at
// 250, both valid over [0,1000). With horizon 200, D is not visible to every
// query covered by the horizon, so R must remain and a query at 150 returns R.
// With horizon 1000, D can replace R for all queries at or above the horizon.
// A query at 1000 returns D; a query at 150 may no longer return R because it
// lies below the pruning horizon.
const openInterval = int64(1_000) // valid-time interval [0,1000) shared by both rows

func TestCompactionRouteTxTimeGapRedThenGreen(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	flusher := database.NewL0Flusher(alloc, lfs, "compact-bucket")

	// R is older than D; both cover the same valid-time interval.
	insertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, openInterval, []byte{'R'})
	insertRowInterval(t, alloc, lfs, flusher, entity, 250, 0, openInterval, []byte{'D'})

	// Horizon 200 does not admit D, so R cannot be pruned.
	resLow, resolverLow := compactWithHorizon(t, ctx, alloc, lfs, entity, true, 200)
	assert.Equalf(t, 0, resLow.RowsPruned, "horizon 200 pruned %d rows; R must remain while D is above the horizon", resLow.RowsPruned)
	assert.Equalf(t, 2, resLow.RowsAfter, "low-horizon compaction returned %d rows, want 2", resLow.RowsAfter)

	// At transaction time 150, only R is visible.
	gap, err := resolverLow.AsOf(ctx, entity, nsToTime(500), nsToTime(150))
	require.NoError(t, err, "query at transaction time 150 failed")
	assert.Equalf(t, []byte{'R'}, gap.Payload, "query at 150 returned %q, want R", gap.Payload)
	assert.Equalf(t, int64(100), gap.SystemTime, "query at 150 did not return R (SystemTime=100)")
	t.Logf("horizon 200 retained R; query at 150 returned R (SystemTime=100)")

	// Use a fresh store for horizon 1000 so the second L1 is unambiguous. D is
	// then visible throughout the live query range and can replace R.
	lfs2 := newLocalFS(t)
	flusher2 := database.NewL0Flusher(alloc, lfs2, "compact-bucket")
	insertRowInterval(t, alloc, lfs2, flusher2, entity, 100, 0, openInterval, []byte{'R'})
	insertRowInterval(t, alloc, lfs2, flusher2, entity, 250, 0, openInterval, []byte{'D'})
	resHigh, resolverHigh := compactWithHorizon(t, ctx, alloc, lfs2, entity, true, 1000)
	assert.Equalf(t, 1, resHigh.RowsPruned, "horizon 1000 pruned %d rows, want R pruned", resHigh.RowsPruned)
	assert.Equalf(t, 1, resHigh.RowsAfter, "high-horizon compaction returned %d rows, want only D", resHigh.RowsAfter)

	// At transaction time 1000, both preserve-all and pruned compactions select D.
	live, err := resolverHigh.AsOf(ctx, entity, nsToTime(500), nsToTime(1000))
	require.NoError(t, err, "query at transaction time 1000 failed after pruning")
	assert.Equalf(t, []byte{'D'}, live.Payload, "query at 1000 returned %q, want D", live.Payload)
	assert.Equalf(t, int64(250), live.SystemTime, "query at 1000 did not return D (SystemTime=250)")

	// Below the horizon, R has been pruned and D is not yet visible, so this
	// query returns ErrEntityNotFound. Callers must not issue such queries after
	// choosing the horizon; the low-horizon case above preserves R instead.
	_, gapErr := resolverHigh.AsOf(ctx, entity, nsToTime(500), nsToTime(150))
	t.Logf("below-horizon query at 150 returned %v after R was pruned", gapErr)
}

// TestCompactionRouteContainmentRedThenGreen checks valid-time containment.
// A newer D with interval [200,800) cannot replace R with [0,1000): a query at
// valid time 10 still needs R. Reversing the widths lets D cover R completely;
// with horizon 1000, R can then be pruned and a covered query returns D.
func TestCompactionRouteContainmentRedThenGreen(t *testing.T) {
	ctx := context.Background()

	// A narrower D cannot cover R's valid-time interval.
	lfsA := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "beta"
	flusherA := database.NewL0Flusher(alloc, lfsA, "compact-bucket")
	insertRowInterval(t, alloc, lfsA, flusherA, entity, 100, 0, 1000, []byte{'R'})  // wider
	insertRowInterval(t, alloc, lfsA, flusherA, entity, 250, 200, 800, []byte{'D'}) // narrower dominator
	resA, resolverA := compactWithHorizon(t, ctx, alloc, lfsA, entity, true, 1000)
	assert.Equalf(t, 0, resA.RowsPruned, "narrower D pruned %d rows; R must remain", resA.RowsPruned)
	// Valid time 10 lies outside D but inside R.
	boundary, err := resolverA.AsOf(ctx, entity, nsToTime(10), nsToTime(1000))
	require.NoError(t, err, "boundary query at valid time 10 failed")
	assert.Equalf(t, []byte{'R'}, boundary.Payload, "boundary query returned %q, want R", boundary.Payload)
	t.Logf("narrower D retained R; valid time 10 resolved to R")

	// A wider, horizon-admitted D covers R and can replace it.
	lfsB := newLocalFS(t)
	flusherB := database.NewL0Flusher(alloc, lfsB, "compact-bucket")
	insertRowInterval(t, alloc, lfsB, flusherB, entity, 100, 200, 800, []byte{'R'}) // narrower (to be dropped)
	insertRowInterval(t, alloc, lfsB, flusherB, entity, 250, 0, 1000, []byte{'D'})  // wider dominator
	resB, resolverB := compactWithHorizon(t, ctx, alloc, lfsB, entity, true, 1000)
	assert.Equalf(t, 1, resB.RowsPruned, "wider D pruned %d rows, want R pruned", resB.RowsPruned)
	// Both rows cover valid time 500, and newer D must win.
	covered, err := resolverB.AsOf(ctx, entity, nsToTime(500), nsToTime(1000))
	require.NoError(t, err, "covered query at valid time 500 failed")
	assert.Equalf(t, []byte{'D'}, covered.Payload, "covered query returned %q, want D", covered.Payload)
	t.Logf("wider D pruned R; valid time 500 resolved to D")
}

// TestCompactionPreserveAllByteIdenticalDefault compares the default pruning
// configuration with enabled pruning at a non-positive horizon, which the
// compactor coerces to preserve-all with a warning. Both must retain all three
// rows and produce identical L1 bytes. A third compaction at horizon 1000 keeps
// only the newest row, proving that enabled pruning changes the L1.
func TestCompactionPreserveAllByteIdenticalDefault(t *testing.T) {
	ctx := context.Background()
	const entity = "gamma"

	writeRows := func(lfs *LocalFS, alloc *database.JemallocAllocator) {
		flusher := database.NewL0Flusher(alloc, lfs, "compact-bucket")
		// Three rows share [0,1000) and have increasing system times.
		insertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, 1000, []byte{'A'})
		insertRowInterval(t, alloc, lfs, flusher, entity, 200, 0, 1000, []byte{'B'})
		insertRowInterval(t, alloc, lfs, flusher, entity, 300, 0, 1000, []byte{'C'})
	}

	// Default compaction preserves every row.
	lfsA := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	writeRows(lfsA, alloc)
	resA, _ := compactWithHorizon(t, ctx, alloc, lfsA, entity, false, 0)
	require.Equalf(t, 0, resA.RowsPruned, "default compaction pruned %d rows", resA.RowsPruned)
	require.Equalf(t, 3, resA.RowsAfter, "default compaction returned %d rows, want 3", resA.RowsAfter)
	l1BytesA := readObject(t, lfsA, resA.L1Key)

	// Enabled pruning with a non-positive horizon is coerced to preserve-all.
	lfsB := newLocalFS(t)
	writeRows(lfsB, alloc)
	resB, _ := compactWithHorizon(t, ctx, alloc, lfsB, entity, true, 0)
	require.Equalf(t, 0, resB.RowsPruned, "coerced compaction pruned %d rows", resB.RowsPruned)
	require.Equalf(t, 3, resB.RowsAfter, "coerced compaction returned %d rows, want 3", resB.RowsAfter)
	l1BytesB := readObject(t, lfsB, resB.L1Key)

	// Default and coerced preserve-all compaction must produce identical bytes.
	assert.True(t, bytesEqual(l1BytesA, l1BytesB),
		"default and coerced preserve-all L1 bytes differ")
	t.Logf("default and coerced preserve-all produced identical %d-byte L1s", len(l1BytesA))

	// At horizon 1000, newest C dominates A and B over their shared interval.
	lfsC := newLocalFS(t)
	writeRows(lfsC, alloc)
	resC, _ := compactWithHorizon(t, ctx, alloc, lfsC, entity, true, 1000)
	require.Equalf(t, 2, resC.RowsPruned, "enabled pruning removed %d rows, want 2", resC.RowsPruned)
	require.Equalf(t, 1, resC.RowsAfter, "enabled pruning returned %d rows, want only C", resC.RowsAfter)
	l1BytesC := readObject(t, lfsC, resC.L1Key)
	assert.False(t, bytesEqual(l1BytesA, l1BytesC),
		"pruned L1 unexpectedly matches preserve-all bytes")
	t.Logf("horizon 1000 pruned A and B; L1 retained only C")
}

// TestCompactionLiveQueryEquivalence compares preserve-all and pruned L1s for
// four rows with shared valid-time interval [0,1000) and system times 100
// through 400. At horizon 1000, only D survives pruning. Across several valid
// times and transaction times at or above the horizon, both resolvers must
// return the same payload and SystemTime.
func TestCompactionLiveQueryEquivalence(t *testing.T) {
	ctx := context.Background()
	const entity = "delta"

	writeRows := func(lfs *LocalFS, alloc *database.JemallocAllocator) {
		flusher := database.NewL0Flusher(alloc, lfs, "compact-bucket")
		insertRowInterval(t, alloc, lfs, flusher, entity, 100, 0, 1000, []byte{'A'})
		insertRowInterval(t, alloc, lfs, flusher, entity, 200, 0, 1000, []byte{'B'})
		insertRowInterval(t, alloc, lfs, flusher, entity, 300, 0, 1000, []byte{'C'})
		insertRowInterval(t, alloc, lfs, flusher, entity, 400, 0, 1000, []byte{'D'})
	}

	// Preserve all rows in the reference store.
	lfsPA := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	writeRows(lfsPA, alloc)
	resPA, resolverPA := compactWithHorizon(t, ctx, alloc, lfsPA, entity, false, 0)
	require.Equalf(t, 0, resPA.RowsPruned, "reference compaction pruned %d rows", resPA.RowsPruned)
	require.Equalf(t, 4, resPA.RowsAfter, "reference compaction returned %d rows, want 4", resPA.RowsAfter)

	// Prune the same input at horizon 1000 in a separate store.
	lfsPR := newLocalFS(t)
	writeRows(lfsPR, alloc)
	resPR, resolverPR := compactWithHorizon(t, ctx, alloc, lfsPR, entity, true, 1000)
	require.Equalf(t, 3, resPR.RowsPruned, "pruned compaction removed %d rows, want 3", resPR.RowsPruned)
	require.Equalf(t, 1, resPR.RowsAfter, "pruned compaction returned %d rows, want only D", resPR.RowsAfter)

	// Sweep valid times within [0,1000) at transaction times at or above the
	// horizon. Both resolvers must return the same dominant row.
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
		require.NoErrorf(t, errPA, "%s: preserve-all AsOf failed at txTime=%d", p.name, p.tx)
		gotPR, errPR := resolverPR.AsOf(ctx, entity, nsToTime(p.v), nsToTime(p.tx))
		require.NoErrorf(t, errPR, "%s: pruned AsOf failed at txTime=%d", p.name, p.tx)
		assert.Equalf(t, gotPA.Payload, gotPR.Payload, "%s: payload differs between preserve-all and pruned results", p.name)
		assert.Equalf(t, gotPA.SystemTime, gotPR.SystemTime, "%s: SystemTime differs between preserve-all and pruned results", p.name)
		t.Logf("%s: preserve-all=(%q, sys=%d), pruned=(%q, sys=%d)", p.name, gotPA.Payload, gotPA.SystemTime, gotPR.Payload, gotPR.SystemTime)
	}
}

// nsToTime converts Unix nanoseconds to the time.Time expected by AsOf.
func nsToTime(ns int64) time.Time { return time.Unix(0, ns).UTC() }

// bytesEqual compares length and content without importing bytes for one helper.
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
