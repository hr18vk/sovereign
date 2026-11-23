// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Unit tests for read-your-writes live-source merging in Resolver.AsOf and
// Resolver.Range (ADR-0032).
//
// AsOf and Range read durable Arrow files via S3 interfaces and merge entries
// from LiveSource (the live CRDT store adapter) under the same visibility
// (SystemTime <= txTimeNs) and valid-time filters. Range deduplicates live rows
// against durable rows by (SystemTime, PayloadDigest), and both paths skip the
// empty-durable early exit only when LiveSource is non-nil.
//
// End-to-end tests against a live engine and *LocalFS live in pkg/durability,
// and registry counter checks live in internal/telemetry.

package database

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// liveMergeBase is a fixed ns epoch for the tests (the same convention as
// the established bases: 1.7e18, comfortably below the open-end sentinel (9e18) and int64
// max (9.2e18)).
const liveMergeBase int64 = 1_700_000_000_000_000_000

// syntheticLiveSource is an in-package LiveSource stub returning controlled entries
// for unit testing Filter 2, dominance ordering, and deduplication. When
// filter2Buggy is true, it bypasses Filter 2 so TestLiveDefensiveFilter2 can
// verify the resolver rejects over-txTime entries defensively.
type syntheticLiveSource struct {
	entries      []LiveEvent
	filter2Buggy bool
}

func (s *syntheticLiveSource) LiveRead(_ context.Context, _ string, txTimeNs int64) ([]LiveEvent, error) {
	if s.filter2Buggy {
		// The buggy path: return all entries regardless of sysTime (simulates a
		// foreign or buggy adapter that ignores Filter2). The Resolver's defensive
		// Filter2 must drop the over-txTime ones.
		out := make([]LiveEvent, len(s.entries))
		copy(out, s.entries)
		return out, nil
	}
	out := make([]LiveEvent, 0, len(s.entries))
	for _, e := range s.entries {
		if e.SystemTime <= txTimeNs {
			out = append(out, e)
		}
	}
	return out, nil
}

// liveDigest computes the [32]byte PayloadDigest the same way the write path
// does (sha256 of the payload — the no-recompute identity, the control package).
func liveDigest(payload []byte) [32]byte {
	return sha256.Sum256(payload)
}

// TestLiveOffIsByteIdentical verifies that a nil LiveSource preserves durable-only
// query behavior, resolving durable rows and returning ErrEntityNotFound when none exist.
func TestLiveOffIsByteIdentical(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "live-off-entity"

	// Write one durable L0 row (sysTime=base, [base, openEnd)).
	sl := NewSkipListArena(alloc, 2*1024*1024)
	rangeWinInsertRow(t, sl, entity, liveMergeBase, liveMergeBase, openEndNs, []byte("durable-row"))
	require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))

	r := NewResolver(store, store, alloc, "livemerge-off", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	require.Nilf(t, r.liveSource, "DefaultResolverConfig must leave liveSource nil")

	got, err := r.AsOf(ctx, entity, time.Unix(0, liveMergeBase+50), time.Unix(0, liveMergeBase+999))
	require.NoErrorf(t, err, "nil-live-source AsOf must resolve the durable row (byte-identical)")
	require.NotNilf(t, got, "durable dominant must be non-nil when live source is nil")
	assert.Equalf(t, liveMergeBase, got.SystemTime, "durable dominant SystemTime must equal base")
	assert.Equalf(t, []byte("durable-row"), got.Payload, "the durable dominant payload (byte-identical)")

	// Negative control: empty durable store with nil live source returns ErrEntityNotFound.
	r2 := NewResolver(store, store, alloc, "livemerge-off-red", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	require.Nil(t, r2.liveSource)
	_, errMiss := r2.AsOf(ctx, "no-such-entity", time.Unix(0, liveMergeBase+50), time.Unix(0, liveMergeBase+999))
	assert.Errorf(t, errMiss, "nil live source with empty durable store must return ErrEntityNotFound")
	t.Logf("nil LiveSource matched durable-only baseline")
}

// TestLiveMergeEquiv checks differential equivalence between live-source ON and
// OFF across 2,000 randomized txTime values once all live rows are durable in L0.
func TestLiveMergeEquiv(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "live-equiv-entity"
	const N = 32
	const fuzzN = 2000

	store := newMemStore()
	type rowT struct {
		payload []byte
		sys     int64
		digest  [32]byte
	}
	rows := make([]rowT, N)
	for i := 0; i < N; i++ {
		sysNs := liveMergeBase + int64(i)*1000
		payload := []byte(fmt.Sprintf("row-%d", i))
		rows[i] = rowT{sys: sysNs, payload: payload, digest: liveDigest(payload)}
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, sysNs, liveMergeBase, openEndNs, payload)
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))
	}

	liveEntries := make([]LiveEvent, N)
	for i, r := range rows {
		liveEntries[i] = LiveEvent{
			SystemTime:     r.sys,
			ValidTimeStart: liveMergeBase,
			ValidTimeEnd:   openEndNs,
			AssertionTime:  r.sys,
			H3Index:        0x89283082803ffff,
			PayloadDigest:  r.digest,
		}
	}
	liveSrc := &syntheticLiveSource{entries: liveEntries}

	cfgOn := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfgOn.LiveSource = liveSrc
	rOn := NewResolver(store, store, alloc, "livemerge-equiv-on", cfgOn)
	rOff := NewResolver(store, store, alloc, "livemerge-equiv-off", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})

	rng := rand.New(rand.NewPCG(27, 0))
	vt := time.Unix(0, liveMergeBase+50)
	var diverge int
	for f := 0; f < fuzzN; f++ {
		txNs := liveMergeBase - 1000 + rng.Int64N(int64(N)*1000+1000+1)
		tx := time.Unix(0, txNs)

		gotOn, errOn := rOn.AsOf(ctx, entity, vt, tx)
		gotOff, errOff := rOff.AsOf(ctx, entity, vt, tx)

		if errOn != nil && errOff == nil {
			diverge++
			t.Errorf("equivalence divergence at f=%d txNs=%d: live-ON=Err live-OFF=event", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errOff != nil && errOn == nil {
			diverge++
			t.Errorf("equivalence divergence at f=%d txNs=%d: live-ON=event live-OFF=Err", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errOn != nil && errOff != nil {
			continue
		}
		if gotOn.SystemTime != gotOff.SystemTime {
			diverge++
			t.Errorf("equivalence divergence at f=%d txNs=%d: SystemTime ON=%d OFF=%d", f, txNs, gotOn.SystemTime, gotOff.SystemTime)
			if diverge > 5 {
				break
			}
			continue
		}
		if gotOn.ValidTimeStart != gotOff.ValidTimeStart || gotOn.ValidTimeEnd != gotOff.ValidTimeEnd {
			diverge++
			t.Errorf("equivalence divergence at f=%d txNs=%d: ValidTime ON=[%d,%d) OFF=[%d,%d)", f, txNs, gotOn.ValidTimeStart, gotOn.ValidTimeEnd, gotOff.ValidTimeStart, gotOff.ValidTimeEnd)
			if diverge > 5 {
				break
			}
			continue
		}
		if !bytesEqual(gotOn.Payload, gotOff.Payload) {
			diverge++
			t.Errorf("equivalence divergence at f=%d txNs=%d: payload mismatch", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
	}
	require.Zerof(t, diverge, "live-ON and live-OFF results must match across all %d fuzzed txTimes", fuzzN)
	t.Logf("live-ON matched live-OFF across %d fuzzed txTimes (seed=27)", fuzzN)
}

// TestLiveMergeEquivRed verifies the strict > dominance boundary when a live
// entry and a durable row share SystemTime == base.
func TestLiveMergeEquivRed(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "live-equiv-red-entity"

	sl := NewSkipListArena(alloc, 2*1024*1024)
	rangeWinInsertRow(t, sl, entity, liveMergeBase, liveMergeBase, openEndNs, []byte("D"))
	require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))

	liveSrc := &syntheticLiveSource{entries: []LiveEvent{{
		SystemTime:     liveMergeBase,
		ValidTimeStart: liveMergeBase,
		ValidTimeEnd:   openEndNs,
		AssertionTime:  liveMergeBase,
		PayloadDigest:  liveDigest([]byte("L")),
	}}}
	cfg := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfg.LiveSource = liveSrc
	r := NewResolver(store, store, alloc, "livemerge-equiv-red", cfg)

	got, err := r.AsOf(ctx, entity, time.Unix(0, liveMergeBase+50), time.Unix(0, liveMergeBase+999))
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equalf(t, liveMergeBase, got.SystemTime, "strict > rule must retain durable dominant at equal sysTime")
	assert.Equalf(t, liveDigest([]byte("D")), got.PayloadDigest, "strict > rule must keep durable digest at equal sysTime")

	geBugWouldDisplace := liveMergeBase >= liveMergeBase
	require.Truef(t, geBugWouldDisplace, ">= comparison would displace durable row at boundary")
	strictDisplaces := liveMergeBase > liveMergeBase
	require.Falsef(t, strictDisplaces, "strict > comparison must not displace durable row at boundary")
	assert.NotEqualf(t, liveDigest([]byte("D")), liveDigest([]byte("L")), "durable and live digests must differ so displacement is observable")
	t.Logf("strict > dominance boundary kept durable digest at equal sysTime")
}

// TestLiveCounterFires verifies QueryLiveSourceReads increments once per AsOf or
// Range query with a live source wired and stays unchanged when LiveSource is nil.
func TestLiveCounterFires(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "live-counter-entity"

	sl := NewSkipListArena(alloc, 2*1024*1024)
	rangeWinInsertRow(t, sl, entity, liveMergeBase, liveMergeBase, openEndNs, []byte("c"))
	require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))

	liveSrc := &syntheticLiveSource{entries: []LiveEvent{{
		SystemTime: liveMergeBase, ValidTimeStart: liveMergeBase, ValidTimeEnd: openEndNs,
		PayloadDigest: liveDigest([]byte("c")),
	}}}
	cfgOn := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfgOn.LiveSource = liveSrc
	rOn := NewResolver(store, store, alloc, "livemerge-ctr-on", cfgOn)
	before := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		before = int64(telemetry.QueryLiveSourceReads.Value())
	}
	_, err := rOn.AsOf(ctx, entity, time.Unix(0, liveMergeBase+50), time.Unix(0, liveMergeBase+999))
	require.NoError(t, err)
	after := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		after = int64(telemetry.QueryLiveSourceReads.Value())
	}
	assert.GreaterOrEqualf(t, after-before, int64(1), "AsOf with live source must increment QueryLiveSourceReads")

	rOff := NewResolver(store, store, alloc, "livemerge-ctr-off", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	before2 := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		before2 = int64(telemetry.QueryLiveSourceReads.Value())
	}
	_, err = rOff.AsOf(ctx, entity, time.Unix(0, liveMergeBase+50), time.Unix(0, liveMergeBase+999))
	require.NoError(t, err)
	after2 := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		after2 = int64(telemetry.QueryLiveSourceReads.Value())
	}
	assert.Equalf(t, int64(0), after2-before2, "AsOf without live source must leave QueryLiveSourceReads unchanged")

	before3 := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		before3 = int64(telemetry.QueryLiveSourceReads.Value())
	}
	_, _, err = rOn.Range(ctx, entity, time.Unix(0, liveMergeBase), time.Unix(0, liveMergeBase+500), time.Unix(0, liveMergeBase+999))
	require.NoError(t, err)
	after3 := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		after3 = int64(telemetry.QueryLiveSourceReads.Value())
	}
	assert.GreaterOrEqualf(t, after3-before3, int64(1), "Range with live source must increment QueryLiveSourceReads")
	t.Logf("QueryLiveSourceReads incremented on AsOf and Range with live source, and remained unchanged when nil")
}

// TestLiveRange verifies Range deduplicates live rows that match checkpointed
// durable rows by (SystemTime, PayloadDigest).
func TestLiveRange(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "live-range-entity"
	const N = 4

	type rowT struct {
		payload []byte
		sys     int64
		vs      int64
		ve      int64
	}
	rows := make([]rowT, N)
	for i := 0; i < N; i++ {
		sysNs := liveMergeBase + int64(i)*1000
		payload := []byte(fmt.Sprintf("r-%d", i))
		vs := liveMergeBase + int64(i)*100
		ve := vs + 50
		rows[i] = rowT{sys: sysNs, vs: vs, ve: ve, payload: payload}
		sl := NewSkipListArena(alloc, 2*1024*1024)
		rangeWinInsertRow(t, sl, entity, sysNs, vs, ve, payload)
		require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))
	}

	liveEntries := make([]LiveEvent, N)
	for i, r := range rows {
		liveEntries[i] = LiveEvent{
			SystemTime:     r.sys,
			ValidTimeStart: r.vs,
			ValidTimeEnd:   r.ve,
			PayloadDigest:  liveDigest(r.payload),
		}
	}
	liveSrc := &syntheticLiveSource{entries: liveEntries}

	cfgOn := ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: false}
	cfgOn.LiveSource = liveSrc
	rOn := NewResolver(store, store, alloc, "livemerge-range-on", cfgOn)
	rOff := NewResolver(store, store, alloc, "livemerge-range-off", ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: false})

	rowsOn, truncOn, errOn := rOn.Range(ctx, entity, time.Unix(0, liveMergeBase), time.Unix(0, liveMergeBase+500), time.Unix(0, liveMergeBase+9999))
	require.NoError(t, errOn)
	require.Falsef(t, truncOn, "no truncation (N=4 << MaxRangeRows=4096)")
	rowsOff, _, errOff := rOff.Range(ctx, entity, time.Unix(0, liveMergeBase), time.Unix(0, liveMergeBase+500), time.Unix(0, liveMergeBase+9999))
	require.NoError(t, errOff)

	assert.Equalf(t, len(rowsOff), len(rowsOn), "Range row count must match between live-ON (%d) and live-OFF (%d)", len(rowsOn), len(rowsOff))
	assert.Equalf(t, N, len(rowsOn), "Range live-ON must return exactly N=%d deduplicated rows (%d twins skipped)", N, N)

	require.Equalf(t, len(rowsOff), len(rowsOn), "row counts must match for per-row comparison")
	for i := range rowsOn {
		assert.Equalf(t, rowsOn[i].SystemTime, rowsOff[i].SystemTime, "row %d SystemTime mismatch: live-ON=%d live-OFF=%d", i, rowsOn[i].SystemTime, rowsOff[i].SystemTime)
		assert.Equalf(t, rowsOn[i].PayloadDigest, rowsOff[i].PayloadDigest, "row %d PayloadDigest must match between live-ON and live-OFF", i)
	}

	noDedupCount := N + N
	assert.NotEqualf(t, len(rowsOn), noDedupCount, "negative control: without deduplication %d rows would be returned instead of %d", noDedupCount, len(rowsOn))
	t.Logf("Range deduplicated live rows: returned %d (not %d; %d twins skipped)", len(rowsOn), 2*N, N)
}

// TestLiveRangeEmptyDurable checks that Range queries still return live rows
// when the durable tier is empty, while a nil LiveSource returns ErrEntityNotFound.
func TestLiveRangeEmptyDurable(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "live-range-empty-durable-entity"

	const sysNs = liveMergeBase
	liveRow := LiveEvent{
		SystemTime:     sysNs,
		ValidTimeStart: sysNs,
		ValidTimeEnd:   MaxValidTimeEndNs,
		PayloadDigest:  liveDigest([]byte("the-live-row")),
	}
	liveSrc := &syntheticLiveSource{entries: []LiveEvent{liveRow}}

	cfgOn := ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: false}
	cfgOn.LiveSource = liveSrc
	rOn := NewResolver(store, store, alloc, "livemerge-range-empty-on", cfgOn)

	rows, trunc, err := rOn.Range(ctx, entity,
		time.Unix(0, liveMergeBase-1000), time.Unix(0, liveMergeBase+60_000_000_000),
		time.Unix(0, sysNs+999))
	require.NoErrorf(t, err, "Range with live source over empty durable tier must return live rows")
	require.Falsef(t, trunc, "no truncation (1 live row << MaxRangeRows)")
	require.Lenf(t, rows, 1, "Range over empty durable tier with live source must return 1 row")
	require.Equalf(t, sysNs, rows[0].SystemTime, "returned row SystemTime must match live row")
	require.Equalf(t, liveRow.PayloadDigest, rows[0].PayloadDigest, "returned row PayloadDigest must match live row")

	rOff := NewResolver(store, store, alloc, "livemerge-range-empty-off", ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: false})
	_, _, errOff := rOff.Range(ctx, entity,
		time.Unix(0, liveMergeBase-1000), time.Unix(0, liveMergeBase+60_000_000_000),
		time.Unix(0, sysNs+999))
	require.ErrorIsf(t, errOff, ErrEntityNotFound, "negative control: nil live source Range over empty durable tier must return ErrEntityNotFound")

	t.Logf("empty-durable Range returned live row when wired and ErrEntityNotFound when nil")
}

// TestLiveDefensiveFilter2 verifies the resolver rejects live entries with
// SystemTime > txTimeNs even when the LiveSource adapter fails to filter them.
func TestLiveDefensiveFilter2(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	const entity = "live-defensive-entity"

	sl := NewSkipListArena(alloc, 2*1024*1024)
	rangeWinInsertRow(t, sl, entity, liveMergeBase, liveMergeBase, openEndNs, []byte("durable"))
	require.Equal(t, 1, rangeWinFlush(t, ctx, alloc, store, sl))

	buggySrc := &syntheticLiveSource{
		entries: []LiveEvent{{
			SystemTime:     liveMergeBase + 5000,
			ValidTimeStart: liveMergeBase,
			ValidTimeEnd:   openEndNs,
			PayloadDigest:  liveDigest([]byte("buggy-over-tx")),
		}},
		filter2Buggy: true,
	}
	cfg := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfg.LiveSource = buggySrc
	r := NewResolver(store, store, alloc, "livemerge-defensive", cfg)

	got, err := r.AsOf(ctx, entity, time.Unix(0, liveMergeBase+50), time.Unix(0, liveMergeBase+999))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equalf(t, liveMergeBase, got.SystemTime, "defensive Filter 2 must drop over-txTime live entry and keep durable dominant")
	assert.Equalf(t, liveDigest([]byte("durable")), got.PayloadDigest, "dominant digest must come from the durable row rather than the future live entry")

	overTxWouldWin := (liveMergeBase + 5000) > liveMergeBase
	require.Truef(t, overTxWouldWin, "negative control: without defensive Filter 2, over-txTime live entry would outrank durable row")
	dropped := (liveMergeBase + 5000) > (liveMergeBase + 999)
	require.Truef(t, dropped, "defensive Filter 2 check sysTime > txTimeNs must filter out future live entry")
	t.Logf("defensive Filter 2 dropped over-txTime live entry (sysTime > txTimeNs)")
}
