// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// These integration tests connect Resolver's live source to a real CRDT engine
// and LocalFS (ADR-0032). An entry inserted with InsertLocal must be visible to
// AsOf before a checkpoint writes it to L0. After an equivalent durable row is
// flushed, the query must return the same digest.
//
// TestLiveReadYourWritesEBRRace runs concurrent AsOf and InsertLocal calls.
// LiveRead holds an EBR pin while iterating State().Get results so replacement
// of a shard root cannot reclaim memory still in use. Run this test with -race.
//
// The adapter mirrors engineHAMTAdapter in cmd/sovereign-node. It is duplicated
// here because package main cannot be imported and internal/database cannot
// import pkg/sync. Pure live-merge and telemetry behavior is tested in those
// packages.

package durability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLiveAdapter implements database.LiveSource with the same EBR sequence,
// State().Get lookup, system-time visibility check, and field mapping as
// engineHAMTAdapter in cmd/sovereign-node. Keeping those operations aligned is
// essential: divergence would test the adapter rather than production behavior.
//
// State materializes an O(total entries) merged view and retires the previous
// view through EBR. The tests use small working sets because concurrent readers
// can retain several such views during the grace period.
type testLiveAdapter struct {
	engine *eng.DeltaCRDTEngine
}

func (a *testLiveAdapter) LiveRead(_ context.Context, entityID string, txTimeNs int64) ([]database.LiveEvent, error) {
	if a == nil || a.engine == nil {
		return nil, nil
	}
	ebr := a.engine.EBR()
	participant := ebr.Acquire()
	participant.Enter(ebr)
	defer ebr.Release(participant)

	state := a.engine.State()
	if state == nil {
		return nil, nil
	}
	entries := state.Get(entityID)
	out := make([]database.LiveEvent, 0, len(entries))
	for i := range entries {
		e := entries[i]
		// Entries after txTimeNs are not visible to this query.
		if e.SystemTime > txTimeNs {
			continue
		}
		out = append(out, database.LiveEvent{
			SystemTime:     e.SystemTime,
			ValidTimeStart: e.ValidTimeStart,
			ValidTimeEnd:   e.ValidTimeEnd,
			AssertionTime:  e.AssertionTime,
			H3Index:        e.H3Index,
			PayloadDigest:  e.PayloadDigest,
			// CRDTEntry stores the payload digest, not the payload body.
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Read-your-writes over live and durable state.
// ---------------------------------------------------------------------------

// TestLiveReadYourWrites inserts into the live HAMT and resolves the entry
// before any durable files exist. It repeats the query without a live source as
// a negative control, then flushes an equivalent L0 row and verifies that the
// live and durable results carry the same digest (ADR-0032).
func TestLiveReadYourWrites(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "live-rw-entity"

	// The engine supplies live state; LocalFS is initially empty and supplies
	// durable state after the explicit flush below.
	engine, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, testArenaSize)
	require.NoError(t, err, "NewDeltaCRDTEngine: the live HAMT")

	// The write path identifies the payload by its SHA-256 digest.
	payload := []byte("live-row")
	digest := sha256.Sum256(payload)

	// Build the temporal fields normally supplied by the write path. The valid-
	// time interval includes baseSysNs+50; InsertLocal supplies the dot fields.
	const baseSysNs int64 = 1_700_000_000_000_000_000
	const openEnd int64 = 9_000_000_000_000_000_000
	entry := eng.CRDTEntry{
		PayloadDigest:  digest,
		SystemTime:     baseSysNs,
		ValidTimeStart: baseSysNs,
		ValidTimeEnd:   openEnd,
		AssertionTime:  baseSysNs,
		H3Index:        0x89283082803ffff,
	}
	// Insert locally without creating a checkpoint or WAL entry.
	dot := engine.InsertLocal(entity, entry)
	if dot == (eng.CausalDot{}) {
		t.Fatalf("InsertLocal returned a zero dot (the engine refused the write)")
	}

	// Disable firstSys skipping to isolate live-source behavior; no durable
	// objects exist yet.
	cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfg.LiveSource = &testLiveAdapter{engine: engine}
	resolver := database.NewResolver(lfs, lfs, alloc, "ryw-bucket", cfg)

	// With no durable files, a nil live source returns ErrEntityNotFound. The
	// configured live source instead supplies the dominant from the HAMT.
	live, err := resolver.AsOf(ctx, entity, time.Unix(0, baseSysNs+50), time.Unix(0, baseSysNs+999))
	require.NoErrorf(t, err, "immediate query could not resolve the live entry")
	require.NotNilf(t, live, "immediate query returned no dominant")
	assert.Equalf(t, baseSysNs, live.SystemTime, "live dominant has a different SystemTime")
	assert.Equalf(t, digest, live.PayloadDigest, "live dominant carries a different payload digest")

	// Without LiveSource, the same empty durable store cannot answer the query.
	cfgNoLive := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	resolverNoLive := database.NewResolver(lfs, lfs, alloc, "ryw-nolive-bucket", cfgNoLive)
	_, errNoLive := resolverNoLive.AsOf(ctx, entity, time.Unix(0, baseSysNs+50), time.Unix(0, baseSysNs+999))
	assert.Errorf(t, errNoLive, "query without LiveSource unexpectedly resolved an empty durable store")

	// Flush an equivalent durable L0 row. L0Flusher exercises the storage half
	// of AppendCheckpoint without requiring a WAL for this resolver test.
	flusher := database.NewL0Flusher(alloc, lfs, "ryw-bucket")
	sl := database.NewSkipListArena(alloc, 2*1024*1024)
	// Build the same 40-byte key and packed value as the compaction fixtures,
	// using the live entry's fields and digest.
	fullHash := sha256.Sum256([]byte(entity))
	key := make([]byte, 40)
	copy(key[0:16], fullHash[:16])
	putBE64(key[16:24], uint64(baseSysNs)) // sysNs
	putBE64(key[24:32], uint64(baseSysNs)) // validStartNs
	putBE64(key[32:40], uint64(baseSysNs)) // assertNs == sysNs
	// Pack entity ID, H3 cell, valid-time end, digest, and payload.
	val := makePackedValue(entity, 0x89283082803ffff, openEnd, digest, payload)
	err = sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
	require.NoError(t, err)
	_, err = flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err, "durable L0 flush failed")
	sl.Free()

	// The durable scan and live merge now find equal system times. Strict
	// dominance keeps the durable result, whose digest must match the live one.
	durable, err := resolver.AsOf(ctx, entity, time.Unix(0, baseSysNs+50), time.Unix(0, baseSysNs+999))
	require.NoErrorf(t, err, "post-flush query failed")
	require.NotNilf(t, durable, "post-flush query returned no dominant")
	assert.Equalf(t, digest, durable.PayloadDigest, "durable dominant carries a different digest")
	assert.Equalf(t, live.PayloadDigest, durable.PayloadDigest, "live and durable digests differ")
	t.Logf("live entry resolved before and after the durable flush with the same digest")
}

// TestLiveReadYourWritesEBRRace runs 100 AsOf calls concurrently with 250
// InsertLocal calls. LiveRead holds an EBR pin from Acquire/Enter until
// Release, preventing reclamation of shard roots being iterated while writers
// replace them. Run with -race to detect unsynchronized access or premature
// reclamation (ADR-0032). All reads of the seeded entity must succeed.
func TestLiveReadYourWritesEBRRace(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const seedEntity = "live-race-seed-entity"
	const baseSysNs int64 = 1_700_000_000_000_000_000
	const openEnd int64 = 9_000_000_000_000_000_000

	engine, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, testArenaSize)
	require.NoError(t, err)

	// The resolver with the live source (EBR-pinned LiveRead).
	cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfg.LiveSource = &testLiveAdapter{engine: engine}
	resolver := database.NewResolver(lfs, lfs, alloc, "ryw-race-bucket", cfg)

	// Seed a distinct entity that writers do not modify, giving every reader a
	// stable live row to resolve.
	seedDigest := sha256.Sum256([]byte("seed"))
	engine.InsertLocal(seedEntity, eng.CRDTEntry{
		PayloadDigest:  seedDigest,
		SystemTime:     baseSysNs,
		ValidTimeStart: baseSysNs,
		ValidTimeEnd:   openEnd,
		AssertionTime:  baseSysNs,
		H3Index:        0x89283082803ffff,
	})

	// Spread writes across entities to keep each HAMT leaf small. Each State
	// call materializes an O(total entries) merged view, and concurrent readers
	// can retain earlier views until EBR reclaims them. The small working set
	// isolates root replacement during LiveRead rather than arena pressure.
	const nReaders = 20
	const readsPer = 5 // 100 AsOf calls total
	const nWriters = 5
	const writesPer = 50 // 250 InsertLocal total
	const entitiesPerWriter = 20

	var wg sync.WaitGroup
	var readErrs atomic.Int64
	var readOK atomic.Int64
	// Readers resolve the seeded entity while writers replace other roots.
	// Atomic counters avoid introducing a data race in the test itself.
	for r := 0; r < nReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < readsPer; i++ {
				// Query above the seed's system time so it is visible.
				_, qerr := resolver.AsOf(ctx, seedEntity, time.Unix(0, baseSysNs+50), time.Unix(0, baseSysNs+999999))
				if qerr != nil {
					// The seed should remain visible throughout the test; count any
					// unexpected resolver error for the assertions below.
					readErrs.Add(1)
					continue
				}
				readOK.Add(1)
			}
		}()
	}
	// Writers replace shard roots while readers hold EBR pins.
	for w := 0; w < nWriters; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < writesPer; i++ {
				// Reuse a small set of distinct entities to distribute writes
				// without growing one large leaf.
				ent := fmt.Sprintf("race-w%d-%d", wid, i%entitiesPerWriter)
				dig := sha256.Sum256([]byte(ent))
				engine.InsertLocal(ent, eng.CRDTEntry{
					PayloadDigest:  dig,
					SystemTime:     baseSysNs + int64(i+1)*1000, // ascending sysTime (newer wins)
					ValidTimeStart: baseSysNs,
					ValidTimeEnd:   openEnd,
					AssertionTime:  baseSysNs + int64(i+1)*1000,
					H3Index:        0x89283082803ffff,
				})
			}
		}(w)
	}
	wg.Wait()

	// Every seeded read must succeed; premature root reclamation would surface
	// as an error, panic, or race-detector report.
	assert.Zerof(t, readErrs.Load(), "%d/%d AsOf calls failed during concurrent InsertLocal", readErrs.Load(), nReaders*readsPer)
	assert.Equalf(t, int64(nReaders*readsPer), readOK.Load(), "resolved %d AsOf calls during %d InsertLocal calls", nReaders*readsPer, nWriters*writesPer)
	t.Logf("%d AsOf calls concurrent with %d InsertLocal calls across %d entities completed without read errors",
		nReaders*readsPer, nWriters*writesPer, entitiesPerWriter)
}
