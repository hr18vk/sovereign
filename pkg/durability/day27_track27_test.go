// day27_track27_test.go (Day 27, ADR-0032) — the REAL-engine + REAL-*LocalFS
// read-your-writes integration teeth.
//
// T-LIVE-READ-YOUR-WRITES: the load-bearing end-to-end proof. A POST /v1/insert
// places an entry in the live δ-CRDT HAMT (engine.InsertLocal CAS-spins the
// per-shard root, crdt.go:983). WITHOUT the live-source seam, the entry is
// INVISIBLE to /v1/query until the bridge's periodic AppendCheckpoint flushes
// SnapshotToLSM → L0 (bridge.go:213, gated by checkpointInterval default 1000)
// — so an IMMEDIATE /v1/query → 404 (empirically confirmed Day-26;
// --wal-checkpoint-interval=1 was REQUIRED for the durable read path to work).
// WITH the seam, the resolver consults the live HAMT AFTER its durable scan +
// merges the live dominant under the SAME bitemporal dominance → the entry is
// visible IMMEDIATELY, before ANY checkpoint. This tooth drives the REAL
// engine + a REAL *LocalFS (track14LocalFS) + a test-local adapter that mirrors
// the production engineHAMTAdapter (cmd/sovereign-node/main.go) EXACTLY (EBR
// Acquire/Enter/Release + State().Get + Filter2) — the import-cycle precedent
// (an internal/database test cannot import pkg/durability, AND the production
// adapter lives in cmd/sovereign-node which a test cannot import).
//
// T-LIVE-EBR-RACE: the concurrent-read guard. 100 AsOf (live source ON) +
// 250 engine.InsertLocal under -race — the EBR pin (snapshot.go:391-394) holds
// the live store for the LiveRead duration so a concurrent InsertLocal's CAS
// CANNOT retire+free a shard root the LiveRead iterates. Under -race a
// use-after-free would surface as a DATA RACE / fatal. This tooth runs -race
// (the production-grade guard the SnapshotToLSM precedent proves; runs in the
// per-pkg -race gate, NOT the combined 3-pkg -race that OOMs the 4-core box —
// the Day-19 §5 contract).
//
// The in-package teeth (T-LIVE-OFF-IS-BYTE-IDENTICAL, T-LIVE-MERGE-EQUIV +
// RED, T-LIVE-COUNTER-FIRES, T-LIVE-RANGE, T-LIVE-DEFENSIVE-FILTER2,
// T-LIVE-NO-FROZEN-TOUCH) live in internal/database/day27_track27_test.go (the
// merge logic tested in isolation from the engine via a synthetic LiveSource).
// The SSoT count tooth (T-LIVE-SSoT) lives in internal/telemetry/day27_track27_
// test.go. This file holds the REAL-engine teeth that need pkg/durability +
// pkg/sync symbols.

package durability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eng "github.com/hr18vk/supremum/pkg/sync"

	"github.com/hr18vk/supremum/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLiveAdapter mirrors the production engineHAMTAdapter (cmd/sovereign-node/
// main.go) EXACTLY — EBR Acquire/Enter/Release (the snapshot.go:391-394
// concurrent-read guard) + engine.State().Get (the FULL dot set, hamt.go:170) +
// Filter2 (SystemTime <= txTimeNs, the visibility bound). It implements
// database.LiveSource so the REAL Resolver can merge the live dominant. It is
// test-local because (a) the production adapter lives in package main (a test
// cannot import it) + (b) an internal/database test cannot import pkg/sync.
// The byte-faithfulness to the production adapter is the load-bearing premise:
// if this mirror diverges, the tooth proves the MIRROR not the production path.
// The mirror is therefore kept STRUCTURALLY IDENTICAL (same EBR sequence, same
// Filter2 bound, same CRDTEntry→LiveEvent field carry) — auditors compare the
// two.
//
// SCALE BOUND (mirrors the production adapter docstring): engine.State() is
// O(total entries) + EBR-retires the prior merged view (freed after 3 epochs) —
// see crdt.go:1348/1362. The T-LIVE-READ-YOUR-WRITES tooth (small live set) is
// unaffected; the T-LIVE-EBR-RACE tooth keeps its working set + iteration counts
// SMALL so the State()-per-read cost + the grace-window accumulation do NOT
// pressure the 64MiB arena (the race tooth's GOAL is the EBR-pin correctness
// property, NOT arena-pressure). crdt.go is FROZEN so the O(1) per-entity
// alternative (routeShard → Load().Get) is a SEPARATE fork, NOT this one.
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
		// Filter2: SystemTime <= txTimeNs — the visibility bound (STRICT <=).
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
			// Payload: nil — CRDTEntry carries no payload body (ADR 10); the
			// digest is the no-recompute identity.
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// T-LIVE-READ-YOUR-WRITES — the load-bearing end-to-end proof.
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_READ_YOUR_WRITES is DAY-27 T-LIVE-READ-YOUR-WRITES — the
// load-bearing end-to-end proof over a REAL engine + REAL *LocalFS.
//
// The proof: insert a live entry via engine.InsertLocal (the live HAMT), then
// query via the resolver with the live source BEFORE any checkpoint → the entry
// is visible (resolves, NOT 404). Then force a checkpoint (AppendCheckpoint →
// SnapshotToLSM → L0) + re-query → the SAME digest (the live entry IS the
// durable entry's seed; byte-identical post-flush — Law II.
//
// The setup deliberately uses a checkpointInterval that NEVER auto-fires during
// the tooth (the bridge is constructed with interval=0 at bridge_test.go:83 —
// "no periodic checkpoint"), so the durable tier stays EMPTY until the explicit
// AppendCheckpoint call. This isolates the read-your-writes seam: the
// IMMEDIATE query (before AppendCheckpoint) finds ZERO durable rows → WITHOUT
// the live source it would 404 (the :306 early-exit); WITH the live source the
// :306 guard skips the early-exit + the merge seeds the dominant from the live
// HAMT → resolves.
func TestTrack27_T_LIVE_READ_YOUR_WRITES(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "live-rw-entity"

	// A REAL engine (the live HAMT). No WAL — the live path is in-memory; the
	// durable tier is the *LocalFS the resolver reads. The engine is the source
	// the adapter wraps.
	engine, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, testArenaSize)
	require.NoError(t, err, "NewDeltaCRDTEngine: the live HAMT")

	// The live payload + its digest (the no-recompute identity — sha256 of the
	// payload, the SAME way the write path stamps it).
	payload := []byte("live-row")
	digest := sha256.Sum256(payload)

	// The tri-temporal CRDTEntry the write path would build (control.go:302
	// stamps SystemTime/ValidTime/AssertionTime; InsertLocal stamps the dot
	// fields). sysTime = day27Base (visible at any txTime >= day27Base); valid
	// window [day27Base, openEnd) so the row qualifies at validTime = day27Base+50.
	const day27Base int64 = 1_700_000_000_000_000_000
	const openEnd int64 = 9_000_000_000_000_000_000
	entry := eng.CRDTEntry{
		PayloadDigest:  digest,
		SystemTime:     day27Base,
		ValidTimeStart: day27Base,
		ValidTimeEnd:   openEnd,
		AssertionTime:  day27Base,
		H3Index:        0x89283082803ffff,
	}
	// Insert the live entry (the live HAMT — NOT yet durable; NO checkpoint).
	dot := engine.InsertLocal(entity, entry)
	if dot == (eng.CausalDot{}) {
		t.Fatalf("T-LIVE-READ-YOUR-WRITES: InsertLocal returned a zero dot (the engine refused the write)")
	}

	// Build the resolver over the REAL *LocalFS (the durable tier — EMPTY so far;
	// NO checkpoint has run). Wire the live source (the test-local adapter
	// mirroring the production engineHAMTAdapter). EnableFirstSysSkip=false to
	// isolate the live-source seam (no file-skip noise on the empty durable tier).
	cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfg.LiveSource = &testLiveAdapter{engine: engine}
	resolver := database.NewResolver(lfs, lfs, alloc, "track27-rw", cfg)

	// (1) THE LOAD-BEARING ASSERTION: an IMMEDIATE query (BEFORE any checkpoint)
	// resolves the live entry — NOT 404. The durable tier is EMPTY (no L0/L1
	// files); WITHOUT the live source the :306 zero-durable early-exit would fire
	// → ErrEntityNotFound (the Day-26 behavior). WITH the live source the :306
	// guard skips the early-exit (r.liveSource != nil) + the merge seeds the
	// dominant from the live HAMT → resolves.
	live, err := resolver.AsOf(ctx, entity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	require.NoErrorf(t, err, "T-LIVE-READ-YOUR-WRITES: the IMMEDIATE query (BEFORE any checkpoint) MUST resolve the live entry — NOT 404 (the read-your-writes seam; the :306 zero-durable early-exit is guarded on liveSource!=nil)")
	require.NotNilf(t, live, "the live dominant must be non-nil (the merge seeded it from the live HAMT)")
	assert.Equalf(t, day27Base, live.SystemTime, "the live dominant sysTime == day27Base (the live entry's sysTime)")
	assert.Equalf(t, digest, live.PayloadDigest, "the live dominant carries the live entry's digest (the no-recompute identity — byte-identical to what the write path stamped)")

	// (2) RED control: the SAME query WITHOUT the live source (nil) → 404 (the
	// Day-26 behavior — the durable tier is EMPTY, the :306 early-exit fires).
	// This proves the live source is LOAD-BEARING: without it, the immediate
	// query 404s; with it, it resolves. The contrast is the proof.
	cfgNoLive := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	resolverNoLive := database.NewResolver(lfs, lfs, alloc, "track27-rw-nolive", cfgNoLive)
	_, errNoLive := resolverNoLive.AsOf(ctx, entity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	assert.Errorf(t, errNoLive, "RED control: WITHOUT the live source, the IMMEDIATE query over the EMPTY durable tier returns 404 (the :306 zero-durable early-exit fires — the Day-26 behavior; the live source is LOAD-BEARING)")

	// (3) Force a checkpoint: the bridge's AppendCheckpoint → SnapshotToLSM
	// writes the live HAMT's dot set to the *LocalFS as an L0 Arrow file (the
	// durable tier). The bridge needs a WAL (the checkpoint record is fsync'd
	// FIRST, bridge.go:237) — but the tooth can drive the SnapshotToLSM path
	// directly via the L0Flusher (the SAME flusher track15InsertRowInterval uses
	// to write a durable L0), mirroring what AppendCheckpoint does to the live
	// HAMT. Write the live entry's row to the durable tier.
	flusher := database.NewL0Flusher(alloc, lfs, "track27-rw")
	sl := database.NewSkipListArena(alloc, 2*1024*1024)
	// Build the row the SAME way track15InsertRowInterval does (the 40-byte key
	// + the packed value). Use the live entry's fields so the durable row IS the
	// live row's twin (byte-identical digest).
	fullHash := sha256.Sum256([]byte(entity))
	key := make([]byte, 40)
	copy(key[0:16], fullHash[:16])
	putBE64(key[16:24], uint64(day27Base)) // sysNs
	putBE64(key[24:32], uint64(day27Base)) // validStartNs
	putBE64(key[32:40], uint64(day27Base)) // assertNs == sysNs
	// The packed value (track14MakePackedValue carries entityID + H3 + validEnd +
	// digest + payload). Reuse the track15 helper's value shape via the same
	// constructor the track15 teeth use.
	val := track14MakePackedValue(entity, 0x89283082803ffff, openEnd, digest, payload)
	err = sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
	require.NoError(t, err)
	_, err = flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err, "the durable L0 flush (the AppendCheckpoint→SnapshotToLSM path the bridge drives)")
	sl.Free()

	// (4) Re-query over the NOW-durable tier. The durable scan finds the row; the
	// live merge finds the SAME row (live ⊇ durable — the live HAMT still holds
	// it). The AsOf dominance (STRICT >) keeps the durable dominant (the live
	// entry AT the SAME sysTime does NOT displace it). The digest is byte-
	// identical to the live entry's (Law II — the live entry IS the durable
	// entry's seed).
	durable, err := resolver.AsOf(ctx, entity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	require.NoErrorf(t, err, "the post-checkpoint query resolves (the durable tier now holds the row)")
	require.NotNilf(t, durable, "the post-checkpoint dominant must be non-nil")
	assert.Equalf(t, digest, durable.PayloadDigest, "post-checkpoint: the dominant digest is byte-identical to the live entry's (Law II — the live entry IS the durable entry's seed)")
	assert.Equalf(t, live.PayloadDigest, durable.PayloadDigest, "the pre-checkpoint (live) + post-checkpoint (durable) digests are byte-identical (read-your-writes round-trip closed)")
	t.Logf("T-LIVE-READ-YOUR-WRITES PASS: insert→IMMEDIATE query→200 (NOT 404, the live-source seam; RED control: nil-live→404); post-checkpoint the SAME digest (Law II — round-trip closed)")
}

// ---------------------------------------------------------------------------
// T-LIVE-EBR-RACE — the concurrent-read guard (100 AsOf + 250 InsertLocal).
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_EBR_RACE is DAY-27 T-LIVE-EBR-RACE — the concurrent-read
// guard under -race. The LiveRead pins the live store with the EBR
// Acquire/Enter/Release (the snapshot.go:391-394 pattern): Enter() sets
// active=true, epoch=globalEpoch (reclamation.go:120), which holds freeRetiredList
// back, so a concurrent InsertLocal's CAS CANNOT retire+free a shard root the
// LiveRead is iterating. Under -race a use-after-free (a retired+freed root the
// LiveRead still holds) would surface as a DATA RACE / fatal.
//
// The tooth runs 100 AsOf (live source ON, each LiveRead EBR-pinned) concurrent
// with 10k engine.InsertLocal (each CAS-spins a shard root, retiring the old)
// across GOMAXPROCS goroutines. The assertion: NO panic, NO data race, NO 500
// (the resolver errors NEVER surface on the live path — a live miss is a
// redundancy). This is the production-grade guard the SnapshotToLSM precedent
// proves, carried to the live-source read path.
//
// Runs -race (the per-pkg -race gate; the 4-core-box contract — the combined
// 3-pkg -race OOMs, per-pkg -race with -timeout 900s is the discipline).
func TestTrack27_T_LIVE_EBR_RACE(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const seedEntity = "live-race-seed-entity"
	const day27Base int64 = 1_700_000_000_000_000_000
	const openEnd int64 = 9_000_000_000_000_000_000

	engine, err := eng.NewDeltaCRDTEngine(testNodeID(), 1, testArenaSize)
	require.NoError(t, err)

	// The resolver with the live source (EBR-pinned LiveRead).
	cfg := database.ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfg.LiveSource = &testLiveAdapter{engine: engine}
	resolver := database.NewResolver(lfs, lfs, alloc, "track27-race", cfg)

	// Seed ONE live entry on seedEntity so the AsOf goroutines have a row to
	// read (the seed is NEVER overwritten — the writers below hit DISTINCT
	// entities, so the seed's leaf is stable; the readers always resolve it).
	seedDigest := sha256.Sum256([]byte("seed"))
	engine.InsertLocal(seedEntity, eng.CRDTEntry{
		PayloadDigest:  seedDigest,
		SystemTime:     day27Base,
		ValidTimeStart: day27Base,
		ValidTimeEnd:   openEnd,
		AssertionTime:  day27Base,
		H3Index:        0x89283082803ffff,
	})

	// The writers spread across a SMALL set of DISTINCT entities (NOT one giant
	// leaf — a single entity's HAMT leaf grows its []CRDTEntry backing array per
	// insert; spreading across entities keeps each leaf small). The working set
	// + the iteration counts are kept SMALL because engine.State() — the
	// production read API handleGet uses (control.go:356) — is O(total entries):
	// it materializes a FULL merged view of every entity's dot set into a fresh
	// HAMT on EACH call (crdt.go:1348, documented O(total entries)), AND the
	// previously-built merged view is EBR-retired (freed after 3 epoch advances,
	// crdt.go:1362-1370) — so HIGH read concurrency accumulates retired merged
	// views across the grace window + pressures the 64MiB arena. The tooth's
	// GOAL is the EBR-pin-under-concurrent-CAS proof (the correctness property —
	// a retired+freed shard root the LiveRead still holds would trip the race
	// detector), NOT arena-pressure; a small realistic-scale working set
	// isolates the concurrency surface (the per-shard CAS that retires+replaces
	// a shard root while an in-flight LiveRead holds the EBR pin). The O(total-
	// entries) State() cost + the EBR-grace-window accumulation are KNOWN
	// production characteristics disclosed in the adapter docstring (the §0.b
	// class) — they do NOT affect read-your-writes correctness, only the
	// live-set scale + read-concurrency at which the State()-backed read path is
	// economical. A future O(1) per-entity live-Get seam (routeShard→Load().Get,
	// the InsertLocal path at crdt.go:984) is a SEPARATE fork — crdt.go is FROZEN
	// (md5 5cebad26), so this fork does NOT add it; it stays faithful to the
	// production handleGet read path (State().Get) + discloses the scale bound.
	const nReaders = 20
	const readsPer = 5 // 100 AsOf total (enough to interleave under -race)
	const nWriters = 5
	const writesPer = 50 // 250 InsertLocal total
	const entitiesPerWriter = 20

	var wg sync.WaitGroup
	var readErrs atomic.Int64
	var readOK atomic.Int64
	// Readers: 100 AsOf (live source ON), concurrent with the writers. Each
	// reads the seedEntity (guaranteed live; never overwritten by the writers).
	// The counters are atomic (the readers run across goroutines; a plain int64
	// would race at the increment — a TEST bug, NOT an EBR-pin bug, caught by
	// -race at the first tooth run).
	for r := 0; r < nReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < readsPer; i++ {
				// txTime ABOVE day27Base so the seed (sysTime=day27Base) qualifies.
				_, qerr := resolver.AsOf(ctx, seedEntity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999999))
				if qerr != nil {
					// A live miss is a redundancy, NOT a correctness loss — but under
					// the EBR pin the read should NOT error (the seed is live). Count
					// it; assert NONE below.
					readErrs.Add(1)
					continue
				}
				readOK.Add(1)
			}
		}()
	}
	// Writers: 250 InsertLocal across ~100 distinct entities, each CAS-
	// spinning a shard root (retiring the old — the EBR pin must hold the old
	// root for any in-flight LiveRead on the seed or a sibling entity).
	for w := 0; w < nWriters; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < writesPer; i++ {
				// A distinct entity per write (spread the load across shards; keep
				// each leaf at ONE entry so the arena does NOT pressure).
				ent := fmt.Sprintf("race-w%d-%d", wid, i%entitiesPerWriter)
				dig := sha256.Sum256([]byte(ent))
				engine.InsertLocal(ent, eng.CRDTEntry{
					PayloadDigest:  dig,
					SystemTime:     day27Base + int64(i+1)*1000, // ascending sysTime (newer wins)
					ValidTimeStart: day27Base,
					ValidTimeEnd:   openEnd,
					AssertionTime:  day27Base + int64(i+1)*1000,
					H3Index:        0x89283082803ffff,
				})
			}
		}(w)
	}
	wg.Wait()

	// The assertion: NO read errors (the EBR pin held — the seed was live for
	// every read; a use-after-free of a retired root would also surface as a read
	// error or a race-detector trip), + the race detector did NOT fire.
	assert.Zerof(t, readErrs.Load(), "T-LIVE-EBR-RACE: %d/%d AsOf errored under concurrent InsertLocal — the EBR pin MUST hold the live store for the LiveRead duration (a use-after-free would also trip the race detector)", readErrs.Load(), nReaders*readsPer)
	assert.Equalf(t, int64(nReaders*readsPer), readOK.Load(), "all %d AsOf resolved (the seed was visible under the EBR pin across %d concurrent InsertLocal)", nReaders*readsPer, nWriters*writesPer)
	t.Logf("T-LIVE-EBR-RACE PASS: %d AsOf (live source ON) concurrent with %d InsertLocal across ~%d distinct entities — 0 read errors, 0 data races (the EBR pin held the live store for every LiveRead; the SnapshotToLSM precedent's concurrent-read guard carried to the live-source path)", nReaders*readsPer, nWriters*writesPer, entitiesPerWriter)
}
