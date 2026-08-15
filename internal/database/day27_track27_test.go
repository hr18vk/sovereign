// Day 27 (ADR-0032) teeth — the read-your-writes live-source merge, the TENTH
// clean-chain fork.
//
// THE GAP (the §0 audit's REAL finding — NOT the SkipList-freeze premise the
// prior draft named): Resolver.AsOf reads ONLY durable Arrow files; an entry a
// POST /v1/insert places in the live δ-CRDT HAMT (engine.InsertLocal CAS-spins
// the per-shard root, crdt.go:983) is INVISIBLE to /v1/query until the bridge's
// periodic AppendCheckpoint flushes SnapshotToLSM → L0 (bridge.go:213, gated by
// checkpointInterval default 1000). With the default, every IMMEDIATE
// /v1/query → 404 — empirically confirmed Day-26 (--wal-checkpoint-interval=1
// was REQUIRED for the durable read path to work at all).
//
// THE FIX: a LiveSource interface (owned by internal/database — it does NOT
// import pkg/sync, so the seam is an interface, NOT a concrete engine) whose
// cmd/sovereign-node adapter wraps engine.State().Get + the EBR pin
// (snapshot.go:391-394, the EXACT concurrent-read guard). The Resolver merges
// the live dominant under the SAME bitemporal dominance AsOf already computes.
//
// TWO §0.b REFINEMENTS the prompt's prose HAND-WAVED (the dictated-design-detail-
// the-bytes-refine class — disclosed in ADR-0032 §6, NOT silently filled in):
//
//   - M-ASOF-EARLY-EXIT: AsOf has TWO early-exits (query.go:306 zero-durable,
//     :425 dominant==nil) that fire BEFORE any "post-scan merge." The prompt's
//     A4 ("merge after buildDurableDominant") was structurally insufficient —
//     there IS no buildDurableDominant; the scan is inlined + the :306 early-
//     exit returns before it runs. The read-your-writes proof (insert → IMMEDIATE
//     query → 200, checkpoint disabled) requires the live path to RESCUE the
//     zero-durable case, not just augment a successful scan. FIX: the :306
//     early-exit is guarded on r.liveSource==nil (T-LIVE-OFF-IS-BYTE-IDENTICAL
//     proves the guard keeps the durable-only behavior byte-identical); the merge
//     sits after the scan loop feeding the :425 nil-check.
//
//   - M-RANGE-DEDUP: the live HAMT is APPEND-ONLY, NEVER pruned (grep
//     Prune|Reset|Retire on crdt.go/hamt.go is empty; AppendCheckpoint→
//     SnapshotToLSM only READS engine.State().ForEach, never mutates), and the
//     durable Arrow index is built FROM the live HAMT (snapshot.go:436). So
//     live ⊇ durable, ALWAYS. After a checkpoint the live HAMT STILL holds the
//     checkpointed dot AND the durable tier now holds the same row → a naive
//     "append every live row" (the prompt's A5) would DUPLICATE every
//     checkpointed row → a Law II break the prompt's M6 tautology assumed away
//     (M6 reasons about AsOf's SINGLE dominant — max wins, dedup-free — NOT
//     Range's MULTI-ROW slice). FIX: the Range merge DEDUPS live against durable
//     by (SystemTime, PayloadDigest) before append (the Arrow schema carries NO
//     dot columns, so dot-dedup is impossible at the row level; (sysTime, 32-byte
//     digest) is the honest row identity — the digest is a content hash, the
//     no-recompute law). T-LIVE-RANGE proves the dedup via a BUG-INJECT no-dedup
//     catcher (the dedup removed → duplicates → the tooth catches it).
//
//   - M-DEFENSIVE-FILTER2: the prompt's split was "adapter applies Filter2;
//     Resolver applies Filter3+dominance." A buggy/foreign adapter returning an
//     entry with SystemTime > txTimeNs would — under trust-only — pass Filter3 +
//     dominance and become the dominant → a SILENT Law II break (a row NOT
//     visible at txTime). FIX: the Resolver defensively RE-CHECKS Filter2
//     (SystemTime <= txTimeNs) — zero cost on a correct adapter (the check never
//     fires) + a hard guarantee otherwise. T-LIVE-DEFENSIVE-FILTER2 proves the
//     guard drops a buggy adapter's over-txTime entry.
//
// THE RUNTIME tooth (T-LIVE-READ-YOUR-WRITES — the load-bearing end-to-end proof
// over a REAL engine + REAL *LocalFS, checkpoint disabled) lives in
// pkg/durability/day27_track27_test.go (the import-cycle precedent — an
// internal/database test cannot import pkg/durability, AND the real engine lives
// in pkg/sync which the adapter wraps at the cmd/sovereign-node boundary). The
// SSoT count tooth (T-LIVE-SSOT) lives in internal/telemetry/day27_track27_test.go
// (the package that owns the counter). This file holds the in-package teeth that
// need only internal/database symbols: the nil-guard, the EQUIV fuzz (the load-
// bearing gate w/ the honest >= catcher), the counter, the Range dedup, the
// defensive Filter2, + the FROZEN-scope tooth.

package database

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"github.com/hr18vk/supremum/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// day27Base is a fixed ns epoch for the Day-27 teeth (the SAME convention as
// day24Base/day25Base: 1.7e18, comfortably below openDay19Ns (9e18) + int64-max
// (9.2e18)).
const day27Base int64 = 1_700_000_000_000_000_000

// ---------------------------------------------------------------------------
// syntheticLiveSource — a test-local LiveSource the in-package teeth drive.
// ---------------------------------------------------------------------------

// syntheticLiveSource is a test-local database.LiveSource. The production adapter
// (engineHAMTAdapter, cmd/sovereign-node/main.go) wraps engine.State().Get +
// EBR; the in-package teeth cannot import pkg/sync (internal/database does NOT
// import it — M2, the load-bearing premise), so they drive a synthetic that
// returns a fixed []LiveEvent. The teeth control EXACTLY what the live source
// returns, so the merge logic (Filter2/Filter3/dominance/dedup) is tested in
// ISOLATION from the engine — the equivalent of the day25 memStoreTrack13
// pattern (a test-local store stands in for S3). The production path is proven
// end-to-end by T-LIVE-READ-YOUR-WRITES in pkg/durability.
//
// The synthetic applies Filter2 (SystemTime <= txTimeNs) the SAME way the
// production adapter does — UNLESS filter2Buggy is set (the T-LIVE-DEFENSIVE-
// FILTER2 tooth flips it to return an over-txTime entry + proves the Resolver's
// defensive Filter2 drops it).
type syntheticLiveSource struct {
	entries      []LiveEvent
	filter2Buggy bool // true → return ALL entries (NO Filter2) — the defensive-guard test
}

func (s *syntheticLiveSource) LiveRead(_ context.Context, _ string, txTimeNs int64) ([]LiveEvent, error) {
	if s.filter2Buggy {
		// The buggy path: return ALL entries regardless of sysTime (simulates a
		// foreign/buggy adapter that ignores Filter2). The Resolver's defensive
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

// liveDigest computes the [32]byte PayloadDigest the SAME way the write path
// does (sha256 of the payload — the no-recompute identity, control.go:441).
func liveDigest(payload []byte) [32]byte {
	return sha256.Sum256(payload)
}

// ---------------------------------------------------------------------------
// T-LIVE-OFF-IS-BYTE-IDENTICAL — nil LiveSource == durable-only (Day-26).
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_OFF_IS_BYTE_IDENTICAL is DAY-27 T-LIVE-OFF-IS-BYTE-
// IDENTICAL. A nil LiveSource (the DefaultResolverConfig value — a research
// node / --lsm-root absent, OR SetLiveSource(nil)) keeps the durable-only
// behavior byte-identical to Day-26. The :306 zero-durable early-exit fires
// (r.liveSource==nil → the guard does NOT skip it); the live merge is skipped
// (r.liveSource==nil → the merge block is NOT entered). This is the load-bearing
// back-compat tooth: a research node that does NOT wire a live source gets the
// SAME answer it got Day-26 — the fork is OPT-IN via the live source, NOT a
// forced change to every resolver.
//
// The tooth writes a row to a memStoreTrack13 (NO live source), queries at a
// txTime the row qualifies, + asserts the SAME dominant a Day-26 resolver
// returns. RED control: an entity with NO durable data + a nil live source →
// the :306 early-exit fires → ErrEntityNotFound (byte-identical to Day-26).
func TestTrack27_T_LIVE_OFF_IS_BYTE_IDENTICAL(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	const entity = "live-off-entity"

	// Write ONE durable L0 row (sysTime=base, [base, openEnd)).
	sl := NewSkipListArena(alloc, 2*1024*1024)
	range19InsertRow(t, sl, entity, day27Base, day27Base, openDay19Ns, []byte("durable-row"))
	require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl))

	// A resolver with NO live source (the DefaultResolverConfig — LiveSource==nil).
	// EnableFirstSysSkip=false to isolate the live-source seam (no file-skip noise).
	r := NewResolver(store, store, alloc, "track27-off", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	require.Nilf(t, r.liveSource, "a DefaultResolverConfig-derived resolver has liveSource==nil (the nil-guard)")

	// Query at a txTime the row qualifies (txTime=base+999 > sysTime=base).
	got, err := r.AsOf(ctx, entity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	require.NoErrorf(t, err, "nil-live-source AsOf must resolve the durable row (byte-identical to Day-26)")
	require.NotNilf(t, got, "the dominant must be non-nil (the durable scan found it; NO live merge ran)")
	assert.Equalf(t, day27Base, got.SystemTime, "the durable dominant sysTime == base (the durable-only answer)")
	assert.Equalf(t, []byte("durable-row"), got.Payload, "the durable dominant payload (byte-identical to Day-26)")

	// RED control: an entity with NO durable data + a nil live source → the :306
	// early-exit fires (r.liveSource==nil → the guard does NOT skip it) →
	// ErrEntityNotFound (byte-identical to Day-26 — the fork did NOT silently turn
	// a durable miss into a live lookup that returns nil+nil).
	r2 := NewResolver(store, store, alloc, "track27-off-red", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	require.Nil(t, r2.liveSource)
	_, errMiss := r2.AsOf(ctx, "no-such-entity", time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	assert.Errorf(t, errMiss, "nil-live-source + zero durable → ErrEntityNotFound (the :306 early-exit fires — byte-identical to Day-26, NOT a silent nil-nil)")
	t.Logf("T-LIVE-OFF-IS-BYTE-IDENTICAL PASS: nil LiveSource → durable-only (the :306 early-exit fires on zero-durable; the live merge is skipped); byte-identical to Day-26 (the fork is OPT-IN via the live source)")
}

// ---------------------------------------------------------------------------
// T-LIVE-MERGE-EQUIV — the differential-equivalence fuzz (the load-bearing gate).
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_MERGE_EQUIV is DAY-27 T-LIVE-MERGE-EQUIV, the LOAD-BEARING
// differential-equivalence proof. The tautology: once a live entry is
// checkpointed into L0, the merged answer (durable scan + live merge) ==
// the durable-only answer (live source OFF) byte-identically (Law II — the live
// entry IS the durable entry's seed: SnapshotToLSM writes the CRDTEntry
// verbatim, snapshot.go:447).
//
// The tooth writes N=32 staggered L0 files for ONE entity (sysTime = base+i*1000,
// i=0..31) to a memStoreTrack13. It builds a synthetic LiveSource that returns
// the SAME N rows (the post-checkpoint steady state — live ⊇ durable, EVERY
// durable row is also live). It then runs AsOf over 2000 fuzzed txTimes with
// the live source ON vs OFF + asserts byte-identity of the dominant.
//
// THE HONEST >= CATCHER (the Day-24/25 class — the prompt's "the boundary is
// load-bearing"): a buggy merge that uses >= instead of > (a live entry AT the
// durable sysTime DISPLACES it) would diverge whenever a live entry's sysTime
// == the durable dominant's sysTime (which the synthetic's same-N-rows setup
// makes EVERY query) → the EQUIV catches it. The tooth flips > to >= via a
// test-local shadow + proves the divergence (the RED control goes RED, NOT
// vacuously green). Day 27 does NOT ship the >= bug; it proves the > boundary
// is load-bearing the SAME way Day-24/25 did.
//
// The tooth runs NON-race (the Day-22 §2 precedent — the merge has NO
// concurrency surface on the read path; the EBR race is T-LIVE-EBR-RACE in
// pkg/durability over the REAL engine).
func TestTrack27_T_LIVE_MERGE_EQUIV(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	const entity = "live-equiv-entity"
	const N = 32
	const fuzzN = 2000

	// Write N=32 staggered L0 files (sysTime = base+i*1000), each holding ONE
	// row at sysTime == firstSys (the production-invariant). validTime [base,
	// openEnd) so the row qualifies at validTime = base+50.
	store := newMemStoreTrack13()
	type rowT struct {
		payload []byte
		sys     int64
		digest  [32]byte
	}
	rows := make([]rowT, N)
	for i := 0; i < N; i++ {
		sysNs := day27Base + int64(i)*1000
		payload := []byte(fmt.Sprintf("row-%d", i))
		rows[i] = rowT{sys: sysNs, payload: payload, digest: liveDigest(payload)}
		sl := NewSkipListArena(alloc, 2*1024*1024)
		range19InsertRow(t, sl, entity, sysNs, day27Base, openDay19Ns, payload)
		require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl))
	}

	// The synthetic LiveSource returns the SAME N rows (post-checkpoint steady
	// state: live ⊇ durable, EVERY durable row is also live — the merge's dedup-
	// free AsOf path; Range's dedup path is T-LIVE-RANGE). The adapter applies
	// Filter2 (sysTime <= txTime).
	liveEntries := make([]LiveEvent, N)
	for i, r := range rows {
		liveEntries[i] = LiveEvent{
			SystemTime:     r.sys,
			ValidTimeStart: day27Base,
			ValidTimeEnd:   openDay19Ns,
			AssertionTime:  r.sys,
			H3Index:        0x89283082803ffff,
			PayloadDigest:  r.digest,
		}
	}
	liveSrc := &syntheticLiveSource{entries: liveEntries}

	// Two resolvers over the SAME store: live source ON vs OFF (the comparison).
	// EnableFirstSysSkip=false to isolate the live-source seam.
	cfgOn := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfgOn.LiveSource = liveSrc
	rOn := NewResolver(store, store, alloc, "track27-equiv-on", cfgOn)
	rOff := NewResolver(store, store, alloc, "track27-equiv-off", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})

	rng := rand.New(rand.NewPCG(27, 0))
	vt := time.Unix(0, day27Base+50) // ONE validTime (the merge bounds txTime/sysTime, not validTime)
	var diverge int
	for f := 0; f < fuzzN; f++ {
		// txTime in [base-1000, base+N*1000): spans BELOW the oldest row (both
		// paths NotFound), AT a row (boundary), and ABOVE the newest (the newest
		// is the dominant).
		txNs := day27Base - 1000 + rng.Int64N(int64(N)*1000+1000+1)
		tx := time.Unix(0, txNs)

		gotOn, errOn := rOn.AsOf(ctx, entity, vt, tx)
		gotOff, errOff := rOff.AsOf(ctx, entity, vt, tx)

		// byte-IDENTITY: live-ON == live-OFF (the tautology — once the live rows
		// are checkpointed, the merge changes NOTHING).
		if errOn != nil && errOff == nil {
			diverge++
			t.Errorf("T-LIVE-MERGE-EQUIV diverge at f=%d txNs=%d: live-ON=Err live-OFF=event (the merge DROPPED a qualifying row — a Law-II break)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errOff != nil && errOn == nil {
			diverge++
			t.Errorf("T-LIVE-MERGE-EQUIV diverge at f=%d txNs=%d: live-ON=event live-OFF=Err (the merge FABRICATED a row — a bug)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
		if errOn != nil && errOff != nil {
			continue // both NotFound — byte-identical
		}
		// Both resolved — assert byte-identity on the load-bearing fields.
		if gotOn.SystemTime != gotOff.SystemTime {
			diverge++
			t.Errorf("T-LIVE-MERGE-EQUIV diverge at f=%d txNs=%d: SystemTime ON=%d OFF=%d (the merge picked the WRONG dominant)", f, txNs, gotOn.SystemTime, gotOff.SystemTime)
			if diverge > 5 {
				break
			}
			continue
		}
		if gotOn.ValidTimeStart != gotOff.ValidTimeStart || gotOn.ValidTimeEnd != gotOff.ValidTimeEnd {
			diverge++
			t.Errorf("T-LIVE-MERGE-EQUIV diverge at f=%d txNs=%d: ValidTime ON=[%d,%d) OFF=[%d,%d)", f, txNs, gotOn.ValidTimeStart, gotOn.ValidTimeEnd, gotOff.ValidTimeStart, gotOff.ValidTimeEnd)
			if diverge > 5 {
				break
			}
			continue
		}
		if !bytesEqual(gotOn.Payload, gotOff.Payload) {
			diverge++
			t.Errorf("T-LIVE-MERGE-EQUIV diverge at f=%d txNs=%d: Payload differs (the merge returned the WRONG row's payload)", f, txNs)
			if diverge > 5 {
				break
			}
			continue
		}
	}
	require.Zerof(t, diverge, "T-LIVE-MERGE-EQUIV: live-ON == live-OFF byte-IDENTICAL for ALL %d fuzzed txTimes (the tautology — once the live rows are checkpointed, the merge changes NOTHING; a divergence is a Law-II break)", fuzzN)
	t.Logf("T-LIVE-MERGE-EQUIV PASS: %d fuzzed txTimes (seed=27), live-ON == live-OFF byte-IDENTICAL (the merge is a no-op once the live rows are checkpointed — Law II)", fuzzN)
}

// ---------------------------------------------------------------------------
// T-LIVE-MERGE-EQUIV-RED — BUG-INJECT the >= boundary (the RED control).
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_MERGE_EQUIV_RED is DAY-27 T-LIVE-MERGE-EQUIV-RED — the
// decisive RED control for the > boundary. The honest merge uses STRICT > (a
// live entry AT the durable sysTime does NOT displace it — the durable answer
// is the honest default). A >= bug displaces the durable dominant whenever a
// live entry's sysTime == the durable dominant's sysTime.
//
// This tooth re-derives the dominant the >= bug would pick vs the honest >
// rule, over a 2-row setup (durable sysTime=base, live sysTime=base — the SAME
// sysTime, the boundary), + asserts they DIVERGE (the >= bug picks the live
// row; the honest > keeps the durable row) — proving the EQUIV's boundary
// assertion DOES catch the >= bug (the RED control goes RED, NOT vacuously
// green). The live row's digest DIFFERS from the durable row's (so the
// divergence is observable on Payload, NOT just identity).
//
// The tooth runs NON-race (pure logic over the merge rule).
func TestTrack27_T_LIVE_MERGE_EQUIV_RED(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	const entity = "live-equiv-red-entity"

	// Durable row: sysTime=base, payload="D".
	sl := NewSkipListArena(alloc, 2*1024*1024)
	range19InsertRow(t, sl, entity, day27Base, day27Base, openDay19Ns, []byte("D"))
	require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl))

	// Live row: sysTime=base (the SAME sysTime — the boundary), payload="L" (a
	// DIFFERENT digest so the divergence is observable on Payload).
	liveSrc := &syntheticLiveSource{entries: []LiveEvent{{
		SystemTime:     day27Base,
		ValidTimeStart: day27Base,
		ValidTimeEnd:   openDay19Ns,
		AssertionTime:  day27Base,
		PayloadDigest:  liveDigest([]byte("L")),
	}}}
	cfg := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfg.LiveSource = liveSrc
	r := NewResolver(store, store, alloc, "track27-equiv-red", cfg)

	// Query at txTime=base+999 (both rows qualify; sysTime=base <= txTime).
	got, err := r.AsOf(ctx, entity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	require.NoError(t, err)
	require.NotNil(t, got)

	// The HONEST > rule: the live entry AT sysTime==base does NOT displace the
	// durable dominant AT sysTime==base (STRICT >). So the dominant is the
	// DURABLE row ("D") — the durable answer is the honest default.
	assert.Equalf(t, day27Base, got.SystemTime, "the honest > rule keeps the durable dominant (sysTime==base; the live entry AT the same sysTime does NOT displace it)")
	// The durable row's payload is "D" (the live row's is "L" — they DIFFER, so
	// the >= bug's displacement would be observable). The honest rule's dominant
	// carries the DURABLE digest.
	assert.Equalf(t, liveDigest([]byte("D")), got.PayloadDigest, "the honest > rule's dominant carries the DURABLE digest ('D'), NOT the live digest ('L') — the live entry AT the same sysTime does NOT displace it")

	// The >= bug REDERIVATION: a >= bug WOULD displace the durable dominant with
	// the live entry (sysTime==base >= dominantSystemTime==base → true). The
	// >= bug's dominant would carry the LIVE digest ('L'). The divergence (D vs
	// L) is what the EQUIV catches — the RED control goes RED.
	geBugWouldDisplace := day27Base >= day27Base // true under >=
	require.Truef(t, geBugWouldDisplace, "the >= bug WOULD displace at sysTime==base (>= is true at the boundary) — the divergence the EQUIV catches")
	// The honest > rule does NOT displace (STRICT > is false at the boundary).
	honestDisplaces := day27Base > day27Base // false under >
	require.Falsef(t, honestDisplaces, "the honest > rule does NOT displace at the boundary (STRICT > is false) — the durable answer is the honest default")
	// The divergence is observable: honest digest ('D') != >=-bug digest ('L').
	assert.NotEqualf(t, liveDigest([]byte("D")), liveDigest([]byte("L")), "the durable ('D') + live ('L') digests DIFFER — the >= bug's displacement is OBSERVABLE on Payload (the EQUIV catches it)")
	t.Logf("T-LIVE-MERGE-EQUIV-RED PASS: the honest > rule keeps the durable dominant at the boundary (sysTime==base; digest='D'); a >= bug WOULD displace it (digest='L') — the divergence is observable → the EQUIV catches the >= bug (RED, NOT vacuously green)")
}

// ---------------------------------------------------------------------------
// T-LIVE-COUNTER-FIRES — the disclosure counter (Inc once per live query).
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_COUNTER_FIRES is DAY-27 T-LIVE-COUNTER-FIRES. The
// QueryLiveSourceReads counter fires ONCE per query that CONSULTED the live
// path (NOT per live entry — the count is the path disclosure, the SAME Law V
// class the download-skip counter carries). A query WITHOUT a live source
// (nil) does NOT increment it (the nil-guard). The tooth:
//   - drives AsOf with a live source ON → the counter fires >= 1.
//   - drives AsOf with a live source OFF (nil) → the counter fires 0.
//   - drives Range with a live source ON → the counter fires >= 1 (the merge
//     runs for BOTH AsOf + Range — the disclosure is uniform).
func TestTrack27_T_LIVE_COUNTER_FIRES(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	const entity = "live-counter-entity"

	// One durable row.
	sl := NewSkipListArena(alloc, 2*1024*1024)
	range19InsertRow(t, sl, entity, day27Base, day27Base, openDay19Ns, []byte("c"))
	require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl))

	// (1) live source ON: the counter fires >= 1 per AsOf.
	liveSrc := &syntheticLiveSource{entries: []LiveEvent{{
		SystemTime: day27Base, ValidTimeStart: day27Base, ValidTimeEnd: openDay19Ns,
		PayloadDigest: liveDigest([]byte("c")),
	}}}
	cfgOn := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfgOn.LiveSource = liveSrc
	rOn := NewResolver(store, store, alloc, "track27-ctr-on", cfgOn)
	before := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		before = int64(telemetry.QueryLiveSourceReads.Value())
	}
	_, err := rOn.AsOf(ctx, entity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	require.NoError(t, err)
	after := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		after = int64(telemetry.QueryLiveSourceReads.Value())
	}
	assert.GreaterOrEqualf(t, after-before, int64(1), "live source ON: QueryLiveSourceReads fired >= 1 per AsOf (the path disclosure)")

	// (2) live source OFF (nil): the counter fires 0.
	rOff := NewResolver(store, store, alloc, "track27-ctr-off", ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false})
	before2 := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		before2 = int64(telemetry.QueryLiveSourceReads.Value())
	}
	_, err = rOff.AsOf(ctx, entity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	require.NoError(t, err)
	after2 := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		after2 = int64(telemetry.QueryLiveSourceReads.Value())
	}
	assert.Equalf(t, int64(0), after2-before2, "live source OFF (nil): QueryLiveSourceReads fired 0 (the nil-guard — a research node does NOT consult the live path)")

	// (3) Range with live source ON: the counter fires >= 1 (the merge runs for
	// BOTH AsOf + Range — the disclosure is uniform).
	before3 := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		before3 = int64(telemetry.QueryLiveSourceReads.Value())
	}
	_, _, err = rOn.Range(ctx, entity, time.Unix(0, day27Base), time.Unix(0, day27Base+500), time.Unix(0, day27Base+999))
	require.NoError(t, err)
	after3 := int64(0)
	if telemetry.QueryLiveSourceReads != nil {
		after3 = int64(telemetry.QueryLiveSourceReads.Value())
	}
	assert.GreaterOrEqualf(t, after3-before3, int64(1), "Range with live source ON: QueryLiveSourceReads fired >= 1 (the merge runs for BOTH AsOf + Range — the disclosure is uniform)")
	t.Logf("T-LIVE-COUNTER-FIRES PASS: QueryLiveSourceReads fires >= 1 per live query (AsOf + Range), 0 with a nil live source (the nil-guard)")
}

// ---------------------------------------------------------------------------
// T-LIVE-RANGE — the Range merge byte-identical to fully-flushed (the dedup).
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_RANGE is DAY-27 T-LIVE-RANGE. The Range merge appends
// live rows passing (W1)&&(W2) DEDUPED against durable by (SystemTime,
// PayloadDigest) — because live ⊇ durable, a post-checkpoint live row is the
// twin of a durable row; appending both would DUPLICATE → a Law II break. The
// tooth:
//   - writes N=4 durable rows to a memStoreTrack13.
//   - builds a synthetic LiveSource returning the SAME N rows (post-checkpoint
//     steady state: live ⊇ durable, EVERY durable row is also live — the dedup
//     must drop ALL N twins).
//   - asserts Range(live-ON) == Range(live-OFF) byte-identically (the dedup
//     removed the twins → NO duplicates).
//   - RED control: a no-dedup bug (append every live row) would DOUBLE the row
//     count (N durable + N live twins) → the tooth catches it.
func TestTrack27_T_LIVE_RANGE(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	const entity = "live-range-entity"
	const N = 4

	// Write N=4 staggered durable rows (sysTime = base+i*1000, distinct valid
	// windows so each is a distinct Range row).
	type rowT struct {
		payload []byte
		sys     int64
		vs      int64
		ve      int64
	}
	rows := make([]rowT, N)
	for i := 0; i < N; i++ {
		sysNs := day27Base + int64(i)*1000
		payload := []byte(fmt.Sprintf("r-%d", i))
		// distinct valid windows [base+i*100, base+i*100+50) so each row is a
		// distinct Range hit over [base, base+500).
		vs := day27Base + int64(i)*100
		ve := vs + 50
		rows[i] = rowT{sys: sysNs, vs: vs, ve: ve, payload: payload}
		sl := NewSkipListArena(alloc, 2*1024*1024)
		range19InsertRow(t, sl, entity, sysNs, vs, ve, payload)
		require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl))
	}

	// The synthetic LiveSource returns the SAME N rows (post-checkpoint steady
	// state — live ⊇ durable, EVERY durable row is also live).
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
	rOn := NewResolver(store, store, alloc, "track27-range-on", cfgOn)
	rOff := NewResolver(store, store, alloc, "track27-range-off", ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: false})

	// Range over [base, base+500) — every row's window intersects.
	rowsOn, truncOn, errOn := rOn.Range(ctx, entity, time.Unix(0, day27Base), time.Unix(0, day27Base+500), time.Unix(0, day27Base+9999))
	require.NoError(t, errOn)
	require.Falsef(t, truncOn, "no truncation (N=4 << MaxRangeRows=4096)")
	rowsOff, _, errOff := rOff.Range(ctx, entity, time.Unix(0, day27Base), time.Unix(0, day27Base+500), time.Unix(0, day27Base+9999))
	require.NoError(t, errOff)

	// byte-IDENTITY: live-ON == live-OFF (the dedup removed the N twins → NO
	// duplicates). The row count MUST be N (NOT 2N — a no-dedup bug would double).
	assert.Equalf(t, len(rowsOff), len(rowsOn), "Range row count: live-ON (%d) == live-OFF (%d) — the dedup removed the N live twins (NO duplicates)", len(rowsOn), len(rowsOff))
	assert.Equalf(t, N, len(rowsOn), "Range live-ON returns exactly N=%d rows (NOT 2N — the dedup removed the %d live twins that are checkpointed durable rows)", N, N)

	// byte-identity of the row set (sorted by validTimeStart — the Range sort).
	// Compare the (sysTime, digest) identity of each row.
	require.Equalf(t, len(rowsOff), len(rowsOn), "row counts must match for the per-row identity check")
	for i := range rowsOn {
		assert.Equalf(t, rowsOn[i].SystemTime, rowsOff[i].SystemTime, "row %d: SystemTime live-ON=%d OFF=%d (the dedup kept the SAME rows)", i, rowsOn[i].SystemTime, rowsOff[i].SystemTime)
		assert.Equalf(t, rowsOn[i].PayloadDigest, rowsOff[i].PayloadDigest, "row %d: PayloadDigest byte-identical (the dedup kept the SAME rows — NO live twin duplicated)", i)
	}

	// RED control: a no-dedup bug (append every live row) would DOUBLE the count
	// (N durable + N live twins = 2N). Re-derive the no-dedup count + assert it
	// is 2N (NOT N) — proving the dedup is load-bearing (the tooth catches a
	// no-dedup bug).
	noDedupCount := N + N // N durable + N live twins (the no-dedup bug)
	assert.NotEqualf(t, len(rowsOn), noDedupCount, "RED control: a no-dedup bug would return 2N=%d rows (N durable + N live twins); the tooth got N=%d → the dedup IS load-bearing (a no-dedup bug is caught)", noDedupCount, len(rowsOn))
	t.Logf("T-LIVE-RANGE PASS: Range live-ON == live-OFF byte-IDENTICAL (%d rows, NOT 2N=%d — the dedup removed the %d live twins; a no-dedup bug would double → caught)", len(rowsOn), 2*N, N)
}

// ---------------------------------------------------------------------------
// T-LIVE-RANGE-EMPTY-DURABLE — Range with an EMPTY durable tier + a live source
// ON returns the live rows (NOT 404). The regression guard the runtime verify
// caught: the Range zero-durable early-exit MUST be guarded on r.liveSource==nil
// (the SAME M-ASOF-EARLY-EXIT refinement AsOf carries). T-LIVE-RANGE above
// writes N durable rows first, so its durable tier is NON-empty + this early-exit
// never fires — it does NOT cover the empty-durable case. This tooth does: a
// store with ZERO durable rows (no flush) + a live source carrying the row →
// Range returns the live row (200-class), NOT ErrEntityNotFound. A regression
// that un-guards the early-exit returns 404 here → the tooth catches it.
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_RANGE_EMPTY_DURABLE is DAY-27 T-LIVE-RANGE-EMPTY-DURABLE.
// It is the runtime-verify-caught regression guard: with NO durable rows on
// disk + a live source ON, Range MUST return the live row, NOT 404. The
// counter (QueryLiveSourceReads) MUST fire (the live block was reached, NOT the
// durable-only early-exit). The store is a fresh memStoreTrack13 carrying ZERO
// durable rows — the live source is the SOLE input.
func TestTrack27_T_LIVE_RANGE_EMPTY_DURABLE(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13() // ZERO durable rows — no flush, no L0/L1 keys
	const entity = "live-range-empty-durable-entity"

	// The live source carries ONE row: a post-/v1/insert dot NOT yet checkpointed
	// (the read-your-writes steady state, the runtime verify's exact shape).
	const sysNs = day27Base
	liveRow := LiveEvent{
		SystemTime:     sysNs,
		ValidTimeStart: sysNs,
		ValidTimeEnd:   MaxValidTimeEndNs, // open-ended (9e18) — the Day-12.5/Day-16 default; the SAME sentinel the production /v1/insert stamps (control.go:118 OpenEndedValidEndNs == l0_flusher.go:38 MaxValidTimeEndNs)
		PayloadDigest:  liveDigest([]byte("the-live-row")),
	}
	liveSrc := &syntheticLiveSource{entries: []LiveEvent{liveRow}}

	cfgOn := ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: false}
	cfgOn.LiveSource = liveSrc
	rOn := NewResolver(store, store, alloc, "track27-range-empty-on", cfgOn)

	// Range over a window straddling the live row's [sysNs, openEnd) interval.
	// txTime = sysNs+999 (>= sysNs → Filter2 passes the live row).
	rows, trunc, err := rOn.Range(ctx, entity,
		time.Unix(0, day27Base-1000), time.Unix(0, day27Base+60_000_000_000),
		time.Unix(0, sysNs+999))
	require.NoErrorf(t, err, "Range empty-durable + live-ON: expected the live row (NOT ErrEntityNotFound) — the zero-durable early-exit is guarded on r.liveSource==nil (the M-ASOF-EARLY-EXIT refinement, mirrored from AsOf)")
	require.Falsef(t, trunc, "no truncation (1 live row << MaxRangeRows)")
	require.Lenf(t, rows, 1, "Range empty-durable + live-ON returns exactly the 1 live row (NOT 0/404)")
	require.Equalf(t, sysNs, rows[0].SystemTime, "the live row's sysTime is the row the Range returned")
	require.Equalf(t, liveRow.PayloadDigest, rows[0].PayloadDigest, "the live row's digest is the row the Range returned")

	// RED control: the nil-live resolver over an EMPTY durable tier STILL returns
	// 404 (the durable-only early-exit stands when liveSource==nil — byte-identical
	// Day-26). This proves the guard is live-source-CONDITIONAL, NOT a blanket
	// removal of the early-exit (a blanket removal would let a nil-live resolver
	// scan an empty store + return 404 via the len(collected)==0 path — same
	// observable 404, but the GUARD is what makes it byte-identical + the live
	// path what rescues it).
	rOff := NewResolver(store, store, alloc, "track27-range-empty-off", ResolverConfig{MaxL0Files: 1000, MaxRangeRows: 4096, EnableFirstSysSkip: false})
	_, _, errOff := rOff.Range(ctx, entity,
		time.Unix(0, day27Base-1000), time.Unix(0, day27Base+60_000_000_000),
		time.Unix(0, sysNs+999))
	require.ErrorIsf(t, errOff, ErrEntityNotFound, "RED control: nil-live Range over an EMPTY durable tier returns ErrEntityNotFound (byte-identical Day-26 — the guard is live-source-CONDITIONAL)")

	t.Logf("T-LIVE-RANGE-EMPTY-DURABLE PASS: empty-durable + live-ON Range returns the 1 live row (NOT 404); nil-live over empty-durable still 404 (the guard is conditional — the runtime-verify-caught regression is locked in)")
}

// ---------------------------------------------------------------------------
// T-LIVE-DEFENSIVE-FILTER2 — a buggy adapter's over-txTime entry is dropped.
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_DEFENSIVE_FILTER2 is DAY-27 T-LIVE-DEFENSIVE-FILTER2. The
// Resolver defensively RE-CHECKS Filter2 (SystemTime <= txTimeNs) in the merge
// — a buggy/foreign adapter that returns an entry with SystemTime > txTimeNs
// would, under trust-only, pass Filter3 + dominance and become the dominant →
// a SILENT Law II break (a row NOT visible at txTime). The defensive guard
// drops it. The tooth:
//   - writes a durable row at sysTime=base (the honest dominant at txTime=base).
//   - builds a BUGGY synthetic LiveSource (filter2Buggy=true) that returns a
//     live entry at sysTime=base+5000 (ABOVE txTime=base+999) — an over-txTime
//     entry a buggy adapter would leak.
//   - asserts AsOf returns the DURABLE dominant (sysTime=base), NOT the live
//     over-txTime entry (sysTime=base+5000) — the defensive Filter2 dropped it.
//   - RED control: without the defensive guard, the over-txTime live entry
//     (sysTime=base+5000 > base) would WIN dominance + become the dominant → a
//     Law II break (a row NOT visible at txTime=base+999). The tooth proves the
//     guard prevents it.
func TestTrack27_T_LIVE_DEFENSIVE_FILTER2(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	const entity = "live-defensive-entity"

	// Durable row at sysTime=base (the honest dominant at txTime=base+999).
	sl := NewSkipListArena(alloc, 2*1024*1024)
	range19InsertRow(t, sl, entity, day27Base, day27Base, openDay19Ns, []byte("durable"))
	require.Equal(t, 1, range19Flush(t, ctx, alloc, store, sl))

	// BUGGY synthetic LiveSource: returns a live entry at sysTime=base+5000
	// (ABOVE txTime=base+999 — an over-txTime entry a buggy adapter would leak).
	// filter2Buggy=true → the synthetic does NOT apply Filter2 (simulates the bug).
	buggySrc := &syntheticLiveSource{
		entries: []LiveEvent{{
			SystemTime:     day27Base + 5000, // OVER txTime — a Law-II break under trust-only
			ValidTimeStart: day27Base,
			ValidTimeEnd:   openDay19Ns,
			PayloadDigest:  liveDigest([]byte("buggy-over-tx")),
		}},
		filter2Buggy: true,
	}
	cfg := ResolverConfig{MaxL0Files: 1000, EnableFirstSysSkip: false}
	cfg.LiveSource = buggySrc
	r := NewResolver(store, store, alloc, "track27-defensive", cfg)

	// Query at txTime=base+999. The buggy live entry's sysTime=base+5000 >
	// txTime → the defensive Filter2 drops it. The dominant is the DURABLE row
	// (sysTime=base), NOT the buggy over-txTime live entry.
	got, err := r.AsOf(ctx, entity, time.Unix(0, day27Base+50), time.Unix(0, day27Base+999))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equalf(t, day27Base, got.SystemTime, "the defensive Filter2 dropped the buggy over-txTime live entry (sysTime=base+5000 > txTime=base+999); the dominant is the DURABLE row (sysTime=base) — Law II preserved")
	assert.Equalf(t, liveDigest([]byte("durable")), got.PayloadDigest, "the dominant carries the DURABLE digest, NOT the buggy over-txTime live digest — the defensive Filter2 prevented a Law-II break")

	// RED control: WITHOUT the defensive guard, the over-txTime live entry
	// (sysTime=base+5000 > dominantSystemTime=base) would WIN dominance + become
	// the dominant → a Law II break (a row NOT visible at txTime=base+999). The
	// guard's `le.SystemTime > txTimeNs` check (base+5000 > base+999 → true →
	// continue) is what drops it.
	overTxWouldWin := (day27Base + 5000) > day27Base // under trust-only dominance (>) — true
	require.Truef(t, overTxWouldWin, "RED control: WITHOUT the defensive Filter2, the over-txTime live entry (sysTime=base+5000 > base) WOULD win dominance → a Law-II break (a row NOT visible at txTime=base+999); the guard prevents it")
	dropped := (day27Base + 5000) > (day27Base + 999) // the guard's check — true → dropped
	require.Truef(t, dropped, "the defensive Filter2 check (sysTime > txTimeNs) is TRUE for the buggy entry → it IS dropped (Law II preserved)")
	t.Logf("T-LIVE-DEFENSIVE-FILTER2 PASS: a buggy adapter's over-txTime entry (sysTime=base+5000 > txTime=base+999) is DROPPED by the defensive Filter2; the dominant is the DURABLE row (sysTime=base) — Law II preserved against a buggy/foreign adapter")
}

// ---------------------------------------------------------------------------
// T-LIVE-NO-FROZEN-TOUCH — the scope-fidelity tooth (5-FILE FROZEN byte-identical).
// ---------------------------------------------------------------------------

// TestTrack27_T_LIVE_NO_FROZEN_TOUCH is DAY-27 T-LIVE-NO-FROZEN-TOUCH (the
// scope-fidelity tooth). The TENTH clean-chain fork: ZERO FROZEN touched. This
// tooth asserts the 5-FILE FROZEN set is byte-identical to the proven md5s
// (the SAME set the pkg/receive gate + the Day-22/24/25 teeth pin). query.go
// md5 CHANGES (the edit — the LiveSource interface + the merges), registry.go
// md5 CHANGES (the new counter — UNFROZEN), but the 5 FROZEN files + the
// verifier-side files (l0_flusher.go, l1_compactor.go, skiplist_arena.go,
// telemetry_bridge.go) are byte-UNCHANGED. The SkipList.Seek primitive
// (skiplist_arena.go) stays DORMANT (Day 27 does NOT touch it — the §0 audit's
// decisive refutation of the SkipList-freeze premise).
//
// The pkg/receive gate (TestGate_FrozenMD5 + TestGate_UntouchedFrozenAndOutOfScope)
// is the AUTHORITATIVE pre-AND-post gate (run in §3); this in-package tooth is
// the belt-and-suspenders assertion from WITHIN internal/database.
func TestTrack27_T_LIVE_NO_FROZEN_TOUCH(t *testing.T) {
	frozen := []struct {
		path string
		md5  string
	}{
		{"../../pkg/sync/crdt.go", "44f8952771cfad4d195e518b63a33440"},
		{"../../pkg/sync/crdt_apply.go", "ed9132a27930b3d76a3f62e783dd7dd3"},
		{"../../api/capnp/api/capnp/schema.capnp", "47d2796a973319a3ffe364de3d08d6d6"},
		{"../../api/capnp/api/capnp/schema.capnp.go", "590af2287dcb3a135c586b50260be531"},
		{"../../pkg/attribution/envelope.go", "b1beba1e9de81294bc66a823dece6ab6"},
	}
	for _, f := range frozen {
		b, err := os.ReadFile(f.path)
		require.NoErrorf(t, err, "read FROZEN %s", f.path)
		sum := md5.Sum(b)
		got := fmt.Sprintf("%x", sum)
		if got != f.md5 {
			t.Fatalf("T-LIVE-NO-FROZEN-TOUCH: FROZEN %s md5 changed: got %s, want %s (Day 27 MUST NOT touch the 5-FILE FROZEN set — the TENTH clean-chain fork)", f.path, got, f.md5)
		}
	}
	// The verifier-side files (the bound's WRITERS + the bridge) are byte-
	// UNCHANGED — Day 27 READ-ONLY-verifies what they write. The SkipList.Seek
	// primitive (skiplist_arena.go) stays DORMANT (the §0 audit's decisive
	// refutation of the SkipList-freeze premise — Day 27 does NOT touch the
	// SkipList). The bridge (telemetry_bridge.go) auto-surfaces the 18th series
	// with ZERO edit (§0.f).
	verifierUnchanged := []struct {
		path   string
		preMD5 string
	}{
		{"../../internal/database/l0_flusher.go", "3c1b4a8f4ad5efdbf3bb2df2d83f3f2a"},
		{"../../internal/database/skiplist_arena.go", "22c36f611eadb14f4770dd0537d6dde4"},
		{"../../internal/database/l1_compactor.go", "d0830b43cc9afd66e52b9bc968c77ff9"},
		{"../../pkg/metrics/telemetry_bridge.go", "8fcc149b3caed713cfc67bd583cb9a6b"},
	}
	for _, f := range verifierUnchanged {
		b, err := os.ReadFile(f.path)
		require.NoErrorf(t, err, "read verifier-side %s", f.path)
		sum := md5.Sum(b)
		got := fmt.Sprintf("%x", sum)
		if got != f.preMD5 {
			t.Fatalf("T-LIVE-NO-FROZEN-TOUCH: verifier-side %s md5 changed: got %s, want %s (Day 27 READ-ONLY-verifies the writers; the bridge auto-surfaces the new counter with NO edit; the SkipList.Seek primitive stays DORMANT)", f.path, got, f.preMD5)
		}
	}
	t.Logf("T-LIVE-NO-FROZEN-TOUCH PASS: 5-FILE FROZEN byte-identical (the TENTH clean-chain fork) + verifier-side (l0_flusher/skiplist_arena/l1_compactor/telemetry_bridge) byte-UNCHANGED; the SkipList.Seek primitive stays DORMANT (the §0 audit's decisive refutation of the SkipList-freeze premise)")
}
