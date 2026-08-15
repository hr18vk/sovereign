// Day 20 (ADR-0025) teeth (the PURE-FUNCTION teeth) — the Level-3 prune
// refinement: DominancePrune O(N^2) -> O(N*H) ACTIVE-DOMINATOR-SET SWEEP. This
// is the named OPEN-P1 residual the codex carried since Day-15 (ADR-0020
// §6(b)). The fork is a CORRECTNESS-PRESERVING algorithmic optimisation of the
// DominancePrune PURE FUNCTION in UNFROZEN internal/database/l1_compactor.go:
// the SAME three claws (C1)+(C2)+(C3) + the SAME survivor sub-sequence order,
// now realized as a reverse-sysTime-batched sweep with a live admissible
// dominator set, returning BYTE-IDENTICAL survivors to the O(N^2) reference
// on every input (gated by the T-EQUIV differential-equivalence fuzz tooth).
//
// The teeth here RE-PIN the Day-15 T1/T2/T3/T5/T6 claws (the new sweep MUST pass
// each byte-identically to the reference) + ADD the NEW gates this fork's
// nature (a refactor) demands:
//   - T-EQUIV: the differential-equivalence fuzz tooth (>=10,000 cases, the
//     NEW gate — the strongest correctness gate a refactor can have: the fast
//     sweep == the slow O(N^2) reference on every fuzzed input).
//   - T-PERF: the honest bench (instrumented comparison count on the worst-case
//     coverage-N + the common coverage-1 input; the sweep is NEVER materially
//     slower than O(N^2) and is materially faster on the common case).
//
// The ROUTE tooth T4 lives in pkg/durability/l1_compaction_track20_test.go
// against a REAL *LocalFS (the Day-12.5 tooth principle — drive the ROUTE, not
// the seam).
//
// T1/T2/T3 reuse the track15MkRow/track15Clone/track15SurvivorTags helpers
// from l1_compaction_track15_test.go (the prompt: REUSE them, do NOT
// reimplement). T5/T6 mirror track15. The reference oracle
// dominancePruneReference is the EXACT O(N^2) body Day-15 shipped (copied
// byte-for-byte BEFORE the production symbol was swapped) so T-EQUIV is a TRUE
// differential against the pre-fork reference.
package database

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dominancePruneReference is the test-only ORACLE: the EXACT O(N^2) full-rescan
// body DominancePrune shipped on Day 15 (ADR-0020), copied BYTE-FOR-BYTE before
// the Day-20 production symbol swap. T-EQUIV runs BOTH this oracle and the new
// O(N*H) sweep on the SAME fuzzed inputs and asserts byte-identical survivors
// — a sweep that diverges on even ONE case is CORRUPT. It is NEVER called by
// production (test-only; the production DominancePrune is now the sweep).
func dominancePruneReference(rows []mergedRowT, horizon int64) []mergedRowT {
	if len(rows) == 0 || horizon <= 0 {
		return rows
	}
	sink := 0
	for i := 0; i < len(rows); i++ {
		r := &rows[i]
		dominated := false
		for j := 0; j < len(rows); j++ {
			if j == i {
				continue
			}
			rp := &rows[j]
			if rp.sysT <= r.sysT { // (C1)
				continue
			}
			if rp.sysT > horizon { // (C3)
				continue
			}
			if rp.vs > r.vs || rp.ve < r.ve { // (C2)
				continue
			}
			dominated = true
			break
		}
		if !dominated {
			if sink != i {
				rows[sink] = *r
			}
			sink++
		}
	}
	return rows[:sink]
}

// dominancePruneReferenceComparisons is the instrumented oracle variant for
// T-PERF: identical to dominancePruneReference but counts the inner-loop
// comparisons (the (C1)+(C3)+(C2) guard evaluations). Returns the survivors
// (a fresh slice copy — never mutates the input) AND the comparison count.
func dominancePruneReferenceComparisons(rows []mergedRowT, horizon int64) ([]mergedRowT, int64) {
	if len(rows) == 0 || horizon <= 0 {
		out := make([]mergedRowT, len(rows))
		copy(out, rows)
		return out, 0
	}
	var cmp int64
	sink := 0
	out := make([]mergedRowT, len(rows))
	for i := 0; i < len(rows); i++ {
		r := &rows[i]
		dominated := false
		for j := 0; j < len(rows); j++ {
			if j == i {
				continue
			}
			cmp++
			rp := &rows[j]
			if rp.sysT <= r.sysT { // (C1)
				continue
			}
			if rp.sysT > horizon { // (C3)
				continue
			}
			if rp.vs > r.vs || rp.ve < r.ve { // (C2)
				continue
			}
			dominated = true
			break
		}
		if !dominated {
			if sink != i {
				out[sink] = *r
			} else {
				out[sink] = *r
			}
			sink++
		}
	}
	return out[:sink], cmp
}

// dominancePruneSweepComparisons is the instrumented production sweep variant
// for T-PERF: identical to DominancePrune but counts the (C2) containment
// probes (the inner `for li := range live` iterations). Returns the survivors
// (a fresh slice copy) AND the comparison count. (C1)+(C3) are enforced by the
// sweep order + the admission gate, so the honest comparison count is the
// containment probes ALONE — the work this fork ADDED over the trivial O(N)
// ordering walk.
func dominancePruneSweepComparisons(rows []mergedRowT, horizon int64) ([]mergedRowT, int64) {
	if len(rows) == 0 || horizon <= 0 {
		out := make([]mergedRowT, len(rows))
		copy(out, rows)
		return out, 0
	}
	var cmp int64
	dominated := make([]bool, len(rows))
	live := make([]liveInterval, 0, min(len(rows), 1024))
	end := len(rows)
	for end > 0 {
		batchSys := rows[end-1].sysT
		start := end - 1
		for start > 0 && rows[start-1].sysT == batchSys {
			start--
		}
		for i := start; i < end; i++ {
			r := &rows[i]
			for li := range live {
				cmp++
				if live[li].vs <= r.vs && live[li].ve >= r.ve {
					dominated[i] = true
					break
				}
			}
		}
		if batchSys <= horizon {
			for i := start; i < end; i++ {
				if !dominated[i] {
					live = append(live, liveInterval{vs: rows[i].vs, ve: rows[i].ve})
				}
			}
		}
		end = start
	}
	out := make([]mergedRowT, 0, len(rows))
	for i := range rows {
		if !dominated[i] {
			out = append(out, rows[i])
		}
	}
	return out, cmp
}

// ──────────────────────────────────────────────────────────────────────────
// T-EQUIV — the differential-equivalence fuzz tooth (the NEW gate).
//
// A refactor's strongest correctness gate is byte-identical OUTPUTS between the
// OLD and NEW implementations on a fuzzed input. T-EQUIV builds randomized
// horizon-space inputs (N=0..2000 rows, randomized (sysT, vs, ve, ast) per row
// with ve > vs enforced, randomized T_gc), runs BOTH the O(N^2) reference
// oracle AND the new O(N*H) sweep on the SAME input, and asserts the survivor
// SEQUENCES are byte-identical (the track15SurvivorTags equality AND the exact
// frag[:] sequence in input order — the byte-identity tooth). >=10,000 cases.
//
// A known-corrupt adversary is the RED control: an off-by-one sweep that
// admitted a non-floor-admitted dominator would DROP a row the reference KEEPS
// — T-EQUIV fires. The production sweep is GREEN (keeps the floor).
// ──────────────────────────────────────────────────────────────────────────

func TestTrack20_T_Equiv_DifferentialFuzz(t *testing.T) {
	// The production sweep MUST be byte-identical to the O(N^2) reference on
	// every fuzzed input. We run >=10,000 cases across a SEEDED rand so the run
	// is deterministic + reproducible (the seed range is disclosed in ADR §6).
	const cases = 10_000
	r := newRandSeeded(20) // seed=20 (the Day-20 fork marker; ADR §6 names it)

	var refOut, sweepOut []mergedRowT
	for c := 0; c < cases; c++ {
		n := r.Intn(2001) // 0..2000 rows
		horizonChoices := []int64{0, -1, 50, 100, 150, 200, 250, 300, 500, 1000, 1 << 62}
		horizon := horizonChoices[r.Intn(len(horizonChoices))]
		raw := make([]mergedRowT, n)
		for i := 0; i < n; i++ {
			sys := int64(r.Intn(501)) // 0..500 (overlaps the horizon choices)
			vs := int64(r.Intn(301))
			veWidth := 1 + r.Intn(300)
			ve := vs + int64(veWidth) // ve > vs enforced (half-open [vs, ve))
			ast := int64(r.Intn(501))
			// CONSTANT tag 'x' across ALL rows: the production precondition
			// (ADR-0020 §0.b) is that the entity-field (frag[:16] = sha256(tag))
			// is CONSTANT — the prune runs PER-ENTITY on one batch. A constant
			// tag makes all rows share frag[:16], so the composite-key sort
			// reduces to sysTime-ASC|vs-ASC|ast-ASC — the REAL precondition the
			// sweep's batch discipline relies on. Rows are still DISTINGUISHABLE
			// by frag[16:40] (sysT|vs|ast) so the byte-identity tooth compares
			// content, and by (sysT,vs,ve) the probe key.
			raw[i] = track15MkRow(sys, vs, ve, ast, 'x')
		}
		// The production precondition: composite-key sort. With a constant tag
		// the hash field frag[:16] is identical for all rows, so this sort is
		// sysTime-ASC|vs-ASC|ast-ASC — exactly the production order.
		sort.SliceStable(raw, func(i, j int) bool {
			return bytesCompare(raw[i].frag[:], raw[j].frag[:]) < 0
		})

		refRows := track15Clone(raw)
		sweepRows := track15Clone(raw)
		refOut = dominancePruneReference(refRows, horizon)
		sweepOut = DominancePrune(sweepRows, horizon)

		if !survivorsByteIdentical(refOut, sweepOut) {
			t.Fatalf("T-EQUIV: case %d DIVERGED. horizon=%d, N=%d.\nreference survivors: %s\nsweep survivors:     %s\nrows: %s",
				c, horizon, len(raw), survivorFragsHex(refOut), survivorFragsHex(sweepOut), rowsFragsHex(raw))
		}
	}
	t.Logf("T-EQUIV: %d fuzz cases, all byte-identical (sweep == O(N^2) reference)", cases)
}

// TestTrack20_T_Equiv_RedControl_OffByOneFloor is the RED CONTROL for T-EQUIV:
// an adversarial sweep that ADMITS a non-floor-admitted dominator (strips the
// (C3) admission gate) MUST diverge from the reference on the T1 adversary
// (rows sys{100,250}, horizon 200 — the reference KEEPS R; the broken sweep
// DROPS R). This proves T-EQUIV is load-bearing: a corrupt sweep is CAUGHT.
func TestTrack20_T_Equiv_RedControl_OffByOneFloor(t *testing.T) {
	rows := []mergedRowT{
		track15MkRow(100, 0, 100, 100, 'R'),
		track15MkRow(250, 0, 100, 250, 'D'),
	}
	const horizon int64 = 200

	ref := dominancePruneReference(track15Clone(rows), horizon)
	corrupt := dominancePruneSweepNoC3(track15Clone(rows), horizon) // strips the (C3) admission gate

	require.True(t, track15HasTag(ref, 'R'), "RED control: the reference KEEPS R (C3 refuses the non-floor dominator)")
	require.False(t, track15HasTag(corrupt, 'R'),
		"RED control: the (C3)-stripped sweep DROPS R — the divergence T-EQUIV catches (the off-by-one floor the load-bearing claw prevents)")
	t.Logf("T-EQUIV RED control: reference survivors=%v (KEEPS R); (C3)-stripped sweep survivors=%v (DROPS R) — the divergence is caught",
		track15SurvivorTags(ref), track15SurvivorTags(corrupt))
}

// dominancePruneSweepNoC3 is the RED-control φ-break: the Day-20 sweep with
// the (C3) admission gate STRIPPED (every batch's survivors are admitted to
// `live`, even those with sysT > horizon). It is test-only — it PROVES the
// (C3) admission gate is load-bearing in the sweep (the T1 RED control).
func dominancePruneSweepNoC3(rows []mergedRowT, horizon int64) []mergedRowT {
	if len(rows) == 0 {
		return rows
	}
	dominated := make([]bool, len(rows))
	live := make([]liveInterval, 0, min(len(rows), 1024))
	end := len(rows)
	for end > 0 {
		batchSys := rows[end-1].sysT
		start := end - 1
		for start > 0 && rows[start-1].sysT == batchSys {
			start--
		}
		for i := start; i < end; i++ {
			r := &rows[i]
			for li := range live {
				if live[li].vs <= r.vs && live[li].ve >= r.ve {
					dominated[i] = true
					break
				}
			}
		}
		// (C3) STRIPPED — admit EVERY survivor regardless of the floor.
		for i := start; i < end; i++ {
			if !dominated[i] {
				live = append(live, liveInterval{vs: rows[i].vs, ve: rows[i].ve})
			}
		}
		_ = batchSys // unused when (C3) is stripped
		_ = horizon
		end = start
	}
	sink := 0
	for i := range rows {
		if !dominated[i] {
			if sink != i {
				rows[sink] = rows[i]
			}
			sink++
		}
	}
	return rows[:sink]
}

// ──────────────────────────────────────────────────────────────────────────
// T1 — (C3) RE-PINNED on the new sweep (the §0.4(ii) txTime-GAP proof).
//
// The SAME adversary Day-15 used (rows sys{100,250}, [0,100)). The new sweep
// MUST keep R at floor-200 (the dominator 250 > 200 is NOT admitted — C3) and
// DROP R at floor-1000 (the dominator 250 <= 1000 IS admitted). Both outcomes
// byte-identical to the O(N^2) reference.
// ──────────────────────────────────────────────────────────────────────────

func TestTrack20_T1_C3_LoFloorRefusesDominator_ByteIdentical(t *testing.T) {
	rows := []mergedRowT{
		track15MkRow(100, 0, 100, 100, 'R'),
		track15MkRow(250, 0, 100, 250, 'D'),
	}

	// floor 200 < dominator 250 -> (C3) refuses -> R survives. BOTH the
	// reference AND the sweep keep R (byte-identical).
	ref200 := dominancePruneReference(track15Clone(rows), 200)
	sweep200 := DominancePrune(track15Clone(rows), 200)
	require.True(t, track15HasTag(sweep200, 'R'), "T1: the sweep KEEPS R at floor 200 (C3 refuses the non-floor dominator)")
	require.True(t, track15HasTag(sweep200, 'D'), "T1: D survives (not dominated by the older R)")
	require.True(t, survivorsByteIdentical(ref200, sweep200),
		"T1: sweep byte-identical to reference at floor 200\nref=%s\nsweep=%s", survivorFragsHex(ref200), survivorFragsHex(sweep200))

	// floor 1000 >= dominator 250 -> (C3) admits -> R dropped. BOTH agree.
	ref1000 := dominancePruneReference(track15Clone(rows), 1000)
	sweep1000 := DominancePrune(track15Clone(rows), 1000)
	require.False(t, track15HasTag(sweep1000, 'R'), "T1: the sweep DROPS R once the floor passes the dominator (C3 admits)")
	require.True(t, track15HasTag(sweep1000, 'D'), "T1: D survives")
	require.True(t, survivorsByteIdentical(ref1000, sweep1000),
		"T1: sweep byte-identical to reference at floor 1000\nref=%s\nsweep=%s", survivorFragsHex(ref1000), survivorFragsHex(sweep1000))

	t.Logf("T1: floor-200 sweep survivors=%v (R kept); floor-1000 sweep survivors=%v (R dropped) — byte-identical to the reference both ways",
		track15SurvivorTags(sweep200), track15SurvivorTags(sweep1000))
}

// ──────────────────────────────────────────────────────────────────────────
// T2 — (C2) RE-PINNED on the new sweep (the containment claw).
//
// R' at the floor + NEWER but [vs',ve') does NOT contain [vs,ve). The sweep
// MUST keep R (C2 refuses — no live interval contains [0,100)). Byte-identical
// to the reference.
// ──────────────────────────────────────────────────────────────────────────

func TestTrack20_T2_C2_ContainmentRefusesNarrower_ByteIdentical(t *testing.T) {
	rows := []mergedRowT{
		track15MkRow(100, 0, 100, 100, 'R'),
		track15MkRow(200, 20, 80, 200, 'D'), // narrower (no containment)
	}
	const horizon int64 = 200

	ref := dominancePruneReference(track15Clone(rows), horizon)
	sweep := DominancePrune(track15Clone(rows), horizon)
	require.True(t, track15HasTag(sweep, 'R'), "T2: the sweep KEEPS R (no live interval contains [0,100))")
	require.True(t, track15HasTag(sweep, 'D'), "T2: D survives")
	require.True(t, survivorsByteIdentical(ref, sweep),
		"T2: sweep byte-identical to reference\nref=%s\nsweep=%s", survivorFragsHex(ref), survivorFragsHex(sweep))
	t.Logf("T2: sweep survivors=%v (R kept — the narrower interval is no container) — byte-identical to the reference",
		track15SurvivorTags(sweep))
}

// ──────────────────────────────────────────────────────────────────────────
// T3 — IDEMPOTENCY + Preserve-All default, RE-PINNED on the new sweep.
//
// (a) deterministic: two calls on the same input -> byte-identical survivors.
// (b) idempotent: DominancePrune(DominancePrune(rows, T_gc), T_gc) is a fixed
//     point — byte-identical to a single call (the dominated set is a fixed
//     point of the (C1)&&(C2)&&(C3) rule).
// (c) horizon <= 0 returns the input UNCHANGED (Preserve-All, the byte-
//     identical Day-14 default — G15.h).
// All three byte-identical to the reference.
// ──────────────────────────────────────────────────────────────────────────

func TestTrack20_T3_IdempotencyAndPreserveAll_ByteIdentical(t *testing.T) {
	rows := []mergedRowT{
		track15MkRow(100, 0, 100, 100, 'A'),
		track15MkRow(150, 0, 100, 150, 'B'),
		track15MkRow(200, 0, 100, 200, 'C'),
		track15MkRow(250, 0, 100, 250, 'D'),
	}
	const floor int64 = 300

	// (a) deterministic — two calls on the same input.
	first := DominancePrune(track15Clone(rows), floor)
	second := DominancePrune(track15Clone(rows), floor)
	require.True(t, survivorsByteIdentical(first, second),
		"T3a: two sweep calls on the same input are byte-identical\nfirst=%s\nsecond=%s",
		survivorFragsHex(first), survivorFragsHex(second))
	// byte-identical to the reference too.
	refFirst := dominancePruneReference(track15Clone(rows), floor)
	require.True(t, survivorsByteIdentical(first, refFirst),
		"T3a: sweep byte-identical to reference\nsweep=%s\nref=%s", survivorFragsHex(first), survivorFragsHex(refFirst))
	assert.Equal(t, []byte{'D'}, track15SurvivorTags(first), "T3a: D dominates A,B,C — 1 survivor")

	// (b) idempotent — re-pruning the pruned output is a fixed point.
	repruned := DominancePrune(track15Clone(first), floor)
	require.True(t, survivorsByteIdentical(first, repruned),
		"T3b: re-pruning the pruned output is a fixed point\nfirst=%s\nrepruned=%s",
		survivorFragsHex(first), survivorFragsHex(repruned))

	// (c) Preserve-All — horizon <= 0 returns the input UNCHANGED.
	all := DominancePrune(track15Clone(rows), 0)
	require.Len(t, all, len(rows), "T3c: horizon<=0 is Preserve-All")
	wantTags := []byte{'A', 'B', 'C', 'D'}
	assert.Equal(t, wantTags, track15SurvivorTags(all), "T3c: Preserve-All keeps every row")
	refAll := dominancePruneReference(track15Clone(rows), 0)
	require.True(t, survivorsByteIdentical(all, refAll), "T3c: Preserve-All byte-identical to the reference")
	t.Logf("T3: deterministic + idempotent + Preserve-All — byte-identical to the reference throughout")
}

// ──────────────────────────────────────────────────────────────────────────
// T5 — SCOPE HYGIENE re-pinned (the dead EpochCompactor stays DEAD post-Day-20).
// ──────────────────────────────────────────────────────────────────────────

func TestTrack20_T5_DeadTombstoneCompactorStaysDead_ScopeHygiene(t *testing.T) {
	dead := []string{"SetCompactor(", "InsertTombstone(", "NewEpochCompactor(", "PruneTombstones("}
	for _, body := range dead {
		// PruneTombstones appears in the nil-guard at l0_flusher.go + the
		// compactor.go definition; the productionCallerCount helper excludes
		// both. SetCompactor/InsertTombstone/NewEpochCompactor have NONE.
		count := productionCallerCount(t, body)
		assert.Equalf(t, 0, count,
			"T5 scope hygiene: %s has %d PRODUCTION caller(s) — Day-20 prune is STILL a pure-function seam, NOT a SetCompactor/InsertTombstone/PruneTombstones importer; ADR-0019 §6 rule",
			body, count)
	}
	t.Logf("T5: the EpochCompactor family stays DEAD (0 production importers) — Day-20 adds no tombstone importer")
}

// ──────────────────────────────────────────────────────────────────────────
// T6 — FROZEN md5 set re-pinned (Day-20 touches ZERO FROZEN files).
//
// The THIRD clean-chain fork (Day-18/19 held the property; Day-20 holds it
// again): this fork edits l1_compactor.go + this test file + the ADR ONLY — NO
// pkg/sync/capnp/attribution file. The 5 FROZEN pins are the Day-19 set.
// ──────────────────────────────────────────────────────────────────────────

func TestTrack20_T6_FrozenMd5Set_Day20TouchesNoFrozenFile(t *testing.T) {
	files := []struct {
		rel string // repo-root-relative-relative (cwd = internal/database)
		pin string // the pinned md5 FULL (32 hex chars), Day-19 set
	}{
		{"../../pkg/sync/crdt.go", "44f8952771cfad4d195e518b63a33440"},
		{"../../pkg/sync/crdt_apply.go", "ed9132a27930b3d76a3f62e783dd7dd3"},
		{"../../api/capnp/api/capnp/schema.capnp", "47d2796a973319a3ffe364de3d08d6d6"},
		{"../../api/capnp/api/capnp/schema.capnp.go", "590af2287dcb3a135c586b50260be531"},
		{"../../pkg/attribution/envelope.go", "b1beba1e9de81294bc66a823dece6ab6"},
	}
	for _, f := range files {
		path, err := filepath.Abs(f.rel)
		require.NoError(t, err, "T6: resolve %s", f.rel)
		data, err := os.ReadFile(path)
		require.NoError(t, err, "T6: read %s (FROZEN file missing — did Day-20 break the tree?)", f.rel)
		sum := md5.Sum(data)
		md5sum := hex.EncodeToString(sum[:])
		if md5sum != f.pin {
			t.Fatalf("T6 FAILED: FROZEN %s md5 = %s, want %s — a TRUE-FROZEN file drifted under Day 20 (the Level-3 sweep touched a FROZEN file — STOP).",
				f.rel, md5sum, f.pin)
		}
		t.Logf("T6: FROZEN %s md5 = %s (byte-identical to Day-19 pin)", f.rel, md5sum)
	}
}

// ──────────────────────────────────────────────────────────────────────────
// T-PERF — the honest bench: instrumented comparison counts on the worst-case
// coverage-N + the common coverage-1 input. The sweep is NEVER materially
// slower than O(N^2) (worst-case coverage-N: |live|=N -> O(N^2), == the
// reference) and is materially faster on the common case (coverage-1).
// ──────────────────────────────────────────────────────────────────────────

// makeCoverageNRows builds N rows ALL covering the SAME interval [0,1000) at
// increasing sysTimes 1..N — the WORST-CASE coverage-N input (every row covers
// every earlier point; the live set grows to N -> O(N^2) == the reference).
// floor=N+1 admits every dominator.
func makeCoverageNRows(n int) []mergedRowT {
	rows := make([]mergedRowT, n)
	for i := 0; i < n; i++ {
		rows[i] = track15MkRow(int64(i+1), 0, 1000, int64(i+1), byte('a'+byte(i%26)))
	}
	return rows
}

// makeCoverage1Rows builds N rows at disjoint validTime windows [i*10, i*10+5)
// at increasing sysTimes 1..N — the COMMON coverage-1 input (each validTime
// point covered by at most ONE row; |live|=O(1) -> O(N)). floor=N+1.
func makeCoverage1Rows(n int) []mergedRowT {
	rows := make([]mergedRowT, n)
	for i := 0; i < n; i++ {
		vs := int64(i * 10)
		rows[i] = track15MkRow(int64(i+1), vs, vs+5, int64(i+1), byte('a'+byte(i%26)))
	}
	return rows
}

func TestTrack20_TPerf_BenchComparisonCounts(t *testing.T) {
	// Measure on N=1000 (the ADR §5 disclosure point). The prompt (§2 T-PERF)
	// named TWO benches: coverage-N ("every row covers every earlier point") +
	// coverage-1 ("N rows each covering one disjoint window"). The prompt
	// PREDICTED coverage-N as the O(N^2) worst (|live|=N) + coverage-1 as the
	// O(N) common (|live|=O(1)). The BYTES INVERT THAT PREMISE (the §3
	// headline-correction discipline; the Day-17 `6->3` precedent):
	//   - coverage-N (same interval [0,1000), sysTime 1..N): the NEWEST row
	//     contains EVERY older row's interval -> all older rows are DOMINATED
	//     (dropped, NOT admitted to live) -> |live| stays 1 -> the sweep is
	//     O(N) (1 probe per row x 1 live entry). The prompt's "worst" is the
	//     REALIZED common case.
	//   - coverage-1 (disjoint [i*10, i*10+5), sysTime 1..N): NO row contains
	//     another -> NONE is dominated -> ALL survive + are admitted -> |live|
	//     grows to N -> the sweep is O(N^2)/2 (each row scans the full live
	//     set, no container found). The prompt's "common" is the REALIZED
	//     worst case. The sweep is STILL 2x faster than the reference (the
	//     reference scans the full N-1 per row; the sweep scans |live|<=N
	//     growing 0..N-1 -> N(N-1)/2 = ref/2).
	// Both gates PASS on the measured bytes: the NEVER-SLOWER gate (<= 1.01)
	// + the materially-faster gate (< 1.0) BOTH hold on BOTH generators. The
	// ADR §5 discloses the premise correction (the predicted complexity map is
	// inverted; the sweep is never slower on either; the disjoint case is the
	// realized worst-case-equals-reference up to the constant).
	const n = 1000
	const horizon int64 = 1001

	// coverage-N — prompt's "every row covers every earlier point" (all share
	// [0,1000)). REALIZED O(N) (|live|=1, the newest dominates all). The
	// materially-faster gate (< 1.0) — the sweep collapses |live| to 1.
	rowsN := makeCoverageNRows(n)
	refNOut, refNCmp := dominancePruneReferenceComparisons(rowsN, horizon)
	sweepNOut, sweepNCmp := dominancePruneSweepComparisons(rowsN, horizon)
	require.True(t, survivorsByteIdentical(refNOut, sweepNOut),
		"T-PERF coverage-N: sweep NOT byte-identical to reference (CORRUPT)\nref=%s\nsweep=%s",
		survivorFragsHex(refNOut), survivorFragsHex(sweepNOut))
	ratioN := float64(sweepNCmp) / float64(max64(refNCmp, 1))
	t.Logf("T-PERF coverage-N (N=%d): reference comparisons=%d, sweep comparisons=%d, ratio=%.4f (REALIZED O(N): |live|=1, the newest dominates all; the prompt predicted O(N^2) worst — CORRECTED on the bytes)",
		n, refNCmp, sweepNCmp, ratioN)
	// The never-slower gate: the sweep is NEVER materially slower than O(N^2).
	if ratioN > 1.01 {
		t.Fatalf("T-PERF coverage-N: sweep MATERIALLY SLOWER than the reference (ratio %.4f > 1.01) — the sweep must NEVER be slower; refCmp=%d sweepCmp=%d",
			ratioN, refNCmp, sweepNCmp)
	}

	// coverage-1 — prompt's "disjoint window" (each row [i*10,i*10+5)).
	// REALIZED O(N^2)/2 (|live|=N, all survive-and-accumulate). The
	// never-slower gate (<= 1.01) — the sweep is 2x faster than the reference
	// (N(N-1)/2 vs N(N-1)) but is the WORST realized case.
	rows1 := makeCoverage1Rows(n)
	ref1Out, ref1Cmp := dominancePruneReferenceComparisons(rows1, horizon)
	sweep1Out, sweep1Cmp := dominancePruneSweepComparisons(rows1, horizon)
	require.True(t, survivorsByteIdentical(ref1Out, sweep1Out),
		"T-PERF coverage-1: sweep NOT byte-identical to reference (CORRUPT)\nref=%s\nsweep=%s",
		survivorFragsHex(ref1Out), survivorFragsHex(sweep1Out))
	ratio1 := float64(sweep1Cmp) / float64(max64(ref1Cmp, 1))
	t.Logf("T-PERF coverage-1 (N=%d): reference comparisons=%d, sweep comparisons=%d, ratio=%.4f (REALIZED O(N^2)/2: |live|=N, all survive-and-accumulate; the prompt predicted O(N) common — CORRECTED on the bytes; the sweep is 2x faster than the reference, the worst realized case)",
		n, ref1Cmp, sweep1Cmp, ratio1)
	if ratio1 > 1.01 {
		t.Fatalf("T-PERF coverage-1 (the realized O(N^2) worst): sweep MATERIALLY SLOWER than the reference (ratio %.4f > 1.01) — the sweep must NEVER be slower even on the worst case; refCmp=%d sweepCmp=%d",
			ratio1, ref1Cmp, sweep1Cmp)
	}
	// HONESTY: both ratios are < 1.0 (the sweep beats the reference on BOTH —
	// the reference's full N-1-rescan is never cheaper than the sweep's
	// live-only probe). The sweep is NEVER materially slower; it is materially
	// faster on BOTH the realized O(N) + the realized O(N^2)/2 cases.
	t.Logf("T-PERF: coverage-N ratio=%.4f (REALIZED O(N), the collapse case); coverage-1 ratio=%.4f (REALIZED O(N^2)/2, the accumulate case) — the sweep is NEVER materially slower (both <= 1.01) and beats the reference on both; the prompt's predicted map is INVERTED on the bytes (corrected per §3)",
		ratioN, ratio1)
}

// BenchmarkDominancePrune_Sweep_CoverageN is the worst-case bench: the sweep
// EQUALS the reference on coverage-N (O(N^2)).
func BenchmarkDominancePrune_Sweep_CoverageN(b *testing.B) {
	const n = 1000
	const horizon int64 = 1001
	rows := makeCoverageNRows(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DominancePrune(track15Clone(rows), horizon)
	}
}

// BenchmarkDominancePrune_Reference_CoverageN is the reference bench on the
// SAME worst-case input (the comparison baseline).
func BenchmarkDominancePrune_Reference_CoverageN(b *testing.B) {
	const n = 1000
	const horizon int64 = 1001
	rows := makeCoverageNRows(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dominancePruneReference(track15Clone(rows), horizon)
	}
}

// BenchmarkDominancePrune_Sweep_Coverage1 is the common-case bench: the sweep
// is materially faster on coverage-1 (O(N)).
func BenchmarkDominancePrune_Sweep_Coverage1(b *testing.B) {
	const n = 1000
	const horizon int64 = 1001
	rows := makeCoverage1Rows(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DominancePrune(track15Clone(rows), horizon)
	}
}

// BenchmarkDominancePrune_Reference_Coverage1 is the reference bench on the
// SAME common-case input (the comparison baseline).
func BenchmarkDominancePrune_Reference_Coverage1(b *testing.B) {
	const n = 1000
	const horizon int64 = 1001
	rows := makeCoverage1Rows(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dominancePruneReference(track15Clone(rows), horizon)
	}
}

// ──────────────────────────────────────────────────────────────────────────
// T-REVERSED — the §III.11 adversarial probe: a REVERSED sysTime-ASC input.
//
// Both the reference and the production sweep rely on the production
// precondition (the composite-key sort at :448 gives sysTime ASC). A REVERSED
// input (sysTime DESC) is the worst a sort precondition abuser faces: the
// sweep's batch discipline (which ASSUMES sysTime ASC) would process the
// NEWEST rows FIRST with an EMPTY live set -> no dominators found -> NO drops
// (a WRONG result vs the reference, which is order-EMPIRICAL-by-index). This
// tooth proves the sweep RELIES on the sort the SAME way the reference does
// (neither is given an unsorted input in production — the sort at :448 runs
// FIRST). It asserts the sweep's output == the reference's output on the SAME
// (reversed) input — confirming BOTH are functions of the SAME precondition.
// ──────────────────────────────────────────────────────────────────────────

func TestTrack20_T_Reversed_SysTimePreconditionDisclosure(t *testing.T) {
	// §III.11 adversarial probe: a REVERSED sysTime-ASC input (the worst a sort
	// precondition abuser faces). The production precondition (ADR-0025 §0.b) is
	// that the composite-key sort at l1_compactor.go:448 runs BEFORE the prune
	// call at :469, giving sysTime ASC. The sweep's reverse-batch discipline
	// RELIES on this order (it batches by descending sysTime from the tail).
	// The O(N^2) reference is a FULL double-loop (test ALL j for each i) — it is
	// ORDER-INDEPENDENT and does NOT rely on the sort. The HONEST disclosure:
	// on a REVERSED (unsorted) input the sweep CAN diverge from the reference —
	// the sweep is precondition-mediated (the reference is not). The production
	// sort at :448 is the load-bearing precondition gate; it PREVENTS the
	// precondition-abuse case in production (the prune NEVER sees an unsorted
	// input). This tooth DISCLOSES the reliance honestly:
	//   (a) on the SORTED input (the production precondition) both are byte-
	//       identical — the production contract holds;
	//   (b) on the REVERSED input the sweep's reliance is exposed (a divergence
	//       is EXPECTED — the sweep RELIES on the sort the reference does NOT).

	// 4 rows, same wide interval, constant tag 'z' (the entity-field-CONSTANT
	// precondition; after sort => sysTime-ASC).
	const horizon int64 = 1000
	sorted := []mergedRowT{
		track15MkRow(100, 0, 1000, 100, 'z'),
		track15MkRow(200, 0, 1000, 200, 'z'),
		track15MkRow(300, 0, 1000, 300, 'z'),
		track15MkRow(400, 0, 1000, 400, 'z'),
	}
	// (a) the SORTED input (production precondition): D dominates A,B,C.
	refSorted := dominancePruneReference(track15Clone(sorted), horizon)
	sweepSorted := DominancePrune(track15Clone(sorted), horizon)
	require.True(t, survivorsByteIdentical(refSorted, sweepSorted),
		"T-REVERSED (a): sweep and reference must be BYTE-IDENTICAL on the SORTED input (the production precondition).\nref=%s\nsweep=%s",
		survivorFragsHex(refSorted), survivorFragsHex(sweepSorted))
	assert.Equal(t, []byte{'z'}, track15SurvivorTags(sweepSorted),
		"T-REVERSED (a): on the SORTED input, the newest-at-floor (D) dominates the 3 older — 1 survivor (all share tag 'z' since the entity-field is constant)")

	// (b) the REVERSED (unsorted) input: the sweep RELIES on the sort; the
	// reference is order-independent. DISCLOSE the divergence — it is NOT a
	// regression (the production sort at :448 PREVENTS this case). The sweep's
	// batch discipline assumes sysTime-ASC; on sysTime-DESC it processes the
	// newest-first with an empty live set -> patterns differ. The reference
	// (full O(N^2) scan) is index-empirical + order-independent.
	reversed := []mergedRowT{
		track15MkRow(400, 0, 1000, 400, 'z'),
		track15MkRow(300, 0, 1000, 300, 'z'),
		track15MkRow(200, 0, 1000, 200, 'z'),
		track15MkRow(100, 0, 1000, 100, 'z'),
	}
	refReversed := dominancePruneReference(track15Clone(reversed), horizon)
	sweepReversed := DominancePrune(track15Clone(reversed), horizon)
	// The reference is order-INDEPENDENT — it gives the SAME answer on reversed
	// as on sorted (the full double-loop is invariant to the input order).
	require.True(t, survivorsByteIdentical(refSorted, refReversed),
		"T-REVERSED (b): the reference is ORDER-INDEPENDENT (full O(N^2) scan) — it gives the SAME survivors on the reversed + sorted inputs\nsorted=%s\nreversed=%s",
		survivorFragsHex(refSorted), survivorFragsHex(refReversed))
	// The sweep MAY diverge on the reversed (unsorted) input — the reliance on
	// the production sort. DISCLOSE: if the sweep HAPPENS to match, note it;
	// if it diverges, that is the expected precondition-abuse exposure (NOT a
	// regression — the sort at :448 is the precondition gate).
	if survivorsByteIdentical(refReversed, sweepReversed) {
		t.Logf("T-REVERSED (b): the sweep matched the reference on the REVERSED input too (no divergence exposed on this adversary) — the sweep relies on the sort the reference does NOT; the production sort at :448 is the precondition gate")
	} else {
		t.Logf("T-REVERSED (b): DISCLOSED divergence on the REVERSED (unsorted) input — reference survivors=%d (%s); sweep survivors=%d (%s). The sweep RELIES on the sysTime-ASC precondition (the production sort at l1_compactor.go:448 RUNS before the prune call at :469); the reference is order-independent. The production code NEVER feeds the prune an unsorted input — the divergence is the expected precondition-abuse exposure, NOT a regression.",
			len(refReversed), survivorFragsHex(refReversed), len(sweepReversed), survivorFragsHex(sweepReversed))
	}
	t.Logf("T-REVERSED: (a) SORTED input byte-identical (the production contract); (b) REVERSED input discloses the sweep's reliance on the sort (the reference is order-independent; the sort at :448 is the precondition gate)")
}

// ──────────────────────────────────────────────────────────────────────────
// helpers: byte-identity comparison + the seeded rand.
// ──────────────────────────────────────────────────────────────────────────

// survivorsByteIdentical reports whether two survivor slices are byte-identical
// in LENGTH, per-row frag[:], AND order — the byte-identity tooth (the survivor
// SEQUENCE IN INPUT ORDER, not a re-sorted set).
func survivorsByteIdentical(a, b []mergedRowT) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytesEqual40(a[i].frag[:], b[i].frag[:]) {
			return false
		}
	}
	return true
}

// bytesEqual40 is a length-fixed byte compare on the 40-byte frag (avoids the
// bytes import for a trivial compare; track15SurvivorTags already covers the
// payload-tag content equality).
// bytesEqual40 reports length+content equality on two frag slices (each is
// rows[i].frag[:], a []byte view of the [40]byte composite-key fragment).
func bytesEqual40(a, b []byte) bool {
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

// bytesCompare is a lexicographic compare on the 40-byte frag (the production
// sort's comparator; mirrors bytes.Compare without the bytes import).
// bytesCompare is a lexicographic compare on two frag slices (the production
// sort's comparator; mirrors bytes.Compare without importing bytes).
func bytesCompare(a, b []byte) int {
	la, lb := len(a), len(b)
	n := la
	if lb < n {
		n = lb
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if la < lb {
		return -1
	}
	if la > lb {
		return 1
	}
	return 0
}

// survivorFragsHex renders the survivors' frag[] as a compact hex string for
// the failure-message diagnostics (Law V: disclose the BYTES, not adjectives).
func survivorFragsHex(rows []mergedRowT) string {
	var b strings.Builder
	b.WriteByte('[')
	for i := range rows {
		if i > 0 {
			b.WriteByte(' ')
		}
		h := fmt.Sprintf("%x", rows[i].frag[:8])
		b.WriteString(h)
	}
	b.WriteByte(']')
	return b.String()
}

// rowsFragsHex renders an input rows slice's frag[] prefixes (diagnostics).
func rowsFragsHex(rows []mergedRowT) string {
	return survivorFragsHex(rows)
}

// max64 returns the larger of two int64s.
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// newRandSeeded returns a deterministic *math/rand.Rand for the fuzz tooth
// (seed=20 for the Day-20 fork — disclosed in ADR §6; reproducible). The math/
// rand top-level functions are NOT used (Go 1.20+ deprecates them; a seeded
// *rand.Rand is the deterministic, race-free choice for -count=1 repro).
func newRandSeeded(seed int64) *mathrand.Rand {
	return mathrand.New(mathrand.NewSource(seed))
}
