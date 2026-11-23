// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Differential and performance tests for the O(N*H) active-dominator-set sweep
// in DominancePrune (ADR-0025), comparing it against the O(N^2) reference
// implementation across randomized horizon inputs and edge cases. End-to-end
// *LocalFS tests live in pkg/durability.
package database

import (
	"fmt"
	mathrand "math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dominancePruneReference is the O(N^2) reference implementation used by
// differential fuzz tests to verify DominancePrune survivor identity.
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

// dominancePruneReferenceComparisons matches dominancePruneReference while
// counting inner-loop comparisons (C1/C3/C2) without mutating the input slice.
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

// dominancePruneSweepComparisons matches DominancePrune while counting inner
// containment probes against the live interval slice.
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

// Differential equivalence fuzz test: builds 10,000 randomized inputs
// (N=0..2000 rows) and asserts DominancePrune returns the same survivor
// sequence as the O(N^2) reference.

func TestEquivDifferentialFuzz(t *testing.T) {
	const cases = 10_000
	r := newRandSeeded(20)

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
			// Constant tag 'x' sets identical frag[:16] across all rows so composite-key
			// sorting orders rows by (sysTime, validTimeStart, assertionTime) ascending.
			raw[i] = mkRow(sys, vs, ve, ast, 'x')
		}
		// The production precondition: composite-key sort. With a constant tag
		// the hash field frag[:16] is identical for all rows, so this sort is
		// sysTime-ASC|vs-ASC|ast-ASC — exactly the production order.
		sort.SliceStable(raw, func(i, j int) bool {
			return bytesCompare(raw[i].frag[:], raw[j].frag[:]) < 0
		})

		refRows := cloneRows(raw)
		sweepRows := cloneRows(raw)
		refOut = dominancePruneReference(refRows, horizon)
		sweepOut = DominancePrune(sweepRows, horizon)

		if !survivorsByteIdentical(refOut, sweepOut) {
			t.Fatalf("case %d diverged (horizon=%d, N=%d):\nreference survivors: %s\nsweep survivors:     %s\nrows: %s",
				c, horizon, len(raw), survivorFragsHex(refOut), survivorFragsHex(sweepOut), rowsFragsHex(raw))
		}
	}
	t.Logf("fuzz cases: %d, all matched O(N^2) reference", cases)
}

// TestEquivRedControlOffByOneFloor checks the negative control where (C3) is
// omitted from the sweep so a dominator above the horizon wrongly drops R.
func TestEquivRedControlOffByOneFloor(t *testing.T) {
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'R'),
		mkRow(250, 0, 100, 250, 'D'),
	}
	const horizon int64 = 200

	ref := dominancePruneReference(cloneRows(rows), horizon)
	corrupt := dominancePruneSweepNoC3(cloneRows(rows), horizon)

	require.True(t, hasTag(ref, 'R'), "negative control: reference keeps R because (C3) rejects a dominator above the floor")
	require.False(t, hasTag(corrupt, 'R'),
		"negative control: sweep without (C3) drops R, demonstrating the missing-floor failure")
	t.Logf("negative control: reference=%v; sweep without (C3)=%v",
		survivorTags(ref), survivorTags(corrupt))
}

// dominancePruneSweepNoC3 omits the (C3) admission guard for negative-control testing.
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
		// (C3) stripped — admit every survivor regardless of the floor.
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

// Verify (C3) horizon gating in DominancePrune matches the O(N^2) reference.

func TestLoFloorRefusesDominatorByteIdentical(t *testing.T) {
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'R'),
		mkRow(250, 0, 100, 250, 'D'),
	}

	// Floor 200 < dominator sysTime 250: (C3) rejects admission so R survives.
	ref200 := dominancePruneReference(cloneRows(rows), 200)
	sweep200 := DominancePrune(cloneRows(rows), 200)
	require.True(t, hasTag(sweep200, 'R'), "sweep must keep R at floor 200 when dominator exceeds horizon")
	require.True(t, hasTag(sweep200, 'D'), "dominator D must survive")
	require.True(t, survivorsByteIdentical(ref200, sweep200),
		"sweep must match reference at floor 200\nref=%s\nsweep=%s", survivorFragsHex(ref200), survivorFragsHex(sweep200))

	// Floor 1000 >= dominator sysTime 250: (C3) admits D so R is dropped.
	ref1000 := dominancePruneReference(cloneRows(rows), 1000)
	sweep1000 := DominancePrune(cloneRows(rows), 1000)
	require.False(t, hasTag(sweep1000, 'R'), "sweep must drop R once horizon passes dominator")
	require.True(t, hasTag(sweep1000, 'D'), "dominator D must survive")
	require.True(t, survivorsByteIdentical(ref1000, sweep1000),
		"sweep must match reference at floor 1000\nref=%s\nsweep=%s", survivorFragsHex(ref1000), survivorFragsHex(sweep1000))

	t.Logf("floor 200 survivors=%v; floor 1000 survivors=%v (both matched reference)",
		survivorTags(sweep200), survivorTags(sweep1000))
}

// Verify (C2) interval containment gating in DominancePrune matches the reference.

func TestContainmentRefusesNarrowerByteIdentical(t *testing.T) {
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'R'),
		mkRow(200, 20, 80, 200, 'D'),
	}
	const horizon int64 = 200

	ref := dominancePruneReference(cloneRows(rows), horizon)
	sweep := DominancePrune(cloneRows(rows), horizon)
	require.True(t, hasTag(sweep, 'R'), "sweep must keep R when newer interval is narrower")
	require.True(t, hasTag(sweep, 'D'), "newer row D must survive")
	require.True(t, survivorsByteIdentical(ref, sweep),
		"sweep must match reference for non-containing interval\nref=%s\nsweep=%s", survivorFragsHex(ref), survivorFragsHex(sweep))
	t.Logf("narrower interval survivors=%v (matched reference)", survivorTags(sweep))
}

// Verify determinism, idempotency, and horizon <= 0 retain-all behavior.

func TestIdempotencyAndPreserveAllByteIdentical(t *testing.T) {
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'A'),
		mkRow(150, 0, 100, 150, 'B'),
		mkRow(200, 0, 100, 200, 'C'),
		mkRow(250, 0, 100, 250, 'D'),
	}
	const floor int64 = 300

	first := DominancePrune(cloneRows(rows), floor)
	second := DominancePrune(cloneRows(rows), floor)
	require.True(t, survivorsByteIdentical(first, second),
		"repeated DominancePrune calls must be deterministic\nfirst=%s\nsecond=%s",
		survivorFragsHex(first), survivorFragsHex(second))
	refFirst := dominancePruneReference(cloneRows(rows), floor)
	require.True(t, survivorsByteIdentical(first, refFirst),
		"sweep must match reference\nsweep=%s\nref=%s", survivorFragsHex(first), survivorFragsHex(refFirst))
	assert.Equal(t, []byte{'D'}, survivorTags(first), "D dominates A, B, C leaving 1 survivor")

	repruned := DominancePrune(cloneRows(first), floor)
	require.True(t, survivorsByteIdentical(first, repruned),
		"DominancePrune must be idempotent\nfirst=%s\nrepruned=%s",
		survivorFragsHex(first), survivorFragsHex(repruned))

	all := DominancePrune(cloneRows(rows), 0)
	require.Len(t, all, len(rows), "horizon <= 0 must preserve all rows")
	wantTags := []byte{'A', 'B', 'C', 'D'}
	assert.Equal(t, wantTags, survivorTags(all), "horizon <= 0 must retain every original row")
	refAll := dominancePruneReference(cloneRows(rows), 0)
	require.True(t, survivorsByteIdentical(all, refAll), "horizon <= 0 must match reference")
	t.Logf("determinism, idempotency, and horizon<=0 retain-all verified")
}

// Verify EpochCompactor methods remain unused across production code.

func TestSweepDeadCompactorScopeHygiene(t *testing.T) {
	dead := []string{"SetCompactor(", "InsertTombstone(", "NewEpochCompactor(", "PruneTombstones("}
	for _, body := range dead {
		count := productionCallerCount(t, body)
		assert.Equalf(t, 0, count,
			"scope hygiene: %s has %d production caller(s); DominancePrune must not import EpochCompactor (ADR-0019)",
			body, count)
	}
	t.Logf("EpochCompactor methods have 0 production callers")
}

// Instrumented comparison-count check over overlapping coverage-N and disjoint
// coverage-1 workloads.

// makeCoverageNRows builds N rows all covering [0, 1000) at increasing sysTimes
// 1..N. Because the newest row dominates all earlier ones, the live set stays size 1.
func makeCoverageNRows(n int) []mergedRowT {
	rows := make([]mergedRowT, n)
	for i := 0; i < n; i++ {
		rows[i] = mkRow(int64(i+1), 0, 1000, int64(i+1), byte('a'+byte(i%26)))
	}
	return rows
}

// makeCoverage1Rows builds N rows over disjoint validTime windows [i*10, i*10+5)
// at increasing sysTimes 1..N, so all rows survive and live grows to N.
func makeCoverage1Rows(n int) []mergedRowT {
	rows := make([]mergedRowT, n)
	for i := 0; i < n; i++ {
		vs := int64(i * 10)
		rows[i] = mkRow(int64(i+1), vs, vs+5, int64(i+1), byte('a'+byte(i%26)))
	}
	return rows
}

func TestPruneBenchComparisonCounts(t *testing.T) {
	const n = 1000
	const horizon int64 = 1001

	// Overlapping intervals [0, 1000): the newest row dominates all earlier rows,
	// keeping the live set at size 1 (O(N)).
	rowsN := makeCoverageNRows(n)
	refNOut, refNCmp := dominancePruneReferenceComparisons(rowsN, horizon)
	sweepNOut, sweepNCmp := dominancePruneSweepComparisons(rowsN, horizon)
	require.True(t, survivorsByteIdentical(refNOut, sweepNOut),
		"coverage-N sweep must match reference\nref=%s\nsweep=%s",
		survivorFragsHex(refNOut), survivorFragsHex(sweepNOut))
	ratioN := float64(sweepNCmp) / float64(max64(refNCmp, 1))
	t.Logf("coverage-N (N=%d): reference comparisons=%d, sweep comparisons=%d, ratio=%.4f (O(N))",
		n, refNCmp, sweepNCmp, ratioN)
	if ratioN > 1.01 {
		t.Fatalf("coverage-N: sweep slower than reference (ratio %.4f > 1.01); refCmp=%d sweepCmp=%d",
			ratioN, refNCmp, sweepNCmp)
	}

	// Disjoint intervals [i*10, i*10+5): no row dominates another, so live grows
	// to N (O(N^2)/2 comparisons vs N(N-1) for the reference).
	rows1 := makeCoverage1Rows(n)
	ref1Out, ref1Cmp := dominancePruneReferenceComparisons(rows1, horizon)
	sweep1Out, sweep1Cmp := dominancePruneSweepComparisons(rows1, horizon)
	require.True(t, survivorsByteIdentical(ref1Out, sweep1Out),
		"coverage-1 sweep must match reference\nref=%s\nsweep=%s",
		survivorFragsHex(ref1Out), survivorFragsHex(sweep1Out))
	ratio1 := float64(sweep1Cmp) / float64(max64(ref1Cmp, 1))
	t.Logf("coverage-1 (N=%d): reference comparisons=%d, sweep comparisons=%d, ratio=%.4f (O(N^2)/2)",
		n, ref1Cmp, sweep1Cmp, ratio1)
	if ratio1 > 1.01 {
		t.Fatalf("coverage-1: sweep slower than reference (ratio %.4f > 1.01); refCmp=%d sweepCmp=%d",
			ratio1, ref1Cmp, sweep1Cmp)
	}
	t.Logf("comparison ratios: coverage-N=%.4f (O(N)), coverage-1=%.4f (O(N^2)/2)",
		ratioN, ratio1)
}

// BenchmarkDominancePrune_Sweep_CoverageN is the worst-case bench: the sweep
// equals the reference on coverage-N (O(N^2)).
func BenchmarkDominancePrune_Sweep_CoverageN(b *testing.B) {
	const n = 1000
	const horizon int64 = 1001
	rows := makeCoverageNRows(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DominancePrune(cloneRows(rows), horizon)
	}
}

// BenchmarkDominancePrune_Reference_CoverageN is the reference bench on the
// same worst-case input (the comparison baseline).
func BenchmarkDominancePrune_Reference_CoverageN(b *testing.B) {
	const n = 1000
	const horizon int64 = 1001
	rows := makeCoverageNRows(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dominancePruneReference(cloneRows(rows), horizon)
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
		_ = DominancePrune(cloneRows(rows), horizon)
	}
}

// BenchmarkDominancePrune_Reference_Coverage1 is the reference bench on the
// same common-case input (the comparison baseline).
func BenchmarkDominancePrune_Reference_Coverage1(b *testing.B) {
	const n = 1000
	const horizon int64 = 1001
	rows := makeCoverage1Rows(n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dominancePruneReference(cloneRows(rows), horizon)
	}
}

// Precondition disclosure test: Compaction sorts rows by composite key (sysTime
// ascending) before invoking DominancePrune. The reference double loop is order-
// independent whereas the reverse-batch sweep relies on that sort order.

func TestReversedSysTimePreconditionDisclosure(t *testing.T) {
	// Sorted input matches Compaction's composite-key order (sysTime ascending).
	const horizon int64 = 1000
	sorted := []mergedRowT{
		mkRow(100, 0, 1000, 100, 'z'),
		mkRow(200, 0, 1000, 200, 'z'),
		mkRow(300, 0, 1000, 300, 'z'),
		mkRow(400, 0, 1000, 400, 'z'),
	}
	refSorted := dominancePruneReference(cloneRows(sorted), horizon)
	sweepSorted := DominancePrune(cloneRows(sorted), horizon)
	require.True(t, survivorsByteIdentical(refSorted, sweepSorted),
		"sweep and reference must match on sorted input\nref=%s\nsweep=%s",
		survivorFragsHex(refSorted), survivorFragsHex(sweepSorted))
	assert.Equal(t, []byte{'z'}, survivorTags(sweepSorted),
		"newest row D dominates the three older rows on sorted input")

	// Unsorted input (sysTime descending) violates the sweep precondition: the
	// oldest row is seen first and prevents newer dominators from pruning it,
	// whereas the reference double loop is order-independent.
	reversed := []mergedRowT{
		mkRow(400, 0, 1000, 400, 'z'),
		mkRow(300, 0, 1000, 300, 'z'),
		mkRow(200, 0, 1000, 200, 'z'),
		mkRow(100, 0, 1000, 100, 'z'),
	}
	refReversed := dominancePruneReference(cloneRows(reversed), horizon)
	sweepReversed := DominancePrune(cloneRows(reversed), horizon)
	require.True(t, survivorsByteIdentical(refSorted, refReversed),
		"reference is order-independent between sorted and reversed inputs\nsorted=%s\nreversed=%s",
		survivorFragsHex(refSorted), survivorFragsHex(refReversed))
	if survivorsByteIdentical(refReversed, sweepReversed) {
		t.Logf("sweep matched reference on reversed input as well")
	} else {
		t.Logf("disclosed divergence on unsorted input: reference=%d (%s); sweep=%d (%s); Compaction always sorts before DominancePrune",
			len(refReversed), survivorFragsHex(refReversed), len(sweepReversed), survivorFragsHex(sweepReversed))
	}
	t.Logf("sorted input matched reference; reversed input documents sweep sort precondition")
}

// ──────────────────────────────────────────────────────────────────────────
// helpers: byte-identity comparison + the seeded rand.
// ──────────────────────────────────────────────────────────────────────────

// survivorsByteIdentical reports whether two survivor slices are byte-identical
// in length, per-row frag[:], and order — the byte-identity test (the survivor
// sequence in input order, not a re-sorted set).
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
// bytes import for a trivial compare; survivor tags already covers the
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

// survivorFragsHex formats survivor frag prefixes in hex for test diagnostics.
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

// newRandSeeded returns a deterministic *math/rand.Rand for fuzzing.
func newRandSeeded(seed int64) *mathrand.Rand {
	return mathrand.New(mathrand.NewSource(seed))
}
