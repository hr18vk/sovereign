// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Tests for DominancePrune (ADR-0020): the tri-temporal dominance lattice
// with a transaction-time garbage-collection floor. These unit tests invoke
// DominancePrune directly over synthetic merged rows; end-to-end tests against
// *LocalFS live in pkg/durability.
//
// A row R in the merged L1 set is safe to drop iff a retained row R' satisfies:
//
//	(C1) sysTime(R') > sysTime(R)         -- R' is a newer assertion
//	(C2) [vs', ve') contains [vs, ve)     -- R' covers every validTime R covers
//	(C3) sysTime(R') <= T_gc               -- R' is floor-admitted
//
// Each condition is necessary on its own:
//   - TestLoadBearingTxTimeGapRedThenGreen verifies (C3) (transaction-time gap)
//   - TestLoadBearingContainmentRedThenGreen verifies (C2) (interval containment)
//   - TestIdempotencyAndPreserveAllDefault verifies determinism, idempotency, and Preserve-All
//   - TestDominancePruneDeadCompactorScopeHygiene verifies EpochCompactor remains unused
//
// Negative controls use helper variants missing one condition (pruneNoC3 and
// pruneNoC2) to verify each condition prevents silent data loss before testing
// DominancePrune itself.
package database

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mkRow builds an extracted mergedRowT carrier with explicit sysTime,
// validStart, validEnd, and assertionTime plus a 1-byte payload tag, and packs
// the 40-byte composite-key frag the same way readEntityRowsFromKey does:
// hash[0:16], BigEndian sysTime[16:24], validStart[24:32], assertTime[32:40].
// The frag makes a re-sort by bytes.Compare deterministic (the production
// compaction sort), so the pure-function tests are order-independent of the
// slice we hand them (the tests hand pre-sorted slices anyway — DominancePrune
// is a pure function of (rows, horizon), not order).
func mkRow(sys, vs, ve, ast int64, tag byte) mergedRowT {
	var m mergedRowT
	m.sysT, m.vs, m.ve, m.ast = sys, vs, ve, ast
	// A distinct hash per tag so two rows with the same (sys,vs,ve,ast) but
	// different tags still sort deterministically (the byte tag is the source
	// of truth; the hash only orders ties).
	h := sha256.Sum256([]byte{tag})
	copy(m.frag[:16], h[:16])
	binary.BigEndian.PutUint64(m.frag[16:24], uint64(sys))
	binary.BigEndian.PutUint64(m.frag[24:32], uint64(vs))
	binary.BigEndian.PutUint64(m.frag[32:40], uint64(ast))
	m.pdz = h // a non-zero digest (byte-identity only for the route tests)
	m.pld = []byte{tag}
	return m
}

// survivorTags returns the 1-byte payload tags of the survivors (sorted by tag
// for a stable assertion independent of the retained order).
func survivorTags(got []mergedRowT) []byte {
	out := make([]byte, 0, len(got))
	for i := range got {
		if len(got[i].pld) > 0 {
			out = append(out, got[i].pld[0])
		}
	}
	// stable sort for a deterministic assertion
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// hasTag reports whether tag survived the prune.
func hasTag(got []mergedRowT, tag byte) bool {
	for _, b := range survivorTags(got) {
		if b == tag {
			return true
		}
	}
	return false
}

// cloneRows copies a mergedRowT slice (so the tests do not mutate the fixture
// across sub-assertions — each sub-test gets a fresh copy).
func cloneRows(in []mergedRowT) []mergedRowT {
	out := make([]mergedRowT, len(in))
	copy(out, in)
	return out
}

// TestLoadBearingTxTimeGapRedThenGreen proves (C3) is necessary.
//
// With sysTime(R') > sysTime(R) and [vs',ve') containing [vs,ve), a historical
// query at txTime in [sysTime(R), sysTime(R')) admits R but skips R'
// (sysTime(R') > txTime). Dropping R when sysTime(R') > T_gc loses the only
// matching row for that interval. DominancePrune keeps R when the dominator is
// above T_gc and drops it once T_gc passes sysTime(R'); pruneNoC3 omits (C3) as
// a negative control.
func TestLoadBearingTxTimeGapRedThenGreen(t *testing.T) {
	// R: sys=100, valid=[0,100); R': sys=250, valid=[0,100) (superset interval).
	// (C1) 250>100; (C2) [0,100) contains [0,100); (C3) checked against floor.
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'R'),
		mkRow(250, 0, 100, 250, 'D'),
	}

	// Floor T_gc=200 sits below the dominator (sys=250 > 200), so R survives.
	green := DominancePrune(cloneRows(rows), 200)
	if !hasTag(green, 'R') {
		t.Fatalf("R must survive when the dominator is above the floor (C3 refuses); got %v", survivorTags(green))
	}
	if !hasTag(green, 'D') {
		t.Fatalf("D must survive (not dominated by older R); got %v", survivorTags(green))
	}

	// Negative control: without (C3), R is dropped even though txTime in
	// [100,250) admits only R.
	red := pruneNoC3(cloneRows(rows))
	if hasTag(red, 'R') {
		t.Fatalf("negative control without (C3) must drop R; got %v", survivorTags(red))
	}
	t.Logf("survivors with floor 200 = %v; negative control without (C3) = %v",
		survivorTags(green), survivorTags(red))

	// Once T_gc=1000 passes the dominator (sys=250 <= 1000), (C3) admits D and
	// R is safely dropped.
	green2 := DominancePrune(cloneRows(rows), 1000)
	if hasTag(green2, 'R') {
		t.Fatalf("once floor passes dominator, R should be dropped; got %v", survivorTags(green2))
	}
	if !hasTag(green2, 'D') {
		t.Fatalf("dominator D must survive; got %v", survivorTags(green2))
	}
	t.Logf("survivors with floor 1000 (>= dominator 250) = %v", survivorTags(green2))
}

// pruneNoC3 omits the (C3) floor check as a negative control for
// TestLoadBearingTxTimeGapRedThenGreen; never called outside tests.
func pruneNoC3(rows []mergedRowT) []mergedRowT {
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
			// (C3) stripped — no horizon guard.
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

// TestLoadBearingContainmentRedThenGreen proves (C2) interval containment is necessary.
//
// When R' is floor-admitted and newer than R but [vs',ve') does not contain
// [vs,ve), queries in [vs, vs') match only R. Dropping R corrupts those queries.
func TestLoadBearingContainmentRedThenGreen(t *testing.T) {
	// R: sys=100, valid=[0,100); R': sys=200, valid=[20,80) (narrower interval).
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'R'),
		mkRow(200, 20, 80, 200, 'D'),
	}

	green := DominancePrune(cloneRows(rows), 200)
	if !hasTag(green, 'R') {
		t.Fatalf("R must survive when the interval is not contained; got %v", survivorTags(green))
	}
	if !hasTag(green, 'D') {
		t.Fatalf("D must survive; got %v", survivorTags(green))
	}

	// Negative control: without (C2), R is dropped even though [0,20) matches only R.
	red := pruneNoC2(cloneRows(rows))
	if hasTag(red, 'R') {
		t.Fatalf("negative control without (C2) must drop R; got %v", survivorTags(red))
	}
	t.Logf("survivors = %v; negative control without (C2) = %v", survivorTags(green), survivorTags(red))
}

// pruneNoC2 omits the (C2) containment check as a negative control; test-only.
func pruneNoC2(rows []mergedRowT) []mergedRowT {
	const fakeFloor int64 = 1 << 62 // large enough that the floor never refuses
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
			if rp.sysT > fakeFloor { // (C3) (kept — only (C2) is stripped)
				continue
			}
			// (C2) stripped — no containment guard.
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

// TestIdempotencyAndPreserveAllDefault checks determinism, idempotency, and the
// horizon <= 0 Preserve-All contract.
func TestIdempotencyAndPreserveAllDefault(t *testing.T) {
	// 4 rows, same interval, sysT 100/150/200/250. Floor=300 admits the newest
	// (250) as the dominator for all three older -> 1 survivor; the rest chains.
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'A'),
		mkRow(150, 0, 100, 150, 'B'),
		mkRow(200, 0, 100, 200, 'C'),
		mkRow(250, 0, 100, 250, 'D'),
	}
	const floor int64 = 300

	first := DominancePrune(cloneRows(rows), floor)
	second := DominancePrune(cloneRows(rows), floor)
	// Determinism: two calls on the same input produce identical survivors.
	require.Equal(t, survivorTags(first), survivorTags(second),
		"DominancePrune is deterministic: two calls on the same input must match")
	assert.Equal(t, []byte{'D'}, survivorTags(first),
		"newest admitted row D (sys=250) dominates the 3 older rows")

	// Idempotency: re-pruning the output is a fixed point.
	repruned := DominancePrune(cloneRows(first), floor)
	require.Equal(t, survivorTags(first), survivorTags(repruned),
		"DominancePrune must be idempotent across repeated invocations")

	// Preserve-All default: horizon <= 0 returns the input unchanged.
	all := DominancePrune(cloneRows(rows), 0)
	require.Len(t, all, len(rows),
		"horizon <= 0 must preserve all rows without dropping")
	wantTags := []byte{'A', 'B', 'C', 'D'}
	assert.Equal(t, wantTags, survivorTags(all),
		"horizon <= 0 must preserve every row's identity and payload")
}

// TestDominancePruneDeadCompactorScopeHygiene verifies that DominancePrune does
// not introduce production callers of the unused EpochCompactor methods.
func TestDominancePruneDeadCompactorScopeHygiene(t *testing.T) {
	type symbol struct {
		name string
		body string
	}
	dead := []symbol{
		{"SetCompactor(", ".SetCompactor("},
		{"InsertTombstone(", ".InsertTombstone("},
		{"NewEpochCompactor(", "NewEpochCompactor("},
		{"PruneTombstones(", ".PruneTombstones("},
	}
	// Definitions reside in compactor.go with a nil-guarded call in l0_flusher.go.
	for _, s := range dead {
		count := productionCallerCount(t, s.body)
		assert.Equalf(t, 0, count,
			"scope hygiene: %s has %d production caller(s); DominancePrune must not import EpochCompactor (ADR-0019)",
			s.name, count)
	}
	t.Logf("SetCompactor/InsertTombstone/NewEpochCompactor/PruneTombstones each have 0 production callers")
}

// productionCallerCount greps the repo's production Go source trees
// (internal/, pkg/, cmd/) for `pattern`, excluding test files and the dead
// symbol definition sites (compactor.go and l0_flusher.go, which hold the
// method declarations and the nil-guarded field). A production caller is a use
// outside those definition files; the count returned is the number of source
// files with a hit (0 = the symbol is dead).
//
// The walk is scoped to internal/pkg/cmd so it does not descend into
// stale git worktrees (which hold old copies of the dead symbols — not
// production callers; the scope excludes them).
func productionCallerCount(t *testing.T, pattern string) int {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	require.NoError(t, err, "resolve repo root")
	var count int
	walk := func(dir string) error {
		return filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			name := filepath.Base(path)
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			abs, _ := filepath.Abs(path)
			switch abs {
			case filepath.Join(repoRoot, "internal", "database", "compactor.go"),
				filepath.Join(repoRoot, "internal", "database", "l0_flusher.go"):
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(string(data), pattern) {
				count++
			}
			return nil
		})
	}
	for _, d := range []string{"internal", "pkg", "cmd"} {
		require.NoError(t, walk(d), "productionCallerCount walk %s", d)
	}
	return count
}
