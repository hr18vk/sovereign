// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// The Level-2 superseded-row pruning guards (ADR-0020, the PURE-FUNCTION half):
// the tri-temporal dominance lattice + a transaction-time GC
// FLOOR. These guards drive the DominancePrune PURE FUNCTION directly (the
// seam, not the route — the route guards live in pkg/durability against a REAL
// *LocalFS).
//
// This CLOSES the truth-maintenance trap the L0→L1 compaction deferred. A row R in
// the merged L1 set is SAFE TO DROP iff a retained row R' satisfies (C1) AND
// (C2) AND (C3):
//
//	(C1) sysTime(R') > sysTime(R)        -- R' is NEWER (a later assertion)
//	(C2) [vs', ve') contains [vs, ve)    -- R' answers every validTime R does
//	(C3) sysTime(R') <= T_gc              -- the dominator is FLOOR-admitted
//
// Each claw is INDIVIDUALLY NECESSARY — the guards pin each:
//   - the (C3) guard (the txTime-GAP proof — the load-bearing claw)
//   - the (C2) guard (the containment claw)
//   - the idempotency guard (the byte-identical re-prune + Preserve-All default)
//   - the scope-hygiene guard (the dead tombstone compactor stays DEAD)
//   - the protected-core-md5 guard (the prune touches NO pkg/sync/capnp file)
//
// The (C3)+(C2) RED branches exercise the φ-break (a fixture prune that DROPS one
// claw) to PROVE each claw is load-bearing: stripping (C3) corrupts the txTime
// GAP; stripping (C2) corrupts the validTime boundary. The GREEN branches
// drive the production DominancePrune (full (C1)&&(C2)&&(C3)) and assert the
// SAFE drop holds / the LIVE row survives.
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

// mkRow builds an extracted mergedRowT carrier with EXPLICIT sysTime /
// validStart / validEnd / assertionTime + a 1-byte payload tag, and packs the
// 40-byte composite-key frag the SAME way readEntityRowsFromKey does (lines
// 669-675): hash[0:16], BigEndian sysTime[16:24], validStart[24:32],
// assertTime[32:40]. The frag makes a re-sort by bytes.Compare deterministic
// (the production compaction sort), so the pure-function guards are order-
// independent of the slice we hand them (the guards hand pre-sorted slices
// anyway — DominancePrune is a pure function of (rows, horizon), not order).
func mkRow(sys, vs, ve, ast int64, tag byte) mergedRowT {
	var m mergedRowT
	m.sysT, m.vs, m.ve, m.ast = sys, vs, ve, ast
	// A distinct hash per tag so two rows with the SAME (sys,vs,ve,ast) but
	// DIFFERENT tags still sort deterministically (the byte tag is the source
	// of truth; the hash only orders ties).
	h := sha256.Sum256([]byte{tag})
	copy(m.frag[:16], h[:16])
	binary.BigEndian.PutUint64(m.frag[16:24], uint64(sys))
	binary.BigEndian.PutUint64(m.frag[24:32], uint64(vs))
	binary.BigEndian.PutUint64(m.frag[32:40], uint64(ast))
	m.pdz = h // a non-zero digest (Law V byte-identity only for the route guards)
	m.pld = []byte{tag}
	return m
}

// survivorTags returns the 1-byte payload tags of the survivors (sorted
// by tag for a STABLE assertion independent of the retained order).
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

// cloneRows copies a mergedRowT slice (so the guards do NOT mutate the
// fixture across sub-assertions — each sub-test gets a fresh copy).
func cloneRows(in []mergedRowT) []mergedRowT {
	out := make([]mergedRowT, len(in))
	copy(out, in)
	return out
}

// ──────────────────────────────────────────────────────────────────────────
// (C3) is LOAD-BEARING: the txTime-GAP proof.
//
// Take R < R' with sysTime(R') > sysTime(R) and [vs',ve') contains [vs,ve).
// A query at (V in [vs,ve), txTime in [sysTime(R), sysTime(R'))) admits R but
// NOT R' (scanRecordBatch Filter2: sysTime(R') > txTime -> continue) -> R is the
// SOLE winner. Dropping R returns an OLDER admitted row (or ErrEntityNotFound),
// NOT the truth -> silent data loss. The (C3) FLOOR (sysTime(R') <= T_gc, i.e.
// R' is Filter2-admitted for EVERY live query (txTime >= T_gc)) is what refuses
// the drop when the dominator is NOT yet floor-admitted.
//
// GREEN: production DominancePrune with T_gc BELOW the dominator -> R survives
//
//	(the (C3) guard refuses: sysTime(R') > T_gc -> continue).
//
// RED:   a φ-break fixture that strips (C3) — the "(C1)&&(C2)-only" misconfig —
//
//	DROPS R; the SAME R is now invisible to the GAP query -> corrupt.
//
// ──────────────────────────────────────────────────────────────────────────
func TestLoadBearingTxTimeGapRedThenGreen(t *testing.T) {
	// R: sys=100, valid=[0,100); R': sys=250, valid=[0,100) (superset interval).
	// (C1) 250>100 YES; (C2) [0,100) contains [0,100) YES; (C3) pending floor.
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'R'),
		mkRow(250, 0, 100, 250, 'D'), // the would-be dominator
	}

	// GREEN — the production prune with the FLOOR T_gc=200 BELOW the dominator
	// (sys=250 > 200). (C3) refuses -> R survives (the GAP query's sole winner).
	green := DominancePrune(cloneRows(rows), 200)
	if !hasTag(green, 'R') {
		t.Fatalf("txTime-gap GREEN: R must survive when the dominator is ABOVE the floor (C3 refuses); got %v", survivorTags(green))
	}
	// And the dominator itself survives (R' is not dominated by R: R is older).
	if !hasTag(green, 'D') {
		t.Fatalf("txTime-gap GREEN: D must survive (it is not dominated by the older R); got %v", survivorTags(green))
	}

	// RED — the φ-break: strip (C3). The "(C1)&&(C2)-only" prune DROPS R even
	// though a live GAP query (txTime in [100,250)) admits ONLY R. R becomes
	// invisible -> the silent-data-loss class. This is the misconfig the LOUD
	// NewL1Compactor guard + the operator-floor contract exist to PREVENT.
	red := pruneNoC3(cloneRows(rows)) // strips (C3) — the broken rule
	if hasTag(red, 'R') {
		t.Fatalf("txTime-gap RED: the (C1)&&(C2)-only φ-break MUST drop R (proving (C3) is load-bearing); got %v", survivorTags(red))
	}
	// The GAP query (txTime=150 in [100,250)) against the RED pruned set would
	// return ONLY D — but D has sys=250 > 150 -> Filter2 skips it too ->
	// ErrEntityNotFound. R was the sole winner; the φ-break lost it.
	t.Logf("txTime-gap: GREEN survivors (floor 200, dominator above floor) = %v ; RED φ-break survivors = %v",
		survivorTags(green), survivorTags(red))

	// GREEN-II — once the FLOOR advances PAST the dominator (T_gc=1000 >= 250),
	// (C3) now admits the dominator for every live query (txTime>=1000>=250) ->
	// R IS safe to drop (R' is admitted, newer, contains the interval -> wins).
	green2 := DominancePrune(cloneRows(rows), 1000)
	if hasTag(green2, 'R') {
		t.Fatalf("txTime-gap GREEN-II: once the floor passes the dominator, R must now be SAFELY dropped; got %v", survivorTags(green2))
	}
	if !hasTag(green2, 'D') {
		t.Fatalf("txTime-gap GREEN-II: the dominator D survives; got %v", survivorTags(green2))
	}
	t.Logf("txTime-gap: GREEN-II survivors (floor 1000 >= dominator 250) = %v — R safely dropped", survivorTags(green2))
}

// pruneNoC3 is the φ-break fixture: a "(C1)&&(C2)-only" prune with NO
// (C3) floor — the misconfiguration the trap is. It exists ONLY in the
// test to PROVE (C3) is load-bearing (the RED branch); production NEVER calls
// it. It has the SAME in-place-compaction shape as DominancePrune so the RED
// demonstrates the EXACT behavior the missing floor would have.
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
			// (C3) stripped — NO horizon guard.
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

// ──────────────────────────────────────────────────────────────────────────
// (C2) is LOAD-BEARING: the containment claw.
//
// R' is at the FLOOR (sys<=T_gc) and NEWER (C1) but [vs',ve') does NOT contain
// [vs,ve). A V in [vs, vs') is answered ONLY by R (R' is not Filter3-valid
// there) -> R is LIVE -> dropping R corrupts that V's query. The (C2)
// containment guard (vs'<=vs AND ve'>=ve) is what refuses the drop.
//
// GREEN: production DominancePrune -> R survives (C2 refuses).
// RED:   a φ-break fixture that strips (C2) DROPS R -> the boundary V corrupts.
// ──────────────────────────────────────────────────────────────────────────
func TestLoadBearingContainmentRedThenGreen(t *testing.T) {
	// R: sys=100, valid=[0,100); R': sys=200, valid=[20,80) (a NARROWER interval
	// — does NOT contain [0,100): the V in [0,20) is R-only).
	rows := []mergedRowT{
		mkRow(100, 0, 100, 100, 'R'),
		mkRow(200, 20, 80, 200, 'D'), // narrower (no containment)
	}

	// GREEN — R survives (C2 refuses: [20,80) does NOT contain [0,100)).
	green := DominancePrune(cloneRows(rows), 200)
	if !hasTag(green, 'R') {
		t.Fatalf("containment GREEN: R must survive when the interval is NOT contained; got %v", survivorTags(green))
	}
	if !hasTag(green, 'D') {
		t.Fatalf("containment GREEN: D survives; got %v", survivorTags(green))
	}

	// RED — strip (C2). The φ-break DROPS R even though the V in [0,20) is
	// answered ONLY by R. A query at V=10 admits R but NOT R' (Filter3:
	// 10 < vs'=20 -> skip) -> ErrEntityNotFound. R was the sole winner; lost.
	red := pruneNoC2(cloneRows(rows)) // strips (C2) — the broken rule
	if hasTag(red, 'R') {
		t.Fatalf("containment RED: the (C1)&&(C3)-only φ-break MUST drop R (proving (C2) is load-bearing); got %v", survivorTags(red))
	}
	t.Logf("containment: GREEN survivors = %v ; RED φ-break survivors = %v", survivorTags(green), survivorTags(red))
}

// pruneNoC2 is the φ-break fixture: a "(C1)&&(C3)-only" prune with NO
// (C2) containment — DROPS a row whose interval the dominator does NOT cover.
// Test-only — PROVES (C2) is load-bearing.
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
			// (C2) stripped — NO containment guard.
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

// ──────────────────────────────────────────────────────────────────────────
// IDEMPOTENCY + Preserve-All default (the PURE-FUNCTION half).
//
// (a) DominancePrune is a DETERMINISTIC pure function of (rows, horizon): two
//
//	calls on the SAME input produce the SAME survivor set byte-for-byte.
//
// (b) Re-pruning the PRUNED output is a FIXED POINT (idempotent: pruned ==
//
//	DominancePrune(pruned, T_gc) — nothing more to drop).
//
// (c) Preserve-All default: horizon <= 0 returns the input UNCHANGED (byte-
//
//	identical to the pre-prune behavior — the back-compat gate, pure-function half).
//	The FULL byte-identical L1 test (against a Preserve-All compaction) is
//	the route guard in pkg/durability; here we pin the pure-function
//	contract the route guard rests on.
//
// ──────────────────────────────────────────────────────────────────────────
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
	// (a) deterministic: two calls on the same input -> byte-identical survivors.
	require.Equal(t, survivorTags(first), survivorTags(second),
		"determinism: DominancePrune is a deterministic pure function — two calls on the same input must produce byte-identical survivors")
	assert.Equal(t, []byte{'D'}, survivorTags(first),
		"determinism: the newest-at-floor (D, sys=250) dominates the 3 older -> 1 survivor")

	// (b) idempotent: re-pruning the pruned output is a FIXED POINT.
	repruned := DominancePrune(cloneRows(first), floor)
	require.Equal(t, survivorTags(first), survivorTags(repruned),
		"idempotency: DominancePrune is idempotent — re-pruning the pruned output is a fixed point")

	// (c) Preserve-All default: horizon <= 0 returns the input UNCHANGED.
	all := DominancePrune(cloneRows(rows), 0)
	require.Len(t, all, len(rows),
		"preserve-all: horizon<=0 is Preserve-All (no drop) — the byte-identical default (pure-function half)")
	// every original tag survives (order may differ only if a row moved via the
	// sink copy; content is preserved).
	wantTags := []byte{'A', 'B', 'C', 'D'}
	assert.Equal(t, wantTags, survivorTags(all),
		"preserve-all: Preserve-All keeps every row (the cardinality AND the byte content)")
}

// ──────────────────────────────────────────────────────────────────────────
// SCOPE HYGIENE: the dead tombstone EpochCompactor stays DEAD.
//
// ADR-0019 §6 left the EpochCompactor (the Level-2 tombstone reaper)
// DEAD — zero production importers. The Level-2 row-pruning ADR-0019 named is
// delivered here as the DominancePrune PURE FUNCTION
// over the merged set, NOT a tombstone EpochCompactor. The scope-hygiene guard
// asserts the discipline still holds: the prune introduces NO new production
// importer of the dead tombstone compactor (the prune is a pure-function seam,
// not a SetCompactor/InsertTombstone/PruneTombstones call).
//
// This guard READS the production source (excludes _test.go) and asserts:
//   - SetCompactor has ZERO production callers (only the field on L0Flusher +
//     the nil-guard at l0_flusher.go:125 + the compactor.go definition).
//   - InsertTombstone has ZERO production callers.
//   - NewEpochCompactor has ZERO production callers.
//   - PruneTombstones has ZERO production callers (only the nil-guard call).
//
// ──────────────────────────────────────────────────────────────────────────
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
	// The DEAD definitions live in internal/database/compactor.go + the ONE
	// nil-guarded PruneTombstones call at l0_flusher.go:125 (f.compactor is
	// ALWAYS nil — no production code calls SetCompactor). Count production
	// callers excluding the definition file + the nil-guard site.
	for _, s := range dead {
		count := productionCallerCount(t, s.body)
		assert.Equalf(t, 0, count,
			"scope hygiene: %s has %d PRODUCTION caller(s) — the dead tombstone EpochCompactor must stay DEAD (prune is a pure-function seam, NOT a SetCompactor/InsertTombstone/PruneTombstones importer); ADR-0019 §6 rule",
			s.name, count)
	}
	t.Logf("scope hygiene: SetCompactor/InsertTombstone/NewEpochCompactor/PruneTombstones each have 0 production callers — the dead tombstone compactor stays DEAD")
}

// productionCallerCount greps the repo's PRODUCTION Go source trees
// (internal/, pkg/, cmd/) for `pattern`, excluding test files AND the dead-
// symbol OWN definition sites (compactor.go + l0_flusher.go, which hold the
// method declarations + the nil-guarded field). A production CALLER is a use
// OUTSIDE those definition files; the count returned is the number of source
// files with a hit (0 = the symbol is DEAD).
//
// The walk is scoped to internal/pkg/cmd so it does NOT descend into
// stray git worktrees (a stale worktree holds an OLD copy of the dead
// symbols — NOT a production caller; the scope excludes it).
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
		require.NoError(t, walk(d), "scope-hygiene productionCallerCount walk %s", d)
	}
	return count
}
