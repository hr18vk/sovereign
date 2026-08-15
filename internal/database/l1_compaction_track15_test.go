// Day 15 (ADR-0020) teeth (the PURE-FUNCTION teeth) — the Level-2 superseded-
// row pruning fork: the tri-temporal dominance lattice + a transaction-time GC
// FLOOR. These teeth drive the DominancePrune PURE FUNCTION directly (the
// seam, not the route — the route teeth live in pkg/durability against a REAL
// *LocalFS).
//
// The fork CLOSES the §0.4 truth-maintenance trap Day-14 deferred. A row R in
// the merged L1 set is SAFE TO DROP iff a retained row R' satisfies (C1) AND
// (C2) AND (C3):
//
//	(C1) sysTime(R') > sysTime(R)        -- R' is NEWER (a later assertion)
//	(C2) [vs', ve') contains [vs, ve)    -- R' answers every validTime R does
//	(C3) sysTime(R') <= T_gc              -- the dominator is FLOOR-admitted
//
// Each claw is INDIVIDUALLY NECESSARY — the teeth pin each:
//   - T1 pins (C3) (the §0.4(ii) txTime-GAP proof — the load-bearing claw)
//   - T2 pins (C2) (the containment claw)
//   - T3 pins idempotency (the byte-identical re-prune + Preserve-All default)
//   - T5 pins scope hygiene (the dead tombstone compactor stays DEAD)
//   - T6 pins the FROZEN md5 set (the prune touches NO pkg/sync/capnp file)
//
// The T1+T2 RED branches exercise the φ-break (a fixture prune that DROPS one
// claw) to PROVE each claw is load-bearing: stripping (C3) corrupts the txTime
// GAP; stripping (C2) corrupts the validTime boundary. The GREEN branches
// drive the production DominancePrune (full (C1)&&(C2)&&(C3)) and assert the
// SAFE drop holds / the LIVE row survives.
package database

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// track15MkRow builds an extracted mergedRowT carrier with EXPLICIT sysTime /
// validStart / validEnd / assertionTime + a 1-byte payload tag, and packs the
// 40-byte composite-key frag the SAME way readEntityRowsFromKey does (lines
// 669-675): hash[0:16], BigEndian sysTime[16:24], validStart[24:32],
// assertTime[32:40]. The frag makes a re-sort by bytes.Compare deterministic
// (the production compaction sort), so the pure-function teeth are order-
// independent of the slice we hand them (the teeth hand pre-sorted slices
// anyway — DominancePrune is a pure function of (rows, horizon), not order).
func track15MkRow(sys, vs, ve, ast int64, tag byte) mergedRowT {
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
	m.pdz = h // a non-zero digest (Law V byte-identity only for the route teeth)
	m.pld = []byte{tag}
	return m
}

// track15SurvivorTags returns the 1-byte payload tags of the survivors (sorted
// by tag for a STABLE assertion independent of the retained order).
func track15SurvivorTags(got []mergedRowT) []byte {
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

// track15HasTag reports whether tag survived the prune.
func track15HasTag(got []mergedRowT, tag byte) bool {
	for _, b := range track15SurvivorTags(got) {
		if b == tag {
			return true
		}
	}
	return false
}

// track15Clone copies a mergedRowT slice (so the teeth do NOT mutate the
// fixture across sub-assertions — each sub-test gets a fresh copy).
func track15Clone(in []mergedRowT) []mergedRowT {
	out := make([]mergedRowT, len(in))
	copy(out, in)
	return out
}

// ──────────────────────────────────────────────────────────────────────────
// T1 — (C3) is LOAD-BEARING: the §0.4(ii) txTime-GAP proof.
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
func TestTrack15_T1_C3_LoadBearing_TxTimeGap_RedThenGreen(t *testing.T) {
	// R: sys=100, valid=[0,100); R': sys=250, valid=[0,100) (superset interval).
	// (C1) 250>100 YES; (C2) [0,100) contains [0,100) YES; (C3) pending floor.
	rows := []mergedRowT{
		track15MkRow(100, 0, 100, 100, 'R'),
		track15MkRow(250, 0, 100, 250, 'D'), // the would-be dominator
	}

	// GREEN — the production prune with the FLOOR T_gc=200 BELOW the dominator
	// (sys=250 > 200). (C3) refuses -> R survives (the GAP query's sole winner).
	green := DominancePrune(track15Clone(rows), 200)
	if !track15HasTag(green, 'R') {
		t.Fatalf("T1 GREEN: R must survive when the dominator is ABOVE the floor (C3 refuses); got %v", track15SurvivorTags(green))
	}
	// And the dominator itself survives (R' is not dominated by R: R is older).
	if !track15HasTag(green, 'D') {
		t.Fatalf("T1 GREEN: D must survive (it is not dominated by the older R); got %v", track15SurvivorTags(green))
	}

	// RED — the φ-break: strip (C3). The "(C1)&&(C2)-only" prune DROPS R even
	// though a live GAP query (txTime in [100,250)) admits ONLY R. R becomes
	// invisible -> the silent-data-loss class. This is the misconfig the LOUD
	// NewL1Compactor guard + the operator-floor contract exist to PREVENT.
	red := track15PruneNoC3(track15Clone(rows)) // strips (C3) — the broken rule
	if track15HasTag(red, 'R') {
		t.Fatalf("T1 RED: the (C1)&&(C2)-only φ-break MUST drop R (proving (C3) is load-bearing); got %v", track15SurvivorTags(red))
	}
	// The GAP query (txTime=150 in [100,250)) against the RED pruned set would
	// return ONLY D — but D has sys=250 > 150 -> Filter2 skips it too ->
	// ErrEntityNotFound. R was the sole winner; the φ-break lost it.
	t.Logf("T1: GREEN survivors (floor 200, dominator above floor) = %v ; RED φ-break survivors = %v",
		track15SurvivorTags(green), track15SurvivorTags(red))

	// GREEN-II — once the FLOOR advances PAST the dominator (T_gc=1000 >= 250),
	// (C3) now admits the dominator for every live query (txTime>=1000>=250) ->
	// R IS safe to drop (R' is admitted, newer, contains the interval -> wins).
	green2 := DominancePrune(track15Clone(rows), 1000)
	if track15HasTag(green2, 'R') {
		t.Fatalf("T1 GREEN-II: once the floor passes the dominator, R must now be SAFELY dropped; got %v", track15SurvivorTags(green2))
	}
	if !track15HasTag(green2, 'D') {
		t.Fatalf("T1 GREEN-II: the dominator D survives; got %v", track15SurvivorTags(green2))
	}
	t.Logf("T1: GREEN-II survivors (floor 1000 >= dominator 250) = %v — R safely dropped", track15SurvivorTags(green2))
}

// track15PruneNoC3 is the φ-break fixture: a "(C1)&&(C2)-only" prune with NO
// (C3) floor — the misconfiguration the §0.4(ii) trap is. It exists ONLY in the
// test to PROVE (C3) is load-bearing (the RED branch); production NEVER calls
// it. It has the SAME in-place-compaction shape as DominancePrune so the RED
// demonstrates the EXACT behavior the missing floor would have.
func track15PruneNoC3(rows []mergedRowT) []mergedRowT {
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
// T2 — (C2) is LOAD-BEARING: the containment claw.
//
// R' is at the FLOOR (sys<=T_gc) and NEWER (C1) but [vs',ve') does NOT contain
// [vs,ve). A V in [vs, vs') is answered ONLY by R (R' is not Filter3-valid
// there) -> R is LIVE -> dropping R corrupts that V's query. The (C2)
// containment guard (vs'<=vs AND ve'>=ve) is what refuses the drop.
//
// GREEN: production DominancePrune -> R survives (C2 refuses).
// RED:   a φ-break fixture that strips (C2) DROPS R -> the boundary V corrupts.
// ──────────────────────────────────────────────────────────────────────────
func TestTrack15_T2_C2_LoadBearing_Containment_RedThenGreen(t *testing.T) {
	// R: sys=100, valid=[0,100); R': sys=200, valid=[20,80) (a NARROWER interval
	// — does NOT contain [0,100): the V in [0,20) is R-only).
	rows := []mergedRowT{
		track15MkRow(100, 0, 100, 100, 'R'),
		track15MkRow(200, 20, 80, 200, 'D'), // narrower (no containment)
	}

	// GREEN — R survives (C2 refuses: [20,80) does NOT contain [0,100)).
	green := DominancePrune(track15Clone(rows), 200)
	if !track15HasTag(green, 'R') {
		t.Fatalf("T2 GREEN: R must survive when the interval is NOT contained; got %v", track15SurvivorTags(green))
	}
	if !track15HasTag(green, 'D') {
		t.Fatalf("T2 GREEN: D survives; got %v", track15SurvivorTags(green))
	}

	// RED — strip (C2). The φ-break DROPS R even though the V in [0,20) is
	// answered ONLY by R. A query at V=10 admits R but NOT R' (Filter3:
	// 10 < vs'=20 -> skip) -> ErrEntityNotFound. R was the sole winner; lost.
	red := track15PruneNoC2(track15Clone(rows)) // strips (C2) — the broken rule
	if track15HasTag(red, 'R') {
		t.Fatalf("T2 RED: the (C1)&&(C3)-only φ-break MUST drop R (proving (C2) is load-bearing); got %v", track15SurvivorTags(red))
	}
	t.Logf("T2: GREEN survivors = %v ; RED φ-break survivors = %v", track15SurvivorTags(green), track15SurvivorTags(red))
}

// track15PruneNoC2 is the φ-break fixture: a "(C1)&&(C3)-only" prune with NO
// (C2) containment — DROPS a row whose interval the dominator does NOT cover.
// Test-only — PROVES (C2) is load-bearing.
func track15PruneNoC2(rows []mergedRowT) []mergedRowT {
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
// T3 — IDEMPOTENCY + Preserve-All default (the PURE-FUNCTION half).
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
//	identical Day-14 — the back-compat gate G15.h, pure-function half).
//	The FULL byte-identical L1 test (against a Preserve-All compaction) is
//	the route tooth in pkg/durability (T3b); here we pin the pure-function
//	contract the route tooth rests on.
//
// ──────────────────────────────────────────────────────────────────────────
func TestTrack15_T3_IdempotencyAndPreserveAllDefault(t *testing.T) {
	// 4 rows, same interval, sysT 100/150/200/250. Floor=300 admits the newest
	// (250) as the dominator for all three older -> 1 survivor; the rest chains.
	rows := []mergedRowT{
		track15MkRow(100, 0, 100, 100, 'A'),
		track15MkRow(150, 0, 100, 150, 'B'),
		track15MkRow(200, 0, 100, 200, 'C'),
		track15MkRow(250, 0, 100, 250, 'D'),
	}
	const floor int64 = 300

	first := DominancePrune(track15Clone(rows), floor)
	second := DominancePrune(track15Clone(rows), floor)
	// (a) deterministic: two calls on the same input -> byte-identical survivors.
	require.Equal(t, track15SurvivorTags(first), track15SurvivorTags(second),
		"T3a: DominancePrune is a deterministic pure function — two calls on the same input must produce byte-identical survivors")
	assert.Equal(t, []byte{'D'}, track15SurvivorTags(first),
		"T3a: the newest-at-floor (D, sys=250) dominates the 3 older -> 1 survivor")

	// (b) idempotent: re-pruning the pruned output is a FIXED POINT.
	repruned := DominancePrune(track15Clone(first), floor)
	require.Equal(t, track15SurvivorTags(first), track15SurvivorTags(repruned),
		"T3b: DominancePrune is idempotent — re-pruning the pruned output is a fixed point")

	// (c) Preserve-All default: horizon <= 0 returns the input UNCHANGED.
	all := DominancePrune(track15Clone(rows), 0)
	require.Len(t, all, len(rows),
		"T3c: horizon<=0 is Preserve-All (no drop) — the byte-identical Day-14 default (G15.h pure-function half)")
	// every original tag survives (order may differ only if a row moved via the
	// sink copy; content is preserved).
	wantTags := []byte{'A', 'B', 'C', 'D'}
	assert.Equal(t, wantTags, track15SurvivorTags(all),
		"T3c: Preserve-All keeps every row (the cardinality AND the byte content)")
}

// ──────────────────────────────────────────────────────────────────────────
// T5 — SCOPE HYGIENE: the dead tombstone EpochCompactor stays DEAD.
//
// Day-14 ADR-0019 §6 left the EpochCompactor (the Level-2 tombstone reaper)
// DEAD — zero production importers. Day-15 row-pruning is the FUTURE Level-2
// fork that ADR-0019 named (now delivered as the DominancePrune PURE FUNCTION
// over the merged set, NOT a tombstone EpochCompactor). The scope-hygiene guard
// asserts the discipline still holds: Day-15 introduces NO new production
// importer of the dead tombstone compactor (the prune is a pure-function seam,
// not a SetCompactor/InsertTombstone/PruneTombstones call).
//
// This tooth READS the production source (excludes _test.go) and asserts:
//   - SetCompactor has ZERO production callers (only the field on L0Flusher +
//     the nil-guard at l0_flusher.go:125 + the compactor.go definition).
//   - InsertTombstone has ZERO production callers.
//   - NewEpochCompactor has ZERO production callers.
//   - PruneTombstones has ZERO production callers (only the nil-guard call).
//
// ──────────────────────────────────────────────────────────────────────────
func TestTrack15_T5_DeadTombstoneCompactorStaysDead_ScopeHygiene(t *testing.T) {
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
			"T5 scope hygiene: %s has %d PRODUCTION caller(s) — the dead tombstone EpochCompactor must stay DEAD (Day-15 prune is a pure-function seam, NOT a SetCompactor/InsertTombstone/PruneTombstones importer); ADR-0019 §6 rule",
			s.name, count)
	}
	t.Logf("T5: SetCompactor/InsertTombstone/NewEpochCompactor/PruneTombstones each have 0 production callers — the dead tombstone compactor stays DEAD")
}

// ──────────────────────────────────────────────────────────────────────────
// T6 — the FROZEN md5 set: Day-15 touches NO pkg/sync/capnp/attribution file.
//
// The Level-2 prune is a pure-function seam in internal/database/l1_compactor.go
// — it MUST NOT touch the 5 TRUE-FROZEN files (the Day-9/14 G09.c set). This
// tooth mirrors the G09.c discipline: pin each file's md5 PREFIX and FAIL loud
// on drift (a TRUE-FROZEN file drifted under Day 15). The full md5 is logged
// (Law V — disclose the bytes, not adjectives). The 5 files are the FROZEN set
// the prune MUST NOT reach (ADR-0014 §6 rule 6 — a TRUE-FROZEN file is locked
// behind the 3-contract teeth + the next unfreeze, never touched piecemeal).
//
// This tooth pins the set from the internal/database test (cwd = the package
// dir); the FROZEN files are at repo root under pkg/sync, api/capnp, and
// pkg/attribution — reached via ../../{path}.
// ──────────────────────────────────────────────────────────────────────────
func TestTrack15_T6_FrozenMd5Set_Day15TouchesNoPkgSyncCapnpFile(t *testing.T) {
	files := []struct {
		name string
		rel  string // repo-root-relative path (cwd = internal/database)
		pin  string // the pinned md5 prefix (8 hex chars)
	}{
		{"pkg/sync/crdt.go", "../../pkg/sync/crdt.go", "44f89527"}, // Day-17 re-pin (ADR-0022: Join sort.Slice->slices.SortFunc no-capture comparator; was a50fee8f Day-16). Day-16 re-pin (ADR-0021: comment-only var DataDir warning; was 705ac671 the Day-10 ADR-0015 pin)
		{"pkg/sync/crdt_apply.go", "../../pkg/sync/crdt_apply.go", "ed9132a2"},
		{"api/capnp/api/capnp/schema.capnp", "../../api/capnp/api/capnp/schema.capnp", "47d2796a"},
		{"api/capnp/api/capnp/schema.capnp.go", "../../api/capnp/api/capnp/schema.capnp.go", "590af228"},
		{"pkg/attribution/envelope.go", "../../pkg/attribution/envelope.go", "b1beba1e"},
	}
	for _, f := range files {
		path, err := filepath.Abs(f.rel)
		require.NoError(t, err, "T6: resolve %s", f.name)
		data, err := os.ReadFile(path)
		require.NoError(t, err, "T6: read %s (FROZEN file missing — did the prune break the tree?)", f.name)
		// Same provenance as G09.c (md5 — the TRUE-FROZEN set's canonical pin).
		sum := md5.Sum(data)
		md5sum := hex.EncodeToString(sum[:])
		if md5sum[:8] != f.pin {
			t.Fatalf("T6 FAILED: FROZEN %s md5 prefix = %s, want %s — a TRUE-FROZEN file drifted under Day 15 (the Level-2 prune touched pkg/sync/capnp/attribution). Full: %s",
				f.name, md5sum[:8], f.pin, md5sum)
		}
		t.Logf("T6: FROZEN %s md5 = %s (prefix %s == pinned)", f.name, md5sum, md5sum[:8])
	}
}

// productionCallerCount greps the repo's PRODUCTION Go source trees
// (internal/, pkg/, cmd/) for `pattern`, excluding test files AND the dead-
// symbol OWN definition sites (compactor.go + l0_flusher.go, which hold the
// method declarations + the nil-guarded field). A production CALLER is a use
// OUTSIDE those definition files; the count returned is the number of source
// files with a hit (0 = the symbol is DEAD).
//
// The walk is scoped to internal/pkg/cmd so it does NOT descend into
// .claude/worktrees (a stale git worktree holds an OLD copy of the dead
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
		require.NoError(t, walk(d), "T5 productionCallerCount walk %s", d)
	}
	return count
}
