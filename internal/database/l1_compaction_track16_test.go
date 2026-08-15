// Day 16 (ADR-0021) teeth — the L0 reaper fork's internal/database teeth: the
// re-pinned FROZEN md5 set (T5) + the scope-hygiene guard (T6).
//
// The reaper's ROUTE teeth (T1/T2/T3/T4) drive a REAL *LocalFS and live in
// pkg/durability/l0_reaper_track16_test.go (the Day-14 import-cycle precedent:
// an internal/database test cannot import pkg/durability because snapshot.go
// imports internal/database). This file holds the two teeth that need only
// internal/database symbols + repo-root file reads.
//
//   - T5 — the FROZEN md5 set: Day-16 re-pins crdt.go (the ONLY FROZEN file it
//     touches, a comment-only change above `var DataDir` at crdt.go:17 so the
//     recovery.go SetDataDi r fix has an honest FROZEN-side warning). The md5
//     drifts 705ac671 → a50fee8f — the re-pin, disclosed in the commit body +
//     ADR-0021 §1, following the Day-10 re-pin precedent (ADR-0015 §7: a TRUE-
//     FROZEN file drifted by a comment is re-pinned, the sibling files stay byte-
//     identical, the act + cause appear in the commit message). The other 4
//     FROZEN files (crdt_apply.go, schema.capnp, schema.capnp.go, envelope.go)
//     are byte-identical (the reaper / the MaxValidTime const / the SetDataDir
//     fix touch NONE of them).
//
//   - T6 — scope hygiene: the reaper is a NEW type (internal/database/l0_reaper.go),
//     NOT a new importer of the dead tombstone EpochCompactor. The DeadCompactor
//     discipline (ADR-0019 §6, ADR-0020 T5) still holds: SetCompactor /
//     InsertTombstone / NewEpochCompactor / PruneTombstones retain ZERO production
//     importers post-Day-16. This tooth READS the production source (excludes
//     _test.go) + the dead-symbol definition sites and asserts the count is 0.
package database

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────────────────────────────────
// T5 — the FROZEN md5 set: Day-16 re-pins crdt.go (comment-only), the other 4
// stay byte-identical. The re-pin is the Day-10 precedent (ADR-0015 §7).
// ──────────────────────────────────────────────────────────────────────────
func TestTrack16_T5_FrozenMd5Set_RepinnedCrdtGo_Other4Identical(t *testing.T) {
	files := []struct {
		name   string
		rel    string // repo-root-relative path (cwd = internal/database)
		pin    string // the pinned md5 prefix (8 hex chars)
		remark string // what changed (or "byte-identical")
	}{
		// crdt.go: RE-PINNED. Day-16 adds a comment above `var DataDir` (crdt.go:17)
		// warning that the FROZEN ctor reads it + that engine.SetDataDir is the
		// instance-safe override. The comment is the ONLY change; the recovery.go
		// SetDataDir fix is in pkg/durability (NOT FROZEN). The md5 drifts 705ac671
		// → a50fee8f. The re-pin is disclosed in the commit body + ADR-0021 §1
		// (the Day-10 ADR-0015 §7 precedent: comment-only drift re-pinned, the
		// sibling files stay byte-identical, the act + cause in the commit msg).
		{"pkg/sync/crdt.go", "../../pkg/sync/crdt.go", "44f89527", "RE-PINNED (Day-17 ADR-0022: sort.Slice->slices.SortFunc no-capture comparator; was a50fee8f Day-16 comment-only)"},
		// The other 4 FROZEN files: byte-identical. Day-16 touches NONE of them.
		{"pkg/sync/crdt_apply.go", "../../pkg/sync/crdt_apply.go", "ed9132a2", "byte-identical"},
		{"api/capnp/api/capnp/schema.capnp", "../../api/capnp/api/capnp/schema.capnp", "47d2796a", "byte-identical"},
		{"api/capnp/api/capnp/schema.capnp.go", "../../api/capnp/api/capnp/schema.capnp.go", "590af228", "byte-identical"},
		{"pkg/attribution/envelope.go", "../../pkg/attribution/envelope.go", "b1beba1e", "byte-identical"},
	}
	for _, f := range files {
		path, err := filepath.Abs(f.rel)
		require.NoError(t, err, "T5: resolve %s", f.name)
		data, err := os.ReadFile(path)
		require.NoError(t, err, "T5: read %s (FROZEN file missing — did the Day-16 reaper break the tree?)", f.name)
		sum := md5.Sum(data)
		md5sum := hex.EncodeToString(sum[:])
		if md5sum[:8] != f.pin {
			t.Fatalf("T5 FAILED: FROZEN %s md5 prefix = %s, want %s — %s. Full: %s",
				f.name, md5sum[:8], f.pin, f.remark, md5sum)
		}
		t.Logf("T5: FROZEN %s md5 = %s (prefix %s == pinned) — %s", f.name, md5sum, md5sum[:8], f.remark)
	}
}

// ──────────────────────────────────────────────────────────────────────────
// T6 — SCOPE HYGIENE: the dead tombstone EpochCompactor stays DEAD post-Day-16.
//
// The reaper (internal/database/l0_reaper.go) is a NEW type — it reclaims
// superseded L0 files via the S3Deleter seam, NOT a tombstone compactor. Day-16
// introduces NO new production importer of SetCompactor / InsertTombstone /
// NewEpochCompactor / PruneTombstones (the ADR-0019 §6 + ADR-0020 T5 discipline).
// This tooth READS the production source (excludes _test.go + the dead-symbol
// OWN definition sites) and asserts the count is 0 — the DeadCompactor invariant.
// ──────────────────────────────────────────────────────────────────────────
func TestTrack16_T6_DeadTombstoneCompactorStaysDead_ScopeHygiene(t *testing.T) {
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
	// nil-guarded PruneTombstones call at l0_flusher.go (f.compactor is ALWAYS
	// nil — no production code calls SetCompactor). Count production callers
	// excluding the definition file + the nil-guard site. The reaper adds NONE.
	for _, s := range dead {
		count := productionCallerCountTrack16(t, s.body)
		assert.Equalf(t, 0, count,
			"T6 scope hygiene: %s has %d PRODUCTION caller(s) — the dead tombstone EpochCompactor must stay DEAD post-Day-16 (the reaper is a NEW type over S3Deleter, NOT a SetCompactor/InsertTombstone/NewEpochCompactor/PruneTombstones importer); ADR-0019 §6 rule",
			s.name, count)
	}
	t.Logf("T6: SetCompactor/InsertTombstone/NewEpochCompactor/PruneTombstones each have 0 production callers — the reaper added NONE (the dead tombstone compactor stays DEAD)")
}

// productionCallerCountTrack16 greps the repo's PRODUCTION Go source trees
// (internal/, pkg/, cmd/) for `pattern`, excluding test files AND the dead-
// symbol OWN definition sites (compactor.go + l0_flusher.go, which hold the
// method declarations + the nil-guarded field). A production CALLER is a use
// OUTSIDE those definition files; the count returned is the number of source
// files with a hit (0 = the symbol is DEAD).
//
// The walk is scoped to internal/pkg/cmd so it does NOT descend into
// .claude/worktrees (a stale git worktree holds an OLD copy of the dead
// symbols — NOT a production caller; the scope excludes it). This is the
// track15 productionCallerCount relocated into the track16 file (the helper is
// package-scoped so the track15 copy still builds — the track16 tests use this
// copy to keep the symbol count self-contained; grep -n confirms only one is
// referenced per binary, Go picks neither over the other at compile time
// because track15_test.go and track16_test.go reference their OWN copies).
//
// NOTE: track15_test.go ALSO defines productionCallerCountTrack15-free
// productionCallerCount (same name) — so this file uses a DISTINCT name
// (productionCallerCountTrack16) to avoid the duplicate-declaration compile
// error across test files in the same package.
func productionCallerCountTrack16(t *testing.T, pattern string) int {
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
		require.NoError(t, walk(d), "T6 productionCallerCountTrack16 walk %s", d)
	}
	return count
}

// Keep the reaper's L0Repeater/Reap symbols referenced (the route teeth in
// pkg/durability exercise Reap; this is the unused-symbol guard so THIS file,
// which only does md5 + grep, still pulls the reaper into the build-cert set).
var (
	_ = NewL0Reaper
)
