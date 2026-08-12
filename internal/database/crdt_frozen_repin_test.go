// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

// The L0 reaper's scope-hygiene guard.
//
// The reaper's ROUTE guards drive a REAL *LocalFS and live in
// pkg/durability (the import-cycle constraint:
// an internal/database test cannot import pkg/durability because snapshot.go
// imports internal/database). This file holds the guard that needs only
// internal/database symbols + repo-root file reads.
//
// Scope hygiene: the reaper is a NEW type (internal/database/l0_reaper.go),
// NOT a new importer of the dead tombstone EpochCompactor. The DeadCompactor
// discipline (ADR-0019 §6, ADR-0020) still holds: SetCompactor /
// InsertTombstone / NewEpochCompactor / PruneTombstones retain ZERO production
// importers. This guard READS the production source (excludes
// _test.go) + the dead-symbol definition sites and asserts the count is 0.
package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────────────────────────────────
// SCOPE HYGIENE: the dead tombstone EpochCompactor stays DEAD.
//
// The reaper (internal/database/l0_reaper.go) is a NEW type — it reclaims
// superseded L0 files via the S3Deleter seam, NOT a tombstone compactor. It
// introduces NO new production importer of SetCompactor / InsertTombstone /
// NewEpochCompactor / PruneTombstones (the ADR-0019 §6 + ADR-0020 discipline).
// This guard READS the production source (excludes _test.go + the dead-symbol
// OWN definition sites) and asserts the count is 0 — the DeadCompactor invariant.
// ──────────────────────────────────────────────────────────────────────────
func TestReaperDeadCompactorScopeHygiene(t *testing.T) {
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
		count := deadSymbolCallerCount(t, s.body)
		assert.Equalf(t, 0, count,
			"T6 scope hygiene: %s has %d PRODUCTION caller(s) — the dead tombstone EpochCompactor must stay DEAD post- (the reaper is a NEW type over S3Deleter, NOT a SetCompactor/InsertTombstone/NewEpochCompactor/PruneTombstones importer); ADR-0019 §6 rule",
			s.name, count)
	}
	t.Logf("T6: SetCompactor/InsertTombstone/NewEpochCompactor/PruneTombstones each have 0 production callers — the reaper added NONE (the dead tombstone compactor stays DEAD)")
}

// deadSymbolCallerCount greps the repo's PRODUCTION Go source trees
// (internal/, pkg/, cmd/) for `pattern`, excluding test files AND the dead-
// symbol OWN definition sites (compactor.go + l0_flusher.go, which hold the
// method declarations + the nil-guarded field). A production CALLER is a use
// OUTSIDE those definition files; the count returned is the number of source
// files with a hit (0 = the symbol is DEAD).
//
// The walk is scoped to internal/pkg/cmd so it does NOT descend into
// stray git worktrees (a stale worktree holds an OLD copy of the dead
// symbols — NOT a production caller; the scope excludes it).
//
// NOTE: dominance_prune_test.go ALSO defines a same-named helper
// (productionCallerCount) — so this file uses a DISTINCT name
// (deadSymbolCallerCount) to avoid the duplicate-declaration compile
// error across test files in the same package.
func deadSymbolCallerCount(t *testing.T, pattern string) int {
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
		require.NoError(t, walk(d), "T6 deadSymbolCallerCount walk %s", d)
	}
	return count
}

// Keep the reaper's L0Repeater/Reap symbols referenced (the route guards in
// pkg/durability exercise Reap; this is the unused-symbol guard so THIS file,
// which only does grep, still pulls the reaper into the build set).
var (
	_ = NewL0Reaper
)
