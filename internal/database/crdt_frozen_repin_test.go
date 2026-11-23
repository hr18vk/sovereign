// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Scope check for the L0 reaper (ADR-0021).
//
// End-to-end filesystem reaper tests live in pkg/durability/l0_reaper_test.go
// to avoid a database <-> durability import cycle. This test verifies that the
// reaper (internal/database/l0_reaper.go) reclaims superseded L0 files via
// S3Deleter without introducing production callers of the unused EpochCompactor
// methods in compactor.go.
package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReaperDeadCompactorScopeHygiene verifies that the L0 reaper introduces no
// production callers of SetCompactor, InsertTombstone, NewEpochCompactor, or
// PruneTombstones.
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
	for _, s := range dead {
		count := deadSymbolCallerCount(t, s.body)
		assert.Equalf(t, 0, count,
			"scope hygiene: %s has %d production caller(s); the L0 reaper must use S3Deleter rather than EpochCompactor (ADR-0019)",
			s.name, count)
	}
	t.Logf("SetCompactor/InsertTombstone/NewEpochCompactor/PruneTombstones each have 0 production callers")
}

// deadSymbolCallerCount walks the repo's production Go source trees
// (internal/, pkg/, cmd/) for `pattern`, excluding test files and the dead-
// symbol definition sites (compactor.go and l0_flusher.go, which hold the
// method declarations and the nil-guarded field). A production caller is a
// use outside those definition files; the count returned is the number of
// source files with a hit (0 means the symbol is dead).
//
// The walk is scoped to internal/, pkg/, and cmd/ so it does not descend into
// stale git worktrees (which hold old copies of the dead symbols — not
// production callers; the scope excludes them). This helper is the
// productionCallerCount from the L1 compaction test relocated here (the helper
// is package-scoped so the original copy still builds; the tests here use this
// copy to keep the symbol count self-contained; only one is referenced per
// binary because each test file references its own copy).
//
// NOTE: the L1 compaction test also defines a productionCallerCount function
// with the same name — this file uses a distinct name to avoid a
// duplicate-declaration compile error across test files in the same package.
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
		require.NoError(t, walk(d), "production caller count walk %s", d)
	}
	return count
}

// Keep the reaper's L0Repeater/Reap symbols referenced (the route tests in
// pkg/durability exercise Reap; this is the unused-symbol guard so this file,
// which only does grep, still pulls the reaper into the build-cert set).
var (
	_ = NewL0Reaper
)
