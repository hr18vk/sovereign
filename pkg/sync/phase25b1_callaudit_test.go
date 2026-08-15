package sync

// ---------------------------------------------------------------------------
// Phase 2.5b.1 — Chaos-Digest Release Discipline: the static CONTRACT PIN.
// ---------------------------------------------------------------------------
//
// This is tooth R3c: a STATIC regex guard that pins the Release-contract
// invariant at every GenerateDigest() call site. It is the engine's contract
// pin — it bites RED the moment any future engineer drops a Release on an
// arena-backed digest, even on a branch that never runs the chaos mesh's
// TestStage6 gate. Two teeth, two axes: the 10K-round OOM drive (R3a) bites on
// the leak rate at runtime; this tooth bites on the source shape statically.
//
// The contract (Phase 2.5b.1 §R3c): for EVERY non-comment line that calls
// `.GenerateDigest()`, a `.Release()` call (deferred or direct) MUST appear
// WITHIN 3 LINES AFTER the GenerateDigest call. The tooth loads the source as
// a string, walks each GenerateDigest site, scans the next 3 lines for a
// `.Release()`, and FAILS printing the offending line + missing Release if the
// contract is broken.
//
// Walked files:
//   - pkg/sync/crdt_test.go   (the R1b leak sites at 308/314/320/326/375)
//   - internal/chaos/partition.go (the R1a panic caller at 221)
//
// Mutation M2 (§R3b): comment out the FIRST digestB.Release() in crdt_test.go
// and re-run this tooth — it MUST FAIL because the regex no longer matches
// every GenerateDigest-within-3-lines-of-Release site. Restore, GREEN.
//
// This tooth does NOT downgrade red. It does NOT t.Skip under any condition
// other than testing.Short() (mirroring Phase 2m's raceEnabled discipline).
// It has NO raceEnabled guard — it is a static source scan.
// ---------------------------------------------------------------------------

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// generateDigestCallSitePattern matches a non-comment line that calls
// `<expr>.GenerateDigest()`. The leading token may include dots (e.g.
// `dstEng.GenerateDigest()`, `engines[j].GenerateDigest()`, `engineB.GenerateDigest()`).
// We deliberately reject lines whose first non-space, non-tab code is a
// comment marker (`//` or `/*`), so commented-out mutations do not count as
// contract violations — the mutating engineer comments the Release, and this
// tooth still sees the StateDigest call on an uncommented line and bites
// because there is no Release within 3 lines of it.
var generateDigestCallSitePattern = regexp.MustCompile(`GenerateDigest\(\)`)

// releaseWithinPattern matches a `.Release()` call on a line (defer or direct).
var releaseWithinPattern = regexp.MustCompile(`\.Release\(\)`)

// commentLinePattern matches a line whose first non-whitespace runes are a
// Go comment marker. Used to skip comment-only lines when scanning for the
// Release-within-3-lines companion.
var commentLinePattern = regexp.MustCompile(`^\s*(//|/\*|\*)`)

// auditFileForReleaseContract walks src line-by-line. For every line that
// contains a GenerateDigest() call and is NOT itself a comment line, it asserts
// a `.Release()` appears within the next 3 lines (deferred or direct). The 3-
// line window is the contract the 2.5b.1 §R3c mandate pins.
func auditFileForReleaseContract(t *testing.T, path string) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("callaudit: cannot read %s: %v", path, err)
	}
	lines := strings.Split(string(src), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !generateDigestCallSitePattern.MatchString(line) {
			continue
		}
		// Skip comment-line GenerateDigest references (e.g. a doc comment
		// quoting the call). The mandate's contract is about executable code,
		// not prose.
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		// Scan the contract window (the next 3 lines after the call) for a
		// LIVE .Release(). A commented-out `<var>.Release()` (the muscle
		// mutation M2 drops the discipline) MUST NOT satisfy the contract,
		// so comment-only lines are skipped — the tooth bites the moment a
		// once-disciplined Release is muted.
		found := false
		windowEnd := i + 3
		if windowEnd >= len(lines) {
			windowEnd = len(lines) - 1
		}
		for j := i + 1; j <= windowEnd; j++ {
			cand := lines[j]
			ct := strings.TrimLeft(cand, " \t")
			if strings.HasPrefix(ct, "//") || strings.HasPrefix(ct, "/*") || strings.HasPrefix(ct, "*") {
				continue
			}
			if releaseWithinPattern.MatchString(cand) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("callaudit: %s:%d calls GenerateDigest() but no .Release() within 3 lines after it:\n  %d: %s\nThe bounded per-engine HamtArena (Phase 2.5b) makes a forgotten Release observable as `HamtArena: OOM`. Add `defer <digest>.Release()` (or a direct Release at the bottom of a loop iteration).",
				filepath.Base(path), i+1, i+1, line)
		}
	}
}

// TestPhase25B1_GenerateDigestReleaseContractPin is the static contract pin.
// It walks crdt_test.go and the chaos partition.go and asserts the
// Release-within-3-lines invariant at every GenerateDigest() call site.
func TestPhase25B1_GenerateDigestReleaseContractPin(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 2.5b.1 static callaudit scans source; skip in -short")
	}
	// pkg/sync/crdt_test.go — the R1b leak sites (308/314/320/326/375).
	// Path is relative to the package dir (this file lives in pkg/sync).
	auditFileForReleaseContract(t, "crdt_test.go")
	// internal/chaos/partition.go — the R1a panic caller (line 221).
	// pkg/sync and internal/ are siblings under the repo root; pkg/sync reaches
	// internal/chaos via ../../internal/chaos (single-module repo).
	auditFileForReleaseContract(t, filepath.Join("..", "..", "internal", "chaos", "partition.go"))
}
