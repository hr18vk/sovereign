package receive

// track36_day35_scope_test.go is the Day-35 (ADR-0040) SCOPE negative-control
// tooth (T-OOB-SCOPE). It complements the existing TestTrack36_ScopeTooth
// (track36_crosscheck_test.go:727), which is a PASSIVE git-diff reader: it
// enumerates `git diff --name-only HEAD -- pkg/` + exempts the in-scope files
// via the track36ExemptDayNN maps. A passive reader can PASS VACUOUSLY — if the
// git diff returned EMPTY (e.g. run from the wrong cwd, or a future refactor
// that breaks the pathspec), the tooth would pass without exercising its claim.
//
// This tooth adds TWO controls:
//
//  1. the POSITIVE control: the in-scope Day-35 files (the 3 source files +
//     the 3 §III test files) ARE in track36ExemptDay35 — so the real scope tooth
//     exempts them (the Day-35 edits do NOT fire t.Errorf). A future fork that
//     renames a Day-35 file WITHOUT updating the map would FAIL this (the file
//     would appear in git diff but NOT be exempt → the real scope tooth fires).
//  2. the NEW NEGATIVE control (the gap the agent surfaced — no existing
//     negative-control tamper test exists): write `// x\n` to an OUT-OF-SCOPE
//     git-tracked file (pkg/durability/wal.go — a pkg/ file Day 35 does NOT
//     touch), run the SAME git-diff enumeration, + assert the tampered file
//     appears in the changed set AND is NOT in any exempt map → the real scope
//     tooth WOULD fire t.Errorf (the tooth is load-bearing, NOT vacuous). Then
//     REVERT the tamper via `git checkout -- <file>` so the working tree is
//     restored (the tooth leaves NO residue). A future author who breaks the
//     git-diff pathspec (so it returns EMPTY) would make this control FAIL (the
//     tampered file would NOT appear in the changed set) — the tooth catches the
//     vacuous-always-pass class the Day-33 /ruthless-auditor caught in the fuzz
//     corpus + the Day-34 FROZEN-touch tooth caught via os.Stat.
//
// PACKAGE receive: the tooth lives here (NOT in pkg/mesh) because the
// track36ExemptDayNN maps are package-private to pkg/receive. A cross-package
// tooth could not reach them.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestT_OOB_SCOPE is the T-OOB-SCOPE tooth (the Day-35 negative-control). See
// the file doc above for the two controls.
func TestT_OOB_SCOPE(t *testing.T) {
	root := repoRoot(t) // the EXISTING helper (track36_crosscheck_test.go:712)

	// (1) the POSITIVE control: the in-scope Day-35 files ARE in
	// track36ExemptDay35. These are the files Edit A/B/C/F touch; a future fork
	// that renames one WITHOUT updating the map would FAIL this.
	inScope := []string{
		"cmd/sovereign-node/provisioning.go",
		"pkg/mesh/peer.go",
		"cmd/sovereign-node/main.go",
		"pkg/mesh/day35_oob_test.go",
		"cmd/sovereign-node/provisioning_test.go",
		"pkg/receive/track36_day35_scope_test.go",
	}
	for _, p := range inScope {
		if !track36ExemptDay35[p] {
			t.Fatalf("T-OOB-SCOPE positive: the in-scope Day-35 file %s is NOT in track36ExemptDay35 — the real scope tooth would fire t.Errorf on it (a future fork that renamed it without updating the map would break the gate)", p)
		}
	}
	t.Logf("GATE PASS: T-OOB-SCOPE positive — all %d in-scope Day-35 files ARE in track36ExemptDay35 (the real scope tooth exempts them)", len(inScope))

	// (2) the NEW NEGATIVE control: tamper an out-of-scope git-tracked pkg/ file
	// + assert the git-diff enumeration SURFACES it (proving the scope tooth is
	// load-bearing, NOT vacuous). pkg/durability/wal.go is a pkg/ file Day 35
	// does NOT touch (grep-verified clean at tooth-write time). The tamper is a
	// trailing `// x\n` comment appended to the file (a syntactically-valid
	// no-op so the file still compiles if the revert fails — the tooth is
	// defensive: a test that leaves the tree broken is worse than a test that
	// fails loudly).
	const tampered = "pkg/durability/wal.go"
	tamperedAbs := filepath.Join(root, tampered)
	// Verify the target is git-tracked + clean BEFORE tampering (the tooth's
	// precondition — a target that is already dirty would make the assertion
	// ambiguous; skip honestly).
	if pre, _ := exec.Command("git", "-C", root, "diff", "--name-only", "HEAD", "--", tampered).Output(); len(strings.TrimSpace(string(pre))) != 0 {
		t.Skipf("T-OOB-SCOPE negative: the tamper target %s is already dirty at HEAD — skipping (the assertion would be ambiguous)", tampered)
	}
	if _, err := os.Stat(tamperedAbs); err != nil {
		t.Skipf("T-OOB-SCOPE negative: the tamper target %s does not exist — skipping (the tooth needs a real git-tracked pkg/ file)", tampered)
	}
	// Append the tamper (a trailing comment — a no-op that compiles).
	f, err := os.OpenFile(tamperedAbs, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("T-OOB-SCOPE negative: open %s for append: %v", tampered, err)
	}
	if _, err := f.WriteString("\n// T-OOB-SCOPE tamper (reverted by the tooth)\n"); err != nil {
		f.Close()
		t.Fatalf("T-OOB-SCOPE negative: write tamper to %s: %v", tampered, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("T-OOB-SCOPE negative: close %s: %v", tampered, err)
	}
	// Revert the tamper NO MATTER WHAT (the tooth leaves NO residue — a test
	// that breaks the working tree is a scope catastrophe per the standing
	// git_stash_pop_unstages_index hazard). `git checkout -- <file>` restores
	// the file to HEAD; the deferred runs even on a t.Fatalf below.
	defer func() {
		if err := exec.Command("git", "-C", root, "checkout", "--", tampered).Run(); err != nil {
			t.Errorf("T-OOB-SCOPE negative: FAILED to revert the tamper on %s — the working tree may be dirty (run `git checkout -- %s` manually): %v", tampered, tampered, err)
		}
	}()
	// Run the SAME git-diff enumeration the real TestTrack36_ScopeTooth uses
	// (track36_crosscheck_test.go:729): `git diff --name-only HEAD -- pkg/`.
	out, err := exec.Command("git", "-C", root, "diff", "--name-only", "HEAD", "--", "pkg/").Output()
	if err != nil {
		t.Fatalf("T-OOB-SCOPE negative: git diff --name-only unavailable (%v) — the scope tooth's enumeration is broken (the vacuous-always-pass class)", err)
	}
	changed := strings.Fields(string(out))
	// The tampered file MUST appear in the changed set (the enumeration is
	// load-bearing). A future author who breaks the pathspec (so it returns
	// EMPTY) would make this FAIL — the tooth catches the vacuous class.
	found := false
	for _, p := range changed {
		if p == tampered {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("T-OOB-SCOPE negative: the tampered file %s did NOT appear in `git diff --name-only HEAD -- pkg/` (got %d changed files) — the scope tooth's enumeration is VACUOUS (a passive reader that does not surface a real edit would PASS VACUOUSLY — the Day-33 /ruthless-auditor class)", tampered, len(changed))
	}
	// The tampered file MUST NOT be in ANY exempt map (so the real scope tooth
	// WOULD fire t.Errorf on it — the tooth is load-bearing). Check all the
	// per-day exempt maps + the Day-33 prefix.
	if track36ExemptDay29[tampered] || track36ExemptDay30[tampered] || track36ExemptDay31[tampered] || track36ExemptDay32[tampered] || track36ExemptDay33[tampered] || track36ExemptDay34[tampered] || track36ExemptDay35[tampered] {
		t.Fatalf("T-OOB-SCOPE negative: the tampered file %s is in an exempt map — the negative control is invalid (the tooth needs a genuinely out-of-scope file)", tampered)
	}
	if strings.HasPrefix(tampered, track36ExemptDay33Prefix) {
		t.Fatalf("T-OOB-SCOPE negative: the tampered file %s matches the Day-33 prefix — the negative control is invalid", tampered)
	}
	t.Logf("GATE PASS: T-OOB-SCOPE negative — the tampered out-of-scope file %s SURFACED in `git diff --name-only HEAD -- pkg/` + is NOT in any exempt map → the real scope tooth WOULD fire t.Errorf (the scope tooth is load-bearing, NOT vacuous); the tamper is REVERTED by the deferred git checkout", tampered)
}
