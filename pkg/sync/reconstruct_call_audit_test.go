// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// GenerateDigest returns arena-backed data that its caller must release. This
// static guard checks every call in crdt_test.go and the chaos partition probe:
// a deferred or direct Release call must occur within the next three lines.
// Comment-only lines satisfy neither side of the check.
//
// Removing a digest Release in either file makes the test fail with the call's
// path and line number. The runtime leak tests cover sustained digest use;
// this check also covers branches those tests may not execute. Only short mode
// skips the source scan.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// generateDigestCallSitePattern finds GenerateDigest calls, including calls on
// indexed or qualified expressions. auditFileForReleaseContract separately
// excludes comment-only lines so prose cannot create a call site.
var generateDigestCallSitePattern = regexp.MustCompile(`GenerateDigest\(\)`)

// releaseWithinPattern matches a `.Release()` call on a line (defer or direct).
var releaseWithinPattern = regexp.MustCompile(`\.Release\(\)`)

// commentLinePattern matches a line whose first non-whitespace runes are a
// Go comment marker. Used to skip comment-only lines when scanning for the
// Release-within-three-lines companion.
var commentLinePattern = regexp.MustCompile(`^\s*(//|/\*|\*)`)

// auditFileForReleaseContract requires a deferred or direct Release within
// three lines after each executable GenerateDigest call.
func auditFileForReleaseContract(t *testing.T, path string) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("digest release contract: cannot read %s: %v", path, err)
	}
	lines := strings.Split(string(src), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !generateDigestCallSitePattern.MatchString(line) {
			continue
		}
		// A GenerateDigest reference in prose is not a call site.
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		// Only executable Release calls satisfy the three-line window;
		// commented-out calls are ignored.
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
			t.Errorf("%s:%d calls GenerateDigest() without a Release within three lines:\n  %d: %s\nRelease the digest before the next loop iteration or defer its Release.",
				filepath.Base(path), i+1, i+1, line)
		}
	}
}

// TestGenerateDigestReleaseContractPin scans crdt_test.go and the chaos
// partition probe for GenerateDigest calls without a nearby Release.
func TestGenerateDigestReleaseContractPin(t *testing.T) {
	if testing.Short() {
		t.Skip("skip the digest release source scan in short mode")
	}
	// Paths are relative to the package directory used by go test.
	auditFileForReleaseContract(t, "crdt_test.go")
	auditFileForReleaseContract(t, filepath.Join("..", "..", "internal", "chaos", "partition.go"))
}
