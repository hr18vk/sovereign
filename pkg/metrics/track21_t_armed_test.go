package metrics

// Day 21 (ADR-0026) cross-package teeth — the T-ARMED gate that FLIPS the
// Day-18 T6 prose contract "telemetry.Init has ZERO production callers" into a
// GATED assertion of the new Day-21 reality: telemetry.Init has EXACTLY ONE
// production caller (under cmd/sovereign-node/ — the armOTel helper in
// otel.go, invoked by main.go's run), and the bridge (pkg/metrics) STILL does
// NOT call it (the two-exporter separation; ADR-0023 §0.d refreshed ADR-0026
// §3). The OLD T-Init-uncalled PROSE (prose-only, byte-verified) is REPLACED by
// this gated tooth; the ADR §7 names the dictated-flip.
//
//   T-ARMED (gated, NEW): a productionCallerCount grep over the repo's
//     production Go source (internal/, pkg/, cmd/) asserts telemetry.Init has
//     EXACTLY ONE production caller (the armOTel helper in
//     cmd/sovereign-node/otel.go, called by main.go). The bridge
//     (pkg/metrics) does NOT call Init — the two exporters MUST stay separate
//     (§0.d). The OLD T-Init-uncalled PROSE is replaced.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTrack21_T_Armed asserts the new Day-21 contract: telemetry.Init has
// EXACTLY ONE production caller (under cmd/sovereign-node/ — the armOTel
// helper), and the bridge (pkg/metrics) STILL does NOT call it. This FLIPS the
// Day-18 T6 prose contract that was prose-only (the bridge test COMMENT said
// "telemetry.Init has ZERO production callers" but the test body only
// asserted the FROZEN md5 set). Day-21 DELIBERATELY flips the contract: arming
// Init at boot IS the deliverable — so this gated tooth asserts the NEW form
// (ONE production caller, not ZERO) byte-verified via a source grep.
func TestTrack21_T_Armed(t *testing.T) {
	caller := countTelemetryInitCallers(t)
	if caller == 0 {
		t.Fatalf("T-ARMED: telemetry.Init has ZERO production callers — the Day-21 deliverable (arm Init at boot) is NOT shipped. ADR-0026 requires EXACTLY ONE caller under cmd/sovereign-node/")
	}
	if caller > 1 {
		t.Fatalf("T-ARMED: telemetry.Init has %d production callers, want EXACTLY ONE (each Init under a different production path risks racing the once-per-process guard or splitting the OTel stream — ADR-0026 §0.a)", caller)
	}
	// The single caller MUST be under cmd/ — NOT pkg/metrics (the bridge must
	// never call Init; the two-exporter separation §0.d). Walk prod source to
	// confirm the one caller and that no pkg/metrics file contains the call.
	if err := assertSingleCallerInCmdAndNotInMetrics(t); err != nil {
		t.Fatalf("T-ARMED: %v", err)
	}
	// Belt-and-braces: the bridge package itself must NEVER call telemetry.Init
	// (the two-exporter separation; Day-18 T6 carried this as prose, Day-21
	// gates it).
	if bridgeCallsInit(t) {
		t.Fatalf("T-ARMED: pkg/metrics (the bridge) calls telemetry.Init — the two-exporter separation is BROKEN (§0.d); the OTel reader would be coupled to the bridge's prometheus Registry")
	}
	t.Logf("T-ARMED PASS: telemetry.Init has EXACTLY ONE production caller (under cmd/sovereign-node/) and the bridge (pkg/metrics) does NOT call it — the two-exporter separation is intact; the Day-18 T-Init-uncalled PROSE is REFRESHED to the gated T-ARMED contract")
}

// countTelemetryInitCallers greps the repo's PRODUCTION Go source trees
// (internal/, pkg/, cmd/) for `telemetry.Init(` (the call-site token; the
// registry.go DEFINITION site is excluded by name — it's the func receiver),
// excluding test files. Returns the count of source files with a hit
// (the §0.a once-per-process contract makes >1 production caller a hazard).
func countTelemetryInitCallers(t *testing.T) int {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	const token = "telemetry.Init("
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
			// Skip the telemetry package's OWN definition file — it holds the
			// func Init declaration (the definition, not a caller). Production
			// callers are OUTSIDE internal/telemetry.
			if strings.Contains(path, "internal/telemetry/") {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(data), token) {
				count++
			}
			return nil
		})
	}
	for _, d := range []string{"internal", "pkg", "cmd"} {
		if err := walk(d); err != nil {
			t.Fatalf("T-ARMED walk %s: %v", d, err)
		}
	}
	return count
}

// assertSingleCallerInCmdAndNotInMetrics confirms the one telemetry.Init
// production caller is under cmd/sovereign-node/ (the armOTel helper), and
// that NO pkg/ file (the bridge included) calls telemetry.Init.
func assertSingleCallerInCmdAndNotInMetrics(t *testing.T) error {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		return err
	}
	const token = "telemetry.Init("
	var cmdHits []string
	var pkgHits []string
	scan := func(dir string, sink *[]string) error {
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
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(data), token) {
				rel, _ := filepath.Rel(repoRoot, path)
				*sink = append(*sink, rel)
			}
			return nil
		})
	}
	if err := scan("cmd", &cmdHits); err != nil {
		return err
	}
	if err := scan("pkg", &pkgHits); err != nil {
		return err
	}
	if len(cmdHits) != 1 {
		return fmt.Errorf("expected EXACTLY ONE telemetry.Init caller under cmd/, got %d: %v", len(cmdHits), cmdHits)
	}
	if !strings.HasPrefix(cmdHits[0], "cmd/sovereign-node/") {
		return fmt.Errorf("the single cmd/ caller is %s, expected under cmd/sovereign-node/", cmdHits[0])
	}
	if len(pkgHits) != 0 {
		return fmt.Errorf("pkg/ contains telemetry.Init callers: %v — the bridge must NOT call Init (the two-exporter separation §0.d)", pkgHits)
	}
	return nil
}

// bridgeCallsInit returns true if pkg/metrics contains a telemetry.Init call in
// NON-TEST source. The two-exporter separation forbids this.
func bridgeCallsInit(t *testing.T) bool {
	t.Helper()
	repoRoot, _ := filepath.Abs("../..")
	bp := filepath.Join(repoRoot, "pkg", "metrics")
	var found bool
	_ = filepath.WalkDir(bp, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(data), "telemetry.Init(") {
			found = true
		}
		return nil
	})
	return found
}
