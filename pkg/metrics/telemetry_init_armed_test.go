// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package metrics

// These source checks preserve the boundary established by ADR-0026: the
// command's armOTel helper is the only production caller of telemetry.Init,
// and pkg/metrics never initializes OTel itself. Keeping initialization in the
// command separates the OTel exporter from the bridge's Prometheus registry
// and avoids concurrent rebinding of the package-level counters.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestArmedBridge checks that production source has exactly one telemetry.Init
// caller under cmd/sovereign-node and none under pkg/. Additional callers could
// rebind counters or couple the OTel exporter to the Prometheus bridge.
func TestArmedBridge(t *testing.T) {
	caller := countTelemetryInitCallers(t)
	if caller == 0 {
		t.Fatalf("telemetry.Init has no production caller; want armOTel under cmd/sovereign-node")
	}
	if caller > 1 {
		t.Fatalf("telemetry.Init has %d production callers, want one", caller)
	}
	if err := assertSingleCallerInCmdAndNotInMetrics(t); err != nil {
		t.Fatalf("telemetry.Init caller check: %v", err)
	}
	if bridgeCallsInit(t) {
		t.Fatalf("pkg/metrics calls telemetry.Init; initialization belongs to the command")
	}
	t.Logf("telemetry.Init has one command caller and no pkg/metrics caller")
}

// countTelemetryInitCallers counts production Go files under internal/, pkg/,
// and cmd/ that contain telemetry.Init. It excludes tests and the defining
// internal/telemetry package.
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
			// The defining package cannot be a production caller of itself.
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
			t.Fatalf("walk %s: %v", d, err)
		}
	}
	return count
}

// assertSingleCallerInCmdAndNotInMetrics requires the sole production caller
// to be under cmd/sovereign-node and rejects calls anywhere under pkg/.
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
		return fmt.Errorf("expected exactly one telemetry.Init caller under cmd/, got %d: %v", len(cmdHits), cmdHits)
	}
	if !strings.HasPrefix(cmdHits[0], "cmd/sovereign-node/") {
		return fmt.Errorf("the single cmd/ caller is %s, expected under cmd/sovereign-node/", cmdHits[0])
	}
	if len(pkgHits) != 0 {
		return fmt.Errorf("pkg/ contains telemetry.Init callers: %v — the bridge must not call Init (two-exporter separation per ADR-0023)", pkgHits)
	}
	return nil
}

// bridgeCallsInit reports whether non-test source in pkg/metrics contains a
// telemetry.Init call.
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
