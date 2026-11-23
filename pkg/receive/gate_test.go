// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package receive

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Gear check: every benchmark and tag uses "_4c" / GOMAXPROCS=4; no "_32c"
// on receive-package benchmarks. A gear check (mirrors the same principle
// used in the in-process transport work).
// ---------------------------------------------------------------------------

// TestGate_GearHonesty is the gear check. This box is 4-core
// (nproc=4, CPU part 0xd40, Graviton3-era). The 32-core figure is the
// publication number from the 32-core benchmark, not this gear. Using a
// 32-core tag on receive-package benchmarks is a mislabel class that the
// detector catches. The test asserts the 4-core count and skips with rationale
// if the box reports something else, rather than printing a false tag.
func TestGate_GearHonesty(t *testing.T) {
	n := runtime.NumCPU()
	gmp := runtime.GOMAXPROCS(0)
	t.Logf("gear: NumCPU=%d GOMAXPROCS=%d (tag: _4c / GOMAXPROCS=4)", n, gmp)
	if n != 4 {
		t.Skipf("box reports NumCPU=%d, not the 4-core gear this test targets; refusing to tag a false core count", n)
	}
	if gmp != 4 {
		t.Skipf("GOMAXPROCS=%d, not 4; refusing to tag a false core count", gmp)
	}
}

// TestGate_No32cTagInReceiveSource scans pkg/receive non-test source for a
// "_32c" tag (the mislabel class). Receive-package benchmarks and tags must
// read "_4c" / GOMAXPROCS=4; a "_32c" tag on receive source is caught by the
// detector.
func TestGate_No32cTagInReceiveSource(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(b), "_32c") {
			t.Errorf("forbidden \"_32c\" tag in %s (receive benches read \"_4c\" / GOMAXPROCS=4; the 32-core figure is the publication number from the 32-core benchmark, not this 4-core gear)", name)
		}
	}
}
