// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package receive

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// TestGate_GearHonesty is the gear-honesty guard. This box is 4c (nproc=4, CPU
// part 0xd40, Graviton3-era). The 32c figure is a separately-published number,
// NOT this gear. The test asserts the honest 4c count and skips (with
// rationale) if the box reports something else, rather than printing a false
// tag.
func TestGate_GearHonesty(t *testing.T) {
	n := runtime.NumCPU()
	gmp := runtime.GOMAXPROCS(0)
	t.Logf("honest gear: NumCPU=%d GOMAXPROCS=%d (tag: _4c / GOMAXPROCS=4)", n, gmp)
	if n != 4 {
		t.Skipf("box reports NumCPU=%d, not the 4c gear this package targets; refusing to tag a false core count (no _32c on these benches)", n)
	}
	if gmp != 4 {
		t.Skipf("GOMAXPROCS=%d, not 4; refusing to tag a false core count", gmp)
	}
}

// TestGate_No32cTagInReceiveSource greps pkg/receive non-test source for a
// "_32c" tag. These benches read "_4c" / GOMAXPROCS=4; a "_32c" tag on this
// source is the mislabel class.
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
			t.Errorf("forbidden \"_32c\" tag in %s (these benches read \"_4c\" / GOMAXPROCS=4; the 32c figure is a separately-published number, NOT this 4c gear)", name)
		}
	}
}
