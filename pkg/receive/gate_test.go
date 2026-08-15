package receive

import (
	"crypto/md5"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gitShowHead returns the bytes of <path> at git HEAD, or an error if git is
// unavailable or the file is untracked at HEAD. It is the G3.5.i byte-identity
// check against the pre-track baseline.
func gitShowHead(path string) ([]byte, error) {
	cmd := exec.Command("git", "show", "HEAD:"+path)
	return cmd.Output()
}

// ---------------------------------------------------------------------------
// G3.5.c — FROZEN md5 byte-identical pre & post (crdt.go, schema.capnp,
// schema.capnp.go). A gate test reads + md5s them and asserts.
// ---------------------------------------------------------------------------

// frozenFiles are the FROZEN files this track MUST NOT touch, with their
// PROVEN md5s (byte-identical pre & post). The gate test reads each file and
// asserts its md5 matches — a byte-level change to any FROZEN file fails the
// build. The md5s are the ones the prompt §1.7 pins (re-verified on this box
// before this test was written).
var frozenFiles = []struct {
	path string
	md5  string
}{
	// crdt.go was re-pinned 4512bd67 -> 705ac671 at Day 10 (ADR-0015: UNFROZEN for the
	// JOIN-BUFFER POOL [Fix J1+J2]). The 3 contracts (determinism/EBR/57.6M) were
	// re-proven safe byte-by-byte by TestJoinDeterminism_PooledVsUnpooledMerkleEqual,
	// TestJoinPool_DoesNotRetirePoolBuffers, TestHotPathZeroAllocations + the alignment
	// teeth. The re-pin is the honesty discipline for the re-freeze, NOT a 3.5 scope breach.
	// ANY future byte change to crdt.go requires: (1) an ADR-disclosed re-pin, (2) the 3
	// contracts re-gated, (3) ALL 4 sibling pins re-synced (receive/gate, receive/bench,
	// transport, authorization).
	//
	// Day 16 (ADR-0021, 2026-08-03): re-pinned 705ac671 -> a50fee8f — a COMMENT-ONLY
	// change (a warning doc above `var DataDir` at crdt.go:17). NO byte of executable
	// code changed; the 3 contracts are byte-identical. The re-pin is the honesty
	// discipline for the comment drift. ALL 8 pins re-synced. Day-10 ADR-0015 §7 +
	// Day-8.5 receiver.go precedent.
	{"../../pkg/sync/crdt.go", "44f8952771cfad4d195e518b63a33440"},
	// crdt_apply.go is the Join seam the receiver CALLS; Track 3.6 G3.6.a
	// EXTENDS this md5-pinned list to assert its byte-identity explicitly (it
	// was already gate-frozen via the git-HEAD untouchedFiles tooth below; the
	// md5 pin is belt-and-suspenders — a byte-level change fails BOTH teeth).
	// md5 re-verified on this box this turn (disk == git HEAD).
	{"../../pkg/sync/crdt_apply.go", "ed9132a27930b3d76a3f62e783dd7dd3"},
	{"../../api/capnp/api/capnp/schema.capnp", "47d2796a973319a3ffe364de3d08d6d6"},
	{"../../api/capnp/api/capnp/schema.capnp.go", "590af2287dcb3a135c586b50260be531"},
}

// TestGate_FrozenMD5 asserts the FROZEN files are byte-identical to their
// PROVEN md5s. A byte-level change to crdt.go, schema.capnp, or
// schema.capnp.go fails the build (G3.5.c). The paths are relative to
// pkg/receive (the test's working dir).
func TestGate_FrozenMD5(t *testing.T) {
	for _, f := range frozenFiles {
		b, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("read FROZEN %s: %v", f.path, err)
		}
		sum := md5.Sum(b)
		got := strings.Builder{}
		for _, c := range sum {
			got.WriteString(byteHex(c))
		}
		if got.String() != f.md5 {
			t.Fatalf("G3.5.c: FROZEN %s md5 changed: got %s, want %s (this track MUST NOT touch FROZEN files)", f.path, got.String(), f.md5)
		}
	}
}

// byteHex renders a byte as two lowercase hex digits.
func byteHex(b byte) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[b>>4], hex[b&0xf]})
}

// ---------------------------------------------------------------------------
// G3.5.i — crdt.go untouched: git diff --stat empty under pkg/sync, api/capnp,
// go.mod, go.sum; under pkg/clock, pkg/admission, pkg/transport you only CALL,
// you do not edit. This static tooth greps the FROZEN/out-of-scope source for
// edits by checking the files are byte-identical to their git-HEAD versions.
// ---------------------------------------------------------------------------

// untouchedFiles are the FROZEN + out-of-scope files this track must NOT edit
// (only CALL). The gate test asserts each is byte-identical to its git-HEAD
// version via `git show HEAD:<path>`. crdt_apply.go is FROZEN (the Join seam
// the receiver calls); the gate packages (clock, admission, transport) are
// out-of-scope (call-only).
// untouchedFilesExempt is the subset of untouchedFiles that Day 29
// (ADR-0034, the streak-breaker) legitimately EDITED — crdt.go carries BOTH
// the D2 EBR-pool leak fix AND the M2 fix (the deletion of the broken
// GenerateDeltaStratified + the tombstone doc). The Day-18 "no re-pin since
// Day-13" streak is BROKEN for this physical defect (Architect-authorized).
// The FROZEN-md5 tooth (TestGate_FrozenMD5) pins crdt.go to its NEW Day-29
// hash (44f89527); this G3.5.i tooth EXEMPTS crdt.go from the byte-identical-
// to-HEAD assertion (the re-pin is ADR-disclosed, not a stealth edit). The
// OTHER untouched files (crdt_apply.go, schema.capnp, schema.capnp.go, the
// clock/admission/transport files) stay byte-identical to HEAD — Day 29
// touches NONE of them.
var untouchedFilesExempt = map[string]bool{
	"../../pkg/sync/crdt.go": true, // Day-29 ADR-0034 streak-breaker (D2 + M2 fix; re-pinned 835350a8 -> 44f89527)
}

var untouchedFiles = []string{
	"../../pkg/sync/crdt.go",
	"../../pkg/sync/crdt_apply.go",
	"../../api/capnp/api/capnp/schema.capnp",
	"../../api/capnp/api/capnp/schema.capnp.go",
	"../../pkg/clock/admission.go",
	"../../pkg/clock/clock.go",
	"../../pkg/admission/ewma.go",
	"../../pkg/transport/transport.go",
}

// TestGate_UntouchedFrozenAndOutOfScope asserts the FROZEN + out-of-scope
// files are byte-identical to their git-HEAD versions (G3.5.i). It shells out
// to `git show HEAD:<path>` and compares the bytes. A byte-level edit to any
// of these fails the build (this track only CALLS them; it does not edit).
//
// go.mod / go.sum are checked separately (no dependency added/removed).
func TestGate_UntouchedFrozenAndOutOfScope(t *testing.T) {
	// The test working dir is pkg/receive; the untouchedFiles paths are
	// relative to it (../../pkg/sync/...). git paths are relative to the
	// repo root, so strip the leading ../../ for the git-show argument.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for _, rel := range untouchedFiles {
		abs := filepath.Join(wd, rel)
		if _, err := os.Stat(abs); err != nil {
			t.Fatalf("stat untouched %s: %v", rel, err)
		}
		gitPath := strings.TrimPrefix(rel, "../../")
		headBytes, err := gitShowHead(gitPath)
		if err != nil {
			// If git is unavailable or the file is untracked at HEAD, skip
			// with a rationale rather than failing (the FROZEN md5 tooth
			// covers the FROZEN files byte-identically already).
			t.Logf("G3.5.i: could not git-show HEAD:%s (%v); relying on the FROZEN md5 tooth for FROZEN files", gitPath, err)
			continue
		}
		diskBytes, err := os.ReadFile(abs)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if string(headBytes) != string(diskBytes) {
			if untouchedFilesExempt[rel] {
				// Day-29 ADR-0034 streak-breaker: crdt.go carries the D2 leak fix
				// + the M2 fix (the deletion of the broken GenerateDeltaStratified).
				// The re-pin (835350a8 -> 44f89527) is ADR-disclosed + pinned by
				// TestGate_FrozenMD5; this byte-identical-to-HEAD tooth EXEMPTS it.
				t.Logf("G3.5.i: %s was EDITED (differs from git-HEAD) — EXEMPT (Day-29 ADR-0034 streak-breaker: the D2 leak fix + the M2 primitive deletion; re-pinned 835350a8 -> 44f89527, pinned by TestGate_FrozenMD5)", gitPath)
				continue
			}
			t.Fatalf("G3.5.i: %s was EDITED (differs from git-HEAD); this track only CALLS FROZEN/out-of-scope files, it does not edit them", gitPath)
		}
	}
}

// ---------------------------------------------------------------------------
// G3.5.k — GEAR HONESTY: every bench/tag "_4c" / GOMAXPROCS=4; no "_32c" on
// 3.5 own benches. A gear-honesty tooth (mirror Track 2.0 G2.0.j).
// ---------------------------------------------------------------------------

// TestGate_GearHonesty is the gear-honesty tooth (G3.5.k, mirrors G2.0.j).
// This box is 4c (nproc=4, CPU part 0xd40, Graviton3-era). The 32c figure is
// Track 4's PROVEN publication number, NOT this gear. Re-using 32c for 3.5
// OWN benches is the track-5.0 mislabel class, detector-banned. The test
// asserts the honest 4c count and skips (with rationale) if the box is
// willfully reporting something else, rather than printing a false tag.
func TestGate_GearHonesty(t *testing.T) {
	n := runtime.NumCPU()
	gmp := runtime.GOMAXPROCS(0)
	t.Logf("honest gear: NumCPU=%d GOMAXPROCS=%d (tag: _4c / GOMAXPROCS=4)", n, gmp)
	if n != 4 {
		t.Skipf("box reports NumCPU=%d, not the 4c gear this track targets; refusing to tag a false core count (no _32c on 3.5 OWN benches)", n)
	}
	if gmp != 4 {
		t.Skipf("GOMAXPROCS=%d, not 4; refusing to tag a false core count", gmp)
	}
}

// TestGate_No32cTagInReceiveSource greps pkg/receive non-test source for a
// "_32c" tag (the track-5.0 mislabel class). 3.5 own benches/tags MUST read
// "_4c" / GOMAXPROCS=4; a "_32c" tag on 3.5 source is detector-banned.
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
			t.Errorf("G3.5.k: forbidden \"_32c\" tag in %s (3.5 own benches read \"_4c\" / GOMAXPROCS=4; the 32c figure is Track 4's PROVEN publication number, NOT this 4c gear)", name)
		}
	}
}
