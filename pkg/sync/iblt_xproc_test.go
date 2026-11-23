// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package sync cross-process tests exercise digest reconciliation across
// independent Go runtimes. Runtime maphash includes per-process keying, so
// using it for bucket placement prevents common keys from cancelling after
// subtraction and drives GenerateDelta to the full-keyset fallback.
//
// The helpers re-execute this test binary with an environment-selected mode.
// TestIBLT_XprocDeterminism compares hashes, indices, and wire bytes from a
// parent and two children. TestIBLT_XprocConvergence reconciles 1,000 keys
// against the first 900 in two subprocesses and requires exactly the 100
// A-only entries. TestIBLT_BucketUniformity checks 10,000 keys against
// Poisson-derived load bounds and includes a weak-placement negative control.
package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// ibltXprocSeedWord is shared by every helper process. Hashing depends only on
// this wire word and the key, not on process-local runtime state.
const ibltXprocSeedWord uint64 = 0x9E3779B97F4A7C15

// ibltXprocHelperEnv selects the helper mode when the tests re-execute their
// own binary. "probe" prints hashes and wire bytes, "convA" reconciles 1,000
// keys against a supplied digest, and "convB" prints a 900-key digest. An
// ordinary test run leaves it unset and skips the helper.
const ibltXprocHelperEnv = "SOVEREIGN_TEST_IBLT_XPROC_HELPER"

// ibltXprocProbeKey is the i-th deterministic digest key in the ENGINE'S OWN key
// shape: HashCausalDot over a fixed (nodeID, counter=i+1) dot and a fixed
// payload digest. Pure FNV-1a arithmetic — no maphash — so the keys themselves
// are identical in every process; only the BUCKET PLACEMENT may diverge.
func ibltXprocProbeKey(i int) uint64 {
	dot := CausalDot{
		NodeID:  [16]byte{0xF0, 0x22},
		Counter: uint64(i + 1),
	}
	return HashCausalDot(dot, sha256.Sum256([]byte(fmt.Sprintf("iblt-xproc-key-%d", i))))
}

// ibltXprocConvEngine builds the first n convergence keys with entity IDs
// iblt-conv-<i> and the same node ID in every process. Identical inserts mint
// identical dots, so A(0..999) and B(0..899) share exactly the first 900 digest
// keys and A-B contains exactly keys 900 through 999.
func ibltXprocConvEngine(t *testing.T, n int) *DeltaCRDTEngine {
	t.Helper()
	e := newTestEngine(t, [16]byte{0xF0, 0x22}, 0)
	for i := 0; i < n; i++ {
		entry := CRDTEntry{
			SystemTime:    int64(1_700_000_000 + i),
			H3Index:       uint64(i),
			PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("iblt-conv-p-%d", i))),
		}
		e.InsertLocal(fmt.Sprintf("iblt-conv-%d", i), entry)
	}
	return e
}

// TestIBLT_XprocHelper produces data for the parent process. It skips when the
// helper environment is unset; all assertions remain in the spawning tests so
// a child failure cannot become a silent pass.
func TestIBLT_XprocHelper(t *testing.T) {
	mode := os.Getenv(ibltXprocHelperEnv)
	if mode == "" {
		t.Skip("cross-process helper only; set " + ibltXprocHelperEnv + " to probe, convA, or convB")
	}
	switch mode {
	case "probe", "1":
		ibltXprocProbeMode(t)
	case "convA":
		ibltXprocConvAMode(t)
	case "convB":
		ibltXprocConvBMode(t)
	default:
		t.Fatalf("cross-process helper: unknown mode %q; want probe, convA, or convB", mode)
	}
}

// ibltProbeLines renders per-key hashes and bucket indices followed by the
// full marshaled digest. Parent and child processes call this same function,
// so their output can be compared byte for byte.
func ibltProbeLines() []string {
	seed := Uint64ToSeed(ibltXprocSeedWord)
	ib := NewIBLTWithSeed(64, 4, seed)
	defer ib.Release()
	lines := make([]string, 0, 10)
	for i := 0; i < 8; i++ {
		key := ibltXprocProbeKey(i)
		ph, h1, h2, n := ib.hashKeyWithSeed(key)
		var idx [ibltMaxK]int
		ib.getHashesInto(&idx, key)
		lines = append(lines, fmt.Sprintf(
			"IBLTPROBE key=%#016x primaryHash=%#016x h1=%#016x h2=%#016x n=%d idx=%v",
			key, ph, h1, h2, n, idx[:ib.K()]))
		ib.Insert(key)
	}
	wire, err := MarshalIBLT(ib)
	if err != nil {
		panic("ibltProbeLines: MarshalIBLT: " + err.Error())
	}
	lines = append(lines, fmt.Sprintf("IBLTPROBE wirelen=%d wire=%x", len(wire), wire))
	return lines
}

// ibltXprocProbeMode prints a digest probe for manual comparison:
//
//	SOVEREIGN_TEST_IBLT_XPROC_HELPER=probe go test -run '^TestIBLT_XprocHelper$' -v ./pkg/sync/
//
// Separate invocations produce identical key, index, and wire lines; the pid
// line is expected to differ.
func ibltXprocProbeMode(t *testing.T) {
	fmt.Printf("IBLTPROBE pid=%d seedWord=%#x\n", os.Getpid(), ibltXprocSeedWord)
	for _, ln := range ibltProbeLines() {
		fmt.Println(ln)
	}
}

// ibltXprocConvBMode builds the first 900 convergence keys and prints their
// marshaled digest. The parent passes this hex frame to the convA child for
// the same MarshalIBLT, hex, UnmarshalIBLT path used by the mesh.
func ibltXprocConvBMode(t *testing.T) {
	e := ibltXprocConvEngine(t, 900)
	seed := Uint64ToSeed(ibltXprocSeedWord)
	d := e.GenerateDigestWithSeed(seed)
	wire, err := MarshalIBLT(d)
	d.Release()
	if err != nil {
		t.Fatalf("convB: MarshalIBLT: %v", err)
	}
	fmt.Printf("IBLTCONVB pid=%d wirelen=%d wire=%x\n", os.Getpid(), len(wire), wire)
}

// ibltXprocConvAMode builds 1,000 convergence keys, decodes B's digest from
// ibltXprocPeerWireEnv, and prints GenerateDelta's peel result and entry set.
// The caller has more keys because GenerateDelta returns caller keys missing
// from the remote. A successful peel yields exactly the 100 A-only entries;
// an incomplete peel selects all 1,000.
func ibltXprocConvAMode(t *testing.T) {
	raw := os.Getenv(ibltXprocPeerWireEnv)
	if raw == "" {
		t.Fatalf("convA: env %s is empty — the peer wire was not handed over", ibltXprocPeerWireEnv)
	}
	wire, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("convA: peer wire is not hex: %v", err)
	}
	remote, err := UnmarshalIBLT(wire)
	if err != nil {
		t.Fatalf("convA: UnmarshalIBLT: %v", err)
	}
	e := ibltXprocConvEngine(t, 1000)
	delta := e.GenerateDelta(remote)
	var eids []string
	delta.Entries(func(entityID string, _ CRDTEntry) bool {
		eids = append(eids, entityID)
		return true
	})
	peel := "<nil>"
	if delta.peelErr != nil { // same package: read the unexported outcome directly
		peel = delta.peelErr.Error()
	}
	diffNil := delta.diffNil
	delta.Release()
	remote.Release()
	sort.Strings(eids)
	fmt.Printf("IBLTCONVA pid=%d peelErr=%s diffNil=%v count=%d entries=%s\n",
		os.Getpid(), peel, diffNil, len(eids), strings.Join(eids, ","))
}

// ibltXprocPeerWireEnv carries the convA child's input (B's marshaled digest
// wire, hex) from the spawning parent to the child process.
const ibltXprocPeerWireEnv = "SOVEREIGN_TEST_IBLT_PEER_WIRE"

// ibltXprocSpawn re-executes this test binary in mode and returns its stdout
// and process ID. Callers require distinct parent and child IDs so an
// in-process result cannot satisfy a cross-process assertion.
func ibltXprocSpawn(t *testing.T, mode string, extraEnv ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestIBLT_XprocHelper$", "-test.timeout=120s")
	env := append([]string{}, os.Environ()...)
	env = append(env, ibltXprocHelperEnv+"="+mode)
	env = append(env, extraEnv...)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cross-process spawn mode=%s: %v\n--- child stdout ---\n%s", mode, err, out)
	}
	if cmd.Process == nil {
		t.Fatalf("cross-process spawn mode=%s returned no process handle", mode)
	}
	return string(out), cmd.Process.Pid
}

// ibltFilterLines keeps only the marker-prefixed lines the helper printed.
func ibltFilterLines(out, prefix string) []string {
	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, prefix) {
			lines = append(lines, ln)
		}
	}
	return lines
}

// TestIBLT_XprocDeterminism compares a parent with two child processes. Every
// per-key hash, bucket index, and MarshalIBLT byte must match. Runtime
// maphash would fail this comparison because each process has different
// internal keying; the deterministic hash depends only on key and seed word.
func TestIBLT_XprocDeterminism(t *testing.T) {
	parent := ibltProbeLines()
	out1, pid1 := ibltXprocSpawn(t, "probe")
	out2, pid2 := ibltXprocSpawn(t, "probe")
	if pid1 == pid2 || pid1 == os.Getpid() || pid2 == os.Getpid() {
		t.Fatalf("children are not distinct processes: parent=%d child1=%d child2=%d", os.Getpid(), pid1, pid2)
	}
	join := func(out string) []string {
		lines := ibltFilterLines(out, "IBLTPROBE key=")
		lines = append(lines, ibltFilterLines(out, "IBLTPROBE wirelen=")...)
		return lines
	}
	child1 := join(out1)
	child2 := join(out2)
	if len(child1) != len(parent) || len(child2) != len(parent) {
		t.Fatalf("probe line count mismatch: parent=%d child1=%d child2=%d\nchild1 output:\n%s\nchild2 output:\n%s", len(parent), len(child1), len(child2), out1, out2)
	}
	for i := range parent {
		if child1[i] != parent[i] || child2[i] != parent[i] {
			t.Fatalf("cross-process determinism mismatch at line %d:\n parent: %s\n child1: %s\n child2: %s", i, parent[i], child1[i], child2[i])
		}
	}
	t.Logf("cross-process determinism: parent and two children agree on all %d probe lines, including full digest wire bytes", len(parent))
}

// TestIBLT_XprocConvergence passes B's 900-key digest through the wire codec
// and reconciles it in subprocess A, which holds 1,000 keys with the same node
// ID. A.GenerateDelta must return exactly iblt-conv-900 through iblt-conv-999
// with no peel error. Process-local placement would instead break subtraction
// and select the 1,000-entry fallback. The reverse direction is not a useful
// control: B is a subset of A, so it returns no entries even when A cannot
// decode its larger difference.
func TestIBLT_XprocConvergence(t *testing.T) {
	outB, pidB := ibltXprocSpawn(t, "convB")
	wireLines := ibltFilterLines(outB, "IBLTCONVB pid=")
	if len(wireLines) != 1 {
		t.Fatalf("convB produced %d wire lines; want 1:\n%s", len(wireLines), outB)
	}
	const wireTag = " wire="
	wi := strings.Index(wireLines[0], wireTag)
	if wi < 0 {
		t.Fatalf("convB line has no %q field: %s", wireTag, wireLines[0])
	}
	wireHex := wireLines[0][wi+len(wireTag):]

	outA, pidA := ibltXprocSpawn(t, "convA", ibltXprocPeerWireEnv+"="+wireHex)
	aLines := ibltFilterLines(outA, "IBLTCONVA ")
	if len(aLines) != 1 {
		t.Fatalf("convA produced %d result lines; want 1:\n%s", len(aLines), outA)
	}
	if pidA == pidB || pidA == os.Getpid() || pidB == os.Getpid() {
		t.Fatalf("A and B are not distinct processes: parent=%d A=%d B=%d", os.Getpid(), pidA, pidB)
	}
	var peelErr, countStr, entriesStr string
	for _, f := range strings.Fields(aLines[0]) {
		switch {
		case strings.HasPrefix(f, "peelErr="):
			peelErr = strings.TrimPrefix(f, "peelErr=")
		case strings.HasPrefix(f, "count="):
			countStr = strings.TrimPrefix(f, "count=")
		case strings.HasPrefix(f, "entries="):
			entriesStr = strings.TrimPrefix(f, "entries=")
		}
	}
	if peelErr != "<nil>" {
		t.Fatalf("cross-process peel failed: peelErr=%s count=%s; want exactly 100 A-only entries. Line: %s", peelErr, countStr, aLines[0])
	}
	if countStr != "100" {
		t.Fatalf("A.GenerateDelta(B digest) returned %s entries; want exactly 100 A-only entries. Line: %s", countStr, aLines[0])
	}
	got := strings.Split(entriesStr, ",")
	if len(got) != 100 {
		t.Fatalf("cross-process peel returned %d entries; want 100. Line: %s", len(got), aLines[0])
	}
	for i := 0; i < 100; i++ {
		want := fmt.Sprintf("iblt-conv-%d", 900+i)
		if got[i] != want {
			t.Fatalf("cross-process peel entry %d = %q; want %q (full set: %s)", i, got[i], want, entriesStr)
		}
	}
	t.Logf("cross-process A(1000)-B(900) returned exactly the 100 A-only entries through the wire round trip")
}

// TestIBLT_BucketUniformity inserts 10,000 deterministic keys with k=4 into
// 1024 buckets, producing 40,000 placements with lambda=39.06 and sigma=6.24.
// The preselected Poisson bounds are maximum load 90 (lambda+8 sigma), minimum
// load 8 (P(X<=7|lambda=39) about 1e-9 per bucket), and chi-square 1534
// (1.5*1023 degrees of freedom). Clustered placement can saturate an IBLT even
// for small differences, so deterministic hashing must also distribute keys.
func TestIBLT_BucketUniformity(t *testing.T) {
	const bucketsN, keysN, k = 1024, 10000, 4
	seed := Uint64ToSeed(ibltXprocSeedWord)
	ib := NewIBLTWithSeed(bucketsN, k, seed)
	defer ib.Release()
	for i := 0; i < keysN; i++ {
		ib.Insert(ibltXprocProbeKey(i))
	}
	loads := make([]int, bucketsN)
	total := 0
	for b := range loads {
		loads[b] = int(ib.buckets[b].Count)
		total += loads[b]
	}
	if total != keysN*k {
		t.Fatalf("total placements = %d; want %d because every Insert touches k buckets", total, keysN*k)
	}
	if err := ibltUniformityBound(loads, bucketsN, keysN*k); err != nil {
		t.Fatalf("hash placement exceeds uniformity bound: %v", err)
	}
	// key<<32 has zero low bits. With h1=x and h2=(x>>32)|1, index j is
	// (h1+j*h2)%1024=j, placing all keys in only four buckets. The same bound
	// must reject this control; identity or sequential keys modulo 1024 would
	// be uniform and would not demonstrate that the check can fail.
	weak := make([]int, bucketsN)
	for i := 0; i < keysN; i++ {
		x := ibltXprocProbeKey(i) << 32
		h1, h2 := x, (x>>32)|1
		for j := 0; j < k; j++ {
			weak[(h1+uint64(j)*h2)%uint64(bucketsN)]++
		}
	}
	if err := ibltUniformityBound(weak, bucketsN, keysN*k); err == nil {
		t.Fatalf("weak key<<32 placement passed the uniformity bound; the negative control must be rejected")
	}
	t.Logf("bucket uniformity: 40,000 placements satisfied the Poisson bounds; the weak placement control was rejected")
}

// ibltUniformityBound applies the a-priori Poisson bounds to a load vector.
// nil = uniform-enough; an error names the breach otherwise.
func ibltUniformityBound(loads []int, bucketsN, placements int) error {
	lam := float64(placements) / float64(bucketsN)
	chi2 := 0.0
	maxL, minL := 0, 1<<30
	for _, l := range loads {
		if l > maxL {
			maxL = l
		}
		if l < minL {
			minL = l
		}
		d := float64(l) - lam
		chi2 += d * d / lam
	}
	if maxL > 90 {
		return fmt.Errorf("max bucket load %d > 90 (λ=%.2f, expected max ≈ 62)", maxL, lam)
	}
	if minL < 8 {
		return fmt.Errorf("min bucket load %d < 8 (λ=%.2f)", minL, lam)
	}
	if chi2 > 1534 {
		return fmt.Errorf("chi-square %.0f > 1534 (df=%d)", chi2, bucketsN-1)
	}
	return nil
}

// BenchmarkIBLT_HashKeyWithSeed measures deterministic hash and index
// generation without table insertion. Digest construction performs this work
// for every key and each of its k placements.
func BenchmarkIBLT_HashKeyWithSeed(b *testing.B) {
	seed := Uint64ToSeed(ibltXprocSeedWord)
	ib := NewIBLTWithSeed(1024, 4, seed)
	defer ib.Release()
	keys := make([]uint64, 256)
	for i := range keys {
		keys[i] = ibltXprocProbeKey(i)
	}
	var scratch [ibltMaxK]int
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ib.getHashesInto(&scratch, keys[i&255])
	}
}
