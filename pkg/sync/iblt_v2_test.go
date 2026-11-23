// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestIBLT_V2DecorrelatedFloor measures v1 pair collisions and the v2 2-core
// transition with 12 deterministic seeds (ADR-0064). Arithmetic-progression
// indices have approximately B²/4 possible k-cell sets, giving a pair-collision
// probability near 4/B² independent of k. Decorrelated indices move that floor
// toward B^-k; at B=1024, k=4 the remaining model is the c4=1.295 threshold,
// approximately 790 differences.
//
// The pinned results distinguish placement from table size: v1 prunes 11/12
// seeds at D=400 and 8/12 at D=700, while v2 prunes all 12 at both points.
// At D=780, immediately below the asymptotic threshold, v2 prunes 11/12; the
// single failure is expected finite-size behavior, not a clean guarantee. At
// D=900, c4*D=1166 exceeds 1024 and every v2 seed falls back. Doubling to 2048
// buckets restores 12/12 pruning. Replacing decorrelated placement with the
// arithmetic progression reduces the D=700 arm to 8/12, providing a negative
// control for the placement mechanism.
func TestIBLT_V2DecorrelatedFloor(t *testing.T) {
	// Restore the default v1 scheme for the rest of the package on every exit.
	t.Cleanup(func() { SetIBLTSchemeV2(false) })

	nodeID := [16]byte{0xF0, 0x20}
	const total = 1200
	const seeds = 12

	// buildEngines constructs A (total keys) vs B (total−diff keys) — same
	// insert order means same dots, so the common keys cancel in the subtract.
	buildEngines := func(diff int) (*DeltaCRDTEngine, *DeltaCRDTEngine) {
		engineA := newTestEngine(t, nodeID, 0)
		engineB := newTestEngine(t, nodeID, 0)
		common := total - diff
		for i := 0; i < total; i++ {
			entry := CRDTEntry{
				SystemTime:    int64(1_700_000_000 + i),
				H3Index:       uint64(i),
				PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i))),
			}
			eid := fmt.Sprintf("k-%d", i)
			engineA.InsertLocal(eid, entry)
			if i < common {
				engineB.InsertLocal(eid, entry)
			}
		}
		return engineA, engineB
	}

	// runPeels builds B's digest at buckets and reconciles it against A. The
	// local side adopts the remote bucket count. Results are classified as an
	// exact pruned difference, a full-keyset fallback (PeelErr or DiffNil), or
	// an invalid delta.
	runPeels := func(engineA, engineB *DeltaCRDTEngine, buckets, diff int) (prune, oversend, wrong int) {
		for s := 0; s < seeds; s++ {
			seed := Uint64ToSeed(uint64(s+1) * 0x9E3779B97F4A7C15)
			digestB := engineB.GenerateDigestSizedWithSeed(seed, buckets)
			delta := engineA.GenerateDelta(digestB)
			n := 0
			delta.Entries(func(string, CRDTEntry) bool { n++; return true })
			switch {
			case delta.PeelErr() == nil && !delta.DiffNil() && n == diff:
				prune++
			case delta.PeelErr() != nil || delta.DiffNil():
				oversend++
			default:
				wrong++
			}
			delta.Release()
			digestB.Release()
		}
		return prune, oversend, wrong
	}

	// Deterministic placement makes these counts stable across processes.
	// D=400 demonstrates the v1 floor below the v2 transition; D=700 provides
	// a stronger pair-collision point near 61% under the B² model.
	SetIBLTSchemeV2(false)
	eA400, eB400 := buildEngines(400)
	prune, oversend, wrong := runPeels(eA400, eB400, 1024, 400)
	t.Logf("(i) v1  D=400 B=1024: prune=%d/%d oversend=%d wrong=%d", prune, seeds, oversend, wrong)
	if wrong != 0 || prune != 11 || oversend != 1 {
		t.Fatalf("v1 D=400/B=1024 returned prune=%d oversend=%d wrong=%d; want 11/1/0 for the 12 deterministic seeds", prune, oversend, wrong)
	}
	eA700, eB700 := buildEngines(700)
	prune7, oversend7, wrong7 := runPeels(eA700, eB700, 1024, 700)
	t.Logf("(i) v1  D=700 B=1024: prune=%d/%d oversend=%d wrong=%d", prune7, seeds, oversend7, wrong7)
	if wrong7 != 0 || prune7 != 8 || oversend7 != 4 {
		t.Fatalf("v1 D=700/B=1024 returned prune=%d oversend=%d wrong=%d; want 8/4/0 for the 12 deterministic seeds", prune7, oversend7, wrong7)
	}

	// At D=700, 700*1.295=906.5 leaves 11.5% headroom in 1024
	// buckets. Decorrelated placement must prune every seed where v1 pruned
	// only 8/12.
	SetIBLTSchemeV2(true)
	prune7v2, oversend7v2, wrong7v2 := runPeels(eA700, eB700, 1024, 700)
	t.Logf("(i-b) v2  D=700 B=1024: prune=%d/%d oversend=%d wrong=%d (v1 was 8/12 prune and 4 oversend)", prune7v2, seeds, oversend7v2, wrong7v2)
	if wrong7v2 != 0 || prune7v2 != seeds || oversend7v2 != 0 {
		t.Fatalf("v2 D=700/B=1024 returned prune=%d oversend=%d wrong=%d; want %d/0/0 because 700*1.295=906.5 is below 1024", prune7v2, oversend7v2, wrong7v2, seeds)
	}

	// D=400 has comfortable v2 headroom. D=780 is close enough to the
	// transition that one deterministic seed falls back.
	SetIBLTSchemeV2(true)
	prune, oversend, wrong = runPeels(eA400, eB400, 1024, 400)
	t.Logf("(ii) v2  D=400 B=1024: prune=%d/%d oversend=%d wrong=%d", prune, seeds, oversend, wrong)
	if wrong != 0 || prune != seeds {
		t.Fatalf("v2 D=400/B=1024 returned prune=%d/%d wrong=%d; want %d successful peels and no invalid deltas", prune, seeds, seeds, wrong)
	}
	eA780, eB780 := buildEngines(780)
	prune780, oversend780, wrong780 := runPeels(eA780, eB780, 1024, 780)
	t.Logf("(ii) v2  D=780 B=1024: prune=%d/%d oversend=%d wrong=%d (780 is below the approximate 790 transition)", prune780, seeds, oversend780, wrong780)
	if wrong780 != 0 || prune780 != 11 || oversend780 != 1 {
		t.Fatalf("v2 D=780/B=1024 returned prune=%d oversend=%d wrong=%d; want 11/1/0 for the 12 deterministic near-threshold seeds", prune780, oversend780, wrong780)
	}

	// D=900 exceeds c4*D=1166 at 1024 buckets, so every seed falls back.
	eA900, eB900 := buildEngines(900)
	prune, oversend, wrong = runPeels(eA900, eB900, 1024, 900)
	t.Logf("(iii) v2 D=900 B=1024: prune=%d/%d oversend=%d wrong=%d (c4*900=1166 > 1024)", prune, seeds, oversend, wrong)
	if prune != 0 {
		t.Fatalf("v2 D=900/B=1024 pruned %d/%d seeds; want 0 above the 2-core threshold", prune, seeds)
	}
	if wrong != 0 || oversend != seeds {
		t.Fatalf("v2 D=900/B=1024 returned oversend=%d/%d wrong=%d; want every seed to use the full-keyset fallback", oversend, seeds, wrong)
	}

	// Doubling the table puts the same difference back below the threshold.
	prune, oversend, wrong = runPeels(eA900, eB900, 2048, 900)
	t.Logf("(iv) v2 D=900 B=2048: prune=%d/%d oversend=%d wrong=%d (1166 < 2048)", prune, seeds, oversend, wrong)
	if wrong != 0 || prune != seeds {
		t.Fatalf("v2 D=900/B=2048 returned prune=%d/%d wrong=%d; want all %d seeds to peel after doubling capacity", prune, seeds, seeds, wrong)
	}
}

// TestIBLT_ArenaBucketCeiling checks the exact arena payload boundary:
// 524,288 bytes minus the 8-byte header holds 21,845 Buckets of 24 bytes.
// A larger request would make allocVar return the largest class and clearMem
// write beyond it, so NewArenaIBLT must panic before allocation.
//
// The test accepts 21,845 buckets, recovers the panic at 21,846, and checks
// ClampIBLTBuckets at its lower bound, upper bound, and representative remote
// inputs. GenerateDelta with a 699,050-bucket remote must return a DiffNil
// full-keyset fallback without allocating that table in the arena. Replacing
// the clamp with identity fails the lower-bound cases and can reach the panic,
// providing a negative control for both boundaries.
func TestIBLT_ArenaBucketCeiling(t *testing.T) {
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	nodeID := [16]byte{0xF0, 0x20}

	// (a) the exact ceiling is accepted.
	engine := newTestEngine(t, nodeID, 0)
	seed := Uint64ToSeed(0x9E3779B97F4A7C15)
	ok21945 := NewArenaIBLT(MaxArenaIBLTBuckets, 4, seed, engine.arena)
	if ok21945 == nil || ok21945.NumBuckets() != MaxArenaIBLTBuckets {
		t.Fatalf("(a) NewArenaIBLT(21845) failed or mis-sized: got %v buckets", ok21945.NumBuckets())
	}
	if MaxArenaIBLTBuckets != 21845 {
		t.Fatalf("(a) MaxArenaIBLTBuckets=%d, want 21845 (524,280/24 — the derivation drifted; check blockSizeForClass/varAllocHeaderSize)", MaxArenaIBLTBuckets)
	}
	ok21945.Release()

	// (b) one bucket past the ceiling must panic before allocation.
	did := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				did = true
				msg := fmt.Sprint(r)
				if !strings.Contains(msg, "silent-overflow boundary") {
					t.Fatalf("(b) panic does not identify the silent-overflow boundary: %q", msg)
				}
			}
		}()
		bad := NewArenaIBLT(MaxArenaIBLTBuckets+1, 4, seed, engine.arena)
		bad.Release()
	}()
	if !did {
		t.Fatalf("(b) NewArenaIBLT(21846) did not panic; the arena overflow boundary is unguarded")
	}

	// (c) the clamp maps the remote-controlled domain.
	cases := []struct{ in, want int }{
		{0, minDynamicBuckets}, {1, minDynamicBuckets}, {5000, 5000},
		{MaxArenaIBLTBuckets, MaxArenaIBLTBuckets},
		{MaxArenaIBLTBuckets + 1, MaxArenaIBLTBuckets},
		{699050, MaxArenaIBLTBuckets},
	}
	for _, tc := range cases {
		if got := ClampIBLTBuckets(tc.in); got != tc.want {
			t.Fatalf("(c) ClampIBLTBuckets(%d)=%d, want %d — the remote-input trust-domain clamp is wrong", tc.in, got, tc.want)
		}
	}

	// (d) the largest wire digest must use DiffNil and the full-keyset
	// fallback rather than panic or build a 699,050-bucket arena table.
	engine.InsertLocal("phantom", CRDTEntry{SystemTime: 1, H3Index: 1, PayloadDigest: sha256.Sum256([]byte("x"))})
	remote := NewIBLTWithSeed(699050, 4, seed)
	defer remote.Release()
	before := DigestSnapshotRestarts()
	delta := engine.GenerateDelta(remote)
	if delta == nil {
		t.Fatalf("(d) GenerateDelta returned nil for the oversized remote; want a full-keyset fallback delta")
	}
	if !delta.DiffNil() {
		t.Fatalf("(d) oversized remote produced DiffNil=false; the clamped local size must reject subtraction")
	}
	delta.Release()
	if DigestSnapshotRestarts() != before {
		t.Fatalf("(d) the stable-cut restarted on a quiescent engine — restarts must be zero without concurrent writes")
	}
}

// TestIBLT_V1LegacyCompatAndVersionLockstep checks v1 compatibility and both
// directions of scheme rejection. With v1 selected, getHashesInto must use the
// arithmetic progression and MarshalIBLT must emit IBL1. A v2 table emits IBL2.
// Each process accepts its own frame and rejects the other scheme, preventing
// subtraction across incompatible placement. The mesh-side check is in
// pkg/mesh/iblt_mesh_test.go.
//
// GenerateDigestWithSeed must marshal identically to
// GenerateDigestSizedWithSeed with IBLTDigestDefaultBuckets. A one-bucket
// remote is clamped to 128 buckets locally, so their size mismatch produces
// DiffNil and the full-keyset fallback.
func TestIBLT_V1LegacyCompatAndVersionLockstep(t *testing.T) {
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	if IBLTSchemeV2() {
		t.Fatalf("default scheme is v2; an earlier test did not restore v1")
	}
	seed := Uint64ToSeed(0x9E3779B97F4A7C15)

	// (a) Recompute the expected arithmetic progression for v1.
	ib := NewIBLTWithSeed(64, 4, seed)
	defer ib.Release()
	for _, key := range []uint64{1, 42, 0xdeadbeef, 1 << 40} {
		_, h1, h2, n := ib.hashKeyWithSeed(key)
		var got [ibltMaxK]int
		ib.getHashesInto(&got, key)
		for i := 0; i < ib.k; i++ {
			want := int((h1 + uint64(i)*h2) % n)
			if got[i] != want {
				t.Fatalf("(a) v1 placement at key=%d i=%d = %d; want %d from (h1+i*h2)%%n", key, i, got[i], want)
			}
		}
	}

	// (b)+(c) Check the default wire tag and decoder.
	offTable := NewIBLTWithSeed(16, 4, seed)
	defer offTable.Release()
	wire, err := MarshalIBLT(offTable)
	if err != nil {
		t.Fatalf("(b) MarshalIBLT(v1 table): %v", err)
	}
	if binary.LittleEndian.Uint32(wire[0:4]) != 0x49424C31 {
		t.Fatalf("(b) v1 wire magic = %#x; want IBL1 (0x49424C31)", binary.LittleEndian.Uint32(wire[0:4]))
	}
	if _, err := UnmarshalIBLT(wire); err != nil {
		t.Fatalf("(c) v1 UnmarshalIBLT rejected its own frame: %v", err)
	}
	SetIBLTSchemeV2(true)
	onTable := NewIBLTWithSeed(16, 4, seed)
	wire2, err := MarshalIBLT(onTable)
	onTable.Release()
	if err != nil {
		t.Fatalf("(b) MarshalIBLT(v2 table): %v", err)
	}
	if binary.LittleEndian.Uint32(wire2[0:4]) != 0x49424C32 {
		t.Fatalf("(b) v2 wire magic = %#x, want 'IBL2' (0x49424C32)", binary.LittleEndian.Uint32(wire2[0:4]))
	}
	if _, err := UnmarshalIBLT(wire2); err != nil {
		t.Fatalf("(c) v2 UnmarshalIBLT rejected its own v2 frame: %v", err)
	}
	// Each scheme rejects the other's frames in both directions.
	SetIBLTSchemeV2(false)
	if _, err := UnmarshalIBLT(wire2); err == nil {
		t.Fatalf("(c) v1 process accepted an IBL2 frame; cross-scheme placement would not cancel common keys")
	}
	SetIBLTSchemeV2(true)
	if _, err := UnmarshalIBLT(wire); err == nil {
		t.Fatalf("(c) v2 process accepted an IBL1 frame; cross-scheme placement would not cancel common keys")
	}
	SetIBLTSchemeV2(false)

	// (d) The sized and unsized wrappers must emit identical bytes.
	nodeID := [16]byte{0xF0, 0x20}
	engine := newTestEngine(t, nodeID, 0)
	for i := 0; i < 40; i++ {
		eid := fmt.Sprintf("k-%d", i)
		engine.InsertLocal(eid, CRDTEntry{SystemTime: int64(i), H3Index: uint64(i), PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("p-%d", i)))})
	}
	d1 := engine.GenerateDigestWithSeed(seed)
	w1, _ := MarshalIBLT(d1)
	d1.Release()
	d2 := engine.GenerateDigestSizedWithSeed(seed, IBLTDigestDefaultBuckets)
	w2, _ := MarshalIBLT(d2)
	d2.Release()
	if !bytes.Equal(w1, w2) {
		t.Fatalf("(d) digest wrappers produced different byte lengths %d and %d at the default bucket count", len(w1), len(w2))
	}

	// (e) Clamping a one-bucket remote preserves the DiffNil fallback.
	fallback := NewIBLT(1, 4)
	defer fallback.Release()
	delta := engine.GenerateDelta(fallback)
	if delta == nil || !delta.DiffNil() {
		t.Fatalf("(e) one-bucket remote returned DiffNil=%v; want true after the local clamp to 128", delta != nil && delta.DiffNil())
	}
	delta.Release()
}

// TestIBLT_DigestStableCutSnapshot verifies digest consistency under concurrent
// writes. The builder captures all shard roots, walks that snapshot, and
// compares a second capture. A changed root restarts the whole build, up to
// three attempts; retrying individual shards would reapply XOR entries and
// could clear digest cells. digestSnapshotRestarts records each restart.
//
// Two quiescent same-seed builds must have identical wire bytes and no
// restarts. A concurrent writer must trigger at least one restart within 600
// builds while every returned digest retains exactly 1024 buckets. The
// quiescent build also has an allocation check. Removing the root comparison
// leaves the restart counter at zero under the writer, providing the negative
// control.
func TestIBLT_DigestStableCutSnapshot(t *testing.T) {
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	SetIBLTSchemeV2(true)
	nodeID := [16]byte{0xF0, 0x20}
	seed := Uint64ToSeed(0x9E3779B97F4A7C15)
	base := DigestSnapshotRestarts()

	engine := newTestEngine(t, nodeID, 0)
	for i := 0; i < 300; i++ {
		engine.InsertLocal(fmt.Sprintf("sk-%d", i), CRDTEntry{
			SystemTime:    int64(1_700_000_000 + i),
			H3Index:       uint64(i),
			PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("skp-%d", i))),
		})
	}

	// (1) quiescent determinism.
	d1 := engine.GenerateDigestSizedWithSeed(seed, 1024)
	w1, err := MarshalIBLT(d1)
	d1.Release()
	if err != nil {
		t.Fatalf("(1) MarshalIBLT(d1): %v", err)
	}
	d2 := engine.GenerateDigestSizedWithSeed(seed, 1024)
	w2, err := MarshalIBLT(d2)
	d2.Release()
	if err != nil {
		t.Fatalf("(1) MarshalIBLT(d2): %v", err)
	}
	if !bytes.Equal(w1, w2) {
		t.Fatalf("(1) two consecutive quiescent same-seed builds differ (%d vs %d bytes) — the snapshot is non-deterministic even without a writer", len(w1), len(w2))
	}
	if got := DigestSnapshotRestarts() - base; got != 0 {
		t.Fatalf("(1) a quiescent engine restarted the stable cut %d times — skew without a writer means the capture/compare itself is racing something", got)
	}

	// The allocation check excludes MarshalIBLT, which allocates its result.
	// AllocsPerRun supplies 20 warmups. Race instrumentation perturbs allocation
	// counters, so that configuration logs the value; the ordinary test run
	// requires zero allocations for the digest build and stable cut.
	allocs := testing.AllocsPerRun(20, func() {
		d := engine.GenerateDigestSizedWithSeed(seed, 1024)
		d.Release()
	})
	if raceEnabled {
		t.Logf("(3) digest build under -race: %.0f B/op; allocation counters include race instrumentation", allocs)
	} else if allocs != 0 {
		t.Fatalf("(3) digest build allocated %.0f B/op; want 0 from arena-backed roots and table storage", allocs)
	}

	// (2) concurrent writer: hot inserts across shards while building.
	const hotKeys = 20000
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for i := 0; i < hotKeys; i++ {
			select {
			case <-stop:
				return
			default:
			}
			engine.InsertLocal(fmt.Sprintf("hot-%d", i), CRDTEntry{
				SystemTime:    int64(1_800_000_000 + i),
				H3Index:       uint64(i),
				PayloadDigest: sha256.Sum256([]byte(fmt.Sprintf("hp-%d", i))),
			})
		}
	}()
	const maxBuilds = 600
	builds := 0
	for DigestSnapshotRestarts()-base == 0 && builds < maxBuilds {
		d := engine.GenerateDigestSizedWithSeed(seed, 1024)
		if d == nil || d.NumBuckets() != 1024 {
			nb := -1
			if d != nil {
				nb = d.NumBuckets()
			}
			close(stop)
			<-writerDone
			t.Fatalf("(2) build %d tore: nil=%v buckets=%d (want 1024) — a torn snapshot escaped the stable cut", builds, d == nil, nb)
		}
		w, err := MarshalIBLT(d)
		d.Release()
		if err != nil {
			close(stop)
			<-writerDone
			t.Fatalf("(2) build %d marshal: %v — a torn snapshot escaped the stable cut", builds, err)
		}
		_ = w
		builds++
	}
	close(stop)
	<-writerDone
	if got := DigestSnapshotRestarts() - base; got == 0 {
		t.Fatalf("(2) stable cut did not restart in %d builds with %d concurrent inserts; root-change detection did not fire", builds, hotKeys)
	}
	t.Logf("(2) stable cut restarted %d times across %d builds with %d concurrent inserts", DigestSnapshotRestarts()-base, builds, hotKeys)
}

// ibltV2XprocHelperEnv selects the v2 probe mode in a re-executed test binary.
// An ordinary go test run leaves it unset and skips the helper.
const ibltV2XprocHelperEnv = "SOVEREIGN_TEST_IBLT_V2_HELPER"

// TestIBLT_V2XprocHelper selects decorrelated placement before constructing
// its probe table, then prints ibltProbeLines. Parent and children therefore
// use the same hashKeyWithSeed, getHashesInto, and wire-marshal path.
func TestIBLT_V2XprocHelper(t *testing.T) {
	mode := os.Getenv(ibltV2XprocHelperEnv)
	if mode == "" {
		t.Skip("v2 helper mode only: spawned by the v2 cross-process test, or run manually with " +
			ibltV2XprocHelperEnv + "=probe")
	}
	switch mode {
	case "probe", "1":
		SetIBLTSchemeV2(true)
		for _, ln := range ibltProbeLines() {
			fmt.Println(ln)
		}
	default:
		t.Fatalf("v2 helper: unknown mode %q (want probe)", mode)
	}
}

// spawnIBLTV2XprocHelper re-executes this test binary in v2 probe mode and
// returns the child's stdout and process ID.
func spawnIBLTV2XprocHelper(t *testing.T, mode string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestIBLT_V2XprocHelper$", "-test.timeout=120s")
	env := append([]string{}, os.Environ()...)
	env = append(env, ibltV2XprocHelperEnv+"="+mode)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("v2 spawn mode=%s: %v\n--- child stdout ---\n%s", mode, err, out)
	}
	if cmd.Process == nil {
		t.Fatalf("v2 spawn mode=%s: no process handle (impossible)", mode)
	}
	return string(out), cmd.Process.Pid
}

// TestIBLT_V2XprocDeterminism compares v2 hashes, bucket indices, and IBL2 wire
// bytes from a parent and two distinct children. Splitmix64 placement depends
// only on key and seed word, with no maphash or per-process key schedule.
// Adding process-local state to the index stream makes the outputs differ and
// supplies a negative control.
func TestIBLT_V2XprocDeterminism(t *testing.T) {
	t.Cleanup(func() { SetIBLTSchemeV2(false) })
	SetIBLTSchemeV2(true)
	parent := ibltProbeLines()
	out1, pid1 := spawnIBLTV2XprocHelper(t, "probe")
	out2, pid2 := spawnIBLTV2XprocHelper(t, "probe")
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
			t.Fatalf("v2 cross-process mismatch at line %d:\n parent: %s\n child1: %s\n child2: %s", i, parent[i], child1[i], child2[i])
		}
	}
	t.Logf("v2 cross-process determinism: parent and two children agree on all %d probe lines, including IBL2 wire bytes", len(parent))
}

// BenchmarkIBLT_DigestBuildCost compares 10,000-key digest construction under
// v1 and v2 with the arithmetic cost of disjoint 16-bit bucket indices. The
// bit-field alternative is measured for comparison but is not used by tables:
// it requires power-of-two sizes and shifts beyond 64 bits collapse indices
// above k=4 to bucket zero, while wire decoding accepts k in [1,8].
//
//	go test -bench=IBLT_DigestBuildCost -benchmem ./pkg/sync/
func BenchmarkIBLT_DigestBuildCost(b *testing.B) {
	nodeID := [16]byte{0xF0, 0x20}
	for _, arm := range []struct {
		name string
		v2   bool
	}{
		{"v1", false},
		{"v2", true},
	} {
		b.Run(arm.name, func(b *testing.B) {
			SetIBLTSchemeV2(arm.v2)
			b.Cleanup(func() { SetIBLTSchemeV2(false) })
			e, err := NewDeltaCRDTEngine(nodeID, 0, 64*1024*1024)
			if err != nil {
				b.Fatalf("NewDeltaCRDTEngine: %v", err)
			}
			b.Cleanup(func() { e.Close() })
			for i := 0; i < 10000; i++ {
				e.InsertLocal(fmt.Sprintf("bc-%d", i), CRDTEntry{SystemTime: int64(i), H3Index: uint64(i)})
			}
			seed := Uint64ToSeed(0x9E3779B97F4A7C15)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d := e.GenerateDigestSizedWithSeed(seed, 1024)
				d.Release()
			}
		})
	}
	// Measure the alternative index calculation without wiring it into a table.
	b.Run("bitfield-rejected", func(b *testing.B) {
		seed := Uint64ToSeed(0x9E3779B97F4A7C15)
		ib := NewIBLTWithSeed(1024, 4, seed)
		b.Cleanup(func() { ib.Release() })
		keys := make([]uint64, 1024)
		for i := range keys {
			keys[i] = uint64(i)*0x9E3779B97F4A7C15 + 1
		}
		var sink uint64
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, key := range keys {
				ph, _, _, n := ib.hashKeyWithSeed(key)
				for j := 0; j < 4; j++ {
					sink += (ph >> (16 * j)) & (n - 1)
				}
			}
		}
		b.StopTimer()
		if sink == 0 {
			b.Fatalf("bitfield bench sunk nothing — the compiler folded the work away")
		}
	})
}
