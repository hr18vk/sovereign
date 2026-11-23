// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// The Tier-1 migration (ADR-0066) replaces per-iteration State() merged-view
// rebuilds with caller-owned PointGet copies. The earlier per-shard PointGet
// migration (ADR-0051) measured +34,618,200B of arena allocations from N State() calls;
// the migrated path is flat. The observable is engine.Arena().HighWater() —
// the monotone bump offset that the durability bridge also reads. The migrated
// paths never bump the arena because MerkleRootFromShards allocates only on
// the Go heap, so any high-water growth indicates a wiring error. The scope
// covers the exact-conviction direction; the negative-control direction guards
// against the never-freeing stranding class (the freelist cannot mask it).
// A hypothetical freelist-recycling leak is a different class these tests do
// not claim to catch.
//
// The converge-shape allowance: the converge-family negative control runs real
// sweeps, which legitimately bump-allocate digest IBLTs (NewArenaIBLT per
// generateSweepDelta — freed via ReleaseLocal, but HighWater is the monotone
// bump mark, so one fresh-sized digest build raises it by tens of KB: measured
// +33,024/+20,608B across the quiesced second converge on the 32-core -race
// machine). The assert therefore uses an allowance form (<=256KiB per converge
// per side: 4.9x above the measured legitimate bump, 13x below the Tier-1
// leak's per-converge signature — so even a single merged-view build at this
// mesh's 1000 entities (~1.2MB) trips it). The strict-zero form stays for the
// no-sweep shapes (the probe churn negative control, the chaos oracle negative
// control — their paths never build digests).
//
// The wiring negative control (scratch-revert mold): in a scratch copy of the
// tree with one site reverted to State().MerkleRoot(), the negative control
// that drives that site fails on growth — a clean t.Fatalf long before any
// arena exhaustion (never a panic-as-failure).

import (
	"context"
	"fmt"
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// TestTier1ProbePollerArenaFlat drives the production diagnostic poller
// (ConvergenceProbe.WaitForConvergence) on a diverged pair — the pure churn
// shape: roots never equal, the loop polls to context expiry. A minimal probe
// is constructed in-package: WaitForConvergence touches only the two engine
// fields (+ healAt for its wall clock); the gossiper/peerset fields belong to
// the partition/heal paths this negative control never enters. The negative
// control: a diverged pair must yield ErrSLONotMet — anything else means the
// drive never churned and the flat assert below would pass without exercising
// the defect.
func TestTier1ProbePollerArenaFlat(t *testing.T) {
	var idA, idB [16]byte
	idA[0], idB[0] = 0xA1, 0xB2
	eA := newTestEngine(t, idA, t.TempDir())
	defer func() { _ = eA.Close() }()
	eB := newTestEngine(t, idB, t.TempDir())
	defer func() { _ = eB.Close() }()
	// 1000 entities on A only — the divergence is permanent (B never learns
	// them; no sweep is running in this drive).
	for i := 0; i < 1000; i++ {
		eA.InsertLocal(fmt.Sprintf("f38-probe-%d", i), eng.CRDTEntry{SystemTime: int64(i), H3Index: uint64(i)})
	}
	hwA0, hwB0 := eA.Arena().HighWater(), eB.Arena().HighWater()
	p := &ConvergenceProbe{engine: eA, engineB: eB} // in-package minimal probe (documented above)
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Millisecond)
	defer cancel()
	if _, err := p.WaitForConvergence(ctx, 100*time.Millisecond, 40*time.Millisecond); err != ErrSLONotMet {
		t.Fatalf("Tier1ProbePollerArenaFlat: the diverged pair returned %v, want ErrSLONotMet — the poll loop did not run to expiry (the flat assert would pass without exercising the defect)", err)
	}
	hwA1, hwB1 := eA.Arena().HighWater(), eB.Arena().HighWater()
	t.Logf("Tier1ProbePollerArenaFlat: churn-poll flat check — A high-water %d -> %d (delta %d), B %d -> %d (delta %d)", hwA0, hwA1, hwA1-hwA0, hwB0, hwB1, hwB1-hwB0)
	if hwA1 != hwA0 || hwB1 != hwB0 {
		t.Fatalf("Tier1ProbePollerArenaFlat: the poller grew the arena high-water (A +%d B +%d bytes) — a merged-view build is still on the poll path (the Tier-1 leak): MerkleRootFromShards allocates zero arena bytes", hwA1-hwA0, hwB1-hwB0)
	}
}

// tier1QuiesceMesh drives the real sweep loops (the converge shape, 20ms
// tick) and waits until both engines' arena high-water is stable across
// four or more consecutive 100ms samples with roots equal — the mesh is
// quiet by observation: the sweeps still tick (~20 rounds across the
// stability window) yet allocate nothing. This makes the strict-zero premise
// of the second converge true by measurement, never by assumption (an
// earlier version assumed converge-return implied quiescence; the mesh
// answered with a 500-entry phantom-miss oversend round +8192B of
// legitimate in-flight join residue — the negative control was wrong, not
// the migration). A mesh that cannot quiesce within the deadline is a real
// engine finding, failed loudly.
func tier1QuiesceMesh(t *testing.T, h *PQHybridHarness) (hwA, hwB uint64) {
	t.Helper()
	loopCtx, cancel := context.WithCancel(h.ctx)
	doneA := make(chan struct{})
	doneB := make(chan struct{})
	go func() { h.gA.SweepLoop(loopCtx, 20*time.Millisecond); close(doneA) }()
	go func() { h.gB.SweepLoop(loopCtx, 20*time.Millisecond); close(doneB) }()
	defer func() { cancel(); <-doneA; <-doneB }()
	deadline := time.Now().Add(time.Duration(30*jitterRaceScale) * time.Second)
	stable := 0
	lastA, lastB := ^uint64(0), ^uint64(0)
	for time.Now().Before(deadline) {
		ra := h.engineA.MerkleRootFromShards()
		rb := h.engineB.MerkleRootFromShards()
		a, b := h.engineA.Arena().HighWater(), h.engineB.Arena().HighWater()
		if ra == rb && ra != [32]byte{} && a == lastA && b == lastB {
			stable++
			if stable >= 4 {
				return a, b
			}
		} else {
			stable = 0
		}
		lastA, lastB = a, b
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("tier1QuiesceMesh: the mesh did not quiesce within 30s*racescale — high-water still moving (A %d B %d, last-stable-run %d): a real engine finding (phantom-miss oversend that never settles?), not a negative-control defect", lastA, lastB, stable)
	return 0, 0
}

// TestTier1ConvergePollerArenaFlat drives the converged real-loop poller
// family (the real-loop convergence driver — the Tier-1 migration's
// validation site) over an already-converged, observed-quiescent mesh: the
// first converge pays the legitimate state growth (both engines learn the
// 1000 events); tier1QuiesceMesh proves the sweep pipeline has drained (no
// in-flight phantom-miss oversend can masquerade as poller growth); the
// second and third converges must then be exact-flat — and a leak repeats
// (the repetition discriminator: residue grows once, the Tier-1 stranding
// grows every poll).
func TestTier1ConvergePollerArenaFlat(t *testing.T) {
	seedA := bytesRepeat(0xA1, 32)
	seedB := bytesRepeat(0xB2, 32)
	h := newPQHybridHarnessSeeded(t, false, false, seedA, seedB)
	defer h.close()
	h.insertEvents(t, 1000)
	jitterConvergeViaRealLoop(t, h)      // pays the legitimate state growth
	hwA0, hwB0 := tier1QuiesceMesh(t, h) // quiet by observation, not assumption
	// The allowance form (see the file header): sweeps legitimately
	// bump-allocate the freed digest IBLTs (+53,632B measured combined on
	// the 32-core -race machine); the Tier-1 leak is +3.5MB/side per
	// converge. 256KiB separates them 4.9x / 13x — even a single
	// merged-view build at 1000 entities (~1.2MB) trips it.
	const tier1ConvergeDigestAllowance = 262_144
	jitterConvergeViaRealLoop(t, h) // converged + quiescent: the poller's growth must be zero — the only legitimate movement is the bounded digest bump
	hwA1, hwB1 := h.engineA.Arena().HighWater(), h.engineB.Arena().HighWater()
	t.Logf("Tier1ConvergePollerArenaFlat: second-converge allowance check — A high-water %d -> %d (delta %d), B %d -> %d (delta %d); allowance %dB", hwA0, hwA1, hwA1-hwA0, hwB0, hwB1, hwB1-hwB0, tier1ConvergeDigestAllowance)
	if hwA1-hwA0 > tier1ConvergeDigestAllowance || hwB1-hwB0 > tier1ConvergeDigestAllowance {
		t.Fatalf("Tier1ConvergePollerArenaFlat: the quiesced second converge grew the arena high-water beyond the digest-bump allowance (A +%d B +%d bytes vs %dB) — with the mesh observed-quiet, growth beyond a digest-scale bump is the poller's (the Tier-1 leak: a merged-view build on the poll path; the legitimate bump is the freed-then-rebuilt digest IBLT, disclosed in the file header)", hwA1-hwA0, hwB1-hwB0, tier1ConvergeDigestAllowance)
	}
	jitterConvergeViaRealLoop(t, h) // repetition discriminator: a leak repeats at MB scale; the digest bump is one bounded event
	hwA2, hwB2 := h.engineA.Arena().HighWater(), h.engineB.Arena().HighWater()
	if hwA2-hwA1 > tier1ConvergeDigestAllowance || hwB2-hwB1 > tier1ConvergeDigestAllowance {
		t.Fatalf("Tier1ConvergePollerArenaFlat: the repeated converged poll loop grew the high-water beyond the allowance again (A +%d B +%d bytes vs %dB) — a leak repeats at MB scale; a one-time digest bump does not (the Tier-1 stranding is per-poll)", hwA2-hwA1, hwB2-hwB1, tier1ConvergeDigestAllowance)
	}
	t.Logf("Tier1ConvergePollerArenaFlat: third-converge allowance check — A high-water %d -> %d (delta %d), B %d -> %d (delta %d)", hwA1, hwA2, hwA2-hwA1, hwB1, hwB2, hwB2-hwB1)
}
