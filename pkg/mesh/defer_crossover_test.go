// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover the saturation crossover in ADR-0071. Each guard has a
// negative control: removing the marker, cooldown, or size bound makes the
// corresponding test fail.
//
// The selection test drives a 10,000-key divergence on a two-node mesh. The
// full keyset ships once, the pair converges in bounded rounds, and a clean
// digest clears the episode marker. Further tests cover repeated divergence
// within one episode, cooldown after a failed publish, timeout classification,
// the deferCrossoverMaxEntries bound, and disabled-crossover behavior.
//
// All measurements here come from an in-process two-node loopback mesh or
// direct state inspection; they make no larger-fleet timing claim.

import (
	"testing"
	"time"

	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// DeferCrossoverOpts extends the defer-handler test options with the
// crossover flag.
type DeferCrossoverOpts struct {
	DeferOpts
	crossover bool
}

// buildDeferCrossoverMesh builds a two-node loopback mesh and enables the
// crossover before any sweep runs. The tests drive sweeps manually, so no
// reader is concurrent with this setting.
func buildDeferCrossoverMesh(t *testing.T, opts DeferCrossoverOpts) *DeferMesh {
	t.Helper()
	m := buildDeferMesh(t, opts.DeferOpts)
	if opts.crossover {
		m.gA.SetDeferCrossover(true)
		m.gB.SetDeferCrossover(true)
	}
	return m
}

// TestCrossoverSelection drives a 10,000-key divergence with crossover
// enabled. The pair ships the full keyset once and converges in bounded
// rounds. Its next clean digest clears both the once-marker and cooldown
// anchor, allowing a later divergence episode to use crossover again.
func TestCrossoverSelection(t *testing.T) {
	const (
		deferBaseKeys       = 100
		deferDivergenceKeys = 10000 // S = 10,000 < the 20,000 bound
		crossoverRoundLimit = 12
	)
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, batchSize: 100, digestWait: 50 * time.Millisecond}, true})
	deferInsert(t, m.gA, "crossover-selection-%d", deferBaseKeys, deferDivergenceKeys)
	converged := false
	for r := 0; r < crossoverRoundLimit && !converged; r++ {
		deferSweepRound(t, m)
		converged = deferDrain(t, m, 2*time.Second)
	}
	if !converged {
		t.Fatalf("crossover selection: no convergence in %d rounds", crossoverRoundLimit)
	}
	if got := m.gA.digestCrossoverShips.Load(); got != 1 {
		t.Fatalf("crossover selection: digestCrossoverShips = %d, want 1 for the pair's divergence episode", got)
	}
	if n := deferCountPresent(t, m.engineB, "crossover-selection-%d", deferBaseKeys, deferDivergenceKeys); n != deferDivergenceKeys {
		t.Fatalf("crossover selection: B holds %d of %d keys after the full-keyset ship", n, deferDivergenceKeys)
	}
	// A converged pair skips digest exchange, so its marker clears only on
	// an actual clean peel. Inserting one key reopens the change gate; the
	// resulting small diff peels cleanly and resetDeferPeer clears the marker
	// and cooldown anchor.
	deferInsert(t, m.gA, "crossover-selection-clean-%d", 99000, 1)
	for r := 0; r < 3; r++ {
		deferSweepRound(t, m)
		deferDrain(t, m, 500*time.Millisecond)
	}
	if got := m.gA.digestCrossoverShips.Load(); got != 1 {
		t.Fatalf("crossover selection: digestCrossoverShips = %d after clean rounds, want 1", got)
	}
	// The clean-peel exchange ends the divergence episode and clears both
	// fields.
	ds, ok := m.gA.deferState[m.identB.NodeID]
	if !ok || ds.crossoverServed || !ds.crossoverAt.IsZero() {
		t.Fatalf("crossover selection: clean digest left episode state set (ok=%v served=%v at-zero=%v)", ok, ds.crossoverServed, ds.crossoverAt.IsZero())
	}
	// A new bulk divergence after the clean digest starts a new episode:
	// the ship counter advances to 2 and the once-marker is set again.
	deferInsert(t, m.gA, "crossover-selection-fresh-%d", 50000, 10000)
	deferSweepRound(t, m)
	if got := m.gA.digestCrossoverShips.Load(); got != 2 {
		t.Fatalf("crossover selection: digestCrossoverShips = %d for a fresh episode, want 2", got)
	}
	ds = m.gA.deferState[m.identB.NodeID]
	if !ds.crossoverServed {
		t.Fatalf("crossover selection: new episode did not set the once-marker")
	}
}

// TestCrossoverOnceMarker adds another bulk divergence before a clean peel.
// The existing episode marker must keep the ship counter at 1 while the defer
// ladder handles the new divergence. Removing the marker assignment makes the
// test fail on the second round.
func TestCrossoverOnceMarker(t *testing.T) {
	const (
		deferBaseKeys           = 100
		deferDivergenceKeys     = 10000
		crossoverPreDrainRounds = 4 // pre-drain rounds: the join backlog keeps the pair mismatched
	)
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: 50 * time.Millisecond}, true})
	deferInsert(t, m.gA, "crossover-once-%d", deferBaseKeys, deferDivergenceKeys)
	// The first capacity failure ships once; the sweep waits for that ship
	// to complete synchronously.
	deferSweepRound(t, m)
	if got := m.gA.digestCrossoverShips.Load(); got != 1 {
		t.Fatalf("crossover once-marker: first capacity failure produced %d ships, want 1", got)
	}
	// No clean peel occurs between these divergences, so the once-marker
	// refuses another crossover and the defer ladder handles the new keys.
	// Adding keys explicitly makes this independent of join-drain timing.
	deferInsert(t, m.gA, "crossover-once-fresh-%d", 5000, 10000)
	for r := 0; r < crossoverPreDrainRounds-1; r++ {
		deferSweepRound(t, m)
		if got := m.gA.digestCrossoverShips.Load(); got != 1 {
			t.Fatalf("crossover once-marker: round %d produced %d total ships, want 1 within one episode", r, got)
		}
	}
	if m.gA.digestDefers.Load() == 0 {
		t.Fatalf("crossover once-marker: fresh in-episode divergence did not use the defer ladder")
	}
}

// TestCrossoverCooldown finalizes a crossover with advance=false, as after a
// Publish failure or cancelled context. The failure clears the once-marker,
// records the cooldown anchor, refuses an immediate retry, and permits a new
// attempt after deferCrossoverCooldown.
func TestCrossoverCooldown(t *testing.T) {
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: 50 * time.Millisecond}, true})
	deferInsert(t, m.gA, "crossover-cooldown-%d", 100, 1000)
	peer := m.identB.NodeID
	delta := m.gA.engine.GenerateDelta(eng.NewIBLT(1, 4)) // the full-keyset delta (diffNil yield-everything)
	defer delta.Release()
	if _, ok := m.gA.deferCrossoverTry(peer, delta); !ok {
		t.Fatalf("crossover cooldown: first eligible attempt refused (S=1000, no marker or cooldown)")
	}
	// The finalize hook consumes the pending marker, clears the once-marker,
	// and records the failed ship's cooldown anchor.
	m.gA.finalizeDeferShip(peer, false)
	ds := m.gA.deferState[peer]
	if ds.crossoverServed {
		t.Fatalf("crossover cooldown: failed ship did not clear the once-marker")
	}
	if ds.crossoverAt.IsZero() {
		t.Fatalf("crossover cooldown: failed ship did not set crossoverAt")
	}
	// During cooldown the defer ladder owns the retry.
	if _, ok := m.gA.deferCrossoverTry(peer, delta); ok {
		t.Fatalf("crossover cooldown: retry was eligible during cooldown")
	}
	// A failed ship does not exclude the pair from crossover permanently.
	ds = m.gA.deferState[peer]
	ds.crossoverAt = time.Now().Add(-deferCrossoverCooldown - time.Second)
	m.gA.deferState[peer] = ds
	if _, ok := m.gA.deferCrossoverTry(peer, delta); !ok {
		t.Fatalf("crossover cooldown: crossover did not re-arm after cooldown")
	}
}

// TestCrossoverTimeoutDoesNotShip checks that only ErrIncompletePeel permits
// crossover. With B not responding and only A sweeping, the digest wait
// expires; that timeout must defer without a full-keyset crossover ship.
func TestCrossoverTimeoutDoesNotShip(t *testing.T) {
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: 50 * time.Millisecond}, true})
	m.gB.disableDigestRespond.Store(true)
	deferInsert(t, m.gA, "crossover-timeout-%d", 100, 1000)
	deferSweepAOnly(t, m) // no response arrives before the 50ms digest wait expires
	if got := m.gA.digestCrossoverShips.Load(); got != 0 {
		t.Fatalf("crossover timeout: digestCrossoverShips = %d, want 0 for a timeout", got)
	}
	if m.gA.digestDefers.Load() == 0 {
		t.Fatalf("crossover timeout: timeout did not trigger the defer ladder")
	}
}

// TestCrossoverKeysetBound refuses crossover above
// deferCrossoverMaxEntries even for a capacity failure. The eligibility walk
// still records sEst, so the defer ladder can hash-anchor its first slice
// without a separate count round.
func TestCrossoverKeysetBound(t *testing.T) {
	const sBeyond = deferCrossoverMaxEntries + 1000
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, digestWait: 50 * time.Millisecond}, true})
	deferInsert(t, m.gA, "crossover-bound-%d", 100, sBeyond)
	peer := m.identB.NodeID
	delta := m.gA.engine.GenerateDelta(eng.NewIBLT(1, 4))
	defer delta.Release()
	if _, ok := m.gA.deferCrossoverTry(peer, delta); ok {
		t.Fatalf("crossover keyset bound: oversized keyset was eligible (S=%d, bound=%d)", sBeyond, deferCrossoverMaxEntries)
	}
	ds, ok := m.gA.deferState[peer]
	if !ok || ds.sEst != sBeyond {
		t.Fatalf("crossover keyset bound: seed walk got size=%d (ok=%v sEst=%d), want a matching estimate", sBeyond, ok, ds.sEst)
	}
}

// TestCrossoverDisabledUsesDeferLadder repeats the 10,000-key divergence with
// the defer handler enabled and crossover disabled. The pair must converge
// through bounded slices without any crossover ships.
func TestCrossoverDisabledUsesDeferLadder(t *testing.T) {
	const (
		deferBaseKeys       = 100
		deferDivergenceKeys = 10000
		crossoverRoundLimit = 40 // the ladder's rotation budget: ~3 pre-rounds + ceil(10,100/405)=26 slices + slack
	)
	m := buildDeferCrossoverMesh(t, DeferCrossoverOpts{DeferOpts{deferHandler: true, stratified: true, batchSize: 100, digestWait: 50 * time.Millisecond}, false})
	deferInsert(t, m.gA, "crossover-disabled-%d", deferBaseKeys, deferDivergenceKeys)
	converged := false
	for r := 0; r < crossoverRoundLimit && !converged; r++ {
		deferSweepRound(t, m)
		converged = deferDrain(t, m, 2*time.Second)
	}
	if !converged {
		t.Fatalf("crossover disabled: two-node ladder did not converge with 10,000 divergent keys")
	}
	if got := m.gA.digestCrossoverShips.Load(); got != 0 {
		t.Fatalf("crossover disabled: digestCrossoverShips = %d, want 0", got)
	}
	if m.gA.digestDefers.Load() == 0 {
		t.Fatalf("crossover disabled: capacity divergence did not trigger the defer ladder")
	}
}
