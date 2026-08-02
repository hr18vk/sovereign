// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package admission

// admission_sawtooth_test.go — (ADR-0045): in-process falsification
// guards for the ADMISSION SAWTOOTH that collapsed silicon.
//
// These guards run against the REAL PeerBucket — no mocks, no reimplementation.
// pkg/admission is a BYZANTINE-DEFENSE seam, so every assertion below states the
// property it defends, not just the value it observes.
//
// WHAT THE SILICON RUN MEASURED (the numbers these guards reproduce in-process):
// Once the batch relay was wired, admission collapsed on EVERY node —
// including the seed's own bucket, fed by reflected relays of its own batches:
//
//	node-0 (THE SEED) 77,838 DropRate / 5,945 Accept (7.1% admitted)
//	node-34 (eu) 72,831 DropRate / 4,442 Accept (5.75%)
//	node-38 (eu) 99,334 DropRate / 4,535 Accept (4.4%)
//
// The killing signature: ALL 4,442 of node-34's accepts fall in ONE 10-second
// window (13:08:10→13:08:20); the first DropRate fires at 13:08:20 and there are
// ZERO accepts for the remaining 72 seconds. That is permanent admission DEATH,
// not throttling. And 4,442 × 100 deltas = 444,200 ≈ 44× the 10,000-key universe,
// so ≥97.7% of what got through were duplicates — the window shut before a full
// set could arrive.
//
// WHY IT ONLY APPEARED AFTER THE BATCH RELAY: converged intra-region PRECISELY BECAUSE
// the relay was dead — each node saw the origin's seqs DIRECTLY, i.e. MONOTONICALLY.
// The batch relay made 34 relayers interleave one origin's old and new seqs into ONE
// origin-keyed bucket, and Accept's core assumption (monotone arrival) died.
//
// THE TWO DEFECTS (verified on the bytes at ewma.go:187-240):
// 1. `peer.lastCounter = counter` is UNCONDITIONAL — a non-monotonic arrival
// REWINDS the high-water mark, so the same seq gap is re-drained on every
// rewind (sawtooth amplification; the 1<<20 budget dies in ~10 s).
// 2. `if delta >= peer.budget` at budget==0 drops even delta-0 (already-seen)
// frames FOREVER, because 0 >= 0.
//
// RUN: go test -race -count=1./pkg/admission/

import (
	"math"
	"testing"
)

// relayInterleave builds the arrival stream a RELAY MESH actually produces,
// derived from the measured run's shape rather than a convenient toy: `relayers` distinct
// relayers each re-ship an origin's batches, and because they sweep independently
// they interleave OLD retained seqs with NEW ones. The origin's true advancement is
// `newSeqs` batches (the high-water mark), but the receiver sees each old seq
// re-presented after a newer one — the non-monotonic pattern that rewinds the HWM.
//
// Shape: for each new seq S (1..newSeqs), one relayer delivers S, then the other
// relayers re-deliver an OLDER seq (S-1, S-2, …) they still hold in relayCache.
// This is exactly what 34 relayers × a retained batch window produce.
func relayInterleave(relayers, newSeqs int) (stream []uint64, hwm uint64) {
	base := uint64(100) // the origin's starting OriginSeq (arbitrary, non-zero)
	for i := 1; i <= newSeqs; i++ {
		fresh := base + uint64(i)
		stream = append(stream, fresh)
		if fresh > hwm {
			hwm = fresh
		}
		// The other relayers re-ship older retained seqs (the interleave).
		for r := 1; r < relayers; r++ {
			old := fresh - uint64(r)
			if old <= base {
				break
			}
			stream = append(stream, old)
		}
	}
	return stream, hwm
}

// TestSawtoothAmplificationBounded is R1: the budget drain must be bounded
// by the origin's TRUE high-water-mark advancement, not by the sum of re-opened
// gaps.
//
// RED on current bytes: every non-monotonic arrival rewinds lastCounter, so the
// next fresh seq re-drains the whole gap it already paid for. With 34 relayers the
// drain is ~O(relayers × advancement) instead of O(advancement) — the 1<<20 budget
// dies in seconds, which is what killed on every node.
func TestSawtoothAmplificationBounded(t *testing.T) {
	b := NewPeerBucket()
	origin := makePub(41)
	stream, hwm := relayInterleave(34, 200) // the relayer count

	// Buckets are created LAZILY (ewma.go:205), and Budget() returns 0 for an
	// absent peer (:258) — so the first arrival is what mints the bucket. Feed it,
	// THEN read the baseline: the first frame is a fresh-peer delta-0 and is never
	// charged, so this is the honest pre-drain reference.
	// NOTE (measured, not assumed): a fresh peer's lastCounter starts at 0, so its
	// FIRST frame is charged its full absolute seq (101 tokens here), not delta-0 —
	// the docstring at ewma.go:212 says "a fresh peer is never penalized for its
	// first frame", which is true only for seq 1. Immaterial to this guard and NOT
	// changed by the fix (a fresh origin's absolute seq is a one-time charge, bounded by
	// the seq itself); the baseline is therefore read AFTER that first frame.
	b.Accept(pubBytes(origin), stream[0])
	before := b.Budget(pubBytes(origin))
	if before == 0 {
		t.Fatalf("premise: the origin's bucket must exist after its first frame, got budget 0")
	}
	for _, seq := range stream[1:] {
		b.Accept(pubBytes(origin), seq)
	}
	after := b.Budget(pubBytes(origin))
	drained := before - after

	// The origin advanced from its first-seen seq to hwm. The FIRST frame is a
	// fresh-peer delta-0 (never charged), so the true advancement is hwm - first.
	trueAdvance := hwm - stream[0]
	if drained > trueAdvance {
		t.Fatalf("R1 SAWTOOTH AMPLIFICATION: the origin's budget drained %d tokens while its TRUE high-water-mark advancement was only %d (%.1fx over-charge) across %d relay-interleaved arrivals from %d relayers.\n\nMECHANISM (ewma.go:187-240): `peer.lastCounter = counter` is UNCONDITIONAL, so a non-monotonic arrival REWINDS the HWM and the next fresh seq re-drains a gap it already paid for. On silicon the run this drained the 1<<20 budget in ~10 seconds on EVERY node (seed 77,838 DropRate/5,945 Accept; node-34-eu 72,831/4,442), and admission NEVER recovered — 72 seconds with zero accepts.\n\nFIX (the accepted admission mechanism): compute delta from the HWM (counter > lastCounter ? counter-lastCounter: 0) and NEVER rewind; advance lastCounter ONLY on the Keep path.",
			drained, trueAdvance, float64(drained)/float64(max64(trueAdvance, 1)), len(stream), 34)
	}
	t.Logf("GREEN (R1) — %d relay-interleaved arrivals from 34 relayers drained %d tokens against a true HWM advancement of %d: the drain is bounded by real advancement, so a relay mesh can no longer sawtooth an origin's budget to death.", len(stream), drained, trueAdvance)
}

// TestNoPermanentDropAtZero is R2: once the budget is exhausted, an
// ALREADY-SEEN sequence (delta 0) must still be admitted.
//
// RED on current bytes: `if delta >= peer.budget` with budget==0 and delta==0
// satisfies 0 >= 0 → Drop. Every duplicate is dropped FOREVER, which is the
// "permanent admission death" signature (node-34: zero accepts for 72 seconds).
//
// WHY KEEP IS CORRECT: Join is idempotent, so admitting a duplicate costs a verify
// plus an idempotent apply — bounded work. Frame-rate flooding is transport
// backpressure, NOT this gate's job. Dropping delta-0 buys no Sybil
// protection (a duplicate advances nothing) and costs convergence.
func TestNoPermanentDropAtZero(t *testing.T) {
	b := NewPeerBucket()
	origin := makePub(42)

	// Establish a HWM, then drain the budget with one over-large gap.
	if got := b.Accept(pubBytes(origin), 1); got != Keep {
		t.Fatalf("premise: first sight must Keep, got %v", got)
	}
	b.Accept(pubBytes(origin), initialBudget+10) // a gap larger than the budget
	// Now present an ALREADY-SEEN seq: delta is 0 against the HWM.
	got := b.Accept(pubBytes(origin), 1)
	if got != Keep {
		t.Fatalf("R2 PERMANENT DROP AT ZERO: an already-seen sequence (delta 0 against the high-water mark) returned %v, want Keep, after the budget was exhausted.\n\nMECHANISM (ewma.go:234): `if delta >= peer.budget` is satisfied by 0 >= 0 once the budget hits 0, so EVERY duplicate drops FOREVER. On silicon the run node-34-eu admitted 4,442 batches inside ONE 10-second window and then ZERO for the next 72 seconds — permanent admission death, not throttling.\n\nWHY KEEP IS CORRECT: Join is idempotent (a duplicate is bounded work), a duplicate advances the origin's sequence by NOTHING so dropping it buys no Sybil protection, and frame-rate flooding is transport backpressure — never this gate's job.\n\nFIX (the accepted admission mechanism): delta == 0 → Keep IMMEDIATELY, no budget touch, no lastCounter write.", got)
	}
	t.Logf("GREEN (R2) — with the budget exhausted, an already-seen sequence is still admitted (delta-0 → Keep): a saturated bucket no longer means permanent admission death, and Join's idempotence bounds the duplicate work.")
}

// TestReplayRewindPoisoning is R3, the Byzantine case: an attacker
// that replays an old sequence must not be able to make the receiver re-charge the
// origin's budget for advancement it already paid for.
//
// RED on current bytes: accept up to 10,000, replay seq 1 (which REWINDS the HWM to
// 1), then send 10,001 — the receiver charges ~10,000 a SECOND time. Repeat and any
// origin's budget can be drained by an attacker that never advances anything.
func TestReplayRewindPoisoning(t *testing.T) {
	b := NewPeerBucket()
	origin := makePub(43)

	// Read the baseline AFTER the bucket exists: Budget() returns 0 for an absent
	// peer (ewma.go:258, lazy creation at:205), so reading it first and subtracting
	// would UNDERFLOW rather than measure. The first frame (seq 1) charges 1 token.
	b.Accept(pubBytes(origin), 1) // first sight
	before := b.Budget(pubBytes(origin))
	b.Accept(pubBytes(origin), 10_000) // honest advance: charges 9,999
	b.Accept(pubBytes(origin), 1)      // REPLAY (Byzantine): must NOT rewind the HWM
	b.Accept(pubBytes(origin), 10_001) // one more honest step: must charge 1, not 10,000
	after := b.Budget(pubBytes(origin))
	drained := before - after

	const wantCeiling = 10_001 // total true advancement from seq 1 to seq 10,001
	if drained > wantCeiling {
		t.Fatalf("R3 REPLAY-REWIND POISONING: the sequence (1 → 10,000 → replay 1 → 10,001) drained %d tokens, but the origin's TOTAL true advancement is at most %d.\n\nMECHANISM: the replay of seq 1 rewinds lastCounter to 1 (ewma.go's unconditional write), so the following 10,001 is charged as a ~10,000 gap the origin ALREADY paid for. An attacker who advances NOTHING can therefore drain any origin's lifetime budget by alternating replay/fresh — and with no refill anywhere in the tree (initialBudget is a LIFETIME quota) that is permanent.\n\nFIX (the accepted admission mechanism): the high-water mark NEVER rewinds; a replay is delta-0 and charges nothing.", drained, wantCeiling)
	}
	t.Logf("GREEN (R3) — an interleaved replay (1 → 10,000 → replay 1 → 10,001) drained %d tokens against a %d ceiling: a replaying attacker can no longer re-charge advancement the origin already paid for.", drained, wantCeiling)
}

// TestRatchetDoesNotAdvanceHWM is R4 — THE TRAP. It must be GREEN
// BEFORE and AFTER the fix, and it pins the hazard the fix could introduce.
//
// The hazard: if the fix advances the high-water mark on a DROPPED frame, then one
// MaxUint64 ratchet frame sets HWM = MaxUint64 and EVERY later frame becomes
// delta-0 → Keep. The attacker converts a single dropped frame into a PERMANENT
// ADMISSION BYPASS — strictly worse than the bug being fixed.
//
// Note this guard is RED-BY-CONSTRUCTION on the CURRENT bytes for the second half:
// today's Accept rewinds/advances lastCounter even on the Drop path, so the
// post-ratchet small-seq probe already sees a poisoned HWM. That is not a
// hypothetical — it is a live pre-existing hole that the fix closes.
func TestRatchetDoesNotAdvanceHWM(t *testing.T) {
	b := NewPeerBucket()
	attacker := makePub(44)

	// Establish a modest HWM.
	if got := b.Accept(pubBytes(attacker), 1); got != Keep {
		t.Fatalf("premise: first sight must Keep, got %v", got)
	}
	if got := b.Accept(pubBytes(attacker), 500); got != Keep {
		t.Fatalf("premise: a small honest advance must Keep, got %v", got)
	}
	// THE RATCHET: MaxUint64. The EXISTING acceptance semantics require Drop
	// (MaxUint64-500 >= 1<<20) — that half must never regress.
	if got := b.Accept(pubBytes(attacker), math.MaxUint64); got != Drop {
		t.Fatalf("R4 (existing semantics REGRESSED): a MaxUint64 ratchet MUST Drop — the delta exceeds initialBudget=%d. Got %v. This is the Day-Byzantine acceptance contract; the fix must not weaken it.", uint64(initialBudget), got)
	}
	// THE TRAP: the DROPPED ratchet must NOT have advanced the high-water mark.
	// Probe it behaviorally (no new exported surface): a seq just above the OLD
	// HWM must still be treated as a REAL advance (charged), not as delta-0.
	budgetBeforeProbe := b.Budget(pubBytes(attacker))
	if got := b.Accept(pubBytes(attacker), 600); got != Keep {
		t.Fatalf("R4: a legitimate small advance (600) after a DROPPED ratchet must still be admitted, got %v — the attacker must not be able to lock the bucket by getting one frame dropped", got)
	}
	budgetAfterProbe := b.Budget(pubBytes(attacker))
	if budgetBeforeProbe == budgetAfterProbe {
		t.Fatalf("R4 PERMANENT ADMISSION BYPASS: after the MaxUint64 ratchet was DROPPED, a follow-up seq 600 was admitted WITHOUT charging the budget (%d before, %d after) — proof the high-water mark ADVANCED to MaxUint64 on the DROPPED frame, so every subsequent frame is delta-0 and admits free.\n\nThe attacker converted ONE dropped frame into a permanent admission bypass. A fix that advances the HWM on a Drop is strictly WORSE than the sawtooth it replaces.\n\nFIX (the accepted admission mechanism): advance lastCounter ONLY on the Keep path — never on a Drop.", budgetBeforeProbe, budgetAfterProbe)
	}
	t.Logf("GREEN (R4 trap) — the MaxUint64 ratchet Drops (existing Byzantine contract intact) AND does not advance the high-water mark: the follow-up seq 600 was charged %d tokens as a real advance, so one dropped frame cannot become a permanent admission bypass.", budgetBeforeProbe-budgetAfterProbe)
}

// max64 is a tiny local helper (the divide-by-zero guard in R1's ratio log).
func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
