// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package admission

// These tests exercise PeerBucket with the non-monotonic arrival order produced
// by independent relayers sharing one origin. They assert admission behavior
// directly against the real implementation.
//
// A relay run with 34 relayers exhausted the 1<<20 budget in about 10 seconds:
//
//	node-0 (seed)  77,838 drops / 5,945 accepts  (7.1% admitted)
//	node-34 (eu)   72,831 drops / 4,442 accepts  (5.75% admitted)
//
// All 4,442 accepts on node-34 fell in one 10-second window, followed by 72
// seconds with no accepts. At 100 deltas per batch, those accepts represented
// about 44 times the 10,000-key universe, so at least 97.7% were duplicates.
// Independent relay sweeps had interleaved old and new OriginSeq values in one
// origin-keyed bucket. Rewinding lastCounter on each replay charged the same
// advancement repeatedly; a zero budget also rejected delta-0 frames because
// the duplicate case came after the delta >= budget comparison.
//
// Run: go test -run 'TestSawtooth|TestNoPermanent|TestReplay|TestRatchet' -race -count=1 ./pkg/admission/

import (
	"math"
	"testing"
)

// relayInterleave models independent relayers re-sending retained batches
// from one origin. For each new sequence S, one relayer delivers S and the
// others deliver older values S-1, S-2, and so on when those values exceed the
// origin's starting sequence. The returned high-water mark is the newest value
// in the stream; every older value after it tests non-monotonic arrival.
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

// TestSawtoothAmplificationBounded checks that replayed sequences cannot
// increase the budget drain beyond the origin's actual advancement. If an old
// sequence rewound lastCounter, each later fresh sequence would charge the same
// gap again, multiplying the drain by the number of relayers.
func TestSawtoothAmplificationBounded(t *testing.T) {
	b := NewPeerBucket()
	origin := makePub(41)
	stream, hwm := relayInterleave(34, 200)

	// Create the bucket before reading its baseline budget. A fresh peer's
	// lastCounter is zero, so counter 101 charges 101 tokens; the remaining
	// sequence 102..300 supplies 199 tokens of actual advancement. Commit each
	// charge to model the receiver's post-authentication call. Without those
	// commits, the pending watermark would repeatedly charge absolute counters
	// instead of testing replay handling.
	if _, ch := b.Accept(pubBytes(origin), stream[0]); ch > 0 {
		b.CommitHWM(pubBytes(origin), stream[0])
	}
	before := b.Budget(pubBytes(origin))
	if before == 0 {
		t.Fatalf("premise: the origin's bucket must exist after its first frame, got budget 0")
	}
	for _, seq := range stream[1:] {
		if _, ch := b.Accept(pubBytes(origin), seq); ch > 0 {
			b.CommitHWM(pubBytes(origin), seq)
		}
	}
	after := b.Budget(pubBytes(origin))
	drained := before - after

	// Measure only advancement after the baseline established above.
	trueAdvance := hwm - stream[0]
	if drained > trueAdvance {
		t.Fatalf("sawtooth amplification: budget drained %d tokens for %d tokens of high-water-mark advancement (%.1fx over-charge) across %d arrivals from %d relayers; replays must not re-charge accepted advancement",
			drained, trueAdvance, float64(drained)/float64(max64(trueAdvance, 1)), len(stream), 34)
	}
	t.Logf("sawtooth bound: %d arrivals from 34 relayers drained %d tokens for %d tokens of actual advancement", len(stream), drained, trueAdvance)
}

// TestNoPermanentDropAtZero checks that an already-committed sequence remains
// admissible after an over-budget gap. The rejected gap is uncharged and does
// not change the watermark; the later duplicate therefore has delta zero.
//
// Duplicates do not advance the sequence, so they bypass this budget. Join is
// idempotent, while signature verification and transport backpressure remain
// separate costs and responsibilities (ADR-0002).
func TestNoPermanentDropAtZero(t *testing.T) {
	b := NewPeerBucket()
	origin := makePub(42)

	// Commit a small first counter, then reject an over-budget gap. The gap
	// must leave both the budget and the committed watermark unchanged.
	got, ch := b.Accept(pubBytes(origin), 1)
	if got != Keep {
		t.Fatalf("premise: first sight must Keep, got %v", got)
	}
	if ch > 0 {
		b.CommitHWM(pubBytes(origin), 1)
	}
	_, _ = b.Accept(pubBytes(origin), initialBudget+10)
	// Replay the committed counter after the rejected gap.
	got, _ = b.Accept(pubBytes(origin), 1)
	if got != Keep {
		t.Fatalf("duplicate after an uncharged over-budget gap returned %v, want Keep; delta-zero frames must bypass the budget without changing the watermark", got)
	}
	t.Logf("duplicate remained admissible after an uncharged over-budget gap")
}

// TestReplayRewindPoisoning checks that replaying an old sequence cannot make
// the receiver charge again for advancement it already accepted. If replaying
// sequence 1 after sequence 10,000 rewound the watermark, the following 10,001
// would charge roughly 10,000 tokens a second time.
func TestReplayRewindPoisoning(t *testing.T) {
	b := NewPeerBucket()
	origin := makePub(43)

	// Create the bucket before reading its baseline. The first counter charges
	// one token, and each charged frame commits after authentication.
	if _, ch := b.Accept(pubBytes(origin), 1); ch > 0 {
		b.CommitHWM(pubBytes(origin), 1)
	}
	before := b.Budget(pubBytes(origin))
	if _, ch := b.Accept(pubBytes(origin), 10_000); ch > 0 {
		b.CommitHWM(pubBytes(origin), 10_000)
	}
	_, _ = b.Accept(pubBytes(origin), 1)
	if _, ch := b.Accept(pubBytes(origin), 10_001); ch > 0 { // charges 1, not 10,000
		b.CommitHWM(pubBytes(origin), 10_001)
	}
	after := b.Budget(pubBytes(origin))
	drained := before - after

	const wantCeiling = 10_001 // conservative bound including the initial token
	if drained > wantCeiling {
		t.Fatalf("replay sequence (1, 10000, 1, 10001) drained %d tokens, exceeding the %d-token advancement ceiling; replayed counters must not rewind the watermark", drained, wantCeiling)
	}
	t.Logf("replay sequence drained %d tokens against a %d-token advancement ceiling", drained, wantCeiling)
}

// TestRatchetDoesNotAdvanceHWM checks that a rejected MaxUint64 counter cannot
// become the peer's watermark. The follow-up counter 600 must still be charged;
// if the rejected counter were committed, every later frame would be a free
// duplicate and the rate limit would be bypassed.
func TestRatchetDoesNotAdvanceHWM(t *testing.T) {
	b := NewPeerBucket()
	attacker := makePub(44)

	// Charge two small advances without committing their watermarks. A write
	// on the drop path would therefore be visible in the probe below.
	if got, _ := b.Accept(pubBytes(attacker), 1); got != Keep {
		t.Fatalf("first small advance returned %v, want Keep", got)
	}
	if got, _ := b.Accept(pubBytes(attacker), 500); got != Keep {
		t.Fatalf("second small advance returned %v, want Keep", got)
	}
	// The MaxUint64 gap exceeds the initial budget and must be rejected.
	if got, _ := b.Accept(pubBytes(attacker), math.MaxUint64); got != Drop {
		t.Fatalf("MaxUint64 ratchet must Drop because its delta exceeds initialBudget=%d; got %v", uint64(initialBudget), got)
	}
	// Probe the watermark through the public behavior: counter 600 must still
	// be charged as new advancement rather than accepted as a free duplicate.
	budgetBeforeProbe := b.Budget(pubBytes(attacker))
	if got, _ := b.Accept(pubBytes(attacker), 600); got != Keep {
		t.Fatalf("counter 600 after a rejected ratchet returned %v, want Keep", got)
	}
	budgetAfterProbe := b.Budget(pubBytes(attacker))
	if budgetBeforeProbe == budgetAfterProbe {
		t.Fatalf("rejected MaxUint64 counter became the watermark: counter 600 left the budget unchanged (%d before, %d after), want a positive charge; rejected counters must not make later frames free", budgetBeforeProbe, budgetAfterProbe)
	}
	t.Logf("rejected MaxUint64 counter did not commit: counter 600 was charged %d tokens", budgetBeforeProbe-budgetAfterProbe)
}

// max64 guards the over-charge ratio against division by zero.
func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
