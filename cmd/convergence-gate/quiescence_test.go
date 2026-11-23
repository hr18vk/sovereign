// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package main

// These tests cover the probe that starts the convergence SLO clock. A faulty
// probe can start the clock while the origin is still committing or stall the
// gate indefinitely. With a write-behind WAL, a stable Merkle root does not
// prove quiescence while a commit remains outstanding (ADR-0045), so only polls
// with commitInFlight == 0 advance the stability streak. Millisecond intervals
// keep the cases short and deterministic.

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestProbeQuiescence_StabilizesAfterChurn checks the exact poll count after a
// changing root settles: K changes, one fetch that establishes the final root,
// then need equal polls. Starting earlier could overlap a commit; polling longer
// would delay convStart.
func TestProbeQuiescence_StabilizesAfterChurn(t *testing.T) {
	const K, need = 7, 4
	calls := 0
	fetch := func() (string, int64, error) {
		calls++
		if calls <= K {
			return fmt.Sprintf("root-%d", calls), 0, nil
		}
		return "final-root", 0, nil
	}
	root, ok, _, _ := probeQuiescence(fetch, time.Millisecond, need, 10*time.Second)
	if !ok || root != "final-root" {
		t.Fatalf("probe failed to detect stabilization: root=%q ok=%v", root, ok)
	}
	if calls != K+1+need {
		t.Fatalf("probe polled %d times, want %d (K changes + 1 landing + need stable)", calls, K+1+need)
	}
}

// TestProbeQuiescence_ErrorResetsStreak verifies that a failed fetch clears both
// the streak and the remembered root; a successful read after the error must
// establish a new baseline.
func TestProbeQuiescence_ErrorResetsStreak(t *testing.T) {
	const need = 3
	calls := 0
	fetch := func() (string, int64, error) {
		calls++
		switch {
		case calls <= 2:
			return "same-root", 0, nil // streak building (1, then 2)
		case calls == 3:
			return "", 0, errors.New("transient read failure") // must reset the streak
		default:
			return "same-root", 0, nil
		}
	}
	root, ok, _, _ := probeQuiescence(fetch, time.Millisecond, need, 10*time.Second)
	if !ok || root != "same-root" {
		t.Fatalf("probe failed after a transient error: root=%q ok=%v", root, ok)
	}
	// Calls 1-2 build the streak. Call 3 clears it and the remembered root;
	// call 4 establishes a new baseline, and calls 5-7 reach the required streak.
	if calls != 7 {
		t.Fatalf("quiesced at call %d, want 7 after the error resets the streak and remembered root", calls)
	}
}

// TestProbeQuiescence_NeverStableFailsLoudly verifies that a changing root keeps
// polling until the cap and returns quiesced=false rather than starting the SLO
// clock.
func TestProbeQuiescence_NeverStableFailsLoudly(t *testing.T) {
	calls := 0
	fetch := func() (string, int64, error) {
		calls++
		return fmt.Sprintf("root-%d", calls), 0, nil
	}
	_, ok, _, _ := probeQuiescence(fetch, time.Millisecond, 100, 25*time.Millisecond)
	if ok {
		t.Fatalf("changing root reported quiesced; the SLO clock could start before the root settles")
	}
	if calls < 10 {
		t.Fatalf("probe stopped after %d polls, want it to continue until the cap", calls)
	}
}

// TestProbeQuiescence_StableRootWithCommitInFlightIsNotQuiescence covers the
// write-behind case: the root can stop changing before the WAL fsync completes
// (ADR-0045). Polls with an outstanding commit must not advance the streak.
func TestProbeQuiescence_StableRootWithCommitInFlightIsNotQuiescence(t *testing.T) {
	const need = 4
	const inFlightPolls = 6
	calls := 0
	fetch := func() (string, int64, error) {
		calls++
		if calls <= inFlightPolls {
			return "stable-root", 1, nil // root stable while a commit remains outstanding
		}
		return "stable-root", 0, nil
	}
	root, ok, _, _ := probeQuiescence(fetch, time.Millisecond, need, 10*time.Second)
	if !ok || root != "stable-root" {
		t.Fatalf("probe did not quiesce after the commit drained: root=%q ok=%v", root, ok)
	}
	// In-flight polls retain the last root but keep the streak at zero. The first
	// commit-free poll therefore matches immediately, and need clean polls finish.
	if calls != inFlightPolls+need {
		t.Fatalf("quiesced at call %d, want %d (%d in-flight polls + %d commit-free)", calls, inFlightPolls+need, inFlightPolls, need)
	}
}

// TestProbeQuiescence_CommitNeverDrainsFailsLoudly checks the cap and the final
// in-flight count when the root stays stable but a commit never completes.
// ADR-0045 records one such run that looked quiescent after 3.12 s while a
// commit remained outstanding for about 213 s; root stability alone made the
// subsequent convergence measurement include the WAL commit tail.
func TestProbeQuiescence_CommitNeverDrainsFailsLoudly(t *testing.T) {
	fetch := func() (string, int64, error) {
		return "stable-root", 1, nil
	}
	root, ok, _, lastInFlight := probeQuiescence(fetch, time.Millisecond, 4, 25*time.Millisecond)
	if ok {
		t.Fatalf("stable root with a permanent commit reported quiesced (root=%q)", root)
	}
	if lastInFlight != 1 {
		t.Fatalf("last in-flight count = %d, want 1 for the failure report", lastInFlight)
	}
}

// TestR1PollVerdict_FalsePassGuard requires the extended poll to apply the same
// empty-mesh guard as the main convergence loop. Without it, an injection whose
// batches all return 503 could make every node report the empty root, produce a
// passing verdict, and trigger the external crash-recovery harness even though
// no keys were inserted.
func TestR1PollVerdict_FalsePassGuard(t *testing.T) {
	emptyRoot := strings.Repeat("0", 64)

	// All batches fail and every node serves the empty HAMT root.
	if conv, reason := r1PollVerdict(10000, 10000, emptyRoot, 0); conv || reason == "" {
		t.Fatalf("all-failed injection with empty roots returned converged=%v reason=%q; want a guard reason", conv, reason)
	}
	// An empty seed root also blocks convergence after a partial injection.
	if conv, _ := r1PollVerdict(10000, 500, emptyRoot, 0); conv {
		t.Fatalf("empty seed root with %d failed inserts reported convergence", 500)
	}
	if conv, reason := r1PollVerdict(10000, 0, "9f3c", 0); !conv {
		t.Fatalf("non-empty matching roots with a clean injection did not converge: %q", reason)
	}
	if conv, _ := r1PollVerdict(10000, 0, "9f3c", 7); conv {
		t.Fatal("poll with 7 mismatches reported convergence")
	}
}
