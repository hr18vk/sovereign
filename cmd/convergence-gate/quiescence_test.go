// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package main

// quiescence_test.go — the guard for the gate's
// starting-line clock. The probe decides WHEN the 10s SLO stopwatch starts; a
// wrong probe re-opens the starting-line defect (ADR-0045) or
// stalls the gate forever. The commit-in-flight
// premise: root stability under a write-behind WAL is NOT
// quiescence (a run declared quiesced at 3.12 s with a ~213 s commit
// outstanding), so the streak counts only polls with commitInFlight == 0.
// All cases are deterministic (millisecond-scale poll intervals only).
//
//	go test -run TestProbeQuiescence -count=1 -v./cmd/convergence-gate/

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// a root that changes K times then stabilizes must be detected after
// exactly (K+1)+need fetches: K changing fetches, one fetch that lands the
// stable value (resetting the streak), then `need` consecutive equal polls.
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
		t.Fatalf("probe polled %d times, want exactly %d (K changes + 1 landing + need stable) — a longer probe delays convStart (the SLO starts late); a shorter one starts it mid-commit", calls, K+1+need)
	}
}

// a fetch ERROR must reset the stability streak — a transient read
// failure is not quiescence (the root could have changed behind it).
func TestProbeQuiescence_ErrorResetsStreak(t *testing.T) {
	const need = 3
	calls := 0
	fetch := func() (string, int64, error) {
		calls++
		switch {
		case calls <= 2:
			return "same-root", 0, nil // streak building (1, then 2)
		case calls == 3:
			return "", 0, errors.New("transient read failure") // must RESET the streak
		default:
			return "same-root", 0, nil
		}
	}
	root, ok, _, _ := probeQuiescence(fetch, time.Millisecond, need, 10*time.Second)
	if !ok || root != "same-root" {
		t.Fatalf("probe failed after a transient error: root=%q ok=%v", root, ok)
	}
	// calls 1-2 build streak {0,1} (call 1 establishes `last`); call 3 errors
	// (streak → 0 AND last → ""); call 4 re-establishes `last` (streak stays 0);
	// calls 5,6,7 build {1,2,3} → quiesced at call 7.
	if calls != 7 {
		t.Fatalf("streak did not reset on error: quiesced at call %d, want 7 (the error at call 3 must zero the streak AND the remembered root)", calls)
	}
}

// a root that NEVER stabilizes must exhaust the cap and report
// NOT quiesced — never silently start the clock.
func TestProbeQuiescence_NeverStableFailsLoudly(t *testing.T) {
	calls := 0
	fetch := func() (string, int64, error) {
		calls++
		return fmt.Sprintf("root-%d", calls), 0, nil
	}
	_, ok, _, _ := probeQuiescence(fetch, time.Millisecond, 100, 25*time.Millisecond)
	if ok {
		t.Fatalf("a never-stable root reported quiesced — the clock would start mid-commit (the starting-line defect, reintroduced)")
	}
	if calls < 10 {
		t.Fatalf("probe gave up after %d polls (< cap) — a never-stable root must poll until the cap", calls)
	}
}

// A root that is STABLE while a commit is
// in flight is NOT quiescence — the write-behind WAL put the batch in the root
// before the fsync, so the root had nothing left to change (ADR-0045).
// The streak must not advance on any in-flight poll.
func TestProbeQuiescence_StableRootWithCommitInFlightIsNotQuiescence(t *testing.T) {
	const need = 4
	const inFlightPolls = 6
	calls := 0
	fetch := func() (string, int64, error) {
		calls++
		if calls <= inFlightPolls {
			return "stable-root", 1, nil // the failing shape: root frozen, commit outstanding
		}
		return "stable-root", 0, nil
	}
	root, ok, _, _ := probeQuiescence(fetch, time.Millisecond, need, 10*time.Second)
	if !ok || root != "stable-root" {
		t.Fatalf("probe must quiesce once the commit drains: root=%q ok=%v", root, ok)
	}
	// The 6 in-flight polls keep the streak at 0 (the root tracker stays warm,
	// so the first clean poll already matches); quiescence lands after exactly
	// `need` commit-free polls.
	if calls != inFlightPolls+need {
		t.Fatalf("quiesced at call %d, want %d (%d in-flight polls + %d commit-free) — if fewer, in-flight polls counted toward the streak (the defect: the clock starts behind an outstanding commit)", calls, inFlightPolls+need, inFlightPolls, need)
	}
}

// a commit that NEVER drains must exhaust the cap and report NOT
// quiesced, with the in-flight count surfaced for the failure line. Before the
// fix, this shape reported quiesced at 3.12 s — the gate then
// "measured convergence" against a commit that was still on the disk.
func TestProbeQuiescence_CommitNeverDrainsFailsLoudly(t *testing.T) {
	fetch := func() (string, int64, error) {
		return "stable-root", 1, nil // stable root, commit forever in flight
	}
	root, ok, _, lastInFlight := probeQuiescence(fetch, time.Millisecond, 4, 25*time.Millisecond)
	if ok {
		t.Fatalf("a permanently in-flight commit reported quiesced (root=%q) — the falsified premise reintroduced", root)
	}
	if lastInFlight != 1 {
		t.Fatalf("the failure line needs the last in-flight count (got %d) — 'never quiescent' must say WHY", lastInFlight)
	}
}

// TestR1PollVerdict_FalsePassGuard — a regression guard for a review finding.
// The extended poll re-detected convergence on
// len(mismatch)==0 WITHOUT re-applying the main loop's FALSE-PASS guard, so a
// totally-failed inject (all batches 503: injectFail==numKeys, zero timeouts)
// converged ~5s in on the all-empty roots: gatePass=true, "GATE 1 VERDICT:
// PASS", exit 0 — on a run that inserted NOTHING — and the orchestrator's
// converged_at_ms= grep would then launch the crash leg against an empty mesh.
// This test pins the false-pass guard inside the r1PollVerdict decision.
func TestR1PollVerdict_FalsePassGuard(t *testing.T) {
	emptyRoot := strings.Repeat("0", 64)

	// The finding's exact scenario: all-503 inject, every node serving the
	// empty HAMT root. The poll must REFUSE to call this convergence.
	if conv, reason := r1PollVerdict(10000, 10000, emptyRoot, 0); conv || reason == "" {
		t.Fatalf("false-PASS: all-failed inject + empty roots reported converged=%v reason=%q — an empty mesh must never pass the convergence gate", conv, reason)
	}
	// The empty-root leg alone must also refuse (partial failures, seed empty).
	if conv, _ := r1PollVerdict(10000, 500, emptyRoot, 0); conv {
		t.Fatalf("empty seed root with numKeys>0 must refuse convergence (injectFail=%d < numKeys)", 500)
	}
	// numKeys==0 is the degenerate no-inject invocation — not the guard's case.
	// Honest convergence still passes: non-empty root, clean inject, all equal.
	if conv, reason := r1PollVerdict(10000, 0, "9f3c", 0); !conv {
		t.Fatalf("honest all-equal poll must converge, got converged=false reason=%q", reason)
	}
	// A divergent poll never converges regardless of the guard.
	if conv, _ := r1PollVerdict(10000, 0, "9f3c", 7); conv {
		t.Fatal("mismatch>0 must never converge")
	}
}
