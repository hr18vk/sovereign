// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

//commit_stats_test.go — guards for the WAL
// group-commit tail instrument (ADR-0045). The ~213 s single-batch
// commit was the GATE-1 SLO mechanism, observable until now only as
// its downstream symptoms (the 30 s client timeout, the 188.885 s
// "convergence"). The instrument: every AppendMutation/AppendMutations call is
// timed (commitCount / Σ ns / max ns), a commit past slowCommitLogNs logs a
// SLOW COMMIT line, and CommitStats surfaces the counters to /v1/merkle.
//
// These guards pin: (1) BOTH commit paths advance the counters, (2) a FAILED
// commit is counted too (the failure is the SLO-killer shape — an instrument
// that skips it lies by omission), (3) the slow-log emitter actually emits.

import (
	"errors"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// logCapture redirects the `log` package's output for the duration of a test.
// log.Logger serializes its own writes; the mutex guards the test's READS.
type logCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func TestCommitStatsCountedOnSuccessAndFailure(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "cstats.wal")
	live := newLiveBridge(t, walPath, 0)

	// Two single-item commits + one 3-item batch = 3 commits, 5 entries.
	if _, err := live.PutLocal(utf8EntityID(0), stagedPayload(0), stagedEntry(0)); err != nil {
		t.Fatalf("PutLocal 0: %v", err)
	}
	if _, err := live.PutLocal(utf8EntityID(1), stagedPayload(1), stagedEntry(1)); err != nil {
		t.Fatalf("PutLocal 1: %v", err)
	}
	items := []LocalItem{
		{EntityID: utf8EntityID(2), Payload: stagedPayload(2), Entry: stagedEntry(2)},
		{EntityID: utf8EntityID(3), Payload: stagedPayload(3), Entry: stagedEntry(3)},
		{EntityID: utf8EntityID(4), Payload: stagedPayload(4), Entry: stagedEntry(4)},
	}
	if _, _, err := live.PutLocals(items); err != nil {
		t.Fatalf("PutLocals: %v", err)
	}

	count, total, mx := live.CommitStats()
	if count != 3 {
		t.Fatalf("want 3 commits counted (2 PutLocal + 1 PutLocals), got %d", count)
	}
	if total <= 0 || mx <= 0 || mx > total {
		t.Fatalf("nonsense stats: count=%d total_ns=%d max_ns=%d (want total>0, 0<max<=total)", count, total, mx)
	}

	// THE FAILURE PATH: an fsync failure must STILL be counted — the
	// 30 s timeout was exactly a commit that never returned cleanly, and an
	// instrument that only counts successes would be blind to its own target.
	live.WAL().SetSyncHookForTest(func() error { return errors.New("injected fsync failure") })
	if _, _, err := live.PutLocals(items); err == nil {
		t.Fatalf("premise broken: the batch must FAIL under the injected fsync failure")
	}
	live.WAL().SetSyncHookForTest(nil)
	count2, total2, _ := live.CommitStats()
	if count2 != 4 {
		t.Fatalf("a FAILED commit must be counted (it is the SLO-killer shape): count %d -> %d, want 4", count, count2)
	}
	if total2 <= total {
		t.Fatalf("the failed commit's wall time must accumulate: total %d -> %d", total, total2)
	}
}

// TestCommitTailLocalShape measures the per-commit wall time across
// batch sizes on THIS box and prints it — the instrument's own calibration.
// HONEST FRAMING: this is the local 4-core box's disk (t.TempDir), NOT the
// gate's instance-store NVMe under 34 colocated nodes; the numbers prove the
// instrument reads real latency and give the healthy-floor order of magnitude.
// The 213 s class itself is measurable only on the gate (a degraded/contended
// device) — the SLOW COMMIT line is the production capture for it.
func TestCommitTailLocalShape(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "shape.wal")
	live := newLiveBridge(t, walPath, 0)
	prevCount, prevTotal, _ := live.CommitStats()
	for _, n := range []int{1, 100, 1000, 10000} {
		items := make([]LocalItem, n)
		for i := range items {
			items[i] = LocalItem{
				EntityID: utf8EntityID(1000 + i),
				Payload:  stagedPayload(i),
				Entry:    stagedEntry(i),
			}
		}
		if _, _, err := live.PutLocals(items); err != nil {
			t.Fatalf("PutLocals(%d): %v", n, err)
		}
		count, total, _ := live.CommitStats()
		if count != prevCount+1 {
			t.Fatalf("one PutLocals must be ONE commit: count %d -> %d", prevCount, count)
		}
		t.Logf("batch=%6d commit wall = %v", n, time.Duration(total-prevTotal))
		prevCount, prevTotal = count, total
	}
	_, total, mx := live.CommitStats()
	t.Logf("TOTALS: commits=4 total=%v max=%v — the group commit makes the FSYNC count independent of N (1 per batch); a single commit's wall time is NOT bounded by it (write(N bytes) + 1 fsync, both unbounded under device degradation) — ADR-0044 AMORTISES the barrier, it does not BOUND the tail.",
		time.Duration(total), time.Duration(mx))
}

func TestSlowCommitLogFires(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "slowlog.wal")
	live := newLiveBridge(t, walPath, 0)

	cap1 := &logCapture{}
	prev := log.Writer()
	log.SetOutput(cap1)
	defer log.SetOutput(prev)

	// Threshold at 1 ns: EVERY commit is "slow" — the LOUD emitter is proven
	// without a fake clock or a 1 s sleep.
	live.slowCommitLogNs.Store(1)
	if _, err := live.PutLocal(utf8EntityID(0), stagedPayload(0), stagedEntry(0)); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	if !strings.Contains(cap1.String(), "SLOW COMMIT") {
		t.Fatalf("the SLOW COMMIT emitter is silent with the threshold at 1 ns — the 213 s class would be invisible in production logs. got: %q", cap1.String())
	}

	// Reset the capture, restore the default threshold: a healthy µs-scale
	// commit must NOT log (the line is rare by construction, not per-commit).
	cap2 := &logCapture{}
	log.SetOutput(cap2)
	live.slowCommitLogNs.Store(int64(time.Second))
	if _, err := live.PutLocal(utf8EntityID(1), stagedPayload(1), stagedEntry(1)); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	if strings.Contains(cap2.String(), "SLOW COMMIT") {
		t.Fatalf("a healthy commit must NOT log SLOW COMMIT (the line is the alarm, not the heartbeat): %q", cap2.String())
	}
}
