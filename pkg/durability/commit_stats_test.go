// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// Tests for the WAL group-commit timing instrument. Each AppendMutation and
// AppendMutations call contributes to CommitStats, including calls whose fsync
// fails. CommitStats exposes the count, total duration, and maximum duration to
// /v1/merkle; a commit beyond slowCommitLogNs also writes a SLOW COMMIT log
// line. Failed and slow commits must remain visible because either can delay
// convergence while the caller is waiting.

import (
	"errors"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// logCapture redirects the standard logger during a test. The logger serializes
// its writes; the mutex also protects reads from the test goroutine.
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

	// A failed fsync still contributes a commit and its elapsed time. Excluding
	// it would hide the commits most likely to explain a convergence delay.
	live.WAL().SetSyncHookForTest(func() error { return errors.New("injected fsync failure") })
	if _, _, err := live.PutLocals(items); err == nil {
		t.Fatalf("batch succeeded despite the injected fsync failure")
	}
	live.WAL().SetSyncHookForTest(nil)
	count2, total2, _ := live.CommitStats()
	if count2 != 4 {
		t.Fatalf("failed commit was not counted: count %d -> %d, want 4", count, count2)
	}
	if total2 <= total {
		t.Fatalf("the failed commit's wall time must accumulate: total %d -> %d", total, total2)
	}
}

// TestCommitTailLocalShape reports commit durations for several batch sizes on
// the test machine's temporary filesystem. These values calibrate the counters
// for that machine only; they are not multi-node or contended-storage results.
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
			t.Fatalf("one PutLocals must increment the commit count once: count %d -> %d", prevCount, count)
		}
		t.Logf("batch=%6d  commit wall = %v", n, time.Duration(total-prevTotal))
		prevCount, prevTotal = count, total
	}
	_, total, mx := live.CommitStats()
	t.Logf("totals: commits=4 total=%v max=%v; group commit uses one fsync per batch, but writing and syncing can still take unbounded time under device degradation",
		time.Duration(total), time.Duration(mx))
}

func TestSlowCommitLogFires(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "slowlog.wal")
	live := newLiveBridge(t, walPath, 0)

	cap1 := &logCapture{}
	prev := log.Writer()
	log.SetOutput(cap1)
	defer log.SetOutput(prev)

	// A 1 ns threshold makes the next commit cross the slow-log threshold
	// without a fake clock or a sleep.
	live.slowCommitLogNs.Store(1)
	if _, err := live.PutLocal(utf8EntityID(0), stagedPayload(0), stagedEntry(0)); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	if !strings.Contains(cap1.String(), "SLOW COMMIT") {
		t.Fatalf("no SLOW COMMIT line with a 1 ns threshold; got log output %q", cap1.String())
	}

	// Restore the default threshold. An ordinary fast commit must not emit the
	// slow-commit line.
	cap2 := &logCapture{}
	log.SetOutput(cap2)
	live.slowCommitLogNs.Store(int64(time.Second))
	if _, err := live.PutLocal(utf8EntityID(1), stagedPayload(1), stagedEntry(1)); err != nil {
		t.Fatalf("PutLocal: %v", err)
	}
	if strings.Contains(cap2.String(), "SLOW COMMIT") {
		t.Fatalf("ordinary fast commit emitted SLOW COMMIT at the default threshold: %q", cap2.String())
	}
}
