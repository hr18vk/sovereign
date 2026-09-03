// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// relay_counters_test.go — guards (ADR-0045):
//
// 1. THE misses SPLIT. Before the split, the sweep's `misses` counter conflated
//     two classes: the ORPHAN class (SELF entry, no payload recorded, no
//     commit in flight — a real defect, zero at steady state) and the
//     RELAY-RETENTION class (FOREIGN entry, no retained frame — the delta
//     propagates one hop and a relay holding the frame ships it next sweep).
//     A counter that means two things means nothing. The split moves the
//     foreign class to relay_misses.
//  2. THE HEARTBEAT. The sweep summary line was suppressed whenever every
//     counter was 0, so a STALLED sweep and a QUIET one were byte-identical in
//     the log — silence was not evidence of quiet. Every sweepHeartbeatRounds
//     -th round now prints unconditionally.

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/pkg/identity"
	eng "github.com/hr18vk/sovereign/pkg/sync"
)

// relayLogSink captures the `log` package's output; log.Logger serializes its
// own writes, the mutex guards the test's reads.
type relayLogSink struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *relayLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *relayLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// waitRelayKeys polls engineA's state until all n keys prefix-0..n-1 are
// present or the deadline expires (the receive path applies asynchronously).
func waitRelayKeys(t *testing.T, m *batchMesh, prefix string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := 0
		st := m.engineA.State()
		for i := 0; i < n; i++ {
			if len(st.Get(fmt.Sprintf("%s%d", prefix, i))) > 0 {
				got++
			}
		}
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("premise broken: A received %d/%d of B's keys (the receive path, not the relay counter, is broken)", got, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRelayMissSplitFromOrphanMiss is the split guard: a FOREIGN entry
// with NO retained frame must move relay_misses and MUST NOT move misses (the
// orphan counter); with the retainer wired, the same shape ships and neither
// counter moves.
func TestRelayMissSplitFromOrphanMiss(t *testing.T) {
	originate := func(m *batchMesh, prefix string, n int) {
		for i := 0; i < n; i++ {
			m.gB.InsertLocalEvents(fmt.Sprintf("%s%d", prefix, i), "v",
				eng.CRDTEntry{SystemTime: int64(1_700_400_000 + i), H3Index: uint64(i)})
		}
	}

	t.Run("unwired_retainer_counts_relay_miss_not_orphan", func(t *testing.T) {
		m, _ := newCommitWindowMesh(t)
		defer m.close()
		m.gB.SetBatchSize(100)
		m.gA.SetBatchSize(100)
		// NO WireRelayHooks on A: the receive path applies (state advances) but
		// retains nothing — the unwired shape, and the ONLY way a
		// relay miss arises.
		originate(m, "relay-unwired-", 5)
		m.gB.AntiEntropySweep(context.Background())
		waitRelayKeys(t, m, "relay-unwired-", 5)

		st := m.gA.AntiEntropySweep(context.Background())
		if st.relayMisses != 5 {
			t.Fatalf("the relay class must count on relay_misses: got %d, want 5 (5 foreign entries, no retained frame)", st.relayMisses)
		}
		if st.payloadMisses != 0 {
			t.Fatalf("the orphan counter must NOT move for the relay class: misses=%d — that conflation is exactly what the split removes", st.payloadMisses)
		}
		if st.shippedEnvelopes != 0 {
			t.Fatalf("nothing may ship without a retained frame: shipped_env=%d", st.shippedEnvelopes)
		}
	})

	t.Run("wired_retainer_ships_and_relay_misses_stay_zero", func(t *testing.T) {
		m, _ := newCommitWindowMesh(t)
		defer m.close()
		m.gB.SetBatchSize(100)
		m.gA.SetBatchSize(100)
		m.gA.WireRelayHooks(m.recvA) // the production wiring seam
		originate(m, "relay-wired-", 5)
		m.gB.AntiEntropySweep(context.Background())
		waitRelayKeys(t, m, "relay-wired-", 5)

		st := m.gA.AntiEntropySweep(context.Background())
		if st.relayMisses != 0 {
			t.Fatalf("with the retainer wired there is nothing to relay-miss: got %d", st.relayMisses)
		}
		if st.payloadMisses != 0 {
			t.Fatalf("no orphans on this shape: misses=%d", st.payloadMisses)
		}
		if st.shippedEnvelopes == 0 {
			t.Fatalf("the retained foreign batch must RELAY (Root-2 closure): shipped_env=0")
		}
	})
}

// TestSweepHeartbeatSilenceIsNotQuiet drives the REAL SweepLoop on a
// zero-peer gossiper (nothing to ship, nothing to miss — every counter 0) and
// asserts the summary line still prints at the heartbeat cadence, carrying the
// all-zero counters. Pre-this shape printed NOTHING.
func TestSweepHeartbeatSilenceIsNotQuiet(t *testing.T) {
	sink := &relayLogSink{}
	prev := log.Writer()
	log.SetOutput(sink)
	defer log.SetOutput(prev)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 41)
	}
	owner, err := NewNodeIdentity(seed)
	if err != nil {
		t.Fatalf("NewNodeIdentity: %v", err)
	}
	engine := newTestEngine(t, owner.NodeID, t.TempDir())
	t.Cleanup(func() { _ = engine.Close() })
	g := NewGossiper(NewPeerSet(nil, nopFrameSink{}, owner, engine), owner, engine, identity.NewDirectory())
	// NO peers, NO inserts: every sweep is all-zero counters — the exact shape
	// the pre-print condition suppressed.

	ctx, cancel := context.WithCancel(context.Background())
	// JOIN THE LOOP: SweepLoop reads the engine (stampConvergence →
	// MerkleRootFromShards) on every tick, so the goroutine must be provably
	// EXITED before the test returns — otherwise t.Cleanup's engine.Close frees
	// the arena under a mid-flight sweep (the constructor-cleanup
	// SIGSEGV class; observed: fault in stampConvergence→HAMT.Len).
	done := make(chan struct{})
	go func() { g.SweepLoop(ctx, time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()
	// Poll the captured log until a heartbeat line lands (cadence 100 rounds ≈
	// 100 ms at the 1 ms tick; a 5 s cap absorbs a loaded 4-core box without a
	// hard-coded sleep count that would flake under it).
	deadline := time.Now().Add(5 * time.Second)
	for {
		out := sink.String()
		if strings.Contains(out, "sweep round=") {
			if !strings.Contains(out, "misses=0 relay_misses=0 pending=0") {
				t.Fatalf("the heartbeat must carry the all-zero counters (the quiet-state evidence); got: %q", out)
			}
			return // the deferred cancel+<-done joins the loop before cleanup
		}
		if time.Now().After(deadline) {
			t.Fatalf("HEARTBEAT MISSING: 5 s of zero-activity sweeps printed no `sweep round=` line — a stalled sweep is indistinguishable from a quiet one (the §15.15 blind spot the heartbeat closes)")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
