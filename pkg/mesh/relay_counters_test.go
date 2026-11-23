// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover two sweep diagnostics (ADR-0045 §7).
//
// A self-originated entry without a payload and without a commit in flight is
// an orphan and increments misses. A foreign entry without a retained frame is
// a relay miss and increments relay_misses instead. Separate counters
// distinguish missing local payloads from relay retention.
//
// The sweep summary is also printed every sweepHeartbeatRounds rounds, even
// when all counters are zero. A periodic line distinguishes an idle sweep from
// one that has stalled.

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

// RelayCountersLogSink captures the `log` package's output; log.Logger
// serializes its own writes, the mutex guards the test's reads.
type RelayCountersLogSink struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *RelayCountersLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *RelayCountersLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// relayCountersWaitKeys polls engineA's state until all n keys with the given
// prefix are present or the deadline expires (the receive path applies
// asynchronously).
func relayCountersWaitKeys(t *testing.T, m *batchMesh, prefix string, n int) {
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
			t.Fatalf("receive path applied %d/%d of B's keys before the deadline", got, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRelayMissSplitFromOrphanMiss checks that a foreign entry without a
// retained frame increments relay_misses and leaves the orphan counter alone.
// With the retainer wired, the same entry ships and neither counter moves.
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
		// No WireRelayHooks on A: the receive path applies (state advances) but
		// retains nothing — the batch retainer unwired shape, and the only way a
		// relay miss arises.
		originate(m, "relay-unwired-", 5)
		m.gB.AntiEntropySweep(context.Background())
		relayCountersWaitKeys(t, m, "relay-unwired-", 5)

		st := m.gA.AntiEntropySweep(context.Background())
		if st.relayMisses != 5 {
			t.Fatalf("the relay class must count on relay_misses: got %d, want 5 (5 foreign entries, no retained frame)", st.relayMisses)
		}
		if st.payloadMisses != 0 {
			t.Fatalf("the orphan counter must not move for the relay class: misses=%d — that conflation is exactly what the split removes", st.payloadMisses)
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
		m.gA.WireRelayHooks(m.recvA) // the production wiring seam (batch retainer)
		originate(m, "relay-wired-", 5)
		m.gB.AntiEntropySweep(context.Background())
		relayCountersWaitKeys(t, m, "relay-wired-", 5)

		st := m.gA.AntiEntropySweep(context.Background())
		if st.relayMisses != 0 {
			t.Fatalf("with the retainer wired there is nothing to relay-miss: got %d", st.relayMisses)
		}
		if st.payloadMisses != 0 {
			t.Fatalf("no orphans on this shape: misses=%d", st.payloadMisses)
		}
		if st.shippedEnvelopes == 0 {
			t.Fatalf("retained foreign batch was not relayed")
		}
	})
}

// TestSweepHeartbeatSilenceIsNotQuiet drives SweepLoop on a zero-peer
// gossiper. The heartbeat must still print at its cadence and include the zero
// counters even though there is nothing to ship or miss.
func TestSweepHeartbeatSilenceIsNotQuiet(t *testing.T) {
	sink := &RelayCountersLogSink{}
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
	// No peers and no inserts keep every counter at zero.

	ctx, cancel := context.WithCancel(context.Background())
	// SweepLoop reads the engine on every tick. Cancel and join it before
	// cleanup closes the engine and releases its arena.
	done := make(chan struct{})
	go func() { g.SweepLoop(ctx, time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()
	// Poll the captured log until a heartbeat line lands. The cadence is 100
	// rounds, about 100 ms at this tick; the 5 s deadline accommodates a loaded
	// host without relying on a fixed number of sleeps.
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
			t.Fatalf("zero-activity sweeps printed no heartbeat within 5s; an idle sweep must be distinguishable from a stalled one")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
