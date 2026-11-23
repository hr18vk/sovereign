// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package mesh

// These tests cover ReconnectLoop behavior when many colocated peers reconnect
// (ADR-0045). Each configured peer has its own loop, so one host-wide event can
// wake thousands of goroutines together.
//
// A configured listen address does not identify an inbound edge in byAddr:
// RegisterInbound uses the ephemeral remote address. liveReconnectEdge therefore
// also checks ps.peers, the map Publish uses, both before and after waiting on a
// connection's done channel. A live peer returns to the wait instead of dialing
// again. Repeated stale dials could otherwise make the peers replace each other's
// connections and sustain a reconnection cycle.
//
// Independent per-loop PCG sources add uniform ±20% jitter to the exponential
// backoff. This spreads dial and TLS work after a simultaneous disconnect rather
// than preserving lockstep timing through every backoff rung.

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stormDialer records every dial attempt and always refuses it, keeping each
// ReconnectLoop on its backoff ladder without requiring listeners or TLS.
type stormDialer struct {
	mu     sync.Mutex
	count  int64 // atomic
	stamps []time.Duration
	t0     time.Time
}

func (d *stormDialer) Dial(network, addr, serverName string) (*tls.Conn, error) {
	atomic.AddInt64(&d.count, 1)
	d.mu.Lock()
	d.stamps = append(d.stamps, time.Since(d.t0))
	d.mu.Unlock()
	return nil, fmt.Errorf("stormDialer: dial refused (by design)")
}

func (d *stormDialer) dials() int64 { return atomic.LoadInt64(&d.count) }

func (d *stormDialer) snapshot() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]time.Duration, len(d.stamps))
	copy(out, d.stamps)
	return out
}

// TestReconnectStormLivePeerNotRedialed starts one ReconnectLoop per live peer.
// Each peer is installed in ps.peers by node ID and in byAddr by an ephemeral
// address different from its configured dial address. The loops must find the
// peer through ps.peers and wait without dialing. A byAddr-only lookup misses
// this topology and produces at least one dial per peer.
func TestReconnectStormLivePeerNotRedialed(t *testing.T) {
	const peers = 20
	d := &stormDialer{t0: time.Now()}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Install `peers` live inbound edges exactly the way RegisterInbound does:
	// keyed in ps.peers under the real nodeID, and in byAddr under the peer's
	// ephemeral address — deliberately different from the configured dial addr the
	// ReconnectLoop holds. This is the colocated topology that defeated the
	// byAddr-only lookup.
	type peerFixture struct {
		nodeID     [16]byte
		configAddr string
		pc         *peerConn
	}
	fixtures := make([]peerFixture, peers)
	ps.mu.Lock()
	for i := range fixtures {
		var id [16]byte
		id[0] = 0xC1
		id[1] = byte(i + 1) // never the zero nodeID (that bucket is excluded by design)
		f := peerFixture{
			nodeID:     id,
			configAddr: fmt.Sprintf("10.0.0.%d:7373", i+1), // the configured listen addr
			pc: &peerConn{
				addr:   fmt.Sprintf("10.0.0.%d:%d", i+1, 40000+i), // the ephemeral addr
				peerID: id,
				done:   make(chan struct{}),
			},
		}
		ps.peers[f.nodeID] = f.pc   // the live edge
		ps.byAddr[f.pc.addr] = f.pc // keyed under the ephemeral port, as RegisterInbound does
		fixtures[i] = f
	}
	ps.mu.Unlock()

	// A configured address in byAddr would let the address-only lookup pass
	// without exercising the node-ID lookup this test targets.
	ps.mu.RLock()
	for _, f := range fixtures {
		if _, hit := ps.byAddr[f.configAddr]; hit {
			ps.mu.RUnlock()
			t.Fatalf("byAddr unexpectedly contains configured address %s; inbound edges must use ephemeral keys for this test", f.configAddr)
		}
	}
	ps.mu.RUnlock()

	// Fire all N loops simultaneously (the colocated herd).
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, f := range fixtures {
		wg.Add(1)
		go func(f peerFixture) {
			defer wg.Done()
			<-start
			ps.ReconnectLoop(ctx, f.configAddr, "localhost", f.nodeID, 20*time.Millisecond, 200*time.Millisecond)
		}(f)
	}
	close(start)

	// Observe for a window that would contain many backoff ticks (20 ms base → ~5
	// rungs in 300 ms). A storming loop cannot hide inside this window.
	time.Sleep(300 * time.Millisecond)
	got := d.dials()
	if got != 0 {
		t.Fatalf("%d dials fired in 300 ms against %d live peers, want 0; liveReconnectEdge must check ps.peers[peerID] because byAddr contains only the ephemeral address", got, peers)
	}
	t.Logf("%d ReconnectLoops with live inbound edges made %d dials in 300 ms", peers, got)

	// Closing every done channel must wake every loop. Suppressing duplicate
	// dials for live peers must not disable reconnection after teardown.
	for _, f := range fixtures {
		f.pc.closeDone()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.dials() >= peers {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if woke := d.dials(); woke < peers {
		t.Fatalf("closing all %d live edges produced only %d dials within 2 s, want one per peer", peers, woke)
	}
	cancel()
	wg.Wait()
	t.Logf("closing all %d edges produced %d reconnection dials", peers, d.dials())
}

// TestReconnectStormJitterDecorrelates releases N loops together with no live
// peers and compares timestamps in their second dial wave. Deterministic backoff
// would align that wave; ±20% jitter from per-loop PCG sources must spread it.
// The test asserts timestamp variance rather than a scheduler-sensitive instant
// for any individual dial.
func TestReconnectStormJitterDecorrelates(t *testing.T) {
	const peers = 24
	const base = 40 * time.Millisecond
	d := &stormDialer{t0: time.Now()}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// With no installed peers, every dial fails and every loop stays on the
	// backoff ladder. This isolates jitter from liveness deduplication.
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < peers; i++ {
		var id [16]byte
		id[0] = 0xC2
		id[1] = byte(i + 1)
		addr := fmt.Sprintf("10.1.0.%d:7373", i+1)
		wg.Add(1)
		go func(addr string, id [16]byte) {
			defer wg.Done()
			<-start
			ps.ReconnectLoop(ctx, addr, "localhost", id, base, 400*time.Millisecond)
		}(addr, id)
	}
	close(start)
	// Let each loop complete its first dial (immediate) + the first jittered
	// backoff + its second dial. The window covers the first two rungs.
	time.Sleep(220 * time.Millisecond)
	cancel()
	wg.Wait()

	stamps := d.snapshot()
	if len(stamps) < 2*peers {
		t.Fatalf("got fewer than %d dials across %d loops (actual %d), so jitter cannot be measured", 2*peers, peers, len(stamps))
	}
	// The first wave is immediate. The second wave includes the first jittered
	// backoff for every loop.
	second := stamps[peers : 2*peers]
	var mean float64
	for _, s := range second {
		mean += float64(s.Nanoseconds())
	}
	mean /= float64(len(second))
	var variance float64
	for _, s := range second {
		dv := float64(s.Nanoseconds()) - mean
		variance += dv * dv
	}
	stddev := time.Duration(math.Sqrt(variance / float64(len(second))))

	// A 40 ms rung with ±20% jitter spans 16 ms, whose uniform standard
	// deviation is about 4.6 ms. One millisecond rejects lockstep dialing while
	// leaving room for scheduler noise.
	const minSpread = time.Millisecond
	if stddev < minSpread {
		t.Fatalf("second-wave dials across %d loops have stddev %v, want at least %v; check per-loop PCG jitter on the timer", peers, stddev, minSpread)
	}
	t.Logf("second-wave dials across %d loops: mean %v, stddev %v (minimum %v)",
		peers, time.Duration(mean), stddev, minSpread)
}

// TestReconnectStormNoSpinOnZeroBackoff passes zero for both backoff limits.
// ReconnectLoop must normalize them and retain the normalized base after a dial.
// Resetting to the raw zero argument would make every timer immediate and cause
// a tight dial loop. The 250 ms observation window permits at most five dials.
func TestReconnectStormNoSpinOnZeroBackoff(t *testing.T) {
	d := &stormDialer{t0: time.Now()}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var id [16]byte
	id[0] = 0x00
	id[1] = 0xFF
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// backoff0 = 0 and backoffMax = 0 — both must normalize.
		ps.ReconnectLoop(ctx, "10.2.0.1:7373", "localhost", id, 0, 0)
	}()
	time.Sleep(250 * time.Millisecond)
	got := d.dials()
	cancel()
	wg.Wait()

	// The normalized base is one second: one immediate dial, then a wait. The
	// ceiling leaves room for scheduling without admitting a tight loop.
	const ceiling = 5
	if got > ceiling {
		t.Fatalf("%d dials in 250 ms with zero backoff limits, want at most %d; the loop did not retain a normalized backoff", got, ceiling)
	}
	t.Logf("zero backoff limits produced %d dials in 250 ms (ceiling %d)", got, ceiling)
}

// TestReconnectStormZeroPeerIDNotDeduped verifies that the zero node ID is not
// a liveness key. Unprovisioned peers share that map bucket, so one peer's live
// connection must not suppress another peer's reconnect. With a zero peer ID,
// liveReconnectEdge uses only the configured address lookup.
func TestReconnectStormZeroPeerIDNotDeduped(t *testing.T) {
	d := &stormDialer{t0: time.Now()}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A live peerConn parked in the zero-nodeID bucket (what an un-provisioned,
	// reconcile-missed peer looks like), keyed in byAddr under a different addr
	// than the loop's configured one.
	live := &peerConn{addr: "10.3.0.9:55555", done: make(chan struct{})}
	ps.mu.Lock()
	ps.peers[[16]byte{}] = live
	ps.byAddr[live.addr] = live
	ps.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The loop targets a different addr and carries the zero peerID.
		ps.ReconnectLoop(ctx, "10.3.0.1:7373", "localhost", [16]byte{}, 30*time.Millisecond, 120*time.Millisecond)
	}()
	time.Sleep(150 * time.Millisecond)
	got := d.dials()
	cancel()
	wg.Wait()

	if got == 0 {
		t.Fatalf("zero-peerID loop made no dials while an unrelated live connection occupied ps.peers[zero]; the shared bucket must not suppress reconnection")
	}
	t.Logf("zero-peerID loop made %d dials despite an unrelated connection in ps.peers[zero]", got)
}
