// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package mesh

// reconnect_storm_test.go — ADR-0045: the
// ReconnectLoop colocated-stampede RED→GREEN guards.
//
// THE BUG (silicon, 100 nodes / 3 hosts / 34 nodes per host): every node
// runs one ReconnectLoop goroutine per configured peer (main.go:1443), so a
// 34-colocated host runs 34 × 99 = 3366 of them. Two defects made that a storm:
//
//	— the post-wait liveness gap. The loop looked up ps.byAddr[addr] BEFORE
//	     waiting on pc.done, but never re-checked AFTER the wait; it dialed
//	     unconditionally. Worse, the only lookup it did was byAddr[configuredAddr],
//	     which STRUCTURALLY CANNOT see a live inbound edge: RegisterInbound keys
// byAddr under conn.RemoteAddr — the peer's EPHEMERAL port (peer.go:529) —
//	     while ReconnectLoop holds the configured listen addr. So a node with a
//	     perfectly good, publishable, registered inbound edge from a peer
//	     re-dialed that peer anyway. The remote's RegisterInbound then stale-closed
//	     the peer's own outbound peerConn (peer.go:542-563), waking THAT node's
//	     ReconnectLoop, which re-dialed back: a self-sustaining ping-pong that
//	     re-registered the same nodeID ~10× at different ephemeral ports (exactly
// what's logs show) and starved the anti-entropy sweep to 1 round
//	     in 91 seconds.
//
//	— zero jitter. The backoff ladder (1s→2s→4s→8s→10s) was perfectly
//	     deterministic, so thousands of loops dropped by one host-wide event
//	     re-dialed in LOCKSTEP, and doubling PRESERVES that phase alignment at
//	     every rung. The herd never de-synchronized on its own.
//
// THE FIX: liveReconnectEdge (byAddr OR ps.peers — the map Publish consults) is
// consulted both before the wait AND after it; a live edge means "return to the
// wait", not "dial". Plus ±20% uniform jitter from a per-loop PCG source.
//
// RUN: go test -run 'TestReconnect' -race -count=1 ./pkg/mesh/

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

// stormDialer counts every Dial attempt and records when each one happened. It
// ALWAYS fails: a failing dial is what drives the loop onto the backoff ladder,
// which is precisely the path the jitter governs. Failing also keeps the guard
// free of TLS/listener machinery, so what it measures is the loop's dial-decision
// behavior and nothing else.
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

// TestReconnectLivePeerNotRedialed is the guard: N ReconnectLoops
// whose peers are ALL ALREADY LIVE via the INBOUND edge (registered in
// ps.peers under the real nodeID, keyed in byAddr under an ephemeral port — the
// exact colocated shape) must issue ZERO dials.
//
// This is the load-bearing storm assertion. On the pre-code every loop dials
// immediately, because byAddr[configuredAddr] misses (the inbound edge is keyed
// under the ephemeral port) so the pc.done wait is SKIPPED and Dial is called
// unconditionally → N dials in the first tick. With, liveReconnectEdge finds the
// peer in ps.peers and the loop blocks on that edge's done channel → 0 dials.
//
// RED→Positive control: verified by fault-injection (documented in the change log) —
// reverting liveReconnectEdge to a byAddr-only lookup makes this FAIL with
// dials >= N.
func TestReconnectLivePeerNotRedialed(t *testing.T) {
	const peers = 20
	d := &stormDialer{t0: time.Now()}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Install `peers` LIVE inbound edges exactly the way RegisterInbound does:
	// keyed in ps.peers under the real nodeID, and in byAddr under the peer's
	// EPHEMERAL address — deliberately DIFFERENT from the configured dial addr the
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
			configAddr: fmt.Sprintf("10.0.0.%d:7373", i+1), // the CONFIGURED listen addr
			pc: &peerConn{
				addr:   fmt.Sprintf("10.0.0.%d:%d", i+1, 40000+i), // the EPHEMERAL addr
				peerID: id,
				done:   make(chan struct{}),
			},
		}
		ps.peers[f.nodeID] = f.pc   // what Publish consults — the live edge
		ps.byAddr[f.pc.addr] = f.pc // keyed under the EPHEMERAL port, as RegisterInbound does
		fixtures[i] = f
	}
	ps.mu.Unlock()

	// Sanity: the configured addr each loop will hold must NOT be in byAddr — the
	// premise of the test. If it were, the guard would pass via the pre-fix lookup
	// and prove nothing about.
	ps.mu.RLock()
	for _, f := range fixtures {
		if _, hit := ps.byAddr[f.configAddr]; hit {
			ps.mu.RUnlock()
			t.Fatalf("PREMISE BROKEN: byAddr contains the CONFIGURED addr %s — the test must model RegisterInbound's EPHEMERAL keying, else it cannot distinguish the storm guard from the pre-fix byAddr-only lookup", f.configAddr)
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

	// Observe for a window that would contain MANY backoff ticks (20ms base → ~5
	// rungs in 300ms). A storming loop cannot hide inside this window.
	time.Sleep(300 * time.Millisecond)
	got := d.dials()
	if got != 0 {
		t.Fatalf("STORM: %d dials fired in 300ms against %d peers that are ALL ALREADY LIVE via the accept-symmetry inbound edge (ps.peers keyed by real nodeID). Expected ZERO. A live, publishable peer must NEVER be re-dialed: the re-dial makes the remote's RegisterInbound stale-close that peer's own outbound peerConn (peer.go:542-563), waking its ReconnectLoop into a re-dial ping-pong — the run-#4 storm that starved the sweep to 1 round/91s. Check liveReconnectEdge consults ps.peers[peerID], not just byAddr[addr] (RegisterInbound keys byAddr under the EPHEMERAL port, so byAddr alone CANNOT see an inbound edge).", got, peers)
	}
	t.Logf("GREEN (storm guard) — %d ReconnectLoops, all peers live via the accept-symmetry INBOUND edge (ps.peers by real nodeID; byAddr under the ephemeral port): %d dials in 300ms. The loops are parked on their live edges' done channels, so the colocated re-dial ping-pong cannot start.", peers, got)

	// Now DROP every edge at once — the host-wide event. Each loop must wake and
	// re-dial (liveness is real, not a permanent mute), proving did not simply
	// disable reconnection.
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
		t.Fatalf("OVER-SUPPRESSION: after closing ALL %d live edges, only %d dials fired within 2s. The storm guard must dedupe LIVE peers only — a dead peer MUST still be re-dialed, or the mesh never heals (the liveness discipline). Check that liveReconnectEdge returns nil once pc.done is closed.", peers, woke)
	}
	cancel()
	wg.Wait()
	t.Logf("GREEN (storm-guard liveness is REAL) — after all %d edges dropped, %d dials fired: the dedupe suppresses re-dials of LIVE peers only; dead peers still heal. The guard is a storm drain, not a reconnection kill-switch.", peers, d.dials())
}

// TestReconnectJitterDecorrelates is the guard: N loops dialing
// DEAD peers in lockstep must NOT re-dial in phase. It measures the spread of dial
// timestamps within one backoff rung.
//
// The pre-ladder is perfectly deterministic, so with all loops released at the
// same instant every one of them fires its k-th dial at the same offset (base ×
// (2^k − 1)), and the timestamps cluster into tight spikes. With ±20% jitter drawn
// from a per-loop PCG source seeded by (addr, peerID), the k-th dials spread across
// a window. The assertion is on the SPREAD, not on any single dial time — that is
// the property that converts O(all colocated) instantaneous dial load into
// O(fanout).
func TestReconnectJitterDecorrelates(t *testing.T) {
	const peers = 24
	const base = 40 * time.Millisecond
	d := &stormDialer{t0: time.Now()}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// No peers installed at all → every dial fails → every loop rides the backoff
	// ladder. This isolates: there is no liveness to dedupe, only jitter.
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
		t.Fatalf("C2 guard premise: expected >= %d dials (each of %d loops dialing at least twice), got %d — the loops are not riding the backoff ladder; the guard cannot measure jitter", 2*peers, peers, len(stamps))
	}
	// The FIRST `peers` dials are the immediate ones (no backoff yet, so no jitter
	// is expected there). The jitter governs the SECOND wave: dials [peers, 2*peers).
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

	// With ±20% jitter on a 40ms rung the offsets are uniform over a 16ms window;
	// a uniform distribution's stddev is width/sqrt(12) ≈ 4.6ms. Require >= 1ms:
	// comfortably above scheduler noise on a loaded box, and far above the
	// sub-100µs clustering a ZERO-jitter ladder produces.
	const minSpread = time.Millisecond
	if stddev < minSpread {
		t.Fatalf("C2 LOCKSTEP: the second-wave dials of %d loops have stddev %v (< %v) — they are re-dialing IN PHASE. A deterministic ladder re-synchronizes the herd at every rung (doubling preserves phase), so a host-wide drop at colocated density spikes O(all edges) of dial+TLS work per instant and starves the anti-entropy sweep goroutine. Check the +/-20 pct jitter is applied to the TIMER value (d), drawn from the per-loop rand.NewPCG source.", peers, stddev, minSpread)
	}
	t.Logf("GREEN (C2) — second-wave dial timestamps across %d loops: mean %v, stddev %v (>= %v). The +/-20 pct per-loop PCG jitter de-correlates the ladder, so a host-wide drop spreads dial arrivals across a window instead of spiking in lockstep.",
		peers, time.Duration(mean), stddev, minSpread)
}

// TestReconnectNoSpinOnZeroBackoff pins the latent tight-spin this change
// also closed: the pre-fix loop normalized backoff0<=0 into `b` but then reset with
// `b = backoff0` (the RAW argument) after a successful dial, so a caller passing 0
// got NewTimer(0) and `b *= 2 == 0` — a 100%-CPU re-dial spin. At colocated density
// a zero-backoff loop IS a stampede, so it belongs to the backoff-bucket fix.
//
// The assertion is a dial-RATE ceiling: with backoff0=0 the loop must still back off
// (normalized to 1s), so a 250ms window admits very few dials. A spinning loop would
// fire thousands.
func TestReconnectNoSpinOnZeroBackoff(t *testing.T) {
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
		// backoff0 = 0 AND backoffMax = 0 — both must normalize.
		ps.ReconnectLoop(ctx, "10.2.0.1:7373", "localhost", id, 0, 0)
	}()
	time.Sleep(250 * time.Millisecond)
	got := d.dials()
	cancel()
	wg.Wait()

	// Normalized base is 1s, so in 250ms: 1 immediate dial, then a wait. Allow a
	// small margin for jitter/scheduling; a spin would be orders of magnitude above.
	const ceiling = 5
	if got > ceiling {
		t.Fatalf("TIGHT SPIN: %d dials in 250ms with backoff0=0 (ceiling %d). The loop is not backing off — a zero/negative backoff0 must normalize (base = 1s) AND the post-dial reset must restore the NORMALIZED base, not the raw argument. A 100 pct-CPU re-dial spin per dropped peer is a stampede by itself at 34 nodes/host.", got, ceiling)
	}
	t.Logf("GREEN (no spin) — backoff0=0/backoffMax=0 normalized: %d dials in 250ms (ceiling %d). The post-dial reset restores the NORMALIZED base, so a caller passing zero cannot arm a tight re-dial spin.", got, ceiling)
}

// TestReconnectZeroPeerIDNotDeduped guards the deliberate EXCLUSION in
// liveReconnectEdge: the ZERO nodeID must NOT be honored as a liveness key.
//
// Dial keys an un-provisioned peer whose leaf-CN reconcile misses under the zero
// peerID, so ps.peers[zero] is a COLLISION BUCKET shared by every un-provisioned
// peer. Honoring it would let ONE peer's liveness suppress a DIFFERENT peer's
// reconnect — a false dedupe that silently partitions the mesh. For the zero
// peerID the predicate must degrade to exactly the pre-fix byAddr-only behavior.
func TestReconnectZeroPeerIDNotDeduped(t *testing.T) {
	d := &stormDialer{t0: time.Now()}
	ps := NewPeerSet(d, nopFrameSink{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A LIVE peerConn parked in the zero-nodeID bucket (what an un-provisioned,
	// reconcile-missed peer looks like), keyed in byAddr under a DIFFERENT addr
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
		// The loop targets a DIFFERENT addr and carries the ZERO peerID.
		ps.ReconnectLoop(ctx, "10.3.0.1:7373", "localhost", [16]byte{}, 30*time.Millisecond, 120*time.Millisecond)
	}()
	time.Sleep(150 * time.Millisecond)
	got := d.dials()
	cancel()
	wg.Wait()

	if got == 0 {
		t.Fatalf("FALSE DEDUPE: a ReconnectLoop carrying the ZERO peerID issued 0 dials while an UNRELATED live peerConn sat in ps.peers[zero]. The zero nodeID is a COLLISION BUCKET (every un-provisioned, reconcile-missed peer lands there), so honoring it lets one peer's liveness suppress another peer's reconnect — a silent mesh partition. liveReconnectEdge must SKIP the ps.peers half when peerID is zero.")
	}
	t.Logf("GREEN (zero-peerID exclusion) — a zero-peerID loop still dialed %d times despite an unrelated live conn in ps.peers[zero]: the collision bucket is correctly EXCLUDED, so the predicate degrades to byAddr-only for un-provisioned peers (no false dedupe, no silent partition).", got)
}
