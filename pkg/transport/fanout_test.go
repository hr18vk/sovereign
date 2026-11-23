// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package transport

// These tests cover deterministic routing, flow affinity, and independence
// from signature verification in ReusePortFanout. Fixed sample sizes make any
// mis-route a failure rather than one contributor to a throughput average.
//
// The virtual-network tests exercise the Go selector, not kernel delivery.
// Kernel coverage lives in ebpf_reuseport_test.go behind the ebpf_kernel tag.

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hr18vk/sovereign/internal/chaos"
	"github.com/hr18vk/sovereign/pkg/attribution"
)

// TestSelectRouteDeterminism checks that the same connection ID and socket
// count produce the same index for 1<<20 calls.
func TestSelectRouteDeterminism(t *testing.T) {
	const numSockets uint32 = 32
	var cid [attribution.OriginNodeIDSize]byte
	// A non-trivial CID (not all-zero) so the hash exercises real input.
	for i := range cid {
		cid[i] = byte(i + 1)
	}
	f := &ReusePortFanout{}
	want := f.SelectRoute(cid, numSockets)
	const iters = 1 << 20
	for i := 0; i < iters; i++ {
		got := f.SelectRoute(cid, numSockets)
		if got != want {
			t.Fatalf("determinism violated at iter %d: want %d got %d (numSockets=%d)", i, want, got, numSockets)
		}
	}
	if want >= numSockets {
		t.Fatalf("index out of range: %d >= %d", want, numSockets)
	}
	t.Logf("determinism holds: SelectRoute(cid, %d) == %d for %d iterations", numSockets, want, iters)
}

// TestRoamStickiness_32ListIncomplete sends 1,000 frames with one originNodeID
// and varying source node IDs through a virtual ingress node. All frames must
// arrive at the same one of 32 workers, demonstrating that routing ignores the
// changing network identity.
func TestRoamStickiness_32ListIncomplete(t *testing.T) {
	const (
		numWorkers uint32 = 32
		n                 = 1000
	)

	// The application connection ID remains fixed while the source node ID,
	// which represents the changing network identity, varies per frame.
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(0xA0 + (i % 16))
	}

	// NewSignedRelayEnvelopeV3 places originNodeID at [80:96]. The remaining
	// fields can stay empty because the selector consumes only the ID.
	env := attribution.NewSignedRelayEnvelopeV3(
		make([]byte, 0),                   // innerWire: unused by the route
		[attribution.OriginSigSize]byte{}, // originSig: unused by the route
		0,                                 // dotCounter: unused by the route
		cid,                               // originNodeID: the route key
		nil,                               // hops: unused by the route
	)
	frame := env.Marshal()
	routedCID := env.OriginNodeID()
	if routedCID != cid {
		t.Fatalf("OriginNodeID() round-trip mismatch: want %x got %x", cid, routedCID)
	}

	// Disable loss and jitter so receipt counts measure routing rather than the
	// virtual network's fault injection.
	vn := chaos.NewVirtualNet(chaos.ChaosProfile{
		Drop:             0,
		Duplicate:        0,
		ReorderMaxJitter: 0,
		DeliveryBase:     0,
	})
	defer vn.Stop()

	// Worker callbacks count actual deliveries. The WaitGroup prevents the
	// assertions from racing ahead of those callbacks.
	var receipts [numWorkers]int64
	var workerIDs [numWorkers][16]byte
	var wg sync.WaitGroup
	wg.Add(n)
	for w := uint32(0); w < numWorkers; w++ {
		var wid [16]byte
		wid[0] = byte(w)
		workerIDs[w] = wid
		idx := w // capture for the closure
		vn.AddNode(wid, func(msg chaos.NetMessage) {
			atomic.AddInt64(&receipts[idx], 1)
			wg.Done()
		})
	}

	// Compute the expected worker once, then use the same stateless selector in
	// the ingress callback for every frame.
	f := &ReusePortFanout{}
	preRoamWorker := f.SelectRoute(routedCID, numWorkers)
	t.Logf("pre-roam worker index: %d (cid=%x)", preRoamWorker, routedCID)

	// The ingress callback selects one worker and forwards the frame. Completion
	// is signaled by the receiving worker, not by this forwarding step.
	const ingressID = 0xFF
	var ingressNode [16]byte
	ingressNode[0] = ingressID
	vn.AddNode(ingressNode, func(msg chaos.NetMessage) {
		// Route by the application connection ID; msg.From does not participate.
		worker := f.SelectRoute(routedCID, numWorkers)
		if worker >= numWorkers {
			t.Errorf("route out of range: %d >= %d", worker, numWorkers)
			wg.Done() // do not leak the WaitGroup on a (impossible) out-of-range
			return
		}
		// msg.To is the ingress node, so this forwards from ingress to the worker.
		if err := vn.Send(msg.To, workerIDs[worker], frame); err != nil {
			t.Errorf("forward to worker %d: %v", worker, err)
			wg.Done() // do not leak the WaitGroup on a send failure
		}
	})

	// Vary the source node ID for every frame while retaining the envelope.
	for i := 0; i < n; i++ {
		var src [16]byte
		src[0] = byte(i >> 8)
		src[1] = byte(i)
		src[2] = 0x01 // mark as a roaming source
		if err := vn.Send(src, ingressNode, frame); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	wg.Wait()

	// Count both delivery loss and receipts outside the expected worker.
	var failures int
	var totalReceipts int64
	for w := uint32(0); w < numWorkers; w++ {
		got := atomic.LoadInt64(&receipts[w])
		totalReceipts += got
		if w != preRoamWorker && got != 0 {
			failures += int(got)
		}
	}
	if totalReceipts != int64(n) {
		t.Errorf("receipt count mismatch: want %d got %d (frames lost by the net)", n, totalReceipts)
	}

	// Log the expected worker and observed distribution for diagnosis.
	t.Logf("roam stickiness table: pre-roam-worker=%d post-roam-worker=%d n=%d failures=%d",
		preRoamWorker, preRoamWorker, n, failures)
	t.Logf("per-worker receipts: worker %d -> %d (the pinned core); all others -> 0",
		preRoamWorker, atomic.LoadInt64(&receipts[preRoamWorker]))

	if failures != 0 {
		t.Fatalf("roam stickiness failed: %d/%d frames landed on a worker other than the pinned core %d",
			failures, n, preRoamWorker)
	}
	if got := atomic.LoadInt64(&receipts[preRoamWorker]); got != int64(n) {
		t.Fatalf("pinned worker %d received %d, want %d", preRoamWorker, got, n)
	}
}

// TestNoCryptoBeforeRoute instruments attribution.VerifyHookCount and checks
// that SelectRoute performs no signature verification. Header-based routing
// must remain independent of the later verification step.
func TestNoCryptoBeforeRoute(t *testing.T) {
	count := new(attribution.VerifyHookCount)
	attribution.SetVerifyHook(count.Hook)
	defer attribution.ClearVerifyHook()

	const numSockets uint32 = 32
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(0x5A - i)
	}

	// Run the routing decision many times — the selector must route without
	// ever invoking Verify.
	const iters = 10000
	f := &ReusePortFanout{}
	for i := 0; i < iters; i++ {
		_ = f.SelectRoute(cid, numSockets)
	}

	if got := count.Load(); got != 0 {
		t.Fatalf("SelectRoute issued %d Verify calls, want 0: routing must precede verification", got)
	}
	t.Logf("no-crypto check holds: SelectRoute issued 0 Verify calls across %d routing decisions", iters)
}

// TestNoPanicOnZeroFrame covers zero-valued inputs to SelectRoute. An empty
// socket group returns the zero sentinel without panicking, while a zero-value
// connection ID still hashes deterministically when sockets are available.
func TestNoPanicOnZeroFrame(t *testing.T) {
	f := &ReusePortFanout{}

	// An empty group returns the zero sentinel without panicking.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SelectRoute panicked on numSockets=0: %v", r)
		}
	}()
	var zeroCID [attribution.OriginNodeIDSize]byte
	got := f.SelectRoute(zeroCID, 0)
	if got != 0 {
		t.Fatalf("SelectRoute(zeroCID, 0)=%d, want 0", got)
	}

	// A zero-value CID with a valid group still produces an in-range index.
	got2 := f.SelectRoute(zeroCID, 32)
	if got2 >= 32 {
		t.Fatalf("zero-CID route out of range: %d >= 32", got2)
	}
	t.Logf("zero inputs: empty group returned 0; zero CID selected worker %d", got2)
}
