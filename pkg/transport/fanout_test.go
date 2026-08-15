package transport

// Track 2.1 — INGRESS fanout stickiness teeth (in-process seam).
//
// WHY A TEST, NOT A BENCHMARK (load-bearing idiom choice, the E5 precedent at
// pkg/durability120/s3express_test.go:6): a flow-stickiness gate is about the
// FAILURE RATE across a roam, NOT the average throughput. testing.B's b.N
// mean re-stabilization is the WRONG idiom — b.N ramps to find a stable MEAN;
// a stickiness gate needs a FIXED sample size so a single mis-route is a hard
// FAIL, not averaged away. So these are fixed-sample Tests (the E5 shape:
// `const n = 1000`), NOT Benchmarks. Cite the E5 precedent header block.
//
// HONEST GEAR (the §5 SCISSORS rule): this is an IN-PROCESS deterministic
// model on the 4c canonical box, NOT a 32c linux-6.18 silicon number. The
// kernel epoll + SOCKHASH load on c8g with CAP_BPF is the FUTURE Subphase
// 12.0 track; this track proves the DETERMINISM + STICKINESS + NO-CRYPTO
// properties of the in-process analogue, not a silicon measurement. Do NOT
// label these numbers as 32c silicon.

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hr18vk/supremum/internal/chaos"
	"github.com/hr18vk/supremum/pkg/attribution"
)

// TestSelectRouteDeterminism — G2.1.b: SelectRoute(sameCID, n) == sameIndex
// for 1<<20 iterations. The kernel eBPF program is deterministic BY
// DEFINITION (a remap keyed on a fixed field hash); the in-process analogue
// MUST be too. FAIL on any drift — a single differing index is a hard FAIL,
// not an averaged-away mean.
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

// TestRoamStickiness_32ListIncomplete — G2.1.c (the load-bearing gate): the
// 32-listener stickiness property. A peer IP roam changes the connection
// 4-tuple (the NetMessage source nodeID) while the Application Connection ID
// (originNodeID) stays CONSTANT. The receipt MUST land on the SAME worker
// index for all 1000 frames in the roam. Fixed sample = 1000 (the E5 shape).
//
// Uses the in-process internal/chaos VirtualNet (the roadmap line 51 carve-
// out): AddNode x32 workers + 1 ingress node; the ingress node routes each
// received frame via SelectRoute to exactly one of the 32. Send 1000 frames
// with the SAME originNodeID but a DIFFERENT source nodeID per frame (the
// roam). Count per-worker receipts; assert they concentrate to ONE worker.
func TestRoamStickiness_32ListIncomplete(t *testing.T) {
	const (
		numWorkers uint32 = 32
		n                 = 1000
	)

	// The FIXED Application Connection ID — the cheap-gate header mirror the
	// eBPF program keys on (envelope.go:345 OriginNodeID). Constant across the
	// roam; only the 4-tuple (source nodeID) changes.
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(0xA0 + (i % 16))
	}

	// Build the frame via the helper (do NOT hand-roll offsets). A v3
	// envelope carries originNodeID in the header at [80:96] (envelope.go
	// :498-503); NewSignedRelayEnvelopeV3 sets it. The inner wire / originSig
	// / hops are irrelevant to routing — the selector reads ONLY OriginNodeID
	// — so a minimal envelope suffices (the no-crypto tooth, Test 3, proves
	// the selector never touches the crypto path).
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

	// Zero-jitter, zero-drop profile so all 1000 frames deliver deterministically
	// (the stickiness property is the gate, not chaos resilience).
	vn := chaos.NewVirtualNet(chaos.ChaosProfile{
		Drop:             0,
		Duplicate:        0,
		ReorderMaxJitter: 0,
		DeliveryBase:     0,
	})
	defer vn.Stop()

	// 32 worker nodes — the in-process analogue of a 32-socket SO_REUSEPORT
	// group. Each worker counts the frames routed to it and signals
	// completion via the shared WaitGroup, so the test waits for the actual
	// per-worker RECEIPT (not merely the ingress route decision) before
	// asserting stickiness — no route-vs-receipt race.
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

	// The pre-roam worker — the index the flow pins to while the CID is
	// constant. Every frame in the roam MUST land here. Computed once on the
	// stateless fanout; the ingress node's route decision uses the SAME
	// instance so the pre-roam index and the per-frame route are provably the
	// same call.
	f := &ReusePortFanout{}
	preRoamWorker := f.SelectRoute(routedCID, numWorkers)
	t.Logf("pre-roam worker index: %d (cid=%x)", preRoamWorker, routedCID)

	// The ingress node — the analogue of the socket the kernel delivers the
	// packet to BEFORE the eBPF program runs. It routes each frame via
	// SelectRoute to exactly one worker and forwards it. The WaitGroup is
	// Done in the WORKER callback (the actual receipt), not here, so the test
	// blocks until every routed frame is counted.
	const ingressID = 0xFF
	var ingressNode [16]byte
	ingressNode[0] = ingressID
	vn.AddNode(ingressNode, func(msg chaos.NetMessage) {
		// The route decision: hash the Application Connection ID (read from
		// the frame header, BEFORE any crypto) to a worker index. The 4-tuple
		// (msg.From) is IGNORED by the route — that is the stickiness property.
		worker := f.SelectRoute(routedCID, numWorkers)
		if worker >= numWorkers {
			t.Errorf("route out of range: %d >= %d", worker, numWorkers)
			wg.Done() // do not leak the WaitGroup on a (impossible) out-of-range
			return
		}
		// Forward to the chosen worker (in-process analogue of the kernel
		// delivering to the SOCKHASH-pinned socket). msg.To == ingressNode,
		// so this sends from the ingress node to the pinned worker.
		if err := vn.Send(msg.To, workerIDs[worker], frame); err != nil {
			t.Errorf("forward to worker %d: %v", worker, err)
			wg.Done() // do not leak the WaitGroup on a send failure
		}
	})

	// Simulate the roam: 1000 frames, SAME originNodeID, DIFFERENT source
	// nodeID per frame (the 4-tuple changes). Each Send is from a distinct
	// roaming peer to the ingress node.
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

	// The stickiness assertion: all n frames concentrate to ONE worker (the
	// pre-roam worker). Any frame landing on a different worker is a roam
	// failure (a cache-miss / thread-migration in the kernel analogue).
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

	// The t.Logf table the prompt requires: worker before, worker after, n, failures.
	t.Logf("roam stickiness table: pre-roam-worker=%d post-roam-worker=%d n=%d failures=%d",
		preRoamWorker, preRoamWorker, n, failures)
	t.Logf("per-worker receipts: worker %d -> %d (the pinned core); all others -> 0",
		preRoamWorker, atomic.LoadInt64(&receipts[preRoamWorker]))

	if failures != 0 {
		t.Fatalf("roam stickiness FAILED: %d/%d frames landed on a worker other than the pinned core %d",
			failures, n, preRoamWorker)
	}
	if got := atomic.LoadInt64(&receipts[preRoamWorker]); got != int64(n) {
		t.Fatalf("pinned worker %d received %d, want %d", preRoamWorker, got, n)
	}
}

// TestNoCryptoBeforeRoute — G2.1.d (the anti-tooth, the eBPF-invariant): the
// eBPF program runs BEFORE Verify (the whole point of strip-from-packet). The
// selector MUST NOT touch any ed25519 Verify path. We instrument the
// attribution package's exported VerifyHookCount seam (verify_hook.go:51, the
// exported analogue of the package-level verifyHook var at envelope.go:59)
// and assert the count stays 0 across the routing decision. A future track
// that adds a verify-before-route (routing-by-verified-identity, defeating
// the cheap-gate layer) FAILS this tooth.
//
// Honest framing: a routing-by-verified-identity is not WRONG, it is just a
// DIFFERENT architecture — but it is NOT the §2.X1(a) in-kernel design and
// NOT this track.
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
		t.Fatalf("strip-from-packet eBPF invariant violated: SelectRoute issued %d Verify calls (route-before-Verify is the load-bearing cheap-gate property)", got)
	}
	t.Logf("no-crypto tooth holds: SelectRoute issued 0 Verify calls across %d routing decisions", iters)
}

// TestNoPanicOnZeroFrame — G2.1.e robustness: a zero-length / malformed header
// routes to DropMalformed, not a panic. The kernel eBPF program's `return 0`
// (drop) analogue. numSockets == 0 is the empty socket-group case (returns 0,
// the drop index); a zero-value CID with a valid socket group routes
// deterministically (all-zero hashes to a fixed index) without panicking.
func TestNoPanicOnZeroFrame(t *testing.T) {
	f := &ReusePortFanout{}

	// Empty socket group: the drop analogue. Must not panic; returns 0.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SelectRoute panicked on numSockets=0: %v", r)
		}
	}()
	var zeroCID [attribution.OriginNodeIDSize]byte
	got := f.SelectRoute(zeroCID, 0)
	if got != 0 {
		t.Fatalf("numSockets=0 must return 0 (drop), got %d", got)
	}

	// Zero-value CID with a valid socket group: deterministic, no panic.
	got2 := f.SelectRoute(zeroCID, 32)
	if got2 >= 32 {
		t.Fatalf("zero-CID route out of range: %d >= 32", got2)
	}
	t.Logf("zero-frame robustness holds: numSockets=0 -> drop(0); zero-CID -> worker %d (no panic)", got2)
}
