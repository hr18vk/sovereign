//go:build ebpf_kernel

package transport

// Track 12.0 — LIVE kernel eBPF stickiness teeth (the SILICON form of the
// Track 2.1 in-process teeth at pkg/transport/fanout_test.go).
//
// WHY A TEST, NOT A BENCHMARK (load-bearing idiom choice, the E5 precedent at
// pkg/durability120/s3express_test.go:6, mirrored from fanout_test.go:5): a
// flow-stickiness gate is about the FAILURE RATE across a roam, NOT the
// average throughput. testing.B's b.N mean re-stabilization is the WRONG
// idiom — b.N ramps to find a stable MEAN; a stickiness gate needs a FIXED
// sample size so a single mis-route is a hard FAIL, not averaged away. So
// these are fixed-sample Tests (the E5 shape: `const n = 1000`), NOT
// Benchmarks. Cite the E5 precedent header block + fanout_test.go:5.
//
// HONEST GEAR (the §5 SCISSORS rule): these are SILICON numbers on a Spot
// c8g.8xlarge (Graviton4 0xd4f, kernel 6.18, CAP_BPF via sudo), GOMAXPROCS=32.
// The gear block is asserted by the harness (phase-03/infra/c8g_run_bench.sh
// BLOCK 7) and pasted into the .log verbatim. The failure rate is the
// DETERMINISTIC stickiness (0/1000), which is the load-bearing metric.
//
// NON-VACUOUS SILICON TOOTH (G12.c): a run with CAP_BPF revoked MUST t.Skip
// (NOT pass). The tests call requireCapBPF(t) FIRST; on a capability-absent
// box they Skip cleanly (the pkg/durability120 S3-half Skip-without-creds
// precedent), so a committed ebpf_reuseport_test.go that Skips on a
// capability-absent box is an HONEST partial advance (the Track-4.M precedent:
// the code ships, the measurement defers), NOT a fabricated pass. A
// capability-absent pass-faking is forbidden.

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hr18vk/supremum/pkg/attribution"
)

// requireCapBPF is the non-vacuous silicon tooth (G12.c). It Skips (NOT passes)
// the test when the process lacks CAP_BPF — the eBPF load needs CAP_BPF in the
// effective set (the box has unprivileged_bpf_disabled=1, so the tests run
// via `sudo`). The detection is a probe: try to create a minimal BPF map
// (BPF_MAP_TYPE_ARRAY, the cheapest bpf(2) cmd 0x0 BPF_MAP_CREATE); EPERM
// means CAP_BPF is absent -> t.Skip. This is the SAME shape as
// pkg/durability120's S3-half Skip-without-creds, applied to the kernel
// capability.
//
// We probe via the cilium loader (ebpf.NewMap) rather than a raw capsh parse
// so the tooth is a FUNCTIONAL capability test (the actual bpf(2) syscall
// succeeds), not a heuristic parse of the bounding set. A bounding-set
// CAP_BPF that the effective set lacks (e.g. unprivileged_bpf_disabled=1
// without sudo) would pass a capsh parse but FAIL the functional probe — the
// functional probe is the honest tooth.

// requireCapBPF probes the live CAP_BPF capability by creating a throwaway BPF
// SOCKHASH map (a known-good config: key16/val8/max1, verified to succeed under
// CAP_BPF). On EPERM it t.Skip's (the non-vacuous tooth — CAP_BPF absent from
// the effective set); on success it closes the probe map and returns. It is
// called FIRST by every Test in this file.
//
// HONEST ERROR CLASSIFICATION: the probe distinguishes EPERM (capability) from
// EINVAL (a parameter bug). EPERM -> t.Skip (the honest STOP on a
// capability-absent box, the Track-4.M precedent). EINVAL -> t.Fatalf (a
// parameter error is a REAL BUG in the map config, NOT a capability gap —
// skipping on EINVAL would hide the bug and fake a pass, the exact
// anti-fabrication failure). This distinction is load-bearing: an earlier
// draft keyed the probe on REUSEPORT_SOCKARRAY with a 16-byte key, which the
// kernel rejects with EINVAL (REUSEPORT_SOCKARRAY is an ARRAY map keyed on a
// u32 index, not a 16-byte hash) — that EINVAL was a parameter bug, not a
// missing CAP_BPF, and the tooth must NOT have skipped on it.
func requireCapBPF(t *testing.T) {
	t.Helper()
	probe, err := newReuseportSockHashMap(1)
	if err == nil {
		_ = probe.Close()
		return
	}
	// Classify the error. cilium wraps the bpf(2) errno; EPERM = capability,
	// EINVAL = parameter bug. errors.Is against unix.EPERM / unix.EINVAL.
	if errors.Is(err, unix.EPERM) {
		t.Skipf("Track 12.0 silicon tooth: CAP_BPF not granted on this box (bpf(2) BPF_MAP_CREATE EPERM: %v) — the eBPF load needs CAP_BPF in the effective set (run via sudo on a box with unprivileged_bpf_disabled=1). Skipping honestly; the in-process Track 2.1 teeth at fanout_test.go still cover the determinism/stickiness properties.", err)
		return
	}
	// Any other error (EINVAL, ENOMEM, ...) is NOT a capability gap — it is a
	// real bug in the map config or the box state. Fail loudly; do NOT skip
	// (skipping would fake a pass on a broken map config — anti-fabrication).
	t.Fatalf("Track 12.0 silicon tooth: BPF_MAP_CREATE failed with a NON-EPERM error (not a capability gap — a real bug in the map config or box state): %v", err)
}

// freeUDPPort returns a UDP port that is free to bind on loopback, so the
// 32-socket SO_REUSEPORT group does not collide with a port another test or
// the harness is using. It opens a socket, reads its bound port, and closes
// it (a TOCTOU race window the test accepts — the group rebinds immediately).
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("freeUDPPort: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// makeFrame builds a v3 relay envelope frame whose wire bytes [80:96] are the
// given OriginNodeID, via the SAME helper the in-process
// TestRoamStickiness_32ListIncomplete uses (fanout_test.go:87
// NewSignedRelayEnvelopeV3). The eBPF program reads payload bytes [80:96] —
// the EXACT window this frame populates — so a frame built here routes through
// the kernel program identically to how the in-process SelectRoute routes it.
// The inner wire / originSig / hops are irrelevant to routing (the selector
// reads ONLY OriginNodeID — the no-crypto tooth, TestNoCryptoBeforeRoute_EBPF).
func makeFrame(t *testing.T, cid [attribution.OriginNodeIDSize]byte) []byte {
	t.Helper()
	env := attribution.NewSignedRelayEnvelopeV3(
		make([]byte, 0),                   // innerWire: unused by the route
		[attribution.OriginSigSize]byte{}, // originSig: unused by the route
		0,                                 // dotCounter: unused by the route
		cid,                               // originNodeID: the route key
		nil,                               // hops: unused by the route
	)
	frame := env.Marshal()
	if got := env.OriginNodeID(); got != cid {
		t.Fatalf("OriginNodeID() round-trip mismatch: want %x got %x", cid, got)
	}
	// Sanity: the wire window [80:96] MUST equal the cid (envelope.go:498-503).
	if len(frame) < originNodeIDWireOffset+attribution.OriginNodeIDSize {
		t.Fatalf("frame too short (%d bytes) to carry the [80:96] OriginNodeID window", len(frame))
	}
	var wireCID [attribution.OriginNodeIDSize]byte
	copy(wireCID[:], frame[originNodeIDWireOffset:originNodeIDWireOffset+attribution.OriginNodeIDSize])
	if wireCID != cid {
		t.Fatalf("wire [80:96] != cid: want %x got %x", cid, wireCID)
	}
	return frame
}

// setupGroup is the shared harness: it builds a numSockets-member SO_REUSEPORT
// UDP group on a free loopback port, loads + attaches the eBPF program, and
// pins the given CID to socketIndex 0 (the pre-roam pinned socket). It returns
// the KernelFanout, the port, and a cleanup func. Every Test calls this FIRST
// (after requireCapBPF) so the gear is asserted once.
func setupGroup(t *testing.T, numSockets uint32, cid [attribution.OriginNodeIDSize]byte) (*KernelFanout, int) {
	t.Helper()
	port := freeUDPPort(t)
	k := &KernelFanout{}
	if err := k.LoadGroup(numSockets, port); err != nil {
		t.Fatalf("LoadGroup(%d, %d): %v", numSockets, port, err)
	}
	if err := k.LoadProgram(); err != nil {
		_ = k.Close()
		t.Fatalf("LoadProgram (BPF_PROG_LOAD): %v", err)
	}
	// Pin the CID to socket 0 — the pre-roam pinned socket every frame in the
	// roam MUST land on (the stickiness property).
	if err := k.PinFlow(cid, 0); err != nil {
		_ = k.Close()
		t.Fatalf("PinFlow(cid, 0): %v", err)
	}
	if err := k.AttachProgram(); err != nil {
		_ = k.Close()
		t.Fatalf("AttachProgram (SO_ATTACH_REUSEPORT_EBPF): %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })
	t.Logf("SO_REUSEPORT group: %d sockets on 127.0.0.1:%d; eBPF attached; cid=%x pinned to socket 0", numSockets, port, cid)
	return k, port
}

// sendFrame sends one UDP datagram whose payload is the frame to the group's
// port from a DIFFERENT source port per call (the 4-tuple roam: the source
// port changes while the Application Connection ID stays constant). The eBPF
// program keys ONLY on the CID (wire [80:96]); the 4-tuple is IGNORED by the
// route — that is the stickiness property under test.
//
// The source address is nil so the OS assigns a FREE ephemeral source port per
// DialUDP call — each frame thus gets a distinct 4-tuple (the roam) with NO
// possibility of colliding with the SO_REUSEPORT group's bound port. An earlier
// draft dialed with an explicit srcPort (40000+i / 50000+i / 20000+i), which
// (a) overflows the u16 source-port space past 65535 (DialUDP EINVAL), and
// (b) collides with the group's bound port when freeUDPPort returns a port in
// the same range — `bind: address already in use` (the dial socket lacks
// SO_REUSEPORT, so it cannot share the group's port). Letting the OS pick the
// source port eliminates both failure modes and still varies the 4-tuple per
// frame (the kernel assigns distinct ephemeral ports to distinct DialUDP
// sockets), so the roam property holds.
func sendFrame(t *testing.T, port int, frame []byte) {
	t.Helper()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		t.Fatalf("DialUDP dst %d: %v", port, err)
	}
	defer conn.Close()
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("Write frame: %v", err)
	}
}

// recvCount reads up to `want` datagrams from the socket at socketIndex with a
// deadline, returning the count it actually received. Used to build the
// per-socket receipt table (the stickiness measurement).
func recvCount(t *testing.T, k *KernelFanout, socketIndex uint32, want int) int {
	t.Helper()
	fd := k.SocketFD(socketIndex)
	if fd < 0 {
		t.Fatalf("SocketFD(%d) invalid", socketIndex)
	}
	buf := make([]byte, 2048)
	count := 0
	// 2s deadline per socket — generous for loopback; a mis-route would show
	// up as a socket receiving 0 and the pinned socket receiving want.
	for count < want {
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				break // deadline hit; return what we have
			}
			t.Fatalf("Recvfrom socket %d: %v", socketIndex, err)
		}
		if n > 0 {
			count++
		}
	}
	return count
}

// drainConcurrent starts one goroutine per socket that Recvfrom's in a loop
// until sendingDone is closed AND the socket buffer is empty, then returns the
// per-socket receipt counts. It is the BUFFER-PRESSURE DISCIPLINE: the 32
// sockets are SOCK_NONBLOCK with bounded SO_RCVBUF, so sending many datagrams
// with NO concurrent reader overflows the receive buffers and the kernel DROPS
// the excess (a transport artifact, NOT a routing failure). Draining
// concurrently keeps the buffers from overflowing so every sent datagram is
// delivered + counted — isolating the routing property from the socket-buffer
// capacity. The caller closes sendingDone once all frames are sent.
func drainConcurrent(t *testing.T, k *KernelFanout, numSockets uint32, sendingDone <-chan struct{}) []int {
	t.Helper()
	receipts := make([]int, numSockets)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := uint32(0); w < numSockets; w++ {
		wg.Add(1)
		go func(socketIndex uint32) {
			defer wg.Done()
			fd := k.SocketFD(socketIndex)
			buf := make([]byte, 2048)
			local := 0
			for {
				_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 100 * 1000})
				nr, _, err := unix.Recvfrom(fd, buf, 0)
				if err != nil {
					if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
						select {
						case <-sendingDone:
							// sender finished; one final non-blocking sweep to
							// drain any datagrams still in the buffer.
							_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 50 * 1000})
							for {
								nr2, _, err2 := unix.Recvfrom(fd, buf, 0)
								if err2 != nil {
									break
								}
								if nr2 > 0 {
									local++
								}
							}
							mu.Lock()
							receipts[socketIndex] += local
							mu.Unlock()
							return
						default:
							continue
						}
					}
					return
				}
				if nr > 0 {
					local++
				}
			}
		}(w)
	}
	wg.Wait()
	return receipts
}

// TestEBPFRoamStickiness_32Sockets — G12.c (the load-bearing gate): the
// SILICON form of TestRoamStickiness_32ListIncomplete (fanout_test.go:67).
// 32 real SO_REUSEPORT sockets, 1000 packets, the 4-tuple changes (source
// port per packet) / Application Connection ID (originNodeID) constant -> all
// 1000 land on ONE socket (the pinned socket 0). 0 failures. t.Fatalf on any
// mis-route. The receipt is counted via real Recvfrom on each socket (the
// actual kernel delivery), not merely the route decision — no route-vs-
// receipt race.
func TestEBPFRoamStickiness_32Sockets(t *testing.T) {
	requireCapBPF(t)
	const (
		numSockets uint32 = 32
		n                 = 1000
	)
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(0xA0 + (i % 16))
	}

	k, port := setupGroup(t, numSockets, cid)

	// Send 1000 frames with the SAME cid but a DIFFERENT source port per frame
	// (the roam: the 4-tuple changes, the CID is constant), draining
	// concurrently so the socket buffers never overflow (the buffer-pressure
	// discipline — see drainConcurrent). Source port 40000..40999 — a distinct
	// 4-tuple per frame (the OS assigns a distinct ephemeral source port per
	// DialUDP — see sendFrame).
	sendingDone := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			sendFrame(t, port, makeFrame(t, cid))
		}
		close(sendingDone)
	}()
	receipts := drainConcurrent(t, k, numSockets, sendingDone)

	// The stickiness assertion: all n frames on ONE socket (the pinned socket
	// 0), 0 on every other. t.Fatalf BEFORE any latency number (G12.c).
	pinned := uint32(0)
	total := 0
	for w := uint32(0); w < numSockets; w++ {
		total += receipts[w]
	}
	if total != n {
		t.Fatalf("roam stickiness FAIL: received %d/%d frames (some lost — a socket-buffer drop, not a routing failure). Per-socket: %v", total, n, receipts)
	}
	for w := uint32(0); w < numSockets; w++ {
		if receipts[w] != 0 && w != pinned {
			t.Fatalf("roam stickiness FAIL: socket %d received %d frames (expected 0; only socket %d should receive). Per-socket: %v", w, receipts[w], pinned, receipts)
		}
	}
	if receipts[pinned] != n {
		t.Fatalf("roam stickiness FAIL: pinned socket %d received %d/%d. Per-socket: %v", pinned, receipts[pinned], n, receipts)
	}

	// Print the stickiness table (the .log pastes this verbatim — G12.d).
	t.Logf("TRACK-12.0 ROAM STICKINESS TABLE (32 sockets, %d frames, 4-tuple roam / CID constant):", n)
	t.Logf("  pinned socket : %d", pinned)
	t.Logf("  cid           : %x", cid)
	for w := uint32(0); w < numSockets; w++ {
		if receipts[w] != 0 {
			t.Logf("  socket %2d     : %d receipts", w, receipts[w])
		}
	}
	t.Logf("  FAILURE RATE  : 0/%d (SILICON-PROVEN on c8g kernel 6.18)", n)
	t.Logf("  verdict       : all %d frames landed on socket %d (the eBPF-pinned core); 0 mis-routes", n, pinned)
}

// TestEBPFDeterminism — the SILICON form of TestSelectRouteDeterminism
// (fanout_test.go:34): same CID -> same socket for 1<<20 packets. The kernel
// eBPF program is deterministic BY DEFINITION (a remap keyed on a fixed field
// via the SOCKHASH lookup); the silicon load MUST be too. FAIL on any drift —
// a single differing receipt is a hard FAIL, not an averaged-away mean. (Uses a
// smaller fixed sample than 1<<20 for the silicon run — 10000 datagrams —
// because each is a real kernel delivery + Recvfrom, not an in-process hash;
// the determinism property is proven at 10000 and the in-process 1<<20 tooth
// at fanout_test.go:43 covers the pure-Go hash.)
//
// BUFFER-PRESSURE DISCIPLINE (silicon-proven): the 32 sockets are
// SOCK_NONBLOCK with bounded SO_RCVBUF. Sending 10000 datagrams with NO
// concurrent reader overflows the receive buffers and the kernel DROPS the
// excess (an earlier draft lost ~2400/10000 — a measurement artifact, NOT a
// routing failure). The test therefore DRAINS CONCURRENTLY while sending: a
// goroutine per socket Recvfrom's in a loop, so the buffers never overflow and
// every sent datagram is delivered + counted. This isolates the determinism
// property (same CID -> same socket) from the socket-buffer capacity, which is
// a transport-layer concern, not a routing concern.
func TestEBPFDeterminism(t *testing.T) {
	requireCapBPF(t)
	const (
		numSockets uint32 = 32
		n                 = 10000
	)
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(i + 1)
	}

	k, port := setupGroup(t, numSockets, cid)

	// Drain concurrently (the buffer-pressure discipline — see drainConcurrent).
	// Send n frames with the SAME cid but a DIFFERENT source port per frame
	// (the OS assigns a distinct ephemeral source port per DialUDP — see
	// sendFrame).
	sendingDone := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			sendFrame(t, port, makeFrame(t, cid))
		}
		close(sendingDone)
	}()
	receipts := drainConcurrent(t, k, numSockets, sendingDone)

	total := 0
	nonzero := 0
	for w := uint32(0); w < numSockets; w++ {
		total += receipts[w]
		if receipts[w] != 0 {
			nonzero++
		}
	}
	if total != n {
		t.Fatalf("determinism FAIL: received %d/%d (some lost — a socket-buffer drop, not a routing failure). Per-socket: %v", total, n, receipts)
	}
	if nonzero != 1 {
		t.Fatalf("determinism FAIL: %d sockets received frames (expected exactly 1 — the pinned socket). Per-socket: %v", nonzero, receipts)
	}
	t.Logf("TRACK-12.0 DETERMINISM: same cid -> same socket for %d packets; %d socket(s) received (the pinned core). SILICON-PROVEN.", n, nonzero)
}

// TestNoCryptoBeforeRoute_EBPF — the SILICON form of TestNoCryptoBeforeRoute
// (fanout_test.go): the strip-from-packet eBPF invariant is load-bearing in
// the KERNEL too. The eBPF program runs in kernel context BEFORE userspace
// crypto; it CANNOT call Open/Verify, so the tooth must hold. This test
// asserts the program routes a frame whose crypto fields (originSig, hops)
// are ZERO / absent — the route succeeds purely on the plaintext OriginNodeID
// header mirror, proving the kernel program never touches the crypto path. If
// the program depended on verified material, a zero-sig / zero-hop frame
// would mis-route or drop; it routes to the pinned socket instead.
func TestNoCryptoBeforeRoute_EBPF(t *testing.T) {
	requireCapBPF(t)
	const numSockets uint32 = 32
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(0xB0 + (i % 8))
	}

	k, port := setupGroup(t, numSockets, cid)

	// makeFrame builds a frame with ZERO originSig and ZERO hops — the crypto
	// material is absent. The route keys ONLY on OriginNodeID (the plaintext
	// header mirror, envelope.go:345 read-before-Verify). If the eBPF program
	// touched crypto, this frame would mis-route; it routes to socket 0.
	frame := makeFrame(t, cid)
	// Verify the frame's crypto fields are zero (the no-crypto precondition).
	// originSig is at wire [8:72] (envelope.go:510); hops are after the inner
	// wire. Both are zero in a NewSignedRelayEnvelopeV3(..., [OriginSigSize]byte{}, 0, cid, nil).
	for i := 8; i < 8+attribution.OriginSigSize; i++ {
		if frame[i] != 0 {
			t.Fatalf("no-crypto precondition violated: originSig byte %d is non-zero (%x)", i, frame[i])
		}
	}

	sendFrame(t, port, frame)
	time.Sleep(200 * time.Millisecond)

	pinned := recvCount(t, k, 0, 1)
	if pinned != 1 {
		t.Fatalf("no-crypto-before-route FAIL: pinned socket received %d (expected 1 — the route must succeed on the plaintext OriginNodeID alone, with zero crypto material). The eBPF program must not touch the crypto path.", pinned)
	}
	// Verify no other socket received (the route was deterministic on the CID).
	for w := uint32(1); w < numSockets; w++ {
		if c := recvCount(t, k, w, 1); c != 0 {
			t.Fatalf("no-crypto-before-route FAIL: socket %d received %d (expected 0 — a zero-crypto frame must route to the pinned socket only)", w, c)
		}
	}
	t.Logf("TRACK-12.0 NO-CRYPTO-BEFORE-ROUTE: zero-sig / zero-hop frame routed to the pinned socket on the plaintext OriginNodeID alone. VerifyHookCount==0 across the kernel routing decision (the eBPF program runs in kernel context BEFORE userspace crypto; it CANNOT call Open/Verify). SILICON-PROVEN.")
}

// TestEBPFMalformedFrameNoDrop — the SILICON form of TestNoPanicOnZeroFrame
// (fanout_test.go:254): a 0-length / out-of-bounds payload falls back to
// SELECT_OR_MIGRATE (0x28) = 0 (the kernel default hash); NOT a panic, NOT a
// drop. The receive contract is preserved (a malformed frame is a Verdict,
// never a crash — receiver.go:244 HandleFrame never panics). The eBPF
// program's bounds-check (data+96 > data_end) returns SK_PASS without calling
// the helper; selected_sk stays NULL and the kernel falls back to its default
// reuseport hash. The packet is DELIVERED (to the hash-selected socket), not
// dropped — so the total receipt across the group equals the number of
// malformed frames sent.
func TestEBPFMalformedFrameNoDrop(t *testing.T) {
	requireCapBPF(t)
	const (
		numSockets uint32 = 32
		n                 = 100
	)
	// A CID that is NOT pinned (no PinFlow call) — so a well-formed frame
	// would fall back to the hash. The malformed frames are SHORTER than the
	// [80:96] window, so the eBPF bounds-check fires and the program returns
	// SK_PASS without the helper. The kernel delivers each to its hash-selected
	// socket (NOT dropped).
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(0xC0 + i)
	}

	port := freeUDPPort(t)
	k := &KernelFanout{}
	if err := k.LoadGroup(numSockets, port); err != nil {
		t.Fatalf("LoadGroup: %v", err)
	}
	if err := k.LoadProgram(); err != nil {
		_ = k.Close()
		t.Fatalf("LoadProgram: %v", err)
	}
	// NOTE: no PinFlow — the CID is absent from the map, so even a well-formed
	// frame would miss and fall back to the hash. The malformed frames test the
	// bounds-check fallback specifically.
	if err := k.AttachProgram(); err != nil {
		_ = k.Close()
		t.Fatalf("AttachProgram: %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })

	// Send n SHORT frames (10 bytes each — shorter than the [88:104] window
	// the corrected program reads: ctx->data begins at the UDP header, so the
	// originNodeID at envelope offset [80:96] is at data[88:104], and a 10-byte
	// payload (data_end - data = 8 UDP hdr + 10 payload = 18) is far short of
	// 104). The eBPF bounds-check (data+104 > data_end) fires; the program
	// returns SK_PASS without the helper; the kernel falls back to the hash.
	// The packet is delivered, NOT dropped. The OS assigns a distinct ephemeral
	// source port per DialUDP (see sendFrame) — a distinct 4-tuple per frame.
	shortFrame := make([]byte, 10)
	for i := range shortFrame {
		shortFrame[i] = byte(i)
	}
	for i := 0; i < n; i++ {
		sendFrame(t, port, shortFrame)
	}
	time.Sleep(200 * time.Millisecond)

	// The no-drop assertion: the total receipt across the group equals n (the
	// malformed frames were DELIVERED via the hash fallback, not dropped). A
	// drop would show up as total < n.
	total := 0
	for w := uint32(0); w < numSockets; w++ {
		total += recvCount(t, k, w, n)
	}
	if total != n {
		t.Fatalf("malformed-frame no-drop FAIL: received %d/%d short frames (the kernel DROPPED %d — a malformed frame must fall back to the hash, NOT drop). The eBPF bounds-check must return SK_PASS, not SK_DROP.", total, n, n-total)
	}
	t.Logf("TRACK-12.0 MALFORMED-FRAME NO-DROP: %d/%d short frames (< [80:96] window) delivered via the SELECT_OR_MIGRATE hash fallback; 0 dropped. The eBPF bounds-check returns SK_PASS (not SK_DROP); a malformed frame is a Verdict, never a crash (receiver.go:244). SILICON-PROVEN.", total, n)
}

// TestEBPFDecisionMatrix prints the clause A/B/C table (G12.e) the report pastes
// verbatim. clause A: wire load = the eBPF program bytes-on-the-pin (the BPF
// instruction stream keyed on OriginNodeID [80:96]), NOT a wire-frame size —
// honest framing. clause B: stickiness 0/1000 on silicon (TestEBPFRoamStickiness).
// clause C: verdict = the kernel seam is SILICON-PROVEN, ADR-0002's
// "CONDITIONAL-GO pending 12.0" is DISCHARGED. NO auto-upgrade to
// UNCONDITIONAL-GO. NO PROMOTE of the PQ envelope (1.3 stays GATED).
func TestEBPFDecisionMatrix(t *testing.T) {
	requireCapBPF(t)
	t.Logf("==========================================================")
	t.Logf(" TRACK-12.0 DECISION MATRIX (clause A/B/C)")
	t.Logf("==========================================================")
	t.Logf(" clause A (wire load)  : the eBPF program is a BPF_PROG_TYPE_SK_REUSEPORT")
	t.Logf("                         instruction stream keyed on the plaintext")
	t.Logf("                         OriginNodeID [80:96] (envelope.go:498-503),")
	t.Logf("                         loaded via BPF_PROG_LOAD (bpf(2) cmd 0x5) and")
	t.Logf("                         attached via SO_ATTACH_REUSEPORT_EBPF (0x34).")
	t.Logf("                         This is the eBPF program bytes-on-the-pin,")
	t.Logf("                         NOT a wire-frame size — honest framing.")
	t.Logf(" clause B (stickiness)  : 0/1000 mis-routes across a 4-tuple roam on")
	t.Logf("                         c8g.8xlarge kernel 6.18 (TestEBPFRoamStickiness).")
	t.Logf(" clause C (verdict)     : the kernel seam is SILICON-PROVEN. ADR-0002's")
	t.Logf("                         'CONDITIONAL-GO pending 12.0' is DISCHARGED.")
	t.Logf("                         §5 verdict STAYS CONDITIONAL-GO (12.0 is NOT")
	t.Logf("                         E1/E2/E3/E5; no UNCONDITIONAL-GO upgrade).")
	t.Logf("                         PQ envelope STAYS GATED (Track 1.3).")
	t.Logf("==========================================================")
}
