// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build ebpf_kernel

package transport

// These tests exercise eBPF SO_REUSEPORT routing on Linux, complementing the
// in-process tests in fanout_test.go. They use fixed sample sizes because one
// mis-routed datagram fails the flow-affinity property; averaging throughput
// samples would hide that failure.
//
// Each test first probes BPF_MAP_CREATE. Tests skip when the process lacks
// CAP_BPF, so an unprivileged run does not claim kernel coverage.

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hr18vk/sovereign/pkg/attribution"
)

// requireCapBPF probes CAP_BPF by creating the same kind of SOCKHASH map used
// by KernelFanout. A successful probe is closed immediately. EPERM skips the
// calling test; other errors fail it because they indicate an invalid map or
// host configuration rather than a missing capability. The functional probe
// checks the effective capability instead of inferring it from process state.
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
		t.Skipf("CAP_BPF is unavailable (bpf(2) BPF_MAP_CREATE: %v); skipping kernel tests, while fanout_test.go still covers the Go selector", err)
		return
	}
	// Errors other than EPERM indicate a bad map or host configuration, not a
	// missing capability, so they must not be hidden by a skip.
	t.Fatalf("BPF_MAP_CREATE failed for a reason other than missing CAP_BPF: %v", err)
}

// freeUDPPort reserves a kernel-assigned loopback UDP port and releases it for
// the socket group. Another process could claim the port before the group
// binds; the subsequent bind reports that collision.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("freeUDPPort: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// makeFrame builds a v3 relay envelope with cid at wire bytes [80:96]. The
// inner wire, signature, and hops stay empty because routing uses only the
// plaintext connection ID. The test also checks the encoded offset.
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
	// Sanity: the wire window [80:96] equals the cid (envelope.go: OriginNodeID wire offset).
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

// setupGroup creates a SO_REUSEPORT group on an ephemeral port, loads and
// attaches the program, and pins cid to socket 0. It registers cleanup and
// returns the group and its bound port.
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
	// roam must land on (the stickiness property).
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

// sendFrame writes one datagram through a fresh UDP socket. The kernel selects
// its ephemeral source port, allowing the network 4-tuple to vary while the
// Application Connection ID in frame stays fixed.
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

// recvCount reads at most want datagrams from socketIndex. A receive timeout
// ends the count, producing the per-socket totals used by the routing checks.
func recvCount(t *testing.T, k *KernelFanout, socketIndex uint32, want int) int {
	t.Helper()
	fd := k.SocketFD(socketIndex)
	if fd < 0 {
		t.Fatalf("SocketFD(%d) invalid", socketIndex)
	}
	buf := make([]byte, 2048)
	count := 0
	// Stop waiting after two seconds when a socket has no more datagrams.
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

// drainConcurrent reads every socket while the sender runs, limiting receive
// buffer pressure that could otherwise cause datagram loss. After sendingDone
// closes, each reader makes a final non-blocking pass and reports its total.
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

// TestEBPFRoamStickiness_32Sockets sends 1,000 frames with one connection ID
// through fresh UDP sockets. All datagrams must arrive on pinned socket 0 of
// the 32-socket group; any receipt elsewhere fails flow affinity.
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

	// Each send uses a fresh UDP socket while cid remains constant. Drain all
	// sockets concurrently to keep buffer pressure out of the routing check.
	sendingDone := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			sendFrame(t, port, makeFrame(t, cid))
		}
		close(sendingDone)
	}()
	receipts := drainConcurrent(t, k, numSockets, sendingDone)

	// Every datagram must arrive, and only the pinned socket may receive one.
	pinned := uint32(0)
	total := 0
	for w := uint32(0); w < numSockets; w++ {
		total += receipts[w]
	}
	if total != n {
		t.Fatalf("roam stickiness: received %d/%d frames; per-socket receipts: %v", total, n, receipts)
	}
	for w := uint32(0); w < numSockets; w++ {
		if receipts[w] != 0 && w != pinned {
			t.Fatalf("roam stickiness: socket %d received %d frames, want 0 (only socket %d may receive); per-socket receipts: %v", w, receipts[w], pinned, receipts)
		}
	}
	if receipts[pinned] != n {
		t.Fatalf("roam stickiness: pinned socket %d received %d/%d frames; per-socket receipts: %v", pinned, receipts[pinned], n, receipts)
	}

	// Report nonzero receipts after the assertions have established the totals.
	t.Logf("roam stickiness table (32 sockets, %d frames, 4-tuple roam with constant CID):", n)
	t.Logf("  pinned socket: %d", pinned)
	t.Logf("  cid: %x", cid)
	for w := uint32(0); w < numSockets; w++ {
		if receipts[w] != 0 {
			t.Logf("  socket %d: %d receipts", w, receipts[w])
		}
	}
	t.Logf("  mis-routes: 0/%d", n)
	t.Logf("  all %d frames landed on eBPF-pinned socket %d", n, pinned)
}

// TestEBPFDeterminism sends 10,000 datagrams with one connection ID and checks
// that exactly one socket receives them. Concurrent draining reduces loss from
// bounded socket receive buffers; a short total still fails the test.
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

	// Use fresh UDP sockets for the sends and drain every group member.
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
		t.Fatalf("determinism: received %d/%d frames; per-socket receipts: %v", total, n, receipts)
	}
	if nonzero != 1 {
		t.Fatalf("determinism: %d sockets received frames, want exactly 1; per-socket receipts: %v", nonzero, receipts)
	}
	t.Logf("determinism: same cid -> same socket for %d packets; %d socket(s) received", n, nonzero)
}

// TestNoCryptoBeforeRoute_EBPF checks that a frame with an empty signature and
// no hops reaches its pinned socket using only the plaintext OriginNodeID.
func TestNoCryptoBeforeRoute_EBPF(t *testing.T) {
	requireCapBPF(t)
	const numSockets uint32 = 32
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(0xB0 + (i % 8))
	}

	k, port := setupGroup(t, numSockets, cid)

	frame := makeFrame(t, cid)
	// Confirm crypto fields are zeroed: originSig spans [8:72] per envelope.go.
	for i := 8; i < 8+attribution.OriginSigSize; i++ {
		if frame[i] != 0 {
			t.Fatalf("no-crypto precondition violated: originSig byte %d is non-zero (%x)", i, frame[i])
		}
	}

	sendFrame(t, port, frame)
	time.Sleep(200 * time.Millisecond)

	pinned := recvCount(t, k, 0, 1)
	if pinned != 1 {
		t.Fatalf("no-crypto routing: pinned socket received %d frames, want 1", pinned)
	}
	for w := uint32(1); w < numSockets; w++ {
		if c := recvCount(t, k, w, 1); c != 0 {
			t.Fatalf("no-crypto routing: socket %d received %d frames, want 0", w, c)
		}
	}
	t.Logf("no-crypto-before-route: zero-sig / zero-hop frame routed to pinned socket on plaintext OriginNodeID alone")
}

// TestEBPFMalformedFrameNoDrop sends payloads too short to contain data[88:104].
// The program must skip its lookup, return SK_PASS, and let the kernel hash
// deliver every datagram instead of dropping it.
func TestEBPFMalformedFrameNoDrop(t *testing.T) {
	requireCapBPF(t)
	const (
		numSockets uint32 = 32
		n                 = 100
	)
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
	// Leave the map empty to isolate the short-frame bounds-check fallback.
	if err := k.AttachProgram(); err != nil {
		_ = k.Close()
		t.Fatalf("AttachProgram: %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })

	// Eight UDP-header bytes plus a 10-byte payload leave data+104 beyond
	// data_end, forcing the SK_PASS fallback.
	shortFrame := make([]byte, 10)
	for i := range shortFrame {
		shortFrame[i] = byte(i)
	}
	for i := 0; i < n; i++ {
		sendFrame(t, port, shortFrame)
	}
	time.Sleep(200 * time.Millisecond)

	total := 0
	for w := uint32(0); w < numSockets; w++ {
		total += recvCount(t, k, w, n)
	}
	if total != n {
		t.Fatalf("short-frame delivery: received %d/%d frames, lost %d; bounds check must return SK_PASS", total, n, n-total)
	}
	t.Logf("short-frame delivery: %d/%d frames delivered through the kernel hash fallback", total, n)
}

// TestEBPFDecisionMatrix logs the kernel routing configuration and its build
// constraint. TestEBPFRoamStickiness_32Sockets records per-run receipt counts.
func TestEBPFDecisionMatrix(t *testing.T) {
	requireCapBPF(t)
	t.Logf("==========================================================")
	t.Logf(" kernel reuseport fanout summary (ADR-0002 / ADR-0003)")
	t.Logf("==========================================================")
	t.Logf(" wire field    : BPF_PROG_TYPE_SK_REUSEPORT reads plaintext")
	t.Logf("                 OriginNodeID at envelope [80:96] (data[88:104]),")
	t.Logf("                 matching the ReusePortFanout connection ID.")
	t.Logf("                 loaded via BPF_PROG_LOAD and")
	t.Logf("                 attached via SO_ATTACH_REUSEPORT_EBPF.")
	t.Logf("                 The program is loaded into the kernel;")
	t.Logf("                 these entries do not describe a wire-frame size.")
	t.Logf(" flow affinity : see TestEBPFRoamStickiness_32Sockets")
	t.Logf("                 for this run's per-socket receipt counts.")
	t.Logf(" build         : included only with -tags ebpf_kernel;")
	t.Logf("                 the in-process selector is tested separately.")
	t.Logf("                 Hybrid TLS KEM reporting is configured independently.")
	t.Logf("                 KernelFanout is referenced by ebpf-tagged receive code")
	t.Logf("                 and tests, not by non-tagged production code.")
	t.Logf("==========================================================")
}
