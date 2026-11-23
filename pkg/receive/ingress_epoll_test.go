// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build ebpf_kernel

package receive

// These Linux-specific tests exercise EpollIngress with real SO_REUSEPORT
// sockets and an attached eBPF selector. They cover frame delivery, delivery
// with the selector detached, and optional non-loopback binding.
//
// Tests require CAP_BPF. requireCapBPF skips only when the kernel denies the
// capability probe with EPERM; other probe failures indicate a broken test
// environment or invalid map configuration and fail the test.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/hr18vk/sovereign/pkg/attribution"
	"github.com/hr18vk/sovereign/pkg/transport"
	"golang.org/x/sys/unix"
)

// originNodeIDWireOffset locates OriginNodeID in a v3 envelope. The selector
// reads the corresponding bytes after the 8-byte UDP header.
const originNodeIDWireOffset = 80

// requireCapBPF attempts the same SOCKHASH map creation used by the kernel
// fanout. EPERM skips the calling test or benchmark; every other error fails.
func requireCapBPF(tb testing.TB) {
	tb.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.SockHash,
		KeySize:    16,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err == nil {
		_ = m.Close()
		return
	}
	if errors.Is(err, unix.EPERM) {
		tb.Skipf("CAP_BPF unavailable: BPF_MAP_CREATE returned EPERM: %v; in-process fanout tests still cover routing", err)
		return
	}
	tb.Fatalf("BPF_MAP_CREATE failed for a reason other than missing CAP_BPF: %v", err)
}

// freeUDPPort returns a UDP port that is free to bind on the given IP, so the
// 32-socket SO_REUSEPORT group does not collide with a port another test or the
// harness is using. It opens a socket, reads its bound port, and closes it (a
// TOCTOU race window the test accepts — the group rebinds immediately).
func freeUDPPort(t testing.TB, bindIP [4]byte) int {
	t.Helper()
	var ip net.IP
	if bindIP == [4]byte{} {
		ip = net.IPv4(127, 0, 0, 1)
	} else {
		ip = net.IPv4(bindIP[0], bindIP[1], bindIP[2], bindIP[3])
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Fatalf("freeUDPPort: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// makeFrame builds a v3 envelope with cid in the OriginNodeID bytes read by
// the eBPF selector. Routing does not inspect the inner wire, signature, or
// hops, so those fields can remain empty.
func makeFrame(t testing.TB, cid [attribution.OriginNodeIDSize]byte) []byte {
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
	// Check the selector's view of the marshaled bytes.
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

// lengthPrefixFrame adds the outer framing expected by FrameReader and
// EpollIngress.deliverDatagram.
func lengthPrefixFrame(envelopeBytes []byte) []byte {
	out := make([]byte, frameLenPrefixSize+len(envelopeBytes))
	binary.BigEndian.PutUint32(out[:frameLenPrefixSize], uint32(len(envelopeBytes)))
	copy(out[frameLenPrefixSize:], envelopeBytes)
	return out
}

// setupGroup creates a UDP fanout group, loads and attaches its eBPF selector,
// and pins cid to socket zero. A zero bindIP selects the loopback default used
// by freeUDPPort; a non-zero value selects a specific interface address.
func setupGroup(t testing.TB, numSockets uint32, cid [attribution.OriginNodeIDSize]byte, bindIP [4]byte) (*transport.KernelFanout, int, func()) {
	t.Helper()
	port := freeUDPPort(t, bindIP)
	k := &transport.KernelFanout{}
	if err := k.LoadGroupOnIP(numSockets, port, bindIP); err != nil {
		t.Fatalf("LoadGroupOnIP(%d, %d, %v): %v", numSockets, port, bindIP, err)
	}
	if err := k.LoadProgram(); err != nil {
		t.Fatalf("LoadProgram (BPF_PROG_LOAD): %v", err)
	}
	if err := k.PinFlow(cid, 0); err != nil {
		t.Fatalf("PinFlow(cid, 0): %v", err)
	}
	if err := k.AttachProgram(); err != nil {
		t.Fatalf("AttachProgram (SO_ATTACH_REUSEPORT_EBPF): %v", err)
	}
	cleanup := func() {
		_ = k.Close()
	}
	if bindIP == [4]byte{} {
		t.Logf("SO_REUSEPORT group: %d sockets on 127.0.0.1:%d; eBPF attached; cid=%x pinned to socket 0", numSockets, port, cid)
	} else {
		t.Logf("SO_REUSEPORT group: %d sockets on %d.%d.%d.%d:%d; eBPF attached; cid=%x pinned to socket 0", numSockets, bindIP[0], bindIP[1], bindIP[2], bindIP[3], port, cid)
	}
	return k, port, cleanup
}

// setupGroupWithMapSize creates an attached group whose SOCKHASH map can hold
// the benchmark's full CID churn set. The default map size only accommodates
// the socket count, so it would reject additional PinFlow entries with E2BIG.
func setupGroupWithMapSize(t testing.TB, numSockets uint32, mapMaxEntries uint32, bindIP [4]byte) (*transport.KernelFanout, int, func()) {
	t.Helper()
	port := freeUDPPort(t, bindIP)
	k := &transport.KernelFanout{}
	if err := k.LoadGroupOnIP(numSockets, port, bindIP); err != nil {
		t.Fatalf("LoadGroupOnIP(%d, %d, %v): %v", numSockets, port, bindIP, err)
	}
	if err := k.LoadProgramWithMapSize(mapMaxEntries); err != nil {
		t.Fatalf("LoadProgramWithMapSize(%d) (BPF_PROG_LOAD): %v", mapMaxEntries, err)
	}
	if err := k.AttachProgram(); err != nil {
		t.Fatalf("AttachProgram (SO_ATTACH_REUSEPORT_EBPF): %v", err)
	}
	cleanup := func() {
		_ = k.Close()
	}
	if bindIP == [4]byte{} {
		t.Logf("SO_REUSEPORT group: %d sockets on 127.0.0.1:%d; eBPF attached; map MaxEntries=%d", numSockets, port, mapMaxEntries)
	} else {
		t.Logf("SO_REUSEPORT group: %d sockets on %d.%d.%d.%d:%d; eBPF attached; map MaxEntries=%d", numSockets, bindIP[0], bindIP[1], bindIP[2], bindIP[3], port, mapMaxEntries)
	}
	return k, port, cleanup
}

// sendFrame sends a single length-prefixed frame to the given port on the given
// IP (loopback or real NIC). It uses net.DialUDP so the kernel assigns a
// distinct ephemeral source port per call (the 4-tuple roam property).
func sendFrame(t testing.TB, ip net.IP, port int, frame []byte) {
	t.Helper()
	dst := &net.UDPAddr{IP: ip, Port: port}
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		t.Fatalf("DialUDP dst %s:%d: %v", ip, port, err)
	}
	defer conn.Close()
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("Write frame: %v", err)
	}
}

// recvCount reads up to `want` datagrams from the socket at socketIndex with a
// deadline, returning the count it actually received. Used to build the
// per-socket receipt table (the stickiness measurement).
func recvCount(t testing.TB, k *transport.KernelFanout, socketIndex uint32, want int) int {
	t.Helper()
	fd := k.SocketFD(socketIndex)
	if fd < 0 {
		t.Fatalf("SocketFD(%d) invalid", socketIndex)
	}
	buf := make([]byte, 2048)
	count := 0
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

// TestEBPFEpollIngress_DeliveryWiring sends a valid length-prefixed envelope
// through a 32-socket group and verifies that the epoll loop delivers it to
// HandleFrame.
func TestEBPFEpollIngress_DeliveryWiring(t *testing.T) {
	requireCapBPF(t)

	const numSockets = 32
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(i + 0x10)
	}

	k, port, cleanup := setupGroup(t, numSockets, cid, [4]byte{})
	defer cleanup()

	// Build a real signed envelope that passes HandleFrame's gates (so the
	// delivery count is meaningful, not just a DropMalformed).
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, 7)
	env, originPub, _ := relayChain(t, innerWire, 1, 1_700_000_000_000_000)
	frame := lengthPrefixFrame(env.Marshal())

	// Register the origin so the delivery reaches a valid receive pipeline.
	r, sc, dir, engine := setupReceiver(t, 1_700_000_000_000_000, 1_000_000_000, originPub)
	_ = sc
	_ = dir
	_ = engine

	// Start the EpollIngress loop in a goroutine.
	ingress := NewEpollIngress(k, r)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = ingress.Serve()
	}()

	// Give the loop time to EpollCtl-ADD the 32 fds and enter EpollWait.
	time.Sleep(50 * time.Millisecond)

	// Send one frame to the group (loopback).
	sendFrame(t, net.IPv4(127, 0, 0, 1), port, frame)

	// Wait for the loop to process it (Frames() increments).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ingress.Frames() >= 1 {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	ingress.Shutdown()
	wg.Wait()

	if ingress.Frames() != 1 {
		t.Fatalf("delivery wiring: got %d frames, want 1", ingress.Frames())
	}
	t.Logf("delivery wiring: one frame sent and %d delivered", ingress.Frames())
}

// TestEBPFEpollIngress_AttachVsDetach_AntiCorrelation checks that delivery
// works both with eBPF steering and with kernel hash fallback. Per-socket
// routing is covered separately by the transport fanout tests.
func TestEBPFEpollIngress_AttachVsDetach_AntiCorrelation(t *testing.T) {
	requireCapBPF(t)

	const numSockets = 32
	const nFrames = 1000
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(i + 0x20)
	}

	// First deliver with the eBPF selector attached.
	k, port, cleanup := setupGroup(t, numSockets, cid, [4]byte{})
	defer cleanup()

	// Build frames that pass HandleFrame (so delivery counts are meaningful).
	innerWire := buildCRDTDeltaWire(t, rcvEntityID, 7)
	env, originPub, _ := relayChain(t, innerWire, 1, 1_700_000_000_000_000)
	frame := lengthPrefixFrame(env.Marshal())

	r, sc, dir, engine := setupReceiver(t, 1_700_000_000_000_000, 1_000_000_000, originPub)
	_ = sc
	_ = dir
	_ = engine

	ingress := NewEpollIngress(k, r)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = ingress.Serve()
	}()
	time.Sleep(50 * time.Millisecond)

	// Send N frames (4-tuple roam: each DialUDP gets a new ephemeral port).
	for i := 0; i < nFrames; i++ {
		sendFrame(t, net.IPv4(127, 0, 0, 1), port, frame)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ingress.Frames() >= uint64(nFrames) {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	attachedFrames := ingress.Frames()
	ingress.Shutdown()
	wg.Wait()

	// Repeat with a fresh socket group and no eBPF selector, leaving kernel
	// hash fallback responsible for delivery.
	k2, port2, cleanup2 := setupGroup(t, numSockets, cid, [4]byte{})
	defer cleanup2()

	if err := k2.DetachProgram(); err != nil {
		t.Fatalf("DetachProgram: %v", err)
	}

	r2, sc2, dir2, engine2 := setupReceiver(t, 1_700_000_000_000_000, 1_000_000_000, originPub)
	_ = sc2
	_ = dir2
	_ = engine2

	ingress2 := NewEpollIngress(k2, r2)
	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		_ = ingress2.Serve()
	}()
	time.Sleep(50 * time.Millisecond)

	for i := 0; i < nFrames; i++ {
		sendFrame(t, net.IPv4(127, 0, 0, 1), port2, frame)
	}

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ingress2.Frames() >= uint64(nFrames) {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	detachedFrames := ingress2.Frames()
	ingress2.Shutdown()
	wg2.Wait()

	// Both steering modes must deliver every frame to the receive pipeline.
	if attachedFrames != uint64(nFrames) {
		t.Fatalf("attached delivery: want Frames()=%d, got %d", nFrames, attachedFrames)
	}
	if detachedFrames != uint64(nFrames) {
		t.Fatalf("detached delivery: want Frames()=%d, got %d", nFrames, detachedFrames)
	}
	t.Logf("delivery with eBPF attached=%d frames, detached=%d frames", attachedFrames, detachedFrames)
}

// BenchmarkEBPFDelivery_vs_HashFallback_32c compares attached eBPF steering
// with detached kernel hash fallback over a 256-CID churn workload. Both runs
// execute b.N sends through otherwise identical setups. The benchmark fails if
// the attached run takes longer; its intended comparison is -cpu=32 with
// -benchtime=3s -count=3.
func BenchmarkEBPFDelivery_vs_HashFallback_32c(b *testing.B) {
	requireCapBPF(b)

	const numSockets = 32
	const nCIDs = 256 // churn: vary CID across 256 values to exercise cache-miss

	// REAL_NIC_BIND_IP selects a non-loopback destination when provided. Both
	// runs use the same destination; only selector attachment differs. An invalid
	// address fails rather than silently reverting to loopback.
	bindIP := [4]byte{127, 0, 0, 1}
	dst := net.IPv4(127, 0, 0, 1)
	dstLabel := "loopback"
	if env := os.Getenv("REAL_NIC_BIND_IP"); env != "" {
		var p [4]byte
		if _, err := fmt.Sscanf(env, "%d.%d.%d.%d", &p[0], &p[1], &p[2], &p[3]); err != nil {
			b.Fatalf("invalid REAL_NIC_BIND_IP %q: %v", env, err)
		}
		bindIP = p
		dst = net.IPv4(p[0], p[1], p[2], p[3])
		dstLabel = env
	}
	b.Logf("bench dst: %s (REAL_NIC_BIND_IP=%q)", dstLabel, os.Getenv("REAL_NIC_BIND_IP"))

	// Pre-build frames for each CID (so the bench loop only sends, no Marshal).
	frames := make([][]byte, nCIDs)
	cids := make([][attribution.OriginNodeIDSize]byte, nCIDs)
	for i := 0; i < nCIDs; i++ {
		var cid [attribution.OriginNodeIDSize]byte
		for j := range cid {
			cid[j] = byte((i + j) & 0xff)
		}
		cids[i] = cid
		innerWire := buildCRDTDeltaWire(b, rcvEntityID, uint64(i))
		env, originPub, _ := relayChain(b, innerWire, 1, 1_700_000_000_000_000)
		frames[i] = lengthPrefixFrame(env.Marshal())
		_ = originPub // the benchmark intentionally leaves origins unregistered
	}

	// Each run performs exactly b.N sends and returns its elapsed time.
	runBench := func(attach bool) int64 {
		// The map must hold every CID in the churn set.
		k, port, cleanup := setupGroupWithMapSize(b, numSockets, uint32(nCIDs), bindIP)
		defer cleanup()

		if !attach {
			if err := k.DetachProgram(); err != nil {
				b.Fatalf("DetachProgram: %v", err)
			}
		}

		// Pin all CIDs to socket 0 (the pre-roam pinned socket). The eBPF
		// program will select among them; under detach the hash fallback
		// spreads them. The loop delivers all to HandleFrame either way.
		for i := 0; i < nCIDs; i++ {
			if err := k.PinFlow(cids[i], 0); err != nil {
				b.Fatalf("PinFlow(%d): %v", i, err)
			}
		}

		r, sc, dir, engine := setupReceiver(b, 1_700_000_000_000_000, 1_000_000_000, nil)
		_ = sc
		_ = dir
		_ = engine

		ingress := NewEpollIngress(k, r)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ingress.Serve()
		}()
		time.Sleep(50 * time.Millisecond)

		start := time.Now()
		for i := 0; i < b.N; i++ {
			sendFrame(b, dst, port, frames[i%nCIDs])
		}

		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if ingress.Frames() >= uint64(b.N) {
				break
			}
			time.Sleep(1 * time.Millisecond)
		}

		elapsed := time.Since(start)
		ingress.Shutdown()
		wg.Wait()

		if ingress.Frames() != uint64(b.N) {
			b.Fatalf("bench: expected Frames()=%d, got %d (lost frames)", b.N, ingress.Frames())
		}
		return elapsed.Nanoseconds()
	}

	// Compare both runs on loopback or the selected non-loopback destination.
	b.ReportAllocs()
	b.ResetTimer()
	elapsedNsA := runBench(true)
	elapsedNsB := runBench(false)

	b.ReportMetric(float64(elapsedNsA)/float64(b.N), "ns/frame-colA")
	b.ReportMetric(float64(elapsedNsB)/float64(b.N), "ns/frame-colB")

	if elapsedNsA > elapsedNsB {
		b.Fatalf("eBPF steering slower than hash fallback on %s: "+
			"attached=%dns, detached=%dns; "+
			"both runs delivered every frame, "+
			"but the attached run took longer",
			dstLabel, elapsedNsA, elapsedNsB)
	}
	switch {
	case elapsedNsA < elapsedNsB:
		b.Logf("eBPF steering faster than hash fallback on %s: "+
			"attached=%dns, detached=%dns", dstLabel, elapsedNsA, elapsedNsB)
	case elapsedNsA == elapsedNsB:
		b.Logf("eBPF steering and hash fallback tied on %s: "+
			"elapsed=%dns", dstLabel, elapsedNsA)
	default:
		b.Logf("eBPF steering no slower than hash fallback on %s: attached=%dns, detached=%dns", dstLabel, elapsedNsA, elapsedNsB)
	}
}

// TestEBPFEpollIngress_RealNIC binds the group to REAL_NIC_BIND_IP and checks
// that all sent frames reach HandleFrame. The test skips when that address is
// not configured. REAL_NIC_IFACE and REAL_NIC_ETHTOOL_L add optional interface
// details to the log. Per-socket stickiness is asserted by the transport tests;
// this test checks delivery through the selected interface.
func TestEBPFEpollIngress_RealNIC(t *testing.T) {
	requireCapBPF(t)

	bindIPStr := os.Getenv("REAL_NIC_BIND_IP")
	if bindIPStr == "" {
		t.Skip("REAL_NIC_BIND_IP not set; loopback tests still cover epoll delivery")
	}
	var bindIP [4]byte
	if _, err := fmt.Sscanf(bindIPStr, "%d.%d.%d.%d", &bindIP[0], &bindIP[1], &bindIP[2], &bindIP[3]); err != nil {
		t.Fatalf("REAL_NIC_BIND_IP parse: %v", err)
	}

	iface := os.Getenv("REAL_NIC_IFACE")
	if iface == "" {
		iface = "unknown"
	}
	ethtoolL := os.Getenv("REAL_NIC_ETHTOOL_L")
	if ethtoolL == "" {
		ethtoolL = "not captured"
	}
	t.Logf("real-NIC delivery run")
	t.Logf("  bind IP        : %s", bindIPStr)
	t.Logf("  interface      : %s", iface)
	t.Logf("  ethtool -l     : %s", ethtoolL)
	t.Logf("  nproc          : %d", runtime.NumCPU())
	t.Logf("  GOMAXPROCS     : %d", runtime.GOMAXPROCS(0))

	const numSockets = 32
	const nFrames = 1000
	var cid [attribution.OriginNodeIDSize]byte
	for i := range cid {
		cid[i] = byte(i + 0x30)
	}

	k, port, cleanup := setupGroup(t, numSockets, cid, bindIP)
	defer cleanup()

	innerWire := buildCRDTDeltaWire(t, rcvEntityID, 7)
	env, originPub, _ := relayChain(t, innerWire, 1, 1_700_000_000_000_000)
	frame := lengthPrefixFrame(env.Marshal())

	r, sc, dir, engine := setupReceiver(t, 1_700_000_000_000_000, 1_000_000_000, originPub)
	_ = sc
	_ = dir
	_ = engine

	ingress := NewEpollIngress(k, r)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = ingress.Serve()
	}()
	time.Sleep(50 * time.Millisecond)

	// Send frames to the real NIC IP (not loopback).
	dstIP := net.IPv4(bindIP[0], bindIP[1], bindIP[2], bindIP[3])
	for i := 0; i < nFrames; i++ {
		sendFrame(t, dstIP, port, frame)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ingress.Frames() >= uint64(nFrames) {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	delivered := ingress.Frames()
	ingress.Shutdown()
	wg.Wait()

	if delivered != uint64(nFrames) {
		t.Fatalf("real-NIC delivery: want %d frames, got %d", nFrames, delivered)
	}
	t.Logf("real-NIC delivery: sent %d frames to %s; delivered=%d", nFrames, bindIPStr, delivered)
}
