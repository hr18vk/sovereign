//go:build ebpf_kernel

package receive

// Track 12.1 — the epoll ingress loop WITH KernelFanout wired into the engine's
// receive path (the Gap-1 + Gap-4 closers named in ADR-0003 §8).
//
// 12.0 (21e3289) proved the BPF steering half on loopback, correctness-only:
// it pinned a flow to one socket across a 4-tuple roam (0/1000 mis-routes) but
// NEVER drove an ingress loop (`grep EpollWait|EpollCtl|EpollCreate pkg/transport/`
// returned zero) and NEVER wired the selector into the production receive path
// (`grep KernelFanout pkg/receive/receiver.go` returned zero — the seam lived
// in a test file). This file closes BOTH:
//
//   - Gap 1 (epoll): an edge-triggered epoll loop over the 32 SO_REUSEPORT fds
//     at GOMAXPROCS=32. EPOLLET is load-bearing: edge-triggered is the §2.X1(a)
//     contract (Phase3.md:358 "epoll COUPLED WITH SO_ATTACH_REUSEPORT_EBPF" — the
//     two together); the Go netpoller is edge-triggered and the eBPF pinnings
//     assume it. A level-triggered loop would re-fire on the same core and
//     DEFEAT the "eradicating cache invalidation" claim (Phase3.md:102).
//   - Gap 4 (wiring): the loop Recvfrom's the eBPF-pinned fd, reassembles to a
//     frame boundary, and invokes receiver.HandleFrame on the bytes. The wiring
//     is ABOVE HandleFrame (delivery), NOT inside it — the gate-stack order at
//     receiver.go:244 (cheap gates -> Verify) is PROVEN and untouched. This is
//     the seam in the ENGINE, not in a test file.
//
// This file is GATED by the `ebpf_kernel` build tag (the pq_preview /
// ebpf_reuseport.go shape). The DEFAULT build EXCLUDES it entirely — the
// production ingress seam stays on the in-process ReusePortFanout (fanout.go)
// PROVEN in Track 2.1 (ADR-0002, commit 1e5317f). Under -tags ebpf_kernel this
// file is the SILICON form: it drives the real 32-member SO_REUSEPORT group the
// 12.0 KernelFanout bound, attaches the eBPF program (KernelFanout.AttachProgram),
// EpollCtl-ADD's the 32 fds (EPOLLIN|EPOLLET edge-triggered), and EpollWait-drives
// them into HandleFrame.
//
// The epoll precedent is the EXISTING live loop internal/transport/capnp_server.go
// :119 EpollCreate1, :222 EpollWait, :462/:486 EpollCtl, :158 SO_REUSEPORT —
// CITED here, NOT duplicated. The 12.1 loop reuses the same x/sys/unix epoll
// surface (EpollCreate1/EpollCtl/EpollWait/EpollEvent) the capnp_server.go loop
// already exercises on this box; it does NOT re-invent bpf(2) (the 12.0 cilium
// loader owns that) and does NOT fork HandleFrame's gate stack.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/hr18vk/supremum/pkg/transport"
	"golang.org/x/sys/unix"
)

// epollMaxEvents is the maximum events returned per EpollWait call. It matches
// the capnp_server.go:50 EpollMaxEvents precedent (256) — the same batch size
// the existing live loop drains per wake. CITED, not re-tuned.
const epollMaxEvents = 256

// EpollIngress is the edge-triggered epoll ingress loop that drives the 12.0
// KernelFanout's SO_REUSEPORT socket group into the engine's receive path. It
// is the Gap-1 + Gap-4 closer: the loop the §2.X1(a) ruling names ("epoll
// coupled with SO_ATTACH_REUSEPORT_EBPF"), wired so each reassembled frame
// crosses the PROVEN gate stack at receiver.go:244 (HandleFrame) — the seam in
// the engine, not in a test file.
//
// It composes two PROVEN halves and adds the loop that couples them:
//   - transport.KernelFanout (12.0, 21e3289): the 32-member SO_REUSEPORT group
//     + the attached BPF_PROG_TYPE_SK_REUSEPORT program that pins a flow to one
//     socket on the plaintext OriginNodeID. LoadGroup/LoadProgram/AttachProgram
//     are the 12.0 surface; this loop does NOT re-load or re-attach — it
//     consumes an already-attached KernelFanout (the caller owns the setup, so
//     the loop and the test share ONE setup path, not two).
//   - *Receiver (Track 3.5): the gate-stack composition (HandleFrame). The loop
//     calls HandleFrame on each reassembled frame; it does NOT fork the gate
//     order (the wiring is delivery, above HandleFrame, not inside it).
//
// EPOLLET (edge-triggered) is load-bearing: the §2.X1(a) contract is
// edge-triggered (the Go netpoller is edge-triggered; the eBPF pinnings assume
// it). Edge-triggered requires DRAINING all ready datagrams per wake (a
// level-triggered loop would re-fire on the same core and defeat the
// cache-locality claim). The loop Recvfrom's in a tight EAGAIN-bounded loop
// per fd per wake, exactly like capnp_server.go:305 handleRead's EPOLLET drain.
type EpollIngress struct {
	// fanout is the 12.0 KernelFanout whose 32 SO_REUSEPORT fds the loop drives.
	// It MUST be already LoadGroup'd + LoadProgram'd + AttachProgram'd by the
	// caller (the loop consumes the attached group; it does not own setup, so
	// the loop and the silicon test share one setup path).
	fanout *transport.KernelFanout

	// receiver is the gate-stack composition (Track 3.5). HandleFrame is called
	// on each reassembled frame — the Gap-4 wiring (the seam in the engine).
	receiver *Receiver

	// epollFd is the epoll instance fd (EpollCreate1). -1 until Serve creates it.
	epollFd int

	// bufs is the per-fd reassembly buffer. UDP is datagram-oriented, so each
	// Recvfrom returns one complete datagram; a datagram may carry one OR more
	// length-prefixed frames (the GAP-2 wire shape from forward.go:104
	// LengthPrefixFrame: [uint32 frameLen BE][envelope bytes]). The reassembler
	// parses the prefix and extracts each frame, invoking HandleFrame per frame.
	// One buffer per fd (the fds are driven single-threaded by the loop, so no
	// per-fd mutex is needed — the loop is the sole reader).
	bufs [][]byte

	// frames is the per-loop-iteration count of frames delivered to HandleFrame
	// (instrumentation; the silicon test reads it for the stickiness table).
	frames atomic.Uint64

	// drops is the per-loop-iteration count of frames HandleFrame dropped (any
	// non-Accept verdict). Instrumentation; the silicon test reads it.
	drops atomic.Uint64

	// running gates the EpollWait loop (the capnp_server.go:221 atomic.Bool
	// precedent). Shutdown sets it false; the loop's 100ms EpollWait timeout
	// lets it observe the flag and exit.
	running atomic.Bool
}

// NewEpollIngress binds an already-attached 12.0 KernelFanout to a Receiver's
// gate stack. The caller owns the KernelFanout setup (LoadGroup + LoadProgram +
// AttachProgram) so the loop and the silicon test share ONE setup path, not
// two. The loop does NOT re-attach the program (re-attaching would race the
// test's attach-vs-detach control — the Gap-3 bench's ONLY delta is the attach,
// and the loop must not perturb it).
func NewEpollIngress(fanout *transport.KernelFanout, receiver *Receiver) *EpollIngress {
	return &EpollIngress{
		fanout:   fanout,
		receiver: receiver,
		epollFd:  -1,
	}
}

// Serve runs the edge-triggered epoll ingress loop. It blocks until Shutdown is
// called (the capnp_server.go:136 eventLoop precedent — block-until-stopped).
// It is the §2.X1(a) closer: epoll (this loop) COUPLED WITH
// SO_ATTACH_REUSEPORT_EBPF (the 12.0 attach the caller already did), driving
// the eBPF-pinned fds into HandleFrame.
//
// Every kernel-symbol call site cites its precedent:
//   - unix.EpollCreate1(unix.EPOLL_CLOEXEC) — capnp_server.go:119.
//   - unix.EpollCtl(epollFd, unix.EPOLL_CTL_ADD, fd, &ev) — capnp_server.go:486.
//   - unix.EpollEvent{Events, Fd: int32(fd)} — capnp_server.go:482.
//   - unix.EpollWait(epollFd, events, 100) — capnp_server.go:222 (100ms timeout
//     for the shutdown check, the capnp_server.go:222 precedent).
//   - unix.Recvfrom(fd, buf, 0) — ebpf_reuseport_test.go:217 (the 12.0 receipt
//     path; the loop reuses the SAME Recvfrom the 12.0 stickiness table used).
//   - unix.EAGAIN / unix.EWOULDBLOCK — capnp_server.go:255 / ebpf_reuseport_test.go:219.
//   - unix.EINTR — capnp_server.go:224.
//
// EPOLLET (edge-triggered) is set on every fd: EPOLLIN|EPOLLET (the
// capnp_server.go:290 EPOLLET precedent, minus EPOLLRDHUP — these are UDP
// DGRAM sockets, not TCP, so there is no half-close to watch).
func (e *EpollIngress) Serve() error {
	if e.fanout == nil {
		return fmt.Errorf("receive: EpollIngress.Serve: nil KernelFanout")
	}
	if e.receiver == nil {
		return fmt.Errorf("receive: EpollIngress.Serve: nil Receiver")
	}
	n := int(e.fanout.NumSockets())
	if n == 0 {
		return fmt.Errorf("receive: EpollIngress.Serve: KernelFanout has zero sockets")
	}

	// 1. Create the epoll instance. capnp_server.go:119 precedent.
	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("receive: EpollCreate1: %w", err)
	}
	e.epollFd = epollFd

	// 2. EpollCtl-ADD the 32 SO_REUSEPORT fds, EPOLLIN|EPOLLET (edge-triggered).
	//    capnp_server.go:486 EpollCtl + capnp_server.go:482 EpollEvent precedent.
	//    EPOLLET is load-bearing (the §2.X1(a) edge-triggered contract).
	for i := 0; i < n; i++ {
		fd := e.fanout.SocketFD(uint32(i))
		if fd < 0 {
			_ = unix.Close(epollFd)
			e.epollFd = -1
			return fmt.Errorf("receive: EpollIngress.Serve: KernelFanout.SocketFD(%d) invalid", i)
		}
		ev := unix.EpollEvent{
			Events: unix.EPOLLIN | unix.EPOLLET,
			Fd:     int32(fd),
		}
		if err := unix.EpollCtl(epollFd, unix.EPOLL_CTL_ADD, fd, &ev); err != nil {
			_ = unix.Close(epollFd)
			e.epollFd = -1
			return fmt.Errorf("receive: EpollCtl ADD fd %d: %w", fd, err)
		}
	}

	// 3. Per-fd reassembly buffers. UDP datagrams are bounded by maxFrameSize
	//    (the receiver.go:65 defensive cap); size each buffer to hold a full
	//    datagram so Recvfrom never truncates. One buffer per fd (the loop is
	//    the sole reader — no per-fd mutex).
	e.bufs = make([][]byte, n)
	for i := range e.bufs {
		e.bufs[i] = make([]byte, maxFrameSize)
	}

	e.running.Store(true)

	// 4. The edge-triggered event loop. capnp_server.go:218 eventLoop precedent.
	events := make([]unix.EpollEvent, epollMaxEvents)
	for e.running.Load() {
		// 100ms timeout so the loop observes the running flag (the
		// capnp_server.go:222 shutdown-check timeout precedent).
		ne, err := unix.EpollWait(epollFd, events, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue // capnp_server.go:224 precedent — signal interrupted, retry.
			}
			return fmt.Errorf("receive: EpollWait: %w", err)
		}
		for i := 0; i < ne; i++ {
			fd := int(events[i].Fd)
			if events[i].Events&(unix.EPOLLERR|unix.EPOLLHUP) != 0 {
				// Socket error / hangup. UDP has no half-close; an EPOLLERR on a
				// DGRAM socket is a transient error (e.g. a pending ICMP error).
				// Log-and-continue (do NOT tear the loop down on one bad fd).
				continue
			}
			if events[i].Events&unix.EPOLLIN == 0 {
				continue
			}
			// EPOLLET drain: read ALL ready datagrams on this fd until EAGAIN
			// (capnp_server.go:305 handleRead's edge-triggered drain precedent).
			e.drainFD(fd)
		}
	}

	_ = unix.Close(epollFd)
	e.epollFd = -1
	return nil
}

// drainFD reads all ready datagrams on fd until EAGAIN (the EPOLLET drain
// discipline: edge-triggered requires draining, else the wake is lost). Each
// datagram is reassembled to frame boundaries (the GAP-2 length-prefixed wire
// shape) and each frame is handed to HandleFrame — the Gap-4 wiring.
//
// The fd->bufIndex map is the per-fd reassembly buffer. The fds are the
// KernelFanout's socket indices; SocketFD(i) returns the fd for index i, so the
// buffer index is recovered by a linear scan over the (<=32) fds — O(32) per
// wake, negligible vs the Recvfrom cost.
func (e *EpollIngress) drainFD(fd int) {
	bufIdx := -1
	for i := range e.bufs {
		if e.fanout.SocketFD(uint32(i)) == fd {
			bufIdx = i
			break
		}
	}
	if bufIdx < 0 {
		return // unknown fd (should not happen — only the 32 group fds are added).
	}
	buf := e.bufs[bufIdx]
	for {
		// unix.Recvfrom(fd, buf, 0) — ebpf_reuseport_test.go:217 precedent.
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if n > 0 {
			e.deliverDatagram(buf[:n])
		}
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return // capnp_server.go:255 / ebpf_reuseport_test.go:219 — edge drained.
			}
			if errors.Is(err, unix.EINTR) {
				continue // capnp_server.go:224 — signal interrupted, retry the read.
			}
			// A non-EAGAIN/EINTR error on a DGRAM socket is a transient ICMP-
			// sourced error (ECONNREFUSED on a prior send). Log-and-continue;
			// do NOT tear the loop down (the capnp_server.go:338 closeConn is a
			// TCP-stream concern; UDP has no connection to close).
			return
		}
		if n == 0 {
			return // UDP has no EOF; a zero-length read is a no-op.
		}
	}
}

// deliverDatagram reassembles the length-prefixed frames in a single UDP
// datagram and invokes HandleFrame on each. The wire shape is the GAP-2
// [uint32 frameLen BE][envelope bytes] from forward.go:104 LengthPrefixFrame
// (the inverse of receiver.go:485 FrameReader.ReadFrame). A datagram may carry
// one OR more frames; the reassembler parses the prefix and extracts each.
//
// A short / malformed prefix (datagram shorter than frameLenPrefixSize, or a
// declared frameLen > remaining bytes, or frameLen > maxFrameSize) is a
// DropMalformed — it is handed to HandleFrame is NOT possible (there is no
// envelope to parse), so it is counted as a drop and the datagram is skipped.
// This mirrors receiver.go:244 HandleFrame's "a forged frame is a Verdict,
// never a panic" discipline at the delivery layer.
func (e *EpollIngress) deliverDatagram(datagram []byte) {
	off := 0
	for off < len(datagram) {
		// Need at least frameLenPrefixSize bytes for the prefix.
		if len(datagram)-off < frameLenPrefixSize {
			e.drops.Add(1)
			return
		}
		frameLen := int(binary.BigEndian.Uint32(datagram[off : off+frameLenPrefixSize]))
		if frameLen <= 0 || frameLen > maxFrameSize {
			e.drops.Add(1)
			return
		}
		start := off + frameLenPrefixSize
		end := start + frameLen
		if end > len(datagram) {
			// Declared frame longer than the datagram carries — malformed.
			e.drops.Add(1)
			return
		}
		frame := datagram[start:end]
		off = end

		// The Gap-4 wiring: hand the reassembled frame to the PROVEN gate stack.
		// HandleFrame (receiver.go:244) runs cheap gates -> Verify -> Join; the
		// wiring is ABOVE it (delivery), NOT inside it (the gate order is
		// untouched). A non-Accept verdict is a drop (counted), never a panic.
		verdict := e.receiver.HandleFrame(frame)
		e.frames.Add(1)
		if verdict.Verdict != Accept {
			e.drops.Add(1)
		}
	}
}

// Frames returns the total frames delivered to HandleFrame (instrumentation;
// the silicon test reads it for the stickiness / delivery table).
func (e *EpollIngress) Frames() uint64 { return e.frames.Load() }

// Drops returns the total frames dropped by HandleFrame or the delivery
// reassembler (instrumentation; the silicon test reads it).
func (e *EpollIngress) Drops() uint64 { return e.drops.Load() }

// Shutdown signals the loop to stop. The loop's 100ms EpollWait timeout lets it
// observe the flag and exit within one wake (the capnp_server.go:491 Shutdown
// precedent). It is safe to call concurrently with Serve.
func (e *EpollIngress) Shutdown() {
	e.running.Store(false)
}
