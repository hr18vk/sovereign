// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build ebpf_kernel

package receive

// EpollIngress adapts a transport.KernelFanout to Receiver.HandleFrame. An
// edge-triggered epoll loop drains the SO_REUSEPORT sockets, separates
// length-prefixed frames from each datagram, and passes them to the receive
// pipeline without changing its gate order.
//
// The adapter is available only with the ebpf_kernel build tag. The default
// ingress path uses ReusePortFanout; no non-test code currently constructs an
// EpollIngress. The caller creates and attaches the KernelFanout before
// starting the loop. See ADR-0002 and ADR-0005 for the transport design.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/hr18vk/sovereign/pkg/transport"
	"golang.org/x/sys/unix"
)

// epollMaxEvents bounds each EpollWait result, matching the epoll loop in
// internal/transport's Cap'n Proto server.
const epollMaxEvents = 256

// EpollIngress delivers frames from an attached KernelFanout to a Receiver.
// The caller owns fanout setup and attachment; the loop only registers the
// existing sockets with epoll and receives datagrams from them.
//
// Sockets use EPOLLIN|EPOLLET. Edge-triggered operation requires each ready
// socket to be drained through EAGAIN before waiting again. Serve is the sole
// reader of the per-socket reassembly buffers.
type EpollIngress struct {
	// fanout must already be loaded and attached by the caller.
	fanout *transport.KernelFanout

	receiver *Receiver

	// epollFd is -1 until Serve creates the epoll instance.
	epollFd int

	// bufs holds one receive buffer per socket. Each datagram can contain one
	// or more LengthPrefixFrame frames. Serve is the only reader.
	bufs [][]byte

	frames atomic.Uint64
	drops  atomic.Uint64

	// Shutdown clears running. EpollWait's 100 ms timeout bounds the delay
	// before Serve observes the change.
	running atomic.Bool
}

// NewEpollIngress binds an attached KernelFanout to a Receiver. It does not
// load or attach the fanout's eBPF program.
func NewEpollIngress(fanout *transport.KernelFanout, receiver *Receiver) *EpollIngress {
	return &EpollIngress{
		fanout:   fanout,
		receiver: receiver,
		epollFd:  -1,
	}
}

// Serve registers every fanout socket for edge-triggered input and blocks
// until Shutdown. It returns an error for invalid construction, epoll setup
// failures, or an unrecoverable EpollWait failure. Interrupted waits retry;
// transient socket errors do not stop the loop.
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

	// Create the epoll instance and register every socket for edge-triggered
	// input. UDP sockets have no half-close notification to monitor.
	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("receive: EpollCreate1: %w", err)
	}
	e.epollFd = epollFd

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

	// A maxFrameSize buffer receives each datagram without truncation.
	e.bufs = make([][]byte, n)
	for i := range e.bufs {
		e.bufs[i] = make([]byte, maxFrameSize)
	}

	e.running.Store(true)

	events := make([]unix.EpollEvent, epollMaxEvents)
	for e.running.Load() {
		ne, err := unix.EpollWait(epollFd, events, 100)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue // capnp_server.go's precedent — signal interrupted, retry.
			}
			return fmt.Errorf("receive: EpollWait: %w", err)
		}
		for i := 0; i < ne; i++ {
			fd := int(events[i].Fd)
			if events[i].Events&(unix.EPOLLERR|unix.EPOLLHUP) != 0 {
				// Socket error / hangup. UDP has no half-close; an EPOLLERR on a
				// DGRAM socket is a transient error (e.g. a pending ICMP error).
				// Log and continue (do not tear the loop down on one bad fd).
				continue
			}
			if events[i].Events&unix.EPOLLIN == 0 {
				continue
			}
			// EPOLLET drain: read all ready datagrams on this fd until EAGAIN
			// (handleRead's edge-triggered drain precedent in capnp_server.go).
			e.drainFD(fd)
		}
	}

	_ = unix.Close(epollFd)
	e.epollFd = -1
	return nil
}

// drainFD receives from fd through EAGAIN or EWOULDBLOCK, as required by
// edge-triggered epoll. A linear scan over the fanout sockets finds the
// buffer associated with fd. Interrupted reads retry; other read errors end
// the current drain without stopping Serve.
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
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if n > 0 {
			e.deliverDatagram(buf[:n])
		}
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			// A UDP error can report an earlier ICMP response. Leave the socket
			// registered so later datagrams can still be received.
			return
		}
		if n == 0 {
			return // UDP has no EOF; a zero-length read is a no-op.
		}
	}
}

// deliverDatagram separates the LengthPrefixFrame frames in one datagram and
// calls HandleFrame for each. A truncated prefix, an invalid length, or a frame
// that extends beyond the datagram increments drops and discards the remaining
// bytes. No malformed frame reaches HandleFrame.
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
		// Copy before handing the frame to HandleFrame. Relay retention takes
		// ownership of this slice, while the next Recvfrom reuses datagram's
		// backing buffer.
		frame := make([]byte, end-start)
		copy(frame, datagram[start:end])
		off = end

		verdict := e.receiver.HandleFrame(frame)
		e.frames.Add(1)
		if verdict.Verdict != Accept {
			e.drops.Add(1)
		}
	}
}

// Frames returns the number of complete frames passed to HandleFrame.
func (e *EpollIngress) Frames() uint64 { return e.frames.Load() }

// Drops returns the number of malformed datagrams plus non-Accept verdicts.
func (e *EpollIngress) Drops() uint64 { return e.drops.Load() }

// Shutdown asks Serve to return after its current epoll wait. It is safe to
// call concurrently with Serve.
func (e *EpollIngress) Shutdown() {
	e.running.Store(false)
}
