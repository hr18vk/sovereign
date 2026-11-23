// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build linux

// Package transport implements a Cap'n Proto ingestion listener on Linux.
// One epoll event loop serves all connections to a server, with edge-triggered
// reads and a jemalloc-backed reassembly buffer for each connection.
//
// A SingleSegment arena decodes each TriTemporalEvent in place. The event is
// dispatched synchronously, before its portion of the buffer can be reused.
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/hr18vk/sovereign/internal/network"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

const (
	// MaxMessageSize is the largest segment payload the server will parse.
	// A larger message closes the connection.
	MaxMessageSize = 64 * 1024 * 1024 // 64 MiB

	// ReadBufSize is the initial per-connection reassembly buffer size.
	ReadBufSize = 64 * 1024 // 64 KiB

	// MaxConnections is the maximum concurrent connections the server accepts.
	MaxConnections = 4096

	// EpollMaxEvents is the maximum events returned per epoll_wait call.
	EpollMaxEvents = 256
)

// connState tracks TCP reassembly for one connection. Its buffer storage is
// allocated by jemalloc rather than on the Go heap.
type connState struct {
	fd     int
	buf    []byte // jemalloc-backed reassembly buffer
	bufLen int    // number of valid bytes in buf
	bufCap int    // usable length of buf for reads and reallocation
}

// EventHandler handles one decoded TriTemporalEvent. The event is valid only
// for the duration of the call; retain copies of any fields needed later.
// Returned errors are logged and do not stop the event loop.
type EventHandler func(event capnp_schema.TriTemporalEvent) error

// EpollServer is the EPOLLET-based Cap'n Proto ingestion server.
type EpollServer struct {
	allocator  *database.JemallocAllocator
	handler    EventHandler
	epollFd    int
	listenFd   int
	conns      map[int]*connState
	running    atomic.Bool
	eventsRecv atomic.Uint64
	bytesRecv  atomic.Uint64
}

// NewEpollServer creates an edge-triggered Cap'n Proto server. The allocator
// supplies connection buffers, and the handler runs on the event-loop
// goroutine.
func NewEpollServer(allocator *database.JemallocAllocator, handler EventHandler) *EpollServer {
	return &EpollServer{
		allocator: allocator,
		handler:   handler,
		conns:     make(map[int]*connState, MaxConnections),
		epollFd:   -1,
		listenFd:  -1,
	}
}

// ListenAndServe binds addr and runs the epoll event loop. A normal shutdown
// closes all connections and descriptors before ListenAndServe returns.
//
// Accepted address forms are:
//   - "tcp::9100" or ":9100" for TCP
//   - "unix:/var/run/sovereign.sock" for a Unix domain socket
func (s *EpollServer) ListenAndServe(addr string) error {
	var socketFd int
	var err error

	// Parse address type.
	if len(addr) > 5 && addr[:5] == "unix:" {
		socketFd, err = s.listenUnix(addr[5:])
	} else {
		if len(addr) > 4 && addr[:4] == "tcp:" {
			addr = addr[4:]
		}
		socketFd, err = s.listenTCP(addr)
	}
	if err != nil {
		return fmt.Errorf("transport: listen failed: %w", err)
	}
	s.listenFd = socketFd

	// Create epoll instance.
	s.epollFd, err = unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		if err := unix.Close(s.listenFd); err != nil {
			log.Printf("[TRANSPORT] close listen fd: %v", err)
		}
		return fmt.Errorf("transport: epoll_create1: %w", err)
	}

	// Register the listen socket with EPOLLIN (level-triggered for accept).
	if err := s.epollAdd(s.listenFd, unix.EPOLLIN); err != nil {
		s.cleanup()
		return fmt.Errorf("transport: epoll_ctl listen fd: %w", err)
	}

	s.running.Store(true)
	log.Printf("[TRANSPORT] EPOLLET server listening on %s (epollFd=%d, listenFd=%d)", addr, s.epollFd, s.listenFd)

	return s.eventLoop()
}

// listenTCP creates a non-blocking TCP listener.
func (s *EpollServer) listenTCP(addr string) (int, error) {
	// Resolve address.
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return -1, err
	}

	// Create socket.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}

	// Allow address reuse and multiple listeners on the same port.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("setsockopt SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("setsockopt SO_REUSEPORT: %w", err)
	}

	// Disable Nagle's algorithm on sockets created from this listener.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("setsockopt TCP_NODELAY: %w", err)
	}

	// Bind.
	sa := &unix.SockaddrInet4{Port: tcpAddr.Port}
	// A nil IP means INADDR_ANY. To4 returns nil in that case, leaving
	// sa.Addr zeroed. This listener supports IPv4 only.
	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		copy(sa.Addr[:], ip4)
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	// Listen with a large backlog.
	if err := unix.Listen(fd, 4096); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	return fd, nil
}

// listenUnix creates a non-blocking Unix domain socket listener.
func (s *EpollServer) listenUnix(path string) (int, error) {
	// Unlink path before binding; any unlink error is ignored.
	_ = syscall.Unlink(path)

	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}

	sa := &unix.SockaddrUnix{Name: path}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	if err := unix.Listen(fd, 4096); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	return fd, nil
}

// eventLoop waits for socket events until Shutdown clears running.
func (s *EpollServer) eventLoop() error {
	events := make([]unix.EpollEvent, EpollMaxEvents)

	for s.running.Load() {
		n, err := unix.EpollWait(s.epollFd, events, 100) // 100ms timeout for shutdown check
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue // Retry after an interrupted wait.
			}
			return fmt.Errorf("transport: epoll_wait: %w", err)
		}

		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)

			if fd == s.listenFd {
				// Accept new connections.
				s.acceptConnections()
			} else if events[i].Events&(unix.EPOLLERR|unix.EPOLLHUP|unix.EPOLLRDHUP) != 0 {
				// Connection error or hangup.
				s.closeConn(fd)
			} else if events[i].Events&unix.EPOLLIN != 0 {
				// Data available for reading.
				s.handleRead(fd)
			}
		}
	}

	s.cleanup()
	return nil
}

// acceptConnections accepts pending connections until Accept4 would block.
func (s *EpollServer) acceptConnections() {
	for {
		connFd, _, err := unix.Accept4(s.listenFd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return // All pending connections accepted.
			}
			log.Printf("[TRANSPORT] accept error: %v", err)
			return
		}

		if len(s.conns) >= MaxConnections {
			log.Printf("[TRANSPORT] max connections reached, rejecting fd=%d", connFd)
			_ = unix.Close(connFd)
			continue
		}

		// Disable Nagle on the accepted connection.
		_ = unix.SetsockoptInt(connFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1) // Best-effort; non-fatal.

		// Allocate per-connection reassembly buffer from jemalloc (off-heap).
		buf := s.allocator.Allocate(ReadBufSize)

		// Allocate returns the full jemalloc size class, which can be larger
		// than ReadBufSize. bufCap records the usable length for reads and Free.
		usable := len(buf)
		if usable < ReadBufSize {
			usable = ReadBufSize
		}
		s.conns[connFd] = &connState{
			fd:     connFd,
			buf:    buf,
			bufLen: 0,
			bufCap: usable,
		}

		// Register for edge-triggered reads and half-close notifications.
		if err := s.epollAdd(connFd, unix.EPOLLIN|unix.EPOLLET|unix.EPOLLRDHUP); err != nil {
			log.Printf("[TRANSPORT] epoll_ctl add failed for fd=%d: %v", connFd, err)
			s.closeConn(connFd)
		}
	}
}

// handleRead drains the socket because its read notifications are edge-triggered.
func (s *EpollServer) handleRead(fd int) {
	conn, ok := s.conns[fd]
	if !ok {
		return
	}

	for {
		// Ensure buffer has room. Grow if needed.
		if conn.bufLen >= conn.bufCap {
			newCap := conn.bufCap * 2
			if newCap > MaxMessageSize {
				log.Printf("[TRANSPORT] connection fd=%d exceeded max message size, closing", fd)
				s.closeConn(fd)
				return
			}
			conn.buf = s.allocator.Reallocate(newCap, conn.buf[:conn.bufCap])
			// Reallocate also returns the full usable size class, which can
			// exceed newCap. Keep bufCap equal to the returned slice length.
			conn.bufCap = len(conn.buf)
		}

		// Read available bytes directly into the reassembly buffer.
		n, err := syscall.Read(fd, conn.buf[conn.bufLen:conn.bufCap])
		if n > 0 {
			conn.bufLen += n
			s.bytesRecv.Add(uint64(n))

			// Parse every complete message now available.
			s.parseMessages(conn)
		}

		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return // The socket has no more data to read.
			}
			if !errors.Is(err, syscall.EINTR) {
				s.closeConn(fd)
				return
			}
			// Retry after an interrupted read.
		}

		if n == 0 {
			// The client closed the connection.
			s.closeConn(fd)
			return
		}
	}
}

// parseMessages extracts complete Cap'n Proto messages from the reassembly buffer.
//
// Cap'n Proto stream framing format (per message):
//
//	Bytes 0-3:  uint32 segmentCount - 1  (little-endian)
//	Bytes 4-7:  uint32 segment0Size (in 8-byte words, little-endian)
//	[If segmentCount > 1: additional uint32 segment sizes]
//	[Padding to 8-byte boundary if segmentCount is even]
//	Segment data (segmentSize × 8 bytes each)
//
// The ingestion protocol accepts only single-segment messages:
//
//	Bytes 0-3:  0x00000000  (segment count = 1, encoded as 0)
//	Bytes 4-7:  uint32 segmentWords (data section size in 8-byte words)
//	Bytes 8+:   segment data
func (s *EpollServer) parseMessages(conn *connState) {
	for {
		if conn.bufLen < 8 {
			return // Not enough for framing header.
		}

		buf := conn.buf[:conn.bufLen]

		// Parse segment count (always 0 for single-segment messages).
		segCountMinusOne := binary.LittleEndian.Uint32(buf[0:4])
		if segCountMinusOne != 0 {
			// The ingestion server accepts only single-segment messages.
			log.Printf("[TRANSPORT] rejecting multi-segment message (segments=%d) on fd=%d",
				segCountMinusOne+1, conn.fd)
			s.closeConn(conn.fd)
			return
		}

		// Parse segment size in 8-byte words.
		segWords := binary.LittleEndian.Uint32(buf[4:8])
		segBytes := int(segWords) * 8

		// Bounds check: prevent reading beyond MaxMessageSize.
		if segBytes > MaxMessageSize || segBytes < 0 {
			log.Printf("[TRANSPORT] message too large (%d bytes) on fd=%d, closing", segBytes, conn.fd)
			s.closeConn(conn.fd)
			return
		}

		// Total message size = 8 (header) + segBytes (data).
		totalMsgSize := 8 + segBytes
		if conn.bufLen < totalMsgSize {
			return // Wait for the rest of the message.
		}

		// Extract the segment data (past the 8-byte framing header).
		msgData := conn.buf[8:totalMsgSize]

		// Decode from the jemalloc buffer without copying the segment.
		arena := network.NewIngestionArena(msgData)
		msg := &capnp.Message{Arena: arena}

		// Parse the TriTemporalEvent root struct.
		event, err := capnp_schema.ReadRootTriTemporalEvent(msg)
		if err != nil {
			log.Printf("[TRANSPORT] Cap'n Proto parse error on fd=%d: %v", conn.fd, err)
			// Skip this message and advance the buffer.
			s.advanceBuffer(conn, totalMsgSize)
			msg.Release()
			continue
		}

		// Dispatch synchronously while msgData is valid. The handler must copy
		// any fields it needs before advanceBuffer reuses this storage below.
		var handlerErr error
		pinIngestionMessage(msgData, func() {
			handlerErr = s.handler(event)
		})
		if handlerErr != nil {
			log.Printf("[TRANSPORT] handler error on fd=%d: %v", conn.fd, handlerErr)
		}

		s.eventsRecv.Add(1)

		// Release the Cap'n Proto message (safe: only sets internal data to nil).
		msg.Release()

		// Advance the reassembly buffer past the consumed message.
		s.advanceBuffer(conn, totalMsgSize)
	}
}

// advanceBuffer discards consumed bytes and moves any remaining bytes to the
// front. The overlapping copy preserves an incomplete following message.
func (s *EpollServer) advanceBuffer(conn *connState, consumed int) {
	remaining := conn.bufLen - consumed
	if remaining > 0 {
		copy(conn.buf[:remaining], conn.buf[consumed:conn.bufLen])
	}
	conn.bufLen = remaining
}

// closeConn tears down a connection and frees its jemalloc resources.
func (s *EpollServer) closeConn(fd int) {
	conn, ok := s.conns[fd]
	if !ok {
		return
	}

	// Remove from epoll first.
	if err := unix.EpollCtl(s.epollFd, unix.EPOLL_CTL_DEL, fd, nil); err != nil {
		log.Printf("[TRANSPORT] epoll_ctl DEL fd=%d: %v", fd, err)
	}

	// Close the socket.
	if err := unix.Close(fd); err != nil {
		log.Printf("[TRANSPORT] close fd=%d: %v", fd, err)
	}

	// Free the jemalloc reassembly buffer.
	if conn.buf != nil {
		s.allocator.Free(conn.buf[:conn.bufCap])
		conn.buf = nil
	}

	delete(s.conns, fd)
}

// epollAdd registers a file descriptor with epoll.
func (s *EpollServer) epollAdd(fd int, events uint32) error {
	ev := unix.EpollEvent{
		Events: events,
		Fd:     int32(fd),
	}
	return unix.EpollCtl(s.epollFd, unix.EPOLL_CTL_ADD, fd, &ev)
}

// Shutdown signals the event loop to exit. It does not wait for cleanup;
// ListenAndServe closes all remaining connections and descriptors before returning.
func (s *EpollServer) Shutdown() {
	s.running.Store(false)
}

// cleanup closes every connection, the epoll descriptor, and the listener.
func (s *EpollServer) cleanup() {
	// closeConn deletes from s.conns, so iterate over a separate descriptor
	// slice.
	fds := make([]int, 0, len(s.conns))
	for fd := range s.conns {
		fds = append(fds, fd)
	}
	for _, fd := range fds {
		s.closeConn(fd)
	}

	if s.epollFd >= 0 {
		_ = unix.Close(s.epollFd)
		s.epollFd = -1
	}

	if s.listenFd >= 0 {
		_ = unix.Close(s.listenFd)
		s.listenFd = -1
	}

	log.Printf("[TRANSPORT] Server shutdown. Events received: %d, Bytes received: %d",
		s.eventsRecv.Load(), s.bytesRecv.Load())
}

// Stats returns server statistics for telemetry.
func (s *EpollServer) Stats() (eventsRecv, bytesRecv uint64, activeConns int) {
	return s.eventsRecv.Load(), s.bytesRecv.Load(), len(s.conns)
}
