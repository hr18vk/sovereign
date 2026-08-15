//go:build linux

// Package transport implements the EPOLLET-based Cap'n Proto RPC listener
// for the Supremum Ledger ingestion pipeline. This is the network entry
// point that replaces Kafka with zero-copy, zero-GC message ingestion.
//
// ARCHITECTURAL JUSTIFICATION:
// Go's standard net.Listener spawns a goroutine per connection and allocates
// bufio.Reader buffers on the Go heap. At 100K RPS, this creates 100K+
// heap allocations/sec, inducing GC pauses that violate our <200μs P99 target.
//
// This implementation uses raw epoll(7) with EPOLLET (edge-triggered) mode:
//   - No goroutines per connection (single event loop thread).
//   - All read buffers are jemalloc-backed (invisible to GC).
//   - Cap'n Proto messages are overlaid directly on the read buffer via
//     unsafe.Slice + SingleSegment — zero deserialization overhead.
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

	"github.com/hr18vk/supremum/internal/database"
	"github.com/hr18vk/supremum/internal/network"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/supremum/api/capnp/api/capnp"
)

const (
	// MaxMessageSize is the hard limit for a single Cap'n Proto message.
	// Messages exceeding this are from malformed or adversarial clients.
	MaxMessageSize = 64 * 1024 * 1024 // 64MB

	// ReadBufSize is the initial per-connection reassembly buffer size.
	// Sized for typical ingestion messages (1-10KB).
	ReadBufSize = 64 * 1024 // 64KB

	// MaxConnections is the maximum concurrent connections the server accepts.
	MaxConnections = 4096

	// EpollMaxEvents is the maximum events returned per epoll_wait call.
	EpollMaxEvents = 256
)

// connState tracks per-connection state for the reassembly state machine.
// Each connection has its own jemalloc-backed buffer to handle TCP
// fragmentation without heap allocations.
type connState struct {
	fd     int
	buf    []byte // jemalloc-backed reassembly buffer
	bufLen int    // number of valid bytes in buf
	bufCap int    // capacity of buf (for jemalloc realloc)
}

// EventHandler is the callback invoked for each successfully deserialized
// TriTemporalEvent. The handler receives the raw Cap'n Proto message and
// the parsed event struct. The handler MUST NOT retain references to the
// message or event after returning — the underlying jemalloc memory may
// be reused for the next message on this connection.
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

// NewEpollServer creates a new EPOLLET Cap'n Proto server.
// addr is a TCP address (e.g., ":9100") or a Unix socket path (prefixed with "unix:").
func NewEpollServer(allocator *database.JemallocAllocator, handler EventHandler) *EpollServer {
	return &EpollServer{
		allocator: allocator,
		handler:   handler,
		conns:     make(map[int]*connState, MaxConnections),
		epollFd:   -1,
		listenFd:  -1,
	}
}

// ListenAndServe binds to the given address and starts the epoll event loop.
// This function blocks until Shutdown() is called.
//
// addr format:
//   - "tcp::9100" or ":9100" — TCP listener
//   - "unix:/var/run/supremum.sock" — Unix domain socket
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

	// SO_REUSEADDR + SO_REUSEPORT for zero-downtime restarts.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("setsockopt SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("setsockopt SO_REUSEPORT: %w", err)
	}

	// TCP_NODELAY disables Nagle's algorithm — critical for low-latency RPC.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("setsockopt TCP_NODELAY: %w", err)
	}

	// Bind.
	sa := &unix.SockaddrInet4{Port: tcpAddr.Port}
	// E2 FIX: Defensive nil check for IPv4 binding.
	// net.ResolveTCPAddr("tcp", ":9100") returns IP=nil for INADDR_ANY.
	// tcpAddr.IP.To4() on nil IP returns nil. copy() with nil src is a no-op,
	// which correctly zero-fills sa.Addr (0.0.0.0 = INADDR_ANY).
	// IPv6 requires AF_INET6 + SockaddrInet6 — not supported in this sprint.
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
	// Remove stale socket file. Ignore ENOENT (file doesn't exist).
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

// eventLoop is the core EPOLLET event processing loop.
func (s *EpollServer) eventLoop() error {
	events := make([]unix.EpollEvent, EpollMaxEvents)

	for s.running.Load() {
		n, err := unix.EpollWait(s.epollFd, events, 100) // 100ms timeout for shutdown check
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue // Signal interrupted — retry.
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

// acceptConnections accepts all pending connections (edge-triggered: must drain).
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

		// M1 FIX: Allocate returns a slice whose len == the jemalloc usable size
		// (>= ReadBufSize, size-class-rounded). Track THAT as bufCap so the read
		// window conn.buf[bufLen:bufCap] stays in bounds and Free gets the exact
		// size jemalloc recorded for the block. ReadBufSize is the floor.
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

		// Register with EPOLLIN | EPOLLET | EPOLLRDHUP (edge-triggered).
		if err := s.epollAdd(connFd, unix.EPOLLIN|unix.EPOLLET|unix.EPOLLRDHUP); err != nil {
			log.Printf("[TRANSPORT] epoll_ctl add failed for fd=%d: %v", connFd, err)
			s.closeConn(connFd)
		}
	}
}

// handleRead processes incoming data on a connection.
// EPOLLET requires draining ALL available data in a single notification.
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
			// M1 FIX: Reallocate returns a slice whose len == the jemalloc usable
			// size (>= newCap, size-class-rounded). Track len(conn.buf) as bufCap so
			// the read window and Free see the size jemalloc recorded for the block,
			// eliminating the size-class mismatch that risked sdallocx corruption.
			conn.bufCap = len(conn.buf)
		}

		// Read directly into jemalloc buffer. Zero heap allocation.
		// Use raw syscall.Read to bypass Go's net.Conn GC-tracked buffers.
		n, err := syscall.Read(fd, conn.buf[conn.bufLen:conn.bufCap])
		if n > 0 {
			conn.bufLen += n
			s.bytesRecv.Add(uint64(n))

			// Attempt to parse complete messages from the reassembly buffer.
			s.parseMessages(conn)
		}

		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return // No more data available — edge drained.
			}
			if !errors.Is(err, syscall.EINTR) {
				s.closeConn(fd)
				return
			}
			// EINTR: retry read.
		}

		if n == 0 {
			// EOF — client closed connection.
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
// For our single-segment schema, this simplifies to:
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
			// Multi-segment messages are not supported in the ingestion schema.
			// This is either corruption or a protocol violation.
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
			return // Incomplete message — wait for more data.
		}

		// Extract the segment data (past the 8-byte framing header).
		msgData := conn.buf[8:totalMsgSize]

		// Create zero-copy Cap'n Proto arena over the jemalloc buffer.
		// NewIngestionArena wraps SingleSegment(b) with bp=nil, fromPool=false.
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

		// PIN-IN-DISPATCH: pin the backing []byte of the zero-copy TriTemporalEvent
		// for the duration of the handler. While pinned, the GC cannot relocate the
		// slice out from under the event's Text pointer fields. See pinner.go for
		// the physics (runtime.Pinner, Go 1.21+; dossier §DOMAIN 3).
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

// advanceBuffer shifts unconsumed data to the front of the reassembly buffer.
// Uses copy() which is a single memmove — O(remaining) but amortized O(1)
// when messages arrive in quick succession.
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

// Shutdown signals the server to stop accepting new connections and exit
// the event loop. Existing connections are drained and closed.
func (s *EpollServer) Shutdown() {
	s.running.Store(false)
}

// cleanup releases all resources: close all connections, epoll fd, listen fd.
func (s *EpollServer) cleanup() {
	// E3 FIX: Collect keys first, then iterate. Prevents potential
	// undefined behavior if closeConn ever has side effects on the map.
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
