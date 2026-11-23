// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package transport implements the sync engine's egress paths.
//
// Sends from an mmap-backed frame use this order:
//
//	make([]byte, len) -> copy(heap, mmap) -> Pin(&heap[0]) -> send -> Unpin
//
// runtime.Pinner.Pin affects Go-heap objects. Pinning an address in jemalloc,
// C, or mmap memory has no effect because the runtime does not associate that
// address with a Go heap span. Copying first ensures that the pin applies to a
// Go-heap object rather than being a no-op on the source address.
//
// Both Pin calls in this file target &heap[0], where heap is a newly allocated
// []byte. TestTransmitHeapBuffer_SourceGuardViolated_FailsBuild checks this
// source invariant.
//
// MSG_ZEROCOPY requires the caller to set SO_ZEROCOPY before sendmsg. The
// kernel reports zero-copy completions through the socket error queue and may
// use an in-kernel copy instead. These functions do not wait for error-queue
// completion; that belongs to the epoll integration in ADR-0002. The tests
// check payload delivery whether or not the kernel selects zero-copy.
package transport

import (
	"crypto/tls"
	"errors"
	"runtime"

	"golang.org/x/sys/unix"
)

// ErrEmptyPayload is returned when an empty mmap frame is passed to a transmit
// helper; there is nothing to copy, pin, or send.
var ErrEmptyPayload = errors.New("transport: empty mmap payload; nothing to transmit")

// TransmitHeapBuffer copies mmapPayload into a new Go-heap slice and pins its
// first byte. It returns the copy and the Pinner. Empty input returns
// ErrEmptyPayload.
//
// The caller must call pin.Unpin after the send completes. SendPinnedHeap leaves
// this step to the caller; TransmitHeapBufferSend performs it with a defer.
// Until Unpin runs, the Pinner retains the pinned span.
//
// Pinning &heap[0] pins an object managed by the Go runtime. Pinning an address
// in the mmap, C, or jemalloc source would have no effect.
func TransmitHeapBuffer(mmapPayload []byte) (heap []byte, pin *runtime.Pinner, err error) {
	if len(mmapPayload) == 0 {
		return nil, nil, ErrEmptyPayload
	}
	heap = make([]byte, len(mmapPayload))
	copy(heap, mmapPayload)
	var p runtime.Pinner
	p.Pin(&heap[0]) // Pin the Go-heap slice, not the mmap source.
	return heap, &p, nil
}

// SendPinnedHeap sends the pinned heap copy produced by TransmitHeapBuffer
// with MSG_ZEROCOPY. It makes no additional user-space copy and leaves Unpin to
// the caller.
//
// The caller must set SO_ZEROCOPY on fd for the kernel to attempt zero-copy.
// Without that option, the kernel uses an in-kernel copy (ADR-0006).
func SendPinnedHeap(fd int, heap []byte, to unix.Sockaddr) (sent int, err error) {
	if err := unix.Sendmsg(fd, heap, nil, to, unix.MSG_ZEROCOPY); err != nil {
		return 0, err
	}
	return len(heap), nil
}

// TransmitHeapBufferSend copies mmapPayload to the Go heap, pins the copy, sends
// it with MSG_ZEROCOPY, and unpins it before returning. Empty input returns
// ErrEmptyPayload. The deferred Unpin runs after successful and failed sends.
func TransmitHeapBufferSend(fd int, mmapPayload []byte, to unix.Sockaddr) (sent int, err error) {
	if len(mmapPayload) == 0 {
		return 0, ErrEmptyPayload
	}
	heap := make([]byte, len(mmapPayload))
	copy(heap, mmapPayload)
	var p runtime.Pinner
	p.Pin(&heap[0])
	defer p.Unpin()
	if err := unix.Sendmsg(fd, heap, nil, to, unix.MSG_ZEROCOPY); err != nil {
		return 0, err
	}
	return len(heap), nil
}

// TransmitTLSFrame writes one already length-prefixed frame to a TLS
// connection. The crypto/tls record layer copies plaintext into record buffers,
// encrypts those records, and writes them to the underlying connection without
// MSG_ZEROCOPY. This path therefore uses conn.Write (ADR-0006).
//
// AF_XDP UMEM sends use a different path: the ring supplies userspace addresses
// directly to the NIC. TransmitTLSFrame does not call TransmitHeapBuffer, Pin,
// or MSG_ZEROCOPY.
func TransmitTLSFrame(conn *tls.Conn, frame []byte) (int, error) {
	return conn.Write(frame)
}
