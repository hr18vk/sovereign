// Package network implements the Cap'n Proto transport layer for the Supremum
// Ledger ingestion pipeline. This file provides the NewIngestionArena function
// which creates a read-only capnp.Arena from off-heap jemalloc memory, completely
// bypassing the go-capnp library's internal bufferpool.Default (sync.Pool).
//
// ARCHITECTURAL DECISION (Production Bug Prevention):
// The original design specified a custom capnp.Arena implementation (JemallocArena).
// However, the capnp.Arena interface's Allocate() method returns an unexported
// type `address` — making it impossible to implement from outside the capnp package.
// Any attempt would fail with: "cannot use type address outside package capnp".
//
// The solution uses capnp.SingleSegment(b) which, when b != nil, creates a
// SingleSegmentArena with bp=nil and fromPool=false. This means:
//   - Allocate() returns an error (read-only), enforcing our ingestion-plane invariant.
//   - Release() does NOT zero the buffer, does NOT return it to bufferpool.Default,
//     and does NOT inject the arena into sync.Pool. It only sets seg.data = nil.
//   - The jemalloc-backed byte slice is never registered with any Go runtime pool.
package network

import (
	capnp "capnproto.org/go/capnp/v3"
)

// NewIngestionArena creates a read-only Cap'n Proto arena from a jemalloc-backed
// byte slice containing a single-segment message (framing header already stripped).
//
// CRITICAL INVARIANTS:
//  1. messageData MUST be bounded to the exact message length parsed from the
//     Cap'n Proto framing header. Passing a slice with excess capacity is safe
//     (cap > len is fine), but len(messageData) must equal the segment size
//     declared in the framing header. This prevents the decoder from over-reading
//     into uninitialized jemalloc memory (cross-request data leak).
//  2. messageData MUST remain valid (not freed by jemalloc) for the entire
//     lifetime of the returned Arena and any Message constructed from it.
//  3. The returned Arena is READ-ONLY. Any Allocate() call will return an error.
//  4. Release() is safe to call and will NOT corrupt the underlying jemalloc memory.
//
// USAGE PATTERN (in the ingestion hot path):
//
//	// tcpBuf is a []byte backed by JemallocAllocator.Allocate()
//	// msgData is tcpBuf[headerLen:headerLen+segmentSize] (bounded slice)
//	arena := network.NewIngestionArena(msgData)
//	msg := capnp.NewMessage(arena)
//	event, _ := capnp_schema.ReadRootTriTemporalEvent(msg)
//	lat := event.Latitude()
//	lng := event.Longitude()
//	// ... process ...
//	msg.Release()  // Safe: only sets internal data to nil, does not touch jemalloc
func NewIngestionArena(messageData []byte) capnp.Arena {
	// SingleSegment(b) with b != nil:
	// - Creates &SingleSegmentArena{seg: Segment{data: b}} with bp=nil, fromPool=false
	// - This is a READ-ONLY arena (Allocate returns error when bp==nil)
	// - Release() does NOT interact with bufferpool.Default or sync.Pool
	// - The byte slice is NOT copied — Cap'n Proto reads directly from jemalloc memory
	return capnp.SingleSegment(messageData)
}
