// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build linux

// Package transport exposes Cap'n Proto event text as views into the
// reassembly buffer. Handler dispatch is synchronous so those views remain
// valid until the handler returns.
//
// The server's jemalloc buffers are outside the Go heap, so the garbage
// collector neither moves nor frees them. If pinIngestionMessage receives a
// Go-backed slice instead, runtime.Pinner keeps its backing allocation at a
// fixed address during dispatch. Pin deliberately ignores non-Go pointers.
package transport

import "runtime"

// pinIngestionMessage calls dispatch with msgData's backing storage held at a
// fixed address when that storage is Go-managed. runtime.Pinner ignores non-Go
// pointers, including the jemalloc buffers used by the ingestion server.
//
//	pinIngestionMessage(msgData, func() { handler(event) })
//
// msgData must be the segment slice passed to NewIngestionArena. Neither the
// slice nor an event decoded from it may be retained after dispatch returns;
// the caller can then overwrite or free the reassembly buffer.
func pinIngestionMessage(msgData []byte, dispatch func()) {
	if len(msgData) == 0 {
		if dispatch != nil {
			dispatch()
		}
		return
	}
	if dispatch == nil {
		return
	}
	// A zero-value Pinner is ready to use. Pin is a no-op for the server's
	// jemalloc-backed storage; it records a pin only for a Go heap object.
	var pin runtime.Pinner
	// Pin the backing allocation, not the slice header. For Go storage,
	// pinning the object containing msgData[0] covers the entire allocation.
	pin.Pin(&msgData[0])
	defer pin.Unpin()
	dispatch()
}
