//go:build linux

// Package transport: Pinner-pinned zero-copy Cap'n Proto ingestion.
//
// PHYSICS (see "Go High-Performance Architecture Research", §DOMAIN 3, and
// SUPREMUM_STYLE §1):
//
//   - The EPOLLET ingress path decodes each TriTemporalEvent directly off the
//     reassembly buffer, surfaced through Go as a []byte slice. go-capnp v3's
//     SingleSegment arena keeps this zero-copy: the parsed TriTemporalEvent's
//     pointer fields reference the slice's backing array in place — NO
//     materialization into a Go struct.
//
//   - The hazard: a Go slice's backing array is GC-visible. If it ever moves
//     (smallbuf move, stack-growth copy, or any future relocation) from under
//     the parsed TriTemporalEvent, its Text pointer fields would dangle into
//     stale memory — silent cross-request data corruption, the worst failure
//     mode for an ingestion hot path.
//
//   - runtime.Pinner (Go 1.21+; available here on Go 1.26.1) is the runtime
//     contract that a pinned Go object will NOT be moved by the GC until
//     Unpin(). We pin the slice's backing array (via its first-element pointer)
//     for the lifetime of the handler invocation, then unpin. This is the
//     dossier's mandated "lock the Epoll memory map and read the
//     TriTemporalEvent directly off the raw bytes" primitive, rendered in the
//     language's safe vocabulary.
//
//   - Pinning is Zero-GC: Pin/Unpin do not allocate (the Pinner is a stack
//     value here). The per-message cost is a mark bit flip on the pinned
//     object's GC header — a few ns, absorbed inside handler dispatch which
//     already dwarfs it.
//
// INVARIANT: pinIngestionMessage pins the *first element* of msgData, i.e. the
// START of the backing array. Go's GC pins the whole contiguous object, so the
// entire backing array — every Text pointer the TriTemporalEvent indexes into —
// is locked for the pinned duration. Pinning a slice header directly is NOT
// legal (runtime.Pinner.Pin requires a pointer to a Go object, not a slice),
// hence &msgData[0].
package transport

import "runtime"

// pinIngestionMessage pins the backing memory of the data slice for the
// lifetime of handler dispatch, then unpins. It is the zero-copy safety
// boundary: while pinned, the GC cannot relocate msgData's backing array out
// from under the TriTemporalEvent whose Text pointers index into it.
//
//	pinIngestionMessage(msgData, func() { handler(event) })
//
// msgData MUST be the sub-slice handed to NewIngestionArena, and it MUST NOT be
// retained past the dispatch closure return — the ingestion path consumes or
// rejects synchronously, never deferring, so the unpin is the last reference.
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
	// runtime.Pinner is a small struct; kept on the stack. Pin/Unpin never
	// allocate. Pin the GC-managed backing-array OBJECT (its first element),
	// which is exactly the memory the GC could otherwise relocate.
	var pin runtime.Pinner
	// &msgData[0] is a pointer to the first element of the slice's backing
	// array — a Go object, which is what Pinner.Pin requires. Pinning it pins
	// the entire contiguous array, so every Text pointer into msgData is
	// locked against relocation for the duration of dispatch.
	pin.Pin(&msgData[0])
	defer pin.Unpin()
	dispatch()
}
