package database

/*
#cgo LDFLAGS: -ljemalloc
#include <jemalloc/jemalloc.h>
#include <stdlib.h>
#include <string.h>

static inline void* je_mallocx_aligned_zero(size_t size) {
    return mallocx(size, MALLOCX_ALIGN(64) | MALLOCX_ZERO);
}

static inline void* je_rallocx_aligned_zero(void* ptr, size_t size) {
    return rallocx(ptr, size, MALLOCX_ALIGN(64) | MALLOCX_ZERO);
}

// Override 10.3: Sized deallocation bypasses jemalloc's internal radix-tree
// lookup to resolve size class. ~10-50ns faster per free on the hot path.
static inline void je_sdallocx(void* ptr, size_t size) {
    sdallocx(ptr, size, 0);
}

// je_malloc_usable_size_raw returns the actual number of usable bytes jemalloc
// granted for a block allocated with mallocx/rallocx. jemalloc rounds every
// request up to the nearest size class, so the usable size is ALWAYS >= the
// requested size. M1/M2 FIX: we track and free against THIS size, never the
// caller-furnished requested size, so BytesAllocated() reflects true off-heap
// RSS and sdallocx receives exactly the size jemalloc recorded for the block
// (eliminating the size-class mismatch that risked jemalloc's size assertion
// or silent radix-tree corruption).
static inline size_t je_malloc_usable_size_raw(void* ptr) {
    return malloc_usable_size(ptr);
}
*/
import "C"

import (
	"sync/atomic"
	"unsafe"

	"github.com/apache/arrow/go/v17/arrow/memory"
)

// Compile-time interface satisfaction check.
var _ memory.Allocator = (*JemallocAllocator)(nil)

// JemallocAllocator implements memory.Allocator using CGO-bound jemalloc arenas.
// All memory allocated through this allocator is invisible to the Go GC.
// This is the foundational substrate for the zero-GC Temporal Store write path.
type JemallocAllocator struct {
	bytesAllocated atomic.Int64
}

// NewJemallocAllocator creates a new jemalloc-backed allocator.
func NewJemallocAllocator() *JemallocAllocator {
	return &JemallocAllocator{}
}

// Allocate returns a byte slice of the given size backed by jemalloc memory.
// The returned slice is NOT tracked by the Go GC.
// CRITICAL: The caller MUST call Free() when done, or memory will leak.
func (a *JemallocAllocator) Allocate(size int) []byte {
	if size <= 0 {
		return nil
	}

	// mallocx with MALLOCX_ZERO flag ensures zeroed memory (matching Go's behavior).
	ptr := C.je_mallocx_aligned_zero(C.size_t(size))
	if ptr == nil {
		panic("jemalloc: out of memory")
	}

	// M1/M2 FIX: account for the size-class-rounded USABLE size. The returned
	// slice has len = usableSize so:
	//   1. BytesAllocated equals true off-heap RSS jemalloc will release, so the
	//      MemTable 256MB ceiling is enforced against reality (not a systematic
	//      under-estimate that lets the engine blow through it after up-rounding).
	//   2. Free(b) passes len(b) = usableSize to sdallocx, which is exactly the
	//      size jemalloc recorded for the block — no size-class drift, no radix
	//      tree corruption.
	// usableSize is always >= size, so callers indexing [0:size) and the
	// transport reassembly buffer [0:bufCap] with bufCap <= usableSize stay in
	// bounds.
	usableSize := int(C.je_malloc_usable_size_raw(ptr))
	a.bytesAllocated.Add(int64(usableSize))

	// Create a Go slice header pointing at the jemalloc memory.
	// This slice is invisible to the GC — the GC will not scan, move, or free it.
	// len = usableSize: the full cache-line-rounded block is usable.
	return unsafe.Slice((*byte)(ptr), usableSize)
}

// Reallocate resizes a jemalloc-backed byte slice. The old data is preserved
// up to min(oldSize, newSize). The old memory is freed.
func (a *JemallocAllocator) Reallocate(size int, b []byte) []byte {
	if len(b) == 0 {
		return a.Allocate(size)
	}
	if size <= 0 {
		a.Free(b)
		return nil
	}

	oldSize := len(b)
	ptr := unsafe.Pointer(&b[0])

	newPtr := C.je_rallocx_aligned_zero(ptr, C.size_t(size))
	if newPtr == nil {
		panic("jemalloc: out of memory on realloc")
	}

	// M1/M2 FIX: rallocx may relocate the block (cross-size-class growth) and
	// ALWAYS grants a size-class-rounded usable size >= the new request. Account
	// for the delta between the OLD usable size (len(b)) and the NEW usable size
	// so BytesAllocated tracks the true RSS delta. The returned slice len matches
	// the size Free will release via sdallocx.
	newUsable := int(C.je_malloc_usable_size_raw(newPtr))
	a.bytesAllocated.Add(int64(newUsable - oldSize))

	return unsafe.Slice((*byte)(newPtr), newUsable)
}

// Free releases jemalloc-backed memory. After this call, the byte slice MUST
// NOT be accessed — it is undefined behavior.
func (a *JemallocAllocator) Free(b []byte) {
	if len(b) == 0 {
		return
	}

	ptr := unsafe.Pointer(&b[0])
	size := len(b)

	// Override 10.3: sdallocx with known size bypasses radix-tree lookup.
	C.je_sdallocx(ptr, C.size_t(size))

	a.bytesAllocated.Add(-int64(size))
}

// BytesAllocated returns the current number of bytes allocated via jemalloc.
// This is used for MemTable capacity enforcement (256MB ceiling).
func (a *JemallocAllocator) BytesAllocated() int64 {
	return a.bytesAllocated.Load()
}
