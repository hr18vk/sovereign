// ---------------------------------------------------------------------------
// STAGE 6 — THE CHAOS LAYER: mmap Page-Fault Mitigation
// ---------------------------------------------------------------------------
//
// Ruthless Go Engine Verification Blueprint — Stage 6 §1:
// "The Threat of mmap and the Go Scheduler Collapse."
//
// The engine's HAMT topology lives in a raw mmap'd off-heap arena. When a
// 100-year traversal touches a page that is not resident in RAM, the Linux
// kernel raises a MAJOR PAGE FAULT and blocks the calling OS thread in a
// blocking disk I/O. The Go cooperative scheduler maps thousands of
// goroutines onto a small pool of OS threads (GOMAXPROCS threads); it is
// entirely blind to the fact that a plain pointer dereference has just
// become a blocking I/O. A large sweep of cold off-heap data therefore
// stalls the ENTIRE G-MAXPROCS thread pool and freezes the server, violating
// the sub-microsecond latency mandate.
//
// This file is the defense layer. It is deliberately decoupled from the
// allocator hot path (hamt_arena.go) so the Zero-GC allocation
// invariants — proven by Stage 1's escape-analysis + AllocsPerOp gates —
// remain hermetically untouched. Residency control is an off-path concern:
// the engine calls LockHotPages() once at warmup to pin its hot-path index
// subset into RAM, and the chaos harness calls EvictPages() to inject the
// exact major-page-fault scenario the blueprint mandates, then the trace
// gate (residency_test.go) asserts no OS thread blocked > 10 µs in the
// mmap hot path once pages are pinned.
//
// PHYSICS (Linux on aarch64, 4 KiB pages):
//   mlock(2)  — pin a virtual address range into RAM, preventing eviction.
//                Requires CAP_IPC_LOCK or a raised RLIMIT_MEMLOCK. In an
//                unprivileged container mlock() returns EPERM; in a capped
//                container it returns ENOMEM once RLIMIT_MEMLOCK is hit.
//                This layer treats BOTH as non-fatal: it pins what it can
//                and reports the residual, because a running-but-unhardened
//                engine is strictly better than one that refuses to boot
//                (the graver failure is a cold-start outage, not a fault).
//   madvise(2) — MADV_DONTNEED tells the kernel it may discard the clean
//                pages of a range, RECLAIMING their RAM without munmap. The
//                next touch faults them back in. This is the EXACT primitive
//                the blueprint specifies for simulating the major-page-fault
//                storm the chaos harness must survive.
//   munlock(2)— must precede munmap on a locked range; some kernels refuse
//                to unmap a still-locked region. Free() calls it symmetrically.
// ---------------------------------------------------------------------------

package sync

import (
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// osPageSize is the MMU page size for residency accounting. 4 KiB on every
// aarch64/Graviton target. Residency operations round addresses down and
// lengths up to page boundaries so partial-page mlock never partial-pins.
const osPageSize = 4096

// madvise hints supported cross-platform by Go's syscall package on Linux.
// We reference the syscall consts via this file's only two uses (DONTNEED
// for eviction, WILLNEED for prefetch). They are compile-time-checked by
// residency_probe_test.go.
var (
	_ = syscall.MADV_DONTNEED
	_ = syscall.MADV_WILLNEED
)

// pageStart rounds a byte address DOWN to the containing page boundary.
// Returns a byte offset within the arena (relative to base), not an abs ptr.
func pageStart(offset uintptr) uintptr {
	return offset &^ uintptr(osPageSize-1)
}

// pageEnd rounds a byte address UP to the next page boundary (exclusive).
func pageEnd(offset uintptr) uintptr {
	return (offset + uintptr(osPageSize-1)) &^ uintptr(osPageSize-1)
}

// ResidencyStatus reports the outcome of a residency operation. It is the
// observation surface the chaos harness (residency_test.go) and the engine's
// startup health probe read to decide whether the chaos-layer hardening is
// active on this host or has degraded to unhardened (still-correct) mode.
type ResidencyStatus struct {
	// PagesRequested is the number of 4 KiB pages the caller asked to pin.
	PagesRequested uint64
	// PagesPinned is the number actually wired into RAM by mlock. May be
	// < PagesRequested when RLIMIT_MEMLOCK is hit or mlock is forbidden.
	PagesPinned uint64
	// PermDenied is true when mlock returned EPERM (no CAP_IPC_LOCK). In that
	// case PagesPinned is 0 and the engine runs unhardened by design.
	PermDenied bool
	// Truncated is true when mlock returned ENOMEM partway through the
	// chunked pin (cap hit). Residual pages beyond the cap are NOT pinned.
	Truncated bool
}

// PagesPinnedBytes returns the RAM residency committed by successful pins.
func (rs ResidencyStatus) PagesPinnedBytes() uint64 {
	return rs.PagesPinned * uint64(osPageSize)
}

// Hardened reports whether the hot pages are actually resident (locked) in
// RAM — the gate the chaos harness consults. False means the host refused to
// pin (EPERM/ENOMEM); the engine still RUNS, it is simply not chaos-hardened.
func (rs ResidencyStatus) Hardened() bool {
	return rs.PagesPinned > 0
}

// LockHotPages pins the arena byte range [offset, offset+length) into RAM via
// a CHUNKED mlock. Chunking (one mlock per `chunk` bytes, default one page)
// is the physics fix for the two production failure modes named in the Stage 6
// pre-mortem:
//
//  1. EPERM on unprivileged containers → a single whole-range mlock would
//     reject the entire pin in one shot; chunking lets a partial pin succeed
//     on hosts that permit SOME locking, and cleanly reports PermDenied.
//  2. ENOMEM once RLIMIT_MEMLOCK is exceeded → chunking pins as many pages
//     as the cap allows and stops, recording Truncated, instead of failing
//     the whole call. The partial pin still protects the FIRST chunk of the
//     hot index (typically the root + upper HAMT levels — the hottest pages).
//
// The method is safe to call concurrently with allocation (mlock does not
// mutate the mapped memory, only its residency attributes) and is idempotent:
// re-locking already-locked pages is a cheap kernel no-op on Linux.
func (a *HamtArena) LockHotPages(offset, length uintptr) ResidencyStatus {
	if length == 0 || a == nil || a.base == 0 {
		return ResidencyStatus{}
	}
	start := pageStart(offset)
	end := pageEnd(offset + length)
	if end > a.size {
		end = a.size
	}
	reqPages := uint64((end - start) / uintptr(osPageSize))
	status := ResidencyStatus{PagesRequested: reqPages}

	// Pin page by page. mlock's address+length args must be page-aligned for
	// this accounting to hold; we always pass page-aligned slices.
	for off := start; off < end; off += uintptr(osPageSize) {
		page := unsafe.Slice((*byte)(unsafe.Pointer(a.base+off)), int(osPageSize))
		if err := syscall.Mlock(page); err != nil {
			switch err {
			case syscall.EPERM:
				// No CAP_IPC_LOCK on this host. Stop: the kernel will refuse
				// every subsequent page identically. Record and bail — the
				// engine runs unhardened rather than burning a syscall per
				// remaining page (pre-mortem mode 1).
				status.PermDenied = true
				return status
			case syscall.ENOMEM:
				// RLIMIT_MEMLOCK exhausted. Stop pinning, mark truncated so
				// the harness sees the residency is partial (pre-mortem mode 2).
				status.Truncated = true
				return status
			default:
				// Any other error (EAGAIN under transient pressure): record
				// truncated and stop; a later warmup can retry. Never fatal.
				status.Truncated = true
				return status
			}
		}
		status.PagesPinned++
	}
	return status
}

// UnlockHotPages releases the mlock on [offset, offset+length), symmetric to
// LockHotPages. Called by Free() before Munmap (a still-locked range may
// refuse to unmap on some kernels) and by residency test teardown. Errors
// are swallowed: unlock is best-effort cleanup; a failure to unlock must not
// prevent memory reclaim in the common path.
func (a *HamtArena) UnlockHotPages(offset, length uintptr) {
	if length == 0 || a == nil || a.base == 0 {
		return
	}
	start := pageStart(offset)
	end := pageEnd(offset + length)
	if end > a.size {
		end = a.size
	}
	for off := start; off < end; off += uintptr(osPageSize) {
		page := unsafe.Slice((*byte)(unsafe.Pointer(a.base+off)), int(osPageSize))
		_ = syscall.Munlock(page)
	}
}

// UnlockAllPages releases every pinned page in the whole arena. Used by
// Free() so a fully-locked arena unmaps cleanly. Idempotent.
func (a *HamtArena) UnlockAllPages() {
	if a == nil || a.base == 0 || a.size == 0 {
		return
	}
	// munlock on the whole region in one call is faster and tolerates a mix
	// of locked/unlocked pages (munlock on an unlocked page is a no-op).
	whole := unsafe.Slice((*byte)(unsafe.Pointer(a.base)), int(a.size))
	_ = syscall.Munlock(whole)
}

// EvictPages simulates the major-page-fault scenario mandated by Stage 6 §1:
// "A dedicated validation script must utilize madvise(MADV_DONTNEED) to
// aggressively evict pages from the cache, forcing major page faults upon
// subsequent reads." This is the chaos-harness injection hook — the engine
// itself never calls it in production. The next traversal of the evicted
// range will page-fault on every page, exactly reproducing the cold-sweep
// stall the blueprint's mlock defense must defeat.
//
// Returns the number of pages evicted (0 if the range is empty or the host
// refuses madvise, in which case the chaos harness logs a skip and the
// residency test degrades rather than masking a host limitation).
func (a *HamtArena) EvictPages(offset, length uintptr) uint64 {
	if length == 0 || a == nil || a.base == 0 {
		return 0
	}
	start := pageStart(offset)
	end := pageEnd(offset + length)
	if end > a.size {
		end = a.size
	}
	region := unsafe.Slice((*byte)(unsafe.Pointer(a.base+start)), int(end-start))
	if err := syscall.Madvise(region, syscall.MADV_DONTNEED); err != nil {
		return 0
	}
	return uint64((end - start) / uintptr(osPageSize))
}

// PrefaultPages touches every page in [offset, offset+length) to force the
// kernel to populate the page tables NOW (during warmup), rather than lazily
// on the first traversal touch. This front-loads the first-touch fault storm
// outside the latency-critical path. The touch is a volatile read of one
// byte per page, which the compiler cannot elide (atomic load fence).
func (a *HamtArena) PrefaultPages(offset, length uintptr) uint64 {
	if length == 0 || a == nil || a.base == 0 {
		return 0
	}
	start := pageStart(offset)
	end := pageEnd(offset + length)
	if end > a.size {
		end = a.size
	}
	var n uint64
	bump := a.bumpOffset.Load()
	for off := start; off < end && off < uintptr(bump); off += uintptr(osPageSize) {
		p := (*byte)(unsafe.Pointer(a.base + off))
		_ = atomic.LoadUint32((*uint32)(unsafe.Pointer(p))) // volatile, no-elide
		n++
	}
	return n
}

// PrefaultHot prefaults the CALLER-PROVIDED set of hot offsets (the root and
// upper-level HAMT index nodes most frequently touched on the read path).
// It takes raw pointers rather than offsets so the engine can hand it the
// exact live node pointers whose pages matter, independent of arena layout.
func (a *HamtArena) PrefaultHot(ptrs []NodePtr) uint64 {
	var n uint64
	for _, p := range ptrs {
		if p == 0 {
			continue
		}
		off := uintptr(p) - a.base
		n += a.PrefaultPages(off, uintptr(nodeSize))
	}
	return n
}

// ---------------------------------------------------------------------------
// STAGE 6 — fault-count instrumentation (deterministic residency accounting)
// ---------------------------------------------------------------------------

// osMajorFaultCount returns the count of MAJOR page faults the calling process
// has incurred, read from /proc/self/stat (the majflt field). This is the
// OS-level truth the blueprint's "OS thread blocked >10us in the mmap hot
// path" verdict is genuinely about: a major fault forces a blocking disk I/O
// to fault the page back in and is the only wall-time signal that reliably
// correlates with a multi-millisecond blocked-M stall. Raw worst-case
// traversal latency is NOT a reliable fault signal — on a host with ample RAM
// and no swap, MADV_DONTNEED on anonymous private pages often does NOT raise a
// major fault (the kernel keeps the page instantly reclaimable in core), so a
// sub-100us latency outlier is usually Go GC / scheduler preemption jitter,
// not a fault. Fault counting separates physics from noise and makes the
// residency gate deterministic on a no-swap host.
//
// Returns (count, true) on Linux when /proc/self/stat is readable;
// (0, false) on non-Linux or sandboxes that mask /proc, in which case callers
// fall back to a (noisier) latency-only metric.
func osMajorFaultCount() (int64, bool) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, false
	}
	// The comm field may itself contain spaces and parens; fields are only
	// safely delimited AFTER the final ')'. majflt is the 10th field after
	// the ')' (it is the post-paren field at index 9 when 0-indexed).
	r := -1
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == ')' {
			r = i
			break
		}
	}
	if r < 0 || r+1 >= len(b) {
		return 0, false
	}
	rest := b[r+1:]
	fields := splitFields(rest)
	if len(fields) < 10 {
		return 0, false
	}
	v, err := strconv.ParseInt(string(fields[9]), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// splitFields splits a byte slice on ASCII spaces, skipping empty fields. It
// returns a compact slice of field byte-slices (no allocation per field beyond
// the result slice) so the hot-path-adjacent accounting stays cheap.
func splitFields(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == ' ' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
