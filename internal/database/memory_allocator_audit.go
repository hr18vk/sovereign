// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package database

// Heap-audit diagnostic instrument for the jemalloc allocator.
//
// ARMED only when SUPREMUM_JEMALLOC_AUDIT is set in the environment. In
// production (env unset) every hook is a single never-taken package-bool branch
// with ZERO allocation — the hot-path gate is unaffected.
//
// WHY THIS INSTRUMENT: the fault is an intermittent jemalloc heap corruption
// (SIGSEGV addr=0x30 on the 64KB size class) that (a) a -race run cannot see
// (cgo/jemalloc memory is outside the Go data-race model) and (b) the jemalloc
// redzone cannot see (this 5.3.0 build REJECTS redzone:true). Isolated repros of
// the flush path are CLEAN, so the corruption is SEEDED by one suite test and
// DETONATES in another (the process-global jemalloc heap is shared across every
// JemallocAllocator instance in one `go test` process). To catch the CULPRIT
// (not the victim) we register every live block and validate every Free:
//
//	INVALID FREE    — Free of a ptr jemalloc never handed out here (or interior).
//	DOUBLE FREE     — Free of a ptr already freed (still-registered => live).
//	WRONG-SIZE FREE — Free with a len != the usable size recorded at alloc
//	                  (the size-accounting contract; a mismatch feeds sdallocx a
//	                  wrong size class => heap metadata corruption at a later op).
//
// It adds NO guard bands and does NOT change any size passed to mallocx/sdallocx,
// so it does NOT perturb the heap layout or mask the size contract under test.
// (OOB-write / UAF-write detection is the separate guard-band variant.)

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

// jemallocAuditOn is read once at package init. Package-level + immutable so the
// hot-path check is a single predictable branch (no atomic load, no alloc).
var jemallocAuditOn = os.Getenv("SUPREMUM_JEMALLOC_AUDIT") != ""

// auditRec records one live block: the usable size jemalloc granted and the
// allocation stack (for attributing a later bad free to its origin). Fields are
// ordered pointer-first to stay fieldalignment-clean (diagnostic, off hot path).
type auditRec struct {
	stack []uintptr
	size  int
}

var jemallocAuditReg = struct {
	live map[uintptr]*auditRec
	mu   sync.Mutex
}{live: make(map[uintptr]*auditRec)}

// auditCallers captures a compact PC stack for later attribution.
func auditCallers() []uintptr {
	var pcs [24]uintptr
	n := runtime.Callers(3, pcs[:]) // skip Callers, the hook, the allocator method
	out := make([]uintptr, n)
	copy(out, pcs[:n])
	return out
}

func auditFormatStack(pcs []uintptr) string {
	if len(pcs) == 0 {
		return "(no stack)"
	}
	frames := runtime.CallersFrames(pcs)
	out := ""
	for {
		fr, more := frames.Next()
		out += fmt.Sprintf("\n    %s:%d %s", fr.File, fr.Line, fr.Function)
		if !more {
			break
		}
	}
	return out
}

func auditAllocHook(ptr unsafe.Pointer, usableSize int) {
	if !jemallocAuditOn {
		return
	}
	p := uintptr(ptr)
	jemallocAuditReg.mu.Lock()
	jemallocAuditReg.live[p] = &auditRec{size: usableSize, stack: auditCallers()}
	jemallocAuditReg.mu.Unlock()
}

// auditReallocHook retires the old pointer and registers the new one. rallocx may
// grow in place (old==new) or relocate; either way the registry ends with exactly
// the live block recorded.
func auditReallocHook(oldPtr, newPtr unsafe.Pointer, newUsable int) {
	if !jemallocAuditOn {
		return
	}
	jemallocAuditReg.mu.Lock()
	if oldPtr != newPtr {
		delete(jemallocAuditReg.live, uintptr(oldPtr))
	}
	jemallocAuditReg.live[uintptr(newPtr)] = &auditRec{size: newUsable, stack: auditCallers()}
	jemallocAuditReg.mu.Unlock()
}

// auditFreeHook runs BEFORE the free (call-site gated on jemallocAuditOn). It is
// a DETECTOR: a DOUBLE or INVALID free (the pointer is not a live registered
// block) is a hard panic with the culprit stack — the sized-free fix does NOT make
// double-free safe (malloc_usable_size on a freed block is UB), so this stays a
// guard. A WRONG-SIZE free call (callerLen != the usable size recorded at alloc)
// is now HARMLESS (Free derives the size from malloc_usable_size, not len(b)),
// but is logged as a caller bug — a resliced free is always a mistake.
func auditFreeHook(ptr unsafe.Pointer, callerLen int) {
	p := uintptr(ptr)
	jemallocAuditReg.mu.Lock()
	rec, ok := jemallocAuditReg.live[p]
	if ok {
		delete(jemallocAuditReg.live, p)
	}
	jemallocAuditReg.mu.Unlock()

	if !ok {
		auditReportFatal("INVALID-OR-DOUBLE-FREE", p, callerLen, nil)
		return
	}
	if rec.size != callerLen {
		fmt.Fprintf(os.Stderr, "\n[JEMALLOC-AUDIT] WRONG-SIZE-FREE-CALL ptr=%#x caller_len=%d (0x%x) recorded_usable=%d (0x%x) (harmless post-fix; caller resliced before Free)\n[JEMALLOC-AUDIT] alloc stack:%s\n",
			p, callerLen, callerLen, rec.size, rec.size, auditFormatStack(rec.stack))
	}
}

func auditReportFatal(kind string, ptr uintptr, size int, rec *auditRec) {
	fmt.Fprintf(os.Stderr, "\n[JEMALLOC-AUDIT] %s ptr=%#x free_size=%d (%#x)\n", kind, ptr, size, size)
	if rec != nil {
		fmt.Fprintf(os.Stderr, "[JEMALLOC-AUDIT] recorded_usable_size=%d (%#x)\n[JEMALLOC-AUDIT] alloc stack:%s\n",
			rec.size, rec.size, auditFormatStack(rec.stack))
	}
	// Panic (not os.Exit) so the Go runtime dumps ALL goroutine stacks — the
	// concurrent context that -race could not attribute.
	panic("JEMALLOC-AUDIT: " + kind)
}
