// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

// Heap-audit instrument for the jemalloc allocator.
//
// Armed only when SUPREMUM_JEMALLOC_AUDIT is set in the environment. When unset,
// every hook is a single predictable branch with zero allocation.
//
// Records live allocations and checks Free calls for invalid/double frees and
// caller length mismatches against malloc_usable_size without altering size
// classes or allocator layout.

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

// auditFreeHook validates a Free call before deallocation: an unregistered
// pointer panics with the stack trace, while a resliced length mismatch is
// logged before Free frees the recorded usable size.
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
	// Panic (not os.Exit) so the Go runtime dumps all goroutine stacks — the
	// concurrent context that -race could not attribute.
	panic("JEMALLOC-AUDIT: " + kind)
}
