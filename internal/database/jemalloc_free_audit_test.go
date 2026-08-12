// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package database

// Regression guards for an intermittent internal/database jemalloc heap
// corruption (SIGSEGV addr=0x30 on the 64KB size class), root-caused
// to a WRONG-SIZE FREE: a caller freed a RESLICED jemalloc buffer (buf[:n]), so
// sdallocx received the content length n (3266) instead of the usable size
// jemalloc recorded (32768), returning a 32KB large block to the wrong size class
// and corrupting the heap metadata that a later 64KB flush alloc/free tripped
// over. The fix makes Free derive the size from malloc_usable_size (jemalloc's
// ground truth), not len(b). These guards pin that contract.

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

// The determinized culprit guard. Drives the EXACT wrong-size-free pattern (free a
// resliced buffer) and asserts the engine survives AND the usable-size accounting
// stays exact. Deterministic: pre-fix the accounting drift (Free subtracts
// len(b)=content, not the usable size) fails the balance check on EVERY run —
// it does not depend on the intermittent SIGSEGV. Bug-injection-proven: reverting
// Free to sdallocx(ptr, len(b)) makes this FAIL.
func TestReslicedFreeIsSafeAndBalanced(t *testing.T) {
	a := NewJemallocAllocator()
	base := a.BytesAllocated()
	const req = 32 * 1024 // the size class the wrong-size-free culprit crossed (32KB large)
	for i := 0; i < 512; i++ {
		buf := a.Allocate(req)
		content := 1000 + (i % 2000) // a variable content length < req
		for j := 0; j < content; j++ {
			buf[j] = byte(j)
		}
		// THE BUG PATTERN: free a reslice (buf[:content]), not the full buffer.
		// Pre-fix this corrupted the heap AND drifted the accounting; post-fix
		// Free frees the whole block via malloc_usable_size.
		a.Free(buf[:content])
	}
	if got := a.BytesAllocated(); got != base {
		t.Fatalf("resliced free mis-sized the accounting: BytesAllocated=%d, want %d — Free must free the usable size, not len(b)", got, base)
	}
	// Heap-integrity sweep on the 64KB victim size class: after 512 resliced
	// frees of 32KB blocks, allocating/freeing 64KB blocks must run clean.
	for i := 0; i < 256; i++ {
		x := a.Allocate(64 * 1024)
		x[0] = 1
		x[len(x)-1] = 2
		a.Free(x)
	}
	if got := a.BytesAllocated(); got != base {
		t.Fatalf("post-sweep BytesAllocated=%d, want %d", got, base)
	}
}

// The usable-size-exact accounting pin. The 2048->32768 anomaly was a
// symptom of the corrupted heap lying about a block's usable size; post-fix the
// accounting is exact on every transition. Pin: BytesAllocated tracks the live
// blocks' usable sizes exactly and returns to baseline after the last free.
func TestReallocateAccountingExact(t *testing.T) {
	a := NewJemallocAllocator()
	if got := a.BytesAllocated(); got != 0 {
		t.Fatalf("fresh allocator BytesAllocated=%d, want 0", got)
	}
	buf := a.Allocate(1024)
	if got := a.BytesAllocated(); got != int64(len(buf)) {
		t.Fatalf("after Allocate: BytesAllocated=%d, want len(buf)=%d", got, len(buf))
	}
	buf = a.Reallocate(2048, buf)
	if got := a.BytesAllocated(); got != int64(len(buf)) {
		t.Fatalf("after Reallocate grow: BytesAllocated=%d, want len(buf)=%d", got, len(buf))
	}
	buf = a.Reallocate(512, buf) // shrink
	if got := a.BytesAllocated(); got != int64(len(buf)) {
		t.Fatalf("after Reallocate shrink: BytesAllocated=%d, want len(buf)=%d", got, len(buf))
	}
	a.Free(buf)
	if got := a.BytesAllocated(); got != 0 {
		t.Fatalf("after Free: BytesAllocated=%d, want 0 (no drift)", got)
	}
}

// The audit instrument is LOAD-BEARING (not vacuous). Armed
// (SUPREMUM_JEMALLOC_AUDIT=1) it must (a) flag a resliced wrong-size free call
// and (b) PANIC on a double free. Runs the offending call in a subprocess so the
// panic cannot abort the parent suite. This guards the diagnostic that found the
// wrong-size-free defect against silently rotting into a tautology.
func TestAuditInstrumentIsLoadBearing(t *testing.T) {
	switch os.Getenv("JEMALLOC_AUDIT_SELFTEST") {
	case "wrongsize":
		// child: a resliced free (the wrong-size-free caller pattern) — the audit must LOG it.
		a := NewJemallocAllocator()
		buf := a.Allocate(32768)
		a.Free(buf[:1000])
		return
	case "doublefree":
		// child: a double free — audit must PANIC (this class stays unsafe).
		a := NewJemallocAllocator()
		buf := a.Allocate(4096)
		a.Free(buf)
		a.Free(buf)
		return
	}
	if testing.Short() {
		t.Skip("subprocess audit guard runs outside -short")
	}

	// Wrong-size arm: the fix makes the free safe, so the child EXITS CLEANLY,
	// but the armed audit must have logged the wrong-size call to stderr.
	cmdWrong := exec.Command(os.Args[0],
		"-test.run", "^TestAuditInstrumentIsLoadBearing$", "-test.count=1", "-test.v")
	cmdWrong.Env = append(os.Environ(), "SUPREMUM_JEMALLOC_AUDIT=1", "JEMALLOC_AUDIT_SELFTEST=wrongsize")
	outWrong, errWrong := cmdWrong.CombinedOutput()
	if !bytes.Contains(outWrong, []byte("WRONG-SIZE-FREE-CALL")) {
		t.Fatalf("armed audit did NOT flag a resliced wrong-size free (instrument is vacuous); output: %s (err=%v)", outWrong, errWrong)
	}

	// Double-free arm: the audit must PANIC (non-zero exit) naming the class.
	cmdDbl := exec.Command(os.Args[0],
		"-test.run", "^TestAuditInstrumentIsLoadBearing$", "-test.count=1")
	cmdDbl.Env = append(os.Environ(), "SUPREMUM_JEMALLOC_AUDIT=1", "JEMALLOC_AUDIT_SELFTEST=doublefree")
	outDbl, errDbl := cmdDbl.CombinedOutput()
	if errDbl == nil {
		t.Fatalf("armed audit did NOT panic on a double free (exit 0); instrument is vacuous; output: %s", outDbl)
	}
	if !bytes.Contains(outDbl, []byte("INVALID-OR-DOUBLE-FREE")) {
		t.Fatalf("armed audit double-free did not report INVALID-OR-DOUBLE-FREE; output: %s", outDbl)
	}
}
