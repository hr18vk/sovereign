// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

// Regression tests for jemalloc Free() usable-size tracking.
//
// Free derives the block's allocation size from malloc_usable_size rather than
// len(b) so freeing a resliced buffer (buf[:n]) still returns the full block to
// the right jemalloc size class and keeps BytesAllocated accurate.

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

// TestReslicedFreeIsSafeAndBalanced frees resliced 32KB buffers and verifies
// BytesAllocated stays balanced across subsequent 64KB allocations.
func TestReslicedFreeIsSafeAndBalanced(t *testing.T) {
	a := NewJemallocAllocator()
	base := a.BytesAllocated()
	const req = 32 * 1024 // the size class the corruption crossed (32KB large)
	for i := 0; i < 512; i++ {
		buf := a.Allocate(req)
		content := 1000 + (i % 2000) // a variable content length < req
		for j := 0; j < content; j++ {
			buf[j] = byte(j)
		}
		// The bug pattern: free a reslice (buf[:content]), not the full buffer.
		// Pre-fix this corrupted the heap and drifted the accounting; post-fix
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

// TestReallocateAccountingExact verifies BytesAllocated tracks usable sizes
// across Allocate, grow/shrink Reallocate, and Free.
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

// TestAuditInstrumentIsLoadBearing verifies that SUPREMUM_JEMALLOC_AUDIT=1
// logs resliced frees and panics on double frees in isolated subprocesses.
func TestAuditInstrumentIsLoadBearing(t *testing.T) {
	switch os.Getenv("JEMALLOC_AUDIT_SELFTEST") {
	case "wrongsize":
		// child: a resliced free (the corruption caller pattern) — the instrument must log it.
		a := NewJemallocAllocator()
		buf := a.Allocate(32768)
		a.Free(buf[:1000])
		return
	case "doublefree":
		// child: a double free — the instrument must panic (this class stays unsafe).
		a := NewJemallocAllocator()
		buf := a.Allocate(4096)
		a.Free(buf)
		a.Free(buf)
		return
	}
	if testing.Short() {
		t.Skip("subprocess audit test runs outside -short")
	}

	// Wrong-size arm: the fix makes the free safe, so the child exits cleanly,
	// but the armed instrument must have logged the wrong-size call to stderr.
	cmdWrong := exec.Command(os.Args[0],
		"-test.run", "^TestAuditInstrumentIsLoadBearing$", "-test.count=1", "-test.v")
	cmdWrong.Env = append(os.Environ(), "SUPREMUM_JEMALLOC_AUDIT=1", "JEMALLOC_AUDIT_SELFTEST=wrongsize")
	outWrong, errWrong := cmdWrong.CombinedOutput()
	if !bytes.Contains(outWrong, []byte("WRONG-SIZE-FREE-CALL")) {
		t.Fatalf("armed audit did not flag a resliced wrong-size free; output: %s (err=%v)", outWrong, errWrong)
	}

	// Double-free arm: the instrument must panic (non-zero exit) naming the class.
	cmdDbl := exec.Command(os.Args[0],
		"-test.run", "^TestAuditInstrumentIsLoadBearing$", "-test.count=1")
	cmdDbl.Env = append(os.Environ(), "SUPREMUM_JEMALLOC_AUDIT=1", "JEMALLOC_AUDIT_SELFTEST=doublefree")
	outDbl, errDbl := cmdDbl.CombinedOutput()
	if errDbl == nil {
		t.Fatalf("armed instrument did not panic on a double free (exit 0); output: %s", outDbl)
	}
	if !bytes.Contains(outDbl, []byte("INVALID-OR-DOUBLE-FREE")) {
		t.Fatalf("armed audit double-free did not report the expected class; output: %s", outDbl)
	}
}
