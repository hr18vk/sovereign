// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// ---------------------------------------------------------------------------
// Worker crash probe: the deliberate off-heap SIGSEGV.
// ---------------------------------------------------------------------------
//
// The supervisor sends OpCrashProbe to ask the worker to self-destruct in the
// exact way the crash probe must recover from: a raw SIGSEGV in off-heap C-space
// that recover() cannot catch and that kills the whole worker process. A
// successful probe "response" is the silence of the worker's stdout pipe — the
// supervisor observes EOF (not an OpBye) and triggers WAL recovery.
//
// Crash mechanism:
//
//	recover() cannot catch SIGSEGV; on Linux, dereferencing an unmapped
//	address such as 0xDEADDEADDEADDEAD raises SIGSEGV and Go's default signal
//	handler terminates the worker process. The observable contract the
//	supervisor keys on is that the worker exits and its stdout closes, so the
//	supervisor's blocking ReadFrameFromReader returns io.EOF.
//
// How the probe faults deterministically:
//  1. Take the engine's current HAMT root and its off-arena root NodePtr.
//  2. If the engine has at least one inserted entity, the root node's bitmap is
//     non-zero and its childrenPtr points to a live children array. We corrupt
//     the first child NodePtr slot in that array via CorruptOffHeapPointer,
//     read the poisoned value, and dereference it directly with
//     derefDeadPointer -> SIGSEGV.
//  3. If the engine is empty or has no live children array (bitmap == 0), we
//     dereference the unmapped address 0xDEADDEADDEADDEAD directly.
//     CorruptOffHeapPointer also ORs the top bit when the pointer is in range.
//
// Failure modes:
//  1. If a poisoned slot is not subsequently dereferenced, the worker still
//     exits nonzero so any stdout closure (EOF or exit) triggers recovery.
//  2. If a poisoned child slot still falls inside the arena mapping, setting
//     the top bit moves it into unmapped arm64 user-space.
//  3. To avoid racing concurrent InsertLocal rewrites of the root, the probe
//     snapshots a single root HAMT under an EBR epoch pin so the underlying
//     arena region stays resident for the duration of this call.
package chaos

import (
	"errors"
	"unsafe"

	"github.com/hr18vk/sovereign/pkg/sync"
)

// WorkerExecuteCrashProbe deliberately corrupts an off-heap child pointer in
// the worker's engine and then dereferences it, raising a SIGSEGV that kills
// the worker process. The supervisor observes the resulting stdout EOF and
// triggers WAL recovery. This function does not return under normal operation;
// if control returns the probe failed to fault and the caller exits nonzero.
func WorkerExecuteCrashProbe(eng *sync.DeltaCRDTEngine) {
	if eng == nil {
		// Nothing to corrupt; still fault deterministically so the supervisor
		// sees a crash rather than a silent no-op.
		derefDeadPointer(unmappedFaultAddr)
		return
	}
	// Snapshot the HAMT state inside an EBR epoch pin so a concurrent
	// InsertLocal/DeleteLocal CAS cannot decrement and free the child array via
	// AdvanceEpoch while this structural read prepares the fault. On any early
	// return that does not fault, release the participant; on the fault path
	// the process terminates via SIGSEGV and OS teardown reaps the slot.
	ebr := eng.EBR()
	participant := ebr.Acquire()
	hasFaulted := false
	defer func() {
		// On any path that did not take the deliberate SIGSEGV, drop the pin.
		if !hasFaulted {
			ebr.Release(participant)
		}
	}()

	arena := eng.Arena()
	state := eng.State()
	if arena == nil || state == nil || arena.Base() == 0 || arena.Size() == 0 {
		derefDeadPointer(unmappedFaultAddr)
		return
	}
	baseLo := arena.Base()
	baseHi := baseLo + arena.Size()

	// Snapshot the live root HAMT and root node. EBR guarantees the root node
	// stays mapped for this goroutine's epoch; we operate on this snapshot only.
	rootPtr := state.RootPtr()
	if rootPtr == 0 {
		// Empty engine: no live node to poison. Synthesize the crash directly.
		// We corrupt a within-arena slot that is not the root wrapper and then
		// dereference the synthetic unmapped address — independent of any HAMT
		// node, so no EBR interaction.
		derefDeadPointer(unmappedFaultAddr)
		return
	}

	// HamtNode layout (pkg/sync/hamt_arena.go): refCount(4) + bitmap(4) +
	// pad(4) + childrenPtr(8) + entriesPtr(8) + merkleHash(32). We read the
	// root node's childrenPtr to locate the children array, then poison the
	// first child NodePtr slot. Layout offsets are computed structurally so
	// the probe does not depend on any unexported field name.
	const (
		offChildrenPtr = 12 // refCount(4)+bitmap(4)+pad(4)
	)
	rootNodeAddr := uintptr(rootPtr)
	if rootNodeAddr < baseLo || rootNodeAddr+offChildrenPtr+8 > baseHi {
		// Defensive: root pointer out of expected range. Synthesize.
		derefDeadPointer(unmappedFaultAddr)
		return
	}
	childrenPtrSlot := (*uint64)(unsafe.Pointer(rootNodeAddr + offChildrenPtr))
	childrenAddr := uintptr(*childrenPtrSlot)
	if childrenAddr == 0 || childrenAddr < baseLo || childrenAddr+8 > baseHi {
		// No live children array (bitmap == 0). Synthesize the crash.
		derefDeadPointer(unmappedFaultAddr)
		return
	}
	firstChildSlot := (*uint64)(unsafe.Pointer(childrenAddr))
	// Poison the first child pointer to a guaranteed-unmapped address.
	before, after, err := CorruptOffHeapPointer(baseLo, baseHi, unsafe.Pointer(firstChildSlot))
	_ = before
	_ = after
	if err != nil {
		// CorruptOffHeapPointer refused (shouldn't happen here). Synthesize.
		derefDeadPointer(unmappedFaultAddr)
		return
	}
	// Force the dereference of the poisoned child pointer. We only need to
	// *read* the now-poisoned uint64 as a NodePtr; the actual SIGSEGV fires on
	// the next pointer chase. To make the fault observable this call, we read
	// the corrupted value and dereference it directly.
	poisoned := uintptr(*firstChildSlot)
	// This deref is the deliberate, deterministic SIGSEGV the probe is
	// designed to raise. Mark faulted so the deferred pin Release is skipped
	// — the process dies here anyway.
	hasFaulted = true
	derefDeadPointer(poisoned)
	_ = err
	_ = errors.New // keep errors import if needed by future revisions
}

// unmappedFaultAddr is a synthetic address guaranteed outside any aarch64
// user-space mapping: the top bit set makes it above 2^63. Dereferencing it
// raises SIGSEGV.
const unmappedFaultAddr uintptr = 0xDEADDEAD_DEADDEAD

// derefDeadPointer reads 1 byte at addr via a volatile unsafe read. The
// compiler cannot elide it because the escape is through unsafe.Pointer. If
// addr is unmapped this raises SIGSEGV and the process dies.
//
//go:noinline
func derefDeadPointer(addr uintptr) {
	if addr == 0 {
		addr = unmappedFaultAddr
	}
	// volatile read via the unsafeptr intrinsic path: assign through a pointer
	// the optimizer cannot prove is dead.
	p := (*byte)(unsafe.Pointer(addr))
	_ = *p
}
