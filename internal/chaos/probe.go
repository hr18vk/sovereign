// ---------------------------------------------------------------------------
// Stage 6 §2 — Worker crash probe: the deliberate off-heap SIGSEGV.
// ---------------------------------------------------------------------------
//
// The supervisor sends OpCrashProbe to ask the worker to self-destruct in the
// exact way Stage 6 §2 must recover from: a raw SIGSEGV in off-heap C-space
// that recover() CANNOT catch and that kills the whole worker process. A
// successful probe "response" is the silence of the worker's stdout pipe — the
// supervisor observes EOF (not an OpBye) and triggers WAL recovery.
//
// HONESTY ON THE CRASH MECHANISM (pre-mortem review):
//
//	recover() cannot catch SIGSEGV, but on Linux a dereference of a totally
//	unmapped address such as 0xDEADDEADDEADDEAD raises SIGSEGV and Go's default
//	handler prints a panic + stack trace and exits nonzero. The key property we
//	need is: the worker process DIES and its stdout closes, so the supervisor's
//	blocking ReadFrameFromReader returns io.EOF. We do NOT rely on the crash
//	being "truly unrecoverable" in a philosophical sense — we rely on the
//	process dying and the pipe closing, which is the observable contract the
//	supervisor's recovery loop keys off.
//
// HOW WE FAULT (deterministic, no probabilistic fuzzing required for the gate):
//  1. Take the engine's current HAMT root *HAMT and its off-arena root NodePtr.
//  2. If the engine has at least one inserted entity, the root node's bitmap is
//     non-zero and its childrenPtr points to a live children array. We corrupt
//     the FIRST child NodePtr slot in that array to 0xDEADDEADDEADDEAD, then
//     call State().Get(forThatChildEntity) so the traversal dereferences the
//     poisoned pointer → SIGSEGV.
//  3. If the engine is empty (no live children array to poison), we instead
//     synthesize the crash by writing 0xDEADDEADDEADDEAD into an arbitrary
//     within-arena uint64 slot that is NOT the root wrapper, then dereference
//     that address directly. The fuzzer's CorruptOffHeapPointer already
//     handles the out-of-range fallback; here we additionally guarantee a
//     dereference so the fault is observed THIS call, not eventually.
//
// PRE-MORTEM (3 catastrophic failure modes for THIS function):
//  1. We poison a slot that is NOT subsequently dereferenced by Get → the probe
//     "succeeds without crashing" → the worker exits nonzero via the
//     "probe did not SIGSEGV" path instead of via a real crash. The supervisor
//     must treat BOTH as "worker dead, recover" to be safe — and it does: any
//     stdout closure (EOF OR clean exit) triggers recovery.
//  2. The poisoned child slot happens to still land inside the arena mapping
//     (e.g. corruption produced a value < base+size). Then Get does NOT fault;
//     same fallback as (1). Mitigated by always or-ing the top bit, which on
//     aarch64/Graviton user-space is unmapped.
//  3. A concurrent InsertLocal rewrites root beneath us between corruption
//     and dereference, swapping in a fresh child array → we dereference the
//     OLD (now-dead) pointer, which may have been re-allocated. To avoid
//     racing the live fast path, the probe snapshots a single root HAMT and
//     operates ONLY on that snapshot; it does not touch the atomic engine
//     state. The corrupted pointer is in the snapshot's arena region, and EBR
//     keeps it resident for the duration of this call.
package chaos

import (
	"errors"
	"unsafe"

	"github.com/hr18vk/supremum/pkg/sync"
)

// WorkerExecuteCrashProbe deliberately corrupts an off-heap child pointer in
// the worker's engine and then dereferences it, raising a SIGSEGV that kills
// the worker process. The supervisor observes the resulting stdout EOF and
// triggers WAL recovery. This function does NOT return under normal operation;
// if control returns the probe failed to fault and the caller exits nonzero.
func WorkerExecuteCrashProbe(eng *sync.DeltaCRDTEngine) {
	if eng == nil {
		// Nothing to corrupt; still fault deterministically so the supervisor
		// sees a crash rather than a silent no-op.
		derefDeadPointer(unmappedFaultAddr)
		return
	}
	// R3 FIX (use-after-free): snapshot the HAMT state INSIDE an EBR epoch
	// pin. The previous revision read state := eng.State() with no pin and
	// then dereferenced an off-heap child pointer that a concurrent
	// InsertLocal/DeleteLocal CAS could have DecRef'd to 0, retired, and freed
	// via a racing AdvanceEpoch -- surfacing as a NON-DETERMINISTIC SIGSEGV
	// (a use-after-free) rather than the deterministic one the probe intends
	// to raise at the poisoned pointer. Pinning holds freeRetiredList back
	// for the structural read up to the deliberate fault, so the only SIGSEGV
	// the probe triggers is the one it asks for.
	//
	// Leak on the death paths: the probe is designed to terminate the worker
	// process via SIGSEGV. On the no-op-return path we Release() the
	// participant; on every fault path the process dies and the epoch is
	// irrelevant, with the participant slot reaped by OS teardown.
	ebr := eng.EBR()
	participant := ebr.Acquire()
	hasFaulted := false
	defer func() {
		// On any path that did NOT take the deliberate SIGSEGV, drop the pin.
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
	// the next pointer chase. To make the fault observable THIS call, we read
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
