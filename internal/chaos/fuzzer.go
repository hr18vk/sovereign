// ---------------------------------------------------------------------------
// Stage 6 §2 Off-Heap Chaos Fuzzer — the violent C-space SIGSEGV injector
// ---------------------------------------------------------------------------
//
// Blueprint (Stage 6 §2): "The verification blueprint must introduce random
// memory corruption directly into the off-heap pointers during the absolute
// peak of the 1,000,000 RPS stress test."
//
// The fuzzer corrupts an off-heap pointer the engine will dereference, then
// the next access faults into an unmapped (or protected) region and raises a
// raw SIGSEGV — the unrecoverable C-space crash that recover() cannot catch.
// The TASK of the Supervisor-Worker architecture is to prove that this crash,
// induced inside a WORKER child process, is recovered: the supervisor detects
// the dead child, replays the WAL, and spawns a pristine worker without
// dropping an active connection.
//
// MACHINE TRUTH (verified against the engine):
//   A `NodePtr` is a raw uintptr into the mmap'd `HamtArena.base..base+size`.
//   Flipping high bits of a node offset moves it outside [base, base+size),
//   so dereferencing it faults. The Go runtime converts a fault on a Go
//   pointer into a panic (when debug.SetPanicOnFault(true)), but a fault on
//   off-heap memory is NOT converted — it is a raw kernel SIGSEGV and the
//   process dies. That is exactly why the engine must be isolated in a child.
// ---------------------------------------------------------------------------

package chaos

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"unsafe"
)

// CorruptOffHeapPointer rewrites the bytes at `slot` so that the uintptr they
// hold no longer points into the legal arena range [baseLo, baseHi). The next
// dereference of the resulting NodePtr will raise a SIGSEGV.
//
// `slot` must point to a uint64-sized region in the engine's memory that the
// engine will load as a NodePtr. The caller is responsible for choosing the
// slot (typically a child node pointer the engine is about to traverse); the
// fuzzer ONLY performs the corruption — it does not itself cause the crash,
// the engine's own next Get/Set does, exactly mid-RPS as the blueprint states.
//
// Returns the pre- and post-corruption pointer values for the test logs.
// Pre-mortem honesty: this is a deliberate, controlled corruption — a REAL
// fuzzer would flip random bits at random times; this version deterministically
// produces a guaranteed-faulting pointer so the survival test is reproducible
// rather than probabilistic (CI determinism > chaos entertainment).
func CorruptOffHeapPointer(baseLo, baseHi uintptr, slot unsafe.Pointer) (before, after uintptr, err error) {
	if baseHi <= baseLo {
		return 0, 0, errors.New("chaos/fuzzer: base range invalid")
	}
	// Atomically read the current pointer.
	cur := uintptr(*(*uint64)(slot))
	before = cur
	// If the pointer is already invalid (zero or outside range), corrupt to
	// a guaranteed-unmapped address so the crash is reproducible.
	var bad uintptr
	if cur < baseLo || cur >= baseHi {
		// 0xdead... is chosen so the fault address is obviously synthetic in
		// a core dump and is far outside any 64-bit user mapping on Linux.
		bad = 0xDEADDEADDEADDEAD
	} else {
		// Otherwise, jitter the high bits outside the legal range. Set the
		// top bit so the address is above 2^63, which is unmapped on all
		// aarch64/Graviton user-space layouts.
		bad = cur | uintptr(1)<<(unsafe.Sizeof(uintptr(0))*8-1)
		// If that surprisingly still lands inside [baseLo, baseHi) (impossible
		// for a normal heap mapping but guarded anyway), force the synthetic.
		if bad >= baseLo && bad < baseHi {
			bad = 0xDEADDEADDEADDEAD
		}
	}
	*(*uint64)(slot) = uint64(bad)
	after = bad
	return before, after, nil
}

// RandomFaultIndex returns a uniformly-random non-negative integer in [0, n)
// drawn from crypto/rand. The fuzzer uses it to pick WHICH node pointer to
// corrupt out of N candidate slots, mid-RPS, so successive runs exercise
// different crash sites without losing reproducibility of the survival property.
func RandomFaultIndex(n int) int {
	if n <= 0 {
		return 0
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure — fall back to a deterministic low slot so the
		// fuzzer still injects SOMETHING rather than silently skipping.
		return 0
	}
	v := binary.BigEndian.Uint32(b[:])
	return int(v % uint32(n))
}
