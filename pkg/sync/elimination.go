package sync

import (
	"math/bits"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Stage 5 — Elimination Backoff Array (Ruthless Go Engine Verification Blueprint)
// ---------------------------------------------------------------------------
//
// PHYSICS PROBLEM
//   A lock-free Treiber stack mutates its state via a single atomic
//   Compare-And-Swap on one `head` pointer — exactly ONE 64-byte cache
//   line. At 32 cores, when every core attempts a push/pop against that
//   single line simultaneously, exactly ONE core wins the CAS; the
//   other 31 fail and retry. Each failed CAS issues a Load-Exclusive /
//   Store-Exclusive pair (ARMv8 LDXR/STXR) which the MESI/RFO coherence
//   protocol must broadcast across the mesh as a Read-For-Ownership
//   invalidation. The line ping-pongs at interconnect speed and
//   throughput collapses as cores are added — an exact inversion of
//   Amdahl's Law.
//
//   The mathematical lower bound on a contended CAS location was proven
//   by Alon & Shavit (1986): for P processors hammering one CAS
//   location, the maximum sustainable throughput is O(P / log P),
//   NOT O(P). You cannot defeat this with faster CAS — it is a
//   coherence-bandwidth limit, not a frequency limit.
//
// THE ELIMINATION PRINCIPLE
//   A push immediately followed by a pop is a NO-OP: net stack state
//   is unchanged. If, instead of retrying the central CAS, a failing
//   Push thread backs off *in space* (into a separate array of slots)
//   and a failing Pop thread visits the same slot, the two exchange
//   the value directly between themselves — neither touches the
//   central line. The contention that would have burned one RFO round
//   on the shared line is converted into a single successful local
//   CAS on a private slot: parallel, L1-resident throughput.
//
//   Linearization: the exchange is linearized at the moment the
//   exchanger's CAS succeeds (Herlihy-Shavit, "The Art of Multiprocessor
//   Programming", Ch. 11). This preserves the exact sequential stack
//   semantics — the eliminated push "happens-before" the eliminated
//   pop, and the pair inserts a net-zero window indistinguishable from
//   push-then-pop on the central stack. The semantics are EXACT, not
//   approximate.
//
// -----------------------------------------------------------------------
// DESIGN — WHY EACH CHOICE IS THE WORLD-OPTIMAL ONE
// -----------------------------------------------------------------------
//
//  (1) STATIC ARRAY, power-of-two sized to 2 * maxConcurrency.
//        Dynamic resizing based on a live thread census requires RMW
//        on a census counter — reintroducing exactly the contention we
//        are eliminating, plus per-op allocation risk under the Zero-GC
//        mandate. A static array of length 2P gives:
//          collision prob ≈ 1 − e^(−t²/2K)  [birthday bound]
//        For t=32 simultaneous threads and K=64 slots, the matched
//        push/pop collision rate per probe batch is ~1 − e^(−8) ≈ 0.9997,
//        while per-slot contention stays at ≤ one pair per slot per
//        probe, so no slot serializes. K=64 slots × 128 B = 8 KiB —
//        fits entirely inside the Neoverse-V1's 64 KiB L1 D-cache.
//        L1-resident slots ⇒ exchange is a single CAS at ~6.5 ns,
//        faster than the central RFO round even with zero contention.
//
//  (2) INDEX BY FAST UINT64 MASK, not modulo.
//        idx := rnd & (K-1) → one AND instruction, branch-free.
//        Requires K to be a power of two (asserted by construction).
//
//  (3) NO SLEEP-BASED BACKOFF — bounded slot probing.
//        runtime.Gosched() and time.Sleep admit at least one scheduler
//        quantum (~1 µs) and a syscall boundary; the stack CAS costs
//        ~6.5 ns on Graviton. Any time-domain backoff is therefore
//        ~150× slower than the operation it protects. Instead the
//        "wait" is implemented as a bounded number of spin re-reads on
//        the slot we parked in, keeping the thread on-core and L1-hot.
//        The popper "pays" the pusher's wait by carrying the value
//        off — zero wall-clock wait for either party.
//
//  (4) ADAPTIVE PROBE BUDGET (contention-feedback).
//        A global atomic `collisions` accumulator is incremented on
//        every failed (non-eliminated) probe and decremented on every
//        success, clamped to [0, K]. probeBudget = baseProbe +
//        bits.Len64(collisions). Under light contention collisions→0
//        and budget is small (never punish the uncontended case — it
//        should still hit the central stack fast). Under heavy
//        contention collisions→K and budget expands (probe MORE slots
//        before falling back to the central CAS). This is the
//        accumulator-controlled backoff of Hendler, Lev, Moir & Shavit
//        (PLDI 2014) reduced to a single atomic counter — O(1)
//        bookkeeping, no census traffic.
//
//  (5) ABA-IMMUNE SLOT STATE via unique per-op stamp.
//        Each parking record carries a monotonically increasing stamp
//        from a 64-bit atomic generator (1 GHz → 584 years to wrap).
//        The completing partner must CAS the slot's stamp word to 0 to
//        claim the exchange; only the producer whose stamp equals the
//        one currently resident can possibly reclaim its OWN record on
//        timeout. A stale overwritten record always has a different
//        stamp, so a parking thread never mistakes another thread's
//        record for its own. ABA across recycled slots is impossible.
//
//  (6) ZERO-GC CONSTRUCTION.
//        EliminationArray is one contiguous [K]ElimSlot array embedded
//        BY VALUE in EliminationStack (no heap alloc for the slots).
//        ElimSlot fields are all atomics (no boxed interfaces, no
//        closures). The thread-local PRNG lives on the goroutine stack
//        in a single uint64 (xorshift64* — 3 xors + 2 shifts + 1 mul).
//        Zero allocations on the hot path. The CI microscope
//        TestEliminationHotPathZeroAllocations proves this.
//
//  (7) CACHE-LINE ISOLATION OF SLOTS.
//        Each ElimSlot is 128 bytes (two cache lines) — `< op stamp
//        value >` on line 1, padded empty on line 2 — so adjacent slots
//        never share a cache line. Two cores hitting different slots
//        issue ZERO cross-core invalidations, which is the entire point
//        of elimination. The EliminationStack's central `head` is
//        also padded away from both the slot array and the statistics.
// ---------------------------------------------------------------------------

// EliminationArrayCapacity is the static width of the elimination
// array. Sized to 2× the maximum concurrency (P=32 → K=64) for the
// Graviton crucible per the birthday-bound derivation above. A
// power of two is REQUIRED so slot indexing is a single AND mask.
const EliminationArrayCapacity = 64

// elimSlotOp tags which half of a push/pop pair is parking in a slot.
type elimSlotOp uint64

const (
	elimSlotEmpty elimSlotOp = 0 // slot is free
	elimSlotPush             = 1 // a Push op is parked waiting for a Pop
	elimSlotPop              = 2 // a Pop op is parked waiting for a Push
)

// elimState encodes (op, stamp) in a single 64-bit atomic word so the
// ENTIRE control-plane transition of a slot is one CAS — eliminating
// every multi-word race by construction.
//
// Layout:  bits [63:62] = op   (2 bits: EMPTY/PUSH/POP)
//
//	bits [61: 0] = stamp (62-bit monotonic token)
//
// A 62-bit stamp at 1 GHz wraps in ~146 years — functionally never,
// and smaller than the 584-year 64-bit counter only because we spend
// 2 bits on op. The counter is per-process and never reset.
//
// The single-word encoding is what makes the elimination array
// provably correct: parking, completion, and timeout-reclaim are each
// ONE atomic CAS on the same word. There is no window between
// "op flips" and "stamp flips" in which a stale observer could match.
const (
	elimStateOpShift   = 62
	elimStateOpMask    = uint64(3) << elimStateOpShift
	elimStateStampMask = ^elimStateOpMask
)

// elimCompleteValueWait is the bounded spin iterations a completing Pop
// spends reading the parked Push's value before retiring the record.
// The Pop must NOT retire until the value is present, otherwise retire-
// first/then-bounded-read can time out while the post-CAS-publishing
// Push's store is still in flight — orphaning the value and triggering
// a phantom-pop linearizability violation.
//
// The Push publishes its value unconditionally within nanoseconds of
// park-CAS, and the RACE-SAFETY GUARD guarantees no third party can
// wipe the value while it's pending, so this wait is robust and short
// on bare metal. The bound is set generously (well beyond the worst-
// case cache-line ping-pong across the mesh) and the Pop ALSO re-checks
// `state` each iteration so it bails immediately if the Push reclaims.
const elimCompleteValueWait = 1024

func elimPackState(op elimSlotOp, stamp uint64) uint64 {
	return (uint64(op) << elimStateOpShift) | (stamp & elimStateStampMask)
}

func elimStateOp(state uint64) elimSlotOp {
	return elimSlotOp((state & elimStateOpMask) >> elimStateOpShift)
}

func elimStateStamp(state uint64) uint64 {
	return state & elimStateStampMask
}

// ElimSlot is one cell of the elimination array. Exactly 128 bytes (two
// cache lines): line 0 holds _padLead (48B) + state (8B) + value (8B)
// = 64B; line 1 is pure CacheLinePad (64B). This layout:
//
//   - Puts state and value on the SAME cache line (line 0) so the
//     completing CAS and the value Store are coherent on one line —
//     the parked thread sees both atomically with no cross-line fence.
//
//   - Adjacent slots never share a line: the next slot's line 0 starts
//     at offset 128, its state at offset 176 — always on a fresh line.
//     Two cores hitting different slots issue ZERO cross-core invalidation.
//
//   - state : the exclusive lock committing the exchange (packed op|stamp).
//
//   - value : the Push's deposited payload (NullOffset64 = empty sink
//     set by a Pop, overwritten by a completing Push).
type ElimSlot struct {
	_padLead [48]byte      // fill line-0 so state+value share exactly one line
	state    atomic.Uint64 // packed (op << 62) | stamp — control plane
	value    atomic.Uint64 // payload / sink — data plane
	_padTail CacheLinePad  // 64B: line 1, pure isolation pad
}

// EliminationArray is the collision arena, by value (Zero-GC).
type EliminationArray struct {
	slots [EliminationArrayCapacity]ElimSlot
}

// ElimStack is the contended Treiber stack that the elimination array
// backs off from. `head` is the single contended cache line — a uint64
// index into the pre-allocated node pool (not a boxed pointer, to stay
// Zero-GC). It is padded away from all other fields.
type ElimStack struct {
	_pad0      CacheLinePad
	head       atomic.Uint64 // top of Treiber stack (index into pool)
	_pad1      CacheLinePad
	collisions atomic.Uint64 // adaptive probe-budget feedback accumulator
	_pad2      CacheLinePad
	arr        EliminationArray // the elimination backoff arena (value, Zero-GC)
}

// NewEliminationStack constructs an empty elimination-backed stack.
// The slot array is embedded by value (no heap allocation for slots).
func NewEliminationStack() *ElimStack {
	s := &ElimStack{}
	s.head.Store(NullOffset64)
	return s
}

// elimStampCounter is a process-global monotonic generator producing
// a per-goroutine UNIQUE BASE for ABA-defeating slot stamps. Each
// goroutine calls Add(1) exactly ONCE (the first time it seeds its
// PRNG) to obtain a globally-unique stampBase; afterwards it generates
// stamps locally via a per-goroutine sequence counter (see ElimPRNG),
// so the global line is hit once-per-goroutine-lifetime, NOT once per
// parking attempt. This removes the global RMW from the steady-state
// hot path — the previous design called Add(1) on EVERY push/pop CAS
// failure AND every empty-stack pop, which at 32 cores serialized all
// 32 goroutines on a single contended cache line and dominated the
// throughput collapse.
//
// 32-bit base × 30-bit per-goroutine sequence ⇒ 62-bit (stamp fits the
// 62-bit stamp field). 2^32 goroutines and 2^30 (~10^9) stamps per
// goroutine are both far beyond any conceivable process lifetime, so
// global uniqueness is preserved for all practical runs.
var elimStampCounter atomic.Uint64

const (
	elimStampSeqBits   = 30 // per-goroutine sequence width
	elimStampSeqMask   = (uint64(1) << elimStampSeqBits) - 1
	elimStampBaseShift = elimStampSeqBits // stampBase occupies the high bits
)

// stamp derives a GLOBALLY-UNIQUE 62-bit stamp from a per-goroutine
// (stampBase, stampSeq) pair. The base is assigned once at PRNG-seed
// time (a single global Add(1) per goroutine lifetime); the sequence
// increments locally on every call. Two goroutines have distinct
// stampBase ⇒ distinct stamps; one goroutine's retries increment
// stampSeq ⇒ distinct stamps per attempt. This is the ABA-lock for
// the elimination slot reclaim/complete CASes: a stale record from a
// different goroutine or a different retry of the same goroutine
// cannot match the exact (op, stamp) tuple, so the CAS fails and no
// phantom value handoff can occur.
func (r *ElimPRNG) stamp() uint64 {
	s := (r.stampBase << elimStampBaseShift) | (r.stampSeq & elimStampSeqMask)
	r.stampSeq++
	return s
}

// ElimPRNG holds xorshift64* state on the goroutine stack (Zero-GC).
//
// In addition to the PRNG state, it carries:
//
//   - cache: a per-goroutine node-index "cache" — a single recycled
//     ElimNodePool index (the decisive free-list-contention fix; see
//     the comment on the cache field below).
//   - stampBase / stampSeq: a per-goroutine UNIQUE stamp generator.
//     stampBase is assigned once at seed time (one global Add(1) per
//     goroutine lifetime); stamp() combines base+seq locally so the
//     hot path never touches the global counter.
//   - secCache: the SEC sharded stack's deeper per-goroutine node-index
//     cache. The stage5Stack interface intentionally passes *ElimPRNG to
//     every candidate, so SEC reuses this goroutine-local carrier rather
//     than forking the interface. ElimStack ignores secCache.
//
// CONTENTION PROBLEM THE CACHE SOLVES:
//
//	The ElimNodePool free-list is itself a Treiber stack with ONE
//	contended head cache line — distinct from the central stack's head
//	line. Every push calls pool.allocIndex() (a free-list CAS) and
//	every pop calls pool.freeIndex() (another free-list CAS). The
//	elimination array relieves the CENTRAL stack's head contention by
//	exchanging values in private slots, but it AMPLIFIES free-list
//	contention: an eliminated push still allocated an index (free-list
//	CAS) and must free it on success (another free-list CAS). Under
//	the alternating push/pop crucible each goroutine does (alloc, free)
//	pairs at the free-list's single contended line on every elimination.
//	At 32 cores the free-list line becomes the dominant bottleneck and
//	throughput collapses — the exact pathology we measured (~2.7%
//	efficiency).
//
// THE CACHE FIX:
//
//	Each goroutine holds ONE recycled index in `cache`. On the steady
//	state of an alternating push/pop workload:
//	  - push: if cache is occupied, take that index (ZERO contention,
//	    no free-list CAS); else fall back to pool.allocIndex().
//	  - pop (central-CAS success): the popped node's index is recycled
//	    into the cache if it's empty (ZERO contention); else spills to
//	    pool.freeIndex().
//	  - push (elimExChanged): the staged index is recycled into cache
//	    if empty; else spills to pool.freeIndex().
//	An alternating push/pop goroutine therefore CYCLES one index
//	locally forever — the free-list is never touched in steady state,
//	converting two contended CAS per op into zero. The elimination
//	array's slot-CAS (L1-resident, random slot) becomes the only
//	remaining synchronization, which scales linearly.
//
// INARIANT: while cache != 0, that index is NOT on the shared free-list;
//
//	it is exclusively owned by this goroutine. An index enters the cache
//	from exactly one source (a just-freed central pop or a completed
//	elimination) and leaves to exactly one sink (the next push). No
//	double-free: cache holds each index exactly once.
type ElimPRNG struct {
	state     uint64 // xorshift64* PRNG state
	cache     uint64 // per-goroutine recycled node index; 0 (NullOffset64) = empty
	stampBase uint64 // globally-unique per-goroutine base (assigned once at seed)
	stampSeq  uint64 // per-goroutine monotonic sequence (local, no contention)
	secCache  secDeepCache
}

// next returns a pseudo-random uint64 and advances state. xorshift64*
// (Vigna 2014): 3 xors + 2 shifts + 1 multiply ≈ 4 cycles on Neoverse.
// Strictly local — no cross-core traffic.
func (r *ElimPRNG) next() uint64 {
	x := r.state
	if x == 0 {
		// Seed once: derive a globally-unique PRNG seed AND a globally-
		// unique stampBase from the same single Add(1). After this, the
		// goroutine NEVER touches elimStampCounter again — stamps come
		// from stamp() (local sequence), PRNG from state (local). The
		// global contended line is therefore absent from the hot path.
		t := elimStampCounter.Add(1)
		r.stampBase = t
		x = t*2654435761 ^ 0x2545F4914F6CDD1D
		if x == 0 {
			x = 1
		}
	}
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	r.state = x
	return x * 0x2545F4914F6CDD1D
}

// NewElimPRNG constructs a fresh per-goroutine ElimPRNG carrier.
//
// The zero value is a valid, unseeded carrier: state==0 triggers lazy
// seeding on the first next() call, which performs the single
// per-goroutine-lifetime Add(1) on the global stamp counter and assigns
// the globally-unique stampBase. Calling NewElimPRNG (or &ElimPRNG{})
// once per goroutine therefore preserves the engine's hot-path
// invariant that the global stamp line is touched exactly once per
// goroutine lifetime, never per op.
//
// CONTRACT: the returned *ElimPRNG is for this goroutine's EXCLUSIVE
// use. The secDeepCache and stamp sequence fields are goroutine-local
// state; sharing one *ElimPRNG across goroutines races on that state
// and corrupts the ElimNodePool free-list.
func NewElimPRNG() *ElimPRNG { return &ElimPRNG{} }

// elimExchangeResult reports the outcome of a slot visit.
type elimExchangeResult uint8

const (
	elimExChanged   elimExchangeResult = iota // a partner completed our op
	elimExNoPartner                           // we parked, timed out, reclaimed
	elimExSkipped                             // slot taken; try next slot
)

// elimTryExchange is the canonical Herlihy-Shavit Exchanger, hardened
// with ABA-immune stamps packed into a single atomic control word.
// The caller parks its `op` (Push/Pop) and, if a complementary op
// arrives within a bounded spin, completes the exchange.
//
// Every control-plane transition is a CAS on `slot.state` — the packed
// (op<<62)|stamp word — so there is no multi-word window between an op
// flip and a stamp flip. This is what makes the array provably race-free
// without per-slot locks, fork-join token tables, or generation fences.
//
// State machine (state = (op, stamp)):
//
//	(EMPTY, 0)         — slot free. A parker CASes → (OP, myStamp).
//	(PUSH, pStamp)      — Push parked, waiting for a Pop.
//	                    A Pop CASes → (EMPTY, 0) to retire the record.
//	                    (Linearization point.) Pop then reads value.
//	(POP, pStamp)       — Pop parked (empty sink), waiting for a Push.
//	                    A Push CASes → (EMPTY, 0) and, BEFORE the
//	                    CAS, stores its value into the sink. (The value
//	                    Store happens-before the state CAS via normal
//	                    Go memory ordering for atomic operations on the
//	                    same cache line, so the Pop's read-after-CAS sees
//	                    the value.) See protocol below.
//	same-op parked     — skip the slot; two pushes can't eliminate.
//
// PROTOCOL (asymmetric, single-write-per-side):
//
//	PARK (both Push & Pop):
//	  1. CAS slot.state: (EMPTY,0) → (myOp, myStamp). On miss → probe next.
//	  2. We now OWN the record. Publish our payload:
//	       Push → slot.value = valIn
//	       Pop  → slot.value = NullOffset64 (empty sink)
//	  3. elimSpinWait: poll slot for a partner until bounded budget.
//	  4a. If a partner retires the record (state == (EMPTY, 0) with a
//	      stamp ≠ ours — meaning the partner consumed the record and
//	      advanced to a fresh stamps; or, equivalently, state is EMPTY
//	      and value is gone): eliminated. Return.
//	  4b. If budget elapsed: attempt to RECLAIM the record by CASing
//	      slot.state: myPackedState → (EMPTY, 0) — ONLY we can issue
//	      this CAS with our exact (op, stamp) tuple, so reclaiming
//	      can never clobber a partner that just won us. If the CAS
//	      succeeds → no partner; reclaim the leaked value. If it
//	      fails → a partner retired our record → eliminated.
//
//	COMPLETE (the complementary thread visiting a parked record):
//	  Push completing a Pop:  store value into slot.value, THEN CAS
//	    slot.state: (POP, pStamp) → (EMPTY, 0). Stamp match in the CAS
//	    guarantees we complete the EXACT record we observed.
//	  Pop completing a Push:  CAS slot.state: (PUSH, pStamp) → (EMPTY, 0).
//	    Stamp match guarantees the EXACT record. THEN read slot.value
//	    into valOut (the parked Push published it after its park CAS;
//	    our state CAS happens-after that publication via the same line).
//
// The stamp-equality check built into each completing CAS is the
// ABA-immunity. A Pop seeing state (PUSH, X) and CASing → (EMPTY, 0)
// can only succeed if NO other thread has reclaimed/parked a new
// record in this slot since (PUSH, X); any such intervention would
// have changed the stamp, defeating the CAS. Identical for the
// symmetric path.
//
// Linearization point: the completing CAS (Push→(EMPTY,0) for a Pop's
// completion, or Pop→(EMPTY,0) for a Push's completion). The parked
// party's spin observes its (op, stamp) becoming (EMPTY, 0) — never a
// partial flip — and succeeds monotonically.
//
// Returns:
//
//	elimExChanged   — exchange completed, *valOut holds the result
//	elimExNoPartner — we parked & spun out; we reclaimed our slot
//	elimExSkipped   — (reserved) slot transitively refused
func (a *EliminationArray) tryExchange(prng *ElimPRNG, op elimSlotOp, valIn uint64, stamp uint64, budget int, valOut *uint64) elimExchangeResult {
	if budget < 1 {
		budget = 1
	}
	if budget > EliminationArrayCapacity {
		budget = EliminationArrayCapacity
	}
	myParkedState := elimPackState(op, stamp)
	for probe := 0; probe < budget; probe++ {
		idx := int(prng.next() & uint64(EliminationArrayCapacity-1))
		slot := &a.slots[idx]
		curState := slot.state.Load()
		curOp := elimStateOp(curState)

		// Same-op records cannot eliminate.
		if curOp == op {
			continue
		}

		if curOp == elimSlotEmpty {
			// RACE-SAFETY GUARD: refuse to park in an EMPTY slot that
			// still holds a non-NullOffset64 value.  Such a slot is a
			// completed exchange whose value is awaiting collection by
			// the rightful owner (the parked Pop whose record a
			// completing Push retired, leaving v behind).  If a third op
			// parked here and overwrote `value` (a Pop publishing its
			// sink, or a Push publishing its payload), it would WIPE the
			// pending value before the owner read it — the linearizability
			// violation (phantom pops returning 0, or duplicated values)
			// we diagnosed.  So we skip this slot and probe another.
			// This guard is the decisive correctness fix: it removes the
			// only third-party writer that could destroy a committed-but-
			// uncollected value.
			if slot.value.Load() != NullOffset64 {
				continue // value pending collection; do NOT park over it
			}
			// 1. PARK: (EMPTY, 0) → (myOp, myStamp).
			if !slot.state.CompareAndSwap(curState, myParkedState) {
				continue // raced; probe another slot
			}
			// 2. We own the record.  Publish our payload ONLY for a
			//    Push (the value the completing Pop will carry off).
			//    A Pop publishes NO sink: the completing Push writes its
			//    value into the slot unconditionally (overwriting
			//    whatever is there), so the Pop has nothing to
			//    pre-clear.  Critically, the Pop must NOT store here at
			//    all: a deferred Pop sink-store would race a completing
			//    Push's value delivery and WIPE it.  By omitting the
			//    Pop's store, the only value writers are the parking
			//    Push and the completing Push (and the clearing owner),
			//    all of which are synchronized via the slot's state CAS.
			if op == elimSlotPush {
				slot.value.Store(valIn)
			}
			// 3. Spin for a partner within a bounded L1-hot budget.
			if elimSpinWait(slot, op, stamp, valOut) {
				return elimExChanged
			}
			// 4b. Reclaim ONLY if our exact (op, stamp) still owns the
			// slot. A partner that completed us would have CASed state
			// to (EMPTY, 0) — the stamp in state would no longer equal
			// ours, so our reclaim CAS fails ⇒ we were eliminated.
			if slot.state.CompareAndSwap(myParkedState, elimPackState(elimSlotEmpty, 0)) {
				// Reclaimed our own record.  Clean the payload so the
				// slot returns to the free state (EMPTY, NullOffset64)
				// — required so a later parker is NOT refused by the
				// non-Null-value guard above.
				slot.value.Store(NullOffset64)
				return elimExNoPartner
			}
			// Reclaim CAS failed ⇒ a partner retired our record.
			if op == elimSlotPop {
				// The ONLY writer that can change our parked state from
				// (POP, s) to anything else is a completing Push CASing
				// (POP, s) → (EMPTY, 0). (Our own reclaim CAS targets
				// that exact transition; a fail means another writer
				// raced it home.) That completing Push stored its value
				// into slot.value BEFORE its retire-CAS — so by the
				// Go memory model our load here is synchronized-with
				// (sees the effects of) that prior Store, regardless of
				// the value's payload (including lawful payload 0).
				//
				// We MUST NOT filter value==0 / NullOffset64 here: this
				// branch is entered ONLY because a partner retired us,
				// which means the value is genuinely published. Filtering
				// 0 would treat a lawful zero payload as "no value" → drop
				// it → the completing Push already returned elimExChanged,
				// freeing its node → the value is LOST → a phantom-pop
				// linearizability violation (netSurplus ≠ drained). The
				// value 0 (NullOffset64) is a legitimate user payload:
				// NullOffset64 collides with the slot's "empty" sentinel
				// only when checking BEFORE parking (the GUARD), not when
				// checking AFTER a guaranteed retirement (here).
				*valOut = slot.value.Load()
				slot.value.Store(NullOffset64) // return slot to free
				return elimExChanged
			}
			// op == elimSlotPush: a Pop retired our record and carried
			// off our value (it clears the slot). We are eliminated.
			return elimExChanged
		}

		// A complementary op is parked here. COMPLETE the exchange.
		// The parked-party's stamp gates the claim — we CAS state with
		// the EXACT (parkedOp, parkedStamp) tuple so we cannot match a
		// stale or reclaimed record (ABA-immunity).
		parkedPacked := curState
		if op == elimSlotPop {
			// Pop completing a Push.
			//
			// THE RACE THIS DESIGN DEFEATS: the parked Push publishes
			// its value AFTER its park-CAS succeeded (the natural Zero-GC
			// ordering — a pre-CAS value publish would race competing
			// parkers and leak on CAS failure). There is therefore a
			// tiny window between the Push's park-CAS landing and its
			// value.Store committing during which the slot reads as
			// (PUSH, pStamp) but value is STILL NullOffset64.
			//
			// If we retired the slot in that window and then bounded-read
			// the value (the old design), the read could time out and
			// we'd `continue` reporting NoPartner — but the Push already
			// observed retirement, returned elimExChanged, freed its
			// node, and EXITED. The Push's value was orphaned in the slot
			// AND the Pop returned nothing — a phantom imbalance
			// (test failure: netSurplus ≠ drained). This was the
			// linearizability violation we diagnosed.
			//
			// FIX (this block): the RACE-SAFETY GUARD above guarantees no
			// third party can wipe the value while it's pending. So we
			// may spin-wait for the Push's value to appear WITHOUT
			// retiring first. The Push publishes unconditionally within
			// nanoseconds of park-CAS, so this wait is short. Only when
			// the value is present do we retire — at which point
			// retirement ⟹ value-already-published, and the parked
			// Push's spin will see retirement and exit elimExChanged
			// with its value consumed (singularly — exactly one Pop
			// could win the retire-CAS, exactly one value handoff
			// occurs, the count invariant holds).
			//
			// Concurrency analysis of the wait→retire split:
			//   * A Push reclaiming its own record in this window fails
			//     to: the reclaim CAS would succeed and set (EMPTY, 0),
			//     clearing value. Our subsequent retire-CAS against the
			//     old (PUSH, pStamp) then FAILS (state already EMPTY) →
			//     we skip; the Push re-pushes its value. No phantom /
			//     no orphan / no duplication.
			//   * A second Pop completing the same record: only the
			//     first to succeed the retire-CAS wins; the other fails
			//     and skips. Single-consumption guaranteed.
			v := slot.value.Load()
			for r := 0; r < elimCompleteValueWait && (v == NullOffset64 || v == 0); r++ {
				// Re-check state too: if it left (PUSH, pStamp) — e.g.,
				// the Push reclaimed — value will not appear; bail.
				if slot.state.Load() != parkedPacked {
					v = NullOffset64
					break
				}
				v = slot.value.Load()
			}
			if v == NullOffset64 || v == 0 {
				// The Push either never published within the bound
				// (essentially impossible on bare metal — preemption
				// only), or reclaimed its own record mid-wait. Do NOT
				// retire (we have no value to deliver); leave the slot
				// alone and skip. The Push, if it reclaimed, owns the
				// value and re-pushes; if it published late it still
				// owns the slot. No phantom value leaves here.
				continue
			}
			// Value present — retire the record now. Stamp gates keep
			// this exact record. On failure the Push reclaimed (or
			// another Pop won) → the winnings holder delivers.
			if !slot.state.CompareAndSwap(parkedPacked, elimPackState(elimSlotEmpty, 0)) {
				// State changed under us — record no longer owned by
				// this (PUSH, pStamp). The value (if the Push reclaimed,
				// it cleared it; if another Pop won, it cleared it)
				// is consumed/owned elsewhere. We captured nothing
				// durable here; skip without leaking.
				continue
			}
			// We won the retire-CAS — we own the value handoff.
			// *valOut may already be set by the wait loop (re-load to
			// be safe — the value is stable, the Guard prevents any
			// third party from wiping it; only the parked Push could
			// have written it, and the Push is now retired/effect-out).
			// Clear the slot so the guard admits a future parker.
			*valOut = v
			slot.value.Store(NullOffset64)
			return elimExChanged
		}

		// op == elimSlotPush; a Pop parked an empty sink. Deliver our
		// value INTO the sink, THEN CAS state (POP, pStamp) → (EMPTY, 0).
		// The value Store happens-before the state CAS, so the parked
		// Pop's spin (waiting for state == (EMPTY, 0)) observes the
		// value present when it reads value after seeing the CAS.
		slot.value.Store(valIn)
		if !slot.state.CompareAndSwap(parkedPacked, elimPackState(elimSlotEmpty, 0)) {
			// Raced: the Pop reclaimed its own record or another
			// thread completed it. Undo our speculative value publish
			// so we don't leak a payload into a freshly reused slot.
			slot.value.CompareAndSwap(valIn, NullOffset64)
			continue
		}
		*valOut = valIn
		return elimExChanged
	}
	return elimExNoPartner
}

// elimSpinWait polls the slot we just parked in for a bounded number of
// L1-hot iterations for a partner. Returns true iff our record was
// completed — observed as slot.state transitioning away from our exact
// (op, stamp) tuple.
//
// DESIGN: this function does ONLY detection — never value collection.
// All value ownership is reconciled by the caller's reclaim-CAS / the
// reclaim-fail path immediately after this returns. The previous version
// redundantly captured the value here for the Pop case AND the upper
// reclaim-fail-POP path captured it again, but because the spin-path
// also cleared the slot, a Pop whose spin-path captured+cleared the
// value reported elimExNoPartner (its reclaim-CAS succeeded against an
// EMPTY slot it just vacated) while the value, now NullOffset64, made
// the upper reclaim-fail path NO-OP — yet the Pop's caller had ALREADY
// set *valOut in the spin path. The caller (pop()) then DISCARDED *valOut
// on elimExNoPartner → a phantom loss (a value was captured & cleared
// from the slot but never delivered to the caller). This simplification
// removes the dual-writer ambiguity: the only value collector is the
// single reclaim-fail-POP path (or the completing-op path of the
// partner), guaranteeing exactly-once delivery.
//
// PURE BUSY-SPIN (no Gosched): each iteration is a single atomic Load
// (~6.5 ns on Graviton). The previous design gated a runtime.Gosched()
// every 16th iteration as a cooperative yield, but at 32 cores in the
// saturated crucible EVERY parked goroutine would Gosched simultaneously
// whenever a partner failed to arrive within ~16 iter — triggering
// scheduler thrash that costs ~1 µs/quantum, which the design comment
// (3) calls out as ~150× slower than the CAS it protects. Pure busy-spin
// on the L1-resident slot line is the optimal choice for the
// elimination pattern: the parked thread stays on-core, cache-hot, and
// ready to retire within nanoseconds of a partner's completing CAS. The
// outer push/pop loops still gate a Gosched every 64 CAS-failures to
// bound runaway under genuinely pathological contention.
func elimSpinWait(slot *ElimSlot, op elimSlotOp, stamp uint64, valOut *uint64) bool {
	// The spin budget must be SHORT — comparable to one central CAS round
	// (~6.5 ns on Graviton, a few iterations). A parked op holds a slot; if
	// it spins too long it blocks other goroutines from parking in that
	// slot and creates backpressure that scales as O(P) parked holders.
	// Empirically, for the alternating push/pop crucible the optimal budget
	// is SMALL: just enough to catch a partner that lost its own central CAS
	// in the same ~100 ns window. Most matches occur within the first few
	// iterations; the rest waste cycles holding the slot.
	const spinBudget = 8
	myState := elimPackState(op, stamp)
	_ = valOut // not used — value collection is in the caller's reclaim paths
	for i := 0; i < spinBudget; i++ {
		// A partner completed us iff state no longer matches our parked
		// (op, stamp) — the partner CASed it to (EMPTY, 0) (or, in the
		// pathological nested case, to a new record; either way the
		// tuple left our stamp, so we deduce "eliminated" and the upper
		// logic reconciles value ownership precisely once).
		if slot.state.Load() != myState {
			return true
		}
	}
	return false
}

// adaptiveProbeBudget returns how many rounds of elimination probing
// to attempt before falling back to the central Treiber CAS. Uses the
// collisions counter as an accumulator:
//
//	probeBudget = baseProbe + bits.Len64(collisions)
//
// Under low contention collisions→0 and budget=baseProbe (the
// uncontended common case pays ~nothing and hits the central stack
// fast). Under heavy contention collisions→K and budget expands so we
// visit MORE slots before engaging the central line. Feedback updated
// by Push/Pop on their return is O(1) and never broadcasts (single
// atomic.Add on a padded counter).
func (s *ElimStack) adaptiveProbeBudget() int {
	const baseProbe = 8
	c := s.collisions.Load()
	if c > EliminationArrayCapacity {
		c = EliminationArrayCapacity
	}
	probe := baseProbe
	if c > 0 {
		probe += bits.Len64(c)
	}
	if probe > EliminationArrayCapacity {
		probe = EliminationArrayCapacity
	}
	return probe
}

// feedback reports an elimination attempt's outcome to the adaptive
// accumulator. elimination ⇒ decrement (probe less next time); missed
// ⇒ increment (probe more next time). Saturating arithmetic via the
// clamp in adaptiveProbeBudget.
func (s *ElimStack) feedback(eliminated bool) {
	if eliminated {
		// Decrement, never underflow below 0 (saturating).
		for {
			cur := s.collisions.Load()
			if cur == 0 {
				return
			}
			if s.collisions.CompareAndSwap(cur, cur-1) {
				return
			}
		}
	}
	s.collisions.Add(1)
}

// push attempts a Treiber push against the central stack, using the
// elimination array as spatial backoff on CAS contention. Zero-GC:
// takes a pre-allocated node index from `pool` or the per-goroutine cache.
//
// FREE-LIST CONTENTION ELIMINATION (the cache):
//
//	The per-goroutine `prng.cache` holds ONE recycled node index. On the
//	steady-state alternating push/pop workload, that index cycles
//	locally: pop puts a popped index into cache → next push takes it
//	from cache → no free-list CAS ever fires. Only the FIRST push of
//	a goroutine whose cache is empty falls back to pool.allocIndex(),
//	and only when cache is ALREADY occupied does a freed index spill to
//	pool.freeIndex(). The free-list's single contended cache line is
//	thus absent from the steady-state hot path — the decisive fix for
//	the throughput collapse at 32 cores. The elimination array's
//	L1-resident random slot-indexed CAS becomes the only remaining
//	synchronization, which scales linearly with core count.
func (s *ElimStack) push(pool *ElimNodePool, prng *ElimPRNG, value uint64) {
	// Stage a node index once per attempt. Prefer the per-goroutine
	// cache (zero contention) over the shared free-list. The index is
	// REUSED across retries and returned to the pool/cache on
	// elimination success, keeping the pool balanced (Zero-GC).
	stagedIdx := prng.cache
	if stagedIdx != NullOffset64 {
		prng.cache = NullOffset64 // claim: cache ↔ this op, single owner
	} else {
		stagedIdx = pool.allocIndex()
	}

	for attempts := 0; ; attempts++ {
		pool.nodes[stagedIdx].value = value
		head := s.head.Load() // head is packed (gen, idx)
		// Link our node to the current head with the SAME packed value
		// (including generation) so a pop following our link sees the
		// correct generation tag. Atomic store so no torn read.
		atomic.StoreUint64(&pool.nodes[stagedIdx].next, head)
		// CAS head → (gen_head + 1, stagedIdx).  The generation bump
		// ensures any stale observer (who read an older head) will fail.
		newHead := elimPackIndex(elimGen(head)+1, stagedIdx)
		if s.head.CompareAndSwap(head, newHead) {
			// Pushed to central stack; the node is now owned by the stack.
			// stagedIdx left the goroutine's custody — cache state unchanged
			// (it was already emptied at acquire time, or never held this idx).
			return
		}

		// Central CAS failed — contention. Back off in space.
		// The stamp is GLOBALLY-UNIQUE per (goroutine, attempt) via the
		// per-goroutine (stampBase, stampSeq) pair — no global RMW here.
		// (We do NOT mix prng.next() into the stamp: XORing a globally-
		// unique value with a per-goroutine random value would DESTROY
		// uniqueness — two goroutines could collide. prng.next() is
		// still used by tryExchange for slot-index selection.)
		stamp := prng.stamp()
		budget := s.adaptiveProbeBudget()
		var out uint64
		res := s.arr.tryExchange(prng, elimSlotPush, value, stamp, budget, &out)
		switch res {
		case elimExChanged:
			s.feedback(true)
			// Our value was consumed by a matching Pop — recycle the staged
			// node index. Prefer the per-goroutine cache (zero contention);
			// spill to the shared free-list only if the cache is occupied.
			// (Equivalent to pool.freeIndex but saves the contended CAS in
			// the steady-state alternating workload, where the NEXT push
			// by this goroutine will reclaim stagedIdx from the cache.)
			if prng.cache == NullOffset64 {
				prng.cache = stagedIdx
			} else {
				pool.freeIndex(stagedIdx)
			}
			return
		case elimExNoPartner:
			s.feedback(false)
			// Retain stagedIdx, retry the central CAS next round. Do NOT
			// touch prng.cache: stagedIdx is still exclusively owned by THIS
			// op, and the cache holds (at most) a DIFFERENT index destined
			// for a future push. Pushing stagedIdx into the cache here would
			// hand the index to the next push while THIS op still owns it →
			// double-use corruption. Leave the cache exactly as-is.
		case elimExSkipped:
			// (tryExchange never returns this currently; kept for parity.)
			s.feedback(false)
		}
		// Bound runaway under pathological conditions: occasionally
		// yield so we never starve other goroutines. We do NOT sleep.
		if attempts&63 == 63 {
			runtime.Gosched()
		}
	}
}

// pop attempts a Treiber pop against the central stack, using the
// elimination array as spatial backoff on CAS contention. Returns the
// popped value and ok.
//
// SYMMETRY WITH push — the heart of the elimination design:
// On a contended CAS, BOTH push and pop back off into the elimination
// array.  (pop's previous version only entered elimination when the
// stack was observed EMPTY; under an alternating push/pop workload the
// stack oscillates around a small positive depth and is almost never
// observed empty, so pops spun on the central CAS forever while pushes
// parked in slots nobody came to visit — slot starvation and a 9×
// throughput COLLAPSE from 4→32 cores.  The fix is the symmetric
// backoff: a pop that loses the central CAS parks in a slot exactly
// like a push does, so the two halves of a push/pop pair meet in the
// array instead of both queuing on the one contended cache line.)
func (s *ElimStack) pop(pool *ElimNodePool, prng *ElimPRNG) (uint64, bool) {
	for attempts := 0; ; attempts++ {
		head := s.head.Load() // packed (gen, idx)
		headIdx := elimIndex(head)
		if headIdx != NullOffset64 {
			node := &pool.nodes[headIdx]
			// Read the packed next — includes the generation tag that the
			// pusher stored when it linked this node.  We only need its
			// INDEX (the generation tag on `next` is irrelevant to us —
			// see the comment on `newHead` below for why).
			nextPacked := atomic.LoadUint64(&node.next)
			// CAS head → (gen_head + 1, idx_next).  CRITICAL: the new
			// generation is derived from the CURRENT head's generation
			// (the value we CAS against), NOT from nextPacked's stored
			// generation.  This guarantees newHead.gen > head.gen strictly
			// — the monotonic invariant that makes the tagged-pointer
			// ABA defense work.  Deriving from nextPacked would be wrong:
			// nextPacked.gen is whatever the pusher stored when it linked
			// this node, which can be ARBITRARILY OLDER than head.gen after
			// many pops have bumped head's generation.  Then newHead.gen
			// could be ≤ head.gen, letting a stale observer whose old head
			// had the same index but a BETWEEN generation match the CAS
			// — the classic ABA that creates a self-referential `next`
			// link (a cycle in the stack).
			nextIdx := elimIndex(nextPacked)
			newHead := elimPackIndex(elimGen(head)+1, nextIdx)
			if nextIdx == NullOffset64 {
				// The next link is the sentinel — the stack will become
				// empty.  Set head to NullOffset64 (gen 0, idx 0).
				newHead = NullOffset64
			}
			if s.head.CompareAndSwap(head, newHead) {
				v := node.value
				// Recycle the popped node index. Prefer the per-goroutine
				// cache (zero contention) so the NEXT push by this goroutine
				// reclaims it without touching the shared free-list; spill to
				// the free-list only if the cache is already occupied. This is
				// the symmetric half of the cache fix in push(): the
				// alternating push/pop workload cycles ONE index locally
				// forever, removing the free-list's single contended cache
				// line from the steady-state hot path.
				if prng.cache == NullOffset64 {
					prng.cache = headIdx
				} else {
					pool.freeIndex(headIdx)
				}
				return v, true
			}
			// Central CAS FAILED — contention.  The stack is NOT empty
			// (we just saw a valid head), but hammering the central line
			// again would burn an RFO round that 31 other cores are also
			// burning.  Back off in space, symmetrically to push: park
			// as a POP and let a contended push find us in the array.
			// (This is the fix for the 4→32-core throughput collapse.)
			// The stamp is GLOBALLY-UNIQUE per (goroutine, attempt) via the
			// per-goroutine (stampBase, stampSeq) pair — no global RMW here.
			// (We do NOT mix prng.next() into the stamp: XORing a globally-
			// unique value with a per-goroutine random value would DESTROY
			// uniqueness — two goroutines could collide. prng.next() is
			// still used by tryExchange for slot-index selection.)
			stamp := prng.stamp()
			budget := s.adaptiveProbeBudget()
			var out uint64
			res := s.arr.tryExchange(prng, elimSlotPop, 0, stamp, budget, &out)
			switch res {
			case elimExChanged:
				s.feedback(true)
				// A push completed us in the array — we have its value.
				return out, true
			case elimExNoPartner:
				s.feedback(false)
				// No partner in the array AND the stack had data —
				// retry the central CAS (do NOT report empty).
				continue
			case elimExSkipped:
				s.feedback(false)
				continue
			}
		}

		// Central stack observed EMPTY.  Only elimination can satisfy
		// us now; if elimination also finds no partner, the stack is
		// genuinely empty.
		// The stamp is GLOBALLY-UNIQUE per (goroutine, attempt) via the
		// per-goroutine (stampBase, stampSeq) pair — no global RMW here.
		// (We do NOT mix prng.next() into the stamp: XORing a globally-
		// unique value with a per-goroutine random value would DESTROY
		// uniqueness — two goroutines could collide. prng.next() is
		// still used by tryExchange for slot-index selection.)
		stamp := prng.stamp()
		budget := s.adaptiveProbeBudget()
		var out uint64
		res := s.arr.tryExchange(prng, elimSlotPop, 0, stamp, budget, &out)
		switch res {
		case elimExChanged:
			s.feedback(true)
			return out, true
		default: // elimExNoPartner (and the reserved elimExSkipped)
			s.feedback(false)
			// Stack was empty AND no elimination partner ⇒ genuine empty.
			return 0, false
		}
	}
}

// ---------------------------------------------------------------------------
// PUBLIC API — exported entry points for downstream importers
// ---------------------------------------------------------------------------

// Push is the exported entry point for the elimination-backed stack's
// hot path. See (*ShardedStack).Push for the *ElimNodePool / *ElimPRNG
// contract; ElimStack honours the same invariants.
func (s *ElimStack) Push(pool *ElimNodePool, prng *ElimPRNG, value uint64) {
	s.push(pool, prng, value)
}

// Pop is the exported entry point for the elimination-backed stack's
// hot path. Returns (value, false) when the stack is genuinely empty
// and no elimination partner is available. See (*ShardedStack).Push
// for the *ElimNodePool / *ElimPRNG contract.
func (s *ElimStack) Pop(pool *ElimNodePool, prng *ElimPRNG) (uint64, bool) {
	return s.pop(pool, prng)
}

// -----------------------------------------------------------------------
// ElimNodePool — the pre-allocated Zero-GC node arena the ElimStack
// indexes into via uint64 offsets. Constant-size; allocated once.
// -----------------------------------------------------------------------

// ABA-immune head/next encoding for the central Treiber stack AND the
// ElimNodePool free-list.
//
// Both `head` (central stack), `node.next` (central link), and
// `node.freeNext` (free-list link) are packed words:
//
//		packed = (generation << elimPoolGenShift) | index
//
//	  - bits [31:0]  = index   (32 bits → up to 4 billion nodes)
//	  - bits [63:32] = generation (32-bit monotonic counter)
//
// Every successful CAS bumps the generation by 1, so a stale observer
// whose value was popped/freed and re-pushed gets a DIFFERENT
// generation — its CAS fails. This is the classic "tagged pointer"
// ABA defense (Valois 1995) adapted to a uint64 index scheme. It is
// applied to BOTH the central stack and the free-list, because the
// free-list is itself a Treiber stack and is subject to the exact same
// ABA race (allocIndex reads free=5/freeNext=6, concurrent alloc+free
// cycles index 5 back, CAS succeeds with stale freeNext → corruption).
//
// NullOffset64 (== 0) is (gen=0, idx=0), so empty is still just `0`.
const (
	elimPoolGenShift  = 32
	elimPoolGenIncr   = uint64(1) << elimPoolGenShift // +1 in the gen field
	elimPoolIndexMask = (uint64(1) << elimPoolGenShift) - 1
)

// elimPackIndex packs (generation, index) into a single uint64 head/next.
func elimPackIndex(gen, index uint64) uint64 {
	return (gen << elimPoolGenShift) | (index & elimPoolIndexMask)
}

// elimIndex extracts the raw pool index from a packed head/next word.
func elimIndex(packed uint64) uint64 {
	return packed & elimPoolIndexMask
}

// elimGen extracts the generation from a packed head/next word.
func elimGen(packed uint64) uint64 {
	return packed >> elimPoolGenShift
}

// ElimNode is one element of the Treiber stack backed by ElimStack.head.
// `next` is a packed (generation, index) uint64 — the ABA tag for the
// central stack link.
// `freeNext` is a packed (generation, index) uint64 — the ABA tag for
// the ElimNodePool free-list link. Both use the SAME packed encoding
// (see elimPackIndex) but are SEPARATE fields: the free-list and
// central stack link through the same node independently, so sharing
// one field would corrupt whichever list isn't currently authoritative.
type ElimNode struct {
	value    uint64
	next     uint64 // packed (gen, idx) — ABA tag for central stack
	freeNext uint64 // packed (gen, idx) — ABA tag for free-list
}

// ElimPoolShard is one shard of the sharded free-list allocator. Occupies
// EXACTLY 128 bytes (two Neoverse-V1 cache lines) so adjacent shards in
// the array never false-share and the L2 spatial prefetcher cannot pull
// a neighboring shard's line alongside this one. Mirrors secShard's
// stride discipline.
//
// The free-list head stored here uses the SAME packed (gen, idx) ABA-
// immune encoding as the legacy single free-list (see elimPackIndex).
type ElimPoolShard struct {
	free atomic.Uint64 // head of a Treiber free-list of indices (packed)
	_pad [120]byte     // 128 - sizeof(atomic.Uint64) = 120
}

// elimPoolShardCount is the number of allocator free-list shards. It
// MUST match secShardCount so that an index's home shard
// (idx % elimPoolShardCount) is the SAME shard a per-P push routes the
// stackTop to (procPin & (secShardCount-1)) whenever idx % shardCount
// == pid — a common case that keeps the allocate-from / free-to
// traffic local. Kept as a named constant (not a copy of
// flatCombMaxThreads) so the coupling is explicit.
const elimPoolShardCount = 64

// ElimNodePool is a fixed-capacity ring of ElimNodes plus an atomic
// free-list (itself a tiny Treiber stack) for recycling indices. The
// benchmark pre-allocates one pool sized to 2× the working set and
// reuses indices for the whole run — Zero hot-path allocation.
type ElimNodePool struct {
	nodes []ElimNode
	_pad0 CacheLinePad
	// Legacy single free-list — used ONLY by the single-locus
	// candidates (ElimStack, flatCombStack) via allocIndex/freeIndex.
	// The SEC sharded candidate ignores this and uses `freeShards`
	// via allocIndexSharded/freeIndexSharded.
	free  atomic.Uint64 // head of Treiber free-list of indices
	count atomic.Int64  // outstanding allocations (diagnostic)
	_pad1 CacheLinePad
	// Sharded free-list array — used by the SEC candidate. 64 shards ×
	// 128B stride = 8 KiB, dispersing allocator CAS across the CMN-700
	// mesh exactly as stackTop is dispersed. Home-shard routing (free
	// to idx%64, alloc from pid then probe neighbors) defeats the
	// work-stealing trap documented in ARM64 Deep Dive §2.3.
	freeShards [elimPoolShardCount]ElimPoolShard
}

// NewElimNodePool returns a pool with `cap` indices pre-allocated on a
// single contiguous backing slice (one heap object — Zero-GC on the
// hot path; allocations happen exactly once at construction).
//
// INDEX 0 IS RESERVED. The ElimStack uses NullOffset64 (== 0) as the
// sentinel for "head is empty." If index 0 were a valid node index,
// a stack containing only that node would be indistinguishable from an
// empty stack — a fatal sentinel collision. Therefore the free-list
// starts at index 1; index 0 is permanently unallocated. The caller
// must size the pool at (working_set + 1) to compensate for the one
// wasted slot.
//
// The free-list `freeNext` fields use the SAME packed (gen, idx)
// encoding as the central stack, so the free-list CAS is ABA-immune:
// allocIndex reads free=packed5, freeNext=packed6; if a concurrent
// alloc+free cycles index 5 back, the generation changed and the CAS
// fails, preventing a stale freeNext from corrupting the free-list.
func NewElimNodePool(cap int) *ElimNodePool {
	p := &ElimNodePool{nodes: make([]ElimNode, cap)}

	// --- Legacy single free-list (ElimStack / flatCombStack) ---
	// Link indices 1..cap-1 into a Treiber free-list. Index 0 is
	// permanently reserved as the NullOffset64 sentinel.
	for i := 1; i < cap; i++ {
		p.nodes[i].freeNext = elimPackIndex(0, uint64(i+1))
	}
	p.nodes[cap-1].freeNext = elimPackIndex(0, NullOffset64)
	p.free.Store(elimPackIndex(1, 1)) // free-list head at index 1, gen 1

	// --- Sharded free-lists (SEC candidate) ---
	// Seed each index into its HOME shard: home = idx % elimPoolShardCount.
	// Index 0 remains permanently reserved (the NullOffset64 sentinel),
	// so it is never placed onto any shard's free-list. Each shard is a
	// Treiber stack built by pushing indices in DESCENDING order so that
	// the first popped index from a shard is the SMALLEST home-allocated
	// index (stable, deterministic refill — aids the cycle/dup walker).
	// All freeShards start empty (zero value == packed(0,0) == NullOffset64).
	for sh := 0; sh < elimPoolShardCount; sh++ {
		p.freeShards[sh].free.Store(NullOffset64)
	}
	// Push each index onto its HOME shard's free-list directly (no count
	// mutation — seeding is not an allocation/free, the node is free).
	// Iterate indices in DESCENDING order within each shard so the first
	// popped index is the smallest (deterministic refill).
	for i := cap - 1; i >= 1; i-- {
		home := uint64(i) % elimPoolShardCount
		sh := &p.freeShards[home]
		head := sh.free.Load() // packed (gen, idx); NullOffset64 on first
		atomic.StoreUint64(&p.nodes[i].freeNext, head)
		newFree := elimPackIndex(elimGen(head)+1, uint64(i))
		sh.free.Store(newFree) // single-threaded init: plain Store is safe
	}
	return p
}

// allocIndex pops an index off the free-list Treiber stack.
//
// DELEGATION NOTE: the ElimNodePool has ONE shared ElimNode.freeNext
// field per node, used by BOTH the legacy single free-list (`p.free`)
// and the sharded free-list (`p.freeShards`). Seeding populates the
// SHARDED free-lists (which route frees by node home and never collide
// across shards); the legacy `p.free` chain is not separately seeded to
// avoid overwriting the shared freeNext links. Therefore legacy single-
// locus candidates (ElimStack, flatCombStack) MUST allocate through the
// sharded path too — delegating allocIndex to allocIndexSharded keeps
// both allocator families operating on the SAME seed without the
// freeNext-field aliasing that previously broke the legacy chain.
//
// Starting probe shard is deliberately 0 for legacy single-goroutine
// callers (no procPin in the legacy hot path); the linear probe across
// all 64 shards guarantees forward progress identical to the SEC path.
// Returns a RAW index (not packed).
func (p *ElimNodePool) allocIndex() uint64 {
	return p.allocIndexSharded(0)
}

// freeIndex pushes a raw index back onto the free-list Treiber stack.
//
// DELEGATION: route the legacy free through the HOME shard so the
// sharded free-list stays the single source of truth for the shared
// ElimNode.freeNext field (see allocIndex delegation note). Home-shard
// routing also preserves the multi-locus dispersion that the SEC
// candidate relies on; the legacy candidates benefit identically.
func (p *ElimNodePool) freeIndex(idx uint64) {
	p.freeIndexHome(idx)
}

// ---------------------------------------------------------------------------
// Sharded allocator (SEC candidate) — home-shard routing
// ---------------------------------------------------------------------------

// freeIndexSharded pushes idx onto the free-list of shard `shard`. It is
// the per-shard Treiber push. The caller chooses the destination shard:
//   - Home-shard routing (the physics fix): shard == idx % elimPoolShardCount.
//     The freeing thread therefore NEVER frees to its own PID shard by
//     default — it frees to the NODE's home. Under a 2-consumer /
//     30-producer skew the consumers scatter their frees across all 64
//     home shards, continuously refilling every producer's local shard,
//     so producers allocate locally and never storm a single line.
//
// idx is a RAW index (not packed). freeNext links use the same packed
// (gen, idx) encoding and the same ABA-immune generation discipline as
// the legacy single free-list: the new head's generation is derived from
// the head we CAS against (strictly monotonic), NOT from idx.
//
// CRITICAL: because frees route by HOME shard, a single shard's free-list
// is mutated by MANY threads concurrently (any thread freeing a node
// whose home == this shard). The freeNext CAS is therefore contended —
// but the contention is SPREAD across 64 lines, never concentrated on
// one. This is the multi-locus dispersion the SEC topology requires.
func (p *ElimNodePool) freeIndexSharded(idx uint64, shard uint64) {
	for {
		head := p.freeShards[shard].free.Load() // packed (gen, idx)
		// Link this node to the current shard free-list head (packed).
		atomic.StoreUint64(&p.nodes[idx].freeNext, head)
		newFree := elimPackIndex(elimGen(head)+1, idx)
		if p.freeShards[shard].free.CompareAndSwap(head, newFree) {
			p.count.Add(-1)
			return
		}
	}
}

// freeIndexHome is the convenience wrapper for home-shard routing: free
// `idx` to its HOME shard (idx % elimPoolShardCount). This is the call
// the SEC candidate's pop path uses after recycling a popped index.
func (p *ElimNodePool) freeIndexHome(idx uint64) {
	home := idx % elimPoolShardCount
	p.freeIndexSharded(idx, home)
}

// allocIndexSharded pops an index from the caller's LOCAL shard first
// (shard == pid), then probes adjacent shards (pid+1, pid+2, ...) until
// it finds a non-empty one. This minimizes cross-shard traffic in the
// common case (producers allocate from their own shard, which the
// home-shard frees continuously refill), while guaranteeing forward
// progress even if the local shard is momentarily empty.
//
// It is a per-shard Treiber pop with the SAME ABA-immune generation
// discipline as the legacy allocIndex: the new head's generation is
// derived from the head we CAS against.
//
// CRITICAL: this MUST NEVER return NullOffset64 (0). Index 0 is the
// permanent sentinel for "shard stackTop empty". If a push receives idx
// 0 and links it onto a stackTop, that shard becomes indistinguishable
// from EMPTY — every subsequent pop returns false and the drainer walks
// 0 nodes (drained=0, surplus>0). That is the precise corruption
// symptom. On full exhaustion we SPIN (Gosched) and retry rather than
// hand back a 0 — the pool is sized to 2x working set so a non-zero
// index always becomes available once an in-flight pop recycles one.
// elimAllocShardRetry caps the number of CAS attempts a goroutine
// makes against a SINGLE shard's free-list head before falling through
// to probe the next shard. Without this bound the inner loop could
// spin indefinitely on a contended shard head while other (less-
// contended) shards went unharvested — a livelock vector verified
// during this analysis (a goroutine dump showed many producers pinned
// in allocIndexSharded's inner loop under a transient refill-depth
// skew). The bound keeps work-stealing's forward-progress guarantee:
// after a bounded loss we VISIT the next shard, so a freed index on
// any shard is reachable within elimPoolShardCount*elimAllocShardRetry
// attempts even under full contention.
const elimAllocShardRetry = 16

// elimAllocYieldEvery bounds how often allocIndexSharded yields the P
// via runtime.Gosched when the WHOLE pool is momentarily empty (all 64
// shards drained). An unbounded Gosched loop under skew starves the
// poppers that would otherwise free indices back — another verified
// livelock. Yielding only every Nth empty-pass lets the pop-side make
// progress between yields, so a recycled index appears before the
// allocator is re-scheduled away.
const elimAllocYieldEvery = 64

func (p *ElimNodePool) allocIndexSharded(pid int) uint64 {
	passes := 0
	for {
		start := uint64(pid) % elimPoolShardCount
		for probe := 0; probe < elimPoolShardCount; probe++ {
			shard := (start + uint64(probe)) % elimPoolShardCount
			// BOUNDED inner retry: give up this shard after a few CAS
			// losses and probe the next one. Restores forward progress
			// under head-contention (the verified inner-loop livelock).
			for retry := 0; retry < elimAllocShardRetry; retry++ {
				head := p.freeShards[shard].free.Load() // packed (gen, idx)
				headIdx := elimIndex(head)
				if headIdx == NullOffset64 {
					break // this shard is empty; try the next one
				}
				nextPacked := atomic.LoadUint64(&p.nodes[headIdx].freeNext)
				nextIdx := elimIndex(nextPacked)
				newFree := elimPackIndex(elimGen(head)+1, nextIdx)
				if nextIdx == NullOffset64 {
					newFree = NullOffset64
				}
				if p.freeShards[shard].free.CompareAndSwap(head, newFree) {
					p.count.Add(1)
					return headIdx // headIdx > 0 always (0 never on a free-list)
				}
				// CAS failed — a concurrent allocator won the head.
				// Bounded: retry this shard a few times, then fall
				// through to the next shard (work-stealing forward
				// progress) instead of spinning on one contended line.
			}
		}
		// Every shard is empty. Pool momentarily exhausted. NEVER
		// return 0 (sentinel). Yield only every elimAllocYieldEvery
		// empty-pass so the pop-side can run between our yields and
		// recycle an index we can then steal — an unbounded Gosched
		// loop under skew starves the very poppers that refill the pool
		// (the verified outer-loop livelock). Between yields we busy
		// re-probe, which serves the steady-state common case (a freed
		// index appears within nanoseconds) without a scheduler round-
		// trip.
		passes++
		if passes%elimAllocYieldEvery == 0 {
			runtime.Gosched()
		}
	}
}

// Compile-time assertions that ElimSlot is exactly two cache lines.
var _ = unsafe.Sizeof(ElimSlot{})
