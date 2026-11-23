// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"math/bits"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Elimination backoff array for the Treiber stack
// ---------------------------------------------------------------------------
//
// A lock-free Treiber stack serializes compare-and-swap operations on its head.
// Under contention, failed operations repeatedly invalidate the same cache
// line. The elimination array gives complementary pushes and pops a separate
// place to exchange a value without changing the central stack head.
//
// A completing slot CAS is the exchange's linearization point. The eliminated
// push happens before the paired pop, and the pair leaves the central stack
// unchanged (Herlihy-Shavit, "The Art of Multiprocessor Programming", Ch. 11).
//
// Design choices:
//
//  (1) A static, power-of-two array of 64 slots avoids resizing and allocation
//      on the hot path. At 128 bytes per slot, the array occupies 8 KiB.
//
//  (2) A mask selects a slot with one bitwise AND; modulo is unnecessary.
//
//  (3) Slot waits use bounded spins rather than sleeps. The outer push/pop
//      loops yield periodically after repeated failed attempts.
//
//  (4) A collision counter adjusts the probe budget. Successful eliminations
//      decrement it; missed exchanges increment it. The budget is clamped to
//      the array capacity.
//
//  (5) Each parked record carries a unique per-goroutine, per-attempt stamp.
//      Completion and timeout reclaim compare the packed operation and stamp,
//      preventing an old record from completing against a recycled slot.
//
//  (6) The slot array is embedded by value and its fields are atomics. Node
//      storage is preallocated, and PRNG and stamp state is goroutine-local.
//
//  (7) Each slot occupies two 64-byte cache lines. Its state and value share
//      the first line; padding keeps adjacent slots and the central head from
//      false-sharing.
// ---------------------------------------------------------------------------

// EliminationArrayCapacity fixes the array at twice the 32-core design
// concurrency. The power-of-two width permits masked slot indexing.
const EliminationArrayCapacity = 64

// elimSlotOp tags which half of a push/pop pair is parking in a slot.
type elimSlotOp uint64

const (
	elimSlotEmpty elimSlotOp = 0 // slot is free
	elimSlotPush             = 1 // a Push op is parked waiting for a Pop
	elimSlotPop              = 2 // a Pop op is parked waiting for a Push
)

// elimState packs an operation and stamp into one atomic word:
//
//	bits [63:62] = operation (empty, push, or pop)
//	bits [61:0]  = stamp
//
// Parking, completion, and timeout reclaim each compare and swap this whole
// word. An observer therefore cannot see a new operation with an old stamp.
const (
	elimStateOpShift   = 62
	elimStateOpMask    = uint64(3) << elimStateOpShift
	elimStateStampMask = ^elimStateOpMask
)

// elimCompleteValueWait bounds how long a completing Pop waits for a parked
// Push to publish its value. Retiring the slot before publication could leave
// the Push reporting a completed exchange while the Pop has no value. The Pop
// also rechecks state so it stops waiting if the Push reclaims its record.
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

// ElimSlot occupies 128 bytes. Leading padding, state, and value fill the
// first 64-byte line; trailing padding isolates the next slot. State packs the
// operation and stamp that commit an exchange. Value holds a Push payload or
// NullOffset64 when no payload is pending.
type ElimSlot struct {
	_padLead [48]byte      // fill line-0 so state+value share exactly one line
	state    atomic.Uint64 // packed (op << 62) | stamp — control plane
	value    atomic.Uint64 // payload / sink — data plane
	_padTail CacheLinePad  // 64B: line 1, pure isolation pad
}

// EliminationArray holds the fixed slot array by value.
type EliminationArray struct {
	slots [EliminationArrayCapacity]ElimSlot
}

// ElimStack combines a central Treiber stack with an elimination array. Head
// is a packed pool index and generation, padded away from the collision counter
// and slot array.
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

// elimStampCounter assigns a distinct base when each goroutine seeds its
// ElimPRNG. Later stamps advance a local sequence, keeping this shared counter
// off the steady-state hot path. The base and 30-bit sequence fit the 62-bit
// stamp field.
var elimStampCounter atomic.Uint64

const (
	elimStampSeqBits   = 30 // per-goroutine sequence width
	elimStampSeqMask   = (uint64(1) << elimStampSeqBits) - 1
	elimStampBaseShift = elimStampSeqBits // stampBase occupies the high bits
)

// stamp combines the goroutine's base with a local sequence. Distinct bases
// separate goroutines, and the sequence separates retries. Completion and
// reclaim CAS operations compare the exact operation and stamp, so a recycled
// slot cannot be mistaken for the earlier record.
func (r *ElimPRNG) stamp() uint64 {
	s := (r.stampBase << elimStampBaseShift) | (r.stampSeq & elimStampSeqMask)
	r.stampSeq++
	return s
}

// ElimPRNG carries goroutine-local random, stamp, and node-recycling state.
// The cache holds one node index taken from a central pop or completed
// elimination. The next push reuses it without a shared free-list CAS; if the
// cache is full, a freed index returns to the shared pool.
//
// stampBase is assigned once during lazy seeding and stampSeq advances locally.
// secCache is the deeper cache used by the sharded stack; ElimStack ignores it.
//
// A cached index belongs exclusively to this goroutine and is not on any shared
// free-list. Sharing an ElimPRNG between goroutines would violate that ownership.
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
		// Seed once: derive a globally-unique PRNG seed and a globally-
		// unique stampBase from the same single Add(1). After this, the
		// goroutine never touches elimStampCounter again — stamps come
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
// Contract: the returned *ElimPRNG is for this goroutine's exclusive
// use. The secDeepCache and stamp sequence fields are goroutine-local
// state; sharing one *ElimPRNG across goroutines races on that state
// and corrupts the ElimNodePool free-list.
func NewElimPRNG() *ElimPRNG { return &ElimPRNG{} }

// elimExchangeResult reports the outcome of a slot visit.
type elimExchangeResult uint8

const (
	elimExChanged   elimExchangeResult = iota // partner completed the operation
	elimExNoPartner                           // parked, timed out, and reclaimed
	elimExSkipped                             // slot taken; probe another
)

// tryExchange parks a Push or Pop, or completes a complementary parked
// operation. Slot state packs the operation and stamp into one atomic word, so
// completion and timeout reclaim cannot match a stale record.
//
// An empty slot accepts either operation with a fresh stamp. A complementary
// operation completes the exchange by CASing that exact state to empty; this
// CAS is the linearization point. Same-operation records are skipped. A Push
// publishes its value after parking, while a Push completing a Pop stores the
// value before retiring the record.
//
// Parking starts with an empty-to-(op, stamp) CAS. A parked Push then publishes
// its value; a parked Pop does not write the slot. After a bounded wait, the
// owner tries to reclaim its exact state. Reclaim success means no partner
// arrived; failure means a partner completed the exchange.
//
// A Push completing a Pop stores its value before the state CAS. A Pop
// completing a Push waits for the published value, retires the exact state,
// then returns that value. The value clear after completion admits later
// parkers.
//
// A stamp mismatch makes the completing CAS fail if another operation has
// reclaimed or reused the slot. elimExChanged reports a completed exchange;
// elimExNoPartner reports a timeout and successful reclaim. elimExSkipped is
// reserved and is not currently returned.
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
			// An empty state can still hold a completed value awaiting
			// collection. Do not park over it; a third operation would
			// overwrite the value before its owner reads it.
			if slot.value.Load() != NullOffset64 {
				continue // value pending collection; do not park over it
			}
			// 1. PARK: (empty, 0) → (myOp, myStamp).
			if !slot.state.CompareAndSwap(curState, myParkedState) {
				continue // raced; probe another slot
			}
			// Only a parked Push publishes here. A completing Push also
			// writes the value, so a parked Pop must not clear it and race
			// that delivery. The state CAS orders these writers.
			if op == elimSlotPush {
				slot.value.Store(valIn)
			}
			// 3. Spin for a partner within a bounded L1-hot budget.
			if elimSpinWait(slot, op, stamp, valOut) {
				return elimExChanged
			}
			// Reclaim only the exact parked state. If a partner completed
			// the exchange, this CAS fails because the state changed.
			if slot.state.CompareAndSwap(myParkedState, elimPackState(elimSlotEmpty, 0)) {
				// Clear the reclaimed payload so a later parker sees the
				// free (empty, NullOffset64) state.
				slot.value.Store(NullOffset64)
				return elimExNoPartner
			}
			// A failed reclaim means a partner retired the record.
			if op == elimSlotPop {
				// The completing Push stored the value before its state CAS,
				// so this load observes the published payload. Zero and
				// NullOffset64 are valid here: retirement, not a sentinel
				// comparison, establishes that a value was delivered.
				*valOut = slot.value.Load()
				slot.value.Store(NullOffset64) // return slot to free
				return elimExChanged
			}
			// A Pop retired the Push record and collected its value.
			return elimExChanged
		}

		// A complementary op is parked here. COMPLETE the exchange.
		// Complete only the exact parked operation and stamp. A reclaimed
		// or replaced record has a different state and fails the CAS.
		parkedPacked := curState
		if op == elimSlotPop {
			// Pop completing a Push. The Push publishes after its park CAS,
			// so wait for a non-sentinel value before retiring the record.
			// Retiring earlier could make the Push report completion while
			// this Pop has no value to return. The empty-state guard keeps a
			// third operation from overwriting the pending value.
			//
			// If the Push reclaims first, the old-state CAS below fails and
			// this Pop probes elsewhere. Only one Pop can win that CAS, so a
			// published value has exactly one collector.
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
				// Publication did not arrive before the bound, or the Push
				// reclaimed the record. Leave it for the owner and probe on.
				continue
			}
			// Retire the exact record only after its value is present. A
			// failed CAS means the owner or another Pop completed it.
			if !slot.state.CompareAndSwap(parkedPacked, elimPackState(elimSlotEmpty, 0)) {
				// The state changed, so this record is no longer owned by
				// the observed Push. Its owner or another Pop handles the
				// value; probe elsewhere without collecting it here.
				continue
			}
			// The successful retire CAS assigns this value to the Pop.
			// Clear it so a later operation can park in the slot.
			*valOut = v
			slot.value.Store(NullOffset64)
			return elimExChanged
		}

		// Push completing a Pop: store the value before retiring the exact
		// parked state. The state CAS publishes the value to the parked Pop.
		slot.value.Store(valIn)
		if !slot.state.CompareAndSwap(parkedPacked, elimPackState(elimSlotEmpty, 0)) {
			// The Pop reclaimed or another thread completed the record.
			// Undo the speculative value publish so a reused slot does not
			// inherit this payload.
			slot.value.CompareAndSwap(valIn, NullOffset64)
			continue
		}
		*valOut = valIn
		return elimExChanged
	}
	return elimExNoPartner
}

// elimSpinWait reports whether the parked state changed within eight loads.
// It only detects completion; the caller's reclaim path collects the value and
// clears the slot exactly once. The short busy wait avoids a scheduler yield
// while holding a slot. The outer push/pop loops still yield after repeated
// failed attempts.
func elimSpinWait(slot *ElimSlot, op elimSlotOp, stamp uint64, valOut *uint64) bool {
	// Keep the wait short: a parked operation holds its slot, and most matches
	// arrive soon after the complementary central CAS fails.
	const spinBudget = 8
	myState := elimPackState(op, stamp)
	_ = valOut // not used — value collection is in the caller's reclaim paths
	for i := 0; i < spinBudget; i++ {
		// A partner completed the operation when the exact parked state
		// changed. The caller reconciles value ownership on this result.
		if slot.state.Load() != myState {
			return true
		}
	}
	return false
}

// adaptiveProbeBudget returns baseProbe plus bits.Len64(collisions), clamped
// to the array capacity. Low collision counts retry the central stack sooner;
// high counts probe more slots before the next central attempt.
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

// push stages a node index from the goroutine cache or shared pool, then tries
// the central Treiber stack. A failed head CAS leads to elimination probing.
// An eliminated Push recycles its staged index through the goroutine cache when
// possible; a central push transfers ownership of the node to the stack.
func (s *ElimStack) push(pool *ElimNodePool, prng *ElimPRNG, value uint64) {
	// Stage a node index once per attempt. Prefer the per-goroutine
	// cache (zero contention) over the shared free-list. The index is
	// reused across retries and returned to the pool/cache on
	// elimination success, keeping the pool balanced (zero-GC).
	stagedIdx := prng.cache
	if stagedIdx != NullOffset64 {
		prng.cache = NullOffset64 // claim: cache ↔ this op, single owner
	} else {
		stagedIdx = pool.allocIndex()
	}

	for attempts := 0; ; attempts++ {
		pool.nodes[stagedIdx].value = value
		head := s.head.Load() // head is packed (gen, idx)
		// Preserve the observed packed head in the link and store it atomically.
		atomic.StoreUint64(&pool.nodes[stagedIdx].next, head)
		// Incrementing the generation rejects a stale head CAS.
		newHead := elimPackIndex(elimGen(head)+1, stagedIdx)
		if s.head.CompareAndSwap(head, newHead) {
			// The central stack now owns stagedIdx.
			return
		}

		// On contention, try an elimination exchange. Stamps come only from
		// the goroutine's base and sequence; mixing in random bits could
		// collide with another goroutine's stamp.
		stamp := prng.stamp()
		budget := s.adaptiveProbeBudget()
		var out uint64
		res := s.arr.tryExchange(prng, elimSlotPush, value, stamp, budget, &out)
		switch res {
		case elimExChanged:
			s.feedback(true)
			// A matching Pop consumed the value. Recycle stagedIdx through
			// the goroutine cache, or the shared free-list if the cache is full.
			if prng.cache == NullOffset64 {
				prng.cache = stagedIdx
			} else {
				pool.freeIndex(stagedIdx)
			}
			return
		case elimExNoPartner:
			s.feedback(false)
			// This operation still owns stagedIdx, so retain it for the next
			// central attempt. Caching it here would let a later push use the
			// same index concurrently.
		case elimExSkipped:
			// (tryExchange never returns this currently; kept for parity.)
			s.feedback(false)
		}
		// Yield periodically after repeated failed attempts; do not sleep.
		if attempts&63 == 63 {
			runtime.Gosched()
		}
	}
}

// pop tries the central Treiber stack and uses elimination probing after a
// failed head CAS or when the stack is empty. Symmetric backoff lets a Pop meet
// a contended Push even when the central stack contains other values. It
// returns false only when the observed stack was empty and no partner arrived.
func (s *ElimStack) pop(pool *ElimNodePool, prng *ElimPRNG) (uint64, bool) {
	for attempts := 0; ; attempts++ {
		head := s.head.Load() // packed (gen, idx)
		headIdx := elimIndex(head)
		if headIdx != NullOffset64 {
			node := &pool.nodes[headIdx]
			// Only the next index is needed; newHead takes its generation
			// from the observed head below.
			nextPacked := atomic.LoadUint64(&node.next)
			// Derive the new generation from the current head, not from
			// nextPacked. The link may carry an older generation; reusing it
			// could let a stale head CAS succeed after the same index returns.
			// Incrementing the observed head generation prevents that ABA case.
			nextIdx := elimIndex(nextPacked)
			newHead := elimPackIndex(elimGen(head)+1, nextIdx)
			if nextIdx == NullOffset64 {
				// The next link is the sentinel, so the stack becomes empty.
				newHead = NullOffset64
			}
			if s.head.CompareAndSwap(head, newHead) {
				v := node.value
				// Recycle through the goroutine cache when possible, otherwise
				// return the index to the shared free-list.
				if prng.cache == NullOffset64 {
					prng.cache = headIdx
				} else {
					pool.freeIndex(headIdx)
				}
				return v, true
			}
			// The observed stack was nonempty, so a failed central CAS leads
			// to symmetric elimination probing. Stamps use only the goroutine's
			// base and sequence; random bits could collide across goroutines.
			stamp := prng.stamp()
			budget := s.adaptiveProbeBudget()
			var out uint64
			res := s.arr.tryExchange(prng, elimSlotPop, 0, stamp, budget, &out)
			switch res {
			case elimExChanged:
				s.feedback(true)
				// A Push completed this Pop and supplied its value.
				return out, true
			case elimExNoPartner:
				s.feedback(false)
				// No partner in the array and the stack had data —
				// retry the central CAS (do not report empty).
				continue
			case elimExSkipped:
				s.feedback(false)
				continue
			}
		}

		// The observed stack was empty. Only an elimination partner can
		// supply a value; otherwise report empty. Stamps use the goroutine's
		// base and sequence without random bits.
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
			// Stack was empty and no elimination partner ⇒ genuine empty.
			return 0, false
		}
	}
}

// ---------------------------------------------------------------------------
// Exported stack operations.
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
// ElimNodePool — the pre-allocated zero-GC node arena the ElimStack
// indexes into via uint64 offsets. Constant-size; allocated once.
// -----------------------------------------------------------------------

// ABA-immune head/next encoding for the central Treiber stack and the
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
// whose value was popped/freed and re-pushed gets a different
// generation — its CAS fails. This is the classic "tagged pointer"
// ABA defense (Valois 1995) adapted to a uint64 index scheme. It is
// applied to both the central stack and the free-list, because the
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
// the ElimNodePool free-list link. Both use the same packed encoding
// (see elimPackIndex) but are separate fields: the free-list and
// central stack link through the same node independently, so sharing
// one field would corrupt whichever list isn't currently authoritative.
type ElimNode struct {
	value    uint64
	next     uint64 // packed (gen, idx) — ABA tag for central stack
	freeNext uint64 // packed (gen, idx) — ABA tag for free-list
}

// ElimPoolShard is one shard of the sharded free-list allocator. Occupies
// exactly 128 bytes (two Neoverse-V1 cache lines) so adjacent shards in
// the array never false-share and the L2 spatial prefetcher cannot pull
// a neighboring shard's line alongside this one. Mirrors secShard's
// stride discipline.
//
// The free-list head stored here uses the same packed (gen, idx) ABA-
// immune encoding as the legacy single free-list (see elimPackIndex).
type ElimPoolShard struct {
	free atomic.Uint64 // head of a Treiber free-list of indices (packed)
	_pad [120]byte     // 128 - sizeof(atomic.Uint64) = 120
}

// elimPoolShardCount is the number of allocator free-list shards. It
// must match secShardCount so that an index's home shard
// (idx % elimPoolShardCount) is the same shard a per-P push routes the
// stackTop to (procPin & (secShardCount-1)) whenever idx % shardCount
// == pid — a common case that keeps the allocate-from / free-to
// traffic local. Kept as a named constant (not a copy of
// flatCombMaxThreads) so the coupling is explicit.
const elimPoolShardCount = 64

// ElimNodePool is a fixed-capacity ring of ElimNodes plus an atomic
// free-list (itself a tiny Treiber stack) for recycling indices. The
// benchmark pre-allocates one pool sized to 2× the working set and
// reuses indices for the whole run — zero hot-path allocation.
type ElimNodePool struct {
	nodes []ElimNode
	_pad0 CacheLinePad
	// Legacy single free-list head (unused; allocIndex and freeIndex route to
	// the sharded free-lists).
	free  atomic.Uint64 // head of Treiber free-list of indices
	count atomic.Int64  // outstanding allocations (diagnostic)
	_pad1 CacheLinePad
	// The sharded allocator uses 64 free-lists with 128-byte strides.
	// Frees go to the node's home shard; allocations start at the caller's
	// shard and probe neighbors to spread cache-line contention.
	freeShards [elimPoolShardCount]ElimPoolShard
}

// NewElimNodePool preallocates cap nodes in one backing slice. Index zero is
// reserved for NullOffset64, so callers must include one extra slot beyond the
// working set. Free-list links use packed generation and index values; each CAS
// increments the generation to reject stale links after an index is recycled.
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
	// Seed each index into home = idx % elimPoolShardCount, excluding the
	// reserved zero index. Descending insertion leaves the smallest home index
	// at each shard head and gives deterministic allocation order.
	for sh := 0; sh < elimPoolShardCount; sh++ {
		p.freeShards[sh].free.Store(NullOffset64)
	}
	// Build the home free-lists directly without changing the allocation
	// count. Descending insertion gives deterministic refill order.
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

// allocIndex allocates through allocIndexSharded because every node has one
// freeNext link shared by the single and sharded free-list representations.
// Only the sharded lists are seeded; maintaining a separate p.free chain would
// overwrite those links. Starting at shard zero and probing all shards returns
// an unpacked index while preserving forward progress.
func (p *ElimNodePool) allocIndex() uint64 {
	return p.allocIndexSharded(0)
}

// freeIndex returns an unpacked index to its home shard. This keeps one
// authoritative sharded free-list for ElimNode.freeNext and distributes
// allocator contention across shards.
func (p *ElimNodePool) freeIndex(idx uint64) {
	p.freeIndexHome(idx)
}

// ---------------------------------------------------------------------------
// Sharded allocator (SEC candidate) — home-shard routing
// ---------------------------------------------------------------------------

// freeIndexSharded pushes an unpacked index onto the selected shard's Treiber
// free-list. Home routing spreads frees across all 64 shard heads, refilling
// the local shards from which producers allocate. The new head generation comes
// from the observed head so a recycled index cannot make a stale CAS succeed.
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

// freeIndexHome returns idx to shard idx % elimPoolShardCount.
func (p *ElimNodePool) freeIndexHome(idx uint64) {
	home := idx % elimPoolShardCount
	p.freeIndexSharded(idx, home)
}

// elimAllocShardRetry bounds CAS retries on one shard before allocation probes
// the next. The bound prevents a contended head from monopolizing a goroutine
// while other shards have free indices.
const elimAllocShardRetry = 16

// elimAllocYieldEvery controls how often an exhausted allocator yields.
// Busy probes between yields let poppers recycle indices without repeatedly
// descending into the scheduler.
const elimAllocYieldEvery = 64

// allocIndexSharded probes from the caller's shard through all 64 shards.
// Each shard uses the packed generation to reject stale free-list heads. Index
// zero is reserved, so exhaustion causes more probing rather than a sentinel
// return that would make a nonempty stack appear empty.
func (p *ElimNodePool) allocIndexSharded(pid int) uint64 {
	passes := 0
	for {
		start := uint64(pid) % elimPoolShardCount
		for probe := 0; probe < elimPoolShardCount; probe++ {
			shard := (start + uint64(probe)) % elimPoolShardCount
			// Limit retries on this shard before probing the next so a
			// contended head cannot prevent forward progress.
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
		// All shards are empty. Keep probing rather than returning the zero
		// sentinel, and yield only every elimAllocYieldEvery passes so
		// poppers can recycle indices between scheduler rounds.
		passes++
		if passes%elimAllocYieldEvery == 0 {
			runtime.Gosched()
		}
	}
}

// Keep unsafe.Sizeof referenced alongside the layout-sensitive slot definition.
var _ = unsafe.Sizeof(ElimSlot{})
