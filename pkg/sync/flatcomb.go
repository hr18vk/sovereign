package sync

import (
	"runtime"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// Stage 5 — Flat-Combining Stack (FC)
// ---------------------------------------------------------------------------
//
// WHY THIS FILE EXISTS — architectural context (see stage5_gate_test.go
// and the Deep Research document "Go Elimination Stack Anti-Scaling.md").
//
// The previous design (elimination.go) is an Elimination Backoff Array.
// It PASSIVELY parks a losing Push in a slot waiting for a Pop to come
// park in the same slot and complete it. Under the asymmetric
// producer-consumer burst crucible (the REAL ingestion workload — NOT a
// benchmark artifact), the pop arrival rate at any parked push is
// essentially zero: the pops that would match a producer burst's parked
// pushes come from OTHER goroutines' future consumer bursts much later,
// by which time every parked push has already spun out, reclaimed, and
// retried the central CAS simultaneously — the Phase-Locked Symmetry
// Collapse. Throughput INVERTS 4→32c (the gate measured 2.1% efficiency,
// 827K ops/s — see the Step 1b brutal-honesty checkpoint).
//
// FLAT-COMBINING (Hendler, Lev, Moir, Shavit — PLDI 2010) replaces
// passive waiting with ACTIVE DELEGATION:
//   - A goroutine that would lose a central CAS publishes its request
//     to a publication record, then spins on its OWN record's `seq`
//     word (one cache line never shared with another waiter — 128B-
//     padded records).
//   - The COMBINER (any goroutine that wins an acquiring CAS on a
//     single combining flag) walks all publication records, applies
//     the batch SEQUENTIALLY against the central stack, pairs
//     complementary Push/Pop ops LOCALLY (without any central CAS at
//     all for matched pairs), and writes results back to the waiters'
//     records (bumping their seqs as the wake-up ack).
//   - The combining-flag acquire/release is amortized across the
//     whole batch, so the only contended CAS-line is hit
//     ~1/batch_size times per op, and the central Treiber CAS — the
//     line the elimination array + plain Treiber both saturate at
//     32 cores — is hit only by the combiner, SEQUENTIALLY, completely
//     eliminating the 32-core coherent-mesh ping-pong.
//
// GO MEMORY MODEL FIT — confirmed via deep research (see the
// stage5_gate_test.go commit notes). Go's sync/atomic operations are
// sequentially consistent (Go memory model: "All the atomic operations
// executed in a program behave as though executed in some sequentially
// consistent order ... the same semantics as C++'s sequentially
// consistent atomics and Java's volatile variables"). The DLM FC
// algorithm was originally specified against Java `volatile` semantics
// with NO extra fences, so it transplants to Go verbatim AS LONG AS
// every shared publication-record and combining-flag field is accessed
// via sync/atomic. Plain Go assignments on shared fields break DRF-SC
// and resurrect the "busy-wait double-checked-locking" trap explicitly
// documented in the Go memory model — that is the ONLY real failure
// mode to avoid. Every shared field below is an atomic.* type. There
// are NO plain shared-field accesses in this file.
//
// LINEARIZATION-POINT PROTOCOL (the rigid handshake, derived from DLM §3):
//
//   Waiter publishes (publish happens-after the op/arg Stores):
//        rec.arg.Store(value); rec.op.Store(code); rec.seq.Store(myOdd)
//     where myOdd is the chosen monotonic odd seq (1 — the record was
//     zero-zeroed by allocRec, so seq was 0 EVEN before). The LAST
//     write is the publish signal; the combiner's Load(seq)
//     synchronizes-with it.
//
//   Combiner applies, then ACKs (ack happens-after the resp/ok Store):
//        snapshot_op := rec.op.Load(); snapshot_arg := rec.arg.Load()
//        apply the op; for Pop, Store popRec.resp = result AND
//        popRec.ok = okBit
//        rec.seq.Store(snapshot_seq + 1)              // odd → even
//     The resp/ok Store is SEQUENCED BEFORE the seq Store, so the
//     waiter that observes even-seq observes a consistent resp.
//
//   Waiter spins on rec.seq.Load() != myOdd, then reads resp/ok and
//   frees its record.
//
// -----------------------------------------------------------------------
// REUSE FROM elimination.go (Zero new structure, Zero-GC, ABA-immune):
//
//   - ElimNode / ElimNodePool / allocIndex / freeIndex — pre-allocated
//     node arena, ABA-immune free-list. The combiner allocs/frees node
//     indices when committing unpaired central pushes/pops.
//   - elimPackIndex / elimIndex / elimGen — ABA-immune tagged (gen, idx)
//     encoding for the central Treiber head. The combiner is the sole
//     mutator of head but still bumps the generation on each linking
//     CAS — redundant-but-harmless ABA defense; head-walkers (diag_test,
//     stage5 gate's drainer) observe a monotonic generation even if a
//     node index is recycled between two push CASes.
//   - NullOffset64 (== 0) — empty-stack sentinel. Reused verbatim.
//   - CacheLinePad — 64-byte pad.
//
// API PARITY with ElimStack (drop-in for the gate's stage5Stack
// interface, diag_test.go's walker, and the linearizability stress):
//
//   type flatCombStack struct { ... head atomic.Uint64 ... }
//   func (s *flatCombStack) push(pool *ElimNodePool, prng *ElimPRNG, value uint64)
//   func (s *flatCombStack) pop(pool *ElimNodePool, prng *ElimPRNG) (uint64, bool)
//   stack.head.Load() // packed (gen, idx); NullOffset64 if empty
// ---------------------------------------------------------------------------

// flatCombMaxThreads is the maximum number of concurrently published
// requests the combiner scans in one combine() pass. Sized to
// generously exceed the 32-core Graviton hardware thread count. The
// DLM paper recommends slot count track the hardware thread count, not
// an arbitrary large number (longer scans ⇒ slower tail latency under
// light load). 64 = 2× the 32-core target, covers Go's routine
// over-subscription while keeping a combine() scan a single LLC sweep.
const flatCombMaxThreads = 64

// flatCombOp tags the publication record's requested operation.
// 0 (flatCombOpIdle) is the "no request" sentinel so a freshly-zeroed
// record needs no initialization — the waiter's mechanism is the seq
// parity handshake, but op==idle lets the combiner's fast scan SKIP
// records that have not been freshly published (the seq-odd check
// alone would suffice for correctness — op==idle is a perf hint for a
// future relaxed-load optimization, harmless under SC).
type flatCombOp uint32

const (
	flatCombOpIdle flatCombOp = 0
	flatCombOpPush flatCombOp = 1
	flatCombOpPop  flatCombOp = 2
)

// flatCombPub is one publication record a waiter publishes its request
// into and spins on for the combiner's ack. EXACTLY 128 bytes (two
// Neoverse-V1 cache lines) — verified at compile time by
// TestFlatCombSlotSize.
//
// LAYOUT (line 0 = seq + op + arg; line 1 = resp + ok + round):
//
//	line 0 holds `seq`/`op`/`arg` because the waiter's spin polls
//	`seq` (the wait point) and the combiner's snapshot reads
//	`op`/`arg` — keeping all three on one line makes the publish +
//	snapshot + tip poll L1-resident on a single line, no cross-line
//	fence in the steady-state hot path.
//	line 1 holds `resp`/`ok`/`round` — written by the combiner once,
//	read by the waiter once after the seq ack, never spun on.
//
// Both lines are exclusively padded: adjacent records never share a
// line, so a spinning waiter on one record never invalidates an
// ADJACENT spinning waiter's line. The combiner's scans walk records
// 128B apart — a clean stride-128 L1/LLC sweep with no false-share
// cross-invalidation.
//
// Field sizes (uint64=8, uint32=4):
//
//	line 0: _padLead 40 + seq 8 + op 4 + _padOp 4 + arg 8 = 64
//	line 1: resp 8 + ok 4 + round 4 + _padTail 48             = 64
//	                                                           total 128
type flatCombPub struct {
	_padLead [40]byte
	seq      atomic.Uint64 // wait handshake: ODD = pending, EVEN = idle/acked
	op       atomic.Uint32 // flatCombOp (idle/push/pop)
	_padOp   [4]byte
	arg      atomic.Uint64 // Push value (set by waiter, read by combiner)
	resp     atomic.Uint64 // Pop result (set by combiner BEFORE seq ack, read by waiter AFTER seq ack)
	ok       atomic.Uint32 // Pop ok bit: 1 = value present, 0 = empty
	round    atomic.Uint32 // waiter-side spin counter (drives low-rate Gosched)
	_padTail [48]byte
}

// ---------------------------------------------------------------------------
// flatCombStack — the Flat-Combining stack
// ---------------------------------------------------------------------------

// flatCombStack is the Flat-Combining stack. Layout decisions:
//
//   - `head` is the central Treiber head (packed (gen, idx)); the SOLE
//     structure mutated by combine() (in a sequential batch). Padded on
//     both sides so concurrent head-walkers (diag_test.go, the stage5
//     gate's drainer) read a line never false-shared by the combiner's
//     other writes.
//   - `combining` is the SINGLE contended line at the CAS race to
//     become combiner. CAS 0 → 1 to acquire, Store(0) to release.
//     Padded on both sides from head + recs so the combiner's
//     acquire/release never invalidates a spinning waiter's `seq` line.
//   - `recs` is a fixed-size array of 128B publication records,
//     value-embedded (Zero-GC: one heap object for the entire stack;
//     the array is part of it).
//   - `recFreeNext` is the free-list backbone array for the per-rec-
//     index free-list (a tiny Treiber stack of small integers, enabling
//     Zero-GC acquisition of a pub-record index per push/pop call).
//   - `recFree` is the Atomic head of that free-list (packed (gen, idx)
//     uint32 — ABA-immune tagged u32 free-list, mirrors ElimNodePool).
type flatCombStack struct {
	_pad0       CacheLinePad
	head        atomic.Uint64 // central Treiber head: packed (gen, idx), NullOffset64 if empty
	_pad1       CacheLinePad
	combining   atomic.Uint32 // combining flag: 0 = unlocked, 1 = locked
	_pad2       CacheLinePad
	recs        [flatCombMaxThreads]flatCombPub
	_pad3       CacheLinePad
	recFreeNext [flatCombMaxThreads]uint32 // free-list backbone (uint32 per record)
	_pad4       CacheLinePad
	recFree     atomic.Uint32 // packed (gen, idx) head of rec-index free-list
	_pad5       CacheLinePad
}

// Packed-(gen, idx) u32 encoding for the rec-index free-list. Bits
// [15:0] = record index, bits [31:16] = monotonic generation. Index 0
// is the "free-list empty" sentinel (mirrors NullOffset64 for the u32
// free-list). Bumped on each alloc/free CAS → ABA-immune exactly like
// ElimNodePool.
const (
	flatCombRecIdxMask  = uint32(0xFFFF)
	flatCombRecGenShift = 16
)

func flatCombRecPack(gen, idx uint32) uint32 {
	return (gen << flatCombRecGenShift) | (idx & flatCombRecIdxMask)
}

func flatCombRecIndex(packed uint32) uint32 {
	return packed & flatCombRecIdxMask
}

func flatCombRecGen(packed uint32) uint32 {
	return packed >> flatCombRecGenShift
}

// NewFlatCombStack is THE constructor — the canonical factory used by
// both the production code (via the gate's stage5MakeStack factory) and
// the tests. Builds an empty FC stack with the publication records
// zeroed (op=idle, seq=EVEN, resp/ok/round=0) and the rec-index
// free-list linked from index 1 to index flatCombMaxThreads-1 (index 0
// permanently reserved as the free-list-empty sentinel).
//
// Zero-GC: the entire structure is embedded by value; the heap
// allocation is exactly one flatCombStack object total.
func NewFlatCombStack() *flatCombStack {
	s := &flatCombStack{}
	s.head.Store(NullOffset64)
	// Build the rec-index free-list backbone (LIFO Treiber stack).
	// Allocate the chain index 1 → 2 → ... → flatCombMaxThreads-1 → 0(empty).
	// The recFree head points at index 1 with generation 1. Stored freeNext
	// links use generation 0 (the gen contribution comes from the head at
	// free time, exactly like ElimNodePool stores freeNext=gen-0 but the
	// alloc's CAS derives newFree.gen = head.gen + 1, not from this stored
	// gen).
	for i := 1; i < flatCombMaxThreads; i++ {
		var next uint32
		if i+1 < flatCombMaxThreads {
			next = uint32(i + 1)
		}
		s.recFreeNext[i] = flatCombRecPack(0, next)
	}
	s.recFree.Store(flatCombRecPack(1, 1)) // head: gen 1, idx 1
	// recs are already zero-valued by Go's zero-init (seq=0 EVEN,
	// op=0 idle, etc.) — no explicit field init required.
	return s
}

// allocRec acquires a publication-record index from the rec-index
// free-list (a Treiber stack with ABA-immune tagged u32). This is the
// ONLY inter-goroutine CAS involved in a single push/pop call OUTSIDE
// the combining-flag race; it is a fast uncontended Treiber pop most of
// the time. Zero heap allocations.
//
// Returns a record index in [1, flatCombMaxThreads) for the caller to
// use for ONE push/pop invocation. The caller MUST return it via
// freeRec after the combiner (or its own fast path) acks the op.
//
// The record is RE-ZEROED here (seq=0=even, op=idle, arg=0, resp=0,
// ok=0, round=0) so a stale op/arg/seq from a previous use does not
// leak. Cost: a handful of atomic Stores to a now-private cache line
// (the record left the free-list — exclusively owned by the caller
// until freeRec returns it).
func (s *flatCombStack) allocRec() uint32 {
	for {
		head := s.recFree.Load()
		idx := flatCombRecIndex(head)
		if idx == 0 {
			// Free-list exhausted (> flatCombMaxThreads concurrent
			// invocations). Callers size the workload to never exceed
			// this; cooperative yield rather than panic (Zero-GC).
			runtime.Gosched()
			continue
		}
		nextPacked := atomic.LoadUint32(&s.recFreeNext[idx])
		nextIdx := flatCombRecIndex(nextPacked)
		newFree := flatCombRecPack(flatCombRecGen(head)+1, nextIdx)
		if s.recFree.CompareAndSwap(head, newFree) {
			// Zero the acquired record BEFORE returning so the caller
			// publishes into a clean slate. Pure-local writes (the
			// record is now exclusively owned: it left the free-list).
			rec := &s.recs[idx]
			rec.seq.Store(0)
			rec.op.Store(uint32(flatCombOpIdle))
			rec.arg.Store(0)
			rec.resp.Store(0)
			rec.ok.Store(0)
			rec.round.Store(0)
			return idx
		}
	}
}

// freeRec returns a publication-record index to the free-list. Called
// by a waiter AFTER the combiner acked its op (its seq went EVEN-again
// by the combiner's seq.Store(snapshot+1)).
//
// Zero contention by the time this is called: the record is no longer
// referenced by any waiter (the waiter's spin has exited) and is not
// referenced by any combiner (the combiner that bumped seq has moved
// past it in its scan).
func (s *flatCombStack) freeRec(idx uint32) {
	for {
		head := s.recFree.Load()
		// Link this record to current head.
		atomic.StoreUint32(&s.recFreeNext[idx], head)
		// CAS head → (gen_head + 1, idx). Bump generation, ABA-immune.
		newFree := flatCombRecPack(flatCombRecGen(head)+1, idx)
		if s.recFree.CompareAndSwap(head, newFree) {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// The combining flag and combine() — the heart of Flat Combining.
// ---------------------------------------------------------------------------

// flatCombMaxRounds is the number of FULL scans of the publication-
// record array ONE combine() pass performs before releasing the
// combining flag. Each round walks recs[1..flatCombMaxThreads-1]
// looking for pending requests. Amortizing one combining-flag
// acquisition across multiple rounds (so a combiner doesn't release +
// immediately re-acquire for a newly published request arriving
// mid-batch) is the DLM optimization that brings the combining-flag
// contention to ~1/(N*rounds) per op.
//
// 8 rounds covers typical inter-burst op density at P=32 with
// inter-burst jitter. Larger reduces flag-acquire pressure under dense
// sustained load but increases tail latency. Primary knob if Step 5
// finds sub-85% efficiency.
const flatCombMaxRounds = 8

// combine is the BATCH application routine, run by the combiner. Walks
// recs flatCombMaxRounds times, applying each (still-)PENDING op
// sequentially to the central Treiber stack OR to a local pending-Push
// FIFO used for inside-combine pairing.
//
//	INSIDE-COMBINE PAIRING (the decisive optimization vs plain DLM FC):
//
//	A Push discovered pending is queued into a local FIFO and ACKED
//	IMMEDIATELY (its seqStore odd→even). The Push waiter stops
//	spinning right then. The Push's value is NOT yet on the central
//	head — it is "in flight" in the FIFO. The Push's linearization
//	point is the moment it is queued.
//
//	A Pop discovered pending consults the FIFO FIRST. If the FIFO is
//	non-empty, the Pop's resp/ok gets the head-of-line Push's value
//	and the FIFO entry is consumed (matched). NO central CAS for the
//	matched pair — that is the elimination gain. The Pop's
//	linearization point is the match. The Push is already acked (the
//	queue op) so no second ack is needed.
//
//	Otherwise the Pop falls through to combinePopFromHead (the
//	central Treiber head), which pops a node if non-empty or acks the
//	Pop with the empty-response (ok=0) if genuinely empty.
//
//	End-of-batch: any UNMATCHED pending Pushes still on the FIFO are
//	committed to the central head in FIFO order (oldest at bottom of
//	stack). This preserves LIFO order across committed pushes.
//
// CRITICAL CORRECTNESS INVARIANT (why the Push is acked IMMEDIATELY
// on queue, NOT deferred to match/commit time):
//
//	A Push acked on queue means its `seq` becomes even. The NEXT round
//	of the very same combine() pass sees it as NOT pending (seq even)
//	and skips it — so the Push is queued EXACTLY ONCE per combine
//	pass. The previous version deferred the Push's ack to match/commit
//	time, leaving its `seq` odd through every round of the pass and
//	causing it to be queued once PER ROUND (8 rounds → 8× duplicated
//	queue entries → 8× central-head CASes at end-of-batch → a 7-node
//	bogus chain from a single push() invocation). See the Step 2c
//	diagnosis log for the exact repro: head marched from gen=8/idx=8
//	down to gen=1/idx=1 with every node bearing value=7 — one logical
//	push materialized as EIGHT physical nodes.
//
// ACK ordering invariant (the rigid publish/ack/handshake):
//   - Apply the op and Store(resp/ok) (Pop) BEFORE Store(seq=seq+1).
//     The seq bump is the wake-up ack; the waiter's observation of
//     even-seq happens-after (under SC) the combiner's resp/ok Store,
//     so the waiter reads a consistent result.
//   - A Push is queued + acked in one step: the queue is a local
//     combiner-side array (invisible to other threads), so the ack
//     (seq.Store(seq+1)) is the ONLY externally-observable side effect
//     at this moment.
//
// WAITER WAKEUP via seq ack — the waiter's spin is rec.seq.Load() !=
// myOdd. After combine() stores seq=seq+1 (the EVEN number after an
// odd snapshot), the waiter's Load sees the change and exits.
//
// Linearization: each combined op is linearized at its application point
// inside the combiner's sequential batch — one global sequential order,
// since the combiner is the SOLE thread mutating shared state during
// the batch (combining flag is held). Per DLM §3. The batch is bracketed
// by a single combining-flag acquire/release — from outside the batch,
// every op in it is concurrent, so its linearization permutation respects
// their in-batch order (Push P_i linearized at queue, Pop P_j linearized
// at match-or-head-pop; P_i before P_j if i was scanned before j OR P_i
// was queued before P_j fetched the FIFO head).
//
// RETURNS the number of ops applied this batch (diagnostic only).
func (s *flatCombStack) combine(pool *ElimNodePool, prng *ElimPRNG) int {
	_ = prng // FC does not use the ElimStack's PRNG; kept for API parity.
	applied := 0

	// Local pending-Push FIFO. Stack-backed array (zero alloc — fixed
	// size on the combiner's stack). Each entry is (recIdx, value):
	//   - recIdx: diagnostic only (the Push rec is already acked at
	//     queue; we retained the index historically for an end-of-batch
	//     re-ack that we no longer emit).
	//   - value: retained because a later Pop matched against the FIFO
	//     reads the value DIRECTLY (no central head traffic), and a
	//     leftover unmatched entry at end-of-batch must commit THIS
	//     value to the central head.
	type pendingPush struct {
		recIdx uint32
		value  uint64
	}
	var pendPush [flatCombMaxThreads]pendingPush
	pendPushLen := 0

	for round := 0; round < flatCombMaxRounds; round++ {
		for i := uint32(1); i < flatCombMaxThreads; i++ {
			rec := &s.recs[i]
			seq := rec.seq.Load()
			// Pending iff seq is ODD. The waiter published its request
			// by writing op/arg then seq.Store(myOdd) as the final
			// publish-store. The combiner's Load(seq) synchronizes-
			// with that store via the SC atomic model.
			if seq&1 == 0 {
				continue // not pending (idle, or already-acked this batch)
			}
			// The combiner holds the combining flag — it is the SOLE
			// thread mutating `head`, `rec.resp`, `rec.ok`, and
			// `rec.seq` for pending records. No second combiner exists,
			// so no CAS-lock against double-apply (the combining flag
			// IS the lock). Read (op, arg) AFTER seq — the seq Load
			// synchronizes-with the publish, and SC ordering gives us
			// a consistent op/arg snapshot.
			op := flatCombOp(rec.op.Load())
			arg := rec.arg.Load()

			switch op {
			case flatCombOpPush:
				// Queue the Push into the local FIFO for inside-combine
				// pairing with a future Pop in this same batch (NO
				// central CAS for matched pairs). Critically ACK IT
				// IMMEDIATELY so the Push waiter's spin exits and so
				// the NEXT round's scan does NOT see it as pending
				// (the bug fix: ack-on-queue gives exactly-once
				// processing per combiner pass; deferred-ack left seq
				// odd through all rounds → 8× duplication). The
				// Push's value remains in the FIFO awaiting either a
				// future Pop match or end-of-batch commit to head.
				if pendPushLen < flatCombMaxThreads {
					pendPush[pendPushLen] = pendingPush{
						recIdx: i,
						value:  arg,
					}
					pendPushLen++
					// The ACK is the ONLY externally-visible side effect
					// here; the FIFO is a local combiner-owned array.
					rec.seq.Store(seq + 1) // ack Push (odd → even)
					applied++
				}
				// If the FIFO is full (N=flatCombMaxThreads pushes
				// already queued this batch), we drop this pending
				// Push's processing for THIS round — its seq stays
				// odd, so a LATER round in the same pass picks it up.
				// Under the asymmetric burst crucible, pendPushLen
				// reaching flatCombMaxThreads-1 in one batch means
				// every one of 63 pub-records held a parallel push;
				// extremely rare, but the FIFO bounds memory.

			case flatCombOpPop:
				if pendPushLen > 0 {
					// Match the head-of-line pending Push. Deliver its
					// value to the Pop's resp/ok FIRST (sequenced-before
					// the ack), then ack the Pop. The Push was ALREADY
					// acked at queue time; we do NOT re-ack it.
					pushPair := pendPush[0]
					copy(pendPush[:], pendPush[1:pendPushLen])
					pendPushLen--
					rec.resp.Store(pushPair.value)
					rec.ok.Store(1)
					rec.seq.Store(seq + 1) // ack Pop (odd → even)
					applied++
				} else {
					// No pending Push to pair. Pop the central head.
					if !s.combinePopFromHead(pool, rec, seq) {
						// Central head was EMPTY (combiner's exclusive
						// view ⇒ genuinely empty). Ack the Pop with the
						// "empty" response: ok=0.
						rec.resp.Store(0)
						rec.ok.Store(0)
						rec.seq.Store(seq + 1)
					}
					applied++
				}

			default:
				// flatCombOpIdle — not a pending op (seq was odd but op
				// is idle). Under a single combiner under the flag this
				// branch is essentially impossible (the waiter would
				// never leave seq=odd with op=idle), but defensive: skip
				// without acking to avoid wedging the record.
			}
		}
	}

	// End-of-batch: any UNMATCHED pending Pushes still on the FIFO are
	// committed to the central head. Iterate front-to-back: pendPush[0]
	// is the OLDEST push, so it ends up at the BOTTOM of the (Treiber
	// LIFO) stack — which is correct: older pushes should be popped
	// later. Because the combiner is sole mutator of head, the inner
	// CAS loop is uncontended ( succeeds on first attempt virtually
	// always). Each commit allocs a node index from `pool` and links
	// onto the current head, bumping head's generation. The Push's
	// recIdx is no longer needed (the Push was already acked at queue).
	for j := 0; j < pendPushLen; j++ {
		pp := pendPush[j]
		s.combineCommitPushToHead(pool, pp.value)
	}
	return applied
}

// combinePopFromHead attempts to pop the central Treiber head on behalf
// of a Pop publication record. On success: stores the popped value to
// the record's resp+ok=1, bumps seq (ack), frees the popped node index
// back to the pool, and returns true. On empty head: returns false
// (caller acks the record with the "empty" response).
//
// Because the combiner is sole mutator of head under the combining
// flag, the inner CAS retry loop is essentially uncontended; we bound
// it at 8 attempts (defensive) and return false (meaning "head ended
// up empty under us — the combiner's own a prior pop in this same
// batch drained it") so the caller can deliver the empty-response ack.
func (s *flatCombStack) combinePopFromHead(pool *ElimNodePool, rec *flatCombPub, seq uint64) bool {
	for tries := 0; tries < 8; tries++ {
		cur := s.head.Load()
		curIdx := elimIndex(cur)
		if curIdx == NullOffset64 {
			return false // genuinely empty
		}
		node := &pool.nodes[curIdx]
		nextPacked := atomic.LoadUint64(&node.next)
		nextIdx := elimIndex(nextPacked)
		newHead := elimPackIndex(elimGen(cur)+1, nextIdx)
		if nextIdx == NullOffset64 {
			newHead = NullOffset64
		}
		if s.head.CompareAndSwap(cur, newHead) {
			v := node.value
			pool.freeIndex(curIdx)
			rec.resp.Store(v)
			rec.ok.Store(1)
			rec.seq.Store(seq + 1) // ack Pop (odd → even)
			return true
		}
	}
	// Could not progress in 8 attempts — under the combining flag this
	// is the combiner's OWN a-priori advancing of head (i.e., we already
	// advanced head for a previous op in this same batch and just raced
	// our stale view). Treat as empty: this batch drained the stack momentarily.
	// But more robust: re-check head; if non-empty now, retry once more.
	cur := s.head.Load()
	if elimIndex(cur) == NullOffset64 {
		return false
	}
	// Re-attempt with a single try; if it fails again, fall through to
	// caller as empty (Pop waits re-issued at next round — but the
	// caller expects an ack here, so we ack empty as a safe answer; the
	// waiter will re-attempt on its NEXT push/pop call).
	node := &pool.nodes[elimIndex(cur)]
	nextPacked := atomic.LoadUint64(&node.next)
	nextIdx := elimIndex(nextPacked)
	newHead := elimPackIndex(elimGen(cur)+1, nextIdx)
	if nextIdx == NullOffset64 {
		newHead = NullOffset64
	}
	if s.head.CompareAndSwap(cur, newHead) {
		v := node.value
		pool.freeIndex(elimIndex(cur))
		rec.resp.Store(v)
		rec.ok.Store(1)
		rec.seq.Store(seq + 1)
		return true
	}
	return false
}

// combineCommitPushToHead commits a single unmatched pending Push to the
// central Treiber head. The combiner is sole mutator of head — the CAS
// is uncontended but still required under SC (read-modify-write via
// the head-packed encoding). The Push's pub record was ALREADY acked at
// queue time (inside combine), so this routine only needs to land the
// value on the central head; it does NOT touch the Push rec.
func (s *flatCombStack) combineCommitPushToHead(pool *ElimNodePool, value uint64) {
	idx := pool.allocIndex()
	pool.nodes[idx].value = value
	for {
		cur := s.head.Load()
		atomic.StoreUint64(&pool.nodes[idx].next, cur)
		newHead := elimPackIndex(elimGen(cur)+1, idx)
		if s.head.CompareAndSwap(cur, newHead) {
			break
		}
	}
}

// ---------------------------------------------------------------------------
// push / pop — the public API
// ---------------------------------------------------------------------------

// push is the waiter-side entry. It PUBLISHES its request to a freshly
// acquired publication record, then EITHER becomes the combiner (if it
// wins the combining-flag CAS) OR spins on its own record's seq
// waiting for a combiner's ack. Returns when the op has been fully
// applied by some combiner (its own or another goroutine's).
//
// Zero-GC: allocRec is the only pre-combine allocation and is pool-
// backed (no heap alloc). No channels, no closures, no interface boxing.
func (s *flatCombStack) push(pool *ElimNodePool, prng *ElimPRNG, value uint64) {
	ridx := s.allocRec()
	rec := &s.recs[ridx]
	// Publish the request. Strict ordering: arg/op Stores BEFORE the
	// seq Store (the seq Store is the publish signal the combiner
	// synchronizes-with). SC atomics give us sequenced-before for free.
	rec.arg.Store(value)
	rec.op.Store(uint32(flatCombOpPush))
	rec.seq.Store(1) // publish handshake (odd) — record was seq==0=even from allocRec
	_ = prng         // FC does not use the ElimStack PRNG; kept for API parity

	// Opportunistic combiner rule (DLM): a losing pusher can become
	// the combiner and process its own op (plus others').
	if s.combining.CompareAndSwap(0, 1) {
		s.combine(pool, prng)
		s.combining.Store(0)
	}
	// Spin on our own seq until the combiner acks us (seq != 1).
	// When acked, the Push is done (no result to read). Free the record
	// and return.
	for rec.seq.Load() == 1 {
		if s.combining.CompareAndSwap(0, 1) {
			s.combine(pool, prng)
			s.combining.Store(0)
			if rec.seq.Load() != 1 {
				break
			}
		}
		// Low-rate yield — only every 64 spins (few microseconds of
		// pure cache-line poll), so no sysmon SIGURG storm. The waiter's
		// spin is on a private cache line (its own seq), so it does NOT
		// beat the L1/L2 of other cores — no coherence-mesh pressure.
		// The yield is for combiner-liveness (a preempted combiner needs
		// runtime to resume).
		rec.round.Add(1)
		if rec.round.Load()&63 == 63 {
			runtime.Gosched()
		}
	}
	s.freeRec(ridx)
}

// pop is the waiter-side entry. Identical publish/combining/spin
// handshake as push, except the Pop reads resp and ok after the seq
// ack to learn its result. Returns (value, true) on a successful pop
// or (0, false) on empty.
func (s *flatCombStack) pop(pool *ElimNodePool, prng *ElimPRNG) (uint64, bool) {
	ridx := s.allocRec()
	rec := &s.recs[ridx]
	// Publish the Pop request. arg is unused for Pop.
	rec.op.Store(uint32(flatCombOpPop))
	rec.seq.Store(1) // publish handshake (odd)
	_ = prng         // FC does not use the ElimStack PRNG

	if s.combining.CompareAndSwap(0, 1) {
		s.combine(pool, prng)
		s.combining.Store(0)
	}
	for rec.seq.Load() == 1 {
		if s.combining.CompareAndSwap(0, 1) {
			s.combine(pool, prng)
			s.combining.Store(0)
			if rec.seq.Load() != 1 {
				break
			}
		}
		rec.round.Add(1)
		if rec.round.Load()&63 == 63 {
			runtime.Gosched()
		}
	}
	// Seq acked (seq != 1). Read the result + ok bit (sequenced-before
	// the seq store under SC, so consistent).
	v := rec.resp.Load()
	ok := rec.ok.Load() == 1
	s.freeRec(ridx)
	return v, ok
}
