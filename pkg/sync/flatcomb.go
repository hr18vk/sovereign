// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"runtime"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// Flat-Combining Stack
// ---------------------------------------------------------------------------
//
// An elimination backoff array parks a losing push until a pop arrives in the
// same slot. With alternating producer and consumer bursts, matching pops tend
// to arrive only after parked pushes have timed out and retried the central
// CAS. Those retries synchronize on the same cache line and throughput falls
// as cores are added.
//
// Flat combining (Hendler, Lev, Moir and Shavit, PLDI 2010) delegates work to
// one combiner instead:
//   - A waiter publishes its operation in a 128-byte record and spins on that
//     record's sequence word.
//   - The goroutine that acquires the combining flag scans the records and
//     applies a batch sequentially. Complementary pushes and pops are paired
//     locally, without touching the central stack.
//   - Unmatched operations update the central Treiber stack only through the
//     combiner. Results are stored before the sequence word acknowledges them.
//
// The combining flag and all shared publication fields are accessed with
// sync/atomic. Go's sequentially consistent atomics provide the ordering used
// by the publication protocol:
//
//   - The waiter stores the argument and operation, then stores an odd
//     sequence value to publish the request.
//   - The combiner reads the sequence, operation and argument, applies the
//     request, stores any result, and increments the sequence to acknowledge
//     it.
//   - The waiter observes the even sequence, reads the result if present and
//     returns the record to its free-list.
//
// The central head uses ElimNodePool and the tagged index encoding from
// elimination.go. Its generation still advances on each linking CAS even
// though only the combiner mutates it; diagnostic walkers therefore see a
// monotonic generation when node indices are recycled. NullOffset64 marks an
// empty stack, and CacheLinePad isolates contended words.
//
// flatCombStack has the same push, pop and head interface as ElimStack, so the
// scaling gate and diagnostic walkers can exercise either implementation.
// ---------------------------------------------------------------------------

// flatCombMaxThreads bounds the publication records scanned by combine.
// Sixty-four slots cover the 32-core target with room for goroutine
// oversubscription without making a lightly loaded scan unnecessarily long.
const flatCombMaxThreads = 64

// flatCombOp identifies the operation in a publication record. Its zero
// value is idle; an odd sequence value, rather than the operation field,
// marks a record as pending.
type flatCombOp uint32

const (
	flatCombOpIdle flatCombOp = 0
	flatCombOpPush flatCombOp = 1
	flatCombOpPop  flatCombOp = 2
)

// flatCombPub holds one request and its result. TestFlatCombSlotSize checks
// its 128-byte layout: publication fields occupy the first cache line and
// response fields the second. Padding keeps adjacent waiters from sharing a
// line, so one waiter's sequence poll does not invalidate another's.
//
//	line 0: _padLead 40 + seq 8 + op 4 + _padOp 4 + arg 8 = 64
//	line 1: resp 8 + ok 4 + round 4 + _padTail 48             = 64
//	                                                           total 128
type flatCombPub struct {
	_padLead [40]byte
	seq      atomic.Uint64 // wait handshake: odd = pending, even = idle/acked
	op       atomic.Uint32 // flatCombOp (idle/push/pop)
	_padOp   [4]byte
	arg      atomic.Uint64 // Push value (set by waiter, read by combiner)
	resp     atomic.Uint64 // Pop result (set by combiner before seq ack, read by waiter after seq ack)
	ok       atomic.Uint32 // Pop ok bit: 1 = value present, 0 = empty
	round    atomic.Uint32 // waiter-side spin counter (drives low-rate Gosched)
	_padTail [48]byte
}

// ---------------------------------------------------------------------------
// flatCombStack — the Flat-Combining stack
// ---------------------------------------------------------------------------

// flatCombStack combines requests against one central Treiber head. Padding
// separates the head, combining flag and record free-list head from unrelated
// writes. Publication records are embedded in the stack, so constructing it
// allocates one heap object; recFreeNext and recFree recycle their indices
// without further allocation.
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

// Record free-list heads pack a generation in bits 31:16 and an index in bits
// 15:0. Index zero means empty. Every allocation or release CAS advances the
// generation, preventing ABA when an index is recycled.
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

// NewFlatCombStack constructs an empty stack. Publication records begin idle
// with even sequence values. Record indices 1 through flatCombMaxThreads-1 are
// linked into the free-list; index zero is reserved as its empty sentinel.
// The constructor allocates one flatCombStack object.
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
	// Go's zero initialization leaves records idle with even sequence values.
	return s
}

// allocRec pops a publication-record index from the tagged Treiber free-list
// without allocating. It returns an index in [1, flatCombMaxThreads), which
// the caller releases with freeRec after acknowledgement. The acquired record
// is cleared before reuse so no request or response from its previous owner
// remains visible. If all records are occupied, it yields and retries.
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
			// Zero the acquired record before returning so the caller
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

// freeRec pushes a publication-record index back onto the tagged free-list
// after its operation has been acknowledged. The waiter has left its spin,
// and the acknowledging combiner has advanced beyond this record in its scan.
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

// flatCombMaxRounds is the number of record scans a combiner performs before
// releasing the flag. Repeated scans amortize acquisition over requests that
// arrive during a batch. Eight rounds balance that reuse against the latency
// of requests waiting for another combiner.
const flatCombMaxRounds = 8

// combine applies published requests while holding the combining flag. It
// returns the number applied, for diagnostics.
//
// A pending push enters a local FIFO and is acknowledged immediately by
// changing its sequence from odd to even. Queueing is its linearization
// point. A pop first consumes the oldest queued push, avoiding the central
// stack; otherwise it pops the central head or reports an empty stack.
// Unmatched pushes are linked onto the central head in FIFO order at the end
// of the batch, leaving the oldest at the bottom and preserving LIFO order.
//
// Immediate push acknowledgement is required because subsequent rounds skip
// even sequences. Deferring it until a match or central-head commit would
// leave the request pending and queue the same push once per round.
//
// For every pop, the combiner stores resp and ok before incrementing seq.
// Sequential consistency ensures a waiter that observes the even sequence
// also observes the result. The local FIFO has no externally visible state;
// acknowledging a queued push is its only visible effect at that point.
//
// Holding the combining flag makes the combiner the sole mutator of shared
// stack state. Operations linearize in their application order within the
// batch, which is consistent with their overlapping real-time intervals.
func (s *flatCombStack) combine(pool *ElimNodePool, prng *ElimPRNG) int {
	_ = prng // FC does not use the ElimStack's PRNG; kept for API parity.
	applied := 0

	// The pending-push FIFO is a fixed-size array on the combiner's stack.
	// recIdx records the originating slot for diagnostics. value supplies a
	// matched pop or, if unmatched, the eventual central-head commit.
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
			// An odd sequence marks a pending request. The waiter stored
			// op and arg before publishing seq, so this load orders the
			// combiner's subsequent reads after those stores.
			if seq&1 == 0 {
				continue // not pending (idle, or already-acked this batch)
			}
			// The combining flag excludes other combiners from head and
			// response mutation. Read op and arg after seq so their values
			// belong to the published request.
			op := flatCombOp(rec.op.Load())
			arg := rec.arg.Load()

			switch op {
			case flatCombOpPush:
				// Queue the push for local pairing and acknowledge it now.
				// This releases its waiter and prevents later rounds from
				// queueing it again. Its value remains in the FIFO until a
				// pop matches it or the batch commits it to head.
				if pendPushLen < flatCombMaxThreads {
					pendPush[pendPushLen] = pendingPush{
						recIdx: i,
						value:  arg,
					}
					pendPushLen++
					// The ack is the only externally-visible side effect
					// here; the FIFO is a local combiner-owned array.
					rec.seq.Store(seq + 1) // ack Push (odd → even)
					applied++
				}
				// A full FIFO leaves this push pending for a later round.
				// At most flatCombMaxThreads-1 records can be published,
				// so the fixed array bounds the combiner's stack use.

			case flatCombOpPop:
				if pendPushLen > 0 {
					// Pair with the oldest pending push. Store its value
					// and presence bit before acknowledging the pop; the push
					// was already acknowledged when it entered the FIFO.
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
						// The central head is empty in the combiner's
						// exclusive view. Acknowledge an empty result.
						rec.resp.Store(0)
						rec.ok.Store(0)
						rec.seq.Store(seq + 1)
					}
					applied++
				}

			default:
				// An idle operation is not a valid published request.
				// Leave it unacknowledged rather than acknowledging a
				// result that was never computed.
			}
		}
	}

	// Commit unmatched pushes from oldest to newest so the oldest ends up
	// at the bottom of the LIFO stack. Only the combiner mutates head. Each
	// commit takes a node from pool and advances the packed generation.
	for j := 0; j < pendPushLen; j++ {
		pp := pendPush[j]
		s.combineCommitPushToHead(pool, pp.value)
	}
	return applied
}

// combinePopFromHead pops the central head for a publication record. On
// success it returns the node to the pool, stores the value and presence bit,
// acknowledges the sequence and returns true. It returns false when the head
// is empty or its bounded CAS attempts do not succeed; the caller then
// acknowledges an empty result.
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
	// The bounded loop did not install a new head. Reload once and make a
	// final attempt if the stack is still non-empty.
	cur := s.head.Load()
	if elimIndex(cur) == NullOffset64 {
		return false
	}
	// A failed final CAS is reported as empty to the caller.
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

// combineCommitPushToHead links one unmatched value onto the central Treiber
// head. Its publication record was acknowledged when queued, so only the node
// allocation and packed-head update remain.
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

// push publishes a request and tries to become the combiner. If another
// goroutine holds the flag, push retries acquisition while polling its own
// sequence word. It returns after a combiner queues the value and releases the
// publication record without allocating on the hot path.
func (s *flatCombStack) push(pool *ElimNodePool, prng *ElimPRNG, value uint64) {
	ridx := s.allocRec()
	rec := &s.recs[ridx]
	// Store arg and op before seq; the final odd-seq store publishes both.
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
	// Wait for the queue acknowledgement, retrying the combining flag when
	// it is available, then release the record.
	for rec.seq.Load() == 1 {
		if s.combining.CompareAndSwap(0, 1) {
			s.combine(pool, prng)
			s.combining.Store(0)
			if rec.seq.Load() != 1 {
				break
			}
		}
		// Polling touches only this record's cache line. Yield every 64
		// spins so a preempted combiner can resume without adding frequent
		// scheduler work to the uncontended case.
		rec.round.Add(1)
		if rec.round.Load()&63 == 63 {
			runtime.Gosched()
		}
	}
	s.freeRec(ridx)
}

// pop uses the same publication and combining handshake as push. After the
// sequence acknowledgement, it reads resp and ok. It returns (value, true) for
// a value and (0, false) when the stack is empty.
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
	// The acknowledged sequence orders these result reads after the
	// combiner's resp and ok stores.
	v := rec.resp.Load()
	ok := rec.ok.Load() == 1
	s.freeRec(ridx)
	return v, ok
}
