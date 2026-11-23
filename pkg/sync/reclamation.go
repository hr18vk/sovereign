// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

const (
	InactiveEpoch = ^uint64(0)
	HazardSlots   = 4
)

// arenaRetiredFreelistShardCount distributes each epoch's retired list across
// 256 Treiber stacks to reduce contention on their compare-and-swap heads. The
// power-of-two count permits mask-based routing and matches the engine's shard
// count. Retirement selects one stack per call; epoch advancement still drains
// every stack in the safe epoch, preserving the three-epoch grace interval.
const arenaRetiredFreelistShardCount = 256

// OffHeapNode simulates a pointer to an off-heap HAMT node.
type OffHeapNode struct {
	Data uint64
}

// EBRManager manages epoch-based reclamation with hazard pointers.
//
// AdvanceEpoch updates globalEpoch while Register updates head. Padding places
// these contended atomics on separate cache lines so writes to one do not
// invalidate the other. Retired lists and pools occupy the following lines.
type EBRManager struct {
	_globalEpochPad0 CacheLinePad
	globalEpoch      atomic.Uint64
	_globalEpochPad1 CacheLinePad

	_headPad0 CacheLinePad
	head      atomic.Pointer[Participant]
	_headPad1 CacheLinePad

	retired [3][arenaRetiredFreelistShardCount]RetiredList
	// retiredRoute selects a retired-list shard once per Retire or RetireBlock
	// call, outside the compare-and-swap retry loop. AdvanceEpoch drains every
	// shard and needs no corresponding pop counter. Padding keeps these writes
	// off the cache lines used by globalEpoch and head.
	_retiredRoutePad0 CacheLinePad
	retiredRoute      atomic.Uint64
	_retiredRoutePad1 CacheLinePad
	pool              sync.Pool
	retiredPool       sync.Pool

	// closing is set once by DeltaCRDTEngine.Close before quiescence and arena
	// teardown. Join, Get, and InsertLocal reject later arena access, and
	// perhapsAdvanceEpoch stops reclamation. Its cache line is separate from the
	// atomics that continue to be written during operation.
	_closingPad0 CacheLinePad
	closing      atomic.Bool
	_closingPad1 CacheLinePad
}

func NewEBRManager() *EBRManager {
	m := &EBRManager{}
	m.pool.New = func() any {
		return m.Register()
	}
	m.retiredPool.New = func() any {
		return &RetiredNode{}
	}
	return m
}

func (m *EBRManager) Acquire() *Participant {
	return m.pool.Get().(*Participant)
}

func (m *EBRManager) Release(p *Participant) {
	p.Exit()
	m.pool.Put(p)
}

type CacheLinePad struct {
	_ [64]byte
}

type Participant struct {
	_       CacheLinePad
	active  atomic.Bool
	_       CacheLinePad
	epoch   atomic.Uint64
	_       CacheLinePad
	hazards [HazardSlots]atomic.Pointer[byte]
	_       CacheLinePad
	next    *Participant
}

func (m *EBRManager) Register() *Participant {
	p := &Participant{}
	for {
		head := m.head.Load()
		p.next = head
		if m.head.CompareAndSwap(head, p) {
			break
		}
	}
	return p
}

func (p *Participant) Enter(m *EBRManager) {
	p.ClearHazards()
	p.active.Store(true)
	p.epoch.Store(m.globalEpoch.Load())
}

func (p *Participant) Exit() {
	p.ClearHazards()
	p.epoch.Store(InactiveEpoch)
	p.active.Store(false)
}

func (p *Participant) DetachAndProtect(slot int, ptr unsafe.Pointer) bool {
	if slot < 0 || slot >= HazardSlots {
		return false
	}
	p.hazards[slot].Store((*byte)(ptr))
	p.epoch.Store(InactiveEpoch)
	p.active.Store(false)
	return true
}

func (m *EBRManager) DetachAndProtect(p *Participant, slot int, ptr unsafe.Pointer) bool {
	if p == nil {
		return false
	}
	return p.DetachAndProtect(slot, ptr)
}

func (p *Participant) ClearHazard(slot int) bool {
	if slot < 0 || slot >= HazardSlots {
		return false
	}
	p.hazards[slot].Store(nil)
	return true
}

func (p *Participant) ClearHazards() {
	for i := 0; i < HazardSlots; i++ {
		p.hazards[i].Store(nil)
	}
}

type RetiredList struct {
	head atomic.Pointer[RetiredNode]
}

type RetiredNode struct {
	Type   uint8 // 0: HAMT, 1: ArenaNode, 2: ArenaVar
	Ptr    unsafe.Pointer
	Arena  *HamtArena
	Offset uint64
	next   *RetiredNode
}

func (l *RetiredList) PushHAMT(ptr unsafe.Pointer, pool *sync.Pool) {
	n := pool.Get().(*RetiredNode)
	n.Type = 0
	n.Ptr = ptr
	for {
		head := l.head.Load()
		n.next = head
		if l.head.CompareAndSwap(head, n) {
			break
		}
	}
}

func (l *RetiredList) PushBlock(arena *HamtArena, offset uint64, isNode bool, pool *sync.Pool) {
	n := pool.Get().(*RetiredNode)
	if isNode {
		n.Type = 1
	} else {
		n.Type = 2
	}
	n.Arena = arena
	n.Offset = offset
	for {
		head := l.head.Load()
		n.next = head
		if l.head.CompareAndSwap(head, n) {
			break
		}
	}
}

// routeRetiredShard selects one retired-list stack for a Retire or RetireBlock
// call. Incrementing the route counter here, outside PushBlock or PushHAMT,
// keeps it out of their compare-and-swap retry loops. AdvanceEpoch does not use
// this router because it must drain every stack in the safe epoch.
func (m *EBRManager) routeRetiredShard() int {
	n := arenaRetiredFreelistShardCount
	idx := m.retiredRoute.Add(1)
	if n&(n-1) == 0 {
		return int(idx-1) & (n - 1)
	}
	return int((idx - 1) % uint64(n))
}

func (m *EBRManager) Retire(ptr unsafe.Pointer) {
	e := m.globalEpoch.Load()
	idx := e % 3
	// Select the epoch before choosing its shard. PushHAMT retries only on that
	// shard's head, so routeRetiredShard remains outside the retry loop.
	shard := m.routeRetiredShard()
	m.retired[idx][shard].PushHAMT(ptr, &m.retiredPool)
}

func (m *EBRManager) RetireBlock(arena *HamtArena, offset uint64, isNode bool) {
	e := m.globalEpoch.Load()
	idx := e % 3
	// Compute the epoch index before advancing the route counter. The block then
	// enters exactly one shard of that epoch, and PushBlock retries on that head.
	shard := m.routeRetiredShard()
	m.retired[idx][shard].PushBlock(arena, offset, isNode, &m.retiredPool)
}

func (m *EBRManager) AdvanceEpoch() {
	currentEpoch := m.globalEpoch.Load()
	canAdvance := true
	curr := m.head.Load()
	for curr != nil {
		if curr.active.Load() {
			pe := curr.epoch.Load()
			if pe < currentEpoch {
				canAdvance = false
				break
			}
		}
		curr = curr.next
	}

	if canAdvance {
		if m.globalEpoch.CompareAndSwap(currentEpoch, currentEpoch+1) {
			// Detach every head in the safe epoch before walking any of them.
			// DecRef during the walk can recursively retire more blocks. If the
			// epoch advances concurrently, those blocks can select this same ring
			// slot. They must encounter fresh heads and wait for a later drain;
			// swapping and walking one shard at a time could instead pick up a new
			// retirement before it has received the full grace interval.
			safeIdx := (currentEpoch + 2) % 3
			var heads [arenaRetiredFreelistShardCount]*RetiredNode
			hasWork := false
			for shard := 0; shard < arenaRetiredFreelistShardCount; shard++ {
				heads[shard] = m.retired[safeIdx][shard].head.Swap(nil)
				if heads[shard] != nil {
					hasWork = true
				}
			}
			if !hasWork {
				for shard := 0; shard < arenaRetiredFreelistShardCount; shard++ {
					m.freeRetiredList(heads[shard])
				}
				return
			}
			var hazardSnapshot [64]unsafe.Pointer
			hazards := m.snapshotHazards(&hazardSnapshot)
			for shard := 0; shard < arenaRetiredFreelistShardCount; shard++ {
				if heads[shard] != nil {
					m.freeRetiredListWithHazards(heads[shard], hazards)
				}
			}
		}
	}
}

// SetClosing marks the start of engine teardown. DeltaCRDTEngine.Close calls it
// before Quiesce and arena.Free. Subsequent Join, Get, and InsertLocal calls
// reject arena access, and perhapsAdvanceEpoch stops reclamation. Operational
// reads incur one atomic load through Closing.
func (m *EBRManager) SetClosing() { m.closing.Store(true) }

// Closing reports whether engine teardown has begun. Join, Get, InsertLocal,
// and perhapsAdvanceEpoch read it. The flag is written only once by Close, so
// ordinary reads do not contend with repeated writes.
func (m *EBRManager) Closing() bool { return m.closing.Load() }

// Quiesce waits until no EBR participant is active. Close calls it after
// SetClosing and the persist drain, before arena.Free. Since AdvanceEpoch runs
// from Join and InsertLocal and stops after closing is set, an inactive
// participant list means neither arena access nor reclamation remains in
// flight.
//
// The caller must stop submitting operations before calling Quiesce. SetClosing
// rejects new operations; Quiesce only waits for existing ones. An active
// participant that is never released keeps Quiesce waiting rather than allowing
// referenced arena memory to be unmapped. Quiesce adds no work to normal
// operations.
func (m *EBRManager) Quiesce() {
	for {
		quiescent := true
		for p := m.head.Load(); p != nil; p = p.next {
			if p.active.Load() {
				quiescent = false
				break
			}
		}
		if quiescent {
			return
		}
		runtime.Gosched()
	}
}

// freeRetiredList reclaims entries whose grace period has elapsed. For a HAMT,
// DecRef first retires the root tree, then freeHAMTWrapper clears and retires
// the 32-byte wrapper. Those recursive retirements enter the current epoch and
// are reclaimed by a later AdvanceEpoch, not by the walk already in progress.
//
// A HAMT or arena block protected by a hazard pointer is requeued unchanged for
// another epoch. The protecting reader can continue to follow it until a later
// reclamation attempt finds the hazard clear.
//
// ebrIgnoreHazardsFault is false in production. Tests can set it to bypass
// hazard protection as a negative control for the reclamation race checks.
var ebrIgnoreHazardsFault atomic.Bool

func (m *EBRManager) snapshotHazards(buf *[64]unsafe.Pointer) []unsafe.Pointer {
	hazardCount := 0
	for curr := m.head.Load(); curr != nil; curr = curr.next {
		for i := 0; i < HazardSlots; i++ {
			hp := unsafe.Pointer(curr.hazards[i].Load())
			if hp != nil && hazardCount < len(buf) {
				buf[hazardCount] = hp
				hazardCount++
			}
		}
	}
	return buf[:hazardCount]
}

func (m *EBRManager) freeRetiredList(head *RetiredNode) {
	var hazardSnapshot [64]unsafe.Pointer
	hazards := m.snapshotHazards(&hazardSnapshot)
	if head == nil {
		return
	}
	m.freeRetiredListWithHazards(head, hazards)
}

func (m *EBRManager) freeRetiredListWithHazards(head *RetiredNode, hazards []unsafe.Pointer) {
	// AdvanceEpoch takes one hazard snapshot for all 256 detached lists instead
	// of scanning every participant for every retired node. The stack buffer holds
	// 64 pointers. When it is full, isProtected performs a complete live scan for
	// each candidate so additional hazards are not missed and no heap allocation
	// is needed.
	isProtected := func(ptr unsafe.Pointer) bool {
		if ptr == nil || ebrIgnoreHazardsFault.Load() {
			return false
		}
		for i := 0; i < len(hazards); i++ {
			if hazards[i] == ptr {
				return true
			}
		}
		if len(hazards) == 64 {
			return m.isHazardProtected(ptr)
		}
		return false
	}

	for head != nil {
		next := head.next

		if head.Type == 0 {
			if isProtected(head.Ptr) {
				// Leave the wrapper and its arena pointer intact for the protecting
				// reader, and retry reclamation in another epoch.
				m.Retire(head.Ptr)
			} else {
				// DecRef the root through the wrapper's valid arena pointer. Child
				// blocks enter the current epoch, not the oldest list being drained.
				h := (*HAMT)(head.Ptr)
				arenaLocal := h.arena
				root := h.root
				arenaLocal.DecRef(root)

				// Clear and retire the wrapper as well. Its offset returns through
				// RetireBlock and is recycled by pushFreeVar after another grace period.
				arenaLocal.freeHAMTWrapper(h)
			}
			head.Ptr = nil
		} else {
			ptr := unsafe.Pointer(head.Arena.base + uintptr(head.Offset))
			if isProtected(ptr) {
				// Re-queue block in current epoch.
				m.RetireBlock(head.Arena, head.Offset, head.Type == 1)
			} else {
				if head.Type == 1 {
					head.Arena.pushFreeNode(head.Offset)
				} else {
					head.Arena.pushFreeVar(head.Offset)
				}
			}
			head.Arena = nil
		}

		head.next = nil
		m.retiredPool.Put(head)
		head = next
	}
}

func (m *EBRManager) isHazardProtected(ptr unsafe.Pointer) bool {
	if ptr == nil {
		return false
	}
	curr := m.head.Load()
	for curr != nil {
		for i := 0; i < HazardSlots; i++ {
			if unsafe.Pointer(curr.hazards[i].Load()) == ptr {
				return true
			}
		}
		curr = curr.next
	}
	return false
}
