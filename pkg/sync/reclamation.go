package sync

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

const (
	InactiveEpoch = ^uint64(0)
	HazardSlots   = 4
)

// arenaRetiredFreelistShardCount is the number of Treiber free-list shards the
// EBRManager dedicates to EACH of the 3 epoch retired lists. Phase 2.5a.1's
// pprof measured m.retired[idx].PushBlock at 16.49% cum @32c (PHASE_25B1_REPORT/
// PHASE_25C_REPORT L647/L703) — the EBR retire path CAS concentrate. Phase
// 2.5d S1 re-confirmed 11.20% cum @32c at the 2.5c.2.1 production gear (above
// the 10% gate). 2.5d closes it by mirroring the 2.5a/2.5a.1 256-way sharding
// pattern: each of the 3 epoch lists becomes [256]RetiredList, the route
// counter is bumped OUTSIDE the CAS retry loop, and the 3-epoch ring buffer
// (idx := e%3) and grace invariant (safeIdx = (currentEpoch+2)%3) are
// PRESERVED byte-for-byte — only the per-epoch LIST HEAD is sharded to 256.
// Power-of-two (256) keeps the route a clean & (N-1) bitmask, matches the
// engine shard count, and matches the proved-good 2.5a/2.5a.1 cardinality.
// The same const-not-setter discipline applies.
const arenaRetiredFreelistShardCount = 256

// OffHeapNode simulates a pointer to an off-heap HAMT node.
type OffHeapNode struct {
	Data uint64
}

// EBRManager manages epoch-based reclamation with hazard pointers.
//
// STAGE 4 — CACHE COHERENCE & FALSE SHARING ELIMINATION (AWS Graviton Crucible):
//
// globalEpoch is CAS'd by AdvanceEpoch; head is CAS'd by Register.
// Both are hot atomics accessed by different goroutines concurrently.
// They are now isolated onto separate cache lines to prevent HITM storms.
//
// Layout (post-padding):
//
//	Cache Line 0: globalEpoch (CAS'd by AdvanceEpoch)
//	Cache Line 1: head (CAS'd by Register)
//	Cache Line 2+: retired lists, pools (less hot)
type EBRManager struct {
	_globalEpochPad0 CacheLinePad
	globalEpoch      atomic.Uint64
	_globalEpochPad1 CacheLinePad

	_headPad0 CacheLinePad
	head      atomic.Pointer[Participant]
	_headPad1 CacheLinePad

	retired     [3][arenaRetiredFreelistShardCount]RetiredList
	// retiredRoute is the per-call routing counter for the EBR retire path
	// (RetireBlock / Retire). Advanced by 1 ONCE per call — OUTSIDE the CAS
	// retry loop — and masked by (arenaRetiredFreelistShardCount-1). Routed
	// per-call (NOT per-CAS-retry) so the routing counter increment never
	// lands in the hot CAS frame. The pop-side (AdvanceEpoch drain) does NOT
	// route — it walks ALL 256 shards of the safe epoch unconditionally, so
	// no symmetric pop counter is needed. CacheLinePad-isolated from the
	// other EBR atomics (globalEpoch, head) so the routing counter's writes
	// do not false-share with the CAS surfaces those hold.
	_retiredRoutePad0 CacheLinePad
	retiredRoute      atomic.Uint64
	_retiredRoutePad1 CacheLinePad
	pool              sync.Pool
	retiredPool       sync.Pool
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

// routeRetiredShard picks the EBR retired-list shard this RetireBlock / Retire
// call should push to. It is the byte-faithful sibling of the routeVarFreelist
// routers in hamt_arena.go: routed per-CALL (NOT per-CAS-retry) so the counter
// increment can never land in the hot CAS frame. The route counter is bumped
// ONCE here, masked by (arenaRetiredFreelistShardCount-1) — a clean power-of-
// two bitmask. The AdvanceEpoch drain does NOT route — it walks ALL 256 shards
// of the safe epoch unconditionally (the grace invariant holds PER SHARD now;
// the drain fans out the 3-epoch ring's safe bucket to 256 heads).
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
	// R1d: route this Retire push to ONE retired-list shard for the WHOLE call.
	// Computed ONCE, OUTSIDE the CAS retry loop (PushHAMT's own CAS retry is
	// byte-identical in shape to the pre-R1 body, just over a per-shard head).
	// The 3-epoch routing (idx := e % 3) is the GRACE invariant — preserved
	// byte-for-byte; only the per-epoch LIST HEAD is sharded to 256.
	shard := m.routeRetiredShard()
	m.retired[idx][shard].PushHAMT(ptr, &m.retiredPool)
}

func (m *EBRManager) RetireBlock(arena *HamtArena, offset uint64, isNode bool) {
	e := m.globalEpoch.Load()
	idx := e % 3
	// R1d: route this RetireBlock push to ONE retired-list shard. The ordering
	// is load-bearing: idx := e%3 (the 3-epoch routing — the GRACE invariant)
	// MUST be computed BEFORE the shard route (see R3a C2.4 — route sits AFTER
	// idx := e % 3). The shard route is OUTSIDE the CAS retry loop (PushBlock's
	// own CAS retry is byte-identical in shape to the pre-R1 body, just over a
	// per-shard head).
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
			// R1d: the safe epoch's retired ring is now 256-way sharded. The
			// 3-epoch grace invariant is PRESERVED — safeIdx = (currentEpoch+2) % 3
			// unchanged; only the head drain fans out to 256 shards.
			//
			// CORRECTNESS — two-phase Swap-then-walk: the drain MUST swap-Nil
			// ALL 256 shards BEFORE walking any shard's list. The semantic gap:
			// freeRetiredList (walk phase) recursively calls RetireBlock via
			// DecRef cascades. If globalEpoch advances to (currentEpoch+2)
			// mid-walk, those recursive RetireBlock calls route onto the very
			// bucket I'm draining (safeIdx = (currentEpoch+2)%3). With a single
			// shard-at-a-time Swap-during-walk those fresh retires would land on
			// an UN-SWAPPED shard that my own drain loop later reaches —
			// stealing them into the current drain with 0-epoch grace (a UAF
			// when their wrappers are still in use). Two-phase Swap-then-walk
			// makes my walk operate over an SNAPSHOT of shard heads captured
			// BEFORE any recursive RetireBlock lands on safeIdx: pushes after
			// the snapshot phase append onto a FRESH head on each shard and are
			// deferred to a future epoch's drain (full 2-epoch grace preserved).
			// This mirrors the original single-Swap-then-walk invariant the
			// pre-R1 AdvanceEpoch relied on; the shard fan-out adds 256 Swaps
			// but preserves the grace contract.
			safeIdx := (currentEpoch + 2) % 3
			var heads [arenaRetiredFreelistShardCount]*RetiredNode
			for shard := 0; shard < arenaRetiredFreelistShardCount; shard++ {
				heads[shard] = m.retired[safeIdx][shard].head.Swap(nil)
			}
			for shard := 0; shard < arenaRetiredFreelistShardCount; shard++ {
				m.freeRetiredList(heads[shard])
			}
		}
	}
}

// freeRetiredList physically reclaims every retired node whose EBR grace
// period has elapsed (the global epoch has advanced by 2 since retirement,
// proving zero lingering readers).
//
// STAGE 1 FIX (Zero-GC Microscope):
//
//	Before this fix, Type 0 (HAMT) nodes were DecRef'd recursively but
//	the 32-byte HAMT wrapper struct itself was NEVER returned to the
//	slab free-list. With the wrapper now allocated from the off-heap
//	HamtArena (allocHAMTWrapper), that omission would silently leak 32
//	bytes per Set/Delete and eventually trigger the Linux OOM killer
//	without ever tripping the Go GC. We sequence the teardown as:
//
//	  1. DecRef h.root  — recursively frees the HamtNode tree and any
//	     leaf-owned strings / CRDT entry arrays via EBR RetireBlock.
//	     The HAMT wrapper is STILL VALID while this runs.
//	  2. freeHAMTWrapper — zeros the wrapper (defensively masking the
//	     GC-invisible `arena *HamtArena` field) and routes the
//	     32-byte slot back through EBR RetireBlock for ABA-safe
//	     physical recycling into the slab free-list.
//
//	Both calls defer their physical pushes behind EBR; nothing is
//	physically freed during this function — only during a future
//	AdvanceEpoch's recursive freeRetiredList. Two recursions may push
//	new RetiredNodes onto the CURRENT epoch list; this is safe because
//	we are iterating the OLDEST epoch list (offset +2 mod 3) — the two
//	are disjoint per EBR's three-epoch ring buffer.
//
// HAZARD-PROTECTED HAMT REQUEUE:
//
//	If the wrapper is currently protected by a hazard pointer slot
//	(some reader is still traversing its root tree), the HAMT cannot
//	be safely torn down this epoch. The RetiredNode is re-queued via
//	Retire, where it sits in the current epoch's list waiting for the
//	NEXT epoch to attempt reclamation. The wrapper struct is left
//	untouched in this branch (NOT zeroed, NOT freed) so the protecting
//	reader can still follow its root pointer. The next AttemptEpoch
//	will run this branch again; if the hazard clears, the wrapper is
//	fully torn down then.
func (m *EBRManager) freeRetiredList(head *RetiredNode) {
	// STAGE 2 FIX (O(N²) → O(N) Hazard Scan):
	//   The original implementation called isHazardProtected(ptr) for
	//   EVERY retired node, and each call iterated ALL participants ×
	//   ALL hazard slots. When the retired list grew large (because
	//   epochs couldn't advance while goroutines were active), this
	//   became O(N × P × H) — a catastrophic quadratic blowup that
	//   caused livelock under high concurrency.
	//
	//   The fix: snapshot ALL active hazard pointers into a
	//   stack-allocated array ONCE at the start of freeRetiredList.
	//   Each retired node is then checked against this snapshot in
	//   O(1) via a linear scan of the (typically tiny) hazard array.
	//   This transforms the complexity from O(N × P × H) to
	//   O(P × H + N × H_snapshot) where H_snapshot is the number of
	//   non-nil hazard pointers (typically 0-4 in practice).
	//
	//   The snapshot is safe because EBR's epoch guarantee ensures
	//   that no new hazard pointers can be set on the OLDEST epoch's
	//   retired nodes — any reader that started after the epoch
	//   advanced is pinned to a LATER epoch and cannot reference
	//   these nodes.
	var hazardSnapshot [64]unsafe.Pointer
	hazardCount := 0
	curr := m.head.Load()
	for curr != nil {
		for i := 0; i < HazardSlots; i++ {
			hp := unsafe.Pointer(curr.hazards[i].Load())
			if hp != nil && hazardCount < len(hazardSnapshot) {
				hazardSnapshot[hazardCount] = hp
				hazardCount++
			}
		}
		curr = curr.next
	}

	isProtected := func(ptr unsafe.Pointer) bool {
		if ptr == nil {
			return false
		}
		for i := 0; i < hazardCount; i++ {
			if hazardSnapshot[i] == ptr {
				return true
			}
		}
		return false
	}

	for head != nil {
		next := head.next

		if head.Type == 0 {
			if isProtected(head.Ptr) {
				// Re-queue this HAMT for another epoch's attempt. The
				// wrapper is still alive — its `arena` field is intact
				// and protected from overwrite by the hazard pointer.
				m.Retire(head.Ptr)
			} else {
				// Hazard-free lifetime window — safe to dismantle.
				// 1. Recursively decrement the root subtree via the
				//    wrapper's still-valid arena pointer. Each child
				//    RetireBlock lands in the CURRENT epoch list
				//    (different from this iteration's OLDEST list).
				h := (*HAMT)(head.Ptr)
				arenaLocal := h.arena
				root := h.root
				arenaLocal.DecRef(root)

				// 2. Recycle the 32-byte HAMT wrapper itself. This
				//    zeros the struct (clearing the GC-invisible
				//    `arena *HamtArena` field) and push the offset
				//    through RetireBlock → future pushFreeVar.
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
