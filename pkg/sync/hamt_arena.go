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
	"syscall"
	"unsafe"
)

// NodePtr is a raw off-heap pointer. Using uintptr ensures the Go GC
// does not attempt to scan this memory, achieving true Zero-GC.
type NodePtr uintptr

// NullOffset64 is the sentinel value indicating an empty Treiber free-list.
// Using 0 as sentinel: offset 0 is never allocated (bump starts at nodeSize).
const NullOffset64 uint64 = 0

// HamtNode represents an off-heap HAMT node.
// It includes an atomic reference count for deterministic reclamation.
type HamtNode struct {
	refCount atomic.Int32
	bitmap   uint32
	// padding to align 64-bit pointers
	_ uint32

	// Offsets or pointers to children/entries arrays in the arena
	childrenPtr NodePtr
	entriesPtr  NodePtr

	// Reserved for cached Merkle branch hash. Currently unused; MerkleRoot()
	// sorts leaves across the tree.
	merkleHash [32]byte

	// Reserved intrusive pointer for the lock-free free-list (offset 64).
	// In the current free-list implementation, pushFreeNode stores the Treiber next-offset in
	// bytes 0..7 of the dead node (offset 0) instead of this field.
	nextFree NodePtr
}

const nodeSize = unsafe.Sizeof(HamtNode{})

// ---------------------------------------------------------------------------
// ADR 9: Segregated Slab Allocator Constants
// ---------------------------------------------------------------------------

const (
	// numVarClasses is the number of power-of-2 size classes for variable
	// allocations. Classes cover [16, 32, 64, ..., 524288] bytes.
	// Index 0 is reserved for 72-byte HamtNode (dedicated class).
	numVarClasses = 16

	// varAllocHeaderSize is the overhead prepended to every variable
	// allocation. Stores the uint64 size class index for O(1) free routing.
	varAllocHeaderSize = 8

	// minVarAllocSize is the smallest variable allocation we service.
	// Below this, there is no meaningful data and we return null.
	minVarAllocSize = 16

	// Total number of slab classes: class 0 (HamtNode) + 16 var classes.
	numSizeClasses = 1 + numVarClasses
)

// slabFreeHead is a cache-line-padded atomic Treiber stack head for one size class.
type slabFreeHead struct {
	_    CacheLinePad
	head atomic.Uint64
	_    CacheLinePad
}

// arenaNodeFreelistShardCount spreads recycled HamtNode allocations across
// independent, cache-line-padded Treiber heads. This prevents one shared head
// from serializing path-copying allocations on every core. The power-of-two
// count permits mask-based routing and matches the engine's root shard count.
// It is fixed because the arena has no re-rooting path that could coordinate a
// runtime change.
const arenaNodeFreelistShardCount = 256

// arenaVarFreelistShardCount applies the same contention avoidance to each
// variable-size class. Allocation and reclamation use independent routing
// counters, advanced once per call rather than on each CAS retry.
const arenaVarFreelistShardCount = 256

// arenaVarFreelistSweep bounds the shards allocVar probes before using the
// bump allocator. Since pushes and pops use separate routing counters, the
// first shard can be empty while nearby shards hold blocks of the right class.
// Probing 128 shards under one EBR pin reuses those blocks without an
// unbounded scan. The power-of-two bound also wraps cleanly in mask-based
// routing.
const arenaVarFreelistSweep = 128

// hamtNodeFreelistShards stores independent Treiber heads for the dedicated
// HamtNode class. Padding separates their cache lines. freeHeads[0] remains in
// the common size-class array but is not used by node allocation.
type hamtNodeFreelistShards [arenaNodeFreelistShardCount]slabFreeHead

// varFreelistShards gives every variable-size class its own set of sharded
// Treiber heads. Each head contains a tagged word offset, as documented on
// freeVar.
type varFreelistShards [numVarClasses][arenaVarFreelistShardCount]slabFreeHead

// HamtArena allocates HAMT nodes and variable-sized arrays in an mmap region.
// Class 0 holds HamtNode slots; classes 1 through 16 are power-of-two sizes for
// child arrays, entry arrays, strings and CRDT entries. RetireBlock defers
// reuse until EBR establishes that no reader from an earlier epoch remains.
type HamtArena struct {
	_ CacheLinePad
	// freeHeads[0]  = dedicated 72-byte HamtNode class
	// freeHeads[1]  = 16-byte class
	// freeHeads[2]  = 32-byte class
	// freeHeads[3]  = 64-byte class
	// ...
	// freeHeads[16] = 524288-byte class
	freeHeads [numSizeClasses]slabFreeHead
	// nodeFreelist is the allocation and reclamation surface for HamtNode.
	// AllocNode and pushFreeNode choose a padded shard head once per call.
	nodeFreelist hamtNodeFreelistShards
	// nodeFreelistRoutePop selects an allocation shard. Advancing once per
	// call keeps the routing write outside the CAS retry loop.
	_                    CacheLinePad
	nodeFreelistRoutePop atomic.Uint64
	_                    CacheLinePad
	// nodeFreelistRoutePush is independent of the pop counter because EBR
	// reclamation and allocation can run on different goroutines. All shards
	// hold the same node size, so their push and pop routes need not agree.
	_                     CacheLinePad
	nodeFreelistRoutePush atomic.Uint64
	_                     CacheLinePad
	// varFreelist holds sharded lists for variable-size classes. allocVar
	// sweeps these shards and freeVar pushes to one of them; the parallel
	// freeHeads entries are retained only for the common class layout.
	varFreelist varFreelistShards
	// varFreelistRoutePop selects the first allocation shard once per call.
	_                   CacheLinePad
	varFreelistRoutePop atomic.Uint64
	_                   CacheLinePad
	// varFreelistRoutePush is separate because EBR reclamation need not run on
	// the allocating goroutine. All shards within a class hold equal-sized
	// blocks, so independent push and pop routes are valid.
	_                    CacheLinePad
	varFreelistRoutePush atomic.Uint64
	_                    CacheLinePad
	// bumpOffset tracks the high-water mark of the arena in bytes.
	// Starts at nodeSize to reserve offset 0 as NullOffset64 sentinel.
	bumpOffset atomic.Uint64
	_          CacheLinePad
	base       uintptr
	size       uintptr
	// ebr manages safe epoch-based deferred reclamation of offsets.
	ebr *EBRManager
	// freed makes Free idempotent. Without it, a second call could unmap an
	// address range that the operating system has since assigned to another
	// arena. Only Free accesses this field.
	freed atomic.Bool
}

// NewHamtArena initializes a new off-heap arena of the given size.
// Memory is allocated via mmap, completely invisible to the Go GC.
// The EBRManager is required for ABA-safe deferred reclamation.
func NewHamtArena(size uintptr, ebr *EBRManager) (*HamtArena, error) {
	b, err := syscall.Mmap(-1, 0, int(size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}

	arena := &HamtArena{
		base: uintptr(unsafe.Pointer(&b[0])),
		size: size,
		ebr:  ebr,
	}
	// Initialize all free-lists as empty (NullOffset64 = 0 sentinel).
	for i := range arena.freeHeads {
		arena.freeHeads[i].head.Store(NullOffset64)
	}
	// Every node shard starts empty. The zero-valued routing counters select
	// shard 0 for the first allocation and reclamation, then advance on each
	// subsequent call.
	for i := range arena.nodeFreelist {
		arena.nodeFreelist[i].head.Store(NullOffset64)
	}
	// Initialize every variable-class shard to the empty sentinel. Its routing
	// counters start at zero and advance once per call.
	for c := range arena.varFreelist {
		for s := range arena.varFreelist[c] {
			arena.varFreelist[c][s].head.Store(NullOffset64)
		}
	}
	// Reserve offset 0 so it can serve as the empty sentinel.
	// Bump allocator starts at nodeSize.
	arena.bumpOffset.Store(uint64(nodeSize))
	return arena, nil
}

// Base returns the mmap base address. Crash tests in internal/chaos use it
// with Size to construct a faulting off-heap dereference without exposing the
// allocator's free-list internals. The accessor does not allocate.
func (a *HamtArena) Base() uintptr { return a.base }

// Size returns the total mapped byte size of the off-heap arena.
func (a *HamtArena) Size() uintptr { return a.size }

// HighWater returns the bump allocator's byte offset. Free-list reuse never
// lowers it, so an unchanged value proves that a checkpoint or root-compute
// path allocated no new arena memory for a merged view (ADR-0045 §7). The
// accessor performs one atomic load.
func (a *HamtArena) HighWater() uint64 { return a.bumpOffset.Load() }

// ---------------------------------------------------------------------------
// ADR 9: Size Class Resolution
// ---------------------------------------------------------------------------

// varSizeClassIndex computes the power-of-2 size class index for a variable
// allocation of the given size (including the 8-byte header).
//
// Returns the slab class index [1, numSizeClasses-1] and the actual block
// size to allocate (rounded up to the class boundary).
//
// Class mapping (totalSize = payload + 8-byte header):
//
//	class 1 → 16 bytes  (payload ≤ 8)
//	class 2 → 32 bytes  (payload ≤ 24)
//	class 3 → 64 bytes  (payload ≤ 56)
//	class 4 → 128 bytes (payload ≤ 120)
//	...
//
// A zero payload returns class 0 and size 0 so the caller can avoid an
// allocation and the power-of-two calculation cannot underflow.
func varSizeClassIndex(payloadSize uintptr) (classIdx int, blockSize uintptr) {
	if payloadSize == 0 {
		return 0, 0 // Caller should handle: no allocation needed
	}

	totalSize := payloadSize + varAllocHeaderSize
	// Enforce minimum block size of 16 bytes (must hold next-pointer for Treiber stack)
	if totalSize < minVarAllocSize {
		totalSize = minVarAllocSize
	}

	// Round up to next power of 2
	// bits.Len returns position of highest set bit (1-indexed), so:
	// roundedSize = 1 << bits.Len(totalSize - 1)
	rounded := uintptr(1) << uint(bits.Len64(uint64(totalSize)-1))

	// Class index: log2(rounded) - 3 (since class 1 = 16 = 2^4, offset by class-0 reservation)
	// log2(16) = 4 → class 1, log2(32) = 5 → class 2, etc.
	idx := bits.TrailingZeros64(uint64(rounded)) - 3
	if idx < 1 {
		idx = 1
	}
	if idx >= numSizeClasses {
		idx = numSizeClasses - 1
	}

	return idx, rounded
}

// blockSizeForClass returns the allocation block size for a given class index.
func blockSizeForClass(classIdx int) uintptr {
	if classIdx == 0 {
		return uintptr(nodeSize) // 72 bytes
	}
	// Class 1 = 16, class 2 = 32, class 3 = 64, ...
	return uintptr(1) << uint(classIdx+3)
}

// ---------------------------------------------------------------------------
// HamtNode Allocation (Class 0 — Dedicated 72-byte slab)
// ---------------------------------------------------------------------------

// routeNodeFreelistShard selects the shard used for an entire AllocNode call.
// A per-call counter distributes allocations across shards without relying on
// goroutine pinning. The counter advances outside the CAS retry loop, and a
// power-of-two mask normally replaces integer modulo. Padding isolates this
// write from shard heads and bumpOffset.
func (a *HamtArena) routeNodeFreelistShard() int {
	// arenaNodeFreelistShardCount is a power of two, so & (N-1) is a clean
	// bitmask with no modulo; the defensive power-of-two branch mirrors
	// routeShard's shape in crdt.go.
	n := arenaNodeFreelistShardCount
	idx := a.nodeFreelistRoutePop.Add(1)
	if n&(n-1) == 0 {
		return int(idx-1) & (n - 1)
	}
	return int((idx - 1) % uint64(n))
}

// routeNodeFreelistShardPush selects the shard used for an entire pushFreeNode
// call. EBR reclamation and allocation may run on different goroutines, so they
// use separate counters and avoid contending on a shared routing word. Every
// shard holds the same node size, and EBR protects readers across all shards;
// independent push and pop routes therefore preserve the reclamation contract.
func (a *HamtArena) routeNodeFreelistShardPush() int {
	n := arenaNodeFreelistShardCount
	idx := a.nodeFreelistRoutePush.Add(1)
	if n&(n-1) == 0 {
		return int(idx-1) & (n - 1)
	}
	return int((idx - 1) % uint64(n))
}

// routeVarFreelistShardPop selects the first shard probed by allocVar. It uses
// the same per-call routing discipline as node allocation.
//
// The fault switches exercise the variable free-list regression tests.
// varFreelistABAYieldFault routes both directions to shard 0 and yields around
// header reads to widen the race window. untaggedVarFreelistFault selects the
// legacy untagged representation and non-atomic header write so the tests can
// demonstrate the corruption that tagged heads and atomic headers prevent.
// Both default to false.
var (
	varFreelistABAYieldFault atomic.Bool
	untaggedVarFreelistFault atomic.Bool
)

func (a *HamtArena) routeVarFreelistShardPop() int {
	if varFreelistABAYieldFault.Load() {
		return 0
	}
	n := arenaVarFreelistShardCount
	idx := a.varFreelistRoutePop.Add(1)
	if n&(n-1) == 0 {
		return int(idx-1) & (n - 1)
	}
	return int((idx - 1) % uint64(n))
}

// routeVarFreelistShardPush selects the shard used for an entire freeVar
// call. Push and pop counters are independent because reclamation and
// allocation may run on different goroutines. Blocks in every shard of a class
// have the same size, so independent routes do not violate type or EBR safety.
func (a *HamtArena) routeVarFreelistShardPush() int {
	if varFreelistABAYieldFault.Load() {
		return 0
	}
	n := arenaVarFreelistShardCount
	idx := a.varFreelistRoutePush.Add(1)
	if n&(n-1) == 0 {
		return int(idx-1) & (n - 1)
	}
	return int((idx - 1) % uint64(n))
}

// AllocNode recycles a node from one sharded Treiber list when possible and
// otherwise uses the bump allocator. It holds an EBR participant across the
// pop, preventing a concurrent RetireBlock from returning the observed head to
// any list and causing ABA while the CAS is in progress.
func (a *HamtArena) AllocNode() NodePtr {
	// Pin to EBR epoch — prevents ABA during Treiber pop
	participant := a.ebr.Acquire()
	participant.Enter(a.ebr)

	// Select one shard for the whole call so every retry observes the same
	// head. EBR protection covers all shards.
	shardIdx := a.routeNodeFreelistShard()
	shard := &a.nodeFreelist[shardIdx]

	// 1. Try to pop from the Treiber free-list (recycled memory)
	for {
		head := shard.head.Load()

		if head == NullOffset64 {
			// Free-list is empty — fall through to bump allocator
			break
		}

		// The next link occupies the dead node's first word. The mmap
		// address cannot move, and the EBR pin prevents reuse during this
		// read and the CAS below.
		nextPtr := (*uint64)(unsafe.Pointer(a.base + uintptr(head)))
		nextOffset := atomic.LoadUint64(nextPtr)

		// No generation is needed in a node-list head: EBR prevents the
		// observed node from being recycled while this participant is active.
		if shard.head.CompareAndSwap(head, nextOffset) {
			// Successfully popped — initialize the recycled node
			ptr := NodePtr(a.base + uintptr(head))
			node := (*HamtNode)(unsafe.Pointer(ptr))
			node.refCount.Store(1)
			node.bitmap = 0
			node.childrenPtr = 0
			node.entriesPtr = 0
			node.merkleHash = [32]byte{}
			node.nextFree = 0

			participant.Exit()
			a.ebr.Release(participant)
			return ptr
		}
		// CAS failed — another goroutine raced us. Retry.
	}

	participant.Exit()
	a.ebr.Release(participant)

	// 2. Fall back to the atomic bump allocator
	return a.bumpAllocateNode()
}

// bumpAllocateNode reserves nodeSize bytes from the arena via atomic addition.
func (a *HamtArena) bumpAllocateNode() NodePtr {
	endOffset := a.bumpOffset.Add(uint64(nodeSize))
	startOffset := endOffset - uint64(nodeSize)

	if endOffset > uint64(a.size) {
		panic("HamtArena: OOM - arena exhausted")
	}

	ptr := NodePtr(a.base + uintptr(startOffset))
	node := (*HamtNode)(unsafe.Pointer(ptr))
	node.refCount.Store(1)
	node.bitmap = 0
	node.childrenPtr = 0
	node.entriesPtr = 0
	node.merkleHash = [32]byte{}
	node.nextFree = 0
	return ptr
}

// ---------------------------------------------------------------------------
// ADR 9: Variable-Size Allocation (Classes 1-16)
// ---------------------------------------------------------------------------

// allocVar allocates a variable-sized block and returns the payload address
// after its 8-byte class header. It probes arenaVarFreelistSweep shards under
// one EBR pin, starting at routeVarFreelistShardPop, before falling back to
// the bump allocator.
//
// The sweep matters because freeVar uses an independent routing counter: the
// first shard can be empty while nearby shards hold reusable blocks. Probing
// only one shard would advance bumpOffset even with sufficient recycled
// memory. freeHeads is not a second allocation source because freeVar never
// pushes there; it remains only for the common size-class layout.
func (a *HamtArena) allocVar(payloadSize uintptr) uintptr {
	if payloadSize == 0 {
		return 0
	}

	classIdx, blockSize := varSizeClassIndex(payloadSize)
	if classIdx == 0 {
		return 0 // Should not happen — payloadSize > 0 guaranteed
	}

	// Select the starting shard once. Each CAS retry stays on its current
	// shard, and the bounded sweep determines where to probe next.
	shardIdxStart := a.routeVarFreelistShardPop()
	shards := &a.varFreelist[classIdx-1]

	// 1. Try to pop from the routed shard, then sweep the next
	//    arenaVarFreelistSweep-1 shards (bounded probe). EBR Acquire/Enter is
	//    taken before the sweep so the goroutine is pinned across all probes
	//    (one EBR pin per allocVar call, regardless of which probe succeeds).
	participant := a.ebr.Acquire()
	participant.Enter(a.ebr)

	for probe := 0; probe < arenaVarFreelistSweep; probe++ {
		shardIdx := (shardIdxStart + probe) & (arenaVarFreelistShardCount - 1)
		shard := &shards[shardIdx]

		if untaggedVarFreelistFault.Load() {
			for {
				head := shard.head.Load()
				if head == NullOffset64 {
					break
				}
				if head < uint64(nodeSize) || (head&7) != 0 || head+uint64(blockSize) > a.bumpOffset.Load() {
					// The untagged fault can leave an invalid byte offset in
					// shard.head. Return its payload address instead of performing
					// an unaligned ARM64 atomic load, so the regression test can
					// report the invalid allocation rather than crash with SIGBUS.
					_ = shard.head.CompareAndSwap(head, NullOffset64)
					participant.Exit()
					a.ebr.Release(participant)
					return a.base + uintptr(head) + varAllocHeaderSize
				}
				nextPtr := (*uint64)(unsafe.Pointer(a.base + uintptr(head)))
				if varFreelistABAYieldFault.Load() {
					runtime.Gosched()
				}
				nextOffset := atomic.LoadUint64(nextPtr)
				if varFreelistABAYieldFault.Load() {
					runtime.Gosched()
				}
				if shard.head.CompareAndSwap(head, nextOffset) {
					participant.Exit()
					a.ebr.Release(participant)

					blockPtr := a.base + uintptr(head)
					*(*uint64)(unsafe.Pointer(blockPtr)) = uint64(classIdx)
					payload := blockPtr + varAllocHeaderSize
					clearMem(payload, payloadSize)
					return payload
				}
			}
			continue
		}

		for {
			head := shard.head.Load()
			wordOffset := head & 0xFFFFFFFF
			if wordOffset == 0 {
				// Routed shard (or current probe shard) is empty — break out
				// of the inner CAS retry loop and try the next probe shard.
				break
			}
			blockOffset := wordOffset << 3
			if blockOffset < uint64(nodeSize) || blockOffset+uint64(blockSize) > a.bumpOffset.Load() || (blockOffset&7) != 0 {
				break
			}
			blockPtr := a.base + uintptr(blockOffset)
			hdrPtr := (*uint64)(unsafe.Pointer(blockPtr))
			if varFreelistABAYieldFault.Load() {
				runtime.Gosched()
			}
			hdr := atomic.LoadUint64(hdrPtr)
			if int(hdr&0xFF) != classIdx {
				break
			}
			nextWordOffset := (hdr >> 8) & 0xFFFFFFFF
			if varFreelistABAYieldFault.Load() {
				runtime.Gosched()
			}
			newHead := ((head + (1 << 32)) & 0xFFFFFFFF00000000) | nextWordOffset
			if shard.head.CompareAndSwap(head, newHead) {
				participant.Exit()
				a.ebr.Release(participant)

				// Write size class header atomically (nextWordOffset = 0)
				atomic.StoreUint64(hdrPtr, uint64(classIdx))
				// Zero the payload region
				payload := blockPtr + varAllocHeaderSize
				clearMem(payload, payloadSize)
				return payload
			}
		}
	}

	participant.Exit()
	a.ebr.Release(participant)

	// 2. All arenaVarFreelistSweep probed shards drained — bump allocator.
	endOffset := a.bumpOffset.Add(uint64(blockSize))
	startOffset := endOffset - uint64(blockSize)

	if endOffset > uint64(a.size) {
		panic("HamtArena: OOM - arena exhausted (variable alloc)")
	}

	blockPtr := a.base + uintptr(startOffset)
	// Write size class header atomically (nextWordOffset = 0, low 8 bits = classIdx)
	atomic.StoreUint64((*uint64)(unsafe.Pointer(blockPtr)), uint64(classIdx))
	// Return pointer past the header
	return blockPtr + varAllocHeaderSize
}

// freeVar pushes a variable-sized block back onto its slab free-list.
//
// The list is a tagged Treiber stack. shard.head packs a 32-bit generation tag
// (upper half) with the block's word offset, blockOffset >> 3 (lower half), and
// every push increments the tag, so a compare-and-swap cannot succeed against a
// head that was popped and pushed again in between (the ABA problem). The
// block's 8-byte header stores (nextWordOffset << 8) | classIdx in one atomic
// word, so a concurrent push cannot tear it. Both the EBR-deferred path
// (freeVar) and the direct paths (pushFreeVar, ReleaseLocal) rely on this.
func (a *HamtArena) freeVar(payloadPtr uintptr) {
	if payloadPtr == 0 {
		return
	}

	blockPtr := payloadPtr - varAllocHeaderSize
	if untaggedVarFreelistFault.Load() {
		classIdx := int(*(*uint64)(unsafe.Pointer(blockPtr)))
		if classIdx < 1 || classIdx >= numSizeClasses {
			return
		}
		offset := uint64(blockPtr - a.base)
		offsetPtr := (*uint64)(unsafe.Pointer(blockPtr))
		shardIdx := a.routeVarFreelistShardPush()
		shard := &a.varFreelist[classIdx-1][shardIdx]
		for {
			head := shard.head.Load()
			atomic.StoreUint64(offsetPtr, head)
			if shard.head.CompareAndSwap(head, offset) {
				return
			}
		}
	}

	hdrPtr := (*uint64)(unsafe.Pointer(blockPtr))
	classIdx := int(atomic.LoadUint64(hdrPtr) & 0xFF)

	if classIdx < 1 || classIdx >= numSizeClasses {
		return // Corrupt or invalid — silently skip
	}

	offset := uint64(blockPtr - a.base)
	wordOffset := (offset >> 3) & 0xFFFFFFFF

	// Select one shard for the whole push, outside the CAS retry loop.
	shardIdx := a.routeVarFreelistShardPush()
	shard := &a.varFreelist[classIdx-1][shardIdx]

	// 1. Try to push onto the routed shard (hot path)
	for {
		head := shard.head.Load()
		headWordOffset := head & 0xFFFFFFFF
		atomic.StoreUint64(hdrPtr, (headWordOffset<<8)|uint64(classIdx))
		newHead := ((head + (1 << 32)) & 0xFFFFFFFF00000000) | wordOffset
		if shard.head.CompareAndSwap(head, newHead) {
			return
		}
	}
}

// pushFreeVar is a helper for EBR to reclaim variable-sized blocks by offset.
func (a *HamtArena) pushFreeVar(offset uint64) {
	if offset == 0 {
		return
	}
	payloadPtr := a.base + uintptr(offset)
	a.freeVar(payloadPtr)
}

// clearMem zeroes a region of memory. Used to initialize recycled blocks.
func clearMem(ptr uintptr, size uintptr) {
	if size == 0 || ptr == 0 {
		return
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), size)
	for i := range b {
		b[i] = 0
	}
}

// ---------------------------------------------------------------------------
// Public allocBytes / allocString / allocCRDTEntries (now slab-backed)
// ---------------------------------------------------------------------------

// allocBytes reserves an arbitrary number of bytes from the arena via the
// segregated slab allocator. Alignment is enforced to 8-byte boundary.
// Returns a pointer to the PAYLOAD (the caller never sees the header).
func (a *HamtArena) allocBytes(size uintptr) uintptr {
	alignedSize := (size + 7) &^ 7
	return a.allocVar(alignedSize)
}

// allocString copies a Go string's raw UTF-8 bytes directly into the mmap arena,
// permanently severing any reliance on the Go heap for string persistence.
// Returns a NodePtr offset to the raw bytes and the uint32 length.
func (a *HamtArena) allocString(s string) (NodePtr, uint32) {
	if len(s) == 0 {
		return 0, 0
	}
	alignedLen := (uintptr(len(s)) + 7) &^ 7
	ptr := a.allocVar(alignedLen)
	target := unsafe.Slice((*byte)(toPtr(NodePtr(ptr))), len(s))
	copy(target, s)
	return NodePtr(ptr), uint32(len(s))
}

// allocCRDTEntries copies a []CRDTEntry array into the mmap arena as a contiguous
// block of 120-byte elements. Returns a NodePtr offset and the uint32 count.
func (a *HamtArena) allocCRDTEntries(entries []CRDTEntry) (NodePtr, uint32) {
	if len(entries) == 0 {
		return 0, 0
	}
	size := uintptr(len(entries)) * unsafe.Sizeof(CRDTEntry{})
	ptr := a.allocVar(size)
	target := unsafe.Slice((*CRDTEntry)(toPtr(NodePtr(ptr))), len(entries))
	copy(target, entries)
	return NodePtr(ptr), uint32(len(entries))
}

// hamtWrapperSize is the arena footprint of a HAMT wrapper, including its
// root, arena pointer, hash seed and count.
const hamtWrapperSize = unsafe.Sizeof(HAMT{})

// allocHAMTWrapper allocates a HAMT wrapper in the mmap arena. Its arena field
// points back to a Go-heap object but is invisible to the GC, so the caller
// must keep that HamtArena reachable for every wrapper's lifetime.
// DeltaCRDTEngine.arena provides this root in the engine; tests hold the arena
// directly. maphash.Seed contains no pointer payload and can reside off-heap.
//
// Wrappers must be released through freeHAMTWrapper so their memory is retired
// through EBR rather than immediately reused.
func (a *HamtArena) allocHAMTWrapper() *HAMT {
	// allocVar pins the goroutine to the EBR epoch, attempts to pop a
	// recycled block from the slab free-list, and falls back to the bump
	// allocator. Zero heap allocations, ABA-safe via EBR pin.
	payload := a.allocVar(hamtWrapperSize)
	if payload == 0 {
		panic("HamtArena: OOM — cannot allocate HAMT wrapper")
	}
	return (*HAMT)(unsafe.Pointer(payload))
}

// freeHAMTWrapper clears a wrapper and retires its arena block through EBR.
// Directly pushing it to a free-list could recycle memory while readers from
// earlier epochs still hold it. ptr must come from this arena's
// allocHAMTWrapper, its root subtree must already have been released with
// DecRef, and the owning arena must remain reachable until this call returns.
// The reclamation callback in reclamation.go performs these steps in order.
// The caller must not dereference ptr afterward.
func (a *HamtArena) freeHAMTWrapper(ptr *HAMT) {
	if ptr == nil {
		return
	}
	// Zero the struct so any Go-invisible pointer fields stop aliasing the
	// recycled block (defensive — the `arena` field becomes nil before the
	// block is returned to the slab free-list by RetireBlock processing).
	*ptr = HAMT{}

	// Convert the payload pointer back to its mmap offset and defer the
	// physical free-list push behind EBR. isNode=false routes the block
	// through pushFreeVar (variable-size class), not pushFreeNode (class 0).
	payloadPtr := uintptr(unsafe.Pointer(ptr))
	offset := uint64(payloadPtr - a.base)
	a.ebr.RetireBlock(a, offset, false)
}

// ---------------------------------------------------------------------------
// ADR 9: Deep-Copy Helpers for UAF Prevention
// ---------------------------------------------------------------------------

// copyChildrenArray deep-copies a children NodePtr array into a fresh arena
// allocation. The old and new nodes will own independent array memory,
// eliminating the use-after-free hazard when the old node is DecRef'd.
func (a *HamtArena) copyChildrenArray(srcPtr NodePtr, count int) NodePtr {
	if srcPtr == 0 || count == 0 {
		return 0
	}
	size := uintptr(count) * unsafe.Sizeof(NodePtr(0))
	dst := a.allocVar(size)
	srcSlice := unsafe.Slice((*NodePtr)(toPtr(srcPtr)), count)
	dstSlice := unsafe.Slice((*NodePtr)(toPtr(NodePtr(dst))), count)
	copy(dstSlice, srcSlice)
	return NodePtr(dst)
}

// copyEntriesArray deep-copies a hamtLeaf entries array (length-prefixed)
// into a fresh arena allocation. The 8-byte length prefix is preserved.
func (a *HamtArena) copyEntriesArray(srcPtr NodePtr) NodePtr {
	if srcPtr == 0 {
		return 0
	}
	l := *(*uint64)(toPtr(srcPtr))
	if l == 0 {
		return 0
	}
	totalSize := uintptr(8) + uintptr(l)*unsafe.Sizeof(hamtLeaf{})
	dst := a.allocVar(totalSize)
	*(*uint64)(unsafe.Pointer(dst)) = l
	srcLeaves := unsafe.Slice((*hamtLeaf)(toUintptrPtr(uintptr(srcPtr)+8)), int(l))
	dstLeaves := unsafe.Slice((*hamtLeaf)(toUintptrPtr(dst+8)), int(l))
	for i := range srcLeaves {
		dstLeaves[i] = a.deepCopyLeaf(srcLeaves[i])
	}
	return NodePtr(dst)
}

// deepCopyLeaf deep-copies the leaf struct and its strings/CRDT payloads.
func (a *HamtArena) deepCopyLeaf(src hamtLeaf) hamtLeaf {
	dst := src
	if src.entityPtr != 0 && src.entityLen > 0 {
		strBytes := unsafe.Slice((*byte)(toPtr(src.entityPtr)), src.entityLen)
		alignedLen := (uintptr(len(strBytes)) + 7) &^ 7
		newEntityPtr := a.allocVar(alignedLen)
		copy(unsafe.Slice((*byte)(toUintptrPtr(newEntityPtr)), len(strBytes)), strBytes)
		dst.entityPtr = NodePtr(newEntityPtr)
	}

	if src.entriesPtr != 0 && src.entriesLen > 0 {
		crdtBytes := unsafe.Slice((*CRDTEntry)(toPtr(src.entriesPtr)), src.entriesLen)
		size := uintptr(len(crdtBytes)) * unsafe.Sizeof(CRDTEntry{})
		newEntriesPtr := a.allocVar(size)
		copy(unsafe.Slice((*CRDTEntry)(toUintptrPtr(newEntriesPtr)), len(crdtBytes)), crdtBytes)
		dst.entriesPtr = NodePtr(newEntriesPtr)
	}
	return dst
}

// ---------------------------------------------------------------------------
// Reference Counting and Reclamation
// ---------------------------------------------------------------------------

// IncRef increments the reference count of a node during HAMT path-copying.
func (a *HamtArena) IncRef(ptr NodePtr) {
	if ptr == 0 {
		return
	}
	node := (*HamtNode)(toPtr(ptr))
	node.refCount.Add(1)
}

// DecRef decrements a node's reference count. At zero, it iteratively
// decrements child nodes and retires the node's child array, entry array,
// leaf keys and CRDT entries. Path copying gives each node exclusive ownership
// of these arrays and leaf payloads, so all can be released. RetireBlock
// defers their return to the free-lists until EBR has excluded earlier readers.
func (a *HamtArena) DecRef(ptr NodePtr) {
	var stackBuf [256]NodePtr
	stack := stackBuf[:0]
	stack = append(stack, ptr)

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if current == 0 {
			continue
		}

		node := (*HamtNode)(toPtr(current))

		if node.refCount.Add(-1) == 0 {
			// Snapshot all pointers before the node memory may be reused
			childrenPtr := node.childrenPtr
			entriesPtr := node.entriesPtr
			childCount := bits.OnesCount32(node.bitmap)

			// Enqueue children for deferred decrement
			if childrenPtr != 0 && childCount > 0 {
				children := unsafe.Slice((*NodePtr)(toPtr(childrenPtr)), childCount)
				stack = append(stack, children...)
			}

			// ADR 9: Reclaim leaf-level allocations (strings, CRDT entries)
			// inside the entries array. These are exclusively owned by this node.
			if entriesPtr != 0 {
				l := *(*uint64)(toPtr(entriesPtr))
				if l > 0 {
					leaves := unsafe.Slice((*hamtLeaf)(toUintptrPtr(uintptr(entriesPtr)+8)), int(l))
					for i := range leaves {
						leafEntityPtr := uintptr(leaves[i].entityPtr)
						leafCRDTPtr := uintptr(leaves[i].entriesPtr)

						// Defer-free leaf string bytes
						if leafEntityPtr != 0 {
							offset := uint64(leafEntityPtr - a.base)
							a.ebr.RetireBlock(a, offset, false)
						}
						// Defer-free leaf CRDT entry arrays
						if leafCRDTPtr != 0 {
							offset := uint64(leafCRDTPtr - a.base)
							a.ebr.RetireBlock(a, offset, false)
						}
					}
				}
			}

			// ADR 9: Defer-free the children array itself
			if childrenPtr != 0 {
				offset := uint64(uintptr(childrenPtr) - a.base)
				a.ebr.RetireBlock(a, offset, false)
			}

			// ADR 9: Defer-free the entries array itself
			if entriesPtr != 0 {
				offset := uint64(uintptr(entriesPtr) - a.base)
				a.ebr.RetireBlock(a, offset, false)
			}

			// Defer-free the HamtNode itself (class 0)
			offset := uint64(uintptr(current) - a.base)
			a.ebr.RetireBlock(a, offset, true)
		}
	}
}

// pushFreeNode returns a node to one class-0 Treiber list. EBR invokes it only
// after epoch advancement has excluded earlier readers. The push counter is
// independent of allocation routing because reclamation can run on another
// goroutine; every shard holds the same node size.
func (a *HamtArena) pushFreeNode(offset uint64) {
	// Select the shard once, outside the CAS retry loop.
	shardIdx := a.routeNodeFreelistShardPush()
	shard := &a.nodeFreelist[shardIdx]
	offsetPtr := (*uint64)(unsafe.Pointer(a.base + uintptr(offset)))

	for {
		head := shard.head.Load()
		atomic.StoreUint64(offsetPtr, head)

		if shard.head.CompareAndSwap(head, offset) {
			return
		}
	}
}

// Free unlocks and unmaps the arena. UnlockAllPages is safe even if no pages
// were locked and ensures LockHotPages does not leave residency accounting
// behind. The freed CAS makes concurrent and repeated calls idempotent and
// prevents two calls from unmapping the same address range.
func (a *HamtArena) Free() error {
	// Only the caller that changes freed from false to true may unmap.
	if !a.freed.CompareAndSwap(false, true) {
		return nil
	}
	a.UnlockAllPages()
	b := unsafe.Slice((*byte)(unsafe.Pointer(a.base)), a.size)
	return syscall.Munmap(b)
}

// --- Pointer conversion utilities ---

// toPtr converts a NodePtr to unsafe.Pointer. NodePtr must refer to the mmap
// arena: the Go GC cannot move that memory, whereas converting an arbitrary
// Go-heap integer could produce an invalid pointer.
func toPtr(p NodePtr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p))
}

// toUintptrPtr applies the same arena-only pointer conversion to a uintptr.
func toUintptrPtr(p uintptr) unsafe.Pointer {
	return unsafe.Pointer(p)
}
