// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"sync/atomic"
	"unsafe"
)

const (
	maxHeight     = 11
	nodeSize      = 64 // bytes per node, cache-line aligned
	offsetNil     = 0  // sentinel: no next node (offset 0 is the head node)
	pValue        = 4  // 1/pValue probability of height increase
	keySize       = 40 // 16B entity hash + 8B system + 8B valid + 8B assertion
	nodeNextStart = 20 // byte offset where Next[] array begins in node
	keyHashLen    = 16 // 128-bit SHA-256 entity ID prefix
)

// Retain package-level constants used by tests and external callers.
var (
	_ = offsetNil
	_ = keyHashLen
)

// SkipListArena is a pointerless, array-backed concurrent SkipList.
// All memory is off-heap (jemalloc) so Go GC scans zero pointers.
//
// Arena layout:
//
//	[0..nodeSize)             = head sentinel node
//	[nodeSize..nodeSize*N)    = allocated nodes
//	[...                      = key/value data region (grows downward from end)
//
// Concurrent inserts use lock-free CAS splicing on 32-bit arena offsets.
type SkipListArena struct {
	arena      []byte // jemalloc-backed contiguous buffer
	allocator  *JemallocAllocator
	nodeCount  atomic.Uint32 // number of nodes allocated (excluding head)
	nodeTop    atomic.Uint32 // next free byte offset for nodes
	dataBottom atomic.Uint32 // next free byte offset for data (grows downward from end)
	height     atomic.Int32  // current max height of the skip list
	size       atomic.Int64  // total logical data bytes stored
}

// NewSkipListArena creates a new off-heap SkipList arena.
// arenaSize is the total byte capacity (e.g., 256*1024*1024 for 256MB).
func NewSkipListArena(allocator *JemallocAllocator, arenaSize uint32) *SkipListArena {
	arena := allocator.Allocate(int(arenaSize))

	sl := &SkipListArena{
		arena:     arena,
		allocator: allocator,
	}

	// Initialize head sentinel at offset 0.
	sl.nodeTop.Store(nodeSize) // first real node starts after head
	sl.dataBottom.Store(arenaSize)
	sl.height.Store(1)

	// Head node: height = maxHeight, all next pointers = 0xFFFFFFFF sentinel.
	binary.LittleEndian.PutUint32(arena[0:4], maxHeight)
	// Key/value offsets and lengths remain 0 (unused for head).
	// Next pointers: set all to sentinel value.
	for i := 0; i < maxHeight; i++ {
		off := nodeNextStart + i*4
		binary.LittleEndian.PutUint32(arena[off:off+4], 0xFFFFFFFF)
	}

	return sl
}

// randomHeight generates a random SkipList height using geometric distribution.
func randomHeight() uint32 {
	h := uint32(1)
	for h < maxHeight && rand.Uint32N(pValue) == 0 {
		h++
	}
	return h
}

// nodeKeyOffset reads the key data offset for the node.
func (sl *SkipListArena) nodeKeyOffset(offset uint32) uint32 {
	return binary.LittleEndian.Uint32(sl.arena[offset+4 : offset+8])
}

// nodeValueOffset reads the value data offset for the node.
func (sl *SkipListArena) nodeValueOffset(offset uint32) uint32 {
	return binary.LittleEndian.Uint32(sl.arena[offset+8 : offset+12])
}

// nodeKeyLen reads the key length for the node.
func (sl *SkipListArena) nodeKeyLen(offset uint32) uint32 {
	return binary.LittleEndian.Uint32(sl.arena[offset+12 : offset+16])
}

// nodeValLen reads the value length for the node.
func (sl *SkipListArena) nodeValLen(offset uint32) uint32 {
	return binary.LittleEndian.Uint32(sl.arena[offset+16 : offset+20])
}

// nodeNext atomically reads the next-node offset at the given level for lock-free reads.
func (sl *SkipListArena) nodeNext(offset uint32, level int) uint32 {
	off := offset + uint32(nodeNextStart) + uint32(level)*4
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&sl.arena[off])))
}

// setNodeNext stores the next-node offset at the given level.
// Safe only during node initialization (before the node is visible to readers).
func (sl *SkipListArena) setNodeNext(offset uint32, level int, next uint32) {
	off := offset + uint32(nodeNextStart) + uint32(level)*4
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&sl.arena[off])), next)
}

// casNodeNext atomically compares-and-swaps the next-node offset at the given level.
// Returns true if the swap succeeded (old value matched expected).
func (sl *SkipListArena) casNodeNext(offset uint32, level int, expected, next uint32) bool {
	off := offset + uint32(nodeNextStart) + uint32(level)*4
	return atomic.CompareAndSwapUint32((*uint32)(unsafe.Pointer(&sl.arena[off])), expected, next)
}

// nodeKey returns the key bytes for the node at the given offset.
func (sl *SkipListArena) nodeKey(offset uint32) []byte {
	if offset == 0 || offset == 0xFFFFFFFF {
		return nil
	}
	keyOff := sl.nodeKeyOffset(offset)
	keyLen := sl.nodeKeyLen(offset)
	if keyOff >= uint32(len(sl.arena)) || keyOff+keyLen > uint32(len(sl.arena)) {
		return nil
	}
	return sl.arena[keyOff : keyOff+keyLen]
}

// allocNode reserves space for a node header (growing upward) and its key/value
// data (growing downward) using CAS bounds checks to prevent wrap-around.
func (sl *SkipListArena) allocNode(height uint32, keyLen, valLen uint32) (uint32, uint32, error) {
	var nodeOff uint32
	for {
		currTop := sl.nodeTop.Load()
		if currTop+nodeSize > uint32(len(sl.arena)) {
			return 0, 0, ErrArenaFull
		}
		if sl.nodeTop.CompareAndSwap(currTop, currTop+nodeSize) {
			nodeOff = currTop
			break
		}
	}

	dataLen := keyLen + valLen

	var dataOff uint32
	for {
		currDataBottom := sl.dataBottom.Load()
		if currDataBottom < dataLen {
			return 0, 0, ErrArenaFull
		}
		newDataBottom := currDataBottom - dataLen
		if nodeOff+nodeSize > newDataBottom {
			return 0, 0, ErrArenaFull
		}
		if sl.dataBottom.CompareAndSwap(currDataBottom, newDataBottom) {
			dataOff = newDataBottom
			break
		}
	}

	// Write node header.
	binary.LittleEndian.PutUint32(sl.arena[nodeOff:nodeOff+4], height)
	binary.LittleEndian.PutUint32(sl.arena[nodeOff+4:nodeOff+8], dataOff)
	binary.LittleEndian.PutUint32(sl.arena[nodeOff+8:nodeOff+12], dataOff+keyLen)
	binary.LittleEndian.PutUint32(sl.arena[nodeOff+12:nodeOff+16], keyLen)
	binary.LittleEndian.PutUint32(sl.arena[nodeOff+16:nodeOff+20], valLen)

	// Initialize next pointers to nil sentinel.
	for i := 0; i < maxHeight; i++ {
		off := nodeOff + uint32(nodeNextStart) + uint32(i)*4
		binary.LittleEndian.PutUint32(sl.arena[off:off+4], 0xFFFFFFFF)
	}

	sl.nodeCount.Add(1)
	sl.size.Add(int64(dataLen))

	return nodeOff, dataOff, nil
}

// Put inserts a key-value pair into the SkipList.
// The key must be the 40-byte tri-temporal composite key.
// The valFn writes the packed event data directly into the arena (zero-GC).
//
// Lock-free implementation using CAS-based splicing. No sync.Mutex or
// sync.RWMutex; multiple goroutines can insert concurrently. Algorithm: find
// predecessors at each level, then splice using CAS. If a CAS fails
// (concurrent insert modified a predecessor's next pointer), re-search from
// the predecessor at that level and retry. This is the same algorithm used
// by CockroachDB's arenaskl and Badger's skiplist.
func (sl *SkipListArena) Put(key []byte, valLen int, valFn func(buf []byte)) error {
	height := randomHeight()

	// Allocate the new node. allocNode uses CAS internally — safe for concurrency.
	newNodeOff, dataOff, err := sl.allocNode(height, uint32(len(key)), uint32(valLen))
	if err != nil {
		return err
	}

	// Write key and value data directly into the pre-allocated arena space.
	copy(sl.arena[dataOff:], key)
	valFn(sl.arena[dataOff+uint32(len(key)):])

	// CAS-update the skip list height if this node is taller.
	for {
		currHeight := sl.height.Load()
		if int32(height) <= currHeight {
			break
		}
		if sl.height.CompareAndSwap(currHeight, int32(height)) {
			break
		}
	}

	// Lock-free search-and-splice: for each level, find the predecessor,
	// then CAS-splice the new node. If the CAS fails, re-search at that level.
	var prev [maxHeight]uint32
	var next [maxHeight]uint32

	// First phase: find predecessors and successors at all levels.
	listHeight := int(sl.height.Load())
	x := uint32(0) // start at head (offset 0)

	for i := listHeight - 1; i >= 0; i-- {
		for {
			nxt := sl.nodeNext(x, i)
			if nxt == 0xFFFFFFFF {
				break
			}
			cmp := bytes.Compare(sl.nodeKey(nxt), key)
			if cmp >= 0 {
				break
			}
			x = nxt
		}
		prev[i] = x
		next[i] = sl.nodeNext(x, i)
	}

	// For levels above the current list height, predecessor is the head.
	for i := listHeight; i < int(height); i++ {
		prev[i] = 0
		next[i] = sl.nodeNext(0, i)
	}

	// Second phase: CAS-splice at each level from bottom to top.
	// Bottom-up insertion ensures that level-0 is linked first,
	// so iterators (which only traverse level 0) see the node atomically.
	for i := 0; i < int(height); i++ {
		for {
			// Set new node's next to the expected successor.
			sl.setNodeNext(newNodeOff, i, next[i])

			// CAS the predecessor's next from the expected successor to our new node.
			if sl.casNodeNext(prev[i], i, next[i], newNodeOff) {
				break // Splice succeeded at this level.
			}

			// CAS failed — a concurrent insert modified prev[i]'s next pointer.
			// Re-search from prev[i] to find the correct insertion point.
			x = prev[i]
			for {
				nxt := sl.nodeNext(x, i)
				if nxt == 0xFFFFFFFF {
					break
				}
				cmp := bytes.Compare(sl.nodeKey(nxt), key)
				if cmp >= 0 {
					break
				}
				x = nxt
			}
			prev[i] = x
			next[i] = sl.nodeNext(x, i)
		}
	}

	return nil
}

// Seek returns an iterator positioned at the first node whose composite key
// is >= target, or an exhausted iterator (Valid() == false, current ==
// 0xFFFFFFFF) if target exceeds all keys.
//
// Seek performs a lock-free top-down descent using atomic.LoadUint32 without
// acquiring locks or mutating links. Under concurrent Put calls, multi-level
// reads can transiently observe an upper-level predecessor whose level-0
// successor is < target before bottom-up CAS splicing completes. Seek verifies
// the landed node against target and falls back to seekLowerBoundLinear along
// the stable level-0 chain if needed. On a quiescent arena, descent completes
// in O(maxHeight) steps with one *SkipListIterator allocation and zero
// per-step allocations.
func (sl *SkipListArena) Seek(target []byte) *SkipListIterator {
	listHeight := int(sl.height.Load())
	x := uint32(0) // head (offset 0)
	for i := listHeight - 1; i >= 0; i-- {
		for {
			nxt := sl.nodeNext(x, i)
			if nxt == 0xFFFFFFFF { // end of this level — break, descend.
				break
			}
			if bytes.Compare(sl.nodeKey(nxt), target) >= 0 { // nxt.key >= target
				break
			}
			x = nxt
		}
		// (Put stores prev[i]=x + next[i]=nodeNext(x,i) here; Seek needs only
		// prev[0], captured by the level-0 read after the loop.)
	}
	// x is prev[0] — the level-0 predecessor of the lower bound. nodeNext(x, 0)
	// is the first node whose key >= target (the lower bound), or 0xFFFFFFFF if
	// target > all keys (the sentinel Valid() checks).
	cur := sl.nodeNext(x, 0)
	// Concurrency guard (see the doc above): a read-only multi-level
	// descent has no CAS to self-correct a moved predecessor, so the result can
	// transiently be a node whose key < target. Verify and fall back to the
	// level-0 linear walk (the stable total order) when that happens. The guard
	// is a no-op on a quiescent skiplist (the production precondition).
	if cur != 0xFFFFFFFF && bytes.Compare(sl.nodeKey(cur), target) < 0 {
		cur = sl.seekLowerBoundLinear(target)
	}
	return &SkipListIterator{sl: sl, current: cur}
}

// seekLowerBoundLinear is the O(N) level-0-only lower bound: a fresh walk from
// head returning the offset of the first node whose key >= target, or 0xFFFFFFFF
// if target > all keys. The level-0 chain is the stable total order (a node is
// linked at level 0 only after its predecessor — the bottom-up splice), so this
// walk is a valid lower bound even under concurrent Puts (the multi-level
// descent's transient inconsistency does not arise here — there is no upper
// level to go stale). Seek's concurrency guard falls back to this on the rare
// transient; on a quiescent skiplist it is never called.
func (sl *SkipListArena) seekLowerBoundLinear(target []byte) uint32 {
	cur := sl.nodeNext(0, 0) // head's level-0 next (the first real node)
	for cur != 0xFFFFFFFF {
		if bytes.Compare(sl.nodeKey(cur), target) >= 0 {
			return cur
		}
		cur = sl.nodeNext(cur, 0)
	}
	return 0xFFFFFFFF
}

// NewSeekIterator is a one-liner symmetry with NewIterator: the caller picks
// "full scan" (NewIterator) vs "lower-bound scan" (NewSeekIterator(target)) by
// constructor. Equivalent to `sl.Seek(target)`. A fresh iterator is returned
// (the NewIterator precedent — construct once, iterate; no stateful re-position
// on an existing iterator, which would add a re-init hazard).
func (sl *SkipListArena) NewSeekIterator(target []byte) *SkipListIterator {
	return sl.Seek(target)
}

// Iterator provides sorted iteration over the SkipList (level 0 traversal).
type SkipListIterator struct {
	sl      *SkipListArena
	current uint32
}

// NewIterator creates an iterator starting at the first element.
func (sl *SkipListArena) NewIterator() *SkipListIterator {
	first := sl.nodeNext(0, 0) // head's level-0 next
	return &SkipListIterator{sl: sl, current: first}
}

// Valid returns true if the iterator points to a valid node.
func (it *SkipListIterator) Valid() bool {
	return it.current != 0xFFFFFFFF
}

// Key returns the current node's key bytes.
// Layout: [16B hash][8B sysTime][8B validTime][8B assertTime] = 40 bytes.
func (it *SkipListIterator) Key() []byte {
	return it.sl.nodeKey(it.current)
}

// Value returns the current node's raw value bytes.
// Layout: [2B entityIDLen][entityID string][8B H3Index][8B ValidTimeEnd][32B payloadDigest][4B payloadLen][payload bytes].
// L0Flusher parses this binary layout directly without intermediate Go structs.
func (it *SkipListIterator) Value() []byte {
	if it.current == 0 || it.current == 0xFFFFFFFF {
		return nil
	}
	valOff := it.sl.nodeValueOffset(it.current)
	valLen := it.sl.nodeValLen(it.current)
	if valOff >= uint32(len(it.sl.arena)) || valOff+valLen > uint32(len(it.sl.arena)) {
		return nil
	}
	return it.sl.arena[valOff : valOff+valLen]
}

// Next advances the iterator to the next node.
func (it *SkipListIterator) Next() {
	if it.current == 0xFFFFFFFF {
		return
	}
	it.current = it.sl.nodeNext(it.current, 0)
}

// Count returns the number of entries in the SkipList.
func (sl *SkipListArena) Count() uint32 {
	return sl.nodeCount.Load()
}

// DataSize returns the total bytes of key+value data stored.
func (sl *SkipListArena) DataSize() int64 {
	return sl.size.Load()
}

// Free releases the arena back to jemalloc.
func (sl *SkipListArena) Free() {
	sl.allocator.Free(sl.arena)
	sl.arena = nil
}

// ErrArenaFull is returned when the arena cannot allocate more nodes.
var ErrArenaFull = &ArenaFullError{}

type ArenaFullError struct{}

func (e *ArenaFullError) Error() string {
	return "skiplist arena: arena is full, trigger flush"
}
