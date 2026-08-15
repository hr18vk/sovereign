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
	keySize       = 40 // Override 8.4: 16B hash + 8B system + 8B valid + 8B assertion
	nodeNextStart = 20 // byte offset where Next[] array begins in node
	keyHashLen    = 16 // Override 8.4: 128-bit hash prefix (was 8)
)

// Ensure architectural constants remain in the AST for future sprint consumption.
var (
	_ = offsetNil
	_ = keyHashLen
)

// SkipListArena is a pointerless, array-backed concurrent SkipList.
// All memory is off-heap (jemalloc). The Go GC sees zero pointers.
//
// The arena layout:
//
//	[0..nodeSize)             = head sentinel node
//	[nodeSize..nodeSize*N)    = allocated nodes
//	[...                      = key/value data region (grows from end)
//
// Override 7.1: sync.RWMutex REMOVED. The SkipList is now fully lock-free.
// Concurrent inserts use CAS-based splicing on 32-bit arena offsets.
// This matches the Sprint Directive mandate: "lock-free Compare-And-Swap (CAS)"
// and the Research Document: "Concurrency: Lock-free CAS on offsets".
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

// nodeValLen reads the value length for the node (Override O2.1).
func (sl *SkipListArena) nodeValLen(offset uint32) uint32 {
	return binary.LittleEndian.Uint32(sl.arena[offset+16 : offset+20])
}

// nodeNext atomically reads the next-node offset at the given level.
// Override 7.1: Uses atomic.LoadUint32 for safe lock-free concurrent reads.
func (sl *SkipListArena) nodeNext(offset uint32, level int) uint32 {
	off := offset + uint32(nodeNextStart) + uint32(level)*4
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&sl.arena[off])))
}

// setNodeNext stores the next-node offset at the given level.
// ONLY safe during node initialization (before the node is visible to readers).
func (sl *SkipListArena) setNodeNext(offset uint32, level int, next uint32) {
	off := offset + uint32(nodeNextStart) + uint32(level)*4
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&sl.arena[off])), next)
}

// casNodeNext atomically compares-and-swaps the next-node offset at the given level.
// Override 7.1: This is the core lock-free primitive for concurrent splicing.
// Returns true if the swap succeeded (old value matched `expected`).
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

// Override 5.4: SkipList Arena Wrap-Around Panic (CAS-bounded allocation)
func (sl *SkipListArena) allocNode(height uint32, keyLen, valLen uint32) (uint32, uint32, error) {
	// Prevent uint32 wrap-around and allocate node space (grows upward).
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
	binary.LittleEndian.PutUint32(sl.arena[nodeOff+16:nodeOff+20], valLen) // O2.1: store value length

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
// The key must be the 32-byte tri-temporal composite key.
// The valFn writes the packed event data directly into the arena (Zero-GC).
//
// Override 7.1: TRUE LOCK-FREE implementation using CAS-based splicing.
// No sync.Mutex or sync.RWMutex. Multiple goroutines can insert concurrently.
// Algorithm: Find predecessors at each level, then splice using CAS.
// If a CAS fails (concurrent insert modified a predecessor's next pointer),
// re-search from the predecessor at that level and retry.
// This is the same algorithm used by CockroachDB's arenaskl and Badger's skiplist.
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

	// Phase 1: Find predecessors and successors at all levels.
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

	// Phase 2: CAS-splice at each level from bottom to top.
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

// Seek returns an iterator positioned at the LOWER-BOUND of target: the first
// node whose composite key >= target. It is NOT a point lookup — the returned
// node's key is >= target; if target > all keys the iterator is exhausted
// (Valid()==false, current == the 0xFFFFFFFF end-of-list sentinel).
//
// Seek IS the Put descent WITHOUT the splice (skiplist_arena.go Put:236-250):
// top->bottom, advance while bytes.Compare(nextKey, target) < 0, break on >= OR
// the 0xFFFFFFFF end-of-level sentinel. The descent visits the SAME nodes in
// the SAME order as Put's search phase; the ONLY difference is Seek stores no
// prev[i]/next[i] for i>0 (it needs just prev[0] — the level-0 predecessor of
// the lower-bound). The returned iterator's current is nodeNext(prev[0], 0) =
// the first node whose key >= target. If target <= the first key, prev[0] is
// the head (x stayed 0) + current = nodeNext(0, 0) — the SAME node NewIterator
// returns (byte-identity with the full-scan lower-bound).
//
// CONCURRENCY (Override 7.1): Seek is LOCK-FREE. It takes no mutex + no
// allocator lock; it reads nodeNext via the SAME atomic.LoadUint32 path Put's
// search uses. Put's search is correct under concurrent inserts ONLY because
// its Phase-2 CAS-splice FAILS + re-searches when a predecessor's next moved
// (skiplist_arena.go Put:273-287) — the CAS is the self-correction. A READ-ONLY
// descent has no CAS to detect a moved predecessor, so the multi-level descent
// can observe a transiently-inconsistent snapshot: the high-level predecessor
// prev[0] may reach a level-0 successor whose key is < target at the read
// moment (a concurrent Put's bottom-up splice linked a node between the
// descent's high-level view + the level-0 read; the per-step key comparison
// can read a transient over the still-settling level-0 chain). A NAIVE
// `nodeNext(prev[0], 0)` can therefore return a node whose key is < target — a
// LOWER-BOUND VIOLATION (the §0.c sentinel class fires when target > all keys:
// the descent returns the last node instead of the sentinel). This was PROVEN
// empirically (T-SEEK-CONCURRENT caught it before the fix: ~1-2% of seeks
// returned a node < target under a 100k-key concurrent Put workload; the
// level-0-only linear scan NEVER violated — only the multi-level descent did).
//
// THE FIX (honest, lock-free): after the descent, VERIFY the level-0 result —
// current is accepted iff it is the sentinel OR nodeKey(current) >= target. If
// the descent produced a stale node (key < target), Seek falls back to a FRESH
// level-0 linear walk from head (seekLowerBoundLinear). The level-0 chain is
// the STABLE total order — a node is linked at level 0 only after its
// predecessor (bottom-up splice), so a level-0 walk from head never returns a
// node < target (the keys are monotone along the chain; the first >= target is
// the lower-bound, the sentinel if target > all). The fallback makes Seek's
// RESULT a valid lower-bound under concurrency at the cost of an O(N) re-walk
// on the rare transient (~1-2% of seeks under a heavy concurrent writer). On a
// QUIESCENT skiplist — the production precondition (Seek's only consumer today
// is l0_flusher.go:198 FlushArenaToIPC over a FROZEN arena; the intended Range
// wiring reads frozen/durable data) — the descent is consistent, the fallback
// NEVER fires, and Seek is O(maxHeight) (the §6.c capped-asymptotic).
//
// WINDOW LOWER-BOUND TARGET SHAPE: the skiplist does NOT know the schema; the
// CALLER builds a 40-byte target [entityHash16 | sysTimeFloor8 | vLo8 | 0]
// (the assertion field zeroed — the minimum — so the lower-bound is the FIRST
// row of the entity at-or-after validTimeStart=vLo, any assertion, any sysTime
// >= floor). Seek skips the rows before the window's low end in O(maxHeight)
// (quiescent) rather than scanning them at O(N) (the gain this primitive exists
// for).
//
// ALLOCATION: the descent reads nodeKey (a zero-copy slice header into the
// arena — nodeKey returns arena[off:off+len], NOT a copy). Seek allocates the
// ONE *SkipListIterator struct it returns (the NewIterator precedent — the
// disclosed read-path residual, NOT the write-path zero-alloc gate); the
// per-descent-step count is 0. A target built as a stack [keySize]byte + slice
// header (the memtable.go:159 precedent) keeps the target off the heap.
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
	// x is prev[0] — the level-0 predecessor of the lower-bound. nodeNext(x, 0)
	// is the first node whose key >= target (the LOWER-BOUND), or 0xFFFFFFFF if
	// target > all keys (the sentinel Valid() checks).
	cur := sl.nodeNext(x, 0)
	// HONEST CONCURRENCY GUARD (see the doc above): a read-only multi-level
	// descent has no CAS to self-correct a moved predecessor, so the result can
	// transiently be a node whose key < target. Verify + fall back to the
	// level-0 linear walk (the stable total order) when that happens. The guard
	// is a no-op on a quiescent skiplist (the production precondition).
	if cur != 0xFFFFFFFF && bytes.Compare(sl.nodeKey(cur), target) < 0 {
		cur = sl.seekLowerBoundLinear(target)
	}
	return &SkipListIterator{sl: sl, current: cur}
}

// seekLowerBoundLinear is the O(N) level-0-only lower-bound: a fresh walk from
// head returning the offset of the first node whose key >= target, or 0xFFFFFFFF
// if target > all keys. The level-0 chain is the STABLE total order (a node is
// linked at level 0 only after its predecessor — the bottom-up splice), so this
// walk is a valid lower-bound even under concurrent Puts (the multi-level
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
// constructor. Equivalent to `sl.Seek(target)`. A FRESH iterator is returned
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
// Layout: [16B hash][8B sysTime][8B validTime][8B assertTime] = 40 bytes
// (Override 8.4: the 128-bit hash prefix; was 8B/32B pre-Override).
func (it *SkipListIterator) Key() []byte {
	return it.sl.nodeKey(it.current)
}

// Value returns the current node's raw value bytes (Override 4.1).
// Layout: [2B entityIDLen][entityID string][8B H3Index][8B ValidTimeEnd][4B payloadLen][payload bytes].
// The L0Flusher parses this binary layout directly — zero intermediate Go structs.
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
