package sync

import (
	"crypto/sha256"
	"hash/maphash"
	"math/bits"
	"sort"
	"unsafe"
)

const (
	hamtBits     = 5
	hamtWidth    = 1 << hamtBits
	hamtMask     = hamtWidth - 1
	hamtMaxDepth = 7
)

// CausalDot uniquely identifies a mutation event in the CRDT mesh.
type CausalDot struct {
	NodeID  [16]byte
	Counter uint64
}

// CRDTEntry is a single element in the Add-Wins Set lattice.
//
// ADR 10: Dot fields are flattened from the nested CausalDot struct into
// DotNodeID and DotCounter to eliminate indirection and ensure the struct
// is exactly 120 bytes with zero internal padding.
type CRDTEntry struct {
	PayloadDigest  [32]byte
	OriginNodeID   [16]byte
	DotNodeID      [16]byte
	DotCounter     uint64
	SystemTime     int64
	ValidTimeStart int64
	ValidTimeEnd   int64
	AssertionTime  int64
	DecisionTime   int64
	H3Index        uint64
}

// Dot returns the CausalDot for this entry, bridging the flat fields to
// the CausalDot type expected by compareDots and HashCausalDot.
func (e CRDTEntry) Dot() CausalDot {
	return CausalDot{NodeID: e.DotNodeID, Counter: e.DotCounter}
}

// hamtLeaf stores entries for a single entity ID at a leaf node.
//
// ADR 10: All fields are off-heap. entityPtr and entriesPtr are NodePtr
// values pointing into the mmap arena. entityLen/entriesLen are the
// element counts. This struct is exactly 32 bytes.
type hamtLeaf struct {
	hash       uint64
	entityPtr  NodePtr
	entriesPtr NodePtr
	entityLen  uint32
	entriesLen uint32
}

// makeLeaf allocates the entityID string bytes and CRDTEntry array into
// the arena and returns a hamtLeaf with off-heap pointers.
func makeLeaf(arena *HamtArena, key string, hash uint64, entries []CRDTEntry) hamtLeaf {
	entityPtr, entityLen := arena.allocString(key)
	entriesPtr, entriesLen := arena.allocCRDTEntries(entries)
	return hamtLeaf{
		hash:       hash,
		entityPtr:  entityPtr,
		entriesPtr: entriesPtr,
		entityLen:  entityLen,
		entriesLen: entriesLen,
	}
}

// copyLeaf creates an independent deep copy of a leaf's arena-allocated
// data (entity string and CRDT entry array). This is necessary when
// reusing leaves from an old node in a new node: when the old node is
// DecRef'd, its leaf data is freed, so the new node must own independent
// copies.
//
// Unlike the eradicated "Hybrid Trie" deep copy (which copied ALL trapped
// entries on every intermediate node traversal), this copy is O(1) per
// leaf and only happens during mutations at the leaf level.
func copyLeaf(arena *HamtArena, src hamtLeaf) hamtLeaf {
	dst := src
	if src.entityPtr != 0 && src.entityLen > 0 {
		b := unsafe.Slice((*byte)(toPtr(src.entityPtr)), int(src.entityLen))
		dst.entityPtr, dst.entityLen = arena.allocString(unsafe.String(&b[0], len(b)))
	}
	if src.entriesPtr != 0 && src.entriesLen > 0 {
		entries := unsafe.Slice((*CRDTEntry)(toPtr(src.entriesPtr)), int(src.entriesLen))
		dst.entriesPtr, dst.entriesLen = arena.allocCRDTEntries(entries)
	}
	return dst
}

// entityID reads the entityID string from the arena via the off-heap pointer.
func (l *hamtLeaf) entityID() string {
	if l.entityPtr == 0 || l.entityLen == 0 {
		return ""
	}
	b := unsafe.Slice((*byte)(toPtr(l.entityPtr)), int(l.entityLen))
	return unsafe.String(&b[0], len(b))
}

// crdtEntries reads the CRDTEntry slice from the arena via the off-heap pointer.
func (l *hamtLeaf) crdtEntries() []CRDTEntry {
	if l.entriesPtr == 0 || l.entriesLen == 0 {
		return nil
	}
	return unsafe.Slice((*CRDTEntry)(toPtr(l.entriesPtr)), int(l.entriesLen))
}

// HAMT is an immutable Hash Array-Mapped Trie utilizing an off-heap arena.
type HAMT struct {
	root  NodePtr
	arena *HamtArena
	seed  maphash.Seed
	count int
}

// NewHAMT constructs the empty root HAMT.
//
// STAGE 1 ZERO-GC MANDATE: The wrapper struct itself is allocated from
// the off-heap arena via `arena.allocHAMTWrapper()`, NOT the Go heap.
// This is critical for type-uniformity with HAMT.Set/Delete — the
// DeltaCRDTEngine's InsertLocal retires the OLD root state via
// `e.ebr.Retire(unsafe.Pointer(current))` and the EBR freeRetiredList
// then casts that pointer to `*HAMT` and calls `freeHAMTWrapper` on
// it. If this constructor returned a Go-heap pointer, that free would
// dereference a Go-heap address as a mmap offset and SIGSEGV. Worse,
// it would silently leak the 32-byte Go-heap struct because the EBR
// never routes it back through the slab free-list.
//
// The arena invariant `e.arena` on DeltaCRDTEngine roots the mmap'd
// arena on the Go heap for the lifetime of the engine, satisfying
// the contract documented on allocHAMTWrapper.
func NewHAMT(arena *HamtArena) *HAMT {
	res := arena.allocHAMTWrapper()
	res.root = arena.AllocNode()
	res.arena = arena
	res.seed = maphash.MakeSeed()
	res.count = 0
	return res
}

// newHAMTWithSeed constructs an empty root HAMT with a specific seed —
// used by deterministic Merkle-root tests. Same off-heap contract as
// NewHAMT.
func newHAMTWithSeed(arena *HamtArena, seed maphash.Seed) *HAMT {
	res := arena.allocHAMTWrapper()
	res.root = arena.AllocNode()
	res.arena = arena
	res.seed = seed
	res.count = 0
	return res
}

func (h *HAMT) hashKey(key string) uint64 {
	var hasher maphash.Hash
	hasher.SetSeed(h.seed)
	hasher.WriteString(key)
	return hasher.Sum64()
}

func (h *HAMT) Len() int {
	return h.count
}

func (h *HAMT) Get(entityID string) []CRDTEntry {
	hash := h.hashKey(entityID)
	res := h.root.get(entityID, hash, 0)
	return res
}

// Set returns a new HAMT with `entityID` mapped to `entries`.
//
// PATH-COPYING + ZERO-GC CONTRACT (Stage 1 — Zero-GC Microscope):
//
//	ALLOCATION #1 ELIMINATED — redundant []CRDTEntry clone.
//	  The previous implementation cloned the caller-supplied `entries`
//	  slice via `make([]CRDTEntry, len(entries))` before passing it
//	  down to `root.set`. This was a defensive copy whose contents were
//	  fully and synchronously copied into the mmap arena by makeLeaf →
//	  arena.allocCRDTEntries before Set returned — the Go-heap clone
//	  contributed zero data safety, only one extraneous heap allocation
//	  per Set. It is gone. The caller may reuse / mutate `entries` the
//	  instant Set returns, because by that point the bytes live only in
//	  mmap'd C-space.
//
//	ALLOCATION #2 ELIMINATED — result HAMT wrapper.
//	  The result *HAMT is now provisioned by `h.arena.allocHAMTWrapper()`
//	  from the segregated slab allocator inside the mmap arena, instead of
//	  `res := &HAMT{...}` which the escape analyzer moved to the Go heap.
//	  This severs the last heap-allocation source on the Set hot path.
//	  The arena pointer field inside the wrapper is GC-invisible; the
//	  arena itself stays rooted on the Go heap by the owning engine or
//	  test (see allocHAMTWrapper safety contract).
func (h *HAMT) Set(entityID string, entries []CRDTEntry) *HAMT {
	hash := h.hashKey(entityID)
	existing := h.root.get(entityID, hash, 0)
	// Pass `entries` directly: makeLeaf performs a synchronous memcpy
	// into the mmap arena via arena.allocCRDTEntries before this call
	// returns, so the caller's backing array cannot be mutated in a way
	// that would corrupt the trie.
	newRoot := h.root.set(h.arena, entityID, hash, entries, 0)

	delta := 0
	if existing == nil && len(entries) > 0 {
		delta = 1
	} else if existing != nil && len(entries) == 0 {
		delta = -1
	}

	res := h.arena.allocHAMTWrapper()
	res.root = newRoot
	res.arena = h.arena
	res.seed = h.seed
	res.count = h.count + delta
	return res
}

// Delete returns a new HAMT without `entityID`. Paired with Set in the
// Zero-GC mandate: the result wrapper is allocated from the off-heap
// arena via allocHAMTWrapper, not the Go heap.
//
// NOTE on the no-op path (key absent): this function returns `h` (the
// receiver) directly — no new wrapper is allocated, so no allocation
// occurs for that case. The returned *HAMT is the SAME pointer as the
// receiver, allowing the caller to treat both cases uniformly.
func (h *HAMT) Delete(entityID string) *HAMT {
	hash := h.hashKey(entityID)
	existing := h.root.get(entityID, hash, 0)
	if existing == nil {
		return h
	}
	newRoot := h.root.delete(h.arena, entityID, hash, 0)
	res := h.arena.allocHAMTWrapper()
	res.root = newRoot
	res.arena = h.arena
	res.seed = h.seed
	res.count = h.count - 1
	return res
}

// RootPtr returns the off-heap NodePtr of the HAMT root node. Read-only,
// exposed for the Stage 6 §2 chaos-probe (internal/chaos) so it can locate a
// live pointer to corrupt for the guaranteed off-heap SIGSEGV. Off the hot
// read/write path; Zero-GC invariants are unaffected.
func (h *HAMT) RootPtr() NodePtr { return h.root }

func (h *HAMT) ForEach(fn func(entityID string, entries []CRDTEntry) bool) {
	h.root.forEach(fn)
}

func (h *HAMT) AllEntries() []CRDTEntry {
	var result []CRDTEntry
	h.ForEach(func(_ string, entries []CRDTEntry) bool {
		result = append(result, entries...)
		return true
	})
	return result
}

func (h *HAMT) MerkleRoot() [32]byte {
	type dotPair struct {
		nodeID  [16]byte
		counter uint64
	}

	pairs := make([]dotPair, 0, h.count)
	h.ForEach(func(_ string, entries []CRDTEntry) bool {
		for i := range entries {
			pairs = append(pairs, dotPair{
				nodeID:  entries[i].DotNodeID,
				counter: entries[i].DotCounter,
			})
		}
		return true
	})

	sort.Slice(pairs, func(i, j int) bool {
		for b := 0; b < 16; b++ {
			if pairs[i].nodeID[b] != pairs[j].nodeID[b] {
				return pairs[i].nodeID[b] < pairs[j].nodeID[b]
			}
		}
		return pairs[i].counter < pairs[j].counter
	})

	var buf [24]byte
	var result [32]byte
	if len(pairs) == 0 {
		return result
	}

	h256 := sha256.New()
	for _, p := range pairs {
		copy(buf[:16], p.nodeID[:])
		buf[16] = byte(p.counter >> 56)
		buf[17] = byte(p.counter >> 48)
		buf[18] = byte(p.counter >> 40)
		buf[19] = byte(p.counter >> 32)
		buf[20] = byte(p.counter >> 24)
		buf[21] = byte(p.counter >> 16)
		buf[22] = byte(p.counter >> 8)
		buf[23] = byte(p.counter)
		h256.Write(buf[:])
	}
	copy(result[:], h256.Sum(nil))
	return result
}

// -------------------------------------------------------------------
// NodePtr methods and off-heap helpers
// -------------------------------------------------------------------

func popcount(x uint32) int {
	return bits.OnesCount32(x)
}

func (p NodePtr) node() *HamtNode {
	if p == 0 {
		return nil
	}
	return (*HamtNode)(toPtr(p))
}

func allocChildrenArray(arena *HamtArena, children []NodePtr) NodePtr {
	if len(children) == 0 {
		return 0
	}
	size := uintptr(len(children)) * unsafe.Sizeof(NodePtr(0))
	ptr := arena.allocBytes(size)
	slice := unsafe.Slice((*NodePtr)(toUintptrPtr(ptr)), len(children))
	copy(slice, children)
	return NodePtr(ptr)
}

// allocEntriesArray copies hamtLeaf structs into the arena as a
// length-prefixed contiguous block. This is a SHALLOW copy of the
// hamtLeaf structs — the caller must ensure each leaf's entityPtr and
// entriesPtr point to independently allocated arena data (via copyLeaf
// or makeLeaf) to prevent use-after-free when old nodes are DecRef'd.
func allocEntriesArray(arena *HamtArena, entries []hamtLeaf) NodePtr {
	if len(entries) == 0 {
		return 0
	}
	size := 8 + uintptr(len(entries))*unsafe.Sizeof(hamtLeaf{})
	ptr := arena.allocBytes(size)
	*(*uint64)(toUintptrPtr(ptr)) = uint64(len(entries))
	slice := unsafe.Slice((*hamtLeaf)(toUintptrPtr(ptr+8)), len(entries))
	copy(slice, entries)
	return NodePtr(ptr)
}

func getEntries(ptr NodePtr) []hamtLeaf {
	if ptr == 0 {
		return nil
	}
	l := *(*uint64)(toPtr(ptr))
	return unsafe.Slice((*hamtLeaf)(toUintptrPtr(uintptr(ptr)+8)), int(l))
}

func getChildren(ptr NodePtr, count int) []NodePtr {
	if ptr == 0 || count == 0 {
		return nil
	}
	return unsafe.Slice((*NodePtr)(toPtr(ptr)), count)
}

func incRefChildren(arena *HamtArena, childrenPtr NodePtr, count int) {
	if childrenPtr != 0 && count > 0 {
		children := getChildren(childrenPtr, count)
		for _, child := range children {
			arena.IncRef(child)
		}
	}
}

func (p NodePtr) get(key string, hash uint64, depth int) []CRDTEntry {
	if p == 0 {
		return nil
	}
	n := p.node()

	// Leaf node: entries present, no children
	leaves := getEntries(n.entriesPtr)
	if len(leaves) > 0 {
		for i := range leaves {
			if leaves[i].entityID() == key {
				return leaves[i].crdtEntries()
			}
		}
		return nil
	}

	// Intermediate node: descend by hash segment
	if depth >= hamtMaxDepth {
		return nil
	}

	idx := (hash >> (uint(depth) * hamtBits)) & hamtMask
	bit := uint32(1) << idx

	if n.bitmap&bit == 0 {
		return nil
	}

	pos := popcount(n.bitmap & (bit - 1))
	children := getChildren(n.childrenPtr, popcount(n.bitmap))
	return children[pos].get(key, hash, depth+1)
}

// -------------------------------------------------------------------
// MANDATE 1: set() — mathematically correct HAMT with NO trapped entries
// -------------------------------------------------------------------
//
// A correct HAMT intermediate node holds ONLY children (entriesPtr = 0).
// When a collision occurs at a leaf (a new key must be inserted into a
// leaf that doesn't contain it), the existing entries and the new entry
// are pushed DOWN into deeper child leaves via distributeLeaves().
// Intermediate nodes never carry entriesPtr.

func (p NodePtr) set(arena *HamtArena, key string, hash uint64, entries []CRDTEntry, depth int) NodePtr {
	if p == 0 {
		return 0
	}
	n := p.node()

	// --- LEAF NODE: has entries, no children ---
	if n.entriesPtr != 0 {
		oldLeaves := getEntries(n.entriesPtr)
		if len(oldLeaves) > 0 {
			for i := range oldLeaves {
				if oldLeaves[i].entityID() == key {
					return p.updateLeafEntry(arena, oldLeaves, i, key, hash, entries)
				}
			}

			// Key not found in this leaf — need to expand
			if len(entries) == 0 {
				return p // nothing to delete
			}

			// Expand: push existing node and new entry down into a subtree
			return p.setCollision(arena, oldLeaves[0].hash, key, hash, entries, depth)
		}
	}

	// --- INTERMEDIATE NODE: has children, entriesPtr MUST be 0 ---

	idx := (hash >> (uint(depth) * hamtBits)) & hamtMask
	bit := uint32(1) << idx
	pos := popcount(n.bitmap & (bit - 1))

	if n.bitmap&bit == 0 {
		// No child at this position — create a new leaf
		if len(entries) == 0 {
			return p
		}

		var oneScratch [1]hamtLeaf
		oneScratch[0] = makeLeaf(arena, key, hash, entries)
		leafPtr := arena.AllocNode()
		leaf := leafPtr.node()
		leaf.entriesPtr = allocEntriesArray(arena, oneScratch[:])

		newNodePtr := arena.AllocNode()
		newNode := newNodePtr.node()
		newNode.bitmap = n.bitmap | bit

		oldChildren := getChildren(n.childrenPtr, popcount(n.bitmap))
		// MANDATE 3: stack-allocated scratch array — zero heap allocations
		var childScratch [hamtWidth]NodePtr
		newChildren := childScratch[:len(oldChildren)+1]
		copy(newChildren[:pos], oldChildren[:pos])
		newChildren[pos] = leafPtr
		copy(newChildren[pos+1:], oldChildren[pos:])

		for _, child := range oldChildren {
			arena.IncRef(child)
		}

		newNode.childrenPtr = allocChildrenArray(arena, newChildren)
		// MANDATE 1: intermediate nodes hold ONLY children
		newNode.entriesPtr = 0

		return newNodePtr
	}

	// Child exists — recurse
	oldChildren := getChildren(n.childrenPtr, popcount(n.bitmap))
	childPtr := oldChildren[pos]
	newChildPtr := childPtr.set(arena, key, hash, entries, depth+1)

	if newChildPtr == childPtr {
		return p
	}

	// Child was deleted — remove it from bitmap and children
	if newChildPtr == 0 {
		newNodePtr := arena.AllocNode()
		newNode := newNodePtr.node()
		newNode.bitmap = n.bitmap &^ bit

		var childScratch [hamtWidth]NodePtr
		newChildren := childScratch[:len(oldChildren)-1]
		copy(newChildren[:pos], oldChildren[:pos])
		copy(newChildren[pos:], oldChildren[pos+1:])

		for i, child := range oldChildren {
			if i != pos {
				arena.IncRef(child)
			}
		}

		if newNode.bitmap == 0 {
			return 0
		}

		newNode.childrenPtr = allocChildrenArray(arena, newChildren)
		newNode.entriesPtr = 0
		return newNodePtr
	}

	// Normal: replace child with updated version
	newNodePtr := arena.AllocNode()
	newNode := newNodePtr.node()
	newNode.bitmap = n.bitmap

	var childScratch [hamtWidth]NodePtr
	newChildren := childScratch[:len(oldChildren)]
	copy(newChildren, oldChildren)
	newChildren[pos] = newChildPtr

	for i, child := range oldChildren {
		if i != pos {
			arena.IncRef(child)
		}
	}

	newNode.childrenPtr = allocChildrenArray(arena, newChildren)
	// MANDATE 1: intermediate nodes hold ONLY children
	newNode.entriesPtr = 0

	return newNodePtr
}

// updateLeafEntry creates a new leaf node with the entry at idx updated or removed.
// Old leaves (other than idx) are deep-copied via copyLeaf to ensure independent
// arena data ownership.
func (p NodePtr) updateLeafEntry(arena *HamtArena, oldLeaves []hamtLeaf, idx int, key string, hash uint64, entries []CRDTEntry) NodePtr {
	if len(entries) == 0 {
		// Delete entry at idx
		if len(oldLeaves) == 1 {
			return 0
		}
		newLeaves := make([]hamtLeaf, 0, len(oldLeaves)-1)
		for i := range oldLeaves {
			if i != idx {
				newLeaves = append(newLeaves, copyLeaf(arena, oldLeaves[i]))
			}
		}
		newNodePtr := arena.AllocNode()
		newNode := newNodePtr.node()
		newNode.entriesPtr = allocEntriesArray(arena, newLeaves)
		return newNodePtr
	}

	// Update entry at idx
	newLeaves := make([]hamtLeaf, len(oldLeaves))
	for i := range oldLeaves {
		if i == idx {
			newLeaves[i] = makeLeaf(arena, key, hash, entries)
		} else {
			newLeaves[i] = copyLeaf(arena, oldLeaves[i])
		}
	}
	newNodePtr := arena.AllocNode()
	newNode := newNodePtr.node()
	newNode.entriesPtr = allocEntriesArray(arena, newLeaves)
	return newNodePtr
}

// appendToCollision adds a new entry to a collision node (used at maxDepth).
// Old leaves are deep-copied via copyLeaf to ensure independent arena data ownership.
func (p NodePtr) appendToCollision(arena *HamtArena, oldLeaves []hamtLeaf, key string, hash uint64, entries []CRDTEntry) NodePtr {
	if len(entries) == 0 {
		return p
	}

	newLeaves := make([]hamtLeaf, len(oldLeaves)+1)
	for i := range oldLeaves {
		newLeaves[i] = copyLeaf(arena, oldLeaves[i])
	}
	newLeaves[len(oldLeaves)] = makeLeaf(arena, key, hash, entries)

	newNodePtr := arena.AllocNode()
	newNode := newNodePtr.node()
	newNode.entriesPtr = allocEntriesArray(arena, newLeaves)
	return newNodePtr
}

// setCollision handles a hash collision at a leaf node by building a subtree
// of intermediate nodes until the hash segments diverge, then placing the old
// leaf and the new leaf as distinct children.
func (p NodePtr) setCollision(arena *HamtArena, oldHash uint64, newKey string, newHash uint64, newEntries []CRDTEntry, depth int) NodePtr {
	if depth >= hamtMaxDepth {
		// At max depth, hashes completely collide. Merge into a single collision leaf node.
		oldLeaves := getEntries(p.node().entriesPtr)
		return p.appendToCollision(arena, oldLeaves, newKey, newHash, newEntries)
	}

	idxOld := (oldHash >> (uint(depth) * hamtBits)) & hamtMask
	idxNew := (newHash >> (uint(depth) * hamtBits)) & hamtMask

	newNodePtr := arena.AllocNode()
	newNode := newNodePtr.node()

	if idxOld == idxNew {
		// Still colliding at this depth. Recurse deeper.
		childPtr := p.setCollision(arena, oldHash, newKey, newHash, newEntries, depth+1)
		newNode.bitmap = uint32(1) << uint(idxOld)
		var childScratch [1]NodePtr
		childScratch[0] = childPtr
		newNode.childrenPtr = allocChildrenArray(arena, childScratch[:])
		newNode.entriesPtr = 0
		return newNodePtr
	}

	// Hashes diverge here. Create an intermediate node with two leaf children.
	// 1. The new leaf node
	var oneScratch [1]hamtLeaf
	oneScratch[0] = makeLeaf(arena, newKey, newHash, newEntries)
	newLeafPtr := arena.AllocNode()
	newLeafNode := newLeafPtr.node()
	newLeafNode.entriesPtr = allocEntriesArray(arena, oneScratch[:])

	// 2. The old leaf node (reused completely via IncRef)
	arena.IncRef(p)

	newNode.bitmap = (uint32(1) << uint(idxOld)) | (uint32(1) << uint(idxNew))
	var childScratch [2]NodePtr
	if idxOld < idxNew {
		childScratch[0] = p
		childScratch[1] = newLeafPtr
	} else {
		childScratch[0] = newLeafPtr
		childScratch[1] = p
	}
	newNode.childrenPtr = allocChildrenArray(arena, childScratch[:2])
	newNode.entriesPtr = 0
	return newNodePtr
}

func (p NodePtr) delete(arena *HamtArena, key string, hash uint64, depth int) NodePtr {
	return p.set(arena, key, hash, nil, depth)
}

func (p NodePtr) forEach(fn func(entityID string, entries []CRDTEntry) bool) bool {
	if p == 0 {
		return true
	}
	n := p.node()

	// Leaf node
	leaves := getEntries(n.entriesPtr)
	if len(leaves) > 0 {
		for i := range leaves {
			if !fn(leaves[i].entityID(), leaves[i].crdtEntries()) {
				return false
			}
		}
		return true
	}

	// Intermediate node
	children := getChildren(n.childrenPtr, popcount(n.bitmap))
	for _, childPtr := range children {
		if !childPtr.forEach(fn) {
			return false
		}
	}
	return true
}
