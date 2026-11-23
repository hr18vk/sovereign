// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

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

// CRDTEntry is a single element in the Add-Wins Set lattice. Its dot fields
// are flattened to avoid indirection; the 120-byte layout has no internal
// padding.
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

// hamtLeaf stores entries for one entity ID. The key and entries live in the
// mmap arena; entityPtr and entriesPtr locate them, and the length fields hold
// their byte and element counts respectively. The struct occupies 32 bytes.
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

// copyLeaf copies a leaf's key and entries into fresh arena allocations. The
// new node must own these copies because decrementing the old node's reference
// count eventually releases its leaf data. Copying is confined to leaves on a
// mutation path.
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

// NewHAMT constructs an empty HAMT whose wrapper and root are allocated in
// the arena. InsertLocal retires roots through EBR, which releases their
// wrappers with freeHAMTWrapper; a Go-heap wrapper would make that path treat
// a heap address as an arena offset and would not return the wrapper to its
// slab. DeltaCRDTEngine.arena keeps the mmap-backed allocator reachable for
// the lifetime of these wrappers.
func NewHAMT(arena *HamtArena) *HAMT {
	res := arena.allocHAMTWrapper()
	res.root = arena.AllocNode()
	res.arena = arena
	res.seed = maphash.MakeSeed()
	res.count = 0
	return res
}

// newHAMTWithSeed constructs an empty HAMT with a fixed hash seed for
// deterministic Merkle-root tests. It has the same arena ownership contract
// as NewHAMT.
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

// Set returns a new HAMT with entityID mapped to entries. It path-copies the
// affected nodes and allocates the result wrapper in the arena. makeLeaf
// synchronously copies entries into the arena, so the caller may reuse or
// mutate its slice after Set returns. The caller must keep the arena reachable
// from the Go heap because the off-heap wrapper's arena pointer is invisible
// to the collector.
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

// Delete returns a new HAMT without entityID. As in Set, the result wrapper
// comes from the arena. If the key is absent, Delete returns the receiver
// unchanged and does not allocate a wrapper.
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

// RootPtr returns the root's arena address. The crash tests in internal/chaos
// use it to locate off-heap memory for a fault-injection dereference. It is
// read-only and is not used by HAMT reads or mutations.
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

// allocEntriesArray copies leaf descriptors into a length-prefixed arena
// block. It does not copy their keys or entries: the caller must use copyLeaf
// or makeLeaf so each leaf owns independent data after the old node is
// released.
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

// Intermediate nodes contain children, not leaf entries. A collision at a
// leaf builds deeper nodes until the old and new keys occupy different child
// positions; entries remain in leaf nodes throughout the path copy.

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

	// --- Intermediate node: has children, entriesPtr must be 0 ---

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
		// A fixed-size stack scratch array avoids a Go heap allocation.
		var childScratch [hamtWidth]NodePtr
		newChildren := childScratch[:len(oldChildren)+1]
		copy(newChildren[:pos], oldChildren[:pos])
		newChildren[pos] = leafPtr
		copy(newChildren[pos+1:], oldChildren[pos:])

		for _, child := range oldChildren {
			arena.IncRef(child)
		}

		newNode.childrenPtr = allocChildrenArray(arena, newChildren)
		// Intermediate nodes hold only children
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
	// Intermediate nodes hold only children
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
