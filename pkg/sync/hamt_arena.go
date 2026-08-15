package sync

import (
	"math/bits"
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

	// Cached Merkle branch hash. Mutations path-copy nodes and recompute this
	// field only along the affected HAMT path, making MerkleRoot() O(1).
	merkleHash [32]byte

	// Intrusive pointer for the lock-free free-list.
	// When a node is dead (refCount == 0), the first 8 bytes of this
	// region store the uint64 next-offset for the Treiber stack.
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

// arenaNodeFreelistShardCount is the number of Treiber free-list shards the
// HamtArena dedicates to the class-0 (72-byte HamtNode) pool. Phase 2.5a
// collapsed the engine root into N=256 per-entityID CAS shards and surfaced the
// relocated CAS storm: every per-shard Set path-allocates a fresh HamtNode via
// the SINGLE HamtArena freeHeads[0] Treiber head, which at GOMAXPROCS=32 became
// the new hot stripe (76.47% of CPU cum in sync/atomic.(*Uint64).CompareAndSwap,
// 92% of it inside AllocNode's freeHeads[0].head.CompareAndSwap).
//
// Sharding the class-0 freelist mirrors the byte-faithful precedent shipped in
// Phase 2.5a (crdt.go's shards []shardRoot): each class-0 shard owns its own
// cache-line-padded atomic head, so 32 cores allocating HamtNodes spread across
// 256 heads instead of contending on one. 256 is a power of two (routing is a
// clean bitmask & (arenaNodeFreelistShardCount-1)), matches the engine shard
// count, and is >= any realistic GOMAXPROCS (32-core peak -> 8x cache lines to
// spread across). A real-traffic Phase 3 may surface a better cardinality (a
// 1:1 engine-shard-to-freelist-shard mapping may be optimal on heterogeneous
// engine workloads); this is the honest, reasoned default, not a tuned value.
//
// A const (not a runtime setter) is chosen deliberately: the gate turns on the
// SHAPE (sharded nodeFreelist + routeNodeFreelistShard + per-shard CAS), not on
// a runtime knob, and a const keeps R1's blast radius minimal and the diff
// reviewable (the setter precedent in crdt.go's SetShardCount exists for the
// engine root, which has a persistMu re-root path; the arena has no such mutex
// and the const shape is simpler and safer here).
const arenaNodeFreelistShardCount = 256

// arenaVarFreelistShardCount is the number of Treiber free-list shards the
// HamtArena dedicates to EACH VARIABLE size class (1..numVarClasses). Phase
// 2.5a.1 carried the var-alloc CAS concentrate forward as recorded 7% of CPU at
// GOMAXPROCS=4 (R1f). Phase 2.5d S1 re-measured this at GOMAXPROCS=32 under a
// heavy JoinParallel bench: allocVar/freeHeads[classIdx].head.CompareAndSwap
// rose to 57.91% cum (94.48s) — the dominant concentrate at 32c under Join
// traffic. 2.5d closes it by mirroring the 2.5a/2.5a.1 256-way sharding
// pattern: every var class now owns a [256]slabFreeHead shard array, the
// routing counter is bumped OUTSIDE the CAS retry loop, and freeHeads[classIdx]
// is preserved as the per-class cold-path fallback (two-tier pop/push,
// byte-faithful to the 2.5a.1 freeHeads[0]→nodeFreelist[i] pattern). Power-of-
// two (256) keeps the route a clean & (N-1) bitmask, matches the engine shard
// count, and matches the proved-good 2.5a/2.5a.1 cardinality. The same const-
// not-setter discipline as arenaNodeFreelistShardCount (R1g of 2.5a.1) applies.
const arenaVarFreelistShardCount = 256

// arenaVarFreelistSweep is the bounded number of shards allocVar probes per
// call before falling through to the bump allocator. The pop-routed shard may
// be empty even when OTHER shards for the same class hold recycled blocks
// (freeVar routes on a SEPARATE counter — pop and push visit shards in
// counter-phase over time). Without a sweep, a pop landing on an empty routed
// shard bumps — and at steady state over 20K ops, that initial lag accumulates
// into a 1.4 GB bump-offset leak (S1 measured; pre-sweep). The bounded sweep
// probes the routed shard + the next (arenaVarFreelistSweep-1) shards for this
// class, all under ONE EBR pin taken before the sweep. 64 is chosen because
// under steady-state the per-shard emptiness probability is a function of the
// push/pop counter-phase drift; 8 reduced leak 5× but residual leak exceeded
// the 64 MiB gate. The leak scales inversely with sweep size — doubling the
// sweep squares the cold-fallback probability. 64 yields 256/64 = 4× full-class
// sweeps per round, exponential reduction. Power-of-two so the
// (start+probe)&(N-1) bitmask routing wraps cleanly.
const arenaVarFreelistSweep = 128

// hamtNodeFreelistShards is the sharded class-0 (72-byte HamtNode) Treiber
// free-list. It REPLACES the single freeHeads[0] slot as the hot allocation
// surface for HamtNode; freeHeads[0] is kept as a vestigial slot only because
// the [numSizeClasses]slabFreeHead cartesian layout is shared with the
// variable-size classes (1..16), which are left byte-identical (R1f: allocVar/
// pushFreeVar carry only 7% of CPU — below the 43% CAS gate). Each entry is its
// own CacheLinePad-wrapped slabFreeHead, so the 256 shards live on distinct
// cache lines — byte-faithful to crdt.go's shards []shardRoot.
type hamtNodeFreelistShards [arenaNodeFreelistShardCount]slabFreeHead

// varFreelistShards is the sharded variable-size Treiber free-list type. Each
// of the numVarClasses (=16) variable classes owns an independent 256-shard
// array of slabFreeHead. slabFreeHead.head is atomic.Uint64 (offsets), the SAME
// offset-Treibier shape as the class-0 nodeFreelist — byte-identical signature
// so the allocVar / freeVar CAS frames are byte-faithful to AllocNode /
// pushFreeNode modulo the class-indexed cartesian outer dimension. The two-tier
// pop (shard first, freeHeads[classIdx] as cold-path fallback) mirrors the
// 2.5a.1 freeHeads[0]→nodeFreelist[i] pattern. R1a declares this type; the
// arena struct field below owns the instance.
type varFreelistShards [numVarClasses][arenaVarFreelistShardCount]slabFreeHead

// HamtArena is a concurrent, zero-GC, off-heap allocator for HAMT nodes
// and variable-sized arrays.
//
// ADR 9: Upgraded from single freeHead to segregated slab allocator.
// Class 0 is dedicated to 72-byte HamtNode slots (zero fragmentation).
// Classes 1-16 are power-of-2 geometric classes for variable allocations
// (children arrays, entries arrays, strings, CRDT entry arrays).
//
// ABA immunity is provided by the EBRManager: blocks are deferred via
// RetireBlock() and only recycled when the global epoch proves zero
// lingering readers.
type HamtArena struct {
	_ CacheLinePad
	// freeHeads[0]  = dedicated 72-byte HamtNode class
	// freeHeads[1]  = 16-byte class
	// freeHeads[2]  = 32-byte class
	// freeHeads[3]  = 64-byte class
	// ...
	// freeHeads[16] = 524288-byte class
	freeHeads [numSizeClasses]slabFreeHead
	// nodeFreelist is the sharded class-0 (72-byte HamtNode) Treiber free-list.
	// It REPLACES freeHeads[0] as the hot HamtNode allocation surface (Phase
	// 2.5a.1): freeHeads[0] is kept only to preserve the [numSizeClasses]
	// cartesian layout shared with the variable-size classes 1..16, which
	// are left byte-identical (R1f). Every AllocNode/pushFreeNode now routes
	// through nodeFreelist[routeNodeFreelistShard()] — a per-shard
	// cache-line-padded head, byte-faithful to crdt.go's shards []shardRoot.
	nodeFreelist hamtNodeFreelistShards
	// nodeFreelistRoutePop is the per-call routing counter for the POP side
	// (AllocNode). Each AllocNode call advances it by 1 ONCE — OUTSIDE the
	// CAS retry loop (R1d mandate) — and masks with
	// (arenaNodeFreelistShardCount-1) to pick a shard. Routed per-call (not
	// per-CAS-retry) so the counter increment never enters the hot CAS frame
	// Tier-2's G3 <=43% gate polices. CacheLinePad-isolated from the other
	// atomics so the routing counter's own writes do not false-share with
	// bumpOffset or a shard head.
	_                  CacheLinePad
	nodeFreelistRoutePop atomic.Uint64
	_                  CacheLinePad
	// nodeFreelistRoutePush is the per-call routing counter for the PUSH side
	// (pushFreeNode, invoked from EBR RetireBlock processing). A SEPARATE
	// counter from the pop counter: push and pop may execute on different
	// goroutines (the popper is the allocating worker; the pusher is the EBR
	// epoch-advance reclaimer), so a shared counter would itself become a hot
	// stripe between the two paths. The push/pop asymmetry is SAFE because
	// every nodeFreelist shard services the same 72-byte class-0 HamtNode (a
	// pop from shard A and a push to shard B is benign); EBR's global epoch
	// retains the ABA guarantee (see §2 of PHASE_25A1_REPORT.md).
	_                   CacheLinePad
	nodeFreelistRoutePush atomic.Uint64
	_                   CacheLinePad
	// varFreelist is the sharded variable-size Treiber free-list (Phase
	// 2.5d). It REPLACES the per-class freeHeads[classIdx] (classIdx 1..16)
	// hot path with a 256-way sharded Treiber head array, mirroring the
	// 2.5a.1 nodeFreelist pattern. freeHeads[classIdx] is kept as the per-
	// class cold-path FALLBACK (two-tier pop/push): try shard first, fall
	// back to freeHeads[classIdx] when the routed shard is empty (pop) or
	// use it as the fallback push target when the routed shard push is
	// cold-path. Each entry is its own CacheLinePad-wrapped slabFreeHead,
	// byte-identical offset-Treiber shape to nodeFreelist shards.
	varFreelist varFreelistShards
	// varFreelistRoutePop is the per-call routing counter for the POP side
	// (allocVar). Advanced by 1 ONCE per call — OUTSIDE the CAS retry loop
	// (R1d mandate). CacheLinePad-isolated so the routing counter's writes
	// do not false-share with the shard heads or bumpOffset. The pop is
	// routed per-call (NOT per-CAS-retry) so the increment can never land in
	// the hot CAS frame.
	_                    CacheLinePad
	varFreelistRoutePop  atomic.Uint64
	_                    CacheLinePad
	// varFreelistRoutePush is the asymmetric twin of the pop router for the
	// PUSH side (freeVar, invoked from EBR RetireBlock processing — variable
	// blocks are reclaimed by the epoch-advance reclaimer goroutine, NOT
	// the allocating worker). A SEPARATE counter from the pop counter keeps
	// the two routing streams independent — the same 2.5a.1 push/pop
	// asymmetry discipline. The asymmetry is SAFE: every varFreelist shard
	// services the SAME size class (blockSizeForClass), so a pop from shard
	// A and a push to shard B is benign; EBR's global epoch retains the ABA
	// guarantee across the sharding (see §2 of PHASE_25A1_REPORT.md).
	_                     CacheLinePad
	varFreelistRoutePush  atomic.Uint64
	_                     CacheLinePad
	// bumpOffset tracks the high-water mark of the arena in bytes.
	// Starts at nodeSize to reserve offset 0 as NullOffset64 sentinel.
	bumpOffset atomic.Uint64
	_          CacheLinePad
	base       uintptr
	size       uintptr
	// ebr manages safe epoch-based deferred reclamation of offsets.
	ebr *EBRManager
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
	// R1b: initialize the sharded class-0 HamtNode freelist (mirrors the
	// freeHeads init above). Every class-0 shard head starts empty; the
	// routing counters default to 0 (atomic.Uint64 zero value) so the first
	// AllocNode routes to shard 0 and the first pushFreeNode to shard 0 —
	// Stripe 0 is no busier than any other under steady state because each
	// call bumps the counter by 1 before masking.
	for i := range arena.nodeFreelist {
		arena.nodeFreelist[i].head.Store(NullOffset64)
	}
	// R1b (2.5d): initialize the sharded variable-size freelist. Each of
	// numVarClasses (=16) classes owns an [arenaVarFreelistShardCount]slabFreeHead
	// shard array; every shard head starts empty (NullOffset64). The route
	// counters default to 0 (atomic.Uint64 zero value) so the first allocVar
	// routes to shard 0 and the first freeVar to shard 0 — stripe 0 is no
	// busier than any other under steady state because each call bumps the
	// counter by 1 before masking.
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

// Base returns the raw mmap base address of the off-heap arena.
//
// STAGE 6 §2 chaos-probe seam: the decoupled Worker crash-probe (internal/chaos)
// needs read-only access to the arena's base/size so it can construct a guaranteed-
// faulting dereference entirely within off-heap C-space — the unrecoverable SIGSEGV
// the Supervisor must observe and recover from via the WAL. This accessor is the
// minimum surface that makes that possible without exporting NodePtr arithmetic or
// the whole free-list internals. It is read-only and off the hot path, so the
// Zero-GC invariants proven by Stage 1 are hermetically untouched.
func (a *HamtArena) Base() uintptr { return a.base }

// Size returns the total mapped byte size of the off-heap arena.
func (a *HamtArena) Size() uintptr { return a.size }

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
// CRITICAL: size == 0 is explicitly handled to prevent underflow panic.
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

// AllocNode provisions a new HamtNode, preferring recycled memory from the
// lock-free Treiber free-list (class 0) before falling back to the bump allocator.
//
// routeNodeFreelistShard picks the class-0 HamtNode freelist shard this
// AllocNode call should POP from. It is the byte-faithful sibling of the engine's
// routeShard (crdt.go): instead of maphash(entityID) & (N-1), it routes by a per-
// call atomic counter advanced by 1 OUTSIDE the CAS retry loop and masked by
// (arenaNodeFreelistShardCount-1) — a clean power-of-two bitmask route with no
// modulo. Routed per-CALL (not per-CAS-retry) so the counter increment can never
// land in the hot CAS frame Tier-2's G3 <=43% gate polices; the CAS loop body is
// byte-identical in shape to the pre-R1 loop, just over a per-shard head instead
// of freeHeads[0].head.
//
// Per-goroutine vs per-counter: the standard proc-pin would tie a goroutine to
// one shard, but Go exposes no proc-pin; an atomic counter masked by &(N-1) is
// the textbook race-free shape (mimalloc's sharded-free-list, jemalloc's per-
// arena-bucket use the same idea). It spreads concurrent AllocNode callers
// uniformly across the N shards (the Arena counter advances by 1 per call, so
// back-to-back allocations from the same goroutine land on consecutive shards —
// strictly better than pinning to one). The counter lives in HamtArena,
// CacheLinePad-isolated from the shard heads and bumpOffset so its own writes do
// not false-share.
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

// routeNodeFreelistShardPush picks the class-0 HamtNode freelist shard this
// pushFreeNode call should PUSH to. It is the asymmetric twin of the pop router:
// pushFreeNode is invoked from EBR RetireBlock processing (the epoch-advance
// reclaimer goroutine), NOT from the allocating worker, so the pop and push paths
// are run by DIFFERENT goroutine populations and would contend on a SHARED
// routing counter. A SEPARATE push counter keeps the two routing streams
// independent — documenting both counter sites honestly (R1d/R1e), not
// straw-manning "single counter is fine".
//
// The push/pop asymmetry is SAFE: every nodeFreelist shard services the SAME
// 72-byte class-0 HamtNode, so a pop from shard A and a push to shard B is
// benign (both are class-0 72-byte slots). EBR's global epoch holds ABA across
// the sharding: a recycled node cannot be re-popped concurrently because EBR
// retains the block until the global epoch proves zero readers (the existing
// line-228 comment's invariant holds PER SHARD now). The engine's existing
// per-CAS EBR participant.Enter/Exit is unchanged; only the freelist head each
// pop/push touches is now one of N=256 instead of one.
func (a *HamtArena) routeNodeFreelistShardPush() int {
	n := arenaNodeFreelistShardCount
	idx := a.nodeFreelistRoutePush.Add(1)
	if n&(n-1) == 0 {
		return int(idx-1) & (n - 1)
	}
	return int((idx - 1) % uint64(n))
}

// routeVarFreelistShardPop picks the variable-size freelist shard this
// allocVar call should POP from. It is the byte-faithful sibling of
// routeNodeFreelistShard, routed per-CALL (NOT per-CAS-retry) so the counter
// increment can never land in the hot CAS frame Tier-2's G3 <=43% gate polices.
// The CAS loop body is byte-identical in shape to the pre-R1c allocVar loop,
// just over a per-shard composite head instead of freeHeads[classIdx].head.
// Masked by (arenaVarFreelistShardCount-1) — a clean power-of-two bitmask.
func (a *HamtArena) routeVarFreelistShardPop() int {
	n := arenaVarFreelistShardCount
	idx := a.varFreelistRoutePop.Add(1)
	if n&(n-1) == 0 {
		return int(idx-1) & (n - 1)
	}
	return int((idx - 1) % uint64(n))
}

// routeVarFreelistShardPush picks the variable-size freelist shard this
// freeVar call should PUSH to. It is the asymmetric twin of the pop router:
// freeVar is invoked from EBR RetireBlock processing (the epoch-advance
// reclaimer goroutine), NOT from the allocating worker. A SEPARATE push
// counter keeps the two routing streams independent — the same 2.5a.1
// push/pop asymmetry discipline. The asymmetry is SAFE: every varFreelist
// shard for a given classIdx services the SAME blockSizeForClass(classIdx)
// slot, so a pop from shard A and a push to shard B is benign; EBR's global
// epoch retains the ABA guarantee across the sharding.
func (a *HamtArena) routeVarFreelistShardPush() int {
	n := arenaVarFreelistShardCount
	idx := a.varFreelistRoutePush.Add(1)
	if n&(n-1) == 0 {
		return int(idx-1) & (n - 1)
	}
	return int((idx - 1) % uint64(n))
}

// MANDATE 1 FIX: The goroutine is pinned to the current EBR epoch during
// the Treiber pop CAS loop. This mathematically prevents any concurrent
// RetireBlock physically recycling 'head' back onto the stack
// during this loop, eliminating ABA without generation counters.
func (a *HamtArena) AllocNode() NodePtr {
	// Pin to EBR epoch — prevents ABA during Treiber pop
	participant := a.ebr.Acquire()
	participant.Enter(a.ebr)

	// R1d: route this AllocNode to ONE class-0 freelist shard for the WHOLE call.
	// Computed ONCE, OUTSIDE the CAS retry loop — the loop's Load and CAS read
	// and write the SAME shard's head throughout (EBR ABA safety is per-shard
	// now). The routing-counter increment is on the cold path (once per call);
	// the CAS loop body is byte-identical in shape to the pre-R1 loop, just over
	// a composite-shard head instead of freeHeads[0].head.
	shardIdx := a.routeNodeFreelistShard()
	shard := &a.nodeFreelist[shardIdx]

	// 1. Try to pop from the Treiber free-list (recycled memory)
	for {
		head := shard.head.Load()

		if head == NullOffset64 {
			// Free-list is empty — fall through to bump allocator
			break
		}

		// Read the 64-bit next-pointer stored in the dead node's memory.
		// SAFETY: head points into mmap'd C-space; the GC cannot move it.
		// EBR epoch pin guarantees this memory cannot be recycled during read.
		nextPtr := (*uint64)(unsafe.Pointer(a.base + uintptr(head)))
		nextOffset := atomic.LoadUint64(nextPtr)

		// Pure 64-bit CAS — no generation counter needed.
		// EBR guarantees ABA safety: no concurrent pushFree() can recycle
		// 'head' while we hold an active epoch pin. (Invariant holds PER
		// SHARD now: the shard head replaces freeHeads[0].head but the EBR
		// global epoch is shared across all 256 freelist shards.)
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

// allocVar allocates a variable-sized block from the segregated slab allocator.
// The block is prepended with an 8-byte header storing the size class index
// for O(1) free routing. Returns a pointer to the PAYLOAD (past the header).
//
// Phase 2.5d (R1c): sharded pop with bounded shard sweep. The hot path routes
// ONE shard via routeVarFreelistShardPop() OUTSIDE the CAS retry loop and races
// the CAS over the per-shard head `a.varFreelist[classIdx-1][shardIdx].head`.
// If the routed shard is empty, the pop SWEEPS the NEXT arenaVarFreelistSweep
// shards for this class — bounded 8-shard probe — before falling through to the
// bump allocator. The sweep is the load-bearing correctness fix: a freelist
// push (freeVar) routes on a SEPARATE counter from pop, so over time pop and
// push visits to a given shard drift in counter-phase. Without the sweep, a
// pop landing on an empty routed shard would bump even when other shards for
// the same class are stacked (40-100 blocks pushed but pop visited a different
// shard) — a steady-state arena-bump leak (S1 measured 1.4 GB / 20K ops = 70
// KB/op leak pre-sweep). The bounded sweep covers the per-shard lag window:
// if ANY of {pop_routed_shard + next 7 shards} for this class is non-empty, the
// pop succeeds from there; the bump fallback fires only when an 8-shard
// neighborhood is empty (extremely rare at steady state — 8 × 4.7 ≈ 37 blocks
// would need to be simultaneously drained). The CAS-loop body is byte-identical
// in shape to the pre-R1c loop, just over a per-shard head; EBR's global epoch
// holds ABA across the sharding.
//
// Flow: route shard -> try shard pop -> if empty, sweep next 7 shards -> if all
// 8 empty, fall through to bump allocator. The cold-path freeHeads[classIdx]
// two-tier fallback (mirroring 2.5a.1's freeHeads[0]→nodeFreelist[i] contract)
// is omitted here because freeVar never pushes to freeHeads (its hot path is
// the shard); freeHeads[classIdx] is retained only to preserve the
// [numSizeClasses]slabFreeHead cartesian layout shared with the const
// declarations and the init loop.
func (a *HamtArena) allocVar(payloadSize uintptr) uintptr {
	if payloadSize == 0 {
		return 0
	}

	classIdx, blockSize := varSizeClassIndex(payloadSize)
	if classIdx == 0 {
		return 0 // Should not happen — payloadSize > 0 guaranteed
	}

	// R1c: route this allocVar to ONE var freelist shard for the WHOLE call.
	// Computed ONCE, OUTSIDE the CAS retry loop — the loop's Load and CAS read
	// and write the SAME shard's head throughout (EBR ABA safety is per-shard
	// now). The routing-counter increment is on the cold path (once per call);
	// the CAS loop body is byte-identical in shape to the pre-R1 loop, just over
	// a per-shard head instead of freeHeads[classIdx].head.
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

		for {
			head := shard.head.Load()
			if head == NullOffset64 {
				// Routed shard (or current probe shard) is empty — break out
				// of the inner CAS retry loop and try the next probe shard.
				break
			}

			nextPtr := (*uint64)(unsafe.Pointer(a.base + uintptr(head)))
			nextOffset := atomic.LoadUint64(nextPtr)

			if shard.head.CompareAndSwap(head, nextOffset) {
				participant.Exit()
				a.ebr.Release(participant)

				blockPtr := a.base + uintptr(head)
				// Write size class header
				*(*uint64)(unsafe.Pointer(blockPtr)) = uint64(classIdx)
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
	// Write size class header
	*(*uint64)(unsafe.Pointer(blockPtr)) = uint64(classIdx)
	// Return pointer past the header
	return blockPtr + varAllocHeaderSize
}

// freeVar pushes a variable-sized block back onto its slab free-list.
// CRITICAL: This MUST ONLY be called by the EBR manager on safe epoch processing.
//
// The payload pointer is adjusted backward by 8 bytes to reach the block
// header, which contains the size class index for O(1) routing.
//
// Phase 2.5d (R1c): two-tier sharded push. The hot path routes ONE shard via
// routeVarFreelistShardPush() OUTSIDE the CAS retry loop and races the CAS over
// the per-shard head `a.varFreelist[classIdx-1][shardIdx].head`. The CAS-loop
// body is byte-identical in shape to the pre-R1c freeVar loop, just over a
// per-shard head. The asymmetry (pop and push route on DIFFERENT counters) is
// SAFE: every varFreelist shard for a given classIdx services the SAME
// blockSizeForClass(classIdx) slot.
func (a *HamtArena) freeVar(payloadPtr uintptr) {
	if payloadPtr == 0 {
		return
	}

	blockPtr := payloadPtr - varAllocHeaderSize
	classIdx := int(*(*uint64)(unsafe.Pointer(blockPtr)))

	if classIdx < 1 || classIdx >= numSizeClasses {
		return // Corrupt or invalid — silently skip
	}

	offset := uint64(blockPtr - a.base)
	offsetPtr := (*uint64)(unsafe.Pointer(blockPtr))

	// R1c: route this freeVar push to ONE var freelist shard for the WHOLE
	// call. Computed ONCE, OUTSIDE the CAS retry loop. The push routes on the
	// SEPARATE push counter (varFreelistRoutePush) — the 2.5a.1 push/pop
	// asymmetry discipline (the popper is the allocating worker; the pusher is
	// the EBR epoch-advance reclaimer).
	shardIdx := a.routeVarFreelistShardPush()
	shard := &a.varFreelist[classIdx-1][shardIdx]

	// 1. Try to push onto the routed shard (hot path)
	for {
		head := shard.head.Load()
		atomic.StoreUint64(offsetPtr, head)
		if shard.head.CompareAndSwap(head, offset) {
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

// ---------------------------------------------------------------------------
// MANDATE (Stage 1 Zero-GC Microscope): Off-heap HAMT wrapper allocation
// ---------------------------------------------------------------------------

// hamtWrapperSize is the on-arena footprint of a HAMT struct (root NodePtr +
// arena *HamtArena + seed maphash.Seed + count int). It is computed at
// compile time so the size-class lookup is branchless.
const hamtWrapperSize = unsafe.Sizeof(HAMT{})

// allocHAMTWrapper provisions a HAMT struct in the mmap'd segregated slab
// allocator (class computed from hamtWrapperSize). Returns a *HAMT whose
// backing bytes are in mmap'd C-space — therefore invisible to the Go GC.
//
// STAGE 1 FIX (Zero-GC Microscope):
//
//	HAMT.Set previously allocated the result wrapper on the Go heap via
//	`res := &HAMT{...}`, which the compiler's escape analysis moved to the
//	heap because the struct was returned as a pointer. Every hot-path Set
//	thus paid one heap allocation, violating the strict Zero-GC mandate.
//	Routing the wrapper through the same mmap'd arena that owns the HamtNode
//	tree severs the last heap-allocation source on the Set path.
//
// SAFETY CONTRACT — GC-INVISIBLE POINTER FIELD:
//
//	The returned *HAMT's `arena` field stores a Go-heap pointer that the
//	GC will NOT see, because the struct itself is in C-space. The caller
//	MUST keep the owning HamtArena reachable from the Go heap for the
//	lifetime of all wrappers it has produced. In the DeltaCRDTEngine this
//	invariant is held by `DeltaCRDTEngine.arena` which directly roots the
//	arena; tests likewise hold the arena reference before constructing a
//	HAMT. A separate Go-heap root for the arena therefore exists for any
//	off-heap wrapper that reads its own `arena` field.
//
//	The `seed maphash.Seed` field is an 8-byte opaque random value (no
//	pointer payload), making it safe to store off-heap.
//
// LIFECYCLE:
//
//	The wrapper MUST be reclaimed via freeHAMTWrapper, which routes the
//	block back through EBR RetireBlock. Direct pushFreeVar use would bypass
//	EBR and risk ABA during physical recycling.
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

// freeHAMTWrapper defer-recycles the 32-byte (or class-block-aligned) HAMT
// wrapper slot back to the segregated slab free-list, via the EBR Manager.
//
// MANDATE: This MUST NOT push directly to the Treiber stack; doing so would
// race against concurrent AllocNode/allocVar CAS loops and reintroduce ABA.
// RetireBlock defers physical reclamation until the global epoch has
// advanced by 2, mathematically proving zero lingering readers.
//
// Caller invariants:
//   - ptr was produced by allocHAMTWrapper (this arena, this baseline).
//   - The wrapper's `root` subtree has ALREADY been DecRef'd recursively
//     (DecRef is the responsibility of the EBR Retire callback in
//     reclamation.go, which also invokes freeHAMTWrapper in sequence).
//   - The owning HamtArena is still reachable from the Go heap (so the
//     `arena` field is a valid pointer until this function returns).
//
// After this call the caller MUST NOT dereference ptr.
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

// DecRef decrements the reference count of a node.
// If the count reaches zero, the node's children are iteratively decremented
// and ALL owned memory (children array, entries array, leaf strings, leaf
// CRDT entries) is DEFERRED for reclamation via EBR RetireBlock.
//
// ADR 9 FIX: After the deep-copy fix in hamt.go, every node exclusively
// owns its childrenPtr and entriesPtr arrays. We can unconditionally free
// them when the node dies — no sharing hazard remains.
//
// MANDATE 1 FIX: Physical reclamation is encapsulated in an EBR callback.
// The offset is pushed back to the Treiber stack ONLY when the global epoch
// advances by 2, proving zero lingering readers.
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

// pushFreeNode physically reclaims a HamtNode by pushing its offset onto
// the class-0 lock-free Treiber stack. This is STRICTLY invoked by the
// EBRManager when memory safety is mathematically proven via epoch advancement.
func (a *HamtArena) pushFreeNode(offset uint64) {
	// R1d/R1e: route this push to ONE class-0 freelist shard for the WHOLE call.
	// Computed ONCE, OUTSIDE the CAS retry loop. pushFreeNode is invoked from EBR
	// RetireBlock processing (the epoch-advance reclaimer), NOT from the
	// allocating worker goroutine, so the pop counter and push counter are
	// SEPARATE (routeNodeFreelistShard vs routeNodeFreelistShardPush) — a shared
	// counter would itself contended between the two goroutine populations. The
	// push/pop asymmetry is SAFE: every nodeFreelist shard services the same
	// 72-byte class-0 HamtNode, so a pop from shard A and a push to shard B is
	// benign; EBR's global epoch retains the ABA guarantee across the sharding.
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

// Free destroys the arena, returning memory to the OS.
//
// STAGE 6 (Chaos Layer): any page range locked via LockHotPages MUST be
// munlocked before munmap. Several Linux kernels refuse to unmap a
// still-locked region, and even where they tolerate it the residency
// accounting leaks. UnlockAllPages is idempotent (munlock on an unlocked
// page is a kernel no-op), so calling it unconditionally is correct
// whether or not the arena was ever locked, and costs one syscall on free.
func (a *HamtArena) Free() error {
	a.UnlockAllPages()
	b := unsafe.Slice((*byte)(unsafe.Pointer(a.base)), a.size)
	return syscall.Munmap(b)
}

// --- Pointer conversion utilities ---

// toPtr converts a NodePtr to unsafe.Pointer.
//
// SAFETY: This is safe ONLY because NodePtr values reference mmap'd C-space
// memory that the Go GC never moves. Passing a Go-heap-derived NodePtr
// would trigger memory corruption.
func toPtr(p NodePtr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p))
}

// toUintptrPtr converts a raw uintptr to unsafe.Pointer.
//
// SAFETY: Same invariant as toPtr() — must reference mmap'd C-space memory.
func toUintptrPtr(p uintptr) unsafe.Pointer {
	return unsafe.Pointer(p)
}
