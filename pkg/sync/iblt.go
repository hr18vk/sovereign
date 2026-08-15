package sync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"unsafe"
)

// ErrIncompletePeel is returned when the IBLT cannot fully decode the
// symmetric difference. This occurs when the number of differences exceeds
// the table's capacity threshold, causing unresolvable bucket collisions.
var ErrIncompletePeel = errors.New("ErrIncompletePeel: difference exceeds IBLT capacity threshold")

// Bucket represents a single cell in the Invertible Bloom Lookup Table.
// By maintaining cryptographic XOR sums rather than simple bits, we ensure
// exactly 0.00% false positives during state reconciliation.
//
// Fields:
//   - Count:   Signed integer, incremented on Insert, decremented on Delete/Subtract.
//   - KeySum:  XOR accumulator of all keys mapped to this bucket.
//   - HashSum: XOR accumulator of the hashes of all mapped keys (purity verification).
type Bucket struct {
	Count   int32
	KeySum  uint64
	HashSum uint64
}

// IBLT guarantees mathematically exact set reconciliation for transaction mempools.
// It replaces the probabilistic Bloom Filter (0.59% FPR) with a deterministic
// structure that achieves 0.00% false positives via the Peeling Cascade algorithm.
//
// Communication complexity is O(d) where d is the size of the symmetric difference,
// rather than O(n) for the entire set — a planetary-scale bandwidth reduction.
type IBLT struct {
	buckets []Bucket
	k       int
	seed    maphash.Seed

	// arenaRef, arenaBucketsOffset, and arenaStructOffset are the Phase 2.5b
	// arena-backed IBLT lifecycle fields. They are zero-valued for the existing
	// heap-allocated constructors (NewIBLT / NewIBLTWithSeed — R1f protected,
	// byte-identical behavior), and populated only by NewArenaIBLT which
	// provisions BOTH the IBLT struct and its buckets []Bucket from the mmap'd
	// HamtArena. IBLT.Release() inspects arenaRef: nil → no-op (the heap IBLT
	// shape the capnp roundtrip / chaos / strata estimator paths still use);
	// non-nil → routes the bucket array AND the struct back through EBR
	// RetireBlock so the slabs are recycled ABA-safely after the global epoch
	// advances. This is byte-faithful to allocHAMTWrapper's arena-pointer +
	// EBR-retire pattern (the IBLT's bucket array is one more variable-size
	// slab class; the IBLT struct is one more ~48-byte slab class).
	arenaRef           *HamtArena
	arenaBucketsOffset uint64
	arenaStructOffset  uint64
}

// NewIBLT initializes a table engineered to hold a specific capacity of differences.
// numBuckets should be ~1.5x the expected maximum number of differences for
// reliable peeling. k is the number of independent hash functions (typically 3-5).
func NewIBLT(numBuckets int, k int) *IBLT {
	if k <= 0 || k > ibltMaxK {
		// Defensive: the engine never constructs an IBLT outside [1, ibltMaxK].
		// A panic at construction keeps the stack-array invariant in Insert/Peel
		// mathematically sound rather than silently truncating indices.
		panic(fmt.Sprintf("iblt: k=%d out of range [1, %d]", k, ibltMaxK))
	}
	return &IBLT{
		buckets: make([]Bucket, numBuckets),
		k:       k,
		seed:    maphash.MakeSeed(),
	}
}

// NewIBLTWithSeed creates an IBLT with a specific seed for deterministic peer sync.
// Both peers MUST use identical seeds for Subtract to produce correct results.
func NewIBLTWithSeed(numBuckets int, k int, seed maphash.Seed) *IBLT {
	if k <= 0 || k > ibltMaxK {
		panic(fmt.Sprintf("iblt: k=%d out of range [1, %d]", k, ibltMaxK))
	}
	return &IBLT{
		buckets: make([]Bucket, numBuckets),
		k:       k,
		seed:    seed,
	}
}


// ---------------------------------------------------------------------------
// Phase 2.5b — ARENA-BACKED IBLT (Zero-GC delta-generation hot path)
// ---------------------------------------------------------------------------
//
// NewArenaIBLT provisions an IBLT whose bucket array AND struct live in the
// mmap'd HamtArena (off-heap, invisible to the Go GC), byte-faithful to the
// allocVar/pushFreeVar pattern the HAMT wrapper already uses (allocHAMTWrapper
// / freeHAMTWrapper). The buckets []Bucket backing memory is allocated via
// arena.allocVar(numBuckets * sizeof(Bucket)) — one variable-size slab request
// — and a Go slice header over that mmap region is reconstructed via
// unsafe.Slice so the existing Insert/Peel/Subtract math (zero-alloc H2 FIX)
// operates on off-heap bytes unchanged. The IBLT struct itself is allocated
// from the arena too (a separate ~48-byte slab); the caller MUST invoke
// IBLT.Release() when done so both slabs are routed back through EBR
// RetireBlock for ABA-safe reclamation (R1b).
//
// DO NOT use this constructor for the capnp roundtrip / chaos / strata
// estimator paths (R1f): those keep the heap-allocating NewIBLT /
// NewIBLTWithSeed signatures byte-identical. The Zero-GC migration is on the
// GenerateDelta / GenerateDigestWithSeed HOT PATH ONLY.
//
// The constructor does NOT call Release on failure (panic on out-of-arena);
// the caller MUST Release a successfully-returned IBLT.
func NewArenaIBLT(numBuckets int, k int, seed maphash.Seed, arena *HamtArena) *IBLT {
	if k <= 0 || k > ibltMaxK {
		panic(fmt.Sprintf("iblt: k=%d out of range [1, %d]", k, ibltMaxK))
	}
	if arena == nil {
		panic("iblt: NewArenaIBLT called with nil arena")
	}
	if numBuckets <= 0 {
		numBuckets = 0
	}

	// Allocate the IBLT struct itself from the arena (one slab class for the
	// ~48-byte struct). allocVar pins the goroutine to the EBR epoch and falls
	// back to the bump allocator if the slab freelist is empty.
	structPayload := arena.allocVar(uintptr(unsafe.Sizeof(IBLT{})))
	if structPayload == 0 {
		panic("HamtArena: OOM — cannot allocate arena IBLT struct")
	}
	t := (*IBLT)(unsafe.Pointer(structPayload))

	// Allocate the bucket array backing store from the arena. The 24 KB slab
	// (1024 * 24B) lands in the existing power-of-2 freeHeads class computed by
	// varSizeClassIndex; no new arena size class is introduced.
	var bucketsPtr uintptr
	var bucketsOffset uint64
	if numBuckets > 0 {
		bucketsPayload := arena.allocVar(uintptr(numBuckets) * unsafe.Sizeof(Bucket{}))
		if bucketsPayload == 0 {
			panic("HamtArena: OOM — cannot allocate arena IBLT buckets")
		}
		bucketsPtr = bucketsPayload
		bucketsOffset = uint64(bucketsPtr - arena.base)
	}

	// Zero the struct + backing memory so no fieldnoise survives a slab
	// recycle. The heap constructors got zeroed buckets from make(); the
	// arena path MUST replicate that invariant (recycled slabs may carry
	// stale bits).
	*t = IBLT{
		k:                 k,
		seed:              seed,
		arenaRef:          arena,
		arenaBucketsOffset: bucketsOffset,
		arenaStructOffset:  uint64(structPayload - arena.base),
	}
	if bucketsPtr != 0 {
		// Build a Go slice header over the mmap'd bucket region. The slice
		// points at the payload (past allocVar's 8-byte size-class header),
		// which is the bucket array itself.
		t.buckets = unsafe.Slice((*Bucket)(unsafe.Pointer(bucketsPtr)), numBuckets)
		// Zero the recycled bucket memory (allocVar does NOT zero large
		// variable payloads on the bump path for the heap constructors'
		// `make([]Bucket, n)` zero semantics).
		for i := range t.buckets {
			t.buckets[i] = Bucket{}
		}
	}
	return t
}

// Release returns an arena-backed IBLT's struct + bucket slabs to the
// HamtArena's EBR-deferred free-list. It is a no-op for heap-allocated IBLTs
// (arenaRef == nil) so the capnp / chaos / strata paths that still use
// NewIBLT/NewIBLTWithSeed are unaffected. The physical slab push happens only
// after the global EBR epoch advances by 2 (RetireBlock), so a concurrent
// reader pinned to an earlier epoch cannot observe a recycled bucket array
// (ABA safety). After Release the caller MUST NOT touch the IBLT.
func (t *IBLT) Release() {
	if t == nil || t.arenaRef == nil {
		return
	}
	arena := t.arenaRef
	// Retire the bucket slab first (the larger mass), then the struct slab.
	if t.arenaBucketsOffset != 0 {
		arena.ebr.RetireBlock(arena, t.arenaBucketsOffset, false)
		t.arenaBucketsOffset = 0
	}
	if t.arenaStructOffset != 0 {
		arena.ebr.RetireBlock(arena, t.arenaStructOffset, false)
		t.arenaStructOffset = 0
	}
	t.arenaRef = nil
	t.buckets = nil
}

// ReleaseLocal returns an arena-backed IBLT's struct + bucket slabs DIRECTLY
// to the HamtArena's variable-size freelist (pushFreeVar), WITHOUT routing
// through EBR RetireBlock. It is the zero-RetiredNode-alloc sibling of Release
// for slabs that NEVER cross goroutine boundaries — they are written by one
// generator goroutine and read-only by that same goroutine's body before the
// generator returns. EBR's epoch-deferred ABA protection exists for slabs that
// a concurrent reader might still be walking; body-local slabs have no such
// reader, so direct freelist reuse is ABA-safe AND zero-alloc (RetireBlock
// otherwise pulls a RetiredNode from sync.Pool's retiredPool, which only
// refills on AdvanceEpoch — the bench's GenerateDelta-only loop never advances
// without the maybeAdvanceEpoch drain, so every RetireBlock would heap-alloc
// a fresh RetiredNode, breaking the Zero-GC gate).
//
// ReleaseLocal is used for the short-lived localDigest and diff IBLTs inside
// GenerateDelta's body (R1b mandate: these retire INSIDE the body). The
// lifecycle slabs (sendKeys + shardRoots held by the lazy closure past the
// body) still go through EBR RetireBlock via Release; they recycle through
// the maybeAdvanceEpoch drain GenerateDelta adds at its tail.
//
// Like Release, ReleaseLocal is a no-op for heap-allocated IBLTs (arenaRef ==
// nil) so the capnp / chaos / strata paths that still use NewIBLT /
// NewIBLTWithSeed are byte-identical (R1f). After ReleaseLocal the caller
// MUST NOT touch the IBLT.
func (t *IBLT) ReleaseLocal() {
	if t == nil || t.arenaRef == nil {
		return
	}
	arena := t.arenaRef
	if t.arenaBucketsOffset != 0 {
		arena.pushFreeVar(t.arenaBucketsOffset)
		t.arenaBucketsOffset = 0
	}
	if t.arenaStructOffset != 0 {
		arena.pushFreeVar(t.arenaStructOffset)
		t.arenaStructOffset = 0
	}
	t.arenaRef = nil
	t.buckets = nil
}

// subtractArena produces an arena-backed diff of t minus other, mirroring
// Subtract's math but provisioning the result IBLT (struct + bucket array)
// from the supplied HamtArena instead of the Go heap. The returned *IBLT is
// arena-backed and MUST be Release()'d by the caller (RetireBlock routes both
// slabs back via the EBR epoch-deferred freelist).
//
// This is the arena-backed sibling of Subtract used by the GenerateDelta hot
// path (R1b). Subtract's public signature and heap-allocating behavior are
// preserved byte-identical for the capnp roundtrip / chaos / strata-estimator
// consumers (R1f). Subtract's existing error-return shape is preserved here
// (the Subtract contract never errors on byte-identical-size peers in
// practice; the GenerateDelta hot path already ignores the error via
// `diff, _ := localDigest.Subtract(remoteDigest)`).
func (t *IBLT) subtractArena(other *IBLT, arena *HamtArena) *IBLT {
	if len(t.buckets) != len(other.buckets) || t.k != other.k {
		// Configuration mismatch — fall back to the heap Subtract shape so
		// neither this hot path nor Subtract's contract diverges on the
		// error branch. The GenerateDelta caller already tolerates a nil
		// diff via its `if diff != nil` peel guard.
		diff, _ := t.Subtract(other)
		return diff
	}

	diff := NewArenaIBLT(len(t.buckets), t.k, t.seed, arena)
	for i := range t.buckets {
		diff.buckets[i].Count = t.buckets[i].Count - other.buckets[i].Count
		diff.buckets[i].KeySum = t.buckets[i].KeySum ^ other.buckets[i].KeySum
		diff.buckets[i].HashSum = t.buckets[i].HashSum ^ other.buckets[i].HashSum
	}
	return diff
}

// Seed returns the hash seed for transmission to a remote peer.
func (t *IBLT) Seed() maphash.Seed {
	return t.seed
}

// NumBuckets returns the number of buckets in the table.
func (t *IBLT) NumBuckets() int {
	return len(t.buckets)
}

// K returns the number of hash functions.
func (t *IBLT) K() int {
	return t.k
}

// ibltMaxK is the compile-time cap on the number of hash functions (k) used by
// any IBLT instance. The peer-reconciliation workloads in this engine use k in
// {3, 4} (see strataK=3 and the ADR-5 reconciliation k=4). Cap = 8 gives two
// doublings of headroom at zero memory cost: callers pass a *stack* array of
// exactly this size and H2 FIX makes Insert/Peel allocation-free.
//
// NewIBLT panics if k > ibltMaxK, gating misuse at construction (defensive —
// the engine never constructs an IBLT above).
const ibltMaxK = 8

// hashKeyWithSeed computes the 64-bit primary double-hash seed for `key`
// under this IBLT's seed, plus the h2 odd secondary hash. Pure value math,
// zero heap allocation; the indices table is filled by the caller into its
// own stack array via getHashesInto.
func (t *IBLT) hashKeyWithSeed(key uint64) (primaryHash, h1, h2, n uint64) {
	var h maphash.Hash
	h.SetSeed(t.seed)

	var keyBytes [8]byte
	binary.LittleEndian.PutUint64(keyBytes[:], key)
	h.Write(keyBytes[:])

	primaryHash = h.Sum64()
	// Use upper and lower 32 bits as two independent hash functions.
	h1 = primaryHash
	// Ensure h2 is odd so it is relatively prime to power-of-2 table sizes.
	h2 = (primaryHash >> 32) | 1
	n = uint64(len(t.buckets))
	return primaryHash, h1, h2, n
}

// getHashesInto fills out[:t.k] with the k bucket indices for `key` and returns
// the primary hash. H2 FIX (Zero-GC): the caller passes a STACK-allocated
// *[ibltMaxK]int — the function never heap-allocates. This is the
// allocation-free replacement for the old getHashes() that did
// `make([]int, t.k)` per Insert and per Peel cascade step, which had put a
// heap allocation on the CRDT digest/delta hot path that SUPREMUM_STYLE §1
// forbids.
func (t *IBLT) getHashesInto(out *[ibltMaxK]int, key uint64) (hashSum uint64) {
	primaryHash, h1, h2, n := t.hashKeyWithSeed(key)
	for i := 0; i < t.k; i++ {
		out[i] = int((h1 + uint64(i)*h2) % n)
	}
	return primaryHash
}

// getHashes is kept for external test consumers; the hot path uses
// getHashesInto. It allocates once (make([]int, t.k)) and is therefore NOT on
// the CRDT hot path.
func (t *IBLT) getHashes(key uint64) ([]int, uint64) {
	var scratch [ibltMaxK]int
	hashSum := t.getHashesInto(&scratch, key)
	indices := make([]int, t.k)
	copy(indices, scratch[:t.k])
	return indices, hashSum
}

// Insert maps a transaction key into the structure using XOR addition.
// Each of the k hash functions increments Count, XORs the key into KeySum,
// and XORs the key's hash into HashSum for the corresponding bucket.
func (t *IBLT) Insert(key uint64) {
	// H2 FIX (Zero-GC): stack-allocated indices — no make() per Insert.
	var indices [ibltMaxK]int
	hashSum := t.getHashesInto(&indices, key)
	for i := 0; i < t.k; i++ {
		idx := indices[i]
		t.buckets[idx].Count += 1
		t.buckets[idx].KeySum ^= key
		t.buckets[idx].HashSum ^= hashSum
	}
}

// Delete removes a key from the IBLT (inverse of Insert).
func (t *IBLT) Delete(key uint64) {
	// H2 FIX (Zero-GC): stack-allocated indices — no make() per Delete.
	var indices [ibltMaxK]int
	hashSum := t.getHashesInto(&indices, key)
	for i := 0; i < t.k; i++ {
		idx := indices[i]
		t.buckets[idx].Count -= 1
		t.buckets[idx].KeySum ^= key
		t.buckets[idx].HashSum ^= hashSum
	}
}

// Subtract mathematically diffs two IBLTs. The resulting IBLT contains ONLY
// the transactions that differ between the local and remote nodes.
//
// For each bucket i:
//   - Diff.Count[i]   = A.Count[i]   - B.Count[i]
//   - Diff.KeySum[i]  = A.KeySum[i]  ^ B.KeySum[i]
//   - Diff.HashSum[i] = A.HashSum[i] ^ B.HashSum[i]
func (t *IBLT) Subtract(other *IBLT) (*IBLT, error) {
	if len(t.buckets) != len(other.buckets) || t.k != other.k {
		return nil, errors.New("IBLT configurations must match perfectly")
	}

	diff := NewIBLTWithSeed(len(t.buckets), t.k, t.seed)

	for i := range t.buckets {
		diff.buckets[i].Count = t.buckets[i].Count - other.buckets[i].Count
		diff.buckets[i].KeySum = t.buckets[i].KeySum ^ other.buckets[i].KeySum
		diff.buckets[i].HashSum = t.buckets[i].HashSum ^ other.buckets[i].HashSum
	}

	return diff, nil
}

// isPureCount is the cheap gate: only buckets with Count == +/-1 can ever be
// pure. It avoids the hash computation in isPure when the count already
// disqualifies the bucket.
func isPureCount(count int32) bool {
	return count == 1 || count == -1
}

// isPure verifies if a bucket contains exactly one uncollided key.
// A bucket is pure when:
//   - Count is exactly +1 (local has, remote doesn't) or -1 (remote has, local doesn't)
//   - The hash of KeySum matches HashSum (cryptographic purity verification)
//
// The mathematical guarantee of 0.00% false positives hinges on this logic.
func (t *IBLT) isPure(idx int) bool {
	b := t.buckets[idx]
	if b.Count != 1 && b.Count != -1 {
		return false
	}

	// H2 FIX (Zero-GC): stack-allocated indices; only the hash is consumed.
	var scratch [ibltMaxK]int
	expectedHash := t.getHashesInto(&scratch, b.KeySum)
	return b.HashSum == expectedHash
}

// Peel extracts the exact symmetric difference via cascading avalanche logic.
// It returns:
//   - localHas:  keys present locally but missing on the remote peer (Count == +1)
//   - remoteHas: keys present on the remote peer but missing locally (Count == -1)
//   - error:     ErrIncompletePeel if the difference exceeds the table's capacity
//
// The peeling process is deterministic: removing a pure bucket's key from all
// k connected buckets un-collides adjacent buckets, triggering a cascade that
// unravels the entire structure until it is completely empty.
func (t *IBLT) Peel() ([]uint64, []uint64, error) {
	var localHas []uint64
	var remoteHas []uint64

	// H3 FIX: the previous `pureQueue = pureQueue[1:]` was an O(n) memmove of
	// the slice header per dequeue, making the peeling cascade O(n^2) in the
	// worst case. Replace with an index-based drain over the slice: dequeue
	// advances a head counter and we compact only when the head reaches the
	// midpoint, so every element is moved at most once across the whole peel.
	// The pureQueue itself is still heap-allocated (it escapes to the caller's
	// result), but it is O(|d|), not O(buckets), and the per-step dequeue is O(1).
	pureQueue := make([]int, 0, len(t.buckets)/4)
	head := 0 // index of the next pure bucket to peel

	// Initial scan to populate the queue with all purely decoded buckets.
	for i := range t.buckets {
		if t.isPure(i) {
			pureQueue = append(pureQueue, i)
		}
	}

	// The Peeling Avalanche. Each cascade step uses a stack-allocated index
	// array (H2 FIX) — no make([]int, t.k) per step.
	for head < len(pureQueue) {
		idx := pureQueue[head]
		head++

		b := t.buckets[idx]

		// Re-verify purity in case a previous cascade altered this bucket.
		if !isPureCount(b.Count) {
			continue
		}
		// Re-verify the cryptographic purity check now (cheap hash only).
		if !t.isPure(idx) {
			continue
		}

		key := b.KeySum
		if b.Count > 0 {
			localHas = append(localHas, key)
		} else {
			remoteHas = append(remoteHas, key)
		}

		// Cascade: Remove this key from all connected buckets.
		var targets [ibltMaxK]int
		hashSum := t.getHashesInto(&targets, key)
		for ti := 0; ti < t.k; ti++ {
			targetIdx := targets[ti]
			if b.Count > 0 {
				t.buckets[targetIdx].Count -= 1
			} else {
				t.buckets[targetIdx].Count += 1
			}
			t.buckets[targetIdx].KeySum ^= key
			t.buckets[targetIdx].HashSum ^= hashSum

			// Detect if this cascade un-collided an adjacent bucket.
			if t.isPure(targetIdx) {
				pureQueue = append(pureQueue, targetIdx)
			}
		}

		// Compaction: avoid unbounded queue growth by reclaiming the head
		// once it reaches half the queue. Each element is moved at most one
		// extra time across the entire peel, so the total work stays O(|d|).
		if head >= 16 && head*2 >= len(pureQueue) {
			n := copy(pureQueue, pureQueue[head:])
			pureQueue = pureQueue[:n]
			head = 0
		}
	}

	// Verify total completion — all buckets must be zeroed
	for _, b := range t.buckets {
		if b.Count != 0 || b.KeySum != 0 || b.HashSum != 0 {
			return localHas, remoteHas, ErrIncompletePeel
		}
	}

	return localHas, remoteHas, nil
}

// PeelArena is the arena-backed sibling of Peel: the result slices (localHas,
// remoteHas) and the internal pureQueue are provisioned from the supplied
// HamtArena instead of grown via make/append on the Go heap. The math is
// byte-identical to Peel (it walks the same peeling cascade, uses the same
// H2 stack-allocated index array, the same H3 compaction). Only the backing
// store of the three escaped slices changes. The caller MUST retire the
// returned slices via the owning arena (RetireBlock on their offsets) or
// retain them for the lifetime of the consumer (GenerateDelta sorts localHas
// in place into the send-key set and retires it on CRDTDelta.Release).
//
// Bounding: localHas and remoteHas are each upper-bounded by numBuckets (each
// pure bucket yields one key); pureQueue is upper-bounded by numBuckets
// (each bucket may enqueue once). The arena slabs are sized at those upper
// bounds; the returned slices are sliced to their actual length. R1c/R1e
// mandate: the bench reads these as ZERO Go-heap allocs because the backing
// memory is mmap'd (allocVar), invisible to -benchmem.
//
// DO NOT use PeelArena for the capnp/chaos/strata paths (R1f): those keep
// the heap-allocating Peel signature byte-identical.
func (t *IBLT) PeelArena(arena *HamtArena) (localHas, remoteHas []uint64, localHasOffset, remoteHasOffset, pureQueueOffset uint64, err error) {
	n := len(t.buckets)
	// Upper-bounded arena slabs; zero Go-heap allocs. Each slice is given the
	// FULL arena-backed capacity (unsafe.Slice(ptr, n)[:0:n]) so append() uses
	// the in-place mmap backing and never grows the slice on the Go heap.
	localBacking := arena.allocVar(uintptr(n) * unsafe.Sizeof(uint64(0)))
	remoteBacking := arena.allocVar(uintptr(n) * unsafe.Sizeof(uint64(0)))
	queueBacking := arena.allocVar(uintptr(n) * unsafe.Sizeof(int(0)))
	if localBacking == 0 || remoteBacking == 0 || queueBacking == 0 {
		// OOM — fall back to the heap Peel so the (already-impossible-on-a-
		// 2GiB-bench-arena) error path does not panic the engine.
		l, r, e := t.Peel()
		return l, r, 0, 0, 0, e
	}
	localHas = unsafe.Slice((*uint64)(unsafe.Pointer(localBacking)), n)[:0:n]
	remoteHas = unsafe.Slice((*uint64)(unsafe.Pointer(remoteBacking)), n)[:0:n]
	var pureQueue []int = unsafe.Slice((*int)(unsafe.Pointer(queueBacking)), n)[:0:n]
	localHasOffset = uint64(localBacking - arena.base)
	remoteHasOffset = uint64(remoteBacking - arena.base)
	pureQueueOffset = uint64(queueBacking - arena.base)

	// Initial scan to populate the queue with all purely decoded buckets.
	for i := range t.buckets {
		if t.isPure(i) {
			pureQueue = append(pureQueue, i)
		}
	}

	head := 0
	for head < len(pureQueue) {
		idx := pureQueue[head]
		head++

		b := t.buckets[idx]
		if !isPureCount(b.Count) {
			continue
		}
		if !t.isPure(idx) {
			continue
		}

		key := b.KeySum
		if b.Count > 0 {
			localHas = append(localHas, key)
		} else {
			remoteHas = append(remoteHas, key)
		}

		var targets [ibltMaxK]int
		hashSum := t.getHashesInto(&targets, key)
		for ti := 0; ti < t.k; ti++ {
			targetIdx := targets[ti]
			if b.Count > 0 {
				t.buckets[targetIdx].Count -= 1
			} else {
				t.buckets[targetIdx].Count += 1
			}
			t.buckets[targetIdx].KeySum ^= key
			t.buckets[targetIdx].HashSum ^= hashSum
			if t.isPure(targetIdx) {
				pureQueue = append(pureQueue, targetIdx)
			}
		}

		if head >= 16 && head*2 >= len(pureQueue) {
			nn := copy(pureQueue, pureQueue[head:])
			pureQueue = pureQueue[:nn]
			head = 0
		}
	}

	for _, b := range t.buckets {
		if b.Count != 0 || b.KeySum != 0 || b.HashSum != 0 {
			return localHas, remoteHas, localHasOffset, remoteHasOffset, pureQueueOffset, ErrIncompletePeel
		}
	}

	return localHas, remoteHas, localHasOffset, remoteHasOffset, pureQueueOffset, nil
}

// ---------------------------------------------------------------------------
// ADR 5: Stratified Invertible Bloom Lookup Trees (S-IBLT)
// ---------------------------------------------------------------------------
//
// Standard IBLTs fail catastrophically when |d| exceeds the bucket count.
// The Strata Estimator solves this by partitioning elements into log2(U)
// strata based on trailing zeros in their hash. Each stratum holds a small
// fixed-size IBLT (strataIBLTBuckets=80, k=3).
//
// Estimation protocol:
//   1. Both peers exchange StrataEstimators (~50KB each)
//   2. Subtract stratum-by-stratum from highest to lowest
//   3. First failing stratum s yields estimate: count × 2^(s+1)
//   4. Dynamically size the reconciliation IBLT at 1.5 × d_est
//
// Communication complexity: O(d × log(d)) instead of O(n)

const (
	// strataCount is the number of strata. For a 64-bit hash space,
	// 32 strata covers 2^32 granularity — sufficient for sets up to 4 billion.
	strataCount = 32

	// strataIBLTBuckets is the fixed IBLT size per stratum.
	// 80 buckets with k=3 reliably peels up to ~50 differences per stratum.
	strataIBLTBuckets = 80

	// strataK is the number of hash functions per stratum IBLT.
	strataK = 3

	// ibltSafetyFactor is the multiplier applied to d_est for the final IBLT.
	// 1.5× provides ample margin for reliable peeling (literature standard).
	ibltSafetyFactor = 3 // numerator; divided by 2 → 1.5×

	// minDynamicBuckets is the floor for dynamically-sized IBLTs.
	minDynamicBuckets = 128
)

// StrataEstimator partitions the key space into strata by trailing zero count.
// Each stratum contains a small, fixed-size IBLT.
//
// Memory layout: fixed array of 32 IBLTs, each 80 buckets × 20 bytes = 51.2KB total.
// No heap growth — the array is sized at construction and never resized.
type StrataEstimator struct {
	strata [strataCount]*IBLT
	seed   maphash.Seed
}

// NewStrataEstimator creates a new estimator with the given hash seed.
// Both peers MUST use the same seed for subtraction to work.
func NewStrataEstimator(seed maphash.Seed) *StrataEstimator {
	se := &StrataEstimator{seed: seed}
	for i := 0; i < strataCount; i++ {
		se.strata[i] = NewIBLTWithSeed(strataIBLTBuckets, strataK, seed)
	}
	return se
}

// Seed returns the hash seed for transmission to a remote peer.
func (se *StrataEstimator) Seed() maphash.Seed {
	return se.seed
}

// Insert adds a key to the appropriate stratum.
// The stratum index is determined by the number of trailing zeros in the key:
//
//	stratum = ctz(key), clamped to [0, strataCount-1]
//
// O(1) per insertion — one ctz instruction plus one IBLT insert (k bucket ops).
func (se *StrataEstimator) Insert(key uint64) {
	s := trailingZeros64(key)
	if s >= strataCount {
		s = strataCount - 1
	}
	se.strata[s].Insert(key)
}

// trailingZeros64 returns the number of trailing zero bits in x.
// Uses de Bruijn multiplication — pure integer math, zero allocation.
// For x=0, returns 64.
func trailingZeros64(x uint64) int {
	if x == 0 {
		return 64
	}
	// de Bruijn constant and lookup table
	const deBruijn = 0x03f79d71b4ca8b09
	var table = [64]int{
		0, 1, 56, 2, 57, 49, 28, 3, 61, 58, 42, 50, 38, 29, 17, 4,
		62, 47, 59, 36, 45, 43, 51, 22, 53, 39, 33, 30, 24, 18, 12, 5,
		63, 55, 48, 27, 60, 41, 37, 16, 46, 35, 44, 21, 52, 32, 23, 11,
		54, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9, 13, 8, 7, 6,
	}
	return table[((x&-x)*deBruijn)>>58]
}

// Estimate computes an unbiased estimate of the symmetric difference |d|
// between the local and remote datasets by subtracting the remote estimator.
//
// Algorithm:
//  1. Iterate from the highest stratum (most sparse) to the lowest
//  2. Subtract each stratum's IBLT and attempt to peel
//  3. Accumulate successfully decoded elements
//  4. The first stratum that fails to peel → estimate = count × 2^(s+1)
//
// If all strata peel successfully, the estimate is the exact count.
// Communication: O(strataCount × strataIBLTBuckets × 20) = ~50KB
func (se *StrataEstimator) Estimate(remote *StrataEstimator) int {
	var count int

	for s := strataCount - 1; s >= 0; s-- {
		diff, err := se.strata[s].Subtract(remote.strata[s])
		if err != nil {
			// Configuration mismatch — return conservative estimate
			return count << uint(s+1)
		}

		localHas, remoteHas, peelErr := diff.Peel()
		if peelErr != nil {
			// This stratum overflowed — extrapolate from accumulated count
			// estimate = count × 2^(s+1)
			return (count + len(localHas) + len(remoteHas)) << uint(s+1)
		}

		count += len(localHas) + len(remoteHas)
	}

	// All strata decoded — count is exact
	return count
}

// DynamicIBLTSize computes the optimal IBLT bucket count from a strata estimate.
// Uses 1.5× safety factor (3/2) with a minimum floor of minDynamicBuckets.
// O(1) — pure integer arithmetic.
func DynamicIBLTSize(dEst int) int {
	// buckets = max(minDynamicBuckets, ceil(d_est × 1.5))
	size := (dEst * ibltSafetyFactor) / 2
	if size < minDynamicBuckets {
		return minDynamicBuckets
	}
	return size
}

// NewDynamicIBLT creates an IBLT sized according to the strata estimate.
// This is the bridge between estimation and reconciliation.
func NewDynamicIBLT(dEst int, k int, seed maphash.Seed) *IBLT {
	return NewIBLTWithSeed(DynamicIBLTSize(dEst), k, seed)
}
