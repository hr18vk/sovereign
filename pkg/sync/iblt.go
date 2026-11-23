// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"errors"
	"fmt"
	"hash/maphash"
	"sync/atomic"
	"unsafe"
)

// ErrIncompletePeel is returned when the IBLT cannot fully decode the
// symmetric difference. This occurs when the number of differences exceeds
// the table's capacity threshold, causing unresolvable bucket collisions.
var ErrIncompletePeel = errors.New("ErrIncompletePeel: difference exceeds IBLT capacity threshold")

// Bucket is one cell in an Invertible Bloom Lookup Table. Count tracks the
// signed number of resident keys, KeySum accumulates their XOR, and HashSum
// accumulates the XOR of their hashes. Peel uses HashSum to check whether a
// bucket with count ±1 contains a single key.
type Bucket struct {
	Count   int32
	KeySum  uint64
	HashSum uint64
}

// IBLT reconciles sets by subtracting two tables and peeling pure buckets.
// Its communication cost depends on the symmetric difference rather than the
// full set. If collisions prevent complete decoding, Peel returns
// ErrIncompletePeel instead of presenting a partial difference as complete.
type IBLT struct {
	buckets []Bucket
	k       int
	seed    maphash.Seed

	// Arena constructors allocate both the table and its bucket backing store
	// from HamtArena and record their offsets here. Heap constructors leave
	// these fields zero. Release returns arena slabs through EBR; it is a no-op
	// for heap tables.
	arenaRef           *HamtArena
	arenaBucketsOffset uint64
	arenaStructOffset  uint64

	// schemeV2 captures placement at construction: zero selects arithmetic-
	// progression indices and one selects decorrelated indices. Capturing the
	// process setting here keeps a table's placement fixed for its lifetime,
	// even if another table is later constructed under a different setting.
	// MarshalIBLT records the captured scheme in the frame magic.
	schemeV2 uint64
}

// ibltSchemeV2Enabled selects the scheme for newly constructed tables. The
// node sets it from --iblt-v2 during initialization, before digest builders
// start. Existing tables retain the scheme they captured at construction.
var ibltSchemeV2Enabled atomic.Bool

// SetIBLTSchemeV2 selects decorrelated placement for subsequently constructed
// IBLTs. Call it during initialization, before any table exists. Existing
// tables are not migrated; tests restore the default after constructing tables
// under the opt-in scheme.
func SetIBLTSchemeV2(v2 bool) { ibltSchemeV2Enabled.Store(v2) }

// IBLTSchemeV2 reports the scheme selected for new tables. The wire decoder
// uses it to choose the only frame magic it accepts.
func IBLTSchemeV2() bool { return ibltSchemeV2Enabled.Load() }

// ibltSchemeWord is the constructors' one-shot capture helper.
func ibltSchemeWord() uint64 {
	if ibltSchemeV2Enabled.Load() {
		return 1
	}
	return 0
}

// NewIBLT constructs a heap-allocated table with numBuckets cells and k hash
// indices per key. Bucket capacity determines how large a symmetric difference
// can peel; approximately 1.5 buckets per expected difference is the default
// sizing heuristic. It panics when k is outside [1, ibltMaxK].
func NewIBLT(numBuckets int, k int) *IBLT {
	if k <= 0 || k > ibltMaxK {
		// Defensive: the engine never constructs an IBLT outside [1, ibltMaxK].
		// A panic at construction keeps the stack-array invariant in Insert/Peel
		// mathematically sound rather than silently truncating indices.
		panic(fmt.Sprintf("iblt: k=%d out of range [1, %d]", k, ibltMaxK))
	}
	return &IBLT{
		buckets:  make([]Bucket, numBuckets),
		k:        k,
		seed:     maphash.MakeSeed(),
		schemeV2: ibltSchemeWord(),
	}
}

// NewIBLTWithSeed creates an IBLT with a specific seed for deterministic peer sync.
// Both peers must use identical seeds for Subtract to produce correct results.
func NewIBLTWithSeed(numBuckets int, k int, seed maphash.Seed) *IBLT {
	if k <= 0 || k > ibltMaxK {
		panic(fmt.Sprintf("iblt: k=%d out of range [1, %d]", k, ibltMaxK))
	}
	return &IBLT{
		buckets:  make([]Bucket, numBuckets),
		k:        k,
		seed:     seed,
		schemeV2: ibltSchemeWord(),
	}
}

// ---------------------------------------------------------------------------
// Arena-backed IBLT
// ---------------------------------------------------------------------------
//
// NewArenaIBLT allocates the table and its bucket backing store from arena.
// unsafe.Slice exposes the off-heap bucket memory to the same Insert, Peel,
// and Subtract operations used by heap tables. GenerateDelta uses this
// constructor to keep digest generation off the Go heap; wire decoding and
// strata estimation continue to use heap constructors.
//
// A successful call transfers ownership to the caller, which must call Release
// or ReleaseLocal before discarding the table. Exhaustion panics; the
// constructor does not attempt to clean up a partially allocated table.
func NewArenaIBLT(numBuckets int, k int, seed maphash.Seed, arena *HamtArena) *IBLT {
	if k <= 0 || k > ibltMaxK {
		panic(fmt.Sprintf("iblt: k=%d out of range [1, %d]", k, ibltMaxK))
	}
	if arena == nil {
		panic("iblt: NewArenaIBLT called with nil arena")
	}
	// The largest variable block provides 524,280 payload bytes after its
	// header, exactly 21,845 Buckets. varSizeClassIndex clamps larger requests
	// to that class, so allocVar would clear the requested length beyond the
	// returned block and overwrite adjacent slabs. Callers handling remote
	// sizes pass through ClampIBLTBuckets before reaching this constructor;
	// this panic catches a caller that bypassed the clamp.
	if numBuckets > MaxArenaIBLTBuckets {
		panic(fmt.Sprintf("iblt: NewArenaIBLT numBuckets=%d exceeds the arena variable-block ceiling MaxArenaIBLTBuckets=%d (silent-overflow boundary, not OOM): internal misuse; remote-controlled sizes must be clamped via ClampIBLTBuckets first", numBuckets, MaxArenaIBLTBuckets))
	}
	if numBuckets <= 0 {
		numBuckets = 0
	}

	// allocVar pins the goroutine to the EBR epoch and uses the bump allocator
	// when no suitable freelist block is available.
	structPayload := arena.allocVar(uintptr(unsafe.Sizeof(IBLT{})))
	if structPayload == 0 {
		panic("HamtArena: OOM — cannot allocate arena IBLT struct")
	}
	t := (*IBLT)(unsafe.Pointer(structPayload))

	// The bucket array is one variable-sized arena allocation.
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

	// Heap allocation zeroes buckets; recycled arena memory needs the same
	// initialization before use.
	*t = IBLT{
		k:                  k,
		seed:               seed,
		arenaRef:           arena,
		arenaBucketsOffset: bucketsOffset,
		arenaStructOffset:  uint64(structPayload - arena.base),
		schemeV2:           ibltSchemeWord(),
	}
	if bucketsPtr != 0 {
		// Build a Go slice header over the mmap'd bucket region. The slice
		// points at the payload (past allocVar's 8-byte size-class header),
		// which is the bucket array itself.
		t.buckets = unsafe.Slice((*Bucket)(unsafe.Pointer(bucketsPtr)), numBuckets)
		// Zero the recycled bucket memory (allocVar does not zero large
		// variable payloads on the bump path for the heap constructors'
		// `make([]Bucket, n)` zero semantics).
		for i := range t.buckets {
			t.buckets[i] = Bucket{}
		}
	}
	return t
}

// Release retires an arena-backed table's bucket and struct slabs through EBR.
// Reuse waits for epoch advancement so readers pinned to an earlier epoch
// cannot observe recycled memory. It is a no-op for heap tables. The caller
// must not access the table after Release returns.
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

// ReleaseLocal returns arena slabs directly to the variable-size freelist.
// It is restricted to tables that remain within one goroutine for their whole
// lifetime, where no concurrent reader can retain a pointer into the memory.
// GenerateDelta uses it for its local digest and difference tables; slices
// retained by a delta closure instead use Release and EBR.
//
// Direct return avoids allocating a RetiredNode when epoch advancement is not
// driving the retired-node pool. ReleaseLocal is a no-op for heap tables, and
// the caller must not access the table after it returns.
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

// MaxArenaIBLTBuckets is the number of Buckets that fit in the arena's largest
// variable block after its 8-byte header: 524,280 / 24 = 21,845. Deriving the
// bound with unsafe.Sizeof keeps it aligned with Bucket's in-memory layout.
// NewArenaIBLT rejects larger requests because the allocator would otherwise
// clear beyond the returned block.
var MaxArenaIBLTBuckets = int((blockSizeForClass(numSizeClasses-1) - varAllocHeaderSize) / unsafe.Sizeof(Bucket{})) // == 21845

// IBLTDigestDefaultBuckets is the bucket count used by the fixed-size digest
// wrappers and the v1 wire path.
const IBLTDigestDefaultBuckets = 1024

// ClampIBLTBuckets bounds a digest size to [128, MaxArenaIBLTBuckets] before
// arena allocation. Remote sizes reach it through GenerateDigestSizedWithSeed.
// The lower bound preserves the full-keyset fallback for a one-bucket remote:
// the locally clamped sizes differ, subtraction is rejected, and no partial
// difference is returned.
//
// At k=4, the 21,845-bucket ceiling corresponds to approximately 16,869
// differences at the c4=1.295 transition, or 7,802 with the 2.8 sizing margin.
// Larger differences require rateless, multi-frame continuation, which the
// mesh transport does not currently provide.
func ClampIBLTBuckets(n int) int {
	if n < minDynamicBuckets {
		return minDynamicBuckets
	}
	if n > MaxArenaIBLTBuckets {
		return MaxArenaIBLTBuckets
	}
	return n
}

// digestSnapshotRestarts counts digest builds restarted after a shard root
// changed between snapshot capture and verification. Sweep and responder
// goroutines share the counter.
var digestSnapshotRestarts atomic.Uint64

// DigestSnapshotRestarts reports how many digest builds detected a concurrent
// write and restarted from a new set of shard roots. A quiescent build does
// not increment the counter.
func DigestSnapshotRestarts() uint64 { return digestSnapshotRestarts.Load() }

// subtractArena subtracts other from t and allocates the result from arena.
// The caller owns the returned table and must release it. GenerateDelta uses
// this path to avoid heap allocation; public Subtract retains its heap result.
func (t *IBLT) subtractArena(other *IBLT, arena *HamtArena) *IBLT {
	// Different sizes, k values, or placement schemes cannot be subtracted:
	// common keys would not cancel, and peeling would produce invalid output.
	// Delegate the mismatch to Subtract, whose nil result selects the
	// full-keyset fallback in GenerateDelta.
	if len(t.buckets) != len(other.buckets) || t.k != other.k || t.schemeV2 != other.schemeV2 {
		// Keep the mismatch behavior identical to public Subtract.
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

// ibltMaxK bounds the stack array used for bucket indices. Reconciliation uses
// k=3 or k=4; the cap of 8 leaves room for larger wire values without adding a
// heap allocation to Insert or Peel. Constructors reject values outside it.
const ibltMaxK = 8

// hashKeyWithSeed returns the primary hash and the two values used for v1
// arithmetic-progression placement. It applies the splitmix64 finalizer to the
// key and the seed's serialized backing word, with no heap allocation.
//
// A runtime maphash hasher is unsuitable here because it incorporates
// per-process state: peers using the same wire seed would place a common key
// in different buckets, preventing subtraction from cancelling it. Before the
// deterministic hash, 20 sampled cross-process exchanges all returned the full
// 10,000-key set to peers that already held those keys. Using SeedToUint64
// makes placement a pure function of the transmitted key and seed word.
//
// The primary hash also feeds HashSum, and isPure recomputes this function.
// The wire carries the seed and buckets, not a hash-function identifier.
func (t *IBLT) hashKeyWithSeed(key uint64) (primaryHash, h1, h2, n uint64) {
	// Key the finalizer by the seed's wire word so two processes hashing the
	// same (key, seedWord) agree byte-for-byte. The golden-ratio multiplier
	// decorrelates distinct seeds; splitmix64 avalanches the sum.
	x := key + SeedToUint64(t.seed)*0x9E3779B97F4A7C15
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	x ^= x >> 31
	primaryHash = x
	// Use upper and lower 32 bits as two independent hash functions.
	h1 = primaryHash
	// Ensure h2 is odd so it is relatively prime to power-of-2 table sizes.
	h2 = (primaryHash >> 32) | 1
	n = uint64(len(t.buckets))
	return primaryHash, h1, h2, n
}

// getHashesInto writes the key's k bucket indices to the caller's stack array
// and returns the primary hash used in HashSum. Insert, Peel, and isPure share
// this placement function.
func (t *IBLT) getHashesInto(out *[ibltMaxK]int, key uint64) (hashSum uint64) {
	primaryHash, h1, h2, n := t.hashKeyWithSeed(key)
	if t.schemeV2 == 0 {
		// v1 uses an arithmetic progression derived from h1 and odd h2.
		for i := 0; i < t.k; i++ {
			out[i] = int((h1 + uint64(i)*h2) % n)
		}
		return primaryHash
	}
	// A v1 index set is determined by (h1 mod n, h2 mod n), approximately
	// n²/4 possibilities. Two difference keys therefore share all k cells
	// with probability about 4/n², independent of k; at n=1024 that floor is
	// 2^-18 and does not recede when n grows proportionally to the difference.
	//
	// v2 applies splitmix64 separately for each index. This models the pair-
	// collision floor as n^-k (2^-40 at n=1024, k=4), leaving the 2-core
	// threshold as the binding constraint: peeling succeeds with high
	// probability when n > c_k*d, with c4=1.295 (Goodrich–Mitzenmacher,
	// Theorem 1). These deterministic rounds are not proven k-wise
	// independent, so the Monte Carlo tests measure the finite-size behavior
	// rather than assuming the asymptotic model.
	//
	// Disjoint 16-bit fields would be cheaper but require a power-of-two table
	// and collapse indices above k=4 to bucket zero. Wire decoding accepts k
	// through 8, so those fields are not a suitable replacement.
	for i := 0; i < t.k; i++ {
		x := primaryHash + (uint64(i)+1)*0x9E3779B97F4A7C15
		x ^= x >> 30
		x *= 0xBF58476D1CE4E5B9
		x ^= x >> 27
		x *= 0x94D049BB133111EB
		x ^= x >> 31
		out[i] = int(x % n)
	}
	return primaryHash
}

// getHashes returns an allocated index slice for tests and diagnostic callers.
// Reconciliation uses getHashesInto with stack storage instead.
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
	// Stack-allocated indices — no make() per Insert.
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
	// Stack-allocated indices — no make() per Delete.
	var indices [ibltMaxK]int
	hashSum := t.getHashesInto(&indices, key)
	for i := 0; i < t.k; i++ {
		idx := indices[i]
		t.buckets[idx].Count -= 1
		t.buckets[idx].KeySum ^= key
		t.buckets[idx].HashSum ^= hashSum
	}
}

// Subtract mathematically diffs two IBLTs. The resulting IBLT contains only
// the transactions that differ between the local and remote nodes.
//
// For each bucket i:
//   - Diff.Count[i]   = A.Count[i]   - B.Count[i]
//   - Diff.KeySum[i]  = A.KeySum[i]  ^ B.KeySum[i]
//   - Diff.HashSum[i] = A.HashSum[i] ^ B.HashSum[i]
func (t *IBLT) Subtract(other *IBLT) (*IBLT, error) {
	// The scheme-mismatch reject (the subtractArena sibling — see its
	// comment; never subtract a v1 table against a v2 table, in-process or
	// cross-process).
	if len(t.buckets) != len(other.buckets) || t.k != other.k || t.schemeV2 != other.schemeV2 {
		return nil, errors.New("IBLT configurations must match perfectly (bucket count, k, and digest scheme: cannot subtract a v1 double-hash table against a v2 k-decorrelated table)")
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

// isPure reports whether idx is a usable singleton bucket. Count must be +1
// (local-only) or -1 (remote-only), and hashing KeySum must reproduce HashSum.
// The hash check rejects count collisions except when their hashes also
// collide; Peel still verifies that every bucket is empty before succeeding.
func (t *IBLT) isPure(idx int) bool {
	b := t.buckets[idx]
	if b.Count != 1 && b.Count != -1 {
		return false
	}

	// Stack-allocated indices; only the hash is consumed.
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

	// A head index provides constant-time dequeue without reslicing away the
	// consumed prefix. Periodic compaction reclaims that prefix once at least
	// half the queue has been consumed.
	pureQueue := make([]int, 0, len(t.buckets)/4)
	head := 0 // index of the next pure bucket to peel

	// Initial scan to populate the queue with all purely decoded buckets.
	for i := range t.buckets {
		if t.isPure(i) {
			pureQueue = append(pureQueue, i)
		}
	}

	// Each cascade step uses a stack-allocated index array — no
	// make([]int, t.k) per step.
	for head < len(pureQueue) {
		idx := pureQueue[head]
		head++

		b := t.buckets[idx]

		// Re-verify purity in case a previous cascade altered this bucket.
		if !isPureCount(b.Count) {
			continue
		}
		// Check HashSum as well as the count before decoding the key.
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

		// Compaction reclaims the consumed prefix. Copying is amortized over
		// queue entries, and ordinary dequeues remain constant-time.
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

// PeelArena performs Peel with arena backing for localHas, remoteHas, and the
// pure-bucket queue. It returns arena offsets alongside the result slices so
// the caller can retire their storage. GenerateDelta retains localHas in the
// delta and releases it with CRDTDelta.Release; the other paths use heap Peel.
//
// Arena exhaustion falls back to heap Peel and returns zero offsets. On arena
// success the returned slices use the allocated capacity directly, keeping
// result growth off the Go heap.
func (t *IBLT) PeelArena(arena *HamtArena) (localHas, remoteHas []uint64, localHasOffset, remoteHasOffset, pureQueueOffset uint64, err error) {
	n := len(t.buckets)
	// Preallocate n slots for each slice so ordinary result growth uses arena
	// memory rather than the Go heap. Returned lengths reflect decoded keys.
	localBacking := arena.allocVar(uintptr(n) * unsafe.Sizeof(uint64(0)))
	remoteBacking := arena.allocVar(uintptr(n) * unsafe.Sizeof(uint64(0)))
	queueBacking := arena.allocVar(uintptr(n) * unsafe.Sizeof(int(0)))
	if localBacking == 0 || remoteBacking == 0 || queueBacking == 0 {
		// Arena exhaustion uses the heap implementation rather than panicking.
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
// Stratified Invertible Bloom Lookup Trees
// ---------------------------------------------------------------------------
//
// StrataEstimator partitions keys by trailing zeros in their hash. Each
// stratum holds an 80-bucket, k=3 IBLT. Peers subtract strata from highest to
// lowest; the first stratum that cannot peel supplies the scale for an
// estimate of the symmetric difference. DynamicIBLTSize then applies a 1.5
// sizing factor for reconciliation.

const (
	// strataCount is the number of strata. For a 64-bit hash space,
	// 32 strata covers 2^32 granularity — sufficient for sets up to 4 billion.
	strataCount = 32

	// strataIBLTBuckets is the fixed IBLT size per stratum.
	// 80 buckets with k=3 reliably peels up to ~50 differences per stratum.
	strataIBLTBuckets = 80

	// strataK is the number of hash functions per stratum IBLT.
	strataK = 3

	// ibltSafetyFactor is 3/2: DynamicIBLTSize allocates 1.5 buckets per
	// estimated difference before applying the minimum bucket floor.
	ibltSafetyFactor = 3 // numerator; divided by 2 → 1.5×

	// minDynamicBuckets is the floor for dynamically-sized IBLTs.
	minDynamicBuckets = 128
)

// StrataEstimator partitions keys by trailing-zero count. It contains 32
// independently allocated IBLTs of 80 in-memory Buckets each; construction
// allocates the full structure and later inserts do not resize it.
type StrataEstimator struct {
	strata [strataCount]*IBLT
	seed   maphash.Seed
}

// NewStrataEstimator creates a new estimator with the given hash seed.
// Both peers must use the same seed for subtraction to work.
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

// Estimate estimates the symmetric-difference size by subtracting remote's
// strata from highest to lowest. It accumulates decoded keys until a stratum
// cannot peel, then scales the partial count by 2^(s+1) for that stratum's
// sampling probability. If every stratum peels, it returns the exact count.
// Exchanging an estimator costs strataCount × strataIBLTBuckets × 20 wire
// bytes, excluding headers.
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

// DynamicIBLTSize applies the 1.5 sizing factor to a strata estimate and
// returns at least minDynamicBuckets.
func DynamicIBLTSize(dEst int) int {
	// Integer arithmetic truncates dEst*3/2 before applying the lower bound.
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
