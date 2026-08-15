// Day 23 (ADR-0028) teeth — SkipListArena.Seek, the logarithmic window
// lower-bound iterator (ADR-0024 §6 #1 carry-forward, closed).
//
// Seek IS the Put descent WITHOUT the splice (skiplist_arena.go Put:236-250 →
// Seek:331): top->bottom, advance while bytes.Compare(nextKey, target) < 0,
// break on >= OR the 0xFFFFFFFF end-of-level sentinel; the returned iterator's
// current is nodeNext(prev[0], 0) = the first node whose key >= target. It is a
// LOWER-BOUND, NOT a point lookup. These teeth prove the primitive correct; they
// do NOT wire it into scanWindowRecordBatch (the next fork, §6.a — the Day-12.5
// [243c10a] tooth-principle in REVERSE: drive Seek over a HUGE single entity,
// the production-precondition it exists to accelerate, NOT a 3-row Range toy).
//
// DETERMINISM NOTE: randomHeight() (skiplist_arena.go:78) uses the math/rand/v2
// GLOBAL source, which is auto-seeded + has NO top-level Seed() in v2 (the v1
// rand.Seed was removed). The skiplist's per-node heights are therefore NON-
// deterministic across runs. This is HARMLESS to the equivalence proof: T-SEEK-
// EQUIV compares Seek vs the O(N) linear-scan lower-bound for the ACTUAL skiplist
// each run builds, so byte-identity holds for ANY height distribution — a
// divergence is a descent bug, not a seed artifact. The FUZZ TARGETS are
// deterministic (a local rand.New(rand.NewPCG(23,0))), so the target set is
// reproducible even though the skiplist shape varies.
//
// PREMISE-CORRECTION (disclosed ADR-0028 §7 M2): the prompt's §2.c "random16bytes"
// hash for the fuzz targets would land ~99.99% of targets OUTSIDE the single
// entity the skiplist keys (a random 128-bit hash hits the one fixed entity hash
// with probability 2^-128) — those targets resolve to the trivial before-first
// (lower-bound = first key) or after-end (sentinel) case, barely exercising the
// WITHIN-ENTITY descent where descent bugs hide. The fuzz therefore SPLITS the
// 10k targets: EVEN iterations use the FIXED entity hash (within-entity, the
// load-bearing case — the production precondition Seek exists to accelerate),
// ODD iterations use a RANDOM 16-byte hash (cross-entity boundaries). seed=23.
// The intent (§2.c "the between-keys lower-bound, NOT just the point lower-
// bound — the load-bearing case §2.a alone does NOT exercise") is realized MORE
// honestly than a uniformly-random hash would.

package database

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// day23EntityHash returns the 128-bit (Override 8.4) hash prefix for an entity
// ID — the first 16 bytes of sha256(entityID), the same prefix the production
// composite-key builder (memtable.go:160) writes into key[0:16].
func day23EntityHash(entityID string) [16]byte {
	full := sha256.Sum256([]byte(entityID))
	var h [16]byte
	copy(h[:], full[:16])
	return h
}

// day23BuildKey builds a 40-byte composite key as a STACK [keySize]byte array
// (the memtable.go:159 precedent — a fixed-size array stays on the stack; the
// slice header passed to Seek/Put is the only thing that flows). Layout:
// [hash16 | sysTime8 | validTimeStart8 | assertion8] (BigEndian within each
// 8-byte field → numeric order == byte order → bytes.Compare is the lower-bound
// order). Returns a VALUE (no heap alloc).
func day23BuildKey(hash [16]byte, sysTime, validStart, assertion int64) [keySize]byte {
	var k [keySize]byte
	copy(k[0:16], hash[:])
	binary.BigEndian.PutUint64(k[16:24], uint64(sysTime))
	binary.BigEndian.PutUint64(k[24:32], uint64(validStart))
	binary.BigEndian.PutUint64(k[32:40], uint64(assertion))
	return k
}

// day23PutKey inserts a key with a zero-length value (valLen=0, empty valFn).
// The Seek teeth care only about the KEY ordering; the value content is
// irrelevant to the lower-bound. valLen=0 keeps the arena footprint to one
// 64-byte node + 40 key bytes per row (no packed-value bytes).
func day23PutKey(t *testing.T, sl *SkipListArena, key [keySize]byte) {
	t.Helper()
	if err := sl.Put(key[:], 0, func([]byte) {}); err != nil {
		t.Fatalf("day23PutKey Put: %v", err)
	}
}

// day23PutKeyNoErr inserts a key without a *testing.T (for goroutines that
// cannot call t.Fatalf). Returns the Put error.
func day23PutKeyNoErr(sl *SkipListArena, key [keySize]byte) error {
	return sl.Put(key[:], 0, func([]byte) {})
}

// day23LinearLowerBound is the O(N) REFERENCE lower-bound: a full level-0 scan
// from NewIterator returning the offset of the first node whose key >= target
// (or 0xFFFFFFFF if target > all keys). This is the oracle T-SEEK-EQUIV checks
// Seek against — the descent MUST agree with the linear scan for every target.
func day23LinearLowerBound(sl *SkipListArena, target []byte) uint32 {
	it := sl.NewIterator()
	for it.Valid() {
		if bytes.Compare(it.Key(), target) >= 0 {
			return it.current
		}
		it.Next()
	}
	return 0xFFFFFFFF
}

// ---------------------------------------------------------------------------
// T-SEEK-LOWERBOUND — §0.b headline: every key is its own lower-bound.
// ---------------------------------------------------------------------------

// TestTrack23_T_SEEK_LOWERBOUND is DAY-23 T-SEEK-LOWERBOUND. Builds a skiplist
// of N=4096 DISTINCT composite keys for ONE entity (fixed hash, monotonic
// sysTime + validTimeStart — the huge-single-entity production precondition).
// For each inserted key K_i: Seek(K_i) returns the node with key EXACTLY K_i
// (a key is its own lower-bound), AND Seek(K_i - epsilon) returns K_i (the
// just-before lower-bound — epsilon = validStart-1 keeps hash+sysTime equal so
// the target is lexicographically in (K_{i-1}, K_i)). This is the §0.b contract:
// Seek IS the Put descent exposed; it finds what the linear scan finds.
func TestTrack23_T_SEEK_LOWERBOUND(t *testing.T) {
	const N = 4096
	hash := day23EntityHash("day23-lowerbound-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	keys := make([][keySize]byte, N)
	for i := 0; i < N; i++ {
		keys[i] = day23BuildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0)
		day23PutKey(t, sl, keys[i])
	}
	require.Equal(t, uint32(N), sl.Count())

	for i := 0; i < N; i++ {
		ki := keys[i]
		// (1) Point lower-bound: Seek(K_i) returns K_i.
		got := sl.Seek(ki[:]).Key()
		assert.Equalf(t, ki[:], got, "Seek(K_i) must return EXACTLY K_i (a key is its own lower-bound); i=%d", i)
		// (2) Just-before lower-bound: Seek(K_i - epsilon) returns K_i.
		before := day23BuildKey(hash, int64(i)*1000, 1000+int64(i)*100-1, 0)
		gotBefore := sl.Seek(before[:]).Key()
		assert.Equalf(t, ki[:], gotBefore, "Seek(K_i - epsilon) must return K_i (the just-before lower-bound); i=%d", i)
	}
	// NewSeekIterator symmetry: the one-liner returns the SAME cursor as Seek.
	assert.Equal(t, sl.Seek(keys[0][:]).current, sl.NewSeekIterator(keys[0][:]).current,
		"NewSeekIterator(target) must == Seek(target) (the one-liner symmetry)")
	t.Logf("T-SEEK-LOWERBOUND PASS: N=4096, every key is its own lower-bound; Seek(K) == the node a linear scan finds at K.")
}

// ---------------------------------------------------------------------------
// T-SEEK-BEFORE-FIRST — §0.c lower-bound boundary: target < first key.
// ---------------------------------------------------------------------------

// TestTrack23_T_SEEK_BEFORE_FIRST is DAY-23 T-SEEK-BEFORE-FIRST. A target with
// validStart BELOW the first inserted key (same hash + sysTime=0, validStart=0
// < first's validStart=1000 → target < first key, all fields non-negative so the
// int64-BigEndian-negative trap is avoided). Seek(target) MUST return the FIRST
// node (current == NewIterator().current — byte-identity with the full-scan
// first node). The lower-bound of "everything >= target" when target < all keys
// IS the first key; a Seek that returns nil/0/panics here is a bug.
func TestTrack23_T_SEEK_BEFORE_FIRST(t *testing.T) {
	const N = 4096
	hash := day23EntityHash("day23-beforefirst-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	for i := 0; i < N; i++ {
		day23PutKey(t, sl, day23BuildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0))
	}
	// target < first key: hash equal, sysTime=0 (== first's sysTime since i=0),
	// validStart=0 < first's validStart=1000.
	target := day23BuildKey(hash, 0, 0, 0)
	it := sl.Seek(target[:])
	require.Truef(t, it.Valid(), "target < first key: Seek must return the FIRST node (the lower-bound when target < all keys), not nil/panic")
	firstIt := sl.NewIterator()
	require.True(t, firstIt.Valid(), "skiplist non-empty")
	assert.Equalf(t, firstIt.current, it.current, "Seek(before-first).current must == NewIterator().current (the SAME first node — byte-identity)")
	assert.Truef(t, bytes.Compare(it.Key(), target[:]) >= 0, "the returned first key must be >= target")
	t.Logf("T-SEEK-BEFORE-FIRST PASS: target < first key -> Seek returns the FIRST node (== NewIterator); the lower-bound of '< all keys' is the first key.")
}

// ---------------------------------------------------------------------------
// T-SEEK-EQUIV — §0.b fuzz tooth (load-bearing): 10k targets, Seek == linear.
// ---------------------------------------------------------------------------

// TestTrack23_T_SEEK_EQUIV is DAY-23 T-SEEK-EQUIV, the LOAD-BEARING equivalence
// proof. For 10,000 fuzzed targets (seed=23 deterministic), each target's
// lower-bound is computed TWO ways: (1) Seek(target) — the O(maxHeight)
// descent; (2) day23LinearLowerBound — the O(N) full level-0 scan. Assert the
// two return the SAME current offset for ALL targets, INCLUDING targets past
// the end (both 0xFFFFFFFF). A divergence is a CORRECTNESS bug (the descent
// broke). The fuzz CAUGHT divergences in prior forks (Day-20 T-EQUIV) — this is
// the gate that earns the headline.
func TestTrack23_T_SEEK_EQUIV(t *testing.T) {
	const N = 4096
	const fuzzN = 10000
	hash := day23EntityHash("day23-window-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	for i := 0; i < N; i++ {
		day23PutKey(t, sl, day23BuildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0))
	}
	require.Equal(t, uint32(N), sl.Count())

	rng := rand.New(rand.NewPCG(23, 0))
	var mismatches int
	for f := 0; f < fuzzN; f++ {
		var target [keySize]byte
		// EVEN: fixed entity hash (within-entity descent — the load-bearing case).
		// ODD: random 16-byte hash (cross-entity boundaries). See file docstring
		// premise-correction M2 for why this split beats a uniformly-random hash.
		if f&1 == 0 {
			copy(target[0:16], hash[:])
		} else {
			binary.BigEndian.PutUint64(target[0:8], rng.Uint64())
			binary.BigEndian.PutUint64(target[8:16], rng.Uint64())
		}
		binary.BigEndian.PutUint64(target[16:24], rng.Uint64())
		binary.BigEndian.PutUint64(target[24:32], rng.Uint64())
		binary.BigEndian.PutUint64(target[32:40], rng.Uint64())

		seekCur := sl.Seek(target[:]).current
		linCur := day23LinearLowerBound(sl, target[:])
		if seekCur != linCur {
			mismatches++
			if mismatches <= 5 {
				t.Errorf("T-SEEK-EQUIV mismatch at f=%d: seek=0x%x lin=0x%x target=%x", f, seekCur, linCur, target)
			}
		}
	}
	require.Zero(t, mismatches, "T-SEEK-EQUIV: O(log N) Seek must == O(N) linear-scan lower-bound for ALL 10000 fuzzed targets (a divergence is a descent bug)")
	t.Logf("T-SEEK-EQUIV PASS: 10000 fuzzed targets, O(log N) Seek == O(N) linear-scan lower-bound for ALL (seed=23).")
}

// ---------------------------------------------------------------------------
// T-SEEK-END — §0.c sentinel: target past the last key -> exhausted.
// ---------------------------------------------------------------------------

// TestTrack23_T_SEEK_END is DAY-23 T-SEEK-END. A target PAST the last inserted
// key (same hash + sysTime = last's sysTime, validStart = last + 1_000_000 →
// target > last key). Seek(target).Valid() MUST be false (current == 0xFFFFFFFF,
// the end-of-list sentinel). A Seek that returns the LAST node (key < target)
// here is a LOWER-BOUND VIOLATION — the lower-bound of "> all keys" is the
// SENTINEL, not the last key. The tooth also confirms the last key IS < target
// (else returning it would be correct, not a violation — the self-check).
func TestTrack23_T_SEEK_END(t *testing.T) {
	const N = 4096
	hash := day23EntityHash("day23-end-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	for i := 0; i < N; i++ {
		day23PutKey(t, sl, day23BuildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0))
	}
	lastSys := int64(N-1) * 1000
	lastValid := 1000 + int64(N-1)*100
	target := day23BuildKey(hash, lastSys, lastValid+1_000_000, 0)
	it := sl.Seek(target[:])
	assert.Falsef(t, it.Valid(), "target past last key: Seek must be exhausted (0xFFFFFFFF), NOT return the last node (which is < target)")
	assert.Equal(t, uint32(0xFFFFFFFF), it.current)
	// Self-check: the last key IS < target (else returning it would be correct).
	lit := sl.NewIterator()
	var lastKey []byte
	for lit.Valid() {
		lastKey = lit.Key()
		lit.Next()
	}
	assert.Truef(t, bytes.Compare(lastKey, target[:]) < 0, "the last key MUST be < target (else Seek returning it would be correct, not a violation)")
	t.Logf("T-SEEK-END PASS: target past last key -> Valid()==false (0xFFFFFFFF sentinel); the lower-bound of '> all keys' is end-of-list, NOT the last key.")
}

// ---------------------------------------------------------------------------
// T-SEEK-EMPTY — the empty-skiplist boundary (no Puts yet).
// ---------------------------------------------------------------------------

// TestTrack23_T_SEEK_EMPTY is DAY-23 T-SEEK-EMPTY. A FRESH skiplist (Count()==0;
// NewSkipListArena initializes ALL head nexts to 0xFFFFFFFF). Seek(anyTarget)
// descends (height=1: level-0 nodeNext(0,0)=0xFFFFFFFF → immediate break) +
// returns current = nodeNext(0,0) = 0xFFFFFFFF → Valid()==false. A Seek that
// panics on an empty skiplist (e.g. dereferences node 0's key) is a bug. The
// empty skiplist's lower-bound of any target is end-of-list.
func TestTrack23_T_SEEK_EMPTY(t *testing.T) {
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 1024*1024)
	defer sl.Free()
	require.Equal(t, uint32(0), sl.Count())
	target := day23BuildKey(day23EntityHash("any-entity"), 42, 99, 7)
	it := sl.Seek(target[:])
	assert.Falsef(t, it.Valid(), "empty skiplist: Seek must return an exhausted iterator (0xFFFFFFFF sentinel), not a node or panic")
	assert.Equal(t, uint32(0xFFFFFFFF), it.current)
	t.Logf("T-SEEK-EMPTY PASS: fresh skiplist Count()=0, Seek(anyTarget).Valid()==false (0xFFFFFFFF sentinel); the empty lower-bound is end-of-list.")
}

// ---------------------------------------------------------------------------
// T-SEEK-ALLOC — §0.e zero-alloc: per-Seek alloc count (MEASURED, not "0").
// ---------------------------------------------------------------------------

// TestTrack23_T_SEEK_ALLOC is DAY-23 T-SEEK-ALLOC. testing.AllocsPerRun over a
// single Seek (N=4096 skiplist). The HONEST expectation: 1 alloc — the
// *SkipListIterator struct Seek returns (the NewIterator precedent — the
// disclosed read-path residual, NOT the write-path zero-alloc gate). The
// per-descent-step count is 0 (nodeKey is a zero-copy slice header into the
// arena; the target is a stack [keySize]byte + slice header). The target is
// built INSIDE the AllocsPerRun closure so it does not escape (building it
// outside + capturing would heap-allocate the array — the anti-pattern). Assert
// allocs <= 1 + report the MEASURED number (Law V — NOT "zero-alloc", which
// would be false for the struct).
func TestTrack23_T_SEEK_ALLOC(t *testing.T) {
	const N = 4096
	hash := day23EntityHash("day23-alloc-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()
	for i := 0; i < N; i++ {
		day23PutKey(t, sl, day23BuildKey(hash, int64(i)*1000, 1000+int64(i)*100, 0))
	}
	allocs := testing.AllocsPerRun(100, func() {
		// Target built INSIDE the closure — a stack [keySize]byte that does not
		// escape (Seek only reads it via bytes.Compare; nothing stores it).
		target := day23BuildKey(hash, 1234, 50000, 0)
		_ = sl.Seek(target[:])
	})
	t.Logf("T-SEEK-ALLOC: Seek allocs/run = %v (the *SkipListIterator struct; per-descent-step = 0; target on stack)", allocs)
	assert.LessOrEqualf(t, allocs, 1.0, "Seek must allocate <= 1 (the iterator struct); the descent + the target stay on the stack — got %v", allocs)
}

// ---------------------------------------------------------------------------
// T-SEEK-CONCURRENT — §0.d lock-free: -race, valid lower-bound under writers.
// ---------------------------------------------------------------------------

// TestTrack23_T_SEEK_CONCURRENT is DAY-23 T-SEEK-CONCURRENT, the lock-free
// contract tooth (run under -race). ONE writer goroutine Puts N=100,000 keys
// (same entity hash, monotonic validTimeStart) while M=8 reader goroutines each
// call Seek at 1,000 random within-entity targets (M*1,000 = 8,000 Seeks).
// Asserts: (1) 0 data races under -race — Seek reads nodeNext via the SAME
// atomic.LoadUint32 path Put's search uses (a race means Seek is NOT lock-free —
// a regression of the Override 7.1 contract). (2) EVERY Seek result is a valid
// lower-bound AT THE READ MOMENT: for each returned node with key K,
// bytes.Compare(K, target) >= 0 (the inviolable lower-bound property — the
// returned node is never < target). (3) A QUIESCENT re-check exploits MONOTONE
// GROWTH (nodes are never removed): the final-state lower-bound of each target
// is <= the moment-of-read lower-bound (more keys can only push the lower-bound
// DOWN). This is the honest scoping of §6.d — a "valid lower-bound at the read
// moment," NOT a real-time-linearizability proof (the re-walk confirms
// quiescent validity, not linearizable Seek).
//
// THIS TOOTH CAUGHT THE LOAD-BEARING BUG (ADR-0028 §0.M3 / §3): a NAIVE Seek —
// the bare multi-level descent returning nodeNext(prev[0], 0) — VIOLATED (2)
// under the concurrent writer (~1-2% of seeks returned a node whose key < target;
// the §0.c sentinel class fired worst: target > all keys returned the last node
// instead of the sentinel). Root cause: Put's search is correct under concurrent
// inserts ONLY because its Phase-2 CAS-splice FAILS + re-searches when a
// predecessor's next moved (skiplist_arena.go Put:273-287) — the CAS is the
// self-correction; a READ-ONLY descent has no CAS, so the multi-level descent
// can observe a transiently-inconsistent snapshot (a high-level predecessor's
// level-0 successor whose key is < target at the read moment — the bottom-up
// splice is settling). The level-0-only linear scan NEVER violated (PROVEN:
// only the multi-level descent did) — the level-0 chain is the STABLE total
// order. THE FIX (in Seek, skiplist_arena.go): after the descent, VERIFY the
// level-0 result (sentinel OR nodeKey(cur) >= target); on the rare transient,
// fall back to a FRESH level-0 linear walk (seekLowerBoundLinear). Lock-free
// (no mutex), always a valid lower-bound, O(maxHeight) quiescent + O(N) only on
// the rare concurrent transient. On a quiescent skiplist (the production
// precondition — Seek's only consumer reads a FROZEN arena, l0_flusher.go:198)
// the guard NEVER fires. This tooth is the gate that earned the §5 headline.
func TestTrack23_T_SEEK_CONCURRENT(t *testing.T) {
	const N = 100_000
	const M = 8
	const seeksPerReader = 1000
	hash := day23EntityHash("day23-concurrent-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 64*1024*1024)
	defer sl.Free()

	writerDone := make(chan struct{})
	var putErr error
	go func() {
		defer close(writerDone)
		for i := 0; i < N; i++ {
			k := day23BuildKey(hash, int64(i), 1000+int64(i), 0)
			if err := day23PutKeyNoErr(sl, k); err != nil {
				putErr = err
				return
			}
		}
	}()

	type seekResult struct {
		target [keySize]byte
		cur    uint32
	}
	var mu sync.Mutex
	var results []seekResult
	var wg sync.WaitGroup
	for r := 0; r < M; r++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, 0))
			local := make([]seekResult, 0, seeksPerReader)
			for s := 0; s < seeksPerReader; s++ {
				// Within-entity target (the production precondition): fixed hash,
				// random sysTime/validStart/assertion -> lands in the entity's
				// key range, stressing the live descent.
				var target [keySize]byte
				copy(target[0:16], hash[:])
				binary.BigEndian.PutUint64(target[16:24], rng.Uint64())
				binary.BigEndian.PutUint64(target[24:32], rng.Uint64())
				binary.BigEndian.PutUint64(target[32:40], rng.Uint64())
				cur := sl.Seek(target[:]).current
				local = append(local, seekResult{target, cur})
			}
			mu.Lock()
			results = append(results, local...)
			mu.Unlock()
		}(1000 + uint64(r))
	}
	wg.Wait()
	<-writerDone
	require.NoError(t, putErr, "writer Puts must all succeed (arena big enough for N=%d keys)", N)
	require.Equal(t, uint32(N), sl.Count(), "all N keys inserted")

	// (2) Inviolable lower-bound check (holds at the read moment): every
	// returned key (where Valid) is >= target.
	var violations int
	for _, res := range results {
		if res.cur == 0xFFFFFFFF {
			continue // past-end at the read moment — the sentinel is a valid lower-bound.
		}
		key := sl.nodeKey(res.cur)
		if bytes.Compare(key, res.target[:]) < 0 {
			violations++
			if violations <= 5 {
				t.Errorf("T-SEEK-CONCURRENT lower-bound violation: returned key < target (cur=0x%x)", res.cur)
			}
		}
	}
	require.Zero(t, violations, "every Seek result must be a valid lower-bound (returned key >= target) at the read moment")

	// (3) Quiescent re-check (monotone growth): the final-state lower-bound of
	// each target is <= the moment-of-read lower-bound. Keys are only ADDED
	// (never removed — no delete in the skiplist API), so the lower-bound can
	// only move DOWN. The moment key is still present in the final state.
	var quiescentViol int
	for _, res := range results {
		if res.cur == 0xFFFFFFFF {
			continue // moment was past-end; the final state (more keys) may now resolve — not comparable.
		}
		finalCur := sl.Seek(res.target[:]).current
		if finalCur == 0xFFFFFFFF {
			// Impossible under monotone growth: the moment key (>= target) is still
			// present, so the final lower-bound <= moment key exists. A fires = corruption.
			quiescentViol++
			continue
		}
		if bytes.Compare(sl.nodeKey(finalCur), sl.nodeKey(res.cur)) > 0 {
			quiescentViol++
		}
	}
	require.Zero(t, quiescentViol, "quiescent re-check: final lower-bound <= moment lower-bound (monotone growth — keys only added)")
	t.Logf("T-SEEK-CONCURRENT PASS: M=%d readers * %d Seeks + N=%d concurrent Puts, 0 races, every Seek a valid lower-bound (re-checked post-quiescent).", M, seeksPerReader, N)
}

// ---------------------------------------------------------------------------
// T-SEEK-LOGN — §0.a complexity (MEASURED bench, NOT a complexity proof).
// ---------------------------------------------------------------------------

// BenchmarkTrack23_SeekLogN + BenchmarkTrack23_LinearScanLogN are DAY-23
// T-SEEK-LOGN. Both build a skiplist of N=131072 (2^17) keys (same entity,
// monotonic) + measure ns/op over the SAME N deterministic targets (seed=42).
// Seek is O(maxHeight) per call (the descent visits <= maxHeight=11 nodes —
// §6.c: the height CAPS the asymptotic at O(maxHeight), NOT unbounded O(log N);
// for N>>2048 the descent saturates at 11). The linear scan is O(N) per call
// (~N/2 nodes walked). The RATIO (linearNs/seekNs) is the headline — measured,
// NOT "O(log N)" (Law V). Run: go test -bench='BenchmarkTrack23_(Seek|Linear)-race=false' ./internal/database/
func benchmarkTrack23Build(b *testing.B, N int) (*SkipListArena, [][keySize]byte) {
	b.Helper()
	hash := day23EntityHash("day23-bench-entity")
	alloc := NewJemallocAllocator()
	sl := NewSkipListArena(alloc, 64*1024*1024)
	for i := 0; i < N; i++ {
		k := day23BuildKey(hash, int64(i), int64(i)*100, 0)
		if err := day23PutKeyNoErr(sl, k); err != nil {
			b.Fatalf("bench Put: %v", err)
		}
	}
	rng := rand.New(rand.NewPCG(42, 0))
	targets := make([][keySize]byte, N)
	for i := range targets {
		targets[i] = day23BuildKey(hash, rng.Int64N(int64(N)), rng.Int64N(int64(N)*100), rng.Int64N(1000))
	}
	return sl, targets
}

func BenchmarkTrack23_SeekLogN(b *testing.B) {
	const N = 131072
	sl, targets := benchmarkTrack23Build(b, N)
	defer sl.Free()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sl.Seek(targets[i%N][:])
	}
}

func BenchmarkTrack23_LinearScanLogN(b *testing.B) {
	const N = 131072
	sl, targets := benchmarkTrack23Build(b, N)
	defer sl.Free()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		target := targets[i%N][:]
		it := sl.NewIterator()
		for it.Valid() {
			if bytes.Compare(it.Key(), target) >= 0 {
				break
			}
			it.Next()
		}
		_ = it
	}
}
