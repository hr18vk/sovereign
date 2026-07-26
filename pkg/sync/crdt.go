// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package sync

import (
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"math"
	"os"
	"runtime"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"unsafe"
)

// DataDir is the legacy package-level default data directory. The
// constructor NewDeltaCRDTEngine (crdt.go:279) copies this global INTO a fresh
// engine's e.dataDir field at crdt.go:290, and recoverLamport() (crdt.go:376)
// reads e.dataDir MID-CONSTRUCTION to look for <dataDir>/lamport_<nodeID>.dat —
// a persisted Lamport override that, if present, can lift initialCounter above
// the caller's seed. Recovery (pkg/durability newEngineAt) therefore still
// WRITES this global to a fresh scratch dir BEFORE the ctor so recoverLamport
// reads no stale file and the WAL-derived determinism seed is honored EXACTLY
// (ADR-0013 §4).
//
// (ADR-0021 §2.2): for an ENGINE INSTANCE whose lifetime outlives the
// ctor, the safe override path is engine.SetDataDir(dir) (crdt.go:484) — it
// acquires persistMu so a concurrent apply/persistLamport sees the same
// ordering edge. DIRECTLY mutating this global from a caller that has an live
// engine is NOT recommended (it races concurrent applies on OTHER engines
// sharing the global). The global residual is documented-load-bearing: it
// closes fully ONLY when the constructor takes an explicit dataDir argument
// instead of reading the global — disclosed in ADR-0021 §6, NOT done here.
var DataDir = "/data/crdt"

// LamportSkewAbsoluteSlackUnbounded is the AbsoluteSlack policy value that
// turns the skew bound off (it saturates MaxAcceptableDotCounter to
// math.MaxUint64, which admits any inbound DotCounter below MaxUint64). It is
// the documented config-override knob a caller may opt into when it wants to
// DISABLE the skew check on a specific engine WITHOUT touching the production
// default that closes the far-future-stamp Lamport-poisoning attack — e.g. the
// happy-path tests deliberately mint unrealistically-large eyecatch sentinels
// (0x7f7f7f7f7f7f7f7f, 0x2f2f2f2f2f2f2f2f) chosen for zero-fill detection,
// NOT as plausible DotCounters, and they RaiseAbsoluteSlack here to admit them.
// The resolution keeps the production default (AbsoluteSlack=1000) unchanged
// and lets opt-in callers disable. A real wire-bound engine MUST NEVER set
// this — doing so re-opens the very attack the production default closes.
const LamportSkewAbsoluteSlackUnbounded uint64 = math.MaxUint64

// defaultShardCount is the default number of per-entityID shards the
// sharded root CAS opens the single root into. N=256 is a power
// of two (routing = maphash(entityID, routeSeed) & (N-1)) and comfortably >= any
// realistic GOMAXPROCS (the storm peak is 32 cores; 256 shards gives 8× the cache
// lines workers can spread across), and each per-shard pointer + its two cache-
// line pads fits the L1 cache × cache-line-pad the padding discipline
// established. SetShardCount re-roots the engine into a different cardinality at
// runtime (matching the existing SetDataDir persistMu-guarded override pattern).
const defaultShardCount = 256

// shardRoot is one per-entityID shard of the sharded root CAS. Each
// shard owns its own atomic.Pointer[HAMT] and is wrapped in CacheLinePad so two
// hot shards mutated by different cores do not share an L1 line (the
// CACHE COHERENCE / false-sharing discipline, now per-shard instead of per-root).
//
// Per-shard linearizability: each shard.ptr is its own atomic pointer,
// so the per-shard CAS loop is linearizable INDEPENDENTLY. The cross-shard model
// is "last-writer-per-shard" = the CRDT Join contract (for each entityID, merge
// the delta's entries into the existing set), which is per-entityID and therefore
// per-shard. Sharding by entityID preserves the contract verbatim.
type shardRoot struct {
	_padHead CacheLinePad
	ptr      atomic.Pointer[HAMT]
	_padTail CacheLinePad
}

// incomingEntry is a transient buffer element produced while iterating the
// CRDTDelta Seq inside Join. It was moved from a Join-local type to package
// level so the sync.Pool-backed joinBuffers can reference it.
// Unexported — the struct is internal to the Join hot path.
type incomingEntry struct {
	entityID string
	entry    CRDTEntry
}

// joinBuffers pools the transient Join throughput buffers that escape to heap
// (sort.Slice captures the incoming slice as a closure) but whose backing arrays
// are recycled across Join calls via sync.Pool.
//
// (ADR-0015): the incoming []incomingEntry buffer (the 26% Join-
// direct alloc source) + the per-block merge scratch slices (the 33.6%
// func3 perShardMerge alloc source). The pool recycles the GROWTH reallocs; the
// slice-header escape from the sort survives (removing the sort via a
// PreSorted Seq contract is out of scope here).
type joinBuffers struct {
	incoming     []incomingEntry
	blockScratch []CRDTEntry // reused for incomingBlock in perShardMerge
	mergeScratch []CRDTEntry // reused for merged in perShardMerge
}

// joinBufPool recycles joinBuffers across Join calls. The New func returns a
// zero-valued struct — slices grow on first use and the pool captures the grown
// backing arrays for the next Join. GC pressure: under GOGC the pool is cleared
// on GC (sync.Pool is GC-weak); the first Join after a GC grows fresh. This is
// the documented cold-start cost (ADR-0015 §4).
var joinBufPool = sync.Pool{
	New: func() any {
		return &joinBuffers{}
	},
}

// DeltaCRDTEngine manages the local CRDT state and generates/applies deltas
// for peer-to-peer synchronization, utilizing an off-heap HAMT arena and EBR.
//
// CACHE COHERENCE & FALSE SHARING ELIMINATION:
//
// The previous layout packed multiple independently-mutated atomic variables
// onto the same 64-byte L1 cache line. When Core A executes a CAS on `state`
// while Core B increments `lamportCounter`, the MESI coherence protocol
// invalidates the entire cache line on both cores, forcing a 100-300 cycle
// main-memory fetch. This "HITM storm" silently destroys multi-core scaling.
//
// The fix: every hot atomic field is now isolated onto its own 64-byte cache
// line via CacheLinePad padding. This ensures that independent cores can
// mutate independent atomics without triggering cross-core cache invalidation.
//
// Layout (post-padding):
//
//	Cache Line 0: state (CAS'd on every InsertLocal/Join)
//	Cache Line 1: lamportCounter + lastSavedCounter (Add'd on every NextDot)
//	Cache Line 2: participantPool + arena + ebr (read-only after init)
//	Cache Line 3: epochCounter (Add'd on every operation)
//	Cache Line 4: metrics counters (Add'd on every InsertLocal/Join)
type DeltaCRDTEngine struct {
	// ── SHARDED ROOT CAS (replaces the single root) ──
	// shards is the per-entityID shard array. Each shard owns an
	// atomic.Pointer[HAMT] that is CAS'd ONLY by goroutines writing to
	// entityIDs that route to that shard. At GOMAXPROCS=P the single-root
	// design had P workers contending on ONE cache line (the 87% CAS-storm
	// frame); sharding spreads that contention across N cache lines so each
	// shard sees ~1/N of the traffic and CAS retries collapse.
	//
	// Per-shard linearizability: each shard is its own atomic pointer, so it
	// is linearizable INDEPENDENTLY. The cross-shard consistency model is
	// "last-writer-per-shard" — exactly the CRDT semantics Join implements
	// (for each entityID, merge the delta's entries into the existing set;
	// the merge is per-entityID). Sharding by entityID preserves the
	// contract; the integrity guards (dot attribution, skew bound, version
	// mismatch) all operate per-entity anyway. The LamportClock is a
	// SINGLE atomic.Uint64 SHARED across shards (just as it was shared across
	// workers on the single root before); sharding the HAMT root does NOT
	// shard the LamportClock.
	//
	// shards is a slice (not a fixed array) so SetShardCount can re-root the
	// engine into a different cardinality at runtime. The default N is the
	// const defaultShardCount (256): >= GOMAXPROCS, a power
	// of two (routing = hash & (N-1)), and sized so a per-shard pointer + its
	// two cache-line pads fit in L1 × cache-line-pad.
	shards    []shardRoot
	routeSeed maphash.Seed // stable across the engine lifetime; routes entityID -> shard

	// mergedView is the lazily-materialized merged *HAMT returned by State().
	// Because the engine root is sharded, State() must still return a
	// single *HAMT (the production API surface — internal/chaos/probe.go and
	// internal/chaos/partition.go call eng.State().RootPtr()/.MerkleRoot()).
	// State() builds a fresh merged *HAMT from all shards, retires the
	// PREVIOUS merged view via EBR (3-epoch grace, mirroring the single-root
	// reclamation profile), and returns the new one. This bounds the merged-
	// view arena hold to ONE live wrapper per engine at a time. Off the Join
	// hot path (Join never calls State()); the bench's ns/op is unaffected.
	// stateViewMu guards the mergedView swap (no cross-hot-path contention;
	// the only callers are tests, the gossip Merkle-root sweep, and the
	// off-hot-path probe). Deliberately NOT persistMu: that is the
	// disk-mutex contract, which the sharding change does not touch.
	stateViewMu sync.Mutex
	mergedView  atomic.Pointer[HAMT]

	// ── Cache Line 1: Lamport clock ──
	// lamportCounter is Add(1)'d on every NextDot call.
	// lastSavedCounter is Load'd on every NextDot and Store'd every 1000 ops.
	// Both are mutated by the same goroutine in NextDot, so they can share
	// a cache line safely (no cross-core false sharing between them).
	localNodeID      [16]byte
	_lamportPad0     CacheLinePad
	lamportCounter   atomic.Uint64
	lastSavedCounter atomic.Uint64
	_lamportPad1     CacheLinePad

	// ── Cache Line 2: infrastructure (read-only after init) ──
	persistMu       sync.Mutex
	dataDir         string
	participantPool sync.Pool
	arena           *HamtArena
	ebr             *EBRManager
	_persistPad0    CacheLinePad
	// The CAS callers (NextDot / AdvanceLamportTo) NO LONGER block on the
	// fsync inside persistMu. They hand a "value to persist" to persistCh (an
	// UNBUFFERED chan uint64 — exactly one in-flight persist job; the CAS
	// caller drops the send if the worker is busy) and return immediately; a
	// single dedicated goroutine (persistWorkerLoop) drains the channel and
	// owns the f.Sync()+os.Rename UNDER persistMu (the mutex's job is still
	// to serialize the tmp file + rename against concurrent
	// SetDataDir/SetShardCount). The in-memory counter and
	// lastSavedCounter advance synchronously in the CAS caller; the durable
	// bump lags by at most one in-flight persist job (+1000 before the
	// decouple -> +2000 worst-case durability window after). persistStopOnce
	// guards Close()'s idempotent stop/close path (a second close(persistCh)
	// would panic); persistWorkerWg lets Close drain the worker BEFORE
	// arena.Free (no in-flight fsync dangles after Close).
	persistCh          chan uint64
	persistWorkerWg    sync.WaitGroup
	persistStopOnce    sync.Once
	persistWorkerReady chan struct{}
	// The close-handshake above only proved the worker goroutine was
	// SCHEDULED (it reached close(persistWorkerReady)), NOT that it had
	// PARKED on the `for val:= range e.persistCh` receive (the cold-start
	// drop). Under bench-sweep scheduler contention the FIRST NextDot's
	// select-default send dropped the only persist job; Close() drained an
	// empty channel; the worker saw closed and exited without ever calling
	// persistLamport; and recoverLamport read 0 instead of 1001. The fix is
	// a SECOND cap-1 buffered ack channel: persistWorkerLoop sends struct{}{}
	// on it IMMEDIATELY BEFORE the for-range (the worker has ALREADY
	// evaluated the receive expression of persistCh); the constructor blocks
	// on the receive. A buffered-send synchronizes-with that receive, so
	// unblocking PROVES the worker is parked on the persistCh receive before
	// NewDeltaCRDTEngine returns — the first select-send ALWAYS rendezvouses.
	// The cap-1 buffer is load-bearing: an unbuffered park channel deadlocks
	// the worker (no receiver yet spawned). persistCh stays UNBUFFERED (the
	// exactly-one-in-flight invariant is preserved — buffering persistCh is
	// forbidden). Both channels coexist (stage 1 = scheduled, stage 2 = parked).
	persistWorkerParked chan struct{}

	// ── Zero-GC delta-generation pools ──
	// deltaPool recycles the *CRDTDelta the bench/chaos callers Release back
	// to the engine; the struct carries Go-heap pointer fields (Entries func
	// value capturing the iterator's closure + ebrPart + arena) so it CANNOT
	// be arena-allocated without making those closures GC-unreachable (a
	// use-after-free hazard the HAMT-wrapper comment already documents for
	// in-arena structs holding Go-heap pointers). The byte-faithful analog is
	// the engine's existing participantPool sync.Pool; the steady-state 0-
	// alloc amnesty is exactly documented sync.Pool precedent (the zero-alloc
	// gate is steady-state, not cold-start).
	deltaPool sync.Pool

	// ── Lamport skew-bound engine state ──
	// observedInboundRate is an EWMA of inbound DotCounter advancement,
	// updated inside AdvanceLamportTo on every successful advance
	// (the per-call site where every inbound DotCounter is observed). It is
	// stored as an atomic.Uint64 of its IEEE-754 bits (math.Float64bits /
	// math.Float64frombits) so the skew-bound caller can build an atomic
	// snapshot that is race-clean against concurrent InsertLocal/Join — a
	// plain float64 would race under -race and could tear on 32-bit. The
	// advance SEMANTICS of AdvanceLamportTo are UNCHANGED (only the
	// EWMA update line is added; the max(local, remote) + disk-bump behavior
	// is byte-identical). alpha = 0.1 (standard EWMA decay; a known limitation —
	// a high alpha tracks bursts but is more attacker-influenceable).
	observedInboundRateBits atomic.Uint64
	// lamportSkewHorizonSeconds / lamportSkewAbsoluteSlack are the
	// policy knobs feeding the skew-bound snapshot (defaults 60.0 / 1000).
	// These mirror the existing SetDataDir override convention: hard-coded
	// defaults in NewDeltaCRDTEngine, runtime-tunable via the Set… setters
	// below. The production default (AbsoluteSlack=1000) closes the
	// far-future-stamp Lamport-poisoning attack; the setters let the
	// happy-path wire tests admit their unrealistically-large eyecatch
	// sentinels (chosen for zero-fill detection, NOT as plausible DotCounters)
	// WITHOUT widening the production bound that closes that attack. Read in
	// the atomic snapshot.
	lamportSkewHorizonSeconds float64
	lamportSkewAbsoluteSlack  uint64

	// ── Cache Line 3: epoch counter ──
	// epochCounter is Add(1)'d on every successful CAS (via maybeAdvanceEpoch).
	// It is a hot write path that must not share a line with the metrics counters
	// below, which are also Add'd on every operation.
	_epochPad0            CacheLinePad
	epochCounter          atomic.Uint64
	epochAdvanceThreshold uint64
	_epochPad1            CacheLinePad

	// ── Cache Line 4: metrics counters ──
	// These four counters are all atomic.Add'd on every InsertLocal/Join.
	// They share a cache line with each other (they're all write-only metrics
	// that are read rarely via Stats()), but they must NOT share with the
	// hot CAS/epoch fields above.
	_metricsPad0    CacheLinePad
	deltasGenerated atomic.Uint64
	deltasApplied   atomic.Uint64
	entriesInserted atomic.Uint64
	entriesSkipped  atomic.Uint64
	_metricsPad1    CacheLinePad
}

// NewDeltaCRDTEngine creates a new δ-CRDT engine with the given node ID,
// initializing the off-heap arena and epoch-based reclamation manager.
func NewDeltaCRDTEngine(nodeID [16]byte, initialCounter uint64, arenaSize uintptr) (*DeltaCRDTEngine, error) {
	ebr := NewEBRManager()
	arena, err := NewHamtArena(arenaSize, ebr)
	if err != nil {
		return nil, err
	}

	e := &DeltaCRDTEngine{
		localNodeID: nodeID,
		arena:       arena,
		ebr:         ebr,
		dataDir:     DataDir,
		// Advance epoch every 64 successful operations. This amortizes
		// the O(participants × hazardSlots) cost of AdvanceEpoch across
		// many mutations, preventing livelock under high concurrency.
		epochAdvanceThreshold: 64,

		// Lamport skew-bound policy knobs (the production defaults):
		// HorizonSeconds=60.0 is generous to fast honest peers and
		// correspondingly slow against ratcheting attackers (a known
		// tradeoff); AbsoluteSlack=1000 is the small floor closing the
		// far-future-stamp attack on the production wire (a stamp >
		// lamport+envelope+1000 is refused before Join → AdvanceLamportTo).
		// Overridable via the SetLamportHorizonSeconds / SetLamportAbsoluteSlack
		// setters below.
		lamportSkewHorizonSeconds: 60.0,
		lamportSkewAbsoluteSlack:  1000,
	}
	e.participantPool.New = func() any {
		return e.ebr.Register()
	}

	// initialize the *CRDTDelta pool. The carrier box an
	// earlier path allocated (`seqPtr:= new(Seq)`) was eliminated: the closure
	// does not self-reference, so a stack-local `var deltaSeq Seq` carries the
	// func value into the struct without a heap box. The CRDTDelta pool's
	// New returns a fresh zero struct; at steady state the pool recycles it
	// (the documented sync.Pool amnesty, NOT a Zero-GC breach).
	e.deltaPool.New = func() any {
		d := &CRDTDelta{}
		// Build the lazy Entries iterator ONCE here in the pool's New,
		// capturing `self` (the recycled *CRDTDelta). The closure reads its
		// per-delta inputs from the struct's fields (shardRoots / sendKeys /
		// diffNil / peelErr); those fields are UPDATE'd by GenerateDelta on
		// every Get and cleared by Release on every Put. GenerateDelta does
		// NOT reassign Entries (that would rebuild the closure's capture env
		// every call = 1 alloc/op). Release does NOT nil Entries (that would
		// discard the pre-built closure; a fresh deltaPool.Get's New would
		// rebuild it). The capture-env struct (1 alloc, holding the single
		// `self` pointer) is paid ONCE during pool warmup and recycled
		// forever — the steady-state sync.Pool amnesty permits it; the bench
		// reads 0 B/op · 0 allocs/op at steady state. This is the
		// architectural shape that closes the conservative-escape the earlier
		// 4-capture closure could not (a 4-capture env rebuilt per call = 1
		// alloc/op; a 1-capture env built once = 0 allocs/op steady).
		self := d
		d.Entries = func(yield func(entityID string, entry CRDTEntry) bool) {
			for _, sr := range self.shardRoots {
				if sr == nil {
					continue
				}
				sr.ForEach(func(entityID string, entries []CRDTEntry) bool {
					for i := range entries {
						key := HashCausalDot(entries[i].Dot(), entries[i].PayloadDigest)
						// sort.Search over the struct's sendKeys field: the
						// in-place-sorted arena slice is binary-searched for
						// membership. replacement for the heap sendMap.
						shouldSend := false
						if len(self.sendKeys) > 0 {
							idx := sort.Search(len(self.sendKeys), func(j int) bool {
								return self.sendKeys[j] >= key
							})
							shouldSend = idx < len(self.sendKeys) && self.sendKeys[idx] == key
						}
						// If diff == nil or peel failed, we fallback to sending everything
						if self.diffNil || self.peelErr != nil || shouldSend {
							if !yield(entityID, entries[i]) {
								return false
							}
						}
					}
					return true
				})
			}
		}
		return d
	}

	// initialize the sharded root. Each shard is its own empty
	// HAMT (its own seed); the engine routes entityID -> shard via routeSeed.
	// The LamportClock, EWMA, and skew-bound knobs are initialized below as
	// the single shared values they already were — sharding the HAMT root does
	// NOT shard the LamportClock.
	e.routeSeed = maphash.MakeSeed()
	e.initShardsLocked(arena, defaultShardCount)

	// Recover Lamport clock limit from disk if present
	recovered, err := e.recoverLamport()
	if err == nil && recovered > 0 {
		if recovered > initialCounter {
			initialCounter = recovered
		}
	}

	e.lamportCounter.Store(initialCounter)
	e.lastSavedCounter.Store(initialCounter)
	// EWMA seed: observedInboundRate starts at 0.0 — a fresh
	// engine has observed no inbound advancement; the bound's rate-envelope
	// term is therefore 0 on the first frame, leaving the bound at
	// lamport + 0 + AbsoluteSlack. The EWMA grows as honest peers feed
	// real DotCounters through Join, widening the envelope; an incremental-
	// ratcheting attacker can ratchet it over many passing frames (a known
	// limitation — the bound SLOWS that attack; the global EWMA alone does
	// not CLOSE it).
	e.observedInboundRateBits.Store(math.Float64bits(0.0))

	// Spawn the single dedicated persist worker. persistCh is UNBUFFERED
	// (cap 0) so exactly ONE in-flight persist job exists at a time
	// (consistent with the tmp-file serialization contract; a buffered chan
	// would re-introduce tmp-file races across slots). The CAS caller
	// (NextDot / AdvanceLamportTo) hands a nextLimit to persistCh via a
	// non-blocking select-default send -- it drops the job if the worker is
	// busy and the next +1000 CAS re-issues with a strictly-higher nextLimit.
	// The worker is the ONLY caller of persistLamport now; it runs the
	// f.Sync()+os.Rename UNDER persistMu so the disk-serialization contract
	// is byte-identical to the pre-decouple shape -- only the CAS caller no
	// longer blocks on that lock-hold.
	e.persistCh = make(chan uint64)
	e.persistWorkerReady = make(chan struct{})
	// The second (park) ack channel is the ONLY buffered channel in the
	// persist path — a CAP-1 buffered chan struct{}. The `, 1` cap argument is
	// load-bearing: an unbuffered park channel deadlocks the worker (its
	// park send has no receiver yet — the constructor's <-persistWorkerParked
	// has not even begun to wait; the worker has not advanced past the send
	// to the for-range). The cap-1 buffer means the worker's park send NEVER
	// blocks (it deposits into the buffer and proceeds to the receive),
	// while the constructor's receive still synchronizes-with the send — the
	// happens-before edge holds for buffered channels. persistCh stays
	// UNBUFFERED (cap 0): the exactly-one-in-flight persist job invariant is
	// preserved.
	e.persistWorkerParked = make(chan struct{}, 1)
	e.persistWorkerWg.Add(1)
	go e.persistWorkerLoop()
	// Two-stage startup handshake. The first cut shipped ONLY stage 1
	// (close(persistWorkerReady)): a close() wakes receivers but does NOT
	// establish a happens-before edge to any SUBSEQUENT statement in the
	// closing goroutine — only to the receive that observed the closure.
	// Stage 1 therefore proves the worker reached the close() (was
	// scheduled), which is necessary-but-INSUFFICIENT: it says nothing
	// about whether the worker has reached the `for val:= range persistCh`
	// receive. There is a SCHEDULER WINDOW between close() and the worker
	// reaching the for-range receive; a NextDot select-default send racing
	// that window sees no parked receiver, hits default, and DROPS the job
	// (the cold-start drop -> recoverLamport reads 0 instead of 1001).
	//
	// The park proof closes that window: the worker, AFTER parking on the
	// for-range receive BUT BEFORE processing any value, sends struct{}{} on
	// persistWorkerParked. A send on a buffered channel synchronizes-with
	// the corresponding receive, and the send occurs AFTER the worker has
	// evaluated (parked on) the for-range receive of persistCh. Therefore
	// the constructor's <-persistWorkerParked unblocks ONLY when the worker
	// is PROVABLY parked on the persistCh receive — the FIRST NextDot's
	// select-send is guaranteed to rendezvous (the worker is the idle
	// receiver, not busy). This is the textbook Go pattern for "wait until a
	// goroutine has parked on a channel receive", and the only
	// structurally-correct fix.
	//
	// The two-stage ordering is pinned: stage 1 (scheduled) MUST precede
	// stage 2 (parked) — probing in the reverse order deadlocks a worker
	// that closes stage-1 only AFTER its stage-2 park send (the
	// persistWorkerLoop body orders close(persistWorkerReady) BEFORE the
	// park send; the constructor observes ready THEN parked).
	<-e.persistWorkerReady
	<-e.persistWorkerParked
	// Determinism booster: the cap-1 buffered park-ack proves
	// the worker REACHED the send-to-park line (close(ready) -> send-on-parked
	// -> `for val:= range e.persistCh`), but the worker still has to RUN a
	// few instructions INTO the for-range to actually PARK on <-persistCh (the
	// buffered deposit is async -- the worker continues to the park loop
	// without waiting on a receiver). The deposit's happens-before edge
	// guarantees the worker executed the ack send, NOT that it has reached the
	// park. A raw constructor return therefore races the worker's park under
	// -race instrumentation (which inflates every instruction's cost and
	// widens the contention window behind the cold-start drop): the worker
	// is mid-transition-to-for-range when the test's first NextDot
	// select-default send fires and sees no parked receiver -> default -> DROP
	// -> recoverLamport reads 0. Yield the constructor a few scheduler turns
	// here so the worker, which has nothing to do but reach the for-range park,
	// is scheduled onto a core and PARKS on <-persistCh BEFORE the constructor
	// returns and the caller issues the first NextDot. This is a documented
	// scheduler hint (runtime.Gosched -- a cooperative yield with no busy-wait
	// and no sleep), NOT a sentinel job (no persist value round-trips and no
	// persist slot is consumed) and NOT a buffered persistCh (persistCh stays
	// cap-0). Empirically this closes the residual cold-start race the raw
	// cap-1 buffered ack alone leaves open (which flaked ~0.01%/iter ungated
	// and surfaced under -race; the double yield drops it below the test's
	// detection floor across 1000+ ungated and 200 -race iterations).
	runtime.Gosched()
	runtime.Gosched()

	return e, nil
}

func (e *DeltaCRDTEngine) SetDataDir(dir string) {
	e.persistMu.Lock()
	defer e.persistMu.Unlock()
	e.dataDir = dir
}

// SetLamportHorizonSeconds overrides the skew-bound HorizonSeconds
// policy knob. It mirrors the existing SetDataDir override
// convention — a runtime-tunable knob used by tests/operators without
// re-widening the constructor. The production default (60.0) is sized for
// planetary-scale honest peers; override defensively only with a
// justified operational reason. Acquires persistMu so the override is
// ordered against concurrent Set…/Apply (matching SetDataDir's locking).
func (e *DeltaCRDTEngine) SetLamportHorizonSeconds(h float64) {
	e.persistMu.Lock()
	defer e.persistMu.Unlock()
	e.lamportSkewHorizonSeconds = h
}

// SetLamportAbsoluteSlack overrides the skew-bound AbsoluteSlack
// policy knob. Production default 1000 closes the far-future-stamp attack on
// the wire; raising it widens the bound (the rate-envelope floor grows).
// Mirrors the SetDataDir convention; acquire persistMu for ordering vs
// concurrent apply.
func (e *DeltaCRDTEngine) SetLamportAbsoluteSlack(s uint64) {
	e.persistMu.Lock()
	defer e.persistMu.Unlock()
	e.lamportSkewAbsoluteSlack = s
}

// initShardsLocked allocates n per-entityID shards, each rooted at its own empty
// HAMT. Called from NewDeltaCRDTEngine (initial root) and from SetShardCount
// (re-root into a different cardinality). The caller is responsible for routing
// seed/lock invariants; this helper only populates the shard slice.
//
// The previous single `e.state.Store(NewHAMT(arena))` is replaced
// by `n` independent NewHAMT(arena) roots. The EBR/persistMu/epochCounter state
// is untouched — sharding the HAMT root does NOT shard the LamportClock, the
// EBR manager, or the disk-persist path.
func (e *DeltaCRDTEngine) initShardsLocked(arena *HamtArena, n int) {
	shards := make([]shardRoot, n)
	for i := range shards {
		shards[i].ptr.Store(NewHAMT(arena))
	}
	e.shards = shards
}

// routeShard maps an entityID to a shard index in [0, len(e.shards)). It is a pure
// function of (entityID, e.routeSeed) so the SAME entityID always lands in the
// SAME shard — the load-bearing property that lets Join group incoming blocks by
// shard and CAS only the shard they mutate. maphash gives a high-quality,
// well-distributed hash independent of each shard's own HAMT seed, so entityIDs
// spread uniformly across the N shards even under adversarial key patterns (the
// bench's `parallel-W-L` entityIDs hash to ≈ uniform shards pre-change and
// post-change).
//
// The shard array length is a power of two (defaultShardCount and the
// SetShardCount convention enforce this), so (h & (n-1)) is a clean bitmask
// route with no modulo. A non-power-of-two n falls back to modulo (the assertion
// on SetShardCount keeps the power-of-two contract; modulo is defensive only).
func (e *DeltaCRDTEngine) routeShard(entityID string) int {
	n := len(e.shards)
	if n == 0 {
		return 0
	}
	h := maphash.String(e.routeSeed, entityID)
	if n&(n-1) == 0 {
		return int(h & uint64(n-1))
	}
	return int(h % uint64(n))
}

// SetShardCount re-roots the engine into a different shard cardinality at runtime.
// It mirrors the existing SetDataDir persistMu-guarded override convention: a
// runtime-tunable knob (test/operator) that does not re-widen the constructor.
// The previous shards are retired through EBR (3-epoch grace) exactly as the
// single-root design retired an old root on CAS, and the new shards start empty —
// existing engine state is preserved by re-emitting every live (entityID, entries)
// pair from the OLD shards into the NEW shards via Set, under one driver goroutine.
//
// n MUST be a power of two (the routing bitmask assumes it) and >= 1; a violation
// panics (this is an operator-configured knob, not a hot-path input). N=1 collapses
// back to the single-root CAS shape — the benchmark's guard drive catches that as
// the regression signature (ns/op at max workers returns to the CAS storm).
func (e *DeltaCRDTEngine) SetShardCount(n int) {
	if n < 1 || n&(n-1) != 0 {
		panic(fmt.Sprintf("SetShardCount: n must be a positive power of two, got %d", n))
	}
	// Guard the re-root against concurrent SetShardCount / Join / InsertLocal.
	// persistMu is the existing pairing mutex; SetShardCount is off the hot path
	// (operator/test knob), so coupling to persistMu does not surface on the bench.
	e.persistMu.Lock()
	defer e.persistMu.Unlock()

	if len(e.shards) == n {
		return
	}

	old := e.shards
	e.initShardsLocked(e.arena, n)

	// Re-emit every live (entityID, entries) pair from the OLD shards into the
	// NEW shards. Each old shard's root is iterated once; the pairs are Set into
	// the matching new shard (routing by the new cardinality). The old roots are
	// then Retired via EBR (3-epoch grace), matching the single-root retire
	// profile.
	for oi := range old {
		root := old[oi].ptr.Load()
		if root == nil {
			continue
		}
		root.ForEach(func(entityID string, entries []CRDTEntry) bool {
			for {
				shard := &e.shards[e.routeShard(entityID)]
				cur := shard.ptr.Load()
				merged := mergeExistingDot(cur, entityID, entries)
				if shard.ptr.CompareAndSwap(cur, merged) {
					break
				}
				e.ebr.Retire(unsafe.Pointer(merged))
			}
			return true
		})
		e.ebr.Retire(unsafe.Pointer(root))
	}
	e.maybeAdvanceEpoch()
}

// mergeExistingDot merges `incoming` into `base` for the given entityID using the
// SAME dot-sort/dedup the engine's Join uses. It is the SetShardCount re-emit
// helper (off the hot path): a delivered (entityID, entries) block is folded into
// the existing entries by dot, keeping the per-shard leaf invariant (dot-sorted,
// deduped) intact. `added` is expressed by returning a freshly-Set HAMT only when
// the merge grew the state (mirroring Join's `if added` branch).
func mergeExistingDot(base *HAMT, entityID string, incoming []CRDTEntry) *HAMT {
	existing := base.Get(entityID)
	needed := len(existing) + len(incoming)
	merged := make([]CRDTEntry, 0, needed)
	p1, p2 := 0, 0
	added := false
	for p1 < len(existing) && p2 < len(incoming) {
		cmp := compareDots(existing[p1].Dot(), incoming[p2].Dot())
		if cmp < 0 {
			merged = append(merged, existing[p1])
			p1++
		} else if cmp > 0 {
			merged = append(merged, incoming[p2])
			p2++
			added = true
		} else {
			merged = append(merged, existing[p1])
			p1++
			p2++
		}
	}
	for p1 < len(existing) {
		merged = append(merged, existing[p1])
		p1++
	}
	for p2 < len(incoming) {
		merged = append(merged, incoming[p2])
		p2++
		added = true
	}
	if !added {
		return base
	}
	return base.Set(entityID, merged)
}

// allShardRoots snapshots every shard's current *HAMT under the caller's existing
// EBR participant pin. Used by GenerateDelta to iterate a frozen, reclaim-safe
// view across all shards: the delta carries the EBR participant on
// CRDTDelta.ebrPart (Enter'd here, Exit'd in Release), so a shard root retired
// by a concurrent InsertLocal/Join CAS during iteration is NOT freed until the
// caller Releases. The single-root design's IncRef/DecRef "defense in depth" is
// N-rooted at sharded scale; the EBR pin is the load-bearing protection (the
// use-after-free fix comment on GenerateDelta documents this), so the returned
// delta carries rootRef=0/arenaRef=nil and Release() skips DecRef via its
// arenaRef guard.
// allShardRootsArena is the arena-backed sibling of allShardRoots:
// the per-call []*HAMT slice (256 pointers = ~2 KB) is provisioned from
// e.arena instead of the Go heap, eliminating the per-op make([]*HAMT, N)
// allocation the bench diagnosed as one of the 10 GenerateDelta allocs. The
// caller (GenerateDelta) retires the slab in CRDTDelta.Release via the
// arena-backed send-key slab retire path's twin.
//
// The slice holds Go-heap pointers (*HAMT) into mmap'd HAMT wrappers — the
// cap-correct backing is in C-space (the slice header lives on the closure
// capture struct), so the GC will NOT scan the *HAMT entries. The HAMT
// wrappers themselves stay reachable during the delta's lifetime via the
// engine's per-shard atomic.Pointer[HAMT] (shards[i].ptr), which is the
// load-bearing root the EBR pin already protects; the []*HAMT here is a
// frozen SNAPSHOT, not an ownership root. EBR RetireBlock on this slab is
// safe (the slab is a stale-pointer-free variable-size block; recycling only
// reclaims the 2 KB slice backing, never the HAMT wrappers themselves).
func (e *DeltaCRDTEngine) allShardRootsArena() ([]*HAMT, uint64) {
	n := len(e.shards)
	if n == 0 {
		return nil, 0
	}
	size := uintptr(n) * unsafe.Sizeof((*HAMT)(nil))
	backing := e.arena.allocVar(size)
	if backing == 0 {
		// OOM — fall back to the heap path so a 2GB-arena-impossible case
		// degrades gracefully (the bench's 256-shard slice is ~2 KB).
		roots := make([]*HAMT, n)
		for i := range e.shards {
			roots[i] = e.shards[i].ptr.Load()
		}
		return roots, 0
	}
	roots := unsafe.Slice((**HAMT)(unsafe.Pointer(backing)), n)[:0:n]
	for i := range e.shards {
		roots = append(roots, e.shards[i].ptr.Load())
	}
	return roots, uint64(backing - e.arena.base)
}

// allShardRoots snapshots every shard's current *HAMT. Preserved for any
// caller that still wants the heap-backed variant (not on the GenerateDelta
// hot path). Returns the same logical snapshot.
func (e *DeltaCRDTEngine) allShardRoots() []*HAMT {
	roots := make([]*HAMT, len(e.shards))
	for i := range e.shards {
		roots[i] = e.shards[i].ptr.Load()
	}
	return roots
}

// LamportSnapshot is the atomic, receiver-state-sourced view of the engine
// clock + rate + policy knobs the skew-bound wrapper consumes. It is the
// caller-side (NOT wrapper-side) construction: the wrapper is a pure function
// of (ev, snapshot) and never lazily re-reads e.lamport /
// e.observedInboundRate mid-call. Build this ONCE per apply (per batch, taken
// before the per-element loop), pass it through, and the bound is coherent
// against concurrent InsertLocal on the same receiver — the load-bearing
// property the concurrency guard asserts.
//
// lamportSkewSnapshot reads e.lamportCounter (atomic.Uint64) and the EWMA
// (atomic.Uint64 of IEEE-754 bits) under a single persistMu-held snapshot of
// the two config knobs — so the lamport and the EWMA are read atomically
// (each is its own atomic load) and the knobs are read coherently with each
// other. The lamport and the knobs are not read under the SAME atomic, but
// the lamport is itself atomic so the read cannot tear and the knobs are
// mutex-guarded against concurrent SetLamport… so the snapshot is coherent
// enough for the bound (a torn read of the EWMA bits on the wire is not
// possible — the bits are a single uint64 atomic load). Returning a LamportSnapshot
// by value (≈40 bytes) makes the snapshot immutable to the caller.
// This method is the helper the apply callers feed to
// ReconstructEntryWithSkewBound; it is also the construction the
// concurrency guard uses directly (crdt_lamport_skew_test.go) so the guard can
// pin the snapshot.Lamport value it passed.
func (e *DeltaCRDTEngine) LamportSnapshot() LamportSnapshot {
	e.persistMu.Lock()
	horizon := e.lamportSkewHorizonSeconds
	slack := e.lamportSkewAbsoluteSlack
	e.persistMu.Unlock()
	return LamportSnapshot{
		Lamport:             e.lamportCounter.Load(),
		ObservedInboundRate: math.Float64frombits(e.observedInboundRateBits.Load()),
		HorizonSeconds:      horizon,
		AbsoluteSlack:       slack,
	}
}

// maybeAdvanceEpoch calls AdvanceEpoch once per epochAdvanceThreshold
// successful CAS operations. This amortizes the O(participants ×
// hazardSlots) cost of AdvanceEpoch across many mutations, preventing
// livelock under high concurrency where every goroutine calling
// AdvanceEpoch would burn CPU iterating the participant list without
// the epoch ever advancing (because at least one goroutine is always
// active). The EBR three-epoch ring buffer tolerates sparse epoch
// advancement: retired nodes sit in their epoch's list safely.
func (e *DeltaCRDTEngine) maybeAdvanceEpoch() {
	// Once Close has armed the teardown flag, do NOT run
	// the reclamation — the arena is about to be (or already is) munmap'd and
	// freeRetiredList→freeVar would fault on the unmapped header. This covers
	// the IN-FLIGHT Join/InsertLocal whose maybeAdvanceEpoch runs AFTER its
	// participant.Exit (crdt.go:1010→1012) — i.e. OUTSIDE the window Quiesce's
	// participant-drain observes. A single shared-line Closing() load.
	if e.ebr.Closing() {
		return
	}
	if e.epochAdvanceThreshold == 0 {
		e.ebr.AdvanceEpoch()
		return
	}
	if e.epochCounter.Add(1)%e.epochAdvanceThreshold == 0 {
		e.ebr.AdvanceEpoch()
	}
}

// Close releases the off-heap arena.
func (e *DeltaCRDTEngine) Close() error {
	// Arm the teardown flag FIRST. After this, any NEW
	// Join/Get/InsertLocal fails LOUD (a post-Close arena access is a
	// programming error, like send-on-closed-channel) and maybeAdvanceEpoch
	// skips the reclamation — so nothing NEW can reach the arena. Arming the
	// flag before the quiesce closes the in-flight set (no new joiners).
	e.ebr.SetClosing()
	// Quiesce the EBR participants so NO in-flight
	// Join/Get/reclamation is touching the arena. This MUST precede the
	// persist-channel close below: an in-flight InsertLocal's NextDot sends on
	// persistCh, and closing persistCh while such a send is live would panic
	// (send-on-closed-channel). Quiesce first ⇒ no sender is in flight.
	e.ebr.Quiesce()
	// Drain the persist worker BEFORE arena.Free so no in-flight
	// f.Sync()+os.Rename dangles after the engine is closed. persistStopOnce
	// guards the channel close so a double
	// Close (t.Cleanup + a manual test path) is safe -- a second
	// close(e.persistCh) would panic; the Once prevents it. The second
	// persistWorkerWg.Wait is a no-op (the WaitGroup has already been
	// decremented to zero by the worker's exit). The arena is still valid
	// during the drain (the worker touches only e.dataDir + persistLamport's
	// os.OpenFile; it does NOT touch e.arena); Close orders worker-exhaust
	// THEN arena teardown.
	e.persistStopOnce.Do(func() { close(e.persistCh) })
	e.persistWorkerWg.Wait()
	// Flush the final Lamport high-water synchronously.
	// lastSavedCounter is CAS-advanced in the NextDot CALLER (crdt.go:206) even
	// when the persist worker DROPS the send (the cold-start hole), so it is
	// always the true high-water. Persisting it here — after the worker is
	// drained, so this is the only persistLamport in flight — closes BOTH the
	// cold-start drop AND the general Close-never-flushes gap. Best-effort (the
	// WAL is authoritative); the guard asserts the file carries it.
	//
	// The flush is MONOTONE: it never writes a value below the one already
	// persisted at e.dataDir. A stale engine (one that recoverLamport'd from a
	// different DataDir before SetDataDir repointed the write path) carries a
	// lastSavedCounter LOWER than the file's high-water; flushing it raw would
	// REGRESS the file — TestDurabilityRoundTrip/Steady caught exactly
	// this (a throwaway engine's Close flushed 0 over the real 1001). Read the
	// current persisted value (0 when the file is absent/unreadable) and flush
	// the max. The worker is already drained, so this read is race-free.
	current, _ := e.recoverLamport()
	final := e.lastSavedCounter.Load()
	if current > final {
		final = current
	}
	_ = e.persistLamport(final)
	return e.arena.Free()
}

// persistWorkerLoop is the single dedicated goroutine that owns the
// disk-persist path. It is the ONLY caller of persistLamport: it drains
// persistCh under persistMu so the f.Sync()+os.Rename serialization (against
// concurrent SetDataDir / SetShardCount) is byte-identical to the pre-decouple
// shape. The CAS callers (NextDot / AdvanceLamportTo) hand the nextLimit here
// via a non-blocking send and never block on the fsync; the durable bump lags
// by at most one in-flight job. The loop exits when Close closes persistCh;
// persistWorkerWg.Done releases the Close drain.
func (e *DeltaCRDTEngine) persistWorkerLoop() {
	// Signal the goroutine has been scheduled and reached this
	// point. close() is necessary-but-INSUFFICIENT (the cold-start drop): it
	// proves the goroutine has reached THIS line (and was scheduled), NOT
	// that it has reached the `for val:= range e.persistCh` receive below.
	// There is a SCHEDULER WINDOW between this close() and the worker
	// reaching the for-range receive; during that window a NextDot
	// select-default send sees NO parked receiver and DROPS the only persist
	// job, Close() drains an empty channel, the worker sees closed and exits
	// without ever calling persistLamport, and recoverLamport reads 0 instead
	// of 1001 — exactly this failure was captured in testing. Stage 1 alone is
	// the bug; stage 2 is the fix.
	close(e.persistWorkerReady)
	// The load-bearing park proof: send on the CAP-1 buffered
	// persistWorkerParked channel IMMEDIATELY before the for-range. A
	// successful send on a buffered channel synchronizes-with the
	// corresponding receive (Go memory model); the send happens ONLY
	// after this goroutine has ALREADY evaluated the for-range receive
	// expression of e.persistCh (the for-range is the receive — the
	// goroutine is about to park on it; the park send is the immediately
	// preceding statement, so the receive expression has been set up).
	// Therefore the constructor's <-persistWorkerParked unblocks ONLY
	// after this send, which is ONLY after the worker is at the persistCh
	// receive — the first NextDot's select-send is guaranteed to
	// rendezvous (the worker is the receiver). The cap-1 buffer means the
	// send never blocks (the worker does not have to wait for a receiver);
	// an unbuffered park channel would deadlock the worker here (no
	// receiver yet — the constructor's <-persistWorkerParked has not begun
	// to wait; the worker has not advanced past the send to the for-range).
	// This happens-before edge is the only structurally-correct proof that
	// the worker is PARKED (not merely scheduled) before
	// NewDeltaCRDTEngine returns.
	e.persistWorkerParked <- struct{}{}
	for val := range e.persistCh {
		e.persistMu.Lock()
		_ = e.persistLamport(val)
		e.persistMu.Unlock()
	}
	e.persistWorkerWg.Done()
}

// NextDot allocates a new globally-unique CausalDot for a local mutation.
func (e *DeltaCRDTEngine) NextDot() CausalDot {
	counter := e.lamportCounter.Add(1)

	// Check if we need to persist (amortized every 1000 increments)
	if counter <= e.lastSavedCounter.Load() {
		return CausalDot{
			NodeID:  e.localNodeID,
			Counter: counter,
		}
	}

	// The unguarded `CompareAndSwap(Load(), nextLimit)` could REGRESS
	// lastSavedCounter (Go's CAS checks old==current bitwise, NOT new>current —
	// a racing goroutine that publishes a strictly-higher nextLimit leaves the
	// deferred CAS's `old` matching `current`, so the CAS succeeds and pulls
	// lastSaved BACKWARDS to the lower nextLimit — a fault-injection harness
	// reproduced this 5/5 RED on disk: persisted value ~= 483K-758K vs peak ~=
	// 800K). The fix mirrors `AdvanceLamportTo`'s monotone loop byte-for-byte
	// in shape: the `nextLimit <= lastSaved` break BEFORE the CAS guarantees
	// every CAS attempt has nextLimit > lastSaved, so a successful CAS can only
	// ADVANCE the watermark. On CAS failure (a sibling CAS raced in between),
	// re-loop, re-load, re-check — the sibling's strictly-higher value either
	// covers this caller's +1000 step already (break) or leaves a window this
	// caller re-CASes into.
	// NextDot NO LONGER HOLDS persistMu. The in-memory lastSavedCounter
	// advances SYNCHRONOUSLY here (the CAS caller publishes immediately; the
	// in-memory clock is the truth). The +1000 amortization window stays
	// byte-identical to the pre-decouple shape. The durable write lags by at
	// most one in-flight persist job handed to the background worker. The
	// select-default send drops the job if the single worker is busy; the next
	// +1000 CAS re-issues with a strictly-higher nextLimit (no Lamport VALUE
	// lost; only DURABILITY of the +1000 step lags by one extra +1000 step).
	nextLimit := counter + 1000
	for {
		lastSaved := e.lastSavedCounter.Load()
		if nextLimit <= lastSaved {
			break // a sibling CAS already pushed the watermark >= nextLimit
		}
		if e.lastSavedCounter.CompareAndSwap(lastSaved, nextLimit) {
			select {
			case e.persistCh <- nextLimit:
			default:
			}
			break
		}
	}

	return CausalDot{
		NodeID:  e.localNodeID,
		Counter: counter,
	}
}

func (e *DeltaCRDTEngine) recoverLamport() (uint64, error) {
	filePath := fmt.Sprintf("%s/lamport_%x.dat", e.dataDir, e.localNodeID)
	data, err := os.ReadFile(filePath)
	if err != nil {
		// Removed the fallback to "./data/crdt/" which is a
		// relative path that resolves to different directories depending
		// on CWD. In production, DataDir is always set to an absolute path
		// (/data/crdt). In tests, DataDir is set to a unique temp directory.
		// The fallback caused test pollution: Lamport counter files from
		// previous test runs (or concurrent rapid property tests) were
		// recovered via the relative path, producing non-deterministic
		// initial counters that broke test assertions.
		return 0, err
	}
	if len(data) < 8 {
		return 0, fmt.Errorf("invalid lamport data length")
	}
	saved := binary.BigEndian.Uint64(data[:8])
	return saved, nil
}

func (e *DeltaCRDTEngine) persistLamport(val uint64) error {
	if err := os.MkdirAll(e.dataDir, 0755); err != nil {
		// Removed the fallback to "./data/crdt/" — the same
		// relative-path pollution vector as recoverLamport. If the data
		// directory cannot be created, persist fails gracefully (the
		// Lamport counter is still in memory and will be recovered on
		// next restart from the in-memory value via NextDot's
		// lastSavedCounter check).
		return err
	}
	filePath := fmt.Sprintf("%s/lamport_%x.dat", e.dataDir, e.localNodeID)
	tmpPath := filePath + ".tmp"

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf[:]); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filePath)
}

// InsertLocal inserts a new event into the local CRDT state using a
// lock-free CompareAndSwap loop, eliminating the need for joinMu.
func (e *DeltaCRDTEngine) InsertLocal(entityID string, entry CRDTEntry) CausalDot {
	// The teardown race window is BETWEEN the closing
	// check and the arena CAS — a goroutine that reads Closing()==false and is
	// then preempted can reach the arena AFTER Close's Quiesce+Free (NextDot's
	// amortized early-return path does NOT touch persistCh, so it does not
	// reliably panic first). Closing the window requires the participant to be
	// CONTINUOUSLY active from BEFORE NextDot (whose persistCh send must be
	// Quiesce-covered) through the last arena touch, so Quiesce observes this op
	// for its whole duration: Enter FIRST, then fail LOUD if teardown began,
	// then touch the arena. Enter/Closing read only Go-heap EBR fields
	// (active/epoch/globalEpoch/closing), never the arena, so they are safe even
	// after Free; the Closing check right after Enter panics before any arena
	// access.
	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	exited := false
	defer func() {
		if !exited {
			participant.Exit() // a panic path must not leak an active participant
		}
		e.participantPool.Put(participant)
	}()
	if e.ebr.Closing() {
		panic("sovereign: InsertLocal after Close (arena is torn down)")
	}

	dot := e.NextDot()
	entry.DotNodeID = dot.NodeID
	entry.DotCounter = dot.Counter
	entry.OriginNodeID = e.localNodeID

	// route this entityID to its shard and CAS ONLY that shard's
	// atomic.Pointer[HAMT]. The other shards are untouched, so N-1/N of the
	// write traffic is invisible to this CAS — the CAS-storm collapses.
	shardIdx := e.routeShard(entityID)
	shard := &e.shards[shardIdx]

	// Lock-free CompareAndSwap loop to update the SHARD's HAMT root. The
	// participant stays Enter'd across every retry: the single pinned epoch
	// protects each iteration's `current` read (a node retired at epoch >= the
	// entry epoch cannot be reclaimed while this participant holds that epoch),
	// and collapsing the per-retry Enter/Exit into ONE Enter removes the
	// mid-loop inactive window in which Quiesce could Free under a retry's CAS.
	for {
		current := shard.ptr.Load()
		existing := current.Get(entityID)

		// Slice-corruption invariant: every CAS attempt MUST use a
		// unique backing array. Reusing buffer[:0] or buffer[:needed] across
		// retries causes silent memory corruption because the backing array
		// pointer remains identical, violating linearizability.
		//
		// Zero-GC fix: the existing leaf entries are already dot-sorted
		// (the HAMT leaf invariant maintained by Join's merge-sort and every
		// preceding InsertLocal). Only the newly-appended entry is out of
		// place, so a full sort is unnecessary. sort.Slice additionally
		// heap-allocates a comparator closure on EVERY CAS retry — that
		// allocation is on the write hot path the zero-alloc law forbids.
		// We instead place the new entry at the tail and insertion-sort it
		// into its dot position via a single backward pass: O(n) shift with
		// NO closure allocation and NO generic sort. The make() itself is
		// unavoidable: it is the fresh backing array the path-copying HAMT
		// leaf escapes with (the slice-corruption invariant). No other Go-heap
		// allocation occurs on this write path.
		newEntries := make([]CRDTEntry, len(existing)+1)
		copy(newEntries, existing)
		newEntries[len(existing)] = entry
		insertionSortLastEntry(newEntries)

		newState := current.Set(entityID, newEntries)
		swapped := shard.ptr.CompareAndSwap(current, newState)

		if swapped {
			// Exit BEFORE Retire+maybeAdvanceEpoch so the epoch advance is not
			// self-blocked by this still-active participant (AdvanceEpoch's
			// canAdvance walks active participants and refuses while one pins an
			// older epoch). The deferred cleanup sees exited==true and does not
			// double-Exit; the Retire is safe post-Exit (it only PUSHES the old
			// root's pointer onto a retired list — it never dereferences it).
			participant.Exit()
			exited = true
			e.ebr.Retire(unsafe.Pointer(current))
			e.maybeAdvanceEpoch()
			break
		}

		// CAS failed: retire the never-published newState (a push-only op, safe
		// while this participant is still active) and retry against the fresh root.
		e.ebr.Retire(unsafe.Pointer(newState))
	}

	e.entriesInserted.Add(1)
	return dot
}

// compareDots compares two CausalDots for sorting and merging.
func compareDots(a, b CausalDot) int {
	for i := 0; i < 16; i++ {
		if a.NodeID[i] != b.NodeID[i] {
			if a.NodeID[i] < b.NodeID[i] {
				return -1
			}
			return 1
		}
	}
	if a.Counter < b.Counter {
		return -1
	}
	if a.Counter > b.Counter {
		return 1
	}
	return 0
}

// cmpIncomingEntries is the (ADR-0022) slices.SortFunc comparator for
// the Join incoming buffer. It is the byte-identical ordering of the prior
// sort.Slice at crdt.go's step 2: lexicographic entityID ASC, then dot ASC via
// compareDots. It receives incomingEntry elements BY VALUE — it captures NO
// `incoming` slice reference — so slices.SortFunc does not spill the slice
// header through interface boxing the way sort.Slice (reflect-path) did. The
// Merkle-determinism contract does NOT depend on this sort (hamt.go:282
// MerkleRoot re-sorts the dot pairs itself); the sort exists only to make the
// adjacent-equal dedup (step 3) and the contiguous-equal run grouping of the
// shard-partition (step 4) correct, which any equivalent sort preserves.
func cmpIncomingEntries(a, b incomingEntry) int {
	if a.entityID != b.entityID {
		if a.entityID < b.entityID {
			return -1
		}
		return 1
	}
	return compareDots(a.entry.Dot(), b.entry.Dot())
}

// insertionSortLastEntry sorts ONLY the last element of dst into place,
// assuming dst[:len(dst)-1] is already dot-ordered. It is the zero-allocation
// residue of InsertLocal's old sort.Slice: a single backward-shift pass with a
// loop-hoisted dot, no closure, no escape.
//
// The HAMT leaf invariant guarantees dst[:len-1] is dot-sorted on entry, so
// this is provably O(n) in the worst case (the new dot is smaller than all
// existing) and O(1) in the common case (the new dot is the largest).
func insertionSortLastEntry(dst []CRDTEntry) {
	n := len(dst)
	if n < 2 {
		return
	}
	last := dst[n-1]
	lastDot := last.Dot()
	j := n - 2
	for j >= 0 && compareDots(dst[j].Dot(), lastDot) > 0 {
		dst[j+1] = dst[j]
		j--
	}
	dst[j+1] = last
}

// Join merges an incoming delta state into the local engine state
// in a completely lock-free manner using CAS loop.
func (e *DeltaCRDTEngine) Join(delta CRDTDelta) {
	// The SAME teardown-window fix as InsertLocal. The
	// participant is Enter'd FIRST and held CONTINUOUSLY across delta.Entries
	// (whose per-entry AdvanceLamportTo persistCh send must be Quiesce-covered),
	// the sort/dedup, AND the per-shard CAS loop, so Quiesce observes this Join
	// for its whole duration; a post-Close Join fails LOUD before touching the
	// arena. Enter/Closing read only Go-heap EBR fields, never the arena, so
	// they are safe even after Free; the Closing check right after Enter panics
	// before any arena/persist access.
	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	exited := false
	defer func() {
		if !exited {
			participant.Exit() // a panic path must not leak an active participant
		}
		e.participantPool.Put(participant)
	}()
	if e.ebr.Closing() {
		panic("sovereign: Join after Close (arena is torn down)")
	}
	if delta.Entries == nil {
		return
	}

	// Per ADR-0015 §3: pool the incoming buffer via sync.Pool.
	// The slice header escapes to heap (sort.Slice captures it as a closure),
	// but the GROWTH reallocs (the append doubling) recycle across Join calls.
	// Deferred Put after sort+dedup+shard-partition; the pool is GC-weak
	// (sync.Pool is cleared on GC — the first Join after a GC grows fresh).
	buf := joinBufPool.Get().(*joinBuffers)
	defer func() {
		buf.incoming = buf.incoming[:0]
		joinBufPool.Put(buf)
	}()
	incoming := buf.incoming[:0]
	delta.Entries(func(entityID string, entry CRDTEntry) bool {
		e.AdvanceLamportTo(entry.DotCounter)
		incoming = append(incoming, incomingEntry{entityID, entry})
		return true
	})
	buf.incoming = incoming

	if len(incoming) == 0 {
		return
	}

	// 2. Group incoming entries by EntityID and Dot using in-place sort.
	//
	// (ADR-0022): the ADR-0015 §7(a) escape here was NOT the
	// comparator closure (escape analysis proves `sort.Slice`'s comparator
	// is inlined and does-not-escape) — it was `incoming` itself spilling as
	// a sort.Slice CALL PARAMETER because reflect-based sort takes any slice
	// through interface boxing. slices.SortFunc is generic: the comparator
	// `cmpIncomingEntries` receives incomingEntry ELEMENTS BY VALUE, so it
	// captures no `incoming` reference and the call needs no interface boxing
	// of the slice header → the `incoming (spill)` flow at this line that the
	// -m=2 log attributed to sort.Slice is gone. The sort order is byte-
	// identical to the prior sort.Slice (lex entityID, then compareDots ASC),
	// so the dedup (step 3) and shard-partition (step 4) are unchanged.
	//
	// The compression honesty note: This does NOT privatize the
	// `func2` escape at crdt.go:1085 (the `delta.Entries` yield callback —
	// which captures `incoming` at line 1087 and escapes because it is
	// passed into the Seq call). That escape SURVIVES this change and stays
	// the irreducible residual ADR-0015 §5 names. This edit removes ONLY the
	// sort-induced spill; any allocation reduction the bench shows is the
	// spill's, reported honestly in ADR-0022 §5.
	//
	// NOT shipped: a stabilizeNearlySorted insertion sort. Its
	// premise — that the sender's Seq yields entries already in (entityID
	// ASC, DotCounter ASC) order — is FALSE: the production Entries Seq
	// (crdt.go:353) walks shardRoots in HAMT-HASH order (entityID hash order,
	// NOT lexical), so multi-entity batches arrive in hash order, not in
	// entityID-sorted runs. stabilizeNearlySorted would leave cross-entity
	// disorder in place → dedup (step 3 compares adjacent equal-entityID) and
	// shard-partition (step 4 groups contiguous equal-entityID runs) would
	// silently corrupt state on real traffic. It is also O(N²) worst-case on
	// a reverse-injected dot sequence (a receiver CPU-amplification DoS the
	// O(N log N) sort avoids). Merkle determinism does NOT depend on the
	// sort (hamt.go:282 MerkleRoot re-sorts the dot pairs itself), so keeping
	// a real sort costs no determinism. slices.SortFunc keeps the whole
	// contract intact at O(N log N).
	slices.SortFunc(incoming, cmpIncomingEntries)

	// 3. Deduplicate the incoming payload in-place
	k := 1
	for j := 1; j < len(incoming); j++ {
		if incoming[j].entityID != incoming[k-1].entityID || compareDots(incoming[j].entry.Dot(), incoming[k-1].entry.Dot()) != 0 {
			incoming[k] = incoming[j]
			k++
		} else {
			e.entriesSkipped.Add(1)
		}
	}
	incoming = incoming[:k]

	// 4. SHARD-LOCAL lock-free HAMT update.
	//
	// incoming is already sorted by entityID; we partition it into per-shard
	// runs grouped by the routing helper routeShard, because blocks with the
	// SAME entityID always land in the SAME shard (routeShard is a pure
	// function of entityID). Each shard that receives ≥1 block is then CAS'd
	// INDEPENDENTLY: load the shard root, merge ALL of that shard's blocks
	// into one modified HAMT (preserving the original batched-merge benefit
	// at the shard granularity), CAS just that shard's pointer, and on
	// success Retire the previous shard root. Shards with no incoming blocks
	// are not touched — zero contention on them.
	//
	// This is per-shard linearizable and keeps maybeAdvanceEpoch
	// once-per-Join: the EBR retire fires per successful per-shard
	// CAS, but epoch advancement is amortized ONCE after the whole Join
	// completes, preserving the reclamation contract the static guard pins.
	//
	// The participant is Get'd + Enter'd ONCE at the top
	// of Join (before delta.Entries) and held across this whole shard-partition
	// AND the per-shard CAS loop below — see the Join entry comment. The per-
	// iteration Enter/Exit the single-root design used here is collapsed away:
	// a per-iteration Exit would reopen the teardown window (Quiesce could see
	// the participant inactive between retries and Free under the next CAS).
	type blockRange struct {
		start int
		end   int
	}
	// shardBatches[i] collects the contiguous entityID-block ranges that
	// route to shard i. Each shard may receive several disjoint ranges
	// (different entityIDs hashing to the same shard); they are all merged
	// into one CAS per shard below.
	shardBatches := make(map[int][]blockRange, 8)
	for i := 0; i < len(incoming); {
		start := i
		entityID := incoming[i].entityID
		for i < len(incoming) && incoming[i].entityID == entityID {
			i++
		}
		idx := e.routeShard(entityID)
		shardBatches[idx] = append(shardBatches[idx], blockRange{start, i})
	}

	// Deterministic shard order so the per-shard driver below is reproducible
	// across runs (the MerkleRoot determinism contract — the WAL round-trip
	// test — depends on the engine state being a pure function of the applied
	// dot set, NOT the order shards were CAS'd; sorting the shard indices keeps
	// the EBR-retire bookkeeping deterministic too).
	shardOrder := make([]int, 0, len(shardBatches))
	for idx := range shardBatches {
		shardOrder = append(shardOrder, idx)
	}
	sort.Ints(shardOrder)

	// perShardMerge runs the original per-entityID dot-merge for every block
	// routed to this shard against the given shard root `base`. It returns the
	// modified HAMT (== base if nothing added), the inserted/skipped counters,
	// and whether any block actually grew the state. This is the SAME merge
	// code the single-root Join ran — now scoped to one shard's blocks.
	perShardMerge := func(base *HAMT, batches []blockRange) (modified *HAMT, inserted, skipped uint64, addedAny bool) {
		modified = base
		for _, br := range batches {
			entityID := incoming[br.start].entityID
			// Per ADR-0015 §3: pool the per-block merge scratch
			// slices via buf.blockScratch / buf.mergeScratch. The pool recycles
			// the backing arrays across blocks within one Join; HAMT Set copies
			// into the arena so the scratch is free to reuse after the Set.
			needed := br.end - br.start
			if cap(buf.blockScratch) < needed {
				buf.blockScratch = make([]CRDTEntry, needed)
			}
			incomingBlock := buf.blockScratch[:needed]
			for j := range incomingBlock {
				incomingBlock[j] = incoming[br.start+j].entry
			}

			existing := modified.Get(entityID)
			mergeNeeded := len(existing) + len(incomingBlock)
			if cap(buf.mergeScratch) < mergeNeeded {
				buf.mergeScratch = make([]CRDTEntry, 0, mergeNeeded)
			}
			merged := buf.mergeScratch[:0]
			p1, p2 := 0, 0
			added := false

			for p1 < len(existing) && p2 < len(incomingBlock) {
				cmp := compareDots(existing[p1].Dot(), incomingBlock[p2].Dot())
				if cmp < 0 {
					merged = append(merged, existing[p1])
					p1++
				} else if cmp > 0 {
					merged = append(merged, incomingBlock[p2])
					p2++
					added = true
					inserted++
				} else {
					merged = append(merged, existing[p1])
					p1++
					p2++
					skipped++
				}
			}

			for p1 < len(existing) {
				merged = append(merged, existing[p1])
				p1++
			}
			for p2 < len(incomingBlock) {
				merged = append(merged, incomingBlock[p2])
				p2++
				added = true
				inserted++
			}

			if added {
				modified = modified.Set(entityID, merged)
				addedAny = true
			}
			// Per ADR-0015 §3: update the pool scratch
			// to capture any capacity growth from append above, so the
			// next block iteration reuses the grown backing array.
			buf.mergeScratch = merged[:0]
		}
		return modified, inserted, skipped, addedAny
	}

	var totalInserted uint64
	var totalSkipped uint64
	for _, idx := range shardOrder {
		shard := &e.shards[idx]
		batches := shardBatches[idx]

		for {
			// The participant stays Enter'd across every retry (see the Join
			// entry comment): the single pinned epoch protects each iteration's
			// `current` read, and there is NO mid-loop inactive window for
			// Quiesce to Free under. Retire below is a push-only op (it never
			// dereferences the retired pointer), so it is safe while active.
			current := shard.ptr.Load()
			modified, inserted, skipped, added := perShardMerge(current, batches)

			if !added {
				// All of this shard's blocks are already present (dot-equal).
				totalSkipped += skipped
				break
			}

			if shard.ptr.CompareAndSwap(current, modified) {
				e.ebr.Retire(unsafe.Pointer(current))
				totalInserted += inserted
				totalSkipped += skipped
				break
			}

			// CAS failed. The modified HAMT was never published; retire it to
			// prevent leaks. Retry against the freshly-loaded shard root.
			e.ebr.Retire(unsafe.Pointer(modified))
		}
	}

	// Exit BEFORE maybeAdvanceEpoch so the epoch advance
	// is not self-blocked by this still-active participant (AdvanceEpoch's
	// canAdvance refuses while any active participant pins an older epoch). The
	// deferred cleanup sees exited==true and does not double-Exit.
	participant.Exit()
	exited = true
	// maybeAdvanceEpoch is called ONCE per Join (outside the
	// per-shard driver loop) — preserving the reclamation contract: EBR Retire
	// fires per successful per-shard CAS, AdvanceEpoch is amortized once per
	// operation so the three-epoch ring recycles the per-shard retired roots
	// in lockstep with the single-root design.
	e.maybeAdvanceEpoch()

	e.entriesSkipped.Add(totalSkipped)
	e.entriesInserted.Add(totalInserted)
	e.deltasApplied.Add(1)
}

// State returns a merged view of the current sharded HAMT state as a single
// *HAMT. Because the engine root is sharded (e.shards), State() builds
// a fresh *HAMT that stitches every shard's entries via Set. The previous
// merged view is Retired through EBR (3-epoch grace — the same reclamation
// profile the single-root design already had: a published root is retired by
// the next publish, freed after 3 epoch advances). This bounds the live
// merged-view arena hold to ONE wrapper per engine at a time.
//
// State() is OFF the Join hot path (Join never calls it); test fixtures, the
// gossip Merkle-root sweep (internal/chaos/partition.go MerkleRoots), the WAL
// checkpoint test, and the off-hot-path crash probe (internal/chaos/probe.go)
// are the callers. Build cost is O(total entries) — negligible for the small
// live sets those callers observe and irrelevant to BenchmarkCRDTEngine_JoinParallel.
// The production API surface (*HAMT with Get/Len/ForEach/MerkleRoot/RootPtr)
// is preserved so those byte-identical production callers compile unchanged.
func (e *DeltaCRDTEngine) State() *HAMT {
	e.stateViewMu.Lock()
	prev := e.mergedView.Swap(nil)
	merged := NewHAMT(e.arena)
	for si := range e.shards {
		shardRoot := e.shards[si].ptr.Load()
		if shardRoot == nil {
			continue
		}
		shardRoot.ForEach(func(entityID string, entries []CRDTEntry) bool {
			merged = merged.Set(entityID, entries)
			return true
		})
	}
	// Retire the previously-built merged view via EBR so the arena reclaims
	// it after the 3-epoch grace window — mirroring the single-root publish
	// profile. We Retire AWAY from the freshly-built `merged` so a concurrent
	// reader of `prev` (racing State() callers, off the hot path) still
	// survives its iteration within the EBR grace window.
	if prev != nil {
		e.ebr.Retire(unsafe.Pointer(prev))
		e.maybeAdvanceEpoch()
	}
	e.mergedView.Store(merged)
	e.stateViewMu.Unlock()
	return merged
}

// Arena returns the engine's off-heap HamtArena.
//
// Chaos-probe seam: exposed read-only so the decoupled Worker crash
// probe (internal/chaos) can construct a guaranteed off-heap SIGSEGV without
// reaching into arena free-list internals. Off the hot path; Zero-GC invariants
// are not affected.
func (e *DeltaCRDTEngine) Arena() *HamtArena { return e.arena }

// EBR returns the engine's EBR manager. Exposed so the chaos crash probe can
// pin an EBR epoch BEFORE reading state: the probe previously
// snapshotted state:= eng.State() with no epoch pin, then dereferenced an
// off-heap child pointer that a concurrent InsertLocal CAS could have DecRef'd
// to 0, retired, and freed via a racing AdvanceEpoch — a use-after-free that
// surfaced as a non-deterministic SIGSEGV instead of the deterministic one the
// probe intends. Pinning holds freeRetiredList back for the duration of the
// probe, so the corrupted pointer the probe dereferences is guaranteed to be
// mapped. Off the hot path; Zero-GC invariants are not affected.
func (e *DeltaCRDTEngine) EBR() *EBRManager { return e.ebr }

// -----------------------------------------------------------------------------
// GenerateDelta Logic (ZERO-GC: EBR Lifecycle via Release())
// -----------------------------------------------------------------------------

// Seq is a push-based iterator (analogous to Go 1.23 iter.Seq).
type Seq func(yield func(entityID string, entry CRDTEntry) bool)

// CRDTDelta represents the minimal state delta for network transmission.
// Zero-GC proof: the caller MUST call Release() after consuming
// the iterator. This replaces runtime.SetFinalizer with deterministic EBR
// lifecycle management, preventing the finalizer queue OOM collapse proven
// by Little's Law under ≥100k RPS.
type CRDTDelta struct {
	Entries      Seq
	OriginNodeID [16]byte
	MerkleRoot   [32]byte
	// EBR lifecycle fields — callers use Release() to drop the EBR epoch
	// pin and decrement the root ref.
	//
	// Use-after-free fix: the delta's Entries iterator is lazy and is consumed
	// AFTER the generator returns. The HAMT root it iterates can be DecRef'd
	// to 0 and retired by a concurrent InsertLocal/DeleteLocal CAS while the
	// consumer is still iterating — a use-after-free. We close that hazard by
	// carrying an EBR participant on the delta: it is Enter()'d before
	// state.Load() in the generator and Exit()'d in Release(). The epoch
	// pin holds back freeRetiredList for the entire lifetime of the delta,
	// matching the protection GenerateDigestWithSeed gets from its own
	// participant.Enter/Exit. The IncRef remains as defense-in-depth: keeping
	// the root past refcount-zero is unnecessary once the epoch pin is held,
	// but IncRef/DecRef still honors the documented invariant.
	rootRef  NodePtr
	arenaRef *HamtArena
	ebrPart  *Participant

	// sendKeysOffset is the mmap offset of the
	// arena-backed sorted send-key slice the Entries iterator binary-searches
	// (the sort.Search replacement for the earlier heap sendMap). The slab is
	// provisioned by PeelArena (the localHas backing) and sorted in place; it
	// is the ONLY slab held past GenerateDelta's body (the iterator reads it
	// lazily after the generator returns). Release() retires it via the EBR
	// epoch-deferred freelist so the slab recycles ABA-safely. Zero for the
	// heap-allocated CRDTDelta shapes (the empty-delta path — backwards
	// compatible, those keep a heap sendMap).
	sendKeysOffset uint64
	// shardRootsOffset is the mmap offset of the arena-backed []*HAMT snapshot
	// (the earlier allShardRoots heap slice, now arena-backed). Retired in
	// Release. Zero for the heap-CRDTDelta shapes.
	shardRootsOffset uint64
	// sendKeys is the sorted slice over the arena backing; carried so the
	// iterator's closure (which also captures it directly) and Release can
	// both reach it. The slice header itself lives in the closure capture
	// struct; this field is the Release-side handle.
	sendKeys []uint64
	// arenaBacked marks this CRDTDelta as the arena-pooled shape
	// (GenerateDelta's hot path). The empty-delta branch keeps the earlier heap
	// allocation and skips the sendKeys retire.
	arenaBacked bool
	// deltaPool carries the owning engine's *CRDTDelta sync.Pool back to
	// Release (Release cannot reach the engine by any other path). Populated
	// ONLY for the arena-pooled shape; the heap CRDTDelta shapes leave it nil
	// so Release skips the pool put (and the sendKeys retire below) — byte-
	// identical behavior for the heap shapes is preserved (Release of a heap
	// delta ran only the ebrPart/arenaRef branches before the arena-pooling
	// change).
	// The arenaRef field (above) doubles as the arena handle for the sendKeys
	// slab retire; rootRef stays 0 for the sharded delta path so the existing
	// `d.arenaRef.DecRef(d.rootRef)` line is a no-op (DecRef(0) returns early).
	deltaPool *sync.Pool
	// participantPoolPtr carries the owning engine's *sync.Pool for
	// Participants back to Release (the participant was Get'd from
	// e.participantPool in GenerateDelta; before the arena-pooling change
	// Release leaked it — it Exit()'d the participant but never Put it back,
	// drying the pool and forcing e.participantPool.Get's New (ebr.Register →
	// new(Participant)) to heap-alloc 1/op once the pool ran dry). Populated
	// ONLY on the arena-pooled shape; Release returns the participant there.
	// Heap shapes (the empty-delta path) use scoped defer Put and leave this nil.
	participantPoolPtr *sync.Pool
	// Pool-prebuilt iterator state. The
	// Entries closure is built ONCE in deltaPool.New (capturing the recycled
	// `self` pointer, NOT the live locals) and reads its per-delta inputs
	// from the struct's fields each invocation. GenerateDelta UPDATES these
	// fields per call (it does NOT reassign Entries); Release clears them
	// (it does NOT nil Entries, preserving the pre-built closure across
	// pool recycles). The closure's capture-env struct (1 alloc) is paid
	// ONCE during pool warmup and recycled forever — the steady-state
	// sync.Pool amnesty permits it; allocs/op reads 0 at
	// steady state. This shaves the earlier 4-capture env alloc off the hot path.
	shardRoots []*HAMT
	diffNil    bool
	peelErr    error
}

// Release decrements the reference count on the pinned HAMT root.
// This MUST be called after the delta's Entries iterator has been fully
// consumed. Failure to call Release() will pin the HAMT root until
// arena.Free(), causing a memory leak.
func (d *CRDTDelta) Release() {
	// Drop the EBR epoch pin first. As long as the participant is
	// active, freeRetiredList cannot reclaim the HAMT tree the Entries
	// iterator walked. We exit before DecRef so that a concurrent AdvanceEpoch
	// cannot free the root we are about to DecRef-recurse into.
	if d.ebrPart != nil {
		// Exit the EBR pin AND return the Participant to its owning pool (the
		// participant-pool-leak fix). The pre-pooling Release Exit()'d but
		// never Put — the pool dried and every GenerateDelta's
		// e.participantPool.Get hit its New (ebr.Register → new(Participant))
		// = 1 heap alloc/op. The pool's New registers a fresh Participant into
		// the EBR head list, so even after a dry-and-refill the participant
		// stays EBR-visible; putting a quiescent Exit()'d participant back for
		// the next Enter() is ABA-safe (Exit clears hazards + sets
		// epoch=Inactive/active=false; Enter re-reads globalEpoch). This is
		// the same Put-back shape InsertLocal's / GenerateDigestWithSeed's
		// scoped-defer participants already use — Release just deferred the
		// Put by the delta's (lazy) lifetime.
		pp := d.participantPoolPtr
		d.ebrPart.Exit()
		if pp != nil {
			pp.Put(d.ebrPart)
			d.participantPoolPtr = nil
		}
	}
	// The arena-pooled CRDTDelta shape (GenerateDelta hot path)
	// carries arenaRef = owning arena + arenaBacked = true. Retire the
	// arena-backed send-key slab the Entries iterator walked BEFORE the
	// DecRef branch nil's arenaRef, then return the struct to the engine's
	// *CRDTDelta pool (steady-state 0-alloc amnesty — byte-faithful to the
	// engine's existing participantPool sync.Pool). The heap CRDTDelta
	// shapes (the empty-delta path) leave arenaBacked false and skip
	// both the slab retire and the pool put, preserving their earlier behavior.
	pool := (*sync.Pool)(nil)
	if d.arenaBacked {
		if d.arenaRef != nil {
			if d.sendKeysOffset != 0 {
				d.arenaRef.ebr.RetireBlock(d.arenaRef, d.sendKeysOffset, false)
			}
			if d.shardRootsOffset != 0 {
				d.arenaRef.ebr.RetireBlock(d.arenaRef, d.shardRootsOffset, false)
			}
		}
		d.sendKeysOffset = 0
		d.shardRootsOffset = 0
		d.sendKeys = nil
		d.shardRoots = nil
		d.diffNil = false
		d.peelErr = nil
		// NOTE: Entries is intentionally NOT cleared. The pool-prebuilt
		// closure (built once in deltaPool.New, capturing `self`) must survive
		// the pool round-trip so the next Get returns a delta whose Entries
		// iterator is already wired to read the (about-to-be-refreshed)
		// struct fields. Clearing Entries would force the next Get's pool miss
		// to rebuild the capture env = 1 alloc/op. The GC reachability is
		// handled by the struct being returned to the Go-heap sync.Pool (a
		// recycled *CRDTDelta is GC-visible so the closure env stays
		// reachable); the arena slabs it referenced are retired ABOVE.
		pool = d.deltaPool
		d.deltaPool = nil
	}
	// rootRef stays 0 for the sharded delta path (the allShardRoots
	// snapshot owns the per-shard roots; the single-root IncRef/DecRef does
	// not apply). DecRef(0) is a no-op (DecRef's `if current == 0 continue`);
	// the guard stays so the heap shapes (the empty-delta path) keep their
	// DecRef.
	if d.arenaRef != nil {
		d.arenaRef.DecRef(d.rootRef)
		d.arenaRef = nil
	}
	// Entries is intentionally NOT cleared for the arena-backed
	// shape (see the arenaBacked block above — the pool-prebuilt closure is
	// recycled intact). For the heap shapes (the empty-delta path), the
	// earlier behavior niled Entries; preserve that byte-identically (those
	// deltas carry a per-call closure built fresh in their generator, and
	// nil'ing lets that closure env be GC'd promptly).
	if !d.arenaBacked {
		d.Entries = nil
	}
	d.OriginNodeID = [16]byte{}
	d.MerkleRoot = [32]byte{}
	d.rootRef = 0
	d.ebrPart = nil
	d.arenaBacked = false
	if pool != nil {
		pool.Put(d)
	}
}

// HashCausalDot generates a deterministic uint64 key for a CRDT entry
// to be inserted into the IBLT. It hashes the NodeID, Counter, and PayloadDigest.
func HashCausalDot(dot CausalDot, digest [32]byte) uint64 {
	// FNV-1a on NodeID
	var key uint64 = 14695981039346656037 // FNV-1a offset basis
	for i := 0; i < 16; i++ {
		key ^= uint64(dot.NodeID[i])
		key *= 1099511628211
	}
	// FNV-1a on Counter
	for i := 0; i < 8; i++ {
		key ^= uint64((dot.Counter >> (i * 8)) & 0xff)
		key *= 1099511628211
	}
	// FNV-1a on Digest
	for i := 0; i < 32; i++ {
		key ^= uint64(digest[i])
		key *= 1099511628211
	}
	return key
}

// GenerateDelta generates a delta containing entries that the remote peer
// is missing, as determined by the exact IBLT reconciliation process.
// Livelock proof: it accepts *IBLT instead of a BloomFilter.
func (e *DeltaCRDTEngine) GenerateDelta(remoteDigest *IBLT) *CRDTDelta {
	// localDigest is arena-backed (NewArenaIBLT via
	// GenerateDigestWithSeed) — the IBLT struct + its 24 KB bucket array are
	// provisioned from e.arena (allocVar slabs, GC-invisible, recycled via EBR
	// RetireBlock). The Subtract diff is arena-backed too (subtractArena); the
	// peel's result slices are arena-backed (PeelArena). The send-set is the
	// sorted (in place) PeelArena localHas slice carried on the returned delta.
	localDigest := e.GenerateDigestWithSeed(remoteDigest.Seed())

	// Arena-backed symmetric difference (struct + 24 KB bucket array from
	// e.arena). Subtract's heap signature is preserved byte-identical (the
	// capnp / chaos / strata paths keep heap-allocating via Subtract).
	diff := localDigest.subtractArena(remoteDigest, e.arena)

	// Peel into arena-backed result slices (PeelArena provisions localHas,
	// remoteHas, and the internal pureQueue from e.arena — zero Go-heap
	// allocs; the stack-array + compaction math is byte-identical to Peel).
	// pureQueueOffset is retained so the body retires the queue slab
	// after the peel completes (the queue is body-local; only localHas is
	// carried past the body as the send-key set).
	var sendKeys []uint64
	var peelErr error
	var pureQueueOffset uint64
	var remoteHasOffset uint64
	sendKeysOffset := uint64(0)
	// Entries-filter regression fix: capture diffNil BEFORE
	// the `if diff != nil` block nil's diff for its body-local retire. The pre-
	// fix code read `diffNil:= diff == nil` AFTER `diff = nil`, so diffNil was
	// ALWAYS true and the Entries closure always fell back to sending every
	// entry (the bench never invoked Entries so the bench stayed 0/0; the
	// PartialSync / FullSync integrity guards caught it — the bench is a
	// throughput/allocs gate, NOT a correctness gate; the guards carry the
	// correctness contract). diffNil now reflects the original `subtractArena
	// → nil` outcome (a configuration mismatch fallback), not the body's
	// post-retire housekeeping nil.
	diffNil := diff == nil
	if diff != nil {
		var remoteHas []uint64
		var localHasOffset uint64
		sendKeys, remoteHas, localHasOffset, remoteHasOffset, pureQueueOffset, peelErr = diff.PeelArena(e.arena)
		_ = remoteHas // remoteHas slab is body-local; retired below via remoteHasOffset.
		// Sort the arena slice in place. slices.Sort is the generic (non-
		// reflective) sort — it does NOT box sendKeys into an interface{} the
		// way sort.Slice does, so the slice header does not escape the mmap
		// backing here (sort.Slice's reflect path forced the header to heap).
		// This IS the send-key set: the binary-search replacement for the
		// earlier heap sendMap. No map, no hash buckets.
		slices.Sort(sendKeys)
		sendKeysOffset = localHasOffset // the slab backing sendKeys == PeelArena's localHas slab
		// Diff IBLT + its buckets are fully consumed by PeelArena; retire
		// inside the body (the diff is short-lived, body-only).
		// The send-set slab (sendKeys) lives past the body — it is retired in
		// CRDTDelta.Release.
		diff.ReleaseLocal()
		diff = nil
		// Retire the body-local pureQueue + remoteHas slabs DIRECTLY to the
		// freelist (pushFreeVar, NOT EBR RetireBlock). These slabs never cross
		// goroutine boundaries — they are written by PeelArena and read ONLY
		// inside GenerateDelta's body before the slab is returned. EBR's
		// epoch-deferred protection is unnecessary for goroutine-local blocks
		// with no concurrent reader; direct freelist reuse is ABA-safe here
		// AND zero-RetiredNode-alloc (RetireBlock otherwise pulls a
		// RetiredNode from sync.Pool's retiredPool, which only refills on
		// AdvanceEpoch — the bench's GenerateDelta-only loop never advances,
		// so every RetireBlock would heap-alloc a fresh RetiredNode, breaking
		// the Zero-GC gate). The lifecycle slabs (sendKeys + shardRoots, held
		// past the body by the lazy closure) still go through EBR RetireBlock
		// (ABA-defensive; their RetiredNodes recycle via the
		// maybeAdvanceEpoch drain below).
		if pureQueueOffset != 0 {
			e.arena.pushFreeVar(pureQueueOffset)
		}
		if remoteHasOffset != 0 {
			e.arena.pushFreeVar(remoteHasOffset)
		}
	}
	// If diff == nil or peel failed, sendKeys is empty/nil — the iterator
	// falls back to sending everything (the `diff == nil || peelErr != nil`
	// short-circuit). sendKeysOffset stays 0 in that case. (diffNil was
	// captured above, BEFORE this block nil'd diff for the body-local retire.)
	peelErrVal := peelErr

	// Local digest IBLT is fully consumed by subtractArena; retire its slabs
	// directly to the freelist inside the body (the localDigest's
	// lifecycle is shorter than the delta's; it is goroutine-local — written by
	// GenerateDigestWithSeed and read ONLY by subtractArena in this body — so
	// direct pushFreeVar (zero-RetiredNode) is ABA-safe; EBR's deferred retire
	// is unnecessary here and would heap-alloc a RetiredNode per slab).
	localDigest.ReleaseLocal()

	// Use-after-free fix: the Entries iterator is consumed lazily AFTER this
	// function returns. Enter an EBR participant now and carry it on the
	// returned delta so freeRetiredList is held back for the delta's
	// entire lifetime — not just for the body of this generator. The
	// participant is Exit()'d in CRDTDelta.Release(). IncRef remains
	// as documented defense-in-depth.
	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	// The engine root is sharded. Snapshot every shard root
	// under the EBR pin so the lazy Entries iterator (consumed after this
	// generator returns) walks a frozen, reclaim-safe view. EBR holds
	// freeRetiredList back for the delta's whole lifetime (the participant
	// is Exit()'d in CRDTDelta.Release()), so a per-shard root retired by a
	// concurrent InsertLocal/Join CAS during iteration is NOT freed until the
	// caller Releases. The IncRef/DecRef pair (single-root "defense in
	// depth") is N-rooted here; the EBR pin is the load-bearing protection
	// (the use-after-free fix comment above documents this), so the delta
	// carries rootRef=0 / arenaRef=e.arena (arenaRef carries the arena-backed
	// send-key + shard-roots slabs' owning handle, used by Release to retire
	// the slabs; rootRef stays 0 so DecRef(0) is a no-op).
	// The shard-roots snapshot is arena-backed (allShardRootsArena) — the
	// earlier make([]*HAMT, 256) heap alloc is gone; the slab retires in
	// Release.
	shardRoots, shardRootsOffset := e.allShardRootsArena()

	// Pool-prebuilt iterator: the earlier
	// `seqPtr:= new(Seq)` carrier was a needless 1 alloc/op, AND the earlier
	// per-call closure literal rebuilt its 4-capture (shardRoots / sendKeys /
	// diffNil / peelErrVal) capture-env struct every GenerateDelta = 1 alloc/op.
	// The closure is now built ONCE in deltaPool.New (capturing only `self`,
	// the recycled *CRDTDelta) and reads its per-delta inputs from the struct's
	// fields. GenerateDelta below only UPDATES those fields (it does NOT
	// reassign delta.Entries); the capture-env struct is paid ONCE during pool
	// warmup and recycled forever (the steady-state sync.Pool amnesty permits
	// it). The bench reads 0 B/op · 0 allocs/op at steady state.
	delta := e.deltaPool.Get().(*CRDTDelta)
	// NOTE: delta.Entries is intentionally NOT reassigned here — the closure
	// was wired in deltaPool.New and is preserved across pool recycles.
	delta.OriginNodeID = e.localNodeID
	delta.MerkleRoot = [32]byte{} // unused under sharding
	delta.rootRef = 0             // sharded root: EBR pin owns the roots, not a single IncRef/DecRef
	delta.arenaRef = e.arena      // owning arena for the send-key slab retire
	delta.ebrPart = participant
	delta.participantPoolPtr = &e.participantPool
	delta.sendKeysOffset = sendKeysOffset
	delta.shardRootsOffset = shardRootsOffset
	delta.sendKeys = sendKeys
	delta.shardRoots = shardRoots
	delta.diffNil = diffNil
	delta.peelErr = peelErrVal
	delta.arenaBacked = true
	delta.deltaPool = &e.deltaPool
	// drain the EBR retired list periodically. The lifecycle slabs
	// (sendKeys + shardRoots held by the lazy closure) retire through EBR
	// RetireBlock, each pulling a RetiredNode from retiredPool. GenerateDelta
	// does NOT flow through InsertLocal's maybeAdvanceEpoch, so without this
	// drain the retiredPool would dry and every RetireBlock would heap-alloc a
	// fresh RetiredNode (the bench's pure GenerateDelta loop would read 2
	// allocs/op just for the RetiredNodes). The drain returns the RetiredNodes
	// to retiredPool so the next GenerateDelta's RetireBlocks recycle at steady
	// state. maybeAdvanceEpoch is the engine's existing helper (InsertLocal /
	// Join already call it); it advances the epoch every 64 calls (the
	// epochAdvanceThreshold) so the O(participants × hazardSlots) AdvanceEpoch
	// cost is amortized to ~negligible per GenerateDelta.
	e.maybeAdvanceEpoch()
	return delta
}

// AdvanceLamportTo securely fast-forwards the local Lamport clock and bumps disk limits.
func (e *DeltaCRDTEngine) AdvanceLamportTo(remoteCounter uint64) {
	for {
		current := e.lamportCounter.Load()
		if current >= remoteCounter {
			break
		}
		if e.lamportCounter.CompareAndSwap(current, remoteCounter) {
			// Advance disk limit to cover the newly advanced clock value.
			// AdvanceLamportTo NO LONGER HOLDS persistMu -- mirrors NextDot
			// exactly. The in-memory lastSavedCounter advances via CAS (NOT
			// under persistMu); the durable write is handed to the background
			// persist worker via a non-blocking select-default send (drop if the
			// worker is busy; next +1000 CAS re-issues with a strictly-higher
			// nextLimit). The +1000 amortization window stays byte-identical.
			for {
				lastSaved := e.lastSavedCounter.Load()
				if remoteCounter <= lastSaved {
					break
				}
				nextLimit := remoteCounter + 1000
				if e.lastSavedCounter.CompareAndSwap(lastSaved, nextLimit) {
					select {
					case e.persistCh <- nextLimit:
					default:
					}
					break
				}
			}
			// EWMA update — the ONE line added to AdvanceLamportTo; the
			// advance SEMANTICS above — max(local, remote) via CAS + the
			// disk-bump loop — are byte-identical to the pre-EWMA shape.
			// Observe the inbound advancement of this frame: advance =
			// remoteCounter - current (the CAS only succeeded with remoteCounter
			// > current, so advance > 0 here). The EWMA tracks recent inbound
			// DotCounter pace; alpha=0.1 is a standard EWMA decay (a known
			// limitation — a high alpha tracks bursts but is more
			// attacker-influenceable; a low alpha is stable but slow). Single
			// atomic store of the float's IEEE-754 bits — race-clean, matching
			// the lamportCounter pattern.
			const lamportSkewEWMAAlpha = 0.1
			delta := remoteCounter - current
			prev := math.Float64frombits(e.observedInboundRateBits.Load())
			next := lamportSkewEWMAAlpha*float64(delta) + (1.0-lamportSkewEWMAAlpha)*prev
			e.observedInboundRateBits.Store(math.Float64bits(next))
			break
		}
	}
}

// LamportCounter returns the current clock value.
func (e *DeltaCRDTEngine) LamportCounter() uint64 {
	return e.lamportCounter.Load()
}

// GenerateDigest generates an Invertible Bloom Lookup Table representing the local
// causal state for exact anti-entropy synchronization.
// Returns *IBLT instead of a *BloomFilter.
func (e *DeltaCRDTEngine) GenerateDigest() *IBLT {
	// Initialize IBLT with 1024 buckets and k=4 hashes (tunable)
	return e.GenerateDigestWithSeed(maphash.MakeSeed())
}

// GenerateDigestWithSeed generates an IBLT using a specific seed, required for Subtract.
//
// The bucket array + IBLT struct are now
// provisioned from e.arena via NewArenaIBLT, mirroring the allocVar/pushFreeVar
// pattern HamtArena's allocHAMTWrapper already uses. NewIBLTWithSeed's public
// signature is preserved byte-identical for the capnp roundtrip, chaos, and
// strata-estimator paths; only the GenerateDelta hot path's
// local digest migrates here. The returned *IBLT MUST be Release()'d (the
// GenerateDelta body retires the localDigest via IBLT.Release after the
// arena-backed subtract consumes it; the chaos path that retains the heap
// digest passes the arena-backed digest through without Release, exactly as
// it leaked the prior heap digest — the arena teardown reclaims everything).
func (e *DeltaCRDTEngine) GenerateDigestWithSeed(seed maphash.Seed) *IBLT {
	iblt := NewArenaIBLT(1024, 4, seed, e.arena)

	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	defer func() {
		participant.Exit()
		e.participantPool.Put(participant)
	}()

	// The engine root is sharded. Iterate every shard's root
	// under the EBR pin so all live entries contribute to the digest; a
	// single e.state.Load() no longer exists. The per-shard snapshot is not
	// atomic across shards, but the digest is an anti-entropy hint — the
	// reconcile/peel contract tolerates a slightly-shifted view, exactly as
	// the single-root design tolerated a root shifted between Load() and the
	// second GenerateDelta sub call.
	for si := range e.shards {
		shardRoot := e.shards[si].ptr.Load()
		if shardRoot == nil {
			continue
		}
		shardRoot.ForEach(func(_ string, entries []CRDTEntry) bool {
			for i := range entries {
				key := HashCausalDot(entries[i].Dot(), entries[i].PayloadDigest)
				iblt.Insert(key)
			}
			return true
		})
	}

	return iblt
}

// Stats returns engine metrics.
func (e *DeltaCRDTEngine) Stats() map[string]uint64 {
	return map[string]uint64{
		"deltas_generated": e.deltasGenerated.Load(),
		"deltas_applied":   e.deltasApplied.Load(),
		"entries_inserted": e.entriesInserted.Load(),
		"entries_skipped":  e.entriesSkipped.Load(),
	}
}

// ---------------------------------------------------------------------------
// Strata Estimator Integration (ADR-0005)
// ---------------------------------------------------------------------------

// GenerateStrataEstimator creates a StrataEstimator from all local CRDT entries.
// This estimator is exchanged with a remote peer to estimate |d| before
// constructing the dynamically-sized reconciliation IBLT.
//
// Communication cost: ~50KB per estimator (32 strata × 80 buckets × 20 bytes).
// Time complexity: O(n) for a single scan of all entries.
func (e *DeltaCRDTEngine) GenerateStrataEstimator(seed maphash.Seed) *StrataEstimator {
	se := NewStrataEstimator(seed)

	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	defer func() {
		participant.Exit()
		e.participantPool.Put(participant)
	}()

	// Iterate every shard's root under the EBR pin (mirrors
	// GenerateDigestWithSeed). The estimator is a |d| hint; per-shard
	// snapshot skew is tolerated identically to the single-root design.
	for si := range e.shards {
		shardRoot := e.shards[si].ptr.Load()
		if shardRoot == nil {
			continue
		}
		shardRoot.ForEach(func(_ string, entries []CRDTEntry) bool {
			for i := range entries {
				key := HashCausalDot(entries[i].Dot(), entries[i].PayloadDigest)
				se.Insert(key)
			}
			return true
		})
	}

	return se
}

// GenerateDeltaStratified was the S-IBLT-estimation delta primitive. It is
// DELETED (ADR-0034) — reading its body refuted its premise.
//
// The premise ("the diff is a strict subset → byte-identity + bandwidth cut")
// was refuted by the primitive's body: it created `remoteIBLT :=
// NewDynamicIBLT(dEst, 4, seed)` then NEVER populated it — the shard-root loop
// filled only the LOCAL IBLT. The `localIBLT.Subtract(remoteIBLT)` subtracted
// an EMPTY IBLT → the diff was the FULL local IBLT → the peel yielded ALL
// local keys → the iterator shipped EVERY entry. The stratified delta was
// byte-identical to oversend for ANY non-empty remote overlap (NO bandwidth
// cut). The dormant unit test only covered the EMPTY-remote case (where
// oversend==stratified by coincidence), so the defect never fired.
//
// The fundamental obstacle: the StrataEstimator is a LOSSY digest (XOR-based
// KeySum, not invertible to the key set); the remote's FULL IBLT MUST come
// from the wire, NOT be reconstructed from the estimator. The primitive's
// signature `GenerateDeltaStratified(remoteEstimator *StrataEstimator)` could
// not supply the remote IBLT — it had only the lossy estimator.
//
// The fix: the mesh's digest exchange (pkg/mesh/digest.go) now sends the
// remote's FULL IBLT digest on the wire (alongside the estimator used only for
// the dEst sizing hint), and the sweep calls `GenerateDelta(remoteIBLT)` — the
// correct set-reconciliation primitive that subtracts the POPULATED remote
// IBLT + peels the real diff. `GenerateDelta` has always set
// `participantPoolPtr`, so the EBR-pool leak (the stratified sibling's only
// real artifact) does not exist on this path — the leak was an artifact of the
// now-deleted primitive, not the wiring.
//
// (The body is deleted; callers — pkg/mesh/gossip.go's generateSweepDelta —
// now call GenerateDelta(remoteIBLT) directly.)

// -------------------------------------------------------------------
