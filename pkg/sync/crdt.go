// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

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

// DataDir is the legacy package-level default data directory.
// NewDeltaCRDTEngine copies it into the engine before recoverLamport reads
// <dataDir>/lamport_<nodeID>.dat. A persisted value above initialCounter becomes
// the starting clock value. Durability recovery sets this global to a scratch
// directory before construction so an unrelated file cannot override its seed
// (ADR-0013 §4).
//
// Use SetDataDir to change the directory of an existing engine. It holds
// persistMu, ordering the change against persistence. Writing DataDir while
// engines are running can race with other constructors and is not supported
// (ADR-0021 §2.2).
var DataDir = "/data/crdt"

// LamportSkewAbsoluteSlackUnbounded disables the Lamport skew bound for one
// engine by saturating MaxAcceptableDotCounter. Tests use it to admit large dot
// counters chosen to detect zero-filled fields without changing the production
// default of 1000. Wire-facing engines must not use this value: it removes the
// guard against a far-future counter advancing the local clock.
const LamportSkewAbsoluteSlackUnbounded uint64 = math.MaxUint64

// defaultShardCount is the initial number of per-entity HAMT roots. A power of
// two lets routeShard use a bitmask, and 256 spreads writers across many cache
// lines. SetShardCount can replace the roots with a different cardinality.
const defaultShardCount = 256

// shardRoot holds one independently updated HAMT root. Padding keeps hot roots
// on separate cache lines. Each atomic pointer has its own linearizable CAS
// history; routing by entity ID keeps every merge for an entity in one shard.
type shardRoot struct {
	_padHead CacheLinePad
	ptr      atomic.Pointer[HAMT]
	_padTail CacheLinePad
}

// incomingEntry is one transient element collected from a CRDTDelta Seq during
// Join. It is package-level so the pooled joinBuffers can retain its slice.
type incomingEntry struct {
	entityID string
	entry    CRDTEntry
}

// joinBuffers retains Join's incoming slice and per-entity merge scratch space.
// Reusing their backing arrays avoids repeating growth allocations. The incoming
// slice header can still escape through the delta iterator's callback; pooling
// does not remove that allocation (ADR-0015).
type joinBuffers struct {
	incoming     []incomingEntry
	blockScratch []CRDTEntry // reused for incomingBlock in perShardMerge
	mergeScratch []CRDTEntry // reused for merged in perShardMerge
}

// joinBufPool recycles joinBuffers across Join calls. New returns zero slices,
// whose grown backing arrays are retained for later calls. sync.Pool may drop
// entries during GC, so subsequent Join calls can allocate again (ADR-0015 §4).
var joinBufPool = sync.Pool{
	New: func() any {
		return &joinBuffers{}
	},
}

// DeltaCRDTEngine manages local CRDT state and generates and applies deltas for
// peer synchronization. It stores HAMT nodes in an off-heap arena and uses
// epoch-based reclamation.
//
// CacheLinePad separates groups of frequently written atomics. Without that
// separation, writes to unrelated fields on one cache line would force coherence
// traffic between cores. Each shard root is padded separately for the same
// reason.
type DeltaCRDTEngine struct {
	// shards routes each entity ID to one independently CAS-updated HAMT root.
	// Writes to different shards do not contend on the same root pointer. Join
	// merges dots per entity, so keeping an entity in one shard preserves its
	// merge semantics while each shard remains independently linearizable.
	//
	// The Lamport clock, integrity checks, EBR manager, and persistence path
	// remain shared. The slice representation lets SetShardCount rebuild the
	// roots at a different power-of-two cardinality.
	shards    []shardRoot
	routeSeed maphash.Seed // stable across the engine lifetime; routes entityID -> shard

	// State materializes mergedView by copying every shard into one HAMT.
	// stateViewMu serializes that construction; the previous merged view is
	// retired through EBR. Join does not call State, so this work stays off the
	// delta-apply path. A separate mutex avoids coupling view construction to
	// Lamport persistence.
	stateViewMu sync.Mutex
	mergedView  atomic.Pointer[HAMT]

	// NextDot increments lamportCounter. NextDot and AdvanceLamportTo advance
	// lastSavedCounter in 1000-counter reservation steps; both fields are atomic
	// because multiple goroutines can perform these operations concurrently.
	localNodeID      [16]byte
	_lamportPad0     CacheLinePad
	lamportCounter   atomic.Uint64
	lastSavedCounter atomic.Uint64
	_lamportPad1     CacheLinePad

	// Infrastructure and Lamport persistence.
	persistMu       sync.Mutex
	dataDir         string
	participantPool sync.Pool
	arena           *HamtArena
	ebr             *EBRManager
	_persistPad0    CacheLinePad
	// NextDot and AdvanceLamportTo hand persistence work to persistCh with a
	// nonblocking send instead of waiting for fsync while holding persistMu.
	// persistWorkerLoop serializes temporary-file writes and renames under that
	// mutex. The in-memory durability watermark advances before the handoff; a
	// busy worker can therefore leave the file one reservation step behind.
	// Close uses persistStopOnce and persistWorkerWg to drain the worker once,
	// before freeing the arena.
	persistCh          chan uint64
	persistWorkerWg    sync.WaitGroup
	persistStopOnce    sync.Once
	persistWorkerReady chan struct{}
	// persistWorkerReady reports that the worker started. persistWorkerParked
	// acknowledges the statement immediately before its receive loop; capacity
	// one lets that acknowledgement complete before the constructor receives it.
	// persistCh itself remains unbuffered, so it holds at most one handoff.
	persistWorkerParked chan struct{}

	// deltaPool recycles CRDTDelta values returned by Release. The struct holds
	// Go pointers, including its iterator closure and EBR participant, so the
	// struct itself must remain in GC-managed memory even though its snapshot
	// and key slices use arena storage. Pool warmup allocations are outside the
	// steady-state zero-allocation contract.
	deltaPool sync.Pool

	// observedInboundRateBits stores an EWMA of inbound counter advances as
	// IEEE-754 bits in an atomic uint64. AdvanceLamportTo updates it after a
	// successful clock CAS. Atomic access avoids data races and torn float
	// values; the alpha of 0.1 trades responsiveness against smoothing.
	observedInboundRateBits atomic.Uint64
	// The skew policy defaults to a 60-second horizon and absolute slack of
	// 1000. The setters change these values under persistMu. Tests with large
	// synthetic counters can relax the bound without changing the production
	// default that rejects far-future counters.
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
	// These four counters are incremented by InsertLocal and Join. They can
	// share a cache line because Stats reads them infrequently, but padding
	// separates them from the hot root-CAS and epoch fields.
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

		// The skew bound allows a 60-second rate envelope plus 1000 counters.
		// A larger horizon accommodates faster peers but gives an incremental
		// attacker more room. Frames beyond the bound are rejected before Join
		// can advance the local clock. The setters below override these defaults.
		lamportSkewHorizonSeconds: 60.0,
		lamportSkewAbsoluteSlack:  1000,
	}
	e.participantPool.New = func() any {
		return e.ebr.Register()
	}

	// Build the lazy Entries closure once for each pooled delta. It captures the
	// delta itself and reads the current snapshot, send keys, and peel status
	// from fields refreshed by GenerateDelta and cleared by Release. Reusing the
	// closure avoids rebuilding its capture environment on every call; the
	// one-time allocation belongs to pool warmup rather than steady state.
	e.deltaPool.New = func() any {
		d := &CRDTDelta{}
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
						// membership without allocating a map.
						shouldSend := false
						if len(self.sendKeys) > 0 {
							idx := sort.Search(len(self.sendKeys), func(j int) bool {
								return self.sendKeys[j] >= key
							})
							shouldSend = idx < len(self.sendKeys) && self.sendKeys[idx] == key
						}
						// Send the full set if subtraction or peeling failed.
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

	// Each shard starts with an empty HAMT. routeSeed assigns entity IDs to
	// shards, while the Lamport clock, inbound-rate EWMA, and skew policy remain
	// engine-wide.
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
	// A fresh engine has no observed inbound rate, so its first bound is the
	// local clock plus AbsoluteSlack. Successful inbound advances raise the
	// EWMA and widen the rate envelope. An attacker can also inflate it through
	// many accepted frames; the estimate slows incremental clock poisoning but
	// does not prevent it on its own.
	e.observedInboundRateBits.Store(math.Float64bits(0.0))

	// Start the persistence worker with an unbuffered work channel. A caller
	// whose nonblocking send finds the worker busy skips that write; a later
	// reservation offers a higher watermark instead. Only the worker performs
	// asynchronous writes, under persistMu.
	e.persistCh = make(chan uint64)
	e.persistWorkerReady = make(chan struct{})
	// The park acknowledgement needs capacity one: the worker sends it before
	// the constructor starts receiving. An unbuffered acknowledgement would
	// deadlock startup. persistCh itself remains unbuffered.
	e.persistWorkerParked = make(chan struct{}, 1)
	e.persistWorkerWg.Add(1)
	go e.persistWorkerLoop()
	// Observe the startup acknowledgements in the worker's program order:
	// started, then the statement immediately before the receive loop. Closing
	// ready wakes the constructor but says nothing about later worker statements.
	// The buffered park send establishes a happens-before edge to the corresponding
	// receive, so this receive proves the acknowledgement was sent. It does not
	// prove that the worker has entered the next receive.
	<-e.persistWorkerReady
	<-e.persistWorkerParked
	// Give the worker two opportunities to reach its receive before the caller
	// can issue the first nonblocking persistence send. These are scheduler
	// hints, not a handshake or a durability guarantee; a skipped write is still
	// covered by a later reservation or the final flush in Close.
	runtime.Gosched()
	runtime.Gosched()

	return e, nil
}

func (e *DeltaCRDTEngine) SetDataDir(dir string) {
	e.persistMu.Lock()
	defer e.persistMu.Unlock()
	e.dataDir = dir
}

// SetLamportHorizonSeconds changes the rate-envelope horizon used by the skew
// bound. Larger values tolerate faster peers but also permit faster incremental
// clock advances. persistMu orders the change against other configuration and
// apply operations.
func (e *DeltaCRDTEngine) SetLamportHorizonSeconds(h float64) {
	e.persistMu.Lock()
	defer e.persistMu.Unlock()
	e.lamportSkewHorizonSeconds = h
}

// SetLamportAbsoluteSlack changes the fixed allowance in the skew bound. The
// default is 1000; increasing it permits counters farther ahead of the local
// clock. persistMu orders the change against configuration and apply operations.
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
// Each shard receives an independent empty HAMT in the shared arena. The caller
// holds the appropriate configuration lock; this helper does not alter the
// engine-wide Lamport clock, EBR manager, or persistence state.
func (e *DeltaCRDTEngine) initShardsLocked(arena *HamtArena, n int) {
	shards := make([]shardRoot, n)
	for i := range shards {
		shards[i].ptr.Store(NewHAMT(arena))
	}
	e.shards = shards
}

// routeShard maps entityID to an index in [0, len(e.shards)). The result depends
// only on the ID and the engine's routeSeed, so Join can group all entries for
// an entity into one shard update. The maphash seed is independent of the HAMT
// hash seeds.
//
// Power-of-two shard counts use a bitmask; the modulo branch is defensive for a
// nonstandard internal configuration. SetShardCount enforces a positive power
// of two.
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

// SetShardCount rebuilds the engine with n shards and reinserts every live
// entity into its new root. n must be a positive power of two; other values
// panic. A count of one restores a single-root layout.
//
// Callers must quiesce Join and InsertLocal before re-rooting. persistMu
// serializes this operation with other configuration changes and disk writes;
// those mutation paths do not take that mutex. Old roots are retired through
// EBR after their entries have been copied.
func (e *DeltaCRDTEngine) SetShardCount(n int) {
	if n < 1 || n&(n-1) != 0 {
		panic(fmt.Sprintf("SetShardCount: n must be a positive power of two, got %d", n))
	}
	// Serialize configuration and persistence; re-rooting is off the hot path.
	e.persistMu.Lock()
	defer e.persistMu.Unlock()

	if len(e.shards) == n {
		return
	}

	old := e.shards
	e.initShardsLocked(e.arena, n)

	// Reinsert every live entity into its new shard. Retire each old root after
	// its entries have been copied.
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

// mergeExistingDot merges incoming entries into base for entityID using Join's
// dot ordering and deduplication. It preserves the sorted, duplicate-free leaf
// invariant and returns base unchanged when no new dot is added.
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

// allShardRootsArena snapshots the current HAMT pointer from every shard into
// an arena-backed slice and returns the slice with its arena offset. The caller
// must hold an EBR participant for as long as the snapshot is read; GenerateDelta
// transfers that duty to CRDTDelta.Release so roots retired by concurrent writes
// remain allocated during lazy iteration.
//
// Arena storage avoids a per-call heap slice. The off-heap backing is invisible
// to the GC, but it is only a snapshot, not the ownership root for the HAMT
// wrappers. EBR protects their lifetime, and Release retires the snapshot block
// separately. If arena allocation fails, the function returns a heap slice and
// a zero offset.
func (e *DeltaCRDTEngine) allShardRootsArena() ([]*HAMT, uint64) {
	n := len(e.shards)
	if n == 0 {
		return nil, 0
	}
	size := uintptr(n) * unsafe.Sizeof((*HAMT)(nil))
	backing := e.arena.allocVar(size)
	if backing == 0 {
		// If arena space is exhausted, use a heap-backed snapshot instead of
		// failing delta generation.
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

// allShardRoots returns a heap-backed snapshot for callers outside the pooled
// GenerateDelta path. The same EBR lifetime rules as allShardRootsArena apply.
func (e *DeltaCRDTEngine) allShardRoots() []*HAMT {
	roots := make([]*HAMT, len(e.shards))
	for i := range e.shards {
		roots[i] = e.shards[i].ptr.Load()
	}
	return roots
}

// LamportSnapshot returns the receiver state used by
// ReconstructEntryWithSkewBound. Callers take one snapshot per event or batch so
// validation does not reread changing engine fields partway through the check.
//
// The horizon and slack are read together under persistMu. The clock and EWMA
// bits are read with individual atomic loads after the lock is released, so the
// result is an immutable value for the caller, not a transactionally atomic view
// of all four fields.
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
	// Close sets Closing before unmapping the arena. Do not reclaim retired
	// nodes after that point: freeRetiredList would dereference arena headers
	// that may already be unmapped. This also covers an in-flight Join or
	// InsertLocal that exits its participant before calling maybeAdvanceEpoch.
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
	// Reject new operations and disable reclamation before draining active
	// participants. Enter/Closing only access Go-managed EBR state.
	e.ebr.SetClosing()
	// Quiesce before closing persistCh: an in-flight NextDot or Join could
	// otherwise send on the closed channel. It also ensures that no operation
	// still accesses the arena when it is freed.
	e.ebr.Quiesce()
	// Drain asynchronous persistence before the final synchronous flush. The
	// Once makes repeated Close calls safe; the Wait prevents a worker write
	// from racing the final file update.
	e.persistStopOnce.Do(func() { close(e.persistCh) })
	e.persistWorkerWg.Wait()
	// Flush the in-memory durability watermark even if a nonblocking handoff
	// was skipped. The WAL remains authoritative, and this write is best-effort.
	// Never lower a value already in the file: an engine whose SetDataDir moved
	// it to an existing directory may carry an older watermark than the file.
	// With the worker drained, this read and write do not race persistence.
	current, _ := e.recoverLamport()
	final := e.lastSavedCounter.Load()
	if current > final {
		final = current
	}
	_ = e.persistLamport(final)
	return e.arena.Free()
}

// persistWorkerLoop handles asynchronous Lamport persistence. It serializes
// file writes under persistMu and exits when Close closes persistCh. NextDot
// and AdvanceLamportTo use nonblocking sends, so a busy worker can leave the
// file behind the in-memory watermark until a later write. After this worker
// exits, Close performs its own final synchronous flush.
func (e *DeltaCRDTEngine) persistWorkerLoop() {
	// Report that the worker reached startup. Closing this channel does not
	// order the constructor against any subsequent worker statement.
	close(e.persistWorkerReady)
	// Acknowledge the statement immediately before the receive loop. Capacity
	// one avoids waiting for the constructor's receive. The send has a
	// happens-before edge to the constructor's corresponding receive, proving
	// this statement executed; it does not prove the worker has entered the next
	// receive, which is why the constructor also uses scheduler yields.
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

	// Reserve persistence headroom 1000 counters at a time. Reloading and
	// checking lastSaved before every CAS keeps the watermark monotone: a
	// concurrent higher reservation either makes this one unnecessary or causes
	// a retry. A single unguarded CAS could otherwise install a lower value.
	//
	// The reservation is published in memory without persistMu. The nonblocking
	// handoff omits the file write when the worker is busy; a later reservation
	// offers a strictly higher value, and Close flushes the final watermark.
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
		// Read only the configured directory. A relative-directory fallback
		// could recover a counter belonging to another working directory or
		// test engine and make the initial clock nondeterministic.
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
		// As in recoverLamport, do not fall back to a relative directory.
		// Failure leaves the in-memory counter available for a later write in
		// this process, including the final flush in Close.
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
	// Keep one EBR participant active from before NextDot until the last arena
	// access. Otherwise Close could observe no participants and free the arena
	// between a Closing check and a later CAS. Enter and Closing access only
	// Go-managed EBR fields, so this ordering is safe during teardown; an
	// operation that enters after Close starts panics before touching the arena.
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

	// Update only the shard selected for this entity; unrelated roots do not
	// participate in this CAS.
	shardIdx := e.routeShard(entityID)
	shard := &e.shards[shardIdx]

	// Hold the EBR participant across retries. Its pinned epoch protects each
	// current root from reclamation and prevents Close from freeing the arena
	// during an inactive window between attempts.
	for {
		current := shard.ptr.Load()
		existing := current.Get(entityID)

		// Every CAS attempt needs a fresh backing array. Reusing one after a
		// failed CAS could overwrite entries still reachable from a published
		// path-copying HAMT leaf.
		//
		// Existing entries are already dot-sorted, so only the appended entry
		// needs to move. The backward insertion pass takes O(n) time in the
		// worst case and avoids a general sort and its comparator setup. The
		// make supplies the independent storage required for this attempt.
		newEntries := make([]CRDTEntry, len(existing)+1)
		copy(newEntries, existing)
		newEntries[len(existing)] = entry
		insertionSortLastEntry(newEntries)

		newState := current.Set(entityID, newEntries)
		swapped := shard.ptr.CompareAndSwap(current, newState)

		if swapped {
			// Leave the epoch before retiring and advancing so this participant
			// cannot hold back its own reclamation pass. Retire only appends the
			// old root pointer without dereferencing it; exited prevents a second
			// Exit in the deferred cleanup.
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

// cmpIncomingEntries orders Join input by entity ID and then causal dot. The
// comparator receives elements by value and captures no input slice. Sorting
// places duplicate dots and equal entity IDs next to each other for deduplication
// and shard batching; MerkleRoot independently sorts its own dot pairs
// (ADR-0022).
func cmpIncomingEntries(a, b incomingEntry) int {
	if a.entityID != b.entityID {
		if a.entityID < b.entityID {
			return -1
		}
		return 1
	}
	return compareDots(a.entry.Dot(), b.entry.Dot())
}

// insertionSortLastEntry moves the final element into dot order, assuming the
// preceding elements are already sorted. It uses one backward-shift pass with
// no comparator closure. The worst case is O(n); a largest new dot needs no
// moves.
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

// Join merges an incoming delta with per-shard compare-and-swap loops.
func (e *DeltaCRDTEngine) Join(delta CRDTDelta) {
	// As in InsertLocal, keep the participant active across iteration, Lamport
	// persistence sends, sorting, and every CAS retry. Close cannot drain the
	// participant set or free the arena while this operation is in flight. A
	// Join that enters after Close starts panics before reading the delta.
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

	// Reuse the incoming buffer and merge scratch across calls (ADR-0015 §3).
	// Appends can grow the backing arrays retained in the pool. The iterator
	// callback may still let a slice header escape; sync.Pool may also discard
	// retained buffers at GC, so later calls can allocate again.
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

	// Sort in place before deduplicating and grouping entity runs. The generic
	// comparator avoids the interface boxing of the old reflective sort, though
	// the delta callback can still let incoming escape (ADR-0022).
	//
	// Generated deltas walk HAMTs in hash order, not lexical entity order, so an
	// insertion sort cannot assume nearly sorted input. slices.SortFunc provides
	// O(n log n) worst-case sorting and avoids quadratic work on reversed or
	// adversarial sequences. MerkleRoot does not rely on this order.
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

	// Group contiguous entity runs by their routed shard. Merge all runs for a
	// shard into one candidate root, then CAS that root independently. Shards
	// with no input remain untouched.
	//
	// Retire each replaced root after its successful CAS, but advance the epoch
	// only once after the whole Join. The participant acquired above stays
	// active through partitioning and every retry, including reads of roots
	// that another operation may retire.
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

	// Sort shard indices so map iteration cannot change the order of CAS and
	// retirement operations. The resulting CRDT state depends on the applied dot
	// set, while deterministic bookkeeping makes runs reproducible.
	shardOrder := make([]int, 0, len(shardBatches))
	for idx := range shardBatches {
		shardOrder = append(shardOrder, idx)
	}
	sort.Ints(shardOrder)

	// perShardMerge merges each entity block routed to this shard into base.
	// It returns the modified HAMT, inserted and skipped counts, and whether any
	// new dot was added. With no new dots, modified remains base.
	perShardMerge := func(base *HAMT, batches []blockRange) (modified *HAMT, inserted, skipped uint64, addedAny bool) {
		modified = base
		for _, br := range batches {
			entityID := incoming[br.start].entityID
			// Reuse blockScratch and mergeScratch across entity blocks and CAS
			// retries. HAMT.Set copies the merged entries into arena storage, so
			// these scratch arrays remain reusable after the call.
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
			// Retain any capacity growth from append for the next block.
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
			// The participant remains active across retries, protecting current
			// and preventing a teardown between attempts. Retire only appends
			// the replaced root to the retirement list; it does not dereference
			// that root.
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

	// Leave the epoch before advancing it so this participant cannot hold back
	// its own reclamation pass. The deferred cleanup checks exited to avoid a
	// second Exit.
	participant.Exit()
	exited = true
	// Replaced roots were retired per successful shard CAS. Amortize epoch
	// advancement once per Join rather than once per changed shard.
	e.maybeAdvanceEpoch()

	e.entriesSkipped.Add(totalSkipped)
	e.entriesInserted.Add(totalInserted)
	e.deltasApplied.Add(1)
}

// State builds a single HAMT containing every entry from the current shards.
// It preserves the engine's read API for callers that need Get, Len, ForEach,
// MerkleRoot, or RootPtr. Construction costs O(total entries) and is not part of
// Join.
//
// The previous merged view is retired through EBR when a new view is built.
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
	// Retire the previous merged view through EBR. The newly built view is
	// published below and is not part of this retirement.
	if prev != nil {
		e.ebr.Retire(unsafe.Pointer(prev))
		e.maybeAdvanceEpoch()
	}
	e.mergedView.Store(merged)
	e.stateViewMu.Unlock()
	return merged
}

// Arena returns the engine's off-heap arena. Internal crash tests use it to
// exercise faults in mapped storage without depending on free-list internals.
func (e *DeltaCRDTEngine) Arena() *HamtArena { return e.arena }

// EBR returns the engine's epoch manager. A caller traversing off-heap state
// can pin an epoch first to defer reclamation until the traversal is complete.
func (e *DeltaCRDTEngine) EBR() *EBRManager { return e.ebr }

// GenerateDelta and the CRDTDelta lifecycle.

// Seq is a push-based iterator (analogous to Go 1.23 iter.Seq).
type Seq func(yield func(entityID string, entry CRDTEntry) bool)

// CRDTDelta is a lazily iterated state delta for network transmission. After
// consuming Entries, the caller must call Release to drop the EBR pin and return
// pooled resources. Deterministic release keeps retired roots and arena slabs
// alive for exactly as long as the iterator needs them.
type CRDTDelta struct {
	Entries      Seq
	OriginNodeID [16]byte
	MerkleRoot   [32]byte
	// GenerateDelta enters ebrPart before capturing the shard roots. Entries
	// runs after the generator returns, so a concurrent write can retire those
	// roots during iteration. The participant prevents their reclamation until
	// Release exits it. rootRef and arenaRef retain the reference-counted path
	// used by other delta constructions; sharded generation leaves rootRef zero.
	rootRef  NodePtr
	arenaRef *HamtArena
	ebrPart  *Participant

	// sendKeysOffset locates the sorted send-key slab provisioned by PeelArena.
	// Entries binary-searches sendKeys lazily, and Release retires the slab
	// through EBR. The offset is zero when the keys have heap backing.
	sendKeysOffset uint64
	// shardRootsOffset locates the arena-backed root snapshot retired by
	// Release. It is zero for a heap-backed snapshot.
	shardRootsOffset uint64
	// sendKeys is the sorted view of the arena slab used by the iterator.
	sendKeys []uint64
	// arenaBacked distinguishes GenerateDelta's pooled, arena-backed shape from
	// deltas whose Entries closure and auxiliary slices have heap lifetimes.
	arenaBacked bool
	// deltaPool and participantPoolPtr identify the pools that receive the
	// delta and its EBR participant on Release. They are nil for shapes without
	// pooled lifetimes. arenaRef also supplies the arena used to retire slabs;
	// sharded generation leaves rootRef zero, making DecRef a no-op.
	deltaPool          *sync.Pool
	participantPoolPtr *sync.Pool
	// Entries is built once in deltaPool.New and captures the delta itself.
	// GenerateDelta refreshes these fields for each checkout, and Release
	// clears them without discarding the reusable closure.
	shardRoots []*HAMT
	diffNil    bool
	peelErr    error
}

// Release drops the delta's EBR pin, retires its arena slabs, and returns
// pooled resources. Call it after Entries has been fully consumed. Delaying it
// keeps the iterated roots and slabs from being reclaimed.
func (d *CRDTDelta) Release() {
	// The iterator is finished, so leave the EBR epoch and recycle the
	// participant. Exit clears its hazards and marks it inactive; a later Enter
	// reads the current global epoch before reusing it.
	if d.ebrPart != nil {
		pp := d.participantPoolPtr
		d.ebrPart.Exit()
		if pp != nil {
			pp.Put(d.ebrPart)
			d.participantPoolPtr = nil
		}
	}
	// Retire the send-key and root-snapshot slabs before clearing arenaRef.
	// Non-arena-backed deltas skip slab retirement and pool return.
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
		// Keep Entries intact across the pool round trip. Its closure reads
		// fields refreshed by the next GenerateDelta; discarding it would
		// allocate a new closure. The delta remains GC-managed in sync.Pool,
		// while the arena slabs referenced by its previous use are retired.
		pool = d.deltaPool
		d.deltaPool = nil
	}
	// Sharded deltas use EBR rather than a single root reference, so rootRef is
	// zero and DecRef returns immediately. Other delta shapes retain their
	// reference-counted release here.
	if d.arenaRef != nil {
		d.arenaRef.DecRef(d.rootRef)
		d.arenaRef = nil
	}
	// Heap-backed shapes own a per-call closure, so clearing Entries releases
	// that closure for GC. The pooled shape preserves its reusable closure.
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

// GenerateDelta returns the entries missing from remoteDigest as determined by
// IBLT subtraction and peeling. The caller must call Release after consuming
// Entries. If subtraction or peeling fails, the delta falls back to the full
// local set.
func (e *DeltaCRDTEngine) GenerateDelta(remoteDigest *IBLT) *CRDTDelta {
	// Build the local table with the remote seed and bucket count so subtraction
	// sees compatible configurations. The count is clamped by the digest builder
	// and travels with this call rather than shared engine state, allowing
	// concurrent sweeps to use different sizes. A legacy 1024-bucket digest is
	// unchanged. An incompatible fallback table makes subtraction return nil,
	// which selects full-set transmission.
	localDigest := e.GenerateDigestSizedWithSeed(remoteDigest.Seed(), remoteDigest.NumBuckets())

	// Subtract and peel in arena storage. localHas becomes the send-key set;
	// remoteHas and the pure queue are needed only within this call. Other
	// callers retain IBLT.Subtract's heap-allocating interface.
	diff := localDigest.subtractArena(remoteDigest, e.arena)
	var sendKeys []uint64
	var peelErr error
	var pureQueueOffset uint64
	var remoteHasOffset uint64
	sendKeysOffset := uint64(0)
	// Save the subtraction result before releasing diff. The lazy iterator uses
	// this flag to distinguish a configuration mismatch from a successful peel;
	// reading diff after its cleanup would incorrectly force full-set sending.
	diffNil := diff == nil
	if diff != nil {
		var remoteHas []uint64
		var localHasOffset uint64
		sendKeys, remoteHas, localHasOffset, remoteHasOffset, pureQueueOffset, peelErr = diff.PeelArena(e.arena)
		_ = remoteHas // remoteHas slab is body-local; retired below via remoteHasOffset.
		// Sort localHas in place for binary-search membership tests. The
		// generic sort avoids the interface boxing of a reflective sort and
		// leaves the send keys in their arena backing.
		slices.Sort(sendKeys)
		sendKeysOffset = localHasOffset // the slab backing sendKeys == PeelArena's localHas slab
		// PeelArena has consumed diff, so release it now. Only sendKeys remains
		// needed by the lazy iterator and therefore lives until CRDTDelta.Release.
		diff.ReleaseLocal()
		diff = nil
		// The pure queue and remoteHas never leave this goroutine. Return them
		// directly to the free list instead of allocating EBR retirement nodes.
		// Blocks used later by Entries still require epoch-deferred retirement.
		if pureQueueOffset != 0 {
			e.arena.pushFreeVar(pureQueueOffset)
		}
		if remoteHasOffset != 0 {
			e.arena.pushFreeVar(remoteHasOffset)
		}
	}
	// A nil diff or a peel error leaves sendKeys empty, which makes Entries
	// yield the full local set. diffNil records subtraction failure before the
	// local diff variable was cleared.
	peelErrVal := peelErr

	// localDigest is also local to this call and fully consumed by subtraction,
	// so release it directly rather than through EBR.
	localDigest.ReleaseLocal()

	// Entries runs after this function returns, so hold an EBR participant on
	// the delta until Release. It prevents reclamation of any snapshot root
	// retired by a concurrent InsertLocal or Join during lazy iteration.
	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	// Capture every shard under that pin. The snapshot and send-key slabs use
	// arenaRef for their own retirement; rootRef remains zero because the EBR
	// participant, rather than a single root reference, protects the roots.
	shardRoots, shardRootsOffset := e.allShardRootsArena()

	// Reuse the pool-prebuilt Entries closure. Updating its input fields avoids
	// allocating a new capture environment for shardRoots, sendKeys, diffNil,
	// and peelErr on every call.
	delta := e.deltaPool.Get().(*CRDTDelta)
	// delta.Entries is already wired to this struct by deltaPool.New.
	delta.OriginNodeID = e.localNodeID
	delta.MerkleRoot = [32]byte{} // unused by the sharded delta path
	delta.rootRef = 0             // EBR protects the roots instead of a single reference
	delta.arenaRef = e.arena      // owning arena for slab retirement
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
	// GenerateDelta-only workloads do not pass through InsertLocal or Join.
	// Advance epochs here as well so retired send-key and snapshot slabs can be
	// reclaimed and their RetiredNode values returned to the pool. The usual
	// threshold amortizes the participant scan across calls.
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
			// Advance the durability reservation without waiting for persistMu.
			// As in NextDot, the worker receives a nonblocking handoff; a busy
			// worker defers the file write to a later reservation or Close.
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
			// Record this successful inbound advance in the EWMA. The positive
			// difference is remoteCounter-current. Alpha 0.1 weights recent
			// bursts more heavily than a smaller value would, which also makes
			// the estimate easier for a peer to influence. Store the float bits
			// atomically to avoid races with snapshots.
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

// GenerateDigest returns an IBLT representing local causal state for
// anti-entropy synchronization. It uses a fresh hash seed.
func (e *DeltaCRDTEngine) GenerateDigest() *IBLT {
	return e.GenerateDigestWithSeed(maphash.MakeSeed())
}

// GenerateDigestWithSeed builds an arena-backed IBLT with the supplied seed
// and the legacy default bucket count. Use a common seed for tables that will
// be subtracted. Call Release when the digest is no longer needed; engine arena
// teardown reclaims any remaining storage.
//
// GenerateDigestSizedWithSeed contains the shared implementation. Heap-backed
// construction remains available through NewIBLTWithSeed.
func (e *DeltaCRDTEngine) GenerateDigestWithSeed(seed maphash.Seed) *IBLT {
	return e.GenerateDigestSizedWithSeed(seed, IBLTDigestDefaultBuckets)
}

// GenerateDigestSizedWithSeed builds an arena-backed IBLT with numBuckets and
// the supplied seed. ClampIBLTBuckets bounds remote-influenced sizes before
// allocation. GenerateDelta passes the remote table's size directly through
// this call, avoiding shared mutable sizing state between concurrent sweeps.
//
// To avoid a cross-shard torn snapshot, the builder captures all roots before
// insertion and compares them with the live roots afterward. A mismatch restarts
// the entire digest: IBLT insertion is XOR accumulation, so retrying only one
// shard would cancel its earlier keys. At most three attempts reuse the same
// zeroed buckets and root slice. After the final mismatch, the possibly skewed
// digest is returned; reconciliation treats it as a hint and falls back to the
// full set if peeling cannot recover a difference.
func (e *DeltaCRDTEngine) GenerateDigestSizedWithSeed(seed maphash.Seed, numBuckets int) *IBLT {
	iblt := NewArenaIBLT(ClampIBLTBuckets(numBuckets), 4, seed, e.arena)

	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	defer func() {
		participant.Exit()
		e.participantPool.Put(participant)
	}()

	n := len(e.shards)
	roots, rootsOffset := e.allShardRootsArena()
	// Build the insertion callback once and reuse it if the snapshot restarts.
	insertOne := func(_ string, entries []CRDTEntry) bool {
		for i := range entries {
			key := HashCausalDot(entries[i].Dot(), entries[i].PayloadDigest)
			iblt.Insert(key)
		}
		return true
	}
	const digestSnapshotMaxAttempts = 3
	for attempt := 1; ; attempt++ {
		for si := 0; si < n; si++ {
			shardRoot := roots[si]
			if shardRoot == nil {
				continue
			}
			shardRoot.ForEach(insertOne)
		}
		stable := true
		for si := 0; si < n; si++ {
			if e.shards[si].ptr.Load() != roots[si] {
				stable = false
				break
			}
		}
		if stable || attempt >= digestSnapshotMaxAttempts {
			break
		}
		// A concurrent write changed a root. Count the restart, clear the reused
		// buckets, refresh the root snapshot in place, and rebuild without
		// allocating new slabs.
		digestSnapshotRestarts.Add(1)
		for i := range iblt.buckets {
			iblt.buckets[i] = Bucket{}
		}
		for si := 0; si < n; si++ {
			roots[si] = e.shards[si].ptr.Load()
		}
	}
	if rootsOffset != 0 {
		// The root snapshot does not escape this call, so return its slab
		// directly to the free list without an EBR retirement node.
		e.arena.pushFreeVar(rootsOffset)
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

// Strata estimator integration (ADR-0005).

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

	// Insert every shard's entries under the EBR pin. The estimator is a
	// difference-size hint, so snapshot skew between shards is tolerable.
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

// GenerateDeltaStratified was removed because a StrataEstimator cannot supply
// the remote key set required for reconciliation (ADR-0034). Its XOR summaries
// estimate difference size but are not invertible into a populated remote IBLT.
// The old implementation created an empty remote table and subtracted it, which
// resent every local entry even when the peer already had some of them.
//
// The mesh now sends the remote's full IBLT and calls GenerateDelta directly.
// The estimator remains useful only as a sizing hint.

// -------------------------------------------------------------------
