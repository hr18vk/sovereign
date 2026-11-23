// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package index maintains the optional cross-entity secondary index. The node
// wires it only when --secondary-index is enabled. Its concrete type has one
// non-test importer, cmd/sovereign-node. Other packages use either a feeder
// function with the signature func(entityID string, h3Index uint64,
// systemTime int64) or the SecondaryIndexSource interface owned by
// internal/database.
//
// Each entity has a current (h3Index, systemTime) entry. QueryByH3 and
// QueryBySystemTime can therefore start with a candidate set rather than scan
// every entity, then resolve each candidate through Resolver.AsOf.
//
// An entry moves only when the incoming SystemTime is strictly greater. A
// stale observation cannot move an entity back to an old cell. The resolver's
// choice among equal-time rows depends on encounter order, so the index
// retains each observed cell on a tie. Query-time resolution removes any
// resulting false candidates.
//
// Each shard has a CAS spinlock, implemented with atomic.Uint32 and Gosched,
// rather than a sync.Mutex. The lock covers removal of old memberships and
// insertion of new ones, so readers see either side of a move, never a torn
// intermediate state.
package index

import (
	"runtime"
	"sort"
	"sync/atomic"
)

// Record is the feed record emitted after a write lands. EntityID identifies
// the indexed entity, H3Index is its cell, and SystemTime determines dominance.
// Dot fields are absent because the resolver's encounter-ordered tie rule does
// not use them to determine cell membership.
type Record struct {
	EntityID   string
	H3Index    uint64
	SystemTime int64
}

// DefaultShards is the shard count used by New. Every per-entity structure in
// a shard is keyed by that shard's entities, so Apply touches exactly one
// shard and a move is single-shard atomic.
const DefaultShards = 16

// DefaultEpochNs is the bySysTime bucket granularity: 1 hour. A bucket holds
// every entity whose current SystemTime falls in [k*epoch, (k+1)*epoch). The
// active-bucket count is bounded by the live-entity time span, not by entity
// count, and the within-bucket over-approximation is trimmed by the
// per-entity resolve at query time (the same contract byH3 carries).
const DefaultEpochNs = int64(3600 * 1e9)

// MaxTieCells caps the number of cells retained for equal-SystemTime writes
// to one entity. Further distinct cells at that timestamp are dropped and
// counted in tieDrops. Such a drop can omit a candidate but cannot introduce
// a row that resolution would reject.
const MaxTieCells = 8

// idxEntry is an entity's current index state. cells holds every retained
// cell membership: len==1 in the common case (the latest write's cell); a
// tie (equal SystemTime, different cell) appends — the over-approximation the
// query-side re-check trims. sys is the dominance key; it is the only field
// that decides whether an incoming observation is newer, equal, or stale.
type idxEntry struct {
	sys   int64
	cells []uint64
}

// shard owns all per-entity index state for the entities it covers. Apply
// touches only the shard selected by fnv(entityID) & mask, which lets one lock
// make the move between cells atomic for that entity.
type shard struct {
	// mu is the CAS spinlock: 0 = free, 1 = held. atomic.Uint32 avoids futex
	// stalls on the write path; a failed CAS spins with runtime.Gosched. The
	// atomic acquire/release establishes the happens-before edge required by
	// the race detector for the maps below.
	mu     atomic.Uint32
	latest map[string]idxEntry
	// byH3 maps cell -> the members of that cell among this shard's
	// entities (an entity lives only in its own shard's byH3 — a query
	// unions across shards).
	byH3 map[uint64]map[string]struct{}
	// bySys maps epoch-bucket key -> members whose current SystemTime
	// falls in that bucket. Exactly one membership per entity at all
	// times (moved with the head, never tied-retained: an equal-sys
	// observation stays in the same bucket by construction).
	bySys map[int64]map[string]struct{}
	// sysKeys is the sorted active bucket-key list, maintained on bucket
	// create/remove. CandidatesBySysTime binary-searches it and walks the
	// suffix >= floor(afterT/epoch).
	sysKeys []int64
}

// Index is the sharded cross-entity secondary index.
type Index struct {
	shards []*shard
	epoch  int64
	// tieDrops counts records rejected by MaxTieCells. A nonzero value
	// indicates many distinct cells at one entity timestamp and warrants
	// investigation; it is not an index error by itself.
	tieDrops atomic.Uint64
	// maxEntities caps the distinct-entity count; zero is uncapped, matching
	// the engine's no-eviction live state. At the limit, records for entities
	// not yet indexed are dropped and counted in ceilingDrops. The sticky
	// ceilingTripped flag marks the index degraded so queries return an error
	// instead of an incomplete answer. Moves of existing entities still apply
	// in O(1) work without increasing the entity count.
	maxEntities    int
	ceilingDrops   atomic.Uint64
	ceilingTripped atomic.Bool
	// entities is the monotone distinct-entity count (admitted fresh
	// inserts only — the engine is no-eviction, the index matches).
	// The reserve counts every fresh insert in both ceiling modes so
	// IndexHealth reports the true count in O(1) without walking shards
	// and agrees with Stats().Entities by construction.
	// Cache-line note: it packs with the drop counters (cold in steady
	// state) with no 128-byte stride because fresh inserts are the minority
	// on the ingest layer, ceilingDrops never fires uncapped, and tieDrops
	// is a pathology signal; add padding only if high-churn ingest profiling
	// calls for it.
	entities atomic.Int64
}

// New constructs an Index with DefaultShards shards and DefaultEpochNs
// sysTime buckets.
func New() *Index {
	return NewWith(DefaultShards, DefaultEpochNs)
}

// NewWith constructs an Index with an explicit shard count and bucket epoch.
// The shard count is rounded up to a power of two; values below one select a
// single shard. A nonpositive epoch selects DefaultEpochNs. Tests use small
// values to force single-shard and contended layouts.
func NewWith(shards int, epochNs int64) *Index {
	if shards < 1 {
		shards = 1
	}
	n := 1
	for n < shards {
		n <<= 1
	}
	if epochNs <= 0 {
		epochNs = DefaultEpochNs
	}
	ix := &Index{shards: make([]*shard, n), epoch: epochNs}
	for i := range ix.shards {
		ix.shards[i] = &shard{
			latest: make(map[string]idxEntry),
			byH3:   make(map[uint64]map[string]struct{}),
			bySys:  make(map[int64]map[string]struct{}),
		}
	}
	return ix
}

// lock acquires the shard CAS spinlock. The critical section contains only
// map and slice operations, with no I/O. Gosched yields the processor while a
// waiter retries the CAS.
func (s *shard) lock() {
	for !s.mu.CompareAndSwap(0, 1) {
		runtime.Gosched()
	}
}

// unlock releases the shard spinlock.
func (s *shard) unlock() {
	s.mu.Store(0)
}

// shardOf routes entityID to a shard using FNV-1a over its string bytes. The
// mask is one less than the power-of-two shard count.
func (ix *Index) shardOf(entityID string) *shard {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(entityID); i++ {
		h ^= uint64(entityID[i])
		h *= prime64
	}
	return ix.shards[h&(uint64(len(ix.shards)-1))]
}

// bucketKey floors SystemTime to its epoch bucket. For negative values, floor
// toward negative infinity differs from Go's truncating division: a pre-1970
// timestamp belongs to the bucket below zero, not [0, epoch). Normal wall-clock
// timestamps are positive, but the arithmetic covers the full int64 range.
func (ix *Index) bucketKey(sys int64) int64 {
	k := sys / ix.epoch
	if sys < 0 && sys%ix.epoch != 0 {
		k--
	}
	return k
}

// Apply folds one observed write into the index after the write lands in the
// engine. It is the index's only mutation entry point and follows the
// resolver's dominance rule:
//
//	incoming.sys > cur.sys: remove all old cell and timestamp memberships,
//	    then install the new ones in one critical section. A concurrent query
//	    sees either the old state or the new state.
//	incoming.sys == cur.sys: retain the incoming cell as well, up to
//	    MaxTieCells, unless it is already present.
//	incoming.sys < cur.sys: ignore the stale observation.
func (ix *Index) Apply(rec Record) {
	s := ix.shardOf(rec.EntityID)
	s.lock()
	defer s.unlock()
	cur, ok := s.latest[rec.EntityID]
	if !ok {
		// reserveEntity runs for every fresh insert so IndexHealth counts
		// entities in both capped and uncapped modes. Its CAS loop combines
		// the capacity check and claim, preventing concurrent inserts on
		// different shards from exceeding the ceiling. A refusal drops only
		// the index record, increments ceilingDrops, and marks the derived
		// index degraded; it does not fail the engine write.
		if !ix.reserveEntity() {
			ix.ceilingDrops.Add(1)
			ix.ceilingTripped.Store(true)
			return
		}
		s.latest[rec.EntityID] = idxEntry{sys: rec.SystemTime, cells: []uint64{rec.H3Index}}
		ix.addCell(s, rec.EntityID, rec.H3Index)
		ix.addSys(s, rec.EntityID, rec.SystemTime)
		return
	}
	switch {
	case rec.SystemTime > cur.sys:
		for _, c := range cur.cells {
			ix.removeCell(s, rec.EntityID, c)
		}
		ix.removeSys(s, rec.EntityID, cur.sys)
		s.latest[rec.EntityID] = idxEntry{sys: rec.SystemTime, cells: []uint64{rec.H3Index}}
		ix.addCell(s, rec.EntityID, rec.H3Index)
		ix.addSys(s, rec.EntityID, rec.SystemTime)
	case rec.SystemTime == cur.sys:
		for _, c := range cur.cells {
			if c == rec.H3Index {
				return // already a member
			}
		}
		if len(cur.cells) >= MaxTieCells {
			ix.tieDrops.Add(1)
			return
		}
		cur.cells = append(cur.cells, rec.H3Index)
		s.latest[rec.EntityID] = cur
		ix.addCell(s, rec.EntityID, rec.H3Index)
	}
	// A stale observation takes no action, preserving the newer entry.
}

// addCell installs a (cell, entityID) membership in the shard.
func (ix *Index) addCell(s *shard, entityID string, cell uint64) {
	members, ok := s.byH3[cell]
	if !ok {
		members = make(map[string]struct{})
		s.byH3[cell] = members
	}
	members[entityID] = struct{}{}
}

// removeCell drops a membership and de-registers an emptied cell map.
func (ix *Index) removeCell(s *shard, entityID string, cell uint64) {
	members, ok := s.byH3[cell]
	if !ok {
		return
	}
	delete(members, entityID)
	if len(members) == 0 {
		delete(s.byH3, cell)
	}
}

// addSys installs the entity's single sysTime-bucket membership, creating the
// bucket (and its sorted key) on first sight.
func (ix *Index) addSys(s *shard, entityID string, sys int64) {
	k := ix.bucketKey(sys)
	members, ok := s.bySys[k]
	if !ok {
		members = make(map[string]struct{})
		s.bySys[k] = members
		ix.insertSysKey(s, k)
	}
	members[entityID] = struct{}{}
}

// removeSys drops the bucket membership and de-registers an emptied bucket.
func (ix *Index) removeSys(s *shard, entityID string, sys int64) {
	k := ix.bucketKey(sys)
	members, ok := s.bySys[k]
	if !ok {
		return
	}
	delete(members, entityID)
	if len(members) == 0 {
		delete(s.bySys, k)
		ix.removeSysKey(s, k)
	}
}

// insertSysKey maintains the sorted active-bucket-key slice.
func (ix *Index) insertSysKey(s *shard, k int64) {
	i := sort.Search(len(s.sysKeys), func(i int) bool { return s.sysKeys[i] >= k })
	if i < len(s.sysKeys) && s.sysKeys[i] == k {
		return
	}
	s.sysKeys = append(s.sysKeys, 0)
	copy(s.sysKeys[i+1:], s.sysKeys[i:])
	s.sysKeys[i] = k
}

// removeSysKey drops a bucket key from the sorted slice.
func (ix *Index) removeSysKey(s *shard, k int64) {
	i := sort.Search(len(s.sysKeys), func(i int) bool { return s.sysKeys[i] >= k })
	if i < len(s.sysKeys) && s.sysKeys[i] == k {
		s.sysKeys = append(s.sysKeys[:i], s.sysKeys[i+1:]...)
	}
}

// CandidatesByH3 returns the live candidate set for cell: every entity whose
// current (or tie-retained) index entry names that cell. It unions every
// shard's members under that shard's spinlock (copy-out — the returned slice
// is caller-owned) and sorts for deterministic assertions.
//
// The set can include tie-retained entities and entities whose resolved row at
// the query's txTime names a different cell. The caller resolves each candidate
// through Resolver.AsOf and keeps rows whose resolved H3Index equals cell.
// MaxTieCells overflow and the entity ceiling can omit candidates; Stats and
// IndexHealth report those conditions.
func (ix *Index) CandidatesByH3(cell uint64) []string {
	out := make([]string, 0, 16)
	for _, s := range ix.shards {
		s.lock()
		for id := range s.byH3[cell] {
			out = append(out, id)
		}
		s.unlock()
	}
	sort.Strings(out)
	return out
}

// CandidatesBySysTime returns every entity whose current SystemTime bucket
// is >= the bucket containing afterT. Within the boundary bucket the set
// over-approximates (members modified before afterT ride the same bucket);
// the query-side per-entity resolve trims them — the same contract as byH3.
func (ix *Index) CandidatesBySysTime(afterT int64) []string {
	from := ix.bucketKey(afterT)
	out := make([]string, 0, 16)
	for _, s := range ix.shards {
		s.lock()
		i := sort.Search(len(s.sysKeys), func(i int) bool { return s.sysKeys[i] >= from })
		for ; i < len(s.sysKeys); i++ {
			for id := range s.bySys[s.sysKeys[i]] {
				out = append(out, id)
			}
		}
		s.unlock()
	}
	sort.Strings(out)
	return out
}

// Stats reports index membership counts and tie drops. Each admitted entity
// has one latest entry and one sysTime membership, plus at most MaxTieCells
// retained H3 memberships. Admitted entities are not evicted, so the number of
// admissions and retained ties determines the index's size.
type Stats struct {
	Entities   int
	Cells      int
	H3Members  int
	SysBuckets int
	SysMembers int
	TieDrops   uint64
}

// Stats walks every shard under its spinlock and totals the counts.
func (ix *Index) Stats() Stats {
	var st Stats
	for _, s := range ix.shards {
		s.lock()
		st.Entities += len(s.latest)
		st.Cells += len(s.byH3)
		for _, m := range s.byH3 {
			st.H3Members += len(m)
		}
		st.SysBuckets += len(s.bySys)
		for _, m := range s.bySys {
			st.SysMembers += len(m)
		}
		s.unlock()
	}
	st.TieDrops = ix.tieDrops.Load()
	return st
}

// CandidatesByH3Multi returns candidate sets for several distinct cells from
// one consistent per-shard view. Each shard is locked once for all requested
// cells, so an entity's move cannot make it appear in both its old and new
// cells, or in neither, within the returned view. An entity retained on an
// equal-time tie can legitimately appear in two cells; the no-duplicate
// guarantee applies to moves, not ties. Repeating a cell in cells appends its
// members repeatedly and is outside that guarantee.
//
// Reading a cell and its neighbors with separate CandidatesByH3 calls can
// double-count an entity that moves between calls. This method avoids that
// intermediate view and is the shape exercised by TestIndex_FeedRace.
func (ix *Index) CandidatesByH3Multi(cells ...uint64) map[uint64][]string {
	out := make(map[uint64][]string, len(cells))
	for _, s := range ix.shards {
		s.lock()
		for _, c := range cells {
			for id := range s.byH3[c] {
				out[c] = append(out[c], id)
			}
		}
		s.unlock()
	}
	for c := range out {
		sort.Strings(out[c])
	}
	return out
}

// SetEntityCeiling sets the distinct-entity bound exposed by
// --secondary-index-max-entities. Zero leaves the index uncapped, matching the
// engine's no-eviction behavior. Call it before the first Apply; the node does
// so during construction. A later call affects only future fresh inserts and
// never evicts existing entries. reserveEntity enforces the limit across
// concurrent inserts on different shards.
func (ix *Index) SetEntityCeiling(maxEntities int) { ix.maxEntities = maxEntities }

// reserveEntity atomically claims one entity slot. Checking the limit and
// incrementing the monotone entities counter share one CAS loop, so concurrent
// fresh inserts cannot exceed maxEntities. Every fresh insert uses this path,
// including uncapped inserts, keeping IndexHealth consistent with Stats.
// A capped reservation at or above the limit returns false without
// incrementing; an uncapped reservation always succeeds. Nothing evicts, so
// entities equals Stats().Entities in both modes.
func (ix *Index) reserveEntity() bool {
	for {
		cur := ix.entities.Load()
		if ix.maxEntities > 0 && cur >= int64(ix.maxEntities) {
			return false
		}
		if ix.entities.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// IndexHealth implements the SecondaryIndexSource interface owned by
// internal/database without exposing the concrete Index type across that
// package boundary. It reads the four atomic counters in constant time; the
// values are not a transactional snapshot. Once the entity ceiling drops a
// record, degraded remains true for the index's lifetime. The query tier then
// returns an error instead of serving an incomplete candidate set.
func (ix *Index) IndexHealth() (entities int, tieDrops uint64, ceilingDrops uint64, degraded bool) {
	return int(ix.entities.Load()), ix.tieDrops.Load(), ix.ceilingDrops.Load(), ix.ceilingTripped.Load()
}
