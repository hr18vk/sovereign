// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package index

// Regression tests for move dominance, tie retention, memory bounds, and
// concurrent feeds. The comments describe fault injections that make each
// guard's test fail. The package uses no sync.Mutex and runs under -race.

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIndex_LatestMove checks that a strictly greater SystemTime moves an
// entity out of its old cell and into its new one in both byH3 and bySysTime.
// A stale post-move write must not resurrect the old cell.
//
// Negative control: commenting out the move arm's removeCell loop preserves
// the old membership and fails this test.
func TestIndex_LatestMove(t *testing.T) {
	ix := NewWith(4, 1) // epoch 1ns: exact bySysTime buckets
	ix.Apply(Record{EntityID: "E", H3Index: 0xC1, SystemTime: 100})
	ix.Apply(Record{EntityID: "E", H3Index: 0xC2, SystemTime: 200})

	if got := ix.CandidatesByH3(0xC1); len(got) != 0 {
		t.Fatalf("latest-move: E remains in old cell C1 after the move (candidates=%v); stale membership was not removed", got)
	}
	if got := ix.CandidatesByH3(0xC2); len(got) != 1 || got[0] != "E" {
		t.Fatalf("latest-move: E is not the sole member of the new cell C2 (candidates=%v)", got)
	}
	if got := ix.CandidatesBySysTime(200); len(got) != 1 || got[0] != "E" {
		t.Fatalf("latest-move: E missing from bySysTime at its own sysTime=200 (candidates=%v)", got)
	}
	if got := ix.CandidatesBySysTime(201); len(got) != 0 {
		t.Fatalf("latest-move: bySysTime returned %v for afterT=201; E's current SystemTime is 200", got)
	}
	ix.Apply(Record{EntityID: "E", H3Index: 0xC1, SystemTime: 150})
	if got := ix.CandidatesByH3(0xC1); len(got) != 0 {
		t.Fatalf("latest-move: a stale sys=150 write resurrected cell C1 (candidates=%v)", got)
	}
}

// TestIndex_StaleNoRegress checks that an older remote delta cannot move an
// entity back to its old cell after a newer write. The index uses the
// resolver's strict-greater rule.
//
// Negative control: changing the move guard from `>` to `!=` also moves stale
// deltas and fails this test.
func TestIndex_StaleNoRegress(t *testing.T) {
	ix := NewWith(4, 1)
	ix.Apply(Record{EntityID: "E", H3Index: 0xC2, SystemTime: 200})
	ix.Apply(Record{EntityID: "E", H3Index: 0xC1, SystemTime: 100}) // the reordered arrival
	if got := ix.CandidatesByH3(0xC1); len(got) != 0 {
		t.Fatalf("stale-no-regress: the stale sys=100 delta regressed E into cell C1 (candidates=%v)", got)
	}
	if got := ix.CandidatesByH3(0xC2); len(got) != 1 || got[0] != "E" {
		t.Fatalf("stale-no-regress: E lost its C2 membership on a stale write (candidates=%v)", got)
	}
	// The single-shard contended shape holds the same rule (no sharding escape).
	ix2 := NewWith(1, 1)
	ix2.Apply(Record{EntityID: "E", H3Index: 0xC2, SystemTime: 200})
	ix2.Apply(Record{EntityID: "E", H3Index: 0xC1, SystemTime: 100})
	if got := ix2.CandidatesByH3(0xC1); len(got) != 0 {
		t.Fatalf("stale-no-regress: single-shard shape regressed E into C1 (candidates=%v)", got)
	}
}

// TestIndex_TieRetention checks that equal-SystemTime writes retain both cells
// because the resolver's scan-order-dependent tie winner cannot be predicted
// here. A strictly greater write clears the retained cells. The test also
// checks the MaxTieCells bound and its drop counter.
func TestIndex_TieRetention(t *testing.T) {
	ix := NewWith(2, 1)
	ix.Apply(Record{EntityID: "E", H3Index: 0xC1, SystemTime: 100})
	ix.Apply(Record{EntityID: "E", H3Index: 0xC2, SystemTime: 100}) // the tie
	m1 := ix.CandidatesByH3(0xC1)
	m2 := ix.CandidatesByH3(0xC2)
	if len(m1) != 1 || m1[0] != "E" || len(m2) != 1 || m2[0] != "E" {
		t.Fatalf("tie-retention: equal-sys writes must retain both cells (C1=%v C2=%v)", m1, m2)
	}
	if st := ix.Stats(); st.Entities != 1 || st.H3Members != 2 || st.SysMembers != 1 {
		t.Fatalf("tie-retention: shape mismatch — want 1 entity / 2 h3 members / 1 sys member (got %+v)", st)
	}
	// The strictly-greater move clears the entire retained tie list.
	ix.Apply(Record{EntityID: "E", H3Index: 0xC3, SystemTime: 200})
	if got := ix.CandidatesByH3(0xC1); len(got) != 0 {
		t.Fatalf("tie-retention: the move left the tie-retained C1 membership (candidates=%v)", got)
	}
	if got := ix.CandidatesByH3(0xC2); len(got) != 0 {
		t.Fatalf("tie-retention: the move left the tie-retained C2 membership (candidates=%v)", got)
	}
	if got := ix.CandidatesByH3(0xC3); len(got) != 1 || got[0] != "E" {
		t.Fatalf("tie-retention: E not in the new cell C3 after the move (candidates=%v)", got)
	}
	// MaxTieCells retains the initial cell and seven ties. The remaining four
	// equal-time cells are dropped and counted.
	ix2 := NewWith(1, 1)
	ix2.Apply(Record{EntityID: "cap", H3Index: 0xD0, SystemTime: 50})
	for i := 1; i <= 11; i++ {
		ix2.Apply(Record{EntityID: "cap", H3Index: 0xD0 + uint64(i), SystemTime: 50})
	}
	st := ix2.Stats()
	if st.H3Members != MaxTieCells {
		t.Fatalf("tie-retention: the MaxTieCells cap did not bound the tie list (h3members=%d want %d)", st.H3Members, MaxTieCells)
	}
	if st.TieDrops != 4 { // ties at D8..D11 exceed the cap (D0 + D1..D7 retained)
		t.Fatalf("tie-retention: tieDrops=%d want 4 (the cap drops must be counted, not silent)", st.TieDrops)
	}
}

// TestIndex_MemoryBound checks four properties:
//
//	(1) size: a 100K-entity fill stays within 512 bytes per entity;
//	(2) shape: Stats reports one latest and one bySys membership per entity;
//	(3) rewrite: new cells and strictly greater timestamps leave those counts
//	    unchanged, so a skipped removeCell doubles H3Members and fails;
//	(4) stale writes: Apply performs no allocations for the anti-entropy case.
//
// The test also reports fresh-entity allocations.
func TestIndex_MemoryBound(t *testing.T) {
	const N = 100_000
	ix := NewWith(8, 3600*1e9)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < N; i++ {
		ix.Apply(Record{EntityID: fmt.Sprintf("ent-%d", i), H3Index: uint64(i % 64), SystemTime: int64(i)})
	}
	runtime.GC()
	var afterFill runtime.MemStats
	runtime.ReadMemStats(&afterFill)
	perEntity := float64(afterFill.HeapAlloc-before.HeapAlloc) / float64(N)
	t.Logf("index-bound: measured %.0f bytes/entity steady-state (N=%d over 64 cells)", perEntity, N)
	if perEntity > 512 {
		t.Fatalf("index-bound: %.0f bytes/entity exceeds the 512-byte limit", perEntity)
	}
	st := ix.Stats()
	if st.Entities != N || st.SysMembers != N || st.H3Members != N {
		t.Fatalf("index-bound: got entities=%d h3members=%d sysmembers=%d, want exactly N in all three", st.Entities, st.H3Members, st.SysMembers)
	}
	// Rewrite the same entities with strictly greater timestamps and new cells.
	var beforeRW runtime.MemStats
	runtime.ReadMemStats(&beforeRW)
	for i := 0; i < N; i++ {
		ix.Apply(Record{EntityID: fmt.Sprintf("ent-%d", i), H3Index: uint64(i%64) + 1000, SystemTime: int64(1_000_000 + i)})
	}
	runtime.GC()
	var afterRW runtime.MemStats
	runtime.ReadMemStats(&afterRW)
	rwMallocs := afterRW.Mallocs - beforeRW.Mallocs
	t.Logf("index-bound: rewrite of %d entities: %d mallocs (%.2f/move), heap delta %.1f MB", N, rwMallocs, float64(rwMallocs)/float64(N), float64(int64(afterRW.HeapAlloc)-int64(afterFill.HeapAlloc))/1e6)
	st2 := ix.Stats()
	if st2.Entities != N || st2.SysMembers != N || st2.H3Members != N {
		t.Fatalf("index-bound: the rewrite changed the shape (entities=%d h3members=%d sysmembers=%d) — a move leaked memberships", st2.Entities, st2.H3Members, st2.SysMembers)
	}
	allocs := testing.AllocsPerRun(200, func() {
		ix.Apply(Record{EntityID: "ent-0", H3Index: 0, SystemTime: 1}) // stale: current is 1_000_000
	})
	if allocs != 0 {
		t.Fatalf("index-bound: a stale Apply allocated %g times — the re-gossip hot path must be zero-alloc", allocs)
	}
	recs := make([]Record, 1000)
	for i := range recs {
		recs[i] = Record{EntityID: fmt.Sprintf("fresh-%d", i), H3Index: 1, SystemTime: int64(i)}
	}
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for i := range recs {
		ix.Apply(recs[i])
	}
	runtime.ReadMemStats(&m1)
	t.Logf("index-bound: fresh-entity Apply measured %.2f allocs/entity (new-entity growth, not per-delta)", float64(m1.Mallocs-m0.Mallocs)/1000)
}

// TestIndex_FeedRace moves entities between two cells from concurrent writers
// while a reader polls CandidatesByH3Multi. Every view must contain each
// introduced entity exactly once across the two cells. Removal and insertion
// under one shard lock prevent an entity from appearing in neither cell or in
// both. Running with -race also checks the spinlock's happens-before edges.
//
// Negative control: unlocking between removal and insertion lets the reader
// observe a partial move and reduces the union count.
func TestIndex_FeedRace(t *testing.T) {
	const writers, perWriter = 8, 512
	const total = writers * perWriter
	ix := NewWith(8, 1)
	const cellA, cellB = uint64(0xA), uint64(0xB)
	for w := 0; w < writers; w++ {
		for i := 0; i < perWriter; i++ {
			ix.Apply(Record{EntityID: fmt.Sprintf("w%d-e%d", w, i), H3Index: cellA, SystemTime: int64(1 + i)})
		}
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			sys := int64(1_000)
			for !stop.Load() {
				for i := 0; i < perWriter; i++ {
					id := fmt.Sprintf("w%d-e%d", w, i)
					ix.Apply(Record{EntityID: id, H3Index: cellB, SystemTime: sys})
					ix.Apply(Record{EntityID: id, H3Index: cellA, SystemTime: sys + 1})
				}
				sys += 2
			}
		}(w)
	}
	polls := 0
	deadline := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(deadline) {
		view := ix.CandidatesByH3Multi(cellA, cellB)
		seen := make(map[string]struct{}, total)
		union := 0
		for _, ids := range view {
			for _, id := range ids {
				if _, dup := seen[id]; dup {
					t.Fatalf("feed-race: entity %s in both cells of one consistent view (poll #%d)", id, polls)
				}
				seen[id] = struct{}{}
				union++
			}
		}
		if union != total {
			t.Fatalf("feed-race: torn move observed — %d entities visible across {A,B}, want exactly %d (poll #%d)", union, total, polls)
		}
		polls++
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("feed-race: %d consistent multi-cell views clean over 700ms (8 writers x 512 entities, 8 shards)", polls)
}
