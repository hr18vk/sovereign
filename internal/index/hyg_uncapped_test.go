// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package index

import "testing"

// TestHyg_UncappedCount checks entity accounting when
// --secondary-index-max-entities is unset and maxEntities is zero. IndexHealth
// must count every fresh insert even without a ceiling, matching the shard
// walk in Stats that supplies the /metrics gauge. Moves and stale
// re-observations do not change either count.
//
// Negative control: skipping reserveEntity when maxEntities is zero leaves the
// IndexHealth counter at zero while Stats reports the admitted entities.
func TestHyg_UncappedCount(t *testing.T) {
	ix := NewWith(4, 3600*1e9)
	// No SetEntityCeiling call leaves maxEntities at the default of zero.
	const N = 3
	ix.Apply(Record{EntityID: "hyg-a", H3Index: 0x8928308280fffff, SystemTime: 1000})
	ix.Apply(Record{EntityID: "hyg-b", H3Index: 0x8928308280ffffe, SystemTime: 1001})
	ix.Apply(Record{EntityID: "hyg-c", H3Index: 0x8928308280ffffd, SystemTime: 1002})
	hEnt, _, cd, degraded := ix.IndexHealth()
	if hEnt != N {
		t.Fatalf("uncapped count: IndexHealth().entities=%d, want %d; fresh inserts were not counted", hEnt, N)
	}
	if cd != 0 || degraded {
		t.Fatalf("uncapped count: ceilingDrops=%d degraded=%v, want 0/false because no ceiling is set", cd, degraded)
	}
	st := ix.Stats()
	if st.Entities != N {
		t.Fatalf("uncapped count: Stats().Entities=%d, want %d; the feed did not land", st.Entities, N)
	}
	if st.Entities != hEnt {
		t.Fatalf("uncapped count: shard walk=%d and IndexHealth counter=%d, want equal values for the /metrics gauge and query response", st.Entities, hEnt)
	}
	// A move to a newer cell does not increment the fresh-entity count.
	ix.Apply(Record{EntityID: "hyg-a", H3Index: 0x8928308280ffffc, SystemTime: 2000})
	// A stale re-observation is ignored and does not increment the count.
	ix.Apply(Record{EntityID: "hyg-b", H3Index: 0x8928308280ffffe, SystemTime: 1})
	hEnt2, _, cd2, _ := ix.IndexHealth()
	st2 := ix.Stats()
	if hEnt2 != N || st2.Entities != N || hEnt2 != st2.Entities || cd2 != 0 {
		t.Fatalf("uncapped count: after a move and stale re-observation, want count %d; got counter=%d walk=%d ceilingDrops=%d; neither update is a fresh insert", N, hEnt2, st2.Entities, cd2)
	}
}
