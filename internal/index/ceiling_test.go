// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package index

// These tests cover the distinct-entity ceiling, negative-timestamp bucket
// keys, and concurrent slot reservation. Their comments describe negative
// controls that disable the corresponding guard.

import (
	"fmt"
	"sync"
	"testing"
)

// TestCeiling_ExactAndLoud checks that the entity ceiling is not overshot,
// refusals are counted, and the degraded flag remains set. Moves of existing
// entities still apply without increasing the entity count.
//
// Negative control: making reserveEntity return true unconditionally disables
// the ceiling and fails this test.
func TestCeiling_ExactAndLoud(t *testing.T) {
	ix := NewWith(2, 3600*1e9)
	ix.SetEntityCeiling(2)
	ix.Apply(Record{EntityID: "a", H3Index: 1, SystemTime: 100})
	ix.Apply(Record{EntityID: "b", H3Index: 2, SystemTime: 101})
	ix.Apply(Record{EntityID: "c", H3Index: 3, SystemTime: 102}) // over the cap -> dropped
	if st := ix.Stats(); st.Entities != 2 {
		t.Fatalf("ceiling did not bind: %d entities, want exactly 2", st.Entities)
	}
	if _, _, cd, degraded := ix.IndexHealth(); cd != 1 || !degraded {
		t.Fatalf("ceilingDrops=%d degraded=%v, want 1/true (drop counter and sticky degraded flag)", cd, degraded)
	}
	// An existing entity's move still applies (bounded, no growth).
	ix.Apply(Record{EntityID: "a", H3Index: 9, SystemTime: 200})
	if got := ix.CandidatesByH3(9); len(got) != 1 || got[0] != "a" {
		t.Fatalf("existing entity's move was refused by the ceiling; only new entities may be dropped (candidates=%v)", got)
	}
	// Degraded is sticky: it never silently clears.
	if _, _, _, degraded := ix.IndexHealth(); !degraded {
		t.Fatalf("degraded cleared spontaneously; it must remain set for the index's lifetime")
	}
	// A later record for the dropped entity is still a fresh insert because
	// the entity never entered latest, so it is dropped and counted again.
	ix.Apply(Record{EntityID: "c", H3Index: 3, SystemTime: 50})
	if _, _, cd, _ := ix.IndexHealth(); cd != 2 {
		t.Fatalf("dropped entity's re-arrival must count another ceiling drop, got %d", cd)
	}
	// A zero ceiling leaves the index uncapped, matching the engine's
	// no-eviction behavior.
	ix2 := NewWith(2, 1)
	ix2.Apply(Record{EntityID: "x", H3Index: 1, SystemTime: 1})
	ix2.Apply(Record{EntityID: "y", H3Index: 1, SystemTime: 1})
	if st := ix2.Stats(); st.Entities != 2 {
		t.Fatalf("zero ceiling refused an entity; the uncapped index must admit it (entities=%d)", st.Entities)
	}
}

// TestCeiling_BucketKeyFloorsNegative checks that bucketKey rounds negative
// SystemTime values toward negative infinity rather than truncating toward
// zero. Wall-clock nanoseconds are positive in normal operation; this test
// covers the rest of the int64 domain.
//
// Negative control: plain truncating division maps bucketKey(-1) to zero and
// fails this test.
func TestCeiling_BucketKeyFloorsNegative(t *testing.T) {
	ix := NewWith(1, 100)
	if got := ix.bucketKey(-1); got != -1 {
		t.Fatalf("bucketKey(-1)=%d, want -1 (floor toward -inf, not truncation to 0)", got)
	}
	if got := ix.bucketKey(-100); got != -1 {
		t.Fatalf("bucketKey(-100)=%d, want -1 (exactly one bucket below zero)", got)
	}
	if got := ix.bucketKey(99); got != 0 {
		t.Fatalf("bucketKey(99)=%d, want 0", got)
	}
}

// TestCeiling_ConcurrentExact races 32 goroutines inserting 64 distinct
// entities each against a ceiling of 100. The shard maps and reservation
// counter must both report exactly 100 admissions, with every refusal counted
// and the degraded flag set. A check-then-set reservation can pass the serial
// test while allowing concurrent over-admission.
//
// Negative control: replacing CompareAndSwap with check-then-set passes the
// serial test and fails this concurrent test.
func TestCeiling_ConcurrentExact(t *testing.T) {
	ix := NewWith(8, 3600*1e9)
	const maxEnt = 100
	ix.SetEntityCeiling(maxEnt)
	const workers, per = 32, 64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				ix.Apply(Record{EntityID: fmt.Sprintf("ce-%d-%d", w, i), H3Index: uint64(i), SystemTime: int64(i)})
			}
		}()
	}
	wg.Wait()
	st := ix.Stats()
	hEnt, _, cd, degraded := ix.IndexHealth()
	if st.Entities != maxEnt || hEnt != maxEnt || st.Entities != hEnt {
		t.Fatalf("ceiling.concurrent: shard maps report %d entities and counter reports %d, want exactly %d in both; concurrent reservation exceeded the ceiling", st.Entities, hEnt, maxEnt)
	}
	if want := workers*per - maxEnt; int(cd) != want {
		t.Fatalf("ceiling.concurrent: ceilingDrops=%d, want %d; every refused fresh insert must be counted", cd, want)
	}
	if !degraded {
		t.Fatalf("ceiling.concurrent: degraded=%v, want true after the ceiling refuses an insert", degraded)
	}
}
