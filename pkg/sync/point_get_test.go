// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"encoding/hex"
	"slices"
	"strconv"
	"testing"
)

// seedEntityID returns a deterministic, unique entity ID for the i-th seeded
// entity (distinct keys spread across the shards via routeShard's maphash).
func seedEntityID(i int) string { return "pointget-entity-" + strconv.Itoa(i) }

// canonicalDotSet renders a []CRDTEntry as a sorted set of "nodeIDhex:counter"
// strings so two reads of the same entity compare order-insensitively (the
// "same dot set" property, independent of internal leaf ordering).
func canonicalDotSet(entries []CRDTEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, hex.EncodeToString(e.DotNodeID[:])+":"+strconv.FormatUint(e.DotCounter, 10))
	}
	slices.Sort(out)
	return out
}

// State constructs a merged HAMT, and its path copies can grow the arena
// high-water mark. The first test measures that growth as a negative control.
// The second requires repeated PointGet calls, including misses, to leave the
// same mark unchanged. The third compares PointGet and State().Get dot sets for
// single- and multi-dot entities and checks an absent key.

// TestPointGet_StateLeakNegativeControl seeds 512 entities, warms the arena
// free lists, and requires further State calls to increase the high-water
// mark. That growth demonstrates that the gauge used by the PointGet test can
// detect arena consumption.
func TestPointGet_StateLeakNegativeControl(t *testing.T) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, 256*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	// Seed enough entities that one State() rebuild's path-copy leak is a
	// clearly measurable number of arena allocations.
	const seedN = 512
	for i := 0; i < seedN; i++ {
		engine.InsertLocal(seedEntityID(i), CRDTEntry{H3Index: uint64(i)})
	}

	// Prime the free lists so the measured growth comes from State's path copies
	// rather than first-touch allocation.
	const warmup = 16
	for i := 0; i < warmup; i++ {
		_ = engine.State()
	}

	hw0 := engine.Arena().HighWater()
	const leakCalls = 64
	for i := 0; i < leakCalls; i++ {
		_ = engine.State()
	}
	hw1 := engine.Arena().HighWater()

	growth := hw1 - hw0
	t.Logf("State allocation control: %d calls over %d entities grew the arena high-water from %d to %d bytes (+%d, approximately %d bytes/call)",
		leakCalls, seedN, hw0, hw1, growth, growth/leakCalls)
	if growth == 0 {
		t.Fatalf("State() left the arena high-water unchanged across %d calls; the negative control cannot validate PointGet's no-growth assertion", leakCalls)
	}
}

// TestPointGet_ArenaStaysFlat performs 20,000 hit-and-miss pairs after warming
// the participant pool. PointGet copies results to the Go heap, so none of these
// reads may advance the arena high-water mark.
func TestPointGet_ArenaStaysFlat(t *testing.T) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, 256*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	const seedN = 512
	for i := 0; i < seedN; i++ {
		engine.InsertLocal(seedEntityID(i), CRDTEntry{H3Index: uint64(i)})
	}

	// Prime the EBR participant pool before measuring steady-state reads.
	for i := 0; i < 16; i++ {
		_ = engine.PointGet(seedEntityID(i % seedN))
	}

	hw0 := engine.Arena().HighWater()
	const reads = 20000
	for i := 0; i < reads; i++ {
		_ = engine.PointGet(seedEntityID(i % seedN))                 // rotate across all shards
		_ = engine.PointGet("pointget-absent-" + strconv.Itoa(i%64)) // absent keys too
	}
	hw1 := engine.Arena().HighWater()

	if hw1 != hw0 {
		t.Fatalf("%d PointGet reads grew the arena high-water from %d to %d bytes (+%d); point reads must not allocate arena storage", 2*reads, hw0, hw1, hw1-hw0)
	}
	t.Logf("PointGet flat: %d reads over %d entities left the arena high-water exactly flat at %d bytes", 2*reads, seedN, hw1)
}

// TestPointGet_MatchesStateGet compares sorted dot sets for every seeded
// entity. Multiple dots per entity ensure the comparison covers complete entry
// slices, while an absent key must return no entries from either read path.
func TestPointGet_MatchesStateGet(t *testing.T) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, 256*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	// Seed 256 entities with one to three dots each so complete dot sets are
	// compared rather than only the first entry.
	const seedN = 256
	for i := 0; i < seedN; i++ {
		dots := (i % 3) + 1
		for d := 0; d < dots; d++ {
			engine.InsertLocal(seedEntityID(i), CRDTEntry{H3Index: uint64(i*8 + d)})
		}
	}

	// One merged-view snapshot is valid for the whole (mutation-free) comparison.
	merged := engine.State()
	for i := 0; i < seedN; i++ {
		key := seedEntityID(i)
		got := canonicalDotSet(engine.PointGet(key))
		want := canonicalDotSet(merged.Get(key))
		if !slices.Equal(got, want) {
			t.Fatalf("PointGet(%q) dot set != State().Get: got %v, want %v", key, got, want)
		}
	}
	// Absent key: both must report empty.
	if got := engine.PointGet("pointget-never-written"); len(got) != 0 {
		t.Fatalf("PointGet(absent) returned %d entries, want 0", len(got))
	}
}
