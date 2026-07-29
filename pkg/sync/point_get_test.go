// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

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

// ═══════════════════════════════════════════════════════════════════════════
// (register) — the production read-path OOM.
//
// ROOT CAUSE (physics, one sentence): engine.State() (crdt.go:1457) rebuilds the
// FULL merged HAMT on EVERY call, and Set's functional path-copying (hamt.go:199)
// allocates O(log N) new path nodes + a wrapper per Set while NEVER retiring the
// intermediate roots — the retired view's DecRef frees only the subtree reachable
// from the FINAL root — so each State() call leaks O(N·log N) arena bytes
// MONOTONICALLY, independent of the EBR grace window, until the 64 MiB arena OOMs
// as an allocation PANIC (the /verify crash-harness hit it at ~2000 sequential
// /v1/gets).
//
// THE FIX: a per-shard point-Get — PointGet (point_get.go) — that reads ONLY the
// one shard the entityID routes to (routeShard is deterministic, crdt.go:561), a
// pure O(log N) read that allocates NOTHING in the arena. The production
// point-reads (handleGet control.go:532, engineHAMTAdapter.LiveRead main.go:2535,
// LatestPayload gossip.go:1166) are routed to it. State() is frozen and untouched.
//
// THE GUARDS:
// T1 TestPointGet_StateLeakNegativeControl — the DEFECT PROOF + negative control.
// State()-in-a-loop GROWS the arena high-water. It PASSES on the leaking tree
// (State is frozen, so it still leaks post-fix) and its positive growth PROVES
// the detector works — so T2's "flat" assertion is not vacuous.
// T2 TestPointGet_ArenaStaysFlat — the FIX guard: N PointGet calls leave the arena
// high-water EXACTLY flat (a pure read allocates nothing in the arena).
// T3 TestPointGet_MatchesStateGet — correctness: PointGet(k) returns the SAME dot
// set as State().Get(k) for every seeded entity (routeShard determinism means
// all of an entity's entries live in ONE shard). Bug-injection-proven: routing
// PointGet at the WRONG shard makes this guard FAIL.
// ═══════════════════════════════════════════════════════════════════════════

// T1 — the RED / defect proof. Seeds N entities, warms the arena free-lists to
// steady state, then asserts the high-water GROWS across further State() calls.
// This is the $0 falsification of on the leaking tree the growth is
// strictly positive. It remains as the permanent negative control for T2.
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

	// Warm the arena free-lists to steady state so the growth we then measure
	// is the per-call LEAK, not first-touch free-list priming.
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
	t.Logf(" leak probe: %d State() calls over %d entities grew arena high-water %d -> %d (+%d bytes, ~%d bytes/call)",
		leakCalls, seedN, hw0, hw1, growth, growth/leakCalls)
	if growth == 0 {
		t.Fatalf(" NOT reproduced: State() left the arena high-water FLAT across %d calls — the O(N·log N)-per-call leak is absent, so this negative control cannot validate the T2 fix guard", leakCalls)
	}
}

// T2 — the FIX guard. N PointGet calls must leave the arena high-water EXACTLY
// flat: PointGet is a pure read (HAMT.Get path-copies NOTHING) and copies the
// result to caller-owned Go heap, so it allocates ZERO arena bytes. The negative
// control is T1 (State() grows the same gauge), which proves this "flat"
// assertion is a real leak detector, not a tautology.
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

	// Warm up (prime the EBR participant pool) so we measure steady-state reads.
	for i := 0; i < 16; i++ {
		_ = engine.PointGet(seedEntityID(i % seedN))
	}

	hw0 := engine.Arena().HighWater()
	const reads = 20000
	for i := 0; i < reads; i++ {
		_ = engine.PointGet(seedEntityID(i % seedN))                 // rotate across ALL shards
		_ = engine.PointGet("pointget-absent-" + strconv.Itoa(i%64)) // absent keys too
	}
	hw1 := engine.Arena().HighWater()

	if hw1 != hw0 {
		t.Fatalf(" regression: %d PointGet reads grew the arena high-water %d -> %d (+%d bytes); a pure read must allocate ZERO arena bytes", 2*reads, hw0, hw1, hw1-hw0)
	}
	t.Logf("PointGet flat: %d reads over %d entities left the arena high-water EXACTLY flat at %d bytes", 2*reads, seedN, hw1)
}

// T3 — CORRECTNESS. For every seeded entity (some carrying multiple dots),
// PointGet(k) must return the SAME dot set as State().Get(k): routeShard is
// deterministic, so all of an entity's entries live in ONE shard and the
// single-shard read equals the merged-view read. Bug-injection proof: route
// PointGet at the WRONG shard (routeShard+1) and this guard FAILS.
func TestPointGet_MatchesStateGet(t *testing.T) {
	engine, err := NewDeltaCRDTEngine([16]byte{1}, 0, 256*1024*1024)
	if err != nil {
		t.Fatalf("NewDeltaCRDTEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	// Seed 256 entities; entity i carries (i%3)+1 dots so multi-dot entities are
	// exercised (the dot SET, not a single dot, must match).
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
