// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package sync

// ═══════════════════════════════════════════════════════════════════════════
// The per-shard point-Get that retires the
// production read-path OOM. This is a NEW file: crdt.go is frozen (byte-pinned)
// and is NOT edited. State() is NOT redesigned — the fix
// is this point-Get plus the re-routing of the three production point-reads to
// it (blast-radius containment).
//
// THE DEFECT, in one sentence of physics: State() (crdt.go:1457)
// rebuilds the FULL merged HAMT on every call, and Set's functional
// path-copying (hamt.go:199) allocates O(log N) new path nodes + a wrapper per
// Set while NEVER retiring the intermediate roots (the retired view's DecRef
// frees only the subtree reachable from the FINAL root), so each State() call
// leaks O(N·log N) arena bytes MONOTONICALLY, independent of the EBR grace
// window — a sustained read loop grows the arena until the 64 MiB arena OOMs as
// an allocation PANIC (measured ~541 KB/call over 512
// entities; the /verify crash-harness OOM'd at ~2000 sequential /v1/gets).
//
// THE FIX SHAPE: a point-Get is O(log N) and allocates NOTHING in the arena.
// routeShard (crdt.go:561) is a deterministic pure function of (entityID,
// routeSeed), so ALL of an entity's entries live in exactly ONE shard — reading
// that single shard's HAMT returns the SAME dot set State().Get(entityID) would
// (semantics preserved), without materializing the other N-1 shards. The read
// is the InsertLocal hot path's own access pattern (crdt.go:1042-1043) run in
// reverse: load the shard's atomic.Pointer[HAMT] root, walk it (HAMT.Get,
// hamt.go:170, path-copies NOTHING), copy the one entity's entries out.
// ═══════════════════════════════════════════════════════════════════════════

// PointGet returns the live δ-CRDT entries for a single entityID — the O(log N)
// read-path replacement for the O(total-entries) engine.State().Get(entityID).
//
// RETURN CONTRACT: the returned slice is CALLER-OWNED Go-heap memory, safe to
// hold and dereference after PointGet returns. It is NOT the arena-backed view HAMT.Get returns
// (crdtEntries, hamt.go:107-112 — an unsafe.Slice into the mmap arena). That
// view dangles the instant the read pin is Released: a concurrent InsertLocal
// CAS can publish a new shard root, and after the 3-epoch EBR grace the arena
// reclaims AND REUSES the leaf's bytes. PointGet therefore copies the entity's
// entries OUT under the pin before Release. CRDTEntry is a 120-byte value type
// (no pointers, hamt.go:29-40), so the copy is a pure memcpy of the entity's k
// dots — O(k), GC-reclaimed, off the write hot path, and categorically NOT the
// O(N·log N) monotonic State() leak (which is arena-bytes-lost-forever, not a
// bounded per-call heap value). A nil return means the entity has no live
// entries (the same "absent" signal State().Get gives selectLatestDot).
//
// CONCURRENCY: PointGet takes its OWN EBR read pin
// (Acquire → Enter → read+copy → Release), so it is safe for an UNPINNED caller
// (handleGet, control.go:532) AND benign-nested under a caller that already
// holds one (engineHAMTAdapter.LiveRead, main.go:2530-2533). Nesting is safe
// because EBRManager.Acquire returns a DISTINCT Participant from the pool
// (reclamation.go:97-99) and reclamation holds back frees until the MINIMUM
// epoch across ALL active participants (Participant.Enter/Exit,
// reclamation.go:133-143) — the inner pin's Release drops only its own hold,
// never the outer's. The pin is what makes the shard-root Load + Get safe
// against a concurrent CAS retiring the old root mid-read.
//
// TEARDOWN CONTRACT: like the existing read path (State, LiveRead), PointGet
// does NOT guard the post-Close window — callers must not read after
// engine.Close() (the arena is torn down). This matches the established
// read-path contract exactly; changing it is out of blast radius.
func (e *DeltaCRDTEngine) PointGet(entityID string) []CRDTEntry {
	p := e.ebr.Acquire()
	p.Enter(e.ebr)
	defer e.ebr.Release(p)

	if len(e.shards) == 0 {
		return nil
	}
	shard := e.shards[e.routeShard(entityID)].ptr.Load()
	if shard == nil {
		return nil
	}
	entries := shard.Get(entityID) // arena-backed view — valid ONLY under the pin
	if len(entries) == 0 {
		return nil
	}
	out := make([]CRDTEntry, len(entries))
	copy(out, entries) // copy OUT under the pin; the caller owns `out`
	return out
}
