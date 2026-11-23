// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

// Point reads use the shard selected by routeShard instead of constructing
// State's merged HAMT. Building that view path-copies every entity into new
// arena nodes, and intermediate roots are not retired. Repeated State calls
// can therefore exhaust the arena even though each individual view is later
// released.
//
// All entries for an entity reside in one shard. Reading that HAMT returns the
// same dot set as State().Get without allocating arena nodes; only the returned
// entries are copied to the Go heap.

// PointGet returns the live δ-CRDT entries for entityID. It reads one shard in
// O(log N) time and copies the entity's k entries in O(k) time without
// allocating arena nodes. A nil result means the entity has no live entries.
//
// The returned slice belongs to the caller. HAMT.Get instead returns an
// arena-backed view that reclamation may reuse after the read pin is released,
// so PointGet copies the values before releasing its pin. CRDTEntry contains
// no pointers, making the copy independent of the arena.
//
// Each call acquires a distinct EBR participant. Nested read pins are safe:
// releasing the inner participant does not release an outer caller's pin. The
// pin also prevents a concurrent InsertLocal or Join from freeing the shard
// root during the read.
//
// As with State and LiveRead, callers must not use PointGet after engine.Close
// has torn down the arena.
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
	entries := shard.Get(entityID) // arena-backed view, valid only under the pin
	if len(entries) == 0 {
		return nil
	}
	out := make([]CRDTEntry, len(entries))
	copy(out, entries) // copy under the pin; the caller owns out
	return out
}
