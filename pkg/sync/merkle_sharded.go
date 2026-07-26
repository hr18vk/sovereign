// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package sync

import (
	"crypto/sha256"
	"sort"
)

// This file is the convergence-root sharded-direct path.
//
// MerkleRootFromShards computes the engine's Merkle root by collecting the
// (DotNodeID, DotCounter) dot pairs DIRECTLY from every shard's root HAMT
// and sorting+hashing them with the EXACT same algorithm HAMT.MerkleRoot
// (hamt.go:265) uses. It does NOT build the merged *HAMT view that State()
// (crdt.go:1348) builds — so it allocates ZERO arena nodes. This closes the
// arena-exhaustion root cause: stampConvergence() (gossip.go) called
// State().MerkleRoot() every sweep, and State() duplicated every live entry
// into a fresh merged HAMT whose arena nodes pile up inside the EBR grace
// window (3 epochs = 192 ops) faster than maybeAdvanceEpoch reclaims them —
// at 100 nodes × 10K keys that is the hamt_arena.go:638 "arena exhausted
// (variable alloc)" OOM. MerkleRootFromShards reads the shard roots that
// ALREADY exist (the per-shard atomic.Pointer[HAMT] the engine maintains) and
// touches only the Go heap (one slice of 24-byte dot pairs), so the arena's
// high-water mark (bumpOffset) does not move at all.
//
// BYTE-IDENTITY: the 256 shards are DISJOINT by entityID (routeShard is a
// pure function of entityID; Join partitions incoming blocks by it). State()
// stitches every shard's entries into one merged HAMT via merged.Set — a
// verbatim byte-copy — so the merged HAMT's (entityID→entries) multiset equals
// the union of the shards' multisets. HAMT.MerkleRoot (hamt.go:265) collects
// EVERY entry's (DotNodeID, DotCounter) pair, sorts globally by (nodeID bytes
// ASC, counter ASC), and SHA-256-hashes each 24-byte big-endian pair
// sequentially. Collecting the same pairs directly from the shards yields the
// SAME multiset → the SAME global sort → the SAME hash. QED by construction.
// This was EMPIRICALLY CONFIRMED by merkle_sharded_test.go on both
// 1-entry/entityID and multi-entry/entityID seeded engines: byte-identical
// roots.
//
// Because the root is byte-identical to State().MerkleRoot(), the silicon
// check (/v1/merkle) and any caller that switches to this method produce the
// SAME root under BOTH paths — NO migration, NO root-format change, NO "old
// root vs new root" ambiguity. The convergence proof (same root on convergent
// nodes) is UNCHANGED. State() is NOT deleted: it stays for the chaos probe
// (internal/chaos/partition.go MerkleRoots), the WAL checkpoint test, and the
// loopback check's MerkleRoots() which need the merged view for SMALL live
// sets (the documented State() boundary). The 100×10K path is the ONLY
// path that OOMs, and it now uses this sharded-direct path.
//
// RACE SAFETY (the upgrade over State()): State() takes NO EBR participant
// pin — it relies on the 3-epoch grace window being much larger than the
// synchronous ForEach+copy duration to make a use-after-free astronomically
// unlikely. MerkleRootFromShards instead takes an EBR participant pin
// (mirroring GenerateDelta, GenerateDigestWithSeed, and
// GenerateStrataEstimator): Enter BEFORE loading the shard
// roots, Exit (deferred) after the ForEach+collect completes. The pin holds
// freeRetiredList back for the whole call, so a concurrent InsertLocal/Join
// CAS that retires a shard root mid-ForEach CANNOT free it until the pin
// Exits. This is FORMALLY race-free (not merely grace-window-safe), strictly
// stronger than State(). The pin is off the hot path (one Enter/Exit per
// sweep, the same single-writer SweepLoop discipline stampConvergence already
// runs under), and the participant is recycled through participantPool — zero
// steady-state allocation.
//
// ALLOCATION HONESTY: the only allocation is a single Go-heap slice of dot
// pairs (24 bytes each). At 10K entries that is ~240KB on the Go heap,
// reclaimed by the GC. This is OFF the hot path (the hot path is
// Join/InsertLocal/GenerateDelta, NOT stampConvergence) so the 0-allocs/op
// hot-path invariant (TestHotPathZeroAllocations) is UNAFFECTED. The Go-heap
// alloc is the honest cost of NOT building the merged arena view (which was
// OOM-ing). 240KB on the Go heap is trivial; the merged arena view was
// duplicating 10K entries × arena node size into the mmap arena with NO
// synchronous reclaim. The capacity hint sums per-shard HAMT.Len() (entityID
// count, a lower bound on the entry count) to reduce slice growth reallocs;
// exact capacity is irrelevant to the hash.
//
// FUTURE WORK (an alternative, NOT shipped here): for 1M+ keys a per-shard
// root + concat (a Merkle tree of shard roots) would hash in O(shards) per-
// shard hashes with NO global sort. That root is DIFFERENT but EQUALLY
// DETERMINISTIC, and cheaper. This file ships the byte-identical root (the
// honest closure) and leaves the sharded-root-tree variant as deferred work.

// shardDotPair is the per-entry (DotNodeID, DotCounter) pair collected for
// the global sort+hash. It is the byte-identical twin of the unexported
// dotPair inside HAMT.MerkleRoot (hamt.go:266): same fields, same 24-byte
// big-endian hash layout, so the two paths produce byte-identical roots.
type shardDotPair struct {
	nodeID  [16]byte
	counter uint64
}

// hashShardDotPairs is the verbatim sort+hash tail of HAMT.MerkleRoot
// (hamt.go:282-311), extracted so MerkleRootFromShards AND the
// checkpoint capture (CaptureShardsPinned) share ONE implementation: the same
// multiset + the same comparator ⇒ the same sorted sequence ⇒ the same hash
// (byte-identity with State().MerkleRoot(), as documented above).
func hashShardDotPairs(pairs []shardDotPair) [32]byte {
	// Verbatim sort from HAMT.MerkleRoot (hamt.go:282-289): nodeID bytes ASC,
	// then counter ASC.
	sort.Slice(pairs, func(i, j int) bool {
		for b := 0; b < 16; b++ {
			if pairs[i].nodeID[b] != pairs[j].nodeID[b] {
				return pairs[i].nodeID[b] < pairs[j].nodeID[b]
			}
		}
		return pairs[i].counter < pairs[j].counter
	})

	// Verbatim hash loop from HAMT.MerkleRoot (hamt.go:291-311): each pair
	// serialized as 16-byte nodeID || 8-byte big-endian counter, written
	// sequentially into one SHA-256. Empty multiset → zero [32]byte (matches
	// HAMT.MerkleRoot's empty-path return).
	var buf [24]byte
	var result [32]byte
	if len(pairs) == 0 {
		return result
	}
	h256 := sha256.New()
	for _, p := range pairs {
		copy(buf[:16], p.nodeID[:])
		buf[16] = byte(p.counter >> 56)
		buf[17] = byte(p.counter >> 48)
		buf[18] = byte(p.counter >> 40)
		buf[19] = byte(p.counter >> 32)
		buf[20] = byte(p.counter >> 24)
		buf[21] = byte(p.counter >> 16)
		buf[22] = byte(p.counter >> 8)
		buf[23] = byte(p.counter)
		h256.Write(buf[:])
	}
	copy(result[:], h256.Sum(nil))
	return result
}

// MerkleRootFromShards returns the engine's current Merkle root computed
// directly from the per-shard root HAMTs WITHOUT building the merged view
// State() builds. Byte-identical to State().MerkleRoot() (see the file
// doc). Race-free under concurrent InsertLocal/Join via the EBR participant
// pin (see the file doc). Off the hot path; zero arena growth.
func (e *DeltaCRDTEngine) MerkleRootFromShards() [32]byte {
	// EBR pin: Enter before loading shard roots so a concurrent CAS that
	// retires+freelist-reclaims a shard root mid-ForEach cannot free it
	// until the deferred Exit. Mirrors GenerateDelta/GenerateDigestWithSeed.
	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	defer func() {
		participant.Exit()
		e.participantPool.Put(participant)
	}()

	// Capacity hint: sum of per-shard HAMT.Len() (entityID count). This is a
	// LOWER bound on the entry count (each entityID may carry >1 dot); exact
	// capacity does not affect the hash, only the number of slice reallocs.
	hint := 0
	for si := range e.shards {
		if r := e.shards[si].ptr.Load(); r != nil {
			hint += r.Len()
		}
	}
	pairs := make([]shardDotPair, 0, hint)

	// Collect every entry's (DotNodeID, DotCounter) directly from the shard
	// roots. ForEach yields the arena-backed entry slice per leaf; we read
	// only the two dot fields (24 bytes), never copying into an arena node.
	for si := range e.shards {
		shardRoot := e.shards[si].ptr.Load()
		if shardRoot == nil {
			continue
		}
		shardRoot.ForEach(func(_ string, entries []CRDTEntry) bool {
			for i := range entries {
				pairs = append(pairs, shardDotPair{
					nodeID:  entries[i].DotNodeID,
					counter: entries[i].DotCounter,
				})
			}
			return true
		})
	}

	return hashShardDotPairs(pairs)
}

// CaptureShardsPinned is the checkpoint capture (ADR-0045):
// it walks every shard's root HAMT EXACTLY ONCE — no merged view, zero arena
// allocation — invoking fn(entityID, entries) per entity, and derives from
// THAT SAME WALK both outputs a checkpoint needs:
//
//	root — the Merkle root, byte-identical to State().MerkleRoot()
//
// (same multiset + same sort + same hash; the file-doc proof).
//
//	maxLocalDot — the max DotCounter among entries whose DotNodeID ==
//
// e.localNodeID observed IN THE WALKED VIEW. A checkpoint
// watermark derived this way can never sit ABOVE the image:
// every local dot ≤ maxLocalDot that the WAL durably holds is
// a dot the walk could have seen; LamportCounter() (a mint
// high-water, not a visibility high-water) has no such
// property — that gap was the checkpoint skew source.
//
// PIN CONTRACT (ADR-0045): the caller MUST hold an EBR participant
// pin (EBR().Acquire + Enter) for the whole call AND for as long as any
// yielded data is retained — the entityID strings and entries slices are
// ARENA-BACKED views of the live shards, not copies. AppendCheckpoint holds
// the pin across the walk, the WAL append, and the entire image write. This
// function deliberately does NOT take its own pin: the pin's span is the
// caller's checkpoint, not the walk.
//
// fn may be nil (root + watermark only). fn's bool return mirrors
// HAMT.ForEach: false stops the walk early (the root/watermark of a PARTIAL
// walk are meaningless — early-stop callers must discard them).
func (e *DeltaCRDTEngine) CaptureShardsPinned(fn func(entityID string, entries []CRDTEntry) bool) (root [32]byte, maxLocalDot uint64) {
	hint := 0
	for si := range e.shards {
		if r := e.shards[si].ptr.Load(); r != nil {
			hint += r.Len()
		}
	}
	pairs := make([]shardDotPair, 0, hint)
	stopped := false
	for si := range e.shards {
		if stopped {
			break
		}
		shardRoot := e.shards[si].ptr.Load()
		if shardRoot == nil {
			continue
		}
		shardRoot.ForEach(func(entityID string, entries []CRDTEntry) bool {
			for i := range entries {
				pairs = append(pairs, shardDotPair{
					nodeID:  entries[i].DotNodeID,
					counter: entries[i].DotCounter,
				})
				if entries[i].DotNodeID == e.localNodeID && entries[i].DotCounter > maxLocalDot {
					maxLocalDot = entries[i].DotCounter
				}
			}
			if fn != nil && !fn(entityID, entries) {
				stopped = true
				return false
			}
			return true
		})
	}
	return hashShardDotPairs(pairs), maxLocalDot
}
