// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package sync

import (
	"crypto/sha256"
	"sort"
)

// MerkleRootFromShards computes the convergence root directly from the shard
// HAMTs. It collects each entry's (DotNodeID, DotCounter) pair, then uses the
// same global ordering and SHA-256 encoding as HAMT.MerkleRoot. Unlike State,
// it does not construct a merged HAMT or allocate arena nodes.
//
// Each entity belongs to exactly one shard because routeShard depends only on
// its entity ID. The union of the shard entries therefore equals the merged
// view's entries. Sorting all pairs by node ID and counter makes the hash
// independent of shard boundaries, so both paths return identical roots.
//
// State remains available to callers that need the merged view, including the
// chaos partition probe and small live-set tests. Callers that need only the
// root can avoid the merged view's arena growth without changing the root
// format or the convergence comparison.
//
// An EBR participant pin protects every shard root for the duration of the
// walk. A concurrent InsertLocal or Join may retire a root, but reclamation
// cannot free it until the pin is released. Participants come from
// participantPool, so the pin does not allocate in steady state.
//
// The collected pairs occupy 24 bytes each on the Go heap, approximately
// 240 KB for 10,000 entries. The capacity hint sums HAMT.Len across the shards;
// it counts entities rather than dots and is only a lower bound. This method
// is used by convergence and checkpoint paths, not the zero-allocation write
// path covered by TestHotPathZeroAllocations.
//
// Hashing a tree of shard roots could avoid the global sort, but it would
// define a different root format. This implementation preserves compatibility
// with State().MerkleRoot.

// shardDotPair holds the two dot fields used by HAMT.MerkleRoot. Encoding the
// node ID followed by the counter produces the same 24-byte hash input.
type shardDotPair struct {
	nodeID  [16]byte
	counter uint64
}

// hashShardDotPairs applies HAMT.MerkleRoot's ordering and encoding. Both
// MerkleRootFromShards and CaptureShardsPinned use it so identical pair sets
// produce identical roots.
func hashShardDotPairs(pairs []shardDotPair) [32]byte {
	// Match HAMT.MerkleRoot: node ID bytes first, then counter.
	sort.Slice(pairs, func(i, j int) bool {
		for b := 0; b < 16; b++ {
			if pairs[i].nodeID[b] != pairs[j].nodeID[b] {
				return pairs[i].nodeID[b] < pairs[j].nodeID[b]
			}
		}
		return pairs[i].counter < pairs[j].counter
	})

	// Hash each node ID followed by its big-endian counter. The empty set returns
	// the zero array, matching HAMT.MerkleRoot.
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

// MerkleRootFromShards returns the same root as State().MerkleRoot without
// building State's merged view. An EBR participant pin protects the shard roots
// against reclamation during concurrent InsertLocal and Join calls. The method
// allocates a Go-heap slice but no arena nodes.
func (e *DeltaCRDTEngine) MerkleRootFromShards() [32]byte {
	// Enter before loading shard roots. A concurrent compare-and-swap may retire
	// a root during ForEach, but deferred Exit keeps it allocated until the walk
	// and collection are complete.
	participant := e.participantPool.Get().(*Participant)
	participant.Enter(e.ebr)
	defer func() {
		participant.Exit()
		e.participantPool.Put(participant)
	}()

	// HAMT.Len counts entity IDs, so its sum is a lower bound when entities hold
	// multiple dots. It is only a capacity hint and does not affect the hash.
	hint := 0
	for si := range e.shards {
		if r := e.shards[si].ptr.Load(); r != nil {
			hint += r.Len()
		}
	}
	pairs := make([]shardDotPair, 0, hint)

	// ForEach yields arena-backed entry slices. Copy only the two dot fields into
	// the Go-heap pairs; no arena node is created.
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

// CaptureShardsPinned walks each shard once without building a merged view or
// allocating arena nodes (ADR-0045 §7). It returns the Merkle root and the
// greatest DotCounter belonging to e.localNodeID in the walked view. The local
// watermark is therefore derived from visible state rather than LamportCounter,
// which can include minted dots that are not yet visible.
//
// The caller must hold an EBR participant pin throughout the walk and for as
// long as it retains yielded entity IDs or entry slices. Those values are
// arena-backed views, not copies. AppendCheckpoint keeps its pin through the
// WAL append and image write, so this method does not acquire a shorter pin of
// its own.
//
// If fn is nil, only the root and watermark are computed. A false return from
// fn stops the walk as in HAMT.ForEach; callers that stop early must discard
// the root and watermark because they describe only a partial view.
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
