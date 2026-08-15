// Package database implements the Epoch-Based Tombstone Garbage Collector
// for CRDT pruning (ADR 7).
//
// ADR 7 MANDATE: Over a 100-year temporal ledger lifecycle, tombstones
// and vector clock metadata from OR-Set CRDTs create geometric memory
// bloat. If left unchecked, this metadata exceeds physical RAM limits
// of edge devices. The compactor prunes causally stable tombstones
// during LSM L0 compaction, collapsing space complexity from O(n) to
// O(|active|) — bounded by current active state, not historical trajectory.
package database

import (
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// ADR 7 Constants
// ---------------------------------------------------------------------------

const (
	// DefaultEpochDurationSec is the global epoch bump interval.
	// ADR 7: "The network periodically bumps Epoch E_new."
	// 60 seconds provides a balance between pruning frequency and
	// network convergence time for causal stability.
	DefaultEpochDurationSec = 60

	// DefaultStabilityLag is the number of epochs a tombstone must
	// survive past the globally stabilized watermark before pruning.
	// ADR 7: "Once all threads and remote peers safely clear Epoch E_old,
	// the tombstones inextricably linked to E_old are safely and
	// permanently deleted."
	// A lag of 2 ensures no in-flight delta references a pruned tombstone.
	DefaultStabilityLag uint64 = 2
)

// ---------------------------------------------------------------------------
// TombstoneRecord — A single CRDT deletion marker
// ---------------------------------------------------------------------------

// TombstoneRecord represents a tombstone entry in the CRDT lattice.
// ADR 7: "When a civic record is modified or deleted, the CRDT generates
// a tombstone to permanently record the deletion, ensuring the action
// propagates to all disconnected peers."
//
// Fields are value types — no pointers, no heap escape on the hot path.
type TombstoneRecord struct {
	// EntityID is the identifier of the deleted entity.
	EntityID string

	// Epoch is the epoch number when this tombstone was created.
	// ADR 7: "A peer acquires an entry for a transaction in Epoch E_old."
	Epoch uint64

	// NodeID identifies the originating peer.
	NodeID [16]byte

	// Counter is the Lamport counter at tombstone creation time.
	Counter uint64

	// Timestamp is the wall-clock nanosecond timestamp for TTL enforcement.
	Timestamp int64
}

// ---------------------------------------------------------------------------
// EpochCompactor — ADR 7 Tombstone Garbage Collector
// ---------------------------------------------------------------------------

// EpochCompactor implements Epoch-Based Garbage Collection for CRDT tombstones.
//
// ADR 7 Protocol:
//  1. Active epoch increments globally every DefaultEpochDurationSec
//  2. Peers report their minimum observed epoch via AdvancePeerEpoch
//  3. The global stable epoch = min(all peer epochs)
//  4. Tombstones with epoch <= (stableEpoch - stabilityLag) are pruned
//
// Concurrency model:
//   - currentEpoch: monotonically increasing via atomic.Uint64
//   - peerEpochs: protected by sync.RWMutex (low-frequency updates)
//   - tombstones: protected by sync.Mutex (append-heavy, batch-pruned)
//
// Space complexity after pruning: O(|active|) instead of O(n).
type EpochCompactor struct {
	currentEpoch atomic.Uint64
	stabilityLag uint64

	// peerEpochs tracks the minimum epoch each peer has acknowledged.
	// Key: peer node ID as [16]byte → value: latest epoch they've cleared.
	peerMu     sync.RWMutex
	peerEpochs map[[16]byte]uint64

	// tombstones is the append-only tombstone log, batch-pruned during compaction.
	tombMu     sync.Mutex
	tombstones []TombstoneRecord

	// Metrics
	totalPruned   atomic.Uint64
	totalInserted atomic.Uint64
	lastPruneTime atomic.Int64
}

// NewEpochCompactor creates a new compactor starting at epoch 0.
func NewEpochCompactor(stabilityLag uint64) *EpochCompactor {
	if stabilityLag == 0 {
		stabilityLag = DefaultStabilityLag
	}
	return &EpochCompactor{
		stabilityLag: stabilityLag,
		peerEpochs:   make(map[[16]byte]uint64),
		tombstones:   make([]TombstoneRecord, 0, 1024),
	}
}

// CurrentEpoch returns the current global epoch.
func (c *EpochCompactor) CurrentEpoch() uint64 {
	return c.currentEpoch.Load()
}

// BumpEpoch atomically advances the global epoch.
// ADR 7: "The network periodically bumps Epoch E_new."
// Returns the new epoch value.
func (c *EpochCompactor) BumpEpoch() uint64 {
	return c.currentEpoch.Add(1)
}

// AdvancePeerEpoch updates the acknowledged epoch for a specific peer.
// ADR 7: "Once the global matrix confirms the unanimous receipt of a
// specific vector clock threshold, the local replica executes an
// irreversible pruning sequence."
func (c *EpochCompactor) AdvancePeerEpoch(nodeID [16]byte, epoch uint64) {
	c.peerMu.Lock()
	current, exists := c.peerEpochs[nodeID]
	if !exists || epoch > current {
		c.peerEpochs[nodeID] = epoch
	}
	c.peerMu.Unlock()
}

// StableEpoch computes the globally stable epoch: min(all peer epochs).
// ADR 7: "Causal Stabilization defines a strict point in time where no
// concurrent operations are physically possible."
//
// If no peers are registered, returns 0 (nothing is stable yet).
func (c *EpochCompactor) StableEpoch() uint64 {
	c.peerMu.RLock()
	defer c.peerMu.RUnlock()

	if len(c.peerEpochs) == 0 {
		return 0
	}

	var minEpoch uint64 = ^uint64(0)
	for _, e := range c.peerEpochs {
		if e < minEpoch {
			minEpoch = e
		}
	}
	return minEpoch
}

// InsertTombstone records a new deletion tombstone in the current epoch.
// ADR 7: "A peer acquires an entry for a transaction in Epoch E_old."
func (c *EpochCompactor) InsertTombstone(entityID string, nodeID [16]byte, counter uint64) {
	record := TombstoneRecord{
		EntityID:  entityID,
		Epoch:     c.currentEpoch.Load(),
		NodeID:    nodeID,
		Counter:   counter,
		Timestamp: time.Now().UnixNano(),
	}

	c.tombMu.Lock()
	c.tombstones = append(c.tombstones, record)
	c.tombMu.Unlock()

	c.totalInserted.Add(1)
}

// PruneTombstones executes the epoch-based garbage collection sweep.
//
// ADR 7: "Once all threads and remote peers safely clear Epoch E_old,
// the tombstones inextricably linked to E_old are safely and permanently
// deleted."
//
// Returns the number of tombstones pruned and the remaining count.
//
// CRITICAL: This method is designed to be called during the LSM MemTable
// L0 compaction flush, keeping active memory fast and lock-free.
// ADR 7: "The actual physical excision of tombstones is delayed and
// executed during the LSM MemTable L0 compaction flush."
func (c *EpochCompactor) PruneTombstones() (pruned map[string]struct{}, remaining int) {
	stableEpoch := c.StableEpoch()
	pruned = make(map[string]struct{})

	// Nothing to prune if stable epoch hasn't advanced past the lag
	if stableEpoch < c.stabilityLag {
		c.tombMu.Lock()
		remaining = len(c.tombstones)
		c.tombMu.Unlock()
		return pruned, remaining
	}

	pruneThreshold := stableEpoch - c.stabilityLag

	c.tombMu.Lock()

	// In-place filter: keep tombstones with epoch > pruneThreshold
	writeIdx := 0
	for readIdx := range c.tombstones {
		if c.tombstones[readIdx].Epoch > pruneThreshold {
			if writeIdx != readIdx {
				c.tombstones[writeIdx] = c.tombstones[readIdx]
			}
			writeIdx++
		} else {
			// Mark as pruned
			pruned[c.tombstones[readIdx].EntityID] = struct{}{}
		}
	}

	prunedCount := len(c.tombstones) - writeIdx
	c.tombstones = c.tombstones[:writeIdx]
	remaining = writeIdx

	c.tombMu.Unlock()

	if prunedCount > 0 {
		c.totalPruned.Add(uint64(prunedCount))
		c.lastPruneTime.Store(time.Now().UnixNano())
	}

	return pruned, remaining
}

// TombstoneCount returns the current number of pending tombstones.
func (c *EpochCompactor) TombstoneCount() int {
	c.tombMu.Lock()
	n := len(c.tombstones)
	c.tombMu.Unlock()
	return n
}

// Stats returns compactor metrics.
func (c *EpochCompactor) Stats() map[string]uint64 {
	return map[string]uint64{
		"current_epoch":   c.currentEpoch.Load(),
		"stable_epoch":    c.StableEpoch(),
		"total_inserted":  c.totalInserted.Load(),
		"total_pruned":    c.totalPruned.Load(),
		"pending_count":   uint64(c.TombstoneCount()),
		"stability_lag":   c.stabilityLag,
		"last_prune_time": uint64(c.lastPruneTime.Load()),
	}
}
