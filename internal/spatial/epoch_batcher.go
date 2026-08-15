//go:build linux

// Package spatial provides the EpochBatcher for batch-mode H3 enrichment
// via the SPSC shared-memory ring buffer.
//
// ARCHITECTURAL JUSTIFICATION:
// Synchronous per-event Submit→Collect on the SPSC ring starves the
// ingestion pipeline: the Go thread blocks on each Collect() spin,
// wasting ~100ns waiting for the C++ worker per event. At 100K RPS,
// this wastes 10ms/sec of pure spin-wait time.
//
// Epoch batching stages N coordinates into the ring, issues a single
// memory_order_release barrier, and allows the C++ worker to process
// the entire batch while the Go thread processes the next network epoch.
// Results are collected asynchronously before the MemTable commit.
package spatial

import (
	"fmt"
	"sync/atomic"
	"time"
)

const (
	// DefaultEpochSize is the maximum number of events per epoch batch.
	// Must be <= ringCapacity / 2 to prevent ring exhaustion deadlock.
	DefaultEpochSize = 4096

	// CollectTimeout is the maximum time to wait for a single slot result.
	// If exceeded, the C++ worker is assumed dead and the event is committed
	// with H3Index=0 (null sentinel) for later background reconciliation.
	CollectTimeout = 100 * time.Millisecond
)

// EpochRequest tracks a single coordinate submitted in an epoch.
type EpochRequest struct {
	SeqID     uint64  // Ring buffer sequence ID from Submit()
	Latitude  float64 // Original latitude for error reporting
	Longitude float64 // Original longitude for error reporting
}

// EpochResult contains the H3 enrichment result for a single event.
type EpochResult struct {
	SeqID   uint64
	H3Index uint64
	Timeout bool // True if the result timed out (C++ worker may be dead)
}

// EpochBatcher manages batch-mode interaction with the SPSC ring buffer.
type EpochBatcher struct {
	ring      *SPSCRing
	epochSize int
	pending   []EpochRequest // Pre-allocated request buffer
	results   []EpochResult  // B2 FIX: Pre-allocated results buffer (reused)
	count     int            // Current number of pending requests

	// Metrics
	epochsProcessed atomic.Uint64
	timeouts        atomic.Uint64
}

// NewEpochBatcher creates a new batcher with the given ring buffer.
// epochSize is capped at ringCapacity / 2 to prevent deadlock.
func NewEpochBatcher(ring *SPSCRing, epochSize int) *EpochBatcher {
	maxEpoch := int(ring.capacity) / 2
	if epochSize > maxEpoch {
		epochSize = maxEpoch
	}
	if epochSize <= 0 {
		epochSize = DefaultEpochSize
	}

	return &EpochBatcher{
		ring:      ring,
		epochSize: epochSize,
		pending:   make([]EpochRequest, epochSize),
		results:   make([]EpochResult, epochSize), // B2 FIX: pre-allocate
		count:     0,
	}
}

// Stage adds a coordinate to the current epoch batch.
// When the epoch is full, it is automatically submitted and results collected.
//
// Returns the H3 index if the epoch was flushed, or 0 if the event was staged
// for deferred processing. Callers should use FlushEpoch() to collect remaining
// results before committing events to the MemTable.
func (b *EpochBatcher) Stage(lat, lng float64) error {
	if b.count >= b.epochSize {
		return fmt.Errorf("epoch full: call FlushEpoch() first")
	}

	seqID, err := b.ring.Submit(lat, lng)
	if err != nil {
		return fmt.Errorf("epoch stage: ring submit failed: %w", err)
	}

	b.pending[b.count] = EpochRequest{
		SeqID:     seqID,
		Latitude:  lat,
		Longitude: lng,
	}
	b.count++
	return nil
}

// FlushEpoch collects all pending H3 results from the C++ worker.
// B2 FIX: Returns a slice of the pre-allocated results buffer.
// The caller MUST consume results before the next Stage()/FlushEpoch() cycle.
func (b *EpochBatcher) FlushEpoch() []EpochResult {
	if b.count == 0 {
		return nil
	}

	for i := 0; i < b.count; i++ {
		req := b.pending[i]
		h3Index, timedOut := b.collectWithTimeout(req.SeqID)

		b.results[i] = EpochResult{
			SeqID:   req.SeqID,
			H3Index: h3Index,
			Timeout: timedOut,
		}

		if timedOut {
			b.timeouts.Add(1)
		}
	}

	resultSlice := b.results[:b.count]
	b.epochsProcessed.Add(1)
	b.count = 0
	return resultSlice
}

// collectWithTimeout spins for a result with a bounded timeout.
// B1 FIX: Uses UnixNano() comparison instead of time.Now().After(deadline)
// to avoid *Location heap escape on every check.
func (b *EpochBatcher) collectWithTimeout(seqID uint64) (uint64, bool) {
	idx := seqID % uint64(b.ring.capacity)
	slot := &b.ring.slots[idx]

	// Pre-compute deadline as raw nanoseconds. time.Now().UnixNano()
	// returns int64 — no heap allocation, no *Location pointer.
	deadlineNano := time.Now().UnixNano() + int64(CollectTimeout)
	spinCount := 0

	for atomic.LoadUint32(&slot.State) != SlotDone {
		spinCount++
		if spinCount > 1000 {
			// GOSCHED ERADICATION: Hardware PAUSE replaces runtime.Gosched().
			// procyield(30) keeps L1 cache hot without polluting the Go
			// scheduler run queue or starving the Epoll netpoller.
			// The existing CollectTimeout bound prevents infinite spinning.
			procyield(30)
			spinCount = 0

			if time.Now().UnixNano() > deadlineNano {
				// Timeout: C++ worker may be dead, stalled, or hasn't started.
				//
				// FLAW 7 FIX: Use CAS to safely reclaim the slot.
				// The old StoreUint32 was unconditional — it would force-clear
				// even a SlotProcessing slot, allowing the C++ worker to later
				// overwrite a resubmitted slot's data (ABA problem).
				//
				// We must handle three possible states:
				// 1. SlotReady:      C++ never picked it up. Safe to reclaim.
				// 2. SlotProcessing: C++ is working. Safe to reclaim, but C++
				//                    may later write SlotDone. In the SPSC model,
				//                    the next Submit to this slot index won't
				//                    happen until after this function returns.
				// 3. SlotDone:       C++ finished during timeout. Recover result.
				state := atomic.LoadUint32(&slot.State)
				switch state {
				case SlotDone:
					// C++ finished while we were about to give up — recover result.
					h3Index := slot.H3Index
					atomic.CompareAndSwapUint32(&slot.State, SlotDone, SlotEmpty)
					b.ring.submitWait.Signal()
					return h3Index, false

				case SlotProcessing:
					// C++ is still computing. Reclaim via CAS.
					if atomic.CompareAndSwapUint32(&slot.State, SlotProcessing, SlotEmpty) {
						b.ring.submitWait.Signal()
						return 0, true
					}
					// CAS failed: C++ transitioned to SlotDone between our Load
					// and CAS. Read the result.
					h3Index := slot.H3Index
					atomic.CompareAndSwapUint32(&slot.State, SlotDone, SlotEmpty)
					b.ring.submitWait.Signal()
					return h3Index, false

				default:
					// SlotReady or SlotEmpty: C++ never started processing.
					atomic.CompareAndSwapUint32(&slot.State, SlotReady, SlotEmpty)
					b.ring.submitWait.Signal()
					return 0, true
				}
			}
		}
	}

	h3Index := slot.H3Index
	// Reclaim the slot. Use CAS for defensive consistency — ensures we
	// only transition SlotDone → SlotEmpty, not some other state.
	atomic.CompareAndSwapUint32(&slot.State, SlotDone, SlotEmpty)
	// Signal submitWait to unpark any producer blocked on this slot.
	b.ring.submitWait.Signal()
	return h3Index, false
}

// Pending returns the number of staged requests awaiting collection.
func (b *EpochBatcher) Pending() int {
	return b.count
}

// EpochSize returns the configured maximum epoch size.
func (b *EpochBatcher) EpochSize() int {
	return b.epochSize
}

// Stats returns diagnostic counters.
func (b *EpochBatcher) Stats() (epochsProcessed, timeouts uint64) {
	return b.epochsProcessed.Load(), b.timeouts.Load()
}
