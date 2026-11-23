// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/hr18vk/sovereign/internal/crypto"
	"github.com/hr18vk/sovereign/internal/telemetry"
)

const (
	DefaultArenaSize          = 256 * 1024 * 1024 // 256MB
	DefaultMaxEntries         = 50000
	DefaultMaxInflightFlushes = 4
)

// MemTable is the mutable in-memory buffer for the tri-temporal LSM tree.
// It wraps a SkipListArena and flushes full arenas to L0. Every write applies
// crypto.MaskPII before copying the payload into the arena.
//
// Concurrent insertions hold m.mu for reading while calling SkipListArena.Put.
// The exclusive lock is needed only to swap in a fresh arena (ADR-0018).
// Uploads run in background goroutines; inflightFlushes lets Close wait for
// them, and each frozen jemalloc arena is freed after its upload finishes.
type MemTable struct {
	allocator       *JemallocAllocator
	skipList        *SkipListArena
	flusher         *L0Flusher
	arenaSize       uint32
	maxEntries      uint32
	fallbackDir     string         // per-entity local spill directory for S3 failures
	mu              sync.RWMutex   // protects skipList during arena swaps
	inflightFlushes sync.WaitGroup // tracks asynchronous L0 flushes
	flushSem        chan struct{}  // bounds frozen arenas awaiting upload
	flushCount      atomic.Int64
	flushErrors     atomic.Int64 // asynchronous flush failures
	closed          atomic.Bool
	shutdownChan    chan struct{} // interrupts upload retry sleeps
	shutdownOnce    sync.Once     // closes shutdownChan once
}

// NewMemTable creates a MemTable backed by an off-heap jemalloc arena.
// fallbackDir is the per-entity local spill directory used after an S3 upload
// fails (ADR-0018). A non-empty directory that cannot be created is fatal.
func NewMemTable(allocator *JemallocAllocator, arenaSize uint32, maxEntries uint32, flusher *L0Flusher, fallbackDir string) *MemTable {
	// Create the spill directory at startup rather than discovering a permissions
	// or path error only after an upload has failed.
	if fallbackDir != "" {
		if err := os.MkdirAll(fallbackDir, 0o750); err != nil {
			log.Fatalf("[MemTable] CRITICAL: Failed to initialize fallback directory %s: %v", fallbackDir, err)
		}
	}
	return &MemTable{
		allocator:    allocator,
		skipList:     NewSkipListArena(allocator, arenaSize),
		flusher:      flusher,
		arenaSize:    arenaSize,
		maxEntries:   maxEntries,
		fallbackDir:  fallbackDir,
		flushSem:     make(chan struct{}, DefaultMaxInflightFlushes),
		shutdownChan: make(chan struct{}),
	}
}

// TriTemporalEvent is the logical ingestion event passed to MemTable.Write.
// Write serializes its fields into the off-heap arena and does not retain the
// struct itself.
type TriTemporalEvent struct {
	EntityID       string
	SystemTime     int64 // UnixNano
	ValidTimeStart int64 // UnixNano
	ValidTimeEnd   int64 // UnixNano
	AssertionTime  int64 // UnixNano
	H3Index        uint64
	Payload        []byte
	PayloadDigest  [32]byte
}

// Write masks the payload with crypto.MaskPII and inserts an event into the
// active MemTable. A full arena is handed to the asynchronous L0 flush path.
//
// Write returns after the event is copied into memory; it does not wait for the
// S3 upload. Entity IDs are limited to 65,535 bytes and must be valid UTF-8 for
// downstream Arrow readers. The packed value contains the entity ID, H3 index,
// valid-time end, payload digest, and masked payload.
func (m *MemTable) Write(ctx context.Context, event TriTemporalEvent) error {
	if len(event.EntityID) > 65535 {
		return fmt.Errorf("entity ID exceeds max length of 65535 bytes")
	}

	// Arrow's Utf8/Binary column accepts raw bytes, but readers such as DuckDB
	// and Spark expect valid UTF-8 entity IDs.
	if !utf8.ValidString(event.EntityID) {
		return fmt.Errorf("entity ID contains invalid UTF-8")
	}

	// View the payload as a string without copying it. An unchanged payload can
	// then reuse its original byte slice; MaskPII allocates only when it masks
	// content and returns a new string.
	payloadStr := unsafe.String(unsafe.SliceData(event.Payload), len(event.Payload))
	maskedStr := crypto.MaskPII(payloadStr)
	var sanitizedPayload []byte
	if maskedStr == payloadStr {
		sanitizedPayload = event.Payload
	} else {
		sanitizedPayload = unsafe.Slice(unsafe.StringData(maskedStr), len(maskedStr))
		// This byte view does not keep maskedStr alive by itself. KeepAlive after
		// Put ensures the backing memory survives until valFn has copied it.
	}

	// A read-only byte view avoids copying the entity ID for hashing and packing.
	entityIDBytes := unsafe.Slice(unsafe.StringData(event.EntityID), len(event.EntityID))

	// Hashing does not need the arena lock.
	h := sha256.Sum256(entityIDBytes)

	// Reject an event that cannot fit in an empty arena before entering the
	// swap-and-retry loop.
	totalEventSize := uint64(keySize) + uint64(2+len(entityIDBytes)+8+8+32+4+len(sanitizedPayload)) + nodeSize
	if totalEventSize > uint64(m.arenaSize)-nodeSize {
		return fmt.Errorf("memtable: event too large (%d bytes) for arena capacity (%d bytes)", totalEventSize, m.arenaSize)
	}

	// The fixed-size key can stay on the stack because Put copies it into the
	// arena. Its first 16 bytes are the entity-hash prefix (ADR-0028).
	var key [keySize]byte
	copy(key[0:16], h[:16])
	binary.BigEndian.PutUint64(key[16:24], uint64(event.SystemTime))
	binary.BigEndian.PutUint64(key[24:32], uint64(event.ValidTimeStart))
	binary.BigEndian.PutUint64(key[32:40], uint64(event.AssertionTime))

	// Value layout: [2B entity ID length][entity ID][8B H3 index]
	// [8B valid-time end][32B payload digest][4B payload length][payload].
	valLen := 2 + len(entityIDBytes) + 8 + 8 + 32 + 4 + len(sanitizedPayload)

	// Put supplies an arena-backed value buffer, avoiding a temporary heap slice.
	valFn := func(val []byte) {
		off := 0
		binary.LittleEndian.PutUint16(val[off:off+2], uint16(len(entityIDBytes)))
		off += 2
		copy(val[off:off+len(entityIDBytes)], entityIDBytes)
		off += len(entityIDBytes)
		binary.LittleEndian.PutUint64(val[off:off+8], event.H3Index)
		off += 8
		binary.LittleEndian.PutUint64(val[off:off+8], uint64(event.ValidTimeEnd))
		off += 8
		copy(val[off:off+32], event.PayloadDigest[:])
		off += 32
		binary.LittleEndian.PutUint32(val[off:off+4], uint32(len(sanitizedPayload)))
		off += 4
		copy(val[off:], sanitizedPayload)
	}

	// valFn reads sanitizedPayload from inside Put. The KeepAlive calls after all
	// Put attempts keep maskedStr's backing memory live for those reads.

	// The read lock permits concurrent insertion into the active skiplist.
	m.mu.RLock()

	// Checking closed under the read lock prevents insertion during shutdown.
	if m.closed.Load() {
		m.mu.RUnlock()
		return fmt.Errorf("memtable: closed")
	}

	currentSL := m.skipList

	if currentSL.Count() >= m.maxEntries {
		m.mu.RUnlock()
		m.mu.Lock()
		// Another writer may already have swapped the arena while this writer
		// waited for the exclusive lock.
		if m.skipList == currentSL {
			if err := m.swapAndFlushAsync(ctx); err != nil {
				m.mu.Unlock()
				return err
			}
		}
		m.mu.Unlock()
		m.mu.RLock()
		// Close may run between the unlock and relock. Recheck before writing to
		// the new active arena.
		if m.closed.Load() {
			m.mu.RUnlock()
			return fmt.Errorf("memtable: closed")
		}
		currentSL = m.skipList
	}

	// Several writers can observe the same full arena. The first swaps it; the
	// others retry against the current arena because it may also have filled while
	// they waited. Three retries bound the loop, and the size check above rejects
	// events that cannot fit in an empty arena (ADR-0018, ADR-0019).
	const maxRetries = 3
	err := currentSL.Put(key[:], valLen, valFn)
	for attempt := 0; err != nil && attempt < maxRetries; attempt++ {
		m.mu.RUnlock()
		m.mu.Lock()
		// Swap only if another writer has not already done so.
		if m.skipList == currentSL {
			if flushErr := m.swapAndFlushAsync(ctx); flushErr != nil {
				m.mu.Unlock()
				runtime.KeepAlive(maskedStr)
				return flushErr
			}
		}
		m.mu.Unlock()

		m.mu.RLock()
		if m.closed.Load() {
			m.mu.RUnlock()
			runtime.KeepAlive(maskedStr)
			return fmt.Errorf("memtable: closed")
		}
		currentSL = m.skipList
		err = currentSL.Put(key[:], valLen, valFn)
	}

	m.mu.RUnlock()

	// valFn reads the masked string's backing memory during every Put attempt.
	runtime.KeepAlive(maskedStr)

	if err != nil {
		return fmt.Errorf("memtable: insertion failed after %d retries: %w", maxRetries, err)
	}

	return nil
}

// swapAndFlushAsync replaces the active skiplist with an empty arena and hands
// the frozen arena directly to a background flush. The caller holds m.mu for
// writing; this method does not release it. Waiting for flush capacity can
// block until ctx is cancelled or shutdown begins.
func (m *MemTable) swapAndFlushAsync(ctx context.Context) error {
	if m.skipList.Count() == 0 {
		return nil
	}

	select {
	case m.flushSem <- struct{}{}:
		// Reserve capacity before freezing another arena.
	case <-ctx.Done():
		return fmt.Errorf("memtable: flush backpressure interrupted: %w", ctx.Err())
	case <-m.shutdownChan:
		return fmt.Errorf("memtable: closed")
	}

	frozenArena := m.skipList
	m.skipList = NewSkipListArena(m.allocator, m.arenaSize)
	// Cancellation of the write request must not cancel an upload already
	// responsible for a frozen arena.
	bgCtx := context.WithoutCancel(ctx)

	// Register before launching so Close accounts for this flush.
	m.inflightFlushes.Add(1)

	flushNum := m.flushCount.Add(1)

	// The goroutine owns frozenArena through serialization and upload, then
	// releases its arena, flush slot, and WaitGroup entry.
	go func() {
		defer m.inflightFlushes.Done()
		defer func() { <-m.flushSem }()
		defer frozenArena.Free()

		// FlushArenaToIPC serializes and emits one entity partition at a time
		// (ADR-0018). Only the current partition buffer remains live. The upload
		// callback retains that buffer across retries and frees it before the next
		// partition, so a retry does not serialize the arena again.
		var uploadedPartitions int
		var lastUploadErr error
		serErr := m.flusher.FlushArenaToIPC(frozenArena, func(part L0Partition) error {
			defer part.Buf.Free()

			// Retry the same serialized partition with exponential backoff.
			maxRetries := 10
			baseDelay := 100 * time.Millisecond
			var pErr error
		PRetry:
			for attempt := 0; attempt < maxRetries; attempt++ {
				// Stop retrying after shutdown starts, but allow the first upload
				// attempt to finish even if Close is waiting for it.
				if attempt > 0 && m.closed.Load() {
					log.Printf("[MemTable] Aborting S3 upload retries for flush #%d partition %x due to daemon shutdown",
						flushNum, part.EntityHash[:8])
					pErr = fmt.Errorf("aborted: daemon shutting down")
					break PRetry
				}

				pErr = m.flusher.UploadPartition(bgCtx, part)
				if pErr == nil {
					break PRetry
				}
				log.Printf("[MemTable] WARNING: L0 flush #%d partition %x upload failed on attempt %d: %v",
					flushNum, part.EntityHash[:8], attempt+1, pErr)

				// Either the request or shutdown can interrupt the backoff timer.
				timer := time.NewTimer(baseDelay * time.Duration(1<<attempt))
				select {
				case <-ctx.Done():
					timer.Stop()
					break PRetry
				case <-m.shutdownChan:
					timer.Stop()
					log.Printf("[MemTable] Aborting S3 upload retries for flush #%d partition %x due to daemon shutdown (interrupted sleep)",
						flushNum, part.EntityHash[:8])
					pErr = fmt.Errorf("aborted: daemon shutting down")
					break PRetry
				case <-timer.C:
					// backoff expired, proceed to next attempt
				}
			}

			if pErr != nil {
				lastUploadErr = pErr
				// Spill each failed partition under its entity hash so the read path
				// can find it (ADR-0018). Combining entities in one fallback file
				// would break that lookup contract.
				if m.fallbackDir != "" {
					fallbackPath := filepath.Join(m.fallbackDir, fmt.Sprintf("l0_fallback_%x_%d_%d.arrow",
						part.EntityHash[:8], part.FirstSysTimeNs, time.Now().UnixNano()))
					if writeErr := os.WriteFile(fallbackPath, part.Buf.Bytes(), 0o640); writeErr != nil {
						log.Printf("[MemTable] CRITICAL: Failed to write fallback file %s: %v", fallbackPath, writeErr)
					} else {
						log.Printf("[MemTable] Fallback: L0 flush #%d partition %x saved to %s (%d bytes)",
							flushNum, part.EntityHash[:8], fallbackPath, len(part.Buf.Bytes()))
					}
				}
				// A failed partition does not prevent later entities from flushing.
				return nil
			}
			uploadedPartitions++
			return nil
		})
		if serErr != nil {
			m.flushErrors.Add(1)
			log.Printf("[MemTable] ERROR: L0 flush #%d serialization failed: %v", flushNum, serErr)
			// Without a serialized partition there is no buffer to upload or spill;
			// the deferred Free releases the frozen arena.
			return
		}
		if lastUploadErr != nil {
			m.flushErrors.Add(1)
			log.Printf("[MemTable] ERROR: L0 flush #%d completed with upload errors (last: %v); per-entity fallback engaged where configured", flushNum, lastUploadErr)
		}

		// Retain the per-partition upload count as part of the flush accounting.
		_ = uploadedPartitions

		telemetry.MemTableFlushTotal.Inc()
		// Report allocator usage after this flush; the deferred arena Free runs
		// after the gauge update.
		telemetry.OffHeapAllocatedBytes.Set(float64(m.allocator.BytesAllocated()))

		log.Printf("[MemTable] L0 flush #%d: %d events written to Arrow IPC", flushNum, frozenArena.Count())
	}()

	return nil
}

// Flush synchronously serializes the active MemTable and uploads each entity
// partition to L0. If an upload fails, Flush writes that partition to
// fallbackDir when configured and continues with the remaining entities. It
// returns an error when serialization fails or a partition can neither be
// uploaded nor written to the fallback directory.
func (m *MemTable) Flush(ctx context.Context) error {
	m.mu.Lock()

	if m.skipList.Count() == 0 {
		m.mu.Unlock()
		return nil
	}

	frozenArena := m.skipList
	m.skipList = NewSkipListArena(m.allocator, m.arenaSize)

	m.mu.Unlock()
	// Serialization and uploads run outside the arena lock.

	defer frozenArena.Free()

	// Serialize one entity partition at a time (ADR-0018). The callback uploads
	// that partition or writes its buffer to the entity-keyed fallback path.
	var uploadedPartitions int
	var firstErr error
	serErr := m.flusher.FlushArenaToIPC(frozenArena, func(part L0Partition) error {
		defer part.Buf.Free()
		if err := m.flusher.UploadPartition(ctx, part); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			log.Printf("[MemTable] Sync flush upload failed for partition %x: %v. Writing per-entity disk fallback...", part.EntityHash[:4], err)
			if m.fallbackDir != "" {
				fallbackPath := filepath.Join(m.fallbackDir, fmt.Sprintf("l0_fallback_%x_%d_%d.arrow",
					part.EntityHash[:8], part.FirstSysTimeNs, time.Now().UnixNano()))
				if writeErr := os.WriteFile(fallbackPath, part.Buf.Bytes(), 0o640); writeErr != nil {
					return fmt.Errorf("sync flush failed and fallback write failed: %v (original: %w)", writeErr, err)
				}
			} else {
				return fmt.Errorf("sync flush upload failed and no fallback dir: %w", err)
			}
			// The fallback preserved this partition; continue with the others.
			return nil
		}
		uploadedPartitions++
		return nil
	})
	if serErr != nil {
		return fmt.Errorf("sync flush serialization failed: %w", serErr)
	}

	flushNum := m.flushCount.Add(1)
	log.Printf("[MemTable] L0 sync flush #%d: %d events / %d per-entity partitions uploaded", flushNum, frozenArena.Count(), uploadedPartitions)

	return nil
}

// Close rejects new writes, flushes the active MemTable, waits for asynchronous
// flushes, and frees the empty active arena. Closing shutdownChan interrupts
// upload retry sleeps. If the final synchronous flush fails, Close returns that
// error before waiting or freeing the active arena.
func (m *MemTable) Close(ctx context.Context) error {
	m.closed.Store(true)
	// Concurrent callers cannot close shutdownChan more than once.
	m.shutdownOnce.Do(func() { close(m.shutdownChan) })

	// Flush the final active MemTable synchronously.
	if err := m.Flush(ctx); err != nil {
		return fmt.Errorf("memtable close: final flush failed: %w", err)
	}

	// No upload goroutine remains active after this wait.
	m.inflightFlushes.Wait()

	m.mu.Lock()
	m.skipList.Free()
	m.mu.Unlock()

	if errors := m.flushErrors.Load(); errors > 0 {
		log.Printf("[MemTable] WARNING: %d async flush(es) failed during lifetime", errors)
	}

	return nil
}

// FlushCount returns the number of L0 flushes performed (both sync and async).
func (m *MemTable) FlushCount() int64 {
	return m.flushCount.Load()
}

// FlushErrors returns the number of failed async L0 flushes.
func (m *MemTable) FlushErrors() int64 {
	return m.flushErrors.Load()
}

// EntryCount returns the number of entries in the current active MemTable.
func (m *MemTable) EntryCount() uint32 {
	return m.skipList.Count()
}
