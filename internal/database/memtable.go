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

	"github.com/hr18vk/supremum/internal/crypto"
	"github.com/hr18vk/supremum/internal/telemetry"
)

const (
	DefaultArenaSize          = 256 * 1024 * 1024 // 256MB
	DefaultMaxEntries         = 50000
	DefaultMaxInflightFlushes = 4
)

// MemTable is the mutable in-memory buffer for the Tri-Temporal LSM-Tree.
// It wraps a SkipListArena with automatic L0 flushing. PII masking is applied
// synchronously via crypto.MaskPII() — no wrapper struct (Override O2.5).
//
// CONCURRENCY MODEL (Override O1.4 — Async Double-Buffered Flush):
// Concurrent insertions use RLock() for sl.Put(). The exclusive write lock
// (m.mu) is held ONLY for the O(1) arena pointer swap.
// The S3 upload runs in a background goroutine. m.inflightFlushes tracks
// pending async flushes so Close() can drain them during graceful shutdown.
// The old jemalloc arena is freed ONLY after the async upload completes.
type MemTable struct {
	allocator       *JemallocAllocator
	skipList        *SkipListArena
	flusher         *L0Flusher
	arenaSize       uint32
	maxEntries      uint32
	fallbackDir     string         // Override 8.1: local disk fallback for S3 failures
	mu              sync.RWMutex   // Protects skipList pointer swap
	inflightFlushes sync.WaitGroup // Tracks async L0 flush goroutines
	flushSem        chan struct{}  // Bounds frozen arenas waiting on object storage
	flushCount      atomic.Int64
	flushErrors     atomic.Int64 // Tracks async flush failures for monitoring
	closed          atomic.Bool
	shutdownChan    chan struct{} // Override 10.1: immediately interrupts retry sleep
	shutdownOnce    sync.Once     // V5 Fix: Prevents double-close panic on shutdownChan
}

// NewMemTable creates a new MemTable with off-heap jemalloc arena.
// Override O2.5: No PIIGate parameter — crypto.MaskPII is called directly.
// Override 8.1: fallbackDir specifies where to spill Arrow IPC on S3 failure.
// Override 10.5: MkdirAll failures are fatal — fail-fast on startup.
func NewMemTable(allocator *JemallocAllocator, arenaSize uint32, maxEntries uint32, flusher *L0Flusher, fallbackDir string) *MemTable {
	// Override 10.5: Fail-fast if fallback directory cannot be created.
	// The original `_ = os.MkdirAll(...)` silently ignored errors. If the directory
	// doesn't exist when a critical S3 upload fails, the fallback write crashes,
	// causing unpreventable data loss. Fail on startup, not during a crisis.
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
		shutdownChan: make(chan struct{}), // Override 10.1
	}
}

// TriTemporalEvent is the logical ingestion event passed to MemTable.Write().
// This struct lives briefly on the Go stack during Write(). Its fields are
// serialized into the off-heap arena as raw bytes — the struct itself is
// NEVER stored on the Go heap or in any slice.
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

// Write inserts a tri-temporal event into the MemTable.
// The payload is sanitized through crypto.MaskPII() before insertion (Override O2.5).
// The value is packed with the O2.2 layout: [2B entityIDLen][entityID][8B H3Index][8B ValidTimeEnd][32B PayloadDigest][4B payloadLen][payload].
// If the MemTable is full, it triggers an asynchronous L0 flush.
//
// Write() returns as soon as the event is durably in the active MemTable.
// The S3 upload of the frozen MemTable happens in the background.
func (m *MemTable) Write(ctx context.Context, event TriTemporalEvent) error {
	if len(event.EntityID) > 65535 {
		return fmt.Errorf("entity ID exceeds max length of 65535 bytes")
	}

	// Override 8.3: Reject non-UTF-8 entity IDs at the ingestion boundary.
	// Arrow's Utf8/Binary column stores raw bytes, but downstream readers
	// (DuckDB, Spark) expect valid UTF-8. Validate here to catch corruption early.
	if !utf8.ValidString(event.EntityID) {
		return fmt.Errorf("entity ID contains invalid UTF-8")
	}

	// Override 7.5: Zero-GC PII Gate.
	// The original code: `[]byte(crypto.MaskPII(string(event.Payload)))`
	// performed TWO heap allocations per write:
	//   1. string(event.Payload) — copies []byte to a new Go string.
	//   2. []byte(maskedString) — copies the result back to []byte.
	// Fixed: Use unsafe.String to create a zero-copy string view of the payload,
	// then only allocate if MaskPII actually modified the content.
	payloadStr := unsafe.String(unsafe.SliceData(event.Payload), len(event.Payload))
	maskedStr := crypto.MaskPII(payloadStr)
	var sanitizedPayload []byte
	if maskedStr == payloadStr {
		// No masking occurred — reuse the original byte slice directly. ZERO ALLOC.
		sanitizedPayload = event.Payload
	} else {
		// Masking occurred — we must allocate the new masked bytes.
		// This is the rare path (only when PII is detected).
		sanitizedPayload = unsafe.Slice(unsafe.StringData(maskedStr), len(maskedStr))
		// Override 7.9: Prevent GC from collecting maskedStr's backing array.
		// The unsafe.Slice above creates a []byte view that the GC doesn't track.
		// We need maskedStr alive until sanitizedPayload is copied into the arena.
		// runtime.KeepAlive is called after the copy below (see Override 7.9 marker).
	}

	// Override 7.5: Zero-GC entity ID byte view.
	// The original `[]byte(event.EntityID)` and `sha256.Sum256([]byte(event.EntityID))`
	// both allocate fresh byte slices. Use unsafe to create a read-only byte view.
	entityIDBytes := unsafe.Slice(unsafe.StringData(event.EntityID), len(event.EntityID))

	// Compute entity ID hash (OUTSIDE the lock — pure computation).
	h := sha256.Sum256(entityIDBytes)

	// Override 7.6: Pre-flight size check to prevent infinite flush storm.
	// If a single event cannot fit in a fresh arena, reject it immediately
	// rather than entering an infinite swap-retry loop.
	totalEventSize := uint64(keySize) + uint64(2+len(entityIDBytes)+8+8+32+4+len(sanitizedPayload)) + nodeSize
	if totalEventSize > uint64(m.arenaSize)-nodeSize {
		return fmt.Errorf("memtable: event too large (%d bytes) for arena capacity (%d bytes)", totalEventSize, m.arenaSize)
	}

	// Build tri-temporal composite key (OUTSIDE the lock). Override 8.4: 128-bit hash.
	// Override 7.8: Use fixed-size array instead of make([]byte, keySize) to stay on the stack.
	// make([]byte, 40) heap-allocates at 100K/sec = 100K garbage slices/sec.
	// [keySize]byte is a value type — Go keeps it on the stack. key[:] creates a
	// non-escaping slice view since sl.Put only copies via copy(sl.arena[...], key).
	var key [keySize]byte
	copy(key[0:16], h[:16]) // Override 8.4: 128-bit hash prefix
	binary.BigEndian.PutUint64(key[16:24], uint64(event.SystemTime))
	binary.BigEndian.PutUint64(key[24:32], uint64(event.ValidTimeStart))
	binary.BigEndian.PutUint64(key[32:40], uint64(event.AssertionTime))

	// Override 4.1: Pack value with ALL required fields including ValidTimeEnd.
	// Layout (O2.2): [2B EntityID Len][EntityID String][8B H3Index][8B ValidTimeEnd][32B PayloadDigest][4B Payload Len][Payload Bytes]
	valLen := 2 + len(entityIDBytes) + 8 + 8 + 32 + 4 + len(sanitizedPayload)

	// Override ZGC.1: Write directly into the off-heap arena via valFn.
	// This eliminates `val := make([]byte, valLen)` — avoiding 50,000 heap
	// allocations per L0 flush. The entire ingestion pipeline is now 100% Zero-GC.
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

	// V4 Fix: runtime.KeepAlive(maskedStr) has been relocated to AFTER the Put()
	// call completes (see end of critical section below). The original placement
	// here was too early — valFn captures sanitizedPayload (an unsafe.Slice view
	// into maskedStr's backing array) and is invoked INSIDE Put(). KeepAlive must
	// outlive the Put() call to prevent GC from collecting maskedStr while valFn
	// is copying from its memory.

	// === BEGIN CRITICAL SECTION ===
	// We use RLock to allow highly concurrent insertions into the SkipList.
	m.mu.RLock()

	// Override 4.2: Move closed check inside RLock to prevent shutdown race condition.
	if m.closed.Load() {
		m.mu.RUnlock()
		return fmt.Errorf("memtable: closed")
	}

	currentSL := m.skipList

	// Check capacity before insertion.
	if currentSL.Count() >= m.maxEntries {
		m.mu.RUnlock()
		m.mu.Lock()
		// Override 4.3: Prevent flush storms under high contention
		if m.skipList == currentSL {
			if err := m.swapAndFlushAsync(ctx); err != nil {
				m.mu.Unlock()
				return err
			}
		}
		m.mu.Unlock()
		m.mu.RLock()
		// Override 7.10: Re-check closed after re-acquiring RLock.
		// Between Unlock() and RLock(), Close() may have set m.closed and
		// performed the final flush. Inserting now would silently lose data.
		if m.closed.Load() {
			m.mu.RUnlock()
			return fmt.Errorf("memtable: closed")
		}
		currentSL = m.skipList
	}

	// V3 Fix: Bounded retry loop replaces single-retry to prevent stampede data loss.
	// Under 100K RPS, when the arena fills, thousands of goroutines queue on m.mu.Lock().
	// Only the first goroutine swaps the arena. Trailing goroutines must retry on the
	// fresh arena, but a single retry can fail if the stampede exceeds the new arena's
	// capacity before the trailing goroutines execute. The bounded loop (max 3 attempts)
	// ensures each goroutine re-evaluates arena state and triggers additional swaps
	// if needed, while the bound prevents infinite loops from oversized events
	// (which are already rejected by the pre-flight check at Override 7.6).
	const maxRetries = 3
	err := currentSL.Put(key[:], valLen, valFn)
	for attempt := 0; err != nil && attempt < maxRetries; attempt++ {
		m.mu.RUnlock()
		// Arena full — acquire exclusive lock to trigger swap.
		m.mu.Lock()
		// Override 4.3: Prevent flush storms — only swap if no one else already did.
		if m.skipList == currentSL {
			if flushErr := m.swapAndFlushAsync(ctx); flushErr != nil {
				m.mu.Unlock()
				runtime.KeepAlive(maskedStr) // V4 Fix: ensure maskedStr outlives all Put attempts
				return flushErr
			}
		}
		m.mu.Unlock()

		// Re-acquire read lock and retry on the (possibly new) arena.
		m.mu.RLock()
		// Override 7.10: Re-check closed after re-acquiring RLock.
		if m.closed.Load() {
			m.mu.RUnlock()
			runtime.KeepAlive(maskedStr) // V4 Fix: ensure maskedStr outlives all Put attempts
			return fmt.Errorf("memtable: closed")
		}
		currentSL = m.skipList // Refresh reference to potentially swapped arena
		err = currentSL.Put(key[:], valLen, valFn)
	}

	m.mu.RUnlock()
	// === END CRITICAL SECTION ===

	// V4 Fix: KeepAlive MUST be placed AFTER Put() completes.
	// valFn captures sanitizedPayload (an unsafe.Slice view into maskedStr's
	// backing array) and is invoked INSIDE Put(). If KeepAlive were placed
	// before the critical section (as it was originally at line 186), the GC
	// could collect maskedStr while valFn is reading from its memory.
	runtime.KeepAlive(maskedStr)

	if err != nil {
		return fmt.Errorf("memtable: insertion failed after %d retries: %w", maxRetries, err)
	}

	return nil
}

// swapAndFlushAsync freezes the current SkipList, swaps in a fresh arena,
// and launches a background goroutine to flush the frozen data to S3.
//
// MUST be called with m.mu held. The lock is NOT released by this function —
// the caller continues to hold it for the subsequent Put() call.
//
// Override O2.2: The frozen SkipListArena is passed DIRECTLY to the flusher.
// No DrainSkipList. No intermediate Go heap structs. Lock hold time: O(1).
func (m *MemTable) swapAndFlushAsync(ctx context.Context) error {
	if m.skipList.Count() == 0 {
		return nil
	}

	select {
	case m.flushSem <- struct{}{}:
		// Acquired physical flush capacity before freezing another arena.
	case <-ctx.Done():
		return fmt.Errorf("memtable: flush backpressure interrupted: %w", ctx.Err())
	case <-m.shutdownChan:
		return fmt.Errorf("memtable: closed")
	}

	// Phase 1 (UNDER LOCK): Capture the frozen arena pointer. O(1).
	frozenArena := m.skipList

	// Phase 2 (UNDER LOCK): Swap to a fresh, empty arena. O(1).
	m.skipList = NewSkipListArena(m.allocator, m.arenaSize)
	bgCtx := context.WithoutCancel(ctx) // Override 5.2

	// Phase 3 (UNDER LOCK): Register the in-flight flush BEFORE launching
	// the goroutine, so Close() can track it.
	m.inflightFlushes.Add(1)

	flushNum := m.flushCount.Add(1)

	// Phase 4 (OUTSIDE LOCK): Launch async flush goroutine.
	// The goroutine owns `frozenArena`. It will:
	//   1. Iterate the frozen SkipList directly into Arrow builders (O2.2)
	//   2. Serialize to Arrow IPC File format (O2.4)
	//   3. Upload to S3
	//   4. Free the frozen jemalloc arena
	//   5. Decrement the WaitGroup
	go func() {
		defer m.inflightFlushes.Done()
		defer func() { <-m.flushSem }()
		defer frozenArena.Free() // Free old jemalloc arena AFTER upload completes

		// Day 13 per-entity streaming flush (ADR-0018):
		// FlushArenaToIPC serializes the frozen SkipList into ONE Arrow IPC
		// blob PER ENTITY and emits each partition as soon as it is
		// serialized. Only ONE partition's buffer is live at a time → O(1)
		// memory regardless of entity count (the OLD materialize-all path
		// held 50K unique entities' buffers simultaneously → OOM).
		// Override 9.2 (serialize once): the partition Buf is held through
		// its OWN upload retry loop and freed BEFORE the next partition
		// starts, so re-serialization on retry still never happens.
		var uploadedPartitions int
		var lastUploadErr error
		serErr := m.flusher.FlushArenaToIPC(frozenArena, func(part L0Partition) error {
			defer part.Buf.Free()

			// Override 4.5 & 5.3 & 9.2: per-partition S3 upload retry loop.
			// The partition buffer is the only one live — the retry loop holds
			// it across attempts (no re-serialization on retry).
			maxRetries := 10
			baseDelay := 100 * time.Millisecond
			var pErr error
		PRetry:
			for attempt := 0; attempt < maxRetries; attempt++ {
				// Override 10.1: closed-flag check (non-blocking) before each attempt.
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

				// Override 10.1 + 10.4: NewTimer + shutdownChan interrupt.
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
				// Override 8.1: S3 Outage Durability — per-entity Local Disk Fallback.
				// Write THIS partition's buffer to its own l0_fallback file under
				// the entity hash8 so the read path can still locate it (per-entity
				// keying is the contract; concatenating blobs would re-introduce the
				// silent-miss class in the outage path).
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
				return nil // continue to the next partition; do NOT abort remaining entities
			}
			uploadedPartitions++
			return nil
		})
		if serErr != nil {
			m.flushErrors.Add(1)
			log.Printf("[MemTable] ERROR: L0 flush #%d serialization failed: %v", flushNum, serErr)
			// Override 8.1: Fallback not possible — serialization itself failed.
			// The frozen arena data is lost. This is a critical error.
			return
		}
		if lastUploadErr != nil {
			m.flushErrors.Add(1)
			log.Printf("[MemTable] ERROR: L0 flush #%d completed with upload errors (last: %v); per-entity fallback engaged where configured", flushNum, lastUploadErr)
		}

		// record uploaded count for the caller-visible message below.
		_ = uploadedPartitions

		// Override 5.6: Telemetry Metrics
		// Override 7.7: Removed duplicate m.flushCount.Add(1) — flushNum was already
		// assigned from m.flushCount.Add(1) before the goroutine launched.
		telemetry.MemTableFlushTotal.Inc()
		// Override 7.11: Update OffHeapAllocatedBytes gauge so Prometheus
		// reflects current jemalloc usage. Without this, the gauge declared
		// in Override 9.4 remains at 0 forever.
		telemetry.OffHeapAllocatedBytes.Set(float64(m.allocator.BytesAllocated()))

		log.Printf("[MemTable] L0 flush #%d: %d events written to Arrow IPC", flushNum, frozenArena.Count())
	}()

	return nil
}

// Flush forces a synchronous flush of the current MemTable to L0.
// Used during graceful shutdown to ensure all data is persisted.
// This is the ONLY synchronous flush path — normal writes use async.
//
// Override 10.2: Unified fallback durability. If S3 upload fails (common during
// shutdown when network interfaces are torn down first), the serialized buffer
// is written to the local disk fallback directory before returning.
func (m *MemTable) Flush(ctx context.Context) error {
	m.mu.Lock()

	if m.skipList.Count() == 0 {
		m.mu.Unlock()
		return nil
	}

	// Override O2.2: Capture frozen arena directly, no DrainSkipList.
	frozenArena := m.skipList
	m.skipList = NewSkipListArena(m.allocator, m.arenaSize)

	m.mu.Unlock()
	// Lock released — S3 upload happens outside the critical section.

	defer frozenArena.Free()

	// Day 13 per-entity streaming sync flush (ADR-0018): serialize each entity
	// to its own partition + upload-or-fallback inside the emit callback, O(1)
	// memory. Override 10.2: if any upload fails (common during shutdown when
	// network interfaces tear down first), that partition's buffer is written to
	// the local disk fallback directory before continuing. Fallback is per-
	// entity (the per-entity keying is the contract).
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
			return nil // saved to disk → not lost → continue remaining entities
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

// Close flushes remaining data and waits for all in-flight async flushes.
//
// Shutdown sequence:
//  1. Set closed flag (rejects new Write() calls).
//  2. Synchronously flush the active MemTable (the final partial batch).
//  3. Wait for all in-flight async flushes to complete (WaitGroup drain).
//  4. Free the (now empty) active arena.
func (m *MemTable) Close(ctx context.Context) error {
	m.closed.Store(true)
	// V5 Fix: Protect channel close with sync.Once to prevent double-close panic.
	// If Close() is called twice (e.g., OS signal handler + internal crash recovery),
	// the second close(shutdownChan) would panic with "close of closed channel".
	// sync.Once guarantees exactly-once execution regardless of concurrent callers.
	m.shutdownOnce.Do(func() { close(m.shutdownChan) })

	// Step 1: Synchronously flush the final active MemTable.
	if err := m.Flush(ctx); err != nil {
		return fmt.Errorf("memtable close: final flush failed: %w", err)
	}

	// Step 2: Wait for ALL in-flight async flushes to complete.
	// This ensures no goroutine is still writing to S3 when the daemon exits.
	m.inflightFlushes.Wait()

	// Step 3: Free the active (now empty) arena.
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
