// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/apache/arrow/go/v17/arrow"
	"github.com/apache/arrow/go/v17/arrow/array"
	"github.com/apache/arrow/go/v17/arrow/ipc"
	"github.com/apache/arrow/go/v17/arrow/memory"
	"github.com/hr18vk/sovereign/internal/telemetry"
)

// ResolverConfig holds configuration for the Bitemporal Query Resolver.
type ResolverConfig struct {
	// LiveSource (ADR-0032) is placed first for struct field alignment; see the
	// trailing comment block below for read-your-writes semantics.
	LiveSource LiveSource

	// MaxL0Files limits the number of uncompacted L0 Arrow IPC files scanned
	// per query. Default: 1000. Set to 0 for unlimited.
	MaxL0Files int

	// MaxRangeRows (ADR-0024) caps the rows a single Resolver.Range query
	// returns before JSON marshaling. Default: 4096. When reached, Range
	// returns the collected prefix with truncated=true. Set to 0 for unlimited.
	MaxRangeRows int

	// EnableFirstSysSkip (ADR-0029) skips downloading L0, L1, and manifest files
	// whose filename-encoded minimum SystemTime exceeds the query's txTime.
	// Every row in such a file fails Filter 2 (SystemTime <= txTime), so
	// skipping the download leaves query results unchanged. Unparseable keys
	// fall back to normal download and scan. Default: true.
	EnableFirstSysSkip bool

	// LiveSource (ADR-0032) provides an optional live CRDT store adapter that
	// Resolver.AsOf and Resolver.Range merge with durable Arrow scan results to
	// preserve read-your-writes before the next periodic checkpoint flush. When
	// nil (DefaultResolverConfig), queries read durable storage only.
}

// LiveEvent mirrors TriTemporalEvent without EntityID for rows returned by
// LiveSource. Internal database code delegates engine access through this
// interface so internal/database stays independent of pkg/sync.
type LiveEvent struct {
	// Payload holds an optional payload slice (nil when PayloadDigest carries
	// the content hash alone). Scalar fields stay trailing the [32]byte digest
	// to minimize GC pointer span.
	Payload        []byte
	PayloadDigest  [32]byte
	SystemTime     int64
	ValidTimeStart int64
	ValidTimeEnd   int64
	AssertionTime  int64
	H3Index        uint64
}

// LiveSource is the read-your-writes adapter interface (ADR-0032).
// Implementations wrap live CRDT state lookups, pin any concurrent memory
// reclamation guard (such as epoch-based reclamation) for the duration of
// LiveRead, and return entries with SystemTime <= txTimeNs (Filter 2). Callers
// apply valid-time filters and dominance rules.
type LiveSource interface {
	// LiveRead returns live entries for entityID with SystemTime <= txTimeNs.
	// Returning nil or an empty slice is not an error; read errors are logged
	// via telemetry and fall back to durable results alone.
	LiveRead(ctx context.Context, entityID string, txTimeNs int64) ([]LiveEvent, error)
}

// DefaultResolverConfig returns a ResolverConfig with production-safe defaults.
func DefaultResolverConfig() ResolverConfig {
	return ResolverConfig{
		MaxL0Files:         1000,
		MaxRangeRows:       4096,
		EnableFirstSysSkip: true,
	}
}

// S3Lister abstracts S3 object listing for testability.
// Implementations return object keys under a given prefix, sorted lexicographically.
type S3Lister interface {
	// ListObjects returns up to maxKeys object keys under the given prefix,
	// sorted lexicographically (ascending). If maxKeys <= 0, returns all keys.
	ListObjects(ctx context.Context, bucket, prefix string, maxKeys int) ([]string, error)
}

// S3Downloader abstracts S3 object downloading for testability.
// Implementations return a ReadCloser for the object content.
type S3Downloader interface {
	// Download retrieves the object at the given key and returns its content.
	// The caller must close the returned ReadCloser.
	Download(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}

// S3Deleter abstracts object deletion from object storage (ADR-0021).
// L0Reaper uses it to remove superseded L0 files and manifests after checking
// that the corresponding L1 file exists. Delete must be idempotent for missing
// objects so interrupted sweeps can retry safely.
type S3Deleter interface {
	// Delete removes the object at the given key. Missing objects return nil.
	Delete(ctx context.Context, bucket, key string) error
}

// Resolver implements the Bitemporal Query Resolver.
//
// It scans compacted L1 and uncompacted L0 Arrow IPC files on object storage,
// applying tri-temporal predicates to return the dominant TriTemporalEvent or
// valid-time range windows for an entity.
//
// Allocation discipline:
//   - Arrow record batches are decoded over off-heap jemalloc buffers via
//     ipc.FileReader without json.Unmarshal or map[string]any allocations.
//   - Entity ID verification compares raw byte slices directly.
//   - Only the final matching event allocates on the Go heap.
type Resolver struct {
	lister     S3Lister
	downloader S3Downloader
	allocator  *JemallocAllocator
	// liveSource holds an optional read-your-writes adapter (ADR-0032), placed
	// alongside pointer-width fields for struct alignment.
	liveSource LiveSource
	// secondaryIndex supplies optional cross-entity candidate lookups; nil keeps
	// cross-entity queries disabled with ErrSecondaryIndexDisabled.
	secondaryIndex SecondaryIndexSource
	bucket         string
	config         ResolverConfig

	// pruningFrontierObserved tracks the highest transactionTime.UnixNano()
	// passed to AsOf on this Resolver using an atomic maximum loop (ADR-0027)
	// so L1Compactor.InferHorizon can advance the pruning floor without
	// allocating on the query path.
	pruningFrontierObserved int64
}

// observeQueryTxTime atomically advances pruningFrontierObserved to
// max(current, txTimeNs) so concurrent historical queries cannot move the
// observed frontier backward.
func (r *Resolver) observeQueryTxTime(txTimeNs int64) {
	for {
		cur := atomic.LoadInt64(&r.pruningFrontierObserved)
		if cur >= txTimeNs {
			return
		}
		if atomic.CompareAndSwapInt64(&r.pruningFrontierObserved, cur, txTimeNs) {
			return
		}
	}
}

// QueryTxTimeFrontier returns the maximum transactionTime.UnixNano() observed
// across AsOf calls on this Resolver, or 0 before any query has run.
func (r *Resolver) QueryTxTimeFrontier() int64 {
	return atomic.LoadInt64(&r.pruningFrontierObserved)
}

// NewResolver creates a new Bitemporal Query Resolver.
// MaxRangeRows == 0 is preserved as the unlimited sentinel (ADR-0024).
func NewResolver(lister S3Lister, downloader S3Downloader, allocator *JemallocAllocator, bucket string, config ResolverConfig) *Resolver {
	if config.MaxL0Files <= 0 {
		config.MaxL0Files = 1000
	}
	if config.MaxRangeRows < 0 {
		config.MaxRangeRows = 0
	}
	return &Resolver{
		lister:     lister,
		downloader: downloader,
		allocator:  allocator,
		bucket:     bucket,
		config:     config,
		liveSource: config.LiveSource,
	}
}

// SetLiveSource attaches or replaces the LiveSource read-your-writes adapter
// after resolver construction (ADR-0032). Passing nil disables live merging.
func (r *Resolver) SetLiveSource(src LiveSource) { r.liveSource = src }

// AsOf resolves the dominant TriTemporalEvent for the given entity at the
// specified (validTime, transactionTime) coordinates.
//
// Tri-Temporal Dominance Relation:
//   - A record R2 dominates R1 for the same entityID if:
//     1. R2.SystemTime > R1.SystemTime (later system assertion supersedes)
//     2. R2.ValidTimeStart <= validTime < R2.ValidTimeEnd (valid time contains query point)
//     3. R2.SystemTime <= transactionTime (system time is within query horizon)
//   - The resolver returns the record with the latest SystemTime that satisfies
//     all three conditions.
//
// Sequential Scan Strategy:
//   - Lists compacted L1 files and uncompacted L0 files under the entity prefix.
//   - Excludes L0 files already superseded by compaction manifests and sorts
//     remaining keys newest-first.
//   - Skips files whose filename firstSys exceeds transactionTime when
//     EnableFirstSysSkip is set, otherwise scans record batches with hash,
//     exact entity ID, and temporal predicates.
//   - Merges live CRDT entries when a LiveSource is wired.
//
// Error Conditions:
//   - ErrEntityNotFound: no matching event exists for the given coordinates.
//   - context.Canceled/DeadlineExceeded: query was cancelled or timed out.
//   - S3/IO errors: propagated with wrapping context.
func (r *Resolver) AsOf(ctx context.Context, entityID string, validTime time.Time, transactionTime time.Time) (*TriTemporalEvent, error) {
	if entityID == "" {
		return nil, fmt.Errorf("query: entityID must not be empty")
	}

	// Compute the 128-bit entity ID hash prefix for Arrow column filtering.
	// This matches the hash computation in MemTable.Write().
	entityIDBytes := unsafe.Slice(unsafe.StringData(entityID), len(entityID))
	fullHash := sha256.Sum256(entityIDBytes)
	var hashPrefix [16]byte
	copy(hashPrefix[:], fullHash[:16])

	// Compute hex-encoded prefix for S3 listing scoping.
	var hexBuf [16]byte
	hex.Encode(hexBuf[:], hashPrefix[:8])
	hexPrefixStr := unsafe.String(&hexBuf[0], 16)
	l0Prefix := "l0/" + hexPrefixStr + "/"
	l1Prefix := "l1/" + hexPrefixStr + "/"

	// Convert query time coordinates to nanoseconds (matching Arrow schema).
	validTimeNs := validTime.UnixNano()
	txTimeNs := transactionTime.UnixNano()

	// Record this query's transaction time into the atomic high-water mark used
	// by L1Compactor.InferHorizon (ADR-0027).
	r.observeQueryTxTime(txTimeNs)

	// List L0 + L1 files from S3.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("query: cancelled before listing: %w", err)
	}

	// Scan both compacted L1 files (uncapped merged history) and the uncompacted
	// L0 tail remaining after manifest supersession (ADR-0019).
	l1Keys, err := r.lister.ListObjects(ctx, r.bucket, l1Prefix, 0)
	if err != nil {
		return nil, fmt.Errorf("query: list L1 objects: %w", err)
	}
	// List all L0 objects before filtering out compacted entries so MaxL0Files
	// caps only the uncompacted tail rather than already-superseded files.
	l0Keys, err := r.lister.ListObjects(ctx, r.bucket, l0Prefix, 0)
	if err != nil {
		return nil, fmt.Errorf("query: list L0 objects: %w", err)
	}

	// If no durable files exist and no LiveSource is configured, return not found
	// immediately; otherwise continue into the live-source merge below.
	if len(l1Keys) == 0 && len(l0Keys) == 0 && r.liveSource == nil {
		return nil, ErrEntityNotFound
	}

	// Load compaction manifests so superseded L0 files can be skipped without
	// missing rows already written to L1 (ADR-0019, ADR-0030). Passing txTimeNs
	// lets loadSupersededL0Keys skip manifests whose firstSys exceeds txTimeNs.
	superseded := r.loadSupersededL0Keys(ctx, l0Prefix, txTimeNs)

	// Retain uncompacted L0 tail keys not listed in any compaction manifest.
	var tailKeys []string
	for _, k := range l0Keys {
		if _, skip := superseded[k]; skip {
			continue
		}
		tailKeys = append(tailKeys, k)
	}

	// Apply MaxL0Files cap to the surviving L0 tail and increment telemetry when
	// truncation occurs (ADR-0018).
	if r.config.MaxL0Files > 0 && len(tailKeys) > r.config.MaxL0Files {
		if telemetry.QueryL0ListCapped != nil {
			telemetry.QueryL0ListCapped.Add(1)
		}
		sort.Strings(tailKeys)
		tailKeys = tailKeys[len(tailKeys)-r.config.MaxL0Files:]
	}

	// Combine L1 and remaining L0 keys, falling back to full L0 listing if
	// manifests marked all L0s superseded while no L1 object was listed.
	scanKeys := make([]string, 0, len(l1Keys)+len(tailKeys))
	scanKeys = append(scanKeys, l1Keys...)
	if len(scanKeys) == 0 && len(tailKeys) == 0 {
		scanKeys = l0Keys
	}
	scanKeys = append(scanKeys, tailKeys...)
	if telemetry.QueryL1FilesScanned != nil {
		telemetry.QueryL1FilesScanned.Add(float64(countPrefix(scanKeys, l1Prefix)))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(scanKeys)))

	// Scan files and apply tri-temporal dominance relation.
	var dominant *TriTemporalEvent
	var dominantSystemTime int64

	for _, key := range scanKeys {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("query: cancelled during scan: %w", err)
		}

		// Skip downloading files whose filename minimum SystemTime strictly
		// exceeds txTimeNs, as every contained row fails Filter 2 (ADR-0029).
		// Unparseable filenames fall back to normal download and scan.
		if r.config.EnableFirstSysSkip {
			if firstSys, ok := parseFirstSysFromKey(key); ok && firstSys > txTimeNs {
				if telemetry.QueryDownloadSkippedFirstSys != nil {
					telemetry.QueryDownloadSkippedFirstSys.Inc()
				}
				continue
			}
		}

		match, sysTime, scanErr := r.scanFile(ctx, key, hashPrefix, entityIDBytes, validTimeNs, txTimeNs)
		if scanErr != nil {
			// Skip unreadable files rather than failing the query across remaining objects.
			continue
		}

		if match != nil && sysTime > dominantSystemTime {
			dominant = match
			dominantSystemTime = sysTime
		}
	}

	// Merge live CRDT entries if configured so recent uncheckpointed inserts
	// compete under Filter 3 and strict > dominance (ADR-0032). Read errors fall
	// back to the durable result rather than failing the query.
	if r.liveSource != nil {
		if telemetry.QueryLiveSourceReads != nil {
			telemetry.QueryLiveSourceReads.Inc()
		}
		lcs, lerr := r.liveSource.LiveRead(ctx, entityID, txTimeNs)
		if lerr == nil {
			for _, le := range lcs {
				// Re-check Filter 2 defensively in case an adapter returns entries
				// with SystemTime > txTimeNs.
				if le.SystemTime > txTimeNs {
					continue
				}
				// Filter 3 (point): validStart <= validTimeNs < validEnd.
				if validTimeNs < le.ValidTimeStart || validTimeNs >= le.ValidTimeEnd {
					continue
				}
				// Use strict > so durable rows win ties at identical SystemTime.
				if le.SystemTime > dominantSystemTime {
					dominant = &TriTemporalEvent{
						EntityID:       entityID,
						SystemTime:     le.SystemTime,
						ValidTimeStart: le.ValidTimeStart,
						ValidTimeEnd:   le.ValidTimeEnd,
						AssertionTime:  le.AssertionTime,
						H3Index:        le.H3Index,
						Payload:        le.Payload,
						PayloadDigest:  le.PayloadDigest,
					}
					dominantSystemTime = le.SystemTime
				}
			}
		}
	}

	if dominant == nil {
		return nil, ErrEntityNotFound
	}

	return dominant, nil
}

// Range (ADR-0024) resolves every durable and live row for entityID whose
// valid-time interval intersects [validTimeLo, validTimeHi) and whose
// SystemTime <= transactionTime, returning rows sorted by ValidTimeStart
// ascending along with a truncation flag when MaxRangeRows is reached.
//
// A row R matches iff:
//   - R.ValidTimeStart < validTimeHi and R.ValidTimeEnd > validTimeLo
//   - R.SystemTime <= transactionTime
//   - R's entity hash and exact entity ID match entityID
//
// Returns ErrEntityNotFound if validTimeHi <= validTimeLo or no rows match.
func (r *Resolver) Range(ctx context.Context, entityID string, validTimeLo, validTimeHi time.Time, transactionTime time.Time) ([]*TriTemporalEvent, bool, error) {
	if entityID == "" {
		return nil, false, fmt.Errorf("query: entityID must not be empty")
	}
	if !validTimeHi.After(validTimeLo) {
		return nil, false, ErrEntityNotFound
	}

	entityIDBytes := unsafe.Slice(unsafe.StringData(entityID), len(entityID))
	fullHash := sha256.Sum256(entityIDBytes)
	var hashPrefix [16]byte
	copy(hashPrefix[:], fullHash[:16])

	var hexBuf [16]byte
	hex.Encode(hexBuf[:], hashPrefix[:8])
	hexPrefixStr := unsafe.String(&hexBuf[0], 16)
	l0Prefix := "l0/" + hexPrefixStr + "/"
	l1Prefix := "l1/" + hexPrefixStr + "/"

	validLoNs := validTimeLo.UnixNano()
	validHiNs := validTimeHi.UnixNano()
	txTimeNs := transactionTime.UnixNano()

	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("query: cancelled before listing: %w", err)
	}
	l1Keys, err := r.lister.ListObjects(ctx, r.bucket, l1Prefix, 0)
	if err != nil {
		return nil, false, fmt.Errorf("query: list L1 objects: %w", err)
	}
	l0Keys, err := r.lister.ListObjects(ctx, r.bucket, l0Prefix, 0)
	if err != nil {
		return nil, false, fmt.Errorf("query: list L0 objects: %w", err)
	}
	// Match AsOf's live-source guard: only return ErrEntityNotFound early when
	// both durable tiers are empty and no LiveSource is configured.
	if len(l1Keys) == 0 && len(l0Keys) == 0 && r.liveSource == nil {
		return nil, false, ErrEntityNotFound
	}

	superseded := r.loadSupersededL0Keys(ctx, l0Prefix, txTimeNs)
	var tailKeys []string
	for _, k := range l0Keys {
		if _, skip := superseded[k]; skip {
			continue
		}
		tailKeys = append(tailKeys, k)
	}
	if r.config.MaxL0Files > 0 && len(tailKeys) > r.config.MaxL0Files {
		if telemetry.QueryL0ListCapped != nil {
			telemetry.QueryL0ListCapped.Add(1)
		}
		sort.Strings(tailKeys)
		tailKeys = tailKeys[len(tailKeys)-r.config.MaxL0Files:]
	}
	scanKeys := make([]string, 0, len(l1Keys)+len(tailKeys))
	scanKeys = append(scanKeys, l1Keys...)
	if len(scanKeys) == 0 && len(tailKeys) == 0 {
		scanKeys = l0Keys
	}
	scanKeys = append(scanKeys, tailKeys...)
	if telemetry.QueryL1FilesScanned != nil {
		telemetry.QueryL1FilesScanned.Add(float64(countPrefix(scanKeys, l1Prefix)))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(scanKeys)))

	cap := r.config.MaxRangeRows
	var collected []*TriTemporalEvent
	if cap > 0 {
		collected = make([]*TriTemporalEvent, 0, min(cap, 64))
	} else {
		collected = make([]*TriTemporalEvent, 0, 64)
	}
	truncated := false
	for _, key := range scanKeys {
		if err := ctx.Err(); err != nil {
			return nil, false, fmt.Errorf("query: cancelled during scan: %w", err)
		}
		if r.config.EnableFirstSysSkip {
			if firstSys, ok := parseFirstSysFromKey(key); ok && firstSys > txTimeNs {
				if telemetry.QueryDownloadSkippedFirstSys != nil {
					telemetry.QueryDownloadSkippedFirstSys.Inc()
				}
				continue
			}
		}
		rows, stop, scanErr := r.scanWindowFile(ctx, key, hashPrefix, entityIDBytes, validLoNs, validHiNs, txTimeNs, collected, cap)
		if scanErr != nil {
			// Skip unreadable files so one bad object does not fail remaining scans.
			continue
		}
		collected = rows
		if stop {
			truncated = true
			break
		}
	}

	// Merge live CRDT entries filtered by [validLoNs, validHiNs), deduplicating
	// checkpointed rows by (SystemTime, PayloadDigest) while honoring MaxRangeRows
	// (ADR-0032).
	if r.liveSource != nil {
		if telemetry.QueryLiveSourceReads != nil {
			telemetry.QueryLiveSourceReads.Inc()
		}
		lcs, lerr := r.liveSource.LiveRead(ctx, entityID, txTimeNs)
		if lerr == nil && len(lcs) > 0 {
			seen := make(map[liveRowKey]struct{}, len(collected))
			for _, d := range collected {
				seen[liveRowKey{sys: d.SystemTime, digest: d.PayloadDigest}] = struct{}{}
			}
			for _, le := range lcs {
				if le.SystemTime > txTimeNs {
					continue
				}
				if le.ValidTimeStart >= validHiNs || le.ValidTimeEnd <= validLoNs {
					continue
				}
				key := liveRowKey{sys: le.SystemTime, digest: le.PayloadDigest}
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				if cap > 0 && len(collected) >= cap {
					truncated = true
					break
				}
				collected = append(collected, &TriTemporalEvent{
					EntityID:       entityID,
					SystemTime:     le.SystemTime,
					ValidTimeStart: le.ValidTimeStart,
					ValidTimeEnd:   le.ValidTimeEnd,
					AssertionTime:  le.AssertionTime,
					H3Index:        le.H3Index,
					Payload:        le.Payload,
					PayloadDigest:  le.PayloadDigest,
				})
			}
		}
	}

	if len(collected) == 0 {
		return nil, false, ErrEntityNotFound
	}

	sort.SliceStable(collected, func(i, j int) bool {
		return collected[i].ValidTimeStart < collected[j].ValidTimeStart
	})

	return collected, truncated, nil
}

// CoalesceRange (ADR-0024) collapses raw intersecting Range results by
// ValidTimeStart, retaining the entry with the greatest SystemTime at each
// start timestamp in ascending ValidTimeStart order.
func CoalesceRange(rows []*TriTemporalEvent) []*TriTemporalEvent {
	if len(rows) <= 1 {
		return rows
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].ValidTimeStart != rows[j].ValidTimeStart {
			return rows[i].ValidTimeStart < rows[j].ValidTimeStart
		}
		return rows[i].SystemTime > rows[j].SystemTime
	})
	out := make([]*TriTemporalEvent, 0, len(rows))
	var lastStart int64
	first := true
	for _, r := range rows {
		if first || r.ValidTimeStart != lastStart {
			out = append(out, r)
			lastStart = r.ValidTimeStart
			first = false
		}
	}
	return out
}

// scanFile opens a single L0 or L1 Arrow IPC file and scans for matching records.
// Returns the best matching event within this file (latest SystemTime that
// satisfies the temporal predicates) and its SystemTime for dominance comparison.
//
// Zero-Copy Strategy:
//   - Uses ipc.NewFileReader to read Arrow IPC file format.
//   - Record batches are accessed via typed column accessors (no deserialization).
//   - Entity ID comparison uses raw byte slices (no string conversion).
//   - The returned TriTemporalEvent is constructed from Arrow column values.
func (r *Resolver) scanFile(
	ctx context.Context,
	key string,
	hashPrefix [16]byte,
	entityIDBytes []byte,
	validTimeNs int64,
	txTimeNs int64,
) (*TriTemporalEvent, int64, error) {

	// Download the Arrow IPC file from S3.
	rc, err := r.downloader.Download(ctx, r.bucket, key)
	if err != nil {
		return nil, 0, fmt.Errorf("download %s: %w", key, err)
	}
	defer func() { _ = rc.Close() }()

	// Use jemalloc-backed buffer to keep it off Go heap.
	var alloc = memory.DefaultAllocator
	if r.allocator != nil {
		alloc = r.allocator
	}

	// Dynamically grow the off-heap buffer to prevent OOM on large files and
	// avoid massive memory churn for small files.
	capacity := 32 * 1024 // 32KB initial
	dataBuf := alloc.Allocate(capacity)
	defer func() {
		if dataBuf != nil {
			alloc.Free(dataBuf)
		}
	}()

	var n int
	for {
		if n == capacity {
			capacity *= 2
			dataBuf = alloc.Reallocate(capacity, dataBuf)
		}
		readBytes, err := rc.Read(dataBuf[n:])
		n += readBytes
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read %s: %w", key, err)
		}
	}

	if n == 0 {
		return nil, 0, nil
	}

	reader, err := ipc.NewFileReader(bytes.NewReader(dataBuf[:n]), ipc.WithAllocator(alloc))
	if err != nil {
		return nil, 0, fmt.Errorf("open arrow reader %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	// Validate schema compatibility.
	schema := reader.Schema()
	if schema.NumFields() != ArrowSchema.NumFields() {
		return nil, 0, fmt.Errorf("schema mismatch in %s: expected %d fields, got %d", key, ArrowSchema.NumFields(), schema.NumFields())
	}

	// Per-field type validation
	for i := 0; i < schema.NumFields(); i++ {
		if !arrow.TypeEqual(schema.Field(i).Type, ArrowSchema.Field(i).Type) {
			return nil, 0, fmt.Errorf("type mismatch at field %d in %s: expected %s, got %s",
				i, key, ArrowSchema.Field(i).Type, schema.Field(i).Type)
		}
	}

	var bestMatch *TriTemporalEvent
	var bestSystemTime int64

	// Iterate over all record batches in the file.
	numRecords := reader.NumRecords()
	for i := 0; i < numRecords; i++ {
		if err := ctx.Err(); err != nil {
			return bestMatch, bestSystemTime, nil // Return best so far on cancellation
		}

		rec, err := reader.Record(i)
		if err != nil {
			continue // Skip corrupted record batch
		}

		match, sysTime := r.scanRecordBatch(rec, hashPrefix, entityIDBytes, validTimeNs, txTimeNs, bestSystemTime)
		if match != nil && sysTime > bestSystemTime {
			bestMatch = match
			bestSystemTime = sysTime
		}
	}

	return bestMatch, bestSystemTime, nil
}

// scanWindowFile (ADR-0024) scans one Arrow IPC file for every matching record
// whose valid-time interval intersects [validLoNs, validHiNs) at txTimeNs,
// stopping early and setting stop=true if MaxRangeRows is reached.
func (r *Resolver) scanWindowFile(
	ctx context.Context,
	key string,
	hashPrefix [16]byte,
	entityIDBytes []byte,
	validLoNs int64,
	validHiNs int64,
	txTimeNs int64,
	collected []*TriTemporalEvent,
	cap int,
) ([]*TriTemporalEvent, bool, error) {
	rc, err := r.downloader.Download(ctx, r.bucket, key)
	if err != nil {
		return collected, false, fmt.Errorf("download %s: %w", key, err)
	}
	defer func() { _ = rc.Close() }()

	// Use jemalloc-backed buffer to keep file payloads off the Go heap.
	var alloc = memory.DefaultAllocator
	if r.allocator != nil {
		alloc = r.allocator
	}
	capacity := 32 * 1024
	dataBuf := alloc.Allocate(capacity)
	defer func() {
		if dataBuf != nil {
			alloc.Free(dataBuf)
		}
	}()

	var n int
	for {
		if n == capacity {
			capacity *= 2
			dataBuf = alloc.Reallocate(capacity, dataBuf)
		}
		readBytes, err := rc.Read(dataBuf[n:])
		n += readBytes
		if err == io.EOF {
			break
		}
		if err != nil {
			return collected, false, fmt.Errorf("read %s: %w", key, err)
		}
	}

	if n == 0 {
		return collected, false, nil
	}

	reader, err := ipc.NewFileReader(bytes.NewReader(dataBuf[:n]), ipc.WithAllocator(alloc))
	if err != nil {
		return collected, false, fmt.Errorf("open arrow reader %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	schema := reader.Schema()
	if schema.NumFields() != ArrowSchema.NumFields() {
		return collected, false, fmt.Errorf("schema mismatch in %s: expected %d fields, got %d", key, ArrowSchema.NumFields(), schema.NumFields())
	}
	for i := 0; i < schema.NumFields(); i++ {
		if !arrow.TypeEqual(schema.Field(i).Type, ArrowSchema.Field(i).Type) {
			return collected, false, fmt.Errorf("type mismatch at field %d in %s: expected %s, got %s",
				i, key, ArrowSchema.Field(i).Type, schema.Field(i).Type)
		}
	}

	stop := false
	numRecords := reader.NumRecords()
	for i := 0; i < numRecords; i++ {
		if err := ctx.Err(); err != nil {
			return collected, stop, nil
		}
		rec, err := reader.Record(i)
		if err != nil {
			continue
		}
		collected, stop = r.scanWindowRecordBatch(rec, hashPrefix, entityIDBytes, validLoNs, validHiNs, txTimeNs, collected, cap)
		if stop {
			return collected, stop, nil
		}
	}
	return collected, stop, nil
}

// scanRecordBatch scans a single Arrow record batch for the latest matching
// event at validTimeNs and txTimeNs, deferring event allocation until after
// the loop completes.
//
// Column layout (ArrowSchema in l0_flusher.go), 9 columns [0..8]:
//
//	[0] entity_id_hash   — FixedSizeBinary(16)
//	[1] system_time      — Timestamp(ns, UTC)
//	[2] valid_time_start — Timestamp(ns, UTC)
//	[3] valid_time_end   — Timestamp(ns, UTC)
//	[4] assertion_time   — Timestamp(ns, UTC)
//	[5] h3_index         — Uint64
//	[6] payload_digest   — FixedSizeBinary(32)
//	[7] entity_id        — LargeBinary
//	[8] payload          — LargeBinary
//
// Filtering Strategy (columnar predicate pushdown):
//  1. Hash prefix filter on column[0] — eliminates >99.99% of rows.
//  2. Full entity ID verification on column[7] — eliminates 128-bit hash collisions.
//  3. SystemTime filter: column[1] <= txTimeNs.
//  4. ValidTime range filter: column[2] <= validTimeNs < column[3].
//  5. Dominance selection: max(SystemTime) among qualifying records.
func (r *Resolver) scanRecordBatch(
	rec arrow.Record,
	hashPrefix [16]byte,
	entityIDBytes []byte,
	validTimeNs int64,
	txTimeNs int64,
	currentBestSysTime int64,
) (*TriTemporalEvent, int64) {

	nRows := int(rec.NumRows())
	if nRows == 0 {
		return nil, 0
	}

	// Type-assert columns once (amortized over all rows).
	hashCol := rec.Column(0).(*array.FixedSizeBinary)
	sysTimeCol := rec.Column(1).(*array.Timestamp)
	validStartCol := rec.Column(2).(*array.Timestamp)
	validEndCol := rec.Column(3).(*array.Timestamp)
	assertTimeCol := rec.Column(4).(*array.Timestamp)
	h3Col := rec.Column(5).(*array.Uint64)
	payloadDigestCol := rec.Column(6).(*array.FixedSizeBinary)
	entityIDCol := rec.Column(7).(*array.LargeBinary)
	payloadCol := rec.Column(8).(*array.LargeBinary)

	var bestMatch *TriTemporalEvent
	var bestSysTime int64
	bestRowIndex := -1

	for row := 0; row < nRows; row++ {
		// Filter 1: Hash prefix match (128-bit, O(1) memory comparison).
		rowHash := hashCol.Value(row)
		if !bytes.Equal(rowHash, hashPrefix[:]) {
			continue
		}

		// Filter 2: SystemTime <= transactionTime (record must be visible at query time).
		sysTimeVal := int64(sysTimeCol.Value(row))
		if sysTimeVal > txTimeNs {
			continue
		}

		// Filter 3: ValidTime range contains query point.
		// validTimeStart <= validTimeNs < validTimeEnd
		validStart := int64(validStartCol.Value(row))
		validEnd := int64(validEndCol.Value(row))
		if validTimeNs < validStart || validTimeNs >= validEnd {
			continue
		}

		// Filter 4: Full entity ID verification (prevents hash collision false positives).
		// This is mandatory. Without this check, a 128-bit hash collision would
		// return data for the wrong entity.
		rowEntityID := entityIDCol.Value(row)
		if !bytes.Equal(rowEntityID, entityIDBytes) {
			continue
		}

		// Dominance Selection: Latest SystemTime wins.
		if sysTimeVal <= currentBestSysTime || sysTimeVal <= bestSysTime {
			continue
		}

		// Track index, do not allocate here
		bestRowIndex = row
		bestSysTime = sysTimeVal
	}

	// Single allocation after loop exits
	if bestRowIndex >= 0 {
		row := bestRowIndex
		assertTimeVal := int64(assertTimeCol.Value(row))
		h3Val := h3Col.Value(row)
		payloadBytes := payloadCol.Value(row)
		rowEntityID := entityIDCol.Value(row)

		payloadCopy := make([]byte, len(payloadBytes))
		copy(payloadCopy, payloadBytes)

		entityIDCopy := make([]byte, len(rowEntityID))
		copy(entityIDCopy, rowEntityID)

		payloadDigestBytes := payloadDigestCol.Value(row)
		var pd [32]byte
		copy(pd[:], payloadDigestBytes)

		bestMatch = &TriTemporalEvent{
			EntityID:       unsafe.String(unsafe.SliceData(entityIDCopy), len(entityIDCopy)),
			SystemTime:     bestSysTime,
			ValidTimeStart: int64(validStartCol.Value(row)),
			ValidTimeEnd:   int64(validEndCol.Value(row)),
			AssertionTime:  assertTimeVal,
			H3Index:        h3Val,
			Payload:        payloadCopy,
			PayloadDigest:  pd,
		}
	}

	return bestMatch, bestSysTime
}

// scanWindowRecordBatch (ADR-0024) scans one Arrow record batch and appends
// every row intersecting [validLoNs, validHiNs) with SystemTime <= txTimeNs
// until MaxRangeRows (cap > 0) is reached.
func (r *Resolver) scanWindowRecordBatch(
	rec arrow.Record,
	hashPrefix [16]byte,
	entityIDBytes []byte,
	validLoNs int64,
	validHiNs int64,
	txTimeNs int64,
	collected []*TriTemporalEvent,
	cap int,
) ([]*TriTemporalEvent, bool) {
	nRows := int(rec.NumRows())
	if nRows == 0 {
		return collected, false
	}
	out := collected
	stop := false

	hashCol := rec.Column(0).(*array.FixedSizeBinary)
	sysTimeCol := rec.Column(1).(*array.Timestamp)
	validStartCol := rec.Column(2).(*array.Timestamp)
	validEndCol := rec.Column(3).(*array.Timestamp)
	assertTimeCol := rec.Column(4).(*array.Timestamp)
	h3Col := rec.Column(5).(*array.Uint64)
	payloadDigestCol := rec.Column(6).(*array.FixedSizeBinary)
	entityIDCol := rec.Column(7).(*array.LargeBinary)
	payloadCol := rec.Column(8).(*array.LargeBinary)

	for row := 0; row < nRows; row++ {
		// Filter 1: 128-bit hash prefix match.
		rowHash := hashCol.Value(row)
		if !bytes.Equal(rowHash, hashPrefix[:]) {
			continue
		}

		// Filter 2: SystemTime <= transactionTime.
		sysTimeVal := int64(sysTimeCol.Value(row))
		if sysTimeVal > txTimeNs {
			continue
		}

		// Filter 3 (interval intersection with half-open [validLoNs, validHiNs)):
		// exclude rows ending at or before validLoNs or starting at or after validHiNs.
		validStart := int64(validStartCol.Value(row))
		validEnd := int64(validEndCol.Value(row))
		if validStart >= validHiNs || validEnd <= validLoNs {
			continue
		}

		// Filter 4: exact entity ID comparison (128-bit collision guard).
		rowEntityID := entityIDCol.Value(row)
		if !bytes.Equal(rowEntityID, entityIDBytes) {
			continue
		}

		// Enforce MaxRangeRows cap before copying row bytes.
		if cap > 0 && len(out) >= cap {
			stop = true
			return out, stop
		}

		assertTimeVal := int64(assertTimeCol.Value(row))
		h3Val := h3Col.Value(row)
		payloadBytes := payloadCol.Value(row)

		payloadCopy := make([]byte, len(payloadBytes))
		copy(payloadCopy, payloadBytes)

		entityIDCopy := make([]byte, len(rowEntityID))
		copy(entityIDCopy, rowEntityID)

		payloadDigestBytes := payloadDigestCol.Value(row)
		var pd [32]byte
		copy(pd[:], payloadDigestBytes)

		out = append(out, &TriTemporalEvent{
			EntityID:       unsafe.String(unsafe.SliceData(entityIDCopy), len(entityIDCopy)),
			SystemTime:     sysTimeVal,
			ValidTimeStart: validStart,
			ValidTimeEnd:   validEnd,
			AssertionTime:  assertTimeVal,
			H3Index:        h3Val,
			Payload:        payloadCopy,
			PayloadDigest:  pd,
		})
	}

	return out, stop
}

// loadSupersededL0Keys (ADR-0019, ADR-0030) lists compaction manifests under
// compaction/{hex(hash8)}/ derived from l0Prefix and returns the union of
// superseded L0 keys. When EnableFirstSysSkip is enabled, manifests whose
// filename firstSys exceeds txTimeNs are skipped because both their L1 target
// and every listed L0 file fail Filter 2 and are already skipped by the scan
// loop. Unreadable or unparseable manifests fall back to normal download.
func (r *Resolver) loadSupersededL0Keys(ctx context.Context, l0Prefix string, txTimeNs int64) map[string]struct{} {
	if !strings.HasPrefix(l0Prefix, "l0/") {
		return nil
	}
	manifestsPrefix := "compaction/" + l0Prefix[len("l0/"):]
	keys, err := r.lister.ListObjects(ctx, r.bucket, manifestsPrefix, 0)
	if err != nil {
		return nil
	}
	if len(keys) == 0 {
		return nil
	}
	superseded := make(map[string]struct{}, len(keys))
	for _, mk := range keys {
		if r.config.EnableFirstSysSkip {
			if firstSys, ok := parseFirstSysFromKey(mk); ok && firstSys > txTimeNs {
				if telemetry.QueryManifestSkippedFirstSys != nil {
					telemetry.QueryManifestSkippedFirstSys.Inc()
				}
				continue
			}
		}
		rc, derr := r.downloader.Download(ctx, r.bucket, mk)
		if derr != nil {
			continue
		}
		body, _ := readManifestBody(rc) // Single-grow read (ADR-0031)
		_ = rc.Close()
		_, l0ks := ParseManifest(body)
		for _, l0k := range l0ks {
			superseded[l0k] = struct{}{}
		}
	}
	return superseded
}

// countPrefix returns the number of keys sharing the prefix without issuing a
// second storage listing call.
func countPrefix(keys []string, prefix string) int {
	n := 0
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// parseFirstSysFromKey extracts the non-negative int64 timestamp segment from
// object keys formatted as <prefix>/<hex8>/<int64-decimal>.<ext> (covering both
// .arrow data files and .manifest files; ADR-0029, ADR-0030). It runs with zero
// heap allocations using strings.LastIndexByte and strconv.ParseInt and returns
// (0, false) on any malformed or negative suffix so callers fall back to full
// download.
func parseFirstSysFromKey(key string) (int64, bool) {
	slash := strings.LastIndexByte(key, '/')
	if slash < 0 || slash == len(key)-1 {
		return 0, false
	}
	tail := key[slash+1:]
	dot := strings.LastIndexByte(tail, '.')
	if dot <= 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(tail[:dot], 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// liveRowKey deduplicates live CRDT entries against already-scanned durable
// rows during Resolver.Range by (SystemTime, PayloadDigest) (ADR-0032).
type liveRowKey struct {
	sys    int64
	digest [32]byte
}

// ErrEntityNotFound is returned when no matching event exists for the given
// (entityID, validTime, transactionTime) coordinates.
var ErrEntityNotFound = fmt.Errorf("query: entity not found at specified temporal coordinates")

// Ensure unused imports don't cause compilation errors.
var _ = binary.BigEndian

// SecondaryIndexSource supplies candidate entity IDs for cross-entity queries
// without requiring internal/database to import internal/index.
type SecondaryIndexSource interface {
	// CandidatesByH3 returns entities whose current index placement matches
	// cell (or tie-retained cells), over-approximating for per-row trimming.
	CandidatesByH3(cell uint64) []string
	// CandidatesBySysTime returns entities whose current SystemTime bucket is >=
	// the bucket containing afterT, over-approximating boundary buckets.
	CandidatesBySysTime(afterT int64) []string
	// IndexHealth reports distinct indexed entities, tie drop count, ceiling
	// drop count, and whether the index has tripped its entity ceiling.
	IndexHealth() (entities int, tieDrops uint64, ceilingDrops uint64, degraded bool)
}

// SecondaryIndexDisclosure records candidate counts, loss counters, truncation
// status, and the current-state contract flag returned with cross-entity queries.
type SecondaryIndexDisclosure struct {
	Candidates      int
	IndexedEntities int
	TieDrops        uint64
	CeilingDrops    uint64
	Truncated       bool
	// CurrentState is always true because the secondary index tracks current
	// entity placements rather than full historical cell memberships.
	CurrentState bool
}

// ErrSecondaryIndexDisabled is returned when cross-entity query methods are
// invoked without a SecondaryIndexSource configured.
var ErrSecondaryIndexDisabled = fmt.Errorf("query: secondary index disabled (no candidate source wired)")

// ErrSecondaryIndexDegraded is returned when the secondary index has tripped
// its entity ceiling and cannot guarantee complete candidate coverage.
var ErrSecondaryIndexDegraded = fmt.Errorf("query: secondary index degraded (memory ceiling exceeded — the candidate set is incomplete; raise --secondary-index-max-entities or restart the node)")

// SetSecondaryIndexSource attaches a SecondaryIndexSource to the Resolver.
// Passing nil leaves cross-entity queries disabled with ErrSecondaryIndexDisabled.
func (r *Resolver) SetSecondaryIndexSource(src SecondaryIndexSource) { r.secondaryIndex = src }

// QueryByH3 resolves entities whose current secondary-index placement includes
// cell and whose AsOf event at (validTime, transactionTime) matches H3Index ==
// cell, capping results at MaxRangeRows (ADR-0058).
//
// Because the secondary index stores current placements rather than historical
// cell memberships (CurrentState=true), historical queries after an entity
// moves can miss that entity while never returning false positives. Candidates
// resolving to ErrEntityNotFound are skipped; any other AsOf error aborts the
// query immediately.
func (r *Resolver) QueryByH3(ctx context.Context, cell uint64, validTime time.Time, transactionTime time.Time) ([]*TriTemporalEvent, SecondaryIndexDisclosure, error) {
	if r.secondaryIndex == nil {
		return nil, SecondaryIndexDisclosure{}, ErrSecondaryIndexDisabled
	}
	entities, tieDrops, ceilingDrops, degraded := r.secondaryIndex.IndexHealth()
	disc := SecondaryIndexDisclosure{IndexedEntities: entities, TieDrops: tieDrops, CeilingDrops: ceilingDrops, CurrentState: true}
	if degraded {
		return nil, disc, ErrSecondaryIndexDegraded
	}
	cands := r.secondaryIndex.CandidatesByH3(cell)
	disc.Candidates = len(cands)
	rows := make([]*TriTemporalEvent, 0, len(cands))
	for _, cand := range cands {
		if r.config.MaxRangeRows > 0 && len(rows) >= r.config.MaxRangeRows {
			disc.Truncated = true
			break
		}
		ev, err := r.AsOf(ctx, cand, validTime, transactionTime)
		if err != nil {
			if errors.Is(err, ErrEntityNotFound) {
				continue
			}
			return nil, disc, err
		}
		if ev.H3Index != cell {
			continue
		}
		rows = append(rows, ev)
	}
	return rows, disc, nil
}

// QueryBySystemTime resolves entities whose AsOf event at (validTime,
// transactionTime) has SystemTime >= after, trimmed from the secondary index's
// SystemTime bucket candidates and capped at MaxRangeRows.
func (r *Resolver) QueryBySystemTime(ctx context.Context, after time.Time, validTime time.Time, transactionTime time.Time) ([]*TriTemporalEvent, SecondaryIndexDisclosure, error) {
	if r.secondaryIndex == nil {
		return nil, SecondaryIndexDisclosure{}, ErrSecondaryIndexDisabled
	}
	entities, tieDrops, ceilingDrops, degraded := r.secondaryIndex.IndexHealth()
	disc := SecondaryIndexDisclosure{IndexedEntities: entities, TieDrops: tieDrops, CeilingDrops: ceilingDrops, CurrentState: true}
	if degraded {
		return nil, disc, ErrSecondaryIndexDegraded
	}
	afterNs := after.UnixNano()
	cands := r.secondaryIndex.CandidatesBySysTime(afterNs)
	disc.Candidates = len(cands)
	rows := make([]*TriTemporalEvent, 0, len(cands))
	for _, cand := range cands {
		if r.config.MaxRangeRows > 0 && len(rows) >= r.config.MaxRangeRows {
			disc.Truncated = true
			break
		}
		ev, err := r.AsOf(ctx, cand, validTime, transactionTime)
		if err != nil {
			if errors.Is(err, ErrEntityNotFound) {
				continue
			}
			return nil, disc, err
		}
		if ev.SystemTime < afterNs {
			continue
		}
		rows = append(rows, ev)
	}
	return rows, disc, nil
}
