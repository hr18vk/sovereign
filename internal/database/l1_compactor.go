// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Package database implements per-entity L0-to-L1 compaction (ADR-0019).
//
// AsOf originally scanned only the newest MaxL0Files L0 files per entity,
// making older files invisible to historical queries. A background compaction job
// merges an entity's L0 files into a sorted L1 file so AsOf scans the L1 plus
// only the uncompacted L0 tail.
//
// By default the merge preserves all rows (EnableDominancePruning=false).
// Dominance pruning requires an explicit retention floor because dropping
// superseded rows without one corrupts historical transaction-time queries.
// The EpochCompactor stub in compactor.go remains unused.
//
// Compaction reads L0 files and writes L1 files plus a manifest under
// compaction/{hash8}/{sysNs}.manifest so queries can skip superseded L0 keys.
// Source L0 files stay on disk until the L0 reaper reclaims them.
package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/apache/arrow/go/v17/arrow"
	"github.com/apache/arrow/go/v17/arrow/array"
	"github.com/apache/arrow/go/v17/arrow/ipc"
	"github.com/apache/arrow/go/v17/arrow/memory"
	"github.com/hr18vk/sovereign/internal/telemetry"
)

// CompactionConfig configures the per-entity L0→L1 compaction.
type CompactionConfig struct {
	// L0FilesPerEntityTrigger is the per-entity L0 file count that triggers a
	// compaction job for that entity. The compaction merges the entity's L0
	// files into one sorted L1 file. Default: 64.
	L0FilesPerEntityTrigger int
	// MaxL1FilesPerEntity bounds the L1 files per entity if multi-L1 tiering
	// is introduced later. The current compactor writes a single L1 file per
	// entity covering the merged history. Default: 4.
	MaxL1FilesPerEntity int

	// EnableDominancePruning (ADR-0020) enables superseded-row pruning during
	// compaction. False (the default) retains every row verbatim. Pruning
	// requires a positive PruningHorizonInt64Ns; otherwise NewL1Compactor
	// coerces back to retain-all and logs a warning.
	EnableDominancePruning bool
	// PruningHorizonInt64Ns (ADR-0020) is the transaction-time GC floor T_gc
	// below which the caller guarantees no live AS-OF query will arrive. A row
	// R is dropped only when a retained row R' satisfies: (C1) sysTime(R') >
	// sysTime(R), (C2) [vs', ve') contains [vs, ve), and (C3) sysTime(R') <= T_gc.
	PruningHorizonInt64Ns int64
	// PruneBackoffInt64Ns (ADR-0027) sets how far behind the observed
	// live-query txTime frontier the inferred horizon sits:
	// effective = max(operatorFloor, observedFrontier - backoff). A value <= 0
	// tracks the observed frontier directly up to the operator floor.
	PruneBackoffInt64Ns int64
}

// DefaultCompactionConfig returns a production-safe CompactionConfig.
//
// Dominance pruning defaults to false so L0-to-L1 compaction preserves all rows
// unless the operator explicitly enables pruning with a retention floor.
// PruneBackoffInt64Ns defaults to 0 here; cmd/sovereign-node configures a
// 5-minute backoff when horizon inference is enabled.
func DefaultCompactionConfig() CompactionConfig {
	return CompactionConfig{
		L0FilesPerEntityTrigger: 64,
		MaxL1FilesPerEntity:     4,
	}
}

// L1Compactor merges per-entity L0 Arrow IPC files into a sorted L1 file (ADR-0019).
//
// Each compaction lists all L0 objects under l0/{hex(hash8)}/, reads and filters
// rows matching the entity, sorts by composite key (entity hash, system time,
// valid time start, assertion time), optionally applies dominance pruning when
// enabled with a positive horizon, writes l1/{hex(hash8)}/{firstSysNs}.arrow,
// and records the merged L0 keys in compaction/{hex(hash8)}/{firstSysNs}.manifest.
type L1Compactor struct {
	lister     S3Lister
	downloader S3Downloader
	uploader   S3Uploader
	allocator  *JemallocAllocator
	bucket     string
	cfg        CompactionConfig

	// inferrer holds transaction-time GC floor inference state (ADR-0027).
	// Between compaction sweeps, InferHorizon reads QueryTxTimeFrontier and
	// monotonically advances cfg.PruningHorizonInt64Ns up to
	// max(operatorFloor, observedFrontier - backoff).
	inferrer horizonInferrer
}

// horizonInferrer holds the immutable operator floor and backoff window used by
// InferHorizon and EffectiveHorizon (ADR-0027).
type horizonInferrer struct {
	operatorFloor int64
	backoffNs     int64
}

// NewL1Compactor creates a new per-entity L0->L1 compactor.
//
// If EnableDominancePruning is true without a positive PruningHorizonInt64Ns
// (ADR-0020), construction logs a warning and resets EnableDominancePruning to
// false so rows are preserved rather than pruned without a retention floor.
func NewL1Compactor(lister S3Lister, downloader S3Downloader, uploader S3Uploader, allocator *JemallocAllocator, bucket string, cfg CompactionConfig) *L1Compactor {
	if cfg.L0FilesPerEntityTrigger <= 0 {
		cfg.L0FilesPerEntityTrigger = 64
	}
	if cfg.MaxL1FilesPerEntity <= 0 {
		cfg.MaxL1FilesPerEntity = 4
	}
	operatorFloor := cfg.PruningHorizonInt64Ns
	backoffNs := cfg.PruneBackoffInt64Ns
	if cfg.EnableDominancePruning && cfg.PruningHorizonInt64Ns <= 0 {
		log.Printf("[l1_compactor] WARN: EnableDominancePruning=true with PruningHorizonInt64Ns=%d (<=0) — horizon-less dominance pruning is unsafe; coercing to retain all rows (EnableDominancePruning=false). Set --compaction-prune-horizon-ns to a positive transaction-time GC horizon to enable pruning.",
			cfg.PruningHorizonInt64Ns)
		cfg.EnableDominancePruning = false
		cfg.PruningHorizonInt64Ns = 0
		operatorFloor = 0
	}
	return &L1Compactor{
		lister:     lister,
		downloader: downloader,
		uploader:   uploader,
		allocator:  allocator,
		bucket:     bucket,
		cfg:        cfg,
		inferrer: horizonInferrer{
			operatorFloor: operatorFloor,
			backoffNs:     backoffNs,
		},
	}
}

// Config returns the compactor's configuration (read-only surface for the
// scheduler / tests).
func (c *L1Compactor) Config() CompactionConfig { return c.cfg }

// L0FilesPerEntityTrigger reports the per-entity L0 file count that triggers a
// compaction (convenience for the scheduler).
func (c *L1Compactor) L0FilesPerEntityTrigger() int { return c.cfg.L0FilesPerEntityTrigger }

// InferHorizon (ADR-0027) reads the Resolver's observed live-query txTime
// frontier, computes max(operatorFloor, observedFrontier - backoff), advances
// the compactor's horizon monotonically, and updates the Prometheus gauges. A
// nil resolver leaves the inferrer inactive. Not safe for concurrent calls with
// Compaction; callers invoke it between sweeps on the scheduler goroutine.
func (c *L1Compactor) InferHorizon(resolver *Resolver) {
	if resolver == nil {
		return
	}
	observedFrontier := resolver.QueryTxTimeFrontier()
	effective := c.EffectiveHorizon(observedFrontier)
	applied := c.SetInferredHorizon(effective)
	if telemetry.QueryTxTimeHighWaterMark != nil {
		telemetry.QueryTxTimeHighWaterMark.Set(float64(observedFrontier))
	}
	if telemetry.PruningHorizonEffective != nil {
		telemetry.PruningHorizonEffective.Set(float64(applied))
	}
}

// EffectiveHorizon (ADR-0027) returns max(operatorFloor, observedFrontier - backoffNs),
// ensuring inferred horizons never drop below the operator-configured floor.
func (c *L1Compactor) EffectiveHorizon(observedFrontier int64) int64 {
	inferred := observedFrontier - c.inferrer.backoffNs
	if inferred < c.inferrer.operatorFloor {
		return c.inferrer.operatorFloor
	}
	return inferred
}

// SetInferredHorizon (ADR-0027) monotonically advances cfg.PruningHorizonInt64Ns
// to candidate if candidate exceeds the current horizon. Any attempt to lower
// the horizon is refused, logged, and counted in PruningHorizonRetreatRefused
// because rows already dropped at a higher horizon would otherwise be missing
// from historical queries.
func (c *L1Compactor) SetInferredHorizon(candidate int64) int64 {
	current := c.cfg.PruningHorizonInt64Ns
	if candidate <= current {
		if candidate < current {
			if telemetry.PruningHorizonRetreatRefused != nil {
				telemetry.PruningHorizonRetreatRefused.Add(1)
			}
			log.Printf("[l1_compactor] WARN: SetInferredHorizon retreat refused — candidate=%d < current=%d (a horizon retreat is a silent-data-loss contract violation; the monotone clamp refuses; investigate the query stream's txTime monotonicity)",
				candidate, current)
		}
		return current
	}
	c.cfg.PruningHorizonInt64Ns = candidate
	return candidate
}

// EntityHash8 computes the 8-byte sha256 prefix used in the L0/L1 keying for
// the given entityID (the same prefix AsOf computes).
func EntityHash8(entityID string) [8]byte {
	full := sha256.Sum256(unsafe.Slice(unsafe.StringData(entityID), len(entityID)))
	var h [8]byte
	copy(h[:], full[:8])
	return h
}

// EntityHash8Hex returns the 16-char hex of sha256(entityID)[:8] — the listing
// prefix segment used by l0/, l1/, and compaction/ keying.
func EntityHash8Hex(entityID string) string {
	h := EntityHash8(entityID)
	return hexOf8(h)
}

// mergedRowT is the extracted row carrier for the merge. It carries the
// composite-key fragment (forward-ordered BigEndian so bytes.Compare equals
// lexicographic equals numeric) and the column values. The compaction is a
// background job, not the hot path — it holds copies because the L0 download
// buffer is freed after extraction (O(1) live download memory).
type mergedRowT struct {
	frag [40]byte // composite key: hash(16) | sysTime(8) | validTime(8) | assertTime(8) BigEndian
	sysT int64
	vs   int64
	ve   int64
	ast  int64
	h3   uint64
	pdz  [32]byte
	eid  []byte
	pld  []byte
}

// CompactionResult reports the outcome of one Compaction job.
type CompactionResult struct {
	EntityHash8  [8]byte
	L0Files      []string // merged L0 keys, sorted as written to the manifest
	L1Key        string   // written L1 object key
	ManifestKey  string   // written manifest object key
	Rows         int      // surviving rows written to L1 (equals RowsAfter)
	AlreadyMoved bool     // true when no L0 files or entity rows existed

	// Dominance pruning counts (ADR-0020): RowsBefore is the merged row count
	// before pruning, RowsAfter matches Rows, and RowsPruned == RowsBefore - RowsAfter.
	// With EnableDominancePruning=false, RowsPruned is 0 and RowsAfter == RowsBefore.
	RowsBefore int
	RowsAfter  int
	RowsPruned int
}

// DominancePrune (ADR-0020, ADR-0025) removes superseded rows from a
// composite-key-sorted slice relative to transaction-time GC horizon T_gc.
//
// A row R is dropped iff some retained row R' satisfies:
//
//	(C1) sysTime(R') > sysTime(R)
//	(C2) [validStart(R'), validEnd(R')) contains [validStart(R), validEnd(R))
//	(C3) sysTime(R') <= horizon
//
// (C3) prevents dropping R while historical queries in [sysTime(R), sysTime(R'))
// can still arrive; because no live query targets txTime < T_gc, R' will always
// pass Filter2 when R would have matched.
//
// Input precondition: rows must already be sorted by composite key
// (sysTime ascending). The sweep walks backward by equal-sysTime batches,
// maintaining the live slice of admissible dominator intervals (C2). Runs in
// O(N) when intervals overlap and O(N^2)/2 when disjoint. Returns rows
// unchanged when horizon <= 0.
func DominancePrune(rows []mergedRowT, horizon int64) []mergedRowT {
	if len(rows) == 0 || horizon <= 0 {
		return rows
	}
	// Reverse sweep by equal-sysTime batch preserves strict inequality (C1)
	// within a batch; live holds intervals from newer floor-admitted batches
	// that survived their own probe. By transitivity of containment (C2) and
	// monotonicity of sysTime (C1), probing against surviving floor-admitted
	// rows yields the same survivor subsequence as checking all pairs.

	dominated := make([]bool, len(rows))
	live := make([]liveInterval, 0, min(len(rows), 1024))

	end := len(rows)
	for end > 0 {
		batchSys := rows[end-1].sysT
		start := end - 1
		for start > 0 && rows[start-1].sysT == batchSys {
			start--
		}

		for i := start; i < end; i++ {
			r := &rows[i]
			for li := range live {
				if live[li].vs <= r.vs && live[li].ve >= r.ve {
					dominated[i] = true
					break
				}
			}
		}

		// Admit survivors only when their sysTime is within the GC horizon (C3).
		if batchSys <= horizon {
			for i := start; i < end; i++ {
				if !dominated[i] {
					live = append(live, liveInterval{vs: rows[i].vs, ve: rows[i].ve})
				}
			}
		}
		end = start
	}

	sink := 0
	for i := range rows {
		if !dominated[i] {
			if sink != i {
				rows[sink] = rows[i]
			}
			sink++
		}
	}
	return rows[:sink]
}

// liveInterval holds the valid-time bounds [vs, ve) of an admitted dominator
// during DominancePrune (2 int64 fields, zero pointers).
type liveInterval struct {
	vs int64
	ve int64
}

// Compaction merges one entity's L0 files into a single sorted L1 file.
//
// entityID and entityHash8 identify the entity. entityHash8 must equal
// sha256(entityID)[:8] (callers compute it once; EntityHash8 is the helper).
// The compaction:
//   - lists the entity's L0 files under l0/{hex(entityHash8)}/ (uncapped — the
//     merge must read all L0 files for the entity, not just the newest MaxL0Files);
//   - downloads + extracts this-entity rows from each (Filter1 + Filter4);
//   - sorts by composite key and writes one L1 file at l1/{hex(hash8)}/{firstSysNs}.arrow;
//   - writes a manifest at compaction/{hex(hash8)}/{firstSysNs}.manifest.
//
// The merge is idempotent: re-running on the same L0 set produces the same L1
// byte-content (sorted, schema-identical; the input L0 keys are sorted before
// merging so map iteration nondeterminism cannot bleed). If the entity has zero
// L0 files (or the L0 files contained zero rows for this entity), Compaction
// is a no-op returning AlreadyMoved=true.
func (c *L1Compactor) Compaction(ctx context.Context, entityID string, entityHash8 [8]byte) (*CompactionResult, error) {
	// List the entity's L0 files under l0/{hex(hash8)}/. Unbound pass: the
	// merge must read all L0 files (the whole history), not the cap-sliced
	// newest MaxL0Files. maxKeys=0 = unlimited (LocalFS semantics).
	l0Prefix := "l0/" + hexOf8(entityHash8) + "/"
	l0keys, err := c.lister.ListObjects(ctx, c.bucket, l0Prefix, 0)
	if err != nil {
		return nil, fmt.Errorf("compaction: list L0 %s: %w", l0Prefix, err)
	}
	if len(l0keys) == 0 {
		// Nothing to merge — no durable data exists for this entity yet.
		return &CompactionResult{EntityHash8: entityHash8, AlreadyMoved: true, Rows: 0, RowsBefore: 0, RowsAfter: 0, RowsPruned: 0}, nil
	}
	// Sort L0 keys ascending so the merge is deterministic across S3 listers.
	sort.Strings(l0keys)

	// Reuse scanFile's growable-jemalloc-buffer reader pattern to avoid
	// allocating file payloads on the Go heap.
	var alloc memory.Allocator = memory.DefaultAllocator
	if c.allocator != nil {
		alloc = c.allocator
	}

	var rows []mergedRowT
	for _, key := range l0keys {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("compaction: cancelled: %w", err)
		}
		rowz, rxErr := c.readEntityRowsFromKey(ctx, key, entityID, alloc)
		if rxErr != nil {
			// Skip corrupt L0 files so one bad object does not abort the merge;
			// readable rows still reach L1 while the corrupt file remains for inspection.
			continue
		}
		rows = append(rows, rowz...)
	}

	if len(rows) == 0 {
		// L0 files exist but contained zero rows for this entity (e.g. all rows
		// are co-located under a different entity or the files are corrupt).
		return &CompactionResult{EntityHash8: entityHash8, L0Files: l0keys, AlreadyMoved: true, Rows: 0, RowsBefore: 0, RowsAfter: 0, RowsPruned: 0}, nil
	}

	// Sort by composite key asc. bytes.Compare on [40]byte is lexicographic =
	// BigEndian numeric (the same order the SkipList enforces in skiplist_arena.go).
	sort.SliceStable(rows, func(i, j int) bool {
		return bytes.Compare(rows[i].frag[:], rows[j].frag[:]) < 0
	})

	// Apply superseded-row dominance pruning when enabled with a positive GC horizon.
	rowsBefore := len(rows)
	rowsAfter := rowsBefore
	rowsPruned := 0
	if c.cfg.EnableDominancePruning && c.cfg.PruningHorizonInt64Ns > 0 {
		rows = DominancePrune(rows, c.cfg.PruningHorizonInt64Ns)
		rowsAfter = len(rows)
		rowsPruned = rowsBefore - rowsAfter
		if telemetry.CompactionRowsPruned != nil {
			telemetry.CompactionRowsPruned.Add(float64(rowsPruned))
		}
	}

	if len(rows) == 0 {
		// Guard against an empty slice before indexing rows[0]; a max-sysTime
		// survivor always exists whenever rows was non-empty.
		return &CompactionResult{
			EntityHash8:  entityHash8,
			L0Files:      l0keys,
			AlreadyMoved: true,
			Rows:         0,
			RowsBefore:   rowsBefore,
			RowsAfter:    0,
			RowsPruned:   rowsBefore,
		}, nil
	}

	// Embed the sorted set's minimum sysTime in the L1 filename so key naming is
	// deterministic.
	firstSysT := rows[0].sysT
	l1Key := l1KeyFor(entityHash8, firstSysT)

	// Build the Arrow IPC file with the exact ArrowSchema.
	l1Buf := NewJemallocBuffer(c.allocator)
	defer func() {
		if l1Buf != nil {
			l1Buf.Free()
		}
	}()
	builder := array.NewRecordBuilder(alloc, ArrowSchema)
	for i := range rows {
		r := &rows[i]
		builder.Field(0).(*array.FixedSizeBinaryBuilder).Append(r.frag[:16])
		builder.Field(1).(*array.TimestampBuilder).Append(arrow.Timestamp(r.sysT))
		builder.Field(2).(*array.TimestampBuilder).Append(arrow.Timestamp(r.vs))
		builder.Field(3).(*array.TimestampBuilder).Append(arrow.Timestamp(r.ve))
		builder.Field(4).(*array.TimestampBuilder).Append(arrow.Timestamp(r.ast))
		builder.Field(5).(*array.Uint64Builder).Append(r.h3)
		builder.Field(6).(*array.FixedSizeBinaryBuilder).Append(r.pdz[:])
		builder.Field(7).(*array.BinaryBuilder).Append(r.eid)
		builder.Field(8).(*array.BinaryBuilder).Append(r.pld)
	}
	record := builder.NewRecord()
	defer record.Release()
	writer, werr := ipc.NewFileWriter(l1Buf, ipc.WithSchema(ArrowSchema), ipc.WithAllocator(alloc))
	if werr != nil {
		return nil, fmt.Errorf("compaction: arrow writer create: %w", werr)
	}
	if err := writer.Write(record); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("compaction: arrow write: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("compaction: arrow close: %w", err)
	}
	telemetry.ArrowSerialBytes.Add(float64(len(l1Buf.Bytes())))

	// Upload the L1. ResetRead first (ipc.NewFileWriter left the cursor at EOF);
	// the Upload contract is io.Reader → reads from the current cursor.
	l1Buf.ResetRead()
	if err := c.uploader.Upload(ctx, l1Key, l1Buf, int64(len(l1Buf.Bytes()))); err != nil {
		return nil, fmt.Errorf("compaction: upload L1 %s: %w", l1Key, err)
	}
	if telemetry.CompactionL1Written != nil {
		telemetry.CompactionL1Written.Add(1)
	}
	if telemetry.CompactionMerged != nil {
		telemetry.CompactionMerged.Add(float64(len(l0keys)))
	}

	// Write the compaction manifest listing merged L0 keys so queries can skip
	// superseded L0 files until the L0 reaper reclaims them.
	manifestKey := manifestKeyFor(entityHash8, firstSysT)
	manifestBytes := buildManifest(l1Key, l0keys)
	if err := c.uploader.Upload(ctx, manifestKey, bytes.NewReader(manifestBytes), int64(len(manifestBytes))); err != nil {
		return nil, fmt.Errorf("compaction: upload manifest %s: %w", manifestKey, err)
	}

	return &CompactionResult{
		EntityHash8: entityHash8,
		L0Files:     l0keys,
		L1Key:       l1Key,
		ManifestKey: manifestKey,
		Rows:        len(rows),
		RowsBefore:  rowsBefore,
		RowsAfter:   rowsAfter,
		RowsPruned:  rowsPruned,
	}, nil
}

// readEntityRowsFromKey downloads one L0 file and extracts rows belonging to
// entityID using Filter 1 (128-bit hash prefix) and Filter 4 (exact entity ID).
func (c *L1Compactor) readEntityRowsFromKey(ctx context.Context, key, entityID string, alloc memory.Allocator) ([]mergedRowT, error) {
	// Download into a growable jemalloc buffer (scanFile's pattern).
	rc, err := c.downloader.Download(ctx, c.bucket, key)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", key, err)
	}
	defer func() { _ = rc.Close() }()

	// Compute the full 16-byte hash prefix (Filter1) + entity-id bytes (Filter4).
	entityIDBytes := unsafe.Slice(unsafe.StringData(entityID), len(entityID))
	fullHash := sha256.Sum256(entityIDBytes)
	var fullHash16 [16]byte
	copy(fullHash16[:], fullHash[:16])

	capacity := 32 * 1024
	dataBuf := alloc.Allocate(capacity)
	var n int
	for {
		if n == capacity {
			capacity *= 2
			dataBuf = alloc.Reallocate(capacity, dataBuf)
		}
		readBytes, rerr := rc.Read(dataBuf[n:])
		n += readBytes
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			alloc.Free(dataBuf)
			return nil, fmt.Errorf("read %s: %w", key, rerr)
		}
	}
	defer func() {
		if dataBuf != nil {
			alloc.Free(dataBuf)
		}
	}()
	if n == 0 {
		return nil, nil
	}

	reader, err := ipc.NewFileReader(bytes.NewReader(dataBuf[:n]), ipc.WithAllocator(alloc))
	if err != nil {
		return nil, fmt.Errorf("open arrow reader %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	// Schema-guard: the L1 reuses the exact ArrowSchema; an L0 written by a
	// different (future) schema must not be silently merged.
	schema := reader.Schema()
	if schema.NumFields() != ArrowSchema.NumFields() {
		return nil, fmt.Errorf("schema mismatch in %s: expected %d fields, got %d", key, ArrowSchema.NumFields(), schema.NumFields())
	}
	for i := 0; i < schema.NumFields(); i++ {
		if !arrow.TypeEqual(schema.Field(i).Type, ArrowSchema.Field(i).Type) {
			return nil, fmt.Errorf("type mismatch at field %d in %s: expected %s, got %s",
				i, key, ArrowSchema.Field(i).Type, schema.Field(i).Type)
		}
	}

	var out []mergedRowT
	numRecords := reader.NumRecords()
	for i := 0; i < numRecords; i++ {
		if err := ctx.Err(); err != nil {
			return out, nil
		}
		rec, rerr := reader.Record(i)
		if rerr != nil {
			continue
		}
		out = append(out, extractEntityRowsFromRecord(rec, fullHash16, entityIDBytes)...)
		rec.Release()
	}
	return out, nil
}

// extractEntityRowsFromRecord runs the same Filter1 (hash-prefix) + Filter4
// (full entityID) as scanRecordBatch for this one record batch, returning the
// rows that belong to this entity as mergedRowT copies. The composite-key
// fragment is constructed so a single bytes.Compare on frag[:] matches the
// SkipList's key order (BigEndian hash|sysTime|validTime|assert).
func extractEntityRowsFromRecord(rec arrow.Record, fullHash16 [16]byte, entityIDBytes []byte) []mergedRowT {
	nRows := int(rec.NumRows())
	if nRows == 0 {
		return nil
	}
	hashCol := rec.Column(0).(*array.FixedSizeBinary)
	sysTimeCol := rec.Column(1).(*array.Timestamp)
	validStartCol := rec.Column(2).(*array.Timestamp)
	validEndCol := rec.Column(3).(*array.Timestamp)
	assertTimeCol := rec.Column(4).(*array.Timestamp)
	h3Col := rec.Column(5).(*array.Uint64)
	payloadDigestCol := rec.Column(6).(*array.FixedSizeBinary)
	entityIDCol := rec.Column(7).(*array.LargeBinary)
	payloadCol := rec.Column(8).(*array.LargeBinary)

	var out []mergedRowT
	for row := 0; row < nRows; row++ {
		// Filter 1: full 16-byte hash-prefix match.
		rowHash := hashCol.Value(row)
		if !bytes.Equal(rowHash, fullHash16[:]) {
			continue
		}
		// Filter 4: full entity ID verification (128-bit collision guard).
		rowEntityID := entityIDCol.Value(row)
		if !bytes.Equal(rowEntityID, entityIDBytes) {
			continue
		}
		var m mergedRowT
		copy(m.frag[:16], rowHash)
		m.sysT = int64(sysTimeCol.Value(row))
		binary.BigEndian.PutUint64(m.frag[16:24], uint64(m.sysT))
		m.vs = int64(validStartCol.Value(row))
		binary.BigEndian.PutUint64(m.frag[24:32], uint64(m.vs))
		m.ast = int64(assertTimeCol.Value(row))
		binary.BigEndian.PutUint64(m.frag[32:40], uint64(m.ast))
		m.ve = int64(validEndCol.Value(row))
		m.h3 = h3Col.Value(row)
		pdz := payloadDigestCol.Value(row)
		copy(m.pdz[:], pdz)
		m.eid = append([]byte(nil), rowEntityID...)
		m.pld = append([]byte(nil), payloadCol.Value(row)...)
		out = append(out, m)
	}
	return out
}

// l1KeyFor builds the L1 upload key: l1/{hex(hash8)}/{firstSysTimeNs}.arrow.
func l1KeyFor(hash8 [8]byte, firstSysTimeNs int64) string {
	var hexPrefix [16]byte
	hex.Encode(hexPrefix[:], hash8[:])
	var b strings.Builder
	b.WriteString("l1/")
	b.Write(hexPrefix[:])
	b.WriteByte('/')
	b.WriteString(strconv.FormatInt(firstSysTimeNs, 10))
	b.WriteString(".arrow")
	return b.String()
}

// manifestKeyFor builds the compaction manifest key:
// compaction/{hex(hash8)}/{firstSysTimeNs}.manifest
func manifestKeyFor(hash8 [8]byte, firstSysTimeNs int64) string {
	var hexPrefix [16]byte
	hex.Encode(hexPrefix[:], hash8[:])
	var b strings.Builder
	b.WriteString("compaction/")
	b.Write(hexPrefix[:])
	b.WriteByte('/')
	b.WriteString(strconv.FormatInt(firstSysTimeNs, 10))
	b.WriteString(".manifest")
	return b.String()
}

// buildManifest serializes the manifest body (line 1: the L1 key; subsequent
// lines: each merged L0 key, newline-separated).
func buildManifest(l1Key string, l0Keys []string) []byte {
	var b []byte
	b = append(b, l1Key...)
	b = append(b, '\n')
	for _, k := range l0Keys {
		b = append(b, k...)
		b = append(b, '\n')
	}
	return b
}

// readManifestBody reads a manifest body into a single buffer starting at
// 4096 bytes and doubling only when larger manifests require growth (ADR-0031).
func readManifestBody(r io.Reader) ([]byte, error) {
	const initial = 4096
	b := make([]byte, 0, initial)
	for {
		if cap(b)-len(b) < 256 {
			nb := make([]byte, len(b), cap(b)*2)
			copy(nb, b)
			b = nb
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			return b, err
		}
	}
	return b, nil
}

// ParseManifest parses a manifest body into the L1 key and the merged L0 keys.
// Blank lines and a missing trailing newline are tolerated. Line 0 sets l1Key
// when non-empty; subsequent lines extract l1/ and l0/ prefixed keys and ignore
// unrelated lines.
//
// Scans string(body) with strings.IndexByte rather than strings.Split so
// substrings share the single body allocation without an intermediate []string.
func ParseManifest(body []byte) (l1Key string, l0Keys []string) {
	s := string(body)
	l1Key = ""
	l0Keys = nil
	start := 0
	first := true
	for start < len(s) {
		end := strings.IndexByte(s[start:], '\n')
		if end < 0 {
			end = len(s) - start
		}
		ln := strings.TrimSpace(s[start : start+end])
		if len(ln) > 0 {
			if first {
				l1Key = ln
				first = false
				start = start + end + 1
				continue
			}
			if l1Key == "" && strings.HasPrefix(ln, "l1/") {
				l1Key = ln
			} else if strings.HasPrefix(ln, "l0/") {
				l0Keys = append(l0Keys, ln)
			}
		}
		start = start + end + 1
	}
	return l1Key, l0Keys
}

// SupersededL0Keys loads all compaction manifests for an entity and returns
// the union of L0 keys listed across them so queries can skip superseded files.
// Unreadable or malformed manifests are skipped safely because the uncompacted
// L0 files remain readable on disk.
func (c *L1Compactor) SupersededL0Keys(ctx context.Context, entityHash8 [8]byte) map[string]struct{} {
	manifestsPrefix := "compaction/" + hexOf8(entityHash8) + "/"
	keys, err := c.lister.ListObjects(ctx, c.bucket, manifestsPrefix, 0)
	if err != nil {
		return nil
	}
	superseded := make(map[string]struct{})
	for _, mk := range keys {
		rc, derr := c.downloader.Download(ctx, c.bucket, mk)
		if derr != nil {
			continue
		}
		body, _ := readManifestBody(rc) // single-grow read (ADR-0031), not io.ReadAll's doublings
		_ = rc.Close()
		_, l0ks := ParseManifest(body)
		for _, l0k := range l0ks {
			superseded[l0k] = struct{}{}
		}
	}
	return superseded
}

// ListL0Keys lists the L0 keys under a given prefix (default "l0/" for the
// whole tier, or a per-entity prefix "l0/{hex8}/" for one entity). It is a
// thin convenience wrapper so the scheduler goroutine in cmd/sovereign-node does
// not depend on the concrete S3Lister interface surface. maxKeys=0 → uncapped.
func (c *L1Compactor) ListL0Keys(ctx context.Context, prefix string) ([]string, error) {
	return c.lister.ListObjects(ctx, c.bucket, prefix, 0)
}

// CompactionByHash8 merges the L0 files for an entity identified only by its
// 8-byte hash prefix. It reads the entity ID from the first row of the earliest
// L0 file and delegates to Compaction so Filter 1 and Filter 4 still verify
// every merged row. Empty hash prefixes return AlreadyMoved=true; unreadable
// or empty first files return an error rather than merging without entity
// verification.
func (c *L1Compactor) CompactionByHash8(ctx context.Context, entityHash8 [8]byte) (*CompactionResult, error) {
	l0Prefix := "l0/" + hexOf8(entityHash8) + "/"
	l0keys, err := c.lister.ListObjects(ctx, c.bucket, l0Prefix, 0)
	if err != nil {
		return nil, fmt.Errorf("compaction-by-hash8: list L0 %s: %w", l0Prefix, err)
	}
	if len(l0keys) == 0 {
		return &CompactionResult{EntityHash8: entityHash8, AlreadyMoved: true}, nil
	}
	sort.Strings(l0keys) // deterministic entityID recovery (first file)
	var alloc memory.Allocator = memory.DefaultAllocator
	if c.allocator != nil {
		alloc = c.allocator
	}
	entityID, err := c.firstEntityIDFromKey(ctx, l0keys[0], alloc)
	if err != nil {
		return nil, fmt.Errorf("compaction-by-hash8: recover entityID from %s: %w", l0keys[0], err)
	}
	if entityID == "" {
		return nil, fmt.Errorf("compaction-by-hash8: first L0 file %s has no rows (cannot recover entityID)", l0keys[0])
	}
	return c.Compaction(ctx, entityID, entityHash8)
}

// firstEntityIDFromKey downloads one L0 file and returns the entityID of its
// first row (column 7 — entity_id LargeBinary). The scheduler (which cannot
// invert the hash) uses it to drive the full Compaction with the recovered
// entityID so Filter4 re-verifies every merged row.
func (c *L1Compactor) firstEntityIDFromKey(ctx context.Context, key string, alloc memory.Allocator) (string, error) {
	rc, err := c.downloader.Download(ctx, c.bucket, key)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", key, err)
	}
	defer func() { _ = rc.Close() }()
	capacity := 32 * 1024
	dataBuf := alloc.Allocate(capacity)
	var n int
	for {
		if n == capacity {
			capacity *= 2
			dataBuf = alloc.Reallocate(capacity, dataBuf)
		}
		nb, rerr := rc.Read(dataBuf[n:])
		n += nb
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			alloc.Free(dataBuf)
			return "", fmt.Errorf("read %s: %w", key, rerr)
		}
	}
	defer alloc.Free(dataBuf)
	if n == 0 {
		return "", nil
	}
	reader, err := ipc.NewFileReader(bytes.NewReader(dataBuf[:n]), ipc.WithAllocator(alloc))
	if err != nil {
		return "", fmt.Errorf("open arrow reader %s: %w", key, err)
	}
	defer func() { _ = reader.Close() }()
	if reader.NumRecords() == 0 {
		return "", nil
	}
	rec, rerr := reader.Record(0)
	if rerr != nil {
		return "", rerr
	}
	defer rec.Release()
	if rec.NumRows() == 0 {
		return "", nil
	}
	entityIDCol := rec.Column(7).(*array.LargeBinary)
	id := entityIDCol.Value(0)
	// Copy to a Go-heap string (the buffer is freed after return) — this is the
	// scheduler path, not the hot path. A one-string alloc per compaction job
	// is bounded by the entity count.
	return string(append([]byte(nil), id...)), nil
}

// hexOf8 hex-encodes an [8]byte to a 16-char string.
func hexOf8(b [8]byte) string {
	var buf [16]byte
	hex.Encode(buf[:], b[:])
	return unsafe.String(&buf[0], 16)
}

// Compile-time interface satisfaction (catches a signature drift the moment
// l1_compactor.go is edited).
var _ interface {
	Compaction(ctx context.Context, entityID string, entityHash8 [8]byte) (*CompactionResult, error)
} = (*L1Compactor)(nil)
