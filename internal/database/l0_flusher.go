package database

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"unsafe"

	"github.com/apache/arrow/go/v17/arrow"
	"github.com/apache/arrow/go/v17/arrow/array"
	"github.com/apache/arrow/go/v17/arrow/ipc"
	"github.com/hr18vk/supremum/internal/telemetry"
)

// MaxValidTimeEndNs is the int64-safe sentinel for an OPEN-ENDED valid-time
// interval endpoint (Day 16, ADR-0021 §2.1). It is 9e18 ns from epoch = year
// ~2253, comfortably below math.MaxInt64 (~9.22e18).
//
// The prior `var MaxValidTime = time.Date(9999,12,31,...)` was conceptually an
// open-ended end but `.UnixNano()` OVERFLOWS int64: year 9999 → ~633e9 seconds
// → ~6.33e20 ns, which is NEGATIVE when truncated to int64 (the high bit is
// set) — every call site that passed MaxValidTime.UnixNano() as ValidTimeEnd
// sent a garbage NEGATIVE into the Arrow index (a half-open interval
// [validStart, validEnd<0) is EMPTY for every positive validTime → the row is
// silently invisible to AsOf's Filter3). The mesh's OpenEndedValidEndNs
// (pkg/mesh/control.go:118, Day-12.5) has ALWAYS used the concrete-const-9e18
// pattern — this closes the WRITE-schema side to match the READ/mesh side.
//
// ZERO production callers of MaxValidTime.UnixNano() existed (every caller was
// a _test.go); the var is DELETED. The WRITE path (FlushArenaToIPC) reads
// validTimeEndNs from the packed value bytes directly (line 223), and the
// production injectors now feed MaxValidTimeEndNs — the int64-in-range sentinel
// — into the MemTable via InsertLocalEvents / control.go. No time.Time is
// materialized on the open-ended path.
const MaxValidTimeEndNs int64 = 9_000_000_000_000_000_000

// ArrowSchema defines the tri-temporal event schema for L0 SSTables.
var ArrowSchema = arrow.NewSchema(
	[]arrow.Field{
		{Name: "entity_id_hash", Type: &arrow.FixedSizeBinaryType{ByteWidth: 16}}, // Override 8.4: 128-bit hash
		{Name: "system_time", Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"}},
		{Name: "valid_time_start", Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"}},
		{Name: "valid_time_end", Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"}},
		{Name: "assertion_time", Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"}},
		{Name: "h3_index", Type: arrow.PrimitiveTypes.Uint64},
		{Name: "payload_digest", Type: &arrow.FixedSizeBinaryType{ByteWidth: 32}},
		{Name: "entity_id", Type: arrow.BinaryTypes.LargeBinary}, // Override 8.3: LargeBinary for UTF-8 safety
		{Name: "payload", Type: arrow.BinaryTypes.LargeBinary},
	},
	nil,
)

// S3Uploader is the interface for uploading Arrow IPC files to object storage.
// Implementations: MinIO for local dev, AWS S3 for production.
type S3Uploader interface {
	Upload(ctx context.Context, key string, data io.Reader, size int64) error
}

// L0Flusher serializes a frozen SkipListArena directly into Arrow IPC format
// and uploads to S3. Zero intermediate Go heap structs (Override O2.2).
type L0Flusher struct {
	allocator *JemallocAllocator
	uploader  S3Uploader
	bucket    string
	compactor *EpochCompactor
}

// NewL0Flusher creates a new L0 flusher.
func NewL0Flusher(allocator *JemallocAllocator, uploader S3Uploader, bucket string) *L0Flusher {
	return &L0Flusher{
		allocator: allocator,
		uploader:  uploader,
		bucket:    bucket,
	}
}

// SetCompactor injects the EpochCompactor for ADR 7 tombstone pruning.
func (f *L0Flusher) SetCompactor(c *EpochCompactor) {
	f.compactor = c
}

// L0Partition is one per-entity Arrow IPC blob produced by a flush.
//
// Day 13 (ADR-0018): every entity in a checkpoint's flush gets its OWN file
//
//	l0/{hex(EntityHash[:8])}/{FirstSysTimeNs}.arrow
//
// so AsOf's prefix-list (l0/{hex(sha256(queried)[:8])}/) can never miss. The
// OLD single-blob path (one file for the whole list, keyed under the smallest-
// hash entity) is DELETED — it co-located every entity of a checkpoint into
// one file, making every non-smallest entity a silent ErrEntityNotFound on
// AsOf for data that IS on disk.
type L0Partition struct {
	// EntityHash is key[:16] (the 128-bit sha256(entityID)). The per-entity
	// file is keyed under hex(EntityHash[:8]) — the SAME 8-byte prefix AsOf
	// computes (query.go:137) for the queried entity.
	EntityHash [16]byte
	// FirstSysTimeNs is the partition's smallest key[16:24] (BigEndian) — the
	// {txTimeNs} segment of the filename. The SAME field the old UploadBuffer
	// used, now per-partition (not per-blob).
	FirstSysTimeNs int64
	// Buf is the serialized Arrow IPC for this entity's rows. Owned by the
	// caller of emit (flushed lazily across the upload retry loop), who MUST
	// Free() it before the next partition's buffer starts (streaming → O(1)
	// live memory regardless of entity count).
	Buf *JemallocBuffer
}

// FlushArenaToIPC serializes a frozen SkipListArena into ONE Arrow IPC blob PER
// ENTITY (Day 13 per-entity split-merge) and streams each through `emit` as
// soon as it is serialized. The SkipList is sorted by key[:16] (the 128-bit
// sha256(entityID)); contiguous same-hash entries ARE one entity-partition,
// so the split is a single pass with ZERO re-sort and ZERO re-read of the
// frozen arena.
//
// STREAMING (O(1) memory): `emit` is invoked once per partition with that
// partition's L0Partition, and the partition's Arrow builder is released (and
// its buffer MUST be freed by `emit` before returning) BEFORE the next
// partition begins. Only ONE partition is live at a time regardless of the
// per-checkpoint entity count — the OOM cliff of materializing 50K unique
// entities' buffers simultaneously is closed. The async upload-retry concern
// (Override 9.2 — retain a buffer across upload retries) is the caller's:
// `emit` may hold the partition.Buf through its retry loop, then free it.
//
// A zero-row entity produces NO partition (no empty blobs). The degenerate
// N=1 case yields exactly one emit — the existing single-entity teeth stay green.
//
// Override O2.2: zero intermediate Go heap structs — reads raw off-heap
// SkipList bytes directly into Arrow builders.
// Override O2.3: Arrow column buffers via JemallocAllocator.
// Override O2.4: ipc.NewFileWriter serialization.
func (f *L0Flusher) FlushArenaToIPC(sl *SkipListArena, emit func(L0Partition) error) error {
	if sl.Count() == 0 {
		return nil
	}

	// ADR 7: prune sweep once per flush (the set is the same for every partition).
	var pruned map[string]struct{}
	if f.compactor != nil {
		pruned, _ = f.compactor.PruneTombstones()
	}

	allocator := f.allocator

	// Per-partition builder — only ONE live at a time (streaming, O(1) memory).
	var curBuilder *array.RecordBuilder
	var curHash [16]byte
	var curFirstSys int64
	haveCur := false

	finalize := func() error {
		if !haveCur || curBuilder == nil {
			return nil
		}
		record := curBuilder.NewRecord()
		defer record.Release()
		buf := NewJemallocBuffer(allocator)
		writer, err := ipc.NewFileWriter(buf, ipc.WithSchema(ArrowSchema))
		if err != nil {
			buf.Free()
			curBuilder.Release()
			return fmt.Errorf("arrow ipc file writer create: %w", err)
		}
		if err := writer.Write(record); err != nil {
			buf.Free()
			_ = writer.Close()
			curBuilder.Release()
			return fmt.Errorf("arrow ipc write: %w", err)
		}
		if err := writer.Close(); err != nil {
			buf.Free()
			curBuilder.Release()
			return fmt.Errorf("arrow ipc close: %w", err)
		}
		telemetry.ArrowSerialBytes.Add(float64(len(buf.Bytes())))
		part := L0Partition{
			EntityHash:     curHash,
			FirstSysTimeNs: curFirstSys,
			Buf:            buf,
		}
		// emit owns the partition's lifecycle: upload (with its own retry loop)
		// then Free() before returning, so the next partition's buffer is the
		// only live one.
		if err := emit(part); err != nil {
			buf.Free()
			curBuilder.Release()
			return err
		}
		curBuilder.Release()
		haveCur = false
		curBuilder = nil
		return nil
	}

	it := sl.NewIterator()
	for it.Valid() {
		key := it.Key()
		val := it.Value()

		// Parse value preamble [2B idLen][id] for the prune check.
		entityIDLen := int(binary.LittleEndian.Uint16(val[0:2]))
		entityIDBytes := val[2 : 2+entityIDLen]

		// ADR 7: tombstone pruning — skip the row if the entity is causally stable.
		if pruned != nil {
			entityIDStr := unsafe.String(unsafe.SliceData(entityIDBytes), len(entityIDBytes))
			if _, isPruned := pruned[entityIDStr]; isPruned {
				it.Next()
				continue
			}
		}

		entityHashSlice := key[0:16]
		sysTimeNs := int64(binary.BigEndian.Uint64(key[16:24]))

		// Partition transition on key[:16] (128-bit entity hash).
		if !haveCur {
			curBuilder = array.NewRecordBuilder(allocator, ArrowSchema)
			copy(curHash[:], entityHashSlice)
			curFirstSys = sysTimeNs
			haveCur = true
		} else if curHash != *(*[16]byte)(unsafe.Pointer(unsafe.SliceData(entityHashSlice))) {
			if err := finalize(); err != nil {
				return err
			}
			curBuilder = array.NewRecordBuilder(allocator, ArrowSchema)
			copy(curHash[:], entityHashSlice)
			curFirstSys = sysTimeNs
			haveCur = true
		}

		validTimeNs := int64(binary.BigEndian.Uint64(key[24:32]))
		assertTimeNs := int64(binary.BigEndian.Uint64(key[32:40]))

		off := 2 + entityIDLen
		h3Index := binary.LittleEndian.Uint64(val[off : off+8])
		off += 8
		validTimeEndNs := int64(binary.LittleEndian.Uint64(val[off : off+8]))
		off += 8
		payloadDigestBytes := val[off : off+32]
		off += 32
		payloadLen := int(binary.LittleEndian.Uint32(val[off : off+4]))
		off += 4
		payload := val[off : off+payloadLen]

		curBuilder.Field(0).(*array.FixedSizeBinaryBuilder).Append(entityHashSlice)
		curBuilder.Field(1).(*array.TimestampBuilder).Append(arrow.Timestamp(sysTimeNs))
		curBuilder.Field(2).(*array.TimestampBuilder).Append(arrow.Timestamp(validTimeNs))
		curBuilder.Field(3).(*array.TimestampBuilder).Append(arrow.Timestamp(validTimeEndNs))
		curBuilder.Field(4).(*array.TimestampBuilder).Append(arrow.Timestamp(assertTimeNs))
		curBuilder.Field(5).(*array.Uint64Builder).Append(h3Index)
		curBuilder.Field(6).(*array.FixedSizeBinaryBuilder).Append(payloadDigestBytes)
		curBuilder.Field(7).(*array.BinaryBuilder).Append(entityIDBytes)
		curBuilder.Field(8).(*array.BinaryBuilder).Append(payload)

		it.Next()
	}
	return finalize()
}

// FlushFromArena serializes a frozen SkipListArena to per-entity Arrow IPC
// blobs and uploads EACH as it is serialized — O(1) live memory regardless of
// entity count (Day 13 streaming). SYNCHRONOUS path (Close/Flush): each
// partition is uploaded (no retry) inside the emit callback and its buffer
// freed before the next partition starts.
//
// The async path (swapAndFlushAsync) drives FlushArenaToIPC directly with its
// own emit callback running the per-partition upload retry loop (Override 9.2).
//
// Day 13: returns the count of per-entity uploads (was one upload for the
// WHOLE list, keyed under the smallest-hash entity — the silent-read-miss
// defect, now DELETED).
func (f *L0Flusher) FlushFromArena(ctx context.Context, sl *SkipListArena) (int, error) {
	if sl.Count() == 0 {
		return 0, nil
	}
	var uploaded int
	err := f.FlushArenaToIPC(sl, func(part L0Partition) error {
		defer part.Buf.Free()
		if err := f.UploadPartition(ctx, part); err != nil {
			return err
		}
		uploaded++
		return nil
	})
	if err != nil {
		return uploaded, fmt.Errorf("l0 flush: %w", err)
	}
	return uploaded, nil
}

// UploadPartition uploads a single per-entity L0Partition to S3 under its own key:
//
//	l0/{hex(EntityHash[:8])}/{FirstSysTimeNs}.arrow
//
// Day 13 (ADR-0018): aligns the WRITE keying with the READ keying — AsOf lists
// by l0/{hex(sha256(queriedEntityID)[:8])}/, so per-entity blobs can never be
// missed by the prefix list. The OLD UploadBuffer keyed the whole blob under
// the FIRST (smallest-hash) entry → every co-located non-smallest entity was
// invisible to AsOf. DELETED.
//
// Override 7.2: pass JemallocBuffer directly as io.Reader; the caller resets
// the read cursor as needed.
func (f *L0Flusher) UploadPartition(ctx context.Context, part L0Partition) error {
	var keyBuf [128]byte
	keyBytes := append(keyBuf[:0], "l0/"...)
	var hexPrefix [16]byte
	hex.Encode(hexPrefix[:], part.EntityHash[:8])
	keyBytes = append(keyBytes, hexPrefix[:]...)
	keyBytes = append(keyBytes, '/')
	keyBytes = strconv.AppendInt(keyBytes, part.FirstSysTimeNs, 10)
	keyBytes = append(keyBytes, ".arrow"...)
	key := unsafe.String(unsafe.SliceData(keyBytes), len(keyBytes))

	part.Buf.ResetRead()
	if err := f.uploader.Upload(ctx, key, part.Buf, int64(len(part.Buf.Bytes()))); err != nil {
		return fmt.Errorf("l0 flush upload to %s: %w", key, err)
	}
	return nil
}
