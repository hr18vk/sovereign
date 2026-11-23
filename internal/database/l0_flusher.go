// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

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
	"github.com/hr18vk/sovereign/internal/telemetry"
)

// MaxValidTimeEndNs is the int64-safe sentinel for an open-ended valid-time
// interval endpoint (ADR-0021). It equals 9e18 ns from epoch (2255-03-14T16:00:00Z),
// comfortably below math.MaxInt64 (~9.22e18).
//
// Storing time.Date(9999, 12, 31, ...).UnixNano() overflows int64 and wraps
// negative, making [validStart, validEnd) empty for positive valid times.
// Both the Arrow write path and the node control path use MaxValidTimeEndNs
// directly without materializing a time.Time.
const MaxValidTimeEndNs int64 = 9_000_000_000_000_000_000

// ArrowSchema defines the tri-temporal event schema for L0 SSTables.
var ArrowSchema = arrow.NewSchema(
	[]arrow.Field{
		{Name: "entity_id_hash", Type: &arrow.FixedSizeBinaryType{ByteWidth: 16}}, // 128-bit SHA-256 prefix
		{Name: "system_time", Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"}},
		{Name: "valid_time_start", Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"}},
		{Name: "valid_time_end", Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"}},
		{Name: "assertion_time", Type: &arrow.TimestampType{Unit: arrow.Nanosecond, TimeZone: "UTC"}},
		{Name: "h3_index", Type: arrow.PrimitiveTypes.Uint64},
		{Name: "payload_digest", Type: &arrow.FixedSizeBinaryType{ByteWidth: 32}},
		{Name: "entity_id", Type: arrow.BinaryTypes.LargeBinary}, // LargeBinary preserves raw entity ID bytes
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
// and uploads to S3 without intermediate Go heap structs.
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

// SetCompactor injects the EpochCompactor for epoch-based tombstone pruning.
func (f *L0Flusher) SetCompactor(c *EpochCompactor) {
	f.compactor = c
}

// L0Partition is one per-entity Arrow IPC blob produced by a flush.
//
// ADR-0018: every entity in a checkpoint's flush gets its own file
//
//	l0/{hex(EntityHash[:8])}/{FirstSysTimeNs}.arrow
//
// so AsOf's prefix-list (l0/{hex(sha256(queried)[:8])}/) can never miss. The
// old single-blob path (one file for the whole list, keyed under the smallest-
// hash entity) is deleted — it co-located every entity of a checkpoint into
// one file, making every non-smallest entity a silent ErrEntityNotFound on
// AsOf for data that is on disk.
type L0Partition struct {
	// EntityHash is key[:16] (the 128-bit sha256(entityID)). The per-entity
	// file is keyed under hex(EntityHash[:8]) — the 8-byte prefix AsOf's
	// EntityHash8 computes for the queried entity.
	EntityHash [16]byte
	// FirstSysTimeNs is the partition's smallest key[16:24] (BigEndian) — the
	// {txTimeNs} segment of the filename. The field the old UploadBuffer
	// used, now per-partition (not per-blob).
	FirstSysTimeNs int64
	// Buf is the serialized Arrow IPC for this entity's rows. Owned by the
	// caller of emit (flushed lazily across the upload retry loop), which must
	// Free() it before the next partition's buffer starts (streaming → O(1)
	// live memory regardless of entity count).
	Buf *JemallocBuffer
}

// FlushArenaToIPC serializes a frozen SkipListArena into one Arrow IPC blob per
// entity (per-entity split-merge) and streams each through `emit` as
// soon as it is serialized. The SkipList is sorted by key[:16] (the 128-bit
// sha256(entityID)); contiguous same-hash entries are one entity-partition,
// so the split is a single pass with zero re-sort and zero re-read of the
// frozen arena.
//
// Streaming (O(1) memory): `emit` is invoked once per partition with that
// partition's L0Partition, and the partition's Arrow builder is released (and
// its buffer must be freed by `emit` before returning) before the next
// partition begins. Only one partition is live at a time regardless of the
// per-checkpoint entity count — the OOM cliff of materializing 50K unique
// entities' buffers simultaneously is closed. The async upload-retry concern
// (retain a buffer across upload retries) is the caller's:
// `emit` may hold the partition.Buf through its retry loop, then free it.
//
// A zero-row entity produces no partition (no empty blobs). The degenerate
// N=1 case yields exactly one emit — the existing single-entity tests stay green.
//
// Zero intermediate Go heap structs — reads raw off-heap
// SkipList bytes directly into Arrow builders.
// Arrow column buffers via JemallocAllocator.
// ipc.NewFileWriter serialization.
func (f *L0Flusher) FlushArenaToIPC(sl *SkipListArena, emit func(L0Partition) error) error {
	if sl.Count() == 0 {
		return nil
	}

	// Prune sweep once per flush (the set is the same for every partition).
	var pruned map[string]struct{}
	if f.compactor != nil {
		pruned, _ = f.compactor.PruneTombstones()
	}

	allocator := f.allocator

	// Per-partition builder — only one live at a time (streaming, O(1) memory).
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

		// Tombstone pruning — skip the row if the entity is causally stable.
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
// blobs and uploads each as it is serialized so live memory stays O(1)
// regardless of entity count. The synchronous path uploads each partition once
// inside the emit callback and frees its buffer before the next partition starts;
// the async path (swapAndFlushAsync) supplies an emit callback with upload retries.
//
// Returns the count of per-entity uploads.
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

// UploadPartition uploads a single per-entity L0Partition to S3 under:
//
//	l0/{hex(EntityHash[:8])}/{FirstSysTimeNs}.arrow
//
// ADR-0018: aligns write keying with Resolver.AsOf prefix listing. Passes
// JemallocBuffer directly as io.Reader after resetting the read cursor.
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
