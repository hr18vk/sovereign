// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

package durability

// A checkpoint persists the live HAMT in two forms under the LocalFS directory.
// Without one, recovery replays every local mutation since the WAL was created.
// With a snapshot, it can join the recorded state and replay only the later
// records.
//
// The recovery image at "ckpt/<LamportHigh>" is a plain binary containing every
// (DotNodeID, DotCounter) pair for each entity. Joining it into a seed engine
// reconstructs the same Merkle root, including foreign dots that the local WAL
// does not contain. The sorted dot set is independent of maphash.Seed.
//
// The query index under "l0/<...>" is Arrow IPC written through MemTable and
// L0Flusher. It stores the latest entry per entity. CRDTEntry contains a payload
// digest but no payload body, so these rows carry the digest and an empty body;
// MemTable.Write does not recompute the digest. The LSM snapshot is therefore an
// index, not a payload store. Resolver.AsOf and Resolver.Range read this index.
//
// State does not pin an EBR epoch internally, so a bare State call concurrent
// with InsertLocal can dereference a root that a racing CAS retired. To avoid
// that use-after-free, AppendCheckpoint holds the pin across CaptureShardsPinned
// and the image write. It releases the pin before the slower LSM flush.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"sync/atomic"

	eng "github.com/hr18vk/sovereign/pkg/sync"

	"github.com/hr18vk/sovereign/internal/database"
)

// ErrSnapshotCorrupt reports a mismatch between a v3 image and its whole-image
// CRC32C (Castagnoli). A snapshot is a derived cache, so recovery discards the
// corrupt image and rebuilds from the WAL instead of refusing to boot. The
// recovery witness records the fallback.
var ErrSnapshotCorrupt = errors.New("durability/snapshot: whole-image CRC32C mismatch (corrupt image)")

// snapshotCastagnoliTable is shared by every image checksum. On ARM64, the
// Castagnoli implementation uses the hardware CRC32 instruction.
var snapshotCastagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// snapshotCRC32Skip disables the v3 CRC comparison while still computing the
// checksum. Tests use it to demonstrate that corruption detection depends on the
// comparison. Its zero value enables verification; production code never sets
// it.
var snapshotCRC32Skip atomic.Bool

const (
	// snapshotMagic identifies the recovery-image file format.
	snapshotMagic = "SNSP"
	// snapshotVersionV2 is the legacy format with a CutSeq and MerkleRoot but
	// no content checksum. decodeSnapshotImage accepts it for compatibility;
	// existing v2 bytes cannot gain integrity protection retroactively.
	snapshotVersionV2 = uint8(2)
	// snapshotVersionV3 retains the v2 header and records, then appends a
	// four-byte big-endian Castagnoli CRC32C over both. Images are uploaded as
	// complete buffers, so a CRC mismatch or short trailer is corruption rather
	// than a recoverable torn append.
	snapshotVersionV3 = uint8(3)
	// crdtEntryWireSize is the fixed big-endian size of pkg/sync.CRDTEntry in
	// the snapshot format. A fixed width permits direct bounds checks during
	// decoding without reflection or unsafe struct scans.
	crdtEntryWireSize = 120
	// snapshotHeaderSize is the fixed header before the record stream.
	snapshotHeaderSize = 4 + 1 + 8 + 8 + 8 + 32 // magic + version + lamportHigh + recordCount + cutSeq + root
)

// SnapshotRecord pairs an entityID with one of its CRDTEntries from the live
// HAMT. The recovery image is a flat stream of these.
type SnapshotRecord struct {
	EntityID string
	Entry    eng.CRDTEntry
}

// SnapshotImage is the decoded recovery image at "ckpt/<LamportHigh>". Its
// watermark comes from the checkpoint and identifies the WAL tail to replay.
//
// CutSeq and MerkleRoot bind the image to the 0x05 checkpoint from which they
// were captured (ADR-0045 §4). Back-to-back checkpoints can reuse a key when
// no local write advances maxLocalDot, so the file may belong to an earlier or
// later anchor. A binding mismatch triggers exact-WAL replay rather than a boot
// refusal.
type SnapshotImage struct {
	// fieldalignment: fixed-size arrays + slice, then uint64s. Off the hot path.
	Records     []SnapshotRecord
	MerkleRoot  [32]byte
	LamportHigh uint64
	CutSeq      uint64
}

// The snapshot layout is independent of the in-memory CRDTEntry representation.
// A change to pkg/sync.CRDTEntry requires a new snapshot version and a migration;
// the decoder must never reinterpret an older entry under a new layout.
//
//	Big-endian field offsets within a 120-byte entry:
//	  [0:32)   PayloadDigest
//	  [32:48)  OriginNodeID
//	  [48:64)  DotNodeID
//	  [64:72)  DotCounter
//	  [72:80)  SystemTime
//	  [80:88)  ValidTimeStart
//	  [88:96)  ValidTimeEnd
//	  [96:104) AssertionTime
//	  [104:112) DecisionTime
//	  [112:120) H3Index
func encodeCRDTEntry(entry eng.CRDTEntry, dst []byte) {
	if len(dst) < crdtEntryWireSize {
		panic("durability/snapshot: encode buffer too small")
	}
	copy(dst[0:32], entry.PayloadDigest[:])
	copy(dst[32:48], entry.OriginNodeID[:])
	copy(dst[48:64], entry.DotNodeID[:])
	binary.BigEndian.PutUint64(dst[64:72], entry.DotCounter)
	binary.BigEndian.PutUint64(dst[72:80], uint64(entry.SystemTime))
	binary.BigEndian.PutUint64(dst[80:88], uint64(entry.ValidTimeStart))
	binary.BigEndian.PutUint64(dst[88:96], uint64(entry.ValidTimeEnd))
	binary.BigEndian.PutUint64(dst[96:104], uint64(entry.AssertionTime))
	binary.BigEndian.PutUint64(dst[104:112], uint64(entry.DecisionTime))
	binary.BigEndian.PutUint64(dst[112:120], entry.H3Index)
}

func decodeCRDTEntry(src []byte) (eng.CRDTEntry, error) {
	if len(src) < crdtEntryWireSize {
		return eng.CRDTEntry{}, fmt.Errorf("durability/snapshot: entry wire too short: %d", len(src))
	}
	var entry eng.CRDTEntry
	copy(entry.PayloadDigest[:], src[0:32])
	copy(entry.OriginNodeID[:], src[32:48])
	copy(entry.DotNodeID[:], src[48:64])
	entry.DotCounter = binary.BigEndian.Uint64(src[64:72])
	entry.SystemTime = int64(binary.BigEndian.Uint64(src[72:80]))
	entry.ValidTimeStart = int64(binary.BigEndian.Uint64(src[80:88]))
	entry.ValidTimeEnd = int64(binary.BigEndian.Uint64(src[88:96]))
	entry.AssertionTime = int64(binary.BigEndian.Uint64(src[96:104]))
	entry.DecisionTime = int64(binary.BigEndian.Uint64(src[104:112]))
	entry.H3Index = binary.BigEndian.Uint64(src[112:120])
	return entry, nil
}

// encodeSnapshotImage serializes records in (entityID, DotNodeID, DotCounter)
// order. Engines with the same state therefore produce byte-identical images,
// including the deterministic checksum, even though Join itself is
// order-independent.
func encodeSnapshotImage(image *SnapshotImage) ([]byte, error) {
	// Canonical order: stable sort by (entityID, DotNodeID, DotCounter).
	ordered := make([]SnapshotRecord, len(image.Records))
	copy(ordered, image.Records)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].EntityID != ordered[j].EntityID {
			return ordered[i].EntityID < ordered[j].EntityID
		}
		a, b := ordered[i].Entry.Dot(), ordered[j].Entry.Dot()
		for k := 0; k < 16; k++ {
			if a.NodeID[k] != b.NodeID[k] {
				return a.NodeID[k] < b.NodeID[k]
			}
		}
		return a.Counter < b.Counter
	})

	// Size the buffer once: header + per-record (2B len + entityID + 120B entry).
	total := snapshotHeaderSize
	for _, r := range ordered {
		total += 2 + len(r.EntityID) + crdtEntryWireSize
	}
	buf := make([]byte, 0, total)

	var hdr [snapshotHeaderSize]byte
	copy(hdr[0:4], snapshotMagic)
	hdr[4] = snapshotVersionV3
	binary.BigEndian.PutUint64(hdr[5:13], image.LamportHigh)
	binary.BigEndian.PutUint64(hdr[13:21], uint64(len(ordered)))
	binary.BigEndian.PutUint64(hdr[21:29], image.CutSeq) // §11.5: the anchor binding
	copy(hdr[29:61], image.MerkleRoot[:])
	buf = append(buf, hdr[:]...)

	var entryWire [crdtEntryWireSize]byte
	var lenBuf [2]byte
	for _, r := range ordered {
		if len(r.EntityID) > 0xFFFF {
			return nil, fmt.Errorf("durability/snapshot: entityID too long (%d)", len(r.EntityID))
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(r.EntityID)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, r.EntityID...)
		encodeCRDTEntry(r.Entry, entryWire[:])
		buf = append(buf, entryWire[:]...)
	}
	// Append the whole-image CRC32C (Castagnoli) as a trailing 4-byte
	// big-endian trailer, computed over the entire image so far (the 61-byte
	// header ‖ every record). A v3 image is written whole (one upload), so
	// there is no torn-tail case — at decode the CRC is recomputed over
	// all-but-last-4 and any mismatch is corruption (ErrSnapshotCorrupt),
	// never a partial accept.
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], crc32.Checksum(buf, snapshotCastagnoliTable))
	buf = append(buf, crcBuf[:]...)
	return buf, nil
}

// decodeSnapshotImage parses one complete recovery image. It rejects unknown
// magic or versions, truncation, trailing bytes, and v3 checksum mismatches so
// recovery cannot mistake a different or damaged layout for valid state.
func decodeSnapshotImage(data []byte) (*SnapshotImage, error) {
	if len(data) < snapshotHeaderSize {
		return nil, fmt.Errorf("durability/snapshot: header too short: %d", len(data))
	}
	if string(data[0:4]) != snapshotMagic {
		return nil, fmt.Errorf("durability/snapshot: bad magic %q", data[0:4])
	}
	// Only v3 has a trailing whole-image CRC32C. Version 2 remains decodable
	// without that protection. A v3 checksum mismatch returns ErrSnapshotCorrupt;
	// recovery then discards the image and rebuilds from the WAL.
	switch version := data[4]; version {
	case snapshotVersionV3:
		if len(data) < snapshotHeaderSize+4 {
			return nil, fmt.Errorf("%w: v3 image too short for the CRC trailer (%d bytes)", ErrSnapshotCorrupt, len(data))
		}
		body := data[:len(data)-4]
		want := binary.BigEndian.Uint32(data[len(data)-4:])
		got := crc32.Checksum(body, snapshotCastagnoliTable)
		// Tests can skip this comparison with snapshotCRC32Skip to verify that
		// corruption detection depends on it.
		if !snapshotCRC32Skip.Load() && want != got {
			return nil, fmt.Errorf("%w: stored %08x, computed %08x over %d image bytes", ErrSnapshotCorrupt, want, got, len(body))
		}
		data = body // exclude the CRC trailer from the record stream
	case snapshotVersionV2:
		// Version 2 has no checksum but remains readable for compatibility.
	default:
		return nil, fmt.Errorf("durability/snapshot: unsupported version %d (want %d or %d)", version, snapshotVersionV2, snapshotVersionV3)
	}
	lamportHigh := binary.BigEndian.Uint64(data[5:13])
	recordCount := binary.BigEndian.Uint64(data[13:21])

	image := &SnapshotImage{
		LamportHigh: lamportHigh,
		CutSeq:      binary.BigEndian.Uint64(data[21:29]), // the anchor binding (ADR-0045 §4)
		Records:     make([]SnapshotRecord, 0, recordCount),
	}
	copy(image.MerkleRoot[:], data[29:61])
	off := snapshotHeaderSize
	for i := uint64(0); i < recordCount; i++ {
		if off+2 > len(data) {
			return nil, fmt.Errorf("durability/snapshot: truncated entityID len at record %d", i)
		}
		eidLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+eidLen > len(data) {
			return nil, fmt.Errorf("durability/snapshot: truncated entityID at record %d", i)
		}
		entityID := string(data[off : off+eidLen])
		off += eidLen
		if off+crdtEntryWireSize > len(data) {
			return nil, fmt.Errorf("durability/snapshot: truncated entry at record %d", i)
		}
		entry, err := decodeCRDTEntry(data[off : off+crdtEntryWireSize])
		if err != nil {
			return nil, fmt.Errorf("durability/snapshot: record %d: %w", i, err)
		}
		off += crdtEntryWireSize
		image.Records = append(image.Records, SnapshotRecord{EntityID: entityID, Entry: entry})
	}
	if off != len(data) {
		return nil, fmt.Errorf("durability/snapshot: trailing %d bytes after %d records", len(data)-off, recordCount)
	}
	return image, nil
}

// snapshotKey is the LocalFS key for the recovery image at the given watermark.
// "ckpt/" is a separate prefix from the flusher's "l0/" so the query index and
// the recovery image never collide, and a ListObjects("ckpt/") enumerates
// exactly the available checkpoints.
func snapshotKey(lamportHigh uint64) string {
	// "ckpt/%d" — decimal so ListObjects sorts by watermark ascending
	// (S3/LocalFS sort is lexicographic; decimal under a fixed prefix is
	// monotone for the full uint64 range only if widths agree — recovery does
	// not rely on list order, it loads by exact key, so plain %d is sufficient).
	return fmt.Sprintf("ckpt/%d", lamportHigh)
}

// WriteSnapshotImage writes the dot-bearing recovery image to lfs at the
// checkpoint watermark. It is the durable half of SnapshotToLSM.
func (lfs *LocalFS) WriteSnapshotImage(ctx context.Context, image *SnapshotImage) error {
	data, err := encodeSnapshotImage(image)
	if err != nil {
		return err
	}
	if err := lfs.Upload(ctx, snapshotKey(image.LamportHigh), bytes.NewReader(data), int64(len(data))); err != nil {
		return fmt.Errorf("durability/snapshot: write image %s: %w", snapshotKey(image.LamportHigh), err)
	}
	return nil
}

// LoadSnapshotImage reads and decodes the recovery image at the given watermark.
// A missing image returns a wrapped error matching os.ErrNotExist. Recovery uses
// full WAL replay in that case.
func (lfs *LocalFS) LoadSnapshotImage(ctx context.Context, lamportHigh uint64) (*SnapshotImage, error) {
	rc, err := lfs.Download(ctx, "", snapshotKey(lamportHigh))
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("durability/snapshot: read image %s: %w", snapshotKey(lamportHigh), err)
	}
	image, err := decodeSnapshotImage(data)
	if err != nil {
		return nil, fmt.Errorf("durability/snapshot: decode image %s: %w", snapshotKey(lamportHigh), err)
	}
	if image.LamportHigh != lamportHigh {
		return nil, fmt.Errorf("durability/snapshot: image watermark mismatch: header=%d key=%d", image.LamportHigh, lamportHigh)
	}
	return image, nil
}

// SnapshotExists reports whether a recovery image exists at the given watermark.
func (lfs *LocalFS) SnapshotExists(ctx context.Context, lamportHigh uint64) (bool, error) {
	keys, err := lfs.ListObjects(ctx, "", snapshotKey(lamportHigh), 1)
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if k == snapshotKey(lamportHigh) {
			return true, nil
		}
	}
	return false, nil
}

// snapshotDelta builds a synthetic CRDTDelta whose Entries sequence yields the
// image's records, so engine.Join can merge the recorded dots into a seed
// engine without re-minting them (Join honors the recorded Dot() — it forwards
// entry.Dot() verbatim into the per-shard dot-union merge). All other
// CRDTDelta fields are zero: Join reads only delta.Entries (it never
// dereferences delta.Release/ebrPart/arenaRef/rootRef/deltaPool), so a
// heap-only synthetic delta is safe and needs no Release. The post-Join
// lamport watermark is set by the caller via AdvanceLamportTo(ckpt.LamportHigh)
// (Join's per-entry AdvanceLamportTo is a monotone max, bounded above by
// ckpt.LamportHigh since every image dot was minted at or before the
// checkpoint).
func snapshotDelta(image *SnapshotImage) eng.CRDTDelta {
	records := image.Records // capture for the closure
	return eng.CRDTDelta{
		Entries: func(yield func(entityID string, entry eng.CRDTEntry) bool) {
			for i := range records {
				if !yield(records[i].EntityID, records[i].Entry) {
					return
				}
			}
		},
	}
}

// NewSnapshotMemTable constructs a MemTable and LocalFS-backed L0Flusher for
// the query index. It returns the allocator and flusher for lifecycle
// visibility; the caller closes the MemTable:
//
//	alloc, flusher, mt, err := NewSnapshotMemTable(lfs, fallbackDir)
//	if err != nil { ... }
//	defer mt.Close(ctx)
//
// The arena holds 4 MiB and at most 1<<20 latest-per-entity rows, which keeps
// checkpoint allocation off the hot path.
func NewSnapshotMemTable(lfs *LocalFS, fallbackDir string) (*database.JemallocAllocator, *database.L0Flusher, *database.MemTable, error) {
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "local") // bucket ignored by LocalFS
	// arenaSize 4 MiB + maxEntries 1<<20 is generous for a checkpoint's
	// latest-per-entity rows; growth reallocs are not a checkpoint concern.
	mt := database.NewMemTable(alloc, 4<<20, 1<<20, flusher, fallbackDir)
	return alloc, flusher, mt, nil
}

// SnapshotToLSM persists the image and latest-entry map captured by
// eng.CaptureShardsPinned during Bridge.AppendCheckpoint. It writes the full
// recovery image to "ckpt/<LamportHigh>" and, when mt is non-nil, writes and
// flushes the latest entry per entity to the Arrow query index under "l0/".
// A nil mt omits only the query index; bounded recovery still works.
//
// Root, watermark, and image must come from the same pinned walk (ADR-0045 §4).
// Taking a separate State snapshot would allocate another merged view and could
// include local dots minted after the checkpoint watermark. The caller holds the
// EBR pin across this call because image.Records contains arena-backed entity
// IDs; the pin prevents their storage from being reclaimed before encoding.
func SnapshotToLSM(
	ctx context.Context,
	mt *database.MemTable,
	lfs *LocalFS,
	image *SnapshotImage,
	latest map[string]eng.CRDTEntry,
) error {
	if lfs == nil {
		return errors.New("durability/snapshot: nil LocalFS")
	}
	if image == nil {
		return errors.New("durability/snapshot: nil image (capture ran without a snapshotter?)")
	}

	// 1. Authoritative recovery image (full dot set).
	if err := lfs.WriteSnapshotImage(ctx, image); err != nil {
		return err
	}

	// 2. Query-tier Arrow index (latest entry per entity, payload=sentry).
	//    CRDTEntry carries no payload body — only PayloadDigest — so the index
	//    stores the real digest and an empty body. MemTable.Write trusts the
	//    caller's PayloadDigest.
	if mt != nil {
		for entityID, entry := range latest {
			if err := mt.Write(ctx, queryTierEvent(entityID, entry)); err != nil {
				return fmt.Errorf("durability/snapshot: memtable write %q: %w", entityID, err)
			}
		}
		if err := mt.Flush(ctx); err != nil {
			return fmt.Errorf("durability/snapshot: memtable flush: %w", err)
		}
	}

	return nil
}

// queryTierEvent converts the latest entry for an entity into the row shape
// shared by SnapshotToLSM and the Bridge's delta flush. The row has no payload
// body; it preserves the entry's digest for MemTable.Write.
func queryTierEvent(entityID string, entry eng.CRDTEntry) database.TriTemporalEvent {
	return database.TriTemporalEvent{
		EntityID:       entityID,
		SystemTime:     entry.SystemTime,
		ValidTimeStart: entry.ValidTimeStart,
		ValidTimeEnd:   entry.ValidTimeEnd,
		AssertionTime:  entry.AssertionTime,
		H3Index:        entry.H3Index,
		Payload:        nil, // the query index stores digests, not payload bodies
		PayloadDigest:  entry.PayloadDigest,
	}
}

// compareDotsLocal mirrors pkg/sync.compareDots (unexported there) so the
// snapshot's "latest entry" pick is deterministic and matches the engine's own
// dot ordering. (DotNodeID bytes lexicographic, then DotCounter ascending.)
func compareDotsLocal(a, b eng.CausalDot) int {
	for k := 0; k < 16; k++ {
		if a.NodeID[k] != b.NodeID[k] {
			if a.NodeID[k] < b.NodeID[k] {
				return -1
			}
			return 1
		}
	}
	if a.Counter < b.Counter {
		return -1
	}
	if a.Counter > b.Counter {
		return 1
	}
	return 0
}
