package durability

// Day 11 — M1: the LSM↔DURABILITY seam. The snapshot.
//
// ROOT CAUSE (Day-11 §0): pkg/durability/recovery.go is WAL-replay-only. On
// crash it replays EVERY mutation since genesis because nothing durable holds
// the merged CRDT state. Recovery is O(writes-since-boot), not
// O(writes-since-last-checkpoint).
//
// THE SEAM: on checkpoint, snapshot the LIVE HAMT into two artifacts, both rooted
// under the LocalFS directory:
//
//   1. A dot-bearing RECOVERY IMAGE at "ckpt/<LamportHigh>" (a plain binary,
//      NOT Arrow). It carries the FULL dot set {(DotNodeID, DotCounter)} per
//      entity — the exact state MerkleRoot() folds (hamt.go:265 hashes the
//      sorted full dot set; it does NOT depend on maphash.Seed). On recovery,
//      this image is Joined into a seed engine, so Merkle equality holds even
//      when foreign dots are present (full-replay cannot reproduce foreign dots
//      — the seed trick only re-mints LOCAL consecutive dots). This is the
//      artifact that makes T3 pass and makes bounded recovery STRICTLY BETTER
//      than full replay.
//
//   2. An Arrow IPC INDEX under "l0/<...>" via the EXISTING internal/database
//      MemTable/L0Flusher (the query-tier snapshot). It stores the LATEST entry
//      per entity with payload=SENTRY — CRDTEntry carries NO payload body, only
//      PayloadDigest (hamt.go:29, ADR 10: 120-byte struct), and MemTable.Write
//      trusts the caller's PayloadDigest (it does NOT recompute it from the
//      payload — memtable.go:166 packs event.PayloadDigest as-is). So the index
//      carries the REAL digest and an empty body: honest — the LSM snapshot is
//      the INDEX, not the payload store. Writing + flushing the MemTable here
//      is the act that WIRES internal/database (M8: first importer outside its
//      own package+tests).
//
// HONEST SCOPE (ADR-0016 §5): the query-tier INDEX is wired (M8 satisfied) but
// its tri-temporal dominance resolution (the resolver in query.go) is NOT
// exercised by Day-11 teeth — that is the query seam, a later day. The Arrow
// rows are well-formed (real digest + sentry body) so a future resolver reads
// them without rework.
//
// EBR SAFETY (T4): State() does NOT pin an EBR epoch internally. The EBR()
// docstring (crdt.go:1316) documents that a bare state := eng.State() under
// concurrent InsertLocal can dereference a shard root a racing CAS retired and
// freed — a use-after-free. SnapshotToLSM pins the epoch AROUND State() +
// ForEach via explicit Acquire()+Enter()/Release() (reclamation.go:120 sets
// active=true, epoch=globalEpoch, which holds freeRetiredList back). The
// snapshot extract is therefore safe under concurrent PutLocal (T4).

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	eng "github.com/hr18vk/supremum/pkg/sync"

	"github.com/hr18vk/supremum/internal/database"
)

const (
	// snapshotMagic identifies the recovery-image file format.
	snapshotMagic = "SNSP"
	// snapshotVersion is the recovery-image format version. Bump + write a
	// migration if the wire layout changes; Load refuses other versions.
	snapshotVersion = uint8(1)
	// crdtEntryWireSize is the fixed big-endian size of one CRDTEntry on the
	// wire (120 bytes — ADR 10). A fixed size lets decode bounds-check without
	// per-field reflection and avoids unsafe struct-scan endianness traps.
	crdtEntryWireSize = 120
	// snapshotHeaderSize is the fixed header before the record stream.
	snapshotHeaderSize = 4 + 1 + 8 + 8 // magic + version + lamportHigh + recordCount
)

// SnapshotRecord pairs an entityID with one of its CRDTEntries from the live
// HAMT. The recovery image is a flat stream of these.
type SnapshotRecord struct {
	EntityID string
	Entry    eng.CRDTEntry
}

// SnapshotImage is the in-memory dot-bearing recovery artifact decoded from the
// "ckpt/<LamportHigh>" file. LamportHigh is the watermark the snapshot was
// taken at (== the checkpoint's LamportHigh); it bounds the WAL replay tail.
type SnapshotImage struct {
	// fieldalignment: slice (24B) before uint64. Off the hot path.
	Records     []SnapshotRecord
	LamportHigh uint64
}

// Spell out the CRDTEntry wire layout so encode/decode stay honest about what
// the index/recovery image persists. Changes to CRDTEntry (ADR 10) require a
// snapshotVersion bump + a migration: older images are refused, not
// misinterpreted.
//
//	LAYOUT (big-endian, 120 bytes):
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

// encodeSnapshotImage serializes image to the recovery-image wire format. The
// records are emitted in (entityID, dot) order so two engines that reached the
// same dot set produce byte-identical images — a property T3 leans on
// transitively (the recovery Join is order-independent, but a canonical
// encoding makes a future snapshot-equality tooth byte-comparable).
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
	hdr[4] = snapshotVersion
	binary.BigEndian.PutUint64(hdr[5:13], image.LamportHigh)
	binary.BigEndian.PutUint64(hdr[13:21], uint64(len(ordered)))
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
	return buf, nil
}

// decodeSnapshotImage parses the recovery-image wire format. It refuses
// mismatched magic/version and truncation so recovery never rebuilds on a
// suspect image (the no-silent-misinterpretation rule).
func decodeSnapshotImage(data []byte) (*SnapshotImage, error) {
	if len(data) < snapshotHeaderSize {
		return nil, fmt.Errorf("durability/snapshot: header too short: %d", len(data))
	}
	if string(data[0:4]) != snapshotMagic {
		return nil, fmt.Errorf("durability/snapshot: bad magic %q", data[0:4])
	}
	if data[4] != snapshotVersion {
		return nil, fmt.Errorf("durability/snapshot: unsupported version %d (want %d)", data[4], snapshotVersion)
	}
	lamportHigh := binary.BigEndian.Uint64(data[5:13])
	recordCount := binary.BigEndian.Uint64(data[13:21])

	image := &SnapshotImage{LamportHigh: lamportHigh, Records: make([]SnapshotRecord, 0, recordCount)}
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
	// not rely on list order, it loads by exact key, so plain %d is honest).
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

// LoadSnapshotImage reads + decodes the recovery image at the given watermark.
// Returns os.ErrNotExist-equivalent (wrapped) if absent; the recovery path
// treats absence as "no snapshot → full-replay fallback" (T2).
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

// snapshotDelta builds a synthetic CRDTDelta whose Entries Seq yields the
// image's records, so engine.Join can merge the recorded dots into a seed
// engine WITHOUT re-minting them (Join honors the recorded Dot() — crdt.go:1067
// forwards entry.Dot() verbatim into the per-shard dot-union merge). All other
// CRDTDelta fields are zero: Join reads ONLY delta.Entries (verified at
// crdt.go:1051-1278 — it never dereferences delta.Release/ebrPart/arenaRef/
// rootRef/deltaPool), so a heap-only synthetic delta is safe and needs no
// Release. The post-Join lamport watermark is nailed by the caller via
// AdvanceLamportTo(ckpt.LamportHigh) (Join's per-entry AdvanceLamportTo is a
// monotone max, bounded above by ckpt.LamportHigh since every image dot was
// minted at or before the checkpoint).
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

// NewSnapshotMemTable constructs a FRESH MemTable (the query-tier index target)
// backed by a LocalFS-armed L0Flusher. It returns the allocator + flusher for
// lifecycle visibility; only the MemTable needs Close(ctx). Use:
//
//	alloc, flusher, mt, err := NewSnapshotMemTable(lfs, fallbackDir)
//	if err != nil { ... }
//	defer mt.Close(ctx)
//
// arenaSize/maxEntries are sized for a checkpoint-worth of latest-per-entity
// rows (small, off the hot path). The cgo jemalloc allocator is constructed
// here — internal/database passes -race at HEAD (commit-verified), so this is
// safe to call from the Bridge and from tests.
func NewSnapshotMemTable(lfs *LocalFS, fallbackDir string) (*database.JemallocAllocator, *database.L0Flusher, *database.MemTable, error) {
	alloc := database.NewJemallocAllocator()
	flusher := database.NewL0Flusher(alloc, lfs, "local") // bucket ignored by LocalFS
	// arenaSize 4 MiB + maxEntries 1<<20 is generous for a checkpoint's
	// latest-per-entity rows; growth reallocs are not a checkpoint concern.
	mt := database.NewMemTable(alloc, 4<<20, 1<<20, flusher, fallbackDir)
	return alloc, flusher, mt, nil
}

// SnapshotToLSM is the Day-11 M1 seam. On checkpoint it:
//  1. EBR-pins and extracts the FULL dot set from the live HAMT,
//  2. writes the dot-bearing recovery image to lfs ("ckpt/<LamportHigh>"),
//  3. writes the latest-entry-per-entity Arrow index to mt and flushes it
//     ("l0/<...>" — this is the M8 wire of internal/database).
//
// The recovery image (2) is authoritative for MerkleRoot equality (T3); the
// Arrow index (3) is the query-tier snapshot (wired, semantics out of Day-11
// scope). mt may be nil — in that case the Arrow index is skipped (recovery
// still works; only the query index is omitted). This lets a deployment run
// bounded recovery WITHOUT the cgo/Arrow index if it only needs the CRDT.
//
// WATERMARK (the honest invariant, NOT a TOCTOU guard): the image is stamped
// with `ckpt.LamportHigh` — the watermark the Bridge captured atomically when
// it wrote the WAL checkpoint record (AppendCheckpoint reads LamportCounter()
// once and passes it in). SnapshotToLSM does NOT re-read engine.LamportCounter()
// and compare it to ckpt.LamportHigh: under concurrent PutLocal the live counter
// advances between the checkpoint capture and this extract, so such a check
// would race (T4) and fire spuriously. The extract records whatever dots are
// live NOW (which may include a few dots minted just after the checkpoint), all
// stamped under watermark ckpt.LamportHigh. Recovery is CORRECT regardless:
// dots in the image with DotCounter > ckpt.LamportHigh are also in the WAL
// (their PutLocal fsync'd) and would be replayed by the post-ckpt filter — but
// Join's dot-union dedups them (same DotNodeID+Counter), so the recovered dot
// SET is identical to full replay. The watermark bounds the replay TAIL, not
// the image contents; the image is a best-effort live snapshot at the seam.
func SnapshotToLSM(
	ctx context.Context,
	engine *eng.DeltaCRDTEngine,
	mt *database.MemTable,
	ckpt WALCheckpoint,
	lfs *LocalFS,
) error {
	if engine == nil {
		return errors.New("durability/snapshot: nil engine")
	}
	if lfs == nil {
		return errors.New("durability/snapshot: nil LocalFS")
	}

	// EBR-pin AROUND State()+ForEach so a concurrent InsertLocal (T4) cannot
	// retire+free a shard root the extract is iterating. Enter() sets
	// active=true, epoch=globalEpoch (reclamation.go:120) which holds
	// freeRetiredList back; Release() calls Exit(). This is the explicit form
	// of the crdt.go:1316-1324 EBR() contract (Acquire must be followed by
	// Enter to actually pin).
	ebr := engine.EBR()
	participant := ebr.Acquire()
	participant.Enter(ebr)
	defer ebr.Release(participant)

	state := engine.State()
	if state == nil {
		return errors.New("durability/snapshot: engine State() returned nil")
	}

	image := &SnapshotImage{LamportHigh: ckpt.LamportHigh}
	latest := make(map[string]eng.CRDTEntry, 256) // entityID → latest entry (for the Arrow index)
	state.ForEach(func(entityID string, entries []eng.CRDTEntry) bool {
		for i := range entries {
			image.Records = append(image.Records, SnapshotRecord{
				EntityID: entityID,
				Entry:    entries[i],
			})
			// Latest = max (DotNodeID, DotCounter) — the add-wins "winner" for
			// the query index's one-row-per-entity representative. The FULL dot
			// set is in the recovery image; the index only needs a representative.
			cur, ok := latest[entityID]
			if !ok {
				latest[entityID] = entries[i]
				continue
			}
			cmp := compareDotsLocal(cur.Dot(), entries[i].Dot())
			if cmp < 0 {
				latest[entityID] = entries[i]
			}
		}
		return true
	})

	// 1. Authoritative recovery image (full dot set).
	if err := lfs.WriteSnapshotImage(ctx, image); err != nil {
		return err
	}

	// 2. Query-tier Arrow index (latest entry per entity, payload=sentry).
	//    CRDTEntry carries no payload body — only PayloadDigest — so the index
	//    stores the real digest + an empty body. MemTable.Write trusts the
	//    caller's PayloadDigest (memtable.go:166), so the digest is honest.
	if mt != nil {
		sentry := []byte(nil)
		for entityID, entry := range latest {
			event := database.TriTemporalEvent{
				EntityID:       entityID,
				SystemTime:     entry.SystemTime,
				ValidTimeStart: entry.ValidTimeStart,
				ValidTimeEnd:   entry.ValidTimeEnd,
				AssertionTime:  entry.AssertionTime,
				H3Index:        entry.H3Index,
				Payload:        sentry,
				PayloadDigest:  entry.PayloadDigest,
			}
			if err := mt.Write(ctx, event); err != nil {
				return fmt.Errorf("durability/snapshot: memtable write %q: %w", entityID, err)
			}
		}
		if err := mt.Flush(ctx); err != nil {
			return fmt.Errorf("durability/snapshot: memtable flush: %w", err)
		}
	}

	return nil
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
