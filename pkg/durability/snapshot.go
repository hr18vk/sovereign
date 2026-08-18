// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date (2029-08-15).

package durability

// — M1: the LSM↔DURABILITY seam. The snapshot.
//
// ROOT CAUSE: pkg/durability/recovery.go is WAL-replay-only. On
// crash it replays EVERY mutation since genesis because nothing durable holds
// the merged CRDT state. Recovery is O(writes-since-boot), not
// O(writes-since-last-checkpoint).
//
// THE SEAM: on checkpoint, snapshot the LIVE HAMT into two artifacts, both rooted
// under the LocalFS directory:
//
// 1. A dot-bearing RECOVERY IMAGE at "ckpt/<LamportHigh>" (a plain binary,
// NOT Arrow). It carries the FULL dot set {(DotNodeID, DotCounter)} per
// entity — the exact state MerkleRoot() folds (hamt.go:265 hashes the
// sorted full dot set; it does NOT depend on maphash.Seed). On recovery,
// this image is Joined into a seed engine, so Merkle equality holds even
// when foreign dots are present (full-replay cannot reproduce foreign dots
// — the seed trick only re-mints LOCAL consecutive dots). This is the
// artifact that makes T3 pass and makes bounded recovery STRICTLY BETTER
// than full replay.
//
// 2. An Arrow IPC INDEX under "l0/<...>" via the EXISTING internal/database
// MemTable/L0Flusher (the query-tier snapshot). It stores the LATEST entry
// per entity with payload=SENTRY — CRDTEntry carries NO payload body, only
// PayloadDigest (hamt.go:29, ADR 10: 120-byte struct), and MemTable.Write
// trusts the caller's PayloadDigest (it does NOT recompute it from the
// payload — memtable.go:166 packs event.PayloadDigest as-is). So the index
// carries the REAL digest and an empty body: honest — the LSM snapshot is
// the INDEX, not the payload store. Writing + flushing the MemTable here
// is the act that WIRES internal/database (M8: first importer outside its
// own package+tests).
//
// HONEST SCOPE (ADR-0016 §5): the query-tier INDEX is wired (M8 satisfied) but
// its tri-temporal dominance resolution (the resolver in query.go) is NOT
// exercised by guards — that is the query seam, a later day. The Arrow
// rows are well-formed (real digest + sentry body) so a future resolver reads
// them without rework.
//
// EBR SAFETY (T4): State() does NOT pin an EBR epoch internally. The EBR()
// docstring (crdt.go:1316) documents that a bare state:= eng.State() under
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
	"hash/crc32"
	"io"
	"sort"
	"sync/atomic"

	eng "github.com/hr18vk/sovereign/pkg/sync"

	"github.com/hr18vk/sovereign/internal/database"
)

// ErrSnapshotCorrupt is returned by
// decodeSnapshotImage when a v3 image's whole-image CRC32C does not match — the
// image bytes were corrupted (on-disk / in-transit ROT). A snapshot is a DERIVED
// CACHE (the WAL is the truth), so this is NOT a boot-refusal: recovery routes it
// into the LOUD exact-WAL fallback (recovery.go — the suspect image is DISCARDED
// and state is rebuilt from the WAL, never silently used). Fail-LOUD, not fatal.
var ErrSnapshotCorrupt = errors.New("durability/snapshot: whole-image CRC32C mismatch (corrupt image)")

// snapshotCastagnoliTable is the package-level CRC32C (Castagnoli) table — built
// ONCE, never per image (no crc32.New on the snapshot path). On ARM64 Graviton the
// Castagnoli checksum dispatches to the hardware CRC32 instruction.
var snapshotCastagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// snapshotCRC32Skip is a TEST-ONLY bug-injection seam (guard T4): when
// true, the v3 CRC COMPARISON is skipped (the CRC is still computed), so the
// corrupt-and-detect guard can prove the check is LOAD-BEARING — with it compiled
// out, a corrupted image decodes SILENTLY and the guard goes RED. The zero value
// (false) is the secure default (verify ON); production code never sets it.
var snapshotCRC32Skip atomic.Bool

const (
	// snapshotMagic identifies the recovery-image file format.
	snapshotMagic = "SNSP"
	// snapshotVersionV2 is the LEGACY recovery-image format (
	// §11.5): the header carries CutSeq + MerkleRoot (the anchor binding) but NO
	// content checksum. decodeSnapshotImage still ACCEPTS v2 (an existing on-disk
	// image must keep decoding), but v2 is disclosed-UNPROTECTED — retroactive
	// integrity is impossible for bytes already written without a CRC.
	snapshotVersionV2 = uint8(2)
	// snapshotVersionV3 is the CURRENT format: the
	// SAME 61-byte header + record stream, PLUS a trailing 4-byte big-endian
	// CRC32C (Castagnoli) computed over the ENTIRE image (header ‖ all records).
	// The header layout is UNCHANGED (the version byte is the only header delta);
	// the CRC is a TRAILER, not a header field. A snapshot is written WHOLE (one
	// Upload of a complete buffer), so it has NO torn-tail concept: any CRC
	// mismatch or short read is corruption = FAIL LOUD (ErrSnapshotCorrupt) → the
	// loud exact-WAL fallback, never a silent use of rotten bytes.
	snapshotVersionV3 = uint8(3)
	// crdtEntryWireSize is the fixed big-endian size of one CRDTEntry on the
	// wire (120 bytes — ADR 10). A fixed size lets decode bounds-check without
	// per-field reflection and avoids unsafe struct-scan endianness traps.
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

// SnapshotImage is the in-memory dot-bearing recovery artifact decoded from the
// "ckpt/<LamportHigh>" file. LamportHigh is the watermark the snapshot was
// taken at (== the checkpoint's LamportHigh); it bounds the WAL replay tail.
//
// CutSeq + MerkleRoot are copied from the 0x05
// checkpoint record this image belongs to, at capture time. At load, recovery
// requires them to MATCH the anchor's. The ckpt/<watermark> key repeats across
// back-to-back checkpoints (drainCheckpoints runs one AppendCheckpoint per
// pending crossing with no intervening local write, and the key is maxLocalDot),
// so the file at the key can be a LATER checkpoint's image — stale-but-valid
// state, not corruption. A binding mismatch DISARMS the integrity checks and
// falls back to exact-WAL replay; it NEVER refuses the boot.
type SnapshotImage struct {
	// fieldalignment: fixed-size arrays + slice, then uint64s. Off the hot path.
	Records     []SnapshotRecord
	MerkleRoot  [32]byte
	LamportHigh uint64
	CutSeq      uint64
}

// Spell out the CRDTEntry wire layout so encode/decode stay honest about what
// the index/recovery image persists. Changes to CRDTEntry (ADR 10) require a
// snapshotVersion bump + a migration: older images are refused, not
// misinterpreted.
//
//	LAYOUT (big-endian, 120 bytes):
//
// [0:32) PayloadDigest
// [32:48) OriginNodeID
// [48:64) DotNodeID
// [64:72) DotCounter
// [72:80) SystemTime
// [80:88) ValidTimeStart
// [88:96) ValidTimeEnd
// [96:104) AssertionTime
// [104:112) DecisionTime
// [112:120) H3Index
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
// encoding makes a future snapshot-equality guard byte-comparable).
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
	//append the whole-image CRC32C (Castagnoli) as a trailing
	// 4-byte big-endian trailer, computed over the ENTIRE image so far (the 61-byte
	// header ‖ every record). A v3 image is written WHOLE (one Upload), so there is
	// no torn-tail case — at decode the CRC is recomputed over all-but-last-4 and
	// any mismatch is corruption (ErrSnapshotCorrupt), never a partial accept.
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], crc32.Checksum(buf, snapshotCastagnoliTable))
	buf = append(buf, crcBuf[:]...)
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
	//version-selective integrity. A v3 image carries a trailing
	// whole-image CRC32C; v2 is legacy (no CRC — retroactive protection impossible,
	// disclosed-unprotected). A snapshot is written WHOLE (one Upload), so it has NO
	// torn-tail concept: any CRC mismatch or short trailer is corruption →
	// ErrSnapshotCorrupt, which recovery routes to the LOUD exact-WAL fallback
	// (the suspect image is discarded and state rebuilt from the WAL) — NEVER a
	// silent use of rotten bytes and NEVER a boot-refusal (availability preserved).
	switch version := data[4]; version {
	case snapshotVersionV3:
		if len(data) < snapshotHeaderSize+4 {
			return nil, fmt.Errorf("%w: v3 image too short for the CRC trailer (%d bytes)", ErrSnapshotCorrupt, len(data))
		}
		body := data[:len(data)-4]
		want := binary.BigEndian.Uint32(data[len(data)-4:])
		got := crc32.Checksum(body, snapshotCastagnoliTable)
		// The compare is the load-bearing defense; snapshotCRC32Skip (TEST-ONLY)
		// compiles it out so the corrupt-and-detect guard proves it is not decorative.
		if !snapshotCRC32Skip.Load() && want != got {
			return nil, fmt.Errorf("%w: stored %08x, computed %08x over %d image bytes", ErrSnapshotCorrupt, want, got, len(body))
		}
		data = body // decode the records from the image WITHOUT the CRC trailer
	case snapshotVersionV2:
		// legacy v2: NO CRC. Accepted so an existing on-disk image still decodes.
	default:
		return nil, fmt.Errorf("durability/snapshot: unsupported version %d (want %d or %d)", version, snapshotVersionV2, snapshotVersionV3)
	}
	lamportHigh := binary.BigEndian.Uint64(data[5:13])
	recordCount := binary.BigEndian.Uint64(data[13:21])

	image := &SnapshotImage{
		LamportHigh: lamportHigh,
		CutSeq:      binary.BigEndian.Uint64(data[21:29]), // §11.5: the anchor binding
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
//	alloc, flusher, mt, err:= NewSnapshotMemTable(lfs, fallbackDir)
//	if err != nil {... }
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

// SnapshotToLSM is the M1 seam, rewritten
// (ADR-0045). It is now the pure WRITE half of the checkpoint: it consumes
// the image + latest-entry map the caller captured from
// eng.CaptureShardsPinned (ONE EBR-pinned walk that also produced the
// checkpoint's root and watermark) and:
// 1. writes the dot-bearing recovery image to lfs ("ckpt/<LamportHigh>"),
// 2. writes the latest-entry-per-entity Arrow index to mt and flushes it
// ("l0/<...>" — the M8 wire of internal/database).
//
// mt may be nil — the Arrow index is skipped (recovery still works; only the
// query index is omitted), so a deployment can run bounded recovery WITHOUT
// the cgo/Arrow index if it only needs the CRDT.
//
// WHAT CHANGED AT (and why the old contract was wrong): the pre-
// SnapshotToLSM took the engine, pinned internally, and called engine.State()
// — building a SECOND merged view after bridge.go's State().MerkleRoot() had
// already built one. That was (a) the N1 arena-exhaustion vector (the
// merkle_sharded.go merged-view OOM class carried into the checkpoint path:
// each State() duplicates every live entry into fresh arena nodes, and could
// stampede N checkpoints per crossing) and (b) the skew source: the watermark
// was read at T1 and the image walked at T2>T1, so the image carried
// post-watermark local dots.
// The old doc comment called that "correct regardless" because Join's
// dot-union dedups them — measurement refuted it: HEAD replay RE-MINTED those
// dots (InsertLocal at fresh counters), and dot-union cannot dedup what was
// re-minted under a new identity. An earlier change made replay restore recorded
// dots; this change stops PRODUCING the skew: root, watermark, and image
// now come from ONE pinned walk (root == image by construction, watermark ==
// max local dot the walk observed, never above the image). The capture is
// Bridge.AppendCheckpoint's job; this function only persists what it is
// handed. image.Records' EntityID strings are arena-backed: valid because the
// caller holds the EBR pin across this call (ADR-0045 (b)).
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
	// CRDTEntry carries no payload body — only PayloadDigest — so the index
	// stores the real digest + an empty body. MemTable.Write trusts the
	// caller's PayloadDigest (memtable.go:166), so the digest is honest.
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

// queryTierEvent builds the sentry-payload TriTemporalEvent for ONE
// latest-per-entity row of the query-tier Arrow index (— extracted so
// SnapshotToLSM's full flush and the Bridge's delta flush share the ONE row
// shape). CRDTEntry carries no payload body — only PayloadDigest — so Payload is
// the nil sentry and PayloadDigest is the real digest (MemTable.Write trusts the
// caller's digest, memtable.go:166 — the row is honest).
func queryTierEvent(entityID string, entry eng.CRDTEntry) database.TriTemporalEvent {
	return database.TriTemporalEvent{
		EntityID:       entityID,
		SystemTime:     entry.SystemTime,
		ValidTimeStart: entry.ValidTimeStart,
		ValidTimeEnd:   entry.ValidTimeEnd,
		AssertionTime:  entry.AssertionTime,
		H3Index:        entry.H3Index,
		Payload:        nil, // sentry — the LSM snapshot is the INDEX, not the payload store
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
