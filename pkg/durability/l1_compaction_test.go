// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Per-entity L0-to-L1 compaction tests over real LocalFS storage (ADR-0019).
//
// AsOf lists at most MaxL0Files of an entity's newest L0 files. Without
// compaction, older durable rows can therefore be invisible to a query.
// Compaction merges those files into one sorted L1; AsOf reads that history plus
// the uncompacted L0 tail and uses the manifest to skip superseded L0 keys.
//
// The tests cover recovery of the oldest row beyond the cap, deterministic
// repeated merges, and a query whose dominant row is in the uncompacted tail.
// They live beside LocalFS to avoid an import cycle with internal/database.
package durability

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLocalFS builds a LocalFS in a temporary directory. LocalFS implements the
// uploader, lister, and downloader interfaces used by the storage tests.
func newLocalFS(t *testing.T) *LocalFS {
	t.Helper()
	root := filepath.Join(t.TempDir(), "l0-bucket")
	lfs, err := NewLocalFS(root)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return lfs
}

// insertRow writes one tri-temporal row through a fresh SkipListArena and
// flushes it to L0. Its open-ended valid interval uses the largest int64-safe
// endpoint shared by these fixtures.
func insertRow(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, flusher *database.L0Flusher, entityID string, sysNs int64, payload []byte) {
	t.Helper()
	const openEnd int64 = 9_000_000_000_000_000_000
	sl := database.NewSkipListArena(alloc, 2*1024*1024)
	// Build the composite key + packed value via the test-helper-style layout
	// (mirrors the ADR-0018 insertEntityRow helper, but lives here in
	// pkg/durability so it can use a real *LocalFS).
	fullHash := sha256.Sum256([]byte(entityID))
	key := make([]byte, 40)
	copy(key[0:16], fullHash[:16])
	key[16] = byte(uint64(sysNs) >> 56)
	key[17] = byte(uint64(sysNs) >> 48)
	key[18] = byte(uint64(sysNs) >> 40)
	key[19] = byte(uint64(sysNs) >> 32)
	_ = key[20]
	// BigEndian sysNs (key[16:24]) + validNs (key[24:32]) + assertNs (key[32:40]).
	// To keep the row consistent, set validNs == sysNs and assertNs == sysNs.
	putBE64(key[16:24], uint64(sysNs))
	putBE64(key[24:32], uint64(sysNs))
	putBE64(key[32:40], uint64(sysNs))
	pd := sha256.Sum256(payload)
	val := makePackedValue(entityID, 0x89283082803ffff, openEnd, pd, payload)
	err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
	require.NoError(t, err)
	_, err = flusher.FlushFromArena(context.Background(), sl)
	require.NoError(t, err)
	sl.Free()
}

// putBE64 writes a uint64 in the composite key's big-endian field order.
func putBE64(b []byte, v uint64) {
	_ = b[7]
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

// makePackedValue uses the MemTable value layout so these tests can construct
// rows outside package database: entity length and ID, H3 index, ValidTimeEnd,
// payload digest, payload length, and payload.
func makePackedValue(entityID string, h3Index uint64, validTimeEnd int64, pd [32]byte, payload []byte) []byte {
	id := []byte(entityID)
	v := make([]byte, 2+len(id)+8+8+32+4+len(payload))
	off := 0
	v[0] = byte(len(id))
	v[1] = byte(len(id) >> 8)
	off += 2
	copy(v[off:], id)
	off += len(id)
	v[off] = byte(h3Index)
	v[off+1] = byte(h3Index >> 8)
	v[off+2] = byte(h3Index >> 16)
	v[off+3] = byte(h3Index >> 24)
	v[off+4] = byte(h3Index >> 32)
	v[off+5] = byte(h3Index >> 40)
	v[off+6] = byte(h3Index >> 48)
	v[off+7] = byte(h3Index >> 56)
	off += 8
	v[off] = byte(uint64(validTimeEnd))
	v[off+1] = byte(uint64(validTimeEnd) >> 8)
	v[off+2] = byte(uint64(validTimeEnd) >> 16)
	v[off+3] = byte(uint64(validTimeEnd) >> 24)
	v[off+4] = byte(uint64(validTimeEnd) >> 32)
	v[off+5] = byte(uint64(validTimeEnd) >> 40)
	v[off+6] = byte(uint64(validTimeEnd) >> 48)
	v[off+7] = byte(uint64(validTimeEnd) >> 56)
	off += 8
	copy(v[off:off+32], pd[:])
	off += 32
	v[off] = byte(uint32(len(payload)))
	v[off+1] = byte(uint32(len(payload)) >> 8)
	v[off+2] = byte(uint32(len(payload)) >> 16)
	v[off+3] = byte(uint32(len(payload)) >> 24)
	off += 4
	copy(v[off:], payload)
	return v
}

// writeNCheckpoints writes n single-event L0 files with strictly increasing
// system times. It returns the oldest time and payload for the capped-read and
// post-compaction queries.
func writeNCheckpoints(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, entity string, n int) (oldestSysNs int64, oldestPayload []byte) {
	t.Helper()
	flusher := database.NewL0Flusher(alloc, lfs, "l0-bucket")
	base := time.Now().UnixNano()
	oldestSysNs = base
	oldestPayload = []byte("ckpt-0")
	for i := 0; i < n; i++ {
		sys := base + int64(i)
		payload := []byte("ckpt-" + strconv.Itoa(i))
		if i == 0 {
			oldestSysNs = sys
			oldestPayload = payload
		}
		insertRow(t, alloc, lfs, flusher, entity, sys, payload)
	}
	return oldestSysNs, oldestPayload
}

// TestOldestQuerySurvivesMaxL0CapRedThenGreen first queries beyond the L0 cap
// and requires ErrEntityNotFound. It then compacts the same files and requires
// the identical query to return the oldest row with its original system time,
// payload, and digest.
func TestOldestQuerySurvivesMaxL0CapRedThenGreen(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 20
	const maxL0 = 10 // resolver MaxL0Files = 10 → the oldest 10 are silently dropped without compaction
	oldestSysNs, oldestPayload := writeNCheckpoints(t, alloc, lfs, entity, N)

	// Without compaction, the capped resolver lists only the newest ten L0 files.
	// The oldest durable row is outside that window and must be reported missing.
	redResolver := database.NewResolver(lfs, lfs, alloc, "l0-bucket", database.ResolverConfig{MaxL0Files: maxL0})
	OldestValid := time.Unix(0, oldestSysNs)
	OldestTx := time.Unix(0, oldestSysNs+1)
	redGot, redErr := redResolver.AsOf(ctx, entity, OldestValid, OldestTx)
	// The cap form reproduces: the oldest durable row is invisible under the cap
	// (the 11th-20th-oldest files are dropped by the capped list; the reverse
	// sort keeps the newest 10). The oldest checkpoint's validStart==sysTime is
	// before the 11th-oldest, so no scanned row covers validTime=oldestSysNs.
	assert.ErrorIsf(t, redErr, database.ErrEntityNotFound, "oldest query (sysTime=%d) must fail with MaxL0Files=%d and no L1", oldestSysNs, maxL0)
	assert.Nilf(t, redGot, "oldest durable row unexpectedly resolved outside the L0 cap")

	// Compaction merges all 20 L0 files into one L1, making the oldest row
	// available independently of the L0 listing cap.
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "l0-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (20 L0 files exist)")
	require.Equalf(t, N, res.Rows, "L1 must preserve all %d input rows", N)
	require.NotEmptyf(t, res.L1Key, "an L1 must be written")
	require.NotEmptyf(t, res.L0Files, "the manifest must list the merged L0 keys")
	require.Lenf(t, res.L0Files, N, "all %d L0 keys must be in the manifest", N)

	l1s, _ := lfs.ListObjects(ctx, "local", "l1/"+fmt.Sprintf("%x", h8[:])+"/", 0)
	require.Lenf(t, l1s, 1, "one entity must have exactly one L1 file; got %v", l1s)
	mans, _ := lfs.ListObjects(ctx, "local", "compaction/"+fmt.Sprintf("%x", h8[:])+"/", 0)
	require.Lenf(t, mans, 1, "one compaction must produce exactly one manifest; got %v", mans)

	// The same capped resolver must now return the oldest dominant through the
	// merged L1.
	greenResolver := database.NewResolver(lfs, lfs, alloc, "l0-bucket", database.ResolverConfig{MaxL0Files: maxL0})
	got, gerr := greenResolver.AsOf(ctx, entity, OldestValid, OldestTx)
	require.NoErrorf(t, gerr, "oldest query failed through the merged L1")
	require.NotNilf(t, got, "oldest query returned no result through the merged L1")
	assert.Equalf(t, entity, got.EntityID, "compacted query returned a different entity")
	assert.Equalf(t, oldestSysNs, got.SystemTime, "compacted query did not return the oldest SystemTime")
	wantDigest := sha256.Sum256(oldestPayload)
	assert.Equalf(t, wantDigest, got.PayloadDigest, "compacted query did not preserve the oldest payload digest")
	assert.Equalf(t, oldestPayload, got.Payload, "compacted query did not preserve the oldest payload")

	t.Logf("before compaction, oldest query (sysTime=%d) with MaxL0Files=%d missed %d durable files", oldestSysNs, maxL0, N-maxL0)
	t.Logf("compaction merged %d L0 files into %s (%d rows); oldest query returned sysTime=%d and digest=%x", len(res.L0Files), res.L1Key, res.Rows, got.SystemTime, got.PayloadDigest)
}

// TestIdempotentMergeTwiceSameL1Bytes compacts an unchanged L0 set twice and
// requires the same key and byte-identical sorted L1 contents.
func TestIdempotentMergeTwiceSameL1Bytes(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 8
	writeNCheckpoints(t, alloc, lfs, entity, N)
	h8 := database.EntityHash8(entity)

	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "l0-bucket", database.DefaultCompactionConfig())
	res1, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	l1Bytes1 := readObject(t, lfs, res1.L1Key)

	// Re-run Compaction on the same L0 set (the L0 files were not deleted —
	// delete-after-read-safety). firstSysT is the oldest row's sysTime, unchanged;
	// the L1 key is the same; Upload O_TRUNCs (LocalFS) so the file is replaced
	// byte-identically with the same sorted content.
	res2, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Equalf(t, res1.L1Key, res2.L1Key, "idempotency: the L1 key must be the same (firstSysT is deterministic)")

	l1Bytes2 := readObject(t, lfs, res2.L1Key)
	assert.Equalf(t, l1Bytes1, l1Bytes2, "L1 bytes differ across identical merges (len1=%d len2=%d)", len(l1Bytes1), len(l1Bytes2))
}

// readObject downloads a single key as raw bytes.
func readObject(t *testing.T, lfs *LocalFS, key string) []byte {
	t.Helper()
	rc, err := lfs.Download(context.Background(), "local", key)
	require.NoErrorf(t, err, "download %s", key)
	defer rc.Close()
	data := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, rerr := rc.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	return data
}

// TestAsOfScansL1PlusUncompactedTail writes newer L0 rows after compaction. The
// query's dominant is one of those tail rows, so reading only the L1 would
// return an older value.
func TestAsOfScansL1PlusUncompactedTail(t *testing.T) {
	ctx := context.Background()
	lfs := newLocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const bulk = 20
	const maxL0 = 10
	const extraTail = 5

	oldestSysNs, _ := writeNCheckpoints(t, alloc, lfs, entity, bulk)
	// Run compaction → one L1 (the 20-row merged history).
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "l0-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	_, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)

	// Write extraTail more checkpoints with sysTime newer than the L1's newest.
	// These form the uncompacted tail (L0 files), not in the L1.
	flusher := database.NewL0Flusher(alloc, lfs, "l0-bucket")
	tailLatestSysNs := oldestSysNs + int64(bulk-1) // the L1's newest (last of the bulk)
	var tailDominantSys int64
	var tailDominantPayload []byte
	for i := 0; i < extraTail; i++ {
		sys := tailLatestSysNs + int64(10*(i+1)) // strictly newer than the L1's newest
		payload := []byte("tail-" + strconv.Itoa(i))
		if sys > tailDominantSys {
			tailDominantSys = sys
			tailDominantPayload = payload
		}
		insertRow(t, alloc, lfs, flusher, entity, sys, payload)
	}

	// Query at a validTime covered by both the oldest L1 row [oldestSysNs, openEnd)
	// and the tail dominant [tailDominantSys, openEnd) (openEnd so all rows cover
	// every time >= their validStart). The tail dominant has a newer sysTime than
	// every L1 row → it must win. The L1 alone would return its newest row (wrong);
	// scanning the tail picks the newer tail dominant. This proves AsOf scans both.
	resolver := database.NewResolver(lfs, lfs, alloc, "l0-bucket", database.ResolverConfig{MaxL0Files: maxL0})
	qValid := time.Unix(0, tailDominantSys)
	qTx := time.Unix(0, tailDominantSys+1)
	got, gerr := resolver.AsOf(ctx, entity, qValid, qTx)
	require.NoErrorf(t, gerr, "query failed while reading L1 and the uncompacted tail")
	require.NotNil(t, got)
	assert.Equalf(t, tailDominantSys, got.SystemTime, "query did not select the newer uncompacted tail row")
	wantDigest := sha256.Sum256(tailDominantPayload)
	assert.Equalf(t, wantDigest, got.PayloadDigest, "query did not preserve the tail row's payload digest")
}
