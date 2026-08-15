// Day 14 (ADR-0019) teeth (the REAL *LocalFS teeth) — the L0→L1 per-entity
// compaction fork, driven against a REAL *LocalFS (the Day-12.5 tooth-principle
// "drive the route, not the seam").
//
// These teeth CLOSE the MaxL0Files silent-data-loss cap. AsOf lists ONLY the
// newest MaxL0Files per-entity L0 files per query; every older per-entity file
// is invisible → a query for an OLD valid-time returns ErrEntityNotFound for
// data IS durable on disk. The L0→L1 per-entity compaction eliminates the cap:
// a background compaction merges the N per-entity L0 files into ONE sorted L1
// file; AsOf scans the L1 (always, the full merged history) + the uncompacted
// L0 tail and skips superseded L0 keys via the compaction manifest.
//
// T1 — THE HEADLINE RED→GREEN over a REAL *LocalFS: write N>MaxL0Files per-
// entity checkpoints; RED the OLDEST query → ErrEntityNotFound (silent loss);
// run the compaction (merges the L0s → ONE L1); GREEN the SAME OLDEST query
// → 200 (the right dominant). T3 — idempotent (merge-twice-same-L1-bytes). T4
// — L1+tail (AsOf scans BOTH, not L1 alone).
//
// These teeth live in pkg/durability (the home of LocalFS) because an
// internal/database test cannot import pkg/durability (import cycle: snapshot.go
// imports internal/database). The byte-identity/scope-hygiene/FROZEN teeth
// (T2/T5/T6) live in internal/database/l1_compaction_track14_test.go.
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

	"github.com/hr18vk/supremum/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// track14LocalFS builds a REAL *LocalFS in a temp dir. LocalFS satisfies all
// three database S3 interfaces (S3Uploader/S3Lister/S3Downloader) by signature
// (compile-check at the bottom of localfs.go). This is the production-on-disk
// path the Day-12.5 tooth-principle demands T1 drive.
func track14LocalFS(t *testing.T) *LocalFS {
	t.Helper()
	root := filepath.Join(t.TempDir(), "track14fs")
	lfs, err := NewLocalFS(root)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return lfs
}

// track14InsertRow inserts one tri-temporal row into a fresh SkipListArena with
// the Day-12.5 open-ended ValidTimeEnd sentry (9e18, int64-safe). The row uses
// the production MemTable.Write packing via the database package's exported
// helpers (the SkipList.Put + the 4.1 binary layout).
func track14InsertRow(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, flusher *database.L0Flusher, entityID string, sysNs int64, payload []byte) {
	t.Helper()
	const openEnd int64 = 9_000_000_000_000_000_000
	sl := database.NewSkipListArena(alloc, 2*1024*1024)
	// Build the composite key + packed value via the test-helper-style layout
	// (mirrors the l0_split_track13_test.go insertEntityRow, but lives here in
	// pkg/durability so it can use the REAL *LocalFS).
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
	val := track14MakePackedValue(entityID, 0x89283082803ffff, openEnd, pd, payload)
	err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
	require.NoError(t, err)
	_, err = flusher.FlushFromArena(context.Background(), sl)
	require.NoError(t, err)
	sl.Free()
}

// putBE64 writes a BigEndian uint64 into b (the composite key's field order).
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

// track14MakePackedValue is the pkg/durability-side copy of the 4.1 binary
// layout (the test_helpers_test.go makePackedValue, reproduced because the
// test helper is package database, not exported). Layout:
// [2B entityIDLen][entityID][8B H3Index][8B ValidTimeEnd][32B PayloadDigest][4B payloadLen][payload].
func track14MakePackedValue(entityID string, h3Index uint64, validTimeEnd int64, pd [32]byte, payload []byte) []byte {
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

// track14WriteN writes `n` per-entity checkpoints for ONE entity, one event per
// checkpoint, with a DISTINCT strictly-increasing SystemTime so the OLDEST
// checkpoint is retrievable ONLY if the read path can see the OLDEST file.
// Returns (oldestSysNs, oldestPayload).
func track14WriteN(t *testing.T, alloc *database.JemallocAllocator, lfs *LocalFS, entity string, n int) (oldestSysNs int64, oldestPayload []byte) {
	t.Helper()
	flusher := database.NewL0Flusher(alloc, lfs, "track14-bucket")
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
		track14InsertRow(t, alloc, lfs, flusher, entity, sys, payload)
	}
	return oldestSysNs, oldestPayload
}

// --- T1 — THE HEADLINE: the OLDEST query survives the MaxL0Files cap via the
// L1 (RED-then-GREEN over a REAL *LocalFS). ---
//
// RED at HEAD pre-compaction: write > MaxL0Files (N=20, MaxL0Files=10) per-
// entity checkpoints; the OLDEST query → ErrEntityNotFound (the oldest 10 files
// are silently dropped by the capped list). GREEN post-compaction: run the
// compaction (merges the 20 L0 files → ONE L1); the SAME OLDEST query → 200,
// the right dominant (SystemTime == the oldest checkpoint's sysTime, the
// verbatim PayloadDigest). Both byte-captured here.
func TestTrack14_T1_OldestQuerySurvivesMaxL0Cap_RedThenGreen(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 20
	const maxL0 = 10 // resolver MaxL0Files = 10 → the oldest 10 are silently dropped without compaction
	oldestSysNs, oldestPayload := track14WriteN(t, alloc, lfs, entity, N)

	// --- RED stage: NO compaction. Resolver with MaxL0Files=10 only lists the
	// newest 10 L0 files; the OLDEST 10 (incl. checkpoint 0) are invisible → a
	// query for the oldest valid-time returns ErrEntityNotFound (silent loss of
	// durable data on disk). ---
	redResolver := database.NewResolver(lfs, lfs, alloc, "track14-bucket", database.ResolverConfig{MaxL0Files: maxL0})
	OldestValid := time.Unix(0, oldestSysNs)
	OldestTx := time.Unix(0, oldestSysNs+1)
	redGot, redErr := redResolver.AsOf(ctx, entity, OldestValid, OldestTx)
	// The cap form reproduces: the oldest durable row is INVISIBLE under the cap
	// (the 11th-20th-oldest files are dropped by the capped list; the reverse
	// sort keeps the newest 10). The OLDEST checkpoint's validStart==sysTime is
	// BEFORE the 11th-oldest, so NO scanned row covers validTime=oldestSysNs.
	assert.ErrorIsf(t, redErr, database.ErrEntityNotFound, "RED: the oldest query (sysTime=%d) must be ErrEntityNotFound with MaxL0Files=%d and no L1 — the silent-loss cap form", oldestSysNs, maxL0)
	assert.Nilf(t, redGot, "RED: nil expected, the oldest durable row is invisible under the cap")

	// --- GREEN stage: run the compaction. The 20 L0 files merge → ONE L1;
	// AsOf scans the L1 (always, full history) → the oldest query 200s. ---
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track14-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	res, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Falsef(t, res.AlreadyMoved, "compaction must produce an L1 (20 L0 files exist)")
	require.Equalf(t, N, res.Rows, "the L1 must preserve ALL %d rows (the §0.4 bitemporal invariant — no pruning)", N)
	require.NotEmptyf(t, res.L1Key, "an L1 must be written")
	require.NotEmptyf(t, res.L0Files, "the manifest must list the merged L0 keys")
	require.Lenf(t, res.L0Files, N, "all %d L0 keys must be in the manifest", N)

	l1s, _ := lfs.ListObjects(ctx, "local", "l1/"+fmt.Sprintf("%x", h8[:])+"/", 0)
	require.Lenf(t, l1s, 1, "exactly ONE L1 file per entity (the Day-14 shape); got %v", l1s)
	mans, _ := lfs.ListObjects(ctx, "local", "compaction/"+fmt.Sprintf("%x", h8[:])+"/", 0)
	require.Lenf(t, mans, 1, "exactly ONE manifest per compaction job; got %v", mans)

	// GREEN: the SAME resolver configuration (MaxL0Files=10) now returns the
	// oldest dominant via the L1 — the cap no longer silently loses data.
	greenResolver := database.NewResolver(lfs, lfs, alloc, "track14-bucket", database.ResolverConfig{MaxL0Files: maxL0})
	got, gerr := greenResolver.AsOf(ctx, entity, OldestValid, OldestTx)
	require.NoErrorf(t, gerr, "GREEN: the oldest query must 200 via the L1 (the cap is eliminated)")
	require.NotNilf(t, got, "GREEN: non-nil result expected")
	assert.Equalf(t, entity, got.EntityID, "GREEN: returned a different entity (keying collision)")
	assert.Equalf(t, oldestSysNs, got.SystemTime, "GREEN: SystemTime must be the oldest checkpoint's sysTime (the dominant for the oldest valid-time)")
	wantDigest := sha256.Sum256(oldestPayload)
	assert.Equalf(t, wantDigest, got.PayloadDigest, "GREEN: PayloadDigest must be sha256(oldest payload) (Law V — verbatim digest, not fabricated)")
	assert.Equalf(t, oldestPayload, got.Payload, "GREEN: Payload must be the oldest checkpoint's payload")

	// Byte-capture the RED→GREEN chronology (the Day-13 commit-message precedent).
	t.Logf("T1 RED: oldest query (sysTime=%d) with MaxL0Files=%d → ErrEntityNotFound (silent loss of the OLDEST %d durable files)", oldestSysNs, maxL0, N-maxL0)
	t.Logf("T1 GREEN: compaction merged %d L0 files → L1 %s (%d rows preserved); oldest query now 200 (dominant sysTime=%d, digest=%x)", len(res.L0Files), res.L1Key, res.Rows, got.SystemTime, got.PayloadDigest)
}

// --- T3 — idempotent: the SAME L0 set merged twice → byte-identical L1 bytes
// (deterministic merge: sorted inputs + sorted rows + schema-identical). ---
func TestTrack14_T3_Idempotent_MergeTwiceSameL1Bytes(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const N = 8
	track14WriteN(t, alloc, lfs, entity, N)
	h8 := database.EntityHash8(entity)

	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track14-bucket", database.DefaultCompactionConfig())
	res1, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	l1Bytes1 := track14ReadObject(t, lfs, res1.L1Key)

	// Re-run Compaction on the SAME L0 set (the L0 files were NOT deleted —
	// delete-after-read-safety). firstSysT is the oldest row's sysTime, unchanged;
	// the L1 key is the same; Upload O_TRUNCs (LocalFS) so the file is replaced
	// byte-identically with the same sorted content.
	res2, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)
	require.Equalf(t, res1.L1Key, res2.L1Key, "idempotency: the L1 key must be the same (firstSysT is deterministic)")

	l1Bytes2 := track14ReadObject(t, lfs, res2.L1Key)
	assert.Equalf(t, l1Bytes1, l1Bytes2, "T3 idempotency: L1 byte-content must be identical across merges (len1=%d len2=%d)", len(l1Bytes1), len(l1Bytes2))
}

// track14ReadObject downloads a single key as raw bytes.
func track14ReadObject(t *testing.T, lfs *LocalFS, key string) []byte {
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

// --- T4 — AsOf scans L1 + uncompacted tail, NOT L1 alone. After a compaction
// merges the bulk into an L1, write MORE checkpoints (the uncompacted tail) so
// a query's dominant is a tail row with sysTime NEWER than the L1's newest —
// proving AsOf reads BOTH tiers. ---
func TestTrack14_T4_AsOfScansL1PlusUncompactedTail(t *testing.T) {
	ctx := context.Background()
	lfs := track14LocalFS(t)
	alloc := database.NewJemallocAllocator()
	const entity = "alpha"
	const bulk = 20
	const maxL0 = 10
	const extraTail = 5

	oldestSysNs, _ := track14WriteN(t, alloc, lfs, entity, bulk)
	// Run compaction → ONE L1 (the 20-row merged history).
	compactor := database.NewL1Compactor(lfs, lfs, lfs, alloc, "track14-bucket", database.DefaultCompactionConfig())
	h8 := database.EntityHash8(entity)
	_, err := compactor.Compaction(ctx, entity, h8)
	require.NoError(t, err)

	// Write extraTail MORE checkpoints with sysTime NEWER than the L1's newest.
	// These form the uncompacted tail (L0 files), NOT in the L1.
	flusher := database.NewL0Flusher(alloc, lfs, "track14-bucket")
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
		track14InsertRow(t, alloc, lfs, flusher, entity, sys, payload)
	}

	// Query at a validTime covered by BOTH the oldest L1 row [oldestSysNs, openEnd)
	// AND the tail dominant [tailDominantSys, openEnd) (openEnd so all rows cover
	// every time >= their validStart). The tail dominant has a NEWER sysTime than
	// every L1 row → it must win. The L1 alone would return its newest row (WRONG);
	// scanning the tail picks the newer tail dominant. This proves AsOf scans BOTH.
	resolver := database.NewResolver(lfs, lfs, alloc, "track14-bucket", database.ResolverConfig{MaxL0Files: maxL0})
	qValid := time.Unix(0, tailDominantSys)
	qTx := time.Unix(0, tailDominantSys+1)
	got, gerr := resolver.AsOf(ctx, entity, qValid, qTx)
	require.NoErrorf(t, gerr, "T4: query must resolve (L1+tail scan)")
	require.NotNil(t, got)
	assert.Equalf(t, tailDominantSys, got.SystemTime, "T4: dominant must be the TAIL row (newer sysTime than ANY L1 row) — proves AsOf scans L1 AND tail, not L1 alone")
	wantDigest := sha256.Sum256(tailDominantPayload)
	assert.Equalf(t, wantDigest, got.PayloadDigest, "T4: the tail dominant's digest (Law V)")
}
