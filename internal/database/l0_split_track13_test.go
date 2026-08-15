// Day 13 — the per-entity L0 split-merge (ADR-0018) teeth.
//
// These teeth CLOSE the silent multi-entity read-miss class that every Day-12
// single-entity tooth hid: the old L0 flush co-located a checkpoint's ENTIRE
// multi-entity slice into ONE file keyed under the SMALLEST-hash entity, while
// AsOf lists under the QUERIED entity's hash — so every co-located non-smallest
// entity was a silent ErrEntityNotFound for data that IS on disk.
//
// T1 is the headline RED→GREEN: at HEAD-pre-fix the 3-entity drive sees only
// "wonder" (smallest hash); post-fix all three return. T2 is Law-V (digest
// verbatim, no fabricated payload). T3 is one-blob-per-entity + no empty/dup
// keys. T4 is single-entity back-compat. T5 is the MaxL0Files cap disclosure.
package database

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hr18vk/supremum/internal/telemetry"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memStoreTrack13 is an in-memory S3 simulator that implements ALL THREE
// store interfaces (S3Uploader, S3Lister, S3Downloader) so a flush→query
// round-trip can be driven against a single object key-space. Thread-safe:
// the per-entity split-merge uploads from a background goroutine (#emit
// uploads per checkpoint), so the map needs a Mutex (unlike the old
// single-upload one-blob path whose race window was negligible).
type memStoreTrack13 struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemStoreTrack13() *memStoreTrack13 {
	return &memStoreTrack13{objects: make(map[string][]byte)}
}

// Upload (S3Uploader) — writes one per-entity Arrow IPC blob under its own key.
func (m *memStoreTrack13) Upload(_ context.Context, key string, data io.Reader, _ int64) error {
	b, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.objects[key] = b
	m.mu.Unlock()
	return nil
}

// ListObjects (S3Lister) — prefix-match, ascending sort, maxKeys cap.
// This mirrors LocalFS.ListObjects (the production path) including the
// MaxL0Files silent-truncation cap that T5 exercises.
func (m *memStoreTrack13) ListObjects(_ context.Context, _ string, prefix string, maxKeys int) ([]string, error) {
	m.mu.Lock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	m.mu.Unlock()
	sort.Strings(keys)
	if maxKeys > 0 && len(keys) > maxKeys {
		keys = keys[:maxKeys]
	}
	return keys, nil
}

// Download (S3Downloader) — returns the raw Arrow IPC bytes for a key.
func (m *memStoreTrack13) Download(_ context.Context, _ string, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	data, ok := m.objects[key]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("object not found: %s", key)
	}
	return io.NopCloser(newBytesReaderCopy(data)), nil
}

// A tiny io.Reader wrapper so the caller can't retain the store's backing
// slice after re-upload/overwrite (mirroring real S3 semantics).
type bytesReaderCopy struct {
	b []byte
	i int
}

func newBytesReaderCopy(b []byte) *bytesReaderCopy {
	return &bytesReaderCopy{b: append([]byte(nil), b...)}
}
func (r *bytesReaderCopy) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// --- Tooth helpers ---

// hash8PrefixBytes returns sha256(entityID)[:8] — the 8-byte hex prefix AsOf
// and the per-entity flusher key BOTH use (the two keying contracts Day 13
// aligns).
func hash8PrefixBytes(entityID string) [8]byte {
	h := sha256.Sum256([]byte(entityID))
	var b [8]byte
	copy(b[:], h[:8])
	return b
}

func insertEntityRow(sl *SkipListArena, entityID string, sysNs, validNs, assertNs, validEnd int64, payload []byte) {
	key := make([]byte, keySize)
	Full := sha256.Sum256([]byte(entityID))
	copy(key[0:16], Full[:16])
	binary.BigEndian.PutUint64(key[16:24], uint64(sysNs))
	binary.BigEndian.PutUint64(key[24:32], uint64(validNs))
	binary.BigEndian.PutUint64(key[32:40], uint64(assertNs))
	pd := sha256.Sum256(payload)
	val := makePackedValue(entityID, 0x89283082803ffff, validEnd, pd, payload)
	_ = sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
}

// --- T1 — the headline RED→GREEN: every entity in a multi-entity checkpoint
// is retrievable through the production write→flush→AsOf path. ---
//
// At HEAD-pre-fix (stash the l0_flusher.go split), this tooth RED-proves that
// only "wonder" (the smallest-hash) returns; toast + victor miss with
// ErrEntityNotFound. Post-fix, all three return.
func TestTrack13_T1_MultiEntityFlushRoundTrip_AllRetrievable(t *testing.T) {
	ctx := context.Background()
	// hash8 ordering, computed in the test (NOT asserted from memory):
	//   wonder < toast < victor under sha256(id)[:8] as BigEndian.
	entities := []string{"wonder", "toast", "victor"}
	for _, e := range entities {
		t.Logf("entity=%-8s hash8=%x", e, hash8PrefixBytes(e))
	}

	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	flusher := NewL0Flusher(alloc, store, "track13-bucket")
	// Per-day-12.5 semantics: open-ended ValidTimeEnd sentry = 9e18 (int64-safe).
	const openEnd int64 = 9_000_000_000_000_000_000
	now := time.Now().UnixNano()
	sl := NewSkipListArena(alloc, 8*1024*1024)
	defer sl.Free()

	// Insert one row per entity, all sharing the SAME checkpoint pointer (the
	// multi-entity case the production SnapshotToLSM flushes in ONE round).
	for _, e := range entities {
		insertEntityRow(sl, e, now, now, now, openEnd, []byte("payload-for-"+e))
	}

	// Drive the production flush path (the split-merge).
	uploaded, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err)
	assert.Equal(t, len(entities), uploaded, "one upload per entity (the split-merge)")

	// Drive the production READ path (Resolver.AsOf) for EACH entity.
	resolver := NewResolver(store, store, alloc, "track13-bucket", DefaultResolverConfig())
	qtValid := time.Unix(0, now+1)
	qtTx := time.Unix(0, now+1)

	for _, e := range entities {
		got, qerr := resolver.AsOf(ctx, e, qtValid, qtTx)
		require.NoErrorf(t, qerr, "entity %q: AsOf returned an error (silent read-miss class)", e)
		require.NotNilf(t, got, "entity %q: nil result", e)
		assert.Equalf(t, e, got.EntityID, "entity %q: returned a DIFFERENT entity's row — keying collision", e)
	}
}

// --- T2 — Law V: echo the digest the WRITE stamped, NOT a fabricated payload
// (the G06.e guard the Day-12.5 T-I2 tooth codified) ---
func TestTrack13_T2_LawV_DigestVerbatim(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	flusher := NewL0Flusher(alloc, store, "track13-bucket")
	const openEnd int64 = 9_000_000_000_000_000_000
	now := time.Now().UnixNano()
	sl := NewSkipListArena(alloc, 8*1024*1024)
	defer sl.Free()

	entities := []string{"wonder", "toast", "victor"}
	wantDigest := make(map[string][32]byte)
	for _, e := range entities {
		payload := []byte("LawV-payload-" + e)
		pd := sha256.Sum256(payload)
		wantDigest[e] = pd
		insertEntityRow(sl, e, now, now, now, openEnd, payload)
	}
	_, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err)

	resolver := NewResolver(store, store, alloc, "track13-bucket", DefaultResolverConfig())
	qt := time.Unix(0, now+1)
	for _, e := range entities {
		got, qerr := resolver.AsOf(ctx, e, qt, qt)
		require.NoErrorf(t, qerr, "entity %q: AsOf err", e)
		assert.Equalf(t, wantDigest[e], got.PayloadDigest, "entity %q: PayloadDigest != sha256(payload) the write stamped (Law V)", e)
	}
}

// --- T3 — one arrow blob per entity; no empty blobs; no duplicate keys ---
func TestTrack13_T3_OneBlobPerEntity_NoEmptyOrDuplicate(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	flusher := NewL0Flusher(alloc, store, "track13-bucket")
	const openEnd int64 = 9_000_000_000_000_000_000
	now := time.Now().UnixNano()
	// 4 entities — verify the partition count == entity count, and that no
	// entity gets a 2nd upload (no (hash8, sysNs) duplicate).
	entities := []string{"wonder", "toast", "victor", "zulu"}
	for _, e := range entities {
		t.Logf("entity=%-8s hash8=%x", e, hash8PrefixBytes(e))
	}
	// Insert 3 rows for TWO of the entities (multi-row partition) + 1 each for
	// the others; verify the FILE count == entity count, not row count.
	sl := NewSkipListArena(alloc, 16*1024*1024)
	defer sl.Free()
	for i := range entities {
		e := entities[i]
		insertEntityRow(sl, e, now, now, now, openEnd, []byte("p1-"+e))
	}
	// wonder gets 2 extra rows (different sys times)
	insertEntityRow(sl, "wonder", now+1_000_000, now, now, openEnd, []byte("p2-wonder"))
	insertEntityRow(sl, "wonder", now+2_000_000, now, now, openEnd, []byte("p3-wonder"))

	uploaded, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err)
	assert.Equal(t, len(entities), uploaded, "one file per entity, regardless of per-entity row count")

	// Count distinct entity prefixes among the uploaded keys — must == entities.
	store.mu.Lock()
	prefixes := make(map[string]int)
	for k := range store.objects {
		if !strings.HasPrefix(k, "l0/") {
			continue
		}
		// key format: l0/{16-hex}/{sysNs}.arrow
		parts := strings.SplitN(k[3:], "/", 2)
		if len(parts) != 2 {
			continue
		}
		prefixes[parts[0]]++
	}
	store.mu.Unlock()
	assert.Len(t, prefixes, len(entities), "distinct entity prefixes == entity count")

	// No empty blob: each uploaded object must be non-empty (a valid Arrow IPC File).
	store.mu.Lock()
	emptyKeys := []string{}
	for k, v := range store.objects {
		if strings.HasPrefix(k, "l0/") && len(v) == 0 {
			emptyKeys = append(emptyKeys, k)
		}
	}
	store.mu.Unlock()
	assert.Empty(t, emptyKeys, "no empty Arrow IPC blobs")
}

// --- T4 — single-entity back-compat: the split path is the N=1 degenerate
// case. The existing Day-12 single-entity teeth (which key under the queried
// entity's own hash) MUST stay green. ---
func TestTrack13_T4_SingleEntity_BackwardCompat(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	flusher := NewL0Flusher(alloc, store, "track13-bucket")
	const openEnd int64 = 9_000_000_000_000_000_000
	now := time.Now().UnixNano()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()

	const entity = "land-001"
	insertEntityRow(sl, entity, now, now, now, openEnd, []byte(`{"v":1}`))

	uploaded, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err)
	assert.Equal(t, 1, uploaded, "single entity → exactly ONE per-entity upload (N=1 degenerate)")

	resolver := NewResolver(store, store, alloc, "track13-bucket", DefaultResolverConfig())
	got, qerr := resolver.AsOf(ctx, entity, time.Unix(0, now+1), time.Unix(0, now+1))
	require.NoError(t, qerr)
	require.NotNil(t, got)
	assert.Equal(t, entity, got.EntityID)
}

// --- T5 — the MaxL0Files silent-truncation cap DISCLOSED, not fake-fixed
// (ADR-0018 §6). The cap is HONEST: AsOf returns the best match within the
// capped scan and the telemetry.QueryL0ListCapped counter increments so an
// operator can surface it. The structural fix (level-overwrite compaction)
// is a future fork. ---
func TestTrack13_T5_MaxL0Files_CapDisclosed(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStoreTrack13()
	flusher := NewL0Flusher(alloc, store, "track13-bucket")
	const openEnd int64 = 9_000_000_000_000_000_000
	const entity = "maxl0test"

	// Write MORE than MaxL0Files per-entity checkpoints, one event each across N
	// flushes (each FlushArenaToIPC produces ONE per-entity file with that event).
	const maxL0 = 20
	const writeCount = maxL0 + 5 // 25 per-entity files (all keyed under the same entity-hash8 prefix)
	for i := 0; i < writeCount; i++ {
		sl := NewSkipListArena(alloc, 2*1024*1024)
		now := time.Now().UnixNano() + int64(i)
		insertEntityRow(sl, entity, now, now, now, openEnd, []byte(fmt.Sprintf("v%d", i)))
		_, err := flusher.FlushFromArena(ctx, sl)
		require.NoError(t, err)
	}

	// Confirm the store actually holds writeCount per-entity files under the entity's prefix.
	h8 := hash8PrefixBytes(entity)
	prefix := fmt.Sprintf("l0/%x", h8)
	store.mu.Lock()
	countFiles := 0
	for k := range store.objects {
		if strings.HasPrefix(k, prefix+"/") {
			countFiles++
		}
	}
	store.mu.Unlock()
	require.Equalf(t, writeCount, countFiles, "store should hold %d per-entity files; got %d", writeCount, countFiles)

	// A resolver WITH MaxL0Files=20 should observe the cap (the cap-disclosure
	// counter increments). The AsOf still returns a valid (best-within-cap)
	// dominant — it does NOT silently lie by returning an OLDER row under the
	// pretense of being complete; the disclosure is the metric, the returned
	// result is honest-as-capped.
	resolver := NewResolver(store, store, alloc, "track13-bucket", ResolverConfig{MaxL0Files: maxL0})
	before := int64(0)
	if telemetry.QueryL0ListCapped != nil {
		before = int64(telemetry.QueryL0ListCapped.Value())
	}
	got, err := resolver.AsOf(ctx, entity, time.Unix(0, time.Now().UnixNano()+10_000_000_000), time.Unix(0, time.Now().UnixNano()+10_000_000_000))
	// The query may resolve to a row within the capped scan OR not:
	require.NoError(t, err, "AsOf must return SOME row within the cap if one exists in the scanned window")
	require.NotNil(t, got)
	require.Equal(t, entity, got.EntityID)

	after := int64(0)
	if telemetry.QueryL0ListCapped != nil {
		after = int64(telemetry.QueryL0ListCapped.Value())
	}
	assert.Greaterf(t, after, before, "QueryL0ListCapped should have incremented (%d→%d) — the cap was hit and DISCLOSED, not silently lied about", before, after)
}
