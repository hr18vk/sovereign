// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

// Per-entity L0 split-merge tests (ADR-0018).
//
// Flushing multi-entity SkipList arenas previously wrote one file keyed under
// the smallest entity hash while Resolver.AsOf listed under the queried entity's
// hash, causing read misses for co-located entities. L0Flusher now splits each
// flush into one Arrow IPC file per entity hash:
//   - TestMultiEntityFlushRoundTripAllRetrievable verifies all entities resolve
//   - TestLawVDigestVerbatim checks stored SHA-256 payload digests match writes
//   - TestOneBlobPerEntityNoEmptyOrDuplicate verifies one non-empty file per entity
//   - TestSingleEntityBackwardCompat verifies the single-entity case
//   - TestMaxL0FilesCapDisclosed verifies MaxL0Files truncation triggers telemetry
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

	"github.com/hr18vk/sovereign/internal/telemetry"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memStore is an in-memory S3 simulator that implements all three
// store interfaces (S3Uploader, S3Lister, S3Downloader) so a flush-to-query
// round-trip can be driven against a single object key-space. Thread-safe:
// the per-entity split-merge uploads from a background goroutine (one emit
// upload per checkpoint), so the map needs a mutex (unlike the old
// single-upload one-blob path whose race window was negligible).
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemStore() *memStore {
	return &memStore{objects: make(map[string][]byte)}
}

// Upload (S3Uploader) — writes one per-entity Arrow IPC blob under its own key.
func (m *memStore) Upload(_ context.Context, key string, data io.Reader, _ int64) error {
	b, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.objects[key] = b
	m.mu.Unlock()
	return nil
}

// ListObjects (S3Lister) returns matching keys sorted ascending up to maxKeys,
// mirroring LocalFS.ListObjects including MaxL0Files cap behavior.
func (m *memStore) ListObjects(_ context.Context, _ string, prefix string, maxKeys int) ([]string, error) {
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
func (m *memStore) Download(_ context.Context, _ string, key string) (io.ReadCloser, error) {
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

// hash8PrefixBytes returns sha256(entityID)[:8] — the 8-byte hex prefix AsOf
// and the per-entity flusher key both use (the two keying contracts that
// ADR-0018 aligns).
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

// TestMultiEntityFlushRoundTripAllRetrievable verifies every entity in a
// multi-entity checkpoint resolves through flush and Resolver.AsOf.
func TestMultiEntityFlushRoundTripAllRetrievable(t *testing.T) {
	ctx := context.Background()
	// Expected sha256(id)[:8] big-endian ordering: wonder < toast < victor.
	entities := []string{"wonder", "toast", "victor"}
	for _, e := range entities {
		t.Logf("entity=%-8s hash8=%x", e, hash8PrefixBytes(e))
	}

	alloc := NewJemallocAllocator()
	store := newMemStore()
	flusher := NewL0Flusher(alloc, store, "split-bucket")
	const openEnd int64 = 9_000_000_000_000_000_000
	now := time.Now().UnixNano()
	sl := NewSkipListArena(alloc, 8*1024*1024)
	defer sl.Free()

	for _, e := range entities {
		insertEntityRow(sl, e, now, now, now, openEnd, []byte("payload-for-"+e))
	}

	uploaded, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err)
	assert.Equal(t, len(entities), uploaded, "one upload per entity (the split-merge)")

	resolver := NewResolver(store, store, alloc, "split-bucket", DefaultResolverConfig())
	qtValid := time.Unix(0, now+1)
	qtTx := time.Unix(0, now+1)

	for _, e := range entities {
		got, qerr := resolver.AsOf(ctx, e, qtValid, qtTx)
		require.NoErrorf(t, qerr, "entity %q: AsOf returned an error (silent read-miss class)", e)
		require.NotNilf(t, got, "entity %q: nil result", e)
		assert.Equalf(t, e, got.EntityID, "entity %q: returned a different entity row", e)
	}
}

// TestLawVDigestVerbatim checks that queries return the payload digest stamped
// during the original write without altering or recomputing it.
func TestLawVDigestVerbatim(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	flusher := NewL0Flusher(alloc, store, "split-bucket")
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

	resolver := NewResolver(store, store, alloc, "split-bucket", DefaultResolverConfig())
	qt := time.Unix(0, now+1)
	for _, e := range entities {
		got, qerr := resolver.AsOf(ctx, e, qt, qt)
		require.NoErrorf(t, qerr, "entity %q: AsOf err", e)
		assert.Equalf(t, wantDigest[e], got.PayloadDigest, "entity %q: PayloadDigest != sha256(payload) stamped on write", e)
	}
}

// TestOneBlobPerEntityNoEmptyOrDuplicate verifies each entity receives one
// non-empty Arrow IPC upload with no empty or duplicate keys.
func TestOneBlobPerEntityNoEmptyOrDuplicate(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	flusher := NewL0Flusher(alloc, store, "split-bucket")
	const openEnd int64 = 9_000_000_000_000_000_000
	now := time.Now().UnixNano()
	entities := []string{"wonder", "toast", "victor", "zulu"}
	for _, e := range entities {
		t.Logf("entity=%-8s hash8=%x", e, hash8PrefixBytes(e))
	}
	sl := NewSkipListArena(alloc, 16*1024*1024)
	defer sl.Free()
	for i := range entities {
		e := entities[i]
		insertEntityRow(sl, e, now, now, now, openEnd, []byte("p1-"+e))
	}
	insertEntityRow(sl, "wonder", now+1_000_000, now, now, openEnd, []byte("p2-wonder"))
	insertEntityRow(sl, "wonder", now+2_000_000, now, now, openEnd, []byte("p3-wonder"))

	uploaded, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err)
	assert.Equal(t, len(entities), uploaded, "one file per entity, regardless of per-entity row count")

	store.mu.Lock()
	prefixes := make(map[string]int)
	for k := range store.objects {
		if !strings.HasPrefix(k, "l0/") {
			continue
		}
		parts := strings.SplitN(k[3:], "/", 2)
		if len(parts) != 2 {
			continue
		}
		prefixes[parts[0]]++
	}
	store.mu.Unlock()
	assert.Len(t, prefixes, len(entities), "distinct entity prefixes == entity count")

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

// TestSingleEntityBackwardCompat verifies single-entity flushes emit one upload.
func TestSingleEntityBackwardCompat(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	flusher := NewL0Flusher(alloc, store, "split-bucket")
	const openEnd int64 = 9_000_000_000_000_000_000
	now := time.Now().UnixNano()
	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()

	const entity = "land-001"
	insertEntityRow(sl, entity, now, now, now, openEnd, []byte(`{"v":1}`))

	uploaded, err := flusher.FlushFromArena(ctx, sl)
	require.NoError(t, err)
	assert.Equal(t, 1, uploaded, "single entity must produce one per-entity upload")

	resolver := NewResolver(store, store, alloc, "split-bucket", DefaultResolverConfig())
	got, qerr := resolver.AsOf(ctx, entity, time.Unix(0, now+1), time.Unix(0, now+1))
	require.NoError(t, qerr)
	require.NotNil(t, got)
	assert.Equal(t, entity, got.EntityID)
}

// TestMaxL0FilesCapDisclosed verifies MaxL0Files truncation updates
// telemetry.QueryL0ListCapped while returning the best match within the cap.
func TestMaxL0FilesCapDisclosed(t *testing.T) {
	ctx := context.Background()
	alloc := NewJemallocAllocator()
	store := newMemStore()
	flusher := NewL0Flusher(alloc, store, "split-bucket")
	const openEnd int64 = 9_000_000_000_000_000_000
	const entity = "maxl0test"

	const maxL0 = 20
	const writeCount = maxL0 + 5
	for i := 0; i < writeCount; i++ {
		sl := NewSkipListArena(alloc, 2*1024*1024)
		now := time.Now().UnixNano() + int64(i)
		insertEntityRow(sl, entity, now, now, now, openEnd, []byte(fmt.Sprintf("v%d", i)))
		_, err := flusher.FlushFromArena(ctx, sl)
		require.NoError(t, err)
	}

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

	resolver := NewResolver(store, store, alloc, "split-bucket", ResolverConfig{MaxL0Files: maxL0})
	before := int64(0)
	if telemetry.QueryL0ListCapped != nil {
		before = int64(telemetry.QueryL0ListCapped.Value())
	}
	got, err := resolver.AsOf(ctx, entity, time.Unix(0, time.Now().UnixNano()+10_000_000_000), time.Unix(0, time.Now().UnixNano()+10_000_000_000))
	require.NoError(t, err, "AsOf must return a matching row within the cap")
	require.NotNil(t, got)
	require.Equal(t, entity, got.EntityID)

	after := int64(0)
	if telemetry.QueryL0ListCapped != nil {
		after = int64(telemetry.QueryL0ListCapped.Value())
	}
	assert.Greaterf(t, after, before, "QueryL0ListCapped must increment when MaxL0Files cap is hit (%d->%d)", before, after)
}
