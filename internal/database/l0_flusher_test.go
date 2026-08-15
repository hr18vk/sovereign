package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/apache/arrow/go/v17/arrow/ipc"
	"github.com/apache/arrow/go/v17/arrow/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockS3Uploader records uploads for testing.
// Day-13: per-entity split-merge means a single async flush now produces up to
// maxEntries uploads (one per entity) from a background goroutine, racing with
// the test's len(uploads) reads. The struct therefore serializes the map under
// a Mutex — mirroring the thread-safety a real S3 client (and LocalFS Upload)
// provide. The original one-blob path produced ONE upload per flush, so the
// race window was negligible; the split path materializes the latent race.
type mockS3Uploader struct {
	mu      sync.Mutex
	uploads map[string][]byte
}

func newMockS3() *mockS3Uploader {
	return &mockS3Uploader{uploads: make(map[string][]byte)}
}

func (m *mockS3Uploader) Upload(_ context.Context, key string, data io.Reader, size int64) error {
	buf, _ := io.ReadAll(data)
	m.mu.Lock()
	m.uploads[key] = buf
	m.mu.Unlock()
	return nil
}

func (m *mockS3Uploader) Uploads() map[string][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte, len(m.uploads))
	for k, v := range m.uploads {
		out[k] = v
	}
	return out
}

func (m *mockS3Uploader) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.uploads)
}

// insertTestEvents populates a SkipListArena with test events using O2.1 packing.

// collectPartitions drives FlushArenaToIPC's streaming emit callback and
// collects every partition into a slice for assertion (Day-13 streaming API).
// The caller MUST free each partition's Buf (the emit contract does NOT free
// on success — the streaming call site does).
func collectPartitions(t *testing.T, flusher *L0Flusher, sl *SkipListArena) []L0Partition {
	t.Helper()
	var parts []L0Partition
	err := flusher.FlushArenaToIPC(sl, func(part L0Partition) error {
		// Copy the record bytes into a fresh buffer so subsequent emit calls
		// (none in this test) don't free the slice we hold; for a single emit
		// the lifetimes coincide.
		parts = append(parts, part)
		return nil
	})
	require.NoError(t, err)
	return parts
}

// insertTestEvents populates a SkipListArena with test events using O2.1 packing.
func insertTestEvents(t *testing.T, sl *SkipListArena, count int) {
	now := time.Now().UTC()
	for i := 0; i < count; i++ {
		entityID := "land-001"
		h := sha256.Sum256([]byte(entityID))
		key := make([]byte, keySize)
		copy(key[0:16], h[:16]) // Override 8.4: 128-bit hash
		binary.BigEndian.PutUint64(key[16:24], uint64(now.Add(time.Duration(i)*time.Millisecond).UnixNano()))
		binary.BigEndian.PutUint64(key[24:32], uint64(now.UnixNano()))
		binary.BigEndian.PutUint64(key[32:40], uint64(now.UnixNano())) // Override 8.4: offset shifted

		val := makePackedValue(entityID, 0x89283082803ffff, MaxValidTimeEndNs, [32]byte{}, []byte(`{"type":"land_record","area_sqm":5000}`))
		err := sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
		require.NoError(t, err)
	}
}

func TestL0Flusher_FlushArenaToIPC_RoundTrip(t *testing.T) {
	alloc := NewJemallocAllocator()
	s3 := newMockS3()
	flusher := NewL0Flusher(alloc, s3, "test-bucket")

	sl := NewSkipListArena(alloc, 4*1024*1024) // 4MB arena for 100 events
	defer sl.Free()

	insertTestEvents(t, sl, 100)

	partitions := collectPartitions(t, flusher, sl)
	require.Len(t, partitions, 1, "single-entity flush yields exactly one per-entity partition")
	defer partitions[0].Buf.Free()

	// Verify the Arrow IPC File is readable (Override O2.4 — FileReader matches FileWriter).
	reader, err := ipc.NewFileReader(bytes.NewReader(partitions[0].Buf.Bytes()), ipc.WithAllocator(memory.NewGoAllocator()))
	require.NoError(t, err)
	defer func() { _ = reader.Close() }()

	assert.Equal(t, 1, reader.NumRecords())

	record, err := reader.Record(0)
	require.NoError(t, err)

	assert.Equal(t, int64(100), record.NumRows())
	assert.Equal(t, 9, int(record.NumCols()))
}

func TestL0Flusher_FlushFromArena_UploadToS3(t *testing.T) {
	alloc := NewJemallocAllocator()
	s3 := newMockS3()
	flusher := NewL0Flusher(alloc, s3, "test-bucket")

	sl := NewSkipListArena(alloc, 4*1024*1024)
	defer sl.Free()

	insertTestEvents(t, sl, 50)

	n, err := flusher.FlushFromArena(context.Background(), sl)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "single entity -> one per-entity upload")

	// Verify one upload occurred.
	assert.Equal(t, 1, s3.Len())

	// Verify key format: l0/{prefix}/{timestamp}.arrow
	for key := range s3.Uploads() {
		assert.Contains(t, key, "l0/")
		assert.Contains(t, key, ".arrow")
	}
}

func TestL0Flusher_EmptyArena(t *testing.T) {
	alloc := NewJemallocAllocator()
	s3 := newMockS3()
	flusher := NewL0Flusher(alloc, s3, "test-bucket")

	sl := NewSkipListArena(alloc, 1024*1024)
	defer sl.Free()

	n, err := flusher.FlushFromArena(context.Background(), sl)
	assert.NoError(t, err)
	assert.Equal(t, 0, n, "empty arena -> zero uploads")
	assert.Equal(t, 0, s3.Len())
}

func BenchmarkL0Flusher_FlushArenaToIPC(b *testing.B) {
	alloc := NewJemallocAllocator()
	s3 := newMockS3()
	flusher := NewL0Flusher(alloc, s3, "test-bucket")

	// Pre-populate a large arena.
	sl := NewSkipListArena(alloc, 256*1024*1024)
	defer sl.Free()

	now := time.Now().UTC()
	for i := 0; i < 50000; i++ {
		entityID := "bench-entity"
		h := sha256.Sum256([]byte(entityID))
		key := make([]byte, keySize)
		copy(key[0:16], h[:16]) // Override 8.4: 128-bit hash
		binary.BigEndian.PutUint64(key[16:24], uint64(now.Add(time.Duration(i)*time.Microsecond).UnixNano()))
		binary.BigEndian.PutUint64(key[24:32], uint64(now.UnixNano()))
		binary.BigEndian.PutUint64(key[32:40], uint64(now.UnixNano())) // Override 8.4: offset shifted
		val := makePackedValue(entityID, 0x89283082803ffff, MaxValidTimeEndNs, [32]byte{}, []byte(`{"type":"land_record","area_sqm":5000}`))
		_ = sl.Put(key, len(val), func(buf []byte) { copy(buf, val) })
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = flusher.FlushArenaToIPC(sl, func(part L0Partition) error {
			// single entity (land-001) → exactly one emit; free immediately
			if part.Buf != nil {
				part.Buf.Free()
			}
			return nil
		})
	}
}
