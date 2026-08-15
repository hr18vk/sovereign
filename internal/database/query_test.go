package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"testing"
	"time"
	"unsafe"

	"github.com/apache/arrow/go/v17/arrow"
	"github.com/apache/arrow/go/v17/arrow/array"
	"github.com/apache/arrow/go/v17/arrow/ipc"
	"github.com/apache/arrow/go/v17/arrow/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memWriteSeeker provides an in-memory io.WriteSeeker for testing.
type memWriteSeeker struct {
	buf []byte
	pos int
}

func (m *memWriteSeeker) Write(p []byte) (int, error) {
	need := m.pos + len(p)
	if need > len(m.buf) {
		newBuf := make([]byte, need*2)
		copy(newBuf, m.buf)
		m.buf = newBuf
	}
	copy(m.buf[m.pos:], p)
	m.pos += len(p)
	return len(p), nil
}

func (m *memWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = int64(m.pos) + offset
	case io.SeekEnd:
		newPos = int64(len(m.buf)) + offset
	}
	if newPos < 0 {
		return 0, fmt.Errorf("negative seek")
	}
	m.pos = int(newPos)
	return newPos, nil
}

// --- Mock S3 Infrastructure ---

// mockS3Store provides in-memory S3 simulation for testing.
type mockS3Store struct {
	objects map[string][]byte // key -> Arrow IPC file content
}

func newMockS3Store() *mockS3Store {
	return &mockS3Store{objects: make(map[string][]byte)}
}

func (m *mockS3Store) ListObjects(_ context.Context, _, prefix string, maxKeys int) ([]string, error) {
	var keys []string
	for k := range m.objects {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if maxKeys > 0 && len(keys) > maxKeys {
		keys = keys[:maxKeys]
	}
	return keys, nil
}

func (m *mockS3Store) Download(_ context.Context, _, key string) (io.ReadCloser, error) {
	data, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("object not found: %s", key)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// putArrowFile serializes events into Arrow IPC format and stores in the mock S3.
func (m *mockS3Store) putArrowFile(t *testing.T, key string, events []TriTemporalEvent) {
	t.Helper()

	alloc := memory.NewGoAllocator()
	builder := array.NewRecordBuilder(alloc, ArrowSchema)
	defer builder.Release()

	hashBuilder := builder.Field(0).(*array.FixedSizeBinaryBuilder)
	sysTimeBuilder := builder.Field(1).(*array.TimestampBuilder)
	validStartBuilder := builder.Field(2).(*array.TimestampBuilder)
	validEndBuilder := builder.Field(3).(*array.TimestampBuilder)
	assertTimeBuilder := builder.Field(4).(*array.TimestampBuilder)
	h3Builder := builder.Field(5).(*array.Uint64Builder)
	payloadDigestBuilder := builder.Field(6).(*array.FixedSizeBinaryBuilder)
	entityIDBuilder := builder.Field(7).(*array.BinaryBuilder)
	payloadBuilder := builder.Field(8).(*array.BinaryBuilder)

	for _, ev := range events {
		entityIDBytes := unsafe.Slice(unsafe.StringData(ev.EntityID), len(ev.EntityID))
		fullHash := sha256.Sum256(entityIDBytes)
		hashBuilder.Append(fullHash[:16])
		sysTimeBuilder.Append(arrow.Timestamp(ev.SystemTime))
		validStartBuilder.Append(arrow.Timestamp(ev.ValidTimeStart))
		validEndBuilder.Append(arrow.Timestamp(ev.ValidTimeEnd))
		assertTimeBuilder.Append(arrow.Timestamp(ev.AssertionTime))
		h3Builder.Append(ev.H3Index)
		payloadDigestBuilder.Append(ev.PayloadDigest[:])
		entityIDBuilder.Append(entityIDBytes)
		payloadBuilder.Append(ev.Payload)
	}

	rec := builder.NewRecord()
	defer rec.Release()

	ws := &memWriteSeeker{buf: make([]byte, 0, 1024)}
	writer, err := ipc.NewFileWriter(ws, ipc.WithSchema(ArrowSchema), ipc.WithAllocator(alloc))
	require.NoError(t, err)
	require.NoError(t, writer.Write(rec))
	require.NoError(t, writer.Close())

	m.objects[key] = ws.buf[:ws.pos]
}

// --- Helper Functions ---

func l0Key(entityID string, txTimeNs int64) string {
	hash := sha256.Sum256([]byte(entityID))
	var hexBuf [16]byte
	hex.Encode(hexBuf[:], hash[:8])
	return fmt.Sprintf("l0/%s/%d.arrow", unsafe.String(&hexBuf[0], 16), txTimeNs)
}

func mustTime(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// --- Test Suite ---

// TestAsOf_HistoricalRetrieval validates the core bitemporal query per DR3 S3.3:
// "Inserts 3 versions of entity 'land-001' with different valid times,
//
//	then queries AsOf('land-001', 1995, 2020) and retrieves the correct version."
func TestAsOf_HistoricalRetrieval(t *testing.T) {
	store := newMockS3Store()

	// Version 1: land-001 owned by "Farmer A" from 1990-2000, recorded in 2015.
	// Version 2: land-001 owned by "Farmer B" from 1995-2005, recorded in 2018.
	//   (This is a retroactive correction: the 2018 system assertion supersedes
	//    the 2015 assertion for overlapping valid time 1995-2000.)
	// Version 3: land-001 owned by "Farmer C" from 2005-2025, recorded in 2020.

	v1 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2015-01-01").UnixNano(),
		ValidTimeStart: mustTime("1990-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2000-01-01").UnixNano(),
		AssertionTime:  mustTime("2015-01-01").UnixNano(),
		H3Index:        0x89283082803ffff,
		Payload:        []byte(`{"owner":"Farmer A"}`),
	}

	v2 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2018-06-15").UnixNano(),
		ValidTimeStart: mustTime("1995-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2005-01-01").UnixNano(),
		AssertionTime:  mustTime("2018-06-15").UnixNano(),
		H3Index:        0x89283082803ffff,
		Payload:        []byte(`{"owner":"Farmer B"}`),
	}

	v3 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2020-03-01").UnixNano(),
		ValidTimeStart: mustTime("2005-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2025-01-01").UnixNano(),
		AssertionTime:  mustTime("2020-03-01").UnixNano(),
		H3Index:        0x89283082803ffff,
		Payload:        []byte(`{"owner":"Farmer C"}`),
	}

	// Store across multiple L0 files (simulating multiple flushes).
	store.putArrowFile(t, l0Key("land-001", mustTime("2015-01-01").UnixNano()), []TriTemporalEvent{v1})
	store.putArrowFile(t, l0Key("land-001", mustTime("2018-06-15").UnixNano()), []TriTemporalEvent{v2})
	store.putArrowFile(t, l0Key("land-001", mustTime("2020-03-01").UnixNano()), []TriTemporalEvent{v3})

	resolver := NewResolver(store, store, nil, "test-bucket", DefaultResolverConfig())
	ctx := context.Background()

	// Query: Who owned land-001 in 1995, as known by the system in 2020?
	// Expected: Farmer B (v2), because:
	//   - v1's valid time covers 1995 (1990-2000), SystemTime=2015 <= 2020
	//   - v2's valid time covers 1995 (1995-2005), SystemTime=2018 <= 2020
	//   - v3's valid time does NOT cover 1995 (starts 2005)
	//   - v2.SystemTime (2018) > v1.SystemTime (2015) -> v2 dominates v1.
	result, err := resolver.AsOf(ctx, "land-001", mustTime("1995-06-01"), mustTime("2020-12-31"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "land-001", result.EntityID)
	assert.Equal(t, v2.SystemTime, result.SystemTime)
	assert.Equal(t, []byte(`{"owner":"Farmer B"}`), result.Payload)
	assert.Equal(t, uint64(0x89283082803ffff), result.H3Index)
}

// TestAsOf_EntityNotFound validates ErrEntityNotFound for non-existent entities.
func TestAsOf_EntityNotFound(t *testing.T) {
	store := newMockS3Store()

	v1 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2020-01-01").UnixNano(),
		ValidTimeStart: mustTime("2015-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2025-01-01").UnixNano(),
		AssertionTime:  mustTime("2020-01-01").UnixNano(),
		H3Index:        0x89283082803ffff,
		Payload:        []byte(`{"owner":"Farmer A"}`),
	}
	store.putArrowFile(t, l0Key("land-001", mustTime("2020-01-01").UnixNano()), []TriTemporalEvent{v1})

	resolver := NewResolver(store, store, nil, "test-bucket", DefaultResolverConfig())
	ctx := context.Background()

	// Query for a non-existent entity.
	result, err := resolver.AsOf(ctx, "land-999", mustTime("2020-01-01"), mustTime("2025-01-01"))
	assert.ErrorIs(t, err, ErrEntityNotFound)
	assert.Nil(t, result)
}

// TestAsOf_EmptyStore validates ErrEntityNotFound when no L0 files exist.
func TestAsOf_EmptyStore(t *testing.T) {
	store := newMockS3Store()
	resolver := NewResolver(store, store, nil, "test-bucket", DefaultResolverConfig())
	ctx := context.Background()

	result, err := resolver.AsOf(ctx, "land-001", mustTime("2020-01-01"), mustTime("2025-01-01"))
	assert.ErrorIs(t, err, ErrEntityNotFound)
	assert.Nil(t, result)
}

// TestAsOf_TransactionTimeHorizon validates that records with SystemTime > transactionTime
// are invisible (the query respects the "as of" transaction time horizon).
func TestAsOf_TransactionTimeHorizon(t *testing.T) {
	store := newMockS3Store()

	// v1 recorded in 2015, v2 recorded in 2020. Query with txTime=2017.
	// Only v1 should be visible.
	v1 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2015-01-01").UnixNano(),
		ValidTimeStart: mustTime("2010-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2025-01-01").UnixNano(),
		AssertionTime:  mustTime("2015-01-01").UnixNano(),
		H3Index:        42,
		Payload:        []byte(`{"status":"original"}`),
	}
	v2 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2020-01-01").UnixNano(),
		ValidTimeStart: mustTime("2010-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2025-01-01").UnixNano(),
		AssertionTime:  mustTime("2020-01-01").UnixNano(),
		H3Index:        42,
		Payload:        []byte(`{"status":"corrected"}`),
	}

	store.putArrowFile(t, l0Key("land-001", mustTime("2015-01-01").UnixNano()), []TriTemporalEvent{v1, v2})

	resolver := NewResolver(store, store, nil, "test-bucket", DefaultResolverConfig())
	ctx := context.Background()

	// txTime = 2017: v2 (SystemTime=2020) is invisible, only v1 visible.
	result, err := resolver.AsOf(ctx, "land-001", mustTime("2015-06-01"), mustTime("2017-01-01"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []byte(`{"status":"original"}`), result.Payload)

	// txTime = 2021: both visible, v2 dominates (later SystemTime).
	result2, err := resolver.AsOf(ctx, "land-001", mustTime("2015-06-01"), mustTime("2021-01-01"))
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Equal(t, []byte(`{"status":"corrected"}`), result2.Payload)
}

// TestAsOf_ValidTimeExclusiveEnd validates that ValidTimeEnd is exclusive
// (the standard half-open interval [start, end) convention).
func TestAsOf_ValidTimeExclusiveEnd(t *testing.T) {
	store := newMockS3Store()

	v1 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2020-01-01").UnixNano(),
		ValidTimeStart: mustTime("2010-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2020-01-01").UnixNano(), // Exclusive end
		AssertionTime:  mustTime("2020-01-01").UnixNano(),
		H3Index:        0,
		Payload:        []byte(`{"period":"2010-2020"}`),
	}

	store.putArrowFile(t, l0Key("land-001", mustTime("2020-01-01").UnixNano()), []TriTemporalEvent{v1})

	resolver := NewResolver(store, store, nil, "test-bucket", DefaultResolverConfig())
	ctx := context.Background()

	// Query at validTime = 2019-12-31 (inside [2010, 2020)) -> should find.
	result, err := resolver.AsOf(ctx, "land-001", mustTime("2019-12-31"), mustTime("2021-01-01"))
	require.NoError(t, err)
	require.NotNil(t, result)

	// Query at validTime = 2020-01-01 (AT the exclusive end) -> should NOT find.
	result2, err := resolver.AsOf(ctx, "land-001", mustTime("2020-01-01"), mustTime("2021-01-01"))
	assert.ErrorIs(t, err, ErrEntityNotFound)
	assert.Nil(t, result2)
}

// TestAsOf_MultipleEntitiesInSameFile validates that the resolver correctly
// discriminates between entities sharing the same L0 file.
func TestAsOf_MultipleEntitiesInSameFile(t *testing.T) {
	store := newMockS3Store()

	land001 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2020-01-01").UnixNano(),
		ValidTimeStart: mustTime("2015-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2025-01-01").UnixNano(),
		AssertionTime:  mustTime("2020-01-01").UnixNano(),
		H3Index:        100,
		Payload:        []byte(`{"entity":"land-001"}`),
	}
	land002 := TriTemporalEvent{
		EntityID:       "land-002",
		SystemTime:     mustTime("2020-01-01").UnixNano(),
		ValidTimeStart: mustTime("2015-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2025-01-01").UnixNano(),
		AssertionTime:  mustTime("2020-01-01").UnixNano(),
		H3Index:        200,
		Payload:        []byte(`{"entity":"land-002"}`),
	}

	store.putArrowFile(t, l0Key("land-001", mustTime("2020-01-01").UnixNano()), []TriTemporalEvent{land001, land002})
	store.putArrowFile(t, l0Key("land-002", mustTime("2020-01-01").UnixNano()), []TriTemporalEvent{land001, land002})

	resolver := NewResolver(store, store, nil, "test-bucket", DefaultResolverConfig())
	ctx := context.Background()

	// Query for land-001 -> should return land-001 only.
	result, err := resolver.AsOf(ctx, "land-001", mustTime("2020-06-01"), mustTime("2021-01-01"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "land-001", result.EntityID)
	assert.Equal(t, uint64(100), result.H3Index)

	// Query for land-002 -> should return land-002 only.
	result2, err := resolver.AsOf(ctx, "land-002", mustTime("2020-06-01"), mustTime("2021-01-01"))
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Equal(t, "land-002", result2.EntityID)
	assert.Equal(t, uint64(200), result2.H3Index)
}

// TestAsOf_ContextCancellation validates that queries respect context cancellation.
func TestAsOf_ContextCancellation(t *testing.T) {
	store := newMockS3Store()

	v1 := TriTemporalEvent{
		EntityID:       "land-001",
		SystemTime:     mustTime("2020-01-01").UnixNano(),
		ValidTimeStart: mustTime("2015-01-01").UnixNano(),
		ValidTimeEnd:   mustTime("2025-01-01").UnixNano(),
		AssertionTime:  mustTime("2020-01-01").UnixNano(),
		Payload:        []byte(`{}`),
	}
	store.putArrowFile(t, l0Key("land-001", mustTime("2020-01-01").UnixNano()), []TriTemporalEvent{v1})

	resolver := NewResolver(store, store, nil, "test-bucket", DefaultResolverConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := resolver.AsOf(ctx, "land-001", mustTime("2020-06-01"), mustTime("2021-01-01"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled")
}

// TestAsOf_EmptyEntityIDRejected validates the boundary defense for empty entity IDs.
func TestAsOf_EmptyEntityIDRejected(t *testing.T) {
	store := newMockS3Store()
	resolver := NewResolver(store, store, nil, "test-bucket", DefaultResolverConfig())
	ctx := context.Background()

	_, err := resolver.AsOf(ctx, "", mustTime("2020-06-01"), mustTime("2021-01-01"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entityID must not be empty")
}
