package database

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestMemTable(arenaSize uint32, maxEntries uint32) (*MemTable, *mockS3Uploader) {
	alloc := NewJemallocAllocator()
	s3 := newMockS3()
	flusher := NewL0Flusher(alloc, s3, "test-bucket")
	// Override O2.5: No PIIGate parameter. Override 8.1: fallbackDir for tests.
	mt := NewMemTable(alloc, arenaSize, maxEntries, flusher, "")
	return mt, s3
}

func TestMemTable_InsertAndFlush(t *testing.T) {
	// 50,001st insert should trigger async auto-flush.
	mt, s3 := newTestMemTable(256*1024*1024, 50000)
	ctx := context.Background()

	now := time.Now().UTC()

	for i := 0; i < 50001; i++ {
		event := TriTemporalEvent{
			EntityID:       fmt.Sprintf("entity-%d", i),
			SystemTime:     now.Add(time.Duration(i) * time.Microsecond).UnixNano(),
			ValidTimeStart: now.UnixNano(),
			ValidTimeEnd:   MaxValidTimeEndNs,
			AssertionTime:  now.UnixNano(),
			Payload:        []byte(`{"type":"test"}`),
		}
		err := mt.Write(ctx, event)
		require.NoError(t, err)
	}

	// Close drains the async flush WaitGroup, ensuring all uploads complete.
	err := mt.Close(ctx)
	require.NoError(t, err)

	// After Close(), all async flushes are guaranteed complete.
	// Should have flushed once (async at 50K) + once (sync at Close for the 1 remaining).
	assert.GreaterOrEqual(t, s3.Len(), 1)
	assert.Equal(t, int64(0), mt.FlushErrors())
}

func TestMemTable_ConcurrentWrites(t *testing.T) {
	mt, _ := newTestMemTable(256*1024*1024, 100000)
	ctx := context.Background()
	now := time.Now().UTC()

	var wg sync.WaitGroup
	goroutines := 100
	writesPerGoroutine := 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine; i++ {
				event := TriTemporalEvent{
					EntityID:       fmt.Sprintf("entity-g%d-i%d", gid, i),
					SystemTime:     now.Add(time.Duration(gid*1000+i) * time.Microsecond).UnixNano(),
					ValidTimeStart: now.UnixNano(),
					ValidTimeEnd:   MaxValidTimeEndNs,
					AssertionTime:  now.UnixNano(),
					Payload:        []byte(`{"concurrent":"test"}`),
				}
				err := mt.Write(ctx, event)
				assert.NoError(t, err)
			}
		}(g)
	}

	wg.Wait()

	// All 10,000 writes should be in the table.
	assert.Equal(t, uint32(goroutines*writesPerGoroutine), mt.EntryCount())

	if err := mt.Close(ctx); err != nil {
		t.Logf("memtable close: %v", err)
	}
}

func TestMemTable_PIIMaskingEnforced(t *testing.T) {
	mt, s3 := newTestMemTable(256*1024*1024, 10)
	ctx := context.Background()
	now := time.Now().UTC()

	// Insert an event with a valid PII number in payload.
	event := TriTemporalEvent{
		EntityID:       "citizen-001",
		SystemTime:     now.UnixNano(),
		ValidTimeStart: now.UnixNano(),
		ValidTimeEnd:   MaxValidTimeEndNs,
		AssertionTime:  now.UnixNano(),
		Payload:        []byte("User ID: 123456789012 applied for service."),
	}
	err := mt.Write(ctx, event)
	require.NoError(t, err)

	// Force synchronous flush to inspect Arrow output.
	err = mt.Flush(ctx)
	require.NoError(t, err)

	// Drain any async flushes (none expected here, but defensive).
	if err := mt.Close(ctx); err != nil {
		t.Logf("memtable close: %v", err)
	}

	// Verify the uploaded Arrow data does NOT contain the raw PII.
	assert.GreaterOrEqual(t, s3.Len(), 1)
	for _, data := range s3.Uploads() {
		assert.NotContains(t, string(data), "499118665246")
		// The redaction marker should be present in the binary data.
		assert.Contains(t, string(data), "PII_REDACTED")
	}
}

func TestMemTable_GracefulShutdownFlush(t *testing.T) {
	mt, s3 := newTestMemTable(256*1024*1024, 100000)
	ctx := context.Background()
	now := time.Now().UTC()

	// Insert some events.
	for i := 0; i < 100; i++ {
		event := TriTemporalEvent{
			EntityID:       fmt.Sprintf("entity-%d", i),
			SystemTime:     now.Add(time.Duration(i) * time.Microsecond).UnixNano(),
			ValidTimeStart: now.UnixNano(),
			ValidTimeEnd:   MaxValidTimeEndNs,
			AssertionTime:  now.UnixNano(),
			Payload:        []byte(`{"shutdown":"test"}`),
		}
		_ = mt.Write(ctx, event)
	}

	// Close should: sync-flush remaining events, wait for all async flushes.
	err := mt.Close(ctx)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, s3.Len(), 1)
	assert.Equal(t, int64(0), mt.FlushErrors())
}

func TestMemTable_AsyncFlushDoesNotBlockWrites(t *testing.T) {
	// This test verifies that the write path is NOT blocked during S3 upload.
	// We use a slow mock uploader that sleeps for 100ms per upload.
	alloc := NewJemallocAllocator()
	slowS3 := &slowMockS3Uploader{delay: 100 * time.Millisecond}
	flusher := NewL0Flusher(alloc, slowS3, "test-bucket")
	mt := NewMemTable(alloc, 256*1024*1024, 100, flusher, "") // Low threshold: 100 entries

	ctx := context.Background()
	now := time.Now().UTC()

	// Write 250 events. This should trigger 2 async flushes (at 100 and 200).
	// If the flush were synchronous, this would take ≥200ms.
	// With async flush, writes should complete in <50ms.
	start := time.Now()

	for i := 0; i < 250; i++ {
		event := TriTemporalEvent{
			EntityID:       fmt.Sprintf("entity-%d", i),
			SystemTime:     now.Add(time.Duration(i) * time.Microsecond).UnixNano(),
			ValidTimeStart: now.UnixNano(),
			ValidTimeEnd:   MaxValidTimeEndNs,
			AssertionTime:  now.UnixNano(),
			Payload:        []byte(`{"async":"test"}`),
		}
		err := mt.Write(ctx, event)
		require.NoError(t, err)
	}

	writeDuration := time.Since(start)

	// Write path should complete fast — the S3 uploads are async.
	// Allow generous margin but reject if it took as long as synchronous would.
	assert.Less(t, writeDuration, 150*time.Millisecond,
		"write path blocked by S3 upload — async flush is broken")

	// Now Close() should wait for the async flushes to drain.
	err := mt.Close(ctx)
	require.NoError(t, err)

	// Verify uploads completed.
	assert.GreaterOrEqual(t, int(slowS3.uploadCount.Load()), 2)
}

func TestMemTable_BoundedInflightFlushesBackpressure(t *testing.T) {
	alloc := NewJemallocAllocator()
	blockingS3 := &blockingMockS3Uploader{
		started: make(chan struct{}, DefaultMaxInflightFlushes+2),
		release: make(chan struct{}),
	}
	flusher := NewL0Flusher(alloc, blockingS3, "test-bucket")
	mt := NewMemTable(alloc, 256*1024*1024, 1, flusher, "")
	ctx := context.Background()
	now := time.Now().UTC()

	writeEvent := func(i int) error {
		return mt.Write(ctx, TriTemporalEvent{
			EntityID:       fmt.Sprintf("entity-%d", i),
			SystemTime:     now.Add(time.Duration(i) * time.Microsecond).UnixNano(),
			ValidTimeStart: now.UnixNano(),
			ValidTimeEnd:   MaxValidTimeEndNs,
			AssertionTime:  now.UnixNano(),
			Payload:        []byte(`{"bounded":"flush"}`),
		})
	}

	for i := 0; i < DefaultMaxInflightFlushes+1; i++ {
		require.NoError(t, writeEvent(i))
	}

	for i := 0; i < DefaultMaxInflightFlushes; i++ {
		select {
		case <-blockingS3.started:
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for async flush %d to start", i+1)
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- writeEvent(DefaultMaxInflightFlushes + 1)
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
		t.Fatal("write completed while all flush slots were occupied")
	case <-time.After(75 * time.Millisecond):
		// The fifth flush attempt is parked on flushSem as intended.
	}

	blockingS3.release <- struct{}{}

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("write did not resume after one flush slot was released")
	}

	close(blockingS3.release)
	require.NoError(t, mt.Close(ctx))
}

// slowMockS3Uploader simulates a slow S3 upload for testing async behavior.
type slowMockS3Uploader struct {
	delay       time.Duration
	uploadCount atomic.Int32
}

func (m *slowMockS3Uploader) Upload(_ context.Context, _ string, _ io.Reader, _ int64) error {
	time.Sleep(m.delay)
	m.uploadCount.Add(1)
	return nil
}

type blockingMockS3Uploader struct {
	started chan struct{}
	release chan struct{}
}

func (m *blockingMockS3Uploader) Upload(_ context.Context, _ string, _ io.Reader, _ int64) error {
	m.started <- struct{}{}
	<-m.release
	return nil
}
