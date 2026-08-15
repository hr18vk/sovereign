//go:build linux

package spatial

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestEpochBatcher_BasicFlush validates stage → flush → result cycle.
func TestEpochBatcher_BasicFlush(t *testing.T) {
	ring, err := NewSPSCRing(256, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}
	defer func() { _ = ring.Close() }()

	batcher := NewEpochBatcher(ring, 10)

	const numEvents = 10

	// Start mock consumer.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numEvents; i++ {
			idx := uint32(i) % ring.capacity
			slot := &ring.slots[idx]
			for atomic.LoadUint32(&slot.State) != SlotReady {
			}
			atomic.StoreUint32(&slot.State, SlotProcessing)
			slot.H3Index = slot.RequestID + 100
			atomic.StoreUint32(&slot.State, SlotDone)
		}
	}()

	// Stage events.
	for i := 0; i < numEvents; i++ {
		lat := 10.0 + float64(i)*0.01
		lng := 76.0 + float64(i)*0.01
		if err := batcher.Stage(lat, lng); err != nil {
			t.Fatalf("Stage(%d): %v", i, err)
		}
	}

	// Flush and collect.
	results := batcher.FlushEpoch()
	if len(results) != numEvents {
		t.Fatalf("expected %d results, got %d", numEvents, len(results))
	}

	for i, r := range results {
		if r.Timeout {
			t.Fatalf("result %d timed out", i)
		}
		expected := r.SeqID + 100
		if r.H3Index != expected {
			t.Fatalf("result %d: H3Index=%d, want %d", i, r.H3Index, expected)
		}
	}

	wg.Wait()
}

// TestEpochBatcher_EpochSizeCap validates that epoch size is capped at ring/2.
func TestEpochBatcher_EpochSizeCap(t *testing.T) {
	ring, err := NewSPSCRing(64, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}
	defer func() { _ = ring.Close() }()

	batcher := NewEpochBatcher(ring, 1000) // Request 1000, but ring is 64

	if batcher.EpochSize() != 32 { // 64 / 2
		t.Fatalf("epoch size = %d, want 32", batcher.EpochSize())
	}
}

// TestEpochBatcher_TimeoutRecovery validates graceful timeout handling.
func TestEpochBatcher_TimeoutRecovery(t *testing.T) {
	ring, err := NewSPSCRing(64, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}
	defer func() { _ = ring.Close() }()

	batcher := NewEpochBatcher(ring, 2)

	// Stage 1 event with NO consumer (will timeout).
	if err := batcher.Stage(10.0, 76.0); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	// Flush — should timeout and return H3Index=0.
	results := batcher.FlushEpoch()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if !results[0].Timeout {
		t.Fatal("expected timeout=true")
	}
	if results[0].H3Index != 0 {
		t.Fatalf("expected H3Index=0 on timeout, got %d", results[0].H3Index)
	}
}

// TestEpochBatcher_EmptyFlush validates that flushing an empty epoch is safe.
func TestEpochBatcher_EmptyFlush(t *testing.T) {
	ring, err := NewSPSCRing(64, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}
	defer func() { _ = ring.Close() }()

	batcher := NewEpochBatcher(ring, 10)
	results := batcher.FlushEpoch()
	if results != nil {
		t.Fatalf("expected nil results for empty epoch, got %v", results)
	}
}
