//go:build linux

package spatial

import (
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestRingSlotSize validates the compile-time 64-byte size assertion.
func TestRingSlotSize(t *testing.T) {
	size := unsafe.Sizeof(RingSlot{})
	if size != CacheLineSize {
		t.Fatalf("RingSlot size = %d bytes, want %d (cache line)", size, CacheLineSize)
	}
}

// TestRingHeaderSize validates the header is exactly 3 cache lines (192 bytes).
func TestRingHeaderSize(t *testing.T) {
	size := unsafe.Sizeof(RingHeader{})
	if size != 3*CacheLineSize {
		t.Fatalf("RingHeader size = %d bytes, want %d (3 cache lines)", size, 3*CacheLineSize)
	}
}

// TestNewSPSCRing_PowerOfTwoEnforcement validates capacity constraints.
func TestNewSPSCRing_PowerOfTwoEnforcement(t *testing.T) {
	_, err := NewSPSCRing(100, 9) // Not power of 2
	if err == nil {
		t.Fatal("expected error for non-power-of-2 capacity")
	}

	ring, err := NewSPSCRing(1024, 9) // Power of 2
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = ring.Close() }()

	if ring.capacity != 1024 {
		t.Fatalf("capacity = %d, want 1024", ring.capacity)
	}
}

// TestNewSPSCRing_MemfdCreated validates that NewSPSCRing creates a valid
// memfd file descriptor that can be used for cross-process shared memory.
func TestNewSPSCRing_MemfdCreated(t *testing.T) {
	ring, err := NewSPSCRing(256, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}
	defer func() { _ = ring.Close() }()

	// The memfd should be a valid file descriptor (>= 0).
	fd, totalSize := ring.SharedMemoryFd()
	if fd < 0 {
		t.Fatalf("SharedMemoryFd() returned invalid fd: %d", fd)
	}

	// The total size should be header + slots.
	expectedSize := int(unsafe.Sizeof(RingHeader{})) + int(unsafe.Sizeof(RingSlot{}))*256
	if totalSize != expectedSize {
		t.Fatalf("SharedMemoryFd() totalSize = %d, want %d", totalSize, expectedSize)
	}

	// Verify the fd is readable via fstat (proves it's a real fd, not -1).
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatalf("fstat on memfd failed: %v (fd=%d) — this would be the EBADF crash in production", err, fd)
	}

	// The memfd size should match what we ftruncated to.
	if stat.Size != int64(expectedSize) {
		t.Fatalf("memfd fstat size = %d, want %d", stat.Size, expectedSize)
	}
}

// TestSubmitAndCollect_MockConsumer simulates the C++ worker with a Go goroutine
// to validate the atomic state machine without requiring the C++ binary.
func TestSubmitAndCollect_MockConsumer(t *testing.T) {
	ring, err := NewSPSCRing(256, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}
	defer func() { _ = ring.Close() }()

	const numEvents = 100

	// Start a mock consumer goroutine that reads READY slots and writes
	// back a deterministic H3 index (request ID + 42 for verification).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numEvents; i++ {
			idx := uint32(i) % ring.capacity
			slot := &ring.slots[idx]

			// Spin until READY.
			for atomic.LoadUint32(&slot.State) != SlotReady {
				// tight spin for test
			}

			// Simulate READY → PROCESSING → DONE (matching C++ state machine).
			atomic.StoreUint32(&slot.State, SlotProcessing)

			// Simulate H3 computation.
			slot.H3Index = slot.RequestID + 42 // deterministic

			// Transition to DONE.
			atomic.StoreUint32(&slot.State, SlotDone)
		}
	}()

	// Producer: submit coordinate pairs and verify results.
	for i := 0; i < numEvents; i++ {
		lat := 0.0 + float64(i)*0.001
		lng := 0.0 + float64(i)*0.001

		seqID, err := ring.Submit(lat, lng)
		if err != nil {
			t.Fatalf("Submit(%d): %v", i, err)
		}

		result, err := ring.Collect(seqID)
		if err != nil {
			t.Fatalf("Collect(%d): %v", i, err)
		}

		expected := seqID + 42
		if result != expected {
			t.Fatalf("Collect(%d): got H3Index=%d, want %d", i, result, expected)
		}
	}

	wg.Wait()
}

// TestShutdown validates the shutdown flag mechanism.
func TestShutdown(t *testing.T) {
	ring, err := NewSPSCRing(64, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}
	defer func() { _ = ring.Close() }()

	ring.Shutdown()

	if atomic.LoadUint32(&ring.header.Shutdown) != 1 {
		t.Fatal("shutdown flag not set")
	}
}

// TestRingCapacityExhaustion validates behavior when ring is full.
func TestRingCapacityExhaustion(t *testing.T) {
	// Use a tiny ring (16 slots) to make exhaustion fast.
	ring, err := NewSPSCRing(16, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}
	defer func() { _ = ring.Close() }()

	// Fill all 16 slots without a consumer.
	for i := 0; i < 16; i++ {
		_, err := ring.Submit(10.0+float64(i)*0.01, 76.0+float64(i)*0.01)
		if err != nil {
			t.Fatalf("Submit(%d): %v", i, err)
		}
	}

	// All slots should be in READY state.
	for i := uint32(0); i < 16; i++ {
		state := atomic.LoadUint32(&ring.slots[i].State)
		if state != SlotReady {
			t.Fatalf("slot[%d].State = %d, want %d (READY)", i, state, SlotReady)
		}
	}
}

// TestClose_ReleasesMemfd validates that Close() properly cleans up the memfd.
func TestClose_ReleasesMemfd(t *testing.T) {
	ring, err := NewSPSCRing(64, 9)
	if err != nil {
		t.Fatalf("NewSPSCRing: %v", err)
	}

	fd, _ := ring.SharedMemoryFd()
	if fd < 0 {
		t.Fatalf("memfd is invalid before close: %d", fd)
	}

	// Close should release the memfd.
	if err := ring.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After close, the fd should be invalid.
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err == nil {
		t.Fatal("memfd should be invalid after Close(), but fstat succeeded")
	}
}
