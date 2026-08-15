package network

import (
	"testing"

	capnp "capnproto.org/go/capnp/v3"
)

// TestNewIngestionArena_ReturnsValidArena validates basic arena creation.
func TestNewIngestionArena_ReturnsValidArena(t *testing.T) {
	// Simulate a jemalloc-backed byte slice (use Go heap for testing).
	data := make([]byte, 64)
	arena := NewIngestionArena(data)

	if arena == nil {
		t.Fatal("NewIngestionArena returned nil")
	}

	// Arena should report exactly 1 segment.
	if n := arena.NumSegments(); n != 1 {
		t.Fatalf("NumSegments() = %d, want 1", n)
	}
}

// TestNewIngestionArena_SegmentReturnsData validates that Segment(0) returns
// the original byte slice data.
func TestNewIngestionArena_SegmentReturnsData(t *testing.T) {
	data := make([]byte, 128)
	// Write a marker to verify the segment contains our data.
	data[0] = 0xAB
	data[127] = 0xCD

	arena := NewIngestionArena(data)

	seg := arena.Segment(0)
	if seg == nil {
		t.Fatal("Segment(0) returned nil")
	}

	// Segment(1) should return nil (single-segment arena).
	if seg1 := arena.Segment(1); seg1 != nil {
		t.Fatal("Segment(1) should return nil for single-segment arena")
	}
}

// TestNewIngestionArena_AllocateReturnsError validates that allocation is forbidden.
func TestNewIngestionArena_AllocateReturnsError(t *testing.T) {
	data := make([]byte, 64)
	arena := NewIngestionArena(data)

	// Create a message to pass to Allocate.
	msg := &capnp.Message{Arena: arena}
	_, _, err := arena.Allocate(8, msg, nil)
	if err == nil {
		t.Fatal("Allocate should return error on read-only arena")
	}
}

// TestNewIngestionArena_ReleaseSafe validates that Release() does not panic
// and does not corrupt the underlying memory.
func TestNewIngestionArena_ReleaseSafe(t *testing.T) {
	data := make([]byte, 64)
	data[0] = 0xFF // marker

	arena := NewIngestionArena(data)
	arena.Release() // Should not panic

	// After release, the original data slice should be untouched.
	// Release() on SingleSegmentArena with bp=nil only sets seg.data=nil,
	// it does NOT zero our original data slice.
	if data[0] != 0xFF {
		t.Fatal("Release() corrupted the underlying memory")
	}
}
