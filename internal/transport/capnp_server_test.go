// Copyright 2026 Harsh Rawat
//
// Use of this software is governed by the Business Source License 1.1,
// which can be found in the LICENSE file. Production use requires a written
// grant from the Licensor until the Change Date stated in the LICENSE file.

//go:build linux

package transport

import (
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hr18vk/sovereign/internal/database"

	capnp "capnproto.org/go/capnp/v3"
	capnp_schema "github.com/hr18vk/sovereign/api/capnp/api/capnp"
)

// buildTestMessage constructs a framed, single-segment TriTemporalEvent for
// the ingestion tests.
func buildTestMessage(t *testing.T, lat, lng float64, assertionTime uint64, entityID, payload string) []byte {
	t.Helper()

	// Build a single-segment Cap'n Proto message.
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}

	event, err := capnp_schema.NewRootTriTemporalEvent(seg)
	if err != nil {
		t.Fatalf("NewRootTriTemporalEvent: %v", err)
	}

	event.SetLatitude(lat)
	event.SetLongitude(lng)
	event.SetAssertionTime(assertionTime)
	if err := event.SetEntityId(entityID); err != nil {
		t.Fatalf("SetEntityId: %v", err)
	}
	if err := event.SetPayload(payload); err != nil {
		t.Fatalf("SetPayload: %v", err)
	}

	// Marshal to bytes (includes Cap'n Proto framing header).
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	return data
}

// TestBuildTestMessage_Serialization checks the framing and field values after
// a Cap'n Proto round trip.
func TestBuildTestMessage_Serialization(t *testing.T) {
	data := buildTestMessage(t, 37.7749, -122.4194, 1719907200000, "entity-test-001", "subscription enrollment")

	// Validate Cap'n Proto framing header.
	if len(data) < 8 {
		t.Fatalf("message too short: %d bytes", len(data))
	}

	segCountMinusOne := binary.LittleEndian.Uint32(data[0:4])
	if segCountMinusOne != 0 {
		t.Fatalf("expected single-segment message (segCount-1=0), got %d", segCountMinusOne)
	}

	segWords := binary.LittleEndian.Uint32(data[4:8])
	segBytes := int(segWords) * 8
	expectedTotal := 8 + segBytes // header + segment data
	if len(data) != expectedTotal {
		t.Fatalf("framing mismatch: header claims %d bytes, total is %d", expectedTotal, len(data))
	}

	// Unmarshal the message and compare every field with the input.
	roundTrip, err := capnp.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal round-trip: %v", err)
	}
	event, err := capnp_schema.ReadRootTriTemporalEvent(roundTrip)
	if err != nil {
		t.Fatalf("ReadRootTriTemporalEvent: %v", err)
	}

	if got := event.Latitude(); got != 37.7749 {
		t.Fatalf("Latitude round-trip: got %f, want 37.7749", got)
	}
	if got := event.Longitude(); got != -122.4194 {
		t.Fatalf("Longitude round-trip: got %f, want -122.4194", got)
	}
	if got := event.AssertionTime(); got != 1719907200000 {
		t.Fatalf("AssertionTime round-trip: got %d, want 1719907200000", got)
	}
	eid, err := event.EntityId()
	if err != nil {
		t.Fatalf("EntityId: %v", err)
	}
	if eid != "entity-test-001" {
		t.Fatalf("EntityId round-trip: got %q, want %q", eid, "entity-test-001")
	}
	pl, err := event.Payload()
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	if pl != "subscription enrollment" {
		t.Fatalf("Payload round-trip: got %q, want %q", pl, "subscription enrollment")
	}
}

// TestBuildTestMessage_MaxMessageSizeGuard verifies that the large-payload
// fixture encodes to more than MaxMessageSize bytes.
func TestBuildTestMessage_MaxMessageSizeGuard(t *testing.T) {
	// The payload alone exceeds the server's segment-size limit.
	largePayload := make([]byte, MaxMessageSize+1)
	for i := range largePayload {
		largePayload[i] = 'A'
	}

	// Framing and event fields make the encoded message larger still.
	data := buildTestMessage(t, 0.0, 0.0, 0, "overflow-test", string(largePayload))
	if len(data) <= MaxMessageSize {
		t.Fatalf("expected oversized message (>%d bytes), got %d bytes", MaxMessageSize, len(data))
	}
}

// TestEpollServer_BasicMessage starts a listener on an ephemeral port and
// verifies that Shutdown terminates the event loop.
func TestEpollServer_BasicMessage(t *testing.T) {
	allocator := database.NewJemallocAllocator()

	var received atomic.Int64
	var lastLat, lastLng atomic.Value

	handler := func(event capnp_schema.TriTemporalEvent) error {
		lastLat.Store(event.Latitude())
		lastLng.Store(event.Longitude())
		received.Add(1)
		return nil
	}

	server := NewEpollServer(allocator, handler)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe(":0") // Let the OS pick a port.
	}()

	// Allow ListenAndServe to enter the event loop before requesting shutdown.
	time.Sleep(50 * time.Millisecond)
	server.Shutdown()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("ListenAndServe returned an error on port 0: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not shut down within 2 seconds")
	}
}

// TestParseMessages_FramingHeader checks the single-segment framing values
// used by parseMessages.
func TestParseMessages_FramingHeader(t *testing.T) {
	// Build a header for a single segment containing four 8-byte words.
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header[0:4], 0) // segCount - 1 = 0 (1 segment)
	binary.LittleEndian.PutUint32(header[4:8], 4) // 4 words = 32 bytes

	// Append a zeroed segment, which represents an empty struct.
	data := make([]byte, 32)
	msg := append(header, data...)

	// Verify total size.
	if len(msg) != 40 {
		t.Fatalf("expected 40 bytes, got %d", len(msg))
	}

	// Parse the framing header.
	segCountMinusOne := binary.LittleEndian.Uint32(msg[0:4])
	segWords := binary.LittleEndian.Uint32(msg[4:8])

	if segCountMinusOne != 0 {
		t.Fatalf("expected segCount-1 = 0, got %d", segCountMinusOne)
	}
	if segWords != 4 {
		t.Fatalf("expected segWords = 4, got %d", segWords)
	}
}

// TestMaxMessageSize verifies that the oversized framing fixture exceeds the
// server's segment-size limit.
func TestMaxMessageSize(t *testing.T) {
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header[0:4], 0)
	// Set the segment size to MaxMessageSize plus one word.
	oversize := uint32((MaxMessageSize / 8) + 1)
	binary.LittleEndian.PutUint32(header[4:8], oversize)

	segBytes := int(oversize) * 8
	if segBytes <= MaxMessageSize {
		t.Fatal("test setup error: oversized message is not actually oversized")
	}
}
